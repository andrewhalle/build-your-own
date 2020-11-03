# Build your own: GPG

By: [Andrew Halle](https://github.com/andrewhalle)
Repo: [byo-gpg](https://github.com/andrewhalle/byo-gpg)

Part of [build-your-own](https://andrewhalle.github.io/build-your-own)

## Background

GPG (stands for Gnu Privacy Guard) is an implementation of PGP (which stands for Pretty Good Privacy), an open standard for encryption specified by [RFC 4880](https://tools.ietf.org/html/rfc4880). In this post, we'll build up a program in Rust that implements one part of the PGP standard, verifying cleartext signatures.

_(As an aside, I think it's hilarious that GPG is an implementation of PGP. The obvious right choice was to call it GPGP. I considered calling my tool PGPG, but ultimately decided on pgp-rs, because I'm boring.)_

PGP supports a number of different cryptography suites, but the default cipher suite, and the one I'm most familiar with, is RSA cryptography.

### RSA

A quick review of [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) might be warranted (it certainly was for me). RSA is a public-key cryptosystem (one in which parts of the key used for encryption are allowed to be non-secret) which relies on the impracticality of factoring very large (a normal figure is 2048 bits) composite numbers. Put another way, it is easy to find 3 large integers n, d, and e with the property that

$$
(m^e)^d \equiv m \mod n
$$

but it's very difficult, given only e and n, to discover d. In this way, the tuple (e,n) forms the public key, which can be broadcast to the world, and the tuple (e,d,n) forms the private key, which is kept secret. Messages can be encrypted by computing the ciphertext C

$$
m^e \mod n
$$

C can then be decrypted by anyone with the corresponding private key by computing

$$
C^d \mod n
$$

So C forms a secret message that's only readable by the intended recipient. Similarly, the owner of the private key can compute a signature S

$$
m^d \mod n
$$

which can be verified by anyone with the public key by computing

$$
S^e \mod n
$$

In this way, the owner of the private key can create something that can be verified to be authentic.

### GPG operation

GPG provides operations for generating and distributing keys, encrypting messages, and producing signatures. The particular operation we're interested in right now is producing a *cleartext signature*, one that includes the message for anyone to read, and an associated signature that confirms the message is from the owner of the private key.

In order to produce a cleartext signature, you must first generate a public/private key pair.

```
$ gpg --gen-key
gpg (GnuPG) 2.2.23; Copyright (C) 2020 Free Software Foundation, Inc.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name:
```

GPG will ask for some identifying information, generate a new key (RSA by default), and store it in the keyring. The key can be exported to a file (important for us to ingest it!) via

```
$ gpg --armor --export <the-email-you-used@email.com>
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQGNBF+Q5NcBDACethfnSE2nISgiCPd9YEsZvvIFboLRtAip6fQ7Shu2Q+dcSx9u
mGFi3HcW1sdYGE+sVX+/YSidl8bM32ZBzJnicbM1CzRvWA7fDb2tSk60la7nt/nf
3td90kBV82PwGFWXJip66YxbWbL1QIGLiVMvtrW54pIvaXdbBnxEv/QcavP+vqkn
...
```

We'll get into the format of this key later.

With a key in hand, we can generate a cleartext signature via

```
$ echo 'hello world' > msg.txt
$ gpg --local-user <the-email-you-used@email.com> --clearsign msg.txt
$ bat msg.txt.asc
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

hello world
-----BEGIN PGP SIGNATURE-----

iQHFBAEBCAAvFiEETZeSb43pC1IsVsJXpFDPSuBCLqcFAl+SUssRHG5ld3Rlc3RA
dGVzdC5jb20ACgkQpFDPSuBCLqdPRQwAknGOMSFXh5OzaCS95+tNiDgSKMC6/ix7
d8jRN2qkbk+CGruvWqmbZm1VLeZIZuxhAsAuFje2bOEYeXUbJlmIHKg0XxNY4Gc/
OAF9QUmNnlVYm1KTuEqOIlHnNViCKRThkDaK+CbfQCOT4i13Ov1wcQvEKFdOSMuN
1sUZ+9qqwGLGW9pcIjdmMtCpPRZzP3K2H5g4G4mUawtJpQhvMtaKjcxX5iiLpjRJ
ToBdd2vqExTOS6rgo3QDxflOYpdHoYWYheKQgPP9P1ZC86h81TymmgQTM2N6VTsN
WsHUBXNYgDhWvb40dsyD6W5fLV8yXRhyKJqAN8z+MIf10wdy4WvLXB/JBC/5Fn9k
0N/EkfHugkWcbjVgiWZ104S3Y4smtcpTD7KkwJxh0CQb2w0hnW1zecd/gFpfRWAN
gNRu6pOkl8hR+vNODuC29gW+bJeA7a4AdcDIHkbcVZ+jWyf6qvTP19jjuNXcGzoA
/dnWRtbRfcQgAaoyvrBqtTixLtMm87O2
=eBai
-----END PGP SIGNATURE-----
```

_(as an aside, use [bat](https://github.com/sharkdp/bat)! it's great)_

This is the full signature of the text "hello world" using the keypair I generated for this blog post. We'll also get into the format of this signature later. You now as familiar with GPG as you need to be to go through the rest of this post. So, let's start writing some code!

## Getting started

### Dependencies

We start in the normal way

```
$ cargo new pgp-rs
     Created binary (application) `pgp-rs` package
```

I'll go ahead and add all the dependencies we'll need upfront, just to get it out of the way.

```toml
[package]
name = "pgp-rs"
version = "0.1.0"
authors = ["Andrew Halle <ahalle@berkeley.edu>"]
edition = "2018"

# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

[dependencies]
clap = "3.0.0-beta.1"
num = "0.3.0"
nom = "5.1.2"
base64 = "0.12.3"
byteorder = "1.3.4"
anyhow = "1.0.32"
sha2 = "0.9.1"
regex = "1.4.1"
assert_cmd = "1.0.1"
```
we'll use

  * [clap](https://crates.io/crates/clap) for easily building a CLI _(admittedly this is overkill for a program that does one thing, I originally intended to build out more PGP functionality, before deciding that cleartext signatures alone display all the interesting things I wanted to do)_
  * [num](https://crates.io/crates/num) for working with big numbers, and doing modular exponentiation
  * [nom](https://crates.io/crates/nom) for parsing our files, nom is a parser combinator library (I'll explain that a bit more later)
  * [base64](https://crates.io/crates/base64) for decoding base64 data
  * [byteorder](https://crates.io/crates/byteorder) for decoding numbers of a particular endianness
  * [anyhow](https://crates.io/crates/anyhow) for easy error handling
  * [sha2](https://crates.io/crates/sha2) for computing hash functions (more on this later)
  * [regex](https://crates.io/crates/regex) for replacing newlines _(squints at everyone using windows)_
  * [assert_cmd](https://crates.io/crates/assert_cmd) for easy integration testing

_(phew)_

### CLI

Okay, with that out of the way, we can *really* start writing some code!

In `main.rs` we put our clap description of our CLI

```rust
use anyhow::anyhow;
use clap::{clap_app, ArgMatches};

fn main() -> anyhow::Result<()> {
    let matches = clap_app!(("pgp-rs") =>
        (version: "0.1")
        (author: "Andrew Halle <ahalle@berkeley.edu>")
        (about: "PGP tool written in Rust.")
        (@subcommand ("verify") =>
            (about: "verify a clearsigned message")
            (@arg source: -s --source +takes_value
                "Sets the source file containing the message to verify. Defaults to 'msg.txt.asc'.")
            (@arg publicKey: --publicKey +takes_value
                "Sets the public key containing the public key which verifies the \
                 message. Defaults to 'public.pgp'.")
        )

    )
    .get_matches();

    if let Some(matches) = matches.subcommand_matches("verify") {
        verify(matches)
    } else {
        Err(anyhow!("unknown subcommand"))
    }
}

fn verify(matches: &ArgMatches) -> anyhow::Result<()> {
    let source = matches.value_of("source").unwrap_or("msg.txt.asc");
    let public_key_path = matches.value_of("publicKey").unwrap_or("public.pgp");

    pgp_rs::verify_cleartext_message(source, public_key_path)
}
```

I personally really like the macro method of specifying the CLI, but there are other methods. This defines an app (and its metadata) as well as a subcommand `verify` that takes two command line arguments, `source` which will be the cleartext signature we're verifying, and `publicKey` which will be the public key we use to verify it. After parsing the command-line arguments, and providing some sensible defaults, we call out to `pgp_rs::verify_cleartext_message` which we define in `lib.rs`

```rust
use anyhow::anyhow;

mod parsers;
mod pgp;
mod utils;

use pgp::signature::CleartextSignature;
use utils::read_to_string_convert_newlines;

pub fn verify_cleartext_message(source: &str, public_key_path: &str) -> anyhow::Result<()> {
    let data = read_to_string_convert_newlines(source)?;
    let cleartext_signature = CleartextSignature::parse(&data)?;
    println!("File read. Checksum is valid.");

    let key = read_to_string_convert_newlines(public_key_path)?;
    let key = pgp::PublicKey::parse(&key)?;

    if cleartext_signature.verify(&key)? {
        println!("Signature is valid.");
    } else {
        return Err(anyhow!("Signature is invalid."));
    }

    Ok(())
}
```

We parse the cleartext signature and the key, and then verify the signature with the key. If the signature fails to verify with the key, we return an error so the program exits with an error code. We also set up some modules that we'll use later.

Now, we can get into the meat of this code, the parsing functions. In order to do *that* however, we have to take a brief detour _INTO THE RFC_. Take this `::<>`, it's dangerous to go alone.

## Implementation

The RFC containing the details of PGP is [RFC 4880](https://tools.ietf.org/html/rfc4880). The main sections of the RFC we'll need to deal with in this blog post are sections [3.2](https://tools.ietf.org/html/rfc4880#section-3.2), [4](https://tools.ietf.org/html/rfc4880#section-4), [5.2.3](https://tools.ietf.org/html/rfc4880#section-5.2.3), [5.2.4](https://tools.ietf.org/html/rfc4880#section-5.2.4), [5.5.1.1](https://tools.ietf.org/html/rfc4880#section-5.5.1.1), [6.1](https://tools.ietf.org/html/rfc4880#section-6.1), [6.2](https://tools.ietf.org/html/rfc4880#section-6.2), and [7](https://tools.ietf.org/html/rfc4880#section-7).

### Cleartext signatures

The functionality of PGP that we're implementing is validating _cleartext signatures_ (described in [section 7](https://tools.ietf.org/html/rfc4880#section-7) of the RFC). A cleartext signature is a signature that embeds the text being signed in a readable way into the signature itself. It has several parts:

  * a header of `-----BEGIN PGP SIGNED MESSAGE-----`
  * one or more `Hash` armor headers
  * one empty line
  * the dash-escaped cleartext
  * the ASCII-armored signature

We'll talk about parsing ASCII armor in the next section, but we have enough information to parse most of this already. In order to recognize a cleartext signature, we need to first look for the header, followed by a `Hash: <alg>` (`alg` in this case will be SHA256, but there are other options), an empty line, the cleartext, then finally the signature.

The cleartext will be in form called "dash-escaped", which is described in the RFC. Dash-escaped text is the same as normal text, but if the line starts with a literal `-`, then it is prefixed by `- ` (dash, followed by a space). We'll know when we're done with parsing the cleartext because the ASCII armor always starts with a line beginning with 5 dashes, which we will recognize as not being dash-escaped.

I'll be using [nom](https://crates.io/crates/nom) to build all the different parsers we'll need. Nom is a _parser combinator_ library. Parser combinators are a technique for writing parsers where simple parsers (say, for recognizing a literal word, or a string of characters which are all `a`) are combined to form more complex parsers.All nom parsers have the signature

```rust
fn parser<T, U>(input: T) -> IResult<T, U>
```

where `T` is the raw type we're parsing from (usually `&str` or `&[u8]`) and `U` is the type we're parsing. The parser either succeeds or fails, and if it succeeds, it returns a tuple of `(T, U)` where the first entry of the tuple is the remaining input, and the second entry of the tuple is what was parsed. For example, a simple parser that parses a `Color` enum from a string could look like

```rust
use nom::branch::alt;
use nom::bytes::complete::tag;
use nom::IResult;

#[derive(Debug)]
enum Color {
    Red,
    Green,
    Blue,
}

fn parse_red(input: &str) -> IResult<&str, Color> {
    let (input, _) = tag("Red")(input)?;

    Ok((input, Color::Red))
}

fn parse_green(input: &str) -> IResult<&str, Color> {
    let (input, _) = tag("Green")(input)?;

    Ok((input, Color::Green))
}

fn parse_blue(input: &str) -> IResult<&str, Color> {
    let (input, _) = tag("Blue")(input)?;

    Ok((input, Color::Blue))
}

fn parse_color(input: &str) -> IResult<&str, Color> {
    alt((parse_red, parse_green, parse_blue))(input)
}

fn main() {
    let (remaining, color) = parse_color("Green123").unwrap();

    println!("remaining: {}, color: {:?}", remaining, color); // remaining: 123, color: Green
}
```

This example defines 3 parsers, `parse_red`, `parse_green`, and `parse_blue`, which look for a literal string, and if it's found, return the associated `Color` variant. If the input does not contain the string literal, the parser fails (that's why we can ignore the result of the tag parser, we know what it was, and we can return the built value we wanted). `parse_color` is then built from these basic blocks using the `alt` combinator, which succeeds if one of the parsers passed to it in a tuple succeeds, and it succeeds with that result. The `main` function then parses a single color from the string `"Green123"`, leaving the `123` string remaining.

Now to parse a cleartext signature using nom, we first define a `struct` to parse into (in `pgp/signature.rs`)

```rust
#[derive(Debug)]
pub struct CleartextSignature {
    hash: String,
    cleartext: String,
    signature: SignaturePacket,
}
```

The `hash` field will hold the hash variant we're using (could have been an enum if we were being rigorous, or supporting more than just SHA256), the cleartext (after we remove the dash-escaping), and then the signature (which we'll get to later).

The parser for our cleartext signature will look like the following

```rust
pub fn parse_cleartext_signature_parts(input: &str) -> IResult<&str, CleartextSignatureParts> {
    let parser = tuple((
        tag("-----BEGIN PGP SIGNED MESSAGE-----\n"),
        map(parse_hash_armor_header, |s| String::from(s)),
        parse_possibly_dash_escaped_chunk,
        parse_ascii_armor_parts,
    ));

    let (_, (_, hash, msg, ascii_armor_parts)) = all_consuming(parser)(input)?;

    Ok(("", (hash, msg, ascii_armor_parts)))
}
```

This parser first recognizes the header, then the hash variant, then the cleartext, then the parts of the ASCII armor. It also enforces that there's no more input to consume using the `all_consuming` parser. Assuming all that is successful, we return the pieces we need to assemble the cleartext signature.

Drilling down into the methods we decreed must exist

```rust
pub fn parse_hash_armor_header(input: &str) -> IResult<&str, &str> {
    terminated(preceded(tag("Hash: "), alphanumeric1), many0(newline))(input)
}
```

the `parse_hash_armor_header` function recognizes an `alphanumeric1` string preceeded by `Hash: `.

```rust
/// Parse a set of lines (that may be dash-escaped) into a String. Stops when reaching a line
/// that starts with a dash but is not dash-escaped.
pub fn parse_possibly_dash_escaped_chunk(input: &str) -> IResult<&str, String> {
    let (input, mut chunk) = fold_into_string(input, parse_possibly_dash_escaped_line)?;

    chunk.pop();

    Ok((input, chunk))
}
```

`parse_possibly_dash_escaped_chunk` uses a helper I wrote `fold_into_string` which takes a parser that parses a single line of text and combines them into one string. We then `pop()` the last character off the string, because we don't need the last newline.

```rust
/// Parse a line of text that may be dash-escaped. If a line of text is not dash-escaped, but
/// begins with a '-', then fail.
pub fn parse_possibly_dash_escaped_line(input: &str) -> IResult<&str, &str> {
    alt((parse_dash_escaped_line, parse_non_dash_line))(input)
}

/// Parse a line of text that is dash-escaped. Takes a line that begins with '- ', otherwise fails.
pub fn parse_dash_escaped_line(input: &str) -> IResult<&str, &str> {
    let (input, _) = parse_dash(input)?;
    let (input, _) = parse_space(input)?;

    parse_line_newline_inclusive(input)
}

/// Parse a line of text that does not begin with a dash. Line may be the empty string.
pub fn parse_non_dash_line(input: &str) -> IResult<&str, &str> {
    peek(not(parse_dash))(input)?;

    // since peek did not error, we know the line does not begin with a dash.

    parse_line_newline_inclusive(input)
}
```

`parse_possibly_dash_escaped_line` uses the `alt` combinator we've already seen to either parse a line beginning with no dash, or a line beginning with a dash-space. `parse_line_newline_inclusive` is a helper to grab a string slice including the last newline. Because nom parsers can recognize up to the newline, but not go past it in the same breath, I needed an unsafe function to consume the newline, and then modify the resulting string slice to be 1 byte longer, which is safe because I know the next byte was a newline (or the parser would have failed).

```rust
/// Parse until a newline is encountered, but return a string slice that includes the newline.
pub fn parse_line_newline_inclusive(input: &str) -> IResult<&str, &str> {
    let (input, line) = take_till(is_newline)(input)?;
    let (input, _) = newline(input)?;

    // since the above did not error, we know the byte after line is a newline, so we can
    // use unsafe to extend the slice to include the newline.

    let line = unsafe { extend_str_by_one_byte(line) };
    Ok((input, line))
}

unsafe fn extend_str_by_one_byte(s: &str) -> &str {
    let ptr = s.as_ptr();
    let len = s.len();

    let bytes = std::slice::from_raw_parts(ptr, len + 1);
    std::str::from_utf8(bytes).unwrap()
}
```

Now, we can go back up and see the `Cleartext::parse` function

```rust
impl CleartextSignature {
    pub fn parse(input: &str) -> anyhow::Result<CleartextSignature> {
        let (_, (hash, cleartext, ascii_armor_parts)) = parse_cleartext_signature_parts(input)
            .map_err(|_| anyhow!("failed to parse parts of cleartext signature"))?;

        let ascii_armor = AsciiArmor::from_parts(ascii_armor_parts)?;

        if !ascii_armor.verify() {
            return Err(anyhow!(
                "ascii armor failed to verify: checksum did not match"
            ));
        }

        let mut packets = ascii_armor.into_pgp_packets()?;

        if let PgpPacket::SignaturePacket(signature) = packets.pop().unwrap() {
            Ok(CleartextSignature {
                hash,
                cleartext,
                signature,
            })
        } else {
            Err(anyhow!("did not find a signature packet"))
        }
    }
}
```

This parses the parts of the cleartext signature using the function we just built, does some extra work with the ASCII armor (which we'll talk about in the next section) and then returns the Cleartext signature or an `Err`. Note that this function, even though it's named `parse` does more work than just parsing. Because of that, I chose to have it return a normal `Result` (actually an `anyhow::Result` for simplicity) rather than a nom `IResult`, because errors that can occur in this function aren't strictly parsing errors. Another error that could occur is the ASCII armor contained doesn't have a valid checksum. That's a nice segue into the next section, parsing and validating ASCII armor.

### ASCII Armor

PGP defines a number of data structures for implementations to use. ASCII armor is a method of communicating those data structures, which are expressed as bytes, between implementations. ASCII armor makes use of base64 text and special headers to communicate those raw bytes and their meaning.

Let's start by writing a nom parser for base64 text. I'll use the fact that my PGP implementation writes out base64 chunks in lines of 64 characters (I believe all implementations would do this, but I couldn't find a quick reference for it in the RFC. I don't consider it an important detail).

We start in the same way we started with parsing a chunk of dash-escaped text

```rust
/// Parse a chunk of base64 encoded text.
pub fn parse_base64(input: &str) -> IResult<&str, String> {
    let (input, mut base64) = fold_into_string(input, parse_base64_line)?;

    if input.chars().next() == Some('=') {
        return Ok((input, base64));
    }

    let (input, remaining) = take_while(is_base64_digit)(input)?;
    let (input, _) = newline(input)?;

    base64.push_str(remaining);

    Ok((input, base64))
}
```

`parse_base64` is a nom parser which returns an owned `String` if successful. It uses the same `fold_into_string` helper from the last section, and the parser passed to that function is `parse_base64_line` which takes one line of length 64 characters which is made up entirely of base64 characters. Then, `parse_base64` takes whatever remaining base64 characters that were not on a whole line. It will not take a line that begins with a `=` (I'll explain this later). Then, it returns the chunk of base64 that was parsed. `parse_base64_line` is given by

```rust
/// Parse a single line of length BASE64_LINE_LENGTH which contains only base64 characters.
/// (and does not begin with an '='.)
fn parse_base64_line(input: &str) -> IResult<&str, &str> {
    if input.chars().next() == Some('=') {
        return Err(nom::Err::Error((input, nom::error::ErrorKind::Char)));
    }

    let (input, res) =
        take_while_m_n(BASE64_LINE_LENGTH, BASE64_LINE_LENGTH, is_base64_digit)(input)?;
    let (input, _) = newline(input)?;

    Ok((input, res))
}
```

_(note: there's a bug in these two functions in that something like `a=a=a=a=` would be allowed, even though that's not valid base64. it would be caught in the next section when we turn that base64 string into bytes, but if I were to re-write this, I would make the parser aware of the fact that once it sees any `=` to stop parsing, by parsing sequences of 4 characters, either of the form `aaa=`, `aa==`, or `aaaa`. The reason that these are the only possibilities is that 4 base64 characters represent 3 bytes, with each character representing 6 bits. If we have 1 byte of data and 2 bytes of padding, the last 2 bits from our 8-bit byte leak into the second character, so the most padding we can have is two `=`.)_

With our base64 parsing functions in hand, we can look at the structure of the ASCII armor given in the [RFC](https://tools.ietf.org/html/rfc4880#section-6.2).

  * an armor header, e.g. `-----BEGIN PGP SIGNATURE-----`
  * armor headers, `Key: Value` pairs
  * a blank line
  * the ASCII-armored data, the first base64 chunk we will parse
  * an armor checksum, will go over this in detail shortly
  * the armor tail, e.g. `-----END PGP SIGNATURE-----` needs to match the header

The armor checksum is a quick checksum over the data encoded by the ASCII armor. It is produced by the CRC-24 algorithm, a C version of which is [given](https://tools.ietf.org/html/rfc4880#section-6.1) in the RFC. Here is a direct translation of that code into Rust.

```rust
/// Implementation of CRC24 directly from the RFC.
/// https://tools.ietf.org/html/rfc4880#section-6.1
fn crc24(data: &[u8]) -> u32 {
    let mut crc = CRC24_INIT;
    for curr in data.iter() {
        crc ^= (*curr as u32) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x1000000 != 0 {
                crc ^= CRC24_POLY;
            }
        }
    }

    crc & 0xFFFFFF
}
```

In order to parse ASCII armor, let's start with a struct to parse into.

```rust
#[derive(Debug)]
pub struct AsciiArmor {
    kind: AsciiArmorKind,
    data: Vec<u8>,
    checksum: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub enum AsciiArmorKind {
    Signature,
    PublicKey,
}
```

The `kind` field will store the type of header/tail we parsed, the `data` field will hold the bytes of the data contained by the ASCII armor, and the `checksum` field will hold the checksum bytes. In the last section, we decided that we should have separate `AsciiArmor::from_parts` and `AsciiArmor::verify` functions, which makes sense because an invalid checksum is not really a parsing error, so we want to return that error separately. The parsing function is given below

```rust
pub fn parse_ascii_armor_parts(input: &str) -> IResult<&str, AsciiArmorParts> {
    let parser = tuple((
        alt((
            tag("-----BEGIN PGP SIGNATURE-----\n\n"),
            tag("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n"),
        )),
        parse_base64,
        char('='),
        parse_base64,
    ));
    // needs to match the beginning tag("-----END PGP SIGNATURE-----\n"),

    let (input, (header, data, _, checksum)) = parser(input)?;

    let (kind, footer) = match header {
        "-----BEGIN PGP SIGNATURE-----\n\n" => {
            (AsciiArmorKind::Signature, "-----END PGP SIGNATURE-----\n")
        }
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n" => (
            AsciiArmorKind::PublicKey,
            "-----END PGP PUBLIC KEY BLOCK-----\n",
        ),
        _ => unreachable!(),
    };

    let (input, _) = tag(footer)(input)?;

    Ok((input, (kind, data, checksum)))
}
```

We start by recognizing the header (we'll only need signature and public key types for our purposes), then a base64 chunk, then a single `=`, then another base64 chunk. This is why we didn't allow any lines to begin with `=` in our `parse_base64_line` function, a line that begins with an equal sign marks the start of the checksum. The `parse_ascii_armor_parts` function is called from `CleartextSignature::parse`, and we pass the parts into `AsciiArmor::from_parts`. We then use `AsciiArmor::verify` to verify that the checksum is valid (see last section for the usages). Those functions are given by

```rust
impl AsciiArmor {
    pub fn from_parts(parts: AsciiArmorParts) -> anyhow::Result<AsciiArmor> {
        let (kind, data, checksum) = parts;

        let data = base64::decode(&data)?;
        let checksum = base64::decode(&checksum)?;

        Ok(AsciiArmor {
            kind,
            data,
            checksum,
        })
    }

    pub fn verify(&self) -> bool {
        let checksum_computed = crc24(self.data.as_slice());
        let checksum_stored = (self.checksum[0] as u32) << 16
            | (self.checksum[1] as u32) << 8
            | (self.checksum[2] as u32);

        checksum_computed == checksum_stored
    }
}
```

There's one more function that we specified in the last section that we would need, `AsciiArmor::into_pgp_packets`. In order to implement that function, let's discuss the data structures that are described in the RFC, PGP packets.

### PGP Packets

A PGP message consists of a sequence of data structures known as *packets*. Each packet contains one particular piece of information required for the particular PGP function. In our program, we'll only concern ourselves with signature packets and public key packets, but some other types of packets are "User ID Packet" (for communicating information about who a key belongs to) and "Compressed Data Packet" (for actual encrypted data).

All PGP packets begin with the same header, that gives information about what type of packet is contained, and how big it is. There are two types of header, new format and old format. In this post, we only implement parsing old format packets (because that's all GPG seems to produce on my system).

First, we'll make an enum for PGP packets.

```rust
#[derive(Debug)]
pub enum PgpPacket {
    SignaturePacket(SignaturePacket),
    PublicKeyPacket(PublicKeyPacket),
    // Ignored
    UserIdPacket,
    PublicSubkeyPacket,
}

```

I've made `SignaturePacket` and `PublicKeyPacket` hold their data in separate structs with the same name (I'll cover those structs in future sections). I've included variants for `UserIdPacket` and `PublicSubkeyPacket` because my GPG produces this packets, so I want to recognize them and ignore them.

Packets are formed from sequences of bytes. Because of this, our nom parsers for packets will have a different form than our parsers have thus far. Whereas we've been using parsers of the form

```rust
fn string_parser<T>(input: &str) -> IResult<&str, T>
```

our packet parsers will have the form

```rust
fn bytes_parser<T>(input: &[u8]) -> IResult<&[u8], T>
```

so that we can work with the raw bytes. The top-level function we'll need is a nom parser to turn bytes into a sequence of packets (I'll use `Vec<PgpPacket>` and copy data to avoid ownership issues).

```rust
pub fn parse_pgp_packets(input: &[u8]) -> IResult<&[u8], Vec<PgpPacket>> {
    let parser = all_consuming(many0(parse_pgp_packet));

    let (empty, packets) = parser(input)?;

    Ok((empty, packets))
}
```

This parser repeatedly calls `parse_pgp_packet` (which puts each packet parsed into a `Vec`) and ensures that no input remains. `parse_pgp_packet` is given by

```rust
pub fn parse_pgp_packet(input: &[u8]) -> IResult<&[u8], PgpPacket> {
    let (input, (packet_tag, length_type)): (&[u8], (PgpPacketTag, u8)) =
        bits::<_, _, (_, _), _, _>(|input| {
            let (input, _): (_, usize) = take_bits(2_usize)(input)?;
            let (input, packet_tag): (_, u8) = take_bits(4_usize)(input)?;
            let (input, length_type) = take_bits(2_usize)(input)?;

            Ok((input, (packet_tag.into(), length_type)))
        })(input)?;

    let length = match length_type {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => u32::MAX,
        _ => panic!("unrecognized length_type"),
    };

    let (input, mut packet_length) = take(length)(input)?;
    let packet_length = match length {
        1 => packet_length.read_u8().unwrap().into(),
        2 => packet_length.read_u16::<BigEndian>().unwrap().into(),
        4 => packet_length.read_u32::<BigEndian>().unwrap(),
        _ => unreachable!(),
    };
    let (input, data) = take(packet_length)(input)?;

    let parser = all_consuming(match packet_tag {
        PgpPacketTag::Signature => parse_signature_packet,
        PgpPacketTag::PublicKey => parse_public_key_packet,
        PgpPacketTag::UserId => parse_user_id_packet,
        PgpPacketTag::PublicSubkey => parse_public_subkey_packet,
        _ => unreachable!(),
    });

    let (_, packet): (&[u8], PgpPacket) = parser(data)?;

    Ok((input, packet))
}
```

This is a longer function, so let's take it section by section. The first section parses the packet tag (what type of packet it is) and the length type. `bits` turns a byte-oriented nom parser into a bit-oriented nom parser, which is important because multiple pieces of information are contained in one byte of the header. We also define the enum `PgpPacketTag` for simplicity

```rust
#[derive(Debug)]
pub enum PgpPacketTag {
    Signature,
    PublicKey,
    UserId,
    PublicSubkey,
    Ignored,
}

impl From<u8> for PgpPacketTag {
    fn from(val: u8) -> Self {
        match val {
            2 => PgpPacketTag::Signature,
            6 => PgpPacketTag::PublicKey,
            13 => PgpPacketTag::UserId,
            14 => PgpPacketTag::PublicSubkey,
            _ => PgpPacketTag::Ignored,
        }
    }
}
```

we also implement the `From<u8>` for the new enum, so we can easily get a packet tag from a byte. In the next section of `parse_pgp_packet`, we get the length of the packet based on the length type. The length type indicates how many bytes comprise the length, and we use the `byteorder` crate to read those bytes as a big-endian number. We then parse `length` bytes, and pass those bytes to a particular subparser based on the packet tag. `parse_user_id_packet` and `parse_public_subkey_packet` are dummy functions that will just parse all the bytes, for the purposes of explicitly ignoring those packet types. We'll implement `parse_signature_packet` and `parse_public_key_packet` in the next couple of sections.

_(note: I found [pgpdump](https://github.com/kazu-yamamoto/pgpdump) very useful while implementing this section. `pgpdump` is a tool for dumping the contents of PGP packets, like so_

```
$ pgpdump tests/01/msg.txt.asc
Old: Signature Packet(tag 2)(307 bytes)
        Ver 4 - new
        Sig type - Signature of a canonical text document(0x01).
        Pub alg - RSA Encrypt or Sign(pub 1)
        Hash alg - SHA256(hash 8)
        Hashed Sub: issuer fingerprint(sub 33)(21 bytes)
         v4 -   Fingerprint - 2e cf 30 1f e9 18 f4 73 a8 65 51 0c 84 fa 31 82 76 01 7b 00
        Hashed Sub: signature creation time(sub 2)(4 bytes)
                Time - Fri Oct  2 18:51:15 PDT 2020
        Sub: issuer key ID(sub 16)(8 bytes)
                Key ID - 0x84FA318276017B00
        Hash left 2 bytes - 22 53
        RSA m^d mod n(2045 bits) - ...
                -> PKCS-1
```

_Here we see a dumped signature packet, which is the next thing we'll parse...)_

### Signature Packets

Signature packets contain a signature over some data for some key. In our case, they contain RSA signatures, but other signatures are possible. Some key pieces of data that the signature packet might contain are

 * who generated the signature
 * when the signature was generated
 * how the signature was generated (what algorithm)

Looking at the [RFC](https://tools.ietf.org/html/rfc4880#section-5.2), we can glean the following important pieces of information that will be important for our parser

 * signature packets have tag 2
 * there are versions of signature packet, version 3 and version 4 (in this post, I only parse version 4 packets)
 * signature packets can have subpackets which hold additional information
 * the signature itself is the last piece of data in the signature packet, more or more *multiprecision integers* according to what algorithm was used to generated the signature.

A *multiprecision integer (MPI)* is a number format defined in the RFC ([3.2](https://tools.ietf.org/html/rfc4880#section-3.2)) for communicating very large numbers. A MPI is a length followed by a big-endian number. We begin by writing a parser for MPIs.

```rust
/// Parse a multi-precision integer (MPI) as defined by the RFC in
/// section 3.2.
pub fn parse_mpi(input: &[u8]) -> IResult<&[u8], BigUint> {
    let (input, mut length) = take(2_usize)(input)?;
    let bits = length.read_u16::<BigEndian>().unwrap();
    let bytes = (bits + 7) / 8;

    let (input, num) = take(bytes)(input)?;
    let num = BigUint::from_bytes_be(num);

    Ok((input, num))
}
```

`parse_mpi` is a byte-oriented parser that first takes a 2 byte length, then interprets `length` bytes as a big-endian `BigUint` (from the `num` crate).

_(note: it is not lost on me that major parts of my program are formed by the crates nom and num. perhaps I should have called my crate n.m)_

We'll use this parser in the parser for signature packets which we alluded to in the previous section, `parse_signature_packet`. First, we define the `SignaturePacket` struct

```rust
#[derive(Debug)]
pub struct SignaturePacket {
    pub version: u8,
    pub signature_type: u8,
    pub public_key_algorithm: u8,
    pub hash_algorithm: u8,
    pub hashed_subpacket_data: Vec<u8>,
    pub unhashed_subpacket_data: Vec<u8>,
    /// holds the left 16 bits of the signed hash value.
    pub signed_hash_value_head: u16,

    pub signature: Vec<BigUint>,
}
```

_(note: if I were more interested in some of the initial fields like version and signature_type, I might have made these enums like I did with packet_tag. Additionally, I would have parsed `hashed_subpacket_data` and `unhashed_subpacket_data` into subpacket structs)_

The struct has the obvious form straight from the RFC. One interesting thing to note is that signature packets have both hashed and unhashed subpackets. The hashed subpackets are included in the hashing process, and are therefore protected. The unhashed subpackets are not included, and can be modified. The signature is a `Vec<BigUint>` because the RFC specifies that there can be one or more, but for our purposes, there will only ever be one.

We can now write `parse_signature_packet`

```rust
pub fn parse_signature_packet(input: &[u8]) -> IResult<&[u8], PgpPacket> {
    let (input, version) = take_single_byte(input)?;
    let (input, signature_type) = take_single_byte(input)?;
    let (input, public_key_algorithm) = take_single_byte(input)?;
    let (input, hash_algorithm) = take_single_byte(input)?;

    let (input, hashed_subpacket_data) = parse_length_tagged_data(input)?;
    let (input, unhashed_subpacket_data) = parse_length_tagged_data(input)?;
    let (input, signed_hash_value_head) = parse_u16(input)?;

    let (input, signature) = many1(parse_mpi)(input)?;

    Ok((
        input,
        PgpPacket::SignaturePacket(SignaturePacket {
            version,
            signature_type,
            public_key_algorithm,
            hash_algorithm,
            hashed_subpacket_data: hashed_subpacket_data.to_owned(),
            unhashed_subpacket_data: unhashed_subpacket_data.to_owned(),
            signed_hash_value_head,
            signature,
        }),
    ))
}

pub fn parse_length_tagged_data(input: &[u8]) -> IResult<&[u8], &[u8]> {
    let (input, length) = parse_u16(input)?;

    take(length)(input)
}
```

This uses the helper `take_single_byte` to parse the `version`, `signature_type`, `public_key_algorithm`, and `hash_algorithm` fields. Then, we use `parse_length_tagged_data` to parse `Vec<u8>` that are preceeded by their length. Finally, we use the nom combinator `many1` (which runs its argument parser at least once until it fails, and puts the results in a `Vec`). We assemble these parts into the signature packet.

That completes the signature packet. We have almost everything we need to actually verify a signature. We now just need to parse public key packets.

### Public Key packets

### Putting it all together (`AsciiArmor::into_pgp_packets`)

## Going forward

## Conclusion
