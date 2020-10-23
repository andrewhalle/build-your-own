# Build your own: GPG

By: [Andrew Halle](https://github.com/andrewhalle)
Repo: [byo-gpg](https://github.com/andrewhalle/byo-gpg)

Part of [build-your-own](https://github.com/andrewhalle/build-your-own)

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

## PGP implementation

### PGP Packets

### ASCII Armor

## Signature Packets

## Key packets

## Putting it all together

## Going forward


## Conclusion
