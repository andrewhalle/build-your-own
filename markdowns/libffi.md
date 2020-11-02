# Implementing libffi

_(repo for this post can be found on [GitHub](https://github.com/andrewhalle/clone-libffi))_

How does code written in one language (say, Python) call written in a different
language (say, C). It's clear that this is necessary (e.g. for perforance concerns) but,
if you're anything like me, it seems like black magic that this should be possible. How
can this possibly work.

A _Foreign Function Interface_ is the means why which code written in one language
calls code written in another language.

[libffi](https://github.com/libffi/libffi) is a low-level library that implements
the _calling convention_ for a particular platform. In this post I'll re-implement
a subset of the functionality provided by libffi and prove that it works by replacing
the real libffi and showing that the Python interpreter still works.

## The Basics

How does a function actually get called? On x86, we have the `call` instruction,
which has the following [definition](https://www.felixcloutier.com/x86/call):

> Saves procedure linking information on the stack and branches to the called
> procedure specified using the target operand.

We can see this in action via [a simple example](https://godbolt.org/z/ESQCRy)
(Compiler Explorer is a great tool for looking at compiler output).

<table style="margin-left: auto; margin-right: auto">
<tr>
<th style="padding: 0px 15px"> C </th>
<th style="padding: 0px 15px"> Assembly </th>
</tr>
<tr valign="top">
<td style="padding: 0px 15px">

```c
int add(int x, int y) {
  return x + y;
}

int main(void) {
  int x = add(1, 2);
}
```

</td>
<td style="padding: 0px 15px">

```asm
add:
        push    rbp
        mov     rbp, rsp
        mov     DWORD PTR [rbp-4], edi
        mov     DWORD PTR [rbp-8], esi
        mov     edx, DWORD PTR [rbp-4]
        mov     eax, DWORD PTR [rbp-8]
        add     eax, edx
        pop     rbp
        ret
main:
        push    rbp
        mov     rbp, rsp
        sub     rsp, 16
        mov     esi, 2
        mov     edi, 1
        call    add
        mov     DWORD PTR [rbp-4], eax
        mov     eax, 0
        leave
        ret
```

</td>
</tr>
</table>

This simple example reveals a lot about what the compiler does for us. Let's look closer at
this snippet in particular.

```asm
mov     esi, 2
mov     edi, 1
call    add
```

Why is the compiler putting the arguments to our `add` function into registers? Why these
registers, in this order? This is because of the _calling convention_ as previously mentioned.
The calling convention is the contract between compilers that allows separate compilation to
happen. The `add` function can assume that its first argument will be in `edi` and its second
argument will be in `esi` (more on this later). Moreover, the calling convention allows the calling
code (in this case, the `main` function) allows the calling code to assume that, after a
function is called, its return value will be in `eax`.

When a dynamic language like Python needs to call into some already compiled C code, how
does it marshall arguments into the appropriate registers? This is the job of libffi, and
what we'll implement in the following sections.

## Calling Code Loaded at Runtime

In order to call native code, the Python interpreter must load in a previously compiled
shared library (a .so file on Linux). This is accomplished via the functions `dlopen` and
`dlsym`. `dlopen` loads a shared object and returns a `void*` handle to that object. The
`dlsym` function takes a handle to a shared object and a string symbol to search for in
that shared object. As an example, to call an `add` function in a shared library `libadd.so`
you can write the following C code:

```c
#include <stdio.h>
#include <dlfcn.h>

typedef int (*add_func)(int, int);

int main(void) {
  void *handle = dlopen("./libadd.so", RTLD_NOW);
  add_func add = (add_func) dlsym(handle, "add");
  printf("1 + 2 = %d\n", add(1, 2));
}
```

This code opens the shared object (loading it immediately because of the flag `RTLD_NOW`),
grabs a pointer to the `add` function, casts that `void` pointer to a pointer to a function
taking two `int`s and returning an `int` (notice the `typedef` at the top of the file).

The `typedef` at the top of the file gives the compiler the information to generate code
to call this function. Our first goal will be to call this function without the `typedef`
(so we have to write the code to call this function, the compiler can't help us).

## Calling One Function

Let's start by defining a struct to hold some information for us, namely the address of the
function to call, and the arguments we're going to pass into that function.

```c
typedef struct {
  int x;
  int y;
  void *func;
} callable;
```

If this were a real library, storing the arguments inside the `callable` would be a bad
idea, because we might want to call this function with different arguments. However, it
will suffice for now.

We'd like to be able to write code like this:

```c
int main(void) {
  void *handle = dlopen("./libadd.so", RTLD_NOW);
  void *add = dlsym(handle, "add");
  callable c = { 1, 2, add };
  int retval;
  runtime_call(&c, &x);
  printf("1 + 2 = %d\n", retval);
}
```

What about this mysterious function `runtime_call`? `runtime_call` needs to do a few things:
 
  * put the first argument in `rdi`
  * put the second argument in `rsi`
  * `call` the function pointed to by `func`
  * put the return value (currently in `eax`) into `&retval`

Since we need direct register access (and the ability to issue a raw `call`) we'll need to
write this function in assembly (I use the NASM assembler).

Compiler Explorer can do most of the work for us here. [This example](https://godbolt.org/z/yTaHL6):

<table style="margin-left: auto; margin-right: auto">
<tr>
<th style="padding: 0px 15px"> C </th>
<th style="padding: 0px 15px"> Assembly </th>
</tr>
<tr valign="top">
<td style="padding: 0px 15px">

```c
int add(int x, int y) {
    return x + y;
}

typedef int (*add_func)(int, int);

typedef struct {
    int x;
    int y;
    void *func;
} callable;

void runtime_call(void* c, void* ret) {
    callable *c1 = (callable*) c;
    int *r1 = (int*) ret;
    add_func a = (add_func) c1->func;
    *r1 = a(c1->x, c1->y);
}

int main() {
    callable c = { 1, 2, add };
    int x;
    runtime_call(&c, &x);
    printf("1 + 2 = %d\n", x);
}
```

</td>
<td style="padding: 0px 15px">

```asm
add:
        push    rbp
        mov     rbp, rsp
        mov     DWORD PTR [rbp-4], edi
        mov     DWORD PTR [rbp-8], esi
        mov     edx, DWORD PTR [rbp-4]
        mov     eax, DWORD PTR [rbp-8]
        add     eax, edx
        pop     rbp
        ret
runtime_call:
        push    rbp
        mov     rbp, rsp
        sub     rsp, 48
        mov     QWORD PTR [rbp-40], rdi
        mov     QWORD PTR [rbp-48], rsi
        mov     rax, QWORD PTR [rbp-40]
        mov     QWORD PTR [rbp-8], rax
        mov     rax, QWORD PTR [rbp-48]
        mov     QWORD PTR [rbp-16], rax
        mov     rax, QWORD PTR [rbp-8]
        mov     rax, QWORD PTR [rax+8]
        mov     QWORD PTR [rbp-24], rax
        mov     rax, QWORD PTR [rbp-8]
        mov     edx, DWORD PTR [rax+4]
        mov     rax, QWORD PTR [rbp-8]
        mov     eax, DWORD PTR [rax]
        mov     rcx, QWORD PTR [rbp-24]
        mov     esi, edx
        mov     edi, eax
        call    rcx
        mov     rdx, QWORD PTR [rbp-16]
        mov     DWORD PTR [rdx], eax
        nop
        leave
        ret
.LC0:
        .string "1 + 2 = %d\n"
main:
        push    rbp
        mov     rbp, rsp
        sub     rsp, 32
        mov     DWORD PTR [rbp-16], 1
        mov     DWORD PTR [rbp-12], 2
        mov     QWORD PTR [rbp-8], OFFSET FLAT:add
        lea     rdx, [rbp-20]
        lea     rax, [rbp-16]
        mov     rsi, rdx
        mov     rdi, rax
        call    runtime_call
        mov     eax, DWORD PTR [rbp-20]
        mov     esi, eax
        mov     edi, OFFSET FLAT:.LC0
        mov     eax, 0
        call    printf
        mov     eax, 0
        leave
        ret
```

</td>
</tr>
</table>

clearly parallels what we're trying to do. And indeed, if we copy the assembly output
into a file `runtime-call.s`, build it with `nasm -f elf64 runtime-call.s` and link the
resulting object file with our `main.c` we'll successfully call this function! (this state
of the code is given by commit [ca946232a8545bdb7389be7159abf504d3f5a168](https://github.com/andrewhalle/clone-libffi/tree/ca946232a8545bdb7389be7159abf504d3f5a168)
of the repo for this post).

## Calling Any Function

Okay, the last section was kind of cheating. We only allowed for one possible signature of
the function we might call, so we could copy the compiler output to put the arguments in
the right place. We haven't done anything yet! In this section, we'll make our `runtime_call`
function generic enough to handle functions that take any number of `int`s as arguments, and
return a single `int`.

_(the leap from here to supporting functions that take and return variables of different type is
not trivial, but I think also not very instructive. In order to actually finish this post, I
decided to stop here and restrict my libffi to only work with functions of this type. For more
information on supporting functions that take arbitrary types of arguments, see one of the links
in the Resources)_

For this section, we'll actually need to figure out what the calling convention on our platform
is (I'm using Linux, and include a `Vagrantfile` for a Linux VM in the repo). We'll be
implementing the calling convention for 64bit linux, which is known officially as 
"System V AMD64 ABI" (see [this link](https://cs61.seas.harvard.edu/site/2018/Asm2/) for
more information).

We're interested in the following aspects of this ABI (the following points are quotes from
the above link)

> On x86-64 Linux, the first six function arguments are passed in registers
> %rdi, %rsi, %rdx, %rcx, %r8, and %r9, respectively. The seventh and subsequent
> arguments are passed on the stack, about which more below. The return value is
> passed in register %rax.

That link uses AT&T syntax for registers, while Compiler Explorer and NASM default to
using Intel syntax.

If we imagine we have the following high-level functions (Python syntax for clarity):

  * `push_stack(value)`: pushes `value` onto the hardware stack, equivalent to the `push`
    instruction
  * `overwrite_register(register, value)`: puts `value` into `register` (where `register`
    is the string name of the register), equivalent to the instruction `mov  reg, value`
  * `call(func)`: jump to the function at address `func`, equivalent to the instruction
    `call`
  * `register_value(register)`: returns the value of `register` (where `register` is the
    string name of the register)

then we could implement this ABI in the following way

```python
def runtime_call(func, args):
    argument_registers = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
    
    # push additional arguments onto the stack in reverse order
    while len(args) > 6:
        push_stack(args.pop())

    # put first six arguments in the correct registers
    for i in range(len(args)):
        overwrite_register(argument_registers[i], args[i])

    call(func)

    return register_value('rax')
```

There's one complication to writing this function in assembly. The `overwrite_register`
function takes a string description of the register and loads a value into it. We don't
want to actually resort to string comparisons to determine the register we're loading into.
We'll instead include the instructions for loading all 6 arguments into registers in the
`runtime_call` function, and then jump over the ones we don't want to execute. Since assembly
executes instructions sequentially, this means we have to list out these instructions in reverse
order (since if we have less than 6 arguments, we'll have to jump over the instructions which
load the later arguments that we don't actually have).

The interesting part of the assembly is listed below (look in the repo for the full function):

```asm
.loop_start:   cmp     eax, 6      ; we want to do this for as long as the number of arguments
               jle     .loop_done  ; (currently in eax) is greater than 6
               mov     r10d, DWORD [rbx + 4 * (rax - 1)] ; rbx stores the pointer to the arguments
               push    r10
               dec     eax
               jmp     .loop_start

.loop_done:    cmp     eax, 6      ; since 64bit NASM doesn't allow relative jumps (as
               je      .six_args   ; far as I could tell) we need to explicitly label
               cmp     eax, 5      ; the lines to jump to, and figure out which one
               je      .five_args  ; we're jumping to with comparisons on n_args
               cmp     eax, 4
               je      .four_args
               cmp     eax, 3
               je      .three_args
               cmp     eax, 2
               je      .two_args
               cmp     eax, 1
               je      .one_arg
               cmp     eax, 0
               je      .zero_args

.six_args:     mov     r9d, DWORD [rbx + 4 * 5] ; order of registers is the calling convention
.five_args:    mov     r8d, DWORD [rbx + 4 * 4]
.four_args:    mov     ecx, DWORD [rbx + 4 * 3]
.three_args:   mov     edx, DWORD [rbx + 4 * 2]
.two_args:     mov     esi, DWORD [rbx + 4 * 1]
.one_arg:      mov     edi, DWORD [rbx + 4 * 0]

.zero_args:    mov     rbx, QWORD [rbp-40]  ; move addr of function into rbx
               mov     rbx, QWORD [rbx]
               call    rbx

               mov     rbx, QWORD [rbp-48]  ; move addr of retval into rbx
               mov     DWORD [rbx], eax     ; move retval (currently in eax) into retval

```

Some notes about this assembly:

  * we can reference registers by different names depending on whether we want to treat them
    as 64bit registers or 32 bit registers. In this example, `eax` refers to the 32bit version
    of `rax` (the upper 32 bits will be zeroed) and `r8d` refers to the 32bit version of `r8`
    (the `d` for "double word" indicates this is 4 bytes, as the x86 word size is 16 bits)
  * we assume values are `DWORD` because we've previously stated we only want to work with `int`s
    which on my platform (not all platforms!) is 4 bytes.
  * there's a prelude to this assembly that puts things like the function address and the retval
    address in the correct place, I don't think it's important enough to include here, find the
    full function in the repo.

Our C code will also have to change to support an arbitrary number of arguments. We'll implement
this by changing the structure to include a pointer to the args, and a couple of functions to
initialize this structure with a `malloc`'d array and add args to it.

```c
typedef struct {
  void *func;
  int *args;
  int n_args;
} callable;

void init_callable(callable *c) {
  c->args = (int*) malloc(16 * sizeof(int));
  c->n_args = 0;
}

void add_arg_callable(callable *c, int arg) {
  c->args[c->n_args] = arg;
  c->n_args++;
}
```

We can now write C code like the following:

```c
int main(void) {
  void *handle = dlopen("./libadd.so", RTLD_NOW);
  void *add = dlsym(handle, "add");

  callable c = { add };
  init_callable(&c);
  add_arg_callable(&c, 1);
  add_arg_callable(&c, 2);
  add_arg_callable(&c, 3);
  add_arg_callable(&c, 4);
  add_arg_callable(&c, 5);
  add_arg_callable(&c, 6);
  add_arg_callable(&c, 7);
  add_arg_callable(&c, 8);
  add_arg_callable(&c, 9);
  add_arg_callable(&c, 10);

  int x;
  runtime_call(&c, &x);
  printf("Result: %d\n", x);
}
```

where the `add` function has been separately compiled to have the appropriate number of
arguments.

And that's it! We can now call dynamically loaded functions at runtime, without specifying
their signatures at compile time. All that's left to do is make this compatible with the real
libffi, and we should be able to use our library with Python.

## Writing a Compatibility Layer

First, let me prove that the Python interpreter does in fact use libffi to accomplish this
task. Let us consider the test program

```python
from ctypes import cdll

libadd = cdll.LoadLibrary('./libadd.so')
result = libadd.add(1,2,3,4,5,6,7,8,9,10)
print(result)
```

where `libadd.so` is our previously compiled `add` function, in this case, with 10 arguments.

Running this in our VM (`vagrant up; vagrant ssh; python test.py`) produces the correct answer
of 55.

Now, let's look for `libffi.so` (we know from the libffi docs that we link with libffi using
`-lffi` so the file is probably called `libffi.so` per convention). If we run

```bash
ldconfig -p | grep ffi
```

we'll see the output

```
libffi.so.7 (libc6,x86-64) => /usr/lib/libffi.so.7
libffi.so (libc6,x86-64) => /usr/lib/libffi.so
```

So if we compile our `libffi.so` and replace these files, we can inject our version of
libffi into the system.

_**NOTE: don't actually do this on your system. libffi is incredibily important for a lot
of things (even LLVM links with libffi) so if you remove it on your actual computer, you
won't be able to do a lot of important things. I've included a Vagrantfile for testing,
you can do this on any virtual machine**_

I've restructured our implementation of libffi into `ffi.h` and `ffi.c`, which we can now
compile into `libffi.so` with

```bash
nasm -f elf64 runtime-call.s
clang -shared -fPIC -o libffi.so ffi.c runtime-call.o
```

If we replace the system libffi (again, not on your actual system) with our compiled artifact,
and try to run the test python program, we'll get the following error

```
$ python test.py
Traceback (most recent call last):
  File "test.py", line 1, in <module>
    from ctypes import cdll
  File "/usr/lib/python3.8/ctypes/__init__.py", line 7, in <module>
    from _ctypes import Union, Structure, Array
ImportError: /usr/lib/python3.8/lib-dynload/_ctypes.cpython-38-x86_64-linux-gnu.so: undefined symbol: ffi_closure_alloc, version LIBFFI_CLOSURE_7.0
```

Okay, now we're getting somewhere. This error is happening because Python is loading in our
`libffi.so` and looking for symbols that don't currently exist, but should exist according
to the API offered by libffi. Let's look at the man pages for libffi

```
$ man ffi
FFI(3)                                BSD Library Functions Manual                               FFI(3)

NAME
     FFI — Foreign Function Interface

LIBRARY
     libffi, -lffi

SYNOPSIS
     #include <ffi.h>

     ffi_status
     ffi_prep_cif(ffi_cif *cif, ffi_abi abi, unsigned int nargs, ffi_type *rtype, ffi_type **atypes);

     void
     ffi_prep_cif_var(ffi_cif *cif, ffi_abi abi, unsigned int nfixedargs, unsigned int ntotalargs,
         ffi_type *rtype, ffi_type **atypes);

     void
     ffi_call(ffi_cif *cif, void (*fn)(void), void *rvalue, void **avalue);

DESCRIPTION
     The foreign function interface provides a mechanism by which a function can generate a call to an‐
     other function at runtime without requiring knowledge of the called function's interface at com‐
     pile time.

SEE ALSO
     ffi_prep_cif(3), ffi_prep_cif_var(3), ffi_call(3)

                                           February 15, 2008
```

Clearly we'll need a struct `ffi_cif` (which is the equivalent of our `callable`) and functions
`ffi_prep_cif` (the equivalent of our `init` function) and `ffi_call` (the equivalent of our
`runtime_call`). Note, I didn't learn all this just from the output above, I had to read the other
man pages for libffi (listed in the `SEE ALSO`).

One interesting thing to note, I don't see `ffi_closure_alloc` anywhere in this API. As far as I
can tell, these are optional symbols included by libffi for offering closure type functionality.
I think I got incredibly lucky in that they don't actually have to do anything for the simple case
we've already implemented, they just have to exist. So, we can define empty functions with these
names (going back and forth with python to see what it complains about missing) to move forward.

The resulting code is:

```c
void ffi_closure_alloc(void) {}
void ffi_closure_free(void) {}
void ffi_prep_cif(void) {}
void ffi_call(void) {}
void ffi_prep_closure_loc(void) {}
```

When we now run our test script, we get

```
$ python test.py
$ python test.py
Traceback (most recent call last):
  File "test.py", line 4, in <module>
      result = libadd.add(1,2,3)
      RuntimeError: ffi_prep_cif failed

```

Okay, at this point, we have to actually look at the header file `ffi.h` provided by libffi
to figure out what value we're supposed to return from `ffi_prep_cif` to indicate success,
and what `ffi_prep_cif` and `ffi_call` are supposed to do.

`ffi_prep_cif` is supposed to set up the `ffi_cif` object with the types the function is
supposed to take. Since we've restricted ourselves to functions that only take integers and
return an integer, we're only interested in `n_args`.

`ffi_call` passes a pointer to an array of `void*` which are the arguments we're passing to
the function, and a `void*` indicating where to put the reuslt. At this point, you may notice
our `callable` struct is not exactly mappable to `ffi_cif` because the `callable` struct stores
its arguments, whereas `ffi_cif` does not. We can get around this in a hacky way (if we were
writing an actual library, I would actually fix this). We'll do the following: when `ffi_prep_cif`
is called, store the number of arguments we're expecting. When `ffi_call` is called, grab `n_args`
from the `callable`, then re-init it, and add the arguments using our previously defined function.
Then, call `runtime_call` to actually invoke the function.

The final code is below:

```c
// ffi.h
#ifndef _LIBFFI_CLONE_H
#define _LIBFFI_CLONE_H

typedef enum {
  FFI_OK = 0,
} ffi_status;

// only one supported
typedef enum {
  SYSVAMD64 = 0,
} ffi_abi;

typedef struct {
  void *func;
  int *args;
  int n_args;
} callable;

typedef callable ffi_cif;

void init_callable(callable *c);
void add_arg_callable(callable *c, int arg);
void runtime_call(void *c, void *ret);

#endif

// ffi.c

#include <stdlib.h>
#include <stdio.h>
#include "./ffi.h"

void init_callable(callable *c) {
  c->args = (int*) malloc(16 * sizeof(int));
  c->n_args = 0;
}

void add_arg_callable(callable *c, int arg) {
  c->args[c->n_args] = arg;
  c->n_args++;
}

void ffi_closure_alloc(void) {}
void ffi_closure_free(void) {}

ffi_status ffi_prep_cif(
  ffi_cif *cif,
  ffi_abi abi,
  unsigned int nargs,
  void *ignored1,
  void *ignored2
) {
  cif->n_args = nargs;
  return FFI_OK;
}

void ffi_call(ffi_cif *cif, void *fn, void *retval, void **args) {
  unsigned int n_args = cif->n_args;
  cif->func = fn;
  init_callable(cif);

  // actually add the arguments to the callable
  for (int i = 0; i < n_args; i++) {
    add_arg_callable(cif, *((int*) args[i]));
  }

  runtime_call((void*) cif, retval);
}

void ffi_prep_closure_loc(void) {}
}
```

When we compile this, move it to the path normally occupied by libffi, and run our
test script, it works! We've successfully written an implementation of libffi that's
API-compatibile with the real libffi and supports a subset of it's functionality.

## Wrapping Up

At this point, we're done. We've accomplished our goal of calling functions at runtime
without specifying their type signatures at compile-time, we've made our clone API-compatible
with the real libffi (through a pattern I quite like, we defined our own API that makes sense
to us, then written a compatibility layer for backward compatibility), and we've (if you're
at all like me) become extremely grateful that high quality implementations of this functionality
already exist. Every new language that wants to offer a foreign function interface doesn't have
to write their own implementation of this, and libffi is written with more platforms in mind than
just x86, so this will work across many platforms.

## Resources / Bibliography

I made use of the following links/resources while writing this post:

  * [Compiler Explorer](https://godbolt.org/)
  * one of Matt's many amazing talks [on YouTube](https://www.youtube.com/watch?v=w0sz5WbS5AM)
  * [https://www.cs.virginia.edu/~evans/cs216/guides/x86.html](https://www.cs.virginia.edu/~evans/cs216/guides/x86.html)
  * [https://courses.cs.washington.edu/courses/cse378/10au/sections/Section1_recap.pdf](https://courses.cs.washington.edu/courses/cse378/10au/sections/Section1_recap.pdf)
  * [https://linux.die.net/man/3/dlopen](https://linux.die.net/man/3/dlopen)
  * [https://cs61.seas.harvard.edu/site/2018/Asm2/](https://cs61.seas.harvard.edu/site/2018/Asm2/)
