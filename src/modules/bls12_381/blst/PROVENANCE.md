# Vendored blst

This directory contains a **verbatim** copy of the [supranational/blst](https://github.com/supranational/blst)
BLS12-381 library. Do not edit these files. To update, re-copy from a new
upstream release (see "Re-syncing" below).

## Version

- Upstream: https://github.com/supranational/blst
- Release tag: `v0.3.17`
- Commit: `54e6e55674722fc2797ebb4bbb71b26d881eb4b8`
- License: Apache-2.0 (see `LICENSE`)

## What was copied

- `bindings/blst.h`, `bindings/blst_aux.h` — public C API
- `src/*.c`, `src/*.h` — all curve/field/map/pairing sources (`server.c` `#include`s the rest)
- `build/assembly.S` + `build/{elf,mach-o,coff,win64,cheri}/*.s` — prebuilt assembly

## What was intentionally omitted

- `src/asm/*.pl` — perlasm generators. Not needed: `build/*.s` are already generated.
- `src/blst_t.hpp` — C++ binding header. This module is C-only.
- `build/{refresh.sh,srcroot.go,bindings_trim.pl}` — upstream tooling.

## How it is built

Two translation units are compiled and linked (see `../Makefile.am.include`):

- `src/server.c` — the entire library (it `#include`s every other `src/*.c`)
- `build/assembly.S` — arch-selected prebuilt assembly

`assembly.S` dispatches by platform macros: x86_64 and aarch64 on ELF / Win64 /
Mach-O use hand assembly; any other architecture falls back to the portable C
path (`src/no_asm.h`, 32-bit limbs) automatically; a genuinely unknown platform
triggers `#error "unsupported platform"`.

No perl or build-time code generation is required.

## Only pairing-free G1 is used

The DLEAG proof needs only G1 scalar/point arithmetic, `blst_hash_to_g1`, and
subgroup checks. The G2/Fp12/pairing code is compiled (server.c is monolithic)
but never called; the linker may garbage-collect it with
`-ffunction-sections -Wl,--gc-sections`.

## Re-syncing

    git clone https://github.com/supranational/blst
    cd blst && git checkout <new-tag>
    # copy the files listed under "What was copied" over this directory
    # then update the Version block above
