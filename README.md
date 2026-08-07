# anti-avx

Ahead-of-time AVX to SSE binary translation for x86-64 PE executables.

Modern MSVC builds routinely set a whole-program `/arch:AVX2` baseline. The
compiler then emits VEX-encoded instructions everywhere -- including for
ordinary scalar float maths that has nothing to do with vectorisation -- so
the binary will not start on a pre-2011 CPU, and there is no fallback path for
runtime CPU detection to select. `anti-avx` rewrites those instructions
statically, once, offline, so the result runs natively rather than under
emulation.

The driving case is Starfield on a Xeon X5675 (Westmere, SSE4.2, no AVX). The
measured instruction mix says a translated binary should cost about **+1.3%
in instruction count** and run within a few percent of native -- the
performance argument against this approach does not hold.

**Status: design and measurement. Nothing is translated yet.**

Read [`project.md`](project.md). It is the authoritative record of intent and
wins over the code.

## What exists

```
project.md            the design, the measurements, and every open question
code-style.md         style rules, copied from the global source
tools/vex_scan.py     the operand-level scanner behind the figures in project.md
tools/lower.py        the VEX to SSE lowering rules; 100% of sites covered
tools/f16c_oracle.py  the reference checked against CPython's binary16
src/f16c.c            software half-precision conversion, since Westmere has
                      no F16C -- the only compiled code in the tree
tests/f16c_test.c     exhaustive in both directions
```

## Reproducing the measurements

`make scan` needs the Steamless-unpacked game binary, which is **not** in this
repository -- it is a copyrighted 102 MB artifact obtained through Steam, and
an input to the project rather than a part of it. See `project.md`, "The hard
parts", for how the unpack is reproduced on Linux.

```sh
make scan                      # objdump + vex_scan into $(BUILD_DIR)
make scan TARGET=other.exe     # any /arch:AVX2 PE, not just the driving case
```

It writes about 0.9 GB and takes a little under two minutes. `make clean`
removes both files by name.

## Development

```sh
make check      style gate, lowering proof, and the F16C tests
make hooks      install the commit-msg hook into .git/hooks
make help       every target
```

`make check` needs no game binary. `make coverage` does, and exits non-zero while
any VEX site lacks a lowering rule -- it is a gate rather than a report.

## Licence

**None chosen.** All rights reserved by the copyright holder.

That is deliberate rather than an oversight, and it is the state to leave it
in until the copyright holder decides. A licence is a grant of rights to other
people; an absent one leaves every option open, while a published grant cannot
be taken back from anyone who has already relied on it. It is not to be copied
from another project or inferred from a template.
