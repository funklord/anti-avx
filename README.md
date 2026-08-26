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
measured instruction mix says a translated binary should cost about **+1.34%
in instruction count** and run within a few percent of native -- the
performance argument against this approach does not hold.

**Status: it rewrites. 98.8% of 805,131 VEX sites, and that is not enough.**

A translated binary that is 99.99% correct is worthless: the remaining 0.01%
is a crash at an unpredictable moment. So the number to watch is not how much
is translated but how much is left, and 9,616 sites are left.

**Starfield has now been run, under Proton, and it gets 866 bytes further.**
The original dies on the first AVX instruction it executes; the rewritten one
executes that instruction and three more, through two stubs, and dies on the
next site the rewriter refused. Wine's unwinder walked the rebuilt 431,937-entry
function table and produced a call stack identical to the original's for all
eleven frames. See `project.md`, Finding 74 -- that is a frontier moving, not a
game starting.

Nothing here is Starfield-specific except a Makefile default. The tools take
the binary as an argument, read its PE headers, `.pdata` and relocations, and
have been exercised end to end on twenty-four small PEs this project builds
itself. Starfield is the corpus, not the target.

Read [`project.md`](project.md). It is the authoritative record of intent and
wins over the code, and its "Picking this up again" section is written for
someone starting cold.

## What exists

```
project.md              the design, the measurements, and every open question
code-style.md           style rules, copied from the global source

tool/vex_scan.py       the inventory: every VEX site by mnemonic
tool/lower.py          the lowering RULES; `verify` proves they assemble
tool/patch.py          in-place patching, and the encoding primitives
                        everything else uses
tool/detour.py         the rewriter: collect, place_stubs, build_stub,
                        lower_vex, apply, verify, census, selftest
tool/targets.py        branch targets from .reloc, .pdata, .xdata, switch
                        tables and SEH scope tables
tool/outside.py        the code .pdata does not describe
tool/scratch.py        liveness: find_scratch, and `check` proves its claims
tool/lowering_cases.py generates the executable cases from the real rules
tool/pe_build.py       builds AVX PEs so the rewriter has a target it owns
tool/placement.py      where detours land; icache_bench.c what they cost

src/f16c.c              software half-precision conversion, since Westmere
                        has no F16C
src/fmaddsub.c          alternating-lane FMA, src/permil.c, src/permd.c
test/                  the C tests for those, and lowering_test.c, which
                        executes the rewriter's own lowerings
```

## Rewriting a binary

```sh
make detour          # rewrite $(TARGET) into $(BUILD_DIR)
make detour-verify   # the structural invariants, on the result
make census          # reconcile every surviving VEX site to a named cause
make detour-plan     # what would be rewritten, and what is refused, and why
```

`make scan` and everything above need the Steamless-unpacked game binary,
which is **not** in this repository -- it is a copyrighted 102 MB artifact
obtained through Steam, and an input to the project rather than a part of it.
See `project.md`, "The hard parts", for how the unpack is reproduced on Linux.

```sh
make scan                      # objdump + vex_scan into $(BUILD_DIR)
make scan TARGET=other.exe     # any /arch:AVX2 PE, not just the driving case
```

The listing is about 0.9 GB and `apply` takes roughly ten minutes on the real
binary. `make clean` removes what it wrote, by name.

## Development

```sh
make check        the gate: style, the lowering proof, and the C tests
make check-pe     twenty-four PEs built here, rewritten, under wine
make check-spill  the three ways a stub can get a scratch register
make check-unwind whether an exception can be dispatched from inside a stub
make hooks        install the commit-msg hook into .git/hooks
make help         every target
```

`make check` needs no game binary; the others under `check-` need only `wine`.
`make coverage`, `make scratch-check` and the `detour` targets need the binary.
`make coverage` exits non-zero while any VEX site lacks a lowering rule -- it
is a gate rather than a report.

**The machine is part of the method.** This is a Westmere: it cannot execute
the input and can execute the output, so "the original must crash and the
rewritten one must work" is a real experiment rather than a wish. Every
`check-pe` program asserts both halves.

## Licence

**None chosen.** All rights reserved by the copyright holder.

That is deliberate rather than an oversight, and it is the state to leave it
in until the copyright holder decides. A licence is a grant of rights to other
people; an absent one leaves every option open, while a published grant cannot
be taken back from anyone who has already relied on it. It is not to be copied
from another project or inferred from a template.
