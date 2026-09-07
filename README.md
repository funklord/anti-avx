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

**Status: it rewrites. 99.3% of 805,131 VEX sites, and that is not enough.**

A translated binary that is 99.99% correct is worthless: the remaining 0.01%
is a crash at an unpredictable moment. So the number to watch is not how much
is translated but how much is left, and 5,673 sites are left.

**Starfield has now been run, under Proton, and each run names the next site
to work on.** The original dies on the first AVX instruction it executes.
Wine's unwinder walked the rebuilt function table and produced a call stack
identical to the original's for all eleven frames -- see `project.md`,
Finding 74. The rewritten binary now loads 305 modules before it stops, and
each run has named the next piece of work -- five in a row. That is a
frontier moving, not a game starting.

Nothing here is Starfield-specific except a Makefile default. The tools take
the binary as an argument, read its PE headers, `.pdata` and relocations, and
have been exercised end to end on thirty-three small PEs this project builds
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
make check-pe     thirty-three PEs built here, rewritten, under wine
make check-spill  the four ways a stub can get a scratch register
make check-tls    whether the loader gives us per-thread bytes if asked
make check-unwind whether an exception can be dispatched from inside a stub
make hooks        install the commit-msg hook into .git/hooks
make help         every target
```

The C half of `make check` also builds with [fmake](../fmake), which needs
no build file and nothing beyond the Python standard library:

    python3 ~/src/fmake/fmake test    # the five C tests, and they pass

**Not `/usr/bin/fmake`**, which is older than the assembly support this
needs. `fmake.toml` carries the ISA flags, because here they are semantics
rather than preference -- `-msse4.1` is the baseline these helpers are
written against and `-mno-avx -mno-f16c` keep it there -- and one
`[generate]` stanza for the case table, whose two halves come out of one
run of `tool/lowering_cases.py`.

**It is the C tests and `tool/icache_bench`, and nothing else.** The
rewriter is Python: `make detour`, `make scan`, `make census` and the
`check-pe`, `check-spill`, `check-tls` and `check-unwind` gates run tools
and wine rather than compiling anything, and `make check` also runs the
style gate and the lowering proof. `make` remains the interface; fmake is
the way to build and run the C tests on a machine that has not got this
project's toolchain set up.

`make check` needs no game binary; the others under `check-` need only `wine`.
`make coverage`, `make scratch-check` and the `detour` targets need the binary.
`make coverage` exits non-zero while any VEX site lacks a lowering rule -- it
is a gate rather than a report.

**The machine is part of the method.** This is a Westmere: it cannot execute
the input and can execute the output, so "the original must crash and the
rewritten one must work" is a real experiment rather than a wish. Every
`check-pe` program asserts both halves.

## Copyright

    Copyright (C) 2026 Nabeel Sowan <nabeel@vibes.se>

`python3 tool/detour.py --version` prints the same line.

**It covers this rewriter and its tooling, and nothing else.** anti-avx exists
to modify somebody else's binary; naming the holder here says who wrote the
tool, and says nothing about the artifact the tool emits, in which this project
holds no copyright and claims none.

## Licence

**None chosen.** All rights reserved by the copyright holder.

That is deliberate rather than an oversight, and it is the state to leave it
in until the copyright holder decides. A licence is a grant of rights to other
people; an absent one leaves every option open, while a published grant cannot
be taken back from anyone who has already relied on it. It is not to be copied
from another project or inferred from a template.
