# anti-avx

Ahead-of-time AVX to SSE binary translation for x86-64 PE executables.

## "It's not gonna happen"

When this project started, posters in the Starfield thread on Steam about
the startup crash on CPUs without AVX said it could not be done:

> static binary translation of AVX to SSE without engine source code isn't
> viable; replacing YMM registers with XMM instructions changes code size
> and destroys memory jump offsets, which means the program crashes sooner
> or later anyway. The engine was compiled with AVX; no converter is going
> to fix that. [...] It's not gonna happen.
> ([8 August 2026](https://steamcommunity.com/app/1716740/discussions/0/585056462065333351/?ctp=2#c585056732983623069))

> without source code or PDBs, you have zero clue where compiler-generated
> jump tables, relative offsets, and internal memory validations are hiding.
> You're flying completely blind, and the binary will crash on launch.
> ([8 August 2026](https://steamcommunity.com/app/1716740/discussions/0/585056462065333351/?ctp=2#c585056732983640990))

> circumventing avx2 by other means is no option for starfield.
> ([5 November 2026](https://steamcommunity.com/app/1716740/discussions/0/585056462065333351/?ctp=3#c564798618066777636))

Each objection is specific, and each has an answer in this tree:

- **Code size.** 70.5% of the VEX instructions have an SSE form of the
  same length and are rewritten in place. The rest move to stubs, and
  only the stub's entry is patched into the original code.
- **Jump offsets and jump tables.** Every branch target is recovered from
  the image itself -- relocations, `.pdata`, unwind data, SEH scope tables
  and 1,795 switch tables -- and nothing a branch can land on is
  overwritten.
- **"Crashes on launch."** The rewritten game is played through Steam
  under Proton on a Xeon X5675, where the unmodified one dies in four
  seconds.
- **"A 1 FPS slideshow."** Profiles of play put the rewritten code at 4
  to 6 per cent of the game's CPU samples.

A program compiled with a whole-program `/arch:AVX2` baseline will not start
on a processor without AVX. The compiler is told it may assume the newer
instructions everywhere. So it uses their encoding (VEX) for nearly every
floating-point operation, scalar maths included, and not only in the
code that benefits from wide vectors. There is no second copy of that
code for older processors to fall back on. The first instruction an older
CPU cannot decode raises an illegal-instruction fault, and the process dies
in the first seconds of loading. Such processors, Westmere and earlier, are
still fast enough to run much of that software.

`anti-avx` rewrites the executable once, offline, so that it runs on such a
machine natively. It disassembles the whole image and finds every VEX
instruction. It replaces each with an equivalent sequence of the SSE
instructions the older CPU does have, and writes a new executable that
runs at full speed with no emulator underneath it. Most instructions have a
direct older form. The rest need real work: the 256-bit registers have no
older equivalent, so their upper halves are kept in per-thread memory.
Instructions that grow too long to fit in place are moved out to stubs
that jump back afterwards. The function tables Windows uses to unwind the
stack and dispatch exceptions are extended, so that a fault or a C++ throw
inside a moved instruction is handled exactly as it would have been in place.

The driving case is Starfield on a Xeon X5675 (Westmere, SSE4.2, no AVX).
The unmodified game dies four seconds in, and the rewritten one is played
through Steam under Proton. Nothing in the tool is specific to it, though:
the aim is any `/arch:AVX` or `/arch:AVX2` PE, with every VEX instruction
the older CPU can reach rewritten.

## What it does that the alternatives do not

What people do today without it is emulate, or give up.

- **Intel SDE** runs an unmodified AVX program on any x86 CPU by
  instrumenting it as it runs. It is the usual answer, and for games it has
  been reported at around a frame a minute. anti-avx pays the cost of the
  translation once, offline. Profiles of play put the time spent in the
  rewritten code at a few per cent.
- **Trap-and-emulate shims** catch each illegal-instruction fault and
  interpret the one instruction. That costs a kernel round trip per
  instruction executed, and Starfield has about 805,000 VEX sites.
  anti-avx leaves no faults to catch. The only VEX code it leaves in place
  sits behind the program's own CPU checks, which take that path only on a
  processor that can run it.
- **QEMU, FEX-Emu and Box64** translate dynamically, and FEX and Box64 solve
  the same 256-to-2x128 problem for ARM hosts. None targets the x86-to-x86
  case. All of them translate again on every run, and none produces an
  executable that runs without them.
- **Static rewriters such as Egalito, Multiverse and RetroWrite** work on
  ELF and do not lower instruction sets. anti-avx works on Windows PE. It
  rebuilds `.pdata` and the unwind information as it moves code, which is
  what lets Wine's unwinder produce the same eleven-frame call stack
  through a rewritten image as through the original.
- **Recompiling** needs the source, and a game ships without it.

**What it proves rather than assumes.** Each lowering is checked
bit-for-bit, all sixteen registers, against the original instruction
executed under qemu, since this machine cannot run the original itself.
Small PEs built by the project itself, one per hazard found, must crash
unmodified and run correctly once rewritten. A structural verifier
re-derives every detour from the finished image.

**What it does not do.** FMA becomes a multiply and an add, which rounds
twice where the hardware rounds once (421 sites in Starfield). Bundled DLLs
are not rewritten. A Steam executable has to be unpacked with Steamless
first, because its DRM section disassembles as code that is not there.
The tool takes the binary as an argument and reads the PE headers,
`.pdata` and relocations, so a game update means a fresh unpack and a
rebuild. A new build can contain shapes of code no earlier one had, and
each of those is new work for the rewriter. And a stub that needs a
scratch register can borrow sixteen bytes of stack for a few
instructions: a memory fault inside that span reaches its handler with
the frame sixteen bytes off. No call runs there, so a C++ throw is not
affected.

Read [`project.md`](project.md). It is the authoritative record of intent
and wins over the code, and its "Picking this up again" section is written
for someone starting cold.

## What exists

```
project.md             the design, the measurements, and every open question
code-style.md          the style rules

tool/vex_scan.py       the inventory: every VEX site by mnemonic
tool/lower.py          the lowering RULES; `verify` proves they assemble
tool/patch.py          in-place patching, and the encoding primitives
                       everything else uses
tool/detour.py         the rewriter: plan, apply, verify, census, frontier,
                       selftest
tool/targets.py        branch targets from .reloc, .pdata, .xdata, switch
                       tables and SEH scope tables
tool/outside.py        the code .pdata does not describe
tool/scratch.py        liveness: find_scratch, and `check` proves its claims
tool/lowering_cases.py generates the executable cases from the real rules
tool/pe_build.py       builds AVX PEs so the rewriter has a target it owns
tool/placement.py      where detours land; icache_bench.c what they cost

src/f16c.c             software half-precision conversion, since Westmere
                       has no F16C
src/fmaddsub.c         alternating-lane FMA, src/permil.c, src/permd.c
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
make check-pe     the PEs built here, rewritten, under wine
make check-spill  the four ways a stub can get a scratch register
make check-tls    whether the loader gives us per-thread bytes if asked
make check-unwind whether an exception can be dispatched from inside a stub
make hooks        install the commit-msg hook into .git/hooks
make help         every target
```

The C tests also build and run with
[fmake](https://github.com/funklord/fmake), which needs no build file:

```sh
fmake test        the five C tests
```

The rewriter itself is Python, so that is all fmake has to build here.

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

Covers this rewriter and its tooling, not the binary it rewrites.
`python3 tool/detour.py --version` prints the same line.
