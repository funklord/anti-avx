# anti-avx — ahead-of-time AVX→SSE binary translation

First read ~/.claude/CLAUDE.md for core directives

Static rewriting of x86-64 PE binaries built with a whole-program `/arch:AVX` or
`/arch:AVX2` baseline, so they run on CPUs without AVX.

**Status:** the rewriter works. `tool/detour.py` rewrites **797,907 of 805,131 VEX
sites -- 99.1%** -- through 202,115 detours, and every `make detour-verify` invariant
holds on the result. 7,224 sites are left, and the rewritten binary loads 305 modules
under Proton before the frontier at `0x1428D1492` stops it.

    Copyright (C) 2026 Nabeel Sowan <nabeel@vibes.se>

Attribution for the rewriter and its tooling, and for nothing it emits: this
project modifies somebody else's binary and holds no copyright in the result.
`python3 tool/detour.py --version` prints the same line, and `README.md` carries
it too. Licensing is a separate question and is deliberately not settled -- see
the README.

---

## Motivation

Modern MSVC builds routinely set a global `/arch:AVX2` baseline. The compiler then
emits VEX-encoded instructions *everywhere*, including for ordinary scalar float math
that has nothing to do with vectorisation. The result:

- The binary will not start on any pre-2011 CPU — `#UD` → `EXCEPTION_ILLEGAL_INSTRUCTION`
  (`0xc000001d`).
- There is **no fallback path to select**, so runtime CPU detection cannot help. A
  CPUID check can only report the failure sooner.
- Vendors frequently don't document the requirement, because the CPUs in their
  published minimum spec happen to have AVX.

Runtime emulation (Intel SDE, QEMU-TCG, SIGILL trap-and-emulate) is not a viable
answer — reported at ~1 frame/minute for games. **Ahead-of-time translation is
different**: pay the conversion once, offline, then run natively.

### Driving case

Starfield (Steam appid 1716740) on a Xeon X5675 (Westmere, SSE4.2, no AVX) with an
RTX 3060. The GPU is ~8× a Steam Deck's and the CPU broadly comparable, so the
hardware is well over the bar — the ISA is the only blocker.

---

## Measurements

**Milestone 0 complete.** Full scan of `.text` in `Starfield.exe` (102,476,200 bytes,
`pei-x86-64`, image base `0x140000000`, `.text` 61,071,212 bytes).

**Scan with `objdump -d -j .text`.** Without `-j .text` the 234 KB `.bind` DRM section
is also disassembled (it is flagged `CODE`), injecting ~85,000 phantom instructions
decoded from encrypted data.

```
instructions total           16,542,374
VEX-encoded                     805,130    4.87% of all instructions
  256-bit (ymm)                  35,856    4.45% of VEX
  scalar float (ss/sd)          421,075   52.30% of VEX
  128-bit or scalar                        95.55% of VEX
3-operand register forms        208,054   ← superseded, and self-contradictory: Finding 6
  needing an extra mov          126,576   60.84% of 3-op forms
"AVX2-only / no-SSE" matches     19,390   ← but see Finding 3
```

> ⚠ **The two 3-operand lines above are preserved as the historical record, not as
> figures to build on.** They disagree with each other and with the operand-level
> measurement; see Finding 6. Everything else in this block is corroborated.

Contamination from `.bind` was 85,386 phantom instructions but only **47 phantom VEX**,
of which 2 were in the hard set (`vfmaddcsh`, `vpmaskmovq` — both DRM noise). Headline
figures are unaffected; the rare-mnemonic tail is not.

**These figures are validated against the actual translation target.** Rescanning the
Steamless-unpacked binary produced numbers *identical in every field*, and `.text` is
**bit-identical** between the two files:

```
.text offset 0x600, size 0x3a3df6c in both
sha256 = aab904d66f26e614d86ad0769896f1cdea750c738e736f24d84209e1aae2ebd9   (packed)
sha256 = aab904d66f26e614d86ad0769896f1cdea750c738e736f24d84209e1aae2ebd9   (unpacked)
```

Steamless removed `.bind` and rewrote the PE header (entry point → recovered OEP) and
changed nothing else. Two useful consequences: the unpack is provably non-destructive
to code, and the DRM demonstrably never encrypted `.text`.

> **Methodology note.** An earlier 4 MB sample gave 12.4% VEX density, 2.3% ymm and
> "no 256-bit arithmetic". All three were wrong — the sample happened to land in a
> VEX-dense, move-heavy region. Real density is **4.84%**, and there *is* genuine
> 256-bit arithmetic plus FMA. Sample-based estimates on a 102 MB binary are not
> trustworthy; this is why milestone 0 exists.

### Re-measurement by an independent method

Milestone 0 was counted with `grep -P "\tv[a-z0-9]+ "`, which identifies VEX by **how
the mnemonic is spelled**. `tool/vex_scan.py` re-counts by **the encoding bytes** — a
leading `C4` or `C5`, which in 64-bit mode cannot be `LES`/`LDS` and is therefore
unambiguously a VEX prefix. Re-running the same grep would have been one witness
counted twice; this is a genuinely separate question being asked of the same bytes.

The two agree, and the agreement is worth stating precisely:

```
                        grep (mnemonic)   vex_scan (encoding)
instructions total           16,542,374            16,542,323
VEX total                       805,130               805,131
  256-bit (ymm)                  35,856                35,845
  scalar (ss/sd)                421,075               421,069
vzeroupper                       19,253                19,253   exact
vmovss                          182,107               182,107   exact
vmovups                          98,653                98,653   exact
vmovaps                          93,149                93,149   exact
vmovsd                           58,226                58,226   exact
vmulss                           49,135                49,135   exact
```

The residual few-count differences are fully accounted for and are not noise: the
mnemonic test counts 181 EVEX-encoded instructions that are spelled `v...` but are not
VEX (see Finding 5), while the encoding test counts 180 `C4`/`C5` bytes inside data
that disassemble to `(bad)` (see Finding 8). Each test miscounts in its own direction
by almost exactly the other's amount, which is why the totals land within one.

**Headline figures from milestone 0 stand.** What follows are the figures milestone 0
did not measure, and five places where it was wrong: the 3-operand split (Finding 6),
Class D's size (Finding 9), the `vpermilps` and Class H counts (Class H below), the FMA
count and the `vfmaddsub` gap (Finding 4), and the claim that 256-bit arithmetic sites
are the Y2 set (corrected under Finding 2).

Reproduce with:

```bash
objdump -d -j .text Starfield-unpacked.exe > text.asm    # ~0.9 GB, ~30 s
python3 tool/vex_scan.py text.asm                       # ~75 s, ~1.1 GB RSS
```

or `make scan`, which writes both into `$(BUILD_DIR)` and is what `make clean`
removes. The report carries the **complete** VEX mnemonic inventory — 216 entries
summing to the headline total, `(bad)` included — because that whole list is what a
lowering table has to be built against. It is deliberately not a top-N: the earlier
truncation is what caused a second, slightly different mnemonic count to be extracted
by hand, and two counters that disagree by 322 instructions is the drift
`evidence.md` is about.

### Finding 1 — the binary is overwhelmingly scalar

52% of VEX instructions are **scalar** float ops on single values. The top mnemonics:

```
182,107 vmovss     49,135 vmulss     27,185 vsubss     22,350 vpxor
 98,653 vmovups    44,407 vaddss     27,082 vmovdqu    19,828 vshufps
 93,149 vmovaps    31,451 vxorps     23,175 vcomiss    19,253 vzeroupper
 58,226 vmovsd
```

These are VEX-encoded because of the global compiler flag, not because anything is
vectorised. ~780,000 of 805,177 VEX instructions (97%) lower 1:1 or with one extra mov.

### Finding 2 — 256-bit usage is 94% data movement

```
32,858 vmovups          231 vmulps        93 vfmadd231ps
   496 vmovdqu          160 vaddps        73 vpand
   383 vextractf128     157 vinsertf128   72 vpaddd
   249 vmovaps          101 vsubps        55 vbroadcastss
    41 vmovupd           95 vshufps       ...
```

Moves total 33,644 of 35,869 (93.8%). The `mem → ymm → mem` pattern lowers to two
128-bit copies with **no shadow state at all** (Strategy Y1). That leaves only
**~2,225 genuine 256-bit arithmetic sites** — 0.013% of all instructions. Re-measured on
the unpacked binary: 33,648 moves and **2,197** arithmetic sites, of 35,845.

> **Correction.** This finding originally said those ~2,225 arithmetic sites are the
> ones "needing the Y2 shadow path". That conflates two different questions. Whether a
> site needs Y2 depends on **where its value is consumed**, not on whether it is
> arithmetic: a 256-bit arithmetic result consumed in its own basic block needs no
> shadow, and a plain `vmovups` load consumed after a branch does. Measured properly
> (Finding 7) the Y2 set is **574 of 13,097 ymm definitions**, and 390 of those are
> `vmovups` — moves, not arithmetic.

### Finding 3 — the "AVX2-only" scare is 99.3% `vzeroupper`

```
19,253 vzeroupper       ← TRIVIAL: no-op on a non-AVX host
─────────────────────────────────────────────────────────
    73 vpermilps            6 vpermd
    18 vpbroadcastd         4 vpermpd
    13 vextracti128         3 vinserti128
    12 vperm2f128           2 vpbroadcastw
     6 vpermq
─────────────────────────────────────────────────────────
   137 genuinely hard      (0.0008% of all instructions)
```

`vzeroupper` zeroes the upper halves of all ymm registers. With no AVX state it is a
`nop`; inside Y2 shadow regions it zeroes the shadow slots. Either way it costs nothing.

The remaining **137 instructions** are cross-lane permutes and broadcasts. At that
count they can be handled by out-of-line helper stubs (`call` into a hand-written SSE
routine) with no measurable performance impact.

**No masked stores.** The single `vpmaskmovq` in the contaminated scan was `.bind`
noise — it does not exist in real code. That removes the most awkward lowering in the
set; masked stores need branchy per-element emulation, permutes do not.

### Finding 4 — FMA needs its own rule, and is NOT bit-exact

**421** FMA instructions on the unpacked binary (`vfmadd231ps` 143, `vfmadd231ss` 94,
`vfmadd213ps` 25, `vfmadd132ss` 24, `vfmsub231ss` 23, `vfnmadd231ss` 20, …). Milestone 0
said 424; the three-instruction difference is `.bind` contamination, and 421 is the
figure to use. Westmere has no FMA. Lowering `a*b+c` to `mulps` + `addps` gives **two
roundings where the original had one**, so results differ in the last ULP.

Almost certainly irrelevant for game rendering, but it is the only rule in this design
that is *not* semantics-preserving, and it must be recorded as such. If any code path
depends on exact FP reproducibility (physics determinism, replay, netcode lockstep),
this is where it breaks.

**28 of the 421 are not plain FMA and Class F does not cover them.**
`vfmaddsub231ps` (14) and `vfmsubadd231ps` (14) *alternate* add and subtract across
the lanes of one vector. A `mulps` + `addps` sequence computes the wrong thing for
half the elements, silently. Lowering them with the Class F sequence is a correctness
bug, not a precision one — `test/fmaddsub_test.c` demonstrates it rather than
asserting it, by keeping the naive sequence around and checking it differs on exactly
the two even lanes.

**Written and tested: see Class F-addsub below.**

### Finding 5 — the binary contains real AVX-512, and it is dispatched

**179 EVEX-encoded instructions exist in `.text`.** They are real code, not misdecode:

```
0x1434d87ee - 0x1434d8fd0   2,018 bytes
0x1434daa45 - 0x1434dae64   1,055 bytes
```

```
vmovdqu32 0x752148(%rip),%zmm7        vpdpbusd %zmm8,%zmm1,%zmm4
vpclmullqhqdq %zmm5,%zmm3,%zmm1       vpsadbw %zmm1,%zmm6,%zmm0
kmovq  %rdx,%k1                       vmovdqu8 (%r10),%zmm0{%k1}{z}
vextracti64x4 $0x1,%zmm2,%ymm0        vinserti32x4 $0x2,(%r8),%zmm1,%zmm2
```

`vpclmulqdq` beside `vpsadbw`/`vpaddd` accumulation is a CRC32 and adler32 kernel —
a bundled checksum/compression library (the shape is zlib-ng or ISA-L), not compiler
output. `/arch:AVX2` cannot emit EVEX, so **this is hand-written or intrinsic-coded
ISA-specific assembly**, which answers an open question below in the affirmative.

**It is guarded.** A textbook feature-detection routine sits at `0x1434ddd40`:

```
cpuid   leaf 0                    -> max leaf
cpuid   leaf 1                    -> EDX[26] SSE2, ECX[9] SSSE3, ECX[20] SSE4.2,
                                     ECX[1] PCLMULQDQ, ECX[27] OSXSAVE
bt $0x1b,%ecx / jae               -> skip the XSAVE probe if OSXSAVE is clear
xgetbv                            -> XCR0 & 0x06 == 0x06  (AVX state)
                                     XCR0 & 0xe6 == 0xe6  (AVX-512 state)
                                  -> results stored to a feature struct at (%r8)
```

On a Westmere `OSXSAVE` is clear and both comparisons fail, so the dispatcher selects a
non-AVX path and **this code is never reached**. Two consequences:

- **AVX-512 stays out of scope, and that is now a measured position rather than an
  assumption.** The rewriter must *recognise* EVEX and leave it alone — not choke on
  it, and not attempt to lower it.
- **The dispatcher must survive translation byte-for-byte in behaviour.** It is the
  thing that keeps 179 unexecutable instructions unexecuted. If a rewriting pass
  perturbs the CPUID/XGETBV logic or the feature struct's layout, the binary can
  select a path its host cannot run — a new failure mode this design did not have.

Two further EVEX-looking sites (`0x142d511ac`, `0x14319e280`) are misdecodes: both sit
in `(bad)` runs after a `ret`/`nop`, and decode to nonsense (`{rex2 0x2}` prefixes).
Do not count them.

### Finding 6 — the 3-operand split, and a contradiction in milestone 0

Measured over every 3-operand VEX NDS form, including those whose src2 is a memory
operand and those carrying an immediate:

```
three-operand forms            275,586
  Class B   dst == src1         83,461   30.28%   direct, no cost
  Class C   dst != src1        183,123   66.45%   one extra mov
  C-alias   dst == src2          9,002    3.27%   mov clobbers src2
```

**This contradicts milestone 0, which contradicts itself.** Milestone 0 reported 208,054
3-operand forms, said Class B takes 23.6% and Class C 76.4%, *and* said 126,576 need an
extra mov. Those cannot all hold: 76.4% of 208,054 is 158,953, while 126,576 is 60.8%.
The two statements in the document disagree by 32,000 instructions.

The count differs too. Register-only triples number **178,306** and forms with a memory
src2 add **62,773** more; milestone 0's 208,054 falls between the two, so its basis is
unclear. It is recorded here as unresolved rather than quietly overwritten — but the
figure to build on is 275,586, because a memory-source form still needs the extra mov
when `dst != src1`, and milestone 0's cost model appears to have missed those.

**The C-alias case splits in two, and only one half is cheap.**

```
commutative -- fix by swapping the operands, ZERO extra instructions   4,318   47.97%
NOT commutative -- needs a scratch xmm and two movs                    4,684   52.03%
```

`vaddss %xmm0,%xmm1,%xmm0` is just `addss %xmm1,%xmm0`. `vsubss %xmm0,%xmm1,%xmm0` is
not: it needs a scratch, and there are 4,684 such sites. The largest contributors are
`vsubss` (1,210), `vmaxss` (806), `vdivss` (717), `vcmpless` (608), `vsubps` (409).

> **`vmaxss` and `vminss` are deliberately NOT treated as commutative.** SSE
> `MAXSS(a,b)` returns the *second* operand when either input is NaN, and when both
> are zeros of opposite sign. Swapping them is wrong at exactly the inputs a clamping
> routine is most likely to see, and wrong in a way that no ordinary test detects.
> That is 1,134 of the 4,684. Getting this wrong is the same class of silent error as
> copying src2 instead of src1 in Class C.

### Finding 7 — Y2 is real, but it is 574 sites

The question the Y2 shadow area exists to answer is whether a ymm value's halves ever
have to coexist across a control-flow edge. Measured by walking every SIMD site in
program order, cutting blocks at branch targets and after every control transfer, and
treating a `call` as a kill (the Win64 ABI makes bits 255:128 of every ymm register
volatile):

```
ymm definitions                    13,097
  consumed in the same block (Y1)  12,336   94.19%
  live across a block edge (Y2)       574    4.38%
  dead, overwritten                   174    1.33%
  killed by an intervening call        13    0.10%
```

**Y2 cannot be deleted from the design** — 574 is not zero. But it is 574, and 390 of
them are `vmovups`, so the shadow path is a narrow, enumerable special case rather
than a pervasive one. The full address list is what `tool/vex_scan.py` prints; a
representative site is `0x140311b2e`, where `vmovups 0xd0(%rsp),%ymm1/2/3` is followed
by `jmp 0x140311bd3` and the values are consumed in the target block.

The dominant Y1 pair is confirmed directly: **10,116 `vmovups` → `vmovups`
producer/consumer pairs**, which is the memcpy peephole the design predicted.

> **This is an upper bound on Y2, not an exact count.** Indirect branches are not
> resolved, so a block may be entered somewhere the walk does not know about; and any
> gap wider than 4 KiB between adjacent SIMD sites is treated as a barrier rather than
> analysed. Both errors push sites *into* the Y2 bucket. The true figure is 574 or
> fewer, which is the direction that matters for a go/no-go.

### Finding 8 — 11,892 bytes of `.text` do not disassemble, in 744 islands

```
total (bad) decodes                11,892   0.07% of instructions
islands (separated by > 256 bytes)    744
islands holding exactly one            229
largest:  0x1431a2124 - 0x1431a231a   502 bytes,  351 bad
          0x143617292 - 0x1436179eb 1,881 bytes,  345 bad
          0x1436a8900 - 0x1436a8a84   388 bytes,  241 bad
```

This is **data embedded in `.text`** — jump tables, string blobs and constant pools
that a linear sweep walks straight into. It is not a defect in the binary; it is the
undecidable code/data problem stated concretely, with addresses.

It belongs to **milestone 3, and it is the first thing to check there.** Ddisasm's
whole value is separating these correctly. 744 islands is a tractable number to audit
by hand, and this list is the ground truth to audit *against*: every one of them must
come out of Ddisasm marked as data. Any island Ddisasm calls code, or any region it
calls data that this scan decoded as plausible instructions, is a round-trip failure
found cheaply rather than after a rewrite.

### Finding 9 — Class D is 12x larger than recorded, and was never costed

The two Class D mnemonics are both undercounted by an order of magnitude, and the
larger one is the most awkward lowering left in the design now that masked stores are
ruled out.

```
                  project.md    measured
vblendvps                283       3,542    12.5x
vbroadcastss              47         753    16.0x
vblendvpd                  —          30
vbroadcastsd               —           1
```

**`vblendvps` (3,542 sites) is the problem.** SSE `blendvps` takes its mask in an
*implicit* `%xmm0`; the VEX form names all four registers explicitly, so lowering means
getting the mask into `%xmm0` without destroying anything. Measured over the operand
shapes:

```
mask is already %xmm0                            1,337   cheapest case
dst is %xmm0                                     2,171   dst collides with the mask register
%xmm0 not named anywhere                           608   must save AND restore %xmm0
```

(The first two overlap; the 608 is exact and is the expensive case — `%xmm0` holds a
live value that has to be spilled around the blend.)

**The majority case cannot use the obvious sequence at all**, which was found by
building the rule and reading its output rather than by reasoning about it. The
natural lowering is "save `%xmm0`, load the mask into it, move `src1` into `dst`,
blend, restore `%xmm0`". When `dst` *is* `%xmm0` — 2,171 sites — that sequence
destroys the mask on the third instruction and then destroys the result on the
fifth. Both halves are wrong, and the output still assembles cleanly, so an
assembler-level check does not catch it.

The shapes and their correct sequences:

```
mask already in %xmm0        movaps src1,dst ; blendvps src2,dst
                             cheapest -- nothing to save

dst is %xmm0  (2,171)        movaps src1,%xmmT
                             movaps mask,%xmm0        <- %xmm0 is dead, do not save it
                             blendvps src2,%xmmT      <- blend in the scratch
                             movaps %xmmT,%xmm0       <- and move back

otherwise      (608 worst)   movaps %xmm0,%xmmT       <- save
                             movaps mask,%xmm0
                             movaps src1,dst
                             blendvps src2,dst
                             movaps %xmmT,%xmm0       <- restore
```

Two further aliases have to be handled by renaming rather than by ordering: if
`src1` or `src2` is itself `%xmm0`, its value now lives in the scratch and the blend
must refer to it there. The one case needing a **second** scratch is `dst == %xmm0`
with `src2 == %xmm0`, where src2 has to be staged before the mask overwrites it.

At 283 sites this was a footnote. At 3,542 it is a register-allocation problem in its
own right, and it interacts directly with hard part 5: every one of these competes for
the same scarce scratch registers as Y2 and the non-commutative C-alias sites.

**`vbroadcastss` (753 sites) splits by source and the two halves lower differently:**

```
memory source     735   AVX1 form   ->  movss m,%xmm ; shufps $0,%xmm,%xmm
register source    18   AVX2 form   ->  needs a reg-to-reg splat, not movss
```

The rule as written in Class D covers only the memory form, which is 735 of the 753.

**Neither appears in milestone 0's cost model** — the table jumps from 3-operand movs
straight to 256-bit splitting, with no Class D term at all. Corrected below.

### Finding 10 — the binary needs F16C, which is not a re-encoding problem

`tool/lower.py` carries a rule for every VEX mnemonic and reports what it cannot
cover. Over all 804,951 VEX sites:

```
covered   804,939   99.9985%     <- before src/f16c.c existed
gaps           12    0.0015%
  vcvtph2ps     8
  vcvtps2ph     4
```

> **Resolved.** `src/f16c.c` implements both directions and Class H now calls
> into it, so coverage is **804,951 of 804,951 -- 100.0000%, no gaps**. The
> rest of this finding is why it was hard and what the routine had to avoid;
> the verification is at the end of it.

**Twelve sites, and they are the only ones in the binary with no lowering at all.**
Both mnemonics are F16C -- half-precision float conversion, which arrived with Ivy
Bridge in 2012. **Westmere does not have it**, confirmed against the host's own
`/proc/cpuinfo` rather than from memory.

This is a different kind of problem from everything else in this design. Every other
rule is a re-encoding: the same operation exists in SSE and the work is getting the
operands into the right registers. There is no SSE half-float instruction of any
kind, so these need **a software conversion routine** -- shifts, masks, and explicit
handling of denormals, infinities and NaNs.

**They are not behind a dispatcher.** Unlike the AVX-512 of Finding 5, there is no
`cpuid` or `xgetbv` anywhere in the surrounding 8 KB. They sit in ordinary compiler
output at `0x142dc3aae`-`0x142dc3e27`, 127 bytes into a function, inside what is
plainly a half-float decode loop:

```
vmovdqu   (%r10),%xmm6                 load packed halves
vcvtph2ps (%r10,%rdx,1),%ymm10         hardware half -> single
vpslld    $0x10,%xmm5,%xmm1            ... beside a manual shift-into-exponent
vinsertf128 $0x1,%xmm1,%ymm0,%ymm8     rebuilt into 256-bit lanes
vpand     %xmm5,%xmm14,%xmm1
```

The loop mixes the hardware conversion with hand-rolled shift-and-mask sequences,
which suggests two pixel or sample formats being decoded side by side. Whatever it
feeds, **it runs**, and a translated binary that ignores these twelve instructions
faults exactly as the untranslated one does.

#### The routine, and what it had to avoid

`src/f16c.c`. The governing constraint turned out not to be the format but the
floating-point environment: **nothing in it may depend on MXCSR.** `vcvtps2ph` takes
its rounding mode from bits 2:0 of its own immediate, and the target uses 0 — round
to nearest, ties to even — which ignores MXCSR entirely. Games routinely set
flush-to-zero and denormals-are-zero for speed.

That disqualifies the widely copied implementations. Giesen's `half_to_float_fast5`
multiplies by a magic power of two and relies on exactly the denormal arithmetic DAZ
switches off; `float_to_half_fast3` adds a magic constant and inherits whatever
rounding mode MXCSR happens to hold. Both are correct in an ordinary process and
wrong in the only kind of process this has to be correct in.

So the routine uses integer arithmetic wherever the shift is constant, and `roundps`
where it is not — `roundps` is SSE4.1, on Westmere, and takes its rounding mode from
its own immediate rather than from MXCSR, which is precisely the property that lets
it stand in for `vcvtps2ph`. The one float operation in each direction is a multiply
by a power of two, which is exact under every rounding mode, on operands chosen so
that no denormal ever arises: half-to-single scales integers in 0..1023, and
single-to-half scales into 0..1024.

#### Verification

```
all 65,536 halves          vector == scalar reference     exhaustive
all 4,294,967,296 singles  vector == scalar reference     exhaustive, 48 s
all 65,536 halves          reference == CPython binary16  exhaustive
185,712 sampled singles    reference == CPython binary16  boundary-weighted
built object               no VEX, no EVEX, no F16C       disassembled, not assumed
```

The second pair matters as much as the first. The vector code and the scalar
reference were written by one hand on one afternoon, so however exhaustively they
agree they are **one witness**: if the reference misunderstands the format, the
vector code has been proved to misunderstand it identically. CPython's `struct` has
supported binary16 as format `e` since 3.6 and is the closest thing to an
independent implementation available on a machine with no F16C to ask.

`check-isa` disassembles the built object rather than trusting `-mno-avx -mno-f16c`,
because a compiler flag that silently stopped applying would look exactly like a
clean pass.

**What is still unverified: NaN payloads, against real silicon.** The routine
preserves the payload and forces the quiet bit, per the SDM. CPython canonicalises
NaN through a native float and so cannot confirm it — 2,044 halves and 252 singles
differ from CPython in payload alone, with both sides NaN. Settling it needs an F16C
machine, which is by definition not the translation target.

Consequences:

- **The hardware requirement is AVX2 *and* F16C**, not AVX2 alone. On Intel parts
  that distinction never shows up -- F16C shipped a generation before AVX2, so
  anything with AVX2 has it -- which is precisely why it goes unnoticed until
  something tries to translate rather than run.
- **A twelfth rule class is needed: software emulation.** It is the only place in
  the design where correct output requires an algorithm rather than a substitution,
  and the denormal and NaN cases are where such routines are usually wrong.
- The sites are 256-bit, so they need the Y-class treatment as well.

### Finding 11 — SSE has no greater-than compare, and the compiler used one

AVX widened the compare predicate field from three bits to five. SSE has exactly
eight predicates -- `eq lt le unord neq nlt nle ord` -- and the compiler emitted
some of the twenty-four that only exist in AVX:

```
vcmpnle_uqps / vcmpnle_uqpd    4   quiet variant of nle
vcmple_oqps  / vcmple_oqpd     4   quiet variant of le
vcmpgt_oqps  / vcmpgt_oqpd     4   NO SSE EQUIVALENT
```

The `_oq`/`_uq` forms are the *quiet* variants of predicates SSE already has in
signalling form. With floating-point exceptions masked -- which is every normal
process -- they compute an identical result and differ only in whether a signalling
NaN raises. Those eight lower by a mnemonic change and the difference is recorded
rather than hidden.

**`cmpgt` is the one that is not cosmetic.** There is no greater-than predicate in
SSE at all, so it must become a less-than with **the operands exchanged** -- which
changes which operand the destination has to hold and therefore interacts with the
Class B/C rules. Four sites.

This was not taken on trust: `as` rejects `cmpgtps %xmm1,%xmm0` outright with *no
such instruction*, which is the assembler confirming the gap independently of the
manual.

### Finding 12 — milestone 3 does not pass on this machine

**Ddisasm cannot disassemble the target here.** Two runs, both killed by
`std::bad_alloc` at a peak RSS of **34.3 GB**, seven minutes in, in the *first*
analysis phase.

```
address-space cap   outcome                        peak RSS    wall
38 GB               std::bad_alloc -> SIGABRT       22.7 GB     3:16
44 GB               std::bad_alloc -> SIGABRT       34.3 GB     7:00
44 GB, -F           std::bad_alloc -> SIGABRT       34.3 GB     6:56
```

`-F` (skip function analysis) changes nothing, which locates the wall precisely: it
is in `disassembly load`, the stage that builds the initial Datalog fact base, before
any of the analyses `-F` would skip.

**The requirement was measured rather than guessed.** Ddisasm was run over four PE
binaries of increasing size and the cost normalised on instruction count, which is
what actually drives it — `mshtml.dll` is larger than `wined3d.dll` on disk and
cheaper to analyse, because most of it is not code:

```
binary          instructions   wall s   peak GB   s/Minsn   GB/Minsn
user32.dll           156,062       28      0.84       179       5.38
msxml3.dll           379,714       60      2.02       158       5.32
wined3d.dll          457,842      143      2.90       312       6.33
mshtml.dll           320,624       42      1.49       131       4.65
                                                  mean 195       5.42
```

Starfield has **16,542,323 instructions — 36 times the largest sample**, which
projects to roughly **54 minutes and 90 GB**. The observed failures are consistent
with that: 34.3 GB consumed and still inside the first phase.

**A 128 GB machine would very likely complete it.** Nothing here says the approach is
impossible; it says the go/no-go cannot be answered on 47 GB. The extrapolation is a
36-fold one from samples under half a million instructions, so treat 90 GB as an
order-of-magnitude figure rather than a specification.

#### The finding that matters more than the memory

```
WARNING: Input binary compiled with Profile Guided Optimization. (unsupported)
```

Ddisasm says so on every run, in the first half-second, and it is a statement about
correctness rather than resources. PGO reorders basic blocks, splits functions into
hot and cold fragments placed far apart, and duplicates code along hot paths — all of
which attack exactly the code-discovery assumptions a static disassembler makes. A
128 GB machine removes the memory wall and leaves this one standing.

This deserves its own evaluation before any more is spent on the Ddisasm route,
because it bears on whether a *correct* round-trip is achievable at all, and the
744 data islands of Finding 8 are the ground truth to evaluate it against.

#### What did work

- **Ddisasm 1.9.5 runs on this host**, unpacked from GrammaTech's `focal` packages
  into a scratch prefix with no root. It needs Ubuntu 20.04 Boost 1.71 and
  `libprotobuf17`, which Debian 13 does not have; those come from the Ubuntu archive.
  `tool/run_ddisasm.sh` runs it under `prlimit` and a `timeout`.
- **Loading the 102 MB PE is not the problem.** With `-n` (no analysis) it parses in
  1.2 s using 408 MB and writes a 130 MB GTIRB. The cost is entirely in the analysis.
- **The round trip works end to end on small PEs.** `start.exe` (300 KB) goes to
  GTIRB in 0.57 s and back out as assembly in 0.04 s.
- **The output is MASM, not GAS.** For a PE target `gtirb-pprinter` emits
  `INCLUDELIB` / `EXTERN name:PROC`, so reassembly needs `ml64` or `uasm` rather than
  the GNU assembler. That is a pipeline requirement nothing in this design had
  recorded.

#### Reproducing the ddisasm prefix, without root

Ddisasm is not in Debian and GrammaTech publish for Ubuntu `focal` only. The
packages unpack into a prefix and run from there; nothing needs installing.

```bash
BASE=https://download.grammatech.com/gtirb/files/apt-repo/pool/stable
UB=http://archive.ubuntu.com/ubuntu/pool/main
mkdir -p prefix debs && cd debs
curl -sSLO $BASE/d/ddisasm/ddisasm_1.9.5-focal_amd64.deb
curl -sSLO $BASE/libg/libgtirb/libgtirb_2.3.2-focal_amd64.deb
curl -sSLO $BASE/libg/libgtirb-pprinter/libgtirb-pprinter_2.2.5-focal_amd64.deb
curl -sSLO $BASE/g/gtirb-pprinter/gtirb-pprinter_2.2.5-focal_amd64.deb
curl -sSLO $BASE/libc/libcapstone-dev/libcapstone-dev_5.0.1_gt_amd64.deb
# Debian 13 has Boost 1.83 and protobuf 3.21; focal's builds need these.
curl -sSLO $UB/b/boost1.71/libboost-filesystem1.71.0_1.71.0-6ubuntu6_amd64.deb
curl -sSLO $UB/b/boost1.71/libboost-program-options1.71.0_1.71.0-6ubuntu6_amd64.deb
curl -sSLO $UB/p/protobuf/libprotobuf17_3.6.1.3-2ubuntu5.2_amd64.deb
cd .. && for d in debs/*.deb; do dpkg-deb -x "$d" prefix/; done

export DDISASM_PREFIX=$PWD/prefix
make disassemble TARGET=Starfield-unpacked.exe
```

Do not link Debian's own Boost against these: 1.83 and 1.71 are not ABI
compatible, so a symlink crashes rather than failing cleanly.

#### Bounding it was not optional

Two runs took 34 GB on a 47 GB machine. Unbounded, they would have gone to swap
rather than failing, which is the failure mode `running-code.md` exists to prevent.
`prlimit --as` turned "the machine becomes unusable" into "the run reports
`std::bad_alloc`", and the machine ended each attempt with 41 GB free and no orphans.

### Finding 13 — the PGO warning does not sink the approach

Finding 12 flagged `WARNING: Input binary compiled with Profile Guided Optimization.
(unsupported)` as the thing that mattered more than the memory, and said it needed
evaluating before more was spent on the Ddisasm route. It has been evaluated. **On the
available evidence it is a caution, not a blocker**, and the memory wall remains the
real obstacle.

**What actually triggers it.** The PE carries an `IMAGE_DEBUG_TYPE_POGO` debug
directory entry whose signature is `'LTCG'` — a link-time-codegen section map, which
ordinary MSVC builds have. It is not a marker of profile-guided hot/cold splitting.
Four other binaries on this machine carry it and provoke the identical warning.

**What PGO actually did to this binary.** The POGO entry maps `.text` completely:

```
.text$di      0x1000       2,789,280     dynamic initialisers
.text$mn      0x2a9fa0    55,216,464     the bulk of the code
.text$mn$00   0x37528f0           96
.text$x       0x3752950    1,225,840     EH funclets
.text$yd      0x387ddc0    1,839,532     atexit destructors
                          -----------
                           61,071,212  = the whole .text, exactly
```

`.text$mn` is **one contiguous range**. There is no separate cold section and no split
hot/cold region — the layout is the same shape as a 90 KB MSVC executable's, only
larger. The feared PGO artefact, code fragments exiled to a distant region, is not
visible in the section map.

**The warning was tested rather than reasoned about.** Four binaries carrying it, small
enough to fit, were disassembled and their code/data split audited against an
independent linear sweep. A byte that cannot decode as an instruction but which
Ddisasm calls code is the failure that matters, because anything rewritten there
corrupts the output:

```
binary                     .text bytes   undecodable   called code   unaccounted
d3ddriverquery64.exe            90,540             4             0             0
GameOverlayRenderer64.dll    1,080,596           666             0             0
iscriptevaluator.exe                 -            61             1*            0
obse_1_2_416.dll                     -            12             0             0
mciseq.dll     (no POGO)             -             0             0             0
start.exe      (no POGO)             -             0             0             0
```

Every byte of `.text` is accounted for in all six. The metric is not vacuous — it
could have reached 666 on one of them and reached 0.

**\*The single apparent failure is a defect in the ground truth, not in Ddisasm.**
At `0x140016348` in `iscriptevaluator.exe` the linear sweep had walked into a jump
table, desynchronised, and decoded `62 01 00 cc cc` as one bogus five-byte
instruction — swallowing a legitimate `int3` padding byte. Ddisasm had the table
correctly split into 4-byte data blocks and called that byte a one-byte code block,
which is right. Verified by reading both disassemblies.

**Control Flow Guard, the other "unsupported" warning in the same cluster, does not
apply.** `DllCharacteristics` is `0x8160`; the `GUARD_CF` bit is clear.

#### What this does not establish

The samples are 90 KB to 1 MB of `.text`. Starfield's is **61 MB and 16.5 million
instructions** — a sixty-fold extrapolation, and the actual binary could not be tested
because of Finding 12. Scale is exactly where code-discovery problems appear.

The audit tests **code/data separation only**. It says nothing about whether the
reassembled output is correct — that needs a MASM assembler, which this machine does
not have — nor about symbolisation or jump-table recovery at scale.

And "unsupported" is GrammaTech's word, not a measurement. It plausibly means "we do
not test this configuration" rather than "this produces wrong output", but that
reading is inference. The honest position is that **the specific risk the warning
guards could not be reproduced**, not that it does not exist.

#### A correction to Finding 8

Finding 8 proposed the 744 undecodable islands as "the ground truth to audit against".
This experiment shows that is too strong. **A linear sweep over-marks**: on walking
into data it desynchronises, and its `(bad)` runs bleed into the legitimate code that
follows, as they did at `0x140016348`. The island list is a useful screen — it found
the one case worth inspecting out of 743 bytes — but it is not a clean oracle. An
apparent disagreement has to be read before it counts as one.

### Finding 14 — most of the rewrite needs no relocation at all

Milestone 4 was specified as classes A/B/C/Z through the Ddisasm pipeline, and
milestone 3 blocked. It turns out most of it never needed that pipeline.

**A VEX instruction and its SSE equivalent are usually the same length.** The VEX
prefix packs the legacy prefix, the REX bits, the opcode map and an extra register
operand into two or three bytes; the SSE form spells the same things out as a legacy
prefix, a REX byte and a `0F` escape. Count them and they frequently come to the same
total, and where SSE is shorter the difference is a nop.

So classes A, B and Z can be **patched into the binary in place**:

```
patchable in place    567,736   70.5%   A 469,859  B 78,624  Z 19,253
needs relocation      197,607   24.6%   Class C -- one extra mov, cannot fit
would grow in place    25,887    3.2%   SSE encoding is one byte longer
outside .pdata         13,820    1.7%   not provably code; skipped
```

**That sidesteps hard part 2 entirely for those sites.** Nothing moves, so every
address is unchanged, and `.pdata`, `.xdata`, the base relocations, the jump tables
and the import directory are all still correct *because they were never touched*. The
output is the same size as the input and byte-identical outside the rewritten
instructions.

`tool/patch.py`, `make patch`. Verified on the real binary:

```
size unchanged                       102,242,144 bytes
bytes differing                        1,237,391   every one inside .text
headers                                byte-identical
VEX-encoded instructions       805,131 -> 237,395   567,736 removed, exactly the
                                                    number patched
instruction boundaries              16,542,323      all preserved
```

Class C is left alone, so the binary still faults — later, and at a site the tool can
name, which is what milestone 4 asks for.

#### Two bugs the verification caught, and the invariant that caught them

Neither was visible in the output. Both were found because the counts did not
reconcile: 585,327 instructions stopped being VEX when only 581,556 had been patched.

**objdump wraps long encodings onto a continuation line.**

```
1402aa9db:	c5 f8 10 1d 8d cb 79
1402aa9e2:	04
```

Those trailing bytes are part of the instruction. Reading only the first line makes an
eight-byte instruction look like seven, and writing a seven-byte replacement over it
strands the last byte and corrupts both. This hit **every instruction with a 32-bit
displacement** — the most common shape in the binary.

**A RIP-relative displacement is measured from the end of the instruction.** An
encoding that shrinks and is padded afterwards ends a byte early, so every such
displacement points somewhere else. The fix is to pad at the **front**: the end
address stays fixed, and a branch to the original start lands on the nop and falls
straight through, so both addresses survive.

The invariant that exposes this class of error is worth stating on its own:

> **Every address that began an instruction must still begin one.** A patch that
> changes a length without meaning to desynchronises the disassembler downstream, and
> that shows up here immediately. `make patch-verify` checks all 16.5 million.

#### What it does not do

The patched binary **will not run**. 237,395 VEX instructions remain, so it still
faults with `EXCEPTION_ILLEGAL_INSTRUCTION` — just after 70.5% more of the work has
happened. Class C is the bulk of what is left and genuinely needs somewhere to put an
extra instruction, which is the relocation machinery this approach avoids.

Nothing here has been executed. The invariants are structural: sizes, boundaries, and
which bytes changed. That the rewritten instructions *compute* the same thing rests on
the lowering rules and their tests, not on this tool.

### Finding 15 — Class C by detour, and where it has to stop

Class C cannot be rewritten in place: four bytes become seven. `tool/detour.py`
appends a stub section and turns each site into a jump into it.

```
class C sites (dst != src1)      187,609
  detoured                        94,925   50.6%
  shorter than a jump             91,039   48.5%   left alone -- see below
  outside .pdata                   1,645    0.9%
```

Combined with the in-place work, on the real binary:

```
size                102,242,144 -> 103,548,928   +1,306,784, the stub section
sections after .text                             byte-identical
VEX in .text            805,131 ->     142,470   662,661 removed, 82.3%
  in place                                       567,736
  detoured                                        94,925
instruction boundaries       16,542,323          all preserved
stub section                                     0 VEX, 94,925 jumps back
```

The counts reconcile exactly: 567,736 plus 94,925 is 662,661, and the stub section
holds one jump back per detour.

#### Why only the sites that are already five bytes

A near jump is five bytes. Overwriting a five-byte instruction with one leaves its
start and its end address exactly where they were, and **no address inside an
instruction can be a branch target**, so nothing observable changes. That is the whole
soundness argument, and it is why the length threshold is not an optimisation.

The 91,039 four-byte register-to-register forms would have to swallow the instruction
after them to make room. That reopens a question this cannot answer: an indirect
branch through a jump table can target that next instruction, and **x64 MSVC switch
tables hold offsets relative to the table, which no relocation records** — so the set
of indirect targets cannot be enumerated from the file. Extending a window over an
unknown branch target puts the landing site in the middle of a jump. They are left
alone rather than guessed at.

#### Two things that are fatal if got wrong

**A RIP-relative operand moved into a stub is a different distance from its target.**
Every site with a memory operand has one, and a displacement left alone points
somewhere arbitrary. Checked rather than assumed: 12,507 stubs had their resolved
target compared against the original instruction's, with **no mismatches**.

**The jump back goes to the instruction after the original, not after the jump.**
Those differ whenever the site was longer than five bytes, which is half of them.

A third was caught by reading the output instead of trusting it: the section header
packs `Characteristics` as the last four bytes of a 40-byte entry, and one field too
many in the pack wrote it past the end. The section came out `READONLY, NOREAD` rather
than executable — which objdump says plainly and nothing else would have.

#### What remained after this stage

142,470 VEX instructions, before the windows were widened (Finding 16):

```
class C shorter than a jump     91,039   needs the indirect-target problem solved
A/B that would grow             25,887   SSE encoding one byte longer
outside .pdata                  15,465   not provably code
sequences (D, F, Y, H)          ~5,400   more than one instruction, and register
                                         pressure -- the scratch has to come from
                                         somewhere
EVEX passthrough                   287   correct as is
```

Nothing here has been executed, and the invariants remain structural.

### Finding 16 — the indirect branch targets can be enumerated

Finding 15 stopped at the 91,039 four-byte Class C sites because widening a detour
window past the instruction it replaces needs to know nothing branches into the
window, and indirect branches are not in the disassembly. They can largely be
enumerated, and `tool/targets.py` does it from four sources:

```
.reloc  (absolute pointers)      91,617   COMPLETE, not a heuristic
.pdata  (function starts)       236,427   complete for what it covers
.xdata  (EH handlers)                 6
switch tables (3,009 found)      14,789   inferred, see below
union                           276,809
```

**`.reloc` is what makes this tractable.** Every absolute address stored anywhere in
the image has a base relocation, because the loader must fix it up if the image moves.
So every vtable entry, function pointer and TLS callback is there by construction —
this is a completeness argument, not a scan.

**Switch tables are the one inferred source, and that is stated rather than buried.**
MSVC x64 stores each entry as an offset relative to the table's own address, so nothing
relocates them and nothing marks them as addresses. They are found by self-consistency:
a run of four or more values at address `T` where `T + value` lands in `.text` every
time. A table this misses is a table whose targets are absent from the set — the
dangerous direction — so the scan is deliberately over-inclusive.

With direct branch targets from the disassembly, the blocked set is 1,370,048
addresses. Against it, **85,575 of the 91,039 four-byte sites (94%) can widen safely**;
1,740 are correctly refused because the next instruction genuinely is a branch target.

Combined result on the real binary:

```
VEX in .text            805,131 ->      56,984   748,147 removed, 92.9%
  in place                                       567,736
  detoured                                       145,398
size                102,242,144 -> 104,544,256   +2,302,112, the stub section
sections after .text                             byte-identical
boundaries lost              65,039              every one deliberately swallowed
swallowed instructions       66,715              none reachable by any branch
stub section                                     0 VEX, 145,398 jumps back
```

The counts close: 66,715 swallowed minus 65,039 lost boundaries is 1,676, exactly the
sites refused for an ambiguous displacement.

#### Three bugs the verifier found, none visible in the output

**Overlapping windows.** Two Class C sites can be adjacent, so the first one's widened
window swallows the second — which was then patched again, on top of the jump already
written there. Taking sites in address order and refusing any that starts inside a
committed window is the whole fix; it costs 33,426 sites.

**Swallowed VEX carried across unlowered.** The instruction a window swallows is
usually VEX too, since VEX code comes in runs, and copying it into a stub verbatim
leaves AVX in the output — the one thing the exercise is for. Inside a stub there is
room, so it is lowered rather than refused. 80,015 instructions were affected.

**Stripping a VEX prefix is not always a lowering.** `vbroadcastss` is Class D: opcode
`0F 38 18` exists *only* under VEX, so `66 0f 38 18` is not an instruction at all and
the disassembler desynchronises from there. The lowering now requires the mnemonic to
have a direct SSE form, which is the check that was missing.

#### What remains

56,984 VEX instructions in `.text`, so it still faults:

```
would grow in place              25,887   SSE encoding one byte longer
overlapping windows              33,426   the second of two adjacent sites
outside .pdata                   15,465   not provably code
next instruction is a target      1,740   correctly refused
next transfers control            2,255   a displaced branch needs re-targeting
sequences (D, F, Y, H)           ~5,400   and the scratch register problem
```

The overlap and one-byte-growth cases are both addressable — a second pass would take
the sites the first refused — and neither needs new information. The remaining
sequences need a register allocator, which is the next real piece of work rather than
another special case.

### Finding 17 — the second pass, and what the residue really was

Finding 16 left 56,984 VEX instructions and a prediction about what they were. The
prediction was wrong in a useful way, and **measuring the residue rather than trusting
the projection is what found the remaining work**.

The projection said 33,426 sites had been lost to overlapping windows. They had not:
a swallowed Class C instruction is *lowered inside the stub that swallowed it*, so
those sites were already handled. What was actually left:

```
class A, SSE is 1B longer     23,029   <- never even considered for a detour
outside .pdata                17,234
no direct SSE form             9,428
class C, not detoured          4,484
class B, SSE is 1B longer      2,316   <- likewise
```

Two eligibility bugs, both the same shape: **a filter narrower than the machinery
behind it.**

**`detour.py` only ever considered Class C.** 25,345 class A and B sites were left
alone for no better reason than that their SSE encoding is one byte longer than the
VEX one, which is precisely what a stub exists for. A site that does not fit in place
and does have a lowering is a detour candidate whatever class it belongs to.

**The mnemonic tables do not list the compare forms.** objdump folds the predicate
into the name -- `vcmpneqps`, not `vcmpps` with an immediate -- so every compare
failed a table lookup and was filed under "no direct SSE form". The encoding still
carries the predicate as an imm8, so the SSE form is a plain prefix strip. Only for
the eight predicates SSE has: an AVX-only predicate would leave an immediate `cmpps`
cannot decode, and those still need the operand exchange of Finding 11.

Result:

```
VEX in .text            805,131 ->      33,492   771,639 removed, 95.8%
  in place                                       567,883
  detoured                                       167,697
size                102,242,144 -> 104,830,464   +2,588,320, the stub section
sections after .text                             byte-identical
boundaries lost              66,551              every one deliberately swallowed
swallowed instructions       67,554              none reachable by any branch
stub section                                     0 VEX, 167,697 jumps back
```

The counts close again: 67,554 swallowed minus 66,551 lost boundaries is 1,003,
exactly the sites refused for an ambiguous displacement.

#### The residue, measured rather than projected

```
outside .pdata (not provably code)      17,234
lowerable, no safe detour window        10,407
needs a real sequence (D/F/H/Y)          5,358   vblendvps 3,471, vbroadcastss 749,
                                                 vextractf128 379, FMA 237, ...
destination-in-vvvv (shift group)          304
(bad) -- data, not code                    180
four-operand form                            9
```

Only two of these are work rather than policy. The 10,407 without a window are mostly
sites whose following instruction transfers control -- a displaced branch needs
re-targeting, which is mechanical but is new machinery. The 5,358 sequences need the
Class D, F, H and Y rules, which exist and are tested, plus somewhere to get a scratch
register; that is the register allocator hard part 5 names, and it is the next real
piece of work rather than another special case.

The other 17,718 are deliberate: bytes not provably code, the shift group whose
destination lives in vvvv, and data.

### Finding 18 — a scratch register, without touching the stack

Hard part 5 is where to get a scratch for the multi-instruction sequences.
`tool/scratch.py` answers it, and the first thing to say is what it does **not** do.

**Spilling to the stack is the obvious answer and it is wrong here.** Win64 has no red
zone, so a stub would have to move `rsp` — and the stubs live in a section with no
`.pdata`, so `RtlVirtualUnwind` finds no unwind data, treats the stub as a leaf, and
reads the frame from an `rsp` that has moved. Anything walking the stack while a stub
runs — an exception, a sampling profiler — then gets a wrong answer. Four saved
instructions is a poor price for a broken unwind.

So the scratch has to be a register that is already dead, found by scanning forward
from the site. That is sound without a CFG because it never has to prove a register is
dead *everywhere*, only that nothing reads it before something overwrites it:

- a **full write** kills whatever the register held;
- a **call** kills xmm4 and xmm5 outright — volatile under Win64 and not argument
  registers, so no caller can expect them to survive and no callee is passed anything
  in them. xmm0-xmm3 are argument registers, so a call *reads* them; xmm6-xmm15 are
  preserved, so a call says nothing about them;
- anything else that transfers control ends the scan.

Scan depth is not the constraint — 60 instructions and 240 give 1,590 and 1,592 —
control flow is.

#### Most of these never needed a scratch

Measuring which sites actually need one was worth more than the allocator:

```
vblendv*, mask already in xmm0    1,362   none needed -- it is already where SSE wants it
vbroadcast*, writes its dst         772   none needed
vblendv*, needs a scratch         2,210   ->   773 found (35%)
FMA, needs a scratch                230   ->    51 found (22%)
256-bit (ymm)                       808   not a scratch problem at all
```

#### Result

```
VEX in .text            805,131 ->      24,871   780,260 removed, 96.9%
  in place                                       567,883
  detoured                                       176,121
size                102,242,144 -> 104,945,152   +2,702,751, the stub section
boundaries lost              67,043              every one deliberately swallowed
swallowed instructions       67,974              none reachable by any branch
stub section                                     0 VEX, 176,121 jumps back
```

67,974 swallowed minus 67,043 lost is 931, exactly the refused sites.

**A third filter narrower than its machinery.** A leftover `mnemonic not in nds` test
sat at the top of the candidate loop from when the detour engine handled only Class C.
It excluded every DIRECT-only mnemonic — `vcomiss` and its relatives — as well as
every sequence, long after the code below had learned to handle them. That one line
was worth 9,241 sites.

#### The residue

```
outside .pdata (not provably code)      17,234
lowerable, no safe window or no scratch  5,363
256-bit (needs the Y representation)       943
sequence not implemented                   847   vbroadcastss 694, vpermilps 65, ...
shift group (destination in vvvv)          304
(bad) -- data, not code                    180
```

`vbroadcastss` is the largest remaining sequence and needs **no** scratch — it writes
its destination outright — so it is a `movss` plus a `shufps` away. It is unfinished
here rather than hard.

### Finding 19 — the broadcasts, and a load width that matters

`vbroadcastss` was the largest unwritten sequence at 694 sites, and it needs no
scratch: it writes its destination outright.

```
vbroadcastss m32,%xmm0   ->  movss  m32,%xmm0        32-bit load
                             shufps $0,%xmm0,%xmm0   lane 0 to all four
```

**A single `pshufd $0` would do the whole job in one instruction, and it would be
wrong.** `VBROADCASTSS` reads 32 bits; `pshufd` reads 128. A source four bytes from
the end of a mapped page faults under the replacement where the original was fine —
a difference that would appear only on the pages where it matters and never in
testing. The narrow load stays narrow and the spread is a separate register-to-
register instruction.

`vbroadcastsd` is the one case where a single instruction is honest: SSE3's `movddup`
reads exactly 64 bits and duplicates them. `vpbroadcastd` takes `movd` plus
`pshufd $0`, integer domain throughout.

Verified by disassembling the stubs rather than trusting the encoder — `f3 0f 10 00`
followed by `0f c6 c0 00` is a 32-bit load and a broadcast, and there are no invalid
decodes in the section. 71 RIP-relative broadcast stubs had their resolved target
compared against the original instruction's, with no mismatches.

```
VEX in .text            805,131 ->      24,001   781,130 removed, 97.0%
size                102,242,144 -> 104,957,440   +2,714,651, the stub section
boundaries lost              67,219              every one deliberately swallowed
swallowed instructions       67,974              none reachable by any branch
stub section                                     0 VEX, 176,815 jumps back
```

One crash on the way, worth recording because it was in the *checking* rather than
the output: `collect()` trial-lowers each candidate to find out whether its shape is
handled, and passed a placeholder address of zero. The RIP displacement arithmetic
then overflowed a signed 32-bit field and raised rather than answering the question.
The trial uses the site's own address now, and both displacement computations refuse
a site that will not fit rather than crashing — which cannot happen today, since the
stubs sit 144 MB from `.text`, but a crash is a poor way to learn that stopped being
true.

#### The residue after the broadcasts

```
outside .pdata (not provably code)      17,234
lowerable, no safe window or no scratch  5,187
256-bit (needs the Y representation)       943
shift group (destination in vvvv)          304
(bad) -- data, not code                    180
sequence not implemented                   153   vpermilps 65, FMA 132/213 forms 88
```

The 153 left are `vpermilps` with variable control, which is the Class H helper call
rather than an inline sequence, and the FMA orderings other than 231 — `lower_fma`
handles only `dst = src1*src2 + dst`, and the 132 and 213 forms put the addend
somewhere else. Both are small and known.

### Finding 20 — the vpermilps helper, inlined rather than called

Class H was specified as a `call` into a hand-written routine. **In a stub it must not
be a call**, and for the same reason spilling was rejected in Finding 18: a `call`
pushes a return address, so `rsp` moves inside code with no `.pdata`, and any stack
walk during the helper reads a bogus frame. Stub space is free, so the sequence is
inlined.

`src/permil.c` keeps its value as the *tested specification* — exhaustive over all 256
permutations and mutation-checked — and the emitted code matches it instruction for
instruction:

```
pand   [pool+0x00],%xmm7      bits 1:0 of each control element
pslld  $0x2,%xmm7             element index -> its first byte
pshufb [pool+0x10],%xmm7      replicate that byte across the element
paddb  [pool+0x20],%xmm7      ... and step through its four bytes
movaps %xmm2,%xmm1            destination takes the data
pshufb %xmm7,%xmm1            the permute itself
```

The three constants live at the start of the stub section. That placement is not
cosmetic: a non-VEX SSE instruction with a memory operand faults on an unaligned
address, and the section begins on a page boundary, so offset zero is 16-byte aligned
by construction.

**The immediate form needed none of this.** It is a `shufps` with both operands the
same register, and 50 of the 53 sites handled here are that. Only 3 of the
variable-control sites could be done, because only 3 have a dead register to build the
byte control in — the control operand itself is never dead at any of them.

```
VEX in .text            805,131 ->      23,948   781,183 removed, 97.0%
```

#### What the remaining vpermilps needs

20 sites, and they are not all the same problem. Eight are 256-bit and need the Y
representation. The rest want a scratch that the forward scan cannot find. Nothing
here is a missing rule: the rule exists, is tested, and is emitted correctly where a
register is available.

### Finding 21 — the FMA orderings, and what actually blocks them

`lower_fma` handled one shape: `vfmadd231{ps,ss}`. It now handles every
multiply-add the binary contains — the 132 and 213 orderings, the subtract and
negated forms, and the memory-operand cases.

The 132/213/231 suffix says which operand is the addend, and in AT&T order, where
the operands print as src2, src1, dst:

```
132   dst = dst  * src2 + src1
213   dst = src1 * dst  + src2
231   dst = src1 * src2 + dst
```

That mapping was checked symbolically against the SDM formula for ten shapes before
any of it ran, with no mismatches. It is the part where an error would be invisible:
every ordering produces a plausible-looking sequence and only one is right.

**The scalar forms carry a trap.** `VFMADD213SS` leaves `DEST[127:32]` *unchanged*,
so the result cannot be moved back with a `movaps` — that would overwrite the upper
lanes with whatever the scratch held. `movss` and `movsd` write only their own width,
which is exactly what is wanted.

`vfnmsub` does not occur in this binary, which is worth knowing: it is the one form
needing a genuine negation, and therefore a sign-mask constant. `vfmsubadd` is
refused — its lane pattern needs both results and a blend, so a second scratch.

#### What actually blocks the FMA sites

The orderings were never the constraint. Across all 421:

```
256-bit (needs the Y representation)   191   45%
no dead register                       126   30%
memory operand                          70   17%   -- now handled
lowerable                               34    8%
```

Adding every ordering and the memory operand together moved 25 sites. **Register
pressure and the 256-bit representation are what stand between here and the rest**,
and neither is a missing rule.

```
VEX in .text            805,131 ->      23,923   781,208 removed, 97.0%
```

#### A stale artifact, and the rule that exists for it

An emitted stub appeared to jump into the middle of another one — a corruption that
would have been catastrophic. It was not real: `build/after.asm` had been
disassembled before the last change and compared against a binary rebuilt after it.
The stub was correct all along.

`build-and-commit.md` states the rule as never concluding a test passes or fails from
a binary the build step did not rebuild. The same applies to a *disassembly* of one,
and an ad-hoc `objdump` has no dependency on the thing it describes, where `make`
would have. Half an hour went into chasing it.

### Finding 22 — what a detour actually costs, measured

The cost model in this document counts instructions and says +1.34%. It does not
model the front end at all, and the fair objection to the whole approach is that
176,893 jumps into a section 144 MB from `.text` will cost far more in fetch and
instruction-cache behaviour than they do in issue slots.

That is measurable here, and unusually directly: **this machine is the target**, a
Xeon X5675 with a 32 KB 4-way L1i. `tool/icache_bench.c` generates the same loop
twice at run time -- once straight, once with every Nth adjacent pair replaced by a
jump into a stub that performs the pair and jumps back, which is the widened-window
shape of Finding 16 -- with the stubs mapped 64 MB away so they share no page and no
cache set with the body.

At the real density of **1.07% of instructions**:

```
mix                          3 KB body   24 KB    96 KB
SSE addps  (one FP port)         +0.1%    +2.0%    +1.1%
mov r8-r11 (dependency chain)    -0.6%    +2.0%    +2.4%
3-byte nop (saturates nothing)  +12.0%   +10.5%    +8.4%
```

**The spread between the mixes is the finding, and it is larger than the density.**
`addps` saturates the single FP add port, so the jumps issue elsewhere and their
fetch bubbles overlap with work that was going to take that long anyway. Nops
saturate nothing, so the same bubbles are fully exposed.

That matters for reading the number. This binary is **52% scalar float by instruction
count** -- it looks far more like the first row than the third -- but quoting only the
first would understate a detour that lands in a stretch of pointer chasing or integer
setup. The honest bracket is **1-2% where the code is FP-bound, up to about 10% where
it is not**.

The shape of the curve is worth as much as the point:

```
detour density   addps    nop
       1.07%     +1.1%   +8.4%
       2.13%     +3.8%  +19.8%
       6.25%    +31.1%  +74.7%
      12.50%    +75.2% +142.1%
      25.00%   +204.3% +281.9%
```

Cost is roughly linear in density until about 6%, then runs away. **The objection that
this approach produces a slideshow assumes a density around 25%** -- and at 25% it
would be right. The measured rate is a twentieth of that, because VEX is only 4.87% of
this binary to begin with and 70.5% of those sites never become detours at all.

#### What this does not measure

The benchmark controls density and working-set size; it does not know **where** the
detours fall. That is Finding 23.

It also measures a loop with perfect branch-target locality after the first pass. A
detour taken once and never again pays a cold miss this does not model.

### Finding 23 — where the detours land

Finding 22 measured what a detour costs and could not say where they fall. Execution
counts need the game running, but the structure is in the binary and carries most of
the question. `tool/placement.py`, `make placement`.

**Four fifths of the code is untouched.** Weighting by instructions rather than
counting functions, because the dense ones are small:

```
density        functions  instructions  % of .text  measured slowdown
  none           222,348    11,282,539      79.75%      1.00
  0-1%             1,652       667,603       4.72%      1.01
  1-5%             4,483     1,067,253       7.54%      1.03
  5-10%            3,041       562,016       3.97%      1.31
  10-25%           3,738       456,785       3.23%      1.75
  over 25%         1,165       111,633       0.79%      3.04
```

The tail that the benchmark says is genuinely expensive — over 25% density, where the
same loop runs three times slower — is **0.79% of `.text`**. Only 6.0% of functions
contain a detour at all.

Weighting those measured slowdowns by static code volume gives **+5.5%**. That figure
assumes execution time is spread like code size, which it certainly is not, so it is
an upper bound on the average rather than a prediction.

#### The loop metric, which is the one that matters

A whole-binary average says nothing about a detour inside an inner loop, which is paid
every iteration. A backward branch whose target lies in the same function is a loop,
and its body is the span between them — findable without a CFG or symbols. 150,881 of
them:

```
loop body size      loops   containing a detour
  0-64B            73,334        472    0.6%
  64-256B          41,509      1,823    4.4%
  256-1024B        29,121      4,470   15.3%
  1024-4096B        5,284      1,141   21.6%
  4096B+            1,633        208   12.7%
```

**The tightest loops are 99.4% clean.** That is the shape a hot inner loop has, the
shape most likely to sit in L1i, and therefore the shape where a jump to a section
144 MB away would hurt most — and it is almost entirely untouched. Detours concentrate
in large bodies, which are more often straight-line arithmetic than iteration.

#### The honest residual risk

The densest functions are vectorised maths — the worst is 57.6% detoured and reads
`vshufps`/`vmulps`/`vrcpps`, a reciprocal or normalise kernel. That is exactly the
kind of routine that *can* be hot. 1,165 such functions exist and none of this says
whether any of them runs often.

So the bound is: if the hot set is dominated by tight loops, the cost is near zero,
because 99.4% of them contain nothing. If it is dominated by a handful of dense SIMD
kernels, those specific routines run about three times slower. Which is true needs a
profile, and a profile needs the binary to run.

### Finding 24 -- the code `.pdata` does not describe

With the detour engine complete, the largest remaining refusal was not a missing
lowering rule. It was the code oracle declining to vouch for bytes:

```
outside .pdata                       16,256      68% of everything left
next instruction transfers control    2,968
next instruction is a branch target   2,044
sequence with no usable scratch       1,850
no direct SSE form                      710
sequence shape not handled               89
operand shape not A/B/C                   9
```

`function_ranges` had already named the cause -- the x64 ABI lets a function that
neither allocates stack nor calls anything omit its unwind data -- and estimated
14,162 sites lost to it. What it could not say was how many of the 16,256 were that,
and how many were objdump walking into data. **The two need opposite work**: a leaf
function's VEX must be lowered, and a constant pool that happens to decode as VEX
must be left alone, because "patching" it corrupts the data.

`tool/outside.py`, `make outside`, answers it. The first attempt got it wrong in a
way worth recording: it grouped each run of non-`.pdata` instructions and tested
whether anything branched to the run's *first* address. But MSVC pads between
functions with `int3`, so a run begins with padding, and every genuine leaf function
came back "unreferenced". **Splitting the run at its padding is what makes the test
ask about the function rather than about the gap before it.**

The second error was the target set. `targets.py` recovers branch targets from
`.reloc`, `.pdata`, `.xdata` and switch tables, and **a `call rel32` is none of
those** -- it is PC-relative, carries no relocation, and appears in no table.
Scanning the disassembly for direct calls and jumps adds 1,093,239 more targets and
moves 656 chunks from "uncalled" to "called". 0x1402a9fa0 is the shape of the class:

```
vmovaps %xmm1,%xmm2               called twice, from 0x142661c35
vxorps  %xmm1,%xmm1,%xmm1         and 0x142661d14
vmovss  %xmm2,%xmm1,%xmm2
vinsertps $0x30,%xmm2,%xmm0,%xmm0
ret
```

Pure register work and a `ret`: it touches no stack and calls nothing, so MSVC omits
its unwind data exactly as the ABI permits.

#### Why the extension is sound rather than merely permissive

Four conditions, each ruling out a different way of being wrong: bracketed by `int3`,
entered by a call or jump, ending in a control transfer, and containing no byte
objdump failed to decode.

The load-bearing one is the second, and the argument is about **alignment, not
appearance**. The chunk's first address is the target of a real call, so the sweep is
provably on an instruction boundary there; x86 decoding forward from a known-correct
boundary is deterministic, so every instruction in the chunk is correctly decoded;
and the terminating `ret` or `jmp` confirms the chunk is a whole function rather than
the sweep running past its end. Nothing here rests on the code looking plausible.

```
called, and ends in a transfer     2,074 chunks   13,813 sites   accepted
uncalled, ends in a transfer         868 chunks    3,343 sites   refused
called, but runs off the end          43 chunks      129 sites   refused
contains (bad) -- not code            20 chunks      315 sites   refused
uncalled, runs off the end             1 chunk         4 sites   refused
```

`outside .pdata` fell from 16,256 to 3,378.

### Finding 25 -- the aliasing bug the extension uncovered

Reaching further into the binary put a stub under inspection that turned out to be
wrong, and the fault was not in the new oracle. It was in the Class C lowering, and
it had been there since Class C was written.

`vmovss %xmm2,%xmm1,%xmm2` is src2 `%xmm2`, src1 `%xmm1`, destination `%xmm2`. The
lowering emitted:

```
movaps %xmm1,%xmm2        the destination is set up from src1 ...
movss  %xmm2,%xmm2        ... which has already destroyed src2
```

`lower_vex` decided whether to emit the leading `movaps` by testing whether the
destination differed from src1. It never tested whether the destination *was* src2 --
in which case that `movaps` overwrites src2 before the operation reads it.

**9,000 sites, and the worst of them are silent.** `vsubss` is the most common at
1,210, and it is not commutative: `vsubss %xmm0,%xmm1,%xmm0` should compute
`xmm1 - xmm0` and instead became `movaps %xmm1,%xmm0; subss %xmm0,%xmm0`, which is
**always exactly zero**. Nothing about that output looks wrong. It assembles, it
disassembles, it carries no VEX, and every structural check the verifier makes passes
-- because every one of them is about *shape*, and this is about *meaning*.

Swapping the operands would fix the commutative cases and quietly break the rest.
Even where the arithmetic commutes the NaN propagation does not: x86 chooses which
source NaN survives by operand order. That is the same trap `src/fmaddsub.c` fell
into, where negating the addend to reuse `addsubps` disagreed with the hardware on
291 vectors, every one of them a NaN. So src2 is preserved in a scratch and the
operand order is kept exactly as the VEX form had it:

```
movaps %xmm2,%xmm4        scratch <- src2
movaps %xmm1,%xmm2        destination <- src1
addss  %xmm4,%xmm2        src1 OP src2, in that order
```

1,524 of the 9,000 find a scratch; 6,232 do not and are now refused rather than
mis-lowered. **Coverage went down, from 98.7% to 97.8%, and that is the fix working.**

#### The check that would have caught it

`make check-aliasing`, and the condition is one sentence covering every class: **at
the final operation, the reg operand must still hold the original src1 and the rm
operand the original src2.** Class A and B satisfy it by emitting nothing first;
Class C has to satisfy it while inserting a `movaps`, and the aliasing case while
inserting two.

It needs no execution and no AVX machine, which matters because this one has neither.
Each lowering is assembled, lowered, and disassembled back, and the register moves are
simulated symbolically -- so what is tested is the bytes that would actually be
written rather than a rule table's description of them. Disabling the fix makes it
report all 16 aliasing shapes and neither of the two controls, which is what says the
test discriminates rather than merely passes.

### Finding 26 -- one selection rule, executed once

The aliasing fix made the verifier fail: 356 boundaries lost that were not swallowed
on purpose. The binary was correct; the checker was wrong.

`apply` and `verify` each carried their own copy of the rule for choosing which
candidates become detours. A candidate whose stub cannot be built is refused and
writes nothing, so `apply` left its window uncommitted and went on to detour a later
site inside it. `verify`'s copy committed the window regardless, so it never expected
that later site -- nor the instruction its widened window swallowed.

The divergence had been there the whole time. What made it visible was refusals
rising from 762 to 2,402 when the aliasing check started declining sites with no
scratch. **A model of a rule is a second implementation, and two implementations of
one rule drift.** `place_stubs` is now the only copy and both call it.

The `NameError` that followed is worth one line, because it is `build-and-commit.md`'s
rule again: the refactor broke `apply`, `apply` wrote nothing, and `verify` ran
happily against the binary left over from the previous run and reported a clean pass.
The output is deleted before the run now, so a crash cannot leave a stale artifact
for the next step to bless.

### Finding 27 -- the scan was stopping at branches, not running out of room

The aliasing fix left 6,232 sites refused for want of a scratch register, and the
obvious remedy -- scan further -- turned out to be worth almost nothing. Measured
rather than assumed:

```
a branch ends the scan     5,255      85%
call, xmm4 and xmm5 live     370
ret                          332
limit reached                170       widening the window buys this many
```

`limit` was never the constraint. **The scan stopped at the first branch**, because
the module was written to avoid needing a control flow graph.

It still does not need one. An unconditional jump has exactly one successor, so the
scan continues there; a conditional branch has two, and a register is free only if it
is free on **both**, so the two answers are intersected. Anything unresolvable -- an
indirect jump, a target outside the listing, a back edge, an exhausted budget --
contributes the empty set. That is the conservative direction by construction: it can
only refuse a register that was in fact free, never claim one that was live.

A `ret` was also made to free xmm1 to xmm5. They are volatile under Win64, so the
caller of the function about to return cannot expect them to have survived; xmm0 is
excluded because it carries the result.

Sites that can get a scratch went from 21,735 to 27,016.

#### Two checks, because this is the direction that is dangerous to get wrong

Claiming a live register corrupts arithmetic silently, exactly as Finding 25 did. So
the change carries two pieces of evidence rather than a plausibility argument.

**It never loses.** Every site where the old scan found a register, the new one finds
one too -- 0 regressions across 33,702 sites. A new answer that differs is a
different *valid* choice, since the old scan returned the first kill it met and this
one returns the lowest free register.

**Every claim is verified the other way round.** `make scratch-check` enumerates
concrete paths one at a time and asks of each whether the register is written before
it is read, where `find_scratch` recurses and intersects dead sets. A fault in the
intersection or the union appears here as a path the set arithmetic missed. All
27,016 claims pass, with none unverifiable.

Writing it twice earned its keep immediately, though not in the direction expected.
The first version of the checker tested `register in sources` before `kills ==
register` and reported 597 violations -- every one of them a zeroing idiom, which
names its register as a source and does not read it, which is the entire reason
`ZEROING` exists. **The checker was wrong and the search was right**, which is
`evidence.md`'s rule about suspecting the gate first, arrived at from the other end:
the code was checked before the gate was believed.

### Finding 28 -- widen the window backwards, not just forwards

A site shorter than five bytes cannot hold a jump, so its window has to widen
over a neighbour. **Which neighbour decides which address ends up inside the
window, and the one inside is the one nothing may branch to.**

Widening forward keeps the window's first byte where the site already is and
swallows the instruction that follows. Widening backward puts the first byte on
the previous instruction and swallows the site itself. The second reaches sites the
first cannot, for two reasons that are both properties of compiler output: a
compiler branches to the top of a block far more often than into the middle of one,
and the instruction after a site is frequently a `call` or a jump, which cannot be
swallowed at all.

Measured before it was written -- 3,237 sites that forward widening cannot reach and
backward widening can. The two forward skip reasons collapsed:

```
                                       before   after
next instruction is a branch target     1,732     505
next instruction transfers control      2,334     441
```

The previous instruction must still fall through into the site, so anything that
transfers control rules it out. A `call` is excluded for a sharper reason than
falling through: it returns to the site, and that return would land in the middle of
a window.

The gain in finished sites is smaller than 3,237 because overlap absorbs much of it
-- windows that now extend backwards collide with windows already committed, and
skipped-for-overlap rose from 33,375 to 35,401. Net, VEX fell from 15,647 to 14,757.

### Finding 29 -- a register a whole function never touches

The forward scan asks "is this register overwritten before it is read on every path
from here", and where it cannot get an answer the site is refused. There is a second,
much weaker question that sometimes answers when the first cannot: **is the register
named anywhere in this function at all?**

If xmm4 appears nowhere in a function then nothing in the function reads it; no callee
can expect it, because nothing is passed in it; and no caller can expect it, because
it is volatile. So it is free at *every* point in that function, including points no
forward scan can reach.

Only xmm4 and xmm5 qualify. **xmm0 to xmm3 cannot join them**, and the reason is worth
recording because it is not obvious: a wrapper that calls `g(a, b, c)` forwards its own
arguments in place and never names them, so "unmentioned" does not imply "unread" for
an argument register.

#### The check earned its keep twice more

Adding the rule made `make scratch-check` fail with 22 claims that a path reads. Both
causes are the same thing -- **a `.pdata` entry is not always a whole function** --
and neither was visible from the rule as stated:

  * **Falling off the end.** 0x140a234dd ends at 0x140a235f2 with no terminator and
    runs straight into the next entry, which reads xmm4. The first version looked
    only at jumps leaving the range and missed fall-through entirely.
  * **A branch to another entry.** Treating that as a tail call, and so as an ABI
    boundary, is wrong: the same function's other half has an entry of its own, and
    `je 0x140a2371f` in that range goes to it.

The rule is now the blunt one -- any jump out of the range, any indirect jump, and any
range not ending in a control transfer disqualifies it. Real tail calls are lost with
them, which costs coverage and nothing else. 1,501 sites were predicted before the
tightening and 668 claims rest on the argument after it.

That is twice now that this check has caught something the reasoning behind a change
had missed, and once that it was itself the thing at fault. Its value is not that it
agrees; it is that it is written from the other end.

### Finding 30 -- the third way a function is reachable

3,343 sites sat in 868 chunks that were shaped exactly like functions --
`int3`-bracketed, cleanly decoded, ending in a transfer -- and that **nothing
appeared to reference**. Neither `.reloc`, nor `.pdata`, nor a switch table, nor any
direct call or jump in 16.5 million instructions.

Before deciding whether to touch them, the question was whether anything reaches them
at all. `.reloc` is complete for absolute addresses by construction, and direct calls
and jumps are in the disassembly, so one path remained: a RIP-relative operand. There
are 1,192 landing inside these chunks, **every one of them a `lea`**, and 865 of the
868 chunk starts are the target of one.

`lea rax,[rip+f]` is how MSVC takes a function's address, and it is **PC-relative, so
it produces no relocation** -- `.reloc` is complete for absolute addresses and this is
not one. It is not a call either. A function whose address is only ever taken this way
is invisible to both of the other scans.

What they are is legible once found: a copy constructor at 0x1402ce510 doing a
`vmovups` pair and a `lock xadd` on a refcount, a setter at 0x140544cf0 storing one
float and returning `this`. 99.9% are 16-byte aligned and 813 of 868 end in `ret`.
Nothing calls them because every call site inlined them, and the linker kept the
out-of-line COMDAT copy that address-taking requires.

`outside .pdata` fell from 3,570 to 397, and coverage from 98.3% to 98.7%.

#### It was a safety question too, and the answer was luck

An address taken by `lea` can be called through the pointer, which makes it a branch
target -- and a branch target inside a detour window is an indirect call landing in
the middle of a jump. 164,395 such addresses exist in this binary.

Measured against the output as it then stood: **none of them fell strictly inside a
committed window.** So nothing was wrong. But that is an observation about one binary
rather than a property of the rewriter, and the three scans now feed one set, so it
is a property.

### Finding 31 -- executing the lowerings, on a machine that cannot execute the input

Everything the suite proved about Classes A, B and C was about **shape**: that each
lowering assembles, and that no VEX prefix survives. The src2-aliasing bug of Finding
25 satisfied both while computing a constant zero. Nothing had ever run one.

The obstacle looks fatal and is not. There is no AVX here to produce a reference from
-- but **this machine can execute the output even though it cannot execute the
input**, which is the whole premise of the project turned into a test. The reference
comes from GCC compiling the equivalent SSE intrinsic: a different encoder, a
different register allocator, and no knowledge of what this project believes the
answer to be.

`tool/lowering_cases.py` generates the cases from `detour.lower_vex` itself, so they
cannot drift from what the rewriter emits, and `test/lowering_test.c` runs them.
37 mnemonics across three operand shapes -- `distinct`, `dst_is_src1` and
`dst_is_src2`, that last being the Finding 25 case -- give 111 cases and 888
executions. `make check-lowering`.

Each case loads all sixteen xmm registers, executes the lowered bytes, and stores all
sixteen back. **Comparing only the destination would not have been enough**: a
lowering that computes the right answer and clobbers a bystander is still wrong, so
every register must be unchanged except the scratch, which a lowering is entitled to
destroy.

#### What the mutants show

A passing test is not evidence until it has been shown to fail. Disabling the
aliasing fix produces 250 wrong comparisons, every one in the `dst_is_src2` shape,
with `distinct` and `dst_is_src1` still passing.

The second mutant is the more interesting one, because it re-examines a decision.
Finding 25 rejected swapping the operands -- the cheap fix for the commutative cases
-- on the argument that NaN propagation is ordered. That argument is now a
measurement. Building the swap and running it gives 201 wrong comparisons, and the
distribution says exactly where it would have mattered:

```
vaddps, vmulps      wrong only on the all-NaN inputs
vminps, vmaxps      wrong on ordinary inputs too -- min and max return src2
                    when either operand is NaN, so they never commuted
vpand, vpor, vpxor  not wrong at all
vpaddd, vandps      -- no floating-point semantics, so the swap is harmless
```

So the rejected fix was wrong, and wrong in a narrower way than the argument
implied: safe for the bitwise operations, unsafe for the arithmetic ones, and unsafe
everywhere for min and max.

#### The inputs had to be measured too

The first version of the test put a NaN in only one source at a time, because
register `r` receives pattern `(p + r)` and the two sources of a case are always a
fixed distance apart in the table. **With one NaN either operand order returns it**;
only with two does the choice of which survives become visible. That version caught
the swap in `vaddps` and missed it in `vmulps`, `vpand`, `vpor`, `vpxor`, `vpaddd`,
`vandps` and `vxorps` -- and the gap was found by running the mutant, not by reading
the test. Three consecutive all-NaN rows fixed it.

A generated case with no reference in the C file is a failure, never a skip, so a
mnemonic added to the generator cannot silently stop being covered.

### Finding 32 -- milestone 2: a PE built here, rewritten here, and run

Every claim about the Starfield rewrite is structural, because that binary cannot be
run here: it is a Windows program, this is Linux, and it wants AVX from a CPU that
has none. **A PE this project builds itself removes both obstacles at once** -- wine
answers the first, and the second stops being an obstacle and becomes the experiment.

The asymmetry is the whole test. The original must fail, because its second
instruction is AVX and this Westmere does not implement it. The rewritten one must
run and return the right answer. Neither result means much alone.

```
original    exit 29     0x1D, the low byte of STATUS_ILLEGAL_INSTRUCTION
rewritten   exit 169    the answer
```

`make check-pe`, five seconds from clean. There is no mingw here, so `tool/pe_build.py`
assembles with `as` and writes the headers itself -- less of a detour than it sounds,
since `detour.py` already appends a section to a 102 MB PE without disturbing it, and
these are the same fields read from the other side. No imports and no relocations:
returning from a PE entry point ends the thread with that value as the exit code, and
leaving `DllCharacteristics` at zero means the image loads at its preferred base.

#### What the program is chosen to do

The arithmetic exists to make one instruction observable:

```
vsubss %xmm0,%xmm1,%xmm0     dst = src1 - src2, with dst AND src2 both %xmm0
```

That is Finding 25's aliasing case. Lowered correctly it is 10 - 3 = 7 and the
program returns 169. Lowered the way the bug did it -- `movaps %xmm1,%xmm0` then
`subss %xmm0,%xmm0` -- it is 0 and the program returns 36. **Rebuilding the rewriter
with the fix removed and running it produces 36**, so the test discriminates rather
than merely passes.

The whole chain is visible in the output. The site is four bytes, too short for a
jump, so it widens over the eight-byte `vmovss` that follows into a twelve-byte
window, and the stub reads:

```
movaps %xmm0,%xmm4              scratch <- src2
movaps %xmm1,%xmm0              destination <- src1
subss  %xmm4,%xmm0              src1 - src2, in that order
movss  -0x2ffa(%rip),%xmm2      the swallowed instruction, displacement redone
jmp    0x140001024              back past the window
```

The scratch is `%xmm4`, chosen by the whole-function rule of Finding 29: the function
names only `%xmm0` to `%xmm3`, ends in a `ret`, and jumps nowhere.

#### Two things it checks that were not the point

The constants sit in `.text` past the code and are loaded RIP-relatively, so a linear
disassembly walks straight into them and decodes nonsense. `.pdata` covers the
function only. **They come out byte-identical**, which is the code oracle doing its
job on a case small enough to read.

And the test asserts the original *fails*. On a machine with AVX it would return 169
and prove nothing -- a vacuous pass of exactly the kind `evidence.md` describes -- so
that outcome is a failure with its own message.

#### An aside worth keeping

The expected crash first cost two minutes per run: wine starts winedbg on an
unhandled exception and waits. `AeDebug` did not help, and `Auto=0` made it worse,
that value meaning *prompt* rather than *do not launch*. Disabling winedbg outright
with `WINEDLLOVERRIDES=winedbg.exe=d` returns the same crash in no time at all. It is
the crash-handler-attaches-a-debugger pattern from `running-code.md`, met from the
other side: here the debugger was hanging a test rather than eating 15 GB, and the
fix was the same -- do not let it attach.

### Finding 33 -- three programs, each aimed at the machinery

Extending `check-pe` is cheap now that the harness exists, and the programs worth
adding test the **rewriter**, not the arithmetic -- `check-lowering` already executes
the lowerings across 37 mnemonics. What only a whole binary can exercise is windows,
branch targets, RIP displacements moved into a stub, and the code oracle.

```
aliasing  169   dst == src2, the Finding 25 shape; 36 if it regresses
memory     16   a site whose own source is memory, detoured 12 KB away
branch      6   a four-byte site with a branch target immediately after it
```

Every one begins with `vzeroupper`, which has no SSE form and must be *erased* rather
than lowered. This CPU faults on it, so a program that runs at all proves Class Z
worked.

The third is the interesting one. Forward widening must refuse it -- swallowing the
next instruction would leave the branch landing in the middle of the five-byte jump
that replaced it -- so backward widening takes the `nop` in front instead, and the
window comes out exactly five bytes with no padding:

```
   14000101c:  74 05                je     0x140001023
   14000101e:  e9 0d 30 00 00       jmp    0x140004030     <- the window
   140001023:  f3 0f 58 c0          addss  %xmm0,%xmm0     <- still a boundary
```

The branch is taken at run time, so the target really is entered. Had the rewriter
swallowed it, the program would not merely compute the wrong number -- it would jump
into the middle of an instruction.

### Finding 34 -- the shift-by-immediate forms, which were invisible

Counting what actually survived, by mnemonic, turned up a class the rewriter had
never attempted: `vpsrld`, `vpslld`, `vpsrlq` and their relatives, 323 sites. They
were not refused for any recorded reason. `collect` skipped `DESTINATION_IN_VVVV`
outright and **without counting it**, so they were part of the residue this document
could not account for.

The guard was right and too broad. VEX puts the destination in `vvvv` and uses
`modrm.reg` as an opcode extension, so `modrm.rm` names the *source* -- dropping the
prefix leaves an SSE instruction that writes the source register while looking
entirely reasonable. But that is only true when the two registers differ:

```
c5 f1 72 d1 02    vpsrld $0x2,%xmm1,%xmm1
66 0f 72 d1 02    psrld  $0x2,%xmm1          same modrm, same length
```

Equal registers means the same bytes with a different prefix, and the same length, so
`patch.py` takes it in place. Where they differ the source is copied first:

```
vpsrld $0x2,%xmm1,%xmm0  ->  movdqa %xmm1,%xmm0 ; psrld $0x2,%xmm0
```

`movdqa` rather than `movaps`, which would move the same bits in a byte less: these
are integer instructions and Westmere charges a bypass delay for a value crossing
between the integer and floating-point domains.

Nine mnemonics went into `check-lowering` with them, in both shapes, taking it to 129
cases and 1,032 executions. Mutating the lowering to leave `rm` pointing at the
source is caught 144 times over -- and the diagnostic is worth reading, because it is
the *bystander* check that catches it: `xmm0` holds the unshifted source and `xmm1`
holds the shifted value. Comparing only the destination would have seen a wrong
answer without ever showing where the write went.

VEX in `.text` falls from 10,618 to 10,276.

### Finding 35 -- the accounting question, closed, after two wrong guesses

`make census`. The residue this document called unaccounted was being computed by
subtracting the skip tallies from the survivor count, and **that subtraction was the
mistake**: the two measure different populations. Comparing address sets instead of
totals reconciles them exactly:

```
VEX in the rewritten .text     10,276
  declined by the collector     6,728
  refused, stub not buildable   2,449
  inside a committed window         0
  skipped for overlap           1,018
  undecodable, never classified    81
  unaccounted                       0
```

Getting there cost two hypotheses, both stated confidently and both wrong.

**That declined sites were being swallowed by a neighbour and lowered in its stub.**
Refuted outright: not one of them is inside a committed window.

**That the leftovers were the disassembler inventing VEX prefixes** in bytes it had
desynchronised on. Also wrong, and this one was checkable in a single line: every one
of the 3,548 was an instruction boundary *and* a VEX site in the original. None of it
was the sweep.

What was actually wrong was the census itself. **A window is a range, and one widened
backwards does not start at the site** -- so testing a surviving address against a set
of window *starts* missed every site whose window began on the instruction before it.
1,102 sites looked mysterious because of an off-by-one-instruction in the tool asking
the question, not in the tool being asked about.

Two of the buckets are worth reading as findings rather than bookkeeping:

- **Nothing survives inside a committed window.** That row is zero, and it is the
  strongest single statement in the census: wherever the rewriter committed to a
  window, every instruction in it was lowered.
- **1,018 sites are lost to an interaction between backward widening and overlap.**
  A backward-widened candidate starts on the instruction *before* its site. If that
  earlier byte falls inside a window already committed, the whole candidate is
  refused for overlap -- even where the site itself lies outside that window and
  could have been taken forwards, or in place. That is a real opportunity, not a
  cost that has to be paid, and it is the cheapest 1,018 sites on the list.

### Finding 36 -- take the next one with you

Finding 35's census left a lead rather than a cost: 1,018 sites lost where only a
backward-widened candidate's *start* collided with a committed window. Measured
before anything was written, and the measurement decided the design -- **in all
1,053 such candidates the covering window ended exactly at the site.** Not most. All
of them.

That makes the fix a small one. Before committing a window, look at the candidate
that follows: if it widened backwards, if the start it needs is inside this window,
and if its site sits exactly at this window's end, then extend this window by that
one instruction and lower it in this stub. It is safe for the same two reasons the
candidate itself was -- the site is not a branch target, or backward widening would
never have been allowed to swallow it, and the extended window stays inside one
function, because the two windows overlap and each was already checked.

A rescued site is visible end to end. Three consecutive Class C instructions, the
middle one unreachable any other way:

```
1402ccf56:  e9 61 06 6c 08    jmp 0x14898d5bc      one window, three instructions
1402ccf5b:  0f 1f 80 ...      nopl
1402ccf62:  c3                ret                  untouched
```
```
14898d5bc:  movaps %xmm1,%xmm2 ; addss %xmm0,%xmm2
            movaps %xmm3,%xmm1 ; mulss %xmm3,%xmm1
            movaps %xmm2,%xmm0 ; addss %xmm1,%xmm0
            jmp    0x1402ccf62
```

The dependency between them survives because they are emitted in order: the second
computes `%xmm1` and the third consumes it.

#### The passenger must not cost the ride

The first version marked the rescued candidate as consumed before knowing whether
the extended stub would build. 26 of them did not build, and those sites then
belonged to nobody -- not placed, not overlapped, not refused. **The census caught
it immediately**, which is the second time that tool has found something the change
that produced it did not.

Building the extended stub first and falling back to the plain one restores them.
Taking a passenger along now never costs the stub that was going anyway.

```
skipped for overlap    1,018 -> 97
VEX in .text          10,276 -> 9,355   (before Finding 37 corrected it)
unaccounted                      0
```

### Finding 37 -- every number above was too high: 256-bit was being truncated

**`sse_encoding` never looked at `VEX.L`.** Dropping a VEX prefix from a 256-bit
instruction leaves a perfectly valid 128-bit one, and the rewriter was doing exactly
that:

```
c5 fc 11 00   vmovups %ymm0,(%rax)     stores 32 bytes
0f 11 00      movups  %xmm0,(%rax)     stores 16, and nothing complains
```

**32,749 sites in place, and about 2,200 more through the detour path.** Half of
every one of those writes was being discarded. The upper 128 bits of the source were
never stored, and where the pattern was a 256-bit load the upper half of the
destination kept whatever it happened to hold.

Nothing caught it, and the reasons are worth more than the fix:

- **Every structural check passed, because every one of them is about shape.** The
  bytes assemble, disassemble, carry no VEX, sit at the right addresses, and
  reconcile perfectly in the census. A truncated store is a correct instruction; it
  is simply the wrong one.
- **`check-lowering` executes 1,032 lowerings and could not have caught it**, because
  the generator only ever emitted 128-bit operands. A test is blind to what its
  fixtures cannot express, and this one had no ymm in it anywhere.
- **The census made it *less* visible.** Reconciling every survivor exactly is
  reassuring about sites that survive and says nothing at all about sites that were
  rewritten wrongly. It counted these 32,749 as successes.

The guard belongs in `sse_encoding` rather than in its callers, because it is the one
place every path funnels through, and a caller that wants a 128-bit encoding out of a
256-bit source -- which is exactly what a Y strategy does -- must now say so by
clearing `L` and asking for one half at a time. Silence is not consent.

`tool/lowering_cases.py` carries nine 256-bit forms it asserts are *refused*,
checked when the cases are generated, so the hole the fixtures left is closed by the
fixtures.

#### The honest number

```
                        before      after
VEX in .text             9,355     44,272
translated                98.8%      94.5%
```

The 98.8% was never real. 34,917 of those sites were counted as translated while
being wrong, and the earlier figures in this document -- 97.0%, 97.8%, 98.3%, 98.7%
-- all carry the same error in the same direction.

**This moves milestone 5 from polish to prerequisite.** The Y1 strategy is not an
optimisation for the last few percent; it is the only correct handling for 32,749
sites that are now, correctly, refused. Finding 2 already measured that 94% of ymm
definitions are consumed in their own basic block and need no shadow state, so the
work is scoped -- but it is required work, not optional.

### Finding 38 -- Y1, and the order that removes the scratch register

The 256-bit copy: a 32-byte load into a ymm and an immediate 32-byte store out of it.
7,395 adjacent pairs, 7,142 of them `vmovups` to `vmovups`. It becomes four 128-bit
moves, and **the order of those four is the whole design**:

```
movups 0x10(%rsi),%xmm0        high half first ...
movups %xmm0,0x10(%rdi)
movups (%rsi),%xmm0            ... low half last
movups %xmm0,(%rdi)
```

Doing the high half first leaves the ymm's own xmm holding the **low** sixteen bytes
when the sequence ends -- which is exactly what the lower half of that ymm holds in
the original. So no scratch register is needed at all, and every later 128-bit read
of the register is still correct. Only a read of the *upper* half would differ, and
that is the Y2 case by definition. Reversing the two pairs of lines still copies the
memory correctly and quietly corrupts every later use of the register.

`patch.offset_operand` does the +16, which is less trivial than it sounds: `(%rax)`
has no displacement and has to grow one, and a `disp8` of `0x7f` overflows into a
`disp32` and makes the instruction longer. Free inside a stub. RIP-relative operands
are refused rather than adjusted -- their displacement is measured from the
instruction's end, so moving one means combining the +16 with wherever the stub put
it, and those two corrections are applied by different code.

#### A call ends an upper half's life

The first version scanned forward for a later use of the ymm and treated any control
transfer as opaque. It refused 7,151 of the 7,395 pairs: calls are simply too common
for a scan that stops at one to reach anything.

**The upper half of every ymm is volatile under Win64 without exception.** xmm6 to
xmm15 have their low halves preserved and their upper halves survive nothing -- which
is the entire reason `vzeroupper` exists. So a call ends an upper half's life as
firmly as a return does: the callee may not read it, and the caller may not expect it
back. Conditional branches are still opaque, because following one needs a CFG.

#### What the verifier caught, again

The pair carries no `displaced` list, both instructions being lowered together -- and
the store's boundary disappears just the same. 267 lost boundaries were reported
unexplained until the store was named as swallowed. That is the third time the
structural checks have caught something in the change that produced them.

The PE harness carries a `ymm` program that copies 32 bytes and then reads back from
**offset 16**, the upper half. Truncated, it returns stack garbage; correct, it
returns 91.

```
VEX in .text     44,272 -> 39,880      94.5% -> 95.0%
```

### Finding 39 -- what the rest of the 256-bit work actually needs

Measured after Y1 landed, so the next step is chosen from numbers rather than from
the order the mnemonics happen to appear in:

```
256-bit sites                35,894
  vmovups                    32,858      vextractf128    383
  vmovdqu                       496      vinsertf128     157
  vmovaps                       249      vmulps          230
```

```
load -> store of the same ymm, by distance
  adjacent                    7,395      done, Finding 38
  one instruction apart         842
  two apart                     523
  three apart                   289
```

So the copy idiom accounts for about 9,000 pairs, 7,395 of them already taken. **The
remaining ~14,700 `vmovups` are not copies at all** -- they are loads consumed by
arithmetic, stores of computed values, or halves of a copy whose other half is too
far away to pair locally. Those need a ymm to be *represented* across a stretch of
code as two xmm registers, which is register allocation over a basic block and a
different piece of work from anything here so far.

#### The gapped pair is not a small extension of the adjacent one

It looks like one and is not, and the reason is worth writing down before someone
tries it. The four-move lowering **interleaves the load and the store**:

```
load high ; store high ; load low ; store low
```

With the two instructions adjacent that is safe, because nothing runs between them.
With anything in between, that instruction gets reordered relative to one half or the
other -- put it before the four moves and it moves ahead of the load, put it after
and it moves behind the store. Either is wrong the moment it touches the same memory,
and proving it does not needs alias analysis.

Two ways out, neither free:

- **Load both halves before storing either**, which needs a second register and
  brings back the scratch problem Finding 38's ordering was designed to avoid.
- **Restrict to intervening instructions that cannot interfere**, which is checkable
  -- and has now been checked. It is **68 pairs**, and that closes the option rather
  than opening it.

The full condition turned out to need more clauses than "touches no memory". An
intervening instruction must also not write any register used in either address, or
the store lands somewhere else; and it must not mention the ymm's own **xmm**, since
after the lowering that register holds the low half, and an instruction writing it
between the original load and store would have had its result stored. Of 1,654
gapped pairs, 68 satisfy all of it -- 136 instructions out of 39,880 remaining, which
is not worth a feature.

**This is the measurement earning its keep in the negative direction.** The gapped
pair looked like the obvious next increment, being a variation on something that
already worked, and counting it first cost one query and saved building it.

### Finding 40 -- the upper half nothing ever produced

Finding 39 concluded that the rest of the 256-bit work is register allocation. That
holds for most of it and not for a sixth of it, and the number that says so was sitting
in the shapes rather than the mnemonics:

```
256-bit moves, by shape
  store                    22,347
  load                     11,226
  register to register         75
```

**Two stores for every load.** A copy idiom is one of each, so eleven thousand stores
have no 256-bit load behind them and something else defines the register. Walking back
from each store to the nearest write of it says what:

```
what last wrote the register
  256-bit load (a gapped copy)                   9,447
  128-bit zeroing idiom -- both halves zero      6,538
  no definition found                            6,095
  256-bit, some other producer                     265
  128-bit VEX -- upper half is zero                  2
```

The 6,538 are `vpxor %xmm0,%xmm0,%xmm0` (6,427) and `vxorps` (110), and they matter
because of an architectural fact the design had recorded only as a cost: **every VEX
instruction with `L` clear writes zero to bits [255:128] of its destination.** A
128-bit zeroing idiom therefore leaves the *whole* ymm zero, and a 256-bit store of it
is storing thirty-two bytes that no 256-bit value was ever built to hold. In the real
binary it is MSVC's zero-initialiser, and it looks like this everywhere:

```
14073090b:  vpxor   %xmm0,%xmm0,%xmm0
            vmovups %ymm0,0x20(%rsp)
            vmovups %ymm0,0x40(%rsp)
```

So the lowering is two 128-bit stores of the same register, and it needs **no scratch,
no shadow and no second register** -- the value is zero in both halves, so one xmm
serves for each:

```
movups %xmm0,0x20(%rsp)
movups %xmm0,0x30(%rsp)
```

**The definition needs no coordination, which is what keeps this a one-site change.**
`vpxor %xmm0,%xmm0,%xmm0` is patched in place to `pxor %xmm0,%xmm0`, which zeroes only
the low half -- and that is fine, because the low half is the only half the lowering
reads. Whether the definition was lowered, detoured or refused, `%xmm0` holds zero when
the store runs. Nothing has to be rewritten as a group.

#### The scan, and what it refuses

`detour.zeroed_ymm` walks back to the **nearest** write, so nothing between that write
and the store can have changed the register. Everything it cannot resolve is refused:
a **branch target** in between, because another path could reach the store without
passing the zeroing; a **control transfer**, because the upper half of every ymm is
volatile across a call, which is the same rule Finding 38 relies on pointing the other
way; and an instruction that merely **reads** the register, which could not have
changed it but is refused anyway to keep the rule at "the nearest mention decides".
The 6,538 is measured with those refusals already applied.

`vzeroall` is the one instruction that would write an xmm without naming it. There are
**none in `.text`**, checked rather than assumed.

#### The same fact, pointing the other way

Class Y records this zeroing as **Y3**, a cost to be paid inside Y2 regions. It is also
information, and for these 6,538 sites it is the entire lowering. But the third reading
is the one to carry forward: **lowering a VEX.128 write to SSE destroys the zeroing**,
and `movups` leaves bits [255:128] holding whatever was there. That is harmless today
only because every 256-bit read is either refused, or part of a pair that produced its
own upper half, or one of these stores whose register is zero. **It stops being
harmless the moment the register model lands**, and it applies to all 547,613 in-place
sites rather than to a Y2 region.

#### The test

`make check-pe` gains a fifth program. It poisons thirty-two bytes of stack with
`0x5a5a5a5a`, zeroes `%xmm0` with `vpxor`, stores `%ymm0` over the poison, and reads
back the low half, the high half **and the last dword of the high half** -- or-ing the
three together, so only thirty-two bytes of zeroes give 77.

Changing the lowering's `+16` to `+0` makes it return 167, which is what the poison
becomes. Recorded because a test that has not been shown to fail is not yet evidence:
every structural check in this project passed the two bugs that computed wrong answers.

#### What it moved

```
VEX in .text     39,880 -> 33,848      95.0% -> 95.8%
```

6,352 sites are accepted as candidates and 6,032 survive to the binary; the difference
is windows lost to overlap and to operands that cannot be offset.

The accounting moved further than the translation did. **19,797 sites left "refused,
stub not buildable" for a named decline**, because a 256-bit store used to become a
candidate and fail in `build_stub` where it now declines in the collector with a reason.
Same population, better name -- and `make census` still reconciles every survivor with
nothing unaccounted.

Two leads, both small and both real:

- **156 zero stores are refused for a RIP-relative operand**, which is why that counter
  went from 268 to 424. Unlike the pair case, a zero store's two corrections -- the
  stub's displacement and the `+16` -- could be combined, because objdump's comment
  gives the absolute target.
- **A site with a strategy cannot be a passenger.** The Finding 36 extension lowers its
  passenger with `moved_instruction`, which knows only the plain rules, so both
  strategies are excluded from riding along.

### Finding 41 -- a write is not a read

Finding 38 built the pair rule and Finding 40 left its refusal counter untouched at
5,184, which is 68% of every adjacent 256-bit copy in the binary. Asking what each
refusal actually stopped on says most of them were not reads at all:

```
adjacent pairs                                   7,672
  accepted                                       2,472
  refused                                        5,200
    stopped at a branch, which needs a CFG       2,617
    overwritten whole by a 256-bit move          1,531
    genuinely read                               1,052
```

`upper_half_read_later` returned True on **any** later mention of the ymm, and the
mention it kept finding was the next pair's own load. An unrolled copy -- one 32-byte
copy through a ymm, then another through the same one -- refuses its first pair because
of its second:

```
vmovups (%rsi),%ymm0        the first pair ...
vmovups %ymm0,(%rdi)
vmovups 0x20(%rsi),%ymm0    ... refused because this names %ymm0 ...
vmovups %ymm0,0x20(%rdi)    ... and this one is accepted
```

**A write that does not read it ends its life as firmly as a call does.** The lowering
leaves the upper half stale, and nothing can observe that if the next instruction to
mention the register replaces all 256 bits without consulting them. Between the store
and that instruction nothing named the register and no control transfer ran, so no
other code executed at all.

The mnemonics are restricted to the moves, for the reason `scratch.py`'s `FULL_WRITE`
list is deliberately short: one missing from it costs a pair that was available, and one
wrongly on it costs correctness. `vmovups %ymm1,%ymm0` qualifies and
`vinsertf128 $1,%xmm1,%ymm0,%ymm0` does not, because the register is among its sources.

#### The one thing that reads an upper half without naming it

A scan over operand text is complete only if nothing reads a ymm implicitly.
`xsave`/`xrstor` do -- they carry the whole extended state, upper halves included.
**There are none in `.text`**, nor `fxsave`, checked rather than assumed, and that is
what licenses reading the refusal question off the operand strings.

#### Executing the unrolled copy

`make check-pe` gains a sixth program: the unrolled copy above, reading back the upper
half of **both** copies, 40 + 30 = 70. Without the rule the first load stays VEX and the
rewritten binary dies of an illegal instruction returning 29 -- so this one discriminates
on whether the rule fires at all, as well as on what it computes.

```
VEX in .text     33,848 -> 31,014      95.8% -> 96.1%
ymm upper half read later   5,184 -> 3,654
```

1,417 pairs of the 1,531 available survive to the binary; the rest lose their window to
an overlap or to an operand that cannot be offset, which is why that counter went from
424 to 537.

**2,617 pairs still stop at a branch**, and that is now the largest single bucket in the
pair rule. `tool/scratch.py` already follows edges without building a CFG -- an
unconditional jump has one successor, a conditional has two and the answer is the
intersection -- and the same traversal answers this question. It is the obvious next
increment on Class Y, and it is a bigger change than this one because the walker is
written around register sets rather than around a single yes/no.

### Finding 42 -- the same edges, followed twice

Finding 41 left 2,617 pairs stopping at a branch, and named the fix rather than making
it: `tool/scratch.py` already follows edges without building a CFG, and Finding 27
had already measured that following them was worth almost everything while widening the
window was worth almost nothing. The second scan needed the same answer.

An unconditional jump has one successor and the scan continues there. A conditional has
two, and the upper half is dead only if it is dead on **both**. Everything unresolved --
an indirect jump, a target outside the listing, a back edge, an exhausted budget --
answers "read", which is the conservative direction by construction: it can only refuse
a pair that was in fact safe.

```
ymm upper half read later   3,654 -> 1,766
VEX in .text               31,014 -> 27,462      96.1% -> 96.6%
```

1,888 of the 2,617 branch-stopped pairs resolve, which is 72% of them. `make
detour-plan` takes 2m47s against the 2m30s it took before, so following the edges costs
nothing measurable at this scale -- the `PATH_BUDGET` of 400 positions is what holds
that, and it is the same ceiling `scratch.py` uses.

#### The address index is borrowed, not built

Following an edge needs `{address: index}` over 16.5 million instructions, and building
a second one would cost a gigabyte. The collector already has one: `scratch.py` indexes
`plain`, and `plain` is a comprehension over `instructions`, so the two lists hold the
same instructions in the same order and one mapping serves both. That is a real coupling
and it is why the collector passes the index in rather than letting the scan build its
own.

#### Executing it across a branch

`make check-pe` gains a seventh program. A pair, then a conditional branch, and both
successors reach a `ret` without naming the ymm -- so the upper half is dead on every
path and only a scan that follows the edges can say so. Stopping at the branch refuses
the pair, leaves the load VEX, and the rewritten binary dies of an illegal instruction
returning 29 instead of 55. Checked by disabling the edge following and watching it
happen.

### Finding 43 -- two corrections on the same four bytes

Finding 38 refused a RIP-relative 256-bit operand rather than adjusting one, and said
why: its displacement is measured from the end of the instruction, so moving it means
accounting both for the `+16` and for wherever the stub put it, and the two corrections
were applied by different code. Finding 40 inherited the refusal for the zero store.

Splitting the counter first, because "cannot be offset" was two different pieces of
work wearing one name:

```
ymm pair operand cannot be offset      493
ymm store operand cannot be offset     156
```

**They are the same arithmetic, and the reason they can be combined is that the target
is computable from the original encoding.** `mod` 00 with `rm` 101 is RIP+disp32 and
carries no SIB byte, so the displacement is the last four bytes and the absolute target
is `address + length + disp`. Objdump's comment says the same thing, and is deliberately
not used: one source for the arithmetic rather than two that can disagree.

Each piece then computes its own displacement from where *it* lands:

```
value = (target + delta) - (at + len(piece))
```

`len(piece)` is knowable before the value it needs, because a RIP operand is always
disp32 -- the encoding's length does not depend on the displacement's value. So the
pieces are emitted one at a time, each told where it starts, rather than built as a
batch and placed afterwards.

`narrow_piece` is now the one place that turns half of a 256-bit memory operand into a
128-bit instruction, and both the copy pair and the zero store go through it. **Which of
the two corrections applies is a property of the operand rather than a choice**: an
ordinary displacement is adjusted in place by `offset_operand`, a RIP-relative one is
recomputed. That is what made this a small change rather than a second implementation.

#### Executing both sides

`make check-pe` gains an eighth program, with a RIP-relative operand on each side of the
work: a zero store whose destination is RIP-relative, and a pair whose load reads
RIP-relatively and whose store writes RIP-relatively. Dropping the `+ delta` from the
RIP path returns 165 instead of 88, which was predicted from the poison before it was
run.

**`.text` is writable in the test PEs now**, and that is a real trade rather than an
oversight. A program's data sits after `func_end` in `.text`, because
`objcopy --only-section=.text` is what extracts the assembled program and a symbol in
another section has no address at assembly time -- so without WRITE there is nowhere a
RIP-relative store can legally land, and the case cannot be tested at all. Starfield's
own targets are in `.data` and its `.text` is not writable; the displacement arithmetic
does not depend on which section the target is in.

```
VEX in .text     27,462 -> 26,320      96.6% -> 96.7%
```

All 649 land: 493 pairs at two instructions each plus 156 single stores is 1,142, and
the survivor count fell by exactly that. **Both counters are gone from the refusal list
entirely**, which is the first time a category has closed rather than shrunk.

### Finding 44 -- a wrong guess, and the question it should have asked

Finding 42 followed the edges forwards, so the obvious next move was to follow them
backwards. **Going backwards a conditional branch needs no following at all**, and the
asymmetry is worth understanding rather than just using: forwards a branch splits the
paths and the answer has to hold on both; backwards there is nothing to split, because
reaching this store by falling through a `jcc` means it was not taken on this execution
and everything before it ran in order.

Sound, cheap, and **worth five sites.** Built, measured, and it moved 15,835 to 15,830.

The measurement that should have come first asks what the walk actually meets:

```
what the backward walk meets first, over all 22,347 stores
  a definition that is not a zeroing idiom          9,733
  resolved: the register is zero                    6,543
  an instruction that reads it                      4,485
  a branch target                                   1,568
  an unconditional transfer                            18
```

**Only 1,586 stores are blocked by control flow at all.** Everything else is blocked
because the register genuinely holds a value that came from somewhere -- 13,342 of the
stopping instructions are `vmovups`, which is the copy idiom -- and no amount of
cleverness in the scan reaches those. That closes the whole "make the walk smarter"
avenue rather than opening it, and it is the sharpest statement yet that the remaining
work is register allocation and not analysis.

#### Except for one, and it was in the docstring all along

The 4,485 stopping at an instruction that only **reads** the register were refused by a
simplification Finding 40 wrote down deliberately: "keeping the rule at *the nearest
mention decides* is what makes the scan easy to be sure of, and the sites it costs are
already counted." Counting them says the simplification was costing **3,299 stores**,
which is more than a simplification is worth.

A read cannot have changed the value, so the walk goes past it. In AT&T the destination
is the last operand, and the one family that writes a non-last one is `vgather*`, which
zeroes its mask register -- **there are none in `.text`**, checked rather than assumed,
so a register named anywhere but last is read-only and the rule is complete.

```
ymm value has no known upper half   15,835 -> 12,552
VEX in .text                        26,320 -> 23,042      96.7% -> 97.1%
```

#### Two programs, and what they cost to learn

`make check-pe` gains a ninth and a tenth: a zero store with a not-taken `jcc` between
it and the zeroing, and one with a read between. Both die of an illegal instruction
without their rule, both return their number with it, and both were checked by
disabling the rule and watching it happen.

The five-site rule is kept rather than reverted, because it is three lines and the
walk's rules read as one set. But the lesson is the ordering: **the guess cost a build
and the diagnostic cost one query**, and the diagnostic would have said which of the two
to build. Finding 39 recorded exactly this lesson about the gapped pair, and it was
still not applied here.

### Finding 45 -- the bucket nobody had looked inside

Two questions this time, and the one that was not the plan produced the result.

#### The aliased sites, and an alternative that is worth 249

`vsubss %xmm1,%xmm2,%xmm1` needs a scratch because the `movaps %xmm2,%xmm1` that sets
up the destination destroys src2 first. But there is a second lowering that needs none:

```
subss  %xmm1,%xmm2        src1 -= src2, and its upper lanes are already right
movaps %xmm2,%xmm1        which is exactly what the destination should hold
```

Two instructions instead of three, and it destroys **src1** rather than borrowing a
third register -- so the question is not "is a register free" but "is src1 dead after
this site", which `scratch.dies_here` already answers and which `find_scratch`
structurally *cannot*, the site's own operands being excluded from its search.

```
aliased sites                                8,919
  has a scratch already                      5,271
  no scratch                                 3,648
    src1 is live                             3,399
    src1 is dead -- RECOVERABLE                249
```

**249.** The two questions turn out to be strongly correlated after all: a function with
no dead xmm register at a point is one where everything is live, src1 included. Not
worth a feature, and the measurement cost one query. The option is closed rather than
opened, and preferring the shorter form at the 5,271 sites that *do* have a scratch is
left as an optimisation nobody has needed.

#### `refused, stub not buildable` was never characterised

7,665 sites, the second largest bucket in the census, and nothing had ever asked what
they were. Finding 35's lesson about buckets, unapplied for ten findings:

```
256-bit load into a ymm              3,690      register model
128-bit, no scratch                  2,194      <- not 256-bit at all
256-bit, another shape               1,145      register model
256-bit store from a ymm               334      register model
128-bit, with a scratch                302      <- nor these
```

**2,496 of them are 128-bit.** `build_stub` returns None with no reason, so no counter
anywhere names them, and finding out meant walking its three steps by hand:

```
a displaced instruction will not move      2,437
a preceding instruction will not move         38
the site itself will not lower                21
```

#### A swallowed instruction is a lowering like any other

`moved_instruction` lowered a swallowed VEX neighbour by calling `lower_vex` **with no
scratch**. A `vblendvps`, an FMA, or a Class C whose src2 is its destination cannot
lower without one, so the whole window was refused whenever the neighbour it swallowed
happened to be one of those -- 522 `vblendvps`, then a long tail of aliased scalar
arithmetic.

The scratch a swallowed instruction needs is dead at **its** position rather than at the
site's, and that is also what makes two lowerings in one stub safe: the site's scratch is
dead at the site, so nothing after it -- including this instruction -- reads it; this
one's is dead here, so nothing after reads it either.

The trial lowering runs first and the liveness scan only when it fails, so the cost lands
on the ~2,400 neighbours that need one rather than on every neighbour any window ever
takes. `make detour` went from 2m47s to 2m57s.

```
VEX in .text                    23,042 -> 21,657      97.1% -> 97.3%
refused, stub not buildable      7,665 ->  6,383
skipped for overlap in census       97 ->      0
```

That last row is the incidental one and the most satisfying: with those windows now
committing, every surviving VEX site in the binary is accounted for by exactly three
causes -- declined by the collector, refused for want of a lowering, or bytes objdump
could not decode.

### Finding 46 -- three ways to get a register, and the objection to all of them

`scratch.py` rejected spilling for a stated reason and the decision has sat there since
Finding 18. Building the alternatives rather than arguing about them turned the question
inside out.

`tool/detour.py --spill=none|stack|pool` selects where a borrowed register is saved.
It is an evaluation switch and not a tuning knob: **the default refuses the site, as it
always has**, and the other two exist so that all three can be built and run.

#### What each one costs

```
                         none        stack         pool
VEX in .text           21,657       18,120       18,120
translated              97.3%        97.7%        97.7%
detours               193,485      195,946      195,946
stub bytes          3,061,515    3,168,708    3,161,930
instructions per spill      -            4            2
extra sections              0            0     1, writable
```

**Both recover exactly the same 3,537 sites**, for within 7 KB of the same size, on a
105 MB image. So the choice has nothing to do with coverage or cost and everything to do
with what can go wrong.

`make check-spill` builds and runs all three. `none` must refuse the site and leave the
binary dying at 29 -- that assertion is what stops the other two passing for the wrong
reason, since a site that was never the hard case would run under all of them.

#### The pool wants a writable code section, and cannot be made thread-safe

The first build of the pool spill stored into the stub section and every run died at
`0xC0000005`. Code sections are not writable, and making the stub section writable would
make it W+X. It has a section of its own now -- one page, writable, deliberately not
executable -- which is the option at its best and still costs an extra section.

What it cannot be given is thread safety. One slot is shared by every stub, so two
threads inside any two spilling stubs corrupt each other. A slot per stub is 4,509 x 16
bytes and still races when one hot stub is entered twice at once. **The only fix is
per-thread storage**, and that is worse than it sounds here: a static TLS slot means
extending the TLS directory's raw data, and reaching one costs a load from `gs:[0x58]`,
an index, and a pointer chase -- three or four instructions and a general-purpose
register the site has not got.

#### The experiment that moved the question

The recorded objection is that a stub has no `.pdata`, so `RtlVirtualUnwind` treats it as
a leaf and reads the frame from an `rsp` the spill has moved. **A stub is entered by a
jump**, so `[rsp]` was never a return address, and that reasoning holds whether or not
anything moved it.

`make check-unwind` settles it. Two programs, each faulting on purpose and each
registering a handler through `.pdata` -- which is how a PE with no imports and no CRT
gets SEH at all, the dispatcher finding the handler in the unwind info rather than
through anything registered at run time. The handler points `CONTEXT.Rip` at a recovery
label and returns `ExceptionContinueExecution`, so a dispatch that reaches it answers 42.

```
fault on a plain mov in .text        42    the handler ran
fault inside a stub                   5    0xC0000005, unhandled
```

**With no spill anywhere.** So exception dispatch from a stub is already broken, for all
193,485 of them, and has been since Finding 15. The objection in `scratch.py` is real and
it is misattributed: it is an objection to detouring, not to spilling, and spilling
neither creates it nor measurably worsens it.

That makes the two questions one question. **Giving the stub section unwind data fixes a
live defect and removes the only stated objection to the stack spill at the same time.**
The shape is already known: a `RUNTIME_FUNCTION` per stub whose `UNWIND_INFO` carries
`UNW_FLAG_CHAININFO` back to the enclosing function, plus a `UWOP_ALLOC_SMALL` where the
stub spills, in a `.pdata` copied to a new section with the exception directory
repointed. Every section after `.text` stays byte-identical, because the old `.pdata`
stays where it is and simply stops being pointed at.

One limitation to know before building it: a `__try` scope table is keyed on the
faulting address, and a stub's address is inside no scope. So chaining turns "the process
dies" into "the exception propagates correctly to outer frames" rather than into "the
`__try` that should have caught it does".

#### What this could not test

`wine` is not Windows and its unwinder is a reimplementation, so the 5 was read at the
time as evidence about the mechanism rather than proof about the shipping loader.
**Finding 68 settled it the other way**: the toolchain never allocates stack inside a
chained fragment, so wine's behaviour costs MSVC nothing and this project's pattern is
unexercised rather than unsupported. Nothing here ran more than one thread, so the pool's
race is argued rather than measured; that gap is still open.

### Finding 47 -- the SEH scope table, found while looking at something else

`targets.py` reads the handler RVA out of an `UNWIND_INFO` and stopped there. For a
function MSVC compiled with `__try`/`__except` the handler is `__C_specific_handler`, and
what follows that RVA is a `SCOPE_TABLE` whose records carry a filter funclet and a
`JumpTarget` -- **the address execution resumes at once the `__except` body has run**.
Both are code the unwinder enters, no branch instruction names either, and no relocation
records them. Nothing was stopping a window swallowing one, which is exactly the hazard
Finding 16 exists to prevent for switch tables.

```
functions with a handler            85,878
  handler data is a scope table         21
scope targets                           23
  already in the target set             15
  not in the target set                  8
  swallowed by a committed window        0
```

**A latent hazard rather than a live bug**, and closed because it costs nothing to close.
The parse is permissive and then validated rather than trusted: a C++ EH function carries
a `FuncInfo` there instead, which reads as nonsense, so every field is checked to be a
plausible `.text` address before any of it is believed. Wrong in the generous direction
costs a refused site; wrong the other way costs correctness.

The 21 is low for a 102 MB C++ binary and the reason is worth recording: modern MSVC
folds `__try` into `__CxxFrameHandler4`'s own state machine rather than emitting a
separate scope table, and that format is not decoded here. What saves it is that C++ EH
resumes through funclets which have `.pdata` entries of their own, and continuation
addresses inside them are materialised by `lea` -- both of which the target set already
covers, by Finding 30.

### Finding 48 -- a stub is a piece of a function, and now says so

Finding 46 measured the defect and named the shape of the fix. This is the fix.

**A stub is not a function.** It is a few instructions cut out of one and moved, entered
by a jump, sharing its frame -- so what it needs is not an unwind description of its own
but a pointer back to the one it belongs to. That is what `UNW_FLAG_CHAININFO` is for: an
`UNWIND_INFO` that ends with the primary's own `RUNTIME_FUNCTION`, telling the unwinder
to compute the frame from that function's prologue.

```
function table entries    429,912       236,427 original + 193,485 stubs
unwind info               295,652 bytes
file                  102,242,144 -> 110,759,424   (+8,517,280)
```

Three things make that cheap. **Stubs in the same function share a block**, since the
chain is all a block holds -- 193,485 stubs need 295,652 bytes rather than 3.1 MB. **The
`.xdata` is laid down before the `.pdata`**, because a `RUNTIME_FUNCTION` names its
unwind block by address and that address has to exist first; both sizes are known before
either is placed, a block holding only a `.text` address. And **the old `.pdata` stays
exactly where it is** and simply stops being pointed at, so every section after `.text`
is still byte-identical and the exception directory is the only field that moves.

#### The stubs with nothing to chain to are the ones that need no chain

A stub whose site sits in a range `.pdata` does not describe -- the leaf functions
`outside.py` recovers -- gets a plain empty `UNWIND_INFO` instead. That is not a
fallback. The x64 ABI lets a function omit unwind data **only** when it is a leaf that
neither moves `rsp` nor calls anything, so for exactly those the unwinder's leaf
assumption is right and `[rsp]` really is the return address. The two cases need
opposite treatment and the reason each is correct is the same fact.

#### It answers 42

```
fault inside a stub        5 -> 42
```

`make check-unwind` was written in Finding 46 to assert the defect. It asserts the fix
now, and it is the only check in the tree that exercises the exception path at all.

`make detour-verify` gained the structural half: the exception directory must point at
the rebuilt table, the table must still be sorted -- `RtlLookupFunctionEntry` binary
searches it -- and **every byte of the stub section past the constant pool must be inside
an entry**, exactly rather than approximately. A stub the unwinder cannot find is a stub
an exception cannot be dispatched from, which is the whole defect returning by the back
door.

#### The transposition that read an empty table

The first build emitted one function table entry where there were plainly two. The
section header stores `VirtualSize` **before** `VirtualAddress`, and the new section
walker unpacked them the other way round -- so every RVA lookup missed, the exception
directory resolved to nothing, and the original 236,427 entries were silently dropped.
Nothing crashed; the output was simply a table with the stubs in it and nothing else.

It was caught by a count that should have been 2 being 1, on a program small enough to
hold in the head. `patch.function_ranges` has had the field order right since Finding
14, three feet away in another file.

#### What it does not fix, and what it does not prove

A `__try` scope table is keyed on the faulting address, and a stub's address is inside no
scope. So an exception raised in a stub now propagates correctly to outer frames instead
of killing the process -- but the `__try` that should have caught it still will not.
Fixing that means widening scope ranges to cover the stubs their bodies were cut into,
which is a different piece of work and needs the C++ EH format Finding 47 did not decode.

And `wine` is not Windows. The 42 is strong evidence about the mechanism and not proof
about the shipping loader.

### Finding 49 -- the spill question, answered rather than asked

Finding 46 said the objection to spilling was misattributed and Finding 48 removed it, so
enabling `--spill=stack` looked like a decision waiting on a preference. **It was not a
decision. It was an untested case**, and testing it says no.

`make check-unwind` now reports three outcomes rather than two, because "the handler ran"
and "the frame it was handed was right" are different claims and only the second is at
risk here. `_start` records its own post-prologue `rsp`, the handler compares that against
the establisher frame the unwinder computed, and resumption always uses the recorded
value -- so an answer comes back either way and says which.

```
fault in .text                              42   handler ran, frame correct
fault in a stub                             42   handler ran, frame correct
fault in a stub that spilled                99   handler ran, frame WRONG
```

Measured rather than inferred: the error is **exactly -16**, the spill's own allocation,
not applied. The encoding is not the problem -- the block reads
`21 04 01 00 | 04 12 | 0000 | chain`, which is version 1 with `UNW_FLAG_CHAININFO`, a
four-byte prologue, one `UWOP_ALLOC_SMALL` of sixteen bytes at offset 4, and the primary's
entry. **A chained fragment's own unwind codes are not applied.**

And they cannot be got applied by dropping the chain, because the chain is what reaches
the handler at all:

```
chained, no codes          handler reached, frame correct
chained + alloc code       handler reached, frame wrong by 16
unchained + alloc code     no dispatch at all
```

So a stub that moves `rsp` cannot be described with what is available. The defect
`scratch.py` predicted is real after all -- not for the reason it recorded, and not
fixable by the unwind data that fixed the other half.

**`--spill=none` stays the default, and now it is a measurement rather than a caution.**
The pool variant keeps `rsp` still, so its frames would be right, and it remains
unusable for the reason Finding 46 gave: one slot shared by every stub, and no
per-thread storage within reach. 3,537 sites stay VEX.

`wine` is not Windows, and this is the one place in the project where that matters most:
if the shipping unwinder does apply a chained fragment's codes, the spill is safe there
and this is a wine limitation rather than an ABI one. **That is the single check worth
re-running the day a Windows host exists**, and it is a fifteen-second check -- run
`sse-unwindspill.exe` and see whether it answers 42 or 99.

### Finding 50 -- the register model, and the measurement that picked its shape

Finding 39 refused the gapped copy and gave the reason: the four-move lowering
**interleaves** the load and the store, so anything between them is reordered across one
half or the other, and proving that safe needs alias analysis. It named the way out --
load both halves before storing either, which needs a second register -- and stopped.

Holding the upper half in a second register does not merely make it possible. It makes
the whole problem go away:

```
movups (%rsi),%xmm0        movups 0x10(%rsi),%xmm1
... untouched ...
movups %xmm0,(%rdi)        movups %xmm1,0x10(%rdi)
```

Both loads happen where the load was and both stores where the store was, so **nothing
in between moves at all** and there is nothing to alias-analyse.

#### Two measurements, and the second chose the design

```
gapped copies                                  2,718
  a register is free across the span           2,279     84%
    one window would cover the whole span      2,223     98% of those
```

The first says the model works at all: a register dead at the load and untouched until
the store exists in five cases out of six. The second decided how to build it.

**Two windows that must both commit or neither is atomicity across the placement loop**,
which nothing here has ever needed -- a reservation set, a look-ahead, and a new way for
`census` to be wrong. One window covering the load, the span and the store is an
*ordinary* window: it widens, it swallows, it reconciles, and every existing invariant
applies unchanged. It costs the 2% where a branch target, a control transfer or a
function boundary falls inside the span.

Counting that second number first is what made this a small change. **The measurement
cost one query and saved building the hard design for a 2% return.**

```
VEX in .text     21,657 -> 18,516      97.3% -> 97.7%
refused, stub not buildable      6,383 -> 3,707
```

1,315 spans are taken, against the 2,223 the measurement offered. The gap is the
implementation being stricter than the measurement was: it refuses any mention of the
register inside the span, where the measurement allowed a pure read, and 652 spans hold
an operand that cannot be moved -- a lead, since `narrow_piece` handles RIP-relative
operands and the failures are in `moved_instruction` on the span instead.

**97.7% is the figure `--spill=stack` would have reached**, arrived at without moving
`rsp` and without an unwind question. That was not the plan; it is worth recording
because the two roads were costed against each other and only one of them was safe.

### Finding 51 -- interleaved copies, and a small register allocator

The 652 spans Finding 50 could not take were all one thing: **a `vmovups` inside the
span that will not move**, because it is itself 256-bit. That is what MSVC emits for a
block bigger than 32 bytes:

```
vmovups (%rsi),%ymm0        the load
vmovups 0x20(%rsi),%ymm1    inside its span, and 256-bit
vmovups %ymm0,(%rdi)        the store
vmovups %ymm1,0x20(%rdi)
```

A span holds one pair. A **run** holds as many as are open at once: every 256-bit move
inside it is one half of a copy whose other half is also inside. Each open ymm gets a
helper of its own, which is register allocation on a very small scale -- greedy over the
pairs in load order, which is enough when a run holds ten pairs at the very most.

```
runs                    9,577
  one pair              9,200
  two to ten              377
```

The run subsumes the span rather than adding to it: the single-pair case is a run with
one pair, and `ymm_gapped` is gone.

```
VEX in .text     18,516 -> 18,757
```

**That number went the wrong way, and the reason is Finding 52.** The run itself is worth
about 2,000 sites; the liveness fix found alongside it costs more than that, and costs it
correctly.

#### The test that was too weak, and what it hid

The first interleaved run assembled, disassembled, reconciled, and returned the right
answer -- and was wrong:

```
movups 0x20(%rsi),%xmm1
movups 0x30(%rsi),%xmm1     the second copy's helper is its OWN register
```

Both halves landed in `%xmm1`, so the low half was overwritten before it was stored. The
program still answered 77 because **it only read back the upper halves**, which happened
to be the half that survived. Reading the low halves as well turns it into 112 against a
wanted 77.

That is Finding 37's lesson arriving again in a new costume: a test is blind to what its
fixtures cannot express, and this one had been written to prove the upper half made the
trip. It proved exactly that and nothing else.

### Finding 52 -- the checker and the checked called the same function

`scratch.xmm_numbers` matched `%xmm` and nothing else. **`%xmm5`, `%ymm5` and `%zmm5` are
one register**, so every 256-bit operand was invisible to the liveness scan: `find_scratch`
would hand out a register that a neighbouring `vmovups %ymm5,(%rdi)` was using.

`make scratch-check` exists to catch precisely that, by enumerating paths rather than
intersecting sets -- and it reported zero violations, because `scratch.walk` calls the
same `xmm_numbers`. **Two witnesses, one pair of eyes.** `evidence.md` says corroboration
has to be independent and names the shape: two documents agreeing are one witness if the
same hand wrote both. This is that, in code.

Asking the register-claiming code the old way and walking the answer the new way is the
independent pair the check was supposed to be:

```
claimed the old way    28,160
  killed               27,316
  unknown                 611
  read                    233     wrongly claimed
```

**233 sites.** Not a tightened checker -- a live defect in what the rewriter shipped,
where a stub destroyed a register something still wanted. `vextractf128` and `vmulss`
dominate the examples, which is exactly the mix expected: a Class D or aliased site
sitting next to 256-bit code.

With the fix the same check reports 28,003 claims and **0 read on any path**, and the
binary keeps 241 more VEX sites than it did before -- the price of not claiming registers
that were never free.

### Finding 53 -- the audit Finding 52 asked for, and what it found

Finding 52 was a checker and its subject calling one function. The obvious question is
whether anything else has that shape, and `detour-verify` does -- worse, and provably.

```
the collector refuses to swallow anything in `blocked`
    blocked = targets.collect  +  the listing's direct branches  +  lea targets
verify then checks that nothing swallowed is in `reachable`
    reachable = targets.collect
```

`reachable` is a **subset** of the set the decision was made from, so the intersection is
empty by construction. The check has never been able to fail, and no amount of running it
was ever going to reveal that -- it is visible only by reading what each side is made of.

Demonstrated rather than argued: disabling the collector's branch-target guard and
rewriting a program whose branch is genuinely taken makes the new check below fail and
leaves the old one reporting success.

#### The independent form of the same question

**Every address a direct branch names in the original must still begin an instruction in
the rewritten binary.** If a window swallowed one, that branch now lands in the middle of
the jump that replaced it. It reads the two disassemblies and nothing else -- no
`targets.py`, no collector, no model. It is the output being asked whether it is well
formed rather than the model being asked whether it agrees with itself.

```
all 1,191,070 direct branch targets still begin an instruction
```

A million addresses inspected, which is also the answer to "did it check anything" -- the
question `evidence.md` says to ask of every green result.

#### The false positive was the interesting part

The first run reported exactly one failure, `0x1402ceb07`, and it was not a bug. After an
`int3` at the end of a function sits a repeating `7d e9 2c 00`, which a linear sweep
decodes as a row of `jge`s whose targets land in the middle of the function above:

```
1402ceb15:  c3              ret
1402ceb16:  cc              int3
1402ceb18:  7d e9           jge 0x1402ceb03      <- data, read as code
1402ceb1c:  7d e9           jge 0x1402ceb07      <- and its "target"
```

Finding 8 counted 11,892 bytes of `.text` that do not disassemble, and this is what they
do to anything that trusts the sweep. **The filter needs no oracle**: a target that was
not an instruction boundary in the *original* cannot have been a real one, and a real
target always was. That keeps the check made of two disassemblies and nothing else.

#### What it still cannot say

Indirect targets -- switch tables, relocations, addresses taken by `lea` -- have no
witness but `targets.py`, so for those the weak check above remains the only check. That
is a real gap and it is named rather than papered over: the strengthened half covers
every branch the code writes down, and nothing covers the ones it computes.

### Finding 54 -- what the executable tests had never run

The second audit Finding 52 asked for. `check-lowering`'s reference is GCC and so is
genuinely independent, but **the set of cases is chosen by the thing under test** --
`lowering_cases.py` generates them from `detour.lower_vex`. Finding 37's truncation was
invisible for exactly that reason: every case used 128-bit operands, so no fixture could
express the bug.

The question that finds the rest of it is not "does the suite pass" but "of the sites the
rewriter lowers into Starfield, which kinds has nothing ever run":

```
direct form, executed                                119,167
direct form with a memory operand, NEVER EXECUTED     81,656
sequence: vblendvps                                    3,054
direct form, NEVER EXECUTED: vsqrtss                   2,544
                             vinsertps                 1,670
                             vcvtss2sd                 1,458
                             vdpps                     1,220
                             vcmpltss                    851
                             vpextrq                     780
                             ... and a long tail
```

`make check-lowering` reported "37 mnemonics x 3 operand shapes", which reads like broad
coverage and is, of the shapes it has. It had never executed a single memory operand.

#### The memory shape cost nothing, which is why it is embarrassing

The harness passes the input vectors in `%rdi` and leaves it live, so a case can name the
slot `%xmm2` was loaded from and compute **exactly what the `distinct` shape computes** --
same answer, same reference, no new oracle. Pointing it at the wrong slot instead gives
232 wrong comparisons, so it is executing what it claims to.

`vmovss` and `vmovsd` are exempt because their memory form is a different instruction, a
load that zeroes the rest of the destination rather than a merge. `vinsertps` is exempt
for a sharper reason: its memory form takes a 32-bit operand and **ignores the
source-select half of the immediate**, so it does not compute what the register form
computes and one reference cannot describe both.

A RIP-relative operand is deliberately not generated. The bytes are emitted as `.byte`
and the generator cannot know where the assembler will place them, so the displacement
would be wrong -- that path is covered end to end by the `memory` PE program instead.

```
129 cases, 37 mnemonics, 1,032 executions
211 cases, 49 mnemonics, 1,688 executions
```

#### What is still never executed, named rather than left implicit

- **The sequences.** `vblendvps` at 3,054 sites, the FMA orderings, the broadcasts and
  `vpermilps` are multi-instruction lowerings with a scratch register, and no case runs
  any of them. `make check-aliasing` proves they do not read a register they have already
  written, which is a real property and is about shape. This is the largest remaining
  hole in the executable evidence.
- **GPR destinations.** `vpextrq` and `vcvttss2si` write a general-purpose register, and
  the harness compares the sixteen xmm registers. They need a different harness, not a
  different reference.
- **In-place patches.** 242,345 of them involve a mnemonic with no case. The risk is
  lower -- an in-place patch is a prefix strip, and `make verify` checks the encoding --
  but "lower" is not "none" and the count belongs somewhere.

### Finding 55 -- the blend, executed at last

Finding 54 named the sequences as the largest hole in the executable evidence and
`vblendvps` as the biggest of them: 3,054 sites, lowered by a function with four branches,
checked only for shape. `make check-aliasing` proves it does not read a register it has
already written, which is a real property and is not arithmetic.

The obstacle was the harness, not the reference. **A blend names four registers where SSE
has room for three** -- SSE takes the mask in an implicit `%xmm0` -- so the mask is an
input in its own right and the destination is not always `%xmm0`. Both were assumptions
built into the case table. It carries `source3` and a per-case `destination` now, and a
second reference table for the three-input form.

Five shapes, one per branch of `lower_blendv`:

```
mask_in_xmm0   the mask is already where SSE wants it; no scratch at all
dst_is_xmm0    xmm0's value is dead but cannot hold mask and result at once,
               so the blend runs in the scratch and moves back
xmm0_live      xmm0 is saved, the mask moved in, and xmm0 restored
src2_is_xmm0   the same, and an operand naming xmm0 must be renamed to the
src1_is_xmm0   scratch before the mask overwrites it
```

The last two are what Finding 9 is about. Disabling the renaming -- the exact mistake that
finding records -- makes `src2_is_xmm0` fail on every input pattern, which is the
difference between a test that covers the code and a test that covers the branch that can
go wrong.

```
211 cases, 49 mnemonics, 1,688 executions
221 cases, 49 mnemonics, 1,768 executions
```

#### What is left, and why the hard part is done

`vbroadcastss` and friends at 698 sites, the FMA orderings at 421, and `vpermilps` still
have no executable case. **The machinery they need now exists**: a three-input reference
is what an FMA wants -- `dst = src1 * src2 + dst` for the 213 ordering and a different
arrangement for each of 132 and 231 -- and getting those arrangements wrong is precisely
the kind of mistake that survives a shape check. Class F is deliberately not
semantics-preserving, so the reference is `a * b + c` compiled without FMA, which tests
the ordering and the register handling rather than the fusion.

### Finding 56 -- the FMA orderings, and a stale artifact that nearly won

Ten mnemonics, chosen by counting what the binary uses rather than enumerating what
exists -- there are 48 spellings of a fused multiply-add and Starfield emits these:

```
vfmadd231ps  143    vfmadd231ss   94    vfmadd213ps   25
vfmadd132ss   24    vfmsub231ss   23    vfnmadd231ss  20
vfmadd213pd   17    vfmadd213ss   16    vfmsub231ps    7
vfnmadd231ps   6
```

They need the three-input reference Finding 55 built, because **the destination's incoming
value is an operand**: `132` is `dst*src2 + src1`, `213` is `src1*dst + src2`, `231` is
`src1*src2 + dst`. Twelve mnemonics differing only in which operand goes where is exactly
the shape of mistake a structural check cannot see, and giving `132` the `231` ordering
now produces `-inf` where `+inf` is wanted -- an ordinary number, not a NaN.

```
221 cases, 1,768 executions
231 cases, 1,848 executions
```

#### The NaN payloads are GCC's to choose, so they are not counted

Class F is already not bit-exact -- two roundings replace one. Worse for a C reference:
the compiler decides which operand of a commutative multiply becomes the destination, and
SSE returns the **destination's** NaN when both are NaN. That choice cannot be pinned from
the source, so a lane where both sides are NaN is not evidence and is reported rather than
failed. Eleven of them. Every other lane is still compared exactly, which is what keeps
the ordering under test. `tool/f16c_oracle.py` and `test/fmaddsub_test.c` already draw
the line in the same place.

#### The stale artifact, which is a new shape of an old lesson

Between writing the references and believing them, `vfmadd132ss` disagreed with its
reference on ordinary numbers. Every check said the lowering was right: the source matched
`HEAD`, `git diff` was empty, `inspect.getsource` printed the correct branch, the operands
decoded correctly by hand, and disassembling the lowering **by hand** gave the right four
instructions -- while the generated case held three.

The mutation used to test the check had been reverted from a backup, and the edit
`(destination, source2), source1` to `(source1, source2), destination` is **exactly the
same number of characters**. Python validates a `.pyc` on the source's size and mtime, the
size was unchanged, and the restore landed in the same second. **The stale bytecode was
still being executed**, and `inspect.getsource` reads the file rather than the code object,
so it corroborated the wrong thing.

`project.md` already says never to compare a disassembly against a binary rebuilt after
it. This is that rule in a language that caches compilation invisibly, and `git diff`
being empty is not evidence that what ran was what the file says.

### Finding 57 -- the broadcasts, and the one that cannot be reached this way

`vbroadcastss` at 753 sites and `vpbroadcastd` at 18, both through a memory operand --
and **the load width is the whole point of the lowering**, so a case that did not go
through memory would not exercise it at all. `lower_broadcast`'s own comment makes the
argument: a single `pshufd` would read 128 bits where `vbroadcastss` reads 32, so a source
four bytes from the end of a mapped page would fault where the original did not.

The source slot is deliberately not the destination's. A lowering that read the wrong
address would otherwise be reading the right answer by accident. Changing the spread's
control from lane 0 to lane 1 leaves the low lane zero and fails on every pattern.

```
231 cases, 1,848 executions
233 cases, 1,864 executions
```

`vbroadcastsd` is absent because **it has no 128-bit form at all** -- its destination is a
ymm by definition -- which is also why the binary holds exactly one of them and why
`lower_broadcast` refuses it on `VEX.L`. The generator failing to assemble it is how that
was learned.

#### `vpermilps` needs a different harness, not a different reference

It is the last sequence with no executable case, and the obstacle is structural. The
inline lowering reads its permute constants from the stub section's pool through a
RIP-relative displacement, and the generator emits its cases as `.byte` -- it cannot know
where the assembler will place them, so it cannot compute the displacement. Exactly the
reason a RIP-relative memory operand is not generated either.

What exists instead is `make check-permil`, which is exhaustive over all 256 controls --
but it tests `src/permil.c`, the reference implementation, **not the bytes the rewriter
emits**. That distinction is the whole subject of Findings 54 to 57, so it is written down
rather than left to be rediscovered. Closing it means either a harness that assembles the
lowering from text rather than bytes, or a PE program of the kind `tool/pe_build.py`
already builds -- the second is cheaper and is where the 256-bit strategies are tested.

### Finding 58 -- the remaining stores are copies, not computations

**Half wrong, and corrected by Finding 59: 9,100 of the 9,742 below are copies a run
already lowers, counted as declined because the collector meets the store again on its
own account. The table is right about arithmetic and wrong about what the rest needs.**

Stated here twice that the residue needs the model to track a computed value. **Measured,
it does not.** Asking what defines each of the 12,552 stores the collector still declines:

```
a 256-bit load -- the copy idiom            9,742
a branch target reaches the store           2,186
256-bit arithmetic: the value is computed     316
nothing within 80 instructions                286
a call or jump in between                      19
a 128-bit write: upper half is zero             3
```

Arithmetic is **2.5%** of it. Nine tenths are the copy idiom the run strategy already
lowers, declined for a reason that has nothing to do with what the value is.

The reason is control flow. `ymm_run` requires its whole span to be contiguous, free of
branch targets and free of control transfers, because the span goes into one stub and a
stub may swallow neither. The backward walk that produced the table above is laxer: it
walks over a conditional branch, since falling through one means it was not taken. So the
9,742 are overwhelmingly **copies whose load and store are in different basic blocks** --
which is Class Y2's case, and the first measurement of it since Finding 7 counted 574 ymm
definitions by a different method.

That changes what to build next, and it is the third time in this project that counting
first has redirected the work: the scratch scan wanted branch following rather than a
wider window (Finding 27), the gapped pair looked obvious and was worth 68 sites (Finding
39), and the register model turned out to be needed for control flow rather than for
arithmetic. **The plan stated in this document before this finding was wrong**, and it was
wrong in the direction of building something larger than the problem.

Two routes, neither costed yet:

- **A run that spans basic blocks.** The halves stay where they are and the upper half
  rides a register across the branch, which needs the register to be free on every path
  rather than over a straight line -- `scratch.py` already answers that shape of question
  by intersecting over successors.
- **The Y2 shadow.** Sixteen 16-byte slots, which the design has carried since the
  beginning and which Finding 46 gave a home: the writable section the pool spill needed
  exists, and its thread-safety objection applies here unchanged.

### Finding 59 -- a counter that measured decisions, not work

Finding 58 read 9,742 declined stores as copies blocked by control flow. Asking whether a
run would take them says **9,100 of them are already taken**: a run is anchored at its
load and its window reaches through the store, so the collector's loop meets that store
again and declines it on its own account. The counter was measuring decisions, and a
decision made twice about one instruction counts twice.

This is Finding 35 wearing different clothes -- there, a residue was computed by
subtracting two counts of different populations. The lesson did not transfer because
nothing looked like a subtraction this time.

#### The residue, read from the output

```
surviving VEX sites            18,757
  128-bit                       7,946
  256-bit store to memory       5,031
  256-bit load from memory      3,428
  256-bit, another shape        2,271
  undecodable                      81
```

**The 128-bit share is 42%**, which no reading of the skip counters would have suggested,
and it is dominated by the scratch problem the spill question answered `no` to. The
256-bit store residue is 5,031 rather than 12,552.

#### Where the subtraction belongs

`make detour-plan` now prints, beside each counter, how many of its sites lie outside
every accepted window -- 12,176 against a raw sum near 21,500.

Doing it in the collector instead was tried and **cost 409 sites**. A site inside a window
whose stub later fails to build still deserves its own chance, and taking that away is a
real loss for a cosmetic gain. So the collector still decides per site and the subtraction
happens where the question is *what is left* rather than *what was decided*.

#### What the cross-block copy is actually worth

Of the 9,742, only 642 need two stubs, and 456 of those could be placed: a register is
free across the gap and both halves sit inside a described function. **456, not 9,742**,
and the two-stub machinery is the atomicity Finding 50 chose the single-window design to
avoid. That is the honest price of the last large-looking bucket.

### Finding 60 -- the last lowering nothing had executed

`vpermilps` with a variable control, inlined rather than called (Finding 20). Finding 57
named it as the one sequence `tool/lowering_cases.py` cannot reach, and the reason is
structural rather than awkward: the lowering reads its permute constants from the stub
section's pool through a RIP-relative displacement, and that generator emits `.byte` --
it cannot know where the assembler will place them, so it cannot compute the
displacement.

**A whole PE can, because the rewriter lays the pool down itself.** The stub reads all
three constants and computes the permute:

```
pand   -0x3b(%rip),%xmm3     # 0x140004000, the two-bit mask
pslld  $0x2,%xmm3            # element index to byte index
pshufb -0x39(%rip),%xmm3     # 0x140004010, broadcast within each element
paddb  -0x31(%rip),%xmm3     # 0x140004020, step through the bytes
movaps %xmm2,%xmm0
pshufb %xmm3,%xmm0
```

Only bits [1:0] of each control element are read, so a control of `{3,2,1,0}` reverses the
vector and lane 0 comes back holding what lane 3 held. Changing the `pslld` from 2 to 1 --
scaling an element index by two bytes instead of four -- returns 1 instead of 88.

`make check-permil` remains, and tests something else: it is exhaustive over all 256
controls against `src/permil.c`, the reference implementation. This tests the bytes the
rewriter emits. **Both are worth having and they are not the same claim**, which is the
distinction Findings 54 to 57 exist to draw.

Every lowering the rewriter emits now has an executable case, with two exceptions, both
named: 256-bit, whose strategies are covered by PE programs of their own, and lowerings
whose destination is a general-purpose register -- `vpextrq` at 780 sites and
`vcvttss2si` at 376 -- which need a harness that compares general-purpose registers
rather than a different reference.

### Finding 61 -- the trampoline, closed at 21% reach

511 sites are refused because the next instruction is a branch target and 424 because it
transfers control, and neither can widen backwards either. A window must be five bytes to
hold a `jmp rel32`.

**A two-byte `jmp rel8` needs no widening at all.** It fits inside a four-byte site with
two bytes to spare, and the next instruction keeps its boundary -- which is exactly the
constraint that refused these. It needs somewhere within reach to land: five bytes for a
`jmp rel32` on to the stub. MSVC leaves runs of `int3` between functions for alignment, so
the space plausibly exists.

It does exist, and it is in the wrong places:

```
padding runs of 5+ int3 outside every function   160,018     1,639,100 bytes
sites that cannot widen either way                 9,341
  a padding slot within rel8 reach                 1,929     21%
  nothing in reach                                 7,412
```

1.64 MB of padding and four fifths of the sites cannot see any of it, because `rel8`
reaches 126 bytes back and 129 forward and these sites are in the middle of large
functions. Against the collector's own 935 declines the same fraction gives about 200
sites -- for a **new class of write**, into bytes that are not code, with the verification
that implies: proving each slot lies outside every function, that nothing branches to it,
and that two sites never claim the same one.

Closed. It is the same trade Finding 39 refused at 68 sites and Finding 45 at 249, and the
fourth time counting first has saved building something. The measurement is recorded
because the idea is a good one that will occur to the next reader too, and the reason it
fails is not obvious from the outside -- there is plenty of padding; it is simply not
near enough.

(The 9,341 is a broader population than the collector's 935: it counts every short VEX
site that cannot widen, including those already refused for another reason. The reach
fraction is what decides it and applies to both.)

### Finding 62 -- what milestone 3 would still be worth

`project.md` called milestone 3 the go/no-go: if Ddisasm could not round-trip a 102 MB
binary, nothing downstream mattered and the project stopped. That was right for the design
it was written for, in which every rewrite went through a reassembleable IR. Milestone 4
was then reached **without it**, by patching in place and detouring, and the sentence was
never revisited.

Revisiting it by counting rather than by argument. Sorting the 18,757 survivors by whether
being able to move code freely would help:

```
positional  ~2,000    can't widen (935), overlap (1,041), store is a target (25)
semantic   ~11,100    256-bit representation (6,800), no scratch (3,344),
                      no direct SSE form (592), oracle (403)
```

with the refused-stub bucket, mixed and mostly 256-bit, making up the rest.

**About 11% is positional.** Full reassembly dissolves the window shapes -- no five-byte
minimum, no widening, no overlap -- and does nothing whatever about register pressure or
about representing a 256-bit value in 128-bit registers. So milestone 3 is worth roughly
two thousand sites, not everything, and it is demoted in the table accordingly.

That also revises the "Honest assessment", which said the risk was concentrated in
milestone 3 and in verification. Verification kept its half and then some: four defects
here produced silently wrong output while passing every structural check, and two of the
checks that should have caught them could not -- one shared a function with the code it
checked (Finding 52), and one was empty by construction (Finding 53).

### Finding 63 -- nothing was checking the image was still loadable

Three sections are appended and a data directory repointed, and until now nothing verified
the result was a well-formed PE. `add_section` writes `SizeOfImage` and refuses when the
header has no room for another entry -- but **writing a field is not the same as the field
being right**, and the only evidence was that wine loads the small PEs, which have three
sections where Starfield has ten and a header with room to spare.

`make detour-verify` now checks the image against itself: every section's raw data inside
the file, virtual addresses section-aligned and raw pointers file-aligned, sections in
ascending order and not overlapping in virtual space, `SizeOfImage` covering the highest
section end, the section table inside `SizeOfHeaders`, the entry point inside a section,
and every data directory pointing inside one.

It passes on Starfield and on all fourteen PEs, and it fails when told to: clipping
`SizeOfImage` to `0x2000` reports that it does not cover the highest section end at
`0x6018`.

**This is the check that would catch a malformed image before a loader does**, and it is
worth having for the reason the rest of `verify` is: everything else it proves is about
the code, and an image whose headers are wrong never reaches the code at all. Cheap, and
found by asking what the rewriter writes that nothing reads back.

### Finding 64 -- the run had the pair's bug, and the harness cannot see it

`lower_ymm_run` leaves every ymm in the run with **the low half in its own xmm and the
upper half in a helper register the original code knows nothing about**. That is the same
state the pair lowering leaves behind, and the pair has guarded it since Finding 38:
`upper_half_read_later` refuses whenever a later 256-bit instruction could read the upper
half.

The run never called it. For as long as runs have existed, **108 of them were producing
wrong code** -- a later 256-bit read of any register in the run would take whatever was
left in its upper half, and every structural check passed, because a stale upper half is
a correct instruction reading the wrong bytes.

```
VEX in .text     18,757 -> 19,015      97.7% -> 97.6%
ymm run upper half read later     108
```

258 sites go back to VEX. That is the third time here that the honest number has moved the
wrong way and been right to.

#### What found it, and what could not

Not a test. **Comparing the new strategy against the older one that solves the same
problem** -- the run and the pair leave identical state behind, so any guard one needs the
other needs, and only one had it. The question that surfaced it was asking why
`upper_half_read_later` had exactly one call site.

`make check-pe` cannot reach this class at all, and the reason is worth recording rather
than filing as a gap to close later. Triggering it requires a **surviving** 256-bit
instruction to read the stale register -- and a surviving 256-bit instruction is one this
CPU faults on, so the program dies before it can compute a wrong answer. Putting the read
behind an untaken branch makes the program return the same value whether the run was taken
or refused. The harness's whole power is that this machine can execute the output and not
the input; here that is exactly what puts the case out of reach.

So the guard rests on the argument rather than on an execution, and the argument is the
one Finding 38 wrote down: only a 256-bit instruction can read an upper half, a call and a
return both end its life, and anything unresolved is refused.

### Finding 65 -- what each lowering leaves behind, and what guards it

Finding 64 was found by asking which guards the pair has that the run skipped. That
question is worth asking of every lowering, and the answer is worth writing down, because
"the others are probably fine" is not the same as knowing why. **Each row is the state the
lowering leaves that the original would not have left, and the thing that makes it safe.**

| lowering | what it leaves | what guards it |
|---|---|---|
| pair | xmm holds the low half, the ymm's upper half is stale | `upper_half_read_later`, since Finding 38 |
| run | the same, per register, plus a helper clobbered | `upper_half_read_later` **since Finding 64 and not before**; `free_across` for the helper |
| zero store | nothing -- it reads the low 128 bits twice and writes only memory | no obligation to discharge |
| spill | nothing -- the borrowed register is saved and restored | `movups` moves 128 bits and every SSE write leaves [255:128] alone, so the upper half was never at risk |
| swallowed neighbour | its own scratch clobbered | `find_scratch` at **its** position, not the site's -- Finding 45 |
| in place | nothing | `classify` returns `B` only when destination equals src1, so the Finding 25 alias cannot reach it |
| any of them | never a 256-bit instruction | `sse_encoding` refuses `VEX.L` and `narrow_piece` always clears it; `verify` counts zero VEX in the stub section |

Two rows repay reading twice.

**The zero store looks like it should be in trouble and is not.** It stores a register
whose upper half was zeroed by a `vpxor %xmm0,%xmm0,%xmm0` that the in-place patcher
lowered to `pxor %xmm0,%xmm0` -- which zeroes the low half only, so the upper half really
is stale by the time the store runs. It does not matter, because the lowering reads only
the low 128 bits and writes both halves of memory from it. The hazard is real and the
lowering never touches it.

**The spill's borrowed register never needed its upper half saving.** Every instruction a
lowering emits is 128-bit SSE, and an SSE write leaves bits [255:128] unchanged, so 128
bits saved and 128 restored is the whole of what changes. That is a property of the
emitted code rather than of the spill, which is why it holds for both backing stores.

One defect in seven rows, and it was the row where a new strategy inherited an old one's
obligations without inheriting its guard. **That is the shape to look for**, and it is
cheaper to look for than to test for -- Finding 64 records why `check-pe` cannot reach the
case at all.

### Finding 66 -- the next blocker was right behind the first

1,766 adjacent pairs were refused for `ymm upper half read later`, and asking what does the
reading says **1,019 of them are another store of the same register** -- one source copied
to two destinations. The run closed a register on its first store, so the second store
looked like a read of an upper half that was in fact sitting in a helper.

Two things were wrong and both are fixed. A store does not end a value's life, so a
register now stays tracked across as many stores as follow; and the pair was pre-empting
the run, declining and moving on where the run solves the same problem differently, so a
pair's failure now falls through and its reason is recorded only if the run declines too.

Both are right independently of what they buy. What they buy is **21 sites.**

```
VEX in .text     19,015 -> 18,994

ymm upper half read later      1,766 -> 0        folded into the run
ymm run upper half read later    108 -> 1,190
no register free across a run    446 -> 911
```

The 1,019 became longer runs, and then the Finding 64 guard refused most of them anyway --
because something reads the upper half after the *extended* run too -- while 465 more ran
out of free registers across the now longer span.

#### The lesson, which is the second time

**Measuring what blocks a site is not measuring what unblocking it would gain.** The next
blocker is usually right behind, and a counter of first refusals reads like an
opportunity. Finding 59 was the same shape: 9,742 stores declined for "no known upper
half", of which 9,100 were already being lowered by a run anchored elsewhere.

The honest form of the question is not "why is this refused" but "what happens if I stop
refusing it", and the only way to answer that is to build the change and count -- which is
cheap when the change is small and is exactly why this one was worth making anyway.

The change is kept because it is correct and free, not because of the 21: a store ending a
value's life was wrong, and a strategy pre-empting a better one was wrong. The accounting
is more honest too -- 1,766 sites that read as "the upper half is live" were really "a run
would hold it, and something later still wants it".

### Finding 67 -- the Windows host was never needed, and the GPU was already here

Finding 49 measured that a chained fragment's own unwind codes are not applied, and
concluded that only a Windows host could say whether that is wine's limitation or the
ABI's. **Two assumptions in that sentence were wrong**, and the evidence against both was
already on this machine.

#### The binary is a better witness than a second operating system

If shipping Windows binaries carry chained `UNWIND_INFO` with its own unwind codes, the
real unwinder must handle it. Counting them in the 102 MB of MSVC output sitting in this
directory:

```
function table entries                        236,427
  chained                                      56,269
    with their own unwind codes                31,634
      and a nonzero SizeOfProlog               25,680
```

The header byte MSVC writes is `21` -- version 1, `UNW_FLAG_CHAININFO` -- which is byte
for byte what this project emits. **31,634 times in one binary.** If Windows ignored a
chained fragment's codes, Starfield's own exception handling would be broken across tens
of thousands of its own functions.

So the pattern is standard and the encoding is the one the toolchain uses. Asking for a
Windows host was asking the wrong witness a question the corpus could answer.

#### Which leaves a contradiction, and that is progress

Starfield is played on Linux under Proton, so those same 31,634 chained entries are
already being unwound by wine every day. If wine ignored their codes the game would be
visibly broken. So `check-unwind`'s establisher frame being **exactly 16 bytes out** is not
simply "wine does not support this": either wine handles MSVC's shape and not the one this
project emits -- which would mean a fault in the encoding that reading it has not found --
or the difference is somewhere else entirely, in the epilogue detection or the placement.

That is a question this machine can settle: build a PE whose chained unwind info mimics
MSVC's shape exactly, and bisect against the one that fails. **It is no longer blocked on
anything.**

#### And the machine can run the result

The other assumption was that validating a translated Starfield needs hardware not present.

```
GeForce RTX 3060, Vulkan 1.4.309, wine 10.0
```

The CPU is a Westmere with no AVX, which is the entire point; the GPU is capable and
Vulkan works. Starfield runs on Linux under Proton. **The validation path is this machine**
-- finish the translation, run it under Proton here -- and what is missing is the last
18,994 sites and a Steam licence, not an operating system.

It also means wine is not the test instrument standing in for the real one: **for the
driving case wine IS the real one**, which raises the stakes on the contradiction above
rather than lowering them.

### Finding 68 -- the contradiction resolved: nobody allocates in a fragment

Finding 67 left a contradiction. Wine gives an establisher frame sixteen bytes out for a
spilling stub, yet MSVC emits chained unwind info 31,634 times in this binary and Starfield
is played under Proton every day. Both cannot be true of the same mechanism.

They are true of different mechanisms. Counting which unwind **operations** appear inside a
chained fragment, against those in a primary:

```
inside chained fragments        inside primaries
  SAVE_NONVOL     49,868          PUSH_NONVOL    177,280
  SAVE_XMM128     15,387          SAVE_NONVOL     72,295
                                  ALLOC_SMALL     45,903
  no allocation, ever             ALLOC_LARGE     14,159
```

**Sixty-five thousand unwind codes in fragments and not one of them allocates stack.** The
toolchain puts register saves in a fragment and never a frame adjustment, and the frame
register field is zero in all 55,070 of them.

That explains everything at once. Wine ignoring a fragment's codes costs MSVC almost
nothing, because a `SAVE_*` says where a register is restored *from* and not how big the
frame is -- the unwind chain still walks correctly and only restored register values would
be wrong. So Starfield is unaffected, and this project's pattern -- an `ALLOC_SMALL` inside
a fragment -- is one **nothing in the corpus exercises**. It is unexercised because the
toolchain does not do it, and the ABI's own wording, that a chained entry's frame register
and fixed-stack allocation must match the primary's, says why: **a fragment shares its
primary's frame rather than having one of its own.**

#### So the spill question is closed, and for a better reason

Finding 49 concluded `--spill=none` on the evidence and hoped a Windows host might reopen
it. It will not. A stub that moves `rsp` cannot be described as a chained fragment, and
the alternative -- an unchained entry with a complete frame of its own -- was measured in
Finding 49 to lose the handler entirely, because the chain is what reaches it.

The three ways a stub can get a scratch register are now all closed on evidence rather
than on caution: the stack cannot be described, the pool cannot be made thread-safe, and
`src1` is dead at only 249 sites. The `--spill` switch stays, because the measurement it
carries is what a future reader will want, and its default stays `none`.

**And no external resource would have changed any of this.** The question that looked like
it needed another operating system was answered by counting bytes in a file that was here
all along -- twice, in Findings 67 and 68.

### Finding 69 -- the general-purpose register is scarce in the same places

Per-thread memory was the one untried mechanism for the sites with no scratch register, and
reaching a TLS slot costs a general-purpose register: `mov %gs:0x58,%r`, an index, a
pointer chase. So the question that governs it is whether such a register exists **where
an xmm does not**.

The TLS directory is there to hang a slot on -- rva `0x4f07480`, 40 bytes -- so the
mechanism is not blocked by the file format. The register is the problem:

```
functions                                  273,902
  with r10 or r11 provably free            154,053     56%

sites wanting a scratch
  an xmm is free                            28,003
  no xmm                                     5,699
    a GPR is free                            1,728     30%
    no GPR either                            3,971
```

**Thirty per cent**, and it makes sense in hindsight: a site with no free xmm is in a
register-starved region, and starvation is not independent across register files. The
places that have run out of one have usually run out of the other.

So per-thread memory would recover on the order of a thousand of the surviving
scratch-starved sites, for a new mechanism with real weight -- extending the TLS raw-data
template so the loader allocates more per thread, getting the index right, three or four
instructions and a clobbered register at every site -- and it does **nothing cheaper** for
the 256-bit representation, which needs a value held rather than a register borrowed and
would want the same scarce GPR at far more sites.

#### The bound, and what would move it

The 30% is a **lower bound**, and honestly labelled: it is the whole-function argument
`scratch.function_scope` makes for xmm4 and xmm5 -- the register is named nowhere in the
function, so nothing in it reads one -- and that argument is much weaker than the forward
scan `find_scratch` uses, which reaches 83% for xmm. A forward GPR liveness scan would
find more.

It would also be the hardest analysis in this project to make sound. The xmm file has
almost no implicit operands; the general-purpose file is full of them -- a `call` reads
four argument registers and clobbers four more, `div` reads and writes `rdx:rax`, a
variable shift reads `cl`, the string operations read `rsi`, `rdi` and `rcx`. **Every one
missed is a register claimed while live**, which is the failure mode Finding 52 cost 233
sites to. The cheap version of that analysis is the dangerous one.

#### What this settles

The residue is about ten thousand sites of "nowhere to put a value", and the three
mechanisms that could provide one are now all measured: the stack cannot be described to
the unwinder (Finding 68), a static pool cannot be made thread-safe (Finding 46), and
per-thread memory needs a register that is absent at 70% of the sites that need it. **None
of them is a way through**, and that is a property of the code being translated rather
than of any tool.

### Finding 70 -- the callee home space, which walks through all three walls

Findings 46, 68 and 69 closed every way of giving a stub somewhere to put a value: the
stack cannot be described to the unwinder, a static pool cannot be made thread-safe, and a
general-purpose register is absent at 70% of the sites that need one. The conclusion drawn
was that the residue has no route. **That conclusion assumed a stub must create space, and
Win64 has already created some.**

The ABI makes a *caller* reserve 32 bytes at the bottom of its frame for its callees to
spill their first four register arguments into. Between calls nobody owns it: the caller
does not write it -- the fifth argument onward goes at `[rsp+32]` and up -- and no callee
exists yet.

**It walks through all three objections at once.** Nothing moves `rsp`, so there is nothing
to describe and Finding 68 does not apply. It is the thread's own stack, so Finding 46's
race does not apply. `(%rsp)` needs no register to address, so Finding 69 does not apply.
An exception does not disturb it either: the kernel pushes its context record **below**
`rsp`, and the home space is at and above it.

```
movups %xmm2,(%rsp)        save into the home space
movaps %xmm0,%xmm2         ... the lowering ...
movaps %xmm1,%xmm0
subss  %xmm2,%xmm0
movups (%rsp),%xmm2        restore
```

Two instructions, the same as the pool and half the stack, with neither one's problem.

#### What the corpus says about whether it is really free

```
functions                                    273,902
  containing a call, so the space exists     194,904
sites with no xmm scratch                      5,699
  the function uses that region itself             1
```

**One function in 273,902** addresses `[rsp+0..31]` directly. That number is weaker than it
looks and Finding 72 says why: it counts only accesses written as `(%rsp)`, and a function
that copies `rsp` into another register can reach the region without one. The collector
checks per function either way, and refuses any function that copies `rsp` at all.

#### The honest yield, after closing the hole the first version left

A direct `(%rsp)` operand is not the only way to reach the region: a function that computes
the address of its own frame bottom can write there through the result. Refusing that --
any `lea` into the region, and any copy of `rsp` into another register at all -- costs
1,655 sites.

```
--spill=none      18,994    97.6%
--spill=home      17,972    97.8%     1,022 sites
    before closing the aliasing hole   2,677 sites
```

The refusal is broader than it needs to be: most copies of `rsp` are followed by bounded
uses, and narrowing it needs dataflow rather than a scan. **1,022 is the number that is
safe to claim today.**

#### Why the default stays `none`, and what would change it

This writes into the translated program's own stack frame, on the strength of a textual
scan proving nothing else uses it. That is a different kind of risk from the rest of this
project: five defects here have produced silently wrong output while passing every
structural check, and a missed aliasing path would join them. No test on this machine can
rule one out -- only running the program can.

So `--spill=home` is built, executed by `make check-spill`, and **off by default**. It is
the only mechanism of the four that survives its own objections, and turning it on is a
risk the copyright holder should take deliberately rather than inherit from a default.

**And the walls were not walls.** Three findings concluded "no route" from three correct
measurements, and all three were answering "can the rewriter make space" when the question
was "is there space already". That is worth more than the 1,022 sites.

### Finding 71 -- the home space is exactly the right lifetime, and mostly unavailable

Does the callee home space serve the Y2 shadow? The objection that looks fatal is that it
is dead only **between calls**, and a shadow must hold a value for as long as the value
lives.

**The two lifetimes are the same lifetime.** The upper half of every ymm is volatile across
a call -- that is the whole reason `vzeroupper` exists, and it is what
`upper_half_read_later` has relied on since Finding 38. So a ymm upper half cannot outlive
a call either, and the home space is not a partial shadow that happens to work sometimes:
it is a shadow whose lifetime is exactly the lifetime of the thing it holds.

That is the right shape. Class Y2 has wanted "sixteen 16-byte slots addressed via a
reserved register or TLS" since the design was written, and this is 32 bytes addressed by
`(%rsp)` with no register at all.

#### What it is worth, measured on the case that needs it

The run is where a register is needed and sometimes absent, so that is where to count:

```
runs found                                  9,645
  a register is free for every pair         8,281
  no register free -- the refusal           1,364
    no home space in that function            983
    the home space would serve                378
    32 bytes too small for the run              3
```

```
upper halves live at once, where no register was free
  1   1,112      2   216      3   32      4   4
```

**The size is not the constraint.** Three runs in the binary need more than the two slots
32 bytes provides. What binds is that 983 of the 1,364 -- 72% -- are in functions that
cannot lend it.

#### And the reason is a refusal of this project's own making

`home_space_map` demands a call, no self-addressing, no frame register, and -- since the
aliasing hole was closed -- no `lea` into the region and **no copy of `rsp` into another
register at all**. That last one is broad: most copies of `rsp` are followed by bounded
uses, and it already cost 1,655 sites on the spill.

So the ceiling on the home space, for both uses, is not the ABI or the 32 bytes. It is one
conservative scan, and narrowing it needs dataflow on where a copied `rsp` goes rather than
a regular expression. **That is the single measurement standing between this mechanism and
whatever it is really worth**, and it is the same measurement for the spill and the shadow.

378 sites is not worth building for on its own, so it is recorded rather than done. The
correspondence between the two lifetimes is worth more than the number, because it says
Class Y2's shadow does not need a reserved register or a TLS slot after all -- it needs
permission from the function it sits in.

### Finding 72 -- the dataflow was the lever, and it is worth thirteen sites

Finding 71 named one analysis as "the single measurement standing between this mechanism
and whatever it is really worth": narrowing the refusal of any function that copies `rsp`,
by tracking where the copy points. It is built, measured and reverted.

```
--spill=home, blanket refusal      17,972
--spill=home, with the dataflow    17,959     13 sites
```

The taint analysis is straightforward -- a register receiving `rsp` carries an offset, an
access through it at `d` lands at `offset + d`, and anything else done with it is an escape
-- and of the **2,367** starved sites whose function copies `rsp`, it clears thirteen. A
function that makes a pointer to its own frame bottom essentially always uses it in a way
no scan can vouch for.

#### And the first attempt made things worse, which is the more useful half

The first version also tracked `lea d(%rsp),%rX`, and **lost 625 sites**. A `lea` above the
home space is a pointer to a local, passed to callees all day long, and treating it as
tainted refused every function that does so. A callee reaching back below the object it was
handed would be a bug in the callee, not a risk this has to price -- and `lea` *into* the
region is refused outright anyway. Precision applied in the wrong place is not precision.

#### Where the home space actually goes

```
sites with no xmm scratch                   5,699
  copies rsp somewhere                      2,367
  usable                                    1,531
  a leaf: no home space at all              1,506
  addresses [rsp+0..31] directly              264
  a frame register: rsp not constant           31
```

The two big refusals are **a function that copies `rsp`** and **a function that is a leaf**,
and neither is a scan being timid. A leaf genuinely has no home space -- nothing reserved
it. And the copy case is not conservatism either: the dataflow proves it.

This also qualifies Finding 70's "one function in 273,902". That counted direct `(%rsp)`
accesses, and the 2,367 above are functions that could be reaching the same region through
a register. The region is dead *as written*, which is a weaker statement than it read as.

**So the home space is worth what it is worth: 1,022 sites, and there is no adjacent
analysis that unlocks more.** That closes the last identified lever in the residue.

### Finding 73 -- `--spill=home` is the default

Taken by the copyright holder on the evidence of Findings 70 to 72, after the mechanism was
built, executed, holed, patched and measured against its own alternatives.

```
in place                                      547,613
detoured                                      195,510
skipped for overlap                            36,677
refused, stub not buildable                     4,290
VEX in .text            805,131 ->      17,972   787,159 removed, 97.8%
```

What it did to the refusal list is sharper than the total suggests:

```
src2 aliases dst, no scratch      3,728  ->      43
sequence with no usable scratch     855  ->      87
                       new: no home space to borrow  3,426
```

**The scratch problem is essentially gone where the home space exists**, and what replaces
it is a single honest counter for the functions that cannot lend one -- 1,506 leaves with
nothing reserved, 2,367 that copy `rsp` where it cannot be followed, and the rest.

Every invariant holds on a freshly built binary with the new default: headers
self-consistent, the function table sorted and covering every stub byte, every section
after `.text` byte-identical, all 77,763 lost boundaries deliberate, all 1,191,070 direct
branch targets still instruction starts, zero VEX in the stub section, and `make census`
reconciling every survivor with nothing unaccounted.

The other three modes stay. `stack` and `pool` carry measurements a future reader will
want, and `none` is what a reader comparing against them needs. `make check-spill` runs
all four.

**What is not proven, and cannot be here.** 1,022 sites now write into the translated
program's own stack frame, on the strength of a per-function scan and an ABI argument.
Fifteen small PEs execute the mechanism. Starfield has now been run (Finding 74) and did
not fault, but it got 866 bytes, so that is not evidence about the home space -- nothing
says one of the 1,022 sites was on the path, and a borrowed home slot corrupts silently
rather than faulting anyway. If a function reaches its home space by a path the scan does
not model, the result is silent corruption of a live local -- the same shape as the five
defects this project has already found by reading rather than by running.

### Final state

```
in place                                      547,613
detoured                                      195,510
skipped for overlap                            36,677
refused, stub not buildable                     4,290
VEX in .text            805,131 ->      17,972   787,159 removed, 97.8%
```

Every invariant holds on a freshly built binary: the file grows only by the stub
section, every section after `.text` is byte-identical, all 77,763 lost boundaries
are instructions a widened window swallowed deliberately, none of the 81,985
swallowed is reachable by any branch, and the stub section carries 0 VEX with
exactly one jump back per detour. `make census` reconciles every survivor to a named
cause with nothing unaccounted.

**The 95.0% is honest in a way the earlier figures were not.** Findings 25 and 37 both
found silent wrongness that every structural check had passed, and the numbers before
them were inflated. Anything in this document above Finding 37 that reads higher is
counting truncated 256-bit sites as successes.

What remained at 95.0%, and what remains now. The right-hand column is the collector's
declines under the `--spill=home` default, re-measured for Finding 74:

```
                                        95.0%    --spill=home
ymm value has no known upper half        4,601        12,552   outside any accepted window
no home space to borrow                  2,496         3,426   a leaf, or rsp copied away
ymm upper half read later                1,766         1,591   what the edges could not resolve
no direct SSE form                         710           710   mostly vextractf128/vinsertf128
next instruction is a branch target        511           524
no register free across the ymm run        446           424   needs a helper
next instruction transfers control         424           427
outside .pdata                             403           403
ymm run upper half read later                -            90   the run's own version of it
sequence with no usable scratch            780            87
src2 aliases dst, no scratch                31            43   what the home space could not take
ymm store is a branch target                25            25
sequence shape not handled                 164            14
operand shape not A/B/C                      9             9
                                                     -------
                                                      20,325
```

Those categories account for the *collector's* refusals, which is a different population
from the survivors -- `make census` exists because subtracting one from the other is the
mistake.

**That right-hand column is only trustworthy from Finding 76 onwards.** Before it, `ymm
upper half read later` read as zero and `no register free across the ymm run` as 911,
because the collector computed the pair's reason, held it back, and then discarded it
whenever the run strategy declined -- filing 1,591 sites under register pressure when it
already knew they were blocked on a later 256-bit read of a stale upper half. Findings 75
and 76 measured that and fixed it, and the column above is post-fix. Any earlier version
of this table in this document is mislabelled in exactly that way.

### Finding 74 -- Starfield runs, and the frontier moved 866 bytes

"Starfield has never been run" stood in *What is still not verified* from the beginning.
It has now, under Proton 10.0 on this Westmere. The installed game was not disturbed:
both binaries were copied in beside `Starfield.exe` under new names, and the run used a
scratch prefix rather than the game's own.

Both die. That was the prediction -- 17,972 sites survive -- and **where** each dies is
the measurement.

```
              faults at                 the instruction there
original    RVA 0x22d2bf4     vpxor   %xmm0,%xmm0,%xmm0
rewritten   RVA 0x22d2f56     vmovups -0x29(%rbp),%ymm0
```

866 bytes, inside the same function, reached through the same eleven-frame call stack.
Both faults are `EXCEPTION_ILLEGAL_INSTRUCTION`, which is what a Westmere does with a VEX
prefix.

#### What the 866 bytes contain

Four VEX sites in the original, none in the rewritten, two of them detoured:

    1422d2bf4   vpxor   %xmm0,%xmm0,%xmm0     ->  pxor %xmm0,%xmm0       in place
    1422d2bf8   vmovdqu %ymm0,-0x51(%rbp)     ->  jmp 0x148bbfbfd        stub

    148bbfbfd   movdqu %xmm0,-0x51(%rbp)
    148bbfc02   movdqu %xmm0,-0x41(%rbp)
    148bbfc07   jmp    0x1422d2bfd

That is the Class Y zero fill executing for real, and it is the case Finding 40 named as
a debt. `pxor` does **not** zero [255:128], so the in-place lowering leaves ymm0's upper
half stale -- and it does not matter, because `zeroed_ymm` proved the stored *value* is
zero and the stub writes 32 bytes of zeros in two halves rather than reading the
register's upper one.

**The first stub this project ever wrote into a 110 MB binary was entered and returned
from.** Instructions run in sequence, so reaching 0x22d2f56 requires the `jmp` at
0x22d2bf8 to have been taken and the stub to have come back to 0x22d2bfd.

#### The unwinder is the result that could not be manufactured here

The fault forces wine to walk the rebuilt function table -- 431,937 entries, 299,780 bytes
of unwind info, at a base the original PE never had. Both runs produce the **same eleven
frames**:

    22d3adb  22c7474  186eefb  22c7910  22c7774  28cb219  28cbbc5
    2b7e38   1039     ucrtbase+29e92    365d80c

`detour-verify` already checks that the table is sorted and covers every stub byte, but it
checks our table with our code. This is `RtlLookupFunctionEntry` binary-searching it
431,937 entries deep, eleven times, and agreeing with the original binary's stack exactly.
**It is the first witness to the exception directory that is independent of the tool that
wrote it.**

It is also narrower than it looks, and the narrowing is the honest part: **no unwound
frame was inside the stub section.** The chained-`RUNTIME_FUNCTION` path of Finding 48 --
the thing `make check-unwind` exists for -- was not exercised, because the fault happened
in `.text` with no stub on the stack. What is confirmed at scale is the lookup and the
coverage, not the fragments.

#### What else did not happen

The rewritten run raises exactly the same exception sequence as the control -- `6ba`,
`c000001d`, `c000001d`, `6be`, `6ba` -- and **not one access violation** in either. 287
modules load before the fault against the control's 288: the whole graph, including
`steam_api64.dll`, `sl.interposer.dll`, `bink2w64.dll`, `libxess.dll` and `dxgi.dll`.

So 547,613 in-place patches and 195,510 detours sit in the address space of a process that
loaded 287 modules and ran several hundred milliseconds of its own startup, and nothing
structural broke. That is weak evidence per instruction and strong evidence about the
file: the image loads, the sections are where the loader expects them, the TLS directory
survived, and the relocations are consistent.

#### The site it died on is refused for the right reason under the wrong name

`vmovups -0x29(%rbp),%ymm0` followed immediately by `vmovups %ymm0,-0x51(%rbp)` is an
adjacent copy pair -- the Y1 shape of Finding 38, which needs **no helper register at
all**: load the low half into the destination's own xmm and store it, then the high half.
The collector refused it for `no register free across the ymm run`, which reads as a
missed fallback -- as though the run strategy had claimed a site the pair could have had.

**It is not, and the code says so above the loop.** The pair is tried *first*, precisely
because it needs no helper; the run is the fallback for the pair rather than the other way
round, and `collect` says as much at `tool/detour.py:1620`. What the run's `continue`
discards is not the pair strategy -- that has already run and failed -- but the pair's
**reason**, which the same comment promises to keep: "its reason is held back and only
recorded if the run declines too". It is not. All four run-decline branches record their
own reason and return to the top of the loop, and the held-back one goes with them.

So for this site both refusals are real and the order was: the pair failed because ymm0's
upper half is read downstream, the run then failed for want of a helper, and only the
second was written down. Suppressing `ymm_run` for that one address makes the first
surface -- `ymm upper half read later` -- which is how the order was established rather
than guessed.

**The label is wrong and the verdict is right.** What is open is not whether a fallback
exists -- one already does -- but whether the discarded reasons hide anything: a site
where `ymm_pair` returned `None`, so no pair was ever attempted, drops to the zero-fill
and ordinary paths when its run declines, and those could in principle take it. That is
the measurement, and it is the cheapest lead in the residue.

#### What it is not

**This is a frontier moving, not a game starting.** It got 866 bytes, and the next
survivor being 866 bytes away is the honest scale of 17,972 remaining sites on a hot path:
how far it gets is measured in instructions, not in frames. Nothing here says a lowering
computed the right *value* -- only that four of them did not fault and the code after them
behaved as the original's did.

#### How to reproduce it

    cp build/Starfield-unpacked-detour.exe "$GAME/Starfield-antiavx.exe"
    STEAM_COMPAT_CLIENT_INSTALL_PATH=~/.steam/steam \
    STEAM_COMPAT_DATA_PATH=/some/scratch/prefix \
    PROTON_LOG=1 PROTON_LOG_DIR=/some/scratch \
      "$PROTON/proton" run "$GAME/Starfield-antiavx.exe"

`PROTON_LOG=1` is what makes it a measurement rather than a crash: the fault address, the
register file and the whole unwind walk are in `steam-1716740.log`, and diffing that
against the same run of the unpacked original is where every number above comes from.
Copy the binary in under a new name -- replacing `Starfield.exe` gains nothing and Steam
will silently repair it.

### Finding 75 -- the shadowing costs no sites, and a fallback would cost accounting

Finding 74 left one lead: the run path discards the pair's held-back reason, so 2,101
sites are filed under a run reason. Whether that hides a site some other strategy would
take is now measured, and the answer is no.

Two collector passes over the full listing, both carried through `place_stubs` so the
number counts sites actually placed rather than merely accepted. The second suppresses
`ymm_run` for exactly the 2,101 addresses the first saw the run path decline and for no
others -- which is the fallback exactly, since every run that succeeds still succeeds and
therefore no other window moves and overlap resolution is not perturbed.

```
                                  as it stands    with the fallback
detoured                               195,510             195,510    +0
skipped, window overlapped              36,677              36,677    +0
refused, stub not buildable              4,290               4,804   +514
```

**Zero of 2,101.** Not one site the run path declined is lowered by falling through, and
none of them was being quietly covered by a neighbour's window either.

Where they go instead:

```
ymm upper half read later                1,587   the held-back pair reason, surfacing
accepted, then the stub would not build    514
```

The 1,587 are what Finding 74 predicted from one site: a pair was tried, it failed because
the destination's upper half is read downstream, and the run's failure was written down
instead. Every one of them is a real refusal.

The 514 are the case that pair reason could not describe -- `ymm_pair` returned `None`, so
no pair was ever attempted. Suppressing the run drops them to the zero-fill and ordinary
paths, which accept them as candidates, and then `build_stub` refuses all 514. **That is
worse than neutral.** `build_stub` returns `None` with no reason and no counter names it,
so the fallback would convert 514 precise collector refusals into invisible build-time
ones -- the failure mode Finding 45 had to walk its three steps by hand to diagnose.

#### So the fallback is not implemented

It lowers nothing, and it degrades the accounting for a quarter of the sites it touches.
Recorded here rather than left as an open lead, so it does not get had as an idea again.

#### The labelling defect is real, and it is a different change

`collect` states the intended behaviour at `tool/detour.py:1620` -- "its reason is held
back and only recorded if the run declines too" -- and does not do it. All four
run-decline branches record their own reason and `continue`, and the held-back one goes
with them.

The consequence is now measured rather than asserted: **1,587 of the 2,101 are really
`ymm upper half read later`.** That is a different instruction to whoever picks this up.
`no register free across the ymm run` says register pressure and points at the helper
allocator; `ymm upper half read later` says the Y1 register representation, which is
milestone 5 and would take all 1,587 at once. The current categories point at the wrong
work.

Fixing it changes no output byte -- only `skipped` and `declined`. **Done in Finding 76**,
as its own increment, because it moves numbers this document quotes in several places.

### Finding 76 -- record the held-back reason, and let the check find the four

`held_back(pair_reason, run_reason)` returns the pair's reason where there is one, and all
four run-decline branches route through it. That is the whole change. It carries its
reasoning in a docstring rather than at the call sites, because which of two refusals is
the more specific is not obvious from where they are recorded.

#### The proof, and what it caught

A mechanical change carries a proof, so the invariant was stated before the run: `skipped`
and `declined` feed the census and the plan and nothing else, so **no placement number may
move**, the same addresses must be declined, and the histogram over them may move in the
five keys `held_back` can touch and nowhere else, with the deltas summing to zero.

```
placed        195,510   unchanged
overlapped     36,677   unchanged
refused         4,290   unchanged
declined       20,325   unchanged

no register free across the ymm run     911 ->   424    -487
ymm run upper half read later         1,190 ->    90  -1,100
outside .pdata                          407 ->   403      -4
ymm upper half read later                 0 -> 1,591  +1,591
                                                       ------
                                                            0
```

**The first version of the check failed, and it was the check that was wrong.** It
predicted 1,587 relabelled sites, from Finding 75, and found 1,591. Finding 75 derived its
number by suppressing `ymm_run` over the two reasons *only* the run path can produce -- and
the run path has a fourth decline branch that emits `outside .pdata`, a string the ordinary
path emits too, so it was deliberately left out as unattributable by name. `held_back`
reaches it anyway and should: a site whose run window falls outside `.pdata` is still a
site whose pair was tried and refused for a better reason. Those are the four, and
`407 -> 403` is where they came from.

That is the shape `evidence.md` names -- a gate disagreeing with code believed correct is
the first suspect -- and it is worth recording that the gate earned its keep by disagreeing
rather than by passing. A check that had predicted 1,591 from the start would have proved
less, because nobody would have had to find out where the four came from.

#### What it does not change

**Nothing executes differently.** No candidate, no window, no stub, no byte of any
rewritten binary. `make check` and `make check-pe` pass unchanged, and they would pass
identically with the change reverted, because neither reads a decline reason. The evidence
that this is correct is the reconciliation above, not a test going green.

What it changes is where the next reader looks. 1,591 sites now say the Y1 register
representation would take them, and 424 still say the helper allocator would -- which was
the actual proportion all along.

#### The artifact agrees, which the counters could not prove

The reconciliation above is about counters. A rebuild is about bytes:

```
before  8d0ddf6799ad7ee6b48002b52164662f79321ab2b3c93a194c36e7024a49f690
after   8d0ddf6799ad7ee6b48002b52164662f79321ab2b3c93a194c36e7024a49f690
```

A full `make detour` with the change in -- 547,613 in-place patches, 195,510 detours, a
3,143,556-byte `.avxsse` at 0x148988000, 431,937 function table entries -- reproduces the
binary bit for bit, and run under Proton again it faults at `0x1422D2F56`, the same
address, with the same exception sequence and the same eleven frames as Finding 74.

Two things follow, and the second was not being claimed before:

- **`held_back` moved no output byte.** Asserted from the counters, now checked against
  the artifact, which is the stronger statement of the two.
- **The pipeline is deterministic.** The same binary and listing in gives the same
  110,869,504 bytes out, across a rebuild hours later with the source edited in between.
  Nothing in `apply` depends on a timestamp, a set iteration order or a hash seed. That is
  worth knowing on its own: it makes `sha256sum` the cheapest possible regression test for
  any future change that is meant to be output-neutral, and this is the first time the
  property has been checked rather than assumed.

### Finding 77 -- the allocator keys on lifetimes, before it has to

The first piece of the Y1 register representation, and it changes nothing today. That is
the point of it.

#### What the measurement actually said, after being wrong twice

The first pass counted 12,552 surviving 256-bit stores and was inflated about tenfold. A
256-bit store is declined at **its own** index, where `ymm_pair` sees no load and `ymm_run`
refuses a store -- so every non-zero-fill store lands in `ymm value has no known upper
half` even when the pair window started at its load already covers it. `census`'s docstring
names exactly that trap and the diagnostic walked into it anyway. Excluding sites inside a
placed window:

```
256-bit stores whose value is not a known zero    12,552
  already covered by a pair or run window          7,828
  genuinely unreached                              4,724
    a copy whose load is too far to pair           3,092
    something else (vpxor)                         1,106
    a computed 256-bit value                         354
    no defining write within 200                     136

of the 3,092 copies, what stops the run:
  nothing -- the run reaches it                    2,286   median span 1
  a 256-bit op that is not a copy half               468   median span 4
  a branch target inside the span                    186   median span 3
  a control transfer inside the span                  89   median span 13
  the value is touched other than by a store          63   median span 9
```

**The forward walk is not the blocker.** For 2,286 the run reaches the store and the site
is refused downstream -- 1,591 for `ymm upper half read later` and 424 for `no register
free` account for almost exactly that population.

One block was read closely on the way and it misled: at `0x14004e230` a run dies because a
128-bit write to `%xmm0` clobbers the low half of a tracked register, and `ymm_run` ends
the **whole** run rather than dropping that one register -- leaving `vmovups %ymm1` at
`0x14004e304` behind, though ymm1 was never touched. That reads like the lever and the
count says it is 63 sites. **An example is not a distribution**, and this document has now
recorded that lesson three times: Finding 39 about the gapped pair, Finding 44 about the
backward walk, and here.

#### The rekey, and why it lands before the thing that needs it

Dropping a clobbered register and carrying on means a register can be loaded, stored,
clobbered and loaded again inside one run. `assign_helpers` kept the LAST load and LAST
store per register, so both lifetimes would get one helper and **the earlier lifetime's
store would read a helper the later lifetime had not loaded yet** -- assembling cleanly,
verifying cleanly, and storing the wrong sixteen bytes. That is the sixth member of the
silent-wrongness family this project keeps finding.

So `lifetimes()` returns each `(register, load position, store positions)` and
`assign_helpers` keys its result on **position**, letting `lower_ymm_run` ask which helper
*this* load or store uses rather than which helper this register uses.

```
before  8d0ddf6799ad7ee6b48002b52164662f79321ab2b3c93a194c36e7024a49f690
after   8d0ddf6799ad7ee6b48002b52164662f79321ab2b3c93a194c36e7024a49f690
```

**The bug was latent, and the identical hash is what proves it.** The two keyings can only
agree on all 195,510 placements if no run today holds two lifetimes of one register, which
is exactly what `ymm_run` guarantees by ending at the first touch. The prerequisite is in
before the change that would have made it live, which is the order that costs nothing.

### Finding 78 -- a loop is examined, not unknowable

`upper_half_read_later` answered "read" when its walk returned to a position it had
already recursed through. That refusal was the largest after a genuine read.

#### Splitting the refusal first

The 1,591 sites declined `ymm upper half read later` are not one thing, and the check
reaches its verdict from five different places. Classified by which one fires -- the check
reimplemented with a reason attached, since it recurses through the module global and a
wrapper cannot see which of its own `return`s fired:

```
genuinely read                 1,017    60.5%
  read by vmovups                979    a SECOND 256-bit store of the same value
  read by vextractf128            30
  vmulps, vmovdqu, vinsertf128, vpsadbw   8
the scan giving up               664    39.5%
  a back edge                    487
  the path budget ran out        171
  an indirect branch               6
```

**A read needs the ymm represented as two xmm registers; a give-up needs only a better
scan.** The second is analysis, changes no emitted byte, and is where this went.

#### The argument

`visiting` holds the branches the current path has already recursed through. Returning to
one means every instruction on that cycle has been examined and none of them read the
register -- a read would have returned `True` before the walk got back. Going round again
examines the same instructions and explores the same successors, because the walk is
path-insensitive and takes **both** edges at every branch it can resolve. So the cycle
contributes nothing, and the path is dead rather than unknowable.

Termination is unaffected: the case returns without recursing, and `limit` and `budget`
bound the walk exactly as before.

#### What it is worth

```
placed        195,510 -> 195,803   +293
declined       20,325 ->  20,030   -295
  ymm upper half read later      1,591 -> 1,303   -288
  ymm run upper half read later     90 ->    83     -7
```

**295 of the 487, not all of them.** Resolving the back edge lets the walk carry on, and
some sites then meet a genuine read or exhaust the budget instead -- the first blocking
reason was never the only one. Two of the 295 lose their window to an overlap, so 293
placements.

On the real binary, rebuilt and verified:

```
VEX in .text     805,131 ->  17,379      787,752 removed, 97.8%
                             17,972 before
function table   431,937 -> 432,230      one entry per stub, +293
stub section   3,143,556 -> 3,151,150 bytes
```

**593 sites for 293 detours**, because a window swallows more than the site that opened
it -- a pair is two, a run more. Every `detour-verify` invariant holds unchanged: the
headers self-consistent, the table sorted and covering every stub byte, every section
after `.text` byte-identical, all 77,970 lost boundaries deliberate, all 1,191,070 direct
branch targets still instruction starts, and zero VEX in the stub section with exactly one
jump back per detour.

#### The test, and breaking it on purpose

`make check-pe` gains `loopcopy`: a copy pair followed by a loop that touches only `%ecx`.
**The loop body must not mention the ymm or the program tests nothing** -- a loop that
reloaded it would end the walk at a full overwrite, which is a different rule that already
worked, and the walk would never reach the back edge at all.

```
with the rule      loopcopy -- original 29, rewritten 66, want 66
rule reverted      loopcopy -- original 29, rewritten 29, want 66   FAIL
```

The second line is the one that matters. A new test passing is not evidence that it tests
anything, and this one was checked by putting the old answer back and watching the program
die at 29 again.

#### And the horizon underneath it, which is not a defect

This rests on `upper_half_read_later` at all, so the assumption underneath was settled
first: the walk falls out of its loop to `return False` after 40 instructions, which is
"forty instructions with no call, no branch and no mention of this ymm implies nothing
reads it" -- a number someone chose rather than an argument. Over all 7,540 accepted
pair/run sites:

```
a call or ret ends it     3,384    sound -- Win64 makes every ymm upper half volatile
every successor is dead   2,199    sound -- Finding 42's edge following
overwritten entire        1,889    sound -- a full 256-bit write consults nothing
EXHAUSTED THE HORIZON        68    resting on the assumption
```

**68 of 7,540, and a walk ten times deeper finds a genuine read in none of them.** The
assumption is unproven and empirically clean; 68 is small enough to enumerate if it ever
needs hardening.

### Finding 79 -- the instruction that kills an upper half and does not say so

Finding 78 left 1,303 sites refused for `ymm upper half read later`, and named the shape of
the largest part: 979 blocked by a later `vmovups` that reads the register, which is a
**second 256-bit store of the same value**. `ymm_run` exists for exactly that -- Finding 51
put it in, "a store does not end the value's life" -- so the question was never how to lower
the second store. It was what stops the run reaching it.

```
what blocks the 1,386 declined sites   for those, what stops the run
  read by vmovups          998           the value is touched (vpxor)    558
  the budget ran out       343           the value is touched (vmovsd)   254
  read by vextractf128      27           nothing -- the run reaches it   104
  an unresolved branch      11           a control transfer               47
```

**812 of the 998 are stopped by an instruction writing the register's low half**, and that
is not a run problem at all. It is the scan reading the wrong thing.

#### The blind spot

`vpxor %xmm0,%xmm0,%xmm0` **zeroes bits [255:128] of ymm0.** That is architecture, and it is
the same fact Class Y1-zero is entirely built on. So the upper half a pair is about to leave
stale is dead from that instruction onwards, and nothing after it can observe the
difference.

`upper_half_read_later` searched the operand text for `%ymm0`. Those operands say `%xmm0`.
So the walk stepped over the instruction that **ends the upper half's life** and reported
the 256-bit store beyond it as a live use. One spelling, 812 sites.

The fix is five lines, and the VEX test in the middle of them is load-bearing rather than
defensive: **a legacy SSE write to xmm leaves [255:128] alone**, so matching on the
destination alone would be wrong on precisely the instructions this project emits. Getting
that backwards turns a missed lowering into silent corruption.

#### What the spelling was costing

```
                        before 78    after 78    after 79
placed                    195,510     195,803     196,945
declined                   20,325      20,030      18,882
ymm upper half read later   1,591       1,303         225
```

**+1,142 sites for Finding 79 on its own**, and the category is 86% gone. `ymm run upper
half read later` follows it from 90 to 13.

Rebuilt and verified on the real binary:

```
VEX in .text     805,131 ->  15,083      790,048 removed, 98.1%
                             17,972 at the start of the two findings
function table   431,937 -> 433,372      one entry per stub, +1,435
stub section   3,143,556 -> 3,179,378 bytes
```

**2,889 sites for 1,435 detours**, the same better-than-one-for-one as Finding 78 and for
the same reason: a window swallows more than the site that opened it. Every `detour-verify`
invariant holds -- headers self-consistent, the table sorted and covering every stub byte,
every section after `.text` byte-identical, all 79,097 lost boundaries deliberate, all
1,191,070 direct branch targets still instruction starts, zero VEX in the stub section with
exactly one jump back per detour.

**This is the first time the figure has moved since Finding 73**, and both findings did it
by reading the existing code more accurately rather than by emitting anything new.

#### The condition this rests on, stated rather than assumed

After the pair, this binary's ymm0 upper half is **stale where the original's is zero**. The
lowered `pxor %xmm0,%xmm0` does not zero it, because SSE does not. So every later 256-bit
read of that register must be either a provable zero store -- lowered from `zeroed_ymm`'s
proof, which writes zeros and never reads the register's upper half -- or refused outright.
Both hold: `ymm_run` breaks the moment a tracked register is touched, and `zeroed_ymm`
proves the zero independently of any of this.

That is **Finding 40's Y3 debt**, and it is worth being explicit that this change leans on
it rather than adding to it. The debt is the same one the whole 256-bit design already
rests on: a lowered VEX.128 write no longer zeroes the upper half, which is harmless while
every unprovable 256-bit read is refused, and will need repaying when the Y2 shadow exists.

#### What Finding 79 did to the population it did not take

The 343 sites the split attributed to the path budget were measured **before** this change,
and it moved them: a walk that now ends at a VEX.128 write is a walk that never reaches the
budget. Re-measured afterwards, the residue is 238, and the budget's share of it is **124,
not 343**. A bucket count taken before a change is not a forecast of what that change
leaves behind, which is the third time this document has had to say so.

#### The test, and the consequence it checks

`make check-pe` gains `lowwrite`: a pair, a `vpxor` on the same register's low half, and a
256-bit store after it. It checks the consequence and not merely the mechanism -- the second
store must land as 32 bytes of **zero** while the first lands as the copy, so the program
returns `77 + 0`. A lowering that leaked its stale upper half into the second store returns
something far from 77 rather than something next to it.

```
with the rule      lowwrite -- original 29, rewritten 77, want 77
rule reverted      lowwrite -- original 29, rewritten 29, want 77   FAIL
```

**The check that measured this reported the opposite first, and was wrong.** It counted any
deeper "read" as a counterexample and announced eleven -- every one of which was the deeper
walk *giving up*, ten at a back edge and one at the budget, because a 400-step walk crosses
more of both than a 40-step one. A probe that cannot tell a real read from its own
conservatism returns a negative that reads exactly like a finding. `evidence.md` names it:
a failing check is not evidence either.

### Finding 80 -- a constant with a measurement behind it

`PATH_BUDGET = 400` bounded how many instructions `upper_half_read_later` may examine
across every path it follows from one site. It is a safety valve rather than a knob -- the
walk takes both edges of every branch it can resolve, so a branchy region costs
exponentially in paths and something has to stop it -- and 400 had **no measurement behind
it at all**.

It was binding on 124 sites. Raising it is very nearly free, because only those 124 walks
ever reach it: the other ~805,000 stop at a call, a full overwrite or a resolved branch long
before. Measured end to end, `collect` plus `place_stubs` on the real binary:

```
budget       placed      gain    seconds
   400      196,945         --       213
 4,000      197,025        +80       214
40,000      197,051        +26       213
400,000     197,062        +11       215
```

**+80, +26, +11 against a flat 213 seconds.** The gain is asymptotic and the cost is not
there, which is the whole shape of the finding: a bound that almost never binds costs
nothing to loosen, and 400 was quietly refusing sites for no reason anyone had priced.

Rebuilt and verified:

```
VEX in .text     805,131 ->  14,871      790,260 removed, 98.2%
                             15,083 before
function table   433,372 -> 433,478      one entry per stub, +106
```

Every `detour-verify` invariant holds, and 212 sites go for 106 detours -- the same
better-than-one-for-one as Findings 78 and 79, a window swallowing more than the site that
opened it.

**40,000 was chosen off that curve as the knee, and it was the wrong column to read.**
The argument was that the last point buys only eleven more sites for a bound ten times
looser. Sites are not fungible. Eleven in code that never executes are worth nothing, and
one in the loop the game runs during startup is worth the whole difference -- and the
aggregate count cannot tell them apart, so it decided on a metric blind to the only
distinction that mattered.

**The site Starfield dies on is one of the eleven.** `0x1422d2f56`, the copy pair inside a
loop that Finding 74 recorded and that survived Findings 78 and 79 as well. It is not path
explosion: the walk answers "dead" after consuming 200,196 of the budget in 0.1 seconds, so
it was only ever expensive. At 40,000 it is refused, and the game stops there.

So **400,000**, and the cost side never moved -- 215 seconds against 213, inside the noise,
because the valve binds on barely a hundred walks out of 805,000. Removing the bound
outright would still be wrong: this tooling is not Starfield-specific, and a valve whose job
is to terminate on an unseen binary has to have a number.

#### What is left is not a budget problem

44 sites blew through even 4,000. Those are **path explosion**: the walk re-examines the
same successors along different prefixes, so work that should be linear in the region is
exponential in paths. A memo collapses that, and it has to be a **one-way** one --

- caching a **"read"** is sound, because a read found from a position exists whatever
  prefix reached it;
- caching a **"dead"** is not, because Finding 78 made a revisited branch terminate as
  dead, so a "dead" answer depends on which branches were in `visiting` when it was
  computed. Reused under a shorter prefix it would skip paths that do contain a read.

That asymmetry is the whole difficulty, and it is why this is a rewrite of a load-bearing
analysis rather than a dictionary. For 44 sites it is not obviously worth doing, and it is
recorded here so the next person does not have to rediscover which direction is safe.

### Finding 81 -- short zero stores compete for the same padding

Finding 80 moved the frontier to `0x14186e921`, and what stopped it there was three
consecutive 256-bit zero stores -- Class Y1-zero, a lowering that has existed since
Finding 40, refusing to apply.

#### Why a lowering that exists does not reach them

`vmovups %ymm0,(%rax)` with no displacement encodes in **four bytes** and a `jmp rel32`
needs five, so the site has to widen its window over a neighbour. Where the neighbour is
another 256-bit store, `build_stub` has to lower it as a swallowed instruction -- and
`lower_vex` refuses VEX.L, as Finding 37 made it. The stub cannot be built, and the whole
group is lost.

That is why they show up as lost *after* the collector rather than declined by it:

```
256-bit stores of a provably zero register
  lowered                                        9,468
  surviving                                        327
    4 bytes                                        325
    5 bytes                                          2
  (not declined -- lost after the collector)       323
  outside .pdata                                     4
```

`zero_run` takes a consecutive group as **one window**, already longer than five bytes, so
nothing widens and each member lowers through `lower_ymm_zero_store` instead of through the
general path that refuses it.

```
VEX in .text     805,131 ->  14,547      790,584 removed, 98.2%
                             14,849 before
refused, stub not buildable    4,289 ->   3,987     -302, exactly the gain
```

#### Two mistakes, and the second nearly threw the feature away

**The first version grouped every zero store**, including the 9,468 that lowered perfectly
well alone. **The second read the wrong column.** `gain.py` reports `placed`, which counts
*windows committed* -- and a run collapses several windows into one **by design**, so a
working run necessarily drives that number down. It fell by 1,888 and was reported here as
a net loss of sites. It was nothing of the kind.

The column that was pointing the right way throughout is `refused`, down 302 in both the
narrow and the wide version -- the same number, which is also the evidence that the two
rescue the same sites and the narrowing only avoids collapsing windows that did not need
collapsing.

**A metric that cannot see the thing being changed is worse than no metric**, because it
produces a confident number. This is the fourth time in one sitting that a count measured
something adjacent to the question -- the stores that ignored already-covered windows, the
pair checks that ignored the run succeeding, the horizon probe that counted its own
conservatism, and now windows standing in for sites. The pattern is always the same: the
quantity was easy to obtain and nobody asked what it excluded.

#### The test had the same fault and passed anyway

`check-pe` gains `zerorun`, three consecutive zero stores. **The first version put an
`addq` between them** -- which is padding, exactly what the real code does not offer -- so
each store could widen on its own and the program would have passed with the feature
reverted. Only the mutation caught it:

```
with the rule      zerorun -- original 29, rewritten 88, want 88
rule reverted      zerorun -- original 29, rewritten 29, want 88   FAIL
```

The addressing in the committed version is deliberately bare, `(%rax)` and then
displacements off the same register, because a displacement makes the instruction five
bytes and dissolves the entire difficulty being tested.

### Finding 82 -- the store that was itself the branch target

**A shipped miscompilation, and the sixth of this shape.** Found by chasing why the
frontier did not move after Finding 81, which is not what the chase was for.

`zeroed_ymm` walks back from a 256-bit store to the nearest write of its register, and
refuses a **branch target** it passes over. Its own docstring gives the reason: "another
path reaches the store without passing the zeroing". The walk starts at `index - 1`. It
never looked at the store's own address, where that reason is exactly as true.

At `0x1424e3b5f`, in the binary this project had built and verified:

```
original                            rewritten
1424e3b55: jmp 0x1424e3b5f          jmp 0x1424e3b5f        unchanged
1424e3b5b: vxorps %xmm0,%xmm0,...   xorps %xmm0,%xmm0
1424e3b5f: vmovups %ymm0,0x0(%rbp)  jmp 0x148bf1fe7        detoured

148bf1fe7: movups %xmm0,0x0(%rbp)
148bf1feb: movups %xmm0,0x10(%rbp)  the low half, into both halves
```

Two paths reach that store. The fall-through zeroes ymm0 and the lowering is right; the
`jmp` skips the `vxorps` entirely, and on that path ymm0 holds something else while xmm0
holds something else again. The stub writes the low half twice -- 32 bytes wrong, silently,
in code that runs.

```
256-bit stores zeroed_ymm calls zero          9,795
  the store is ITSELF a branch target            21
    and lowered into a stub, so shipped           2
```

The fix is one test at the top of the walk, and it costs the two sites it was wrong about.

#### Why `check-pe` has no program for this

It was written and then removed, which is worth recording because the reasoning applies to
the whole class. The correct handling of such a site is to **refuse** it -- and a refused
VEX instruction is still VEX, so the program dies at 29 on this CPU. `check-pe` asserts
that the rewritten binary *runs and returns a value*; a program whose correct outcome is
"this must not be lowered" has no such value, and the harness cannot express it.

The program was built, run, and observed to return 29 with the fix in place. That is the
right answer and an unrepresentable one, so the evidence for this finding is the
measurement and the disassembly above rather than a green test. **Saying so is better than
contorting the program into something that passes**, which would have tested the contortion.

#### What the other nineteen are, which matters for how much to worry

All 21 were checked rather than assumed, and they are not one thing:

```
a forward jmp that skips the zeroing        1   0x1424e3b5f, shipped, wrong
an indirect target (reloc/pdata/switch)     1   0x14091d538, shipped, unknowable
a loop back-edge, the store being the head 19   correct, and unprovably so
```

The nineteen are `memset` loops and they all look like this:

```
14092c3f0: vmovups %ymm0,(%rax)        <- the loop head, and the store
           vmovups %ymm0,0x20(%rax)
           vmovups %ymm0,0x40(%rax)
           vmovups %xmm0,0x60(%rax)
           lea     0x80(%rax),%rax
           vmovups %xmm0,-0x10(%rax)
           sub     $0x1,%rdx
           jne     0x14092c3f0
```

**Nothing in the body writes ymm0 or xmm0**, so the register is still zero on every
iteration and lowering them would have been right. The scan cannot see that, and the fix
refuses them -- which costs nothing today, since placement had already lost all nineteen.

So the defect is one site rather than twenty-one, and the honest summary is that the rule
was unsound, one instance of the unsoundness reached the binary, and the rest were correct
by circumstance.

#### And the fix blocks Finding 81 on exactly the shape that motivated it

`0x14186e921`, where Starfield stops, is one of the nineteen. Before this it was refused
because `zeroed_ymm` would not vouch for the *second* store, having crossed the loop head;
now the head is refused for being the head. The `zero_run` of Finding 81 cannot form there
at all.

The way out is a real condition rather than a relaxation: **a loop head keeps its zero if
nothing between it and its own back edge writes the register.** That is bounded, local, and
checkable by exactly the kind of scan this file is full of -- walk from the store to the
`jne` that targets it, refuse on any write to the register or any escape from the range.
It would take all nineteen, and the site the game dies on with them. It is not built here
because Finding 82 is a correctness fix and belongs on its own.

#### What found it

Not a check. The frontier did not move after Finding 81, and asking why led to `zero_run`
correctly declining a group because `zeroed_ymm` had refused its second member -- for
crossing the branch target at the first. Reading that rule to understand the refusal is
what exposed the case it does not cover. **The bug was found by asking why something did
not work, not by any gate**, and no structural check in the project would have caught it:
the output is well formed, the table is sorted, the boundaries reconcile. It writes the
wrong bytes.

### Finding 83 -- the loop head keeps its zero, and that alone is worth nothing

Finding 82 refused every zero store that is a branch target, and nineteen of the
twenty-one were `memset` loops that were correct anyway. `zero_survives_loop` takes them
back, by induction rather than by relaxing anything: the register is zero on the
fall-through by the ordinary walk, and zero on every later iteration because nothing
between the head and its own back edge disturbs it.

The induction needs all of its premises, and stating them is most of the work:

  * **every** edge into the store comes from inside the body, or a third path carries an
    unknown value;
  * **no instruction in the body is a branch target**, or control enters mid-loop and
    reaches the back edge without ever passing the head;
  * nothing in the body **writes** the register, in either spelling;
  * no call and no unconditional transfer out, a call being opaque and every ymm upper
    half volatile across one.

It needed `sources` -- which instruction branches where, not merely that something does --
because a set of targets cannot tell a back edge from an arbitrary entry.

**Measured on Starfield: zero sites.** `make check-pe` gains `loophead` and proves the rule
works, and the binary does not move a byte. The second store in the body walks back, meets
the head, and refuses on the older rule -- so the group still cannot form, the four-byte
head still has to widen over a 256-bit store, and the stub still fails. One conservatism
was removed and the one behind it held every site exactly as before.

### Finding 84 -- a branch target is only opaque if the value at it is

The rule Finding 83 ran into: the backward walk refuses any branch target it passes over.
That is right when the value there is unknown and needless when it is not, and "is this
register zero at that point" is the question the function already answers. So it recurses,
bounded by `depth`, exhausting to a refusal so an unresolved answer stays "not zero".

```
VEX in .text     805,131 ->  13,602      791,529 removed, 98.3%
                             14,549 before, and 947 of them here
```

**And the site Starfield stops on is lowered.** `0x14186e921`, three consecutive four-byte
zero stores at a loop head, becomes one window and one stub:

```
148b0b7e8: movups %xmm0,(%rax)      movups %xmm0,0x10(%rax)
           movups %xmm0,0x20(%rax)  movups %xmm0,0x30(%rax)
           movups %xmm0,0x40(%rax)  movups %xmm0,0x50(%rax)
           jmp 0x14186e92f
```

#### The bug in the fix, which is the same bug as before

The first version tested `blocked` **before** looking at whether the instruction writes the
register. For a branch target that writes it -- `vmovaps something,%ymm0` -- that recurses
and answers about the value *before* the write, then reports zero for a register holding
something else. Silent wrongness in the fix for a silent-wrongness finding, two findings
later.

The order that is right decides on the write first: **an instruction that writes the
register determines its value however control arrived**, which makes the branch-target
question moot rather than prior.

**That guard is not tested, and cannot be here.** Its correct outcome is a refusal, and a
refused VEX instruction still dies at 29 on this CPU, so `check-pe` -- which asserts a
rewritten binary that runs and returns a value -- has no way to express it. It is an
argument in a comment and an ordering in the code. The same limit as Finding 82, recorded
in the same words, because the class keeps recurring: **the cases this project most needs
to test are the ones whose right answer is to refuse.**

What is tested: `zerochain` returns 33 with the recursion and 29 without, and `loophead`
still passes at `depth=0`, which shows the two rules are independent rather than one
masking the other.

### Finding 85 -- 5,477 jumps no control-transfer test could see

Finding 84 moved the frontier to `0x14001eac0`, an import thunk: load a float constant,
tail-jump through a pointer, bracketed by `int3`. It is outside `.pdata`, and
`outside.leaf_ranges` exists precisely to recover such things -- bracketed by padding,
entered by a call or jump, ending in a control transfer, decoding cleanly. It meets every
condition, including the one that looked doubtful: nothing in `.text` references it, but
its address is stored as an absolute pointer at file offset `0x3a4d470`, and `from_reloc`
reads relocated **values**, so it is in `known`.

It was refused anyway, and the reason is that objdump prints a redundant REX prefix as a
token of its own:

```
14001eac8:  48 ff 25 21 1a a2 03    rex.W jmp *0x3a21a21(%rip)

parse_listing ->  mnemonic 'rex.W'   operands 'jmp *0x3a21a21(%rip)'
```

So `terminates` is false for an instruction that is nothing but a jump. And the same is
true of **every** test in this tree that asks what an instruction is:

```
instructions printed with the prefix split off   38,465
  of which the real mnemonic is jmp               5,477
  push 31,457, add 789, and a long tail
```

`zeroed_ymm` walking back is supposed to stop at an unconditional jump; `upper_half_read_
later` walking forward is supposed to follow one rather than fall through it; `ymm_run`
and `zero_run` are supposed to break on one. None of them could see these.

**Whether that produced wrong output or only missed opportunities is not established
here.** The branch-target checks plausibly caught most cases incidentally, the instruction
after a `jmp` usually being a target or padding. It is recorded as unmeasured rather than
argued either way.

#### One rule, two parsers, and a checker that disagreed with the collector

The fix belongs in the parse, and there are two of them: `patch.parse_listing` and
`detour.parse_with_comments`, the same code twice, differing only in that one keeps
objdump's resolved-target comment.

**Fixing one was worse than fixing neither for as long as it lasted.** `verify` reads the
first and its branch-target count moved from 1,191,070 to 1,191,105; `collect` reads the
second and went on treating `rex.W` as a mnemonic. For that build the verifier and the
collector held different views of the same listing, which is the state in which a real
discrepancy gets blamed on the check.

```
VEX in .text     805,131 ->  13,507      791,624 removed, 98.3%
                             13,602 before
in place         547,613 -> 547,707      +94, the thunks patching directly
```

and `0x14001eac0` is `movss 0x4ee528c(%rip),%xmm0` -- in place, no stub needed, because the
SSE form is the same length. It was never hard; it was invisible.

The right structural answer is one parser with an optional comment field. That is a
refactor with its own risk and it is not done inside a correctness fix, so the rule lives
in `patch.REX_PREFIX` and the second parser calls it.

### Finding 86 -- a relative branch is re-aimed, not moved

Finding 85 moved the frontier to `0x14004d240`, and it is the first frontier site that is
not an analysis failure. `vdivss %xmm3,%xmm1,%xmm5` needs seven bytes as SSE and has four,
and both neighbours are branches -- `je` above, `jmp` below -- so there is nothing to
borrow in either direction. No amount of better reasoning moves that arithmetic.

Measured over the whole bucket before building anything:

```
what follows the site, over 427             window if swallowed
  jmp rel8         367  (86%)                6 bytes
  jmp rel32         22                       9 bytes
  call rel32        20                       9 bytes
  ret               13                       5 bytes
  jcc                3                       6-10 bytes
  call indirect      2                      10 bytes
```

**Every one of the 427 would give at least the five bytes a detour needs**, so the
constraint was never the arithmetic. It was that a relative branch cannot be *moved*: `jmp
rel8` reaches 128 bytes and a stub is twelve kilobytes away. It can be **re-aimed** -- the
same absolute target, re-emitted as `jmp rel32` -- and a stub is freely sized, so growing
two bytes into five costs nothing there.

A stub containing an unconditional transfer never reaches its trailing jump home, which is
correct rather than merely harmless. A `call` returns into the stub and falls into that
jump. Conditional branches stay refused: three sites in the whole binary, each needing its
own opcode from a sixteen-entry table, and a table written for three sites is one nobody
checks.

```
VEX in .text     805,131 ->  12,505      792,626 removed, 98.4%
                             13,507 before
detours          197,657 -> 198,660
```

#### Two ways the first version was wrong

**It probed from zero.** `swallowable_transfer` asked `moved_branch` whether a target was
reachable with `at = 0`, and from zero every address in a 0x140000000-based image overflows
rel32 -- so it answered "not swallowable" for all 402 sites it existed to take, and would
have measured as worth nothing. It probes from the branch's own address now.

**It reimplemented the encoder's rules instead of asking it.** Testing `moved_branch`
directly answered yes for an indirect branch through memory, which `moved_instruction`
routes to `relocate`, which refuses it. A collector that accepts what the encoder rejects
makes a candidate that dies in `build_stub` with no reason recorded -- the failure Finding
45 had to diagnose by hand. `swallowable_transfer` now calls `moved_instruction` itself, so
one code path decides both.

#### And the test passed for the wrong reason first

`swallowjmp` had an ordinary `vmovss` before the site. When forward widening is refused the
collector widens **backwards**, so the site was lowered either way and the program returned
81 with the rule reverted. The real site has a `je` above it as well as a `jmp` below, which
is why it is refused at all, so the `jne` in the program is load-bearing rather than
scenery.

That is twice in a row -- `zerorun` had padding the real code does not offer, this had an
escape route the real site does not have. **Both would have been silent additions to a
suite that looks thorough**, and only the mutation caught either.

#### A verify line that stopped meaning what it said

`detour-verify` prints the number of `jmp` instructions in the stub section. It equalled the
detour count for as long as every stub held exactly one jump -- the one home -- and
`project.md` quoted it as "exactly one jump back per detour", an invariant. It was never
asserted: only the VEX count is. Now that a swallowed transfer is re-emitted inside the
stub, 198,660 detours carry 199,798 jumps and both numbers are right.

The line says what it counts now, and the milestone table no longer claims the invariant.
Asserting the real one -- one jump home per stub, at its end -- needs per-stub bounds that
pass does not have, and is its own piece of work.

### Finding 87 -- a conditional branch is the one transfer that falls through

Finding 86 moved the frontier to `0x14004d456`, in the other positional bucket: the
instruction AFTER the site is branched to, so swallowing it would leave that branch landing
inside the five-byte jump that replaced it.

The measurement first, over all 524:

```
one edge, from inside the span   304    conditional predecessor 194, jmp 110
2 direct edges                   139
3 direct edges                    35
one edge, 24+ bytes away          32
a back edge                       10
a static target                    4    <- the only unenumerable ones
```

**Four sites out of 524 have edges nothing in `.text` names.** That bucket was expected to
be the wall and is not.

#### The refusal was one test doing three jobs

Backward widening refused any predecessor that transfers control, reasoning that it "does
not fall through into the site". That is right for a `call`, which returns into the middle
of a window, and for an unconditional `jmp`, after which the site is unreachable. It is
**wrong for a conditional branch**, which falls through by definition -- and that is the
one shape where the window is sound.

Nothing has to be relocated. The branch's target lies outside the window, so the stub holds
the re-emitted branch, the lowered site, and the jump home:

```
148988135: je     0x14004d45a      the original target, re-aimed
14898813b: movaps %xmm1,%xmm0
14898813e: divss  %xmm3,%xmm0      the lowered vdivss
148988142: jmp    0x14004d45a      the jump home
```

Taken skips the divide; not taken performs it and falls into the jump home. Identical to
the original.

```
VEX in .text     805,131 ->  12,042      793,089 removed, 98.5%
                             12,505 before
```

#### The table Finding 86 declined now earns its place

"A sixteen-entry table written for three sites is one nobody checks" was true of the three
conditional sites forward of a window. Backwards there are 194, across six conditions, so
`CONDITION_CODES` is written -- and `jrcxz`, `loop`, `loope` and `loopne` are excluded **by
name**, because they exist only in a rel8 form. There is nothing to widen them into, and a
lookup that missed that would emit a jump to an arbitrary address.

One arithmetic detail worth naming: rel32 is measured from the END of the instruction,
which is five bytes for `e9`/`e8` and **six** for the two-byte conditional opcode. A
constant 5 there lands every conditional one byte short of its target.

#### The mutation discriminates, which is the point of running it

Reverting only the backward path leaves `swallowjmp` passing at 81 and drops `condbefore`
to 29. The two programs exercise different rules rather than one masking the other, which
is what a mutation is for and what two green tests alone would not have shown.

### Finding 88 -- the largest bucket was the one with no reason

`0x1406ed33b`, where Starfield stopped after Finding 87, is not declined by the collector
at all. It is a candidate whose stub would not build -- the 3,959 sites `census` can
reconcile no further than "refused", because `build_stub` returns None and says nothing.

Finding 45 hit this once and had to walk the three steps by hand, discovering that a
swallowed instruction wanted a scratch of its own; that was worth 2,437 stubs and was found
by reading rather than by any report. So every failure path names itself now, and the
answer is lopsided:

```
the site itself will not lower             2,780    70%
a displaced instruction will not move      1,167    29%
a preceding instruction will not move         16
```

**2,780 sites are accepted by the collector and then refused by `lower_vex`.** That is the
collector and the encoder disagreeing about the same instruction, which is the shape
Finding 86 hit in `swallowable_transfer` and fixed by making one code path decide. Here the
collector checks `has_direct_sse_form` and the operand shape, and something else in
`lower_vex` declines afterwards. It is the largest single lever left and it is not yet
diagnosed.

The counter reports 3,963 against 3,959 refusals because `refused` is a set of addresses
and this counts events: four candidates share a start address with another, which backward
widening can produce. Worth knowing before the two numbers are compared again.

Only the fallback `build_stub` call is given the counter. The extension call above it fails
routinely and falls back to the plain stub, so passing it there would name causes for sites
that were placed -- the same over-counting that has had to be corrected four times in this
sitting.

### Finding 89 -- the 2,780 are 256-bit, and were never an encoding gap

Finding 88 named the refused bucket and left its largest part unexplained: 2,780 sites
accepted by the collector and refused by `lower_vex`. Instrumenting its nine paths answers
it in one line.

```
the site itself will not lower             2,780
  256-bit, no Y strategy took it           2,654    95%
  an unsupported opcode map                    0
a displaced instruction will not move      1,167
a preceding instruction will not move         16
```

**Not one is an encoding gap.** `sse_encoding` refuses two things -- an unsupported opcode
map, and `vex["L"]` -- and naming them together hid which, so the first split was worth
making before drawing any conclusion.

#### The collector and the encoder ask different questions

Class Y claims only the **moves**: the adjacent pair, the run, the zero store. A 256-bit
instruction that is not a move -- `vmulps %ymm2,%ymm1,%ymm0` and its kind -- falls past that
branch to the ordinary path, where `has_direct_sse_form` asks whether the **mnemonic** has
an SSE form. It does. So the site becomes a candidate, and `sse_encoding` refuses it later
because that asks about the **encoding**, and VEX.L has no SSE form at all.

That guard is Finding 37's, and it is the one that must not be relaxed: dropping the prefix
from a 256-bit instruction yields a valid 128-bit one that assembles, disassembles, carries
no VEX, and writes half the bytes the program asked for. It was reached once, by 32,749
sites.

So the 2,654 are **correctly unlowerable and wrongly filed**. They need both halves of
every operand in registers, which is the Y register model of milestone 5 -- not a table
entry, not a scratch, and nothing a peephole reaches. Filed as "stub not buildable" they
read as an encoding bug worth chasing; they are the same population the census already
names elsewhere as needing the register model.

The fix is the one Finding 86 applied to `swallowable_transfer`: **let the collector refuse
what the encoder cannot encode**, so a 256-bit site no Y strategy claimed is declined by
name rather than accepted and dropped later. It is worth no sites and stops the largest
bucket in the census pointing at work that does not exist.

### Finding 90 -- the collector refuses what the encoder cannot encode

Finding 89's fix, and it is worth no sites by construction: these were already refused, one
step later and under a name that pointed at work that does not exist.

```
refused, stub not buildable    3,959 ->  1,201
  the site itself will not lower  2,780 ->    21
  a displaced instruction will not move     1,167
  a preceding instruction will not move        16
skipped for overlap           37,075 -> 36,983
VEX in .text                  12,042 -> 12,042
```

**The VEX count is the check that matters.** A change there would mean the refusal had
caught something that was previously being lowered, which is the regression this shape can
produce; it does not move.

The overlap count falling by 92 was not predicted and is the more interesting number: a
site declined up front stops being a candidate, so it stops colliding with its neighbours.
Those 92 windows were being blocked by candidates that could never have been built.

**Sequence and FMA mnemonics are excluded from the refusal deliberately.** They never reach
`sse_encoding` -- `lower_permilps` and `lower_fma` are called directly -- so refusing them
here would decline sites their own lowerings might yet take. The status quo is kept for
them rather than quietly narrowed.

#### What is left in the bucket

`a displaced instruction will not move`, 1,167, is now the largest part and a different
problem: the site is fine and the neighbour it must swallow is not. Finding 45 took 2,437
of these by giving the swallowed instruction a scratch of its own. What remains has not
been broken down, and `moved_instruction` has several ways to refuse -- a VEX neighbour
that will not lower, a RIP displacement that will not reach, a branch shape `moved_branch`
declines. That breakdown is the next cheap measurement.

### Finding 91 -- what is left of the refused bucket is register pressure

With the 256-bit sites declined where they belong, the refused bucket is 1,201, and 1,167
of it is one thing: the site is fine and the neighbour it must swallow will not move.
`moved_instruction` names why:

```
the aliased form has no usable scratch      798    68%
the VEX neighbour would not lower           185
no direct SSE form and not a sequence       111
256-bit, no Y strategy took it               80
the FMA would not lower                        7
vpermilps would not lower                      2
```

**798 are register pressure on the swallowed instruction.** It is a `dst == src2` form,
where the `movaps` that sets up the destination would destroy `src2` before the operation
reads it, so a scratch is required -- and nothing is dead at that position. Finding 45
added `swallowed_scratch` for this exact shape and took 2,437 sites; these are what the
scan cannot find a register for.

That is the first tractable thing in the bucket, and the mechanism already exists.
`--spill=home` borrows the callee home space for a **site** with no dead register and is
worth 1,022 (Findings 70 to 73). A swallowed instruction has never been offered it. The
same argument applies -- the home space is dead by the ABI at any point inside the
function, and the lowering already knows how to save and restore through it -- but the
window is longer, so whether the borrow is still safe across it is the question to settle
before building, not after.

The 185 that report only "the VEX neighbour would not lower" carry no inner reason, which
means `lower_vex` refused them by a path the instrumentation does not name. That is a gap
in the measurement rather than a finding, and it is recorded so the next reader does not
mistake it for one.

The counted events come to 1,183 against 1,167 refusals for the reason Finding 88 gave:
`refused` is a set of addresses and this counts events.

### Finding 92 -- the home space survives these windows, because they are tiny

Finding 91 named 798 sites refused because a swallowed `dst == src2` form had no scratch,
and asked whether `--spill=home` could be offered to a swallowed instruction as it already
is to a site. The site-level argument is that `[rsp+0..31]` is dead by the ABI. A window is
longer than a site, and two things inside one would break that:

  * **a `call`**, because the home space exists precisely so a callee can write its register
    arguments there -- and Finding 86 made this reachable rather than theoretical by letting
    a window swallow `call rel32`;
  * **anything moving `rsp`**, since the save writes `[rsp+0]` and the restore reads it, and
    a `push` in between returns the wrong eight bytes silently.

Measured over the population the borrow would serve:

```
refused for "the aliased form has no usable scratch"   795
  nothing disturbs the home space                      795
window sizes: 8 bytes 640, 9 bytes 153, 10 bytes 2
```

**None of them, and the reason is structural.** These windows are a four-byte site plus one
neighbour. There is no room in eight bytes for a call or a stack adjustment.

#### What that licenses, and what it does not

It licenses the **population**: every one of these 795 could take the borrow today. It does
not license the **mechanism**, and the difference decides how to build it. A window is only
this short because nothing has widened it; a `zero_run` covers up to sixteen stores, an
`ymm_run` a whole span, and Finding 86 admits a swallowed `call` by design. A borrow written
on the strength of this measurement would be correct now and wrong the first time it met a
longer window, with no test to say so -- and a home slot restored after a call returns the
callee's argument, which is a silently wrong value rather than a crash.

**So the guard belongs in the code, not in this document.** Refuse the borrow when the
window contains a call, a push or pop, or a write to `rsp`, and the measurement above stops
being load-bearing: it becomes the reason the guard costs nothing today rather than the
reason it can be omitted.

The count is 795 here against 798 in Finding 91 for the reason Finding 88 gave -- that was
counting events and this is keyed by address.

### Finding 93 -- the home space lends to a neighbour too

Finding 92 asked whether the borrow survives a window and answered yes for all 795, their
windows being eight to ten bytes. **Reading the site's own spill path changed the design and
made that answer beside the point.** The site brackets tightly -- save, one lowering,
restore, nothing in between -- so doing the same for a swallowed instruction means the
bracket never spans the window at all and its length stops mattering.

`emit_swallowed` is one helper called from both the `preceding` and `displaced` loops rather
than the logic written twice, so the tightness is structural instead of something a later
reader has to preserve by discipline.

```
VEX in .text                               12,042 -> 11,751     +291
detours                                   199,124 -> 199,235
refused                                     1,201 ->    909
  moved: the aliased form has no usable scratch  795 ->    517
```

**291 of the 795, and the shortfall is the constraint Finding 71 already measured.** The
borrow needs the function to have home space at all and not to copy `rsp` where the scan
cannot follow it; a leaf has none, and 2,367 functions copy it. The swallowed borrow
inherits the site borrow's limits exactly, which is the answer rather than a disappointment.

Neither `the swallowed borrow could not be saved` nor `... restored` appears in the census,
so `encode_spill` refused nothing -- worth checking rather than assuming, since a save that
silently failed would leave a live register destroyed.

#### What the measurement was actually for

It licensed the population and not the mechanism, and the distinction is the finding. A
borrow written to span a window would be correct today and wrong the first time a
`zero_run` or a swallowed `call` widened one, with no test to say so and a silently wrong
value rather than a crash. The tight bracket makes Finding 92 an explanation of why the
guard costs nothing rather than a reason to omit it.

#### What the executed path is blocked by now

The site Starfield stops on, `0x1406ed33b`, is one of the 517 the borrow cannot serve, and
the reason is worth naming because it closes the avenue rather than leaving it open:

```
site 0x1406ed33b   moved: the aliased form has no usable scratch
  neighbour 0x1406ed33f  vsubss %xmm1,%xmm5,%xmm1   scratch=None  borrow=False

1406ed150: mov %rsp,%rax        the containing function's first instruction
1406ed163: sub $0xe8,%rsp
1406ed16a: vmovaps %xmm6,-0x58(%rax)
```

It is **not a leaf** -- it makes three calls, so the home space exists. It copies `rsp` into
`rax` in its first instruction and addresses its frame through the copy, which is the MSVC
prologue idiom, and `home_space_free` refuses that because it cannot prove the home space is
not reached through it.

That is exactly the case **Finding 72** built a dataflow for and reverted: of 2,367 starved
sites whose function copies `rsp`, tracking where the copy points cleared **thirteen**. The
frontier is therefore blocked by an avenue this document already measured and closed, not by
anything new.

#### Two mislabelled reasons, found while reading the spill path

The instrumentation of Finding 88 attached "the borrowed register could not be restored" to
the site's lowering failing, and "the zero store would not lower" to the restore failing --
each one line off. Both counted zero, so nothing was misread; both would have lied the
moment they fired. Corrected.

### Finding 94 -- the 256-bit residue is 2,234, not 11,624

Going after the 256-bit sites starts with counting them, and the count the census gives is
the wrong one. `ymm value has no known upper half` stands at 11,624 declines, and a store is
declined at **its own index** -- where `ymm_pair` sees no load and `ymm_run` refuses a store
-- so it lands there whether or not the window its load opened covers it. `census`'s
docstring has warned about this since Finding 35 and it is still the easiest number in the
document to misread.

```
256-bit stores whose value is not a known zero   11,714
  already covered by a pair or run window         9,480
  genuinely unreached                             2,234
    a copy whose load is too far to pair          1,530
    a computed 256-bit value                        354
    a vpxor that could not be proved zero           188
    no defining write within 200                    136
```

And of the 1,530 copies, what actually stops a single window spanning them:

```
nothing -- the run reaches it        725    blocked after the walk
a 256-bit op that is not a copy half 467
a branch target inside the span      186
a control transfer inside the span    89
the value is touched                  63
```

**The whole 256-bit store residue is 2,234 sites**, and the largest tractable group in it is
725 where the walk arrives and something downstream -- a helper, the upper-half check,
`.pdata`, an overlap -- refuses. Those are the same causes Findings 78 to 93 have been
taking one at a time.

#### What that does to milestone 5

The milestone row still reads "the 12,552 stores and 11,226 loads that remain do", written
when those were the counts. They are not. The register model is worth **2,234 stores** by
this measurement, plus the loads that pair with them and something under a thousand
arithmetic sites -- `vmulps` 176, `vaddps` 105, `vsubps` 71, `vpaddd` 63, `vpand` 61,
`vfmadd231ps` 71 and a tail.

**84% of the 256-bit declines are `vmovups` with a memory operand**, 13,542 of 16,075, which
confirms Finding 39's framing at the far end of the work: this binary's 256-bit traffic is
memcpy, and the register model it needs is one for data movement rather than a general
allocator over arithmetic.

Two smaller things the same pass turned up, recorded rather than acted on:

  * **49 declines are `(bad)`** -- bytes objdump could not decode, counted as VEX sites.
    Data read as code, and it inflates whatever bucket it lands in.
  * **`no home space to borrow` is 3,390 and only 237 of them are 256-bit.** The other
    ~3,150 are 128-bit sites starved of a scratch in a function the borrow cannot serve --
    a population the size of the aliased one, behind the same `rsp`-copy limit Finding 72
    priced at thirteen.

### Finding 95 -- a run helper can be borrowed too, and this bracket does span

424 sites are declined `no register free across the ymm run`: `assign_helpers` wants one
register per lifetime, dead at the load and untouched to the store, and finds none. That is
register pressure, and the home space is what this project uses for register pressure.

**This bracket spans the window, and Finding 93's did not.** A run's helper carries the
upper half from the load to the store, so a save before the run and a restore after it
enclose everything between. A call cannot be inside one -- `ymm_run` breaks on every control
transfer -- so `rsp` is the whole of what is left to check: a `push` or a `sub $n,%rsp`
between the save and the restore leaves them addressing different memory, and the restore
returns whatever the push wrote. A silently wrong register, not a crash.

Measured before building:

```
424 declined for no free register
  the function cannot lend                 265
  could borrow: the span leaves rsp alone  159
  rsp moves inside the span                  0
```

Not one span touches `rsp`, so the guard costs nothing today -- **which is why it is in the
code and not in this paragraph.** A span that grows later has nothing else to stop it, and
Finding 92 already recorded that distinction the other way round.

```
VEX in .text     11,751 ->  11,409      793,722 removed, 98.6%
detours         199,235 -> 199,360
```

**342 sites from 159 borrows**, because a run window covers the load, its stores and
whatever is interleaved between them rather than one instruction.

Neither `the run borrow could not be saved` nor `... restored` appears, so `encode_spill`
refused nothing in the run path. Every `detour-verify` invariant holds -- the table sorted
and covering every stub byte matters most here, since a spill emitted at the wrong offset
would desynchronise a stub's length from what `place_stubs` recorded.

The 265 that cannot lend are behind the same limits as everything else this session: a leaf
has no home space, and a function that copies `rsp` cannot be vouched for. That is the third
lever in a row capped by Finding 71's constraint rather than by its own mechanism.

### Finding 96 -- the `rsp` copy refuses 2,464 sites and protects none of them

Three levers in a row -- the site borrow, the swallowed borrow of Finding 93, the run
borrow of Finding 95 -- ended capped by `home_space_free` rather than by their own
mechanism, and the executed path has stalled at `0x1406ED33B` for three builds behind the
same check. So the refusals were split by cause, weighted by the sites they cost:

```
4,160 starved sites
  it copies rsp somewhere                   2,464
  a leaf: no home space exists at all       1,262
  the function addresses [rsp+0..31]          361
  outside any known function                   51
  a frame register: rsp is not constant         22
```

The leaves are closed and stay closed: nothing reserved the space, and Finding 49 shut the
alternative. The copy is the majority, and Finding 72 recorded it as equally closed.

**It is not.** There are two home spaces, and the refusal conflates them. The one this
function's caller reserved sits above the return address; the one it reserves for its own
callees sits at the bottom of its frame, and the borrow writes only the second. MSVC's
`mov %rsp,%rax` prologue idiom exists precisely to reach the *first* one after the pushes
have moved `rsp`, so the copy that triggers the refusal is normally pointing a whole frame
away from the region at risk.

`0x1406ed150` is the frontier's own function and shows it without any analysis. It copies
`rsp` at entry, dereferences the copy at `+8` and `+16` -- the caller's shadow -- and at
`-88` through `-168` for saved xmm registers. Its frame is eight pushes and `sub $0xe8`,
so `[rsp+0..31]` is `entry-296` through `entry-265`. Nothing through the copy comes within
97 bytes of it.

Measured across the whole bucket, tracking the copy's offset from entry `rsp` and taking
the frame size from the unwind codes:

```
2,464 sites whose function copies rsp
  provably clearable                          846
  arithmetic derives a pointer not followed  1,420
  the copy escapes                            113
  an indexed lea derives one                    85
  it lands in the region                          0
```

**Not one function reaches the region through the copy.** The 1,505 that are not cleared
are the tracker losing a pointer, which is a limit of the analysis rather than a fact about
the program -- a distinction Finding 72 did not draw, and the reason its conclusion reads
harder than its evidence supports.

The zero is load-bearing, so it carries a capability proof rather than an assurance: the
classifier is fed a store that does land in the region, one eight bytes above it, and a
byte-write that must not be mistaken for a pointer kill. It aborts rather than reporting a
number if any of the three comes back wrong. An earlier revision of the same measurement
returned zero because a bad narrow-write rule had killed the taint early, and a zero from a
probe that cannot find a hit reads exactly like a zero from a program that has none.

#### What this does not settle

**Finding 72 says the opposite and has not been edited.** Its sentence -- that a function
making a pointer to its own frame bottom "essentially always uses it in a way no scan can
vouch for" -- is contradicted by the table above. Its *number* is not explained here: the
dataflow was built and reverted inside `24c0081`, so the code was never in the tree and
cannot be read back. A region conflation would produce exactly thirteen, since the idiom's
stores at `+8/+16/+24` land in `[0,32)` if the frame is never subtracted, but that is a
hypothesis about code nobody can see and is recorded as one.

Two further weaknesses in that model are visible without it. `lea` into the region is
refused separately, so the copy rule was never carrying it; and the escape rule prices a
callee dereferencing the pointer, which no borrow can suffer -- the swallowed bracket
admits nothing between save and restore, and `ymm_run` breaks on every control transfer, so
no window contains a call.

**The change is not made.** Clearing the copy rule would roughly triple the population
writing into the translated program's frame, from 1,022 to something near 3,400, and
Finding 73 records that mechanism as argued from the ABI and executed, never proven. Its
failure mode is silent corruption of a live local. Whether that trade is worth 846 sites
and the frontier is the copyright holder's, not the implementer's, and the code still
refuses every `rsp`-copying function until it is taken.

### Finding 97 -- the 185 unnamed refusals were mostly `vblendv`

Finding 91 recorded that 185 sites reported only `the VEX neighbour would not lower` and
carried no inner reason, and called it a gap in the measurement rather than a finding. It
was one line of cause: `lower_vex` captures a helper's `None` and labels it for
`lower_permilps` and `lower_fma`, and returns three others' results directly --
`lower_vvvv_shift`, `lower_blendv` and `lower_broadcast` -- so a refusal from any of those
three arrived with nothing to say for itself and fell through to the generic counter.

Labelled, the bucket is:

```
moved: vblendv would not lower              162
lower: the vvvv shift would not lower        21    every "site itself" refusal
moved: the broadcast would not lower          5
moved: the vvvv shift would not lower         4
```

The generic label no longer appears at all, so nothing is left unattributed behind it.

**162 of them are Class D**, which puts them in the same family as the 517 refused
`the aliased form has no usable scratch`: `lower_blendv` needs the mask in `%xmm0`, four
registers are named where three fit, and it refuses when there is no scratch or when the
only scratch collides with one of the four. That is register pressure on a swallowed
instruction, and register pressure is what the home space exists to relieve -- so with the
517 it makes a fourth lever standing behind `home_space_free`, the check Finding 96
measured as protecting no function at all.

The rebuild is identical to the one before it -- 11,409 sites, 199,360 detours, 435,787
function table entries, 81,944 lost boundaries, 1,191,105 branch targets, 200,495 stub
jumps -- which is what makes this instrumentation rather than a change that happens to
report differently.

### Finding 98 -- the copy is followed, and it is worth 784 sites

Finding 96 measured the blanket refusal of any function that copies `rsp` and found it
protecting nothing: of 2,464 starved sites, not one function reaches its callee home space
through the copy, and 846 could be proved not to. `copy_reaches_home` replaces the blanket
rule with the offset arithmetic, and `--rsp=blanket` keeps the old behaviour reachable --
a borrow that corrupts a live local does not fault, so comparing two binaries is the only
way to test for one.

```
VEX in .text     11,409 ->  10,625      794,506 removed, 98.7%
detours         199,360 -> 199,782
refused             908 ->     797
  the aliased form has no usable scratch    517 -> 415
  vblendv would not lower                   162 -> 153
```

784 sites against a ceiling of 846, which is the right side of it: a function that can now
lend still has to pass everything else, and 62 did not.

**The frontier is taken.** `0x1406ED33B` held the executed path for three consecutive
builds and was `c5 ca 5c e0`, a VEX `vsubss`; it is now `e9 1d 87 2d 08`. Its function is
the one Finding 96 traced by hand -- the copy addresses the caller's shadow at `+8` and
`+16` and saved registers at `-88` through `-168`, while the region the borrow wants lies
at `-296` through `-265`.

#### What makes the zero trustworthy

The change rests on Finding 96's zero, and a zero is what a broken probe returns too. So
eleven cases run in `detour.py selftest`, in both directions: a store that does reach the
region, one eight bytes above it, the MSVC idiom writing the caller's shadow, a byte write
that must not read as a pointer kill, a 32-bit write that must, a `lea` deriving a pointer
into the region, immediate arithmetic walking one in, arithmetic that cannot be followed,
an indexed access, a copy stored to memory, and an unknown frame.

Three mutations confirm they bite. Removing the guard fails five of them. Restoring the
narrow-write bug -- which is a real bug this session wrote and then caught -- fails exactly
the byte-write case. **And conflating the two home spaces fails the MSVC idiom case**,
making that function refuse itself: the hypothesis Finding 96 offered for where Finding
72's thirteen came from now reproduces on demand, which is as close to confirming it as
anything can get with the code gone from the tree.

#### The test PEs were claiming a frame of zero

`pe_build` wrote `UNWIND_INFO` with no unwind codes for every program, which is honest for
a program nothing unwinds -- and useless for one testing where the home space is, since
`prologue_frame` reads the frame out of exactly those codes. A program written against it
would have been measured against a frame of 0, put the region at `entry+0`, and passed
without exercising the arithmetic at all. `build` takes a declared frame now and emits a
real `UWOP_ALLOC_SMALL`; `rspcopy` declares 104 and reads back as 104.

`rspcopy` runs under wine and returns 107. Under `--rsp=blanket` it does not: exactly one
VEX instruction survives, the aliased `vsubss`, and the program never reaches its answer.
That difference is what says the program tests the new rule rather than passing beside it.

#### What is still not proven

The same thing Finding 73 recorded, and more of it. Roughly 3,400 sites now write into the
translated program's own frame where 1,022 did, on a per-function scan and an ABI
argument. A borrow that lands on a live local corrupts it silently. Every gate passes --
`check`, `check-pe` across twenty-three programs, `check-spill` across all four modes --
and none of them can see that failure, which is why `--rsp=blanket` exists.

The 113 sites whose copy escapes to memory stay refused. No borrow window can contain a
call, so nothing could dereference an escaped pointer while one is live, but that argument
rests on a property asserted in docstrings rather than enforced, and it was not worth
leaning on for 113 sites.

### Finding 99 -- the next frontier is not incrementally reachable

With `0x1406ED33B` taken, Starfield faults at `0x14004E230`, and it is a different class:
`vmovaps 0x4eb9028(%rip),%ymm0`, declined as 256-bit before it was ever a candidate. The
catch-all that reported it said only that no Y strategy took it, so `ymm_run` now carries
its own reason and `plan` names all 3,590:

```
256-bit: arithmetic rather than a copy                        2,034   1,925 outside a window
256-bit: no store before 256-bit arithmetic on the value        858     730
256-bit: no store before a branch target inside the run         212
256-bit: no store before a control transfer                     165
256-bit: no store before the value is touched                   148
256-bit: loaded and never stored before 256-bit arithmetic      112
256-bit: loaded and never stored before the value is touched     61   <- the frontier
```

The reason comes from `ymm_run` rather than from a second walk beside it. Two code paths
answering one question is how a collector and an encoder come to disagree, which has
happened here once already.

**Nothing is wrong with the frontier's own value.** `ymm0` is loaded, stored twice and
dead within four instructions. What takes the run down is `ymm1`, loaded inside it from
`.rdata` and not stored until `0x14004E304` -- fifty instructions later, past the limit of
48, and needing a helper register dead across all of it. The `loaded - stored` check then
discards the run including the two `ymm0` stores that were complete.

#### The option measured and rejected

`ymm_run` carries an upper half in a helper from the load to the last store, which is what
forces both the limit and the long-lived register. Where the SOURCE is a RIP-relative
address in a non-writable section, it need not: the same bytes are there at the store, so
the upper half can be re-read through a scratch live for two instructions rather than
fifty -- and a momentary scratch is what the home space already lends.

Both of this site's sources are in `.rdata`, which the section flags say nothing may
write. So the shape fits. The population does not:

```
of the 3,590 declined
  not a wide move (256-bit arithmetic)                    2,034
  the source is not a RIP constant                        1,307
  read-only source, but no store before it dies             202
  the source is in a WRITABLE section                        35
  READ-ONLY SOURCE, reachable by re-loading                  12
```

Twelve sites, and **all twelve are already within the limit of 48** -- median distance six,
maximum twenty-six. The constraint the strategy relieves is not the one binding them. It
would also need a value tied to its source across window boundaries, since the frontier's
stranded `ymm1` is stored in a different window from the one that loads it. That is a
change to the Y representation rather than an addition to it, for twelve sites.

Recorded rather than built, so the next reader does not measure it again. The measurement
counts a section it cannot classify as writable, stops at every control transfer, and
stops when the register is touched, so twelve is a floor rather than an estimate -- but
not by the order of magnitude the design would need.

#### What is actually left

2,034 sites are arithmetic on a `ymm`, not a copy, and 202 more load a value that
arithmetic consumes. No strategy about copies reaches either. They want the full register
representation -- a shadow for every live upper half, maintained across the whole function
rather than within one window -- which is a larger piece of work than anything in Findings
88 to 98 and is not started here.

### Finding 100 -- the borrow offered the one register the lowering refuses

`spill_register` returns the lowest-numbered register a site does not name, and both
borrow paths took it, tried one lowering with it, and gave up. SSE `blendvps` reads its
mask from an implicit `%xmm0`, so `lower_blendv` rejects a scratch of 0 -- and 0 is
exactly what the first-free rule returns whenever the site does not name it.

So every `vblendv` neighbour that needed a borrow was handed the only register its
lowering documents it cannot use, and refused.

**Three numbers, and the distance between them is the finding:**

```
vblendv instructions whose first free register is %xmm0        600
of those, sites actually REFUSED for it                        153
sites recovered by trying the other candidates                  24
VEX sites that removed                                         106
```

600 is a population, not a prize. Most of those instructions never reach the borrow: they
lower with a dead register `find_scratch` supplies, or they sit inside a window that was
accepted anyway. 153 is what the refusal list actually held, and 24 of those had another
register that worked -- the remaining 129 fail inside `lower_blendv` for reasons no
scratch addresses, being 256-bit or having a memory `src2` the register-direct path does
not handle. The gap from 600 to 24 is the same conflation this project has miscounted
four times before, caught here by rebuilding rather than by predicting.

```
VEX in .text     10,625 ->  10,519      794,612 removed, 98.7%
detours         199,782 -> 199,864
refused             797 ->     773      vblendv 153 -> 129
```

82 more windows removed 106 more sites, a window covering more than the site it is
anchored on.

**The retry lives in one place.** `borrow_that_lowers` asks the lowering rather than
guessing for it, and both callers -- the site's own borrow and `swallowed_borrow` for a
neighbour -- go through it. Two code paths answering one question is how a collector and
an encoder come to disagree about what can be encoded, which has cost this project a
build already, and the same reasoning put the Y decline reason inside `ymm_run` in Finding
99.

The test asserts the defect rather than the fix: that the first free register IS 0 for a
`vblendv` naming four other registers, that `lower_vex` refuses it, and that the borrow
nevertheless returns one that lowers. Reverting to a single candidate makes it report that
the borrow found no register at all, so it guards the behaviour instead of describing it.
The encoding it uses was assembled rather than hand-written.

### Finding 101 -- most of what "arithmetic" refused was not arithmetic

Finding 96 reported 1,420 starved sites lost because something did arithmetic on a tainted
copy of `rsp` that was not an immediate `add`/`sub`, and Finding 98 took that as the
analysis meeting a real limit. It was not one. Asking WHICH arithmetic, by wrapping
`immediate_step` rather than walking beside it:

```
lea       2,959          xchg      15          add        5
test        391          xor       15          sub        4
cmp         162          cmove     12          inc        3
vpextrq      42          imul       8          ... 26 mnemonics in all
```

**None of the top three is arithmetic on a pointer.** `cmp` and `test` write no register
at all -- they set flags -- so a copy in what looks like their destination operand survives
them untouched, and reading that operand as a write gave up on 553 functions doing nothing
to the pointer. `lea` fully overwrites its destination exactly as `mov` does, so it ends a
pointer's life rather than deriving from it; missing from the kill list, it aborted the
walk 2,959 times, by a wide margin the largest single cause.

The rule that was missing is **does the instruction read its destination**. `add`, `sub`,
`and`, `inc` and `imul` do, and derive. `mov`, `lea`, `pop` and `vpextrq` do not, and kill.
`cmp` and `test` write nothing at all.

```
VEX in .text     10,519 ->  10,229      794,902 removed, 98.7%
detours         199,864 -> 200,017
refused             773 ->     737
  the aliased form has no usable scratch    415 -> 385
```

**290 sites, and the refusal buckets understate it.** The walk used to abort at the first
`lea`, which in most prologues is early; now it runs on and sometimes finds a reach that
the abort had been hiding. So the change moves sites in both directions -- some functions
clear, others are refused for a real reason instead of a bookkeeping one -- and the net is
what the site count shows. Nothing shipped on the strength of the bug: an abort answered
"may reach", so everything it touched was refused.

#### The test needs both directions, and one case cannot give them

Giving up and genuinely reaching the region both answer True, so a single `cmp` case would
pass while the walk was aborting. It takes two: one where the copy stays clear of the
region, which fails if the walk aborts, and one where it lands inside, which fails if `cmp`
is treated as a kill instead. Fifteen cases now, and three mutations bite -- `lea` back to
deriving, `cmp`/`test` read as a write, and `cmp` treated as a kill.

The first attempt at that third mutation removed only the bare `test` from the set while
every case used `cmp`, so it tested nothing and reported nothing. That is the vacuous pass
in miniature, inside the very check written to prevent one, and it is how the missing
`test` case was found -- 391 give-ups with no case covering the mnemonic at all.

### Finding 102 -- the refused bucket is exhausted, and three ideas died proving it

After Finding 101 the refused bucket is 737, and every part of it is now accounted for.
None of what remains is reachable without the 256-bit register representation.

```
a displaced instruction will not move                704
  the aliased form has no usable scratch             385
  vblendv would not lower                            119
  no direct SSE form and not a sequence              112
  256-bit, no Y strategy took it                      83
the site itself will not lower                        21   all vvvv shifts
a preceding instruction will not move                 12
the FMA, broadcast, vvvv shift, vpermilps             17
```

**The two largest are the same cause.** Splitting each by why its function cannot lend:

```
                          aliased 385      vblendv 119
a leaf, nothing reserved          129               44
an rsp copy not followed          230               49
the function uses the region       23                9
no candidate register lowers        0               10
outside any known function          3                7
```

A leaf is closed by Finding 49. A function that uses the region is refused correctly. The
ten that no register lowers are exactly the 256-bit `vblendv` -- there are fourteen in the
binary and no scratch can help any of them.

**On the 279 "not followed", the honest reading is narrower than the label.**
`copy_reaches_home` answers True both when it proves a reach and when it gives up, and
this split cannot tell those apart. What can: after Finding 101 removed `lea`, `cmp` and
`test`, the largest remaining give-up cause was the conditional move at 463 events, and
handling it moved **zero** sites. So most of these are functions that genuinely reach their
home space, and the pointer analysis has stopped being what limits this bucket.

#### Three ideas measured and rejected

**Tracking a copy across a conditional move.** Sound, and strictly better than giving up:
keeping the copy tracked checks every later dereference, while the alternative value is
not `rsp`-derived and is covered by the assumption the mechanism already makes for every
untracked register. Only a move between two tracked copies at different offsets is
genuinely ambiguous. It eliminated 463 of the 581 remaining give-ups and gained **no
sites** -- 10,229 before and after, the same detour count, the same buckets -- so it was
reverted rather than committed. Giving up was already safe; precision there could only buy
permissiveness, and there was none left to buy.

**A memory `src2` for `vblendv`.** `lower_blendv` declines `modrm.mod != 3` as "not handled
here", and SSE `blendvps` is specified as `xmm2/m128`, so the refusal is a limitation
rather than a constraint and the RIP machinery to move such an operand into a stub already
exists. Measured across every `vblendv` in the binary: 3,558 register-direct, 14 256-bit,
and **zero with a memory `src2`**. The branch never fires. A lowering written for it would
have been dead code with a test nothing exercised.

**Re-loading a 256-bit upper half from a read-only source.** Finding 99, twelve sites.

#### What is left

The residue is 10,229 and lives in the skipped tallies rather than the refused ones:
11,624 `ymm value has no known upper half`, 2,034 `256-bit: arithmetic rather than a copy`,
858 with no store before arithmetic reaches the value. Every one wants a shadow for each
live upper half, maintained across a function rather than within a window. That is the
whole of the remaining work, and it is a design rather than an increment.

### Finding 103 -- the 256-bit representation is smaller than it has been called

Finding 102 closed the refused bucket and said what was left wants "a shadow for every live
upper half, maintained across a function rather than within a window", calling it a design
rather than an increment. Scoped, it is much closer to an increment, and the number that
was making it look large was never measured.

**Almost nothing has 256-bit code, and almost none of it holds more than one value.**

```
260,729 functions
  7,355 contain any 256-bit instruction          2.8%

peak simultaneous upper halves, of those 7,355
  0 live   2,581    35.1%      no ymm destination at all -- the zero idiom
  1 live   4,026    89.8%
  2 live     612    98.2%
  3 live      67    99.1%
  4+ live    69   100.0%      of which 8 functions reach sixteen
```

So the representation does not need a register allocator. It needs **one register**, and
occasionally two.

**And the register is there.** Taking each lifetime from its defining write to its last
read, ending at the next write to the same register or at a call:

```
12,878 lifetimes
  a register is free across it   12,255    95.2%
  written and never read again      566
  none free                          57     0.4%

registers free across a lifetime: median 15, 10th percentile 11
lifetime length: median 3 instructions, 90th 14, max 208
```

Fifteen of sixteen registers are typically untouched across a span that is usually three
instructions long.

#### The first measurement of this was wrong, and the ABI said so

It reported 1,892 lifetimes with no register free -- 29% -- because it took a lifetime as
running to the last MENTION of the register in the function. A function that defines
`ymm0`, calls something, then redefines and uses `ymm0` again became one long span crossing
the call, and the span was then charged for every register the call clobbers.

**Win64 makes the upper half of every `ymm` volatile across a call**, so a lifetime that
appears to span one cannot be a real lifetime in correct code -- it is two, with a
redefinition between them. The architecture contradicting the measurement is what exposed
it, which is the rule this project already keeps: a gate that disagrees with something
known to be true is the first suspect. Bounding lifetimes properly takes the failures from
1,892 to 57.

#### What the design actually has to solve

Not register pressure. Three things, and only the first is new:

- **A lifetime crosses window boundaries.** `ymm_run` carries an upper half in a helper
  within one stub; here the stub that lowers the definition must hand the value to a
  different stub that lowers the read. A register does persist between them -- that is why
  the shadow works at all -- but nothing today reserves one across that distance, and
  `free_across` is the check that would have to.
- **A branch into the middle of a lifetime** breaks the shadow, exactly as it breaks a run.
  `targets.py` already enumerates what can be branched to and the walk above does not
  consult it, so the 95.2% is an upper bound until it does.
- **The 57 with no register free** fall back to the home space or stay refused, which is
  the same answer every other lever here reached.

The linear walk also ignores control flow within the lifetime, so a value defined on one
path and read on another is counted as one span. Both simplifications push the figure
optimistic; neither moves it by the order of magnitude that would change the conclusion.

### Finding 104 -- a 256-bit value carried between two stubs

Finding 103 scoped the representation and found it needs one register, not an allocator,
and that the register is free across 95.2% of lifetimes. This is the first strategy built
on that, and the smallest useful one: a 256-bit load and a store of the same register too
far apart to share a window.

`ymm_pair` takes the adjacent case; `ymm_run` takes everything that fits a single stub.
Past that the upper half dies at the window edge and the store is declined for want of it
-- 11,624 sites reporting `ymm value has no known upper half`, of which 2,020 lie outside
any accepted window and are therefore real residue. A register reserved from the load to
the store carries the value between two INDEPENDENT stubs: the load's writes the upper half
into it, the store's reads it back.

```
VEX in .text     10,229 ->   9,616      795,515 removed, 98.8%
detours         200,630
refused             737 unchanged
```

613 sites from 613 detours, two per pair, and the refused bucket does not move because
this rescues skipped stores rather than refused ones.

**This is the first mechanism here whose correctness is not local.** Every other one --
a window, a run, a bracketed borrow -- is contained in a single stub and can be read in one
place. This one has a register live across a gap that `place_stubs` does not model, so what
keeps it honest is the collector refusing anything it cannot see the whole of:

  * **the load commits first and records the register**, and the store fires only if the
    load actually committed. The listing is walked in address order, so the load is always
    reached first and the two ends cannot disagree by construction rather than by care;
  * **a branch target anywhere inside the span refuses it.** Control arriving mid-span
    would find the shadow holding whatever the previous lifetime left -- which is exactly
    how Finding 82's shipped miscompilation happened one window over. 14 sites hit this;
  * **a call refuses it**, the upper half being volatile across one by the ABI. 60 sites;
  * **the register comes from `free_across`**, so it is dead rather than merely unmentioned.
    "Untouched across the span" would have clobbered a value defined before the load and
    read after the store.

#### The cap nobody would have found by reading

`free_across` asks `dead_from` for liveness, and that scan stops after 60 instructions. So
a span longer than 60 gets no register whatever the walk allows, and the 200-step limit in
`long_pair_store` is not the binding one. It does not matter here -- the measured span is a
median of 3 and a 90th percentile of 11 -- but it is a real ceiling and it was found by a
test that overshot it rather than by reading the code.

#### What the tests actually prove

The `longpair` program puts 52 instructions between the load and the store: past `ymm_run`'s
limit of 48, so the new path is what runs, and inside `dead_from`'s 60, so a register can be
found. **The first version used 14 and tested nothing** -- `ymm_run` took the whole span
into one stub and the new code never executed. Only the mutation of the padding count made
that visible.

Both mutations return exit 3 rather than crashing, which is the value the program yields
when the upper half never arrives: a mismatched register between the two ends, and a load
that writes only its own half. The failure this feature can really have is wrong DATA, and
that is what the cases detect.

One diversion is worth recording because it cost four steps. The unrewritten program
appeared to hang instead of faulting, which looked like a defect in the test until the same
probe was run against `pe-aliasing`, which has worked for months, and hung identically. The
cause was an ad-hoc `WINEPREFIX` in scratch rather than the initialised one `make check-pe`
uses. **Run the probe against a case known to be good** -- the rule was already written down
and applying it first would have saved all four.

### Finding 105 -- a store does not end the value's life, here either

Finding 104 shipped the long pair taking the FIRST store it found, and Starfield's frontier
moved 32 bytes: from `0x14004E230` to `0x14004E250`, the SECOND store of the same register,
left behind because only one was given the shadow. `ymm_run` had already learned this at
1,019 pairs and the new walk had dropped it.

The walk collects every store the value reaches now, and the reservation is taken across
the LAST of them.

```
VEX in .text      9,616 ->   9,613       795,518 removed, 98.8%
detours         200,630 -> 200,633
frontier   0x14004E250 -> 0x14005D040    some 60 KB further on
```

**Three sites, and it earns its place on the executed path rather than on the count.**
Finding 102 records a conditional-move change that was sound, removed 463 give-ups, gained
zero sites and was reverted for it. The difference is not the size of the number: it is
that one of these three is the instruction the game stops on. A site count measures the
residue and the frontier measures whether the program runs, and they are not the same
currency.

#### What the horizon actually caps

Finding 104 said a span longer than 60 gets no register because `dead_from` scans 60
instructions. That is the right number attached to the wrong quantity. `dead_from` proves a
register dead by seeing it written before it is read, or by reaching the function's `ret`;
what must fall inside the 60 is a point where deadness can be PROVED, not the span itself.

Adding the second store pushed that program's `ret` two instructions past the horizon and
every candidate register vanished at a span of 54, having been available at 53. The test
therefore sits at 48 padding instructions: past `ymm_run`'s limit so the new path runs, and
close enough that the `ret` still proves the register dead.

Two predictions were wrong and both were caught by running rather than reading. The
mutation that records only the first store was expected to return 59, the arithmetic with
one half missing; it returns 124, because an unshadowed store is not lowered at all and the
surviving VEX faults. And a `verify` run was killed at 50 minutes having taken 8 the time
before -- contention from another session building in this tree, not a cost in the check.
**It printed seven of its nine lines and stopped**, which is a truncated log reading as a
pass if nobody counts them.

### Finding 106 -- the last iteration of an unrolled loop fell off the zero proof

Starfield stopped at `0x14005D040`, `vmovups %ymm0,0x1d0(%rbp)`, declined `ymm value has
no known upper half`. The value was zero and had been for 87 instructions:
`vpxor %xmm0,%xmm0,%xmm0` at `0x14005CDCF` is a VEX.128 write and clears bits [255:128],
which is the fact the whole Y1-zero strategy rests on.

Eight stores of `ymm0` follow it at 0x30 intervals -- a structure initialisation the
compiler unrolled, one 32-byte field per 48-byte record. Measured against `zeroed_ymm`:

```
past the vpxor   38  45  52  59  66  73  80   87
zeroed says       T   T   T   T   T   T   T    F
```

`limit=80`, and the eighth store sits at 87. **Seven iterations proved, the last one
refused for want of a budget**, with nothing between them touching the register.

```
VEX in .text      9,613 ->   9,531       795,600 removed, 98.8%
detours         200,633 -> 200,715
frontier   0x14005D040 -> 0x1400665DA    some 37 KB further on
```

**82 sites, and 128 rather than 120 is where they came from.** 120 would have covered the
site that exposed this and left every other unrolled loop with a slightly longer body still
falling off the same cliff. Tuning a constant to the one example that revealed it fixes one
site and leaves the population; the 80-to-128 band held 81 more.

**The horizon is a budget and budgets cost, so the cost was measured rather than assumed.**
`zeroed_ymm` recurses on branch targets to depth 4, so a 60% larger limit need not be a 60%
larger bill. The rebuild took **5m02s**, faster than any today.

That last number is the useful one, and it corrects an assumption running through several
findings: every slow run measured today was contention from another session building in
this tree, not the analysis. One `verify` took 50 minutes and was killed by its timeout
after printing seven of its nine lines; the same check took 8 minutes with the tree quiet.
**A truncated log reads as a pass if nobody counts the lines**, and the fix is to count
them rather than to trust the tail.

### Finding 107 -- set the zero horizon against the distribution, not the frontier

Finding 106 raised `zeroed_ymm`'s limit from 80 to 128 for an unrolled loop whose last
iteration sat at 87, and said 128 rather than 120 was what took the population rather than
the one site. **The next frontier sat at 130.** Stepping a constant until the frontier
stops moving is chasing it, so the distances were measured instead.

For every store still declined `ymm value has no known upper half`, walking back to the
nearest write of its own register:

```
11,128 declined stores
  written by something that is not a zeroing   10,693
  a control transfer first                        219
  zeroed, and this far back                       216

within 128: 12   within 256: 126   within 512: 208
median 228, 90th 465, max 556
```

`limit=640` covers the measured maximum with headroom, and it is set once against that
rather than against whichever site surfaces next.

```
VEX in .text      9,531 ->   9,327       795,804 removed, 98.8%
detours         200,715 -> 200,919
frontier   0x1400665DA -> 0x14082130C    some 7.9 MB further on
```

204 sites, matching what the distribution predicted -- which is the check that the setting
was sized against the population and not against an example.

**And the strategy is nearly done.** Only 216 of 11,128 declined stores are defined by a
zeroing write at all. The other 10,693 are defined by a 256-bit write, a load or
arithmetic, where no horizon helps. That is a boundary rather than a lever, and it is
recorded so the constant is not stepped a third time.

#### `real` is not the cost, and this document has twice said it was

The rebuild reported **24m08s real against 5m25s user**: nineteen minutes waiting, not
computing, from another session building in this tree. Against the previous build's 4m55s
user, five times the budget costs **10% more CPU** -- most walks terminate long before the
budget, so it only pays for the tail that needs it.

Finding 106 called a 5m02s rebuild "faster than any today" and treated a 50-minute `verify`
as contention on the strength of wall clock alone. Both conclusions happened to be right
and neither was measured: **`real` measures how busy the machine was, `user` measures the
code.** Time anything whose cost is in question with both.

#### Two mistakes in the measuring, recorded because they nearly stuck

The first classifier counted only an explicit `vpxor` with identical operands as zeroing a
register, when **any VEX.128 write clears bits [255:128]** -- the fact the whole strategy
rests on. Correcting it moved 212 to 216, so it mattered little here and would have
understated the population in a binary that zeroes differently.

The justification for correcting it was itself wrong. The argument was that 82 sites gained
could not square with 12 zero-defined sites within 128 -- but the 82 had left the declined
set when they were fixed, and were never going to appear in a measurement of what is still
declined. **A cross-check between two numbers is only a check if they measure the same
population.**

### Finding 108 -- a splat is a zero store with a weaker reason

Starfield stopped at `0x14082130C`, `vinsertf128 $0x1,%xmm0,%ymm0,%ymm0`, with the store
of that register immediately after. The insert copies the low half into the high half, so
both halves hold the same sixteen bytes -- MSVC broadcasting a 128-bit constant across a
256-bit field.

**`lower_ymm_zero_store` already emits the right code.** It writes two 128-bit stores of
one register at deltas 0 and 16, and was written for an all-zero ymm where both halves are
zero and the same xmm serves for each. A splat has that property one step weaker: both
halves are the same register, whatever it holds. Identical bytes, different justification,
and the insert itself emits nothing because the value it builds is already in the register
the lowered program keeps.

```
vinsertf128 / vinserti128 in the binary       160
  a splat, upper := the low half               89
    followed at once by a store of it          41
  upper := an xmm, low from another ymm        66
  upper := another xmm, low kept                5
```

```
VEX in .text      9,327 ->   9,245       795,886 removed, 98.9%
detours         200,919 -> 200,960
frontier   0x14082130C -> 0x1408284C7
```

41 pairs, 41 detours, 82 sites, and 41 more lost boundaries. Four numbers that had to
agree and did.

#### `verify` refused the first build, and was right

The strategy worked on the first attempt -- correct stub bytes, correct site count, the PE
test returning 107. What was wrong was the MODEL of what the window consumed: a splat pair
covers two instructions and carries no `displaced` list, so the store's boundary vanishes
with nothing recording that it was deliberate. `place_stubs` already had that exact case
for `ymm_pair`, whose comment reads "the verifier is right to want it named", and `splat`
was added without extending it.

`verify: FAILED -- 41 boundaries lost that were not swallowed on purpose`, one per pair.
**The count named the cause before any code was read.** Nothing else could have caught it:
every emitted byte was correct, and only an invariant reconciling the collector's intent
against the binary's real instruction boundaries can see a bookkeeping error that changes
no output.

#### The precondition no execution test could reach

Loosening the immediate check to accept any `vinsertf128` left every PE test passing,
because **this binary contains no `vinsertf128 $0x0`** -- which writes the LOW half and
keeps the upper, and would have stored the wrong sixteen bytes twice. A shape the input
does not contain is one execution can never exercise, so it is guarded by unit cases
instead: one accepted, four refused -- `$0x0`, a high half from another register, a low
half from another ymm, and a store of a register the insert did not build.

### Finding 109 -- the constant needs no register, because memory is the shadow

Starfield stopped at `0x1408284C7`, `vmovups 0x4223441(%rip),%ymm0`: thirty-two bytes of
`.rdata` loaded into a register, and then stored six times inside a loop that fills a
structure with them. MSVC hoists the load out; the stores are the loop body.

Nothing here could take it, and the three refusals are the same refusal:

  * `ymm_pair` wants the store immediately after the load. It is sixteen instructions and
    a loop head away.
  * `ymm_run` wants both inside one window. The loop head is a branch target, so no
    window may span it.
  * `long_pair_stores` carries the upper half in a register the original never names, and
    that register would have to stay free across the loop, with nothing branching into
    the span.

**All three are about keeping a register intact. None of them is about the value.** The
bytes are in a section the loader maps without `IMAGE_SCN_MEM_WRITE`, so they cannot
change between the load and the store, and the store's stub can simply fetch them again:

```
1489e65e4:  movups -0x3f9aceb(%rip),%xmm1   # 0x144a4b900   the high sixteen
1489e65eb:  movups %xmm1,0x10(%rcx)
1489e65ef:  movups -0x3f9ad06(%rip),%xmm1   # 0x144a4b8f0   the low sixteen
1489e65f6:  movups %xmm1,(%rcx)
```

Those are `lower_ymm_pair`'s four moves exactly, high half first so the register ends
holding the low sixteen -- the same bytes for the same reason as Finding 38, with the
load half taken from wherever the value came from rather than from the instruction
before. The load itself becomes a single move of its low half, and its upper half is
left stale on purpose.

#### The two ends have to agree, and they cannot disagree

A store is lowered on a backward argument: walk to the nearest write of the register and
ask what it was. A load is lowered on a forward one: nothing may read the upper half this
leaves stale unless it is a store that will fetch the bytes for itself. Those are
different questions about the same set of stores, and if they answer differently the
result is a load with a stale upper half and a reader that trusts it.

So they are not two answers. `upper_half_read_later` takes a `covered` predicate, the
predicate calls `constant_ymm`, and `constant_ymm` is what the store branch calls. One
decision, asked from both ends. It compares the LOAD each end walked back to, not the
constant's address: two loads of the same bytes are two definitions, and only one of them
is the one being lowered.

#### `zeroed_ymm` was already the walk this needed

The backward argument is Finding 44's, Finding 82's and Finding 84's, and it was written
once, inside `zeroed_ymm`. What that function actually does is two things: find the
nearest write, then ask whether it was a zeroing idiom. Only the second is about zero.

`reaching_definition` is the first half, extracted -- the walk, the refusal at a call,
the transparency of a conditional branch going backwards, the recursion at a branch
target, and `value_survives_loop`'s induction, which was called `zero_survives_loop` and
never asked what the value was. `zeroed_ymm` and `constant_ymm` are now two questions put
to one answer. Writing the walk twice was the alternative, and Finding 52 is what that
costs.

`value_survives_loop` is what makes the executed site work. The stores are inside the
loop and the load is outside it; the loop head is the first store, its only edge in is
the back edge, and nothing in the body writes the register. That is the same induction
that let nineteen refused zero stores through in Finding 83, reached here for a value
that is not zero.

#### A call still ends it, and being exact about why is the point

The docstring's first draft claimed a call was free too, on the grounds that memory does
not move. That is true of the memory and false of the register: the upper half of every
ymm is volatile across a call under Win64, so a callee may leave something else in it and
the store would write that. `reaching_definition` refuses across one and this inherits
the refusal. **What a constant buys is the register pressure and the distance, not the
call.**

#### A four-byte store at the head of a loop

The first store in the loop is `vmovups %ymm1,(%rcx)` -- four bytes, and a `jmp rel32`
needs five. It can widen neither way: backwards is refused because the site is a branch
target and cannot vanish into the middle of a window, and forwards it would have to
swallow another 256-bit store, which `moved_instruction` refuses. Alone, it is the site
the game would then have stopped on, forty-one bytes further along.

Finding 81 met that exact competition among zero stores and answered it by taking the
group as one window. Nothing in `zero_run` was about zero: it is a scan for adjacent
256-bit stores with a predicate supplied by the caller, so it is `store_run` now and the
constant passes a different predicate. Six stores, two constants, two registers, one
stub, one detour.

#### `.text` is in the read-only map, and that is deliberate

`readonly_ranges` decides on the section characteristics rather than on the name, so
`.text` qualifies -- and this tool writes into `.text`. It is still sound, because both
ends read the same address in the same image: a lowered store fetching bytes the patcher
changed fetches exactly what the original load would have fetched from the rewritten
binary. The divergence is against the ORIGINAL image, and in-place patching has that
everywhere.

Measured through `readonly_ranges` itself rather than against a threshold read off the
section table: of the 1,292 RIP-relative 256-bit loads in `.text`, 850 name a read-only
section that is not `.text`, 442 name one that is writable and are refused, and **none
names `.text`**. The question is recorded because the next binary may answer it
differently.

#### What the count is worth, and the one site that is not fungible

```
VEX in .text      9,245 ->   9,180       795,951 removed, 98.9%
detours         200,960 -> 201,013
candidates      239,731 -> 240,591       830 conststore, 30 constload
refused             737 ->     737
frontier   0x1408284C7 -> 0x14235008F
```

**Sixty-five sites, and one of them is the site the game stops on.** Of the 860 new
candidates, 807 sit inside a window some other strategy had already committed and are
skipped for overlap; 53 detours are placed and they cover 65 sites, the construn covering
six by itself. Finding 80 is the reason to write that number down rather than round it
away: sites are not fungible, and this is the second time the aggregate has been the
wrong column to read.

The refusals it does not take have a name of their own now -- `256-bit: the constant is
read by something that will not reload it`, 182 sites, previously scattered through four
buckets that described the run rather than the value. Those are 256-bit reads that are
not stores: arithmetic on a hoisted constant, which is the register model and nothing
else.

**The cost is paid per iteration, and this is where it shows.** Six stores became
twenty-four moves plus a detour, inside a loop. Every other lowering here is a straight
trade of one instruction for two or three; this one reloads the same thirty-two bytes
six times because there is no register to keep them in. It is correct, it is what makes
the loop run at all, and it is the clearest argument yet for the Y1 register
representation: hoisting the upper half into a spare xmm outside the loop would turn all
twenty-four moves back into six.

#### What the run found next

The game now loads 305 modules before it faults, against 301, and stops on
`vstmxcsr 0x178(%rsp)` at `0x14235008F` -- which is not a 256-bit problem at all. There
are nine of these in the binary, five `vstmxcsr` and four `vldmxcsr`; `lower.py` has had
a rule for both since the beginning, `has_direct_sse_form` says yes to both, and
`sse_encoding` produces eight bytes against the VEX form's nine, so it would fit in place
with a byte to spare.

They survive because they take **one** operand. `patch.classify` tests for two operands
and for three and falls off the end, and `collect` refuses `operand shape not A/B/C` by
the same rule -- so a form neither was written against is refused twice and named once.
That bucket is nine sites, all nine of them these, and the game is standing on one.

### Finding 110 -- nine sites with a rule, a correct encoding, and no way in

The frontier named this one, which is the whole argument for having it. After Finding 109
the game stopped on `vstmxcsr 0x178(%rsp)` at `0x14235008F` -- not a 256-bit instruction,
not a three-operand one, and not hard.

Everything needed was already here. `lower.py` has carried a rule for `vldmxcsr` and
`vstmxcsr` since its first table; `has_direct_sse_form` says yes to both; `sse_encoding`
turns the nine-byte VEX form into `0f ae 9c 24 78 01 00 00`, which disassembles as
`stmxcsr 0x178(%rsp)` and is a byte shorter, so it fits where it stands with a nop to
spare. `make verify` has been assembling both of them and finding no VEX left, on every
run, for as long as that check has existed.

**What refused them is an operand count.** `patch.classify` tests for two operands and
for three and falls off the end returning `None`; `collect` refuses `operand shape not
A/B/C` for any count that is not two or three. Neither was written against a form with
one operand, and a one-operand VEX instruction is uncommon enough that the omission
reads as deliberate until you look for the line that made it. There is no such line.

```
one-operand VEX in .text
  vstmxcsr        5
  vldmxcsr        4
```

Nine, and that is the entire `operand shape not A/B/C` bucket -- a count matching to the
site, which is what made it worth chasing before any code was read.

The one-operand case makes the same `vvvv` test the two-operand case makes, and for the
same reason: VEX.vvvv is required to be 1111b where it is unused, so anything else means
the instruction is not the form it appears to be.

#### Two checks whose union had a hole neither could see

`make verify` proves every lowering rule assembles and leaves no VEX behind. It builds
its own operands -- `sample_operands` returns `["(%rsp)"]` for exactly these two -- so it
never asks a classifier anything, and it passed. The classifiers never asked the rule
table anything, and they refused. **The rule was provably correct and unreachable at the
same time.**

That is Finding 52's shape at one remove. There the checker and the checked shared a
function; here two checks are genuinely independent and the gap is between them, which no
amount of strengthening either one would have closed. What closes it is a program that
goes through the whole path: `check-pe`'s `mxcsr` toggles FTZ, loads the word back, reads
it again, and requires the difference to be exactly that bit -- a round trip rather than a
comparison against a constant, because what MXCSR holds when a process starts belongs to
the runtime and not to the test.

#### Nine sites for two lines

```
VEX in .text      9,180 ->   9,171       795,960 removed, 98.9%
in-place        547,707 -> 547,716
detours         201,013 -> 201,013
frontier   0x14235008F -> 0x1428D1492
```

Nine sites for two lines, and the game is past them.

#### What the frontier names now

`0x1428D1492` is `vmovdqu %ymm0,0x28(%rsp)` -- a 256-bit store of a register that
`vpxor %xmm0,%xmm0,%xmm0` emptied six instructions above it. `zeroed_ymm` is written for
exactly this and refuses it, because `0x1428D1479` lies in between and is in `blocked`.

It is not a branch target. `targets.py` reports it from the `pdata` group: the binary
declares a `RUNTIME_FUNCTION` beginning there, and every function start is treated as
somewhere control can arrive, which is correct for an entry point and is the conservative
answer for anything else. Sitting four instructions into a straight-line run, between a
`mov` and a `lea`, it is far more likely to be a chained fragment -- a region of the
enclosing function with its own unwind record and no separate entry -- than a function
anybody calls.

**That is a measurement, not a guess to act on.** `UNW_FLAG_CHAININFO` in the unwind
info distinguishes the two, and Findings 48, 68 and 70 already read fragment unwind data
for other reasons. What it would take is a reason to believe nothing reaches a fragment
except by falling into it, and the direct branches are already enumerated separately, so
the question is what the indirect ones do. Loosening `blocked` is the most load-bearing
assumption in the tool, and it is not a change to make while passing.


Measured since, because the measurement is most of the work and the decision is not:

```
RUNTIME_FUNCTION entries        236,427
  chained (UNW_FLAG_CHAININFO)   56,269
  primary                       180,158

each chained start, by what precedes it
  an instruction that falls through   46,739
  a ret, jmp, int3 or ud                9,522
  not in the listing at all                 8
```

**Five-sixths are fallen into**, which is what a continuation of straight-line code looks
like -- and everything that could ALSO reach one, a direct branch, a switch table, a
relocation, a PC-relative `lea`, a scope table's handler or its resume target, is
enumerated separately and would stay in `blocked` whatever happened to the `.pdata`
group. The tool already trusts exactly that enumeration for the byte before the fragment
starts.

**The counts above are the second reading, and the first was wrong.** It said 42,184
fallen into and 4,555 with "nothing that decoded before it", and the 4,555 were an
artifact of the instrument: the scan matched a listing line only when it carried a
mnemonic, so objdump's continuation line for an instruction longer than seven bytes was
skipped and the instruction before the fragment measured short of it. **That trap is
written down four sections above, in "Practical things that cost time to learn", and the
scan was written anyway.** There are no genuine gaps: every chained fragment in the
listing is preceded by an instruction that reaches its first byte.

Whether the idea is worth anything, and whether it is safe, are two questions, and it
loses on the first. See Finding 112.

### Finding 111 -- two defects that had never fired, and one that could not

Findings 109 and 110 were read adversarially before anything was built on them, with the
question put as "find another one" rather than "check this". It found two, and the
interesting property they share is that **neither has ever happened in this binary**.
Every structural check passes today and would have gone on passing.

#### A strategy stub deleted the instruction its window swallowed

`place_stubs` may hand any stub a `displaced` list. The Finding 36 extension takes the
next candidate along when its site sits exactly at the window's end, grows the window
over it, and retires that candidate as rescued. The plain path emits it at the end of the
stub. **The six strategy paths -- `run`, `pair`, `longload`, `longstore`, `splat` and now
`construn` and `zerorun` -- wrote their own body and jumped straight home**, so the
passenger vanished.

Nothing could see it. `place_stubs` records the passenger's boundary in `swallowed`, so
`verify`'s "every lost boundary was deliberate" is satisfied. The stub holds no VEX. The
census's "nothing survives inside a committed window" stays zero **because the
instruction does not survive at all** -- it is neither in the stub nor in `.text`, which
is the one state a reconciliation between those two places cannot notice.

Measured on the real binary by wrapping `build_stub` and running the real selection once:
**zero occurrences.** The extension needs a backward-widened candidate beginning inside
the carrier's window with its site exactly at the end of it, and no 256-bit window in
Starfield has one. Latent rather than live, and the same class as `scope_targets`'
latent hazard: closed because closing it costs nothing.

`close_stub` is the fix -- the displaced list and the jump home, written once, called by
all six. The unit case builds a `pair` stub with a passenger and looks for the
passenger's bytes in it. **It was run against a copy of the tool with the `pair` branch
put back the way it was, and it fails there**, which is the only reason to believe it is
checking anything.

#### `vzeroupper` writes an upper half and names nobody

`reaching_definition` decides what wrote a register by reading operand text. Its comment
said `vzeroall` was the one instruction that writes an xmm without naming it and that
there are none in `.text` -- true of `vzeroall`, and the wrong instruction. **There are
19,253 `vzeroupper`**, each of which clears bits [255:128] of every ymm, and the scan
walked straight past all of them.

For a constant that is wrong bytes: the upper half is zero at the store and the stub
would write the constant's high sixteen. `long_pair_stores` has the same hole from the
other direction -- its break test is `register in text`, and a `vzeroupper` has no text.

Measured, twice and in both directions, over the whole listing:

```
256-bit loads seen                              10,791
  a vzeroupper before the value closes           2,490
  a store reached with one in between                0

zero stores the same scan reaches               10,933
  a store reached with a vzeroupper in between        0
```

**The instruction is everywhere and the shape is nowhere**, because MSVC emits
`vzeroupper` immediately before a call or a return and the backward walk stops at either.
So the blunt fix -- treat it as a write and let both callers refuse -- costs zero sites
while being right about the constant, and the shape is guarded by a unit case because
no execution test can reach a shape the input does not contain.

#### The one-operand form was admitted in one place and refused in the other

Finding 110 taught `patch.classify` the one-operand shape and taught `collect` the same,
and `lower_vex` was not told. Its operand dispatch ends `elif len(registers) != 2`, so a
`vstmxcsr` that could not be patched where it stood became a candidate whose stub can
never build, counted under `lower: a four-operand form`. No site was lost -- all nine are
patched in place -- and the accounting was wrong, which is how a bucket stops meaning
what it says. One operand sets nothing up, so admitting it is one line and `sse_encoding`
is the whole lowering.

#### What the 182 refused constants actually are

The bucket Finding 109 named was measured by instrumenting `upper_half_read_later` to
record which of its six refusals fired, and running the real collector once. The answer
is not the walk's limits:

```
a 256-bit read that is genuinely not a store         164
  vfmadd231ps 42, vpand 38, vmulps 18, vxorps 8, vpaddd 6, ...
a 256-bit store the backward proof refused             7
the register is not named at all -- a substring match  2
the path budget exhausted                              0
a branch the walk could not resolve                    0
```

**Not one of the 182 is blocked by a bound.** Finding 80 raised the path budget to
400,000 for eleven sites and worried about the cost; on this bucket the budget and the
branch walk between them account for nothing at all, and 164 of 182 are arithmetic on a
hoisted constant -- the Y1 register representation, and nothing else.

The two substring cases are `%ymm1` matching inside `%ymm13` and `%ymm14`, in
`upper_half_read_later`'s `if register not in operands` pre-filter. It is wrong in the
direction that refuses a site rather than accepting a bad one -- the two tests beside it
are exact comparisons on split fields -- so it costs two sites and no correctness, and it
is recorded rather than changed.

### Finding 112 -- forty-six thousand addresses unblocked, and eleven sites

The frontier stopped on a 256-bit store of a register `vpxor %xmm0,%xmm0,%xmm0` had
emptied six instructions above it, refused because `0x1428D1479` lies between the two and
is in `blocked`. That address is the `begin` of a chained `RUNTIME_FUNCTION` --
`[0x1428d1479, 0x1428d151e)`, `UNW_FLAG_CHAININFO` set -- and **nothing else names it**:
not `.reloc`, not an `.xdata` handler or scope target, and not one of the 17.1 million
lines of disassembly branches there.

So the obvious move is to take chained fragments out of the `.pdata` group. A chained
record is a statement about stack layout over an address range, not a claim that control
arrives at its first byte, and treating one as an entry point is a category error rather
than caution. That argument is right, and it does not matter.

#### What it is worth, before what it costs

Measured by removing the 46,731 fallen-into chained begins from the `pdata` group alone --
leaving every other group intact, and leaving `collect`'s own scan free to put any direct
branch target back -- and running the real collector:

```
                                                 before   unblocked
ymm value has no known upper half                10,086      10,084
next instruction is a branch target                 202         193
256-bit: no store before a control transfer         159         159
outside .pdata                                      321         427
256-bit: no store before 256-bit arithmetic         404         410
no register free across the ymm run                 213         216
──────────────────────────────────────────────────────────────────
not inside any accepted window                    7,143       7,153
```

**Eleven sites gained, and the residue goes up.** 46,731 addresses came out of the set and
eleven refusals changed, because a blocked address has to sit exactly inside a window or
exactly on a proof's path to be costing anything, and almost none of them does.

The 106 that moved into `outside .pdata` are the instructive half. `outside.leaf_ranges`
consults the same set for a different question -- not "can control arrive here" but "is
this address referenced, so is it a function" -- and trimming the set made it recover 106
fewer leaf functions. **One set was answering two questions**, which a proper version
would separate; doing so would take the change from -10 to +11, and eleven is still the
ceiling.

#### The safety argument was also wrong, in the direction that flatters it

The record said funclets are excluded by the fall-through test because they are preceded
by padding or by the end of the function above. Measured over all 489 catch funclets in
the binary: 273 are preceded by `int3`, 151 by `jmp`, 1 by `ret` -- and **64 by a
single-byte `nop`, which falls through.** At `0x14375fcc0` the funclet above ends in a
`call` to the throw thunk, one `0x90` of padding follows, and then the funclet begins.
The fall-through test would have called that one a continuation.

What actually keeps catch funclets safe is something else entirely: **not one of the 489
is a chained entry.** They live in one contiguous region at the top of `.text`,
`0x143759d60` to `0x14387d390`, which holds 6,056 `RUNTIME_FUNCTION` begins and no
chained record among them. The discriminator that works is the population, not the
predecessor -- and the discriminator that was written down would have let sixty-four
funclets through if they had ever been in that population.

#### What the tool's own header says about this, and why it is not true here

`targets.py` opens by naming its four sources and saying which are sound. Of `.reloc`:
"Every absolute address stored anywhere in the image has a base relocation... So vtables,
function pointers, **C++ EH handler addresses** and TLS callbacks are all here. This is
COMPLETE for absolute targets."

The reasoning is right and the example is a 32-bit one. On x64 every exception structure
is image-relative: `UNWIND_INFO`'s handler slot, `FuncInfo`'s `dispOfHandler`, the scope
table's `Handler` and `JumpTarget` are all RVAs, and **an RVA needs no fixup when the
image moves, so the loader records nothing for it.** Measured: of the 29 handler and
scope addresses the tool recovers from `.xdata`, `.reloc` names **zero**.

What that leaves is worth stating plainly, because nothing in the tree stated it:

```
.pdata entries carrying EHANDLER/UHANDLER      85,878
  distinct handler routines                         6
    __CxxFrameHandler4                         85,139
    __GSHandlerCheck_EH4                          353
    __GSHandlerCheck                              264
    __CxxFrameHandler3                             68
    __GSHandlerCheck_EH                            33
    __C_specific_handler                           21

catch funclet entry points                        489
  named by any source other than .pdata             1
```

**Four hundred and eighty-eight catch funclets are in `blocked` for exactly one reason,
and it is the group this finding proposed to trim.** They are safe today because a
funclet is a primary record, so trimming the chained ones would not have touched them --
but that was luck rather than the design, and the design's own header says the cover
comes from somewhere it does not.

#### The decision

**Not made, and not because it is dangerous.** It is worth eleven sites, one of which is
the site the game stops on; Finding 80 is the standing argument that such a site can be
worth the whole difference, and it is a real argument. Against it: the change rests on an
enumeration built for this measurement, whose author could not validate two branches of
the format and did not enumerate destructor funclets at all, and its failure mode is a
value silently wrong rather than an instruction that faults. **Eleven sites is not enough
to buy a silent failure mode**, and the frontier has better roads open -- the register
representation is 3,186.

What would change the answer is the enumeration becoming the tool's rather than a
probe's: parse `FuncInfo` and `FuncInfo4` in `targets.py`, put every funclet in the set
by name, and then the `.pdata` group is a redundant belt rather than the only one. That
is worth doing for its own sake, because the tree currently depends on a property no file
records and no check enforces.

### Finding 113 -- a store does not end the value's life, for the third time

`splat_pair` takes a `vinsertf128 $0x1,%xmmA,%ymmA,%ymmA` and the one store after it.
MSVC does not write one store. It broadcasts a constant into a run of consecutive fields:

```
1406a8da8:  vinsertf128 $0x1,%xmm0,%ymm0,%ymm0
1406a8dae:  vmovups %ymm0,(%rcx)          taken
1406a8db2:  vmovups %ymm0,0x20(%rcx)      refused: ymm value has no known upper half
1406a8db7:  vmovups %ymm0,0x40(%rcx)      refused
   ... 0x60, 0x80, 0xa0, 0xc0, 0xe0 -- eight in all
```

The seven refusals say the value has no known upper half. It has one: **the same sixteen
bytes as the low half**, which is what the insert means and what the first store was
already lowered on.

This is the third time the finding has been the same sentence. Finding 105 learned it for
the long pair -- "a store does not end the value's life, and stopping at the first one
cost the executed path directly". Finding 106 learned it for the zero run. Both times the
fix was to keep walking; both times the walk was written for one store because one store
was the shape in front of it.

#### It needed no new machinery, which is the point

`store_run` was `zero_run` until Finding 109 took the predicate out of it, on the grounds
that "nothing above is about which value it is: the competition for padding is a property
of four-byte stores standing next to each other". A splat passes a third predicate, and
it is the simplest of the three -- **the members are address-adjacent by construction, so
nothing can lie between them to disturb the register**, and the only question left is
whether the store names the register the insert built.

The emitted bytes are `lower_zero_run`'s, unchanged. That is Finding 108's observation
one level up: a splat has the zero's property one step weaker, both halves being the same
register rather than both being zero, and two 128-bit stores of one xmm serve either. The
strategy is named `splatrun` rather than reusing `zerorun` so that the justification stays
readable in `place_stubs` and in the census.

#### Forty-five sites and not one detour

Counted over the whole listing, with objdump's continuation lines joined -- the thing
Finding 112 got wrong:

```
splats followed by at least one store       40
their stores, in total                      85
stores beyond the first                     45

stores per splat    1 -> 17 splats
                    2 -> 19
                    3 ->  1
                    9 ->  3
```

```
VEX in .text      9,171 ->   9,126       796,005 removed, 98.9%
detours         201,013 -> 201,013
frontier   0x1428D1492 -> 0x1428D1492
```

**Forty-five sites and not one detour**, because a run is one stub whether it covers one
store or nine -- the window grows and the jump already written at its head serves all of
it. The independent scan and the rewriter agree to the site, which is the only reason to
believe either.

**The frontier did not move**, and saying so is the honest half. These forty-five are
somewhere else in the binary; the site the game stops on is still the zero store of
Finding 112, still refused by a chained `.pdata` record between it and its `vpxor`. An
increment that does not move the frontier is worth having and is not progress on the thing
being measured, and the two are easy to confuse when the percentage moves.

### Finding 114 -- the splat used once, which needs no register either

Finding 113 took the splat's stores. The shape next to it is the splat used by one
operation and then stored:

```
140454762:  vinsertf128 $0x1,%xmm2,%ymm2,%ymm2
140454768:  vandps 0x240(%rsp),%ymm2,%ymm0
140454771:  vmovups %ymm0,0x200(%rsp)
```

All three were refused, each for a different reason and none of them the real one: the
insert for having no store after it, the `vandps` for being `256-bit: arithmetic rather
than a copy`, the store for having no known upper half.

**The same fact answers all three.** Both halves of `ymm2` are the same sixteen bytes, so
the operation can be done once per half against the two halves of its memory operand, and
the splat's own xmm is never written -- it is still there for the second half. Six
instructions, no helper register, no liveness question:

```
1400040 30:  movaps %xmm2,%xmm0
1400040 33:  andps  0x50(%rsp),%xmm0      the high half of the memory operand
1400040 38:  movups %xmm0,0x70(%rsp)      the high half of the destination
1400040 3d:  movaps %xmm2,%xmm0
1400040 40:  andps  0x40(%rsp),%xmm0
1400040 45:  movups %xmm0,0x60(%rsp)
```

High half first, so the destination's xmm ends holding the low sixteen -- the order is
`lower_ymm_pair`'s and the reason is the same one Finding 38 gave.

#### What has to hold, and the one that is an ISA fact rather than a scan

Three of the four conditions are shape and the scan can see them: the other source must be
memory, because a second ymm source has an upper half nobody knows; the destination must
not be the splat register, or computing the high half destroys what the low half needs;
and the store must be of that destination and follow at once.

The fourth is not a shape. **The operation must be the same operation on each 128-bit
lane**, or two 128-bit instructions are not the 256-bit one -- and no amount of looking at
the operand list says whether it is. `vhaddps` has exactly this shape and adds neighbours;
`vperm2f128` has it and crosses lanes. So `LANE_WISE` is a list by ISA behaviour, and it is
the whole of the safety argument. **Two of its entries occur here**, `vandps` seventeen
times and `vmulps` twice, which means the other thirty are reasoned and not executed. That
is the wrong way round for this project and there is no way to make it the right way round
from one binary: `scratch.py`'s rule applies unchanged, one missing costs a site and one
wrongly present costs correctness.

#### Nineteen triples, fifty-seven sites

```
VEX in .text      9,126 ->   9,069       796,062 removed, 98.9%
detours         201,013 -> 201,032
frontier   0x1428D1492 -> 0x1428D1492
```

Nineteen triples, nineteen detours, **fifty-seven sites** -- and the scan and the rewriter
agree exactly, which is what makes the count worth quoting. Every instruction of every
triple went, because the shape is only lowerable whole.

The frontier is where it was. That is now three increments in a row -- 45, then 57 -- and
none of them has moved it, because the site the game stops on is refused by something none
of them touches. **The percentage and the frontier are measuring different things**, and
the honest reading is that these 102 sites are progress towards a binary that runs and no
progress at all towards knowing what breaks next.

### Finding 115 -- the 320-site estimate was 4, and the check that never checked

Findings 113 and 114 came off a scoping pass that ranked the residue into rungs. Its
second rung was the largest single thing on the list: let `ymm_run` carry a 256-bit ALU
instruction whose ymm sources the run already tracks, rather than stopping at it. That
refusal, `256-bit: arithmetic rather than a copy`, is 1,993 sites and the estimate put the
rung at 320, of which 216 could be given a helper.

**It is four.**

Re-measured by replaying `ymm_run`, `lifetimes` and `assign_helpers` over the 309 `.pdata`
functions holding 1,948 of the 1,993 -- calling the tree's own `free_across`,
`span_keeps_rsp`, `home_space_free` and `upper_half_read_later` rather than a second
implementation of them:

```
256-bit non-moves a walk reaches with every ymm source tracked   169
  of which are genuine arithmetic                                 83
  of which are 256-bit reloads of a tracked register              86
genuine ALU sites that survive to a store, i.e. inside a window   28
  accepted -- helpers found, upper-half guard passed               4
  refused: the value is loaded and never stored                   13
  refused: no register free and no home space                      9
  refused: ymm run upper half read later                           2
```

**The estimate counted qualifying positions.** A position qualifies when the mnemonic is
lane-safe and its sources are tracked; a *site* is taken when the run it belongs to also
reaches a store, gets helpers for every lifetime, and passes the upper-half guard at its
end. 56 of the 83 sit in a run that never reaches a store at all -- `load / arithmetic /
arithmetic / ...` with the result consumed rather than written back, and a run's product
is a store. A further 102 reached positions have an untracked ymm source: 52 of those are
another 256-bit instruction, which is a chain, which is the representation.

That is the third time a number has had to be re-taken in two days -- the 4,555 of Finding
112, the 42,184 of the same, and now this -- and the pattern is the same each time: **a
count of things that look right, quoted as a count of things that work.**

#### What the re-measurement found instead, and it is not costed either

Two adjacent populations, both larger, and both stated here as *reached* rather than as
gained, which is the distinction this finding is about:

  * **`vextractf128 $1,%ymmS,%xmmD` where the source is tracked -- 113 reached**, of 383 in
    the binary. Once the halves are in separate registers this is `movaps H(S),%xmmD` and
    nothing else. It is not the two-halves rule and must not be folded into it: it is
    cross-lane by definition, and it becomes trivial for the opposite reason, that the
    lanes have already been separated.
  * **A 256-bit reload of an already-tracked register -- 86 reached.** Finding 77 rekeyed
    `lifetimes` on position rather than register for exactly this, "before the thing that
    needs it". This is that thing.

And one that needs no new rule at all: **`assign_helpers` is asked for a span reaching the
run's last store, and only that one.** Retrying at each earlier store instead is worth
318 accepted runs to 325, and 656 covered 256-bit sites to 670, on its own. It also has
to be there before the ALU rule can be: carrying an ALU lengthens a run, a longer run is
harder to give helpers to, and without a fallback to the plain walk the change *loses*
runs -- measured at 318 down to 303.

#### A flag that was wrong and was reached by luck

`compare_predicate` returns `(name, avx_only)`. Its last line read

```
			return name, name in AVX_PREDICATES
```

which is `False` by construction: the AVX case returned two lines above it. So a bare
`vcmpgtps` -- objdump's spelling of `GT_OS`, and there are four in `.text` -- came back
flagged SSE-compatible. **Nothing acted on it.** `has_direct_sse_form` ands the flag with
`name in SSE_PREDICATES`, which is False for `gt`, so the site was refused anyway and the
answer was right by the other half of an `and`.

SSE has eight predicates and they are all in `SSE_PREDICATES`, so a name in neither table
is AVX-only whether or not there is a rewrite for it. `gt` and `ge` now have one:
exchanging the operands turns `GT_OS` into `LT_OS` and `GE_OS` into `LE_OS`, which are
exactly SSE's `cmplt` and `cmple` -- and unlike the `_oq` entries beside them **these two
lose nothing at all**, the signalling behaviour agreeing on both sides. All four
`vcmpgtps` here are 256-bit, so no site is gained; what is fixed is a table about
correctness that was wrong.

#### `make verify` did not cover the compares

`verify`'s first sentence is that a rule which has not been through an assembler is a
guess. Its `covered` set was `DIRECT_MNEMONICS | NDS_MNEMONICS | SEQUENCE_MNEMONICS |
FMA_SAMPLES`, and **no compare is in any of those** -- objdump folds the predicate into
the mnemonic, so `vcmpltps` is not a table entry anywhere. Every predicate rewrite in the
tree, including the operand exchange that changes which register the destination has to
hold, had gone through no toolchain at all.

They do now: sixty-four compare mnemonics, and the count of assembled lowerings goes from
439 to 567. All of them pass, which is the good outcome and not the interesting one --
the interesting one is that a check quoted for two months as proving every rule was
silently proving 439 of 567.

### Finding 116 -- the run asked for one span, and the extract that rides in it

Two changes to `ymm_run`, and the first exists so that the second cannot cost anything.

#### The span was the last store's, and only that one

`assign_helpers` asks `free_across` for a register dead from the load to the run's **last**
store. A long span is harder to serve than a short one, so a run refused for want of a
helper may have a prefix that is not -- and the prefix stores real bytes either way. The
run simply ends earlier and whatever followed detours on its own account.

`run_prefixes` offers every valid truncation, longest first, so a run that needs none is
untouched and the first prefix offered is exactly what `ymm_run` returned. A truncation is
`ymm_run`'s own two conditions applied to less of the walk: it ends at a store, because a
run's product is a store, and it leaves nothing loaded and unstored.

**It is worth three sites.** A scoping pass costed it at fourteen, measured over an
extracted subset with its own `blocked` set; on the whole binary the residue goes 7,032 to
7,029 and `no register free across the ymm run` goes 213 to 211. It stays because it can
only add -- and because the second change would otherwise cost runs, a longer run being
harder to give a register to.

#### `vextractf128` is cross-lane, which is why it is free here

`vextractf128 $0x1,%ymmS,%xmmD` moves the upper 128 bits into an xmm. It is cross-lane by
definition and the run walk stopped dead at it. Once the run is holding that half in a
helper, the whole instruction is

```
14000403e:  movaps %xmm1,%xmm2
```

**and that is the entire lowering.** The lanes have already been separated; the
instruction that asks for one of them is asking for a register the stub is holding.

What it must not be, and each is a way the trick fails:

  * `$0x0`, which takes the LOW half -- handing over the helper would be the wrong
    sixteen bytes and nothing downstream would look wrong. There are none in this binary,
    so it is a unit case;
  * a destination that is itself tracked, because writing its xmm destroys the low half
    the run still owes a store;
  * a source outside the run, which has no helper to hand over;
  * an extract whose source's lifetime ended before it. The helper physically still holds
    those bytes and the model says the lifetime is over, so `assign_helpers` refuses the
    run rather than believing otherwise -- which is Finding 77's silent wrongness coming
    back in a new costume.

The memory form -- `vextractf128 $0x1,%ymmS,mem`, a store of the upper half -- is not
claimed. 375 register-form extracts in the binary against 20 memory ones, and the register
form is the one that needs no operand arithmetic at all.

**The destination's upper half is left stale on purpose**, because the original zeroed it
as every VEX.128 write does and a `movaps` does not. The run's existing
`upper_half_read_later` guard covers it: the member records the DESTINATION spelled as a
ymm precisely so that `held_open` includes it.

#### What they are worth

```
VEX in .text      9,069 ->   9,016       796,115 removed, 98.9%
detours         201,032 -> 201,008
skipped, overlap 38,620 ->  38,657
frontier   0x1428D1492 -> 0x1428D1492
```

**Fifty-three sites and twenty-four fewer detours**, which is the shape of the change
rather than an oddity: a run that carries an extract is a longer run, so it swallows what
would otherwise have been detoured beside it. Bigger stubs, fewer of them, and 37 more
sites skipped for overlap because a longer window covers them.

#### A shadowed name, caught by the fixture and not by any check

The first version mapped an extract to its lifetime's helper with

```python
	for kind, position, _register in members:
		...
		if inplace.split_operands(plain[position][3])[1] == _register:
```

inside `for _register, load_at, stores in spans:`. The inner unpack shadows the outer, so
the comparison asked whether the extract's source equalled the extract's own destination
-- always false, so no extract was ever mapped, so the guard below refused every run that
held one. It failed safe, which is why nothing caught it: `selftest` passed, `check-pe`
passed, and the only symptom was a PE sample that produced no detour at all. The name is
`register` and `_held` now, and the fixture is what found it.

### Finding 118 -- forty-two stubs saved two registers to the same sixteen bytes

`encode_spill` emitted `movups %xmm,(%rsp)` -- mod 00, no displacement -- for every
borrowed register, and `build_stub`'s run path loops over the borrowed set calling it once
per register. **Two helpers therefore saved to the same sixteen bytes and restored from
them, and the first register came back holding the second's value.**

Measured on the binary as built, by wrapping `build_stub` and running the real selection:

```
run stubs borrowing 0 registers    1,741
                    1                138
                    2                 38
                    3                  4
```

**Forty-two.** Not a latent shape this time: 42 stubs in the image that has been rebuilt,
verified and run under Proton five times were writing a caller's live register into a slot
another save had already taken. `0x140615c9c` borrows xmm0 and xmm1; `0x1406a8510` borrows
xmm0, xmm1 and xmm2.

#### Everything passed

This is the fourth defect here to produce silently wrong output while every structural
check stayed green, and it is the purest of them. The bytes assemble. No VEX survives. The
census reconciles. `verify` finds every lost boundary deliberate and every branch target
still an instruction. **The borrow is invisible to all of it by construction** -- a
borrowed register is one the original program never named, so nothing in the tool's model
of the original has an opinion about what is in it, and the save and the restore are a
matched pair whatever address they name. Two pairs naming one address is a fact about
arithmetic, not about shape, and shape is all these checks see.

What would have caught it is the thing this project keeps arriving at: asking what the
code computes. No `check-pe` sample borrows twice -- `homespill` borrows one register, and
one register is always correct.

#### The fix, and the refusal that comes with it

`encode_spill` takes a `slot` now, and the run path enumerates the borrowed registers into
slots. The home space is 32 bytes, so it holds two; **a third is refused** rather than
reaching past what the ABI reserved:

```
placed        201,008 -> 201,004
refused           737 ->     741
VEX in .text    9,016 ->   9,040
```

Exactly the four three-register runs, which is the count agreeing with itself from two
directions -- the wrapper counted four before the fix and `place_stubs` refuses four
after.

**The fix costs twenty-four sites**, and that is the right sign. Those twenty-four were
being lowered by stubs that overwrote a saved register, so they were not translated
sites; they were wrong ones. The residue going up is the count becoming honest.

The 38 two-register runs keep working and now write 32 bytes rather than 16 of the home
space. That is still inside the region Win64 reserves for the callee and still below any
frame the function built, so the argument of Finding 73 is unchanged in kind; what changes
is that it now uses the whole of what it was already entitled to.

#### Two things this did not fix, named because they are the same region

A borrowed **nonvolatile** register -- xmm6 to xmm15 -- is a second question, and it is
open. `spill_candidates` returns `range(16)` minus the names the site uses, and the run's
fallback is `min(range(16) - taken - own - the run's registers)`; both can pick xmm7. While
the borrow is live the caller's value is in the home space, and if the lowering faults
there, the unwinder restores nonvolatile xmm registers only from the primary's
`UWOP_SAVE_XMM128` codes -- which a primary that never used xmm7 does not have. The cheap
answer is to order `spill_candidates` volatile-first. The complete one is to emit
`UWOP_SAVE_XMM128 <register>, 0` in the stub's own chained fragment, which is **the one
operation the x64 ABI explicitly sanctions inside a chained fragment** -- and which needs
this finding's slot to exist first, because the code describes one register at one offset.

### Finding 119 -- the AVX host was here all along, and it is qemu

*"The differential harness still has no AVX host"* has stood in the open questions since
milestone 1. `make verify` proves the emitted SSE assembles; `make check-lowering` proves
it agrees with GCC compiling the equivalent intrinsic. **Neither compares the lowering
against the instruction it replaces**, and the reason recorded was that it would need a
machine with AVX or a software model of the VEX semantics.

It needs neither. **`qemu-x86_64` translates rather than dispatches**, so it executes VEX
on a host that has none -- and `qemu-user` was already installed on this machine. The
whole gap was a machine nobody had asked the right question of.

```
make check-vex
   the VEX binary on this CPU: exit -4 (SIGILL -- this host has no AVX)
   233 cases x 7 patterns = 1631 comparisons of 15 registers each
   identical                        1588
   Class F, two roundings (expected) 15
   both operands NaN (oracle defect) 28
   UNEXPLAINED                       0
```

Each case runs the ORIGINAL VEX encoding under qemu and `lower_vex`'s bytes natively, and
compares all sixteen xmm registers -- because a lowering that computes the right answer
and clobbers a bystander is still wrong.

#### The case list is not written twice

`lowering_cases.build()` is called and `detour.lower_vex` is wrapped to record the
encoding it was handed, so the originals and the lowerings come out of **one pass over one
list, in one order**, and the count is asserted. There is no second copy of the operand
shapes to drift from the first, which is the failure `evidence.md` names and which this
project has paid for twice.

#### Two exemptions, and each is asserted rather than excused

**Class F.** `vfmadd*` becomes a multiply and an add: two roundings where the hardware did
one, and the only rule in the design that is not semantics-preserving. A Class F case that
differs is recorded -- and a Class F mnemonic that **never** differs is reported too,
because an exemption nothing exercises is an exemption nobody checked.

That report earned itself immediately. The first run exempted four Class F cases as
expected divergence and **every one of them was the all-NaN pattern**: the two-roundings
difference the exemption exists for had never once been observed, so it was excusing
something other than what it names. Two float triples were searched for -- 600,000
candidates -- that diverge under all twelve combinations of operand assignment, negation
and subtract. With those in the pattern set, **all ten Class F mnemonics differ**, and
Finding 4 is measured rather than asserted for the first time.

**The oracle's own defect.** qemu's softfloat returns SRC2's NaN where Intel returns
SRC1's, and only when BOTH operands are NaN -- measured with a probe, and identical for
the SSE and the VEX encodings, so it is qemu's arithmetic and not its VEX decoder. The
exemption is narrowed twice: it applies only on the pattern where both operands are NaN by
construction, and only when every differing element is a quiet NaN on both sides.

#### Absent, skipped and passed are three different things

`require_oracle` exits **77**, not 0, when qemu is missing or reports no avx2 model. A
harness that treats its own absence as a pass is the vacuous check `evidence.md` opens
with; one that treats it as a failure makes every machine without qemu-user look broken.
It says which.

And the harness has been watched failing. `SABOTAGE=n` flips one bit of case *n*'s lowered
bytes; with `SABOTAGE=0` the run reports three UNEXPLAINED rows and exits 1. **A test
nobody has seen fail is a test nobody has seen.**

#### What it does not settle

The arithmetic is corroborated against real silicon -- the same mnemonics at 128 bits
agree with this Westmere on 445 of 459 comparisons, the other 14 being the NaN defect. The
**lane structure** rests on qemu, which is an independent implementation and demonstrably
distinguishes cross-lane cases, but is not silicon. A machine with AVX2 would settle it
outright. Short of that the residual risk is qemu being wrong about one mnemonic's lanes
in exactly the way that would agree with a misreading of the manual.

### Finding 120 -- three numbers in milestone 0 that measure nothing

Finding 6 flagged milestone 0's three-operand count rather than resolving it, on the
grounds that "the answer decides which document is wrong". The answer is that milestone 0
is, three times over.

**208,054 is not a count of anything.** Measured under nine definitions -- registers only,
with immediates and without, SIMD registers only, memory `src2` in or out, 256-bit in or
out -- and no combination reaches it:

```
3 operands after dropping an immediate (vex_scan.py's own)   275,586
three registers, immediate allowed                           210,500
three registers, no immediate                                184,260
three SIMD registers, immediate allowed                      204,479
three SIMD registers, no immediate                           178,311
memory src2, no immediate                                     62,883
```

The nearest measurable neighbours bracket it at 204,479 and 210,500.

**126,576 is not merely unmatched, it is impossible beside it.** Any 208,054-site subset of
the 210,500 all-register population carries at least 131,912 extra movs, because removing
2,446 sites can remove at most 2,446 movs. Growing the 184,260 no-immediate population up
to 208,054 must add immediate register forms or memory-`src2` forms, and both have a
*higher* extra-mov rate than the population they join. 126,576 of 208,054 needs a 39.16%
`dst == src1` share, which is above every population measured.

**And the 23.6%/76.4% split is wrong independently.** Class B measures 30.3% of 275,586,
36.2% of 210,500 and 37.7% of 184,260. Never 23.6%.

So the milestone 0 lines are retired and Finding 6's replace them -- which reproduce to
the digit: 275,586 three-operand, B 83,461, C 183,123, C-alias 9,002, the alias split
4,318 commutative and 4,684 needing a scratch, and the per-mnemonic tail `vsubss` 1,210,
`vmaxss` 806, `vdivss` 717.

**Finding 6's own bracketing numbers are slightly low**, and saying so is the point of
re-measuring rather than re-quoting: its "register-only triples number 178,306" measures
178,311, and its "memory src2 add 62,773 more" measures 62,883. The 110 is not a narrower
operand shape -- all 62,883 have a base or index register, none is absolute, none has a
non-SIMD destination or `src1`.

#### Why this took three years of findings to settle

Nothing depended on it. The cost model was rebuilt from measured operand shapes in
*Estimated cost of a translated binary*, the milestone 4 row counts real sites, and every
strategy since Finding 14 has been costed against `detour.py plan`. **A number nothing
reads can be wrong indefinitely**, which is the argument for retiring it rather than
correcting it in place: a corrected number nothing reads is a number that will drift
again.

### Finding 121 -- seven dispatchers, not one, and now a check that says so

Finding 5 found a CPUID/XGETBV-dispatched AVX-512 kernel and left two questions open:
whether the rewriter preserves the dispatcher exactly, and whether there are others. Both
are answered, and the second answer is larger than the question expected.

**There are seven ISA dispatchers, in ten functions holding all 32 `cpuid` and 2 `xgetbv`
sites.** Finding 5 read one. The other six record AVX, AVX2, F16C, FMA and the AVX-512
feature bits into five different structures -- a bool table at `0x145fac180`, a mask field
in two near-identical CPU-info constructors, a level 0-4 in the FMA module's own
`0x142dfa9d0`, a packed feature word in Havok's `hkHardwareInfo`, and the MSVC CRT's
`__isa_available` -- and **four of them check no OSXSAVE bit and no XCR0 state at all.**
They are safe on a Westmere because the CPUID bits themselves are zero, not because an
OS-state check says so.

Two more are vendor tests and two are informational: a `cmove` clamping a worker count on
`AuthenticAMD`, Havok warning on an unknown vendor, and two brand-string loops feeding a
telemetry field and a display struct.

#### The rewrite left every one of them alone

Compared instruction by instruction over the whole of each of the ten functions -- 1,346
instructions, not a window around each `cpuid`:

```
eight of ten functions          byte-identical
the two informational ones      24 instructions differ, every one VEX
no cpuid, no xgetbv, no AND mask, no CMP immediate, no bt, no setcc, no jcc
the two named consumers         byte-identical, 728 bytes
all 181 EVEX-prefixed instructions  byte-identical
```

So no feature bit is computed rather than read, no branch target moved, and the AVX-512
selection chain is intact end to end: `0x1434d3d50` reads the struct `0x1434ddd40` fills
and is the only place the four EVEX kernels' addresses are loaded.

#### And the dispatchers are more load-bearing than Finding 5 assumed

Two things the audit turned up, both of which raise the stakes rather than settle them:

  * **The rewrite has changed what the AVX-512 path would compute.** Inside the five
    EVEX-bearing functions there are 122 VEX instructions and **84 were lowered**.
    `vpxor %xmm6,%xmm6,%xmm6` at `0x1434d8808` became `pxor %xmm6,%xmm6`, which zeroes
    only bits 127:0 -- and three instructions later `vpxorq %zmm1,%zmm6,%zmm6` reads all
    512. So if that gate were ever satisfied the symptom would be a silently wrong
    checksum, not the `#UD` Finding 5 anticipated.
  * **The gated paths still hold un-lowered VEX.** The AVX2-gated kernels keep 49, the
    AVX512F-gated 7, the AVX512_VNNI-gated 31. Every one would `#UD` here. The
    dispatchers are keeping 179 EVEX *and* 87 surviving VEX unexecuted.

#### The check, and what makes its pass mean anything

`tool/isa_guard.py`, called from `detour.py verify`. **The invariant is narrow enough to be
exact: inside a function that holds a feature test, only a VEX-encoded instruction may
differ.** That is not a guess about the rewriter but what its own guarantee reduces to --
a same-length lowering touches its site and nothing else, a detour writes five bytes over
a site already five bytes long, and a *widened* window is the one shape that reaches past
its site. Reaching past a site inside a feature test is exactly what this refuses.

Six things have to hold, and each closes a way a comparison can be green having compared
nothing: the site count must match the manifest; every site is re-read from the
**original's** bytes; a site in no `RUNTIME_FUNCTION` is a failure rather than a skip;
every instruction's listing encoding must match the original, so being handed a listing of
the *patched* image fails instead of passing trivially; the named consumers must match
recorded digests, so a stale manifest is loud; and **the comparison is run against a
deliberately corrupted copy first and must reject it**.

That last one is the point. It flips one byte of the `jae` at `0x1434ddd88` -- the branch
that keeps 179 instructions unexecuted -- in an in-memory copy, and if the comparison
cannot see that, the check fails rather than passing. Three external controls were fired
too, one at a time: the AVX-512 XCR0 mask `$0xe6` to `$0xe7`, one byte of the `lea` that
loads an AVX-512 kernel's address, and an EVEX prefix `62` to `63`. All three were caught
with the offending bytes printed.

**It says when it does not apply.** The manifest is one image's; on any other binary the
generic invariant still holds and the counts do not, so the image is recognised by its
consumers' digests and the run says plainly which half it is doing. A binary with no
`cpuid` at all reports that there is nothing to guard rather than passing silently.

#### What it cannot say

Consumers hold no `cpuid`, so they cannot be discovered -- the two named are the whole
chain from the AVX-512 bit to the EVEX kernels, and a consumer of the other six
dispatchers would go unchecked. And a future strategy that detours a *span* inside one of
these ten functions will trip this check even if it re-emits everything correctly. That is
a correct stop rather than a false positive: a rewrite window crossing a feature test's
control flow deserves a human look, and the answer is a narrow exemption with its
reasoning written down, not a weaker rule.

### Finding 122 -- LANE_WISE was reasoned; now it is run

`LANE_WISE` is the whole safety argument of Finding 114: an operation on a splat's two
identical halves can be done once per half **only if the operation is the same operation
in each 128-bit lane**, and nothing in an operand list says whether it is. The set was
written from the manual, and its own comment admitted the cost -- two of its entries occur
in this binary, so the other thirty were reasoned and never executed.

`make check-lanes` executes all of them. For each mnemonic it runs

```
op %ymm2,%ymm1,%ymm0                      under qemu
op (src2+0),(src1+0) then (src2+16),(src1+16)   natively
```

and requires them to agree bit for bit over all 32 bytes -- no forgiveness for NaN
payloads, because both sides run the same elementwise operation on the same bits and a
payload that differs is a real difference.

**Every one of the thirty-five is lane-wise under execution.** That includes the three
that were deliberately held out -- `vpsadbw`, `vphsubd` and `vpblendw`, lane-wise by the
manual and occurring 5, 1 and 2 times, which is far too rare for `check-pe` to catch a
misreading. They are in the set now because something ran them.

#### Three controls, because a harness that agrees with itself proves nothing

  * **Is qemu a blind lane-splitter?** Five genuinely cross-lane AVX2 instructions run
    under it against a model computed here from the ISA definition: 45 of 45 match, and
    the lane-split rival answer -- which is well defined and different for
    `vpbroadcastd` and `vpmovzxbw` -- was produced zero times. So a lane-wise verdict is
    qemu's per-instruction implementation and not the shape of its interpreter.
  * **Is qemu's arithmetic real?** Every case also runs its VEX.128 form under qemu
    against the plain SSE form on this Westmere: 445 of 459 bit-identical, and all 14
    differences are the both-operands-NaN defect Finding 119 measured.
  * **Can it tell a right split from a wrong one?** Each mnemonic's 128-bit side is
    rebuilt wrong twice -- halves swapped, and the low half used for both -- and **both
    sabotages must be rejected for every mnemonic in the set.** A mnemonic whose sabotage
    passes was asked with inputs too symmetric to answer, and its verdict would be
    unearned whichever way it came out. None was.

The negative controls fire as well: `vpslld` and `vpsrlq` are reported NOT lane-wise. That
control was itself vacuous at first -- random 64-bit shift counts are all at least 32, so
both halves shifted everything to zero and the wrong split "agreed" by producing zero
twice. A pattern with counts of 3 and 7 in the two halves fixed it.

#### The list is a second witness, and it is made to stay one

`evidence.md` says two documents agreeing are one witness if the same hand wrote both, so
the set is **copied** into the harness rather than imported -- importing it would make the
check agree with the code by construction. But a copy that drifts silently is worse than
no copy, so `detour.LANE_WISE` **is** imported, for one purpose: to demand that every
entry in it appears in the harness. Adding a mnemonic to the rewriter and not executing it
is a failed check rather than a forgotten one, which is how it was tested -- adding
`vphaddw` to a copy of `detour.py` fails the run by name.

#### Twelve more are available and not taken

The harness also settles `vhaddps`, `vhsubps`, `vphaddd`, `vpshufb`, `vpalignr`, the packs
and five others as lane-wise. They are not in `LANE_WISE`, because none of them appears in
a splat triple in this binary and a set is a liability rather than an asset until
something reads it. **The comment above the set was also wrong about why**: it gave
"nothing horizontal is here (`vhaddps` combines neighbours)" as a reason, and horizontal
is a statement about elements while the set's requirement is about lanes. AVX horizontal
operations are defined per 128-bit lane, so they qualify. The exclusion was safe by
conservatism and wrong by its stated reason.

### Finding 123 -- the borrow was volatile-only by luck, and the reload rung costs four

Two changes measured together and separated afterwards, because measuring them together
said the wrong thing about both.

#### Only a volatile register may be borrowed

Win64 makes xmm0-xmm5 volatile and xmm6-xmm15 the callee's to preserve. A borrow saves and
restores, so inside the stub either kind is fine -- and a borrow bracket cannot contain a
call, since `ymm_run` breaks on every control transfer and `swallowed_borrow` brackets one
instruction. **The only way out of a live bracket is a fault**, and there the unwinder
restores xmm6-xmm15 from the primary's `UWOP_SAVE_XMM128` codes, which a primary that
never used the register does not have. The caller's value is in the home space at that
moment and is lost.

`spill_candidates` returned `range(16)`, lowest first, so it reached a nonvolatile register
only when every volatile one was named. Measured over the whole binary by wrapping
`encode_spill`:

```
saves of a volatile register (xmm0-5)      29,712
saves of a nonvolatile register (xmm6-15)       0

  xmm0 16,474   xmm1 10,611   xmm2 1,940   xmm3 640   xmm4 36   xmm5 11
```

**Zero.** So the restriction costs nothing, and the plan run confirms it to the site: with
`VOLATILE_XMM` reverted the candidate count, the residue and every bucket are identical.
What changes is that a property held by accident is now held by construction, and a binary
that needs a nonvolatile borrow gets a named refusal rather than a silent risk.

#### The reload rung is worth minus four

`ymm_run` stopped when a load targeted a register it already tracked. `lifetimes` has been
ready for that since Finding 77 rekeyed it from the register to the position "before the
thing that needs it", and letting the walk carry on is four lines. A scoping pass costed it
at 86 reached.

```
                                                    before   after
ymm value has no known upper half                   10,086  10,132
no register free across the ymm run                    212     268
256-bit: loaded and never stored before arithmetic      59      12
the long pair store would not lower                     20       8
────────────────────────────────────────────────────────────────
not inside any accepted window                       6,979   6,983
```

**It takes work away from a strategy that was succeeding.** `ymm_run` is tried before
`long_pair_stores`, so a run that carries on through a reload swallows loads the long pair
used to claim -- and then fails for want of a second helper, losing the site both ways. 47
sites leave `loaded and never stored` and 56 arrive in `no register free`; the long pair
falls from 20 to 8 and 46 more stores land in `no known upper half`.

Reverted, with the measurement kept in the code beside the condition it explains. **What
would make it pay is deferring to the long pair rather than out-running it**, which is a
change to the order in which strategies are tried and not to this walk.

#### Three estimates, three measurements

The ladder that came out of the scoping pass is now measured end to end, and the pattern
is worth naming rather than repeating:

```
                                       estimated   measured
retry assign_helpers at earlier stores        14         +3
vextractf128 with a tracked source           113        +50
a 256-bit reload of a tracked register        86         -4
carry a lane-safe ALU inside a run           320    +4 (unbuilt)
```

Every estimate counted **positions that qualify**. A site is gained only when the run it
belongs to also reaches a store, gets a distinct helper for every lifetime, passes the
upper-half guard, and does not take the site from a strategy that already had it. The last
of those is new here and is the one that turned a gain into a loss.

### Finding 125 -- a strategy that cannot lower a site was consuming it

Finding 123 measured the reload rung at minus four and named the cause: `ymm_run` is tried
before `long_pair_stores`, so a run that succeeds takes work the long pair was doing. It
proposed changing the order the strategies are tried in.

**The order was not the fault.** The fault was one `continue`.

When every prefix of a run failed, `collect` recorded a reason and moved to the next
instruction. So the site was *declined* -- and the zero store, the long pair, the constant
store and the ordinary path never saw it. The pair did the same one level up: a site with
a `pair_reason` was declined before any of them ran. **Two strategies that could not lower
a site were each entitled to end its chances.**

The reason machinery for exactly this already existed. `held_back` was written in Finding
75 so that a pair's refusal would be recorded only if the run declined too -- "its reason
is held back and only recorded if the run declines too", in the collector's own words. It
was doing that for the reason and not for the site.

Now the reason is carried past every strategy that follows and recorded only where the
site finally lands.

```
                                            before   after
ymm upper half read later                      106      40
ymm value has no known upper half           10,086  10,015
no register free across the ymm run            212     203
ymm run upper half read later                   37      30
the long pair store would not lower             20      28
outside .pdata                                 321     325
────────────────────────────────────────────────────────
not inside any accepted window               6,979   6,838
```

**A hundred and forty-one sites.** Sixty-six of them are the `ymm upper half read later`
bucket, which is the pair saying "I cannot do this" and, until now, also saying "and
nobody else may try". The long pair gains work rather than losing it -- its own refusal
bucket rises from 20 to 28, which is what a strategy being *offered* more sites looks
like.

#### Why it took a hundred findings to see

Every strategy here was added by measuring what it could take, and each was added at the
front of the chain where its own shape is cheapest to recognise. Nobody measured what a
strategy *costs the ones behind it* -- and the cost is invisible from inside the strategy,
because a declined site looks identical whether it was declined by the last strategy or
the first.

The census could not show it either. `skipped` counts a reason per site, so a site
declined early is one line and a site declined late is one line, and the two are
indistinguishable. What made it visible was Finding 123 measuring a change that made
things *worse* and asking where the sites went.

**The generalisation is worth more than the 141.** Four strategies are tried in an order
nothing has ever justified, and this closes only the two exits that were unconditional.
Whether `ymm_run` should be tried before `long_pair_stores` at all is still unmeasured;
what is fixed is that failing no longer forecloses.

### Finding 126 -- `detour-plan` and the binary disagreed, and the binary is right

The reload rung -- letting `ymm_run` carry on when a load targets a register it already
tracks -- has now been measured three times and reverted twice.

```
                                        detour-plan   the built binary
Finding 123, before the fall-through          6,983   not built
Finding 126, after it                         6,787   8,948 VEX, from 8,899
```

Finding 125 stopped a failed strategy declining its site, and re-measuring the same four
lines took them from minus four to **plus fifty-one**. That was a `plan` number. The
rebuilt binary went the other way: **8,899 VEX to 8,948**, with 44 more stubs refused and
404 more skipped for overlap.

**`detour-plan` does not model `place_stubs`.** It runs `collect` and counts what the
collector declined; it does not choose windows, does not commit them, and cannot see one
window swallowing the site of another. A run that carries on through a reload is a longer
run, so it collides with neighbours that would each have been placed -- which is exactly
the lesson `zero_run`'s caller already carries ("one long window collides with
neighbouring candidates that would each have been placed... the overlap count rose by
2,199 and said so"), arriving here from a strategy rather than from a grouping.

So the collector gained 51 sites and the placer lost 100.

#### The instrument was fine and the reading was not

`plan` is not wrong. It answers "what did the collector refuse", exactly and cheaply, and
for a change that does not alter window lengths its answer and the binary's agree to the
site -- Finding 116's 53 and Finding 125's 141 each match `verify` exactly. **What it
cannot answer is "how many sites got rewritten", and that is the question every one of
these findings is really asking.**

`CLAUDE.md` states the rule this violates: *check the artifact, not a fresh measurement of
where it came from.* An eight-minute `plan` against a twenty-minute rebuild is a real
temptation, and it was taken all session.

**Two details are what make this worth writing down rather than filing under carelessness,
and neither is in the rule.**

The first is that **it agreed twice before it disagreed.** A proxy that diverged on first
use would have been discarded on first use; nobody quotes a number they have just watched
be wrong. It is the run of agreement that earns the trust, and the trust is then spent on
the question the proxy does not answer. Fifty-three and a hundred and forty-one, to the
site, and then a hundred out.

The second is that it did not fail by being **imprecise**. `plan` counted 51 sites the
collector stopped refusing, and every one of those 51 is real -- the collector genuinely
refuses 51 fewer. What it cannot see is that accepting them made 100 others unplaceable,
because a longer window swallows the site of a neighbour that would have been placed. The
two quantities move in opposite directions under exactly the change being measured, so no
margin of error would have covered it: a bigger `plan` gain is evidence of a bigger placer
loss, not of a better change.

#### What that costs the record

Two numbers here are `plan`-derived and are marked so rather than quietly kept:

  * **Finding 116's split.** Its headline 53 is a `verify` number and stands. The split
    inside it -- the prefix retry at +3 and `vextractf128` at +50 -- came from two `plan`
    runs and could be apportioned differently in the binary. The total is right; the
    halves are the collector's view of it.
  * **Finding 123's minus four.** Also `plan`, also never built. The reload rung's real
    cost under the old behaviour is unmeasured; what is measured is that it costs 49 under
    the current one.

Neither changes a decision -- the rung is reverted either way -- and both are the kind of
thing that gets quoted later as though it had been weighed.

**From here a rung is costed by `make detour` and `make detour-verify`, and `plan` is what
says which bucket a refusal landed in.** That is what it is good at, and it is not the same
question.

### Finding 127 -- the argument was sound, so it was made checkable

`copy_reaches_home` refuses to lend a function's home space when a copy of `rsp` is stored
to memory: the pointer leaves this function's text, and nothing here can say where it is
dereferenced. Its own docstring already contained the counter-argument and declined it:

> The escape case is refused although no borrow window can contain a call -- the swallowed
> bracket admits nothing between its save and restore, and `ymm_run` breaks on every
> control transfer -- so nothing could dereference an escaped pointer while the borrow is
> live. That argument is sound and is deliberately not leaned on: it is second-order,
> resting on a property asserted in two docstrings rather than enforced by a check, and it
> is worth 113 sites.

It is worth 702 now, and the objection was never to the argument. It was to where the
argument lived. So the property was made a check.

```
VEX in .text      8,899 ->   8,450       796,681 removed, 99.0%
detours         201,145 -> 201,411
refused             741 ->     676
```

**Four hundred and forty-nine sites**, and the first time this has been above 99%.

#### The check found its own author out first

The property was written as "no stub may contain a call" and asserted over the
disassembled stub section. It failed on its first run against the real binary: **384 call
instructions**, every one a swallowed `call` re-emitted at its new address by Finding 86's
path, which is the rewriter working exactly as designed.

The claim had been invented rather than measured. What anything rests on is narrower --
*no call between a borrow's save and its restore* -- and that is now enforced where the
bytes are emitted, in `emit_swallowed` and in `build_stub`'s run branch, both of which
refuse rather than assume. Neither has fired: `ymm_run` breaks on every control transfer
and the swallowed bracket wraps one lowering, so the property held all along. It is
refused now instead of relied upon.

#### And the reconciliation found it out twice

Narrowed to "every call in the stub is one a window swallowed", it failed again: 384
against 294. The ninety were backward-widened windows whose FIRST instruction is a call --
re-emitted like every other instruction the window covers, and deliberately not in
`swallowed`, because the window's first byte keeps its boundary. The jump is written
there.

The set that reconciles is every instruction a placed window covers, and it does, exactly:
384 against 384.

**Two wrong versions of one check, both caught by running it.** That is the whole argument
for putting a property in a check rather than a docstring, and it is not the argument
usually given. A docstring's claim is never tested, so being wrong costs nothing and shows
nothing; a check's claim is tested on every run, so being wrong is loud and immediate. The
first version of this check was wrong about the binary within twenty minutes of being
written. The docstring it replaced had been wrong about nothing for a hundred findings,
because it never said anything falsifiable.

#### What did not change

Where the pointer is stored is a dereference like any other, and the walk still refuses it
if it lands in `[rsp+0..31]`. What is now allowed is only that the pointer goes somewhere
this scan cannot follow. The selftest case that asserted the old answer is inverted with
its reason rewritten, and a new case sits beside it -- a copy stored *through* a pointer
into the region, which must still be refused and is the boundary the relaxation must not
cross.

### Finding 128 -- the two built rungs, priced against the binary at last

Finding 126 left an item open in as many words: Finding 116's headline 53 is a `verify`
number and stands, but **the split inside it -- the prefix retry at +3 and `vextractf128`
at +50 -- came from two `plan` runs and could be apportioned differently in the binary.**
Both are taken against the binary now, by disabling each in a copy of the tool and
rebuilding.

```
                                  plan, when built   the binary, now
retry assign_helpers at an
  earlier store                             +3                   +2
vextractf128 with a tracked source         +50                  +50
```

`8,452 -> 8,450` for the retry and `8,500 -> 8,450` for the extract. The extract's
number was right; the retry's was one high and has since lost another to the regimes
that changed under it -- Finding 125's fall-through and Finding 127's home space both
reach sites the retry used to be the only way to.

**They do not add to 53 and should not be expected to.** Disabling one changes what the
other reaches, and two regime changes have intervened; 52 against 53 is the interaction,
not an error in either. What the exercise settles is that neither number was materially
wrong, which is worth knowing precisely because Finding 126 could not rule it out.

#### The gap in `run_prefixes` that is not one

A truncation must leave nothing loaded and unstored, so a run holding two registers can
only be cut after both are stored. Where the second register's store is what the run
cannot get a helper for, the cut that would have saved the first is never offered --
`load A, load B, store A, store B` has no valid cut but the full one, because cutting
after `store A` strands B's load inside the window.

Measured: **93 sites** where a prefix was suppressed that way and the site was then
declined, 83 of them for `no register free across the ymm run`. That looked like a
population worth a smarter truncation, one that drops the stranded load rather than only
taking prefixes.

**It is closed by a guard that is already there.** Truncating with B stranded is not
unsafe -- B's low half is loaded correctly, its upper half goes to a helper nobody reads,
and B's own store is refused afterwards for having no known upper half, so it stays VEX
and faults rather than computing wrongly. But `held_open` includes B, and B's store
downstream is a 256-bit read of it, so `upper_half_read_later` refuses the prefix before
any of that can happen. Eight of the 93 are already declined with exactly that reason.

So the binding constraint is the upper-half guard and not the stranding rule, and a
smarter truncation would gain nothing it does not already have. Recorded rather than
built.

### Finding 129 -- what a borrow bracket may hold, and who is left who cannot lend

Two things, both about the same 32 bytes.

#### The bracket rule covers every control transfer now, not just a call

Finding 127 refused a borrow bracket that would wrap a `call`, because
`copy_reaches_home` leans on nothing else running between the save and the restore. A
**branch** is the other half and it is worse: control leaving the bracket means the
restore never runs at all, and the borrowed register stays clobbered for the rest of the
program -- not a wrong value in one place but a wrong register everywhere after it.

Neither can happen today. `ymm_run` breaks on every control transfer and `emit_swallowed`
brackets a single lowering, so the refusal has never fired and the artifact is unchanged
by it. That is the point: the property is refused rather than relied upon, and a future
strategy that widens a bracket meets a check instead of a docstring.

#### The second-largest bucket, decomposed

`no home space to borrow` is 1,594 sites outside any accepted window, second only to the
register representation. It is not one problem:

```
a leaf: there is no home space to lend            854
an rsp copy the walk cannot follow                556
a direct [rsp+0..31] operand                      139
both                                               10
outside every .pdata range                         22
a frame register                                   13
                                                -----
                                                1,594
```

**The three need three different things**, and only one of them is cheap:

  * **The 854 leaves have no 32 bytes to lend.** No argument about what runs inside a
    bracket reaches them; a leaf never reserved a callee home space at all. What reaches
    them is a different region or a different mechanism -- static TLS, priced at 740 sites
    with the file-format half proven, or the caller's own shadow at `[entry_rsp+8, +40)`,
    which is usable at 245 sites of which **all 150 outside any window are leaves**, and
    which writes on parameters rather than locals.
  * **The 556 unfollowable copies want per-position taint.** `copy_reaches_home` answers
    for a whole body, and the precise question is narrower: does anything *inside the
    bracket* reach the region. Answering it needs the taint map at each position rather
    than collapsed to a boolean -- a real piece of work, and the largest single thing in
    this bucket.
  * **The 139 direct operands want one comparison per instruction**, and are the cheap
    case: a function that addresses `[rsp+0..31]` somewhere is refused entirely, when
    what matters is whether the instructions the stub emits do. It is not built, and the
    reason is the ratio rather than the difficulty. **139 sites is not enough to buy a
    new silent failure mode** in the machinery that writes into the translated program's
    own frame, at the end of a session that has twice had to withdraw a confident piece
    of reasoning about this same area.

    **Both of these bullets ask the wrong question, and Finding 131 says why.** "One
    comparison per instruction" and "per-position taint" both assume the borrow is
    confined to its bracket. It is not: the region's contents do not survive it.

The measurement is the deliverable. Whoever takes this next knows that the bucket is
854 + 556 + 139 rather than 1,594, that the largest part of it is a taint problem and not
a spill problem, and that the leaves are a different question entirely.

### Finding 130 -- the caller's shadow, which a leaf has and a leaf could not lend

**8,450 -> 7,971 sites, measured on the binary.** 479 removed, 201,686 detours, 587
refused, every `detour-verify` invariant holding.

#### The residue was not what this document said it was

Finding 129 ended by ranking the leaves behind the taint problem. That ranking came from
the refusal buckets, which count sites the collector *declined*; what survives in `.text`
is a different set, and nobody had asked it directly. Counting the survivors by mnemonic
says:

```
  256-bit           4,737
  128-bit           3,533
```

(After this change: 4,729 and 3,062, plus the same 180 undecodable.)

**Three and a half thousand of the survivors were 128-bit** -- 507 `vaddss`, 346
`vmulss`, 306 `vsubss`, 172 `vmaxss`, 171 `vdivss` -- ordinary scalar float arithmetic
whose destination aliases its second source. Crossed against `declined`, 1,916 of them
are `no home space to borrow`, which makes it the **largest named cause anywhere in the
residue**, ahead of `256-bit: arithmetic rather than a copy` at 1,878. The session had
been reasoning as though the register representation were the whole of what was left.

#### What a leaf has that `home_space_map` never offered it

There are two home spaces and `copy_reaches_home`'s docstring has named both since
Finding 96: the 32 bytes a function reserves for **its own callees**, at the bottom of
its frame, and the 32 bytes **its caller reserved for it**, at entry `[rsp+8..40)`, above
the pushed return address. Win64 makes the caller allocate the second whatever the
callee's arity and lets the callee use it for anything.

`home_space_map` lends only the first, so it needs `calls[i]` -- a function that calls
nothing reserves nothing -- and a leaf can lend nothing at all. The shadow is the other
half of that sentence, and it does not care whether the function calls anything.

The analysis is the same walk with a different region: `copy_reaches_home` takes
`region` now, and `CALLER_SHADOW` is what the shadow path passes. That matters more than
it looks. The **MSVC prologue idiom** -- `mov %rsp,%rax` before the pushes, then
`mov %rcx,0x8(%rax)` -- is `REACH_CASES` case 3, where it asserts **False**: Finding 96
rests on that copy not reaching the callee home space. The same rows must assert **True**
against the shadow, because reaching the shadow is the entire reason the compiler writes
that idiom. One walk, two regions, opposite answers, and a region parameter that did
nothing would pass one and fail the other. `shadow_selftest` runs both.

#### The new thing the shadow needs, and the two rules that make it sound

The callee home space is at `(%rsp)` for every instruction in the function, because
`home_space_map` lends only functions whose `rsp` does not move. The shadow is a whole
frame higher, so lending it needs `rsp`'s **value**, not merely a promise that it has not
moved. `rsp_depths` walks the function tracking it, and two rules are what let a linear
walk be trusted in code full of branches:

  * **Every `ret` must be reached at depth zero.** A return unwinds the frame completely,
    so this is the model checking itself against the code; a function whose returns do
    not balance is one whose frame this tool has misread, and it lends nothing. 45 of the
    starved sites are refused by it.
  * **A branch taken at any other depth refuses the function.** A branch carries its
    depth to a target the walk reaches by falling into it, so this is the only thing
    standing between a linear walk and a guess. 77 sites.

An unknown depth is block-local rather than fatal, and that distinction was worth 1,122
sites on its own -- see below.

#### Four rules that were wrong before one was right

Each was measured, and each is the same mistake in a different coat: a rule that looks
like a safety property and is actually a proxy for something else.

  * **"nothing moves `rsp` after the prologue"** refused 184,724 of 260,729 functions.
    That is not a property about frames; it is "the function has an epilogue".
  * **making an unknown depth fatal** refused 1,122 more. MSVC restores a large frame
    with `mov %r11,%rsp`, which no walk can follow -- and which every site in the
    function precedes. The unknown ends at the terminator, since the block after it is
    entered by a branch and every branch source has just been checked.
  * **the refusal cases in the new selftest passed vacuously.** They asserted
    `seen.get(None) is None`, which is true of a refusal and equally true of a walk that
    refused nothing. Taking the `ret` check out and re-running caught it; the cases check
    the refusal *reason* now. This is `evidence.md`'s first rule arriving in the very
    test written to satisfy it.
  * **`plain[first:]` copies the list.** Slicing a 4.5-million-element list per call
    turned a bounded analysis into an O(n^2) one and took `apply` past twenty minutes
    with nothing printed to say why. Walk by index.

#### What is refused, and one thing refused on purpose

Of the 2,153 sites in the bucket, 417 are lendable and the rest divide honestly:

```
  a copy of rsp reaches the shadow                981
  addresses its own caller shadow                 579
  SHADOW LENDABLE                                 417
  a branch leaves at an unmodelled depth           77
  a return does not balance the frame              45
  not inside a known function                      32
  frame register or no unwind codes                22
```

The first two are 1,560 functions that genuinely use their shadow, which is what it is
for: MSVC spills register parameters there. That is not a gap to close.

**Only a function `.pdata` describes may lend**, which costs 3 sites and is not a
tidiness rule. `outside.py` recovers a range on its being bracketed by `int3` and entered
by a call **or a jump**, and a range entered by a jump is not a function entry: `rsp`
there stands wherever the jumping code left it, so "entry + 8" is not the shadow and the
save lands in live locals. `rsp_depths` can model a frameless leaf and is tested doing
so; what it cannot do is tell a leaf from the tail of somebody else's function.

#### The evidence, on hardware

`shadowspill` is `homespill` with one instruction removed -- the `call helper` that
exists for no reason but to make its own callee home space real. `check-spill` runs it
both ways on this Westmere:

```
check-spill: shadowspill --shadow=off returned 29, want 107
check-spill: shadowspill --shadow=on  returned 107, want 107
```

29 is the illegal-instruction death of a surviving VEX site. The **off** half is what
makes the **on** half mean anything, which is why `--shadow=` exists at all -- the same
reason `--rsp=blanket` does: a borrow written at the wrong displacement corrupts a live
local rather than faulting, so comparing two binaries is the only way to test for it.

The stub itself says the rest. `_start` allocates 40 bytes and the site sits inside that
frame, so the shadow is at 8 + 40:

```
	0f 11 54 24 30    movups %xmm2,0x30(%rsp)
	0f 28 d0          movaps %xmm0,%xmm2
	0f 28 c1          movaps %xmm1,%xmm0
	f3 0f 5c c2       subss  %xmm2,%xmm0
	0f 10 54 24 30    movups 0x30(%rsp),%xmm2
```

257 of the 417 sites need the disp32 form of that, against 160 with disp8, because MSVC
frames run to thousands of bytes. A disp8 would have wrapped them into somebody else's
locals without a word, so all sixteen `encode_spill` shapes were assembled with `gas` and
compared byte for byte -- reading the objdump listing by eye would not have done, since
the eight-byte encodings run onto a continuation line.

### Finding 131 -- the region does not survive the borrow, so the question is liveness

Findings 129 and 130 both left the same next step: the whole-body refusals -- a function
that addresses its home space anywhere, or copies `rsp` anywhere -- want a per-position
answer, because the borrow bracket holds one instruction and nothing can reach the region
while it is live. **That reasoning is wrong, and the disassembly of `shadowspill` is the
proof.** The borrow is:

```
	movups %xmm2,0x30(%rsp)     <- the region's contents are gone here
	...the lowering...
	movups 0x30(%rsp),%xmm2     <- xmm2 is restored; the region is NOT
```

The register is saved and restored. **The region is overwritten and never put back**, and
there is nowhere to put it back from: holding both the borrowed value and the region's
old contents at once needs a second register, which is the thing there was none of. So
the whole-body check is not a conservatism that a tighter bracket would relax. It is
load-bearing, and every plan to narrow it to the bracket is a plan to corrupt a local.

**What is actually being asked is liveness, and that is a much better question.** The
region's contents are destroyed from the site onward, so the borrow is safe exactly when
nothing reads them after it -- not when nothing touches them anywhere. Priced against the
577 sites refused by `addresses its own caller shadow`, with a sound cheap rule (every
reference is earlier in address order, and no branch crosses the site backwards, so no
loop can carry one forward):

```
  a branch crosses the site backwards             354
  REGION DEAD FROM THE SITE                       153
  referenced at or after the site                  46
  also copies rsp                                  24
```

**Only 46 of 577 genuinely read the region after the site.** The other 507 are refused by
a question nobody needed to ask. The 354 are refused by the cheap rule rather than by the
program: a backward branch means address order is not reachability, and following the
edges is what would settle them.

#### Built, and not as a walk per site

**7,971 -> 7,557 sites, measured on the binary.** 414 removed, 201,887 detours, and the
first run to pass 99.1%.

The first sketch was a forward walk from each site, in the shape of
`upper_half_read_later`. That is the wrong shape twice over: a `call` does not end a
region's life the way it ends an upper half's -- execution comes back -- so the walk
loses the thing that keeps that one cheap, and it would run once per starved site.

**Backward from the readers is the same answer for much less.** The reference set is
small and fixed while the sites asking about it are many, so `readers_reachable` builds
the function's CFG once, seeds the positions that reference the region, and propagates
along predecessors to a fixpoint. One pass per function, memoised, and a set membership
test per site.

Every edge it cannot resolve is seeded as reaching a reader -- a fall-through off the end
of the range, a branch into the middle of an instruction. **An indirect branch is the one
exception and it had to be**: seeding it as reaching every position is sound and useless,
because a function with a switch table then refuses its whole body, and in this binary
that is most of the large ones. It goes to `targets.py`'s set restricted to the function
instead, which is the same set the whole detour scheme already trusts to say where a
window may not swallow an instruction.

A `lea` stays a whole-function refusal, and the distinction is the point. A direct
operand is a read or a write AT a place, so reachability answers it. A `lea` forms a
POINTER, which can be stored, passed and dereferenced somewhere no walk over this
function's own instructions can see.

#### The fixture pair, and why one of them is not in `check-pe`

`regionlive` keeps a local in its caller's shadow, reads it back, and never touches it
again; `regionread` is the same program with that read moved after the site. Neither uses
an indirect jump to starve the scratch, as `homespill` and `shadowspill` do, and the
reason is this analysis working correctly: the entry point is a branch target, so an
indirect branch inside the function reaches the top of it and every reference with it.
Both make all six volatile registers live across the site instead.

```
check-spill: regionlive --region=whole returned 29
check-spill: regionlive --region=live  returned 121
check-spill: regionread --region=whole returned 29
check-spill: regionread --region=live  returned 29
```

29 is the illegal-instruction death of a surviving VEX site. The first pair is the gain;
the second is the safety, and it is the one that could not go in `check-pe`, whose rule is
that every sample returns its number -- here the correct outcome is that the site is
refused and the program dies. **The assertion still discriminates**: a borrow wrongly
taken would lower the site, remove the VEX, fault nothing, and return 110 plus the bits
of `%xmm2` read as an integer. Refusing is the only route to 29.

#### Three defects found on the way, and two of them were shipped

**The entry-relative sign was inverted.** `copy_reaches_home` computes a landing as
`depth + displacement`; Finding 130's new scan computed `displacement - depth`. Those are
the same number at depth zero -- which is where MSVC's prologue spills its register
parameters, so the common case agreed, every fixture passed, and `check-spill` went green.
Below the frame allocation they diverge, which is exactly where a function writes its
shadow through a settled `rsp`. **The binary built at `d7ba7a3` could therefore lend the
shadow of a function that uses it.** The scan is `region_references` now, extracted so it
can be tested, and `REFERENCE_CASES` puts every case but one at a non-zero depth.

**Two of the three `emit_swallowed` call sites never got the displacement.** Finding 130
threaded `base` through `close_stub`; `build_stub` calls `emit_swallowed` twice more, for
the instructions a backward-widened window carries and for those a forward-widened one
displaces, and both took the default of zero. So a swallowed neighbour saved itself into a
leaf's own frame while the site beside it used the shadow -- visible in one line of the
`regionlive` stub and in nothing else. `slot` and `base` have no defaults now: this is the
second time an optional parameter on `encode_spill` was missed at a call site and
corrupted a local silently, Finding 118 being the first, and a missing argument is a
`TypeError`.

**And `selftest` reported every failure as a wrong lowering.** Each sub-test adds to one
counter and the summary said "N of 18 lowerings are wrong", which sent a reader to
`SELFTEST` for a bad case in `REFERENCE_CASES`. It says how many cases failed now.

#### What the sabotage runs proved

Four ways of getting the reachability wrong, each caught:

```
gives up on any backward branch                   1 failure
indirect branch treated as reaching nothing       1 failure
a range that falls off its end treated as ending  2 failures
address order instead of reachability             3 failures
```

The first is the cheap rule this finding priced with, and two of the nine cases exist to
separate it from the real thing: a loop closing above the reference must refuse and one
closing below it must not. A rule that gave up on backward branches passes the first and
fails the second while looking careful.

### Finding 132 -- what Finding 127 rested on, and what actually holds it up

Finding 131's insight has a third victim, and this one was shipped and load-bearing.

`copy_reaches_home` allows a copy of `rsp` that is **stored to memory**, where the
pointer leaves what any scan of this function can follow. Finding 127 opened that case,
worth 449 sites at the time, on this argument:

> The pointer leaves this function's text, so nothing here can say where it is
> dereferenced -- but it cannot be dereferenced while a borrow is live, because nothing
> else runs. **After the restore the region holds what it held before**, so a later
> dereference sees what it would have seen.

The first half is true and is enforced rather than asserted -- `emit_swallowed` and the
run branch refuse a bracket containing any control transfer. **The sentence in bold is
false.** A restore is `movups region, %xmm`, which reads the region into the register and
writes nothing back; the region keeps the borrowed value for the rest of the program. The
damage outlives the bracket, so an argument about what can run inside the bracket does not
reach it. There is no repair either: putting the region's contents back needs somewhere to
hold them, which is a register, which is the thing there was none of.

**Refusing the case costs 455 sites, measured on the binary** -- 7,557 back up to 8,012,
about half of what Findings 130 and 131 gained. So it was worth finding out whether
anything better than "refuse" is available, rather than paying that on a hunch.

#### What is true is narrower, and it is a check now

Instrumenting a whole collect: **4,950 escape events, and not one of the pointers points
into the region.**

```
  within 256 bytes above it                     2,390
  more than 256 bytes above it                  2,016
  within 64 bytes above it                        513
  below the region                                 31
  points INTO the region                            0
  distance above the region's base: min -1320, median 224, max 3848
```

That is a measurement of one binary, so it is the check now instead: an escape is allowed
only while the pointer does not point into the region, and refused when it does. It costs
nothing today, and it stops the case that would matter without waiting for a binary where
one occurs. This is Finding 127's own move -- *the argument was sound, so it was made
checkable* -- applied to the narrower argument that survives.

**What it does not cover is named rather than hidden: a consumer that adds a displacement
to the escaped pointer.** The two ways a pointer INTO the region is formed are already
refused, and between them they cover the idiom that would otherwise be alarming:

  * a `lea` into the region refuses the whole function, which is what covers **varargs** --
    `va_start` on Win64 points `va_list` at exactly this memory, the register spill area,
    and reads through it;
  * arithmetic walking a copy into the region is refused by the walk itself.

What remains is a pointer stored to memory, reloaded, and dereferenced with an offset that
happens to land in the region, in a function that keeps a local there and never once
addresses it directly. `--escape=refuse` declines the whole case for whoever wants it, and
the 455 sites are the price on the table.

#### The shape, for the next person

Three findings in a row turned on the same sentence being wrong: **a borrow does not
restore the memory it borrowed.** Findings 129 and 130 wrote plans that assumed it; this
one was resting on it in shipped code. The tell each time was an argument about a
*window of time* -- "nothing runs between the save and the restore" -- answering a
question about a *span of memory*. When a rule's justification talks about when something
happens, check that the thing it protects is not permanent.

### Finding 133 -- the 256-bit residue wants a home space, not a register and not TLS

The largest item left has been "the register representation" for several sessions, filed
as a different kind of work and deferred each time. It turns on one question -- **where
does an upper half live** -- and that question is a measurement, not a preference.

#### How many upper halves are live at once

Win64 makes every ymm upper half volatile, so a lifetime never crosses a call and
`upper_half_read_later` already returns "dead" at one. That bounds the question to the
call-free region a site sits in. Taking an upper half as live from the first 256-bit
instruction writing the register to the last one reading it, at the 4,318 surviving
256-bit sites that fall inside a modelled region:

```
   1 live    1,426   33.0% cumulative
   2 live      629   47.6%
   3 live      255   53.5%
   4 live      114   56.1%
   5 live       91   58.2%
  ...
  11 live      443   85.0%
  16 live      123  100.0%
```

**A third need one, half need two or fewer** -- and a long tail needs ten or more, with
123 sites needing all sixteen. Any answer that only handles one or two leaves that tail,
and any answer that must handle sixteen is doing register allocation on a machine with
none to spare. The span model over-counts, since a register written twice has its span
stretched between the two, which is the direction that does not flatter a small answer.

#### Registers reach an eighth of it

Of the spans mentioning exactly one ymm anywhere, 682 hold a surviving site. Asking the
cheap conservative question -- how many xmm registers does the enclosing FUNCTION never
mention, so that nothing needs saving and nothing reads them after:

```
      481  a volatile xmm the function never mentions
      170  only a NONVOLATILE xmm is untouched
       31  the function mentions all sixteen
```

So a helper register reaches something like 500 to 650 sites of 4,451. `free_across`
would find more, since a register merely dead across the span will also do. It is not
nothing and it is not the answer.

#### TLS was rejected for this, correctly, and that is not the only memory

Finding 69 priced per-thread memory and rejected it for the 256-bit half in one sentence:
reaching a TLS slot costs a general-purpose register, at every site, in code that is
register-starved by definition. That still holds.

**A home space costs no register at all.** It is addressed `N(%rsp)`, and Findings 130 to
132 made both of them -- the 32 bytes a function reserves for its callees and the 32 its
caller reserved for it -- available and decided per site rather than per function.

**And the lifetimes coincide exactly**, which is what makes this more than an
availability coincidence. A ymm upper half is volatile across a call by the ABI. So is a
home space: the callee home space IS the callee's shadow, by definition, and a call
destroys what is in it. The span over which a home space can hold a value is precisely
the span over which an upper half needs to live. Nothing has to be spilled at a call
because nothing survives one on either side.

Asked of every surviving 256-bit site:

```
    1,981   44.5%  neither region will lend
    1,175   26.4%  the callee home space: two slots
    1,138   25.6%  BOTH: four 16-byte slots
      157    3.5%  the caller's shadow: two slots
```

#### Crossed, because two marginals multiplied are a derivation

```
    1,674   37.6%  the slots hold every live upper half
```

That is the prize, and it is larger than every increment this project has taken. What
falls short falls short in two different ways, and they want different answers: **331
sites need one upper half and have no slots at all** -- a function that will lend nothing,
which is the home-space problem of Findings 131 and 132 over again -- while **443 need
eleven**, which no arrangement of 32-byte regions will ever hold.

#### Corrected the same day: 1,674 was capacity, and capacity does not bind

`make spans` is the instrument, `ymm_span` is the analysis behind it, and the number it
returns is **212**, not 1,674.

The two are not measuring the same thing and the earlier one was not wrong -- it was the
wrong bound. **1,674 sites have room for the upper halves live at them.** Room is
necessary and it is nowhere near sufficient, because an upper half exists only in a
machine ymm register that no SSE instruction can reach: it can live in a slot only if
every instruction that produces or consumes it was rewritten too. So the unit is a
**closed span** -- one that begins at a definition this tool can materialise and ends
with every value it tracks dead -- and closure is what binds:

```
surviving 256-bit sites             4,500
covered by a closed span that fits    212

    3,276  does not begin with a 256-bit load
      101  ymm0 is still live after a branch target inside the span
       92  ymm0 is still live after a control transfer
       81  ymm1 is still live after a 256-bit form that is not lane-wise
       57  ymm1 is still live after the value is touched by something narrower
       53  nothing consumes the value
```

(The survey counts 4,500 by decoding every `c4`/`c5` as VEX where the by-mnemonic count
is 4,451; the two admit different bytes and the 180 `(bad)` islands are where they can
differ.)

Of the spans that do close, the slot fit is a second filter and a milder one -- 81 of
about 163 fit, and the common shortfall is wanting three slots with two available.

**So the design Finding 133 named would buy about 212 sites**, against 479 for the
caller's shadow and 414 for region liveness, at several times the complexity and in the
part of the machinery that writes into the translated program's frame. That is not a
trade worth making, and knowing it cost a measurement rather than a build.

#### What would move it, in order of what it is worth

  * **More lane-wise mnemonics.** "a 256-bit form that is not lane-wise" is the largest
    closure refusal once the loads are set aside -- 81 + 45 + 45 and a tail. `LANE_WISE`
    holds 35 and `lane_oracle.py` proves each of them under execution, so extending it is
    bounded work with a proof attached rather than an argument.
  * **Spans that need not close.** 92 sites lose their value at a control transfer and
    101 at a branch target inside the span. Both would be answered by rewriting a whole
    function's 256-bit work at once rather than a straight-line span, which is a much
    larger design and the only one that reaches the 443 sites needing eleven slots.
  * **Definitions other than a load** -- a zeroing idiom, a broadcast, a constant. 53
    spans found nothing to consume the value, and 3,276 sites are not a load at all.

#### What the measurement leaves open

The lowering itself. Each 256-bit instruction becomes a pair of 128-bit ones, and
`lane_oracle.py` already proves 35 mnemonics split lane-wise under execution -- that is
the semantic foundation and it exists. What does not exist is the strategy that assigns
slots across a span, spills nothing, and refuses cleanly when the span grows past its
capacity. `assign_helpers`, `lifetimes` and `free_across` are the shape of it for
registers; the same shape over slots is the work.

Nor does it settle the 1,981 sites in functions that lend nothing, and the honest reading
of that number is that the home-space analysis is now load-bearing for the 256-bit half
as well as the 128-bit one. Every site Findings 131 and 132 add to what a function will
lend is worth more than one site now.

### Finding 134 -- the other whole-body answer, asked at a place instead

**7,557 -> 7,294 sites.** 263 removed, 202,069 detours, `no home space to borrow` down
from 1,620 to 1,391.

Finding 131 made a direct reference to a home space a question about the site rather than
about the function. It left the larger half of the same refusal untouched:
`copy_reaches_home` walks a copy of `rsp` and returns a verdict about the whole function,
and that verdict was the biggest single reason a function would lend nothing.

Instrumenting a whole collect, the refusals inside it divide:

```
    1,708  a dereference lands in the region
    1,158  arithmetic that cannot be followed
      550  an indexed access through the copy
```

**Two of the six refusals are positional and four are not**, and the split is the whole
of what makes this safe:

  * a **dereference** through a tracked copy that lands in the region, and an **indexed
    access** through one, each happen AT a place. If the site cannot reach that place,
    the borrow does not disturb it -- the same argument, and the same
    `readers_reachable`, that Finding 131 applied to a direct operand;
  * a copy **pushed**, or **escaping into the region**, leaves this text entirely; one
    taken at an **unknown depth** was never located; and **arithmetic that cannot be
    followed** poisons every later dereference through that register rather than one.
    None of those four is about a place, and all four stay verdicts about the function.

So `copy_reaches_home` takes a `hazards` list now. Given one, the two positional refusals
record an address and the walk carries on; without one it behaves exactly as before, which
is what `--region=whole` still selects.

#### The invariant that holds it, and it needed no classifying

The risk in turning a refusal into a position is that a refusal goes missing. That is
checkable without deciding which branch each case trips: **every case that refuses must
either still refuse, or name at least one place; and no case that was allowed may start
naming one.** Both halves run over all 18 of `REACH_CASES`.

Sabotaged by dropping the recorded address, six of the eighteen go red.

#### Two rows, one set

A reader is a reader. `home_readers` unions the direct operands and the copy hazards into
one list and hands it to `region_readers`, so the two kinds are answered by one
reachability pass rather than by two rules that could disagree. `copy_reaches_home` takes
rows carrying their addresses to make that possible, and the two selftests that name no
addresses lay theirs out four bytes apart in `_addressed`.

### Finding 135 -- the walk followed the pointer's arithmetic and not its moves

**A hole, found by reading the code to plan the next increment rather than by any
check.** `copy_reaches_home` has tracked a copy of `rsp` since Finding 96, and it followed
what was done TO the pointer -- immediate arithmetic, a `lea`, a narrow write that
destroys it -- but never followed the pointer itself into another register.

```
	mov  %rsp,%rax
	mov  %rax,%rbx        <- %rbx is untracked from here
	mov  %rcx,-0x28(%rbx) <- a write into the region, and invisible
```

Measured on that shape and three others: **three of four reached the region and were
allowed.** `add %rax,%rbx` is worse than the plain move, because it makes `%rbx` a stack
pointer at an offset nothing can name, and it was allowed too.

The rule now: a plain 64-bit `mov` carries the offset exactly and is followed; anything
else that reads a tainted register and writes a **different** one is refused, which is the
same answer the walk already gives to arithmetic it cannot follow. A narrow destination is
neither -- a 32-bit write zeroes the upper half, so what lands there cannot address a
stack at all, which is the existing kill rule read from the other side.

#### It was wide, and in this binary it was nearly free

```
7,294 -> 7,304 sites          the cost, measured on the binary
3,301 times the branch fires  3,217 following a move, 84 refusing
                              (37 cmove, 12 add, 10 cmovbe, 10 movslq, 5 sub,
                               4 cmovae, 2 imul, 2 cmovne, 2 vmovd)
```

**Ten sites.** That is the whole price, and the two numbers together are the finding: the
walk was losing a pointer **3,217 times**, and in this binary almost none of those
pointers went on to touch the region. Finding 96's original measurement -- that no copy in
the binary reaches the callee home space -- survives, and it now survives for a better
reason than that nobody was looking.

**Counting the firings was not optional.** A fix costing ten sites is indistinguishable
from a fix that reaches nothing, and the ten alone would have read as either. The count
is what says which.

Six cases are permanent, and two of them exist so that the fix is not merely "refuse
anything that moves": a second-hand copy dereferenced clear of the region is still
allowed, and so is a 32-bit move.

### Finding 136 -- a pointer whose offset is lost is still a pointer

**7,304 -> 7,224 sites**, and `no home space to borrow` from 1,391 to 1,332.

`copy_reaches_home` refused the whole function whenever it lost a pointer's offset --
arithmetic it could not follow, and, after Finding 135, a conditional move or anything
else that carried a tracked register into a different one. That was the largest refusal
left inside it. But losing the OFFSET is not losing the POINTER: what is known is still
that the value is stack-derived, and what is unknown is only where it points.

So a lost pointer becomes **unlocated** rather than fatal. Any dereference through it is
refused, wherever it points -- which is the same answer as landing inside, since nothing
can be said either way -- and anything that overwrites it ends the matter entirely.

#### The measurement that said it was worth doing, and the one that was wrong

The gain is exactly the pointers nothing dereferences before they die. Probing that
during a real collect:

```
    1,906  dereferenced after the arithmetic
      374  overwritten before any dereference
       10  never dereferenced again
```

**The first version of that probe scanned the whole function** and reported 2,268 of
2,290 dereferenced, which is a number it could hardly have failed to produce: `%rax` is
dereferenced somewhere in almost any function, and the question was only ever about the
suffix. Reading it as a verdict would have closed the case. The corrected probe scans
forward from the arithmetic and stops at an overwrite, and it moved 384 events from
"hopeless" to "free".

The other 1,906 are not lost either: a dereference through an unlocated pointer is a
hazard **at a place**, so Finding 134's reachability answers it exactly as it answers a
located one.

#### What still refuses, and why each has to

An unlocated pointer **pushed** or **stored to memory** refuses the function outright.
Both leave this text, and the escape check Finding 132 added compares the pointer's value
against the region -- which needs a value. There is none, so there is nothing to check
and refusing is the only answer.

Six cases are permanent and three of them must refuse, which is what the sabotage runs
confirm: removing the dereference check turns eight red, the push check two, the escape
check two.

### Finding 137 -- the 128-bit half, measured to its floor rather than abandoned

Four increments took `no home space to borrow` from 2,153 to 1,332, and each returned
less than the last -- 479, 414, 263, 80. **Diminishing returns are not a reason to stop;
they are a reason to find out whether anything is left.** Three measurements say what is,
and the answer for this seam is almost nothing.

#### What still refuses, and it is mostly the program

```
1,332 sites declined `no home space to borrow`

  624  callee: no call, so the region does not exist  |  shadow: still read from here
  408  callee: still read from here                  |  shadow: still read from here
  122  callee: still read from here                  |  shadow: refused whole
   77  callee: no call, so the region does not exist  |  shadow: refused whole
   66  callee: an rsp copy reaches it, unpositionally |  shadow: refused whole
   35  callee: not in .pdata                          |  shadow: refused whole
```

**1,032 of them are refused because a reader is reachable**, which is the analysis
working rather than failing. `readers_reachable` seeds every edge it cannot resolve as
reaching a reader, so that verdict could still have been conservatism -- an indirect
branch it declined to model rather than a real reference. Splitting it by whether any
reference lies at a HIGHER address than the site, which is reachable by falling forward
and cannot be an artefact:

```
  928  a reference at a higher address: a genuine forward read
  104  references only behind it: a loop or an unresolved edge
```

**Nine in ten are the program genuinely using its own home space**, and no sharper
analysis reaches them. The 104 are what a more precise CFG would be worth, and 300 more
are structural -- a leaf with no callee region and a shadow it uses, a copy that reaches
unpositionally, a function outside `.pdata`. What is left needs memory of the
rewriter's own, which is static TLS at 740 sites and priced since Finding 69.

#### `outside .pdata` is near its ceiling too

325 sites are declined for sitting in code `.pdata` does not describe, and `outside.py`
already recovers almost all of what can be recovered:

```
chunks outside .pdata                  89,747
  of which contain a VEX site           3,006
  VEX sites in them                    17,604

  called, and ends in a transfer       2,979 chunks   17,237 sites   accepted
  contains (bad) -- not code              20             315         refused
  called, but runs off the end             4              35         refused
  uncalled, ends in a transfer             3              17         refused
```

**17,237 of 17,604 are already taken.** The ceiling for relaxing it is 52 sites in the
two small classes, and 315 in chunks containing bytes objdump cannot decode -- which are
Finding 8's undecodable islands, the least safe thing in the binary to start calling
code. Not worth a session.

#### The frontier is where it was, and that is a decision

`0x1428D1492` is still `vmovdqu %ymm0,0x28(%rsp)` in the rewritten binary. The
`vzeroupper` six bytes after it did lower, to a `nop`, so the surrounding work landed --
the site itself is refused because `zeroed_ymm` will not cross a `.pdata` chained-fragment
start in `blocked`, which Finding 112 priced at 11 sites and declined.

**None of today's 1,226 sites could have moved it**, because all of them are in the
128-bit half and the frontier is a 256-bit store. That is the copyright holder's ranking
working as intended -- sites removed, not the fault address -- and it is worth stating
plainly rather than leaving a reader to wonder why six increments moved nothing visible.

### Finding 138 -- the TLS claim was prose, and is a check now

`project.md` has said since Finding 69 that static TLS is feasible, that raising the TLS
directory's `SizeOfZeroFill` gives the rewriter per-thread bytes of its own, and that it
is **"proven under wine"**. The tree held nothing that proved it. A measurement recorded
only in prose cannot be taken again, and the next session to build on it would have had
to re-derive the whole thing before writing a line.

`make check-tls` is that proof, and `pe_build.py` grows a TLS directory to carry it. The
structures live in `.text` like every other sample's data, because that is the only
section whose offsets `assemble` reports back, and the directory's fields are absolute
VAs -- workable here only because these images have no ASLR and load at `IMAGE_BASE`.

```
StartAddressOfRawData 0x140001070      SizeOfZeroFill  32
EndAddressOfRawData   0x140001080      Characteristics 0x100000
AddressOfIndex        0x140001080
AddressOfCallBacks    0x140001088
```

`tlsslot` reads `%gs:0x58`, indexes it by the index the loader wrote, and checks four
things in order, returning a different number for each: the array exists, a block exists
for this module, the raw template was copied, and the bytes past it are zeroed, writable
and hold what was written.

#### The sweep is what makes it a measurement rather than a demonstration

```
SizeOfZeroFill=0  returned 14     the area past the template is not zeroed
SizeOfZeroFill=8  returned 15     the block is not as big as we asked
SizeOfZeroFill=16 returned 15
SizeOfZeroFill=32 returned 66
```

**The first version probed only the first four bytes of the area, and a `SizeOfZeroFill`
of 8 passed exactly as readily as one of 32.** It would have confirmed that some bytes
arrived and said nothing about how many, which is the entire question. Reading and writing
at offset 44 as well -- the last four bytes of the 32 -- makes the answer depend on the
field's value, and the sweep then reports three distinct failures before the pass.

So the mechanism's file-format half is now established here rather than remembered: the
loader honours the field, gives each thread exactly what is asked, and zeroes it.

#### What is still not built, and what it needs

Addressing a slot costs a general-purpose register and three instructions, which is
Finding 69's objection and stands: `mov %gs:0x58,%rN`, an index, a load. What this does
not settle is how many of the 1,332 sites still declined `no home space to borrow` have
an `r8`-`r11` free across the bracket -- Finding 69 measured 740 of a differently-sized
bucket, and that number wants re-taking against the current one.

**Its failure mode is the only one in this area that is not silent corruption.** The bytes
belong to nobody but the rewriter, so a slot used wrongly loses the rewriter's own value
rather than a local of the program's -- which is why this is the mechanism to build next
and not another refinement of the home space, whose floor Finding 137 measured.

### Finding 139 -- static TLS is worth 67 sites, not 740, and the fixture said so

Written because it reverses this document's own recommendation. Finding 138 left static
TLS as the top of the build-next list on Finding 69's price of 740 sites. **It is 67.**

#### The addressing is the two-register form, and `check-tls`'s own program proves it

Finding 69 said "one general-purpose register and three instructions" and priced 740
against a `no home space to borrow` bucket of 1,876, with 226 for a two-register form. The
working fixture written for Finding 138 is the two-register form, and it has to be:

```
	movq	%gs:0x58, %rax		/* ThreadLocalStoragePointer */
	movl	tls_index(%rip), %edx	/* the index the loader wrote */
	movq	(%rax,%rdx,8), %rax	/* this module's block */
```

The block is `*(*(gs:[0x58]) + index*8)` -- **two dereferences**, and the index is in
memory rather than in the instruction, because the loader assigns it. Neither order
saves a register: hold the array pointer and the index has nowhere to go; hold the index
and the array pointer has nowhere to go. A segment-prefixed `%gs:0x58(,%r,8)` does not
help, since `0x58` holds a pointer that must be followed before it is indexed.

#### Re-priced against the bucket that exists

`function_scope`'s whole-function argument applied to `r8`-`r11` -- if a function never
names one, nothing in it reads that register, no callee is passed it and no caller expects
it back, all four being volatile:

```
1,332 sites declined `no home space to borrow`
    500  the range has a way out, so nothing is provably free
    398  0 of r8-r11 never mentioned
    335  1 of r8-r11 never mentioned
     46  2
     32  not inside a known function
     12  3
      9  4

    402  have at least ONE   -- the form Finding 69 priced at 740
     67  have at least TWO   -- the form the addressing actually needs
```

**Both halves of the old number moved, and they moved for opposite reasons.** The
denominator aged honestly: the bucket shrank from 1,876 to 1,332 because Findings 130 to
136 took sites out of it, so that half was right when written and was overtaken by the
project working. **The numerator was wrong from the start.** One register never could
encode `*(*(gs:[0x58]) + index*8)`, at any moment in this project's life; that half was
not overtaken by anything.

The first draft of this paragraph said "740 was never wrong for what it measured", which
is true of one half and false of the other, and the distinction is the useful part.
**Re-checking a count while trusting its base is how a figure comes to look measured
without being so** -- and here the base was the half that had never been checked at all.

#### The answer was in this tree for two days, in a program that ran

**The fixture had been demonstrating the two-register form since Finding 138 and nobody
read it as evidence about the mechanism.** It was written to answer one question -- does
the loader honour `SizeOfZeroFill` -- and it necessarily answered a second, because to
ask the first it had to reach a slot. The second answer was the more valuable of the two
and went unread for two days while the price it refutes sat at the top of the build-next
list.

Nothing about that was subtle. `make check-tls` prints its result, the program is
seventeen instructions, and the two registers are on adjacent lines. What was missing was
the question: a fixture gets read for its verdict, and the code that produces the verdict
is treated as scaffolding rather than as a measurement of whatever it had to do to get
there.

**What a test does in passing is data this project already owns**, and it is the cheapest
data here, because somebody has already made it run.

#### 67 is a floor, and the way to raise it is already built

The 500 refused for "a way out" are `function_scope`'s blunt rule, which disqualifies a
range for any jump leaving it and loses real tail calls deliberately. **A borrow bracket
contains no control transfer at all** -- that is enforced, not assumed -- so a register
merely dead across the bracket would serve, and the machinery for asking that question per
position rather than per function is what Findings 131 and 134 built for the home spaces.
Nobody has pointed it at general-purpose registers.

So the honest statement is: 67 by the cheap argument, unknown by the expensive one, and
the expensive one is a day's work on machinery that already exists.

#### The file-format half is confirmed against the binary, not remembered

```
TLS data directory    rva 0x4f07480, 40 bytes
  raw data size         12,896 bytes
  AddressOfIndex        0x145e123e0
  AddressOfCallBacks    0x143a86ea0   (the game has callbacks; raising the
                                       field does not disturb them)
  SizeOfZeroFill        0
  alignment             16 bytes
  a new slot would sit at block offset 12,896
```

Every figure Finding 69 recorded holds. What changed is only what it costs to reach one.

### Finding 140 -- the span survey named its own biggest bucket wrong, and item 1 is worth nothing

Written because it closes the top of this document's build-next list at zero. Item 1 was
**extend `LANE_WISE`**, ranked "first by default rather than by size -- the only item left
that is both small and safe", on the figure that 171 of the span survey's closure failures
were a 256-bit form that does not split lane-wise. Both halves of that were wrong: the
count and what it counted.

#### The survey could say that a span stopped and not what stopped it

`ymm_span` recorded a reason and `spans` printed the eight commonest, and those reasons
carry the register name -- so `a 256-bit form that is not lane-wise` was never one bucket
but one per register, and only the largest few ever appeared. The 171 is the sum of what
fitted on the page. **Counted properly it is 325**, and the refusal list it came from is
4,335 stops across 78 distinct reasons, of which the printed eight are 3,747.

That was a reporting gap, and closing it was three lines: `ymm_span` records the mnemonic
that stopped it and `spans` prints that histogram beside the reasons. What came back is
not a longer version of the same answer.

```
      125  vmovups reg,mem     13  vfmadd213ps      3  vpermpd
       45  vshufps              8  vcvtdq2ps        3  vfmadd213pd
       40  vextractf128         7  vinsertf128      2  vpslld
       30  vbroadcastss         6  vpcmpeqb       ...  325 in 27 forms
       19  vmovups reg,reg      4  vpbroadcastd
```

**Both totals here are printed by the tool now**, and that is the durable half of the
change. A histogram that shows its head must say what the head is a head OF, or the next
reader sums the rows and quotes it -- which is how 171 got into this document and, two
paragraphs into the first draft of this finding, how 319 nearly replaced it.

**The largest entry is a move.** The branch that reports "not lane-wise" is the walk's
catch-all -- everything 256-bit that no earlier branch claimed lands there -- and
`wide_move` claims a move only when one operand is memory, because that is all `ymm_run`
ever needed. So a register-to-register copy, a broadcast and a store of an untracked value
all fell past it and were reported as a lane-structure problem, in instructions that have
no lane structure at all.

Split by operand shape, the bucket is three unrelated populations:

```
  125  vmovups reg,mem                a store of a value the span never defined
   58  reg,reg moves and broadcasts   representable, and unbuilt
   55  lane-wise arithmetic the set did not name
   87  everything else -- FMA, conversions, extracts, the genuinely cross-lane
```

The 125 were never work. The upper half of a value the span never defined sits in a
machine ymm nothing in the rewritten program can read, so refusing is correct and always
was -- but under a label about lane structure they read as sites that extending a set of
mnemonics would reach. **38% of the bucket that ranked item 1 first is a correct
refusal.**

#### All three increments were built, and all three bought nothing

Each was measured on its own against `make detour` and the rebuilt binary, never against
`detour-plan`, per Finding 126.

```
                                            surviving   covered   stops
baseline, HEAD                                  4,494       218     325
+ 9 mnemonics in LANE_WISE                      4,494       218      --
+ copies, broadcasts, and the store reason       4,494       218     248
```

The mechanisms work and the evidence is that the histogram moves: `vshufps`, `vpcmpeqb`,
`vpsubusw`, `vaddsubps` and `vpcmpeqw` leave it after the first change, the broadcasts
leave it entirely after the second, and `vmovups reg,reg` falls from 19 to 16 -- the
sixteen being copies of a source no span defined. **77 stops removed, 325 to 248, four
whole forms gone, and not one additional site covered.**

**77 and not 113, which is the arithmetic worth keeping.** Adding up what each change
removes says 113; the measured net is 77, because a span that stops later is a span that
walked further and can stop at something new. `vpmovmskb` and `vfmadd231ps` appear in the
histogram only AFTER the first change, at 7 and 4 -- they were always there and nothing
had ever reached them. The same shape as Finding 123's reload rung, arrived at from the
other side: there a gain became a loss downstream, here a removal is partly refilled from
further along the same walk.

The slot-demand table is byte-identical across all three runs -- every one of its eleven
rows -- which is the corroboration rather than a coincidence: a span that closed never met
one of these forms at all, and a span that stopped at one now walks further and stops at
the next. Finding 123 said a site is gained only when everything downstream of it also
holds. Here that is the whole of the result rather than a caveat on it.

**So the binary did not change either.** The rewriter's own tallies are the same to the
site -- 547,716 in-place patches, 202,115 detours, 549 refused, every refusal bucket
unmoved -- because `LANE_WISE`'s other reader, `splat_operation`, found no triple using a
new mnemonic.

#### What actually bounds the span, from the same survey

```
  3,273  does not begin with a 256-bit load
    101  the value is still live after a branch target inside the span
     92  ... after a control transfer
     53  nothing consumes the value
```

and among spans that DO close, the slot table refuses 54 more on room rather than on
shape -- 41 wanting one slot with none, 22 wanting three with two. **Recognising more
forms is not what the 218 is short of**, and no further work on the walk's vocabulary
reaches it. That is the finding: not that these three changes were too small, but that the
quantity they move is not the quantity that binds.

#### Kept anyway, and why

None of it is reverted. The survey now names what stops a span, which is what made this
measurable at all and what the next attempt on the 256-bit half will read first; the
refusals are reported under honest names, so the 125 stop looking like work; and
`LANE_WISE` gained nine mnemonics that are correct, executed and free. **What is retired
is the claim on the list, not the code.**

`make check-lanes` settles the nine the way it settles the other thirty-five -- the
256-bit form under qemu against two 128-bit halves natively, bit for bit, with both
sabotages of each split rejected. Finding 122 had already settled twelve more and
deliberately taken none, because `splat_operation` was then the set's only reader and none
of the twelve appears in a splat triple. That reasoning was right when written and expired
when `ymm_span` was built six days later without anyone noticing the set had gained a
second reader.

**And the comment above the set had been wrong since Finding 122 said so.** It gave
"nothing horizontal is here (`vhaddps` combines neighbours)" as the exclusion rule, three
lines above `vphsubd`, which is horizontal and in the set -- AVX defines the horizontal
forms per 128-bit lane, so the test is lanes and never was elements. Finding 122 recorded
that the reason was wrong and did not go back and fix it. A reason that does not hold is
worse than no reason, because the next person to extend the set applies it.

#### The one shape whose test could not fail

The store-of-an-untracked-value change moves a refusal from one bucket to another and
changes no verdict, so a selftest case asserting the refusal passes against the code it
was written to exercise. `SPAN_CASES` now takes a string expectation that checks the
REASON, and the case is real. All four new cases were run against a copy of the tool with
the change taken back out, and all four go red naming exactly what they lost -- Finding
111's rule, which is why it is here.

### Finding 141 -- the registers were dead all along, and static TLS is worth 753

**67 -> 753 sites.** Finding 139 priced static TLS by asking `function_scope`'s question
about general-purpose registers -- does this function ever NAME `r8` -- and said in the
same paragraph that the argument is blunt and that the machinery to do better already
existed. It does, and this is it pointed at GPRs.

```
sites declined `no home space to borrow`     1,332
  not inside a known function                    0

volatile GPRs dead across the bracket      per position   whole function
  none                                              394              905
  one                                               185              370
  two                                               152               13
  three                                             140               15
  four                                              241                5
  five or more                                      220               24

  at least ONE                                      938              402
  at least TWO                                      753               57
```

`make gprs` is the measurement. The right-hand column is the same question asked of the
whole function, in `gpr_function_scope`, kept precisely so the two can be printed side by
side rather than compared across sessions.

**Two registers at once is the number that matters**, because the addressing needs two
(Finding 139) and one is worth nothing to it. It goes from 57 to 753.

#### Why a call kills nothing, which is the decision worth arguing about

The ABI makes all seven volatile, so the obvious rule is that a call clobbers every one
and kills its liveness. **This binary refutes that twice over, and the second way would
have corrupted a frame.**

`__chkstk` at `0x14365d930` opens by saving `r10` and `r11` to the stack and closes by
restoring them: it preserves the two registers the ABI most clearly permits it to destroy.
And its callers rely on that class of behaviour, because the frame-allocation sequence
MSVC emits is

```
	mov  $0x99e0,%eax
	call 0x14365d930
	sub  %rax,%rsp
```

where `rax` is live ACROSS the call. A rule that killed the volatiles would have called
`rax` dead at the `mov` and let a borrow take the frame size, and nothing downstream would
have looked wrong.

**What the ABI permits a callee to do is not what this program relies on it not doing**,
and only the second is safe to assume. So a call READS the four argument registers --
nothing here knows a callee's arity -- and writes nothing. `r10` and `r11` are dead across
a call anyway, not because it clobbers them but because it never reads them.

#### What the per-position question actually buys

`function_scope`'s rule disqualifies a range for any jump leaving it, which loses every
real tail call, and it disqualifies it for a mention anywhere, which loses a register the
program writes before reading. Both are the same conservatism: a verdict about a function
standing in for a question about a place. A borrow bracket holds one instruction and
contains no control transfer at all, so the question that fits it is whether the register
is dead AT THE SITE.

The kill is what most of the gain rests on, and it is one rule: `mov`, `movabs` or `lea`
whose last operand is a bare 32- or 64-bit register writes that register and does not read
it. Deliberately three mnemonics -- `add %rax,%r11` writes `r11` and reads it too, and the
cost of getting that wrong is a borrow over a live value.

#### One site, checked by hand, because 57 to 753 is not a number to take on trust

`make gprs` prints eight sites and the function they sit in, so this is repeatable.
`0x1402ad714`, a `vandnps` inside a vectorised loop in `0x1402ad560-0x1402b04c1` -- a
function containing 20 calls and 239 mentions of `r8`-`r11`, none of them reachable from
the site:

```
	1402ad714:	vandnps %xmm1,%xmm3,%xmm1	<- the site
	1402ad718:	vorps	%xmm1,%xmm2,%xmm2
	1402ad71c:	vmovups %xmm2,(%rax)		<- reads rax
	1402ad720:	mov	%rcx,%rax
	1402ad726:	cmp	%rbx,%rax
	1402ad729:	jb	0x1402ad6e3		<- back to the loop head
	1402ad72d:	jmp	0x1402b02b5		<- to the epilogue
	...
	1402b02b5:	lea	0xa0(%rsp),%r11		<- WRITES r11 before reading it
	1402b02bd:	mov	0x30(%r11),%rbx
	1402b02ed:	mov	%r11,%rsp
	1402b02f9:	ret
```

The loop head is `cmp %r14,%rdi`, and `r14` is non-volatile and not tracked. So `r8`, `r9`
and `r10` are never mentioned on any path out of the site, and `r11` is written before it
is read -- four dead, which is what the survey says.

**The register it does NOT claim is the better evidence.** `rax` is withheld here, and two
instructions after the site `vmovups %xmm2,(%rax)` reads it as a memory base. The same
survey claims `rax` at `0x1402ad682` and `0x1402adb59` in the same function. So the answer
varies with the position rather than with the function, which is the whole claim.

#### What is proven and what is not

Nineteen selftest cases, half of them asserting a register is DEAD -- an analysis that
answered "live" everywhere would be sound, would free nothing, and would pass every case
that only checks for corruption. Seven sabotages, each taking out one rule: killing the
volatiles at a call, dropping the argument-register read, treating a departure from the
range as safe, making a `ret` read everything, letting a narrow write kill, replacing
reachability with address order, and dropping the read of a write's source. Each turns at
least one case red.

**One of those cases was worthless when written and the sabotage is what said so.** The
backward-branch case put the read one instruction after the site, where plain address
order finds it too, so it passed against the sabotage that replaces reachability with "the
next instruction" -- the fixpoint was resting on nothing. The replacement is the pair
Finding 131 named: the read at a LOWER address than the site, reachable only over the
loop's back edge, with a loop closing above it that must carry it and one closing below it
that must not.

**Nothing is built on this yet.** `gpr_live_out` is read by the survey and by nothing in
the rewriter, exactly as `ymm_span` was when Finding 133 scoped it. What it settles is the
price of the item, not the item.

### Finding 142 -- static TLS is built, and it is worth 671 sites

**7,224 -> 6,553 surviving VEX sites**, measured against the binary with `make detour` and
`make detour-verify` in both modes at the same revision, per Finding 126. 99.1% to 99.2%.
`--spill=tls` is built, off by default, and gated by a fixture that runs under wine.

The mechanism is the one Finding 69 described and declined, Finding 138 proved the file
format of, Finding 139 re-priced at 67 sites, and Finding 141 re-priced again at 753 by
asking liveness per position instead of per function. Nothing about it is new; what was
missing was the registers, and they were there all along.

#### What a stub emits

```
	mov	%gs:0x58,%r11		the thread's TLS array
	mov	tls_index(%rip),%r10d	the slot the loader gave this module
	mov	(%r11,%r10,8),%r11	this module's block
	movups	%xmm2,0x3260(%r11)	the borrowed register, saved
	...the lowering...
	movups	0x3260(%r11),%xmm2
```

**Neither general-purpose register is saved, and that is the whole mechanism.** There is
nowhere to save one to that does not need a register to address, which is the circularity
Finding 69 met; the way out is not to save them but to take ones already dead. `r11` and
`r10` are preferred where free because neither is ever an argument or a return value.

`--spill=tls` is the home space's **fallback and not its rival**: it lends the home space
wherever the home space is lendable and reaches for a per-thread slot only where
`borrow_offset` says no. So it is a strict superset of `--spill=home`, which is what makes
the two comparable at all.

#### The file-format half, recomputed rather than remembered

`tls_slot` reads the directory out of the image, and every figure Finding 139 recorded
comes back from the binary rather than from this document:

```
	template          12,896 bytes    (End - Start)
	AddressOfIndex    0x145e123e0
	alignment         16 bytes        (characteristics bits 20-23)
	slot at           12,896
	SizeOfZeroFill    0 -> 16
```

`apply` raises `SizeOfZeroFill` last, after every section is added, because the directory
is addressed by RVA and nothing else moves it. **`verify` now allows exactly that field
and nothing else outside `.text`**: it puts the rewritten four bytes back into the
original's and demands byte-identity again. Written as an identity rather than as a skip,
because a check that tolerated a difference somewhere in the TLS directory would tolerate
one anywhere in it, and the directory holds four pointers this must never move.

#### The fixture, and the A/B that makes it mean something

`tlsspill` is `regionread` with a TLS directory: a leaf, so it reserves no callee home
space of its own, whose caller's shadow holds a local read AFTER the site, so the shadow
cannot be lent either. Both stores refuse it, which is the residue `no home space to
borrow` counts.

```
check-spill: tlsspill --spill=home returned 29, want 121
check-spill: tlsspill --spill=tls  returned 121, want 121
```

29 is the illegal-instruction death of a surviving VEX site. 121 comes back only if BOTH
halves held: `%xmm2` was restored from a per-thread slot, and the local in the shadow was
still there to be added. **The `home` arm is an assertion and not a control run**: if it
ever returns 121 the site was never the hard case and the `tls` arm proves nothing, and
the gate says exactly that.

The two encoders are pinned against `as` byte for byte in `tls_selftest`, because every
other encoder here is exercised by something that runs it and these two are emitted only
where a site has two dead general-purpose registers -- which no fixture is guaranteed to
contain.

#### The 753 was exact, and the first build still lost sites

`make gprs` said 753 sites have two volatile GPRs dead across the bracket. `detour-plan`
with `--spill=tls` took `no home space to borrow` from 1,332 to 579: **753 exactly.** The
liveness measurement and the collector agree to the site, which is the corroboration
Finding 141 could not give itself.

**The first build was nevertheless worse than `--spill=home` by 969 sites**, and the cause
was not the mechanism:

```
                                        home    tls, first build
  no home space to borrow              1,332      579   -753
  no register free across the ymm run     49      400   +351
  not inside any accepted window       5,596    5,883   +287
```

`ymm_run`'s borrow and `swallowed_borrow` both asked `SPILL == SPILL_HOME` **exactly**, so
turning TLS on took the home space away from every run and gave it back to nobody. A mode
added to one test and missed in two others. They go through a named `HOME_SPILLS` now, so
a fifth backing store cannot miss one of the four places.

**`detour-plan` is what found it, and this is the case it is for.** It runs the collector
without the placer, so a refusal moving in the wrong bucket is visible with nothing else
changed -- and the search was about to go to `place_stubs`, which was innocent. Finding
126 says to COST a change with the binary; it does not say to DIAGNOSE one with it.

#### Two ways the measurement lied before it told the truth

Both are recorded because each cost a wrong conclusion, and neither was subtle.

**A truncated list read as a whole one.** The first comparison was `tail -30` of one run
against a full record of another, and the refusal profile looked scrambled -- buckets
apparently vanishing that were merely above the cut. It produced a confident diagnosis of
a defect that was not there, on top of a real one that was.

**`make` will not rebuild what is newer than its prerequisites.** The second A/B ran
`make detour SPILL_FLAGS=--spill=tls` against a binary the `home` half had just built,
printed `Nothing to be done for 'detour'`, and then verified a TLS collection against a
home binary -- reporting 214 lost boundaries, every one of them a site the TLS mode would
have detoured and the home binary had not. **A flag that changes the OUTPUT but not the
prerequisites is invisible to make.** Remove the target before switching modes.

### Finding 143 -- the span was short of slots, and slots stopped being scarce

**218 -> 342 sites.** `make spans` priced a closed 256-bit span against the home space and
the caller's shadow, which is what existed when it was written. Those are 32 bytes each
and cannot grow. A per-thread block grows by editing one field in a directory, so eleven
slots there cost exactly what one costs -- and the survey had no way to say so, because
`--spill=tls` was built the day after it.

```
covered by a span the home space fits      218
  and by one only a block fits             124
  both                                     342
```

Of the 76 closed spans the home space cannot fit:

```
  40  a block would fit it
  25  0 register(s) dead across the span
  11  1 register(s) dead across the span
```

40 of 76, covering 124 surviving sites. The other 36 fail for want of two dead
general-purpose registers across the WHOLE span, which is a floor rather than a modelling
gap -- the registers must survive every instruction the span covers, not merely its first,
because a slot addressed through a register the span itself clobbers is worse than no slot.

**This is the third time a measurement has moved this item before anybody built it.**
Finding 133 scoped the 256-bit residue at 1,674 sites of capacity and corrected itself the
same day to 212 of reach; Finding 140 removed 77 of the 325 stops for zero sites; and this
adds 124 without touching the walk at all, by changing what the answer is priced against.
The span analysis has not changed since Finding 133 built it. What changed is that the
project acquired memory of its own.

#### What it does not touch, which is still the large item

```
  3,273  span: does not begin with a 256-bit load
    101  ... still live after a branch target inside the span
     92  ... after a control transfer
```

**A span must begin at a 256-bit load and a whole-function representation would not**, so
the 3,273 is untouched by any of this and remains the only reason to build the larger
design. What has changed is the case for building it FIRST. Finding 133 parked 443 sites
as needing eleven slots at once, and that figure is part of why the whole-function rewrite
looked mandatory; it is not a constraint any more.

**Nothing is emitted yet.** `ymm_span` remains analysis, as it has been since Finding 133,
and this finding prices it rather than building it. The order that follows from the
numbers is the span first -- 342 sites, an analysis that already exists, and the first
thing here that would EMIT 256-bit code rather than measure it -- and the whole-function
design afterwards, against a smaller residue that is better understood for having had the
cheap half taken out of it.

### Finding 144 -- the span emits, and it computes what the original computed

`ymm_span` has been analysis since Finding 133 and has been priced three times without
emitting a byte. `lower_ymm_span` is the lowering it was pricing, and `make check-span`
runs it.

```
	movups	(%rsi),%xmm0		the low half, in the register the program uses
	movups	0x10(%rsi),%xmm5	the upper half, into the helper
	movups	%xmm5,(%rsp)		and into its slot
	addps	0x40(%rsi),%xmm0	the low half's share of the work
	movups	(%rsp),%xmm5
	addps	0x50(%rsi),%xmm5	the upper half's, at +16 on the operand
	movups	%xmm5,(%rsp)
	movups	%xmm0,(%rdi)
	movups	(%rsp),%xmm5
	movups	%xmm5,0x10(%rdi)
```

One rule per member: **the low half is the original instruction with `VEX.L` cleared,
acting on the xmm the program already uses; the upper half is the same operation between
a slot and one helper register.** A load fills both, a store empties both, and an
operation reads the slot into the helper, applies itself, and puts it back. `narrow_piece`
does the +16 on every memory operand, rip-relative ones included, and `encode_spill`
addresses the slot -- both already existed for the run and the borrow.

#### Proved by running it, because shape checks cannot see arithmetic

The project's own lesson is that every structural check here is about shape, and the two
bugs that produced silently wrong arithmetic had the right shape. So the span is settled
the way `vex_oracle` settles a lowering, with one difference that earns it a tool of its
own: **a span is a representation, and what has to hold is not that one instruction
lowered correctly but that the upper half survives from its definition to its death.**
Only running the sequence end to end asks that.

```
   native exit -4 (SIGILL -- host cannot execute the input)
   a load, a memory-source add and a store                agree
   two values in two slots, each stored                   agree
   a multiply, whose result differs from an add's         agree
   collapsing two slots into one: rejected
```

The 256-bit original runs under qemu, which decodes VEX on a host that has none; the span
runs natively, because the span is pure SSE and that is the point of the project. Both
write 32 bytes and the two must agree bit for bit.

**Three controls.** The capability control requires the 256-bit side to die of SIGILL
here, so an agreement cannot come from both sides running the same thing. The two-slot
case exists because a span that gave both values the same sixteen bytes would return one
of them twice -- Finding 118's defect in the home space, which assembled and verified and
corrupted a register. And the sabotage collapses those two slots into one deliberately and
requires the answer to change: inputs that cannot tell two slots from one would make every
agreement above unearned.

#### What it does not lower yet

An operation whose second source is another tracked ymm. That needs the source's slot as a
memory OPERAND of the operation rather than as something moved in and out, which is a
different encoding problem -- `slot_tail` is written for it and nothing calls it yet.
`span_operand_shape` names the shapes it accepts and refuses the rest, and **a span
containing one shape it cannot emit is refused whole**: half a representation is a program
that reads an upper half nobody wrote.

**Nothing in the rewriter calls this yet.** The collector has no span strategy, so no site
is lowered by it and the binary is unchanged. What exists is the lowering and the proof
that it computes the right answer; what is unbuilt is choosing sites and placing them,
which is where the 342 of Finding 143 would come from.

### Finding 145 -- the span is wired in, and a strategy nobody offers looks exactly like one that refuses

**6,553 -> 6,535 surviving VEX sites.** 18 removed, and the span is the first strategy here
to lower 256-bit arithmetic rather than copies. `span_candidate` turns a closed span into a
window and `build_stub` emits it through `lower_ymm_span`.

Note the shape of the numbers: detours went DOWN by 22 while survivors went down by 18. A
span covers several instructions in one window, so one detour replaces several -- the
count of detours is not the count of work done, and never was.

#### The first wiring took zero sites and every gate passed

It was placed inside the run's own arm -- `if found is not None`, where `found` is a run.
A span exists precisely for a load whose next instruction is arithmetic, and **arithmetic
is what stops a run**, so the one case it was built for could never reach it. The build
was clean: `detour-verify` green, `check-span` green, the lowering proven bit-for-bit
against the original under qemu, and the site count identical to the digit.

**A strategy nobody offers is indistinguishable from one that refuses**, and nothing in the
gate set can tell them apart. Every check here answers "is what you emitted correct"; none
answers "was it ever asked for". The only signal was the site count not moving, which is
why costing a change against the binary is the rule (Finding 126) and why "it verified" is
not evidence that a feature exists.

It is offered after the whole run attempt now. Reaching that point already means the run
did not take the site, because every path that takes one continues.

#### 18 and not 342, which is the first increment's bound rather than the mechanism's

Finding 143 priced a span at 342 sites. This takes 18, and every gap is a condition written
into `span_candidate` on purpose:

  * **the callee home space only** -- 32 bytes, two slots, at one displacement for the
    whole window. The caller's shadow and the per-thread block are what Finding 143's 342
    counts and neither is wired;
  * **peak of two slots**, for the same reason;
  * **one arithmetic shape**, `op mem,%ymmD,%ymmD`, which is what SSE expresses by dropping
    the prefix. An operation whose second source is another tracked ymm needs that source's
    slot as a memory OPERAND, and `slot_tail` is written for it and still uncalled;
  * **a blunt helper**, from `function_scope`'s whole-function argument -- a register the
    function never names is free everywhere in it. `find_scratch` answers for a point and a
    span needs one register dead at every instruction; Finding 141 built the per-position
    machinery for general-purpose registers and nobody has pointed it at xmm.

Each is a separate increment with its own measurement, and none of them is a design
question. **The mechanism is proved; what is unbuilt is its reach.**

### Finding 146 -- the span reaches the block, and the fixture caught what nothing else could

The span's slots may live in a per-thread block now, not only in the callee home space.
`span_slot_move` is the whole of the difference -- `(%rsp)` plus a displacement for a frame
region, a displacement from a general-purpose register for a block -- and the block pointer
is computed once at the top of the span, which is what `window_gpr_free` had to establish
before the span was offered. A pointer clobbered mid-span would address another thread's
data.

The frame comes first wherever it serves, for `--spill=tls`'s reason: a displacement from
`rsp` needs no register and no directory raised. The block is offered where no frame region
will lend, or where the span wants more slots than one region holds. `TLS_SLOTS` is four,
and it is one number for the image because `SizeOfZeroFill` is one number -- the borrow
spill and a span share the area, since a stub runs to completion before another is entered
on the same thread.

#### The defect, which every structural check passed

The low half of a lane-wise operation went through `sse_encoding` and the load and the
store went through `narrow_piece`. Those produce the same bytes for an ordinary
displacement and differ on a RIP-relative one, **which has to absorb the move into the stub
as well** -- Finding 43's correction, which `narrow_piece` does and `sse_encoding` cannot,
because it does not know where the instruction landed.

So the low half of every span whose operation had a rip-relative source read from inside
the stub section:

```
	addps	0x41(%rip),%xmm0	# 0x1400040a2  <- the stub, not the data
	addps	-0x3000(%rip),%xmm4	# 0x140001070  <- correct, addend+16
```

The upper half was right and the lower was wrong, in the same instruction pair.

**Nothing that existed could see it.** `detour-verify` was clean: the shape is perfect, a
rip displacement is a rip displacement. `span_oracle` passed, and could not have failed --
every case in it uses `(%rsi)` and `0x40(%rsi)`, ordinary displacements, so the correction
it needed was never exercised. And `make detour` reported 30 more sites lowered, which read
as progress.

`spanblock` is what caught it, and it returned **5** where it wanted 99. It is a leaf whose
caller's shadow is read after the span, so both frame regions refuse and the block is the
only backing store left; and it reads its answer from the LAST element of the result, which
is in the upper half. The fixture was built before the commit precisely because the
combination it covers -- a span whose slots live in a block -- was new emission that no
existing check exercised, and it earned that on its first run.

**The lesson is the one this project keeps paying for and it has a new instance.** Every
structural check here is about shape; a rip-relative displacement pointing at the wrong
address has exactly the right shape. What catches arithmetic is running it, and what
decides whether running it MEANS anything is whether the case exercises the path -- the
oracle ran three spans and proved nothing at all about this one.

### Finding 147 -- the whole function is the wrong unit, and the right one reaches 3,355

The item this document has deferred five times is "whole-function 256-bit rewriting". **A
whole function is the wrong frame for it**, and the ABI says so: the upper half of every
ymm is volatile across a call, so no upper half is ever live at one. A function containing
calls is not a unit over which anything can be represented.

The unit is a **call-free region** -- bounded by a call, by a branch target, and by a
function's first instruction. At the start of one, every upper half is dead by the ABI.
Two consequences, and they are the whole design:

  * **nothing needs loading at the start**, because there is nothing live to load. The
    span's requirement that it begin at a 256-bit load is an artefact of starting in the
    middle of a region rather than at its edge;
  * **closure is free at the end**, because the region ends at a call and a read of an
    upper half after one would be reading garbage in the ORIGINAL program too. The span's
    other hard requirement -- every value dead at the end -- is discharged by the ABI
    rather than by analysis.

What is left is one question per site: **is every ymm this instruction reads defined by a
256-bit write since the region began?**

```
surviving 256-bit sites                                4,494
  covered by a span, home space only                     218
  covered by a span, plus a per-thread block             342
  every ymm read defined in its own region             3,355
    the value is not defined in its own region           940
    the region start is further than the walk looks      199
```

The 199 are a walk limit of 192 instructions and not a property of the program.

#### 3,355 is a bound on REACH, and it is not a number of sites

**This is the figure Finding 133 got wrong on this exact item and corrected the same day**,
from 1,674 to 212, because the first was capacity and the second was reach. 3,355 is the
same kind of number one level up: it says the REPRESENTATION covers the site. It does not
say the site can be built.

Not counted, and each is a separate bound to measure before anything is designed on this:

  * the peak number of upper halves live at once in a region, which decides slots;
  * one xmm free across the region, for the slot traffic;
  * two general-purpose registers for a block pointer where no frame region will lend, and
    the pointer must be recomputed after every call because the callee clobbers them;
  * whether each instruction's shape can be emitted at all -- `span_operand_shape` handles
    three today and refuses everything else;
  * placement, which cost the ladder's reload rung 49 sites in the binary against a plan
    that promised 51 (Finding 126).

**So the finding is that the region is the right unit and the item is worth building, not
that it is worth 3,355 sites.** Anyone continuing it should take the slot and register
bounds first, exactly as `make spans` took them for the span -- and should expect the
number to fall, because every previous measurement on this item has.

### Finding 148 -- the region is worth 512, and what binds it is one xmm register

Finding 147 measured what a call-free region REACHES -- 3,355 of 4,494 surviving 256-bit
sites -- and said in the same breath that the figure was a bound on reach and not a number
of sites, because Finding 133 made exactly that error on exactly this item. These are the
bounds it said to take.

```
3,355  reachable by the representation
2,782    no xmm free across the region
   61    no frame region and fewer than two GPRs
  512  slots and registers both available
```

**512**, against the span's 342. The region design is worth about 170 sites more than what
is already built, not 3,013.

#### What binds it is not slots

Slot demand is real and heavy -- 676 of the sites sit in a region wanting nine or more
upper halves live at once, and the distribution has a second hump at six:

```
  1: 1,001    4:  71    7:  70
  2:   685    5: 117    8:  28
  3:   291    6: 370    9+: 676
```

But slots stopped being scarce when the per-thread block arrived (Finding 143), and
`SizeOfZeroFill` is a number. **83% of the loss is one xmm register**, which the slot
traffic all goes through.

And that register is chosen by `function_scope`'s whole-function argument: free everywhere
in the function, because the function names it nowhere. Over a span of a few instructions
that is a mild rule. **Over a region that can run to 192 instructions it is nearly always
empty**, and that is the bound -- not the program's register pressure, but the bluntness of
the question asked about it.

**Finding 141 built the per-position machinery for general-purpose registers and nobody has
pointed it at xmm.** That is the same sentence Finding 139 wrote about GPRs before Finding
141 answered it and took static TLS from 67 sites to 753. One instance is not evidence that
it repeats, but it is the obvious next measurement and it is a day's work on machinery that
already exists.

#### The instrument's own flaw, stated because the counts are read off it

The three buckets are exclusive and ordered: a site with no free xmm is counted there even
if it would also have failed on slots. **The 512 is sound** -- it is the case that passes
every check -- but the other 2,843 are attributed to whichever test ran first and must not
be read as three independent causes. In particular the slot check never fires in this run,
so `TLS_SLOTS` at four is not measured against the 676 sites wanting nine.

Fixing the attribution is cheap and was not done here, because the number that decides
whether to build the design is the 512, and that one does not depend on the ordering.

### Finding 149 -- per-position xmm liveness is WORSE than the blunt rule, and the answer is both

Finding 148 said 2,782 of the 3,355 sites a region could represent were refused for want of
one xmm free across it, that the register was chosen by `function_scope`'s whole-function
argument, and that Finding 141 had built the per-position machinery for general-purpose
registers and nobody had pointed it at xmm. Pointed at xmm, **it answers fewer free
registers than the rule it was meant to beat.**

```
a helper by the WHOLE-FUNCTION rule    573
a helper by per-position liveness      272
both together                          764

  slots and registers both available   689     (512 by the function rule alone)
```

They overlap on 81 regions. The function rule finds 492 that liveness refuses and liveness
finds 191 that the function rule refuses. **Neither contains the other**, which is the
finding.

#### Why the analogy to Finding 141 was wrong

There, the whole-function rule and per-position liveness asked the same question over the
same range, and the blunt one lost every site where a register was named once and dead
everywhere that mattered. Here they ask **different questions**:

  * `function_scope` says the function names the register NOWHERE. That holds at every
    position in the function, including after control leaves the region -- which is
    precisely where a region-scoped analysis has nothing to say;
  * `xmm_live_out` says the register is dead at every position IN THE REGION. A region
    ending at a call knows what follows, because the ABI kills every volatile register
    there; a region ending at a BRANCH TARGET does not, so it must seed everything live
    and the answer floods backward.

So the blunt rule reaches past the region's edge and the sharp one does not. Taking both is
sound because each is sound for its own reason, and it is worth 689 against 512.

#### The wrong answer announced itself, and a right-looking one would not have

The first run of this measured **81** free helpers against the function rule's 573, because
`region_end` makes a terminating call the region's last position and `control_successors`
found its successor outside the range, seeded it unresolved, and flooded every position
backward with every register. Modelling that exit by the ABI instead -- nothing volatile is
live after a call -- took it to 272.

**A result worse than the thing it replaces is self-flagging.** Had the first run come back
at 650 it would have been believed, committed, and the flooding would have sat in the
instrument making every later region measurement quietly low. The 81 is recorded in
`register_live_out`'s comment for that reason rather than merely fixed.

#### Where this leaves the item

```
  the span, built                         342
  a region, helper by both rules          689
```

347 sites more than what exists, and the uncounted bounds are now the emittable shapes --
`span_operand_shape` handles three -- and placement, which cost the ladder's reload rung 49
sites against a plan that promised 51. `TLS_SLOTS` at four is still untested against the
676 sites whose region wants nine or more, because the ordered buckets never reach the slot
test.

### Finding 150 -- the shapes, and the one to build next is named by measurement

The last bound Finding 148 left uncounted. A region is a representation, so **every**
256-bit member of it must be emittable or none is -- `span_operand_shape`'s rule applied
to the larger unit, and the reason half a region is a program that reads an upper half
nobody wrote.

```
  of 3,355 sites a region could represent
  every 256-bit member a shape the lowering emits  1,237

  what the rest would need built, by site:
      1,367  a register second source, D of its own
      1,229  an immediate form
      1,152  a register-to-register move
      1,055  four operands -- an insert, a blend or an FMA
      1,054  mem,S,D with a destination of its own
        990  a register second source, D reused
         48  no operands
```

**The register second source is the one to build**, at 1,367 and 990 for its two forms, and
it is the shape `slot_tail` was written for and never called: the second source's slot has
to be a memory OPERAND of the operation rather than something moved in and out. Nothing
else on the list is a bigger population, and the two forms share an encoding problem.

#### Two things the table does not say

**The buckets overlap.** A region carrying three shapes this cannot emit is counted under
all three, which is why they sum to 6,895 against a population of 3,355. They rank what to
build; they do not partition anything.

**The intersection with affordability is not measured.** 1,237 sites sit in a fully
emittable region and 689 sit in one that can afford the slots and a helper (Finding 149),
and those are different populations measured over the same 3,355. The buildable number is
their intersection and is **at most 689** -- so 1,237 is not a site count either, for
exactly the reason Finding 147's 3,355 was not one.

#### Where the item stands, with every bound taken but one

```
  the span, built                            342
  a region: represented                    3,355
            slots and a helper as well       689
            fully emittable as well       <= 689, unmeasured
```

Placement remains on top of that, and it has cost this project sites before -- the ladder's
reload rung gained 51 by plan and lost 49 in the binary. **Every measurement taken on this
item has moved the number down**, four times now, and the honest reading is that the design
is worth a few hundred sites rather than a few thousand.

## Picking this up again

Everything below is what a fresh start needs and none of it is derivable from the
code quickly.

### The two decisions that are not the implementer's

1. ~~**May a stub spill?**~~ **Answered: no, and it was never a decision.** Finding 46
   showed the recorded objection was misattributed, Finding 48 removed it, and Finding
   49 tested what was left: a stub that moves `rsp` hands the unwinder a frame sixteen
   bytes wrong, because a chained fragment's own unwind codes are not applied and
   dropping the chain loses the handler entirely. `--spill=none` stays the default on
   evidence, and **Finding 68 closed it for good**: MSVC never allocates stack inside a
   chained fragment -- not once in 65,255 fragment unwind codes -- because a fragment
   shares its primary's frame rather than having one of its own. A stub that moves `rsp`
   cannot be described.

   **`--spill=home` is the answer and is now the default** (Finding 73). It moves nothing:
   it borrows the callee home space Win64 already reserves, is worth 1,022 sites, and took
   the `src2 aliases dst` refusal from 3,728 to 43.
   It was turned on deliberately, and what it risks is named in Finding 73.

   What follows is kept because it is what was decided against and why.

   Spilling was rejected in `tool/scratch.py` because the stub section has no
   `.pdata`, so `RtlVirtualUnwind` treats a stub as a leaf and reads the frame from an
   `rsp` the spill has moved. **That is true and it is misattributed**: a stub is
   entered by a jump, so `[rsp]` was never a return address, and `make check-unwind`
   shows an exception raised inside a stub going undispatched **with no spill
   anywhere**. The defect belongs to detouring and every one of the 193,485 detours
   already has it.

   **The unwind data is built** -- Finding 48, and it fixed the live defect.
   `--spill=stack` is built and measured at 3,537 sites for 107 KB but hands the
   unwinder a wrong frame; `--spill=pool` buys the identical sites, keeps `rsp` still,
   and cannot be made thread-safe; and Finding 45 closed the one alternative needing no
   spill at all, at 249 sites. All three are built, so the day any of those facts
   changes the flag is already there.
2. **How much further should the Y1 register model go?** Finding 50 built its first
   piece -- the gapped copy, holding an upper half in a second register across a span --
   and it works. What is left needs a ymm represented as two halves across a basic
   block. Findings 39, 40 and 44 have the original measurements, and Finding 40 names
   what the model must repair: the in-place lowerings have already destroyed the
   [255:128] zeroing that VEX.128 writes perform.

   **Findings 133 and 137 have since answered most of the shape of it, and the answer
   is not a register.** An upper half's lifetime never crosses a call, because Win64
   makes it volatile -- and a home space is volatile across a call for the same reason,
   so the two coincide exactly and a slot costs no register to address. A third of the
   256-bit sites need one upper half live and half need two or fewer, but a tail needs
   ten or more with 123 needing all sixteen, so registers alone reach an eighth.

   **What is still the decision** is whether to build the general form. The
   straight-line version is measured at 212 sites (`make spans`); reaching the 443 sites
   that need eleven slots at once, or the 193 that lose their value at a control
   transfer, needs a whole-function rewrite that nobody has started. Do not begin it on
   the 1,674 capacity figure -- that is room, not reach.

### Where the residue actually is

**Re-measured 2026-09-01, on the default build, which is `--spill=tls` since Finding
142.** `make detour-plan` names every refusal and `make census` reconciles them against
the binary; these are the buckets that matter, with the count outside any accepted window
beside the total, because a site inside one has already been taken by whatever strategy
claimed that window.

```
                                                total   outside
ymm value has no known upper half              10,015       966
256-bit: arithmetic rather than a copy          1,974     1,818
no home space to borrow                           579       461
256-bit: no store before 256-bit arithmetic       359       282
outside .pdata                                    325       325
next instruction is a branch target               209       209
the constant is read by something that
  will not reload it                              182       182
256-bit: no store before the value is touched     173       150
256-bit: no store before a control transfer       161       160
256-bit: no store before a branch target          139       138
                                                          -----
everything left, all buckets                              5,095
```

The census reconciles exactly, which is the number to trust:

```
VEX in the rewritten .text          6,553
  declined by the collector          5,424
  refused, stub not buildable          595
  inside a committed window              0
  skipped for overlap                  453
  undecodable, never classified         81
  unaccounted                            0
```

**Counted by width rather than by refusal, which is a different set and the one that
matters:**

```
                 now    under --spill=home
  256-bit      4,445                 4,445
  128-bit      1,928                 2,599
  undecodable    180                   180
```

**Every one of Finding 142's 671 sites is 128-bit, and the 256-bit half did not move at
all.** 2,599 - 1,928 = 671 exactly. That is what static TLS was aimed at and it is worth
recording as a check on the mechanism rather than only as an outcome: a per-thread slot
lends a register to a site that could find no home space, and `no home space to borrow` is
a 128-bit refusal. A gain that had shown up in the 256-bit column would have meant
something else was happening.

**The 180 are not instructions.** They sit inside Finding 8's 744 undecodable islands,
`decode_vex` reads their bytes as a prefix, and they are then counted as refused sites in
a bucket that reads like work. Nothing needs doing about them except knowing.

#### The 128-bit half was at its floor, and the floor was the backing store

Findings 130, 131, 134, 135 and 136 took `no home space to borrow` from 2,153 to 1,332 in
four increments of 479, 414, 263 and 80. **Finding 137 then measured what is left rather
than calling it diminishing returns**: of the 1,032 refused because a reader is reachable,
928 are a genuine forward read -- the program using its own home space, exactly what the
ABI reserves it for -- and 104 are a loop or an edge the CFG declines to model. The other
300 are structural.

That measurement stands and was never the thing to attack. Its conclusion was that **no
further ANALYSIS reaches this half, and what remains wants memory of the rewriter's own**
-- and Finding 142 built it. `no home space to borrow` is 579 now, and every one of the
671 sites is 128-bit. The 928 genuine forward reads are still genuine forward reads; they
simply no longer decide the site, because the site is not asking the program for its
memory any more.

**What is left of this half is 579 sites with no home space AND fewer than two dead
general-purpose registers**, which is a real floor rather than an analysis gap: Finding
141's per-position liveness is already the sharp form of that question, and 394 of the
1,332 had no volatile register free at all.

`outside .pdata` is near its ceiling too: `outside.py` already accepts 17,237 of the
17,604 VEX sites in the chunks it can see, and relaxing it is worth 52 sites in two small
classes plus 315 in chunks holding bytes objdump cannot decode.

#### The 256-bit half is one problem stated several ways

`ymm value has no known upper half` and `256-bit: arithmetic rather than a copy` are the
same thing, and so are the four `no store before ...` buckets and the 182 constants. An
upper half exists only in a machine ymm register no SSE instruction can reach.

**Finding 133 scoped it and then corrected its own number the same day.** 1,674 sites have
room for the upper halves live at them, in a home space, whose lifetime coincides with an
upper half's by the ABI -- both die at a call. But room is capacity, and capacity is not
the bound that binds. `make spans` asks the question that does:

```
surviving 256-bit sites             4,494
covered by a closed span that fits    218   the home space and the shadow
                                      342   with a per-thread block as well
```

A span is worth nothing unless every value it tracks dies inside it, and closure is what
fails -- 3,273 spans never begin at a 256-bit load at all, 101 lose their value at a
branch target inside the span, 92 at a control transfer, 53 have nothing consume it, and
57 lose it to a narrower touch.

**Do not read the remaining refusals as a menu.** Finding 140 took the largest of them --
the forms the walk did not recognise, 325 stops across 27 forms -- and removed 77 of them
in three increments, for zero additional sites. What it measured on the way is the part
worth keeping: 38% of that bucket was a store of a value the span never defined, which is
a correct refusal wearing a label about lane structure, and removing the rest only moved
each span's death to the next obstacle. The 54 spans that close and then fail on the slot
table are a different question from any of this.

### What is worth building next

Ordered by what was measured, not by what looks large.

  1. **Emit the 256-bit span**, at **342 sites** -- Finding 143, which re-prices Finding
     133's 212 against a per-thread block instead of against 32 bytes of home space. The
     analysis has existed since Finding 133 and has never emitted anything; what is
     unbuilt is the lowering. It is the smaller of the two remaining items by a wide
     margin, and it would be the first thing here to EMIT 256-bit code rather than
     measure it.
  2. **Region-based 256-bit rewriting**, which is what "whole-function" should have said
     -- see Finding 147. A call-free region is the largest unit over which an upper half
     can be represented, because the ABI kills every one of them at a call; and at a
     region's edges the span's two hard constraints both dissolve. 3,355 of the 4,494
     surviving 256-bit sites have every ymm they read defined inside their own region,
     and **689 of those can also afford the slots and registers** (Findings 148 and 149)
     -- against 342 for the span that is already built, so the design is worth about 347
     sites as costed today. The helper comes from the UNION of the whole-function rule
     and per-position liveness, which are sound for different reasons and neither of
     which contains the other; per-position alone is worse than the blunt rule, which is
     Finding 149 and not what was expected. Still uncounted: the emittable shapes, of
     which `span_operand_shape` handles three, and placement. **It is the only large item
     left**, which is the real state of the project rather than a complaint about it.

**And do not re-mine these.** Each has a number saying why:

  * the home-space seam (Finding 137: nine in ten of what refuses is the program);
  * `outside .pdata` (Finding 137: 52 safe sites, 315 unsafe);
  * `--spill=stack` (Finding 68: a chained fragment's allocation must equal its primary's,
    so a stub that moves `rsp` cannot be described -- and a Windows host cannot change
    that);
  * `--spill=pool` (Finding 46: it cannot be made thread-safe);
  * the local 256-bit span design as a build (Finding 133: 212 sites, against 479 and 414
    for the two home-space increments, at several times the complexity);
  * **the span walk's vocabulary** (Finding 140: three increments, 77 of its 325 stops
    removed, four whole forms gone, zero sites gained). What the 218 is short of is not
    which forms the walk recognises. 3,273 of its refusals never begin at a 256-bit load
    at all, 193 lose the value at a transfer or a branch target, and 54 spans close and
    then fail on slots rather than on shape -- so the next attempt here is item 3 or
    nothing.

#### The frontier is where it was, and that is deliberate

Measured and explained in Finding 137, and not repeated here: the site is a 256-bit store
refused by a `.pdata` chained-fragment start in `blocked`, which Finding 112 priced at 11
sites and declined. **The ranking is sites removed, not the fault address**, so a session
that removes a thousand sites and moves nothing visible is working correctly.

#### What the ladder cost to find out

Four rungs were once ranked by what a walk *reaches*, and none of the estimates survived:

```
                                            estimated   measured
retry assign_helpers at earlier stores             14         +3   built
vextractf128 with a tracked source                113        +50   built
a 256-bit reload of a tracked register             86         -4   reverted
carry a lane-safe ALU inside a run                320         +4   not built
```

Three lessons, each paid for:

  * **A site is gained only when everything downstream of it also holds.** The reload
    turned from a gain into a loss because `ymm_run` runs before `long_pair_stores`, so a
    longer run swallows loads the long pair was claiming and then fails for want of a
    second helper. Finding 123.
  * **`detour-plan` is the collector's view and the binary is the answer.** The reload
     rung gained 51 by `plan` and cost 49 in the binary: a longer window collides with
     neighbours that would each have been placed, which `plan` cannot model. Cost every
     rung with `make detour`. Finding 126.
  * **Count the survivors by mnemonic before ranking anything.** Every rung above is a
    256-bit rung, because the residue was assumed to be the register representation. At
    8,450 sites, 3,533 of the survivors were 128-bit and their largest single cause was a
    scalar `vaddss` in a leaf with no 32 bytes to borrow. The refusal buckets count what
    the collector declined, which is a different population, and it had stood in for the
    real one for several sessions. Finding 130.

#### The switches, and why each is kept

Every mechanism that could corrupt a local silently keeps its predecessor reachable, so
that two binaries can be compared -- a borrow at the wrong displacement does not fault.

```
--spill=none|stack|pool|home|tls  where a borrowed register is saved (tls)
--rsp=blanket|followed           what a copy of rsp costs (followed)
--shadow=off|on                  lend the caller's shadow as well (on)
--region=whole|live              is a home-space reference a verdict on the
                                 function, or a question about the site (live)
--escape=refuse|allow            a copy of rsp stored to memory (allow)
```

`--region=whole` and `--shadow=off` are what `check-spill` uses to show that
`regionlive`, `regionread` and `shadowspill` are testing what they claim.

### What each tool is for

```
vex_scan.py       the inventory: every VEX site by mnemonic
lower.py          the lowering RULES, and `verify` proves they assemble
patch.py          in-place patching; also the encoding primitives everything
                  else uses -- decode_vex, sse_encoding, offset_operand
detour.py         the rewriter proper: collect, place_stubs, build_stub,
                  lower_vex, apply, verify, census, selftest
targets.py        branch targets from .reloc, .pdata, .xdata, switch tables
outside.py        the code .pdata does not describe, plus lea_targets
scratch.py        liveness: find_scratch, and `check` proves its claims
lowering_cases.py generates the executable test cases from the real rules
pe_build.py       builds AVX PEs so the rewriter has a target it owns,
                  including one with a TLS directory
placement.py      where detours land; icache_bench.c what they cost
isa_guard.py      inside a function holding a cpuid or xgetbv, only a VEX
                  instruction may differ; carries its own control
vex_oracle.py     runs the original VEX under qemu against the lowering's
                  bytes natively, which is how a host with no AVX checks
lane_oracle.py    proves each LANE_WISE mnemonic really does split into two
                  128-bit halves, under execution rather than by argument
span_oracle.py    runs a lowered 256-bit span natively against the original
                  under qemu, which is how a SEQUENCE is proved rather than
                  an instruction
```

And the targets, since several exist only to carry a measurement:

```
make check         the gate: style, the lowering proof, the C tests
make check-pe      thirty-three PEs built here, rewritten, run under wine
make check-spill   the four ways a stub gets a scratch, each with its A/B
make check-tls     whether the loader gives us the per-thread bytes we ask
make check-unwind  whether an exception dispatches from inside a stub
make check-vex     the qemu oracle; make check-lanes the lane-wise one
make check-span    whether a lowered 256-bit span computes what the
                   original did, end to end
make detour        rewrite; make detour-verify the structural invariants
make census        reconcile every survivor to a named cause
make detour-plan   what the COLLECTOR refused, and why -- see the warning
make spans         what a closed 256-bit span could reach (a measurement)
make gprs          how many volatile GPRs are dead at each starved site,
                   which is what static TLS costs (a measurement)
```

### Practical things that cost time to learn

- **Delete `tool/__pycache__` before trusting a source revert.** Python validates a
  cached `.pyc` on the source file's size and mtime, so a same-length edit reverted
  within the same second keeps executing the old bytecode -- and `git diff` is empty,
  and `inspect.getsource` reads the file rather than the code object, so both corroborate
  the wrong thing. Finding 56 lost an hour to it.
- **`build/text.asm` is the input to almost everything** and `make clean` removes it.
  Regenerating is `objdump -d -j .text Starfield-unpacked.exe > build/text.asm`,
  about 30 seconds and 0.9 GB.
- **`apply` takes about ten minutes** on the real binary, `census` and `verify`
  similar. Run them in the background and do not poll them tightly.
- **`detour-plan` is not the measure of a change, and it is eight minutes against
  twenty.** It runs `collect` and counts what the COLLECTOR refused; it does not
  choose windows, does not commit them, and cannot see one window swallowing the
  site of another. For a change that does not alter window lengths its answer and
  the binary's agree to the site. For one that does, they can point opposite ways --
  the reload rung gained 51 by `plan` and lost 49 in the built binary, because a
  longer run collides with neighbours that would each have been placed. **The two
  quantities move in OPPOSITE directions under that change**, so a bigger `plan`
  gain is evidence of a bigger placer loss rather than of a better change -- and
  `plan` had agreed with the binary to the site on the two changes before it, which
  is how it came to be trusted. Cost a change with `make detour` and
  `make detour-verify`; use `plan` to say which bucket a refusal landed in.
  Finding 126.
- **Read a fixture as a measurement, not only as a verdict.** A test has to do real
  work to ask its question, and what it does on the way is evidence about the mechanism
  it exercises. `check-tls`'s program answered "does the loader honour `SizeOfZeroFill`"
  and, unavoidably, "what does reaching a slot cost" -- and the second answer sat unread
  for two days while a price it refutes led the build-next list. Finding 139. The habit
  is cheap: when a fixture passes, ask what it had to establish in order to pass.
- **A green `make style` does not mean what its old wording said.** The gate's
  structural half compares each line's tab count against what the converter would emit,
  and the converter never ADDS indentation -- so a line with too few tabs and no
  alignment spaces is invisible, and a file with no tabs at all used to pass while
  printing that it conformed. Over-indentation is caught; under-indentation is not. The
  pass line says so now, taken from the source tool in `5cb0cca`, and this entry exists
  because "35 files conform" had been quoted as evidence here a dozen times for a
  guarantee it never made.
- **`make` cannot see a flag that changes the output but not the prerequisites.**
  `make detour SPILL_FLAGS=--spill=tls` after a `--spill=home` build prints
  `Nothing to be done for 'detour'` and leaves the home binary in place; verifying
  that with `--spill=tls` then reports lost boundaries for every site the other mode
  would have detoured. Delete the target before switching modes. Finding 142.
- **Never compare a disassembly against a binary rebuilt after it.** That cost half
  an hour once. The same rule as `build-and-commit.md`'s about stale test binaries,
  and it applies to `objdump` output too. Delete the output before a run so a crash
  cannot leave a stale artifact for the next step to bless.
- **objdump wraps encodings longer than seven bytes** onto a continuation line with
  no mnemonic. `parse_listing` joins them; anything else reading a listing must too.
- The style gate treats a `#define` body as file-scope text, so **multi-line macros
  will be flagged**. Write the functions out.
- `wine` needs `WINEDLLOVERRIDES=winedbg.exe=d` or an expected crash hangs for the
  full timeout instead of returning immediately.
- **A wine that will not start returns 1 for every fixture**, and 1 is not any
  fixture's expected answer -- so `check-pe`'s loop blamed the first one and reported
  `rewritten aliasing returned 1, want 169`, which reads as a rewriting defect. The
  cause was that `build/wineprefix` belonged to the account that created it and the
  session running the gate was a different one; wine refuses a prefix it does not own.
  `check-pe` now asks `wine cmd /c exit 0` before the loop and says so. Override
  `PE_PREFIX` to run against a prefix you own. Same shape as the style gate's
  dubious-ownership fault taken in `b3fcb4f` two commits earlier, from the other
  direction: **a tool met a permission it could not read and reported it as a fact
  about the work.**
- `.SECONDARY` **expands its prerequisites where it is read**, so a variable defined
  later expands to nothing and protects nothing.

### The lesson worth keeping

Two bugs in this project produced silently wrong arithmetic while passing every
structural check: the `src2` alias that computed a constant zero, and the `VEX.L`
truncation that stored half of every 256-bit write. **Every structural check here is
about shape, and neither bug had the wrong shape.** What caught them was asking what
the code computes -- `make check-lowering` against a compiler oracle, and `make
check-pe` running real binaries on a CPU that can execute the output but not the
input. Add to those two when adding anything; a new lowering with no executable case
is untested however many other checks pass.

The corollary is that measuring first has repeatedly changed the plan, and twice
saved building the wrong thing: the scratch scan needed branch following rather than
a wider window (Finding 27), and the gapped ymm pair looked like the obvious next
increment and is worth 68 sites (Finding 39).

**And there is a third kind, which neither the oracle nor the executable cases can
reach: a defect whose shape the input does not contain.** A strategy stub that deleted
the instruction its window swallowed, and a `vzeroupper` the backward walk scanned past
-- both real, both wrong, and both at zero occurrences in this binary, so every check
passed and would have gone on passing. What found them was reading the change
adversarially with the question put as "find another one", and what keeps them found is
a unit case run against a copy of the tool with the fix taken back out. **A test you
have not seen fail is a test you have not seen.** Finding 111.

### Estimated cost of a translated binary

Rebuilt from the measured splits above. The earlier estimate is kept alongside,
because the difference is instructive rather than embarrassing:

```
                                              milestone 0    measured
Class C, one extra mov each                       +126,583    +183,123
C-alias commutative, swap operands                       —           0   (4,318 sites)
C-alias non-commutative, scratch + 2 movs                —      +9,368   (4,684 sites)
splitting 256-bit moves      (33,648 × 1)          +33,644     +33,648
splitting 256-bit arithmetic ( 2,197 × 1)           +4,500      +2,197
Y2 shadow traffic            (   574 × ~4)               —      +2,296
Class D vblendv* mask juggling (3,572 × ~2,
  plus 2 more for the 608 needing a spill)               —      +8,360
Class D vbroadcast* splat    (   754 × 1)                —        +754
FMA -> mul + add             (   421 × 2)             +424        +842
vzeroupper elided                                   -19,253     -19,253
──────────────────────────────────────────────────────────────────────
                                                   ~146,000     221,335
                                                      +0.9%      +1.34%
```

The correction has two sources. The larger is the 3-operand term: milestone 0 did not
count forms whose src2 is a memory operand, nor the non-commutative C-alias sites that
need two movs rather than one — partly offset by the commutative C-alias sites, which
cost **nothing**, a fact milestone 0 also did not have. The second is Class D, which
milestone 0 omitted from the model entirely and undercounted 12-fold (Finding 9).

**+1.34%, not +0.9%.** The conclusion is unchanged: call it **2–5% slower than native**
allowing for scratch spills and helper calls. Native class, comfortably. The point of
recording the correction is that the cost model is now derived from measured operand
shapes rather than from a mnemonic histogram, so the next person can see what it
assumes.

---

## Scope

**In scope:** x86-64 PE (`pei-x86-64`), VEX-encoded 128-bit and scalar instructions,
256-bit load/store, host baseline SSE4.2.

**Out of scope (v1):** AVX-512, EVEX, `vgather*`/`vperm*`/`vpsrav*` and other
AVX2-only ops with no SSE analogue, 32-bit PE, ELF, self-modifying code, packed
executables.

> **F16C cannot be scoped out, and is not.** `vcvtph2ps`/`vcvtps2ph` appear in
> ordinary compiler output with no dispatcher in front of them (Finding 10), so
> they execute. Twelve sites, each needing a software conversion routine rather
> than a substitution -- the only place in this design where that is true.
> Implemented in `src/f16c.c`; see Finding 10 for the verification.

> **EVEX is out of scope but it is *present*.** 179 AVX-512 instructions live in
> `.text`, behind a CPUID/XGETBV dispatcher that never selects them on a non-AVX host
> (Finding 5). "Out of scope" therefore means **recognise and pass through unchanged**,
> not "assume absent". A rewriter that assumes absence will fail to decode them.

**Non-goal:** general-purpose emulation. If a binary genuinely vectorises with 256-bit
arithmetic throughout, this approach loses its advantage and dynamic translation is a
better fit.

---

## Architecture

```
Starfield.exe
     │
     ▼
 [1] disassemble ─────► reassembleable IR   (Ddisasm → GTIRB)
     │                   code/data split, function boundaries from .pdata
     ▼
 [2] scan ────────────► VEX site inventory + ymm liveness analysis
     │
     ▼
 [3] lower ───────────► per-site rewrite (rules below)
     │
     ▼
 [4] reassemble ──────► fix .pdata/.xdata RVAs, jump tables, base relocs
     │
     ▼
 [5] verify ──────────► differential trace against a reference AVX host
     │
     ▼
Starfield-sse.exe
```

**Build on [Ddisasm/GTIRB](https://github.com/GrammaTech/ddisasm)** rather than
starting from Capstone. Ddisasm produces *reassembleable* disassembly with an explicit
IR designed for rewriting passes, and handles x64 PE. Steps 1 and 4 are the bulk of
the difficulty and are exactly what it exists to solve.

---

## Lowering rules

### Class A — scalar float, 2-operand VEX (direct)

```
vmovss  m,%xmm0        →  movss  m,%xmm0
vcomiss %xmm1,%xmm0    →  comiss %xmm1,%xmm0
```

### Class B — 3-operand VEX, dst == src1 (direct)

```
vaddss %xmm2,%xmm0,%xmm0   →  addss %xmm2,%xmm0
```

**83,461 sites, 30.28%** of 3-operand forms (measured; milestone 0 said 23.6%).

### Class C — 3-operand VEX, dst != src1 (extra mov)

```
vaddss %xmm2,%xmm1,%xmm0   →  movaps %xmm1,%xmm0
                              addss  %xmm2,%xmm0
```

**183,123 sites, 66.45%** of 3-operand forms. **Correctness note:** VEX scalar ops take
bits [127:32] of the destination from `src1`, and SSE `addss` leaves them untouched —
so the `movaps` must copy `src1`, not `src2`. Getting this backwards is silently wrong.

### Class C-alias — 3-operand VEX, dst == src2 (9,002 sites)

The naive Class C sequence clobbers `src2` before it is read. Measured and split:

**Commutative (4,318 sites) — swap, and it costs nothing:**

```
vaddss %xmm0,%xmm1,%xmm0   →  addss %xmm1,%xmm0
```

**Non-commutative (4,684 sites) — needs a scratch:**

```
vsubss %xmm0,%xmm1,%xmm0   →  movaps %xmm1,%xmmT
                              subss  %xmm0,%xmmT
                              movaps %xmmT,%xmm0
```

⚠ **`vmaxss`/`vminss` (1,134 sites) are in the second group, not the first.** SSE
`MAXSS(a,b)` returns `b` when either operand is NaN and when both are zeros of
opposite sign, so it is *not* commutative at precisely the inputs clamping code hits.
Treating it as commutative is a silent wrong answer that survives ordinary testing.
The full non-commutative inventory is in `tool/vex_scan.py`'s output.

### Class D — no direct SSE form

```
vbroadcastss m,%xmm0   →  movss  m,%xmm0
                          shufps $0,%xmm0,%xmm0
```

**735 sites** in the memory-source form above (not 47). A further **18** use the
AVX2 register-source form, which `movss` cannot express and which needs its own
sequence — the rule above does not cover them.

`vblendvps` maps to `blendvps` but takes an *implicit* `%xmm0` mask, so it requires
shuffling operands and often a spill. **3,542 sites, not 283** — see Finding 9 for the
operand-shape breakdown. This is the largest remaining lowering difficulty in the
design and the one most entangled with scratch-register pressure; 608 of the sites do
not mention `%xmm0` at all and must save and restore it around the blend.

### Class Y — 256-bit

**Y1 — the memcpy peephole (dominant, ~97%).** Match producer/consumer pairs on the
same ymm register with no intervening use:

```
vmovups m1,%ymm0        →  movups m1,%xmm0
vmovups %ymm0,m2           movups %xmm0,m2
                           movups m1+16,%xmm0
                           movups %xmm0,m2+16
```

No shadow state needed. The upper half never becomes architecturally visible.

Whether it stays invisible is the whole of the rule, and three things end its life:
a `ret`, a `call` -- the upper half of every ymm is volatile under Win64 -- and **a
later instruction that overwrites all 256 bits without reading any of them**, which is
what an unrolled copy does to its own predecessor. A branch is followed rather than
stopped at, both successors having to agree. Findings 38, 41 and 42; 5,388 sites.

**Y1-zero — the zero fill (9,806 sites).** A 256-bit store of a register a VEX.128
zeroing idiom emptied. `vpxor %xmm0,%xmm0,%xmm0` zeroes bits [255:128] as well, so both
halves are zero and the same xmm stores each:

```
vpxor   %xmm0,%xmm0,%xmm0   →  pxor   %xmm0,%xmm0      (in place)
vmovups %ymm0,m               movups %xmm0,m
                              movups %xmm0,m+16
```

No scratch, no shadow, and no coordination with the definition -- the low half is the
only half the lowering reads, so it does not matter whether the `vpxor` was lowered.
Findings 40 and 44 have the measurements and the scan's refusals: it walks back to
the nearest **write**, passing over anything that only reads the register and over a
conditional branch it fell through, and refusing a branch target or a call.

**Y1-run — the gapped and interleaved copy (Findings 50 and 51).** Load and store
separated by instructions that must not move, and any number of such copies open at
once. Each upper half rides in a second register, dead at its load and untouched until
its store, and the whole run goes into one stub:

```
vmovups m1,%ymm0        →  movups m1,%xmm0 ; movups m1+16,%xmm7
... in between ...         ... in between, untouched ...
vmovups %ymm0,m2           movups %xmm0,m2 ; movups %xmm7,m2+16
```

**Y2 — shadow fallback (rare, and now counted: 574 sites).** When a ymm value's halves
are separated across basic blocks, maintain a 16 × 16-byte shadow area for upper
halves, addressed via a reserved register or TLS slot. Each 256-bit op becomes a pair
plus shadow traffic, and needs a scratch xmm — spill one.

Measured at **574 of 13,097 ymm definitions (4.38%)**, against 12,336 (94.19%) consumed
inside their own basic block. See Finding 7 for the method and its bounds. Y2 survives
the measurement — it is not zero and cannot be dropped — but at 574 enumerable sites it
is a special case with a known address list, not a general mechanism the design has to
carry everywhere.

**Y3 — upper-half zeroing.** VEX 128-bit ops zero bits [255:128] of their destination.
Where a shadow exists (Y2 regions only), a translated 128-bit op must also zero its
shadow slot. **Confine this to Y2 liveness regions**, or the cost lands on ~769,000
128-bit sites instead of a handful.

Finding 40 turned this from a cost into two other things as well. It is **information**
-- for the 6,352 Y1-zero sites it is the entire lowering -- and it is a **debt**: a
lowered VEX.128 write no longer zeroes the upper half, so every register the model
comes to represent arrives with an upper half that is stale rather than zero. That is
harmless while every 256-bit read is refused and will not be afterwards.

### Class Z — `vzeroupper` (19,253 sites)

Outside Y2 regions: **delete it** (or `nop`). No AVX state exists to zero.
Inside Y2 regions: zero all 16 shadow slots.

This is 99.3% of what a naive "AVX2-only instruction" scan flags as hard, and it is
the cheapest rule in the design. Do not let the raw count mislead scoping.

### Class F — FMA (421 sites) — NOT semantics-preserving

```
vfmadd231ps %xmm2,%xmm1,%xmm0   →  movaps %xmm1,%xmmT
                                   mulps  %xmm2,%xmmT
                                   addps  %xmmT,%xmm0
```

Needs a scratch register. **Two roundings where the hardware did one** — results differ
in the last ULP. The `132`/`213`/`231` suffixes select which operand is the addend;
get the mapping from the SDM, not from intuition.

If exact FP reproducibility matters anywhere (deterministic physics, replays, lockstep
netcode), this rule is where it breaks. Flag every rewritten site so it can be audited.

### Class F-addsub — alternating lanes (28 sites)

`vfmaddsub` and `vfmsubadd` add on some lanes and subtract on others. The SDM, for
the 231 forms:

```
VFMADDSUB231PS   even lanes  product - dst        odd lanes  product + dst
VFMSUBADD231PS   even lanes  product + dst        odd lanes  product - dst
```

SSE3's `addsubps` subtracts on the even lanes and adds on the odd ones — exactly
`VFMADDSUB`, exactly backwards for `VFMSUBADD`. That was **confirmed by running it**
rather than read off the manual, because having it backwards is the failure the rule
exists to prevent and the manual is what one misreads:

```
{10,20,30,40} addsubps {1,2,3,4}  ->  {9,22,27,44}       9 = 10-1, 22 = 20+2
```

**`vfmaddsub` (14 sites)** therefore needs nothing beyond `addsubps`:

```
vfmaddsub231ps %xmm2,%xmm1,%xmm0   →  movaps   %xmm1,%xmmT
                                      mulps    %xmm2,%xmmT
                                      addsubps %xmm0,%xmmT
                                      movaps   %xmmT,%xmm0
```

**`vfmsubadd` (14 sites)** has no SSE instruction. Compute both and blend:

```
vfmsubadd231ps %xmm2,%xmm1,%xmm0   →  movaps   %xmm1,%xmmT
                                      mulps    %xmm2,%xmmT
                                      movaps   %xmmT,%xmmU
                                      addps    %xmm0,%xmmT
                                      subps    %xmm0,%xmmU
                                      blendps  $0xa,%xmmU,%xmmT
                                      movaps   %xmmT,%xmm0
```

> ⚠ **The obvious lowering is wrong, and testing is what found it.** Negating the
> addend and reusing `addsubps` looks correct — IEEE 754 does make `a - b` and
> `a + (-b)` the same operation, signed zeros included — and it is one instruction
> shorter. But the negation is a sign-bit flip across the whole register, and **a NaN
> has a sign bit too**. x86 propagates a source NaN with its sign preserved, so a NaN
> addend came out of that sequence as `ffc00000` where the hardware gives `7fc00000`.
> 291 vectors in the special-value sweep disagreed, every one of them a NaN.
>
> Computing both and blending performs the very add and subtract the hardware does,
> so NaN propagation matches by construction rather than by argument. It also needs
> **no sign-mask constant**, which removes a requirement the design would otherwise
> have inherited: the rewriter does not have to add a read-only constant pool for
> this rule. Two extra instructions across 14 sites is not a cost worth arguing about.

Verification (`make check-fmaddsub`): the lane order checked directly; the naive
sequence shown to differ on exactly the two even lanes; every combination of ten
special values across the lanes, then a random tail, for `ps`; 200,000 vectors with
signed zeros forced through both lanes for `pd`.

**Unresolved, and narrowly so:** two lanes where *both* the product and the addend
are NaN. Which NaN propagates depends on which operand the emitted instruction makes
its destination, and that needs FMA hardware to settle. The exemption in the test is
deliberately narrow — "both results are NaN" would have hidden the sign-flip bug
above, so it requires both *inputs* to be NaN.

### Class H-permil — vpermilps with a control vector (23 sites)

The immediate form is a `shufps` and is handled inline. The variable form has no SSE
instruction, and is the one that needs a helper.

What the instruction does, per element:

```
DEST[i] := SRC1[ SRC2[i][1:0] ]
```

Element `i` of the result is whichever element of the *data* operand the low two bits
of element `i` of the *control* operand select. **Bits 31:2 of each control element
are ignored**, which is part of the contract rather than a detail — the compiler does
leave rubbish up there.

> **Operand order is the easy thing to get backwards.** objdump prints the variable
> form as `vpermilps %xmm2,%xmm3,%xmm3` — that is *control, data, dst*, because the
> VEX `vvvv` field holds the **data** and `r/m` holds the **control**. Decoded from a
> real site rather than assumed: `c4 e2 61 0c da` has `vvvv = 3`, `rm = 2`, and the
> SDM reads "permute values in xmm2 using controls from xmm3/m128".

**It is an in-lane permute.** The 256-bit form permutes within each 128-bit half
independently, so it is exactly two calls and never a cross-lane shuffle. That is what
keeps it cheap and separates it from `vperm2f128` and `vpermq`, which are the genuinely
cross-lane ones.

SSSE3's `pshufb` is already a variable-control permute — it just works on bytes. So
the whole job is turning four element selectors into sixteen byte selectors:

```
pand   {3,3,3,3}                  bits 1:0 of each control element
pslld  $2                         element index -> index of its first byte
pshufb {0,0,0,0,4,4,4,4,8,8,8,8,12,12,12,12}
                                  replicate that byte across its element
paddb  {0,1,2,3} x4               ... and step through the four bytes
pshufb <that>,data                the permute itself
```

> ⚠ **The `pand` is not optional.** Without it the shift can push a control bit into
> position 7, and `pshufb` reads bit 7 of a control byte as *write zero here* — so an
> element whose control happened to hold 32 comes back zeroed instead of permuted.
> This is verified by mutation rather than by argument: building the helper with the
> mask removed makes `test/permil_test.c` fail on exactly the `0x20` and `0xfffffffc`
> control patterns, which is the check being shown to be worth something.

Verification (`make check-permil`) is **exhaustive over the permutation space** —
four elements selected by two bits each is 4^4 = 256 permutations, and every one is
checked against eight high-bit rubbish patterns. Plus destination-aliases-source for
all 256, and a direct check that the 256-bit form stays inside its lanes: a cross-lane
implementation would pass every 128-bit test and be wrong on all eight ymm sites.

### Class H-crosslane — the four cross-lane permutes (25 sites)

The "genuinely hard" set shrinks one more time on inspection. Of the 25 sites, **22
need no helper at all** once the 256-bit value is held as two 128-bit halves — which
is what the Y-class representation already does. Only `vpermd` needs code.

**`vperm2f128` (12 sites) is not a permute after the split.** Each output 128-bit lane
is one of the four input lanes, or zero; the immediate just says which. Split into
halves, it is at most two moves:

```
vperm2f128 $0x20,%ymm2,%ymm0,%ymm0   →  movaps lo(%ymm2),hi(%ymm0)
vperm2f128 $0x1,%ymm0,%ymm0,%ymm0    →  a swap of the two halves
```

Ten of the twelve use `$0x1`, which swaps the halves and therefore needs a scratch —
the second move would otherwise read the half the first has just overwritten. The
rule reports that hazard rather than silently reordering, because which register is
free is the allocator's business.

**`vpermq` (6) and `vpermpd` (4) are immediate permutes of four 64-bit elements.**
Cross-lane, but the control is a constant, so each output half is two chosen qwords
and `shufpd` builds one from two registers in a single instruction — it takes the low
result from the destination and the high result from the source. The two immediates
that occur are both degenerate:

```
$0x4e   {2,3,0,1}   a half swap    →  two movaps, no shuffle at all
$0x1b   {3,2,1,0}   a full reverse →  movaps + shufpd $1, per half
```

All ten sites take their source from memory, so in practice this is two loads and at
most two shuffles.

> `shufpd` on `vpermq`'s integer data crosses the SSE domain, which costs a cycle or
> two on some parts and nothing at all in correctness. `punpck` pairs are the
> alternative if it ever matters; at ten sites it does not.

**`vpermd` (3 sites) is the only one needing a helper.** Eight 32-bit elements, a
control *vector*, and any element free to come from anywhere.

> ⚠ **Its operand order is the opposite of `vpermilps`.** objdump prints
> `vpermd %ymm2,%ymm9,%ymm0` as *data, indices, dst* — `r/m` is the **data** — while
> `vpermilps %xmm2,%xmm3,%xmm3` is *control, data, dst*, where `r/m` is the
> **control**. The SDM sentences settle it: VPERMILPS "permutes values in xmm2 using
> controls from xmm3/m128"; VPERMD "permutes doublewords in ymm3/m256 using indices
> in ymm2". Both were decoded from real sites to be sure. Carrying the `vpermilps`
> convention across gives a permute of the index vector by the data, which is
> nonsense that still runs.

`pshufb` permutes within one register; `vpermd` selects across two. The bridge is
`pshufb`'s own zeroing rule — a control byte with bit 7 set writes zero — so each
output half is built twice and merged:

```
from_low  = pshufb(data_low,  control with bit 7 set where index >= 4)
from_high = pshufb(data_high, control with bit 7 set where index <  4)
result    = from_low | from_high
```

Every element is non-zero in exactly one of the two, because bit 2 of the index
decides which half it comes from and the two controls disagree on precisely that bit.
The `or` then merges them with no blend and no mask register.

**Every `vpermd` site in the binary is inside dispatched code.** All six lie between
`0x1434d847d` and `0x1434d8f1d`, in the CPUID-gated checksum library of Finding 5 —
including the three VEX-encoded `ymm` ones, not just the EVEX `zmm` ones. So none of
them executes on a host without AVX2, and the helper is insurance rather than a hot
path. It is written anyway: "unreachable" is an argument about control flow, and
being correct is not.

Verification (`make check-permd`) is **exhaustive over all 8^8 = 16,777,216 index
combinations**, in under a second, with a rubbish pattern cycled through so every
permutation is seen with several. Plus destination-aliases-source, and a direct check
that every element can reach both halves. Both the index mask and the cross-lane merge
were confirmed load-bearing by mutation: removing either makes the test fail.

### Class H — F16C only (12 sites)

`vpermilps` variable-control (23), `vpbroadcastd` (18), `vextracti128` (13),
`vperm2f128` (12), `vpermq` (6), `vpermd` (6), `vpermpd` (4), `vinserti128` (3),
`vpbroadcastw` (2). The other 50 `vpermilps` use the immediate form and need no helper.

Cross-lane permutes and broadcasts only — **no masked stores** (the `vpmaskmovq` was
DRM noise). No compact SSE sequence exists for the cross-lane cases, but at 87 sites
total, emit a `call` to a hand-written SSE helper operating on the shadow area.
Performance is irrelevant at this frequency; correctness and simplicity win.

**The `vpermilps` split is measured: 50 immediate, 23 variable.** The immediate form is
just `shufps` and needs no helper at all, so **Class H is 87 sites, not 137** — and the
count that actually needs a hand-written stub is 87 rather than 138. Roughly a third of
the "genuinely hard" set evaporates on inspection, which is the same lesson as
`vzeroupper` in Finding 3.

**Both forms are now implemented**, which splits the count again: the 50 immediate
sites lower inline to `shufps` (class `D/permute`), and the 23 variable ones call the
helper in `src/permil.c` (class `H/permil`). What is left genuinely needing a
hand-written stub nobody has written yet is **25 cross-lane sites** —
`vperm2f128` (12), `vpermq` (6), `vpermpd` (4), `vpermd` (3) — plus the 12 F16C sites,
which are written. See Class H-permil below.

```
requiring an out-of-line helper                     87
  vpermilps (variable control)   23      vpermq         6
  vpbroadcastd                   18      vpermd         6
  vextracti128                   13      vpermpd        4
  vperm2f128                     12      vinserti128    3
                                         vpbroadcastw   2
lowering to shufps, no helper                       50
  vpermilps (immediate control)  50
```

---

## The hard parts

Ranked by risk, and none of them are performance:

1. **Complete, correct disassembly.** x86 code/data separation is undecidable in
   general. A single byte of data misidentified as code silently corrupts the output,
   and the symptom appears hours into a playthrough. `.pdata` unwind tables give
   function boundaries and are a large head start — but they cover only what the
   compiler emitted, not hand-written assembly.

   **This is now quantified rather than feared: 11,892 undecodable bytes in 744
   islands** (Finding 8), and hand-written assembly is confirmed present (Finding 5),
   so the `.pdata` caveat above is real rather than theoretical. The island list is the
   audit target for milestone 3.

2. **Relocation.** ~3% growth means nothing patches in place. Every direct branch,
   jump table, indirect branch target, base relocation, TLS callback and — critically
   — every `.pdata`/`.xdata` RVA must be rewritten. Wine's `RtlVirtualUnwind` reads
   those tables, so getting them wrong breaks exception handling rather than crashing
   immediately.

3. **Verification.** See below; this is the make-or-break.

4. ~~**Steam DRM wrapper.**~~ **SOLVED — milestone 2.5 complete.**

   The shipped binary is packed with **SteamStub Variant 3.1 (x64)**, in a `.bind`
   section owning the PE entry point:

   ```
   .bind   [0x148988000 - 0x1489c1248]   234,056 bytes, flags CONTENTS READONLY CODE
   entry point 0x148988310                ← inside .bind
   ```

   **[Steamless](https://github.com/atom0s/Steamless) v3.1.0.5 unpacks it cleanly.**

   ```
   File is packed with SteamStub Variant 3.1 (x64)!
   Step 4 - Handle .bind section  --> .bind section was removed from the file.
   Step 5 - Read, decrypt code    --> Code section is not encrypted.
   Step 6 - Rebuild and save      --> Successfully unpacked file!
   ```

   Result verified:

   ```
   size    102,476,200 → 102,242,144   (delta 234,056 = exactly .bind)
   .bind   REMOVED
   entry   0x148988310 → 0x14365d904   ← now inside .text, the recovered OEP
   all other sections keep their original VMAs — nothing relocated, .pdata RVAs intact
   ```

   **Consequences:**
   - Steamless confirms *"Code section is not encrypted"* — step 1 of the pipeline is
     viable, as the coherent `.text` disassembly suggested.
   - The checksum risk is **eliminated, not mitigated** — there is no stub left to
     validate `.text`.
   - **All rewriting targets the unpacked binary.** Rescan it; do not reuse figures
     from the shipped executable.

   ⚠ Steamless leaves a byte of slack in some section names — `objdump` reports
   `.dataa`, `.xbldA`, `.rsrcA`. Harmless (Windows reads fixed-size names), but any
   tooling matching section names literally must account for it.

   ### Reproducing the unpack on Linux (no root)

   Debian's `wine` package ships **64-bit only** — `wine32` is absent, so
   `winetricks dotnet48` fails and `syswow64` is incomplete. Use **Proton's bundled
   Wine**, which has full `i386-unix`/`i386-windows` support, plus its wine-mono:

   ```bash
   PW="$STEAMLIB/steamapps/common/Proton 10.0/files"
   export WINEPREFIX=$HOME/.wine-steamless WINEDEBUG=-all
   export LD_LIBRARY_PATH="$PW/lib64:$PW/lib:$LD_LIBRARY_PATH"
   "$PW/bin/wine" wineboot -i
   mkdir -p "$WINEPREFIX/drive_c/windows/mono"
   cp -r "$PW/share/wine/mono/wine-mono-10.4.1" "$WINEPREFIX/drive_c/windows/mono/"
   # Steamless: copy Plugins/Steamless.API.dll next to Steamless.CLI.exe or it
   # fails with TypeLoadException on Steamless.API v1.0.0.8
   "$PW/bin/wine" Steamless.CLI.exe --verbose target.exe
   ```

   Steamless removes only the packing layer — the unpacked binary still requires Steam
   running and a valid licence.

5. **Scratch register allocation.** SSE has 16 xmm registers and the original codegen
   assumed all of them. Y2 and some Class D rewrites need a scratch; spilling costs
   more than the instruction count suggests.

---

## Verification strategy

Correctness cannot be established by "it booted." The ladder below was proposed
before any of it existed; the status on each rung is what is actually in the tree
now.

1. **Unit-level.** For each lowering rule, execute it and compare against a
   reference across inputs including the awkward ones. **Done, with one
   substitution.** The plan said "the VEX form on an AVX host"; there is no AVX
   host, so the reference is GCC compiling the equivalent SSE intrinsic. See
   Finding 31. Flags are still not compared, and `comiss`/`ucomiss` set them, so
   that gap is real and named in *What is still not verified* below.

2. **Differential tracing.** Run original and translated side by side, comparing
   architectural state at block boundaries. **Not done, and not possible here** --
   it needs the AVX machine rung 1 also wanted.

3. **Static self-check.** After rewriting, assert no VEX remains and that the
   structure is intact. **Done and considerably exceeded** -- `make detour-verify`
   checks section-by-section identity, boundary reconciliation, branch
   reachability of everything swallowed, and that the stub section contains no
   VEX. It also PRINTS a jmp count, which was quoted here as "one jump back per
   detour" until Finding 86 made stubs carry re-emitted branches too. That
   number was never asserted; the real invariant needs per-stub bounds and is
   not checked yet.

4. **Soak.** Long gameplay sessions. **Not started, but no longer blocked on a host.**
   Finding 74 runs both binaries under Proton on this machine and reads the fault
   address out of `PROTON_LOG`, so the harness for a soak exists; what is missing is a
   translation that survives longer than 866 bytes.

### The machine, because it decides what can be tested

    Xeon X5675 (Westmere), SSE4.2 + AES-NI + PCLMULQDQ, no AVX, no F16C, no FMA
    Linux, wine 10.0, binutils as/objdump/objcopy, gcc -- and no mingw

**The absence of AVX is the project's premise and its best test instrument.** This
CPU cannot execute the input and can execute the output, so "the original must
crash and the rewritten one must work" is a real experiment rather than a wish. It
is also why every reference has to come from somewhere other than the original
instruction.

The absence of mingw is why `tool/pe_build.py` writes PE headers by hand rather
than compiling with MSVC or a cross-compiler.

### What each check proves, and what it does not

| check | proves | does not touch |
|---|---|---|
| `make style` | tabs, alignment, ASCII, and that documents name no missing file | anything about behaviour |
| `make verify` | every lowering rule assembles, and no VEX or EVEX prefix survives | what any of them computes |
| `make check-aliasing` | no lowering reads a register it has already overwritten -- symbolically, over 18 operand shapes | arithmetic; it simulates moves rather than running them |
| `make check-lowering` | 51 mnemonics over four operand shapes, one with src2 in memory; `vblendvps`/`vblendvpd` across all five register arrangements their lowering branches on; ten FMA orderings; and the broadcasts through memory. Every one of 16 registers matching GCC's SSE intrinsic over 8 input patterns including three all-NaN | 256-bit, `vpermilps`, and any lowering whose destination is a general-purpose register -- Findings 54 to 57 count them |
| `make check-f16c`, `check-fmaddsub`, `check-permil`, `check-permd` | the helpers, exhaustively -- both F16C directions, all 256 permute controls, all 16,777,216 `vpermd` index sets | that the rewriter *calls* them; they are not wired in yet |
| `make check-pe` | twenty-two PEs built here, rewritten, and run under wine: originals die of an illegal instruction, rewritten ones return the right answers | scale, and anything Starfield does that these do not |
| `make scratch-check` | every register claimed as scratch is written before read on every path, by enumerating paths rather than intersecting sets | the ABI half of the whole-function argument, which no tool can check. It shared `xmm_numbers` with the code it checks until Finding 52, and so could not see a `%ymm` operand either |
| `make detour-verify` | on Starfield: header self-consistency, size, section identity, boundary reconciliation, stub integrity, that the rebuilt function table is sorted and covers every stub byte, and that all 1,191,070 direct branch targets still begin an instruction | **semantics -- every one of these is about shape.** Indirect branch targets have no witness but `targets.py`, which the collector also used -- Finding 53. Its function-table claim now has an independent witness: Finding 74 has wine looking the table up 431,937 entries deep, eleven frames, and agreeing with the original |
| `make check-spill` | that all three ways of getting a scratch register round-trip it, and that the default still refuses the site | anything about a second thread, or about unwinding |
| `make check-unwind` | that a handler registered through `.pdata` is reached from `.text` and from inside a stub, and that a stub which moved `rsp` still hands it a frame 16 bytes wrong | whether the shipping Windows unwinder agrees with wine's |
| `make bench`, `make placement` | what a detour costs on this CPU, and where detours land structurally | which code is hot, which needs the game running |

The row to keep in mind is `detour-verify`. It is the only check that runs against
the real target, and it is entirely structural. **Everything known about Starfield's
translation is that it is well formed.** The semantic evidence all comes from small
things: the lowerings executed in isolation, and twenty-two PEs built for the purpose.

### What is still not verified

Named rather than left implicit, because an absent gap gets guessed at:

- ~~**Starfield has never been run.**~~ **It has, under Proton -- Finding 74.** It gets
  866 bytes further than the original and dies on the next refused site, which is the
  honest scale of 17,972 survivors on a hot path. What that run does settle is
  structural: the image loads, four lowerings execute including a stub, and wine's
  unwinder walks the rebuilt 431,937-entry function table to a call stack identical to
  the original's. What it does not settle is whether any lowering computed the right
  value.
- **Flags.** `comiss` and `ucomiss` set EFLAGS and nothing compares them. The
  lowering is a prefix strip, so the risk is low, but low is not measured.
- **The helper classes are not wired in.** `f16c`, `fmaddsub`, `permil` and `permd`
  are exhaustively tested and unreachable from the rewriter.
- **256-bit.** Two shapes are lowered without one -- the adjacent copy pair and the
  zero fill -- but the Y1 register representation and the Y2 shadow do not exist, and
  Finding 40 names a consequence that will have to be repaired when they do: the
  in-place lowerings destroy the [255:128] zeroing every VEX.128 write performs.
- **Exception paths.** Finding 46 measured that an exception raised inside a stub was
  never dispatched at all, and Finding 48 fixed it: every stub now has a
  `RUNTIME_FUNCTION` chained back to the function it was cut out of, and
  `make check-unwind` reaches a handler from inside one. What remains is narrower and
  named -- a `__try` scope table is keyed on the faulting address and a stub's address
  is inside no scope, so such an exception propagates correctly to outer frames rather
  than being caught where it should be.
- ~~Surviving VEX sites are unaccounted for.~~ **Closed** by Finding 35: `make
  census` reconciles all 10,276 exactly, and the residue was an error in the
  accounting rather than anything the rewriter did. What it left behind is a real
  lead -- 1,018 sites refused for an overlap that only their backward-widened start
  collides with.

A translated binary that is 99.99% correct is worthless -- the remaining 0.01% is a
crash at an unpredictable moment.

---

## Prior art

- **[Ddisasm / GTIRB](https://github.com/GrammaTech/ddisasm)** — reassembleable
  disassembly, x64 PE support, rewriting IR. The intended foundation.
- **[FEX-Emu](https://github.com/FEX-Emu/FEX)**, **[Box64](https://github.com/ptitSeb/box64)** —
  already lower AVX to ARM NEON (128-bit), i.e. the identical 256→2×128 problem with
  the identical missing-register-file constraint. **Their IR is the reference for
  lowering semantics.** They target ARM hosts; nobody has built the x86→x86 case.
- **Intel SDE** — the runtime alternative, and the performance baseline to beat.
- **Egalito**, **Multiverse**, **RetroWrite** — static rewriters, ELF-focused.

---

## Milestones

| # | Deliverable | Proves | Status |
|---|---|---|---|
| 0 | Full VEX inventory across all 58 MB of `.text` | Scope | **DONE** — see Measurements |
| 0.5 | Operand-level re-measurement on the unpacked binary (`tool/vex_scan.py`) | Lowering rules can be costed and scoped from measured operand shapes, not a mnemonic histogram | **DONE** — Findings 5-8 |
| 1 | Lowering rules + unit test harness, no rewriting | Semantics are right | **DONE** (Finding 119). `make check-vex` runs the ORIGINAL VEX under `qemu-x86_64`, which translates rather than dispatches and so executes it on a host with no AVX, against `lower_vex`'s bytes running natively -- 1,631 comparisons over all sixteen registers, 0 unexplained. That is the differential harness this row asked for, with the instruction itself as the reference rather than the compiler. The AVX host was never needed; the emulator was already installed. Previously: **PARTLY** — rules in `tool/lower.py`, **100% coverage**, every lowering assembles with no VEX left. F16C is implemented and exhaustively tested. Class A/B/C lowerings are now **executed** and checked against GCC's SSE intrinsics (Finding 31), which is the differential harness this row asked for, minus the AVX host: the reference is the compiler rather than the original instruction, because no AVX exists here to run. |
| 2 | Rewrite a small self-built `/arch:AVX2` PE end-to-end | Toolchain works | **DONE** (Finding 32). `tool/pe_build.py` writes the PE, the rewriter rewrites it, and `make check-pe` runs both under wine: the original dies of an illegal instruction and the rewritten one returns 169. Assembled with `as` rather than MSVC, there being no mingw here. |
| 2.5 | Strip Steam DRM with Steamless | `.bind` out of the way before rewriting | **DONE** — SteamStub 3.1 (x64), unpacked cleanly, OEP recovered |
| 3 | Ddisasm round-trip of Starfield.exe with **no** modifications | Disassembly/reassembly is sound — was the biggest single risk, and is now worth a measured ~2,000 sites | **BLOCKED on memory, and off the critical path.** Needs ~90 GB; the machine has 47 (Finding 12). The PGO warning is a caution rather than a blocker (Finding 13). Milestone 4 was reached without it, and Finding 62 counts what it would still buy. |
| 4 | Classes A/B/C/Z only (~97% of sites) | Still crashes, but later — measurable progress | **DONE for A/B/C/Z** — in place (Finding 14), by detour (Finding 15), with widened windows once the indirect targets were enumerated (Finding 16). **797,907 of 805,131 VEX sites, 99.1%** (Findings 24 to 138), with no Ddisasm and no relocation of existing code. The higher figures this row carried before were inflated by the 256-bit truncation of Finding 37. |
| 5 | Y1 peephole + Class F | Covers 94% of 256-bit usage | **Now a prerequisite rather than polish**, and part-built. Finding 37 showed 256-bit sites were being silently truncated and they are refused now. The adjacent copy pair (Findings 38, 41, 42 and 43, 5,881 sites) and the zero fill (Findings 40 and 44, 9,806 sites) are done and need no register model; the 12,552 stores and 11,226 loads that remain do. **Finding 133 scoped what that model would cost and Finding 133's own correction priced it: 212 sites for a straight-line span, because a span is worth nothing unless every value it tracks dies inside it.** |
| 6 | Y2 shadow + Class H helpers | Completeness | **PART-BUILT, and the two halves are at different stages.** The Class H helpers are written and exhaustively tested -- `src/f16c.c`, `src/permil.c`, `src/permd.c`, `src/fmaddsub.c`, through `make check-f16c`, `check-f16c-oracle`, `check-permil`, `check-permd` and `check-fmaddsub`, all in `make check` -- but **the rewriter calls none of them and nothing links one into a PE**. The one Class H form `tool/detour.py` does lower is `vpermilps` with a control vector, and it is *inlined* as the `pshufb` sequence rather than called (`lower_permilps`, because a `call` inside a stub pushes a return address into code with no `.pdata`); `make check-pe`'s `permilps` fixture runs that lowering under wine. `vpermd`, `vperm2f128`, `vpermq`, `vpermpd`, `vcvtph2ps`/`vcvtps2ph` and `vfmsubadd*` all reach `lower: no direct SSE form and not a sequence` and are refused. In `tool/lower.py` the rules are thinner than the helpers: `vpermd` emits a bare `call permd` with no operand marshalling, and both F16C mnemonics are class `HELPER` with **no body at all**, so `make verify` never assembles them. **The Y2 shadow does not exist anywhere.** Two rules name it -- `Y2/extract` and `Y2/insert`, emitting the pseudo-operand `shadow(%reg)` -- and `verify` rewrites that to `(%rsp)` before assembling, so no shadow slot has ever been allocated, written or executed. `tool/detour.py` has no shadow area: its `shadow` is a helper *register* for Finding 50's gapped copy, and `lower_ymm_pair` states in terms that what it leaves behind **is** the Y2 case. Finding 7's 574 sites are untouched. |

**Milestone 3 was the go/no-go, and the project routed around it.** That sentence stood
for a design in which every rewrite went through a reassembleable IR, and it was right for
that design: if Ddisasm could not round-trip a 102 MB binary, nothing downstream mattered.
Milestone 4 was then reached **with no Ddisasm and no relocation of existing code**, by
patching in place where the SSE form fits and detouring where it does not.

So the question is no longer whether the project can proceed without it, but what it would
still be worth -- and the residue says less than it looks. Counting the surviving 18,757
sites by whether full reassembly would help:

```
positional -- would be dissolved by being able to move code
  next instruction is a branch target        511
  next instruction transfers control         424
  window overlapped an earlier one         1,041
  ymm store is a branch target                25
                                          ~2,000

semantic -- would survive any rewriting approach
  256-bit needing a register representation ~6,800
  no scratch register available             ~3,344
  no direct SSE form                           592
  the code oracle cannot vouch for the site    403
```

The rest is the refused-stub bucket, mixed and mostly 256-bit. **Roughly two thousand of
the eighteen thousand are positional.** Being able to move code freely removes the window
shapes and none of the register pressure, so milestone 3 is worth about 11% of what is
left rather than being the thing everything depends on. It is demoted here from the
biggest single risk to a measured 2,000 sites, still blocked on memory, and no longer on
the critical path.

**Milestone 3 now has a ground truth to check against.** Finding 8 enumerates 744
islands inside `.text` that a linear sweep cannot decode — data the disassembler must
classify as data. Auditing Ddisasm's code/data split against that list turns "did the
round-trip work?" from a yes/no impression into a check with a denominator, and it can
be run before any rewriting exists. Do that first; it is the cheapest possible probe of
the project's largest risk.

---

## Open questions

- ~~Does Ddisasm handle a 102 MB PE at all? Runtime and memory footprint unknown.~~
  **Resolved: not on 47 GB.** ~90 GB projected, `std::bad_alloc` at 34.3 GB observed.
  Finding 12.
- ~~**Does Ddisasm's lack of PGO support sink the approach?**~~ **Resolved so far as
  it can be here: no.** The warning fires on an LTCG section map that ordinary MSVC
  builds carry; four binaries carrying it disassemble with a clean code/data split.
  Finding 13. What remains untested is whether that holds sixty times larger, which
  needs the machine Finding 12 asks for.
- **New: what assembles the output?** `gtirb-pprinter` emits MASM for a PE target, so
  the reassembly step needs `ml64` or `uasm`, neither of which is on this machine.
- ~~Is the 4 MB sample representative?~~ **No — resolved by milestone 0.** Real VEX
  density is 4.84%, not 12.4%, and the sample missed FMA and 256-bit arithmetic
  entirely. No `vpgather*` or `vpsrav*` anywhere, which was the main scoping fear.
- ~~`vfmaddcsh` appears exactly once — misdecode?~~ **Resolved: yes, confirmed
  misdecode.** Located at `0x14899ff74`, which is inside **`.bind`** (Steam DRM), not
  `.text`. Its neighbours decode as `fimuls`, `es add`, `rex.WR xchg`, `lret`, `int1`
  and two `(bad)` — high-entropy packed data, not code. This found the DRM wrapper and
  the `.bind`-marked-`CODE` scanning bug, so it was worth chasing.
- ~~Does the Steam stub checksum `.text`?~~ **Moot — the stub is gone.** Steamless
  removes `.bind` entirely, so nothing remains to validate the code section.
- Does `target.exe.unpacked.exe` actually launch? It should still require Steam and a
  valid licence, and will still die on the same AVX instruction — so this only proves
  the unpack didn't break anything. Worth confirming before building on it.
- ~~How many of the 73 `vpermilps` use the immediate form (→ `shufps`) versus the
  variable form (→ helper)?~~ **Resolved: 50 immediate, 23 variable.** Class H drops
  from 138 sites to 87.
- ~~Is any of `.text` hand-written assembly?~~ **Resolved: yes.** Finding 5 — a
  CPUID/XGETBV-dispatched AVX-512 checksum kernel that `/arch:AVX2` cannot have
  emitted. The JIT half of the question is still open.
- ~~Is the Y2 shadow path needed at all, or does Y1 cover every 256-bit site?~~
  **Resolved: needed, 574 sites (4.38% of ymm defs).** Finding 7.
- ~~**New: does the rewriter preserve the ISA dispatcher exactly?**~~ **Resolved:
  yes, and it is checked now.** Every one of the ten functions holding a feature test
  was compared instruction by instruction; eight are byte-identical and the two that
  differ are informational, differing only at VEX sites. `tool/isa_guard.py` runs from
  `detour.py verify` and rejects a corrupted copy before it will pass. Finding 121.
- ~~**New: are there other dispatched ISA paths?**~~ **Resolved: seven of them.** All
  32 `cpuid` and 2 `xgetbv` sites are read and classified -- seven ISA dispatchers, two
  vendor tests, two informational. Four of the seven check no OSXSAVE bit and no XCR0
  state, so they are safe here because the CPUID bits are zero rather than because an
  OS-state check says so. Finding 121.
- ~~**New: what is milestone 0's 208,054 3-operand count actually counting?**~~
  **Resolved: nothing.** Re-measured under nine definitions -- registers only, immediates
  admitted or not, SIMD registers only, memory src2 included or not, 256-bit in or out --
  and no combination produces 208,054; the nearest measurable neighbours bracket it at
  204,479 and 210,500. Its companion 126,576 is not merely unmatched but arithmetically
  impossible beside it: any 208,054-site subset of the 210,500 all-register population
  has at least 131,912 extra movs, and every way of growing the 184,260 no-immediate
  population up to 208,054 raises the extra-mov share rather than lowering it. The stated
  23.6%/76.4% split is wrong too -- Class B measures 30.3%, 36.2% or 37.7% depending on
  the definition, never 23.6%. **Milestone 0's three-operand lines are wrong and Finding
  6's replace them**; Finding 6's own bracketing figures are 5 and 110 low (178,311 and
  62,883 measured). Finding 120.
- ~~**New: is static TLS actually available, or only believed to be?**~~ **Resolved
  for the file format, and it is a check now.** `make check-tls` builds a PE whose TLS
  directory asks for 32 zero-filled bytes per thread and reads them back through
  `%gs:0x58`; a sweep of 0, 8, 16 and 32 returns three distinct failures before the
  pass, so the test measures the field rather than merely observing that some bytes
  arrived. Finding 138. **Still open: the addressing, and it is worth 67 sites rather than
  740.** Finding 139 re-took the price: the form is TWO registers rather than one,
  because the block is `*(*(gs:[0x58]) + index*8)` and the index is in memory, and only
  67 of the 1,332 have two of `r8`-`r11` free by the whole-function argument. 500 more
  are refused only by that argument's bluntness, so 67 is a floor and the per-position
  machinery that would raise it already exists.
- Does anything depend on exact FP reproducibility? Class F breaks bit-exactness, and
  `vfmaddsub`/`vfmsubadd` (28 sites) break *correctness* if lowered as plain FMA.
- ~~**Who writes the F16C software routine, and is it correct at the edges?**~~
  **Resolved: `src/f16c.c`.** Exhaustive in both directions against a scalar
  reference, and that reference checked against CPython's binary16. The one part
  still unverified is NaN *payload* behaviour, which needs F16C hardware — see
  Finding 10.
- ~~**New: the differential harness still has no AVX host.**~~ **Resolved: it does,
  and it was installed.** `qemu-x86_64` translates rather than dispatches, so it runs
  VEX on a machine that has none. `make check-vex` executes the original instruction
  under it and the lowering natively, comparing all sixteen registers: 1,631
  comparisons, 0 unexplained. Finding 119. What is corroborated against silicon is the
  arithmetic; the lane structure rests on qemu.
- ~~Does Starfield ship a Steam DRM wrapper?~~ **Resolved: yes.** `.bind`, 234 KB,
  owns the PE entry point. See "The hard parts" §4.
- Is any of `.text` hand-written assembly or JIT-generated? Both break assumptions.
- The binary uses FMA and `vperm*`, so it genuinely requires **AVX2**, not just AVX1
  as the sample suggested. It also *contains* AVX-512, but behind a runtime check
  (Finding 5), so AVX2 remains the true hardware requirement.
- Is a general tool worth building versus a one-off patch? A working VEX→SSE pass on
  Ddisasm would unlock **every** `/arch:AVX2`-baseline title on pre-2011 hardware,
  which is a much larger prize than one game.

---

## Honest assessment

This is a hard but *bounded* engineering project, not a research dead-end. The
performance argument against it does not hold — the measured instruction mix means a
translated binary should run at near-native speed.

That was written when the risk looked concentrated in milestone 3 -- sound disassembly
and reassembly of a large stripped PE -- and in verification. **Half of it has moved.**
Milestone 3 was routed around rather than solved.

**What is left is 7,224 sites of 805,131, and it is not evenly hard.** 2,599 are 128-bit
and measured to their floor: nine in ten of what still refuses is the program genuinely
using the memory the rewriter wanted to borrow, so no analysis reaches them and only the
rewriter's own memory will -- static TLS, whose file format is proven and whose addressing
is not built. 4,445 are 256-bit and are one problem: a value that exists only in a
register no SSE instruction can reach. That problem has been scoped twice now, and the
local answer is worth 212 sites while the general one is a whole-function rewrite nobody
has started.

**The honest reading is that the remaining work is smaller than it was and harder per
site.** Every cheap mechanism is built; what is left needs either a new place to put
bytes or a real representation change, and both are named, priced and unstarted.

Verification is where the risk actually concentrated, and it earned that. Four defects
here produced silently wrong output while passing every structural check -- the `src2`
alias computing a constant zero, the `VEX.L` truncation storing half of every 256-bit
write, a liveness scan that could not see a `%ymm` operand and handed out 233 live
registers, and an exception that could not be dispatched from inside a stub. Every one was
caught by asking what the code computes rather than what shape it has, and two of the
checks that should have caught them earlier could not: one shared a function with the code
it checked, and one was empty by construction.

**The target now runs, which changes the character of the remaining work rather than the
size of it.** Finding 74 put the rewritten binary 866 bytes past where the original dies,
through four lowerings and one stub, with wine's unwinder validating the rebuilt function
table independently of the tool that wrote it. That number was the point: the residue is
not a tail of exotic cases waiting at the end of a long run, it is dense enough to be hit
immediately, and every one of the 8,450 that remain has to go before any of this can be
soaked.

**What the run adds is a measuring instrument, and it has been the better half of the
method since.** Each fault address names the next site, that site has named a strategy
five times running -- Findings 106 to 110 -- and twice it named something the census had
filed under the wrong cause. The frontier is at `0x1428D1492` now, 305 modules in, and it
names a 256-bit store of a register a `vpxor` emptied six instructions above it, refused
because a `.pdata` function start lies in between.

Reproduce the measurements with:

```bash
objdump -d --start-address=0x141000000 --stop-address=0x141400000 Starfield.exe > sf.asm
grep -cP "\tv[a-z0-9]+ " sf.asm                    # VEX total
grep -cP "\tv[a-z0-9]+ .*ymm" sf.asm               # 256-bit
grep -oP "\tv[a-z0-9]+ " sf.asm | sort | uniq -c | sort -rn   # inventory
```
