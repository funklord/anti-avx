# anti-avx — ahead-of-time AVX→SSE binary translation

First read ~/.claude/CLAUDE.md for core directives

Static rewriting of x86-64 PE binaries built with a whole-program `/arch:AVX` or
`/arch:AVX2` baseline, so they run on CPUs without AVX.

**Status:** design, measurement, and the lowering rules. The translator itself is not
written. `src/f16c.c` is the only compiled code and is complete.

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
the mnemonic is spelled**. `tools/vex_scan.py` re-counts by **the encoding bytes** — a
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
python3 tools/vex_scan.py text.asm                       # ~75 s, ~1.1 GB RSS
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
bug, not a precision one — `tests/fmaddsub_test.c` demonstrates it rather than
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
than a pervasive one. The full address list is what `tools/vex_scan.py` prints; a
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

`tools/lower.py` carries a rule for every VEX mnemonic and reports what it cannot
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
  `tools/run_ddisasm.sh` runs it under `prlimit` and a `timeout`.
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

`tools/patch.py`, `make patch`. Verified on the real binary:

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

Class C cannot be rewritten in place: four bytes become seven. `tools/detour.py`
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
enumerated, and `tools/targets.py` does it from four sources:

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
`tools/scratch.py` answers it, and the first thing to say is what it does **not** do.

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
Xeon X5675 with a 32 KB 4-way L1i. `tools/icache_bench.c` generates the same loop
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
the question. `tools/placement.py`, `make placement`.

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

`tools/outside.py`, `make outside`, answers it. The first attempt got it wrong in a
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

`tools/lowering_cases.py` generates the cases from `detour.lower_vex` itself, so they
cannot drift from what the rewriter emits, and `tests/lowering_test.c` runs them.
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

`make check-pe`, five seconds from clean. There is no mingw here, so `tools/pe_build.py`
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

`tools/lowering_cases.py` carries nine 256-bit forms it asserts are *refused*,
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
pair rule. `tools/scratch.py` already follows edges without building a CFG -- an
unconditional jump has one successor, a conditional has two and the answer is the
intersection -- and the same traversal answers this question. It is the obvious next
increment on Class Y, and it is a bigger change than this one because the walker is
written around register sets rather than around a single yes/no.

### Finding 42 -- the same edges, followed twice

Finding 41 left 2,617 pairs stopping at a branch, and named the fix rather than making
it: `tools/scratch.py` already follows edges without building a CFG, and Finding 27
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

`tools/detour.py --spill=none|stack|pool` selects where a borrowed register is saved.
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

`wine` is not Windows and its unwinder is a reimplementation, so the 5 is strong evidence
about the mechanism and not proof about the shipping loader. Nothing here ran more than
one thread, so the pool's race is argued rather than measured. Both are named because an
absent gap gets guessed at.

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
the ordering under test. `tools/f16c_oracle.py` and `tests/fmaddsub_test.c` already draw
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
lowering from text rather than bytes, or a PE program of the kind `tools/pe_build.py`
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
named it as the one sequence `tools/lowering_cases.py` cannot reach, and the reason is
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

### Final state

```
in place                                      547,613
detoured                                      194,788
skipped for overlap                            36,593
refused, stub not buildable                     3,954
VEX in .text            805,131 ->      18,757   786,374 removed, 97.7%
```

Every invariant holds on a freshly built binary: the file grows only by the stub
section, every section after `.text` is byte-identical, all 78,041 lost boundaries
are instructions a widened window swallowed deliberately, none of the 82,181
swallowed is reachable by any branch, and the stub section carries 0 VEX with
exactly one jump back per detour. `make census` reconciles every survivor to a named
cause with nothing unaccounted.

**The 95.0% is honest in a way the earlier figures were not.** Findings 25 and 37 both
found silent wrongness that every structural check had passed, and the numbers before
them were inflated. Anything in this document above Finding 37 that reads higher is
counting truncated 256-bit sites as successes.

What remains:

```
ymm value has no known upper half      4,601     outside any accepted window
src2 aliases dst, no scratch           2,726     needs a register; 249 do not
ymm upper half read later              1,766     what the edges could not resolve
sequence with no usable scratch          780     needs a register
no direct SSE form                       710     mostly vextractf128/vinsertf128
next instruction is a branch target      511
no register free across the ymm run      446
next instruction transfers control       424
outside .pdata                           403
sequence shape not handled               164
ymm store is a branch target              25
operand shape not A/B/C                    9
```

Those categories account for the *collector's* refusals. The 39,880 survivors also
include the sites whose stub could not be built, which `make census` breaks out.

## Picking this up again

Everything below is what a fresh start needs and none of it is derivable from the
code quickly.

### The two decisions that are not the implementer's

1. ~~**May a stub spill?**~~ **Answered: no, and it was never a decision.** Finding 46
   showed the recorded objection was misattributed, Finding 48 removed it, and Finding
   49 tested what was left: a stub that moves `rsp` hands the unwinder a frame sixteen
   bytes wrong, because a chained fragment's own unwind codes are not applied and
   dropping the chain loses the handler entirely. `--spill=none` stays the default on
   evidence. **Re-run `sse-unwindspill.exe` on a Windows host** -- if it answers 42
   rather than 99, the limitation is wine's and 3,537 sites come back.

   What follows is kept because it is what was decided against and why.

   Spilling was rejected in `tools/scratch.py` because the stub section has no
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
   and it works. 12,552 `vmovups` stores and 11,226 loads are
   neither copies nor zero fills, and need a ymm represented as two xmm registers
   across a basic block -- register allocation, the largest single remaining win, and
   a different kind of work from anything done so far. Findings 39, 40 and 44 have
   the measurements, and Finding 44 is the one that closes the alternatives: only
   1,586 of the unresolved stores are blocked by control flow, the rest holding real
   256-bit values that no scan can reason away, and Finding 40 also names what the model must repair: the in-place
   lowerings have already destroyed the [255:128] zeroing that VEX.128 writes perform.

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
pe_build.py       builds AVX PEs so the rewriter has a target it owns
placement.py      where detours land; icache_bench.c what they cost
```

### Practical things that cost time to learn

- **Delete `tools/__pycache__` before trusting a source revert.** Python validates a
  cached `.pyc` on the source file's size and mtime, so a same-length edit reverted
  within the same second keeps executing the old bytecode -- and `git diff` is empty,
  and `inspect.getsource` reads the file rather than the code object, so both corroborate
  the wrong thing. Finding 56 lost an hour to it.
- **`build/text.asm` is the input to almost everything** and `make clean` removes it.
  Regenerating is `objdump -d -j .text Starfield-unpacked.exe > build/text.asm`,
  about 30 seconds and 0.9 GB.
- **`apply` takes about ten minutes** on the real binary, `census` and `verify`
  similar. Run them in the background and do not poll them tightly.
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
The full non-commutative inventory is in `tools/vex_scan.py`'s output.

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
> mask removed makes `tests/permil_test.c` fail on exactly the `0x20` and `0xfffffffc`
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
   reachability of everything swallowed, and that the stub section contains no VEX
   with exactly one jump back per detour.

4. **Soak.** Long gameplay sessions. **Not started.** Starfield has never been run,
   translated or otherwise; there is no Windows host here.

### The machine, because it decides what can be tested

    Xeon X5675 (Westmere), SSE4.2 + AES-NI + PCLMULQDQ, no AVX, no F16C, no FMA
    Linux, wine 10.0, binutils as/objdump/objcopy, gcc -- and no mingw

**The absence of AVX is the project's premise and its best test instrument.** This
CPU cannot execute the input and can execute the output, so "the original must
crash and the rewritten one must work" is a real experiment rather than a wish. It
is also why every reference has to come from somewhere other than the original
instruction.

The absence of mingw is why `tools/pe_build.py` writes PE headers by hand rather
than compiling with MSVC or a cross-compiler.

### What each check proves, and what it does not

| check | proves | does not touch |
|---|---|---|
| `make style` | tabs, alignment, ASCII, and that documents name no missing file | anything about behaviour |
| `make verify` | every lowering rule assembles, and no VEX or EVEX prefix survives | what any of them computes |
| `make check-aliasing` | no lowering reads a register it has already overwritten -- symbolically, over 18 operand shapes | arithmetic; it simulates moves rather than running them |
| `make check-lowering` | 51 mnemonics over four operand shapes, one with src2 in memory; `vblendvps`/`vblendvpd` across all five register arrangements their lowering branches on; ten FMA orderings; and the broadcasts through memory. Every one of 16 registers matching GCC's SSE intrinsic over 8 input patterns including three all-NaN | 256-bit, `vpermilps`, and any lowering whose destination is a general-purpose register -- Findings 54 to 57 count them |
| `make check-f16c`, `check-fmaddsub`, `check-permil`, `check-permd` | the helpers, exhaustively -- both F16C directions, all 256 permute controls, all 16,777,216 `vpermd` index sets | that the rewriter *calls* them; they are not wired in yet |
| `make check-pe` | fourteen PEs built here, rewritten, and run under wine: originals die of an illegal instruction, rewritten ones return the right answers | scale, and anything Starfield does that these do not |
| `make scratch-check` | every register claimed as scratch is written before read on every path, by enumerating paths rather than intersecting sets | the ABI half of the whole-function argument, which no tool can check. It shared `xmm_numbers` with the code it checks until Finding 52, and so could not see a `%ymm` operand either |
| `make detour-verify` | on Starfield: size, section identity, boundary reconciliation, stub integrity, that the rebuilt function table is sorted and covers every stub byte, and that all 1,191,070 direct branch targets still begin an instruction | **semantics -- every one of these is about shape.** Indirect branch targets have no witness but `targets.py`, which the collector also used -- Finding 53 |
| `make check-spill` | that all three ways of getting a scratch register round-trip it, and that the default still refuses the site | anything about a second thread, or about unwinding |
| `make check-unwind` | that a handler registered through `.pdata` is reached from `.text` and from inside a stub, and that a stub which moved `rsp` still hands it a frame 16 bytes wrong | whether the shipping Windows unwinder agrees with wine's |
| `make bench`, `make placement` | what a detour costs on this CPU, and where detours land structurally | which code is hot, which needs the game running |

The row to keep in mind is `detour-verify`. It is the only check that runs against
the real target, and it is entirely structural. **Everything known about Starfield's
translation is that it is well formed.** The semantic evidence all comes from small
things: the lowerings executed in isolation, and fourteen PEs built for the purpose.

### What is still not verified

Named rather than left implicit, because an absent gap gets guessed at:

- **Starfield has never been run.** No Windows host, and 10,618 VEX sites survive
  anyway, so it would not get far.
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
| 0.5 | Operand-level re-measurement on the unpacked binary (`tools/vex_scan.py`) | Lowering rules can be costed and scoped from measured operand shapes, not a mnemonic histogram | **DONE** — Findings 5-8 |
| 1 | Lowering rules + unit test harness, no rewriting | Semantics are right | **PARTLY** — rules in `tools/lower.py`, **100% coverage**, every lowering assembles with no VEX left. F16C is implemented and exhaustively tested. Class A/B/C lowerings are now **executed** and checked against GCC's SSE intrinsics (Finding 31), which is the differential harness this row asked for, minus the AVX host: the reference is the compiler rather than the original instruction, because no AVX exists here to run. |
| 2 | Rewrite a small self-built `/arch:AVX2` PE end-to-end | Toolchain works | **DONE** (Finding 32). `tools/pe_build.py` writes the PE, the rewriter rewrites it, and `make check-pe` runs both under wine: the original dies of an illegal instruction and the rewritten one returns 169. Assembled with `as` rather than MSVC, there being no mingw here. |
| 2.5 | Strip Steam DRM with Steamless | `.bind` out of the way before rewriting | **DONE** — SteamStub 3.1 (x64), unpacked cleanly, OEP recovered |
| 3 | Ddisasm round-trip of Starfield.exe with **no** modifications | Disassembly/reassembly is sound — the biggest single risk | **BLOCKED on memory, not on PGO.** Needs ~90 GB; the machine has 47 (Finding 12). The PGO warning was evaluated separately and is a caution rather than a blocker (Finding 13). |
| 4 | Classes A/B/C/Z only (~97% of sites) | Still crashes, but later — measurable progress | **DONE for A/B/C/Z** — in place (Finding 14), by detour (Finding 15), with widened windows once the indirect targets were enumerated (Finding 16). **786,374 of 805,131 VEX sites, 97.7%** (Findings 24 to 52), with no Ddisasm and no relocation of existing code. The higher figures this row carried before were inflated by the 256-bit truncation of Finding 37. |
| 5 | Y1 peephole + Class F | Covers 94% of 256-bit usage | **Now a prerequisite rather than polish**, and part-built. Finding 37 showed 256-bit sites were being silently truncated and they are refused now. The adjacent copy pair (Findings 38, 41, 42 and 43, 5,881 sites) and the zero fill (Findings 40 and 44, 9,806 sites) are done and need no register model; the 12,552 stores and 11,226 loads that remain do. |
| 6 | Y2 shadow + Class H helpers | Completeness | |

**Milestone 3 is the go/no-go.** If Ddisasm cannot round-trip a 102 MB game binary
unmodified, nothing downstream matters and the project stops there.

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
- **New: does the rewriter preserve the ISA dispatcher exactly?** Finding 5 makes this
  load-bearing. 179 AVX-512 instructions are unreachable *only because* the feature
  detection at `0x1434ddd40` says so on a Westmere. This is a failure mode the design
  did not previously have, and it needs a verification check of its own.
- **New: are there other dispatched ISA paths?** There are 32 `cpuid` sites and 2
  `xgetbv` sites in `.text`. Only one dispatcher has been read. If a library selects an
  AVX2 path behind a check the rewriter perturbs, the same risk applies at 256 bits.
- **New: what is milestone 0's 208,054 3-operand count actually counting?** It sits
  between the register-only figure (178,306) and the full one (275,586), and its stated
  76.4% Class C share disagrees with its own 126,576 extra-mov figure. Flagged in
  Finding 6 rather than resolved, because the answer decides which document is wrong.
- Does anything depend on exact FP reproducibility? Class F breaks bit-exactness, and
  `vfmaddsub`/`vfmsubadd` (28 sites) break *correctness* if lowered as plain FMA.
- ~~**Who writes the F16C software routine, and is it correct at the edges?**~~
  **Resolved: `src/f16c.c`.** Exhaustive in both directions against a scalar
  reference, and that reference checked against CPython's binary16. The one part
  still unverified is NaN *payload* behaviour, which needs F16C hardware — see
  Finding 10.
- **New: the differential harness still has no AVX host.** `tools/lower.py verify`
  proves the emitted SSE assembles and contains no VEX; it does **not** prove the
  SSE computes what the VEX did. That needs either a machine with AVX or a software
  model of the VEX semantics, and until one exists milestone 1 is only half done.
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

The risk is concentrated almost entirely in milestone 3 (sound disassembly and
reassembly of a large stripped PE) and in verification. Both are known-hard rather
than unknown-hard.

Reproduce the measurements with:

```bash
objdump -d --start-address=0x141000000 --stop-address=0x141400000 Starfield.exe > sf.asm
grep -cP "\tv[a-z0-9]+ " sf.asm                    # VEX total
grep -cP "\tv[a-z0-9]+ .*ymm" sf.asm               # 256-bit
grep -oP "\tv[a-z0-9]+ " sf.asm | sort | uniq -c | sort -rn   # inventory
```
