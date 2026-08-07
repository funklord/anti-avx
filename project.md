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

Correctness cannot be established by "it booted." Proposed ladder:

1. **Unit-level.** For each lowering rule, generate a test harness executing the VEX
   form on an AVX host and the SSE form on both, comparing full register and flag
   state across randomised inputs. Flags matter — `comiss`/`ucomiss` set them.

2. **Differential tracing.** Run original on an AVX machine and translated on the
   host under a tracer, comparing architectural state at basic-block boundaries.
   Divergence localises the faulty rule. Expensive but decisive.

3. **Static self-check.** After rewriting, assert no VEX encodings remain
   (`objdump -d | grep -cP '\tv[a-z0-9]+ '` → 0) and that every original function
   entry has a valid `.pdata` entry pointing at it.

4. **Soak.** Long gameplay sessions; exception-handling paths are the least exercised
   and most likely to be broken by bad `.xdata`.

A translated binary that is 99.99% correct is worthless — the remaining 0.01% is a
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
| 1 | Lowering rules + unit test harness, no rewriting | Semantics are right | **PARTLY** — rules in `tools/lower.py`, **100% coverage**, every lowering assembles with no VEX left. F16C is implemented and exhaustively tested. The differential harness against an AVX host is not built. |
| 2 | Rewrite a small self-built `/arch:AVX2` PE end-to-end | Toolchain works | |
| 2.5 | Strip Steam DRM with Steamless | `.bind` out of the way before rewriting | **DONE** — SteamStub 3.1 (x64), unpacked cleanly, OEP recovered |
| 3 | Ddisasm round-trip of Starfield.exe with **no** modifications | Disassembly/reassembly is sound — the biggest single risk | **FAILS on this hardware** — see Finding 12. Needs ~90 GB; the machine has 47. And ddisasm reports the binary as PGO-built, which it does not support. |
| 4 | Classes A/B/C/Z only (~97% of sites) | Still crashes, but later — measurable progress | |
| 5 | Y1 peephole + Class F | Covers 94% of 256-bit usage | |
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
- **New: does Ddisasm's lack of PGO support sink the approach?** It warns on every
  run. This is the open question that now matters most, and it is a correctness
  question rather than a capacity one.
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
