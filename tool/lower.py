#!/usr/bin/env python3
"""The VEX to SSE lowering rules, and a proof that they assemble.

This is milestone 1: the rules, with no rewriting. It answers two questions
the measurement could not.

  * **Is every VEX site in the binary covered by a rule?** `coverage` reads
    an objdump listing and reports, per mnemonic, which sites have a rule
    and which do not. A gap here is a site the translator would have to
    give up on, so the gap list is the real output.

  * **Does the SSE the rules emit actually exist on the host?** `verify`
    emits every lowering as assembly, assembles it, and disassembles the
    result. A sequence that fails to assemble, or that still contains a
    VEX prefix, is refused. The rules cannot claim to lower anything they
    have not been through an assembler.

The host baseline is Westmere: SSE through SSE4.2, plus AES-NI and
PCLMULQDQ. No AVX, no AVX2, no FMA, and -- the one that catches people --
**no F16C**, which arrived with Ivy Bridge two years later.
"""

import re
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

# What the host can execute. PCLMULQDQ and AES-NI are on Westmere, which is
# why vpclmul* lowers directly; F16C and BMI are not.
HOST_BASELINE = "Westmere: SSE4.2 + AES-NI + PCLMULQDQ"

# Lowering categories.
#
# ELIDE     the instruction disappears entirely
# DIRECT    strip the leading v; operand order and count unchanged
# NDS       three-operand non-destructive source; needs the Class B/C rules
# SEQUENCE  no single SSE instruction exists; emit several
# HELPER    no compact sequence exists; call an out-of-line routine
# GAP       no lowering known -- the translator must refuse the binary
ELIDE, DIRECT, NDS, SEQUENCE, HELPER, GAP = (
	"elide", "direct", "nds", "sequence", "helper", "gap",
)

# Instructions whose SSE form is the VEX mnemonic with the v removed, and
# whose VEX form is two-operand (dst is written whole, or is memory). These
# lower one-to-one with no register juggling at all.
DIRECT_MNEMONICS = frozenset("""
	vmovss vmovsd vmovups vmovaps vmovupd vmovapd vmovdqu vmovdqa
	vmovd vmovq vmovntps vmovddup vmovshdup vmovlps vmovhpd
	vcomiss vcomisd vucomiss vucomisd vptest
	vsqrtps vsqrtpd vrcpps vrsqrtps vroundps vroundpd
	vmovmskps vmovmskpd vpmovmskb
	vextractps vpextrb vpextrw vpextrd vpextrq
	vpshufd vpshuflw vpshufhw
	vldmxcsr vstmxcsr
	vcvttss2si vcvttsd2si vcvtss2si vcvtsd2si
	vcvtps2pd vcvtpd2ps vcvtpd2psx vcvtdq2ps vcvtps2dq vcvttps2dq
	vcvtdq2pd vcvtpd2dq vcvttpd2dq
	vpmovzxbd vpmovzxwd vpmovzxdq vpmovzxwq vpmovzxbw vpmovzxbq
	vpmovsxbd vpmovsxwd vpmovsxdq vpmovsxwq vpmovsxbw vpmovsxbq
""".split())

# Three-operand non-destructive-source forms. The SSE mnemonic is again the
# v stripped, but SSE is two-operand and destructive, so dst must already
# hold src1 -- which is what the Class B / C / C-alias rules arrange.
NDS_MNEMONICS = frozenset("""
	vaddss vaddsd vaddps vaddpd vsubss vsubsd vsubps vsubpd
	vmulss vmulsd vmulps vmulpd vdivss vdivsd vdivps vdivpd
	vminss vminsd vminps vminpd vmaxss vmaxsd vmaxps vmaxpd
	vsqrtss vsqrtsd vroundss vroundsd
	vandps vandpd vandnps vandnpd vorps vorpd vxorps vxorpd
	vpand vpandn vpor vpxor
	vpaddb vpaddw vpaddd vpaddq vpsubb vpsubw vpsubd vpsubq
	vpsubusw vpsubusb vpaddusw vpaddusb
	vpmulld vpmullw vpmuludq vpmaddwd vpmaddubsw vpsadbw
	vpcmpeqb vpcmpeqw vpcmpeqd vpcmpeqq
	vpcmpgtb vpcmpgtw vpcmpgtd vpcmpgtq
	vpmaxud vpmaxub vpmaxsw vpminud vpminub vpminsw
	vunpcklps vunpcklpd vunpckhps vunpckhpd
	vpunpcklbw vpunpcklwd vpunpckldq vpunpcklqdq
	vpunpckhbw vpunpckhwd vpunpckhdq vpunpckhqdq
	vshufps vshufpd vblendps vblendpd vpblendw vdpps vdppd
	vhaddps vhaddpd vhsubps vhsubpd vaddsubps vaddsubpd
	vpackssdw vpacksswb vpackuswb vpackusdw
	vpshufb vphsubd vphaddd vphsubw vphaddw
	vpsllw vpslld vpsllq vpsrlw vpsrld vpsrlq vpsraw vpsrad
	vpslldq vpsrldq
	vinsertps vpinsrb vpinsrw vpinsrd vpinsrq
	vmovlhps vmovhlps
	vpclmullqlqdq vpclmulhqhqdq vpclmullqhqdq vpclmulhqlqdq vpclmulqdq
	vmovss vmovsd vmovhpd vmovlpd vmovhps vmovlps
	vcvtsi2ss vcvtsi2sd vcvtsi2ssl vcvtsi2ssq vcvtsi2sdl vcvtsi2sdq
	vcvtss2sd vcvtsd2ss
""".split())

# objdump disambiguates a few converts by appending an operand-size letter
# that the SSE mnemonic does not carry. Mapping them is not cosmetic: the
# assembler rejects the suffixed spelling outright.
SPECIAL_SSE_NAME = {
	"vcvtpd2psx": "cvtpd2ps",
	"vcvtpd2psy": "cvtpd2ps",
	"vcvtpd2dqx": "cvtpd2dq",
	"vcvtpd2dqy": "cvtpd2dq",
	"vcvttpd2dqx": "cvttpd2dq",
	"vcvttpd2dqy": "cvttpd2dq",
}

# The pclmul pseudo-mnemonics encode their immediate in the name, so the SSE
# form takes two operands where the general vpclmulqdq takes three.
PCLMUL_PSEUDO = frozenset(("vpclmullqlqdq", "vpclmulhqhqdq",
                            "vpclmullqhqdq", "vpclmulhqlqdq"))

# These appear in both tables deliberately: the load and store forms are
# two-operand and DIRECT, while the register merge form is three-operand and
# NDS. Which applies is decided per site by the operand count, not by the
# mnemonic. Getting it wrong silently drops the merge, which for vmovss
# means the upper three quarters of the destination stop being preserved.
DUAL_FORM = frozenset(("vmovss", "vmovsd", "vmovhpd", "vmovlpd",
                        "vmovhps", "vmovlps"))

# The SSE packed-compare predicates, in encoding order. SSE has eight; AVX
# extended the field to thirty-two, and the compiler used some of the new
# ones. Those need more than a mnemonic change -- see AVX_PREDICATES.
SSE_PREDICATES = ("eq", "lt", "le", "unord", "neq", "nlt", "nle", "ord")

# AVX-only compare predicates found in this binary, and what each becomes.
#
# The _oq/_uq suffixes are the *quiet* variants of predicates SSE already
# has in signalling form. With exceptions masked -- which is every normal
# process -- they compute the same result and differ only in whether a
# signalling NaN raises. So they map to the SSE predicate directly, and the
# difference is recorded rather than hidden.
#
# cmpgt_oq is the one that is not cosmetic. **SSE has no greater-than
# predicate at all**; the eight it has are listed above. A greater-than must
# become a less-than with the operands exchanged, which is a real rewrite
# and changes which operand the destination has to hold.
AVX_PREDICATES = {
	"nle_uq": ("nle", False, "quiet variant of nle; identical result with "
	                          "exceptions masked"),
	"le_oq": ("le", False, "quiet variant of le; identical result with "
	                        "exceptions masked"),
	"gt_oq": ("lt", True, "SSE HAS NO GT PREDICATE -- lowers to lt with the "
	                       "operands exchanged"),
	"ge_oq": ("le", True, "SSE has no GE predicate -- lowers to le with the "
	                       "operands exchanged"),
	"lt_oq": ("lt", False, "quiet variant of lt"),
	"neq_oq": ("neq", False, "quiet variant of neq"),
}

# Multi-instruction lowerings. Each entry is a short identifier for the
# strategy plus the note that explains it; the sequence itself is built by
# lower(), which needs the operands.
SEQUENCE_MNEMONICS = {
	"vbroadcastss": "movss + shufps $0 (memory source) -- see lower()",
	"vbroadcastsd": "movsd + unpcklpd (memory source)",
	"vpbroadcastd": "movd + pshufd $0",
	"vpbroadcastw": "movd + pshuflw/pshufd",
	"vblendvps": "blendvps takes its mask in an implicit %xmm0",
	"vblendvpd": "blendvpd takes its mask in an implicit %xmm0",
	"vpblendvb": "pblendvb takes its mask in an implicit %xmm0",
	"vextractf128": "128-bit half extract -- Y-class, becomes a movaps",
	"vinsertf128": "128-bit half insert -- Y-class, becomes a movaps",
	"vextracti128": "128-bit half extract -- Y-class, becomes a movdqa",
	"vinserti128": "128-bit half insert -- Y-class, becomes a movdqa",
	"vpermilps": "immediate control is shufps; variable control calls a helper",
	"vperm2f128": "pure 128-bit lane selection -- moves, once halves are split",
	"vpermq": "immediate 64-bit permute across four qwords -- shufpd pairs",
	"vpermpd": "immediate 64-bit permute across four qwords -- shufpd pairs",
	"vpermd": "variable 32-bit cross-lane permute -- calls src/permd.c",
	"vzeroall": "zero all sixteen xmm registers, or the shadow slots",
}

# Cross-lane operations with no compact SSE expression. At these counts a
# call into a hand-written routine costs nothing measurable.
HELPER_MNEMONICS = {
	# F16C. The only rules here that are an algorithm rather than a
	# substitution: Westmere has no half-precision instruction of any kind,
	# so these call into src/f16c.c, which converts in integer arithmetic
	# and with an explicitly-moded roundps so that nothing depends on MXCSR.
	# See project.md, Finding 10.
	"vcvtph2ps": "software half-to-single -- f16c_ph2ps_8 in src/f16c.c",
	"vcvtps2ph": "software single-to-half -- f16c_ps2ph_8 in src/f16c.c",
	"vpermilpd": "immediate form is shufpd; only variable control needs this",
	"vpermps": "cross-lane, 256-bit only",
}

# Fused multiply-add. Westmere has none. The 132/213/231 suffix selects
# which operand is the addend, and the mapping comes from the SDM rather
# than from intuition:
#
#   vfmadd132 xmm1, xmm2, xmm3  ->  xmm1 = xmm1*xmm3 + xmm2
#   vfmadd213 xmm1, xmm2, xmm3  ->  xmm1 = xmm2*xmm1 + xmm3
#   vfmadd231 xmm1, xmm2, xmm3  ->  xmm1 = xmm2*xmm3 + xmm1
#
# All of these are NOT semantics-preserving: two roundings replace one.
FMA_PATTERN = re.compile(r"^vf(n?)(maddsub|msubadd|madd|msub)(132|213|231)"
                          r"([sp][sd])$")

# Instructions with no lowering at all on this host. Each is a reason the
# translator would have to refuse a binary, so the list is short by design
# and every entry says what is actually missing.
GAP_MNEMONICS = {
	"vgatherdps": "AVX2 gather -- no SSE analogue; needs a scalar loop.",
	"vgatherqps": "AVX2 gather -- no SSE analogue; needs a scalar loop.",
	"vgatherdpd": "AVX2 gather -- no SSE analogue; needs a scalar loop.",
	"vgatherqpd": "AVX2 gather -- no SSE analogue; needs a scalar loop.",
	"vpmaskmovd": "masked store -- needs branchy per-element emulation.",
	"vpmaskmovq": "masked store -- needs branchy per-element emulation.",
	"vmaskmovps": "masked store -- needs branchy per-element emulation.",
	"vmaskmovpd": "masked store -- needs branchy per-element emulation.",
	"vpsravd": "AVX2 variable shift -- no SSE analogue.",
	"vpsllvd": "AVX2 variable shift -- no SSE analogue.",
	"vpsrlvd": "AVX2 variable shift -- no SSE analogue.",
}

# AVX-512. Present in this binary but behind a CPUID/XGETBV dispatcher that
# cannot select it on a host without AVX, so it is passed through untouched
# rather than lowered. Recognising it is the point: a rewriter that assumes
# EVEX is absent fails to decode these.
EVEX_PASSTHROUGH = frozenset(("kmovq", "kmovd", "kmovb", "kmovw"))


def classify(mnemonic, operand_count=None):
	"""Return (category, note) for a mnemonic.

	operand_count disambiguates the mnemonics that have both a two-operand
	and a three-operand form; without it the three-operand reading is
	assumed, because that is the one needing work.
	"""
	if mnemonic == "vzeroupper":
		return ELIDE, "no AVX state exists to zero; delete it"
	if mnemonic in EVEX_PASSTHROUGH:
		return ELIDE, "AVX-512 behind a runtime dispatcher; pass through"
	if mnemonic in GAP_MNEMONICS:
		return GAP, GAP_MNEMONICS[mnemonic]
	if FMA_PATTERN.match(mnemonic):
		return SEQUENCE, "FMA -- mul + add, two roundings where hardware did one"
	if mnemonic in HELPER_MNEMONICS:
		return HELPER, HELPER_MNEMONICS[mnemonic]
	if mnemonic in SEQUENCE_MNEMONICS:
		return SEQUENCE, SEQUENCE_MNEMONICS[mnemonic]

	predicate = compare_predicate(mnemonic)
	if predicate is not None:
		name, avx_only = predicate
		if avx_only:
			sse, swap, note = AVX_PREDICATES[name]
			return (SEQUENCE if swap else NDS), f"AVX predicate {name}: {note}"
		return NDS, f"SSE compare predicate {name}"

	if mnemonic in DUAL_FORM:
		if operand_count == 2:
			return DIRECT, "two-operand load/store form"
		return NDS, "three-operand register merge form"
	if mnemonic in NDS_MNEMONICS:
		return NDS, "three-operand; Class B/C applies"
	if mnemonic in DIRECT_MNEMONICS:
		return DIRECT, "one-to-one, strip the v"
	return GAP, "no rule"


def compare_predicate(mnemonic):
	"""Split a vcmp mnemonic into its predicate, or None if it is not one.

	objdump spells these two ways: the SSE-compatible predicates appear
	folded into the mnemonic (vcmpltss), and the AVX-only ones keep their
	suffix (vcmpnle_uqps). Both have to be recognised, and only the second
	kind needs anything beyond a mnemonic change.
	"""
	if not mnemonic.startswith("vcmp"):
		return None
	body = mnemonic[4:]
	for suffix in ("ss", "sd", "ps", "pd"):
		if body.endswith(suffix):
			name = body[: -len(suffix)]
			if name in AVX_PREDICATES:
				return name, True
			if name in SSE_PREDICATES:
				return name, False
			return name, name in AVX_PREDICATES
	return None


def sse_mnemonic(mnemonic):
	"""The SSE spelling of a VEX mnemonic: strip the leading v.

	Compare predicates keep their folded form (vcmpltss -> cmpltss), which
	is how the assembler spells them too.
	"""
	if mnemonic in SPECIAL_SSE_NAME:
		return SPECIAL_SSE_NAME[mnemonic]
	predicate = compare_predicate(mnemonic)
	if predicate is not None:
		name, avx_only = predicate
		if avx_only:
			sse, _swap, _note = AVX_PREDICATES[name]
			suffix = mnemonic[-2:]
			return f"cmp{sse}{suffix}"
	return mnemonic[1:]


def lower(mnemonic, operands):
	"""Lower one site. Returns (instructions, class_name, notes).

	`operands` is the AT&T operand list as objdump prints it, already split
	-- src2, src1, dst for a three-operand form, with any immediate first.

	The Class C correctness rule is the one that matters here: a VEX scalar
	operation takes bits 127:32 of its destination from **src1**, and SSE
	leaves those bits untouched, so the mov that sets up the destination
	must copy src1 and never src2. Backwards is silently wrong, and it is
	wrong in the upper three quarters of the register where nothing looks
	at it until much later.
	"""
	category, note = classify(mnemonic, len(operands))
	notes = [note]

	if category == ELIDE:
		return [], "Z", notes
	if category in (GAP, HELPER):
		return None, category.upper(), notes
	if category == SEQUENCE:
		return lower_sequence(mnemonic, operands, notes)

	immediate = [o for o in operands if o.startswith("$")]
	registers = [o for o in operands if not o.startswith("$")]
	sse = sse_mnemonic(mnemonic)

	if category == DIRECT:
		return [f"{sse} {','.join(operands)}"], "A", notes

	# From here the form is NDS. Two shapes reach this point, and they differ
	# in where src2 lives:
	#
	#   vaddss  %xmm2,%xmm1,%xmm0   three registers -- src2 is a register
	#   vpslldq $1,%xmm1,%xmm0      an immediate and two -- src2 IS the
	#                               immediate, and SSE pslldq takes exactly
	#                               one operand besides the destination
	#
	# Treating the second shape as if it had three registers is what makes a
	# lowering the assembler rejects, because the SSE shift forms are
	# two-operand and there is no third register to name.
	if len(registers) == 3:
		src2, src1, dst = registers
	elif len(registers) == 2 and immediate:
		src1, dst = registers
		src2 = None
	else:
		# Not actually an NDS site despite the mnemonic -- a store form, or
		# something with a shape this does not model. Emit it unchanged and
		# let verify() catch it if that is wrong.
		return [f"{sse} {','.join(operands)}"], "A", notes

	imm = immediate[0] if immediate else None

	def emit(source, destination):
		parts = [p for p in (imm, source, destination) if p]
		return f"{sse} {','.join(parts)}"

	if dst == src1:
		return [emit(src2, dst)], "B", notes

	if dst != src2:
		return [f"movaps {src1},{dst}", emit(src2, dst)], "C", notes

	# dst aliases src2: the mov would destroy src2 before it is read.
	if is_commutative(mnemonic):
		notes.append("dst aliases src2; operands exchanged (commutative)")
		return [emit(src1, dst)], "C-alias/swap", notes
	notes.append("dst aliases src2; needs a scratch register")
	return (
		[f"movaps {src1},%xmmT", emit(src2, "%xmmT"),
		 f"movaps %xmmT,{dst}"],
		"C-alias/scratch", notes,
	)


# The scratch register the sequences borrow. Which physical register this
# becomes is the allocator's problem, not this table's; every sequence that
# uses one says so in its notes so the cost is visible.
SCRATCH = "%xmmT"
# A second scratch, needed only by the blend case where src2 is itself
# %xmm0 and has to be staged before the mask overwrites it.
SCRATCH2 = "%xmmU"

# One FMA per distinct shape, so verify() reaches every arm of
# lower_fma rather than only the 231 form that dominates the binary.
FMA_SAMPLES = ("vfmadd132ps", "vfmadd213ps", "vfmadd231ps",
               "vfmadd231ss", "vfmsub231ps", "vfnmadd231ps",
               "vfnmadd213ss", "vfmaddsub231ps", "vfmsubadd231ps",
               "vfmadd231pd", "vfmsub213ps")


def lower_sequence(mnemonic, operands, notes):
	"""Emit a multi-instruction lowering. Returns (instructions, class, notes)."""
	immediate = [o for o in operands if o.startswith("$")]
	registers = [o for o in operands if not o.startswith("$")]
	imm = immediate[0] if immediate else None

	fma = FMA_PATTERN.match(mnemonic)
	if fma:
		return lower_fma(fma, registers, notes)

	# Blend with a variable mask. SSE takes the mask in an implicit %xmm0,
	# which the VEX form does not, so the mask has to be moved there and
	# whatever %xmm0 held has to survive. Four registers: mask, src2, src1,
	# dst.
	if mnemonic in ("vblendvps", "vblendvpd", "vpblendvb"):
		if len(registers) != 4:
			return None, "SEQUENCE", notes + ["unexpected operand count"]
		mask, src2, src1, dst = registers
		sse = mnemonic[1:]
		body = []
		notes.append("SSE takes the blend mask in an implicit %xmm0")

		# %xmm0 is doing two jobs at once here and the order matters. Three
		# things can collide, and the naive sequence gets all three wrong:
		#
		#   * the mask must be in %xmm0 when the blend executes;
		#   * the destination must already hold src1, because SSE blendvps
		#     is destructive;
		#   * whatever %xmm0 held before must survive, unless the
		#     instruction overwrites it anyway.
		#
		# Writing src1 into a destination that IS %xmm0 destroys the mask
		# that was just loaded, and restoring %xmm0 afterwards destroys the
		# result. That is the majority case in this binary -- 2,171 of 3,542
		# sites have dst == %xmm0 -- so it is the case to get right first.
		if dst == "%xmm0":
			# The incoming %xmm0 is dead: the instruction overwrites it. But
			# %xmm0 cannot be the blend's destination while it holds the
			# mask, so the blend runs in a scratch and is moved back.
			notes.append("dst is %xmm0: blend runs in a scratch, then moves back")
			body.append(f"movaps {src1},{SCRATCH}")
			staged = src2
			if mask != "%xmm0" and src2 == "%xmm0":
				body.append(f"movaps %xmm0,{SCRATCH2}")
				staged = SCRATCH2
				notes.append("src2 was %xmm0; staged before the mask overwrote it")
			if mask != "%xmm0":
				body.append(f"movaps {mask},%xmm0")
			body.append(f"{sse} {staged},{SCRATCH}")
			body.append(f"movaps {SCRATCH},{dst}")
			return body, "D/blend", notes

		# dst is not %xmm0, so dst can be the blend destination and the only
		# question is preserving %xmm0. Save it first, then rename any
		# operand that referred to it -- that is what keeps the sequence
		# correct when src1 or src2 happens to be %xmm0.
		if mask != "%xmm0":
			body.append(f"movaps %xmm0,{SCRATCH}")
			body.append(f"movaps {mask},%xmm0")
			notes.append("%xmm0 saved and reloaded around the blend")
			if src1 == "%xmm0":
				src1 = SCRATCH
			if src2 == "%xmm0":
				src2 = SCRATCH
		if dst != src1:
			body.append(f"movaps {src1},{dst}")
		body.append(f"{sse} {src2},{dst}")
		if mask != "%xmm0":
			body.append(f"movaps {SCRATCH},%xmm0")
		return body, "D/blend", notes

	# Splat. The memory form is a load plus a shuffle; the register form is
	# AVX2 and needs a move instead of the load.
	if mnemonic == "vbroadcastss":
		source, dst = registers[0], registers[-1]
		notes.append("splat: load or move, then shuffle lane 0 across")
		if source.startswith("%"):
			return [f"movaps {source},{dst}", f"shufps $0,{dst},{dst}"], \
				"D/splat", notes
		return [f"movss {source},{dst}", f"shufps $0,{dst},{dst}"], \
			"D/splat", notes
	if mnemonic == "vbroadcastsd":
		source, dst = registers[0], registers[-1]
		notes.append("splat: 64-bit lane duplicated")
		return [f"movsd {source},{dst}", f"unpcklpd {dst},{dst}"], \
			"D/splat", notes
	if mnemonic == "vpbroadcastd":
		source, dst = registers[0], registers[-1]
		notes.append("splat: integer lane 0 across")
		if source.startswith("%xmm"):
			return [f"pshufd $0,{source},{dst}"], "D/splat", notes
		return [f"movd {source},{dst}", f"pshufd $0,{dst},{dst}"], \
			"D/splat", notes
	if mnemonic == "vpbroadcastw":
		source, dst = registers[0], registers[-1]
		notes.append("splat: 16-bit lane across both halves")
		return [f"movd {source},{dst}", f"pshuflw $0,{dst},{dst}",
		        f"pshufd $0,{dst},{dst}"], "D/splat", notes

	# 128-bit half extract and insert. These are the Y-class boundary: with
	# the Y1 peephole the half is already a separate 128-bit value and the
	# instruction becomes a move; only inside a Y2 region does it touch the
	# shadow area.
	if mnemonic in ("vextractf128", "vextracti128"):
		move = "movaps" if mnemonic.endswith("f128") else "movdqa"
		source, dst = registers[0], registers[-1]
		half = "upper" if imm not in (None, "$0", "$0x0") else "lower"
		notes.append(f"extracts the {half} 128-bit half")
		if half == "lower":
			return [f"{move} {source},{dst}"], "Y/extract", notes
		notes.append("upper half: reads the Y2 shadow slot for this register")
		return [f"{move} shadow({source}),{dst}"], "Y2/extract", notes
	if mnemonic in ("vinsertf128", "vinserti128"):
		move = "movaps" if mnemonic.endswith("f128") else "movdqa"
		source, dst = registers[0], registers[-1]
		half = "upper" if imm not in (None, "$0", "$0x0") else "lower"
		notes.append(f"inserts into the {half} 128-bit half")
		if half == "lower":
			return [f"{move} {source},{dst}"], "Y/insert", notes
		notes.append("upper half: writes the Y2 shadow slot for this register")
		return [f"{move} {source},shadow({dst})"], "Y2/insert", notes

	# vpermilps. The two forms could hardly be more different in cost: an
	# immediate control is a plain shufps, while a variable control has no
	# SSE instruction at all and calls out of line.
	if mnemonic == "vpermilps":
		if imm is not None:
			# A single-source four-element permute. shufps takes its low
			# two elements from the destination and its high two from the
			# source, so aiming both at the same register makes it one.
			data, dst = registers[0], registers[-1]
			notes.append("immediate control is a shufps with both operands "
			             "the same register -- no helper needed")
			if data == dst:
				return [f"shufps {imm},{dst},{dst}"], "D/permute", notes
			return ([f"movaps {data},{dst}", f"shufps {imm},{dst},{dst}"],
			        "D/permute", notes)

		# Variable control. objdump prints control, data, dst -- the VEX
		# vvvv field holds the DATA and r/m the CONTROL, which is the easy
		# thing to get backwards.
		if len(registers) != 3:
			return None, "H/permil", notes + ["unexpected operand count"]
		control, data, dst = registers
		notes.append("variable control -- no SSE instruction; calls the "
		             "pshufb helper in src/permil.c")
		notes.append("the helper is written to clobber only %xmm0 and "
		             "%xmm1 and no general register, which is what keeps "
		             "the call site cheap")
		body = []
		if data != "%xmm0":
			body.append(f"movaps {data},%xmm0")
		if control != "%xmm1":
			body.append(f"movaps {control},%xmm1")
		body.append("call permilps_var")
		if dst != "%xmm0":
			body.append(f"movaps %xmm0,{dst}")
		return body, "H/permil", notes

	# The cross-lane permutes. Three of the four need no helper at all
	# once the 256-bit value is held as two 128-bit halves, which is what
	# the Y-class representation already does. `lo(r)` and `hi(r)` below
	# name those halves the way `shadow(r)` names a Y2 slot.
	if mnemonic == "vperm2f128":
		return lower_perm2f128(imm, registers, notes)
	if mnemonic in ("vpermq", "vpermpd"):
		return lower_perm_qword(mnemonic, imm, registers, notes)
	if mnemonic == "vpermd":
		# objdump prints data, indices, dst -- r/m is the DATA here, the
		# opposite of vpermilps. See src/permd.h.
		if len(registers) != 3:
			return None, "H/permd", notes + ["unexpected operand count"]
		data, indices, dst = registers
		notes.append("variable cross-lane permute -- calls the pshufb "
		             "helper in src/permd.c")
		notes.append("operand order is data, indices, dst -- the OPPOSITE "
		             "of vpermilps, where r/m is the control")
		notes.append(f"data={data} indices={indices} dst={dst}")
		return ["call permd"], "H/permd", notes

	# A compare whose AVX predicate has no SSE spelling and must be reversed.
	predicate = compare_predicate(mnemonic)
	if predicate is not None:
		name, avx_only = predicate
		if avx_only and name in AVX_PREDICATES:
			sse_pred, swap, note = AVX_PREDICATES[name]
			if swap and len(registers) == 3:
				src2, src1, dst = registers
				suffix = mnemonic[-2:]
				sse = f"cmp{sse_pred}{suffix}"
				notes.append("operands exchanged to reverse the comparison")
				if dst == src2:
					return [f"{sse} {src1},{dst}"], "D/predicate", notes
				return [f"movaps {src2},{dst}", f"{sse} {src1},{dst}"], \
					"D/predicate", notes

	if mnemonic == "vzeroall":
		notes.append("zero all sixteen xmm registers")
		return [f"xorps %xmm{n},%xmm{n}" for n in range(16)], "Z", notes

	return None, "SEQUENCE", notes + ["sequence not implemented"]


def lower_perm2f128(imm, registers, notes):
	"""vperm2f128: each output 128-bit lane is one input lane, or zero.

	Once the 256-bit values are held as two 128-bit halves this is not a
	permute at all -- it is at most two moves. The immediate selects, for
	each output half, one of the four input halves; bits 3 and 7 override
	the selection with zero.
	"""
	if imm is None or len(registers) != 3:
		return None, "Y/lane", notes + ["unexpected operand form"]
	src2, src1, dst = registers
	value = int(imm.lstrip("$"), 0)
	sources = [f"lo({src1})", f"hi({src1})", f"lo({src2})", f"hi({src2})"]

	notes.append("pure 128-bit lane selection -- no permute survives the "
	             "split into halves")
	body = []
	for half, (shift, zero_bit) in enumerate(((0, 3), (4, 7))):
		target = f"lo({dst})" if half == 0 else f"hi({dst})"
		if value & (1 << zero_bit):
			notes.append(f"bit {zero_bit} set: this half is zeroed, not moved")
			body.append(f"xorps {target},{target}")
		else:
			source = sources[(value >> shift) & 3]
			if source != target:
				body.append(f"movaps {source},{target}")
			else:
				notes.append(f"{target} already holds what it needs")

	# If the second move reads the half the first one just wrote, the
	# sources have to be staged. Reported rather than silently reordered,
	# because which register is free is the allocator's business.
	if len(body) == 2 and body[0].startswith("movaps"):
		written = body[0].rsplit(",", 1)[1]
		if written in body[1]:
			notes.append("the second move reads the half the first writes: "
			             "stage through a scratch or emit in the other order")
	return body, "Y/lane", notes


def lower_perm_qword(mnemonic, imm, registers, notes):
	"""vpermq and vpermpd: an immediate permute of four 64-bit elements.

	Cross-lane, but the immediate is a constant, so each output half is two
	chosen qwords and `shufpd` builds one from two registers in a single
	instruction: it takes the low result from the destination and the high
	result from the source.
	"""
	if imm is None or len(registers) != 2:
		return None, "Y/permq", notes + ["unexpected operand form"]
	src, dst = registers
	value = int(imm.lstrip("$"), 0)
	halves = (f"lo({src})", f"hi({src})")

	notes.append("immediate control, so each output half is two chosen "
	             "qwords and shufpd builds it in one instruction")
	if mnemonic == "vpermq":
		notes.append("shufpd on integer data crosses the SSE domain, which "
		             "costs a cycle or two on some parts and nothing in "
		             "correctness; punpck pairs are the alternative")

	body = []
	for half, shift in ((0, 0), (1, 4)):
		first = (value >> shift) & 3
		second = (value >> (shift + 2)) & 3
		target = f"lo({dst})" if half == 0 else f"hi({dst})"
		selector = (first & 1) | ((second & 1) << 1)
		source_first = halves[first >> 1]
		source_second = halves[second >> 1]
		if selector == 2 and source_first == source_second:
			# Identity: the low qword comes from the destination and the
			# high one from the source, and both are the same register.
			body.append(f"movaps {source_first},{target}")
			continue
		body.append(f"movaps {source_first},{target}")
		body.append(f"shufpd ${selector:#x},{source_second},{target}")
	notes.append("both output halves read both input halves, so they must "
	             "be built before either is written back")
	return body, "Y/permq", notes


def lower_fma(match, registers, notes):
	"""Lower a fused multiply-add. NOT semantics-preserving.

	The 132/213/231 suffix selects which operand is the addend. Taken from
	the SDM, in AT&T order where the operands print as src2, src1, dst:

	    132   dst = dst  * src2 + src1
	    213   dst = src1 * dst  + src2
	    231   dst = src1 * src2 + dst

	Splitting into a multiply and an add gives **two roundings where the
	hardware did one**, so every site this touches differs from the original
	in the last ULP and must be flagged for audit.
	"""
	negated, operation, order, kind = match.groups()
	if len(registers) != 3:
		return None, "F", notes + ["unexpected operand count"]
	src2, src1, dst = registers
	packed = kind[0] == "p"
	suffix = kind
	mul = ("mulps" if kind == "ps" else "mulpd" if kind == "pd"
	       else "mulss" if kind == "ss" else "mulsd")
	add = mul.replace("mul", "add")
	sub = mul.replace("mul", "sub")
	addsub = "addsubps" if kind == "ps" else "addsubpd"

	notes.append("FMA: two roundings replace one -- NOT bit-exact")

	# Which two values are multiplied, and which is the addend.
	if order == "132":
		factors, addend = (dst, src2), src1
	elif order == "213":
		factors, addend = (src1, dst), src2
	else:
		factors, addend = (src1, src2), dst

	body = [f"movaps {factors[0]},{SCRATCH}", f"{mul} {factors[1]},{SCRATCH}"]
	notes.append("needs a scratch register")

	if operation in ("maddsub", "msubadd"):
		# There is no addsubss or addsubsd. The FMA add/subtract forms are
		# packed-only, so a scalar one is a decode error rather than a
		# lowering problem.
		if kind not in ("ps", "pd"):
			return None, "F/addsub", notes + [
				"no scalar addsub exists -- check the decode"]

		if operation == "maddsub":
			# SSE3 addsubps subtracts on the even lanes and adds on the
			# odd ones, which is exactly what VFMADDSUB does. Confirmed by
			# running it on the host rather than by reading the manual:
			# {10,20,30,40} addsub {1,2,3,4} gives {9,22,27,44}.
			notes.append("even lanes subtract, odd lanes add -- which is "
			             "what addsubps already does")
			body.append(f"{addsub} {addend},{SCRATCH}")
			body.append(f"movaps {SCRATCH},{dst}")
			return body, "F/addsub", notes

		# VFMSUBADD is the opposite pattern -- even lanes add, odd lanes
		# subtract -- and SSE has no instruction for it. Compute both
		# results and blend: even lanes from the add, odd from the
		# subtract.
		#
		# The obvious alternative is to negate the addend and reuse
		# addsubps, since IEEE 754 makes a - b and a + (-b) the same
		# operation, signed zeros included. **That is wrong, and it was
		# caught by test/fmaddsub_test.c rather than by reasoning.** The
		# negation is a sign-bit flip across the whole register, and a NaN
		# has a sign bit too; x86 propagates a source NaN with its sign
		# preserved, so a NaN addend came out as ffc00000 where the
		# hardware gives 7fc00000. 291 vectors in the special-value sweep
		# disagreed, every one of them a NaN.
		#
		# Computing both and blending performs the very add and subtract
		# the hardware does, so NaN propagation matches by construction.
		# It also needs no sign-mask constant, which removes a whole
		# requirement -- the rewriter does not have to add a read-only
		# pool for this rule. Two more instructions across 14 sites.
		blend = "blendps" if kind == "ps" else "blendpd"
		selector = "$0xa" if kind == "ps" else "$0x2"
		notes.append("even lanes add, odd lanes subtract -- the opposite of "
		             "addsubps, so both results are computed and blended")
		notes.append("NOT by negating the addend and reusing addsubps: that "
		             "flips the sign bit of a NaN addend, which the hardware "
		             "preserves")
		notes.append("needs a second scratch, and no constant pool")
		body.append(f"movaps {SCRATCH},{SCRATCH2}")
		body.append(f"{add} {addend},{SCRATCH}")
		body.append(f"{sub} {addend},{SCRATCH2}")
		body.append(f"{blend} {selector},{SCRATCH2},{SCRATCH}")
		body.append(f"movaps {SCRATCH},{dst}")
		return body, "F/subadd", notes

	if operation == "madd":
		if negated:
			# dst = -(a*b) + addend  ==  addend - a*b
			if addend == dst:
				body.append(f"{sub} {SCRATCH},{dst}")
				return body, "F", notes
			body.append(f"movaps {addend},{dst}")
			body.append(f"{sub} {SCRATCH},{dst}")
			return body, "F", notes
		body.append(f"{add} {addend},{SCRATCH}")
	else:
		# msub: dst = a*b - addend
		body.append(f"{sub} {addend},{SCRATCH}")
		if negated:
			notes.append("negated multiply-subtract: result negated")

	body.append(f"movaps {SCRATCH},{dst}")
	return body, "F", notes


# Kept in step with tool/vex_scan.py deliberately: the same set decides the
# cost model there and the emitted sequence here, and two copies that drift
# would make the estimate describe code the lowering does not produce.
#
# maxss/minss are absent on purpose. SSE MAXSS(a,b) returns b when either
# input is NaN and when both are zeros of opposite sign, so exchanging the
# operands is wrong at exactly the inputs clamping code sees.
COMMUTATIVE = frozenset("""
	vaddss vaddsd vaddps vaddpd vmulss vmulsd vmulps vmulpd
	vandps vandpd vorps vorpd vxorps vxorpd vpand vpor vpxor
	vpaddb vpaddw vpaddd vpaddq vpmulld vpmullw vpmuludq
	vpcmpeqb vpcmpeqw vpcmpeqd vpcmpeqq
	vpminub vpmaxub vpminsw vpmaxsw vpmaxud vpminud
""".split())


def is_commutative(mnemonic):
	return mnemonic in COMMUTATIVE


INSTRUCTION = re.compile(r"^\s+([0-9a-f]+):\t([0-9a-f ]+)\t(.*)$")


def split_operands(text):
	"""Split an AT&T operand list on top-level commas."""
	out, depth, start = [], 0, 0
	for i, ch in enumerate(text):
		if ch == "(":
			depth += 1
		elif ch == ")":
			depth -= 1
		elif ch == "," and depth == 0:
			out.append(text[start:i].strip())
			start = i + 1
	tail = text[start:].strip()
	if tail:
		out.append(tail)
	return out


def coverage(path):
	"""Report which VEX sites in a listing have a lowering rule."""
	by_category = Counter()
	sites = Counter()
	gaps = Counter()
	gap_notes = {}
	classes = Counter()

	with open(path, "r", errors="replace") as handle:
		for line in handle:
			parts = line.split("\t")
			if len(parts) < 3:
				continue
			encoding = parts[1].split()
			if not encoding or encoding[0] not in ("c4", "c5"):
				continue
			body = parts[2]
			hash_at = body.find("#")
			if hash_at >= 0:
				body = body[:hash_at]
			fields = body.strip().split(None, 1)
			if not fields:
				continue
			mnemonic = fields[0]
			if mnemonic == "(bad)":
				continue
			operands = split_operands(fields[1]) if len(fields) > 1 else []

			sites[mnemonic] += 1
			category, note = classify(mnemonic, len(operands))
			by_category[category] += 1
			if category == GAP:
				gaps[mnemonic] += 1
				gap_notes[mnemonic] = note
			else:
				result, class_name, _ = lower(mnemonic, operands)
				classes[class_name] += 1

	return by_category, sites, gaps, gap_notes, classes


def verify():
	"""Assemble every lowering and prove no VEX survives.

	A rule that has not been through an assembler is a guess. This emits one
	instance of each lowering, assembles it for x86-64, disassembles the
	result, and fails if any instruction still carries a VEX prefix (a
	leading C4 or C5) or if the assembler rejected the sequence outright.

    The proof is the point: it refuses to report success for a rule whose
	output the toolchain will not accept.
	"""
	# Every mnemonic with a rule, not just the one-to-one ones. The
	# sequences are where the risk actually is: a direct lowering is a
	# mnemonic change an assembler will obviously accept, while a blend or
	# an FMA is several instructions with register constraints, and those
	# are the ones worth putting through a toolchain.
	covered = sorted(
		DIRECT_MNEMONICS | NDS_MNEMONICS
		| set(SEQUENCE_MNEMONICS) | set(FMA_SAMPLES)
	)
	samples = []
	skipped = []
	for mnemonic in covered:
		operands = sample_operands(mnemonic)
		result, class_name, notes = lower(mnemonic, operands)
		if result is None:
			skipped.append((mnemonic, class_name, notes[-1]))
			continue
		for instruction in result:
			# The Y2 shadow slot and the sign mask are memory operands the
			# allocator has not placed yet, so they cannot be assembled as
			# written. Substitute a concrete address to prove the rest of
			# the sequence is well formed.
			text = (instruction.replace("%xmmT", "%xmm15")
			                   .replace("%xmmU", "%xmm14")
			                   .replace("signmask", "(%rsp)"))
			text = re.sub(r"shadow\((%\w+)\)", r"(%rsp)", text)
			text = re.sub(r"(?:lo|hi)\(%[xy](mm\d+)\)", r"%x\1", text)
			samples.append((mnemonic, text))

	body = "\n".join(f"\t{text}" for _m, text in samples)
	source = f".text\n.globl _start\n_start:\n{body}\n"

	with tempfile.TemporaryDirectory() as tmp:
		asm = Path(tmp) / "lowered.s"
		obj = Path(tmp) / "lowered.o"
		asm.write_text(source)
		done = subprocess.run(
			["as", "--64", "-o", str(obj), str(asm)],
			capture_output=True, text=True,
		)
		if done.returncode != 0:
			print("verify: the assembler REJECTED a lowering:", file=sys.stderr)
			print(done.stderr.rstrip(), file=sys.stderr)
			return 1

		listing = subprocess.run(
			["objdump", "-d", "--no-show-raw-insn", str(obj)],
			capture_output=True, text=True,
		)
		raw = subprocess.run(
			["objdump", "-d", str(obj)], capture_output=True, text=True,
		).stdout

	vex_left = []
	for line in raw.splitlines():
		parts = line.split("\t")
		if len(parts) < 3:
			continue
		encoding = parts[1].split()
		if encoding and encoding[0] in ("c4", "c5", "62"):
			vex_left.append(line.strip())

	print(f"verify: host baseline {HOST_BASELINE}")
	print(f"verify: {len(samples)} lowered instructions assembled cleanly")
	if skipped:
		print(f"verify: {len(skipped)} mnemonic(s) emit no sequence:")
		for mnemonic, class_name, note in skipped:
			print(f"    {mnemonic:<16} {class_name:<10} {note}")
	if vex_left:
		print(f"verify: FAILED -- {len(vex_left)} still VEX-encoded:",
		      file=sys.stderr)
		for line in vex_left[:20]:
			print(f"    {line}", file=sys.stderr)
		return 1
	print("verify: no VEX or EVEX prefix survives -- proof holds")
	return 0


def sample_operands(mnemonic):
	"""A plausible operand list for one instance of a mnemonic.

	Only used by verify(), which needs something syntactically valid rather
	than something meaningful.
	"""
	if mnemonic in ("vldmxcsr", "vstmxcsr"):
		return ["(%rsp)"]
	if mnemonic == "vzeroall":
		return []
	# The cross-lane permutes: an immediate that actually crosses lanes, so
	# verify() exercises the interesting arm rather than an identity.
	if mnemonic == "vperm2f128":
		return ["$0x21", "%ymm2", "%ymm1", "%ymm0"]
	if mnemonic in ("vpermq", "vpermpd"):
		return ["$0x1b", "%ymm1", "%ymm0"]
	if mnemonic == "vpermd":
		return ["%ymm2", "%ymm9", "%ymm0"]
	# Splats take a memory or general-register source, never an xmm one --
	# except the AVX2 register forms, which are covered by lower() itself.
	if mnemonic in ("vbroadcastss", "vbroadcastsd", "vpbroadcastd"):
		return ["(%rsp)", "%xmm0"]
	if mnemonic == "vpbroadcastw":
		return ["%eax", "%xmm0"]
	# Blend prints four registers: mask, src2, src1, dst.
	if mnemonic in ("vblendvps", "vblendvpd", "vpblendvb"):
		return ["%xmm3", "%xmm2", "%xmm1", "%xmm0"]
	# The upper-half forms, so verify() exercises the shadow path.
	if mnemonic in ("vextractf128", "vextracti128"):
		return ["$1", "%ymm1", "%xmm0"]
	if mnemonic in ("vinsertf128", "vinserti128"):
		return ["$1", "%xmm2", "%ymm1", "%ymm0"]
	# movd/movq move between a general register and an xmm, never xmm to xmm.
	if mnemonic == "vmovd":
		return ["%xmm0", "%eax"]
	if mnemonic == "vmovq":
		return ["%xmm0", "%rax"]
	# Store-only and load-only forms need a memory operand to be legal at all.
	if mnemonic in ("vmovntps", "vmovntpd", "vmovntdq"):
		return ["%xmm0", "(%rsp)"]
	if mnemonic in ("vmovhpd", "vmovlpd", "vmovhps", "vmovlps"):
		return ["%xmm0", "(%rsp)"]
	if mnemonic in PCLMUL_PSEUDO:
		return ["%xmm2", "%xmm1", "%xmm0"]
	if mnemonic in ("vmovmskps", "vmovmskpd", "vpmovmskb"):
		return ["%xmm1", "%eax"]
	if mnemonic in ("vcvttss2si", "vcvttsd2si", "vcvtss2si", "vcvtsd2si"):
		return ["%xmm1", "%eax"]
	if mnemonic in ("vcvtsi2ss", "vcvtsi2sd", "vcvtsi2ssl", "vcvtsi2sdl"):
		return ["%eax", "%xmm1", "%xmm0"]
	if mnemonic in ("vcvtsi2ssq", "vcvtsi2sdq"):
		return ["%rax", "%xmm1", "%xmm0"]
	if mnemonic in ("vextractps", "vpextrd"):
		return ["$0", "%xmm1", "%eax"]
	if mnemonic == "vpextrq":
		return ["$0", "%xmm1", "%rax"]
	if mnemonic in ("vpextrb", "vpextrw"):
		return ["$0", "%xmm1", "%eax"]
	if mnemonic in ("vpinsrb", "vpinsrw", "vpinsrd"):
		return ["$0", "%eax", "%xmm1", "%xmm0"]
	if mnemonic == "vpinsrq":
		return ["$0", "%rax", "%xmm1", "%xmm0"]
	if mnemonic in ("vpshufd", "vpshuflw", "vpshufhw", "vroundps", "vroundpd"):
		return ["$0", "%xmm1", "%xmm0"]
	if mnemonic in ("vshufps", "vshufpd", "vblendps", "vblendpd", "vpblendw",
	                "vdpps", "vdppd", "vroundss", "vroundsd", "vinsertps",
	                "vpclmulqdq"):
		return ["$0", "%xmm2", "%xmm1", "%xmm0"]
	# The shift-by-immediate forms are NDS with the immediate as src2: SSE
	# takes exactly one operand besides the destination.
	if mnemonic in ("vpsllw", "vpslld", "vpsllq", "vpsrlw", "vpsrld",
	                "vpsrlq", "vpsraw", "vpsrad", "vpslldq", "vpsrldq"):
		return ["$1", "%xmm1", "%xmm0"]
	if mnemonic in ("vcvtsi2ss", "vcvtsi2sd", "vcvtsi2ssl", "vcvtsi2sdl"):
		return ["%eax", "%xmm1", "%xmm0"]
	if mnemonic in ("vcvtsi2ssq", "vcvtsi2sdq"):
		return ["%rax", "%xmm1", "%xmm0"]
	if mnemonic in ("vcvtss2sd", "vcvtsd2ss"):
		return ["%xmm2", "%xmm1", "%xmm0"]
	if mnemonic.startswith("vcvt"):
		return ["%xmm1", "%xmm0"]
	if mnemonic in DIRECT_MNEMONICS:
		return ["%xmm1", "%xmm0"]
	return ["%xmm2", "%xmm1", "%xmm0"]


def main(argv):
	if not argv or argv[0] in ("-h", "--help"):
		print(__doc__.strip())
		print("\nusage: lower.py verify")
		print("       lower.py coverage <listing.asm>")
		print("       lower.py explain <mnemonic> [operands...]")
		return 0

	mode = argv[0]
	if mode == "verify":
		return verify()

	if mode == "explain":
		if len(argv) < 2:
			print("explain: need a mnemonic", file=sys.stderr)
			return 2
		mnemonic = argv[1]
		operands = argv[2:] or sample_operands(mnemonic)
		result, class_name, notes = lower(mnemonic, operands)
		print(f"{mnemonic} {','.join(operands)}")
		print(f"  class {class_name}")
		for note in notes:
			print(f"  note  {note}")
		if result is None:
			print("  NO LOWERING")
		elif not result:
			print("  (deleted)")
		else:
			for instruction in result:
				print(f"    {instruction}")
		return 0

	if mode == "coverage":
		if len(argv) < 2:
			print("coverage: need a listing", file=sys.stderr)
			return 2
		by_category, sites, gaps, gap_notes, classes = coverage(argv[1])
		total = sum(by_category.values())
		print(f"host baseline: {HOST_BASELINE}")
		print(f"VEX sites: {total:,}   distinct mnemonics: {len(sites):,}\n")
		print("by lowering category:")
		for category, count in by_category.most_common():
			print(f"  {category:<10} {count:>10,}   {100.0 * count / total:6.2f}%")
		print("\nby lowering class:")
		for name, count in classes.most_common():
			print(f"  {name:<18} {count:>10,}   {100.0 * count / total:6.2f}%")
		covered = total - by_category[GAP]
		print(f"\ncovered: {covered:,} of {total:,} "
		      f"({100.0 * covered / total:.4f}%)")
		if gaps:
			print(f"\nGAPS -- {sum(gaps.values()):,} sites with no rule:")
			for mnemonic, count in gaps.most_common():
				print(f"  {mnemonic:<16} {count:>8,}")
				print(f"      {gap_notes[mnemonic]}")
		else:
			print("\nno gaps")
		return 1 if gaps else 0

	print(f"lower.py: unknown mode {mode!r}", file=sys.stderr)
	return 2


if __name__ == "__main__":
	raise SystemExit(main(sys.argv[1:]))
