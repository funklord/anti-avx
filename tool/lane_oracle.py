#!/usr/bin/env python3
"""Settle `detour.LANE_WISE` by executing the 256-bit form, not reading it.

**This machine is a Westmere.** It cannot execute a VEX instruction, which
is the project's premise, so `tool/lowering_cases.py` takes its reference
from GCC compiling the equivalent SSE intrinsic -- a separate producer, but
not the original instruction. `qemu-x86_64` in user mode is a separate
producer that IS the original instruction: it decodes and executes VEX on a
host that has none, because it translates rather than dispatches.

What this asks, for one mnemonic at a time, is exactly the question
`LANE_WISE` answers by assertion:

    does  op %ymm2,%ymm1,%ymm0
    equal op (src2+0),(src1+0)  followed by  op (src2+16),(src1+16)

with the 256-bit side executed under qemu and the two 128-bit sides
executed natively on this CPU. Bit-for-bit over all 32 bytes, no
forgiveness: both sides run the same elementwise operation on the same
bits, so a NaN payload that differs is a real difference and not a
reference artifact. Nothing here goes through a compiler's idea of the
answer.

Three controls, because a harness that agrees with itself proves nothing:

  * `--controls` runs genuinely cross-lane AVX2 instructions under qemu and
    compares against a model computed here from the ISA definition. If qemu
    implemented every 256-bit operation as two 128-bit lane loops, these
    would come out lane-split and wrong. They do not, so a "lane-wise"
    verdict below is qemu's per-instruction implementation and not the
    shape of its interpreter.
  * every case also runs its VEX.128 form under qemu against the plain SSE
    form natively. That puts qemu's elementwise arithmetic -- NaN payloads
    included -- against real silicon, per mnemonic, and leaves only the
    lane structure resting on qemu.
  * `--sabotage` rebuilds the 128-bit side wrong on purpose, twice: halves
    swapped, and the low half used for both. A mnemonic whose correct split
    passes while both sabotages fail has been discriminated. One whose
    sabotage also passes was asked with inputs too symmetric to answer.

Usage:  lane_oracle.py [build directory]

**The list here is a copy of `detour.LANE_WISE`, on purpose.** Importing it
would make the check agree with the code by construction, which is
`evidence.md`'s point about corroboration: two documents agreeing are one
witness if the same hand wrote both. But a copy that drifts silently is
worse than no copy, so `detour.LANE_WISE` IS imported -- only to demand that
every entry in it appears here. Gaining a mnemonic in `detour.py` and not
executing it is then a failed check rather than a forgotten one.

It skips rather than fails where `qemu-x86_64` is absent. The check being
unavailable and the check passing are different claims.
"""

import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import detour

WORK = Path("build") / "laneoracle"
QEMU = ["qemu-x86_64", "-cpu", "max"]
TIMEOUT = 300

# The thirty-two of `detour.LANE_WISE`, verbatim from tool/detour.py, plus
# the three deliberately left out of it. Every one has a 128-bit SSE form
# spelled by dropping the v, and every one takes src2 then src1 then dst.
LANE_WISE = """
	vandps vandpd vandnps vandnpd vorps vorpd vxorps vxorpd
	vaddps vaddpd vsubps vsubpd vmulps vmulpd vdivps vdivpd
	vminps vminpd vmaxps vmaxpd
	vpand vpandn vpor vpxor
	vpaddb vpaddw vpaddd vpaddq vpsubb vpsubw vpsubd vpsubq
""".split()

# Left OUT of LANE_WISE, read from the SDM rather than run. `vpblendw`
# carries an immediate; the other two do not.
EXCLUDED = [("vpsadbw", None), ("vphsubd", None), ("vpblendw", "$0x3c"),
            ("vpblendw", "$0xa5"), ("vpblendw", "$0x0f")]

# Neither in the set nor excluded from it. Two reasons, and the second
# arrived a fortnight after the first.
#
# The first twelve were asked because the comment above the set gives
# "nothing horizontal" as a reason. Horizontal is a statement about
# elements; the set's own requirement is about lanes, and these are the
# shapes where the two questions come apart.
#
# The rest were asked because `ymm_span` reads `LANE_WISE` and did not
# exist when the first twelve were settled. Finding 122 declined to take
# them into the set because nothing but the splat triple read it, and a
# set is a liability until something does; a span is a second reader, and
# a 256-bit form it does not recognise closes it. Each of these stops one
# in this binary -- `make spans` ranks them -- and every one has a
# 128-bit SSE form spelled by dropping the v, which is what this harness
# can ask about.
#
# `vshufps` is asked at two immediates for `vpblendw`'s reason: the
# immediate is what selects the elements, so one value settles one
# selection rather than the instruction. $0xe4 is left out deliberately --
# it is the identity, and an identity cannot tell a correct split from a
# sabotaged one.
EXTRA = [("vhaddps", None), ("vhsubps", None), ("vphaddd", None),
         ("vpackssdw", None), ("vpackuswb", None), ("vpunpckldq", None),
         ("vpunpckhqdq", None), ("vpshufb", None), ("vpalignr", "$0x5"),
         ("vpmaddwd", None), ("vpavgb", None), ("vpmulhw", None),
         ("vshufps", "$0x1b"), ("vshufps", "$0x4e"),
         ("vaddsubps", None), ("vpmulld", None), ("vpmuludq", None),
         ("vpcmpeqb", None), ("vpcmpeqw", None), ("vpsubusw", None)]

# **A shape the naive split gets wrong, and the reason it is here.** The
# count operand of a variable shift is one xmm however wide the data is, so
# splitting it at delta 16 reads sixteen bytes that are not the count. If
# this reported "lane-wise" the harness would be measuring nothing.
NEGATIVE = [("vpslld", None), ("vpsrlq", None)]


def key(mnemonic, immediate):
	"""The label a row is reported under -- unique per case.

	`vpblendw` is asked at three immediates, so the mnemonic alone is not
	a key: keyed on it, the three would overwrite each other and the run
	would report one case having executed three.
	"""
	return mnemonic if immediate is None else f"{mnemonic}/{immediate[1:]}"


def le(values, width):
	fmt = {1: "<B", 2: "<H", 4: "<I", 8: "<Q"}[width]
	return b"".join(struct.pack(fmt, v & ((1 << (width * 8)) - 1))
	                for v in values)


def floats(values):
	return b"".join(struct.pack("<f", v) for v in values)


def doubles(values):
	return b"".join(struct.pack("<d", v) for v in values)


def patterns():
	"""[(name, 64 bytes)] -- src1 in the first 32, src2 in the second.

	Every pattern makes the two 128-bit halves DIFFERENT, which is what
	makes a lane confusion visible at all: a value whose halves agree
	cannot distinguish a correct split from a sabotaged one.
	"""
	out = []

	out.append(("bytes_counter",
	            bytes(range(32)) + bytes((255 - 3 * i) & 0xff
	                                     for i in range(32))))

	state = 0x2545F4914F6CDD1D
	rolled = bytearray()
	for _ in range(64):
		state = (state * 6364136223846793005 + 1442695040888963407) \
			& ((1 << 64) - 1)
		rolled.append((state >> 33) & 0xff)
	out.append(("random", bytes(rolled)))

	out.append(("float_mixed",
	            floats([1.5, -2.25, 0.0, -0.0, 3.5e30, -7.75e-30, 1.0, 2.0])
	            + floats([-1.5, 4.0, 1e-45, float("inf"), -float("inf"),
	                      0.5, -0.25, 8.0])))

	nan1 = [struct.unpack("<f", struct.pack("<I", 0x7fc00000 | (i + 1)))[0]
	        for i in range(8)]
	nan2 = [struct.unpack("<f", struct.pack("<I", 0xff800000 | (0x30 + i)))[0]
	        for i in range(8)]
	out.append(("float_nan", floats(nan1) + floats(nan2)))

	out.append(("double_mixed",
	            doubles([1.5, -0.0, float("inf"), 5e300])
	            + doubles([-2.5, 0.0, -float("inf"), 1e-320])))

	dn1 = [struct.unpack("<d", struct.pack("<Q", 0x7ff8000000000000 | (i + 9)))[0]
	       for i in range(4)]
	dn2 = [struct.unpack("<d", struct.pack("<Q", 0xfff0000000000000 | (i + 77)))[0]
	       for i in range(4)]
	out.append(("double_nan", doubles(dn1) + doubles(dn2)))

	out.append(("edges",
	            le([0x80000000, 0x7fffffff, 0, 0xffffffff,
	                0x00008000, 0xffff7fff, 0x01010101, 0x80008000], 4)
	            + le([0xffffffff, 1, 0x80000000, 0x7fffffff,
	                  0x0000ffff, 0x8000_0001, 0xfefefefe, 0x00010001], 4)))

	out.append(("saturate",
	            le([0x7f80, 0x8081, 0xff01, 0x00ff] * 4, 2)
	            + le([0x0001, 0x7fff, 0x8000, 0xfffe] * 4, 2)))

	# **Built for the negative control, and the reason it exists.** A
	# variable shift takes its count from the low 64 bits of ONE xmm. The
	# first attempt used the general patterns, whose counts are random
	# 64-bit values -- every one of them >= 32, so both halves shifted
	# everything out and the split "agreed" by producing zero twice. That
	# is a check whose pass includes the failure. Counts of 3 and 7, in
	# the two halves of src2, make the wrong count visible.
	out.append(("shift_counts",
	            le([0x13579bdf, 0x2468ace0, 0xfedcba98, 0x76543210,
	                0x0f0f0f0f, 0xf0f0f0f0, 0x01234567, 0x89abcdef], 4)
	            + le([3, 0, 0, 0, 7, 0, 0, 0], 4)))

	for name, blob in out:
		assert len(blob) == 64, (name, len(blob))
	return out


PATTERNS = patterns()


def cases(include_extra):
	"""[(label, mnemonic, immediate, expect)] in the order emitted."""
	out = []
	for mnemonic in LANE_WISE:
		out.append(("LANE_WISE", mnemonic, None, "lane-wise"))
	for mnemonic, immediate in EXCLUDED:
		out.append(("excluded", mnemonic, immediate, "unknown"))
	for mnemonic, immediate in NEGATIVE:
		out.append(("negative-control", mnemonic, immediate, "NOT lane-wise"))
	if include_extra:
		for mnemonic, immediate in EXTRA:
			out.append(("extra", mnemonic, immediate, "unknown"))
	return out


def vex_source(case_list):
	"""The 256-bit side: one function per case, run under qemu.

	Also the VEX.128 form of the same instruction, which is the control
	that puts qemu's arithmetic against this CPU's.
	"""
	lines = [".text"]
	for i, (label, mnemonic, immediate, _expect) in enumerate(case_list):
		imm = f"{immediate}," if immediate else ""
		for name, width, move in (("v256", "ymm", "vmovdqu"),
		                          ("v128", "xmm", "vmovdqu")):
			# A variable shift's count is ONE xmm however wide the data is.
			# That is the whole reason it is a negative control, and the
			# assembler refuses the ymm spelling outright.
			src2 = "xmm" if label == "negative-control" else width
			lines += [f".globl {name}_{i}", f".type {name}_{i}, @function",
			          f"{name}_{i}:",
			          f"\t{move} 0(%rdi), %{width}1",
			          f"\t{move} 32(%rdi), %{src2}2",
			          f"\t{mnemonic} {imm}%{src2}2,%{width}1,%{width}0",
			          f"\t{move} %{width}0, 0(%rsi)",
			          "\tvzeroupper", "\tret", ""]
	return "\n".join(lines) + "\n"


def sse_source(case_list, variant):
	"""The two 128-bit sides, run natively on this Westmere.

	`variant` selects the split. "correct" is deltas 0 and 16, which is
	what `lower_ymm_pair` and `splat_operation` emit. The other two are
	wrong on purpose and exist to prove the comparison can fail.
	"""
	deltas = {"correct": ((0, 0), (16, 16)),
	          "swapped": ((0, 16), (16, 0)),
	          "low_twice": ((0, 0), (16, 0))}[variant]
	lines = [".text"]
	for i, (_label, mnemonic, immediate, _expect) in enumerate(case_list):
		sse = mnemonic[1:]
		imm = f"{immediate}," if immediate else ""
		lines += [f".globl s_{i}", f".type s_{i}, @function", f"s_{i}:"]
		for out_delta, in_delta in deltas:
			lines += [f"\tmovdqa {in_delta}(%rdi), %xmm0",
			          f"\t{sse} {imm}{32 + in_delta}(%rdi), %xmm0",
			          f"\tmovdqu %xmm0, {out_delta}(%rsi)"]
		lines += ["\tret", ""]
	# The 128-bit SSE control: one lane only, against qemu's VEX.128.
	for i, (_label, mnemonic, immediate, _expect) in enumerate(case_list):
		sse = mnemonic[1:]
		imm = f"{immediate}," if immediate else ""
		lines += [f".globl c_{i}", f".type c_{i}, @function", f"c_{i}:",
		          "\tmovdqa 0(%rdi), %xmm0",
		          f"\t{sse} {imm}32(%rdi), %xmm0",
		          "\tmovdqu %xmm0, 0(%rsi)", "\tret", ""]
	return "\n".join(lines) + "\n"


def data_source():
	"""The inputs, assembled once and linked into BOTH binaries.

	Generating them twice is how the two sides end up disagreeing about
	something that is not the instruction.
	"""
	lines = [".section .rodata", ".balign 32", ".globl inputs", "inputs:"]
	for name, blob in PATTERNS:
		lines.append(f"\t/* {name} */")
		lines.append("\t.byte " + ", ".join(f"0x{b:02x}" for b in blob))
	return "\n".join(lines) + "\n"


MAIN = r"""
#include <stdio.h>
#include <string.h>

#define PATTERNS %d
#define CASES %d

extern const unsigned char inputs[];
typedef void (*fn)(const void *in, void *out);
static const fn table[] = { %s };
static const char *const names[] = { %s };

int main(void) {
	static unsigned char out[32] __attribute__((aligned(32)));
	for (int c = 0; c < CASES; c++) {
		for (int p = 0; p < PATTERNS; p++) {
			memset(out, 0xa5, sizeof out);
			table[c](inputs + p * 64, out);
			printf("%%s %%d ", names[c], p);
			for (int i = 0; i < 32; i++) printf("%%02x", out[i]);
			printf("\n");
		}
	}
	return 0;
}
"""


def main_source(prefix, case_list, width):
	table = ", ".join(f"{prefix}_{i}" for i in range(len(case_list)))
	names = ", ".join(f'"{key(c[1], c[2])}"' for c in case_list)
	decls = "\n".join(f"void {prefix}_{i}(const void *, void *);"
	                  for i in range(len(case_list)))
	body = MAIN % (len(PATTERNS), len(case_list), table, names)
	return decls + "\n" + body.replace("for (int i = 0; i < 32;",
	                                   f"for (int i = 0; i < {width};")


def build(name, main_c, asm_files):
	src = WORK / f"{name}.c"
	src.write_text(main_c)
	command = ["gcc", "-Os", "-static", "-o", str(WORK / name), str(src)] \
		+ [str(WORK / a) for a in asm_files]
	done = subprocess.run(command, capture_output=True, text=True,
	                      timeout=TIMEOUT)
	if done.returncode != 0:
		print(done.stderr.rstrip(), file=sys.stderr)
		raise SystemExit(f"lane_oracle: {name} did not build")


def run(argv, under_qemu):
	command = (QEMU if under_qemu else []) + [str(WORK / argv)]
	done = subprocess.run(command, capture_output=True, text=True,
	                      timeout=TIMEOUT)
	if done.returncode != 0:
		print(done.stderr.rstrip()[-2000:], file=sys.stderr)
		raise SystemExit(f"lane_oracle: {argv} exited {done.returncode}")
	rows = {}
	for line in done.stdout.splitlines():
		mnemonic, index, value = line.split()
		rows[(mnemonic, int(index))] = value
	return rows


# **The controls that ask whether qemu is a lane-splitter.** Each has a
# 128-bit form spelled the same way, so "two 128-bit operations at deltas 0
# and 16" is a well-defined rival answer -- and a different one. If qemu
# produced the rival answer for these, every verdict below would be an
# artifact of its interpreter rather than a fact about the ISA. The model
# beside each is computed here from the ISA definition, so the comparison
# does not consult qemu twice.
def control_broadcast(src1, src2):
	return src1[0:4] * 8


def control_broadcast_lanesplit(src1, src2):
	return src1[0:4] * 4 + src1[16:20] * 4


def control_movzx(src1, src2):
	return b"".join(bytes((src1[i], 0)) for i in range(16))


def control_movzx_lanesplit(src1, src2):
	return b"".join(bytes((src1[i], 0)) for i in range(8)) \
		+ b"".join(bytes((src1[16 + i], 0)) for i in range(8))


def control_perm2i128(src1, src2):
	return src1[16:32] + src1[0:16]


def control_permq(src1, src2):
	return b"".join(src1[8 * q:8 * q + 8] for q in (3, 2, 1, 0))


def control_inserti128(src1, src2):
	return src1[0:16] + src2[0:16]


CONTROLS = [
	("vpbroadcastd", "vpbroadcastd %xmm1,%ymm0",
	 control_broadcast, control_broadcast_lanesplit),
	("vpmovzxbw", "vpmovzxbw %xmm1,%ymm0",
	 control_movzx, control_movzx_lanesplit),
	("vperm2i128", "vperm2i128 $0x01,%ymm2,%ymm1,%ymm0",
	 control_perm2i128, None),
	("vpermq", "vpermq $0x1b,%ymm1,%ymm0", control_permq, None),
	("vinserti128", "vinserti128 $0x1,%xmm2,%ymm1,%ymm0",
	 control_inserti128, None),
]


def control_source():
	lines = [".text"]
	for i, (_name, text, _model, _rival) in enumerate(CONTROLS):
		lines += [f".globl k_{i}", f".type k_{i}, @function", f"k_{i}:",
		          "\tvmovdqu 0(%rdi), %ymm1", "\tvmovdqu 32(%rdi), %ymm2",
		          f"\t{text}", "\tvmovdqu %ymm0, 0(%rsi)",
		          "\tvzeroupper", "\tret", ""]
	return "\n".join(lines) + "\n"


def run_controls():
	"""Does qemu reproduce genuinely cross-lane behaviour? -> (pass, fail)."""
	(WORK / "control.s").write_text(control_source())
	case_list = [(None, name, None, None) for name, _t, _m, _r in CONTROLS]
	build("controls", main_source("k", case_list, 32),
	      ["control.s", "data.s"])
	got = run("controls", under_qemu=True)
	good, bad, rival_hit = 0, [], []
	for i, (name, _text, model, rival) in enumerate(CONTROLS):
		for p, (pname, blob) in enumerate(PATTERNS):
			src1, src2 = blob[0:32], blob[32:64]
			want = model(src1, src2).hex()
			have = got[(name, p)]
			if have == want:
				good += 1
			else:
				bad.append((name, pname, want, have))
			if rival is not None:
				alternative = rival(src1, src2).hex()
				# Only a rival that DIFFERS from the model is evidence
				# either way; where the pattern makes them equal the
				# control cannot discriminate and is not counted.
				if alternative != want and have == alternative:
					rival_hit.append((name, pname))
	return good, bad, rival_hit


def compare(vex, sse, case_list, what, width=32):
	"""[(mnemonic, pattern)] where the two sides disagree."""
	differ = []
	for _label, mnemonic, immediate, _expect in case_list:
		name = key(mnemonic, immediate)
		for p, (pname, _blob) in enumerate(PATTERNS):
			a = vex[(name, p)][:width * 2]
			b = sse[(name, p)][:width * 2]
			if a != b:
				differ.append((name, pname, a, b))
	return differ


def require_oracle():
	"""qemu present, able to start, and able to run AVX2.

	One implementation for all four oracles, in `detour`, because
	four copies of this guard have been wrong twice: once asking
	presence where the others asked capability, and once blaming a
	missing AVX2 model for a qemu that produced no output at all.
	"""
	detour.require_qemu(QEMU)


def main():
	global WORK
	if len(sys.argv) > 1:
		WORK = Path(sys.argv[1]) / "laneoracle"
	require_oracle()
	argv = {"--all"}
	problems = 0

	# **Drift is a failure, not a note.** The list below is a second witness
	# and must stay one; what it may not do is quietly cover less than the
	# set the rewriter acts on.
	# On the MNEMONIC, not on `key`, which carries an immediate for the
	# shapes that take one -- `vpblendw/0x0f` is `vpblendw` executed.
	claimed = set(detour.LANE_WISE)
	executed = {mnemonic for _l, mnemonic, _i, _e in cases(True)}
	missing = sorted(claimed - executed)
	if missing:
		print(f"lane_oracle: FAILED -- detour.LANE_WISE claims "
		      f"{len(missing)} mnemonic(s) this harness does not execute: "
		      f"{' '.join(missing)}", file=sys.stderr)
		problems += 1

	case_list = cases("--all" in argv or "--extra" in argv)
	WORK.mkdir(parents=True, exist_ok=True)
	(WORK / "data.s").write_text(data_source())
	(WORK / "vex.s").write_text(vex_source(case_list))
	(WORK / "sse.s").write_text(sse_source(case_list, "correct"))

	build("vex256", main_source("v256", case_list, 32), ["vex.s", "data.s"])
	build("vex128", main_source("v128", case_list, 16), ["vex.s", "data.s"])
	build("sse", main_source("s", case_list, 32), ["sse.s", "data.s"])
	build("sse128", main_source("c", case_list, 16), ["sse.s", "data.s"])

	print("== capability control: the 256-bit binary must not run here ==")
	native = subprocess.run([str(WORK / "vex256")], capture_output=True,
	                        timeout=TIMEOUT)
	print(f"   native exit {native.returncode}"
	      f"{' (SIGILL -- host cannot execute the input)' if native.returncode == -4 else ' -- EXPECTED SIGILL'}")

	print("== control: qemu VEX.128 against this CPU's SSE ==")
	v128, s128 = run("vex128", True), run("sse128", False)
	arithmetic = compare(v128, s128, case_list, "128", width=16)
	total = len(case_list) * len(PATTERNS)
	print(f"   {total - len(arithmetic)}/{total} agree bit-for-bit")
	for row in arithmetic:
		print(f"   DIFFER {row[0]:12} {row[1]:14} qemu={row[2]} sse={row[3]}")

	if "--controls" in argv or "--all" in argv:
		print("== control: is qemu a blind lane-splitter? ==")
		good, bad, rival = run_controls()
		print(f"   {good}/{len(CONTROLS) * len(PATTERNS)} cross-lane results "
		      f"match the model computed here")
		for row in bad:
			print(f"   MISMATCH {row[0]} {row[1]} want={row[2]} got={row[3]}")
		print(f"   lane-split rival answer produced: {len(rival)} times "
		      f"(must be 0)")
		problems += len(bad) + len(rival)

	# **Two comparisons, because the first run conflated two questions.**
	# 256-bit under qemu against the split executed NATIVELY is what the
	# rewriter actually does, and it is the answer that matters -- but a
	# difference in it can come from qemu's arithmetic as easily as from
	# the lanes, and on the first run eight of the thirty-two "failed"
	# purely because qemu picks the wrong NaN operand. Running the split
	# under qemu as well cancels every arithmetic quirk the two sides
	# share and leaves nothing but the lane structure.
	print("== the question ==")
	v256 = run("vex256", True)
	native_split = run("sse", False)
	qemu_split = run("sse", True)
	lanes = compare(v256, qemu_split, case_list, "lanes")
	whole = compare(v256, native_split, case_list, "whole")
	lane_bad = {row[0] for row in lanes}
	whole_bad = {row[0] for row in whole}
	arithmetic_bad = {row[0] for row in arithmetic}
	differ = lanes
	verdict = {}
	for _label, mnemonic, immediate, _e in case_list:
		name = key(mnemonic, immediate)
		verdict[name] = "NOT lane-wise" if name in lane_bad else "lane-wise"

	sab = {}
	if "--sabotage" in argv or "--all" in argv:
		for variant in ("swapped", "low_twice"):
			(WORK / "sse.s").write_text(sse_source(case_list, variant))
			build(f"sse_{variant}", main_source("s", case_list, 32),
			      ["sse.s", "data.s"])
			# Under qemu, like the 256-bit side: a sabotage must be
			# rejected for its LANES, not because qemu and this CPU
			# disagree about a NaN.
			wrong = run(f"sse_{variant}", True)
			caught = {row[0] for row in compare(v256, wrong, case_list, variant)}
			sab[variant] = caught

	widest = max(len(key(c[1], c[2])) for c in case_list)
	for label, mnemonic, immediate, expect in case_list:
		name = key(mnemonic, immediate)
		marks = []
		for variant, caught in sab.items():
			marks.append(f"{variant}:"
			             f"{'rejected' if name in caught else 'ACCEPTED'}")
		flag = ""
		if expect != "unknown" and verdict[name] != expect:
			flag = "   <<< DISAGREES WITH THE CLAIM"
		# What the rewriter's own sequence does, and where a difference in
		# it is already explained by qemu's arithmetic at 128 bits.
		if name not in whole_bad:
			composite = "native-split identical"
		elif name in arithmetic_bad:
			composite = "native-split differs: qemu FP (see 128-bit control)"
		else:
			composite = "native-split DIFFERS, unexplained"
		print(f"   {label:16} {name:{widest}}  {verdict[name]:14}"
		      f" {' '.join(marks)}  {composite}{flag}")

	for row in differ:
		print(f"   detail {row[0]:12} {row[1]:14}\n"
		      f"          256 {row[2]}\n          sse {row[3]}")

	print(f"== {len(case_list)} mnemonics x {len(PATTERNS)} patterns = "
	      f"{total} comparisons of 32 bytes each ==")

	# **The verdict has to be a status, or this is a report and not a
	# check.** A mnemonic the rewriter splits and this measures as not
	# lane-wise is a live miscompilation; a sabotage that passes means the
	# inputs could not tell the right split from a wrong one, so the
	# mnemonic's verdict is unearned whichever way it came out.
	for _label, mnemonic, immediate, _expect in case_list:
		if mnemonic not in claimed:
			continue
		name = key(mnemonic, immediate)
		if verdict[name] != "lane-wise":
			print(f"lane_oracle: FAILED -- detour.LANE_WISE splits {name} "
			      f"and it is NOT lane-wise", file=sys.stderr)
			problems += 1
		for variant, caught in sab.items():
			if name not in caught:
				print(f"lane_oracle: FAILED -- the {variant} sabotage of "
				      f"{name} was accepted, so its verdict is unearned",
				      file=sys.stderr)
				problems += 1
	if not problems:
		print(f"lane_oracle: every one of the {len(claimed)} mnemonics "
		      f"detour.LANE_WISE splits is lane-wise under execution, and "
		      f"both sabotages of each were rejected")
	return 1 if problems else 0


if __name__ == "__main__":
	raise SystemExit(main())
