#!/usr/bin/env python3
"""Settle `--fma=exact` by executing it: one rounding, bit for bit.

The original scalar FMA runs under `qemu-x86_64`, which executes it on a
host that has no FMA; the lowering -- the stub and the helper it calls --
runs natively, and is pure SSE. Every case feeds both the same two million
inputs, a quarter of them built so that the product nearly cancels the
addend, which is where two roundings and one disagree. Both sides hash all
sixteen xmm registers afterwards except the scratch, so a helper that
failed to restore what it saved, or a `movss` that disturbed the
destination's upper lanes, shows as well as a wrong low float.

Each side also checks itself against glibc's `fmaf`, which is correctly
rounded in software, with the operands and signs this file names from the
SDM rather than from `detour`'s own reading of the suffix. So qemu and the
lowering agreeing is not the only witness: each agrees with a third.

The control is the default lowering, `mulss` and `addss`, which must be
seen to disagree -- otherwise the inputs cannot tell one rounding from two
and every agreement above is unearned.

Usage:  fma_oracle.py [build directory]
"""

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import detour

WORK = Path("build") / "fmaoracle"
QEMU = ["qemu-x86_64", "-cpu", "max"]
TIMEOUT = 600
VECTORS = 2000000

# `(instruction, scratch, destination, a, b, c, negate product, negate c)`.
# Registers by number, 16 meaning the memory operand, which every case
# addresses as 0x100(%rsi). In AT&T order an FMA is `op src2,src1,dst`:
#     132   dst = dst  * src2 + src1
#     213   dst = src1 * dst  + src2
#     231   dst = src1 * src2 + dst
CASES = [
	("vfmadd231ss %xmm2,%xmm1,%xmm0", 7, 0, 1, 2, 0, 0, 0),
	("vfmadd213ss %xmm2,%xmm1,%xmm0", 7, 0, 1, 0, 2, 0, 0),
	("vfmadd132ss %xmm2,%xmm1,%xmm0", 7, 0, 0, 2, 1, 0, 0),
	("vfmsub231ss %xmm2,%xmm1,%xmm0", 7, 0, 1, 2, 0, 0, 1),
	("vfnmadd231ss %xmm2,%xmm1,%xmm0", 7, 0, 1, 2, 0, 1, 0),
	("vfnmsub231ss %xmm2,%xmm1,%xmm0", 7, 0, 1, 2, 0, 1, 1),
	# A memory factor, and a memory addend.
	("vfmadd231ss 0x100(%rsi),%xmm1,%xmm0", 7, 0, 1, 16, 0, 0, 0),
	("vfmadd213ss 0x100(%rsi),%xmm1,%xmm0", 7, 0, 1, 0, 16, 0, 0),
	# REX everywhere, a scratch the helper's own registers must step
	# around, and both negations against memory.
	("vfmsub132ss 0x100(%rsi),%xmm9,%xmm10", 3, 10, 10, 16, 9, 0, 1),
	("vfnmadd213ss 0x100(%rsi),%xmm11,%xmm3", 0, 3, 11, 3, 16, 1, 0),
	("vfnmsub213ss %xmm12,%xmm13,%xmm14", 15, 14, 13, 14, 12, 1, 1),
	# One register three times: x*x + x.
	("vfmadd231ss %xmm5,%xmm5,%xmm5", 12, 5, 5, 5, 5, 0, 0),
]


def assemble(text):
	"""The instruction's bytes, from `as` rather than from this tool."""
	WORK.mkdir(parents=True, exist_ok=True)
	(WORK / "one.s").write_text(f".text\n\t{text}\n")
	subprocess.run(["as", "-o", str(WORK / "one.o"), str(WORK / "one.s")],
	               check=True, timeout=TIMEOUT)
	subprocess.run(["objcopy", "-O", "binary", "-j", ".text",
	                str(WORK / "one.o"), str(WORK / "one.bin")],
	               check=True, timeout=TIMEOUT)
	return (WORK / "one.bin").read_bytes()


def moves(store):
	"""movups of all sixteen xmm from (%rsi) or to (%rdi), disp32."""
	out = bytearray()
	for n in range(16):
		if n >= 8:
			out.append(0x44)
		out += b"\x0f\x11" if store else b"\x0f\x10"
		out.append(0x80 | ((n & 7) << 3) | (7 if store else 6))
		out += (16 * n).to_bytes(4, "little")
	return bytes(out)


def function(middle, pool):
	"""`run(out, in)`: load, `middle`, store, return, then `pool`.

	`middle` is laid out at `len(moves(False))`, which is the `at` the
	lowering was built for, and the pool at the next 16-byte boundary.
	"""
	body = moves(False) + middle + moves(True) + b"\xc3"
	body += b"\xcc" * (-len(body) % 16)
	return body + pool


def pool_at(middle_length):
	"""Where `function` will put the pool, given the middle's length."""
	length = 2 * len(moves(False)) + middle_length + 1
	return length + (-length % 16)


def lower(encoding, text, scratch):
	"""The stub for one FMA at `at`, reaching its helper. Bytes, or None."""
	mnemonic, operands = text.split(None, 1)
	at = len(moves(False))
	# The stub's length does not depend on where the pool is, so lower it
	# once to measure and again against the real address.
	trial = detour.lower_vex(0, encoding, operands, mnemonic, at, scratch,
	                         at)
	if trial is None:
		return None
	pool = pool_at(len(trial))
	return detour.lower_vex(0, encoding, operands, mnemonic, at, scratch,
	                        pool), pool


MAIN = r"""
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern void run(void *out, const void *in);

static uint32_t state = 12345;
static uint32_t next(void)
{
	state ^= state << 13;
	state ^= state >> 17;
	state ^= state << 5;
	return state;
}

static float pick(void)
{
	static const float special[] = {0.0f, -0.0f, 1.0f, -1.0f, 0x1p-149f,
		-0x1p-149f, 0x1p-126f, 0x1.fffffep127f, INFINITY, -INFINITY, NAN,
		0.5f, 3.0f, 0x1.000002p0f, 0x1.fffffep-1f};
	uint32_t r = next();
	if ((r & 15) == 0)
		return special[next() % (sizeof special / sizeof *special)];
	float f;
	r = next();
	if ((r & 3) == 0)	/* narrow exponents make cancellation likely */
		r = (r & 0x807fffff) | ((uint32_t)(120 + next() % 16) << 23);
	memcpy(&f, &r, 4);
	return f;
}

int main(void)
{
	static float in[17][4] __attribute__((aligned(16)));
	static float out[16][4] __attribute__((aligned(16)));
	uint64_t hash = 14695981039346656037ull;
	long wrong = 0, moved = 0, nans = 0;
	for (long i = 0; i < VECTORS; i++) {
		for (int r = 0; r < 17; r++)
			for (int k = 0; k < 4; k++) {
				uint32_t bits = next();
				memcpy(&in[r][k], &bits, 4);
			}
		float a = pick(), b = pick(), c = pick();
		/* The product nearly cancels the addend: where one rounding and
		 * two disagree. Only from a finite product, because this is the
		 * harness's own arithmetic and qemu propagates a NaN through it
		 * differently from the silicon -- the two sides then fed the FMA
		 * different inputs and the hashes parted for that alone. */
		double product = (double)a * b;
		if ((i & 3) == 0 && isfinite((float)product)) {
			double p = (double)a * b * (NEG_P ? -1 : 1);
			c = (float)-p + (float)((int)(next() & 0xff) - 128)
				* 0x1p-30f * (float)p;
			if (NEG_C)
				c = -c;
		}
		in[A][0] = a;
		in[B][0] = b;
		in[C][0] = c;
		/* where operands share a register the last write is the value */
		a = in[A][0];
		b = in[B][0];
		c = in[C][0];
		float upper[3];
		memcpy(upper, &in[D][1], 12);
		run(out, in);
		/* Which NaN comes out of several is the SSE instructions' choice,
		 * not the FMA's (see FMA_EXACT), so a NaN result is hashed as
		 * one NaN and counted. */
		if (isnan(out[D][0])) {
			uint32_t quiet = 0x7fc00000;
			memcpy(&out[D][0], &quiet, 4);
			nans++;
		}
		for (int r = 0; r < 16; r++) {
			if (r == SCRATCH)
				continue;
			const unsigned char *p = (const unsigned char *)out[r];
			for (int k = 0; k < 16; k++)
				hash = (hash ^ p[k]) * 1099511628211ull;
			if (r != D && memcmp(out[r], in[r], 16))
				moved++;
		}
		if (memcmp(&out[D][1], upper, 12))
			moved++;
		float want = fmaf(NEG_P ? -a : a, b, NEG_C ? -c : c);
		float got = out[D][0];
		uint32_t w, g;
		memcpy(&w, &want, 4);
		memcpy(&g, &got, 4);
		if (w != g && !(isnan(want) && isnan(got)))
			wrong++;
	}
	printf("%016llx %ld %ld %ld\n", (unsigned long long)hash, wrong, moved,
	       nans);
	return 0;
}
"""


def build(where, body, case):
	"""Assemble and link one side. The binary's path."""
	_text, scratch, d, a, b, c, negate_p, negate_c = case
	WORK.mkdir(parents=True, exist_ok=True)
	lines = [".text", ".globl run", ".type run, @function", "run:"]
	for i in range(0, len(body), 16):
		lines.append("\t.byte " + ", ".join(str(x) for x in body[i:i + 16]))
	(WORK / f"{where}.s").write_text("\n".join(lines) + "\n")
	(WORK / f"{where}.c").write_text(MAIN)
	binary = WORK / where
	defines = [f"-DVECTORS={VECTORS}", f"-DSCRATCH={scratch}", f"-DD={d}",
	           f"-DA={a}", f"-DB={b}", f"-DC={c}", f"-DNEG_P={negate_p}",
	           f"-DNEG_C={negate_c}"]
	subprocess.run(["gcc", "-O2", "-ffp-contract=off", *defines, "-o",
	                str(binary), str(WORK / f"{where}.c"),
	                str(WORK / f"{where}.s"), "-lm"],
	               check=True, timeout=TIMEOUT)
	return binary


def run(binary, under_qemu):
	"""(hash, wrong against fmaf, registers disturbed, NaN results)."""
	command = (QEMU if under_qemu else []) + [str(binary)]
	done = subprocess.run(command, capture_output=True, text=True,
	                      timeout=TIMEOUT)
	fields = done.stdout.split()
	if done.returncode != 0 or len(fields) != 4:
		print(f"fma_oracle: {binary.name} exited {done.returncode}: "
		      f"{done.stdout.strip()} {done.stderr.strip()}",
		      file=sys.stderr)
		return None
	return fields[0], int(fields[1]), int(fields[2]), int(fields[3])


def main():
	global WORK
	if len(sys.argv) > 1:
		WORK = Path(sys.argv[1]) / "fmaoracle"
	detour.require_qemu(QEMU)
	problems = 0

	print("== capability control: the original must not run here ==")
	case = CASES[0]
	encoding = assemble(case[0])
	native = build("cap", function(encoding, b""), case)
	done = subprocess.run([str(native)], capture_output=True,
	                      timeout=TIMEOUT)
	print(f"   native exit {done.returncode}"
	      f"{' (SIGILL)' if done.returncode == -4 else ' -- EXPECTED SIGILL'}")
	if done.returncode != -4:
		print("fma_oracle: FAILED -- this host executed an FMA, so the "
		      "comparison proves nothing", file=sys.stderr)
		problems += 1

	detour.FMA_EXACT = True
	pool = detour.stub_pool()
	for i, case in enumerate(CASES):
		text, scratch = case[0], case[1]
		encoding = assemble(text)
		lowered = lower(encoding, text, scratch)
		if lowered is None or lowered[0] is None:
			print(f"fma_oracle: FAILED -- {text}: refused to lower",
			      file=sys.stderr)
			problems += 1
			continue
		stub, where = lowered
		body = function(stub, pool)
		assert len(body) - len(pool) == where, "the pool moved"
		sse = run(build(f"sse{i}", body, case), False)
		vex = run(build(f"vex{i}", function(encoding, b""), case), True)
		good = (sse is not None and vex is not None and sse == vex
		        and sse[1] == 0 and sse[2] == 0)
		note = "" if sse is None else \
			f"{sse[1]:,} off fmaf, {sse[2]:,} registers disturbed"
		print(f"   {text:42} {'agree' if good else 'DIFFER'}  {note}")
		if not good:
			print(f"       lowered {sse}\n       original {vex}",
			      file=sys.stderr)
			problems += 1

	print("== control: the default lowering, two roundings, must differ ==")
	detour.FMA_EXACT = False
	case = CASES[0]
	encoding = assemble(case[0])
	mnemonic, operands = case[0].split(None, 1)
	at = len(moves(False))
	stub = detour.lower_vex(0, encoding, operands, mnemonic, at, case[1])
	fast = run(build("fast", function(stub, b""), case), False)
	vex = run(build("vex0", function(encoding, b""), case), True)
	caught = fast is not None and vex is not None and fast[0] != vex[0] \
		and fast[1] > 0
	print(f"   mulss then addss: "
	      f"{'rejected' if caught else 'ACCEPTED'}"
	      f"{'' if fast is None else f', {fast[1]:,} off fmaf'}")
	if not caught:
		print("fma_oracle: FAILED -- the inputs cannot tell one rounding "
		      "from two, so the agreements above are unearned",
		      file=sys.stderr)
		problems += 1

	if not problems:
		print(f"fma_oracle: {len(CASES)} scalar FMA form(s) lower under "
		      f"--fma=exact to SSE that computes what the original "
		      f"computes, bit for bit, over {VECTORS:,} inputs each")
	return 1 if problems else 0


if __name__ == "__main__":
	raise SystemExit(main())
