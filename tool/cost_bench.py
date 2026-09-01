#!/usr/bin/env python3
"""Time what each lowering emits, because bytes are not cycles.

Finding 162 priced every strategy in bytes of stub per site and said what
the unit could not do: a `movups` to a memory slot and a `movaps` between
registers are the same length and not the same cost, **which is exactly the
difference between a region and a pair**. That is the one comparison the
byte model understates, and it decides where the region belongs in
`collect`'s chain.

This times the emitted bytes instead. Every sequence here comes out of the
real lowering functions rather than being written by hand: `lower_ymm_pair`
for the pair, `lower_ymm_span` for the region, `encode_spill` around a
lowering for the borrow. A benchmark of what somebody believes the tool
emits measures the belief.

**It cannot compare against the original.** This host has no AVX, so the
256-bit form cannot be timed here at all -- which is the project's premise
and the reason `vex_oracle` runs it under qemu. What this answers is the
question that is actually open: given two lowerings that both work, which
costs more per site.

The loop runs the body many times over a buffer that stays in L1, so what
is measured is issue and forwarding rather than memory. A slot in the
callee home space is as hot as any other stack line, which is the case the
rewriter actually creates.

Usage:  cost_bench.py [build directory]
"""

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import detour
import patch as inplace

WORK = Path("build") / "costbench"
ROUNDS = 4_000_000

# A 256-bit copy: the work a `pair` does and a region does differently.
LOAD = bytes.fromhex("c5fc1006")		# vmovups (%rsi),%ymm0
STORE = bytes.fromhex("c5fc1107")		# vmovups %ymm0,(%rdi)
# The same copy with an add in the middle, which only a region can carry.
ADDM = bytes.fromhex("c5fc584640")		# vaddps 0x40(%rsi),%ymm0,%ymm0


def pair_body():
	"""What `lower_ymm_pair` emits for a 256-bit copy: four 128-bit moves."""
	load_vex = inplace.decode_vex(LOAD)
	store_vex = inplace.decode_vex(STORE)
	pair = ((load_vex, LOAD[load_vex["length"]:], 0x1000, len(LOAD)),
	        (store_vex, STORE[store_vex["length"]:], 0x1004, len(STORE)))
	return detour.lower_ymm_pair(pair, 0x2000)


def span_body(rows, members, slots, helper=5, second=4):
	"""What `lower_ymm_span` emits, through slots at `(%rsp)`."""
	ins, at = [], 0x1000
	for encoding, mnemonic, operands in rows:
		bits = bytes.fromhex(encoding)
		ins.append((at, bits, mnemonic, operands, None))
		at += len(bits)
	entries = detour.span_entries(members, ins, slots, None, [])
	return detour.lower_ymm_span(entries, 0, helper, 0x2000, 0, None, second)


def cases():
	"""[(name, sites, body)] -- `sites` is the VEX instructions it replaces."""
	out = []
	out.append(("pair: a 256-bit copy, register helper", 2, pair_body()))
	out.append(("region: the same copy, through a slot", 2, span_body(
		[("c5fc1006", "vmovups", "(%rsi),%ymm0"),
		 ("c5fc1107", "vmovups", "%ymm0,(%rdi)")],
		[("load", 0, "%ymm0"), ("store", 1, "%ymm0")], {"%ymm0": 0})))
	out.append(("region: a copy with an add, which a pair cannot do", 3,
	            span_body(
		[("c5fc1006", "vmovups", "(%rsi),%ymm0"),
		 ("c5fc584640", "vaddps", "0x40(%rsi),%ymm0,%ymm0"),
		 ("c5fc1107", "vmovups", "%ymm0,(%rdi)")],
		[("load", 0, "%ymm0"), ("lane", 1, "%ymm0"),
		 ("store", 2, "%ymm0")], {"%ymm0": 0})))
	return [(name, sites, body) for name, sites, body in out if body]


MAIN = r"""
#include <stdio.h>
#include <time.h>
#define ROUNDS %d
#define PASSES 9
%s
/* **Normal floats, not a byte pattern.** The first version filled this
   with i*7+3 and the case carrying an `addps` timed at 87 ns against 5 ns
   for a sequence two instructions shorter -- a microcode assist on
   denormal inputs, which this Westmere takes on every one. It was
   measuring the FPU's exception path rather than the lowering. Values
   near 1.0 are what the rewritten program's own data looks like and what
   the comparison is about. */
static float buf[128] __attribute__((aligned(64)));
/* **The minimum of several passes, not one pass.** A single timing of a
   three-nanosecond body is dominated by whatever else the machine is
   doing: three consecutive runs gave the pair 3.12, 5.18 and 3.08 ns and
   the region 3.49, 2.28 and 4.64, which is noise larger than the
   difference being measured and reverses the ranking between runs.
   Nothing makes code faster, so the minimum is the measurement and
   everything above it is interference. */
static double run(void (*f)(void *out, const void *in)) {
	struct timespec a, b;
	double best = 1e30;
	f(buf + 64, buf);			/* warm */
	for (int pass = 0; pass < PASSES; pass++) {
		clock_gettime(CLOCK_MONOTONIC, &a);
		for (long i = 0; i < ROUNDS; i++) f(buf + 64, buf);
		clock_gettime(CLOCK_MONOTONIC, &b);
		double ns = (b.tv_sec - a.tv_sec) * 1e9
			+ (b.tv_nsec - a.tv_nsec);
		if (ns < best) best = ns;
	}
	return best;
}
int main(void) {
	for (int i = 0; i < 128; i++) buf[i] = 1.0f + (float)(i %% 17) * 0.25f;
%s
	return 0;
}
"""


def build(rows):
	WORK.mkdir(parents=True, exist_ok=True)
	lines = [".text"]
	for i, (_name, _sites, body) in enumerate(rows):
		lines += [f".globl body_{i}", f".type body_{i}, @function",
		          f"body_{i}:", "\tsubq\t$128, %rsp"]
		for at in range(0, len(body), 8):
			lines.append("\t.byte " + ", ".join(str(b)
			                                    for b in body[at:at + 8]))
		lines += ["\taddq\t$128, %rsp", "\tret", ""]
	(WORK / "bodies.s").write_text("\n".join(lines) + "\n")
	decls = "\n".join(f"extern void body_{i}(void *out, const void *in);"
	                  for i in range(len(rows)))
	# **One run, two columns.** The first version called `run` once per
	# column, so the total and the per-site figure came from different
	# measurements and did not divide -- 3.24 ns printed beside 1.79
	# ns/site for two sites. A number that cannot be checked against the
	# one beside it invites being believed separately.
	calls = "\n".join(
		f'\t{{ double t = run(body_{i}) / ROUNDS;'
		f' printf("%-46s %8.2f ns  %6.2f ns/site\\n", "{name}", t,'
		f' t / {sites}); }}'
		for i, (name, sites, _b) in enumerate(rows))
	(WORK / "bench.c").write_text(MAIN % (ROUNDS, decls, calls))
	binary = WORK / "bench"
	subprocess.run(["gcc", "-O2", "-o", str(binary), str(WORK / "bench.c"),
	                str(WORK / "bodies.s")], check=True, timeout=300)
	return binary


def main():
	global WORK
	if len(sys.argv) > 1:
		WORK = Path(sys.argv[1]) / "costbench"
	rows = cases()
	if not rows:
		print("cost_bench: no lowering produced bytes, which means the "
		      "emitters changed rather than that there is nothing to time",
		      file=sys.stderr)
		return 2
	print(f"== {len(rows)} lowerings, {ROUNDS:,} rounds each, buffer in L1 ==")
	for name, sites, body in rows:
		print(f"   {name:<46} {len(body):>4} bytes, {sites} site(s)")
	print()
	done = subprocess.run([str(build(rows))], capture_output=True, text=True,
	                      timeout=600)
	print(done.stdout, end="")
	if done.returncode != 0:
		print(f"cost_bench: the benchmark exited {done.returncode}",
		      file=sys.stderr)
		return 1
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
