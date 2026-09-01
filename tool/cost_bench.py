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

**Resolution, and how it is known rather than asserted.** The first version
called each body once per iteration, so every measurement carried a `call`,
a frame, a `ret` and a loop -- six or seven cycles wrapped around a
three-uop sequence the core overlapped with them. Everything read 2.1 ns,
one case read below an empty body, and nothing could be ranked (Finding
168). The body is now repeated UNROLL times inside one call, which drops
the floor to about 0.05 ns, and the passes run outside the cases rather
than inside, so a drifting clock moves every case together instead of one
against another.

**The rig checks itself against the ISA.** Eight `addps` in a dependency
chain must take three times eight independent ones, on any clock, because
Westmere gives the instruction three cycles of latency and one per cycle of
throughput. That ratio is printed and enforced: miss it and the tool says
the table is not a measurement and exits 3. It is the only error here that
the table cannot show on its own, since every strategy inflating together
looks exactly like every strategy being slow -- which is what a shared
machine does. See Finding 169.
"""

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import detour
import patch as inplace

WORK = Path("build") / "costbench"
ROUNDS = 100_000
# **The body is repeated inside the function, not called again.** One
# `call`, one frame, one `ret`, one counter and one branch cost six or
# seven cycles on this Westmere, and a lowering is three to five uops the
# core overlaps with them entirely -- which is why every strategy first
# measured at 2.1 ns and one measured below an empty body. Repeating the
# sequence UNROLL times inside one call divides that overhead by UNROLL
# and leaves the sequence itself as the thing being timed.
#
# What this measures is therefore the sequence **back to back with
# itself**, dependencies and all: a `plain` carries a chain through xmm2
# and a `spill` reloads the slot it just wrote. That is the hot-loop case,
# which is the one the rewriter's output has to survive.
UNROLL = 64
# The minimum over more passes, because on a contended machine the
# measurement wanted is the quietest slice that occurred and more passes
# is more chances at one. Each pass is now a fraction of a second.
PASSES = 15

# Calibration, and the only sequences here not emitted by a lowering.
# `addps` on Westmere is 3 cycles of latency and one per cycle of
# throughput, so eight in a dependency chain must take three times eight
# independent ones. That ratio is fixed by the ISA and does not depend on
# the clock, so it checks the harness against something outside itself:
# a rig that cannot see 3.0 here cannot resolve one cycle anywhere.
CALIB_CYCLES = 8
CALIB_INDEP = bytes.fromhex("0f58c1" "0f58d3" "0f58e5" "0f58f7") * 2
CALIB_DEP = bytes.fromhex("0f58c1") * 8

# A Class C site whose src2 IS the destination, which is what `plain`
# lowers and what a borrow is needed for when no register is dead.
ALIASED = bytes.fromhex("c5f05cd2")		# vsubps %xmm2,%xmm1,%xmm2
# A 256-bit store of a register a zeroing idiom emptied: two 128-bit
# stores of the same xmm, no scratch and no second register.
ZEROSTORE = bytes.fromhex("c5fc111f")		# vmovups %ymm3,(%rdi)

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


def plain_body():
	"""What `lower_vex` emits for an aliased Class C site, with a scratch."""
	return detour.lower_vex(0x1000, ALIASED, "%xmm2,%xmm1,%xmm2", "vsubps",
	                        0x2000, scratch=5, pool=0x2000)


def spill_body():
	"""The same site with the scratch BORROWED: save, lower, restore.

	`build_stub`'s `spill` shape exactly. The byte model puts this at 24.4
	per site against a pair's 12.4 and it is the dearest thing done in
	quantity -- 3,013 windows, and what the borrow costs static TLS. Two
	round trips through memory around a lowering is a shape where bytes
	and cycles have every reason to disagree.
	"""
	body = bytearray()
	body += detour.encode_spill(5, True, 0x2000, 0, 0, 0)
	lowered = detour.lower_vex(0x1000, ALIASED, "%xmm2,%xmm1,%xmm2",
	                           "vsubps", 0x2000 + len(body), scratch=5,
	                           pool=0x2000)
	if lowered is None:
		return None
	body += lowered
	body += detour.encode_spill(5, False, 0x2000 + len(body), 0, 0, 0)
	return bytes(body)


def zero_body():
	"""What `lower_ymm_zero_store` emits: two 128-bit stores, no scratch."""
	vex = inplace.decode_vex(ZEROSTORE)
	return detour.lower_ymm_zero_store(vex, ZEROSTORE[vex["length"]:],
	                                   0x1000, len(ZEROSTORE), 0x2000)


def run_body():
	"""What `lower_ymm_run` emits for a load, an add and a store.

	Built by handing the real lowering a strategy, the way `span_body`
	hands `lower_ymm_span` real entries. Three sites, so it is directly
	comparable to the region's copy-with-an-add.

	There is no `zerorun_body`: `zerorun` has no lowering function of its
	own to call, and writing its sequence by hand would measure a belief.
	"""
	def entry(kind, raw, address):
		vex = inplace.decode_vex(raw)
		return (kind, 5, vex, raw[vex["length"]:], address, len(raw), None)

	strategy = ((5,), [entry("load", LOAD, 0x1000),
	                   entry("op", ADDM, 0x1000 + len(LOAD)),
	                   entry("store", STORE,
	                         0x1000 + len(LOAD) + len(ADDM))])
	return detour.lower_ymm_run(strategy, 0x2000, 0x2000)


def cases():
	"""[(name, sites, body)] -- `sites` is the VEX instructions it replaces."""
	out = []
	# The control. An empty body still pays the loop: the counter, the
	# branch, and the call and return around it. Whatever this reads is
	# the floor, and a strategy that measures at the floor has not been
	# distinguished from doing nothing -- which is a statement about the
	# harness's resolution, not about the strategy being free.
	out.append(("(control) an empty body: the loop's own cost", 1, b""))
	out.append(("(calibration) 8 independent addps, 1 cycle each", 1,
	            CALIB_INDEP))
	out.append(("(calibration) 8 chained addps, 3 cycles each", 1,
	            CALIB_DEP))
	out.append(("plain: an aliased site, a dead register to hand", 1,
	            plain_body()))
	out.append(("spill: the same site, the register BORROWED (stack)", 1,
	            spill_body()))
	out.append(("zero: a 256-bit store of an emptied register", 1,
	            zero_body()))
	out.append(("run: a load, an add and a store, split in place", 3,
	            run_body()))
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
	# `is not None`, not truthiness: a lowering that refused returns None
	# and belongs dropped, but an EMPTY body is a real measurement -- the
	# control depends on surviving this line, and a strategy that emitted
	# nothing would otherwise vanish from the table rather than be seen.
	return [(name, sites, body) for name, sites, body in out
	        if body is not None]


MAIN = r"""
#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <time.h>
#define ROUNDS @@ROUNDS@@
#define UNROLL @@UNROLL@@
#define PASSES @@PASSES@@
#define NCASES @@NCASES@@
@@DECLS@@
/* **Normal floats, not a byte pattern.** The first version filled this
   with i*7+3 and the case carrying an `addps` timed at 87 ns against 5 ns
   for a sequence two instructions shorter -- a microcode assist on
   denormal inputs, which this Westmere takes on every one. It was
   measuring the FPU's exception path rather than the lowering. Values
   near 1.0 are what the rewritten program's own data looks like and what
   the comparison is about. */
static float buf[128] __attribute__((aligned(64)));
@@TABLE@@
/* **Thread CPU time, not wall time.** This machine is shared, and a run
   taken at load 106 on twelve cores measured a one-cycle dependent add at
   2.653 ns -- an 8.5x inflation, which is the oversubscription and not the
   code. CLOCK_THREAD_CPUTIME_ID counts only the time this thread was
   actually on a CPU, which removes preemption and recovers about 3x of
   that. It cannot remove an SMT sibling competing for the same ports, so
   a busy machine still reads slow; that is what the calibration is for. */
static double once(void (*f)(void *out, const void *in)) {
	struct timespec a, b;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &a);
	for (long i = 0; i < ROUNDS; i++) f(buf + 64, buf);
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &b);
	return (b.tv_sec - a.tv_sec) * 1e9 + (b.tv_nsec - a.tv_nsec);
}
int main(void) {
	/* Pinned, because a migration between two cases is indistinguishable
	   from one of them being slower. */
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(0, &set);
	sched_setaffinity(0, sizeof set, &set);
	for (int i = 0; i < 128; i++) buf[i] = 1.0f + (float)(i % 17) * 0.25f;
	int bad = 0;
	double best[NCASES];
	for (int c = 0; c < NCASES; c++) {
		best[c] = 1e30;
		FNS[c](buf + 64, buf);		/* warm */
	}
	/* **Passes outside, cases inside.** The first version ran all nine
	   passes of one case before starting the next, so a clock that drifted
	   between them moved one case against another and nothing shared the
	   drift -- which is how an aliased lowering measured 0.26 ns FASTER
	   than an empty body. Interleaved, every case meets the same machine.
	   Nothing makes code faster, so the minimum is the measurement and
	   everything above it is interference. */
	for (int pass = 0; pass < PASSES; pass++)
		for (int c = 0; c < NCASES; c++) {
			double ns = once(FNS[c]);
			if (ns < best[c]) best[c] = ns;
		}
	double each[NCASES];
	for (int c = 0; c < NCASES; c++)
		each[c] = best[c] / (double)ROUNDS / (double)UNROLL;
	double floor_ns = each[0];
	double indep = each[@@INDEP@@] - floor_ns;
	double dep = each[@@DEP@@] - floor_ns;
	double per_cycle = indep / @@CALIB@@;	/* ns in one cycle */
	double ratio = indep > 0 ? dep / indep : 0.0;
	printf("calibration: %.3f ns per cycle (%.2f GHz apparent); "
	       "chained/independent addps = %.2f, the ISA says 3.00\n",
	       per_cycle, 1.0 / per_cycle, ratio);
	printf("floor (an empty body, per repeat): %.3f ns\n\n", floor_ns);
	/* **The calibration is a gate, not a decoration.** Two sequences whose
	   ratio the ISA fixes at 3.00 are the one thing here that can be wrong
	   in a way the table cannot show: every strategy inflating together
	   looks exactly like every strategy being slow. If the rig cannot
	   reproduce a ratio it does not get to rank anything, and saying so is
	   the whole reason the two cases are in the list. */
	if (ratio < 2.70 || ratio > 3.30) {
		printf("cost_bench: the calibration missed 3.00, so what follows "
		       "is not a measurement -- most likely this machine is\n"
		       "            busy enough that execution resources are "
		       "shared. Re-run it quiet; do not rank from these.\n\n");
		bad = 1;
	}
	for (int c = 0; c < NCASES; c++) {
		double over = each[c] - floor_ns;
		printf("%-48s %6.2f ns  %6.2f/site  %6.2f cyc\n",
		       NAMES[c], each[c], over / SITES[c],
		       per_cycle > 0 ? over / per_cycle : 0.0);
	}
	return bad ? 3 : 0;
}
"""


def build(rows):
	WORK.mkdir(parents=True, exist_ok=True)
	lines = [".text"]
	for i, (_name, _sites, body) in enumerate(rows):
		lines += [f".globl body_{i}", f".type body_{i}, @function",
		          "\t.p2align 6", f"body_{i}:", "\tsubq\t$128, %rsp"]
		# **Every case starts from the same register file, holding the
		# same normal floats.** Without this a lowering read whatever the
		# previous case left in xmm1 and xmm2 -- possibly a denormal, and
		# the denormal assist is the fault that once turned one extra
		# instruction into 87 ns. Once per call, outside the repeat.
		for r in range(8):
			lines.append(f"\tmovaps\t{r * 16}(%rsi), %xmm{r}")
		for _ in range(UNROLL):
			for at in range(0, len(body), 8):
				lines.append("\t.byte " + ", ".join(
					str(b) for b in body[at:at + 8]))
		lines += ["\taddq\t$128, %rsp", "\tret", ""]
	(WORK / "bodies.s").write_text("\n".join(lines) + "\n")
	decls = "\n".join(f"extern void body_{i}(void *out, const void *in);"
	                  for i in range(len(rows)))
	names = ",\n\t".join('"%s"' % name for name, _s, _b in rows)
	table = ("static void (*const FNS[])(void *, const void *) = {\n\t"
	         + ", ".join(f"body_{i}" for i in range(len(rows)))
	         + "\n};\n"
	         + "static const char *const NAMES[] = {\n\t" + names + "\n};\n"
	         + "static const double SITES[] = {\n\t"
	         + ", ".join(str(float(sites)) for _n, sites, _b in rows)
	         + "\n};\n")
	source = MAIN
	for token, value in (("@@ROUNDS@@", ROUNDS), ("@@UNROLL@@", UNROLL),
	                     ("@@PASSES@@", PASSES), ("@@NCASES@@", len(rows)),
	                     ("@@DECLS@@", decls), ("@@TABLE@@", table),
	                     ("@@INDEP@@", 1), ("@@DEP@@", 2),
	                     ("@@CALIB@@", float(CALIB_CYCLES))):
		source = source.replace(token, str(value))
	assert "@@" not in source, "a template token was left unfilled"
	(WORK / "bench.c").write_text(source)
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
	load = Path("/proc/loadavg").read_text().split()[0]
	print(f"== {len(rows)} bodies, {ROUNDS:,} x {UNROLL} repeats each, "
	      f"buffer in L1, load average {load} ==")
	for name, sites, body in rows:
		print(f"   {name:<46} {len(body):>4} bytes, {sites} site(s)")
	print()
	done = subprocess.run([str(build(rows))], capture_output=True, text=True,
	                      timeout=600)
	print(done.stdout, end="")
	if done.returncode == 3:
		# The benchmark ran and its self-check failed. That is a report
		# about the machine, not a crash, and it has already said so on
		# stdout -- but it must not exit 0, or a caller that checks the
		# status learns the opposite of what the text says.
		print(f"cost_bench: load average now {load}", file=sys.stderr)
		return 3
	if done.returncode != 0:
		print(f"cost_bench: the benchmark exited {done.returncode}",
		      file=sys.stderr)
		return 1
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
