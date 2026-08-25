#!/usr/bin/env python3
"""Inventory and classify VEX sites in an `objdump -d -j .text` listing.

Reads the listing on stdin or from a path, and answers the measurement
questions the design depends on:

  * headline VEX density, detected from the *encoding bytes* rather than
    from mnemonic spelling, so that it is an independent check on the
    grep-based figures in project.md;
  * the Class B / C / C-alias split of 3-operand VEX forms, which sets the
    real count of extra movs and the count of sites needing a scratch;
  * the vpermilps immediate-versus-variable split, which decides how many
    of those 73 sites are a plain shufps and how many need a helper;
  * ymm liveness, which decides whether the Y2 shadow area is needed at
    all or whether the Y1 peephole covers every 256-bit site.

Nothing here rewrites anything. It only measures.
"""

import re
import sys
from collections import Counter, defaultdict

# Legacy prefixes objdump prints as a separate leading token.
PREFIXES = frozenset((
	"lock", "rep", "repz", "repnz", "repe", "repne", "bnd", "notrack",
	"data16", "addr32", "rex.W", "cs", "ds", "es", "fs", "gs", "ss",
))

# Mnemonics that end a basic block. Conditional jumps are matched
# separately, since there are too many to list.
UNCONDITIONAL_END = frozenset((
	"jmp", "jmpq", "ret", "retq", "retw", "lret", "lretq", "iret",
	"iretq", "ud0", "ud1", "ud2", "hlt", "syscall", "sysret", "int3",
	"int", "into",
))

CALLS = frozenset(("call", "callq"))

JCC = re.compile(r"^j(?!mp)[a-z]+$")

SIMD_REG = re.compile(r"%([xy])mm(\d+)")
HEX_TARGET = re.compile(r"^0x([0-9a-f]+)$")

# A VEX instruction that reads/writes a scalar float. Used only for the
# headline breakdown, and deliberately matches what project.md counted.
SCALAR_SUFFIX = re.compile(r"(ss|sd)$")

# Operations whose two sources may be exchanged without changing the
# result, so that a Class C site where dst aliases src2 can be fixed by
# swapping the operands instead of allocating a scratch register.
#
# maxss/minss are deliberately ABSENT. SSE MAXSS(a,b) returns b when
# either input is NaN, and returns b when both are zeros of opposite
# sign, so it is not commutative at exactly the inputs a game's clamping
# code is most likely to hit. Treating it as commutative is the kind of
# error that survives every test and fails in the field.
COMMUTATIVE = frozenset((
	"vaddss", "vaddsd", "vaddps", "vaddpd",
	"vmulss", "vmulsd", "vmulps", "vmulpd",
	"vandps", "vandpd", "vorps", "vorpd", "vxorps", "vxorpd",
	"vpand", "vpor", "vpxor",
	"vpaddb", "vpaddw", "vpaddd", "vpaddq",
	"vpmulld", "vpmullw", "vpmuludq",
	"vpcmpeqb", "vpcmpeqw", "vpcmpeqd", "vpcmpeqq",
	"vpavgb", "vpavgw",
	"vpminub", "vpmaxub", "vpminsw", "vpmaxsw",
))


def split_operands(text):
	"""Split an AT&T operand list on top-level commas.

	Memory operands contain commas inside parentheses -- 0x10(%rax,%rbx,4)
	is one operand, not three -- so a plain split is wrong.
	"""
	out = []
	depth = 0
	start = 0
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


class instruction:
	"""One decoded line of the listing. Deliberately small -- millions exist."""

	__slots__ = ("addr", "mnemonic", "operands", "vex", "evex", "length")

	def __init__(self, addr, mnemonic, operands, vex, evex, length):
		self.addr = addr
		self.mnemonic = mnemonic
		self.operands = operands
		self.vex = vex
		self.evex = evex
		self.length = length


def parse(stream):
	"""Yield instruction records from an objdump listing.

	objdump wraps long encodings onto continuation lines that carry an
	address and bytes but no mnemonic; those have two tab-separated fields
	instead of three, which is the cheap test used here. Getting this wrong
	inflates the instruction count, which is how a 4 MB sample once
	produced three wrong headline figures.
	"""
	for line in stream:
		parts = line.split("\t")
		if len(parts) < 3:
			continue
		head = parts[0]
		colon = head.rfind(":")
		if colon < 0:
			continue
		try:
			addr = int(head[:colon].strip(), 16)
		except ValueError:
			continue

		encoding = parts[1].split()
		if not encoding:
			continue
		first = encoding[0]

		body = parts[2]
		hash_at = body.find("#")
		if hash_at >= 0:
			body = body[:hash_at]
		body = body.rstrip()
		if not body:
			continue

		fields = body.split(None, 1)
		mnemonic = fields[0]
		rest = fields[1] if len(fields) > 1 else ""
		while mnemonic in PREFIXES and rest:
			fields = rest.split(None, 1)
			mnemonic = fields[0]
			rest = fields[1] if len(fields) > 1 else ""

		# In 64-bit mode C4 and C5 cannot be LES/LDS, so a leading C4 or
		# C5 is unambiguously a VEX prefix. 62 is likewise EVEX. This is
		# the encoding-level test, independent of how the mnemonic is
		# spelled.
		vex = first in ("c4", "c5")
		evex = first == "62"

		yield instruction(addr, mnemonic, rest, vex, evex, len(encoding))


def simd_regs(operand):
	"""Return the set of (width, number) SIMD registers named in an operand."""
	return set(SIMD_REG.findall(operand))


def classify_three_operand(mnemonic, ops):
	"""Return the lowering class of a VEX NDS form, or None if not one.

	AT&T prints VEX three-operand forms as `src2, src1, dst`, so dst is the
	last operand and src1 the one before it. An immediate, where present,
	is printed first and is dropped before the comparison.

	Class B  -- dst == src1, lowers directly.
	Class C  -- dst != src1, needs a mov of src1 into dst first.
	C-alias  -- dst != src1 and dst == src2, so the naive mov clobbers
	            src2 before it is read. Needs a scratch or a reorder.
	"""
	regs = [o for o in ops if not o.startswith("$")]
	if len(regs) != 3:
		return None
	src2, src1, dst = regs
	# All three must be registers for the aliasing question to arise; a
	# memory src2 cannot alias the destination register.
	if not dst.startswith("%"):
		return None
	if not src1.startswith("%"):
		return None
	if dst == src1:
		return "B"
	if dst == src2:
		return "C-alias"
	return "C"


def main():
	path = sys.argv[1] if len(sys.argv) > 1 else None
	stream = open(path, "r", errors="replace") if path else sys.stdin

	total = 0
	vex_total = 0
	evex_total = 0
	vex_by_mnemonic = Counter()
	name_v_total = 0		# mnemonic starts with v, the project.md test
	name_v_not_vex = Counter()	# spelled v..., not VEX-encoded
	vex_not_name_v = Counter()	# VEX-encoded, not spelled v...
	ymm_total = 0
	ymm_by_mnemonic = Counter()
	scalar_total = 0
	three_op = Counter()
	three_op_by_mnemonic = defaultdict(Counter)
	permil = Counter()
	bad_total = 0
	bad_addrs = []

	# Retained for the liveness pass: every instruction that names an xmm
	# or ymm register, plus every call and every block boundary. Only the
	# SIMD instructions are stored whole; branches contribute addresses.
	simd_sites = []
	leaders = set()
	call_addrs = []
	prev_end = None
	prev_ends_block = False

	for ins in parse(stream):
		total += 1

		if prev_ends_block and prev_end is not None:
			leaders.add(ins.addr)
		prev_end = ins.addr + ins.length

		mnemonic = ins.mnemonic
		ops = ins.operands

		if mnemonic == "(bad)":
			bad_total += 1
			bad_addrs.append(ins.addr)

		ends = False
		if mnemonic in UNCONDITIONAL_END or JCC.match(mnemonic):
			ends = True
			target = HEX_TARGET.match(ops.split()[0]) if ops else None
			if target:
				leaders.add(int(target.group(1), 16))
		elif mnemonic in CALLS:
			ends = True
			call_addrs.append(ins.addr)
			# The walk needs to see calls in program order: the Win64
			# ABI makes bits 255:128 of every ymm register volatile, so
			# a call kills any upper half not yet consumed. Without this
			# the killed defs are miscounted as live across an edge, and
			# the Y2 shadow looks necessary when it is not.
			simd_sites.append(ins)
			target = HEX_TARGET.match(ops.split()[0]) if ops else None
			if target:
				leaders.add(int(target.group(1), 16))
		prev_ends_block = ends

		spelled_v = mnemonic.startswith("v") and mnemonic not in (
			"verr", "verw",
		)
		if spelled_v:
			name_v_total += 1

		if ins.evex:
			evex_total += 1

		if not ins.vex:
			if spelled_v:
				name_v_not_vex[mnemonic] += 1
			# Legacy SSE still writes the low half of a ymm register and
			# leaves the upper half alone, so it matters for liveness.
			if "mm" in ops and SIMD_REG.search(ops):
				simd_sites.append(ins)
			continue

		vex_total += 1
		vex_by_mnemonic[mnemonic] += 1
		if not spelled_v:
			vex_not_name_v[mnemonic] += 1

		if "%ymm" in ops:
			ymm_total += 1
			ymm_by_mnemonic[mnemonic] += 1

		if SCALAR_SUFFIX.search(mnemonic):
			scalar_total += 1

		operand_list = split_operands(ops)
		klass = classify_three_operand(mnemonic, operand_list)
		if klass:
			three_op[klass] += 1
			three_op_by_mnemonic[klass][mnemonic] += 1

		if mnemonic.startswith("vpermil"):
			form = "immediate" if any(
				o.startswith("$") for o in operand_list
			) else "variable"
			permil[(mnemonic, form)] += 1

		if SIMD_REG.search(ops):
			simd_sites.append(ins)

	report(
		total, vex_total, evex_total, vex_by_mnemonic, name_v_total,
		name_v_not_vex, vex_not_name_v, ymm_total, ymm_by_mnemonic,
		scalar_total, three_op, three_op_by_mnemonic, permil, bad_total,
		simd_sites, leaders, call_addrs, bad_addrs,
	)


def liveness(simd_sites, leaders, call_addrs):
	"""Classify every ymm definition by where its value is consumed.

	The question this exists to answer is whether the Y2 shadow area is
	needed. A ymm value whose halves never have to coexist across a
	control-flow edge can be lowered by the Y1 peephole with no shadow
	state at all.

	Three things kill a ymm upper half and are treated as such:

	  * a call -- the Win64 ABI makes the upper halves of every ymm
	    register volatile, so no 256-bit value survives one;
	  * a VEX 128-bit write to the same register, which zeroes bits
	    255:128 by definition;
	  * vzeroupper.

	A basic-block boundary is not a kill, only a barrier to the peephole.
	Blocks are cut at leaders derived from direct branch targets and from
	the instruction after any control transfer. Indirect branches are not
	resolved, so a block may in truth be entered somewhere this does not
	know about; that makes the local-consumption figure an *upper* bound
	and the cross-block figure a lower bound. Said plainly because the
	design decision rests on it.
	"""
	# Index the sites by address so that the walk is in program order.
	simd_sites.sort(key=lambda i: i.addr)

	pending = {}		# ("y", n) -> (address, mnemonic) of a def not yet consumed
	local_pairs = Counter()
	outcome = Counter()
	y2_sites = []
	ymm_defs = 0

	def flush(reason, record=False):
		for key, value in pending.items():
			outcome[reason] += 1
			if record:
				y2_sites.append((value[0], value[1], key[1]))
		pending.clear()

	prev_addr = None
	for ins in simd_sites:
		mnemonic = ins.mnemonic

		# A call clobbers bits 255:128 of every ymm register, so anything
		# pending is dead rather than live across the edge. Checked
		# before the block-boundary test, because a call is also a block
		# terminator and would otherwise be counted as cross-block.
		if mnemonic in CALLS:
			flush("killed by call")
			prev_addr = ins.addr
			continue

		if prev_addr is not None:
			if any_leader_between(leaders, prev_addr, ins.addr):
				# Reached from somewhere else, or fallen out of the
				# block: the peephole cannot span this, so a value still
				# pending genuinely needs the Y2 shadow.
				flush("live across block edge (Y2)", record=True)
		prev_addr = ins.addr

		if mnemonic == "vzeroupper":
			flush("killed by vzeroupper")
			continue

		operand_list = split_operands(ins.operands)
		if not operand_list:
			continue
		dst = operand_list[-1]
		uses = operand_list[:-1]

		# Uses first: a pending def consumed here is a Y1 candidate.
		for use in uses:
			for width, num in simd_regs(use):
				key = ("y", num)
				if key in pending:
					local_pairs[(pending[key][1], mnemonic)] += 1
					outcome["consumed in block (Y1)"] += 1
					del pending[key]

		for width, num in simd_regs(dst):
			key = ("y", num)
			if key in pending:
				# Overwritten before any use. For a ymm destination the
				# whole value is dead; for a VEX xmm destination bits
				# 255:128 are zeroed, which kills the upper half just as
				# effectively. Legacy SSE would preserve them, but the
				# compiler emits VEX throughout, so treating both alike
				# is conservative in the direction that matters.
				outcome["dead, overwritten"] += 1
				del pending[key]
			if width == "y":
				ymm_defs += 1
				pending[key] = (ins.addr, mnemonic)

	flush("live at end of walk", record=True)
	return ymm_defs, outcome, local_pairs, y2_sites


def any_leader_between(leaders, lo, hi):
	"""True if a basic-block leader falls in (lo, hi]."""
	# Called once per adjacent SIMD pair; the set is large but this is a
	# handful of lookups rather than a scan, because instructions are
	# dense and the gap is almost always small.
	if hi - lo > 4096:
		return True
	for a in range(lo + 1, hi + 1):
		if a in leaders:
			return True
	return False


def cluster(addrs, gap):
	"""Group sorted addresses into runs separated by more than `gap`."""
	if not addrs:
		return []
	addrs = sorted(addrs)
	runs = []
	start = prev = addrs[0]
	count = 1
	for a in addrs[1:]:
		if a - prev > gap:
			runs.append((start, prev, count))
			start = a
			count = 0
		prev = a
		count += 1
	runs.append((start, prev, count))
	return runs


def report(total, vex_total, evex_total, vex_by_mnemonic, name_v_total,
		name_v_not_vex, vex_not_name_v, ymm_total, ymm_by_mnemonic,
		scalar_total, three_op, three_op_by_mnemonic, permil,
		bad_total, simd_sites, leaders, call_addrs, bad_addrs):
	def pct(n, d):
		return f"{100.0 * n / d:.2f}%" if d else "n/a"

	print("== headline ==")
	print(f"instructions total            {total:>12,}")
	print(f"  (bad) decodes               {bad_total:>12,}   {pct(bad_total, total)}")
	print(f"VEX-encoded (C4/C5 prefix)    {vex_total:>12,}   {pct(vex_total, total)}")
	print(f"EVEX-encoded (62 prefix)      {evex_total:>12,}   {pct(evex_total, total)}")
	print(f"  256-bit (names a ymm)       {ymm_total:>12,}   {pct(ymm_total, vex_total)} of VEX")
	print(f"  scalar float (ss/sd)        {scalar_total:>12,}   {pct(scalar_total, vex_total)} of VEX")
	print()

	print("== encoding test versus mnemonic test ==")
	print(f"mnemonic starts with v        {name_v_total:>12,}")
	print(f"VEX by encoding               {vex_total:>12,}")
	print(f"spelled v..., NOT VEX-encoded {sum(name_v_not_vex.values()):>12,}")
	for m, c in name_v_not_vex.most_common(20):
		print(f"    {m:<24} {c:>10,}")
	print(f"VEX-encoded, NOT spelled v... {sum(vex_not_name_v.values()):>12,}")
	for m, c in vex_not_name_v.most_common(20):
		print(f"    {m:<24} {c:>10,}")
	print()

	print("== 3-operand VEX forms ==")
	tot3 = sum(three_op.values())
	print(f"three-operand register forms  {tot3:>12,}")
	for k in ("B", "C", "C-alias"):
		print(f"  Class {k:<8}                {three_op[k]:>12,}   {pct(three_op[k], tot3)}")
	print()
	alias = three_op_by_mnemonic["C-alias"]
	swappable = sum(c for m, c in alias.items() if m in COMMUTATIVE)
	scratch = sum(c for m, c in alias.items() if m not in COMMUTATIVE)
	print("  Class C-alias breakdown (dst == src2, so the naive mov clobbers src2):")
	print(f"    commutative, fix by swapping operands  {swappable:>10,}   {pct(swappable, swappable + scratch)}")
	print(f"    NOT commutative, needs a scratch xmm    {scratch:>10,}   {pct(scratch, swappable + scratch)}")
	print()
	print("  C-alias sites genuinely needing a scratch, by mnemonic:")
	for m, c in alias.most_common():
		if m not in COMMUTATIVE:
			print(f"    {m:<24} {c:>10,}")
	print()

	print("== vpermil* immediate versus variable ==")
	for (m, form), c in sorted(permil.items()):
		print(f"  {m:<16} {form:<10} {c:>8,}")
	print()

	# The COMPLETE inventory, not a top-N.
	#
	# This used to print the top 40, and that truncation had a cost. The
	# lowering table in tool/lower.py has to carry a rule for every
	# mnemonic that occurs, so building it needed the whole list -- and
	# because the report would not give it, the list got extracted with an
	# ad-hoc grep into a file beside the report that `make clean` did not
	# know to remove. A second, slightly different counter is exactly the
	# drift `evidence.md` warns about: that grep matched only lines with a
	# decodable mnemonic and so missed the 180 VEX-prefixed byte sequences
	# that disassemble to `(bad)`, which is why its total came to 804,809
	# against this tool's 805,131.
	#
	# There is one authority now and it prints everything it counted.
	# `(bad)` is included deliberately -- those bytes really do carry a VEX
	# prefix, and Finding 8 is about what they are.
	print(f"== VEX mnemonics ({len(vex_by_mnemonic)} distinct, all listed) ==")
	for m, c in vex_by_mnemonic.most_common():
		print(f"  {m:<24} {c:>10,}")
	print()

	print("== ymm mnemonics (all) ==")
	for m, c in ymm_by_mnemonic.most_common():
		print(f"  {m:<24} {c:>10,}")
	print()

	print("== ymm liveness ==")
	print(f"basic-block leaders found     {len(leaders):>12,}")
	print(f"call sites                    {len(call_addrs):>12,}")
	print(f"SIMD sites retained           {len(simd_sites):>12,}")
	ymm_defs, outcome, local_pairs, y2_sites = liveness(
		simd_sites, leaders, call_addrs,
	)
	print(f"ymm definitions               {ymm_defs:>12,}")
	for k, c in outcome.most_common():
		print(f"  {k:<30} {c:>10,}   {pct(c, ymm_defs)}")
	print()
	print("  top producer -> consumer pairs (Y1 peephole candidates):")
	for (prod, cons), c in local_pairs.most_common(20):
		print(f"    {prod:<20} -> {cons:<20} {c:>8,}")
	print()
	print(f"  Y2 shadow sites in full ({len(y2_sites)}):")
	by_mnemonic = Counter(m for _, m, _ in y2_sites)
	for m, c in by_mnemonic.most_common():
		print(f"    {m:<24} {c:>8,}")
	print("  addresses:")
	for addr, m, reg in sorted(y2_sites)[:60]:
		print(f"    0x{addr:x}  {m} -> %ymm{reg}")
	if len(y2_sites) > 60:
		print(f"    ... and {len(y2_sites) - 60} more")
	print()

	print("== (bad) decodes: data islands inside .text ==")
	runs = cluster(bad_addrs, 256)
	print(f"total (bad)                   {bad_total:>12,}")
	print(f"islands (gap > 256 bytes)     {len(runs):>12,}")
	big = sorted(runs, key=lambda r: -r[2])[:20]
	print("  largest islands (start, end, count):")
	for lo, hi, n in big:
		print(f"    0x{lo:x} - 0x{hi:x}  span={hi - lo:>7,}  bad={n:>6,}")
	singletons = sum(1 for r in runs if r[2] == 1)
	print(f"  islands holding a single (bad):  {singletons:,}")


if __name__ == "__main__":
	main()
