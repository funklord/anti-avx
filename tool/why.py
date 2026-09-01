#!/usr/bin/env python3
"""Everything known about one address, which is what a fault hands you.

**The frontier method is the project's most productive and its least
tooled.** Run the rewritten binary, it dies, the fault address names a
surviving site, and that site has named the next strategy to build five
times running (Findings 106 to 110). Getting from the address to the
answer meant running `make detour-plan` and grepping, or writing a probe
-- and this session wrote six such probes, two of which measured their own
missing input.

This answers it directly. Given an address it says what the instruction
is, what shape it has, whether the plain lowering takes it, what the
region around it looks like, and which of the region's conditions refuses
it -- each as a separate line, because a site refused for three reasons at
once is not the same as one refused for a reason nobody has attacked.

It reads through `probe.py`, so the twelve minutes of parsing and mapping
are paid once per tree rather than once per question.

Usage:  why.py <binary> <listing> <address> [address ...]
"""

import bisect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import detour
import patch as inplace
import probe
import scratch as scratch_finder


def explain(binary, listing, address):
	"""Print what is known about `address`. True if it was found."""
	instructions, plain, blocked = probe.listing_rows(binary, listing)
	starts = [row[0] for row in plain]
	index = bisect.bisect_left(starts, address)
	if index >= len(starts) or starts[index] != address:
		near = starts[min(index, len(starts) - 1)]
		print(f"0x{address:x}: no instruction begins here. The nearest is "
		      f"0x{near:x}, which usually means the address is mid"
		      f"-instruction or in another section.")
		return False

	_a, encoding, mnemonic, operands, _c = instructions[index]
	vex = inplace.decode_vex(encoding)
	print(f"0x{address:x}: {mnemonic} {operands or ''}")
	print(f"  encoding      {encoding.hex()}")
	if vex is None:
		print("  not VEX, so the rewriter has no business with it")
		return True
	print(f"  width         {'256-bit' if vex['L'] else '128-bit'}")
	print(f"  shape         {detour.span_shape_name(encoding, operands)}")

	ranges = probe.function_ranges(binary, listing)
	inside = inplace.covered_by(ranges, address, len(encoding))
	print(f"  inside .pdata {'yes' if inside else 'NO -- outside every '
	      'range, which refuses it before anything else looks'}")
	print(f"  branch target {'YES -- nothing may widen over it' if address in blocked else 'no'}")

	scope = probe.function_scope(binary, listing)
	free = scratch_finder.scope_free(scope, address)
	print(f"  xmm free by the whole-function rule  "
	      f"{sorted(free) if free else 'none'}")

	# The plain path: does one instruction lower on its own?
	used = set(scratch_finder.xmm_numbers(operands or ""))
	scratch = next((n for n in range(16) if n not in used), None)
	try:
		body = detour.lower_vex(address, encoding, operands, mnemonic,
		                        address, scratch=scratch, pool=address)
	except Exception as error:				# noqa: BLE001
		body = None
		print(f"  plain lowering RAISED {type(error).__name__}: {error}")
	else:
		print(f"  plain lowering {'emits ' + str(len(body)) + ' bytes' if body else 'refuses it'}")

	# The region: where it begins, what it holds, and what refuses it.
	first = detour.region_start(instructions, index, blocked)
	if first is None:
		print("  region        starts further back than the walk looks")
		return True
	last = detour.region_end(instructions, first, blocked)
	print(f"  region        0x{instructions[first][0]:x} .. "
	      f"0x{instructions[last - 1][0]:x}, {last - first} instruction(s)")
	# Through `region_anchor` rather than a rule of its own: this printed
	# "offered only at its first instruction" for one commit after the
	# collector had stopped believing it.
	anchor = detour.region_anchor(instructions, first, last)
	if anchor != index:
		where = f"0x{instructions[anchor][0]:x}" if anchor is not None \
			else "nowhere -- the region holds no 256-bit site"
		print(f"  region offered at {where}, not here")
	found = detour.region_members(instructions, first, last)
	if found is None:
		print("  region members REFUSED -- a shape it cannot emit, or a "
		      "value defined outside the region")
		for position in range(first, last):
			one = inplace.decode_vex(instructions[position][1])
			if one is None or not one["L"]:
				continue
			shape = detour.span_operand_shape(
				one, instructions[position][1][one["length"]:],
				instructions[position][3], None)
			if shape is None:
				print(f"    0x{instructions[position][0]:x}  "
				      f"{detour.span_shape_name(instructions[position][1], instructions[position][3])}"
				      f"  <- not emittable")
		return True
	members, slots = found
	print(f"  region members ok: {len(members)} member(s), "
	      f"{len(slots)} slot(s)")
	return True


def main():
	if len(sys.argv) < 4:
		print("usage: why.py <binary> <listing> <address> [address ...]",
		      file=sys.stderr)
		return 2
	binary, listing = sys.argv[1], sys.argv[2]
	found = 0
	for text in sys.argv[3:]:
		if explain(binary, listing, int(text, 0)):
			found += 1
		print()
	return 0 if found else 1


if __name__ == "__main__":
	raise SystemExit(main())
