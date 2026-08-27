#!/usr/bin/env python3
"""Where the detours land, structurally.

Finding 22 measured what a detour costs and said plainly what it could not
measure: *placement*. A detour in an initialisation path costs nothing; the
same detour in the innermost loop of the renderer is paid every iteration.
Density averaged over 16.5 million instructions says nothing about either.

Execution counts need the game running, which needs a Windows host and the
last 23,923 VEX sites gone. But the structure is in the binary, and it
carries most of the question:

  * `.pdata` gives 236,427 function boundaries, so per-function density is
    exact rather than inferred.

  * A **backward branch whose target lies in the same function** is a loop.
    The span from target to branch is its body. That finds loops without a
    CFG and without symbols, and it is the metric that matters -- a loop
    body containing one detour pays it on every iteration, however small
    the whole-binary average is.

  * Loops are bucketed by body size. A tight loop is likelier to be hot and
    likelier to fit in L1i, so a detour that drags a line in from a section
    144 MB away costs most exactly there.

What this still cannot say is which loops execute. A loop that runs once is
cold whatever is in it. So the honest reading of the output is a *bound*:
if the detoured fraction of tight loops is small, most hot code cannot be
affected no matter which loops turn out to be hot.

  report <binary> <listing>
"""

import sys
from collections import Counter

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))
import detour
import patch as inplace

BACKWARD = ("jmp", "jmpq", "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe",
            "jg", "jge", "jl", "jle", "js", "jns", "jo", "jno", "jp", "jnp",
            "jc", "jnc", "loop", "loope", "loopne")

# Buckets in bytes of loop body. The first two are the ones that matter: a
# body that fits in a few cache lines is the shape a hot inner loop has.
BUCKETS = ((0, 64), (64, 256), (256, 1024), (1024, 4096), (4096, 1 << 30))


def function_index(ranges):
	"""Sorted starts, for locating the function an address belongs to."""
	return [start for start, _end in ranges]


def containing(ranges, starts, address):
	import bisect
	i = bisect.bisect_right(starts, address) - 1
	if i >= 0 and address < ranges[i][1]:
		return i
	return None


def main(argv):
	if not argv or argv[0] in ("-h", "--help"):
		print(__doc__.strip())
		return 0
	if argv[0] != "report":
		print(f"placement.py: unknown mode {argv[0]!r}", file=sys.stderr)
		return 2
	binary, listing = argv[1], argv[2]

	ranges = inplace.function_ranges(binary)
	starts = function_index(ranges)

	# Every instruction, and every backward branch, in one pass.
	instructions = []
	loops = []
	for address, encoding, mnemonic, operands in inplace.parse_listing(listing):
		instructions.append((address, len(encoding)))
		if mnemonic not in BACKWARD or not operands:
			continue
		first = operands.split()[0]
		if not first.startswith("0x"):
			continue
		try:
			target = int(first, 16)
		except ValueError:
			continue
		if target >= address:
			continue			# forward branch; not a loop back-edge
		here = containing(ranges, starts, address)
		if here is None or containing(ranges, starts, target) != here:
			continue			# leaves the function; not a loop
		loops.append((target, address + len(encoding)))

	# Where the detours are.
	patches, candidates, _stats, _skipped, _declined, _home = detour.collect(
		binary, listing)
	committed = 0
	detoured = []
	for entry in sorted(candidates, key=lambda c: c[0]):
		site, window = entry[0], entry[4]
		if site < committed:
			continue
		committed = site + window
		detoured.append(site)
	detoured_set = set(detoured)
	print(f"functions (.pdata)          {len(ranges):>10,}")
	print(f"instructions                {len(instructions):>10,}")
	print(f"detour sites                {len(detoured):>10,}")
	print(f"loops (backward branches)   {len(loops):>10,}")
	print()

	# Per-function density.
	per_function_instructions = Counter()
	per_function_detours = Counter()
	for address, _size in instructions:
		i = containing(ranges, starts, address)
		if i is not None:
			per_function_instructions[i] += 1
	for site in detoured:
		i = containing(ranges, starts, site)
		if i is not None:
			per_function_detours[i] += 1

	touched = len(per_function_detours)
	print(f"functions containing a detour {touched:>8,}   "
	      f"{100.0 * touched / len(ranges):5.1f}% of all functions")
	bands = Counter()
	for i, count in per_function_detours.items():
		total = per_function_instructions.get(i, 0)
		if not total:
			continue
		share = 100.0 * count / total
		band = ("under 1%" if share < 1 else "1-5%" if share < 5 else
		        "5-10%" if share < 10 else "10-25%" if share < 25 else
		        "over 25%")
		bands[band] += 1
	# Counting functions overstates the tail: the dense ones are small.
	# Weight by instructions, which is what execution has to get through.
	print(f"  {'density':<12}{'functions':>11}{'instructions':>14}"
	      f"{'% of .text':>12}{'x slower':>10}")
	total_instructions = sum(per_function_instructions.values())
	weighted = 0.0
	for low, high, slowdown in ((0, 1, 1.01), (1, 5, 1.03), (5, 10, 1.31),
	                            (10, 25, 1.75), (25, 101, 3.04)):
		members = [i for i in per_function_detours
		           if per_function_instructions.get(i)
		           and low <= 100.0 * per_function_detours[i]
		           / per_function_instructions[i] < high]
		count = sum(per_function_instructions[i] for i in members)
		share = count / total_instructions
		weighted += share * slowdown
		print(f"    {f'{low}-{high}%':<10}{len(members):>11,}{count:>14,}"
		      f"{100.0 * share:>11.2f}%{slowdown:>10.2f}")
	clean = total_instructions - sum(per_function_instructions[i]
	                                 for i in per_function_detours)
	weighted += clean / total_instructions
	print(f"    {'none':<10}{len(ranges) - touched:>11,}{clean:>14,}"
	      f"{100.0 * clean / total_instructions:>11.2f}%{1.00:>10.2f}")
	print()
	print(f"  weighting the measured slowdowns by static code volume: "
	      f"{100.0 * (weighted - 1.0):+.1f}%")
	print("  -- which assumes execution time is spread like code size, and it")
	print("     is not. It is an upper bound on the average, not a prediction.")
	print()

	# Loops: the metric that matters.
	print("loop bodies by size, and how many contain a detour:")
	print(f"  {'body size':<14}{'loops':>10}{'with a detour':>16}{'share':>9}")
	import bisect
	site_list = sorted(detoured_set)
	for low, high in BUCKETS:
		total = hit = 0
		for start, end in loops:
			size = end - start
			if not (low <= size < high):
				continue
			total += 1
			i = bisect.bisect_left(site_list, start)
			if i < len(site_list) and site_list[i] < end:
				hit += 1
		if total:
			label = f"{low}-{high}B" if high < (1 << 30) else f"{low}B+"
			print(f"  {label:<14}{total:>10,}{hit:>16,}"
			      f"{100.0 * hit / total:>8.1f}%")
	print()

	# The worst functions, which are where any real problem would be.
	print("functions with the highest detour density (min 40 instructions):")
	worst = sorted(
		((100.0 * per_function_detours[i] / per_function_instructions[i],
		  per_function_detours[i], per_function_instructions[i], ranges[i][0])
		 for i in per_function_detours
		 if per_function_instructions.get(i, 0) >= 40),
		reverse=True)[:10]
	for share, count, total, start in worst:
		print(f"    0x{start:x}  {count:>4} of {total:>5} instructions"
		      f"  {share:5.1f}%")
	return 0


if __name__ == "__main__":
	raise SystemExit(main(sys.argv[1:]))
