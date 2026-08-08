#!/usr/bin/env python3
"""The code `.pdata` does not describe, and how to know it is code.

`.pdata` is the rewriter's code oracle: a run of bytes it covers is certainly
code, so a detour written there certainly lands on an instruction boundary.
Everything else is refused, and that refusal became the single largest reason
sites survived -- 16,256 of the 23,923 left, more than twice every other
reason combined.

`patch.function_ranges` already names the cause: the x64 ABI lets a function
that neither allocates stack nor calls anything omit its unwind data, so a
leaf function legitimately has no `.pdata` entry. What it could not say was
how much of the refused set was that, and how much was objdump walking into
data -- and those need opposite work. A leaf function's VEX must be lowered;
a constant pool that happens to decode as VEX must be left alone, because
"patching" it corrupts the data.

Measured, on 3,006 regions outside `.pdata` holding 17,604 VEX sites:

    called, and ends in a transfer     1,418 regions    6,534 sites
    uncalled, ends in a transfer       1,524 regions   10,622 sites
    called, but runs off the end          40 regions      120 sites
    contains (bad) -- not code            20 regions      315 sites
    uncalled, runs off the end             4 regions       13 sites

The "uncalled" majority was an artifact of asking the wrong set. It is not
that nothing calls them: `targets.py` recovers branch targets from `.reloc`,
`.pdata`, `.xdata` and switch tables, and **a `call rel32` is none of those**
-- it is PC-relative, so it carries no relocation and appears in no table.
Scanning the disassembly for direct calls and jumps finds them. 0x1402a9fa0
is the shape of the whole class:

    vmovaps %xmm1,%xmm2        ; called twice, from 0x142661c35
    vxorps  %xmm1,%xmm1,%xmm1  ; and 0x142661d14
    vmovss  %xmm2,%xmm1,%xmm2
    vinsertps $0x30,%xmm2,%xmm0,%xmm0
    ret

Pure register work and a `ret`: it touches no stack and calls nothing, so
MSVC omits its unwind data exactly as the ABI permits.

So the oracle extends, and `leaf_ranges` states the conditions it extends
under. All four must hold, and each rules out a different way of being
wrong:

  * **Bracketed by `int3`.** MSVC pads between functions with `cc`, so
    padding is where a function provably ends. Splitting there is what makes
    the chunk start at a function start rather than mid-padding.
  * **Starts at something that calls or jumps to it.** A constant pool is
    not the target of a call. This is the positive evidence that the bytes
    are entered as code.
  * **Ends in a control transfer.** Compiler output does not fall off the
    end of a function into padding. A chunk ending any other way is one the
    disassembler desynchronised inside, so its boundaries are not trustworthy
    even if its first byte was.
  * **No `(bad)`.** objdump emits it for bytes that decode to no
    instruction. Real compiler output contains none, so one anywhere in the
    chunk is near-proof the sweep is out of step.

The 20 `(bad)` regions and the 44 that run off the end stay refused. That is
the trade `function_ranges` describes, kept: being slightly less effective
is the right price for not corrupting data.

  report <binary> <listing>
"""

import bisect
import sys
from collections import Counter

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))
import patch as inplace
import targets as target_set

# How a function ends. `int3` cannot appear here -- it terminates a chunk
# before this is consulted -- but a tail call and a plain return both can.
TERMINATORS = ("ret", "retq", "jmp", "jmpq", "ud2")


def covered(starts, ranges, address):
	i = bisect.bisect_right(starts, address) - 1
	return i >= 0 and address < ranges[i][1]


def call_targets(instructions):
	"""Direct call and jump destinations, which no relocation records."""
	found = set()
	for _address, _encoding, mnemonic, operands in instructions:
		if not operands or not mnemonic.startswith(("j", "call", "loop")):
			continue
		first = operands.split()[0]
		if not first.startswith("0x"):
			continue
		try:
			found.add(int(first, 16))
		except ValueError:
			pass
	return found


def chunks(instructions, ranges):
	"""Runs of instructions outside .pdata, split at int3 padding.

	Splitting at padding is the part that matters. A run typically *begins*
	with the padding that follows the previous function, so a chunk taken
	without splitting starts at a `cc` -- and then every test of "does
	anything call this address" asks about the padding and answers no.
	"""
	starts = [start for start, _end in ranges]
	out = []
	current = None
	for address, encoding, mnemonic, _operands in instructions:
		padding = mnemonic == "int3"
		inside = covered(starts, ranges, address)
		if inside or padding or (current and address != current[1]):
			if current:
				out.append(current)
				current = None
			if inside or padding:
				continue
		if not current:
			current = [address, address, 0, 0, 0, ""]
		current[1] = address + len(encoding)
		current[2] += 1
		current[5] = mnemonic
		if encoding[:1] in (b"\xc4", b"\xc5"):
			current[3] += 1
		if mnemonic == "(bad)":
			current[4] += 1
	if current:
		out.append(current)
	return out


def classify(chunk, known):
	"""(verdict, accepted as code) for one chunk."""
	_first, _end, _count, _vex, bad, last = chunk
	terminates = last in TERMINATORS or (last.startswith("j") and last != "(bad)")
	if bad:
		return "contains (bad) -- not code", False
	called = chunk[0] in known
	if called and terminates:
		return "called, and ends in a transfer", True
	if called:
		return "called, but runs off the end", False
	if terminates:
		return "uncalled, ends in a transfer", False
	return "uncalled, runs off the end", False


def leaf_ranges(instructions, ranges, known):
	"""(start, end) of every chunk outside .pdata that is provably code.

	Returned in the same shape as `patch.function_ranges`, so the two
	concatenate into one oracle. See the module docstring for why each of
	the four conditions is required.
	"""
	return sorted((first, end)
	              for chunk in chunks(instructions, ranges)
	              for first, end in [(chunk[0], chunk[1])]
	              if classify(chunk, known)[1])


def main(argv):
	if not argv or argv[0] in ("-h", "--help"):
		print(__doc__.strip())
		return 0
	if argv[0] != "report":
		print(f"outside.py: unknown mode {argv[0]!r}", file=sys.stderr)
		return 2
	binary, listing = argv[1], argv[2]

	ranges = inplace.function_ranges(binary)
	instructions = list(inplace.parse_listing(listing))

	known = set()
	for group in target_set.collect(binary).values():
		known |= group
	relocated = len(known)
	known |= call_targets(instructions)

	print(f"branch targets from .reloc/.pdata/.xdata/tables {relocated:>9,}")
	print(f"  plus direct call and jump destinations        {len(known):>9,}")
	print()

	found = chunks(instructions, ranges)
	with_vex = [c for c in found if c[3]]
	print(f"chunks outside .pdata               {len(found):>9,}")
	print(f"  of which contain a VEX site       {len(with_vex):>9,}")
	print(f"  VEX sites in them                 {sum(c[3] for c in with_vex):>9,}")
	print()

	verdicts, sites, examples = Counter(), Counter(), {}
	accepted_sites = 0
	for chunk in with_vex:
		verdict, accepted = classify(chunk, known)
		verdicts[verdict] += 1
		sites[verdict] += chunk[3]
		if accepted:
			accepted_sites += chunk[3]
		examples.setdefault(verdict, chunk)

	print(f"{'verdict':<36}{'chunks':>8}{'VEX sites':>11}   example")
	for verdict, count in verdicts.most_common():
		first, end, insns, vex, _bad, _last = examples[verdict]
		print(f"  {verdict:<34}{count:>8,}{sites[verdict]:>11,}"
		      f"   0x{first:x} {end - first}B {insns} insns")
	print()
	print(f"accepted as code by leaf_ranges: {accepted_sites:,} VEX sites in "
	      f"{len(leaf_ranges(instructions, ranges, known)):,} chunks")
	return 0


if __name__ == "__main__":
	raise SystemExit(main(sys.argv[1:]))
