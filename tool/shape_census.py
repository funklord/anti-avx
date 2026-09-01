#!/usr/bin/env python3
"""Every VEX shape the binary actually contains, and whether it lowers.

**The case lists in this tree are hand written.** `lowering_cases.build`
enumerates the shapes somebody thought of; `lane_oracle` names its
mnemonics; `span_oracle` spells out four spans. Each is a good list and none
of them is derived from the program under test, so a shape the binary
contains and nobody wrote down is checked by nothing -- and two defects this
week were exactly that. The rip-relative displacement in a span's low half
was missed because every case in `span_oracle` used an ordinary
displacement; the alignment fault was missed because no case put a slot in
an operand.

**What "does not lower" means here, and it is narrower than it sounds.**
This asks `lower_vex`, which is the plain path: one instruction in, SSE
bytes out. Everything the rewriter does with a STRATEGY is invisible to it
-- the pair and the run split 256-bit moves, a sequence handles `vblendv`'s
mask, the span carries a stretch of them -- so a shape reported here as
refused may well be lowered in the binary by something else. The count is
an upper bound on what is unhandled and not a residue; `make census` is
what reconciles against the binary.

What this catches that `census` cannot is a shape nobody wrote a case for,
which is the whole reason it exists.

This enumerates instead. Every VEX instruction in `.text` is reduced to a
SHAPE -- the mnemonic, the width, and the arrangement of its operands with
the register NUMBERS thrown away and only the aliasing kept -- and the
shapes are counted. Then each is offered to `lower_vex`, and the ones it
refuses are reported with an example address so they can be looked at.

What a shape keeps, and why each part:

  * the **mnemonic**, because the lowering is a table keyed on it;
  * the **width**, because a 256-bit form has no SSE encoding at all and a
    128-bit one usually does;
  * **memory or register** per operand, because a memory operand moves and
    a register one aliases;
  * **which operands are the same register**, because that is what Class C
    aliasing is and it is where two of this project's silent-corruption
    bugs lived. `%xmm2,%xmm1,%xmm2` and `%xmm2,%xmm1,%xmm0` are different
    shapes and the first one needs a scratch;
  * whether there is an **immediate**, because it changes the operand count
    and the encoding length.

Register numbers are deliberately thrown away. Keeping them would make
sixteen shapes out of one and drown the thing this is for.

Usage:  shape_census.py <binary> <listing>
"""

import collections
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import detour
import patch as inplace
import scratch as scratch_finder


def shape_of(encoding, mnemonic, operands):
	"""The canonical shape string, or None if this is not VEX.

	Operands are rewritten left to right: the first register seen becomes
	`r0`, the next distinct one `r1`, and a repeat of an earlier one keeps
	its first name. That is what turns sixteen register assignments into
	one shape and keeps the aliasing that matters.
	"""
	vex = inplace.decode_vex(encoding)
	if vex is None:
		return None
	fields = inplace.split_operands(operands or "")
	seen, parts = {}, []
	for field in fields:
		if field.startswith("$"):
			parts.append("imm")
		elif "(" in field:
			parts.append("mem")
		elif field.startswith("%"):
			name = detour.canonical_ymm(field) if field.startswith("%ymm") \
				else field
			if name not in seen:
				seen[name] = f"r{len(seen)}"
			parts.append(seen[name])
		else:
			parts.append("?")
	return f"{mnemonic} {'256' if vex['L'] else '128'} {','.join(parts)}"


def main():
	if len(sys.argv) < 3:
		print("usage: shape_census.py <binary> <listing>", file=sys.stderr)
		return 2
	counts = collections.Counter()
	example = {}
	for address, encoding, mnemonic, operands in inplace.parse_listing(
			sys.argv[2]):
		shape = shape_of(encoding, mnemonic, operands)
		if shape is None:
			continue
		counts[shape] += 1
		example.setdefault(shape, (address, encoding, mnemonic, operands))

	lowered, refused = collections.Counter(), []
	for shape, count in counts.items():
		address, encoding, mnemonic, operands = example[shape]
		# **A scratch the instruction does not itself name.** The first
		# version passed 5 for everything, so every shape whose example
		# happened to use xmm5 was reported as having no lowering -- and
		# they were the Class C aliasing shapes, which the rewriter
		# handles and which are the ones this census exists to watch. A
		# fixed scratch measures the example's register numbers rather
		# than the shape.
		used = set(scratch_finder.xmm_numbers(operands or ""))
		scratch = next((n for n in range(16) if n not in used), None)
		try:
			body = detour.lower_vex(address, encoding, operands, mnemonic,
			                        address, scratch=scratch, pool=address)
		except Exception as error:				# noqa: BLE001
			# A shape that makes the lowering RAISE is worse than one it
			# refuses, and the two must not be reported together: a
			# refusal is a decision and an exception is a case nobody
			# considered. Recorded with the exception's text.
			refused.append((count, shape, f"raised {type(error).__name__}",
			                address))
			continue
		if body is None:
			refused.append((count, shape, "refused", address))
		else:
			lowered[shape] = count

	total = sum(counts.values())
	print(f"VEX instructions           {total:>10,}")
	print(f"distinct shapes            {len(counts):>10,}")
	print(f"  shapes that lower        {len(lowered):>10,}"
	      f"  ({sum(lowered.values()):,} instructions)")
	print(f"  shapes that do not       {len(refused):>10,}"
	      f"  ({sum(c for c, *_r in refused):,} instructions)")
	refused.sort(reverse=True)
	print("\nshapes with no lowering, by how many instructions they are:")
	for count, shape, why, address in refused[:25]:
		print(f"  {count:>8,}  {shape:<44} {why} (0x{address:x})")
	raised = [r for r in refused if r[2].startswith("raised")]
	if raised:
		print(f"\n**{len(raised)} shape(s) made the lowering RAISE**, which is "
		      f"a case nobody considered rather than one it declined:")
		for count, shape, why, address in raised[:10]:
			print(f"  {count:>8,}  {shape:<44} {why} (0x{address:x})")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
