#!/usr/bin/env python3
"""Find a dead xmm register at a site, for the sequences that need one.

Class D, F and H lower to several instructions and most of them need
somewhere to put an intermediate. `project.md` calls this hard part 5, and
it is the reason those sites are still VEX.

**Spilling to the stack is the obvious answer and it is wrong here.** Win64
has no red zone, so a stub would have to move `rsp`; and the stubs live in a
section with no `.pdata`, so `RtlVirtualUnwind` finds no unwind data, treats
the stub as a leaf, and reads the frame from an `rsp` that has been moved.
Anything that walks the stack while a stub is executing -- an exception, a
sampling profiler -- then gets a wrong answer. Buying four instructions with
a broken unwind is a poor trade.

So the scratch has to be a register that is already dead. This finds one by
scanning forward from the site, which is sound because it never has to prove
a register is dead *everywhere* -- only that nothing reads it before
something overwrites it:

  * a **full write** to a register kills whatever it held, so if one happens
    before any read, that register is free at the site;
  * a **call** kills xmm4 and xmm5 outright. They are volatile under Win64
    and are not argument registers, so no caller can expect them to survive
    and no callee is passed anything in them. xmm0 to xmm3 are argument
    registers, so a call *reads* them; xmm6 to xmm15 are preserved, so a
    call tells us nothing about them;
  * anything else that transfers control ends the scan, and the answer is
    "no scratch here". Following the branch would need a CFG and the whole
    point of scanning forward is not to need one.

The conservative direction is refusing a register that was in fact free.
The dangerous direction -- claiming one that was live -- needs a read to be
missed, so reads are counted generously: any register named in any operand
is read unless the instruction is one of the few known to overwrite it
completely.

  measure <listing>    how many sites needing a scratch can get one
"""

import sys
from collections import Counter

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))
import patch as inplace

# Instructions that write the whole 128 bits of their destination without
# reading it. Deliberately a short list: a mnemonic missing from it costs a
# scratch that was available, while a wrong one costs correctness.
#
# The move forms qualify only when the destination is a register. `movss`
# and `movsd` are absent on purpose -- register to register they merge into
# the low lanes and leave the rest of the destination alive.
FULL_WRITE = frozenset("""
	movaps movups movdqa movdqu movapd movupd
	vmovaps vmovups vmovdqa vmovdqu vmovapd vmovupd
""".split())

# Zeroing idioms: the destination is written whole and its previous value is
# not consulted, even though it appears as a source.
ZEROING = frozenset("vxorps vxorpd vpxor xorps xorpd pxor".split())

CONTROL = ("j", "ret", "loop", "iret", "syscall", "sysret", "int", "ud", "hlt")

# Volatile under Win64 and not used to pass arguments, so a call ends their
# lives without reading them.
DEAD_AT_CALL = (4, 5)
ARGUMENT_REGISTERS = (0, 1, 2, 3)


def xmm_numbers(text):
	"""The xmm registers named in an operand string."""
	out = []
	start = 0
	while True:
		at = text.find("%xmm", start)
		if at < 0:
			return out
		digits = ""
		i = at + 4
		while i < len(text) and text[i].isdigit():
			digits += text[i]
			i += 1
		if digits:
			out.append(int(digits))
		start = i


def find_scratch(instructions, index, limit=60):
	"""A register number free to clobber at instructions[index], or None."""
	read = set()
	site_registers = set(xmm_numbers(instructions[index][3]))
	# The site's own operands are live: they are what the sequence works on.
	read |= site_registers

	for step in range(1, limit + 1):
		position = index + step
		if position >= len(instructions):
			return None
		_address, _encoding, mnemonic, operands = instructions[position]

		if mnemonic in ("call", "callq"):
			for candidate in DEAD_AT_CALL:
				if candidate not in read:
					return candidate
			read.update(ARGUMENT_REGISTERS)
			# Nothing can be said about the preserved registers without
			# following the call, so stop rather than guess.
			return None

		if mnemonic.startswith(CONTROL):
			return None

		fields = inplace.split_operands(operands)
		registers = [o for o in fields if not o.startswith("$")]
		if not registers:
			continue

		destination = xmm_numbers(registers[-1])
		sources = []
		for operand in registers[:-1]:
			sources.extend(xmm_numbers(operand))

		kills = None
		if mnemonic in ZEROING and len(registers) >= 2:
			# dst = src ^ src, with every operand the same register.
			everything = set(sources) | set(destination)
			if len(everything) == 1 and destination:
				kills = destination[0]
		elif mnemonic in FULL_WRITE and len(destination) == 1:
			# A register destination, and the source is not the same
			# register (which would be a no-op rather than a kill).
			if destination[0] not in sources:
				kills = destination[0]

		if kills is not None and kills not in read:
			return kills

		# Everything named here is read, including a destination that was
		# only partially written.
		read.update(sources)
		read.update(destination)

	return None


def dies_here(instructions, index, register, limit=60):
	"""True if `register` is not read again after instructions[index].

	A narrower question than find_scratch answers, and a more useful one for
	a sequence whose control operand it is allowed to destroy: the site
	itself reads the register, so what matters is only what happens after.
	Same scan, same conservative direction -- an unresolved answer is "still
	live".
	"""
	for step in range(1, limit + 1):
		position = index + step
		if position >= len(instructions):
			return False
		_address, _encoding, mnemonic, operands = instructions[position]

		if mnemonic in ("call", "callq"):
			# Volatile and not an argument register, so a call ends its life.
			return register in DEAD_AT_CALL
		if mnemonic.startswith(CONTROL):
			return False

		fields = inplace.split_operands(operands)
		registers = [o for o in fields if not o.startswith("$")]
		if not registers:
			continue
		destination = xmm_numbers(registers[-1])
		sources = []
		for operand in registers[:-1]:
			sources.extend(xmm_numbers(operand))
		if register in sources:
			return False
		if register in destination:
			if mnemonic in FULL_WRITE and len(destination) == 1:
				return register not in sources
			if mnemonic in ZEROING:
				return True
			return False			# partial write leaves it alive
	return False


def main(argv):
	if not argv or argv[0] in ("-h", "--help"):
		print(__doc__.strip())
		return 0
	if argv[0] != "measure":
		print(f"scratch.py: unknown mode {argv[0]!r}", file=sys.stderr)
		return 2

	instructions = [(a, e, m, o)
	                for a, e, m, o in inplace.parse_listing(argv[1])]
	needs = Counter()
	found = Counter()
	for i, (address, encoding, mnemonic, operands) in enumerate(instructions):
		if not encoding or encoding[0] not in (0xC4, 0xC5):
			continue
		if inplace.has_direct_sse_form(mnemonic):
			continue
		if mnemonic in inplace.DESTINATION_IN_VVVV or mnemonic == "(bad)":
			continue
		needs[mnemonic] += 1
		if find_scratch(instructions, i) is not None:
			found[mnemonic] += 1

	total_needs = sum(needs.values())
	total_found = sum(found.values())
	print(f"{'mnemonic':<20}{'sites':>10}{'scratch found':>16}{'share':>9}")
	for mnemonic, count in needs.most_common(14):
		got = found[mnemonic]
		print(f"{mnemonic:<20}{count:>10,}{got:>16,}{100.0*got/count:>8.1f}%")
	print(f"\n{'total':<20}{total_needs:>10,}{total_found:>16,}"
	      f"{100.0*total_found/max(total_needs,1):>8.1f}%")
	return 0


if __name__ == "__main__":
	raise SystemExit(main(sys.argv[1:]))
