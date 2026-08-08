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
  * a **`ret`** kills xmm1 to xmm5. They are volatile, so the caller cannot
    expect them to survive the call it is about to return from; xmm0 is
    excluded because it carries the return value;
  * a **branch with a direct target** is followed, and this is where the
    measurement sent the design. Stopping at branches refused 5,255 of the
    6,206 sites that could not get a scratch -- 85% of them -- while the
    scan limit accounted for 170 and `ret` for 332. Widening the limit was
    worth almost nothing; following the edges was worth almost everything.

**Following an edge does not need a control flow graph, and this does not
build one.** An unconditional jump has exactly one successor, so the scan
simply continues there. A conditional branch has two, and a register is free
only if it is free on **both**, so the two answers are intersected. Anything
that cannot be resolved -- an indirect jump, a target outside the listing, a
back edge, an exhausted budget -- contributes the empty set, which is the
conservative direction by construction: it can only refuse a register that
was in fact free.

The conservative direction is refusing a register that was in fact free.
The dangerous direction -- claiming one that was live -- needs a read to be
missed, so reads are counted generously: any register named in any operand
is read unless the instruction is one of the few known to overwrite it
completely.

  measure <listing>    how many sites needing a scratch can get one
  check <listing>      prove every scratch it claims is really dead
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


# Volatile under Win64 and not the return register, so a `ret` ends their
# lives: the caller of the function about to return cannot expect any of
# them to have survived. xmm0 is excluded because it carries the result.
DEAD_AT_RETURN = (1, 2, 3, 4, 5)

UNCONDITIONAL = ("jmp", "jmpq")

# Positions explored per site, across every path. A ceiling rather than a
# tuning knob: without one a site in a dense basic-block graph can fan out
# further than the answer is worth.
BUDGET = 400

_ADDRESS_INDEX = {}


def address_index(instructions):
	"""{address: position}, built once per listing rather than per site."""
	key = id(instructions)
	cached = _ADDRESS_INDEX.get(key)
	if cached is None or cached[0] is not instructions:
		cached = (instructions,
		          {entry[0]: i for i, entry in enumerate(instructions)})
		_ADDRESS_INDEX[key] = cached
	return cached[1]


def branch_target(operands):
	"""The address a direct branch names, or None if it is not direct."""
	if not operands:
		return None
	first = operands.split()[0]
	if not first.startswith("0x"):
		return None
	try:
		return int(first, 16)
	except ValueError:
		return None


def kills_of(mnemonic, registers):
	"""The register this instruction overwrites without reading, or None."""
	if not registers:
		return None, [], []
	destination = xmm_numbers(registers[-1])
	sources = []
	for operand in registers[:-1]:
		sources.extend(xmm_numbers(operand))
	if mnemonic in ZEROING and len(registers) >= 2:
		# dst = src ^ src, with every operand the same register.
		everything = set(sources) | set(destination)
		if len(everything) == 1 and destination:
			return destination[0], sources, destination
	elif mnemonic in FULL_WRITE and len(destination) == 1:
		# A register destination, and the source is not the same register
		# (which would be a no-op rather than a kill).
		if destination[0] not in sources:
			return destination[0], sources, destination
	return None, sources, destination


def dead_from(instructions, position, read, depth, addresses, visiting,
              budget):
	"""Registers safe to clobber on EVERY path forward from `position`.

	The empty set means "nothing proven", never "nothing dead", and every
	unresolved case returns it. That is what keeps the dangerous direction
	-- claiming a live register -- unreachable without a read being missed.
	"""
	if depth <= 0 or budget[0] <= 0 or position >= len(instructions):
		return frozenset()
	if position in visiting:
		return frozenset()		# a back edge; the path is not linear
	budget[0] -= 1
	_address, _encoding, mnemonic, operands = instructions[position]

	if mnemonic in ("call", "callq"):
		return frozenset(DEAD_AT_CALL) - read
	if mnemonic.startswith("ret"):
		return frozenset(DEAD_AT_RETURN) - read
	if mnemonic.startswith(CONTROL):
		target = branch_target(operands)
		if target is None or target not in addresses:
			return frozenset()	# indirect, or off the end of the listing
		successors = [addresses[target]]
		if not mnemonic.startswith(UNCONDITIONAL):
			successors.append(position + 1)	# the branch not taken
		inside = visiting | {position}
		answer = None
		for successor in successors:
			one = dead_from(instructions, successor, read, depth - 1,
			                addresses, inside, budget)
			answer = one if answer is None else (answer & one)
			if not answer:
				break		# an empty intersection cannot recover
		return answer or frozenset()

	fields = inplace.split_operands(operands)
	registers = [o for o in fields if not o.startswith("$")]
	kills, sources, destination = kills_of(mnemonic, registers)

	here = frozenset()
	if kills is not None and kills not in read:
		# Safe from here on regardless of what the rest of the path does.
		here = frozenset([kills])
	# Everything named is read, including a destination only partly written.
	onward = read | set(sources) | set(destination)
	return here | dead_from(instructions, position + 1, onward, depth - 1,
	                        addresses, visiting | {position}, budget)


def find_scratch(instructions, index, limit=60):
	"""A register number free to clobber at instructions[index], or None."""
	# The site's own operands are live: they are what the sequence works on.
	site_registers = frozenset(xmm_numbers(instructions[index][3]))
	free = dead_from(instructions, index + 1, site_registers, limit,
	                 address_index(instructions), set(), [BUDGET])
	for candidate in sorted(free):
		return candidate
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


READ, KILLED, UNKNOWN = "read", "killed", "unknown"


def walk(instructions, addresses, start, register, depth):
	"""Whether `register` is written before read on EVERY path from `start`.

	The same claim find_scratch makes, checked the other way round. That one
	recurses and intersects dead sets; this enumerates concrete paths one at
	a time and asks of each whether the register survives. A fault in the
	intersection or the union shows up here as a path on which the claimed
	register is still live, which set arithmetic alone cannot reveal.

	Writing it twice is the point. The first version of this check tested
	`register in sources` before `kills == register` and reported 597
	violations, every one of them a zeroing idiom -- which names its
	register as a source and does not read it, the whole reason ZEROING
	exists. The checker was wrong and the search was right.
	"""
	stack = [(start, depth, frozenset())]
	while stack:
		position, left, visited = stack.pop()
		while True:
			if left <= 0 or position >= len(instructions):
				return UNKNOWN
			if position in visited:
				return UNKNOWN
			visited = visited | {position}
			_address, _encoding, mnemonic, operands = instructions[position]
			if mnemonic in ("call", "callq"):
				if register in DEAD_AT_CALL:
					break
				return UNKNOWN
			if mnemonic.startswith("ret"):
				if register in DEAD_AT_RETURN:
					break
				return UNKNOWN
			if mnemonic.startswith(CONTROL):
				target = branch_target(operands)
				if target is None or target not in addresses:
					return UNKNOWN
				successors = [addresses[target]]
				if not mnemonic.startswith(UNCONDITIONAL):
					successors.append(position + 1)
				for successor in successors[1:]:
					stack.append((successor, left - 1, visited))
				position, left = successors[0], left - 1
				continue
			fields = inplace.split_operands(operands)
			registers = [o for o in fields if not o.startswith("$")]
			kills, sources, destination = kills_of(mnemonic, registers)
			if kills == register:
				break
			if register in sources or register in destination:
				return READ	# a partial write leaves it alive
			position, left = position + 1, left - 1
	return KILLED


def wants_scratch(mnemonic, operands):
	"""True if a site of this shape asks find_scratch for a register."""
	registers = [o for o in inplace.split_operands(operands)
	             if not o.startswith("$")]
	if inplace.has_direct_sse_form(mnemonic):
		# The src2-aliases-destination case; see detour.lower_vex.
		return (len(registers) == 3 and registers[-1] != registers[-2]
		        and registers[0] == registers[-1])
	return mnemonic not in inplace.DESTINATION_IN_VVVV and mnemonic != "(bad)"


def check(listing):
	instructions = list(inplace.parse_listing(listing))
	addresses = address_index(instructions)
	checked = live = unknown = 0
	for i, (address, encoding, mnemonic, operands) in enumerate(instructions):
		if encoding[:1] not in (b"\xc4", b"\xc5"):
			continue
		if not wants_scratch(mnemonic, operands):
			continue
		register = find_scratch(instructions, i)
		if register is None:
			continue
		checked += 1
		verdict = walk(instructions, addresses, i + 1, register, 60)
		if verdict == READ:
			live += 1
			if live <= 5:
				print(f"check: 0x{address:x} {mnemonic}: xmm{register} is "
				      f"read on some path", file=sys.stderr)
		elif verdict == UNKNOWN:
			unknown += 1
	print(f"check: {checked:,} claimed scratch registers")
	print(f"check: {live:,} read on some path (must be 0), "
	      f"{unknown:,} unverifiable")
	return 1 if live else 0


def main(argv):
	if not argv or argv[0] in ("-h", "--help"):
		print(__doc__.strip())
		return 0
	if argv[0] == "check":
		return check(argv[1])
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
