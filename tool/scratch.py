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
  * a **call** kills xmm4 or xmm5 where the callee clobbers it and does
    not read it. Being volatile is not enough: this binary's callers keep
    values across a call in registers they know the callee leaves alone
    (Finding 350), and `__vectorcall` passes arguments in both;
  * a **`ret`** kills xmm4 or xmm5 where the returning function clobbers
    it, for the same reason. xmm0 to xmm3 can carry a `__vectorcall`
    result and are never killed there;
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
  check <listing> [binary]   prove every scratch it claims is dead
"""

import bisect
import sys
from collections import Counter

sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))
import patch as inplace
import lower			# noqa: E402  -- after the sys.path fix above

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

# Volatile under Win64 and not used to pass arguments by the standard
# convention, so a call CAN end their lives -- but only where the callee
# clobbers them and does not read them, which `calls_dead` decides.
DEAD_AT_CALL = (4, 5)
ARGUMENT_REGISTERS = (0, 1, 2, 3)


# xmm0, ymm0 and zmm0 are one register seen through three widths, so a
# scan for live registers has to answer to all three names. Matching only
# `%xmm` made every 256-bit operand invisible: `find_scratch` would hand out
# a register that a neighbouring `vmovups %ymm5,(%rdi)` was using, and
# `scratch.walk` -- the check written to catch exactly that -- called this
# same function and so could never see it. Finding 52.
REGISTER_NAMES = ("%xmm", "%ymm", "%zmm")


def xmm_numbers(text):
	"""The vector registers named in an operand string, by number."""
	out = []
	for name in REGISTER_NAMES:
		start = 0
		while True:
			at = text.find(name, start)
			if at < 0:
				break
			digits = ""
			i = at + len(name)
			while i < len(text) and text[i].isdigit():
				digits += text[i]
				i += 1
			if digits:
				out.append(int(digits))
			start = i if digits else at + len(name)
	return out


# Volatile under Win64 and not a return register, so a `ret` CAN end their
# lives -- but only where the function about to return clobbers them, which
# `returns_dead` decides. xmm1 to xmm3 are excluded with xmm0 because
# `__vectorcall` returns a homogeneous aggregate in xmm0 to xmm3, which is
# what DirectXMath's matrix functions return.
DEAD_AT_RETURN = (4, 5)

UNCONDITIONAL = ("jmp", "jmpq")

# Positions explored per site, across every path. A ceiling rather than a
# tuning knob: without one a site in a dense basic-block graph can fan out
# further than the answer is worth.
BUDGET = 400

_ADDRESS_INDEX = {}


# **What a function clobbers, which is what its callers may assume.** The
# ABI lets a callee destroy every volatile register, and the rules above
# once took that as what callers expect: a `ret` killed xmm1 to xmm5 and a
# call killed xmm4 and xmm5. This binary was built with whole-program
# register allocation, so a caller knows which registers a callee really
# writes and keeps a value live across a call in any register the callee
# leaves alone. 0x142920cac loads `r9`, calls 0x142ccb870, and stores
# through `r9` after it -- and a stub in that callee took `r9` as dead at
# its `ret`, so Starfield faulted at 0x148ded821 on a pointer holding two
# floats. Finding 350.
#
# So a register dies at a `ret` only if the function clobbers it, and at a
# call only if the callee clobbers it and does not read it. Both sets are
# what the compiler would have computed: the registers a function writes,
# plus those of every function it calls directly, plus everything for an
# indirect call, whose target follows the standard convention. Counting is
# done in the direction that keeps this sound -- a clobber set too SMALL
# costs a scratch, one too large hands out a register a caller is holding
# -- so only instructions reachable from the entry count, jump-table data
# decoded as code cannot add a write, and a write is recognised only in the
# forms below, taken from a census of every last operand in the listing.

# Every spelling of each volatile GPR, keyed to its 64-bit name. A read of
# `%r8b` is a read of `%r8`, and the high-byte forms alias bits 15:8 of the
# first three.
GPR_SPELLINGS = {}
for _wide, _parts in (
		("rax", ("rax", "eax", "ax", "al", "ah")),
		("rcx", ("rcx", "ecx", "cx", "cl", "ch")),
		("rdx", ("rdx", "edx", "dx", "dl", "dh")),
		("r8", ("r8", "r8d", "r8w", "r8b")),
		("r9", ("r9", "r9d", "r9w", "r9b")),
		("r10", ("r10", "r10d", "r10w", "r10b")),
		("r11", ("r11", "r11d", "r11w", "r11b"))):
	for _part in _parts:
		GPR_SPELLINGS[_part] = _wide

ALL_GPRS = frozenset(GPR_SPELLINGS.values())
ALL_XMM = frozenset(range(6))

# Mnemonic prefixes that write a GPR last operand. A positive list, because
# the negative one is open: `cmp`, `test`, `bt`, `push` and one-operand
# `mul`/`div` all end in a register they only read. `imul` is handled apart
# for that reason.
GPR_WRITE_PREFIXES = (
	"adc", "add", "and", "bsf", "bsr", "bswap", "btc", "btr", "bts", "cmov",
	"crc32", "cvtt", "vcvtt", "dec", "inc", "lar", "lea", "lods", "lsl",
	"mov", "neg", "not", "or", "pextr", "vpextr", "pmovmskb", "vpmovmskb",
	"pop", "popcnt", "lzcnt", "tzcnt", "rcl", "rcr", "rol", "ror", "sar",
	"sbb", "set", "shl", "shr", "sub", "vextractps", "vmov", "xchg", "xor")

# Mnemonic prefixes whose vector last operand is read and not written. Every
# other vector instruction writes its last operand when it is a register.
XMM_READ_ONLY_PREFIXES = (
	"comis", "ucomis", "vcomis", "vucomis", "ptest", "vptest", "vtest",
	"pcmpestr", "pcmpistr", "vpcmpestr", "vpcmpistr")


def written(mnemonic, operands):
	"""`(gprs, xmms)` this instruction certainly writes: wide GPR names,
	and the numbers of volatile vector registers."""
	fields = inplace.split_operands(operands or "")
	if not fields:
		return frozenset(), frozenset()
	last = fields[-1]
	if not last.startswith("%") or "(" in last or ":" in last:
		return frozenset(), frozenset()
	name = last[1:]
	if name.startswith(("xmm", "ymm", "zmm")):
		if mnemonic.startswith(XMM_READ_ONLY_PREFIXES):
			return frozenset(), frozenset()
		return frozenset(), frozenset(n for n in xmm_numbers(last)
		                              if n in ALL_XMM)
	wide = GPR_SPELLINGS.get(name)
	if wide is None:
		return frozenset(), frozenset()
	if mnemonic.startswith("imul"):
		return (frozenset((wide,)) if len(fields) >= 2 else frozenset(),
		        frozenset())
	if not mnemonic.startswith(GPR_WRITE_PREFIXES):
		return frozenset(), frozenset()
	out = {wide}
	if mnemonic.startswith("xchg"):
		other = GPR_SPELLINGS.get(fields[0][1:]) \
			if fields[0].startswith("%") else None
		if other is not None:
			out.add(other)
	return frozenset(out), frozenset()


def read_xmm(mnemonic, operands):
	"""Volatile vector registers this instruction may read: every one it
	names, less a destination it certainly overwrites whole."""
	fields = inplace.split_operands(operands or "")
	registers = [o for o in fields if not o.startswith("$")]
	kills, _sources, _destination = kills_of(mnemonic, registers)
	return frozenset(n for n in xmm_numbers(operands or "")
	                 if n in ALL_XMM and n != kills)


_CLOBBERS = {}


def clobbers(instructions, ranges, standard=()):
	"""Register, for `instructions`, what each function clobbers and reads.

	Called by `function_scope`, which every caller of the scan already runs
	over the same listing and ranges. Until it has run, `returns_dead` and
	`calls_dead` answer nothing for that listing, which is the direction
	that costs a scratch rather than a program.

	`standard` is the functions code outside the image calls -- the entry
	point and the exports, `patch.standard_entries`. Their callers know
	nothing of them and assume every volatile register destroyed.
	"""
	addresses = address_index(instructions)
	starts = [start for start, _end in ranges]
	at_start = {start: i for i, start in enumerate(starts)}
	own_gpr = [set() for _ in ranges]
	own_xmm = [set() for _ in ranges]
	reads = [set() for _ in ranges]
	callees = [set() for _ in ranges]
	everything = [False] * len(ranges)
	returns, calls = {}, {}
	for i, (start, end) in enumerate(ranges):
		entry = addresses.get(start)
		if entry is None:
			continue
		seen, work = set(), [entry]
		while work:
			position = work.pop()
			if position in seen or position >= len(instructions):
				continue
			address, _encoding, mnemonic, operands = instructions[position]
			if not start <= address < end:
				continue
			seen.add(position)
			if mnemonic.startswith("ret"):
				returns[position] = i
				continue
			if mnemonic.startswith(("ud", "hlt", "int3", "(bad)")):
				continue
			if mnemonic.startswith("call"):
				target = branch_target(operands)
				callee = at_start.get(target)
				if target is None:
					# Indirect, so the standard convention: it clobbers
					# every volatile register.
					calls[position] = "indirect"
					everything[i] = True
				elif callee is not None:
					calls[position] = callee
					callees[i].add(callee)
				reads[i] |= read_xmm(mnemonic, operands)
				work.append(position + 1)
				continue
			gprs, xmms = written(mnemonic, operands)
			own_gpr[i] |= gprs
			own_xmm[i] |= xmms
			reads[i] |= read_xmm(mnemonic, operands)
			if mnemonic.startswith(CONTROL):
				target = branch_target(operands)
				if target is not None and target in addresses:
					work.append(addresses[target])
				if not mnemonic.startswith(UNCONDITIONAL) \
						and target is not None:
					work.append(position + 1)
				continue
			work.append(position + 1)
	# Through the call graph to a fixed point. The sets only grow and are
	# bounded, so this ends; a cycle simply converges.
	# Called from outside, so clobbering everything -- but that says
	# nothing about what it READS, which an indirect call does: its callee
	# may take `__vectorcall` arguments in xmm4 and xmm5.
	outside_called = [False] * len(ranges)
	for start in standard:
		if start in at_start:
			outside_called[at_start[start]] = True
	gpr = [ALL_GPRS if everything[i] or outside_called[i]
	       else frozenset(own_gpr[i]) for i in range(len(ranges))]
	xmm = [ALL_XMM if everything[i] or outside_called[i]
	       else frozenset(own_xmm[i]) for i in range(len(ranges))]
	used = [ALL_XMM if everything[i] else frozenset(reads[i])
	        for i in range(len(ranges))]
	changed = True
	while changed:
		changed = False
		for i in range(len(ranges)):
			g, x, r = gpr[i], xmm[i], used[i]
			for callee in callees[i]:
				g = g | gpr[callee]
				x = x | xmm[callee]
				r = r | used[callee]
			if (g, x, r) != (gpr[i], xmm[i], used[i]):
				gpr[i], xmm[i], used[i] = g, x, r
				changed = True
	everything_set = (ALL_GPRS, ALL_XMM, ALL_XMM)
	_CLOBBERS[id(instructions)] = (instructions, {
		"returns": {p: (gpr[i], xmm[i]) for p, i in returns.items()},
		"calls": {p: everything_set if i == "indirect"
		          else (gpr[i], xmm[i], used[i])
		          for p, i in calls.items()},
		"functions": (starts, ranges, gpr, xmm, used),
	})


def _clobber_table(instructions):
	cached = _CLOBBERS.get(id(instructions))
	if cached is None or cached[0] is not instructions:
		return None
	return cached[1]


def returns_clobber(instructions, position):
	"""`(gprs, xmms)` the function returning at `position` clobbers, or
	two empty sets where nothing is known."""
	table = _clobber_table(instructions)
	if table is None:
		return frozenset(), frozenset()
	return table["returns"].get(position, (frozenset(), frozenset()))


def calls_clobber(instructions, position):
	"""`(gprs, xmms, xmm_reads)` for the call at `position`. Unknown is
	nothing clobbered and everything read."""
	table = _clobber_table(instructions)
	if table is None:
		return frozenset(), frozenset(), ALL_XMM
	return table["calls"].get(position, (frozenset(), frozenset(), ALL_XMM))


def function_clobber(instructions, address):
	"""`(gprs, xmms, xmm_reads)` for the function holding `address`, or
	None where nothing is known."""
	table = _clobber_table(instructions)
	if table is None:
		return None
	starts, ranges, gpr, xmm, used = table["functions"]
	i = bisect.bisect_right(starts, address) - 1
	if i < 0 or address >= ranges[i][1]:
		return None
	return gpr[i], xmm[i], used[i]


def returns_dead(instructions, position):
	"""Vector registers dead at the `ret` at `position`."""
	return frozenset(DEAD_AT_RETURN) & returns_clobber(instructions,
	                                                   position)[1]


def calls_dead(instructions, position):
	"""Vector registers dead at the call at `position`: clobbered by the
	callee, and not read by it either, since `__vectorcall` passes
	arguments in xmm4 and xmm5 too."""
	_gprs, xmms, reads = calls_clobber(instructions, position)
	return (frozenset(DEAD_AT_CALL) & xmms) - reads


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
	elif len(registers) == 3 and len(destination) == 1 \
			and destination[0] not in sources \
			and not any("{" in operand for operand in registers) \
			and (mnemonic in lower.NDS_MNEMONICS
			     or lower.compare_predicate(mnemonic) is not None):
		# **A VEX non-destructive form writes its destination whole and
		# never reads it**: `dst = op(src1, src2)`, with the bits above
		# 127 zeroed. That is the instruction set's rule rather than this
		# file's, and it is the shape `lower_vex` already lowers as
		# `movaps src1,dst; op src2,dst`, whose first move discards the
		# old `dst`. Counting it as a read hid `xmm5` and `xmm2` from the
		# passenger at 0x142437e09, which `vshufps $0x88,%xmm0,%xmm1,%xmm5`
		# writes before anything reads it -- so the `vmulps` beside it
		# stayed VEX, and Starfield stopped on it. A merge-masked EVEX form
		# (`{%k}`) does read the destination and is excluded. Finding 349.
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
		return calls_dead(instructions, position) - read
	if mnemonic.startswith("ret"):
		return returns_dead(instructions, position) - read
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


# Volatile under Win64 and not argument registers, which is what lets the
# whole-function argument below work. xmm0 to xmm3 cannot join them: a
# wrapper that calls g(a, b, c) forwards its own arguments in place and
# never names them, so "unmentioned" does not imply "dead" for those.
FUNCTION_SCRATCH = (4, 5)


def function_scope(instructions, ranges, standard=()):
	"""Per function, the registers it provably never touches.

	A different argument from the forward scan, and it reaches where that one
	cannot. If xmm4 is not named anywhere in a function then nothing in the
	function reads it; no callee can expect it, provided none reads it; and
	no caller can expect it, provided some callee clobbers it -- being
	volatile is not enough, Finding 350. So it is free at *every* point in
	that function, including points the forward scan cannot get past.

	The way out is control leaving the range, and **a `.pdata` entry is not
	always a whole function**. MSVC splits one function across two entries,
	and the second half is entered with registers live -- so any way out at
	all disqualifies the range. Both of these were found by the check
	rejecting claims this made:

	  * **Falling off the end.** 0x140a234dd ends at 0x140a235f2 without a
	    terminator and runs straight on into the next entry, which reads
	    xmm4. The first version only looked at jumps and missed it entirely.
	  * **A branch to another entry.** Treating that as a tail call, and so
	    as an ABI boundary, is wrong: the same function's other half has an
	    entry of its own, and `je 0x140a2371f` in that range goes to it.

	So the rule is the blunt one: any jump whose target is not inside the
	range, any indirect jump, and any range that does not end in a control
	transfer. Real tail calls are lost with it, which costs coverage and
	costs nothing else.
	"""
	starts = [start for start, _end in ranges]
	mentioned = [set() for _ in ranges]
	escapes = [False] * len(ranges)
	last = [None] * len(ranges)
	for address, _encoding, mnemonic, operands in instructions:
		i = bisect.bisect_right(starts, address) - 1
		if i < 0 or address >= ranges[i][1]:
			continue
		mentioned[i].update(xmm_numbers(operands))
		last[i] = mnemonic
		if not mnemonic.startswith(("j", "loop")):
			continue
		target = branch_target(operands)
		if target is None or not ranges[i][0] <= target < ranges[i][1]:
			escapes[i] = True
	for i, mnemonic in enumerate(last):
		# A range that does not end by transferring control falls through
		# into whatever follows it, carrying live registers with it.
		if mnemonic is None or not (mnemonic.startswith(("ret", "jmp", "ud"))
		                            or mnemonic == "int3"):
			escapes[i] = True
	# **And a caller may hold it across this function** unless the function
	# clobbers it, which is Finding 350's rule: a register this function
	# never names is one it never writes, so it is free here only if a
	# callee writes it -- and no callee reads it, since a `__vectorcall`
	# callee takes arguments in xmm4 and xmm5 that this function would be
	# passing on unnamed.
	clobbers(instructions, ranges, standard)
	table = _clobber_table(instructions)
	_s, _r, _gpr, clobbered, read = table["functions"]
	free = [frozenset() if escapes[i]
	        else frozenset(r for r in FUNCTION_SCRATCH
	                       if r not in mentioned[i]
	                       and r in clobbered[i] and r not in read[i])
	        for i in range(len(ranges))]
	return starts, ranges, free


def scope_free(scope, address):
	"""The whole-function free registers at `address`, if any."""
	if scope is None:
		return frozenset()
	starts, ranges, free = scope
	i = bisect.bisect_right(starts, address) - 1
	if i < 0 or address >= ranges[i][1]:
		return frozenset()
	return free[i]


def find_scratch(instructions, index, limit=60, scope=None):
	"""A register number free to clobber at instructions[index], or None."""
	# The site's own operands are live: they are what the sequence works on.
	site_registers = frozenset(xmm_numbers(instructions[index][3]))
	free = dead_from(instructions, index + 1, site_registers, limit,
	                 address_index(instructions), set(), [BUDGET])
	for candidate in sorted(free):
		return candidate
	# The forward scan gave nothing. Ask the weaker question the whole
	# function can answer.
	for candidate in sorted(scope_free(scope, instructions[index][0])
	                        - site_registers):
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
			# Ends its life only where the callee clobbers it unread.
			return register in calls_dead(instructions, position)
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
				if register in calls_dead(instructions, position):
					break
				return UNKNOWN
			if mnemonic.startswith("ret"):
				if register in returns_dead(instructions, position):
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


def check(listing, binary=None):
	instructions = list(inplace.parse_listing(listing))
	addresses = address_index(instructions)
	scope = None
	if binary is not None:
		import outside
		import targets as target_set
		blocked = set()
		for values in target_set.collect(binary).values():
			blocked |= values
		for _a, _e, mnemonic, operands in instructions:
			if mnemonic.startswith(("j", "call", "loop")) and operands:
				target = branch_target(operands)
				if target is not None:
					blocked.add(target)
		described = inplace.function_ranges(binary)
		ranges = sorted(described
		                + outside.leaf_ranges(instructions, described, blocked))
		scope = function_scope(instructions, ranges,
		                       inplace.standard_entries(binary))
	checked = live = unknown = whole = 0
	for i, (address, encoding, mnemonic, operands) in enumerate(instructions):
		if encoding[:1] not in (b"\xc4", b"\xc5"):
			continue
		if not wants_scratch(mnemonic, operands):
			continue
		register = find_scratch(instructions, i, scope=scope)
		if register is None:
			continue
		checked += 1
		verdict = walk(instructions, addresses, i + 1, register, 60)
		if verdict == READ:
			# A whole-function claim is allowed to fail the path walk only
			# by being unresolvable, never by a read: if the register is
			# named nowhere in the function, no path through it reads one.
			live += 1
			if live <= 5:
				print(f"check: 0x{address:x} {mnemonic}: xmm{register} is "
				      f"read on some path", file=sys.stderr)
		elif verdict == UNKNOWN:
			# The forward walk could not settle it. If the claim rests on
			# the whole-function argument instead, check that premise --
			# which catches a mistake in the range indexing even though the
			# ABI half of the argument is not something a tool can check.
			if register in scope_free(scope, address):
				whole += 1
			else:
				unknown += 1
	print(f"check: {checked:,} claimed scratch registers")
	print(f"check: {live:,} read on some path (must be 0), "
	      f"{whole:,} resting on the whole-function argument, "
	      f"{unknown:,} unverifiable")
	return 1 if live else 0


def main(argv):
	if not argv or argv[0] in ("-h", "--help"):
		print(__doc__.strip())
		return 0
	if argv[0] == "check":
		return check(argv[1], argv[2] if len(argv) > 2 else None)
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
