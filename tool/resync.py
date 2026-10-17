#!/usr/bin/env python3
"""Put the listing's instruction boundaries back on every function start.

    objdump -d -j .text BINARY | tool/resync.py BINARY > LISTING

objdump disassembles `.text` as one linear sweep, so data embedded in it
-- a switch table, a constant -- is decoded as instructions, and the last
of those can run past the data's end into the code after it. The sweep is
then out of step until the encodings happen to line up again, and every
instruction in between is missing from the listing while phantom ones
stand in its place.

**It costs code that nothing ever sees.** 165 of Starfield's 236,427
`.pdata` function starts are not instruction boundaries in the plain
listing -- two of them sitting on a continuation line, which an
address-keyed reading of the listing takes for a boundary. At `0x1424bfb70` the function's first 13 bytes read as
`add`/`in`/`push`/`add`/`cli`/`adc`, and its two `vmovss` were never
counted, never converted, and still VEX in the shipped image.

Every consumer reads the listing, so it is corrected here rather than in
each parser: wherever a row straddles a `.pdata` start, the bytes before
the start become one `(bad)` row -- the shape the rest of the tool already
reads as data -- and the code is decoded afresh from the start until a
boundary agrees with the original sweep. A start that never resynchronises
within `REACH` bytes is a failure, not a guess. Finding 347.
"""

import bisect
import struct
import subprocess
import sys

OBJDUMP = "objdump"
# How far a fresh decode may run before it must meet the original sweep.
REACH = 256


def pdata_starts(path):
	"""Every function start the exception directory names, as addresses."""
	data = open(path, "rb").read()
	pe = struct.unpack_from("<I", data, 0x3C)[0]
	opt = pe + 24
	base = struct.unpack_from("<Q", data, opt + 24)[0]
	rva, size = struct.unpack_from("<II", data, opt + 112 + 3 * 8)
	if not rva or not size:
		return set()
	sections = struct.unpack_from("<H", data, pe + 6)[0]
	table = opt + struct.unpack_from("<H", data, pe + 20)[0]
	at = None
	for i in range(sections):
		vsize, va, _rsize, raw = struct.unpack_from("<IIII", data,
		                                           table + i * 40 + 8)
		if va <= rva < va + vsize:
			at = raw + rva - va
	if at is None:
		return set()
	return {base + struct.unpack_from("<I", data, at + i * 12)[0]
	        for i in range(size // 12)}


def rows(lines):
	"""Group objdump lines into rows: (address, byte count, [lines]).

	A row is one instruction and its continuation lines; anything that is
	not an instruction line passes through as (None, 0, [line]).
	"""
	current = None
	for line in lines:
		parts = line.split("\t")
		head = parts[0]
		colon = head.rfind(":")
		address = None
		if len(parts) >= 2 and colon >= 0:
			try:
				address = int(head[:colon].strip(), 16)
				count = len(parts[1].split())
			except ValueError:
				address = None
		if address is not None and len(parts) == 2 and current is not None:
			current[1] += count
			current[2].append(line)
			continue
		if current is not None:
			yield tuple(current)
			current = None
		if address is not None and len(parts) >= 3:
			current = [address, count, [line]]
		else:
			yield (None, 0, [line])
	if current is not None:
		yield tuple(current)


def fresh(binary, start):
	"""The rows objdump decodes from `start`, as `rows` yields them."""
	out = subprocess.run(
		[OBJDUMP, "-d", "-j", ".text", f"--start-address={start:#x}",
		 f"--stop-address={start + REACH:#x}", binary],
		capture_output=True, text=True, check=True).stdout
	return [r for r in rows(out.splitlines(keepends=True))
	        if r[0] is not None]


def row_bytes(lines):
	"""The encoding bytes a row's lines carry, in order."""
	out = []
	for line in lines:
		out.extend(line.split("\t")[1].split())
	return out


def within(order, low, high):
	"""The sorted addresses strictly between `low` and `high`."""
	k = bisect.bisect_right(order, low)
	out = []
	while k < len(order) and order[k] < high:
		out.append(order[k])
		k += 1
	return out


class Unresolved(Exception):
	"""A function start the fresh decode could not reconcile."""


def resync(binary, lines, report=None):
	"""Yield the listing `lines` with every `.pdata` start on a boundary.

	`lines` is objdump's output for `binary`, line by line. Raises
	`Unresolved` where a start cannot be put back, and at the end if any
	start in the swept range is still off a boundary -- **the proof, rather
	than the claim**. `report`, when given, is called with the count of
	starts spliced.
	"""
	starts = pdata_starts(binary)
	order = sorted(starts)
	seen, spliced = set(), set()
	low = high = None

	def mark(address):
		nonlocal low, high
		low = address if low is None else low
		high = address
		if address in starts:
			seen.add(address)

	source = rows(lines)
	# A row handed back: the one where a fresh decode met the sweep is
	# judged like any other, since it may straddle the next start itself.
	held = []
	while True:
		if held:
			address, count, text = held.pop()
		else:
			try:
				address, count, text = next(source)
			except StopIteration:
				break
		if address is None:
			yield "".join(text)
			continue
		inside = within(order, address, address + count) if count > 1 else []
		if not inside:
			mark(address)
			yield "".join(text)
			continue
		begin = min(inside)
		# The bytes before the start are not this function's, and the row
		# that decoded them as an instruction ran into it.
		head = row_bytes(text)[:begin - address]
		yield f"{address:>12x}:\t{' '.join(head)} \t(bad)\n"
		decoded = fresh(binary, begin)
		boundaries = {r[0] for r in decoded}
		# Read on in the original until it lands on a boundary the fresh
		# decode also has; everything the original said before that was
		# out of step.
		meet = None
		for later in source:
			if later[0] is None:
				continue
			if later[0] in boundaries:
				meet = later
				break
		if meet is None:
			raise Unresolved(f"{begin:#x} does not meet the sweep within "
			                 f"{REACH} bytes")
		for r in decoded:
			if r[0] >= meet[0]:
				break
			if within(order, r[0], r[0] + r[1]):
				raise Unresolved(f"a second function start inside the "
				                 f"fresh decode at {r[0]:#x}")
			mark(r[0])
			yield "".join(r[2])
		held.append(meet)
		spliced.add(begin)
	missing = sorted(s for s in starts if low is not None
	                 and low <= s <= high and s not in seen)
	if missing:
		raise Unresolved(f"{len(missing)} start(s) still off a boundary: "
		                 + " ".join(f"{s:#x}" for s in missing[:20]))
	if report is not None:
		report(len(spliced))


def main(argv):
	if len(argv) != 1:
		print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
		return 2
	try:
		for chunk in resync(argv[0], sys.stdin, lambda n: print(
				f"resync: {n} function start(s) put back on a boundary",
				file=sys.stderr)):
			sys.stdout.write(chunk)
	except Unresolved as e:
		print(f"resync: {e}", file=sys.stderr)
		return 1
	return 0


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]))
