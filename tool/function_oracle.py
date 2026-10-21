#!/usr/bin/env python3
"""Run whole functions of the original and of the rewrite, and compare.

Every other oracle here runs a lowering out of context -- one instruction,
one shape, one span -- in a harness that hands it registers. None of them
runs a STUB: the bytes `apply` placed, with the spill the strategy chose,
the bracket around it, the passengers it carries and the jump back into the
code that reads what it left. Finding 363 was in exactly that gap -- a
correct lowering inside a bracket that wrote the flags a branch read -- and
no instruction-level oracle can see it, because the instruction is right.

So this loads both images at their preferred base in a Linux process
(`function_sweep.c`), calls each function that holds a VEX site through
the Windows ABI on seeded inputs, and prints what it returned and a hash of
everything it could have written. **Both images run under qemu**: one
executor for both sides makes any difference the rewrite's, where running
the rewrite natively would also report qemu's approximate reciprocals and
NaN choices (measured: two such, both identical once one executor ran
both). The rewrite's load-time placeholders are filled as its TLS callback
would fill them -- index 0, TEB slots 5 and 6 -- because the loader that
runs the callback is not here.

**Most calls fault, and that is the harness's limit rather than a
finding.** A function that follows a pointer from a global, or from a field
of a structure, reads whatever the synthetic inputs put there; three input
modes (small floats, raw bits, pointers back into the buffers) are what
lets a few thousand functions run to the end. A fault on both sides is
counted and dropped. A difference is re-run alone before it is reported,
because functions share the image's globals and one difference could
otherwise make every later call in its shard look different too.

Usage:  function_oracle.py <original> <rewrite> <listing> [build directory]
"""

import bisect
import concurrent.futures
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import detour
import patch as inplace

WORK = Path("build") / "functionoracle"
QEMU = ["qemu-x86_64", "-cpu", "max"]
SOURCE = Path(__file__).resolve().parent / "function_sweep.c"
BASE = 0x140000000
TRIALS = 3
LIMIT_MS = 2000
SHARDS = 8
SHARD_TIMEOUT = 2400


def entry_points(data, listing):
	"""Start of every unchained .pdata function holding a VEX site.

	Chained entries are pieces of a function, not places to call. Leaf
	functions with no frame have no entry at all and are reached only
	through their callers -- `0x141117360`, the distance Finding 363 broke,
	was found that way.
	"""
	entries = []
	for begin, end, unwind in detour.existing_pdata(data):
		flags = data[detour.rva_to_offset(data, unwind)] >> 3
		if not flags & 4:
			entries.append((BASE + begin, BASE + end))
	starts = [begin for begin, _end in entries]
	hit = set()
	for address, encoding, _mnemonic, _operands in inplace.parse_listing(
			listing):
		if inplace.decode_vex(encoding) is None:
			continue
		i = bisect.bisect_right(starts, address) - 1
		if i >= 0 and entries[i][0] <= address < entries[i][1]:
			hit.add(entries[i][0])
	return sorted(hit)


def surviving(original, rewrite, listing):
	"""VEX instructions the rewrite left as they were, by address.

	**A surviving site runs under qemu and would not run on the target.**
	qemu has AVX, so it executes the instruction on real ymm registers
	whose upper halves the rewrite keeps elsewhere -- a difference that is
	the harness mixing two representations, not a lowering. Measured:
	`0x142347010` differed only through `0x14374e4f8`, a declined 256-bit
	compare on sin's large-argument path. On a CPU without AVX it is an
	illegal instruction, so that is what the harness makes it -- except
	where the bytes are a switch table that happens to decode as VEX, five
	rows here, which a `ud2` would corrupt.
	"""
	out = []
	for address, encoding, mnemonic, _operands in inplace.parse_listing(
			listing):
		if inplace.decode_vex(encoding) is None or mnemonic == "(bad)" \
				or detour.in_switch_data(address, address + len(encoding)):
			continue
		a = detour.rva_to_offset(original, address - BASE)
		b = detour.rva_to_offset(rewrite, address - BASE)
		if a is None or b is None:
			continue
		if rewrite[b:b + len(encoding)] == original[a:a + len(encoding)]:
			out.append((address, b))
	return out


def filled(original, rewrite, listing, out):
	"""A copy of the rewrite with its load-time placeholders filled, and
	every surviving VEX instruction made a `ud2`."""
	data = bytearray(Path(rewrite).read_bytes())
	pe = struct.unpack_from("<I", data, 0x3C)[0]
	count = struct.unpack_from("<H", data, pe + 6)[0]
	optional = struct.unpack_from("<H", data, pe + 20)[0]
	found = None
	for i in range(count):
		at = pe + 24 + optional + 40 * i
		if data[at:at + 8].rstrip(b"\0") != b".avxsse":
			continue
		size, offset = struct.unpack_from("<II", data, at + 16)
		blob = bytes(data[offset:offset + size])
		index = detour.index_placeholders(blob)
		low, high = detour.teb_placeholders(blob)
		for spot in index:
			struct.pack_into("<I", data, offset + spot, 0)
		for spot in low:
			struct.pack_into("<I", data, offset + spot, 0x1480 + 5 * 8)
		for spot in high:
			struct.pack_into("<I", data, offset + spot, 0x1480 + 6 * 8)
		found = (len(index), len(low), len(high))
	if found is None:
		raise SystemExit("function_oracle: the rewrite has no .avxsse "
		                 "section, so there is nothing to compare")
	detour.analysis_context(original, listing)	# fills SWITCH_DATA
	left = surviving(Path(original).read_bytes(), bytes(data), listing)
	for _address, offset in left:
		data[offset:offset + 2] = b"\x0f\x0b"
	Path(out).write_bytes(data)
	return found + ({address for address, _offset in left},)


def sweep(image, functions, trials=TRIALS):
	"""Run one image over a list file under qemu; the output lines."""
	done = subprocess.run(QEMU + [str(WORK / "sweep"), str(image),
	                              str(functions), str(trials),
	                              str(LIMIT_MS)],
	                      capture_output=True, text=True,
	                      timeout=SHARD_TIMEOUT)
	return done.stdout.splitlines()


def outcome(line):
	"""(function, trial, verdict, fields) from one output line."""
	fields = line.split()
	verdict = fields[2] if fields[2] in ("fault", "timeout") else "ran"
	return fields[0], fields[1], verdict, fields[2:]


def compare(original, rewrite, left=frozenset()):
	"""Counts, and the functions whose calls differ."""
	counts = {"same": 0, "fault": 0, "timeout": 0, "differ": 0,
	          "surviving": 0}
	differ = set()
	if len(original) != len(rewrite):
		raise SystemExit(f"function_oracle: {len(original)} lines against "
		                 f"{len(rewrite)} -- a side stopped early")
	for a, b in zip(original, rewrite):
		fa, ta, va, xa = outcome(a)
		fb, tb, vb, xb = outcome(b)
		if (fa, ta) != (fb, tb):
			raise SystemExit(f"function_oracle: misaligned at {a!r} / {b!r}")
		if "timeout" in (va, vb):
			counts["timeout"] += 1
		elif vb == "fault" and xb[1] == "4" and int(xb[3], 16) in left:
			# Reached a VEX instruction the rewrite left in place.
			counts["surviving"] += 1
		elif va == vb == "fault":
			counts["fault"] += 1
		elif va == vb == "ran" and xa == xb:
			counts["same"] += 1
		else:
			counts["differ"] += 1
			differ.add(fa)
	return counts, sorted(differ)


def main():
	global WORK
	if len(sys.argv) < 4:
		print("usage: function_oracle.py <original> <rewrite> <listing> "
		      "[build directory]", file=sys.stderr)
		return 2
	original, rewrite, listing = sys.argv[1:4]
	if len(sys.argv) > 4:
		WORK = Path(sys.argv[4]) / "functionoracle"
	detour.require_qemu(QEMU)
	WORK.mkdir(parents=True, exist_ok=True)
	subprocess.run(["cc", "-O1", "-o", str(WORK / "sweep"), str(SOURCE)],
	               check=True)
	image = WORK / "rewrite-filled.exe"
	index, low, high, left = filled(original, rewrite, listing, image)
	print(f"function_oracle: filled {index:,} TLS index and {low:,}+{high:,} "
	      f"TEB placeholders in a copy of the rewrite, and made its "
	      f"{len(left)} surviving VEX instruction(s) a ud2")
	functions = entry_points(Path(original).read_bytes(), listing)
	if not functions:
		print("function_oracle: no function holds a VEX site, which means "
		      "the listing is wrong", file=sys.stderr)
		return 2
	shards = []
	for k in range(SHARDS):
		path = WORK / f"shard.{k}"
		path.write_text("".join(f"{f:x}\n" for f in functions[k::SHARDS]))
		shards.append(path)
	print(f"== {len(functions):,} functions holding a VEX site, "
	      f"{TRIALS} trials each, original and rewrite both under qemu ==")
	with concurrent.futures.ThreadPoolExecutor(2 * SHARDS) as pool:
		before = [pool.submit(sweep, original, s) for s in shards]
		after = [pool.submit(sweep, image, s) for s in shards]
		totals = {"same": 0, "fault": 0, "timeout": 0, "differ": 0,
		          "surviving": 0}
		suspects, ran = [], set()
		for a, b in zip(before, after):
			a, b = a.result(), b.result()
			counts, differ = compare(a, b, left)
			for key in totals:
				totals[key] += counts[key]
			suspects += differ
			ran.update(outcome(line)[0] for line in a
			           if outcome(line)[2] == "ran")
	print(f"   {totals['same']:,} calls agree, {totals['fault']:,} fault on "
	      f"both sides, {totals['timeout']:,} timed out; "
	      f"{len(ran):,} functions ran to the end at least once")
	print(f"   {totals['surviving']:,} call(s) reached a VEX instruction the "
	      f"rewrite left in place, which the target would fault on")
	# **Alone, before reporting.** The shards share the image's globals,
	# so a difference is confirmed by running its function by itself.
	confirmed = []
	for function in suspects:
		one = WORK / "one"
		one.write_text(function + "\n")
		a, b = sweep(original, one), sweep(image, one)
		_counts, differ = compare(a, b, left)
		if differ:
			confirmed.append(function)
			for x, y in zip(a, b):
				if x != y:
					print(f"   DIFFER {x}\n          {y}", file=sys.stderr)
					break
	if confirmed:
		print(f"function_oracle: FAILED -- {len(confirmed)} function(s) "
		      f"compute something else after the rewrite, run alone under "
		      f"one executor", file=sys.stderr)
		return 1
	print(f"function_oracle: every function that ran computes what the "
	      f"original computes ({len(suspects)} shard difference(s), none "
	      f"alone)")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
