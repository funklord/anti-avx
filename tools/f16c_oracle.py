#!/usr/bin/env python3
"""Check the scalar F16C reference against an implementation nobody here wrote.

`tests/f16c_test.c` proves the vector code and the scalar reference agree
across the entire input space. That is worth having and it is not enough:
both were written by the same hand in the same afternoon, so however
exhaustively they agree they are one witness, not two. If the reference
misunderstands the format, the vector code has been proved to misunderstand
it identically.

CPython's `struct` has supported IEEE 754 binary16 as format `e` since 3.6.
It is a separate implementation, written by other people for another
purpose, and it is the closest thing to an independent oracle available on
a machine that has no F16C to ask.

Reads `f16c_test --dump-h2f` output on stdin, or runs it if given a path.

What this does NOT settle: whether either matches real F16C silicon. That
needs hardware this project does not have, and the NaN payload rules are
where the two would most plausibly differ.
"""

import struct
import subprocess
import sys


def expected_single(half_bits):
	"""The single-precision bits CPython says this half converts to."""
	value = struct.unpack("<e", struct.pack("<H", half_bits))[0]
	return struct.unpack("<I", struct.pack("<f", value))[0]


def is_nan(single_bits):
	return (single_bits & 0x7F800000) == 0x7F800000 and \
		(single_bits & 0x007FFFFF) != 0


def expected_half(single_bits):
	"""The half bits CPython says this single converts to.

	CPython raises OverflowError where the hardware produces an infinity.
	That is a deliberate difference in what the two are for -- a struct
	packer is entitled to refuse a value it cannot represent, while
	vcvtps2ph must follow IEEE 754, which says an overflow under
	round-to-nearest becomes an infinity. Mapping the exception to an
	infinity is applying the standard, not papering over a disagreement.
	"""
	value = struct.unpack("<f", struct.pack("<I", single_bits))[0]
	try:
		return struct.unpack("<H", struct.pack("<e", value))[0]
	except OverflowError:
		return 0x7C00 | ((single_bits >> 16) & 0x8000)


def is_half_nan(half_bits):
	return (half_bits & 0x7C00) == 0x7C00 and (half_bits & 0x03FF) != 0


def check_single_to_half(lines):
	"""Compare the reference's lossy direction against CPython."""
	checked = 0
	nan_differences = 0
	mismatches = []

	for line in lines:
		fields = line.split()
		if len(fields) != 2:
			continue
		single_bits = int(fields[0], 16)
		ours = int(fields[1], 16)
		theirs = expected_half(single_bits)
		checked += 1

		if ours == theirs:
			continue
		if is_half_nan(ours) and is_half_nan(theirs):
			nan_differences += 1
			continue
		mismatches.append((single_bits, theirs, ours))

	print(f"oracle: {checked:,} singles compared against CPython struct 'e'")
	if nan_differences:
		print(f"oracle: {nan_differences} NaN payload difference(s), not "
		      f"counted as failures -- both sides are NaN")
	if mismatches:
		print(f"oracle: {len(mismatches)} MISMATCH(ES):", file=sys.stderr)
		for single_bits, theirs, ours in mismatches[:20]:
			print(f"    single {single_bits:08x}: CPython {theirs:04x}, "
			      f"reference {ours:04x}", file=sys.stderr)
		return 1
	if checked == 0:
		print("oracle: no values compared -- the dump is empty, so this "
		      "pass proves nothing", file=sys.stderr)
		return 1
	print("oracle: the reference agrees with CPython on every single sampled")
	return 0


def main(argv):
	if argv:
		done = subprocess.run([argv[0], "--dump-h2f"],
		                      capture_output=True, text=True, check=True)
		lines = done.stdout.splitlines()
	else:
		lines = sys.stdin.read().splitlines()

	checked = 0
	mismatches = []
	nan_differences = 0

	for line in lines:
		fields = line.split()
		if len(fields) != 2:
			continue
		half_bits = int(fields[0], 16)
		ours = int(fields[1], 16)
		theirs = expected_single(half_bits)
		checked += 1

		if ours == theirs:
			continue
		# A NaN is a NaN whatever the payload. Python's round-trip through a
		# native float does not promise to carry the bits through, so a
		# difference here is not evidence of a bug -- but it is worth
		# counting rather than hiding.
		if is_nan(ours) and is_nan(theirs):
			nan_differences += 1
			continue
		mismatches.append((half_bits, theirs, ours))

	print(f"oracle: {checked:,} halves compared against CPython struct 'e'")
	if nan_differences:
		print(f"oracle: {nan_differences} NaN payload difference(s), not "
		      f"counted as failures -- both sides are NaN")
	if mismatches:
		print(f"oracle: {len(mismatches)} MISMATCH(ES):", file=sys.stderr)
		for half_bits, theirs, ours in mismatches[:20]:
			print(f"    half {half_bits:04x}: CPython {theirs:08x}, "
			      f"reference {ours:08x}", file=sys.stderr)
		return 1
	if checked != 65536:
		print(f"oracle: expected 65,536 values, saw {checked:,} -- the dump "
		      f"is incomplete, so this pass proves nothing", file=sys.stderr)
		return 1
	print("oracle: the reference agrees with CPython on every half")

	if not argv:
		return 0
	done = subprocess.run([argv[0], "--dump-f2h"],
	                      capture_output=True, text=True, check=True)
	return check_single_to_half(done.stdout.splitlines())


if __name__ == "__main__":
	raise SystemExit(main(sys.argv[1:]))
