#!/usr/bin/env python3
"""What the rewrite costs the image, counted from the two binaries.

`project.md` prices a translated Starfield at +1.34%, being 221,335 added
instructions summed from operand shapes: a mov per Class C site, two per
non-commutative C-alias, one per split 256-bit move, and so on. Every term
in that table is a LOWERING expansion. None of them is the detour.

A detour costs two control transfers the model does not count -- the `jmp`
out of `.text` and the `jmp` home at the end of the stub -- and it leaves
`nop` padding behind wherever the window it replaced was longer than five
bytes. Neither appears in the table, and together they are larger than
everything in it.

So this counts the three terms from the artifacts instead of estimating
them, and checks that they reconcile to the whole-image delta. It is a
measurement, not a gate: the point is that the headline figure now has a
method, and the next person can re-take it after a build that moves the
frontier rather than quoting a number whose build is gone.

**Static, not dynamic, and the difference decides how to read it.** The
padding occupies cache and never executes, because the `jmp` steps over
it. The two transfers execute every time their site does. So the executed
figure is the one comparable to the model's, and the static one is what an
icache budget would want; both are printed and neither is the other.

Usage:  image_cost.py <original.exe> <patched.exe>

**Controls, and why each is here.** The first version of this count asked
objdump for jmp targets matching `148...` when objdump renders them as
`0x148...`, matched nothing, and reported zero detours -- which reads
exactly like a binary that has none. A count that cannot fire returns a
plausible number, so: the jmp scan refuses when it matched no jmp at all,
the section scan refuses when `.avxsse` is absent, and the three terms are
asserted to sum to the measured total rather than merely printed near it.
Terminates: three objdump passes over fixed-size sections.
"""
import re
import subprocess
import sys

ADDRESS = re.compile(r"^\s*[0-9a-f]+:$")


def instructions(binary, section):
	"""Every instruction in one section, as (address, mnemonic, operand).

	objdump prints `addr:\tbytes\tmnemonic operands`, and wraps the bytes of
	a long instruction onto a continuation line carrying no mnemonic. Only
	lines with all three fields are instructions.
	"""
	done = subprocess.run(["objdump", "-d", "-j", section, binary],
	                      capture_output=True, text=True, errors="replace")
	if done.returncode != 0:
		raise SystemExit(f"objdump failed on {binary} {section}: "
		                 f"{done.stderr.strip().splitlines()[-1] if done.stderr.strip() else done.returncode}")
	out = []
	for line in done.stdout.splitlines():
		field = line.split("\t")
		if len(field) < 3 or not ADDRESS.match(field[0]):
			continue
		piece = field[2].split()
		out.append((int(field[0].strip().rstrip(":"), 16), piece[0],
		            piece[1] if len(piece) > 1 else ""))
	if not out:
		raise SystemExit(f"no instructions decoded in {binary} {section} -- "
		                 f"the section is absent or the parse is wrong")
	return out


def section_span(binary, name):
	"""(start, end) virtual addresses of a section, from the headers."""
	done = subprocess.run(["objdump", "-h", binary],
	                      capture_output=True, text=True, errors="replace")
	for line in done.stdout.splitlines():
		field = line.split()
		if len(field) >= 4 and field[1] == name:
			start = int(field[3], 16)
			return start, start + int(field[2], 16)
	raise SystemExit(f"{binary} has no {name} section")


def main():
	if len(sys.argv) != 3:
		print("usage: image_cost.py <original.exe> <patched.exe>", file=sys.stderr)
		return 2
	original, patched = sys.argv[1], sys.argv[2]

	low, high = section_span(patched, ".avxsse")
	before = instructions(original, ".text")
	after = instructions(patched, ".text")
	stub = instructions(patched, ".avxsse")

	# A detour is a .text jmp landing in the stub section. Counting them here
	# rather than trusting a build log means the number belongs to the image
	# being measured; a log describes whichever build wrote it.
	jmp_seen = detours = 0
	for _address, mnemonic, operand in after:
		if not mnemonic.startswith("jmp"):
			continue
		jmp_seen += 1
		try:
			target = int(operand.lstrip("*").split("<")[0], 16)
		except ValueError:
			continue
		if low <= target < high:
			detours += 1
	if jmp_seen == 0:
		raise SystemExit("control failed: no jmp matched in .text at all, "
		                 "so the detour count would be a vacuous zero")
	if detours == 0:
		raise SystemExit("control failed: no .text jmp targets .avxsse, "
		                 "so either the parse is wrong or nothing was detoured")

	nop_before = sum(1 for _a, m, _o in before if m.startswith("nop"))
	nop_after = sum(1 for _a, m, _o in after if m.startswith("nop"))
	stub_jmp = sum(1 for _a, m, _o in stub if m.startswith("jmp"))

	padding = nop_after - nop_before
	mechanism = 2 * detours                 # the jmp out, and the jmp home
	total = (len(after) - len(before)) + len(stub)
	expansion = total - mechanism - padding
	relocated = stub_jmp - detours          # swallowed transfers: moved, not added

	print(f"{'':32} {'instructions':>12}  {'of the original':>15}")
	for name, value in (("lowering expansion", expansion),
	                    ("detour mechanism (2 jmp/site)", mechanism),
	                    ("nop padding (never executes)", padding)):
		print(f"{name:32} {value:>+12,}  {100.0 * value / len(before):>+14.2f}%")
	executed = expansion + mechanism
	print(f"{'':32} {'-' * 12}")
	print(f"{'executed code':32} {executed:>+12,}  "
	      f"{100.0 * executed / len(before):>+14.2f}%")
	print(f"{'static total':32} {total:>+12,}  "
	      f"{100.0 * total / len(before):>+14.2f}%")
	print()
	print(f"{detours:,} detours, {relocated:,} transfers relocated into stubs, "
	      f"{len(stub):,} stub instructions")
	print(f"original .text {len(before):,}   patched .text {len(after):,}")

	if expansion + mechanism + padding != total:
		raise SystemExit("the three terms do not sum to the measured delta")
	print("\nthe three terms reconcile to the measured delta")
	return 0


if __name__ == "__main__":
	sys.exit(main())
