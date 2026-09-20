"""How many TLS slots are gone before this image's callbacks run.

Finding 289 blocked the TEB route on whether `TlsAlloc` returns an index
below 64 when the EXE's TLS callbacks run -- only the 64-entry `TlsSlots`
array at `gs:0x1480` is addressable with no register, and past it a value
sits behind `TlsExpansionSlots`, which is another dereference and another
register. That finding said the question needed a machine with the game.

**It does not.** The rewritten binary runs under Proton, which is wine, and
every slot gone at that moment was taken by the imported DLLs initialising
-- the EXE's own code has not executed yet. So a PE importing the same DLLs
answers it under the runtime that matters, and this builds one.

    python3 tool/tlsslots.py <scratch dir> [image]
    wine <scratch dir>/tlsslots.exe ; echo $?

The exit code is the answer: 53 is wine failing to load the image, 0 means
the callback never ran, 250 means `TlsAlloc` failed, and anything else is
the index plus one.

**Read 53 as a load failure and not as an index.** The first run of this
reported 53 three times and it was `bink2w64.dll` missing, not an answer --
an absent file exits 53 too. Four of Starfield's 66 imports are
game-specific (`bink2w64`, `libxess`, `sl.interposer`, `steam_api64`) and
are dropped here, so the answer is a FLOOR: those four could take slots of
their own.

Measured 2026-09-20 on this machine: **5**, three runs, with 59 DLLs. A
second call returns 6, which is what shows the call reaches `TlsAlloc`
rather than some other export -- consecutive indices are its contract.
Finding 296.
"""

import sys, struct
sys.path.insert(0, "tool")
import detour, pe_build

# Four of the 66 are the game's own and are not on this machine; the rest
# wine provides. Dropping them is what makes the answer a floor.
GAME_DLLS = {"bink2w64.dll", "libxess.dll", "sl.interposer.dll",
             "steam_api64.dll"}


def starfield_imports(path):
	"""[(dll, one exported name)] for every DLL the image imports.

	The names come from the image's own import table, so each is certain
	to resolve -- inventing one would fail the load and read as 53.
	"""
	data = open(path, "rb").read()
	pe = struct.unpack_from("<I", data, 0x3C)[0]
	rva, _size = struct.unpack_from("<II", data, pe + 24 + 112 + 8)

	def at(r):
		for vaddr, vsize, raddr, _rsize in detour.sections_of(data):
			if vaddr <= r < vaddr + vsize:
				return raddr + (r - vaddr)
		return None

	def cstr(off):
		return data[off:data.index(b"\0", off)].decode("ascii", "replace")

	out, off, n = [], at(rva), 0
	while True:
		ilt, _ts, _fc, nm, iat = struct.unpack_from("<IIIII", data,
		                                            off + n * 20)
		if not (ilt or nm or iat):
			break
		dll = cstr(at(nm))
		n += 1
		if dll.lower() in GAME_DLLS:
			continue
		thunk, i = at(ilt or iat), 0
		while True:
			entry = struct.unpack_from("<Q", data, thunk + i * 8)[0]
			if not entry:
				break
			if not (entry >> 63):		# a name, not an ordinal
				out.append((dll, cstr(at(entry & 0x7FFFFFFF) + 2)))
				break
			i += 1
	return out

def main(argv):
	"""Build the probe. `argv` is (scratch dir[, image])."""
	SP = argv[0]
	IMAGE = argv[1] if len(argv) > 1 else "Starfield-unpacked.exe"
	pairs = starfield_imports(IMAGE)
	# TlsAlloc is what the callback calls; put it first in KERNEL32's list.
	by_dll = {}
	for dll, fn in pairs:
		by_dll.setdefault(dll, [])
		if fn not in by_dll[dll]:
			by_dll[dll].append(fn)
	by_dll.setdefault("KERNEL32.dll", [])
	if "TlsAlloc" in by_dll["KERNEL32.dll"]:
		by_dll["KERNEL32.dll"].remove("TlsAlloc")
	by_dll["KERNEL32.dll"].insert(0, "TlsAlloc")
	dlls = list(by_dll.items())

	CALL_MARK = 0x5B5B5B5B

	pe_build.PROGRAMS["tlsslots"] = (0, """
		.text
		.globl _start
	_start:
		movl	seen(%rip), %eax
		ret
	func_end:
	tls_cb:
		cmpl	$1, %edx
		jne	9f
		subq	$40, %rsp
		call	*0x5b5b5b5b(%rip)
		addq	$40, %rsp
		cmpl	$-1, %eax
		jne	1f
		movl	$250, %eax
		jmp	2f
	1:	addl	$1, %eax
	2:	movl	%eax, seen(%rip)
	9:	ret
		.p2align 4
	seen:	.long	0, 0, 0, 0
		.p2align 4
	tls_raw:
		.long	0x55667788, 0x11223344
		.long	0, 0
	tls_raw_end:
	tls_index:
		.long	0
		.long	0
	tls_callbacks:
		.quad	0
		.quad	0
		.p2align 3
	tls_directory:
		.quad	0, 0, 0, 0
		.long	0, 0
	""")
	pe_build.main(["sample", "tlsslots", SP + "/tlsslots.exe"])
	image = bytearray(open(SP + "/tlsslots.exe", "rb").read())

	def layout(base_rva):
		"""(payload, IAT rva of TlsAlloc) for the import section at base_rva."""
		ndesc = (len(dlls) + 1) * 20
		thunks, strings = ndesc, 0
		# reserve: per dll, ILT then IAT, each (n+1) qwords
		off = ndesc
		spots = {}
		for dll, fns in dlls:
			spots[dll] = (off, off + (len(fns) + 1) * 8)
			off += (len(fns) + 1) * 8 * 2
		names_at = off
		blob = bytearray(off)
		names = bytearray()
		def emit(b):
			at = names_at + len(names)
			names.extend(b)
			while len(names) % 2:
				names.append(0)
			return at
		tls_iat = None
		for i, (dll, fns) in enumerate(dlls):
			ilt, iat = spots[dll]
			name_rva = emit(dll.encode() + b"\0")
			struct.pack_into("<IIIII", blob, i * 20,
			                 base_rva + ilt, 0, 0, base_rva + name_rva,
			                 base_rva + iat)
			for j, fn in enumerate(fns):
				hn = emit(struct.pack("<H", 0) + fn.encode() + b"\0")
				struct.pack_into("<Q", blob, ilt + j * 8, base_rva + hn)
				struct.pack_into("<Q", blob, iat + j * 8, base_rva + hn)
				if dll == "KERNEL32.dll" and fn == "TlsAlloc":
					tls_iat = base_rva + iat + j * 8
		return bytes(blob) + bytes(names), tls_iat

	probe, _ = layout(0)
	_img, rva = detour.add_section(bytes(image), b".imports", probe, 0x40000040)
	payload, tls_iat = layout(rva)
	assert len(payload) == len(probe), "layout changed size"
	out, rva2 = detour.add_section(bytes(image), b".imports", payload, 0x40000040)
	assert rva2 == rva, "section moved"
	out = bytearray(out)

	pe = struct.unpack_from("<I", out, 0x3C)[0]
	opt = pe + 24
	struct.pack_into("<II", out, opt + 112 + 1 * 8, rva, (len(dlls) + 1) * 20)

	# patch the call displacement: rip-relative from the end of the instruction
	where = out.find(struct.pack("<I", CALL_MARK))
	assert where > 0 and out.find(struct.pack("<I", CALL_MARK), where + 1) < 0
	for vaddr, vsize, raddr, rsize in detour.sections_of(bytes(out)):
		if raddr <= where < raddr + rsize:
			call_rva = vaddr + (where - raddr) + 4
			break
	struct.pack_into("<i", out, where, tls_iat - call_rva)
	open(SP + "/tlsslots.exe", "wb").write(bytes(out))
	print(f"{len(dlls)} DLLs imported, import table at rva 0x{rva:x}, "
	      f"{len(payload):,} bytes; TlsAlloc IAT at rva 0x{tls_iat:x}")


if __name__ == "__main__":
	sys.exit(main(sys.argv[1:]) or 0)
