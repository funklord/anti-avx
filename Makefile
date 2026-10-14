# anti-avx -- ahead-of-time AVX to SSE binary translation.
#
# The only compiled code in the tree is src/f16c.c, the software
# half-precision conversion that stands in for the F16C instructions
# Westmere does not have. Everything else is analysis tooling in Python.
#
# So this file covers the style gate, the git hooks, the F16C tests, and
# `scan` -- the target that reproduces every figure in project.md from the
# binary itself.
#
# `scan` is the only target here that does real work, and it is deliberately
# not part of `all` or `check`: it needs a 102 MB game binary that is not in
# the repository, and it writes about 0.9 GB. Both are reasons to ask for it
# by name rather than have it happen to somebody.

PROJECT    = anti-avx
PYTHON    ?= python3
OBJDUMP   ?= objdump
CC        ?= cc

# -Os because size is what these projects optimise for. The ISA flags are
# load-bearing rather than decoration: the whole point of this code is to
# run where AVX and F16C do not exist, so the compiler is forbidden from
# emitting either. -mno-f16c in particular stops it from "helpfully"
# recognising the conversion idiom and emitting the very instruction the
# code exists to replace.
CFLAGS    ?= -Os -std=c11 -Wall -Wextra -msse4.1 -mno-avx -mno-f16c
CPPFLAGS  += -Isrc -MMD -MP

# Where build products land. Settable so an isolated run can be kept from
# clobbering a plain one. BUILD_DIR is the canonical name across these
# projects; do not introduce a synonym.
BUILD_DIR ?= build

# Bounds for the ddisasm run. The address-space cap is deliberately below
# total RAM so that a run which does not fit is reported as a failed run
# rather than absorbed by the machine.
DDISASM_LIMIT_GB ?= 28
DDISASM_TIMEOUT  ?= 3600

# Iterations per timed run in `make bench`.
BENCH_ITERATIONS ?= 100000

# The translation target. Not in the repository -- see .gitignore. This is
# the Steamless-unpacked form, which is what every measurement in project.md
# was taken from; the shipped binary has a .bind DRM section that disassembles
# as ~85,000 phantom instructions.
TARGET    ?= Starfield-unpacked.exe

# The full .text listing and the report derived from it. Named here because
# `clean` removes files it names rather than sweeping a directory.
LISTING    = $(BUILD_DIR)/text.asm
REPORT     = $(BUILD_DIR)/report.txt

# The software F16C conversions. This is the only compiled code in the tree.
OBJS       = $(BUILD_DIR)/f16c.o $(BUILD_DIR)/fmaddsub.o \
             $(BUILD_DIR)/permil.o $(BUILD_DIR)/permd.o
TEST_OBJS  = $(BUILD_DIR)/f16c_test.o $(BUILD_DIR)/fmaddsub_test.o \
             $(BUILD_DIR)/permil_test.o $(BUILD_DIR)/permd_test.o \
             $(BUILD_DIR)/lowering_test.o
TEST_BINS  = $(BUILD_DIR)/f16c_test $(BUILD_DIR)/fmaddsub_test \
             $(BUILD_DIR)/permil_test $(BUILD_DIR)/permd_test \
             $(BUILD_DIR)/lowering_test
# Generated from the lowering rules themselves, so the cases cannot drift
# away from what the rewriter actually emits.
GENERATED  = $(BUILD_DIR)/lowering_cases.s $(BUILD_DIR)/lowering_cases.inc
TEST_BIN   = $(BUILD_DIR)/f16c_test
DEPS       = $(OBJS:.o=.d) $(TEST_OBJS:.o=.d)

.PHONY: all test check style style-source style-docs verify check-verify \
        check-f16c \
        check-f16c-exhaustive check-f16c-oracle check-fmaddsub check-permil \
        check-isa \
        scan report \
        coverage disassemble patch patch-plan patch-verify detour bench outside \
        placement check-aliasing check-lowering scratch-check check-pe \
        census spans gprs shapes cost-bench cost status probe why check-shadow check-shadow-pe check-run-borrow check-spill check-tls check-unwind check-vex check-liveness \
        check-lanes check-span check-shapes \
        detour-plan detour-verify hooks clean \
        distclean help

all: check

# `check` is what must pass before committing. There is no test suite yet,
# so it is the gate alone -- and it deliberately does not depend on `scan`,
# which needs a binary a fresh clone does not have.
# `make test` runs the compiled test binaries, as the name means in the
# eleven siblings that answer it. Until now this Makefile had no such
# rule, and with a directory named test/ in the tree that was not an
# error but a silent success: make treated the target as satisfied and
# exited 0 having run nothing, so the cross-project habit reported a
# pass here without building a binary. check remains the wider gate --
# style, the lowering proof and the ISA scan on top of these.
test: check-aliasing check-lowering check-f16c check-fmaddsub \
      check-permil check-permd

check: style verify check-verify check-aliasing check-lowering check-isa \
       check-f16c check-f16c-oracle check-fmaddsub check-permil check-permd check-span

style: style-source style-docs

# Assemble every lowering rule and prove no VEX prefix survives. Needs no
# game binary, so it belongs in `check` where `scan` and `coverage` do not.
verify:
	$(PYTHON) tool/lower.py verify

# Prove no lowering reads a register it has already overwritten. Needs no
# game binary either: it assembles its own operand shapes, lowers them, and
# disassembles the result back to simulate the register moves.
check-aliasing:
	$(PYTHON) tool/detour.py selftest

# Execute the lowerings and check what they computed, against GCC compiling
# the equivalent SSE intrinsic. The one test that runs translated code: this
# machine has no AVX, so it can execute the output but never the input.
check-lowering: $(BUILD_DIR)/lowering_test
	$(BUILD_DIR)/lowering_test

# Execute the ORIGINAL VEX instruction and the lowering that replaces it, and
# compare all sixteen registers. qemu-x86_64 translates rather than
# dispatches, so it runs VEX on a host that has none -- which is the AVX
# oracle this project has been without since milestone 1. The case list is
# tool/lowering_cases.py's, read in one pass, so the originals and the
# lowerings cannot drift apart.
#
# NOT part of `check`: it needs qemu-user, and it says SKIPPED rather than
# passing where that is absent.
#
# Termination: two static binaries, each a counted loop over the case table,
# both under a timeout inside the harness.
check-vex: | $(BUILD_DIR)
	$(PYTHON) tool/vex_oracle.py $(BUILD_DIR)

# Settle LANE_WISE by executing it. Each mnemonic's 256-bit form runs under
# qemu and its two 128-bit halves run natively, and they must agree bit for
# bit -- with two sabotaged splits per mnemonic that must be rejected, and a
# control proving qemu is not itself a blind lane-splitter. It fails if
# detour.LANE_WISE gains a mnemonic this harness does not execute, so the
# list and the evidence cannot drift apart.
#
# NOT part of `check`: it needs qemu-user, and says SKIPPED where that is
# absent.
#
# Termination: four static binaries, each a counted loop over the case
# table, all under a timeout inside the harness.
check-lanes: | $(BUILD_DIR)
	$(PYTHON) tool/lane_oracle.py $(BUILD_DIR)

# Does a lowered 256-bit SPAN compute what the 256-bit original computes?
# The original runs under qemu because this host has no AVX; the span runs
# natively, because the span is pure SSE and that is the whole point.
check-span: | $(BUILD_DIR)
	$(PYTHON) tool/span_oracle.py $(BUILD_DIR)

# **A run that borrows a helper must not borrow one its passengers name.**
# `runborrow` holds every volatile xmm live across a load and a store six
# instructions apart, which is the shape that makes `assign_helpers` borrow.
# Before Finding 252 the borrow excluded only the load's and stores' own
# operands, so a passenger overwrote the half in flight and the stub stored
# the passenger's value as the upper half.
#
# **29 is the pass and 10 is the failure**, which is worth stating because
# 29 is not a lowering. With the fix the run declines the site and the VEX
# survives, so the program dies on an illegal instruction -- an honest
# refusal. Without it the program RUNS and computes 10 where the same
# arithmetic in legacy SSE gives 77. A gate that could only tell "worked"
# from "crashed" would have called the broken one healthier.
check-run-borrow: | $(BUILD_DIR)
	@command -v wine >/dev/null 2>&1 || \
		{ echo "check-run-borrow: wine is not installed"; exit 1; }
	@set -e; \
	$(PYTHON) tool/pe_build.py sample runborrow \
		$(BUILD_DIR)/pe-runborrow.exe >/dev/null; \
	objdump -d -j .text $(BUILD_DIR)/pe-runborrow.exe \
		> $(BUILD_DIR)/pe-runborrow.asm; \
	mkdir -p $(PE_PREFIX); \
	$(PYTHON) tool/detour.py apply $(BUILD_DIR)/pe-runborrow.exe \
		$(BUILD_DIR)/pe-runborrow.asm \
		$(BUILD_DIR)/sse-runborrow.exe > /dev/null; \
	got=0; \
	WINEPREFIX=$(PE_PREFIX) WINEDEBUG=-all WINEDLLOVERRIDES=winedbg.exe=d \
		wine $(BUILD_DIR)/sse-runborrow.exe > /dev/null 2>&1 || got=$$?; \
	if [ "$$got" = "10" ]; then \
		echo "check-run-borrow: returned 10 -- the run borrowed a register"; \
		echo "                  one of its passengers names, and the stub"; \
		echo "                  stored the passenger's value as the upper"; \
		echo "                  half. That is Finding 252, reintroduced."; \
		exit 1; \
	fi; \
	if [ "$$got" != "29" ]; then \
		echo "check-run-borrow: returned $$got, want 29"; exit 1; \
	fi; \
	echo "check-run-borrow: the run declines rather than borrowing a"; \
	echo "                  register its passengers name -- 29, an honest"; \
	echo "                  refusal, where the defect computed 10"

# The uniform shadow representation: every ymm has a PERMANENT slot, so a
# 256-bit operation needs no proof of where its operands came from. This
# asks whether the arithmetic is right under it, which span_oracle cannot
# reach -- a span addresses the high half of a MEMORY operand, and the
# largest refused bucket on the frontier is arithmetic whose source is a
# register. Needs qemu for the 256-bit side, so it says SKIPPED rather than
# passing where that is absent. Finding 243.
check-shadow: | $(BUILD_DIR)
	$(PYTHON) tool/shadow_oracle.py $(BUILD_DIR)

# The representation end to end, on `crossregion`: a ymm defined BEFORE a
# branch target and read in the region after it, with the answer in the
# upper half, so 77 is reachable only if the slot was maintained across the
# boundary. Run both ways, because a control that passes either way is not
# one.
#
# **It was aimed at `laneregadd` and that did not discriminate.** Two
# reasons, and each is worth more than the target was. Its 77 comes from
# the CALLER'S SHADOW, not from permanent slots -- measured, the span uses
# slot 0 and slot 1, which are its own bookkeeping and never a register's
# permanent one. And the flag appeared to matter only because
# `--shadow-regs=` and `--shadow=` shared a variable, so asking for
# permanent slots switched the caller's shadow on as a side effect: with
# the collision fixed, `laneregadd` returns 77 with the flag and without
# it. A control written in the same commit as the bug it was calibrated
# against cannot see it. Finding 246.
#
# **The zero fill is a build argument.** A permanent slot lives in the
# per-thread block, so the fixture needs a TLS directory asking for
# `tls_block_slots() * 16` = 320 bytes; the stock 32 holds two slots and
# the lowering refuses every site. Needs wine.
check-shadow-pe:
	@command -v wine >/dev/null 2>&1 || \
		{ echo "check-shadow-pe: wine is not installed"; exit 1; }
	@set -e; \
	mkdir -p $(PE_PREFIX); \
	for name in crossregion laneswap lanemem bcast permmem permil onegpr nogpr noxmm regmove nonvol unwindsave \
	            backward backtarget commute laneconv \
	            fmamem fma231 fma132 fmareg fmareg213 fmareg132 \
	            fmasub fmaas fmasa fnmreg fnmmem blendv blendv0 blendvx0 \
	            cmpconst cmpreg maskgpr pshufb1 fnm1 staleslot partslot \
	            unaligned256; do \
		$(PYTHON) tool/pe_build.py sample $$name \
			$(BUILD_DIR)/pe-$$name-320.exe 320 >/dev/null; \
		objdump -d -j .text $(BUILD_DIR)/pe-$$name-320.exe \
			> $(BUILD_DIR)/pe-$$name-320.asm; \
		for mode in off all; do \
			$(PYTHON) tool/detour.py --shadow-regs=$$mode apply \
				$(BUILD_DIR)/pe-$$name-320.exe \
				$(BUILD_DIR)/pe-$$name-320.asm \
				$(BUILD_DIR)/sse-$$name-$$mode.exe > /dev/null; \
			got=0; \
			WINEPREFIX=$(PE_PREFIX) WINEDEBUG=-all \
				WINEDLLOVERRIDES=winedbg.exe=d \
				wine $(BUILD_DIR)/sse-$$name-$$mode.exe \
				> /dev/null 2>&1 || got=$$?; \
			echo "check-shadow-pe: $$name --shadow-regs=$$mode -> $$got"; \
			if [ "$$mode" = "off" ]; then \
				if [ "$$got" = "77" ]; then \
					echo "check-shadow-pe: $$name answers 77 without"; \
					echo "                 permanent slots, so it never"; \
					echo "                 needed them and proves nothing"; \
					exit 1; \
				fi; \
			elif [ "$$got" != "77" ]; then \
				echo "check-shadow-pe: $$name wanted 77 with slots"; \
				exit 1; \
			fi; \
		done; \
	done; \
	echo "check-shadow-pe: fmamem, fma231, fma132 -- a 256-bit FMA whose"; \
	echo "                 second source is memory, one per ordering. 205"; \
	echo "                 of the 208 sites the frontier declined for"; \
	echo "                 having no SSE form look exactly like this and"; \
	echo "                 none had a fixture. Each reads back lane 0 from"; \
	echo "                 the low half and lanes 4 and 7 from the upper,"; \
	echo "                 so a lowering that narrows the low half and"; \
	echo "                 drops the high one misses -- which is the way"; \
	echo "                 this shape is likeliest to break"; \
	echo "check-shadow-pe: crossregion -- a ymm defined outside the region"; \
	echo "                 reads 77 from its permanent slot, 29 without"; \
	echo "check-shadow-pe: laneswap -- vextractf128 and vinsertf128 routed"; \
	echo "                 to slot moves, and the extract zeroed the slot"; \
	echo "                 its VEX.128 write implies"; \
	echo "check-shadow-pe: lanemem -- vperm2f128 on both its selectors, and"; \
	echo "                 the memory operands of extract and insert. Its"; \
	echo "                 77 is 60 + 7 + 10, one term per mechanism, and"; \
	echo "                 sabotaging each gives 24, 70 and 67"; \
	echo "check-shadow-pe: bcast -- all four broadcast forms, each read from"; \
	echo "                 the LAST lane of an upper half, so a missing"; \
	echo "                 splat and a missing slot both score zero"; \
	echo "check-shadow-pe: permmem -- cross-lane 64-bit permutes from memory"; \
	echo "                 through movsd and movhpd, read asymmetrically so"; \
	echo "                 an inverted selector cannot sum to 77 anyway"; \
	echo "check-shadow-pe: permil -- the variable-control in-lane permute,"; \
	echo "                 lower_permilps called once per 128-bit half, with"; \
	echo "                 control values carrying rubbish above bit 1 so a"; \
	echo "                 missing mask cannot pass"; \
	echo "check-shadow-pe: onegpr -- six of the seven volatile GPRs live"; \
	echo "                 across the site, so the block pointer has ONE"; \
	echo "                 dead register and the index borrows a live one,"; \
	echo "                 stashed in an xmm. Cutting the restore gives 37"; \
	echo "check-shadow-pe: nogpr -- all SEVEN live, so nothing is dead and"; \
	echo "                 both borrows are saved in the callee home space,"; \
	echo "                 the block for the whole stub. Cutting the block"; \
	echo "                 save gives 37, its restore 245, the index 57"; \
	echo "check-shadow-pe: noxmm -- every volatile xmm live, so the load's"; \
	echo "                 upper half moves through a GPR in two 8-byte"; \
	echo "                 halves and a vextractf128 reads it back. Losing"; \
	echo "                 the mover gives 29, mis-addressing it 12"; \
	echo "check-shadow-pe: regmove -- a 256-bit register-to-register move is"; \
	echo "                 a move: one slot copied to another. A second load"; \
	echo "                 sits between, because a load leaves its upper half"; \
	echo "                 IN the helper and the test was right by accident"; \
	echo "check-shadow-pe: nonvol -- an arithmetic site with every volatile"; \
	echo "                 xmm live, served by borrowing xmm6, which this"; \
	echo "                 function declares with UWOP_SAVE_XMM128. It holds"; \
	echo "                 3.0 across the site, so a lost save gives 74"; \
	$(PYTHON) tool/pe_build.py sample nonvolbad \
		$(BUILD_DIR)/pe-nonvolbad.exe 320 >/dev/null; \
	objdump -d -j .text $(BUILD_DIR)/pe-nonvolbad.exe \
		> $(BUILD_DIR)/pe-nonvolbad.asm; \
	$(PYTHON) tool/detour.py --shadow-regs=all apply \
		$(BUILD_DIR)/pe-nonvolbad.exe $(BUILD_DIR)/pe-nonvolbad.asm \
		$(BUILD_DIR)/sse-nonvolbad.exe > /dev/null; \
	got=0; \
	WINEPREFIX=$(PE_PREFIX) WINEDEBUG=-all WINEDLLOVERRIDES=winedbg.exe=d \
		wine $(BUILD_DIR)/sse-nonvolbad.exe > /dev/null 2>&1 || got=$$?; \
	if [ "$$got" != "77" ]; then \
		echo "check-shadow-pe: nonvolbad returned $$got, want 77 -- the"; \
		echo "                 volatile borrow serves this site now, and 77"; \
		echo "                 needs every live volatile xmm handed back"; \
		exit 1; \
	fi; \
	echo "check-shadow-pe: nonvolbad -- the same .text with the unwind codes"; \
	echo "                 removed used to be REFUSED at 29. Finding 262"; \
	echo "                 gave the borrow a second source -- a live"; \
	echo "                 VOLATILE xmm stashed in one of the block's own"; \
	echo "                 scratch slots, which needs no unwind promise"; \
	echo "                 because nothing preserves xmm0-5 across a call."; \
	echo "                 So its 77 is now a POSITIVE test of that path:"; \
	echo "                 xmm0-5 and xmm6 are all live across the site and"; \
	echo "                 read after it, so a borrow that lost one could"; \
	echo "                 not reach 77. The property it used to guard is"; \
	echo "                 now structural rather than tested -- the saved"; \
	echo "                 set is the only source of a NON-volatile borrow"; \
	echo "                 and the new path draws only from VOLATILE_XMM,"; \
	echo "                 so no fixture can make either borrow the wrong"; \
	echo "                 register. The mode-True refusal that Finding 262"; \
	echo "                 adds is NOT covered by a fixture: see the entry"; \
	echo "                 for what was tried and why it failed"; \
	echo "check-shadow-pe: unwindsave -- the function's OWN save slot still"; \
	echo "                 holds the caller's value after the stub ran, so"; \
	echo "                 the bytes an unwind would restore from survive."; \
	echo "                 Writing the borrow onto that slot gives 70"
	@echo "check-shadow-pe: backward -- a site whose forward walk ends"
	@echo "                 under five bytes, lowered by a window that"
	@echo "                 starts on the instruction BEFORE it and"
	@echo "                 re-emits it; carrying it without re-emitting"
	@echo "                 gives 7 rather than 77"
	@echo "check-shadow-pe: laneconv -- a per-lane conversion, which splits"
	@echo "                 by half because every element is decided by"
	@echo "                 itself: the upper four go through the slot as"
	@echo "                 the lower four go through the register. The"
	@echo "                 round trip int -> float -> int reads back as 70"
	@echo "                 plus 7, so a stale or zeroed upper half gives 70"
	@echo "check-shadow-pe: commute -- op %ymmD,%ymmS,%ymmD, where the"
	@echo "                 destination is the OTHER source. Dropping the"
	@echo "                 VEX prefix throws vvvv away and doubles"
	@echo "                 instead of adding, so the operands have to be"
	@echo "                 exchanged; 30+40 and 3+4 give 77 where the"
	@echo "                 doubling gives 66, which is what makes the"
	@echo "                 answer separate the two emissions"
	@echo "check-shadow-pe: backtarget -- the same shape with the site"
	@echo "                 named by a never-taken jne, so widening back"
	@echo "                 would bury a branch target. The guard refuses"
	@echo "                 and the site keeps its VEX form on dead code;"
	@echo "                 check-verify runs the same tree sabotaged and"
	@echo "                 watches verify reject the buried target"

# -- the software F16C conversions -------------------------------------------

# Tests are built by the test target and by nothing else, so a plain build
# stays fast. The cost of that choice is paid by the dependency rules below
# being correct: -MMD -MP writes a .d beside every object, and every one of
# them is read back, TEST OBJECTS INCLUDED. A test object whose .d is never
# included does not rebuild when f16c.h changes, and the result is a test
# binary built against one layout linking against another.
check-f16c: $(TEST_BIN)
	$(TEST_BIN)

# All 2^32 singles rather than the default spread. A couple of minutes, and
# a counted loop, so it terminates on its own; it is a separate target
# because `make check` should not take minutes.
check-f16c-exhaustive: $(TEST_BIN)
	$(TEST_BIN) exhaustive

# The reference checked against CPython's own binary16 support, which is the
# only implementation on this machine that nobody here wrote. Exhaustive
# over all 65,536 halves.
check-f16c-oracle: $(TEST_BIN)
	$(PYTHON) tool/f16c_oracle.py $(TEST_BIN)

# The alternating-lane FMA lowerings. Separate from check-f16c because they
# are a different rule with a different failure mode: F16C is an algorithm
# that can be subtly inexact, while these are exact and can be subtly
# BACKWARDS -- wrong on half the lanes, right on the other half.
check-fmaddsub: $(BUILD_DIR)/fmaddsub_test
	$(BUILD_DIR)/fmaddsub_test

# The vpermilps variable-control helper. Its permutation space is small
# enough to cover completely, so this is exhaustive rather than sampled.
check-permil: $(BUILD_DIR)/permil_test
	$(BUILD_DIR)/permil_test

# The vpermd cross-lane helper. Exhaustive over all 8^8 index combinations,
# which takes a few seconds -- worth it, since sampling a permutation space
# is how the awkward cases get missed.
check-permd: $(BUILD_DIR)/permd_test
	$(BUILD_DIR)/permd_test

# The proof that matters for the translator: the code that replaces F16C
# must not itself contain AVX or F16C. Checked by disassembling what was
# actually built rather than by trusting the compiler flags -- a flag that
# silently stopped applying would otherwise look exactly like a clean pass.
#
# **It counts what it inspected, and the disassembly is a file rather than
# a pipe.** The first version counted only OFFENDING lines and had no
# floor, so zero instructions read and a clean object printed the same
# sentence and the same exit code -- `objdump -d /nonexistent.o | awk ...`
# reported "no VEX, no EVEX, no F16C" and exited 0, because make's shell
# has no `pipefail` and the status was awk's alone. That is the defect
# this gate exists to catch, in the gate itself: a flag that stopped
# applying and a gate that stopped looking are indistinguishable from a
# pass. Four other checks here already refuse an empty input --
# `f16c_oracle` wants exactly 65,536, `shape_oracle` refuses no rows,
# `style_gate` refuses a collapsed file list -- and this one did not.
check-isa: $(OBJS)
	@$(OBJDUMP) -d $(OBJS) > $(BUILD_DIR)/isa-disasm.txt
	@awk -F'\t' -v want=$(words $(OBJS)) '/file format/ { files++ } \
		NF>=3 { \
		seen++; \
		n = split($$2, b, " "); \
		if (b[1] == "c4" || b[1] == "c5" || b[1] == "62") bad++ } \
		/vcvtph2ps|vcvtps2ph/ { f16++ } \
		END { \
		  if (bad) { printf "check-isa: FAILED -- %d VEX/EVEX encodings\n", bad > "/dev/stderr"; exit 1 } \
		  if (f16) { printf "check-isa: FAILED -- %d F16C instructions\n", f16 > "/dev/stderr"; exit 1 } \
		  if (seen < 1) { print "check-isa: FAILED -- nothing disassembled, so nothing was checked" > "/dev/stderr"; exit 1 } \
		  if (files != want) { printf "check-isa: FAILED -- disassembled %d of %d objects, so some were not checked\n", files, want > "/dev/stderr"; exit 1 } \
		  printf "check-isa: no VEX, no EVEX, no F16C in %d instructions across %d objects\n", seen, files }' \
		$(BUILD_DIR)/isa-disasm.txt

$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/%.o: test/%.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/f16c_test: $(BUILD_DIR)/f16c_test.o $(BUILD_DIR)/f16c.o
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/fmaddsub_test: $(BUILD_DIR)/fmaddsub_test.o $(BUILD_DIR)/fmaddsub.o
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/permil_test: $(BUILD_DIR)/permil_test.o $(BUILD_DIR)/permil.o
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/permd_test: $(BUILD_DIR)/permd_test.o $(BUILD_DIR)/permd.o
	$(CC) $(CFLAGS) -o $@ $^

# Both halves come out of one generator run, so one recipe produces both and
# the .inc names the .s as its sibling rather than repeating the command.
$(BUILD_DIR)/lowering_cases.s: tool/lowering_cases.py tool/detour.py \
                               tool/lower.py tool/patch.py | $(BUILD_DIR)
	$(PYTHON) tool/lowering_cases.py emit $(BUILD_DIR)/lowering_cases.s \
	          $(BUILD_DIR)/lowering_cases.inc

$(BUILD_DIR)/lowering_cases.inc: $(BUILD_DIR)/lowering_cases.s
	@test -f $@

# -I$(BUILD_DIR) so the generated table is found; the .inc is an order-only
# prerequisite of nothing, so it is named here to force generation first.
$(BUILD_DIR)/lowering_test.o: test/lowering_test.c \
                              $(BUILD_DIR)/lowering_cases.inc | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) -I$(BUILD_DIR) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/lowering_test: $(BUILD_DIR)/lowering_test.o \
                            $(BUILD_DIR)/lowering_cases.s
	$(CC) $(CFLAGS) -o $@ $^

# Named explicitly, never bare. A bare `.SECONDARY:` applies to every target
# any pattern rule matches -- including the object pattern above -- and Make
# then declines to rebuild a *missing* secondary whose dependant already
# exists, which is how adding a source file leaves a stale binary and a
# `make` that reports nothing to do.
.SECONDARY: $(TEST_OBJS)

style-source:
	$(PYTHON) tool/style_gate.py

# Holds project.md to the tree: no statement made twice, no backticked path
# naming a file that does not exist.
style-docs:
	$(PYTHON) tool/style_gate.py docs

# -- measurement -------------------------------------------------------------

# Reproduce the figures in project.md. Two steps, kept separate because the
# listing takes ~30 s and the analysis ~75 s, and iterating on the analysis
# should not re-disassemble 61 MB of .text every time.
scan: $(REPORT)
	@echo "scan: $(REPORT)"

report: scan

$(LISTING): $(TARGET) | $(BUILD_DIR)
	@echo "  objdump  $< -> $@  (~0.9 GB, ~30 s)"
	$(OBJDUMP) -d -j .text $< > $@

# Without `-j .text` objdump also disassembles the 234 KB .bind DRM section,
# which is flagged CODE and decodes as ~85,000 phantom instructions from
# encrypted data. That contamination is what produced the one-off `vfmaddcsh`
# and `vpmaskmovq` in the first scan, and chasing them is how the DRM wrapper
# was found. Keep the flag.

$(REPORT): $(LISTING) tool/vex_scan.py | $(BUILD_DIR)
	@echo "  vex_scan $< -> $@  (~75 s, ~1.1 GB RSS)"
	$(PYTHON) tool/vex_scan.py $< > $@

# Which VEX sites in the binary have a lowering rule, and which do not. The
# gap list is the point: it is the set of instructions a translator would
# have to refuse.
#
# This EXITS NON-ZERO while any gap remains, and that is deliberate -- it is
# a gate, not a report. Twelve F16C sites are uncovered today (Finding 10),
# so it fails today. Do not silence it with a `-` or a `|| true`: the whole
# value of the target is that it goes quiet only when the binary can
# actually be translated.
coverage: $(LISTING)
	$(PYTHON) tool/lower.py coverage $<

$(BUILD_DIR):
	mkdir -p $@

$(TARGET):
	@echo "$(TARGET): not present." >&2
	@echo "  It is a copyrighted game binary and is not in the repository." >&2
	@echo "  Unpack it with Steamless first -- see project.md, hard part 4." >&2
	@exit 1

# -- disassembly (milestone 3) -----------------------------------------------

# Ddisasm is not packaged for Debian and is not in this tree. Unpack
# GrammaTech's focal builds into a scratch prefix and point DDISASM_PREFIX at
# it; tool/run_ddisasm.sh does the rest. See project.md, Finding 12, for
# what it needs and what happened.
#
# This target is NOT part of `check`, and not only because it needs the game
# binary: on the real target it consumes tens of gigabytes and fails. The
# bounds in run_ddisasm.sh are what keep that from taking the machine with
# it, so do not invoke ddisasm directly to "save time".
disassemble: | $(BUILD_DIR)
	@test -n "$$DDISASM_PREFIX" || { \
		echo "disassemble: set DDISASM_PREFIX to an unpacked ddisasm tree" >&2; \
		exit 1; }
	tool/run_ddisasm.sh $(TARGET) $(BUILD_DIR)/$(basename $(notdir $(TARGET))).gtirb \
		$(DDISASM_LIMIT_GB) $(DDISASM_TIMEOUT)

# -- in-place rewriting (milestone 4) ----------------------------------------

PATCHED  = $(BUILD_DIR)/$(basename $(notdir $(TARGET)))-sse.exe
DETOURED = $(BUILD_DIR)/$(basename $(notdir $(TARGET)))-detour.exe

# What can be rewritten without moving anything, and what cannot.
patch-plan: $(LISTING)
	$(PYTHON) tool/patch.py plan $(TARGET) $<

# Rewrite classes A, B and Z in place. No relocation, no reassembly: the
# output is the same size as the input and byte-identical outside the
# instructions it rewrote.
$(PATCHED): $(TARGET) $(LISTING) tool/patch.py | $(BUILD_DIR)
	$(PYTHON) tool/patch.py apply $(TARGET) $(LISTING) $@

patch: $(PATCHED)

# The invariants. `verify` disassembles both binaries and checks that every
# address which began an instruction still does -- the check that caught
# both bugs this tool has had, and the one worth running after any change
# to it.
patch-verify: $(PATCHED)
	$(PYTHON) tool/patch.py verify $(TARGET) $(PATCHED)

# Class C, which cannot be rewritten in place: a stub section is appended and
# each site becomes a jump into it. Only sites already five bytes or longer
# are touched -- see project.md, Finding 15, for why the shorter ones are
# left alone rather than made to fit.
detour-plan: $(LISTING)
	$(PYTHON) tool/detour.py plan $(TARGET) $<

# `SPILL_FLAGS` is how a run picks a backing store other than the default,
# e.g. `make detour SPILL_FLAGS=--spill=tls`. It has to reach `verify` and
# `census` too: those place stubs themselves, and a mode disagreement
# between them and `apply` is the defect `place_stubs` exists to prevent.
SPILL_FLAGS ?=

$(DETOURED): $(TARGET) $(LISTING) tool/detour.py tool/patch.py | $(BUILD_DIR)
	$(PYTHON) tool/detour.py $(SPILL_FLAGS) apply $(TARGET) $(LISTING) $@

detour: $(DETOURED)

# **The liveness gate, and the sabotage that proves it can speak.** The
# check itself runs on every `verify`, fixtures included. What needs the
# game binary is the CONTROL: no fixture reaches mode True with no xmm to
# stash in, so the only way to make the gate fail is to reintroduce
# Finding 264 and build with the same tool that checks -- which is the
# whole point, because verifying an image against a tool that did not
# build it recomputes a different placement and reports thousands of
# phantom findings. Findings 264 and 266.
#
# Measured: the sabotaged image reports 793 stubs, every one %rax; the
# correct image reports 0 across 201,585 placed windows.
#
# Termination: two bounded invocations over a fixed input, each under a
# timeout. Roughly an hour, so it is not part of `check`.
# Mode "teb" stands the block pointer up with two segment-prefixed absolute
# saves instead of the callee home space, so it needs nothing from the
# caller and moves no `rsp`. It is reached on Starfield where `lent is
# None`, a frame state Finding 268 established cannot be built by hand --
# so the path is FORCED here, on a fixture that would otherwise take mode
# "home", and the emission is asserted before the answer is believed.
#
# **The assertion is the point.** A fixture that answers 77 through mode
# "home" answers 77 either way, so without reading the stub this target
# would be a control for nothing. Finding 280.
check-teb: $(BUILD_DIR)/pe-nogpr-320.exe
	@command -v wine >/dev/null 2>&1 || \
		{ echo "check-teb: wine is not installed"; exit 1; }
	@set -e; \
	mkdir -p $(PE_PREFIX); \
	objdump -d -j .text $(BUILD_DIR)/pe-nogpr-320.exe \
		> $(BUILD_DIR)/pe-nogpr-320.asm; \
	$(PYTHON) tool/detour.py --shadow-regs=all apply \
		$(BUILD_DIR)/pe-nogpr-320.exe $(BUILD_DIR)/pe-nogpr-320.asm \
		$(BUILD_DIR)/sse-nogpr-home.exe > /dev/null; \
	ANTI_AVX_SABOTAGE=teb $(PYTHON) tool/detour.py --shadow-regs=all \
		--teb-scratch=$(TEB_SCRATCH) apply \
		$(BUILD_DIR)/pe-nogpr-320.exe $(BUILD_DIR)/pe-nogpr-320.asm \
		$(BUILD_DIR)/sse-nogpr-teb.exe > /dev/null; \
	if cmp -s $(BUILD_DIR)/sse-nogpr-home.exe \
		  $(BUILD_DIR)/sse-nogpr-teb.exe; then \
		echo "check-teb: forcing the TEB path produced a byte-identical"; \
		echo "           image, so it was never taken"; \
		exit 1; \
	fi; \
	saves=`objdump -d -j .avxsse $(BUILD_DIR)/sse-nogpr-teb.exe | \
	       grep -cE "mov +%r[a-z0-9]+,%gs:0x"`; \
	if [ "$$saves" -lt 2 ]; then \
		echo "check-teb: the stub holds $$saves segment-prefixed save(s),"; \
		echo "           wanting 2 -- so the block did not stand up"; \
		echo "           through the TEB and a 77 below means nothing"; \
		exit 1; \
	fi; \
	if objdump -d -j .avxsse $(BUILD_DIR)/sse-nogpr-teb.exe | \
	   grep -qE "(sub|add) +\$$0x[0-9a-f]+,%rsp"; then \
		echo "check-teb: a stub moves rsp, which is the thing mode"; \
		echo "           \"frame\" was reverted for -- Findings 67, 68, 270"; \
		exit 1; \
	fi; \
	got=0; \
	$(WINE_ENV) timeout 120 wine $(BUILD_DIR)/sse-nogpr-teb.exe \
		> /dev/null 2>&1 || got=$$?; \
	pkill -x wineserver >/dev/null 2>&1 || true; \
	if [ "$$got" != "77" ]; then \
		echo "check-teb: the forced build returned $$got, want 77"; \
		exit 1; \
	fi; \
	echo "check-teb: a block stood up on two segment-prefixed absolute"; \
	echo "           saves, moved no rsp, and the answer survived"

# **`--teb-scratch=auto` end to end, with the control that makes the 77
# mean something.** The good image returns 77; the same build with the
# callback patching nothing returns 5, because a stub then writes eight
# bytes at %gs:0x5b5b5b00 and that address faults. Without the second
# run the first is a green light with no shown ability to be red --
# and the first version of this control forgot to force the TEB path,
# so it built a home-space stub and returned 77 as well. Finding 297.
check-teb-auto: tool/pe_build.py tool/detour.py | $(BUILD_DIR)
	@command -v wine >/dev/null 2>&1 || \
		{ echo "check-teb-auto: wine is not installed"; exit 1; }
	@set -e; \
	mkdir -p $(PE_PREFIX); \
	$(PYTHON) tool/pe_build.py sample tebauto \
		$(BUILD_DIR)/pe-tebauto.exe 320 >/dev/null; \
	objdump -d -j .text $(BUILD_DIR)/pe-tebauto.exe \
		> $(BUILD_DIR)/pe-tebauto.asm; \
	for kind in teb tebconst; do \
		ANTI_AVX_SABOTAGE=$$kind $(PYTHON) tool/detour.py \
			--shadow-regs=all --teb-scratch=auto apply \
			$(BUILD_DIR)/pe-tebauto.exe $(BUILD_DIR)/pe-tebauto.asm \
			$(BUILD_DIR)/sse-tebauto-$$kind.exe > /dev/null; \
	done; \
	for kind in teb tebconst; do \
		n=`objdump -d -j .avxsse $(BUILD_DIR)/sse-tebauto-$$kind.exe | \
		   grep -c "gs:0x5b5b5b" || true`; \
		if [ "$$n" -ne 4 ]; then \
			echo "check-teb-auto: the $$kind build holds $$n TEB"; \
			echo "                scratch reference(s), wanting 4 --"; \
			echo "                so it is not the path under test"; \
			exit 1; \
		fi; \
	done; \
	good=0; \
	$(WINE_ENV) timeout 120 wine $(BUILD_DIR)/sse-tebauto-teb.exe \
		> /dev/null 2>&1 || good=$$?; \
	pkill -x wineserver >/dev/null 2>&1 || true; \
	bad=0; \
	$(WINE_ENV) timeout 120 wine $(BUILD_DIR)/sse-tebauto-tebconst.exe \
		> /dev/null 2>&1 || bad=$$?; \
	pkill -x wineserver >/dev/null 2>&1 || true; \
	if [ "$$good" != "77" ]; then \
		echo "check-teb-auto: the allocated-slot build returned $$good,"; \
		echo "                want 77"; \
		exit 1; \
	fi; \
	if [ "$$bad" = "77" ]; then \
		echo "check-teb-auto: the build whose callback patches nothing"; \
		echo "                also returned 77, so the patching is not"; \
		echo "                what makes the good one work"; \
		exit 1; \
	fi; \
	echo "check-teb-auto: two TlsAlloc slots carried a block pointer's"; \
	echo "                borrow; unpatched, the same stub died with $$bad"

check-liveness: $(LISTING)
	@set -e; \
	echo "check-liveness: building a deliberately broken image"; \
	ANTI_AVX_SABOTAGE=modetrue timeout 3000 $(PYTHON) tool/detour.py \
		--shadow-regs=all apply $(TARGET) $(LISTING) \
		$(BUILD_DIR)/sse-modetrue.exe > $(BUILD_DIR)/modetrue.log 2>&1; \
	if ANTI_AVX_SABOTAGE=modetrue timeout 3600 $(PYTHON) tool/detour.py \
		--shadow-regs=all verify $(TARGET) \
		$(BUILD_DIR)/sse-modetrue.exe $(LISTING) \
		> $(BUILD_DIR)/modetrue-verify.log 2>&1; then \
		echo "check-liveness: the sabotaged image PASSED verify, so the"; \
		echo "                liveness gate cannot see a clobbered"; \
		echo "                register and its silence means nothing"; \
		exit 1; \
	fi; \
	grep -q "clobber a general-purpose register" \
		$(BUILD_DIR)/modetrue-verify.log || \
		{ echo "check-liveness: the sabotaged image failed, but NOT"; \
		  echo "                through the liveness check -- so that"; \
		  echo "                check may never have run"; exit 1; }; \
	echo "check-liveness: the gate refuses a stub that clobbers a register"; \
	echo "                its site was still using, and passes the same"; \
	echo "                tree built correctly"


detour-verify: $(DETOURED) $(LISTING)
	$(PYTHON) tool/detour.py $(SPILL_FLAGS) verify $(TARGET) $(DETOURED) \
	          $(LISTING)

# Do the documents still say what the rewriter does? Both status lines
# quoted 797,907 / 202,115 / 7,224 while the tool measured 799,458 /
# 202,838 / 5,673 -- stale by 1,551 sites in the most-read line of each,
# and in two places, so correcting one would have left the other. The
# remedy this workspace prescribes for a count quoted often is a target
# comparing it against what the run reports. Finding 241.
#
# The log is cached because the Starfield verify takes half an hour and
# this has to be cheap enough to run after editing a sentence.
$(BUILD_DIR)/detour-verify.log: $(DETOURED) $(LISTING)
	$(PYTHON) tool/detour.py $(SPILL_FLAGS) verify $(TARGET) $(DETOURED) \
	          $(LISTING) > $@ 2>&1 || { cat $@; rm -f $@; exit 1; }

status: $(BUILD_DIR)/detour-verify.log
	$(PYTHON) tool/status_check.py $< project.md README.md

# -- measuring the cost ------------------------------------------------------

# What a detour actually costs on this CPU, which is the translation target.
# NOT part of `check`: it is a timing measurement, so it is slow and its
# result depends on what else the machine is doing.
$(BUILD_DIR)/icache_bench: tool/icache_bench.c | $(BUILD_DIR)
	$(CC) -O2 -std=c11 -Wall -Wextra -o $@ $<

bench: $(BUILD_DIR)/icache_bench
	$(BUILD_DIR)/icache_bench $(BENCH_ITERATIONS)

# Where the detours land: per-function density and, more to the point, how
# many loop bodies contain one. Static structure only -- it cannot say which
# loops execute.
placement: $(LISTING)
	$(PYTHON) tool/placement.py report $(TARGET) $<

# Reconcile what survives against what the rewriter declined, by comparing
# address sets rather than totals.
# Does the loader give us per-thread bytes if we ask for them? `project.md`
# has said static TLS is "proven under wine" since Finding 69 with nothing
# in the tree that proved it. This is that proof, and the sweep is what
# makes it one: a smaller SizeOfZeroFill must NOT return 66.
# Needs wine, and stays out of `check` for that reason. Finding 242.
check-tls:
	@command -v wine >/dev/null 2>&1 || \
		{ echo "check-tls: wine is not installed"; exit 1; }
	@mkdir -p $(PE_PREFIX)
	$(WINE_CANARY)
	@$(WINE_ENV) timeout 300 wine wineboot -i >/dev/null 2>&1 || true
	@set -e; \
	trap 'pkill -x wineserver >/dev/null 2>&1 || true' EXIT; \
	want=`$(PYTHON) tool/pe_build.py names | \
	      awk '$$1 == "tlsslot" { print $$2 }'`; \
	for fill in 0 8 16 32; do \
		$(PYTHON) tool/pe_build.py sample tlsslot \
			$(BUILD_DIR)/pe-tlsslot-$$fill.exe $$fill >/dev/null; \
		$(WINE_ENV) timeout 120 wine \
			$(BUILD_DIR)/pe-tlsslot-$$fill.exe >/dev/null 2>&1 \
			&& got=0 || got=$$?; \
		echo "check-tls: SizeOfZeroFill=$$fill returned $$got"; \
		if [ "$$fill" = "32" ]; then \
			if [ "$$got" != "$$want" ]; then \
				echo "check-tls: the loader did not give us 32 zeroed"; \
				echo "           per-thread bytes -- want $$want"; exit 1; \
			fi; \
		elif [ "$$got" = "$$want" ]; then \
			echo "check-tls: SizeOfZeroFill=$$fill answered $$want too,"; \
			echo "           so the test does not measure the field"; \
			exit 1; \
		fi; \
	done; \
	echo "check-tls: the loader allocates and zeroes exactly what is asked"

# How many volatile general-purpose registers are dead across the borrow
# bracket at each site that could find no home space. This is what static
# TLS costs, and it needs TWO at once. A measurement, not a gate.
#
# It needs no rewritten binary: the question is about the ORIGINAL text,
# and `collect` is what says which sites were starved.
gprs: $(LISTING)
	$(PYTHON) tool/detour.py gprs $(TARGET) $(LISTING)

# Warm the cache every measurement here reads through. Parsing the listing
# and building the home-space map is about twelve minutes and the answer
# has not changed since the binary was unpacked; `probe.py` keys the cache
# on the binary, the listing, every tool that could change the answer, and
# the flag values, so an edit misses rather than serving a stale answer.
probe: $(LISTING)
	$(PYTHON) tool/probe.py $(TARGET) $(LISTING)

# Everything known about one address, which is what a fault hands you.
# `make why ADDR=0x1428d1492`
why: $(LISTING)
	@test -n "$(ADDR)" || { echo "why: pass ADDR=0x..."; exit 1; }
	$(PYTHON) tool/why.py $(TARGET) $(LISTING) $(ADDR)

# What each lowering costs in TIME, which bytes cannot say: a movups to a
# memory slot and a movaps between registers are the same length and not
# the same cost. A measurement, not a gate.
cost-bench: | $(BUILD_DIR)
	$(PYTHON) tool/cost_bench.py $(BUILD_DIR)

# What the rewrite costs the whole image, counted from the two binaries
# rather than summed from operand shapes. The estimate in project.md prices
# the lowering and not the detour that delivers it; this prices all three
# terms and checks they reconcile. A measurement, not a gate.
cost: $(DETOURED)
	$(PYTHON) tool/image_cost.py $(TARGET) $(DETOURED)

# Every VEX shape the binary contains, and whether the plain lowering path
# takes it. A measurement, not a gate: the point is the shapes nobody wrote
# a case for, which no hand-written list can report on itself.
shapes: $(LISTING)
	$(PYTHON) tool/shape_census.py $(TARGET) $(LISTING)

# Every register-only VEX shape the binary contains, run against its
# lowering. A disagreement is a failure unless ONE executor running both
# sides agrees -- which proves the lowering right and leaves qemu and this
# CPU differing about the instruction itself. Eight comparisons are that,
# all `vrcpps`, `vrsqrtps` and `vdpps`.
#
# Not a prerequisite of `check`, for `check-vex`'s reason: it needs qemu
# and takes minutes, and `check` is the gate a commit waits on.
check-shapes: $(LISTING)
	$(PYTHON) tool/shape_oracle.py $(LISTING) $(BUILD_DIR)

# What a closed 256-bit span could reach, which is not what Finding 133's
# capacity figure suggests. A measurement, not a gate: it always exits 0.
spans: $(LISTING) $(DETOURED)
	objdump -d -j .text $(DETOURED) > $(BUILD_DIR)/after.asm
	$(PYTHON) tool/detour.py spans $(TARGET) $(LISTING) $(BUILD_DIR)/after.asm

census: $(LISTING) $(DETOURED)
	objdump -d -j .text $(DETOURED) > $(BUILD_DIR)/after.asm
	$(PYTHON) tool/detour.py $(SPILL_FLAGS) census $(TARGET) $(LISTING) \
	          $(BUILD_DIR)/after.asm

# Which of the sites .pdata refuses to vouch for are real leaf functions.
outside: $(LISTING)
	$(PYTHON) tool/outside.py report $(TARGET) $<

# -- the end-to-end test, on PEs this project builds itself ------------------

PE_NAMES   = aliasing memory branch ymm zerofill unrolled crossblock riprel \
             fallthrough pastread swallowed gapped interleaved permilps \
             twostore loopcopy lowwrite zerorun loophead zerochain \
             swallowjmp condbefore rspcopy longpair splat constant constloop \
             mxcsr splatrun splatop extract shadowspill regionlive \
             tlsspill spanblock regioncarry swallowcall condswallow dataisland repairdrop conservative switchtable memsrc varshift lanealias tramp cmpimm hammock unaligned
PE_SOURCES = $(PE_NAMES:%=$(BUILD_DIR)/pe-%.exe)
PE_LISTINGS= $(PE_NAMES:%=$(BUILD_DIR)/pe-%.asm)
PE_FIXED   = $(PE_NAMES:%=$(BUILD_DIR)/sse-%.exe)
# Wine wants an absolute prefix, and it is kept under BUILD_DIR so that it is
# this build's to remove rather than something in the user's home.
PE_PREFIX  = $(abspath $(BUILD_DIR))/wineprefix
# The TEB offset `check-teb` measures with. There is no default in the
# tool on purpose -- whose bytes these are is unsettled -- so the gate
# names one rather than inheriting it. TlsSlots 62 and 63, which TlsAlloc
# reaches last. Finding 280.
TEB_SCRATCH = 0x1670
# **Every target that runs wine asks whether wine runs first.** A wine that
# will not start returns 1 for every binary, and 1 is not any fixture's
# expected answer -- so a target without this reports a startup failure as
# a verdict on the work. check-pe grew the canary first and kept it to
# itself, and the other three went on misreporting: running the whole gate
# set found check-tls claiming the loader had not zeroed the bytes and
# check-unwind claiming a handler was unreachable, both of them wine
# refusing a prefix owned by another account. A fix that lands in one of
# four places is a quarter of a fix.
WINE_CANARY = @$(WINE_ENV) timeout 300 wine cmd /c exit 0 >/dev/null 2>&1 || \
	{ echo "$@: wine will not start with WINEPREFIX=$(PE_PREFIX)."; \
	  echo "      Every fixture would return 1 and be reported as a"; \
	  echo "      failure of the thing under test. Run:"; \
	  echo "      $(WINE_ENV) wine cmd /c exit 0"; \
	  exit 1; }
# winedbg is disabled deliberately. The originals are MEANT to die of an
# illegal instruction, and with the debugger enabled that crash starts
# winedbg and waits -- two minutes of timeout for a result already known.
# Measured: with the override the same crash returns 29 immediately, and 29
# is the low byte of STATUS_ILLEGAL_INSTRUCTION.
WINE_ENV   = WINEPREFIX=$(PE_PREFIX) WINEDEBUG=-all WINEDLLOVERRIDES=winedbg.exe=d

# Named, and named HERE rather than beside the other one, because .SECONDARY
# expands its prerequisites where it is read -- listed before PE_LISTINGS is
# defined it silently protects nothing. Without it make deletes the listings
# as intermediates, and a missing secondary is not rebuilt when the thing
# depending on it already exists, which is how a stale rewrite would go
# unnoticed.
# The two extra harnesses build PEs that PE_NAMES does not list, so make
# would treat them as intermediates and delete them after every run.
# Named, never bare: a bare .SECONDARY protects every pattern target,
# object files included, and then declines to rebuild a missing one.
EXTRA_PES  = $(BUILD_DIR)/pe-spill.exe $(BUILD_DIR)/pe-spill.asm \
             $(BUILD_DIR)/pe-homespill.exe $(BUILD_DIR)/pe-homespill.asm \
             $(BUILD_DIR)/pe-unwind.exe $(BUILD_DIR)/pe-unwind.asm \
             $(BUILD_DIR)/pe-unwindstub.exe $(BUILD_DIR)/pe-unwindstub.asm \
             $(BUILD_DIR)/pe-unwindspill.exe $(BUILD_DIR)/pe-unwindspill.asm
.SECONDARY: $(PE_LISTINGS) $(EXTRA_PES)

# **The 320-byte zero fill has a rule of its own**, because `pe-%.exe`
# matches `pe-nogpr-320.exe` with a stem of `nogpr-320` and then asks for
# a program of that name, which does not exist. Nothing noticed while the
# artifact happened to be on disk from a `check-shadow` run: `check-teb`
# named it as a prerequisite and make had nothing to do. Editing
# `pe_build.py` invalidated it and the target failed with
# `no program 'nogpr-320'` -- a dependency on another target's leftovers,
# which is the same class of thing as a check that passes because it was
# handed a stale binary. Make prefers the shorter stem, so this rule wins
# for the suffixed names and the plain one still serves the rest.
$(BUILD_DIR)/pe-%-320.exe: tool/pe_build.py | $(BUILD_DIR)
	$(PYTHON) tool/pe_build.py sample $* $@ 320

$(BUILD_DIR)/pe-%.exe: tool/pe_build.py | $(BUILD_DIR)
	$(PYTHON) tool/pe_build.py sample $* $@

$(BUILD_DIR)/pe-%.asm: $(BUILD_DIR)/pe-%.exe
	objdump -d -j .text $< > $@

$(BUILD_DIR)/sse-%.exe: $(BUILD_DIR)/pe-%.exe $(BUILD_DIR)/pe-%.asm \
                           tool/detour.py tool/patch.py tool/outside.py \
                           tool/scratch.py tool/targets.py tool/lower.py
	$(PYTHON) tool/detour.py apply $(BUILD_DIR)/pe-$*.exe \
	          $(BUILD_DIR)/pe-$*.asm $@

# Run the verifier, which until now nothing did. `detour.py verify` is the
# only check that reads the rewritten IMAGE rather than the plan, and it is
# what found the five wrong readers of Finding 194 -- so it was the one
# check no gate ran, and a crash in it shipped green for a whole session
# (Finding 188). It needs no game binary: every PE fixture is an original,
# a rewrite and a listing, which is exactly its three arguments.
#
# **The controls are the point, not the 35 passes.** A verifier nobody has
# watched fail is a green light, and two of these checks had been dead --
# one to a rebound name, one to a `TypeError` that aborted the run before
# its last two checks. So one fixture is deliberately broken twice: once in
# a way an EARLY check must catch and once in a way one of the LAST checks
# must catch, and each is required to fail with the words of the check that
# owns it. A `verify` that dies in the middle passes neither.
#
# Termination: one bounded invocation per fixture, plus two, each under a
# timeout, over a fixed list. Output goes to a file per fixture and is read
# from there -- never piped, so a failure keeps everything it printed.
check-verify: $(PE_FIXED) $(PE_SOURCES) $(PE_LISTINGS)
	@set -e; \
	ran=0; \
	for name in $(PE_NAMES); do \
		if timeout 300 $(PYTHON) tool/detour.py verify \
			$(BUILD_DIR)/pe-$$name.exe $(BUILD_DIR)/sse-$$name.exe \
			$(BUILD_DIR)/pe-$$name.asm \
			> $(BUILD_DIR)/verify-$$name.log 2>&1; then \
			ran=`expr $$ran + 1`; \
		else \
			echo "check-verify: FAILED on $$name"; \
			cat $(BUILD_DIR)/verify-$$name.log; \
			exit 1; \
		fi; \
	done; \
	echo "check-verify: the verifier passed on $$ran rewritten fixtures"
	@set -e; \
	for kind in stubvex section; do \
		$(PYTHON) tool/detour.py sabotage $(BUILD_DIR)/sse-ymm.exe \
			$(BUILD_DIR)/bad-$$kind.exe $$kind; \
		if timeout 300 $(PYTHON) tool/detour.py verify \
			$(BUILD_DIR)/pe-ymm.exe $(BUILD_DIR)/bad-$$kind.exe \
			$(BUILD_DIR)/pe-ymm.asm \
			> $(BUILD_DIR)/verify-bad-$$kind.log 2>&1; then \
			echo "check-verify: the $$kind control PASSED verify, so the"; \
			echo "              35 results above mean nothing"; \
			exit 1; \
		fi; \
	done
	@set -e; \
	grep -q "1 VEX instructions (must be 0)" \
		$(BUILD_DIR)/verify-bad-stubvex.log || \
		{ echo "check-verify: the stubvex control failed, but not through"; \
		  echo "              the stub-section check -- so verify may have"; \
		  echo "              died before reaching it, which is the defect"; \
		  echo "              this control exists for"; exit 1; }
	@set -e; \
	grep -q "sections after .text changed" \
		$(BUILD_DIR)/verify-bad-section.log || \
		{ echo "check-verify: the section control failed, but not through"; \
		  echo "              the section-identity check"; exit 1; }
# The island control needs a fixture that HAS an island, which ymm does not,
# so it runs against dataisland rather than in the loop above.
	@set -e; \
	$(PYTHON) tool/detour.py sabotage $(BUILD_DIR)/sse-dataisland.exe \
		$(BUILD_DIR)/bad-island.exe island; \
	if timeout 300 $(PYTHON) tool/detour.py verify \
		$(BUILD_DIR)/pe-dataisland.exe $(BUILD_DIR)/bad-island.exe \
		$(BUILD_DIR)/pe-dataisland.asm \
		> $(BUILD_DIR)/verify-bad-island.log 2>&1; then \
		echo "check-verify: the island control PASSED verify, so nothing"; \
		echo "              is watching the rewrite stay out of data"; \
		exit 1; \
	fi; \
	grep -q "data island(s) modified by the rewrite" \
		$(BUILD_DIR)/verify-bad-island.log || \
		{ echo "check-verify: the island control failed, but not through"; \
		  echo "              the data-island check"; exit 1; }
# The badrow control is a CODE sabotage: no corrupted image can make a (bad)
# row reach the candidate loop, so the guard is disabled through the
# environment and verify must reject the result. See CODE_SABOTAGE.
	@set -e; \
	if ANTI_AVX_SABOTAGE=badrow timeout 300 $(PYTHON) tool/detour.py verify \
		$(BUILD_DIR)/pe-dataisland.exe $(BUILD_DIR)/sse-dataisland.exe \
		$(BUILD_DIR)/pe-dataisland.asm \
		> $(BUILD_DIR)/verify-bad-badrow.log 2>&1; then \
		echo "check-verify: the badrow control PASSED verify, so nothing"; \
		echo "              watches data stay out of the candidate loop"; \
		exit 1; \
	fi; \
	grep -q "reached the candidate loop" \
		$(BUILD_DIR)/verify-bad-badrow.log || \
		{ echo "check-verify: the badrow control failed, but not through"; \
		  echo "              the candidate-loop check"; exit 1; }
# The staleupper control needs an image built WITHOUT the repair, so it runs
# apply under the environment variable and verifies the result with the
# repair's check on -- the default leaves it off since Finding 340.
# repairdrop is the only fixture the repair pass reaches -- Finding 231
# measured the other 39 as untouched by it.
	@set -e; \
	ANTI_AVX_SABOTAGE=staleupper $(PYTHON) tool/detour.py \
		--stale-repair=on apply \
		$(BUILD_DIR)/pe-repairdrop.exe $(BUILD_DIR)/pe-repairdrop.asm \
		$(BUILD_DIR)/bad-staleupper.exe > /dev/null; \
	if timeout 300 $(PYTHON) tool/detour.py --stale-repair=on verify \
		$(BUILD_DIR)/pe-repairdrop.exe $(BUILD_DIR)/bad-staleupper.exe \
		$(BUILD_DIR)/pe-repairdrop.asm \
		> $(BUILD_DIR)/verify-bad-staleupper.log 2>&1; then \
		echo "check-verify: the staleupper control PASSED verify, so nothing"; \
		echo "              watches the repair keep a stale upper half out"; \
		exit 1; \
	fi; \
	grep -q "left stale" $(BUILD_DIR)/verify-bad-staleupper.log || \
		{ echo "check-verify: the staleupper control failed, but not"; \
		  echo "              through the stale-upper-half check"; exit 1; }
# The five unwinder checks are an if/elif chain, so each needs its own kind:
# only the first failing condition is ever reported. Finding 46 measured what
# their absence costs -- an exception raised in a stub is never dispatched --
# and until Finding 235 nothing had watched any of them fail.
	@set -e; \
	for pair in "notable:no function table" \
	            "unsorted:the function table is not sorted" \
	            "nostub:no stub section" \
	            "stubgap:outside every function table entry" \
	            "stubcall:call instruction(s) in the stub section" \
	            "stubbad:decode to nothing"; do \
		kind=$${pair%%:*}; want=$${pair#*:}; \
		$(PYTHON) tool/detour.py sabotage $(BUILD_DIR)/sse-ymm.exe \
			$(BUILD_DIR)/bad-$$kind.exe $$kind; \
		if timeout 300 $(PYTHON) tool/detour.py verify \
			$(BUILD_DIR)/pe-ymm.exe $(BUILD_DIR)/bad-$$kind.exe \
			$(BUILD_DIR)/pe-ymm.asm \
			> $(BUILD_DIR)/verify-bad-$$kind.log 2>&1; then \
			echo "check-verify: the $$kind control PASSED verify, so the"; \
			echo "              unwinder checks are watching nothing"; \
			exit 1; \
		fi; \
		grep -q "$$want" $(BUILD_DIR)/verify-bad-$$kind.log || \
			{ echo "check-verify: the $$kind control failed, but not"; \
			  echo "              through its own check"; exit 1; }; \
	done
# A conservative candidate is one the walk could not rule out, kept in its
# VEX form at the price of the site (Finding 198). No corrupted image can
# express "a repair that did not happen", so this needs a code control, and
# the `conservative` fixture is the only input that produces one. Both
# halves ask for the repair, which the default leaves off since Finding 340.
	@set -e; \
	ANTI_AVX_SABOTAGE=conservative $(PYTHON) tool/detour.py \
		--stale-repair=on apply \
		$(BUILD_DIR)/pe-conservative.exe $(BUILD_DIR)/pe-conservative.asm \
		$(BUILD_DIR)/bad-conservative.exe > /dev/null; \
	if timeout 300 $(PYTHON) tool/detour.py --stale-repair=on verify \
		$(BUILD_DIR)/pe-conservative.exe $(BUILD_DIR)/bad-conservative.exe \
		$(BUILD_DIR)/pe-conservative.asm \
		> $(BUILD_DIR)/verify-bad-conservative.log 2>&1; then \
		echo "check-verify: the conservative control PASSED verify, so"; \
		echo "              nothing watches a repair that did not happen"; \
		exit 1; \
	fi; \
	grep -q "conservative candidate(s) were narrowed anyway" \
		$(BUILD_DIR)/verify-bad-conservative.log || \
		{ echo "check-verify: the conservative control failed, but not"; \
		  echo "              through the conservative-candidate check"; exit 1; }
# The switch floor: a resolver that has broken still recognises every
# dispatch and reads noise, so "dispatches without tables" is the resolver
# and "no dispatches" is an honest nothing (Finding 196). The sabotage adds
# the image base twice, which is the defect that built the floor, and
# switchtable is the only fixture holding a dispatch at all.
	@set -e; \
	if ANTI_AVX_SABOTAGE=switchbase timeout 300 $(PYTHON) tool/detour.py \
		verify $(BUILD_DIR)/pe-switchtable.exe \
		$(BUILD_DIR)/sse-switchtable.exe \
		$(BUILD_DIR)/pe-switchtable.asm \
		> $(BUILD_DIR)/verify-bad-switchbase.log 2>&1; then \
		echo "check-verify: the switchbase control PASSED verify, so"; \
		echo "              nothing watches the switch resolver"; \
		exit 1; \
	fi; \
	grep -q "recognised and no table resolved" \
		$(BUILD_DIR)/verify-bad-switchbase.log || \
		{ echo "check-verify: the switchbase control failed, but not"; \
		  echo "              through the switch-dispatch check"; exit 1; }
# The backward-widening guard. A unit window may start on the instruction
# BEFORE its site, which puts the site's first byte past the jump -- and if
# anything branches to the site, arriving there runs the padding and falls
# out of the window having skipped the stub entirely.
#
# **Two earlier controls for this were worthless and are worth recording.**
# The first ran against Starfield and reported all 1,191,105 direct branch
# targets intact, because it ran while the `preceding` accounting bug made
# verify exit on lost boundaries before the branch-target check spoke. The
# second disabled the guard and compared images: 388 sites got past it, one
# built a candidate, and that candidate lost at placement -- so the image
# was byte-identical and the control could not fail. A fixture is the only
# instrument here that puts the window somewhere nothing competes for.
#
# It needs the permanent slots, so it builds its own pair rather than using
# the pattern rules, and the two images must DIFFER before anything below
# is believed. Finding 279.
	@set -e; \
	$(PYTHON) tool/pe_build.py sample backtarget \
		$(BUILD_DIR)/pe-backtarget-320.exe 320 >/dev/null; \
	objdump -d -j .text $(BUILD_DIR)/pe-backtarget-320.exe \
		> $(BUILD_DIR)/pe-backtarget-320.asm; \
	$(PYTHON) tool/detour.py --shadow-regs=all apply \
		$(BUILD_DIR)/pe-backtarget-320.exe \
		$(BUILD_DIR)/pe-backtarget-320.asm \
		$(BUILD_DIR)/sse-backtarget-all.exe > /dev/null; \
	ANTI_AVX_SABOTAGE=backtarget $(PYTHON) tool/detour.py --shadow-regs=all \
		apply $(BUILD_DIR)/pe-backtarget-320.exe \
		$(BUILD_DIR)/pe-backtarget-320.asm \
		$(BUILD_DIR)/bad-backtarget.exe > /dev/null; \
	if cmp -s $(BUILD_DIR)/sse-backtarget-all.exe \
		  $(BUILD_DIR)/bad-backtarget.exe; then \
		echo "check-verify: the backtarget sabotage produced a"; \
		echo "              byte-identical image, so it did not apply and"; \
		echo "              a green result below would mean nothing"; \
		exit 1; \
	fi; \
	if ANTI_AVX_SABOTAGE=backtarget timeout 300 $(PYTHON) tool/detour.py \
		--shadow-regs=all verify $(BUILD_DIR)/pe-backtarget-320.exe \
		$(BUILD_DIR)/bad-backtarget.exe \
		$(BUILD_DIR)/pe-backtarget-320.asm \
		> $(BUILD_DIR)/verify-bad-backtarget.log 2>&1; then \
		echo "check-verify: the backtarget control PASSED verify, so"; \
		echo "              nothing watches a window bury a branch target"; \
		exit 1; \
	fi; \
	grep -q "land inside a placed window" \
		$(BUILD_DIR)/verify-bad-backtarget.log || \
		{ echo "check-verify: the backtarget control failed, but not"; \
		  echo "              through the buried-target check -- and the"; \
		  echo "              check that reads like it covers this, the"; \
		  echo "              swallowed-instruction one, does not: the"; \
		  echo "              buried instruction is the window's member"; \
		  echo "              rather than a passenger"; exit 1; }
	@echo "check-verify: all fourteen controls rejected, each by its own check"

# Build AVX PEs, rewrite them, and run both halves under wine. The originals
# must fail -- this CPU has no AVX -- and each rewritten one must return its
# own expected answer.
#
# **Both halves are assertions.** If an original succeeded, the machine would
# have AVX and the test would be proving nothing; that is the vacuous pass
# this shape exists to prevent, so it fails with its own message.
#
# Termination: every wine invocation is wrapped in a timeout, and the trap
# reaps the wineserver even when an assertion fails part way through.
#
# **A wine that will not start returns 1 for every binary here**, and 1 is
# not any fixture's answer -- so the loop below blames the FIRST fixture and
# reports a rewriting defect. That is what it did when this tree was checked
# out under one account and run under another: wine refuses a prefix it does
# not own, and the message named `aliasing`. The canary asks whether wine
# runs at all before any of that, so the cause is stated once instead of
# being attributed to whichever fixture happens to be first.
# Needs wine, so it is not a prerequisite of `check`: a commit gate
# must not fail on a machine without it. Finding 242.
check-pe: $(PE_FIXED) $(PE_SOURCES)
	@command -v wine >/dev/null 2>&1 || \
		{ echo "check-pe: wine is not installed"; exit 1; }
	@mkdir -p $(PE_PREFIX)
	$(WINE_CANARY)
	@$(WINE_ENV) timeout 300 wine wineboot -i >/dev/null 2>&1 || true
	@set -e; \
	trap 'pkill -x wineserver >/dev/null 2>&1 || true' EXIT; \
	for name in $(PE_NAMES); do \
		want=`$(PYTHON) tool/pe_build.py names | \
		      awk -v n=$$name '$$1 == n { print $$2 }'`; \
		$(WINE_ENV) timeout 120 wine $(BUILD_DIR)/sse-$$name.exe \
			>/dev/null 2>&1 && new=0 || new=$$?; \
		$(WINE_ENV) timeout 120 wine $(BUILD_DIR)/pe-$$name.exe \
			>/dev/null 2>&1 && old=0 || old=$$?; \
		echo "check-pe: $$name -- original $$old, rewritten $$new, want $$want"; \
		if [ "$$old" = "$$want" ]; then \
			echo "check-pe: the ORIGINAL $$name returned $$want -- this CPU"; \
			echo "          has AVX, so the test proves nothing here"; \
			exit 1; \
		fi; \
		if [ "$$new" != "$$want" ]; then \
			echo "check-pe: rewritten $$name returned $$new, want $$want"; \
			exit 1; \
		fi; \
	done; \
	echo "check-pe: AVX in, SSE out, and the answers survived the trip"
	@# **A fixture that returns the right answer by another route is not
	@# coverage.** `regioncarry` exists to exercise the region lowering,
	@# and four earlier shapes of it silently became spans -- the span is
	@# tried first, so anything it can carry it does. `regionlive` is the
	@# standing example: it reads as region coverage and places a `spill`.
	@# So assert the strategy row, not just the exit code. Finding 205.
	@# **Asserted under `--shadow-regs=off`, which is where the region
	@# strategy now lives.** Since the default became `all` the collector
	@# offers `unit` first and it takes anything it can, so the placer
	@# table in that mode is `plain`, `unit` and `spill` and nothing else
	@# -- `zero`, `pair`, `run`, `region`, `span`, the splats and the
	@# constants place nothing at all. That is by construction rather than
	@# regression: the uniform representation is only coherent if every
	@# writer maintains its slot, and `unit` is the strategy that does.
	@#
	@# So this fixture went on answering 77 while covering nothing, which
	@# is exactly the failure Finding 205 wrote it against, and the gate
	@# caught it the hour the default changed. Finding 287.
	@#
	@# **Its own output, not `sse-regioncarry.exe`.** Writing the shared
	@# fixture here left an image built under `--shadow-regs=off` that
	@# `make` then took as up to date, and `check-verify` judged it under
	@# the default and failed on six boundaries and a clobbered register.
	@# Finding 340.
	@set -e; \
	$(PYTHON) tool/detour.py --shadow-regs=off apply \
		$(BUILD_DIR)/pe-regioncarry.exe \
		$(BUILD_DIR)/pe-regioncarry.asm \
		$(BUILD_DIR)/sse-regioncarry-off.exe > $(BUILD_DIR)/regioncarry.log; \
	if grep -qE '^apply:   region +[0-9]' $(BUILD_DIR)/regioncarry.log; then \
		echo "check-pe: regioncarry places a region, so the region lowering"; \
		echo "          is the thing its answer came from"; \
	else \
		echo "check-pe: regioncarry placed NO region -- it is being carried"; \
		echo "          by another strategy and covers nothing"; \
		grep -E '^apply:   [a-z]+ +[0-9]' $(BUILD_DIR)/regioncarry.log; \
		exit 1; \
	fi

# The three ways a stub can get a scratch register when none is dead, all
# built and all run. `none` is the default and must REFUSE the site, so the
# rewritten binary still dies of an illegal instruction -- that assertion is
# what stops the other two passing for the wrong reason, since a site that
# was never the hard case would run under all three.
#
# What this proves is that each mechanism round-trips the borrowed register.
# What it cannot prove is what happens when a thread is inside the stub:
# see check-unwind for the stack case, and Finding 46 for the pool's race,
# which no single-threaded test can reach.
#
# Termination: one wine invocation per mode, each under a timeout.
# Needs wine, and stays out of `check` for that reason. Finding 242.
check-spill: $(BUILD_DIR)/pe-spill.exe $(BUILD_DIR)/pe-spill.asm \
             $(BUILD_DIR)/pe-homespill.exe $(BUILD_DIR)/pe-homespill.asm \
             $(BUILD_DIR)/pe-shadowspill.exe $(BUILD_DIR)/pe-shadowspill.asm \
             $(BUILD_DIR)/pe-regionlive.exe $(BUILD_DIR)/pe-regionlive.asm \
             $(BUILD_DIR)/pe-regionread.exe $(BUILD_DIR)/pe-regionread.asm \
             $(BUILD_DIR)/pe-tlsspill.exe $(BUILD_DIR)/pe-tlsspill.asm
	@command -v wine >/dev/null 2>&1 || \
		{ echo "check-spill: wine is not installed"; exit 1; }
	@mkdir -p $(PE_PREFIX)
	$(WINE_CANARY)
	@$(WINE_ENV) timeout 300 wine wineboot -i >/dev/null 2>&1 || true
	@set -e; \
	trap 'pkill -x wineserver >/dev/null 2>&1 || true' EXIT; \
	want=`$(PYTHON) tool/pe_build.py names | \
	      awk '$$1 == "spill" { print $$2 }'`; \
	for mode in none stack pool; do \
		$(PYTHON) tool/detour.py --spill=$$mode apply \
			$(BUILD_DIR)/pe-spill.exe $(BUILD_DIR)/pe-spill.asm \
			$(BUILD_DIR)/sse-spill-$$mode.exe >/dev/null; \
		$(WINE_ENV) timeout 120 wine $(BUILD_DIR)/sse-spill-$$mode.exe \
			>/dev/null 2>&1 && got=0 || got=$$?; \
		echo "check-spill: --spill=$$mode returned $$got, want $$want"; \
		if [ "$$mode" = "none" ]; then \
			if [ "$$got" = "$$want" ]; then \
				echo "check-spill: --spill=none answered $$want, so the"; \
				echo "             site was never the hard case and the"; \
				echo "             other two prove nothing"; \
				exit 1; \
			fi; \
		elif [ "$$got" != "$$want" ]; then \
			echo "check-spill: --spill=$$mode did not round-trip"; \
			exit 1; \
		fi; \
	done; \
	echo "check-spill: none refuses; stack and pool both give the register back"; \
	want=`$(PYTHON) tool/pe_build.py names | \
	      awk '$$1 == "homespill" { print $$2 }'`; \
	for mode in none home; do \
		$(PYTHON) tool/detour.py --spill=$$mode apply \
			$(BUILD_DIR)/pe-homespill.exe $(BUILD_DIR)/pe-homespill.asm \
			$(BUILD_DIR)/sse-homespill-$$mode.exe >/dev/null; \
		$(WINE_ENV) timeout 120 wine \
			$(BUILD_DIR)/sse-homespill-$$mode.exe \
			>/dev/null 2>&1 && got=0 || got=$$?; \
		echo "check-spill: homespill --spill=$$mode returned $$got, want $$want"; \
		if [ "$$mode" = "none" ]; then \
			if [ "$$got" = "$$want" ]; then \
				echo "check-spill: --spill=none answered $$want, so the"; \
				echo "             site was never the hard case"; exit 1; \
			fi; \
		elif [ "$$got" != "$$want" ]; then \
			echo "check-spill: the home space did not round-trip"; exit 1; \
		fi; \
	done; \
	echo "check-spill: and the callee home space lends a register with no rsp"; \
	echo "check-spill: the shadow pair runs with --fallback=off, because the"; \
	echo "             stack fallback rescues the site on its own and the"; \
	echo "             control stops isolating the shadow"; \
	want=`$(PYTHON) tool/pe_build.py names | \
	      awk '$$1 == "shadowspill" { print $$2 }'`; \
	for mode in off on; do \
		$(PYTHON) tool/detour.py --shadow=$$mode --fallback=off apply \
			$(BUILD_DIR)/pe-shadowspill.exe \
			$(BUILD_DIR)/pe-shadowspill.asm \
			$(BUILD_DIR)/sse-shadowspill-$$mode.exe >/dev/null; \
		$(WINE_ENV) timeout 120 wine \
			$(BUILD_DIR)/sse-shadowspill-$$mode.exe \
			>/dev/null 2>&1 && got=0 || got=$$?; \
		echo "check-spill: shadowspill --shadow=$$mode returned $$got, want $$want"; \
		if [ "$$mode" = "off" ]; then \
			if [ "$$got" = "$$want" ]; then \
				echo "check-spill: --shadow=off answered $$want, so the"; \
				echo "             site was never a leaf starved of a home"; \
				echo "             space and the shadow proves nothing"; \
				exit 1; \
			fi; \
		elif [ "$$got" != "$$want" ]; then \
			echo "check-spill: the caller shadow did not round-trip"; \
			exit 1; \
		fi; \
	done; \
	echo "check-spill: and a LEAF lends the shadow its own caller reserved"; \
	want=`$(PYTHON) tool/pe_build.py names | \
	      awk '$$1 == "regionlive" { print $$2 }'`; \
	for name in regionlive regionread; do \
		for mode in whole live; do \
			$(PYTHON) tool/detour.py --region=$$mode --fallback=off \
				apply \
				$(BUILD_DIR)/pe-$$name.exe $(BUILD_DIR)/pe-$$name.asm \
				$(BUILD_DIR)/sse-$$name-$$mode.exe >/dev/null; \
			$(WINE_ENV) timeout 120 wine \
				$(BUILD_DIR)/sse-$$name-$$mode.exe \
				>/dev/null 2>&1 && got=0 || got=$$?; \
			echo "check-spill: $$name --region=$$mode returned $$got"; \
			if [ "$$name/$$mode" = "regionlive/live" ]; then \
				if [ "$$got" != "$$want" ]; then \
					echo "check-spill: a region dead from the site was"; \
					echo "             not lent -- want $$want"; exit 1; \
				fi; \
			elif [ "$$got" = "$$want" ]; then \
				echo "check-spill: $$name --region=$$mode answered $$want,"; \
				echo "             so the borrow was taken when the region"; \
				echo "             was still live, or was never the case"; \
				exit 1; \
			fi; \
		done; \
	done; \
	echo "check-spill: a region dead from the site is lent and a live one is not"; \
	echo "check-spill: the region pair runs with --fallback=off for the same"; \
	echo "             reason the shadow pair does -- the stack fallback"; \
	echo "             rescues the site correctly and the control then has"; \
	echo "             nothing left to demonstrate"; \
	want=`$(PYTHON) tool/pe_build.py names | \
	      awk '$$1 == "tlsspill" { print $$2 }'`; \
	for mode in home tls; do \
		$(PYTHON) tool/detour.py --spill=$$mode apply \
			$(BUILD_DIR)/pe-tlsspill.exe $(BUILD_DIR)/pe-tlsspill.asm \
			$(BUILD_DIR)/sse-tlsspill-$$mode.exe >/dev/null; \
		$(WINE_ENV) timeout 120 wine \
			$(BUILD_DIR)/sse-tlsspill-$$mode.exe \
			>/dev/null 2>&1 && got=0 || got=$$?; \
		echo "check-spill: tlsspill --spill=$$mode returned $$got, want $$want"; \
		if [ "$$mode" = "home" ]; then \
			if [ "$$got" = "$$want" ]; then \
				echo "check-spill: --spill=home answered $$want, so the"; \
				echo "             site had a home space or a shadow after"; \
				echo "             all and static TLS proves nothing here"; \
				exit 1; \
			fi; \
		elif [ "$$got" != "$$want" ]; then \
			echo "check-spill: the per-thread slot did not round-trip"; \
			exit 1; \
		fi; \
	done; \
	echo "check-spill: and a site with neither lends itself sixteen bytes of TLS"

# Can an exception be dispatched from inside a stub? Two programs that fault
# on purpose, both registering a handler through .pdata -- which is how a PE
# with no imports gets SEH at all.
#
# The control faults on a plain `mov`. The other faults on a lowered
# instruction inside a stub, which answered 5 -- an unhandled 0xC0000005 --
# until the stubs were given unwind data, because a stub is entered by a jump
# and the dispatcher was reading a return address that was never one.
#
# **Both answer 42 now, and the second one is the whole point of Finding 48.**
# It is the only check here that exercises the exception path at all, so if it
# ever goes back to 5 something has stopped emitting `.avxpdat`.
#
# Termination: one wine invocation per program, each under a timeout.
# Needs wine, and stays out of `check` for that reason. Finding 242.
check-unwind: $(BUILD_DIR)/sse-unwind.exe $(BUILD_DIR)/sse-unwindstub.exe \
              $(BUILD_DIR)/pe-unwindspill.exe $(BUILD_DIR)/pe-unwindspill.asm
	@command -v wine >/dev/null 2>&1 || \
		{ echo "check-unwind: wine is not installed"; exit 1; }
	@mkdir -p $(PE_PREFIX)
	$(WINE_CANARY)
	@$(WINE_ENV) timeout 300 wine wineboot -i >/dev/null 2>&1 || true
	@set -e; \
	trap 'pkill -x wineserver >/dev/null 2>&1 || true' EXIT; \
	for name in unwind unwindstub; do \
		want=`$(PYTHON) tool/pe_build.py names | \
		      awk -v n=$$name '$$1 == n { print $$2 }'`; \
		$(WINE_ENV) timeout 120 wine $(BUILD_DIR)/sse-$$name.exe \
			>/dev/null 2>&1 && got=0 || got=$$?; \
		echo "check-unwind: $$name returned $$got, want $$want"; \
		if [ "$$got" != "$$want" ]; then \
			echo "check-unwind: $$name changed behaviour"; exit 1; \
		fi; \
	done; \
	$(PYTHON) tool/detour.py --spill=stack apply \
		$(BUILD_DIR)/pe-unwindspill.exe $(BUILD_DIR)/pe-unwindspill.asm \
		$(BUILD_DIR)/sse-unwindspill.exe >/dev/null; \
	want=`$(PYTHON) tool/pe_build.py names | \
	      awk '$$1 == "unwindspill" { print $$2 }'`; \
	$(WINE_ENV) timeout 120 wine $(BUILD_DIR)/sse-unwindspill.exe \
		>/dev/null 2>&1 && got=0 || got=$$?; \
	echo "check-unwind: unwindspill returned $$got, want $$want"; \
	if [ "$$got" != "$$want" ]; then \
		echo "check-unwind: unwindspill changed behaviour"; exit 1; \
	fi; \
	echo "check-unwind: a handler is reached from inside a stub, and a stub"; \
	echo "              that moved rsp still hands it the wrong frame"

# Prove every register the liveness scan claims as scratch is really dead,
# by enumerating paths rather than intersecting sets. Needs the listing, so
# it cannot live in `check`.
scratch-check: $(LISTING)
	$(PYTHON) tool/scratch.py check $< $(TARGET)

# -- git hooks ---------------------------------------------------------------

# The hook lives in tool/hooks/ rather than only in .git/hooks so that it
# survives a clone and can be diffed against its siblings. An untracked hook
# enforces a rule nobody can see.
# **Where the hooks live is git's question, not the filesystem's.** This
# asked `test -d .git`, which is false in a linked worktree and in a
# submodule checkout: there `.git` is a regular FILE naming the real
# gitdir, and both are git repositories. So `make hooks` refused with
# "not a git repository" inside one that is.
#
# Testing -e instead would only move the failure one line down, because
# the install writes into `.git/hooks/`, which is not a directory there
# either. Asking git answers both halves at once, and from a worktree it
# returns the MAIN repository's hooks directory -- which is the one git
# actually runs.
#
# git's absence is reported as its own thing rather than as "not a git
# repository", which would be a message naming a cause nothing tested.
hooks:
	@if ! command -v git >/dev/null 2>&1; then \
		echo "hooks: git is not installed, so there is nowhere to install to." >&2; \
		exit 1; \
	fi; \
	dir=$$(git rev-parse --git-common-dir 2>/dev/null); \
	if [ -z "$$dir" ]; then \
		echo "hooks: not a git repository, so there is nowhere to install to." >&2; \
		exit 1; \
	fi; \
	mkdir -p "$$dir/hooks"; \
	install -m 0755 tool/hooks/commit-msg "$$dir/hooks/commit-msg"; \
	echo "hooks: commit-msg installed from tool/hooks/ into $$dir/hooks/"

# -- cleaning ----------------------------------------------------------------

# Named targets only. No `rm -rf` of a directory and no wildcard sweep: a
# clean target is the one thing everybody runs without reading.
clean:
	rm -f $(LISTING) $(REPORT) $(PATCHED) $(DETOURED) $(GENERATED) \
	      $(PE_SOURCES) $(PE_LISTINGS) $(PE_FIXED) $(EXTRA_PES) \
	      $(BUILD_DIR)/sse-unwind.exe $(BUILD_DIR)/sse-unwindstub.exe \
	      $(BUILD_DIR)/sse-unwindspill.exe \
	      $(BUILD_DIR)/sse-spill-none.exe $(BUILD_DIR)/sse-spill-stack.exe \
	      $(BUILD_DIR)/sse-spill-pool.exe \
	      $(BUILD_DIR)/icache_bench \
	      $(BUILD_DIR)/after.asm $(BUILD_DIR)/patched.asm $(BUILD_DIR)/stubs.asm \
	      $(BUILD_DIR)/isa-disasm.txt $(BUILD_DIR)/region-refused.txt \
	      $(BUILD_DIR)/regioncarry.log $(BUILD_DIR)/sse-regioncarry-off.exe \
	      $(BUILD_DIR)/bad-stubvex.exe $(BUILD_DIR)/bad-section.exe \
	      $(BUILD_DIR)/bad-island.exe \
	      $(PE_NAMES:%=$(BUILD_DIR)/verify-%.log) \
	      $(BUILD_DIR)/verify-bad-stubvex.log \
	      $(BUILD_DIR)/verify-bad-section.log \
	      $(BUILD_DIR)/verify-bad-island.log \
	      $(BUILD_DIR)/verify-bad-badrow.log \
	      $(BUILD_DIR)/verify-bad-staleupper.log \
	      $(BUILD_DIR)/bad-staleupper.exe \
	      $(BUILD_DIR)/bad-notable.exe $(BUILD_DIR)/bad-unsorted.exe \
	      $(BUILD_DIR)/bad-nostub.exe $(BUILD_DIR)/bad-stubgap.exe \
	      $(BUILD_DIR)/bad-stubcall.exe \
	      $(BUILD_DIR)/bad-stubbad.exe \
	      $(BUILD_DIR)/bad-conservative.exe \
	      $(BUILD_DIR)/verify-bad-conservative.log \
	      $(BUILD_DIR)/verify-bad-switchbase.log \
	      $(BUILD_DIR)/detour-verify.log \
	      $(BUILD_DIR)/verify-bad-stubbad.log \
	      $(BUILD_DIR)/verify-bad-notable.log \
	      $(BUILD_DIR)/verify-bad-unsorted.log \
	      $(BUILD_DIR)/verify-bad-nostub.log \
	      $(BUILD_DIR)/verify-bad-stubgap.log \
	      $(BUILD_DIR)/verify-bad-stubcall.log \
	      $(OBJS) $(TEST_OBJS) $(TEST_BINS) $(DEPS)
	@echo "clean: removed $(LISTING) $(REPORT) $(PATCHED) $(DETOURED) $(BUILD_DIR)/icache_bench $(OBJS) $(TEST_OBJS) $(TEST_BINS) $(DEPS)"
	@# The wine prefix is a directory this build created, so it goes
	@# wholesale -- but only after checking the variable is non-empty and
	@# not something that could resolve outside the build tree.
	@case "$(PE_PREFIX)" in \
	  */wineprefix) test -d "$(PE_PREFIX)" && rm -rf "$(PE_PREFIX)" && \
	                echo "clean: removed $(PE_PREFIX)" || true ;; \
	  *) echo "clean: refusing to remove '$(PE_PREFIX)'" ;; \
	esac
	@rmdir $(BUILD_DIR) 2>/dev/null || true

# Adds only what this project's own tooling wrote. It does not sweep for
# editor droppings: a .swp belongs to an editor that may still have the file
# open, and `find .` from here would walk .git as well. `git clean -xdn`
# lists that class, and removing it is the person's call.
distclean: clean
	@find . -name .git -prune -o \( -name __pycache__ -type d \) -print \
	        -exec rm -rf {} + 2>/dev/null || true
	@echo "distclean: done"

help:
	@echo 'Targets:'
	@echo '  check       the style gate -- what must pass before committing'
	@echo '  style       indentation, whitespace and document checks'
	@echo '  verify      assemble every lowering rule; prove no VEX survives'
	@echo '  check-f16c  software half-precision conversions, exhaustive h->f'
	@echo '  check-f16c-exhaustive'
	@echo '              also all 2^32 singles; a couple of minutes'
	@echo '  check-f16c-oracle'
	@echo '              reference vs CPython binary16, an outside opinion'
	@echo '  check-fmaddsub'
	@echo '              the alternating-lane FMA lowerings'
	@echo '  check-permil'
	@echo '              the vpermilps variable-control helper, exhaustive'
	@echo '  check-permd'
	@echo '              the vpermd cross-lane helper, all 8^8 permutations'
	@echo '  check-isa   prove the built object has no AVX, EVEX or F16C'
	@echo '  scan        reproduce project.md from $$(TARGET) into $$(BUILD_DIR)'
	@echo '  coverage    which VEX sites have a lowering rule, and the gaps'
	@echo '  disassemble ddisasm over $$(TARGET), under prlimit bounds'
	@echo '  patch-plan  what can be rewritten in place, and what cannot'
	@echo '  patch       rewrite classes A/B/Z in place into $$(BUILD_DIR)'
	@echo '  patch-verify'
	@echo '              size, headers, and instruction boundaries preserved'
	@echo '  detour-plan what Class C would be detoured'
	@echo '  detour      in-place patches plus Class C detours'
	@echo '  detour-verify'
	@echo '              sections, boundaries and the stub section'
	@echo '  check-lowering  execute every lowering and check the result'
	@echo '  check-pe    build an AVX PE, rewrite it, run both under wine'
	@echo '  bench       what a detour costs on this CPU (a timing run)'
	@echo '  placement   where the detours land: functions and loop bodies'
	@echo '  outside     the code .pdata does not describe'
	@echo '  census      what survives the rewrite, and why'
	@echo '  scratch-check  prove every claimed scratch register is dead'
	@echo '  hooks       install the commit-msg hook into .git/hooks'
	@echo '  clean       remove the listing and the report'
	@echo '  distclean   clean, plus __pycache__'
	@echo
	@echo 'Variables:'
	@echo '  BUILD_DIR   where products land (default: build)'
	@echo '  TARGET      the binary to scan (default: Starfield-unpacked.exe)'

# Every .d written by -MMD -MP above is read back here. Test objects are in
# this list deliberately: leaving them out is the failure that produces a
# test binary compiled against a stale header, which shows up as nonsense
# assertion failures rather than as a build error.
-include $(DEPS)
