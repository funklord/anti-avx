/* What does a detour cost, on the machine the translation targets?
 *
 * project.md's cost model counts instructions and says +1.34%. It does not
 * model the front end at all, and the fair objection to the whole approach
 * is that 176,893 jumps into a section 144 MB away from .text will cost far
 * more in instruction-cache and fetch behaviour than they do in issue slots.
 *
 * That is measurable here, and unusually directly: this machine IS the
 * target, a Xeon X5675 with a 32 KB 4-way L1i and 64-byte lines.
 *
 * The experiment generates two versions of the same loop at run time:
 *
 *   baseline   a straight run of SSE instructions
 *   detoured   the same instructions, except that every Nth adjacent PAIR
 *              is replaced by a `jmp rel32` into a stub that performs the
 *              pair and jumps back -- which is exactly the shape the
 *              rewriter emits for a widened window
 *
 * The stubs are mapped far from the loop body so that they land in
 * different cache sets and different pages, as the real ones do.
 *
 * Three instruction mixes are measured, because which one a loop resembles
 * decides whether a detour costs anything at all -- and the spread between
 * them is wider than the detour density itself:
 *
 *   addps   throughput one per cycle on this part -- a single FP add port.
 *           A loop of these is BACK-END bound, and fetch bubbles hide
 *           behind the port limit. This is what FP-heavy game code looks
 *           like, and the first measurement showed a baseline of exactly
 *           1.00 cycles per instruction, which is the port and not the
 *           front end.
 *
 *   mov     r8 to r11 only, so dependency chains form and this also runs
 *           at about one per cycle. It is here as a cross-check on the
 *           first: a different port, the same answer.
 *
 *   nop     three-byte, depends on nothing, saturates nothing. This is the
 *           worst case and the honest upper bound.
 *
 * The measured spread at the real detour density is the finding: about
 * 1-2% for the two that are port-limited, and 8-12% for the nops. The
 * reason is that addps saturates the single FP add port, so the jumps issue
 * elsewhere and their fetch bubbles overlap with work that was going to
 * take that long anyway. Nops saturate nothing, so the same bubbles are
 * fully exposed.
 *
 * That matters for reading the result. The target binary is 52% scalar
 * float by instruction count -- it looks far more like the first mix than
 * the third -- but quoting only the first would understate the cost of a
 * detour landing in a stretch of pointer chasing or integer setup.
 *
 * Termination: every loop is a counted for over a fixed range. Nothing is
 * spawned, nothing is written to disk.
 */

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

#define LINE 64

/* addps %xmmS,%xmmD -- three bytes, no prefix, no dependency if S and D
 * are varied. */
static int mix_kind;   /* 0 addps, 1 mov, 2 nop */

/* Three bytes either way, so the two mixes lay out identically. */
static int emit_op(uint8_t *at, int destination, int source)
{
	if (mix_kind == 2) {
		/* A three-byte nop. Retires up to four per cycle and depends on
		 * nothing at all, so the loop is limited purely by fetch and
		 * decode. Nothing in real code looks like this; it is here to
		 * bound the worst case, because a detour costs most where there
		 * is nothing to hide it behind.
		 */
		at[0] = 0x0F; at[1] = 0x1F; at[2] = 0x00;
		(void)destination; (void)source;
		return 3;
	}
	if (mix_kind == 1) {
		/* mov %r8d..%r11d -- three per cycle, and the destination is
		 * written without being read, so there is no dependency chain.
		 *
		 * Only r8 to r11. r12 to r15 are callee-saved under SysV, and a
		 * generated function that clobbers them returns into a caller
		 * whose state has been destroyed -- which is a segfault, and was.
		 */
		at[0] = 0x45;
		at[1] = 0x89;
		at[2] = (uint8_t)(0xC0 | ((source & 3) << 3) | (destination & 3));
		return 3;
	}
	at[0] = 0x0F;			/* addps %xmmS,%xmmD */
	at[1] = 0x58;
	at[2] = (uint8_t)(0xC0 | ((destination & 7) << 3) | (source & 7));
	return 3;
}

static int emit_jmp(uint8_t *at, uintptr_t from, uintptr_t to)
{
	int32_t displacement = (int32_t)(to - (from + 5));
	at[0] = 0xE9;
	memcpy(at + 1, &displacement, 4);
	return 5;
}

struct built {
	uint8_t *body;
	size_t body_size;
	uint8_t *stubs;
	size_t stub_size;
	int detours;
};

/* Build one loop. `every` is the pair interval: 0 means no detours, 8 means
 * every eighth pair of instructions is routed through a stub. */
static struct built build(size_t instructions, int every, uint8_t *body_area,
                          uint8_t *stub_area)
{
	struct built out;
	uint8_t *code = body_area;
	uint8_t *stub = stub_area;
	size_t emitted = 0;
	int pair = 0;

	memset(&out, 0, sizeof out);
	uint8_t *loop_top = code;

	while (emitted + 2 <= instructions) {
		int detour = every > 0 && (pair % every) == 0;
		int a = (int)(emitted % 8);
		int b = (int)((emitted + 3) % 8);

		if (!detour) {
			code += emit_op(code, a, (a + 1) % 8);
			code += emit_op(code, b, (b + 1) % 8);
		} else {
			/* Six bytes of body become a jump plus one nop, and the
			 * pair is performed in the stub -- the widened-window
			 * shape from project.md Finding 16. */
			uint8_t *site = code;
			code += emit_jmp(code, (uintptr_t)site, (uintptr_t)stub);
			*code++ = 0x90;

			stub += emit_op(stub, a, (a + 1) % 8);
			stub += emit_op(stub, b, (b + 1) % 8);
			stub += emit_jmp(stub, (uintptr_t)stub, (uintptr_t)code);
			out.detours++;
		}
		emitted += 2;
		pair++;
	}

	/* sub $1,%edi ; jnz loop_top ; ret */
	*code++ = 0x83; *code++ = 0xEF; *code++ = 0x01;
	*code++ = 0x0F; *code++ = 0x85;
	int32_t back = (int32_t)((uintptr_t)loop_top - ((uintptr_t)code + 4));
	memcpy(code, &back, 4); code += 4;
	*code++ = 0xC3;

	out.body = body_area;
	out.body_size = (size_t)(code - body_area);
	out.stubs = stub_area;
	out.stub_size = (size_t)(stub - stub_area);
	return out;
}

static double seconds(void)
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	return now.tv_sec + now.tv_nsec * 1e-9;
}

typedef void (*loop_fn)(unsigned);

/* Best of several runs: the minimum is the least contaminated by anything
 * else the machine is doing. */
static double best_time(loop_fn function, unsigned iterations, int rounds)
{
	double best = 1e30;
	int round;

	function(1000);				/* warm the caches and the BTB */
	for (round = 0; round < rounds; round++) {
		double start = seconds();
		function(iterations);
		double elapsed = seconds() - start;
		if (elapsed < best)
			best = elapsed;
	}
	return best;
}

int main(int argc, char **argv)
{
	const size_t arena = 64u << 20;
	const double ghz = 3.067;
	size_t sizes[] = { 1024, 8192, 32768 };
	int rates[] = { 0, 94, 47, 16, 8, 4 };	/* pairs between detours */
	unsigned iterations = argc > 1 ? (unsigned)strtoul(argv[1], NULL, 0)
	                              : 200000u;
	size_t i, r;

	/* Two mappings far apart, so a stub is never in the body's page or
	 * anywhere near its cache sets -- as .avxsse is 144 MB from .text. */
	uint8_t *body_area = mmap(NULL, arena, PROT_READ | PROT_WRITE,
	                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	uint8_t *stub_area = mmap(NULL, arena, PROT_READ | PROT_WRITE,
	                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (body_area == MAP_FAILED || stub_area == MAP_FAILED) {
		fprintf(stderr, "mmap failed\n");
		return 1;
	}
	printf("body at %p, stubs at %p, %.0f MB apart\n", (void *)body_area,
	       (void *)stub_area,
	       (double)llabs((long long)(stub_area - body_area)) / 1048576.0);
	printf("L1i 32 KB 4-way, 64-byte lines. Detours are 1.07%% of "
	       "instructions in the real rewrite; the other rates show the "
	       "shape of the curve.\n\n");

	static const char *names[] = {
		"SSE addps -- one FP add port, so ~1 insn/cycle (FP-heavy code)",
		"mov r8-r11 -- dependency chains, also ~1 insn/cycle",
		"3-byte nop -- fetch and decode only, the true worst case",
	};
	for (int mix = 0; mix < 3; mix++) {
		mix_kind = mix;
		printf("=== %s ===\n", names[mix]);
		printf("%10s %8s %10s %9s %9s %9s\n", "insns", "body KB", "detour %",
		       "ns/iter", "cyc/insn", "vs base");
		for (i = 0; i < sizeof sizes / sizeof sizes[0]; i++) {
			double baseline = 0.0;
			for (r = 0; r < sizeof rates / sizeof rates[0]; r++) {
				memset(body_area, 0x90, 1u << 20);
				memset(stub_area, 0x90, 1u << 20);
				struct built built = build(sizes[i], rates[r],
				                           body_area, stub_area);
				if (mprotect(body_area, arena, PROT_READ | PROT_EXEC) ||
				    mprotect(stub_area, arena, PROT_READ | PROT_EXEC)) {
					fprintf(stderr, "mprotect failed\n");
					return 1;
				}
				double took = best_time((loop_fn)body_area, iterations, 5);
				double per_iteration = took / iterations * 1e9;
				double cycles = per_iteration * ghz / (double)sizes[i];
				double share = 100.0 * (double)built.detours * 2.0
				               / (double)sizes[i];
				if (r == 0)
					baseline = per_iteration;
				printf("%10zu %8.1f %10.2f %9.1f %9.3f %8.1f%%\n",
				       sizes[i], built.body_size / 1024.0, share,
				       per_iteration, cycles,
				       100.0 * (per_iteration / baseline - 1.0));
				if (mprotect(body_area, arena, PROT_READ | PROT_WRITE) ||
				    mprotect(stub_area, arena, PROT_READ | PROT_WRITE)) {
					fprintf(stderr, "mprotect back failed\n");
					return 1;
				}
			}
			printf("\n");
		}
	}
	return 0;
}
