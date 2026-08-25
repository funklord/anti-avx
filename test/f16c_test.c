/* Exhaustive tests for the software F16C conversions.
 *
 * Two things are being established, and they are different claims:
 *
 *   1. The vector code agrees with the scalar reference. Checked over the
 *      **entire input space** in both directions -- all 65,536 halves, and
 *      all 4,294,967,296 singles -- so this is a proof rather than a
 *      sample. It is the claim that matters for the translator, because the
 *      vector code is what gets emitted.
 *
 *   2. The scalar reference agrees with something nobody here wrote. That
 *      cannot be settled inside this file; `--dump-h2f` prints every
 *      conversion so tool/f16c_oracle.py can compare them against
 *      CPython's own binary16 support. Two implementations by one author
 *      are one witness, however exhaustively they agree.
 *
 * What is NOT established: agreement with real F16C silicon. This machine
 * is the translation target and has no F16C, which is the entire reason
 * these routines exist. NaN payload handling in particular is written to
 * the SDM's description and is unverified against hardware.
 *
 * Termination: every loop below is a counted `for` over a fixed range. The
 * exhaustive single-to-half pass is 2^32 iterations and takes a couple of
 * minutes; it is behind its own argument rather than in the default run.
 */

#include "f16c.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#define BATCH 8

static uint64_t failures;

static void report(const char *direction, uint32_t input,
                   uint32_t expected, uint32_t got)
{
	if (failures < 20)
		fprintf(stderr, "%s: input %08" PRIx32 " expected %08" PRIx32
		        " got %08" PRIx32 "\n", direction, input, expected, got);
	failures++;
}

/* All 65,536 halves. Nothing is sampled: this is the whole domain. */
static int check_half_to_single(void)
{
	uint16_t halves[BATCH];
	uint32_t singles[BATCH];
	uint32_t base, i;

	for (base = 0; base < 0x10000u; base += BATCH) {
		for (i = 0; i < BATCH; i++)
			halves[i] = (uint16_t)(base + i);

		f16c_ph2ps_8(halves, singles);

		for (i = 0; i < BATCH; i++) {
			uint32_t expected = f16c_half_to_single_ref(halves[i]);
			if (singles[i] != expected)
				report("ph2ps", halves[i], expected, singles[i]);
		}
	}

	printf("ph2ps: all 65,536 halves checked against the reference\n");
	return failures == 0;
}

/* All 2^32 singles when `exhaustive`, otherwise the boundaries plus a
 * spread. The boundaries are where every one of these algorithms goes
 * wrong: the normal/subnormal edge, the overflow-to-infinity edge, and the
 * ties that decide rounding. */
static int check_single_to_half(int exhaustive)
{
	static const uint32_t interesting[] = {
		0x00000000u, 0x80000000u,	/* zeros */
		0x00000001u, 0x007FFFFFu,	/* subnormal singles */
		0x33000000u, 0x33800000u,	/* 2^-25, the round-to-zero tie */
		0x33800001u,			/* just above the tie */
		0x387FFFFFu, 0x38800000u,	/* the subnormal/normal half edge */
		0x38000000u, 0x38000001u,
		0x477FE000u,			/* 65504, the largest half */
		0x477FF000u,			/* 65520, ties up to infinity */
		0x477FEFFFu,			/* just below that tie */
		0x47800000u,			/* 65536, past the range */
		0x7F800000u, 0xFF800000u,	/* infinities */
		0x7F800001u, 0x7FC00000u,	/* signalling and quiet NaN */
		0x3F800000u, 0xBF800000u,	/* +/-1.0 */
	};
	const uint32_t count = sizeof interesting / sizeof interesting[0];
	uint32_t batch[BATCH];
	uint16_t halves[BATCH];
	uint32_t i, j;
	uint64_t base, limit, step;

	for (i = 0; i < count; i += BATCH) {
		for (j = 0; j < BATCH; j++) {
			uint32_t k = i + j;
			batch[j] = k < count ? interesting[k] : 0;
		}
		f16c_ps2ph_8(batch, halves);
		for (j = 0; j < BATCH; j++) {
			uint16_t expected = f16c_single_to_half_ref(batch[j]);
			if (halves[j] != expected)
				report("ps2ph", batch[j], expected, halves[j]);
		}
	}

	limit = 0x100000000ull;
	step = exhaustive ? BATCH : 0x1000u;

	for (base = 0; base < limit; base += step) {
		for (j = 0; j < BATCH; j++)
			batch[j] = (uint32_t)(base + j);

		f16c_ps2ph_8(batch, halves);

		for (j = 0; j < BATCH; j++) {
			uint16_t expected = f16c_single_to_half_ref(batch[j]);
			if (halves[j] != expected)
				report("ps2ph", batch[j], expected, halves[j]);
		}

		if (exhaustive && (base & 0x3FFFFFFFull) == 0)
			printf("  ps2ph: %3" PRIu64 "%%\n",
			       (uint64_t)(base * 100ull / limit));
	}

	if (exhaustive)
		printf("ps2ph: all 4,294,967,296 singles checked against the "
		       "reference\n");
	else
		printf("ps2ph: boundaries and a 1-in-512 spread checked "
		       "(use `exhaustive` for all 2^32)\n");
	return failures == 0;
}

/* Every half and the single it becomes, for an outside opinion. */
static void dump_half_to_single(void)
{
	uint32_t value;

	for (value = 0; value < 0x10000u; value++)
		printf("%04" PRIx32 " %08" PRIx32 "\n", value,
		       f16c_half_to_single_ref((uint16_t)value));
}

static void emit_single(uint32_t value)
{
	printf("%08" PRIx32 " %04x\n", value, f16c_single_to_half_ref(value));
}

/* A sample of singles and the halves they become, for the same outside
 * opinion in the lossy direction.
 *
 * 2^32 values cannot go through an interpreter in reasonable time, so this
 * is a sample -- and it is chosen rather than random, because the places
 * these algorithms go wrong are known. Everything is swept at both signs.
 *
 * The strides are sized to keep the whole set near 190,000 values, which an
 * interpreter gets through in seconds. The exhaustive claim for this
 * direction comes from `check-f16c-exhaustive` against the reference; what
 * this set buys is the *independent* opinion, which cannot be exhaustive.
 */
static void dump_single_to_half(void)
{
	/* Indexed rather than stepped. `for (sign = 0; sign <= 0x80000000u;
	 * sign += 0x80000000u)` is the obvious spelling and it never
	 * terminates: the second increment wraps a uint32_t back to zero and
	 * the condition holds again. It was written that way here first. */
	static const uint32_t signs[2] = { 0u, 0x80000000u };
	uint32_t value;
	unsigned index;

	for (index = 0; index < 2; index++) {
		const uint32_t sign = signs[index];

		/* Every exponent and the top mantissa bits: all 32,768 distinct
		 * upper halves, with the low bits clear. */
		for (value = 0; value < 0x8000u; value++)
			emit_single(sign | (value << 16));

		/* The subnormal-to-normal edge, where the shift changes form. */
		for (value = 0x33000000u; value < 0x39000000u; value += 5039u)
			emit_single(sign | value);

		/* The overflow edge, where rounding decides between the largest
		 * half and infinity. */
		for (value = 0x47700000u; value < 0x47900000u; value += 103u)
			emit_single(sign | value);

		/* The round-to-zero tie at 2^-25 and its neighbourhood. */
		for (value = 0x32000000u; value < 0x34000000u; value += 1699u)
			emit_single(sign | value);
	}
}

int main(int argc, char **argv)
{
	int exhaustive = argc > 1 && strcmp(argv[1], "exhaustive") == 0;

	if (argc > 1 && strcmp(argv[1], "--dump-h2f") == 0) {
		dump_half_to_single();
		return 0;
	}
	if (argc > 1 && strcmp(argv[1], "--dump-f2h") == 0) {
		dump_single_to_half();
		return 0;
	}

	check_half_to_single();
	check_single_to_half(exhaustive);

	if (failures != 0) {
		fprintf(stderr, "\n%" PRIu64 " mismatch(es)\n", failures);
		return 1;
	}
	printf("f16c: vector and reference agree everywhere checked\n");
	return 0;
}
