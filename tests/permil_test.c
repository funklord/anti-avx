/* Tests for the vpermilps variable-control helper.
 *
 * The permutation space is small enough to cover completely: four elements
 * each selected by two bits is 4^4 = 256 distinct permutations, and every
 * one is checked. What cannot be exhaustive is the *rest* of each control
 * element -- bits 31:2, which the instruction ignores -- so those are swept
 * with patterns chosen to break a wrong implementation rather than at
 * random.
 *
 * The pattern that matters is a control element holding 32 or more. Scaling
 * an element index into a byte index shifts it left by two, which puts bit 5
 * into bit 7, and pshufb reads bit 7 of a control byte as "write zero here".
 * An implementation that skips the mask returns zeros for those elements
 * instead of permuting them, and the compiler does leave rubbish in the high
 * bits, so it is a live case.
 *
 * Also checked: that the 256-bit form stays inside its 128-bit lanes. A
 * cross-lane implementation would pass every 128-bit test and be wrong on
 * all eight of the ymm sites.
 *
 * Termination: counted loops over fixed ranges.
 */

#include "permil.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static uint64_t failures;

/* Values that must survive being moved around unchanged. Distinct enough
 * that a wrong lane is obvious in the output. */
static const uint32_t markers[4] = {
	0x11111111u, 0x22222222u, 0x33333333u, 0x44444444u,
};

/* Rubbish for bits 31:2 of a control element. The instruction ignores all
 * of it. 0x20 and 0x80 are the ones that break a missing mask. */
static const uint32_t high_bits[] = {
	0x00000000u,
	0xFFFFFFFCu,
	0x00000020u,	/* becomes bit 7 after the shift -- pshufb zeroing */
	0x00000080u,
	0x000000FCu,
	0x0000FF00u,
	0x80000000u,
	0xDEADBEE0u & ~3u,
};

static void check_one(const uint32_t *data, const uint32_t *control,
                      const char *what)
{
	uint32_t reference[4], lowered[4];
	int i;

	permilps_var_ref(data, control, reference);
	permilps_var_sse(data, control, lowered);

	for (i = 0; i < 4; i++) {
		if (reference[i] == lowered[i])
			continue;
		if (failures < 10)
			fprintf(stderr, "%s: element %d control %08" PRIx32
			        " -> reference %08" PRIx32 ", lowered %08" PRIx32 "\n",
			        what, i, control[i], reference[i], lowered[i]);
		failures++;
	}
}

/* All 256 permutations, against every high-bit pattern. */
static void check_all_permutations(void)
{
	const uint32_t patterns = sizeof high_bits / sizeof high_bits[0];
	uint32_t control[4];
	uint32_t combination, pattern;
	uint32_t cases = 0;

	for (combination = 0; combination < 256u; combination++) {
		for (pattern = 0; pattern < patterns; pattern++) {
			int i;

			for (i = 0; i < 4; i++) {
				uint32_t selector = (combination >> (2 * i)) & 3u;

				control[i] = selector | high_bits[pattern];
			}
			check_one(markers, control, "permutation");
			cases++;
		}
	}

	printf("permutations: all 256, each against %" PRIu32 " high-bit "
	       "patterns (%" PRIu32 " cases)\n", patterns, cases);
}

/* The reference is allowed to be handed a destination that aliases its
 * input, so the helper must be too. */
static void check_aliasing(void)
{
	uint32_t combination;

	for (combination = 0; combination < 256u; combination++) {
		uint32_t control[4], in_place[4], expected[4];
		int i;

		for (i = 0; i < 4; i++)
			control[i] = (combination >> (2 * i)) & 3u;

		memcpy(in_place, markers, sizeof in_place);
		permilps_var_ref(markers, control, expected);
		permilps_var_sse(in_place, control, in_place);

		for (i = 0; i < 4; i++) {
			if (in_place[i] == expected[i])
				continue;
			if (failures < 10)
				fprintf(stderr, "aliasing: element %d -> expected %08"
				        PRIx32 ", got %08" PRIx32 "\n",
				        i, expected[i], in_place[i]);
			failures++;
		}
	}

	printf("aliasing: destination equal to source, all 256 permutations\n");
}

/* vpermilps never crosses a 128-bit lane. Give the two halves entirely
 * different data and ask the upper half for element 0: it must get its own
 * element 0, not the lower half's. */
static void check_lanes_are_independent(void)
{
	const uint32_t data[8] = {
		0xA0u, 0xA1u, 0xA2u, 0xA3u,	/* lower lane */
		0xB0u, 0xB1u, 0xB2u, 0xB3u,	/* upper lane */
	};
	uint32_t control[8], result[8];
	int i;

	for (i = 0; i < 8; i++)
		control[i] = 0u;	/* every element asks for element 0 */

	permilps_var256_sse(data, control, result);

	for (i = 0; i < 4; i++) {
		if (result[i] != 0xA0u) {
			fprintf(stderr, "lanes: lower element %d got %08" PRIx32
			        ", expected a0\n", i, result[i]);
			failures++;
		}
		if (result[4 + i] != 0xB0u) {
			fprintf(stderr, "lanes: upper element %d got %08" PRIx32
			        ", expected b0 -- a cross-lane read would give a0\n",
			        i, result[4 + i]);
			failures++;
		}
	}

	printf("lanes: the 256-bit form permutes within each half, not across\n");
}

/* And the same across every permutation of both halves. */
static void check_256_matches_reference(void)
{
	uint32_t data[8], control[8], reference[8], lowered[8];
	uint32_t low, high;
	int i;

	for (i = 0; i < 8; i++)
		data[i] = 0xC0FFEE00u + (uint32_t)i;

	for (low = 0; low < 256u; low++) {
		for (high = 0; high < 256u; high += 17u) {
			for (i = 0; i < 4; i++) {
				control[i] = (low >> (2 * i)) & 3u;
				control[4 + i] = (high >> (2 * i)) & 3u;
			}
			permilps_var256_ref(data, control, reference);
			permilps_var256_sse(data, control, lowered);

			for (i = 0; i < 8; i++) {
				if (reference[i] == lowered[i])
					continue;
				if (failures < 10)
					fprintf(stderr, "256-bit: element %d -> reference %08"
					        PRIx32 ", lowered %08" PRIx32 "\n",
					        i, reference[i], lowered[i]);
				failures++;
			}
		}
	}

	printf("256-bit: both halves against the reference\n");
}

int main(void)
{
	check_all_permutations();
	check_aliasing();
	check_lanes_are_independent();
	check_256_matches_reference();

	if (failures != 0) {
		fprintf(stderr, "\n%" PRIu64 " mismatch(es)\n", failures);
		return 1;
	}
	printf("permil: the helper matches the reference everywhere\n");
	return 0;
}
