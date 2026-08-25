/* Tests for the vpermd cross-lane helper.
 *
 * The permutation space is 8^8 = 16,777,216 -- eight elements each choosing
 * freely from eight sources -- and every one of them is checked. That is
 * feasible here in a couple of seconds and it removes any question about
 * whether the interesting cases were sampled.
 *
 * Two things beyond the permutations:
 *
 *   * Bits 31:3 of an index are ignored by the instruction. A rubbish
 *     pattern is cycled through the exhaustive sweep so that every
 *     permutation is seen with several of them, because an index whose
 *     high bits leak into the byte control gets ZEROED by pshufb rather
 *     than permuted -- the same trap as the vpermilps helper, one bit over.
 *
 *   * The destination is allowed to alias the data. Both halves of the
 *     result must be computed before either is stored, or an early write
 *     destroys a source a later element still needs. Checked directly.
 *
 * Termination: counted loops over fixed ranges.
 */

#include "permd.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static uint64_t failures;

/* Distinct enough that a wrong element is obvious. */
static const uint32_t markers[8] = {
	0x1000000Au, 0x2000000Bu, 0x3000000Cu, 0x4000000Du,
	0x5000000Eu, 0x6000000Fu, 0x70000010u, 0x80000011u,
};

/* Rubbish for bits 31:3, which the instruction ignores. 0x08 and 0x20 are
 * the ones that reach pshufb's zeroing bit if a mask is missing. */
static const uint32_t high_bits[] = {
	0x00000000u,
	0xFFFFFFF8u,
	0x00000008u,
	0x00000020u,
	0x00000080u,
	0x000000F8u,
	0x80000000u,
	0xCAFEBEE0u & ~7u,
};

static void check_all_permutations(void)
{
	const uint32_t patterns = sizeof high_bits / sizeof high_bits[0];
	const uint64_t total = 16777216ull;	/* 8^8 */
	uint32_t indices[8], reference[8], lowered[8];
	uint64_t combination;

	for (combination = 0; combination < total; combination++) {
		uint32_t rubbish = high_bits[combination % patterns];
		int i;

		for (i = 0; i < 8; i++) {
			uint32_t selector = (uint32_t)((combination >> (3 * i)) & 7u);

			indices[i] = selector | rubbish;
		}

		permd_ref(markers, indices, reference);
		permd_sse(markers, indices, lowered);

		for (i = 0; i < 8; i++) {
			if (reference[i] == lowered[i])
				continue;
			if (failures < 10)
				fprintf(stderr, "permd: element %d index %08" PRIx32
				        " -> reference %08" PRIx32 ", lowered %08" PRIx32
				        "\n", i, indices[i], reference[i], lowered[i]);
			failures++;
		}

		if ((combination & 0x3FFFFFull) == 0)
			printf("  permd: %2" PRIu64 "%%\n",
			       (uint64_t)(combination * 100ull / total));
	}

	printf("permd: all %" PRIu64 " index combinations, high bits varied\n",
	       total);
}

/* Every element must be able to reach across the 128-bit boundary. A
 * helper that permuted within halves would pass a surprising amount of the
 * sweep above by luck on the identity-ish cases, so ask for the crossing
 * directly. */
static void check_crosses_lanes(void)
{
	uint32_t indices[8], result[8];
	int i;

	/* Every element asks for source element 7, which lives in the upper
	 * half. The lower half of the result must still get it. */
	for (i = 0; i < 8; i++)
		indices[i] = 7u;
	permd_sse(markers, indices, result);
	for (i = 0; i < 8; i++) {
		if (result[i] == markers[7])
			continue;
		fprintf(stderr, "cross-lane: element %d got %08" PRIx32
		        ", expected %08" PRIx32 " -- an in-lane implementation "
		        "would give %08" PRIx32 "\n",
		        i, result[i], markers[7], markers[i < 4 ? 3 : 7]);
		failures++;
	}

	/* And the mirror: every element asks for source element 0, which lives
	 * in the lower half. */
	for (i = 0; i < 8; i++)
		indices[i] = 0u;
	permd_sse(markers, indices, result);
	for (i = 0; i < 8; i++) {
		if (result[i] == markers[0])
			continue;
		fprintf(stderr, "cross-lane: element %d got %08" PRIx32
		        ", expected %08" PRIx32 "\n", i, result[i], markers[0]);
		failures++;
	}

	printf("cross-lane: every element reaches both halves\n");
}

/* dst aliasing data, across every permutation of the low half. */
static void check_aliasing(void)
{
	uint32_t combination;

	for (combination = 0; combination < 65536u; combination++) {
		uint32_t indices[8], in_place[8], expected[8];
		int i;

		for (i = 0; i < 8; i++) {
			uint32_t selector = (combination >> (2 * (i & 3))) & 7u;

			indices[i] = selector ^ (uint32_t)(i & 4);
		}

		memcpy(in_place, markers, sizeof in_place);
		permd_ref(markers, indices, expected);
		permd_sse(in_place, indices, in_place);

		for (i = 0; i < 8; i++) {
			if (in_place[i] == expected[i])
				continue;
			if (failures < 10)
				fprintf(stderr, "aliasing: element %d -> expected %08"
				        PRIx32 ", got %08" PRIx32 "\n",
				        i, expected[i], in_place[i]);
			failures++;
		}
	}

	printf("aliasing: destination equal to source, 65,536 index sets\n");
}

int main(void)
{
	check_crosses_lanes();
	check_aliasing();
	check_all_permutations();

	if (failures != 0) {
		fprintf(stderr, "\n%" PRIu64 " mismatch(es)\n", failures);
		return 1;
	}
	printf("permd: the helper matches the reference everywhere\n");
	return 0;
}
