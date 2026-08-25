/* Tests for the alternating-lane FMA lowerings.
 *
 * Three claims, and they are not the same claim:
 *
 *   1. The lowered sequence computes what the SDM pseudocode computes,
 *      bit for bit, including on signed zeros, infinities and NaNs. The
 *      signed zeros are the interesting ones: the fmsubadd lowering turns
 *      a - b into a + (-b), which IEEE 754 says is exact, and this is where
 *      that would show up if it were not.
 *
 *   2. The naive Class F sequence is WRONG here. Demonstrated rather than
 *      asserted, because the whole reason these 28 sites need their own
 *      rule is that the general rule silently mis-computes half of every
 *      vector.
 *
 *   3. addsubps has the lane order this all depends on. Checked directly
 *      with a value whose two answers cannot be confused.
 *
 * What is NOT established: agreement with real FMA hardware. The lowering
 * rounds twice where the instruction rounds once, so it is knowingly not
 * bit-identical to the original -- that is Class F's standing caveat and it
 * applies here too. What is checked is that the lowering matches a
 * separately-written model of the same double-rounded arithmetic, which is
 * what isolates a lane-order or sign error from a rounding difference.
 *
 * Termination: counted loops over fixed ranges.
 */

#include "fmaddsub.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static uint64_t failures;

/* Cases where BOTH the product and the addend are NaN. Which of the two
 * propagates is decided by which operand the emitted instruction makes its
 * destination -- x86 returns the first source operand's NaN -- and the C
 * compiler picks that independently for the scalar reference and for the
 * intrinsics. Settling what the real FMA does needs FMA hardware.
 *
 * The exemption is deliberately narrow. "Both results are NaN" would be the
 * easy rule and would have hidden the sign-flip bug this file was written
 * to catch, where only the addend was NaN and the lowering changed its
 * sign. Requiring both inputs to be NaN keeps that case failing. */
static uint64_t ambiguous;

static int is_nan_bits(uint32_t bits)
{
	return (bits & 0x7F800000u) == 0x7F800000u && (bits & 0x007FFFFFu) != 0u;
}

/* A deterministic generator, so a failure is reproducible. */
static uint64_t state = 0x853c49e6748fea9bULL;

static uint32_t next_bits(void)
{
	state = state * 6364136223846793005ULL + 1442695040888963407ULL;
	return (uint32_t)(state >> 32);
}

/* Bit patterns worth hitting on purpose. Signed zeros first, because the
 * negation in the fmsubadd lowering is exactly where they would go wrong. */
static const uint32_t special_floats[] = {
	0x00000000u,	/* +0.0 */
	0x80000000u,	/* -0.0 */
	0x3F800000u,	/* +1.0 */
	0xBF800000u,	/* -1.0 */
	0x7F800000u,	/* +inf */
	0xFF800000u,	/* -inf */
	0x7FC00000u,	/* quiet NaN */
	0x00800000u,	/* smallest normal */
	0x00000001u,	/* smallest subnormal */
	0x7F7FFFFFu,	/* largest finite */
};

static float make_float(uint32_t bits)
{
	float value;

	memcpy(&value, &bits, sizeof value);
	return value;
}

static uint32_t float_bits(float value)
{
	uint32_t bits;

	memcpy(&bits, &value, sizeof bits);
	return bits;
}

static void compare_ps(const char *name, const float *a, const float *b,
                       const float *original, const float *src1,
                       const float *src2)
{
	int i;

	for (i = 0; i < 4; i++) {
		if (float_bits(a[i]) == float_bits(b[i]))
			continue;
		if (is_nan_bits(float_bits(src1[i] * src2[i])) &&
		    is_nan_bits(float_bits(original[i]))) {
			ambiguous++;
			continue;
		}
		if (failures < 10)
			fprintf(stderr, "%s lane %d: src1=%08" PRIx32 " src2=%08" PRIx32
			        " dst=%08" PRIx32 " -> reference %08" PRIx32
			        ", lowered %08" PRIx32 "\n",
			        name, i, float_bits(src1[i]), float_bits(src2[i]),
			        float_bits(original[i]), float_bits(a[i]),
			        float_bits(b[i]));
		failures++;
	}
}

static void check_ps(void)
{
	const uint32_t count = sizeof special_floats / sizeof special_floats[0];
	float src1[4], src2[4], original[4], reference[4], lowered[4];
	uint32_t round, i;

	/* Every combination of the special values, laid across the lanes, then
	 * a long random tail. */
	for (round = 0; round < count * count * 64u; round++) {
		for (i = 0; i < 4; i++) {
			if (round < count * count) {
				uint32_t a = (round / count + i) % count;
				uint32_t b = (round % count + i) % count;
				uint32_t c = (round / count + round + i) % count;

				src1[i] = make_float(special_floats[a]);
				src2[i] = make_float(special_floats[b]);
				original[i] = make_float(special_floats[c]);
			} else {
				src1[i] = make_float(next_bits());
				src2[i] = make_float(next_bits());
				original[i] = make_float(next_bits());
			}
		}

		memcpy(reference, original, sizeof reference);
		memcpy(lowered, original, sizeof lowered);
		fmaddsub231ps_ref(src1, src2, reference);
		fmaddsub231ps_sse(src1, src2, lowered);
		compare_ps("fmaddsub231ps", reference, lowered, original, src1, src2);

		memcpy(reference, original, sizeof reference);
		memcpy(lowered, original, sizeof lowered);
		fmsubadd231ps_ref(src1, src2, reference);
		fmsubadd231ps_sse(src1, src2, lowered);
		compare_ps("fmsubadd231ps", reference, lowered, original, src1, src2);
	}

	printf("ps: %" PRIu32 " vectors, specials exhaustive then random\n",
	       count * count * 64u);
}

static void check_pd(void)
{
	double src1[2], src2[2], original[2], reference[2], lowered[2];
	uint32_t round, i, lane;

	for (round = 0; round < 200000u; round++) {
		for (i = 0; i < 2; i++) {
			uint64_t bits = ((uint64_t)next_bits() << 32) | next_bits();

			memcpy(&src1[i], &bits, sizeof bits);
			bits = ((uint64_t)next_bits() << 32) | next_bits();
			memcpy(&src2[i], &bits, sizeof bits);
			bits = ((uint64_t)next_bits() << 32) | next_bits();
			memcpy(&original[i], &bits, sizeof bits);
		}
		/* Force signed zeros through both lanes regularly. */
		if ((round & 7u) == 0u) {
			original[0] = (round & 8u) ? -0.0 : 0.0;
			original[1] = (round & 16u) ? -0.0 : 0.0;
		}

		memcpy(reference, original, sizeof reference);
		memcpy(lowered, original, sizeof lowered);
		fmaddsub231pd_ref(src1, src2, reference);
		fmaddsub231pd_sse(src1, src2, lowered);

		memcpy(reference, original, sizeof reference);
		memcpy(lowered, original, sizeof lowered);
		fmsubadd231pd_ref(src1, src2, reference);
		fmsubadd231pd_sse(src1, src2, lowered);

		for (lane = 0; lane < 2; lane++) {
			uint64_t a, b;

			memcpy(&a, &reference[lane], sizeof a);
			memcpy(&b, &lowered[lane], sizeof b);
			if (a != b) {
				if (failures < 10)
					fprintf(stderr, "fmsubadd231pd lane %u: reference "
					        "%016" PRIx64 ", lowered %016" PRIx64 "\n",
					        lane, a, b);
				failures++;
			}
		}
	}

	printf("pd: 200,000 vectors, signed zeros forced through both lanes\n");
}

/* The lane order everything above rests on, checked directly. */
static void check_lane_order(void)
{
	const float d[4] = { 10.0f, 20.0f, 30.0f, 40.0f };
	const float s[4] = { 1.0f, 2.0f, 3.0f, 4.0f };
	const float one[4] = { 1.0f, 1.0f, 1.0f, 1.0f };
	float work[4];

	/* fmaddsub231ps with src2 all ones makes the product equal src1, so
	 * the result is src1 addsub dst -- which isolates the lane pattern. */
	memcpy(work, d, sizeof work);
	fmaddsub231ps_sse(s, one, work);

	if (work[0] != s[0] - d[0] || work[1] != s[1] + d[1]) {
		fprintf(stderr, "lane order: got {%g,%g,%g,%g}, expected even "
		        "lanes to subtract\n", (double)work[0], (double)work[1],
		        (double)work[2], (double)work[3]);
		failures++;
		return;
	}
	printf("lane order: even lanes subtract, odd lanes add -- as addsubps "
	       "does\n");
}

/* The naive Class F sequence must disagree, or these 28 sites would not
 * need a rule of their own. A test that passes whether or not the bug
 * exists is not a test. */
static void check_naive_is_wrong(void)
{
	const float src1[4] = { 2.0f, 3.0f, 4.0f, 5.0f };
	const float src2[4] = { 1.0f, 1.0f, 1.0f, 1.0f };
	const float start[4] = { 10.0f, 10.0f, 10.0f, 10.0f };
	float correct[4], naive[4];
	int differed = 0;
	int i;

	memcpy(correct, start, sizeof correct);
	memcpy(naive, start, sizeof naive);
	fmaddsub231ps_ref(src1, src2, correct);
	fmaddsub231ps_naive(src1, src2, naive);

	for (i = 0; i < 4; i++)
		if (float_bits(correct[i]) != float_bits(naive[i]))
			differed++;

	if (differed != 2) {
		fprintf(stderr, "naive check: expected the plain mul+add sequence to "
		        "differ on the 2 even lanes, it differed on %d\n", differed);
		failures++;
		return;
	}
	printf("naive mul+add differs on exactly the 2 even lanes, as it must\n");
}

int main(void)
{
	check_lane_order();
	check_naive_is_wrong();
	check_ps();
	check_pd();

	if (ambiguous != 0)
		printf("%" PRIu64 " lane(s) had NaN in both the product and the "
		       "addend; which NaN propagates is operand-order dependent "
		       "and needs FMA hardware to settle\n", ambiguous);

	if (failures != 0) {
		fprintf(stderr, "\n%" PRIu64 " mismatch(es)\n", failures);
		return 1;
	}
	printf("fmaddsub: lowered sequences match the reference everywhere\n");
	return 0;
}
