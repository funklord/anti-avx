/* The alternating-lane FMA lowerings. See fmaddsub.h.
 *
 * The SDM, for the 231 forms, in Intel operand order (DEST, SRC2, SRC3):
 *
 *   VFMADDSUB231PS   DEST[31:0]   := SRC2[31:0]  *SRC3[31:0]   - DEST[31:0]
 *                    DEST[63:32]  := SRC2[63:32] *SRC3[63:32]  + DEST[63:32]
 *                    DEST[95:64]  := SRC2[95:64] *SRC3[95:64]  - DEST[95:64]
 *                    DEST[127:96] := SRC2[127:96]*SRC3[127:96] + DEST[127:96]
 *
 *   VFMSUBADD231PS   the same with the two operators exchanged.
 *
 * So VFMADDSUB subtracts on the EVEN lanes. SSE3's ADDSUBPS does the same:
 *
 *   ADDSUBPS  DEST[31:0]  := DEST[31:0]  - SRC[31:0]
 *             DEST[63:32] := DEST[63:32] + SRC[63:32]      ... and so on.
 *
 * That was confirmed on the host rather than read off the manual, because
 * having it backwards is the failure this file exists to prevent and the
 * manual is exactly what one misreads:
 *
 *   {10,20,30,40} addsubps {1,2,3,4}  ->  {9,22,27,44}
 *
 * 9 is 10-1 and 22 is 20+2, so even subtracts and odd adds. Confirmed.
 */

#include "fmaddsub.h"

#include <smmintrin.h>		/* SSE3 addsub, SSE4.1 blend */

/* -- scalar references, straight from the pseudocode above ------------- */

void fmaddsub231ps_ref(const float *src1, const float *src2, float *dst)
{
	int i;

	for (i = 0; i < 4; i++) {
		float product = src1[i] * src2[i];

		dst[i] = (i & 1) ? product + dst[i] : product - dst[i];
	}
}

void fmsubadd231ps_ref(const float *src1, const float *src2, float *dst)
{
	int i;

	for (i = 0; i < 4; i++) {
		float product = src1[i] * src2[i];

		dst[i] = (i & 1) ? product - dst[i] : product + dst[i];
	}
}

void fmaddsub231pd_ref(const double *src1, const double *src2, double *dst)
{
	int i;

	for (i = 0; i < 2; i++) {
		double product = src1[i] * src2[i];

		dst[i] = (i & 1) ? product + dst[i] : product - dst[i];
	}
}

void fmsubadd231pd_ref(const double *src1, const double *src2, double *dst)
{
	int i;

	for (i = 0; i < 2; i++) {
		double product = src1[i] * src2[i];

		dst[i] = (i & 1) ? product - dst[i] : product + dst[i];
	}
}

/* -- the lowered sequences -------------------------------------------- */

/* movaps src1,%xmmT ; mulps src2,%xmmT ; addsubps dst,%xmmT ; movaps %xmmT,dst
 *
 * addsubps already has the lane pattern VFMADDSUB wants, so nothing else is
 * needed and no constant is required. Four instructions, one scratch. */
void fmaddsub231ps_sse(const float *src1, const float *src2, float *dst)
{
	__m128 product = _mm_mul_ps(_mm_loadu_ps(src1), _mm_loadu_ps(src2));

	_mm_storeu_ps(dst, _mm_addsub_ps(product, _mm_loadu_ps(dst)));
}

/* movaps src1,%xmmT ; mulps src2,%xmmT ; movaps %xmmT,%xmmU
 * addps dst,%xmmT ; subps dst,%xmmU ; blendps $0xa,%xmmU,%xmmT
 * movaps %xmmT,dst
 *
 * VFMSUBADD is the opposite lane pattern to addsubps and SSE has no
 * instruction for it. Both results are computed and blended: even lanes
 * from the add, odd lanes from the subtract.
 *
 * **The obvious alternative is wrong, and the tests caught it.** Negating
 * the addend and reusing addsubps looks right -- IEEE 754 does make a - b
 * and a + (-b) the same operation, signed zeros included -- but the
 * negation is a sign-bit flip applied to the whole register, and a NaN has
 * a sign bit too. x86 propagates a source NaN with its sign preserved, so
 * a NaN addend came out of that sequence as ffc00000 where the hardware
 * gives 7fc00000. 291 vectors in the special-value sweep disagreed, every
 * one of them a NaN.
 *
 * Computing both and blending has no such problem: it performs the very
 * add and subtract the reference does, so NaN propagation is identical by
 * construction rather than by argument. It also needs no sign-mask
 * constant, which removes the requirement for the rewriter to add a
 * read-only pool. Two extra instructions across 14 sites. */
void fmsubadd231ps_sse(const float *src1, const float *src2, float *dst)
{
	__m128 d = _mm_loadu_ps(dst);
	__m128 product = _mm_mul_ps(_mm_loadu_ps(src1), _mm_loadu_ps(src2));
	__m128 added = _mm_add_ps(product, d);
	__m128 subtracted = _mm_sub_ps(product, d);

	/* 0xa selects lanes 1 and 3 from the subtract. */
	_mm_storeu_ps(dst, _mm_blend_ps(added, subtracted, 0xa));
}

void fmaddsub231pd_sse(const double *src1, const double *src2, double *dst)
{
	__m128d product = _mm_mul_pd(_mm_loadu_pd(src1), _mm_loadu_pd(src2));

	_mm_storeu_pd(dst, _mm_addsub_pd(product, _mm_loadu_pd(dst)));
}

void fmsubadd231pd_sse(const double *src1, const double *src2, double *dst)
{
	__m128d d = _mm_loadu_pd(dst);
	__m128d product = _mm_mul_pd(_mm_loadu_pd(src1), _mm_loadu_pd(src2));
	__m128d added = _mm_add_pd(product, d);
	__m128d subtracted = _mm_sub_pd(product, d);

	/* 0x2 selects lane 1 from the subtract. */
	_mm_storeu_pd(dst, _mm_blend_pd(added, subtracted, 0x2));
}

/* What the plain Class F rule would emit: mul then add, on every lane.
 * Kept so that a test can show it is wrong rather than merely asserting so
 * in a comment. */
void fmaddsub231ps_naive(const float *src1, const float *src2, float *dst)
{
	__m128 product = _mm_mul_ps(_mm_loadu_ps(src1), _mm_loadu_ps(src2));

	_mm_storeu_ps(dst, _mm_add_ps(product, _mm_loadu_ps(dst)));
}
