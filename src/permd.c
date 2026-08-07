/* The vpermd cross-lane helper. See permd.h.
 *
 * pshufb permutes within one 128-bit register, and vpermd selects across
 * two. The trick that bridges the gap is pshufb's own zeroing rule: a
 * control byte with bit 7 set writes zero rather than a byte of the source.
 *
 * So each output half is built twice and combined:
 *
 *     from_low  = pshufb(data_low,  control with bit 7 set where index >= 4)
 *     from_high = pshufb(data_high, control with bit 7 set where index <  4)
 *     result    = from_low | from_high
 *
 * Every element is non-zero in exactly one of the two, because bit 2 of the
 * index decides which half it comes from and the two controls disagree on
 * that bit by construction. The OR then merges them with no blend
 * instruction and no mask register.
 *
 * Building the byte controls is the same shape as the vpermilps helper,
 * with one extra term for the half selector:
 *
 *     pand   {7,7,7,7}       bits 2:0 of each index
 *     -- low three bits split into "which element within a half" and
 *        "which half":
 *     pand   {3,3,3,3} ; pslld $2      element -> first byte of that element
 *     pshufb <replicate byte 0 of each element>
 *     paddb  {0,1,2,3} x4              ... step through its four bytes
 *     -- and the half selector, turned into pshufb's zeroing bit:
 *     pand   {4,4,4,4} ; pslld $5      4 -> 0x80
 *     pshufb <replicate>
 *
 * As in the vpermilps helper the masks are load-bearing rather than tidy:
 * without them a high bit of an index lands on bit 7 of a control byte and
 * silently zeroes an element that should have been permuted.
 */

#include "permd.h"

#include <tmmintrin.h>		/* SSSE3: _mm_shuffle_epi8 */
#include <string.h>

void permd_ref(const uint32_t *data, const uint32_t *indices, uint32_t *dst)
{
	uint32_t out[8];
	int i;

	for (i = 0; i < 8; i++)
		out[i] = data[indices[i] & 7u];

	/* Staged, because dst is allowed to alias data. */
	memcpy(dst, out, sizeof out);
}

/* One output half: four results selected from all eight source elements. */
static __m128i permd_half(__m128i low, __m128i high, __m128i indices)
{
	const __m128i element_mask = _mm_set1_epi32(3);
	const __m128i half_mask = _mm_set1_epi32(4);
	const __m128i replicate = _mm_setr_epi8(0, 0, 0, 0, 4, 4, 4, 4,
	                                         8, 8, 8, 8, 12, 12, 12, 12);
	const __m128i step = _mm_set1_epi32(0x03020100);
	const __m128i zero_bit = _mm_set1_epi8((char)0x80);
	__m128i within, scaled, spread, base;
	__m128i selector, flag, from_low_control, from_high_control;

	/* Which element inside a half, as a byte index. */
	within = _mm_and_si128(indices, element_mask);
	scaled = _mm_slli_epi32(within, 2);
	spread = _mm_shuffle_epi8(scaled, replicate);
	base = _mm_add_epi8(spread, step);

	/* Which half: bit 2 of the index, moved to pshufb's zeroing bit. */
	selector = _mm_and_si128(indices, half_mask);
	flag = _mm_shuffle_epi8(_mm_slli_epi32(selector, 5), replicate);

	/* Zero the elements this half does not supply. The two controls differ
	 * exactly in that bit, so each element survives in one of them. */
	from_low_control = _mm_or_si128(base, flag);
	from_high_control = _mm_or_si128(base, _mm_xor_si128(flag, zero_bit));

	return _mm_or_si128(_mm_shuffle_epi8(low, from_low_control),
	                    _mm_shuffle_epi8(high, from_high_control));
}

void permd_sse(const uint32_t *data, const uint32_t *indices, uint32_t *dst)
{
	__m128i low = _mm_loadu_si128((const __m128i *)data);
	__m128i high = _mm_loadu_si128((const __m128i *)(data + 4));
	__m128i index_low = _mm_loadu_si128((const __m128i *)indices);
	__m128i index_high = _mm_loadu_si128((const __m128i *)(indices + 4));
	__m128i result_low = permd_half(low, high, index_low);
	__m128i result_high = permd_half(low, high, index_high);

	/* Both halves are computed before either is stored, which is what lets
	 * dst alias data. */
	_mm_storeu_si128((__m128i *)dst, result_low);
	_mm_storeu_si128((__m128i *)(dst + 4), result_high);
}
