/* The vpermilps variable-control helper. See permil.h.
 *
 * SSSE3's pshufb is a variable-control permute already -- it just works on
 * bytes rather than on 32-bit elements. So the whole job is turning a
 * vector of four element selectors into a vector of sixteen byte selectors,
 * which is four instructions:
 *
 *     pand   {3,3,3,3}          take bits 1:0 of each control element
 *     pslld  $2                 element index -> byte index of its first byte
 *     pshufb {0,0,0,0,4,4,4,4,8,8,8,8,12,12,12,12}
 *                               replicate that byte across its element
 *     paddb  {0,1,2,3} x4       ... and step through the four bytes
 *     pshufb <that>, data       the permute itself
 *
 * The `pand` is not optional. Without it the shift can push a control bit
 * into position 7, and pshufb reads bit 7 of a control byte as "write zero
 * here" -- so an element whose control happened to hold, say, 32 would come
 * back zeroed instead of permuted. The compiler does leave rubbish in bits
 * 31:2, so this is a live case rather than a theoretical one.
 *
 * Everything used is SSSE3 or older, so it is well inside the Westmere
 * baseline. There is no cross-lane work anywhere, which is what separates
 * this from vperm2f128 and vpermq.
 */

#include "permil.h"

#include <tmmintrin.h>		/* SSSE3: _mm_shuffle_epi8 */
#include <string.h>

void permilps_var_ref(const uint32_t *data, const uint32_t *control,
                      uint32_t *dst)
{
	uint32_t out[4];
	int i;

	for (i = 0; i < 4; i++)
		out[i] = data[control[i] & 3u];

	/* Staged through `out` because dst is allowed to alias data: writing
	 * in place would let an early element overwrite a source a later one
	 * still needs. The register form has no such problem, so this is the
	 * reference paying for being a reference. */
	memcpy(dst, out, sizeof out);
}

void permilps_var_sse(const uint32_t *data, const uint32_t *control,
                      uint32_t *dst)
{
	const __m128i selector_mask = _mm_set1_epi32(3);
	const __m128i first_byte = _mm_setr_epi8(0, 0, 0, 0, 4, 4, 4, 4,
	                                          8, 8, 8, 8, 12, 12, 12, 12);
	const __m128i step = _mm_set1_epi32(0x03020100);
	__m128i values = _mm_loadu_si128((const __m128i *)data);
	__m128i controls = _mm_loadu_si128((const __m128i *)control);
	__m128i selectors, scaled, spread, byte_control;

	selectors = _mm_and_si128(controls, selector_mask);
	scaled = _mm_slli_epi32(selectors, 2);
	spread = _mm_shuffle_epi8(scaled, first_byte);
	byte_control = _mm_add_epi8(spread, step);

	_mm_storeu_si128((__m128i *)dst,
	                 _mm_shuffle_epi8(values, byte_control));
}

/* The 256-bit form is two independent 128-bit permutes, because vpermilps
 * never crosses a 128-bit lane. Written out as two calls rather than
 * cleverly, since that is exactly what the translator emits. */
void permilps_var256_ref(const uint32_t *data, const uint32_t *control,
                         uint32_t *dst)
{
	permilps_var_ref(data, control, dst);
	permilps_var_ref(data + 4, control + 4, dst + 4);
}

void permilps_var256_sse(const uint32_t *data, const uint32_t *control,
                         uint32_t *dst)
{
	permilps_var_sse(data, control, dst);
	permilps_var_sse(data + 4, control + 4, dst + 4);
}
