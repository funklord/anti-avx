/* Software F16C. See f16c.h for why this exists.
 *
 * The governing constraint is that **none of this may depend on MXCSR.**
 *
 * `vcvtps2ph` takes its rounding mode from bits 2:0 of its immediate, and
 * the target binary uses 0 -- round to nearest, ties to even -- which
 * ignores MXCSR entirely. Games routinely set flush-to-zero and
 * denormals-are-zero for speed, so an emulation that reaches for the
 * obvious float tricks inherits both the wrong rounding mode and a flush
 * the original instruction would not have done.
 *
 * That rules out the widely copied approaches. Giesen's half_to_float_fast5
 * multiplies by a magic power of two and relies on the denormal arithmetic
 * that DAZ switches off; float_to_half_fast3 adds a magic constant and
 * inherits whatever rounding mode MXCSR happens to hold. Both are correct
 * in a normal process and wrong in the one process this has to be correct
 * in.
 *
 * So: integer arithmetic where the shift is constant, and `roundps` with an
 * explicit mode where it is not. `roundps` is SSE4.1, present on Westmere,
 * and its rounding mode comes from its own immediate rather than MXCSR --
 * which is exactly the property `vcvtps2ph` has and the reason it can stand
 * in for one.
 */

#include "f16c.h"

#include <smmintrin.h>		/* SSE4.1: _mm_round_ps, _mm_packus_epi32 */

/* -- scalar reference ------------------------------------------------- */

/* Shift right by `shift`, rounding to nearest with ties to even.
 *
 * Written out rather than expressed as a trick because this is the oracle:
 * if it is wrong, everything it certifies is wrong with it.
 */
static uint32_t shift_round_nearest_even(uint32_t value, unsigned shift)
{
	uint32_t keep, rest, half;

	if (shift == 0)
		return value;
	if (shift >= 32)
		return 0;	/* every caller here has value < 2^24 */

	keep = value >> shift;
	rest = value & ((1u << shift) - 1u);
	half = 1u << (shift - 1);

	if (rest > half || (rest == half && (keep & 1u) != 0u))
		keep++;
	return keep;
}

uint32_t f16c_half_to_single_ref(uint16_t half)
{
	uint32_t sign = (uint32_t)(half & 0x8000u) << 16;
	int32_t exponent = (half >> 10) & 0x1F;
	uint32_t mantissa = half & 0x3FFu;

	if (exponent == 31)
		/* Infinity when the mantissa is zero, NaN otherwise. Shifting the
		 * payload left by 13 is what puts it in the same place a single
		 * keeps it, and it cannot collide with infinity because a non-zero
		 * mantissa stays non-zero. */
		return sign | 0x7F800000u | (mantissa << 13);

	if (exponent == 0) {
		if (mantissa == 0)
			return sign;		/* signed zero */

		/* A subnormal half is a normal single: every value it can hold is
		 * comfortably inside the single range. Normalise by walking the
		 * implicit bit up into place. */
		exponent = 1;
		while ((mantissa & 0x400u) == 0u) {
			mantissa <<= 1;
			exponent--;
		}
		mantissa &= 0x3FFu;
	}

	/* 112 is the difference between the two exponent biases, 127 - 15. */
	return sign | ((uint32_t)(exponent + 112) << 23) | (mantissa << 13);
}

uint16_t f16c_single_to_half_ref(uint32_t single)
{
	uint32_t sign = (single >> 16) & 0x8000u;
	uint32_t magnitude = single & 0x7FFFFFFFu;
	uint32_t exponent, significand, adjusted, rounded;
	unsigned shift;

	if (magnitude > 0x7F800000u) {
		/* NaN. Keep as much of the payload as fits and force the quiet bit,
		 * because the hardware instruction delivers a QNaN for a signalling
		 * input. The masked payload cannot make the mantissa zero -- that
		 * would turn a NaN into an infinity -- because the quiet bit is set
		 * unconditionally. */
		return (uint16_t)(sign | 0x7E00u | ((magnitude >> 13) & 0x1FFu));
	}
	if (magnitude >= 0x47800000u)
		/* At or above 65536, which no half can hold. Also catches infinity
		 * itself, since 0x7F800000 is above this. */
		return (uint16_t)(sign | 0x7C00u);

	if (magnitude >= 0x38800000u) {
		/* At or above 2^-14, so the result is a normal half and the shift
		 * is a constant 13. Subtracting the bias difference first leaves
		 * the half exponent and the 23-bit mantissa side by side, so one
		 * rounding shift finishes it.
		 *
		 * Rounding up out of the top of the range lands on 0x7C00, which is
		 * infinity, and that is correct rather than an overflow to guard:
		 * 65520 and above rounds to infinity under ties-to-even. */
		adjusted = magnitude - 0x38000000u;
		rounded = (adjusted + 0x0FFFu + ((adjusted >> 13) & 1u)) >> 13;
		return (uint16_t)(sign | rounded);
	}

	/* Below 2^-14: a subnormal half, or zero. Every such value is an
	 * integer multiple of 2^-24, so the answer is that multiple, rounded.
	 * Scaling by 2^24 turns the question into "round this significand right
	 * by a shift", which shift_round_nearest_even answers exactly. */
	exponent = magnitude >> 23;
	if (exponent == 0)
		/* A subnormal *single* is below 2^-126, which is smaller than half
		 * of the smallest subnormal half by some seventy powers of two. It
		 * rounds to zero, and it does so whether or not DAZ is set -- which
		 * is what keeps this agreeing with the vector code. */
		return (uint16_t)sign;

	significand = 0x800000u | (magnitude & 0x7FFFFFu);
	shift = (unsigned)(126u - exponent);
	rounded = shift_round_nearest_even(significand, shift);

	/* rounded can reach 1024, which is 0x400 -- the smallest normal half.
	 * That needs no special case: the carry out of the mantissa lands in
	 * the exponent field exactly where it belongs. */
	return (uint16_t)(sign | rounded);
}

/* -- vector implementation -------------------------------------------- */

/* Four halves, in the low 64 bits, to four singles. */
static __m128i half_to_single_4(__m128i packed)
{
	const __m128i zero = _mm_setzero_si128();
	__m128i wide, sign, magnitude, mantissa, exponent, biased;
	__m128i normal, infnan, subnormal, is_max, is_zero, result;
	__m128 scaled_mantissa;

	wide = _mm_unpacklo_epi16(packed, zero);	/* zero-extend to 32 bits */

	sign = _mm_slli_epi32(_mm_and_si128(wide, _mm_set1_epi32(0x8000)), 16);
	magnitude = _mm_and_si128(wide, _mm_set1_epi32(0x7FFF));
	mantissa = _mm_and_si128(wide, _mm_set1_epi32(0x03FF));
	exponent = _mm_srli_epi32(magnitude, 10);

	/* Normal. Adding the bias difference to the exponent field before the
	 * shift means one add and one shift do the whole conversion, because
	 * the mantissa rides along untouched in the low bits. */
	biased = _mm_add_epi32(magnitude, _mm_set1_epi32(112 << 10));
	normal = _mm_slli_epi32(biased, 13);

	/* Infinity or NaN: maximum exponent, payload shifted into place. */
	infnan = _mm_or_si128(_mm_set1_epi32(0x7F800000),
	                      _mm_slli_epi32(mantissa, 13));

	/* Subnormal, and zero with it. The value is mantissa * 2^-24, and the
	 * integer-to-float conversion normalises it for free.
	 *
	 * Nothing here is denormal at any point: the input to cvtdq2ps is an
	 * integer in 0..1023 and the result is between 2^-24 and 2^-14, all
	 * comfortably normal singles. So FTZ and DAZ cannot touch it, and the
	 * multiply is by a power of two and therefore exact under any rounding
	 * mode. That is what makes this MXCSR-independent. */
	scaled_mantissa = _mm_mul_ps(_mm_cvtepi32_ps(mantissa),
	                             _mm_set1_ps(5.9604645e-08f));
	subnormal = _mm_castps_si128(scaled_mantissa);

	is_max = _mm_cmpeq_epi32(exponent, _mm_set1_epi32(31));
	is_zero = _mm_cmpeq_epi32(exponent, zero);

	result = normal;
	result = _mm_or_si128(_mm_and_si128(is_zero, subnormal),
	                      _mm_andnot_si128(is_zero, result));
	result = _mm_or_si128(_mm_and_si128(is_max, infnan),
	                      _mm_andnot_si128(is_max, result));
	return _mm_or_si128(result, sign);
}

/* Four singles to four halves, in the low 64 bits. Round to nearest even. */
static __m128i single_to_half_4(__m128i wide)
{
	__m128i sign, magnitude, adjusted, bias, normal, payload;
	__m128i is_nan, is_big, is_small, small, result;
	__m128 scaled, rounded;

	sign = _mm_and_si128(_mm_srli_epi32(wide, 16), _mm_set1_epi32(0x8000));
	magnitude = _mm_and_si128(wide, _mm_set1_epi32(0x7FFFFFFF));

	/* Normal: shift right 13 with ties to even, done in integers so that
	 * MXCSR has no say in it. */
	adjusted = _mm_sub_epi32(magnitude, _mm_set1_epi32(0x38000000));
	bias = _mm_add_epi32(_mm_set1_epi32(0x0FFF),
	                     _mm_and_si128(_mm_srli_epi32(adjusted, 13),
	                                   _mm_set1_epi32(1)));
	normal = _mm_srli_epi32(_mm_add_epi32(adjusted, bias), 13);

	/* Subnormal and zero. Scaling by 2^24 is exact -- it only moves the
	 * exponent -- and roundps takes its mode from its own immediate rather
	 * than from MXCSR, which is the property that lets it stand in for the
	 * rounding vcvtps2ph would have done. */
	scaled = _mm_mul_ps(_mm_castsi128_ps(magnitude),
	                    _mm_set1_ps(16777216.0f));
	rounded = _mm_round_ps(scaled,
	                       _MM_FROUND_TO_NEAREST_INT | _MM_FROUND_NO_EXC);
	small = _mm_cvttps_epi32(rounded);

	/* NaN payload, quiet bit forced on. */
	payload = _mm_or_si128(_mm_set1_epi32(0x7E00),
	                       _mm_and_si128(_mm_srli_epi32(magnitude, 13),
	                                     _mm_set1_epi32(0x1FF)));

	/* Signed compares are safe: magnitude has its top bit cleared, so every
	 * lane is a positive int32. */
	is_nan = _mm_cmpgt_epi32(magnitude, _mm_set1_epi32(0x7F800000));
	is_big = _mm_cmpgt_epi32(magnitude, _mm_set1_epi32(0x477FFFFF));
	is_small = _mm_cmpgt_epi32(_mm_set1_epi32(0x38800000), magnitude);

	result = normal;
	result = _mm_or_si128(_mm_and_si128(is_small, small),
	                      _mm_andnot_si128(is_small, result));
	result = _mm_or_si128(_mm_and_si128(is_big, _mm_set1_epi32(0x7C00)),
	                      _mm_andnot_si128(is_big, result));
	result = _mm_or_si128(_mm_and_si128(is_nan, payload),
	                      _mm_andnot_si128(is_nan, result));
	return _mm_or_si128(result, sign);
}

void f16c_ph2ps_8(const uint16_t *halves, uint32_t *singles)
{
	__m128i packed = _mm_loadu_si128((const __m128i *)halves);
	__m128i low = half_to_single_4(packed);
	__m128i high = half_to_single_4(_mm_unpackhi_epi64(packed, packed));

	_mm_storeu_si128((__m128i *)singles, low);
	_mm_storeu_si128((__m128i *)(singles + 4), high);
}

void f16c_ps2ph_8(const uint32_t *singles, uint16_t *halves)
{
	const __m128i *packed = (const __m128i *)singles;
	__m128i low = single_to_half_4(_mm_loadu_si128(packed));
	__m128i high = single_to_half_4(_mm_loadu_si128(packed + 1));

	/* packus_epi32 saturates a signed int32 into an unsigned int16. Every
	 * lane here is already in 0..0xFFFF, so nothing saturates and this is a
	 * pure narrowing. SSE4.1, so it is on the host. */
	_mm_storeu_si128((__m128i *)halves, _mm_packus_epi32(low, high));
}
