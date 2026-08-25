/* Software F16C: the half-precision conversions Westmere does not have.
 *
 * `vcvtph2ps` and `vcvtps2ph` are the only instructions in the translation
 * target with no SSE equivalent of any kind (project.md, Finding 10). Every
 * other lowering rule substitutes an operation SSE already has; these need
 * an algorithm. Twelve sites, in ordinary unguarded compiler output.
 *
 * Two implementations of each direction live here on purpose:
 *
 *   *_ref   scalar, branchy, written to be read and believed. It is the
 *           oracle the vector code is checked against, not the shipped
 *           routine.
 *   *_sse   the SSE4.1 code the translator emits, four lanes at a time.
 *
 * They are compared exhaustively -- all 65,536 halves for one direction and
 * all 2^32 floats for the other -- by test/f16c_test.c.
 *
 * Note on the calling convention: this is the algorithm and its proof, in C.
 * The stub the translator plants in a PE has to follow Win64, so it will be
 * emitted rather than linked from here.
 */

#ifndef ANTI_AVX_F16C_H
#define ANTI_AVX_F16C_H

#include <stdint.h>

/* Scalar reference conversions, on raw bit patterns rather than float types
 * so that no compiler-inserted conversion can quietly round something. */
uint32_t f16c_half_to_single_ref(uint16_t half);
uint16_t f16c_single_to_half_ref(uint32_t single);

/* Vector conversions. Both take and return packed bit patterns.
 *
 * f16c_ph2ps_8: eight halves (128 bits) to eight singles (256 bits, written
 *               as two 128-bit halves) -- the shape `vcvtph2ps mem,%ymm`
 *               needs.
 * f16c_ps2ph_8: eight singles to eight halves, round to nearest even, which
 *               is what the immediate 0 in the target binary selects.
 */
void f16c_ph2ps_8(const uint16_t *halves, uint32_t *singles);
void f16c_ps2ph_8(const uint32_t *singles, uint16_t *halves);

#endif /* ANTI_AVX_F16C_H */
