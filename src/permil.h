/* The vpermilps variable-control helper.
 *
 * 23 of the 73 vpermilps sites use a control *vector* rather than an
 * immediate. The other 50 are plain shufps and need no helper at all
 * (project.md, Class H), which is why the count that matters here is 23 and
 * not 73.
 *
 * What the instruction does, per the SDM, for each 32-bit element i:
 *
 *     DEST[i] := SRC1[ SRC2[i][1:0] ]
 *
 * so element i of the result is whichever element of the *data* operand the
 * low two bits of element i of the *control* operand select. Bits 31:2 of
 * each control element are ignored, which is a real part of the contract
 * and not a detail -- the compiler emits controls with rubbish up there.
 *
 * It is an IN-LANE permute. The 256-bit form permutes within each 128-bit
 * half independently, so it is exactly two of these and never a cross-lane
 * shuffle. That is what makes it cheap; vperm2f128 and vpermq are the
 * cross-lane ones and they are a different problem.
 *
 * A note on operand order, because it is the easy thing to get backwards.
 * objdump prints the variable form as
 *
 *     vpermilps %xmm2,%xmm3,%xmm3        control, data, dst
 *
 * where the VEX vvvv field holds the DATA and the r/m field holds the
 * CONTROL. Decoded from a real site to be sure: c4 e2 61 0c da has
 * vvvv = 3 and rm = 2, and the SDM reads "permute values in xmm2 using
 * controls from xmm3/m128", so the middle operand is the data.
 */

#ifndef ANTI_AVX_PERMIL_H
#define ANTI_AVX_PERMIL_H

#include <stdint.h>

/* Four 32-bit elements each. `dst` may alias `data` or `control`. */
void permilps_var_ref(const uint32_t *data, const uint32_t *control,
                      uint32_t *dst);
void permilps_var_sse(const uint32_t *data, const uint32_t *control,
                      uint32_t *dst);

/* The 256-bit form: eight elements, permuted within each 128-bit half. */
void permilps_var256_ref(const uint32_t *data, const uint32_t *control,
                         uint32_t *dst);
void permilps_var256_sse(const uint32_t *data, const uint32_t *control,
                         uint32_t *dst);

#endif /* ANTI_AVX_PERMIL_H */
