/* The vpermd cross-lane helper.
 *
 * vpermd is the one genuinely hard permute in the target binary: eight
 * 32-bit elements, a control *vector* rather than an immediate, and a free
 * choice of any source element for any destination element. Unlike
 * vpermilps it crosses the 128-bit lane boundary, so neither half of the
 * result can be computed from one half of the input.
 *
 *     DEST[i] := SRC2[ SRC1[i][2:0] ]        for i in 0..7
 *
 * Bits 31:3 of each index are ignored, exactly as vpermilps ignores bits
 * 31:2 of its control.
 *
 * ** Operand order is the opposite of vpermilps, and that is not a typo. **
 *
 *     vpermilps %xmm2,%xmm3,%xmm3     control, data, dst   (r/m = control)
 *     vpermd    %ymm2,%ymm9,%ymm0     data, indices, dst   (r/m = data)
 *
 * The SDM sentences are what settle it: VPERMILPS "permutes values in xmm2
 * using controls from xmm3/m128", so the vvvv operand is the data; VPERMD
 * "permutes doublewords in ymm3/m256 using indices in ymm2", so the vvvv
 * operand is the indices. Decoded from real sites to be sure --
 * c4 e2 61 0c da has vvvv = 3, rm = 2 for the vpermilps, and
 * c4 e2 35 36 c2 has vvvv = 9, rm = 2 for the vpermd.
 *
 * A reader who carries the vpermilps convention across gets a permute of
 * the index vector by the data, which is nonsense that still runs.
 *
 * ** Every vpermd site in the target is inside dispatched code. ** All six
 * lie between 0x1434d847d and 0x1434d8f1d, in the CPUID-gated checksum
 * library of Finding 5, so none of them executes on a host without AVX2.
 * This helper is therefore insurance rather than a hot path -- but it is
 * written anyway, because "unreachable" is an argument about control flow
 * and being correct is not.
 */

#ifndef ANTI_AVX_PERMD_H
#define ANTI_AVX_PERMD_H

#include <stdint.h>

/* Eight 32-bit elements. `data` and `indices` are 256-bit values held as
 * two 128-bit halves laid out contiguously, which is how the Y-class
 * representation keeps them. `dst` may alias either input. */
void permd_ref(const uint32_t *data, const uint32_t *indices, uint32_t *dst);
void permd_sse(const uint32_t *data, const uint32_t *indices, uint32_t *dst);

#endif /* ANTI_AVX_PERMD_H */
