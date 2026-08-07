/* The alternating-lane FMA lowerings, and their references.
 *
 * `vfmaddsub` and `vfmsubadd` add on some lanes and subtract on others.
 * 28 sites in the target binary, all in the 231 form. They are called out
 * separately from the rest of Class F because lowering them with the plain
 * mul + add sequence is a **correctness** bug rather than the precision
 * caveat the other FMA rules carry: it computes the wrong operation for
 * half the elements, and nothing downstream notices.
 *
 * SSE3's `addsubps` subtracts on the even lanes and adds on the odd ones,
 * which is exactly VFMADDSUB and exactly the opposite of VFMSUBADD. The
 * second is turned into the first by negating the addend.
 *
 * These functions exist to be tested, not to be linked into anything. The
 * translator emits the instruction sequences directly; what is checked here
 * is that the sequence computes what the SDM says the FMA computes.
 */

#ifndef ANTI_AVX_FMADDSUB_H
#define ANTI_AVX_FMADDSUB_H

/* Each takes the two factors and the destination, which is also the addend
 * -- the 231 form, which is the only one the target binary uses. `dst` is
 * read and written. */

void fmaddsub231ps_ref(const float *src1, const float *src2, float *dst);
void fmaddsub231ps_sse(const float *src1, const float *src2, float *dst);

void fmsubadd231ps_ref(const float *src1, const float *src2, float *dst);
void fmsubadd231ps_sse(const float *src1, const float *src2, float *dst);

void fmaddsub231pd_ref(const double *src1, const double *src2, double *dst);
void fmaddsub231pd_sse(const double *src1, const double *src2, double *dst);

void fmsubadd231pd_ref(const double *src1, const double *src2, double *dst);
void fmsubadd231pd_sse(const double *src1, const double *src2, double *dst);

/* The wrong lowering, kept so a test can demonstrate that it IS wrong.
 * This is what plain Class F would emit for vfmaddsub231ps. */
void fmaddsub231ps_naive(const float *src1, const float *src2, float *dst);

#endif /* ANTI_AVX_FMADDSUB_H */
