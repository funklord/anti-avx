/* Scalar single-precision FMA in all four sign arrangements, and from
 * memory. Built with -mfma, gcc emits each fmaf as one vfm*ss; built for
 * the host without it, the same source calls glibc's fmaf, which rounds
 * once in software -- the reference `--fma=exact` must reproduce exactly.
 * With TWO_ROUNDINGS, and -ffp-contract=off, each is the multiply and the
 * add or subtract the default lowering emits, in its order: that build is
 * the default's reference. The loop count is fixed, so it terminates. */
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define COUNT 4096

static uint32_t state = 2463534242u;

static uint32_t next(void)
{
	state ^= state << 13;
	state ^= state >> 17;
	state ^= state << 5;
	return state;
}

static float pick(void)
{
	uint32_t r = next();
	float f;
	/* exponents near zero, so products and addends meet */
	r = (r & 0x807fffff) | ((uint32_t)(118 + next() % 20) << 23);
	memcpy(&f, &r, 4);
	return f;
}

static float a[COUNT], b[COUNT], c[COUNT], out[4][COUNT];

static uint64_t hash(const float *v, int n)
{
	uint64_t h = 14695981039346656037ull;
	const unsigned char *p = (const unsigned char *)v;
	for (int i = 0; i < n * 4; i++)
		h = (h ^ p[i]) * 1099511628211ull;
	return h;
}

int main(void)
{
	for (int i = 0; i < COUNT; i++) {
		a[i] = pick();
		b[i] = pick();
		c[i] = pick();
		/* the product nearly cancels the addend, where one rounding and
		 * two part company */
		if (i & 1)
			c[i] = -(a[i] * b[i]) * (1.0f + (float)(int)(next() % 64)
			                         * 0x1p-23f);
	}
	for (int i = 0; i < COUNT; i++) {
#ifdef TWO_ROUNDINGS
		out[0][i] = a[i] * b[i] + c[i];
		out[1][i] = a[i] * b[i] - c[i];
		out[2][i] = -(a[i] * b[i]) - c[i];
		out[3][i] = c[i] - a[i] * b[i];
#else
		out[0][i] = fmaf(a[i], b[i], c[i]);
		out[1][i] = fmaf(a[i], b[i], -c[i]);
		out[2][i] = fmaf(-a[i], b[i], -c[i]);
		out[3][i] = fmaf(-a[i], b[i], c[i]);
#endif
	}
	for (int k = 0; k < 4; k++)
		printf("form %d: %016llx\n", k,
		       (unsigned long long)hash(out[k], COUNT));
	return 0;
}
