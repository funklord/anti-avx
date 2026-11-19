/* Scalar single-precision FMA in all four sign arrangements, and from
 * memory. Built with -mfma, gcc emits each fmaf as one vfm*ss; built for
 * the host without it, the same source calls glibc's fmaf, which rounds
 * once in software -- the reference `--fma=exact` must reproduce exactly.
 * With TWO_ROUNDINGS, and -ffp-contract=off, each is the multiply and the
 * add or subtract the default lowering emits, in its order: that build is
 * the default's reference. The loop count is fixed, so it terminates.
 *
 * Forms 4 to 6 are packed: with -mfma they are the builtins, so gcc emits
 * vfmadd*ps and vfmaddsub*ps on 128-bit vectors whatever it vectorises;
 * without it each lane is the scalar reference above. maddsub subtracts
 * on the even lanes. With WIDE, forms 7 to 9 are the same three on
 * 256-bit vectors, which the rewriter lowers as a span: the low half in
 * the register, the upper half in a slot, and forms 10 to 17 are spelled
 * in asm, so the orders and the register-only shape Starfield uses are
 * each pinned rather than left to gcc. */
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

static float a[COUNT], b[COUNT], c[COUNT], out[18][COUNT];

typedef float v4 __attribute__((vector_size(16)));
typedef float v8 __attribute__((vector_size(32)));

#ifdef WIDE
#define FORMS 18
#else
#define FORMS 7
#endif

/* One lane of a packed form, the way the host builds compute it. */
static float lane(float x, float y, float z)
{
#ifdef TWO_ROUNDINGS
	return x * y + z;
#else
	return fmaf(x, y, z);
#endif
}

static void packed(int i)
{
	v4 x, y, z, r[3];
	memcpy(&x, &a[i], 16);
	memcpy(&y, &b[i], 16);
	memcpy(&z, &c[i], 16);
#if defined(__FMA__)
	r[0] = __builtin_ia32_vfmaddps(x, y, z);
	r[1] = __builtin_ia32_vfmaddsubps(x, y, z);
	r[2] = __builtin_ia32_vfmaddps(-x, y, z);
#else
	for (int k = 0; k < 4; k++) {
		r[0][k] = lane(x[k], y[k], z[k]);
		r[1][k] = lane(x[k], y[k], k & 1 ? z[k] : -z[k]);
		r[2][k] = lane(-x[k], y[k], z[k]);
	}
#endif
	for (int f = 0; f < 3; f++)
		memcpy(&out[4 + f][i], &r[f], 16);
}

#ifdef WIDE
static void wide(int i)
{
	v8 x, y, z, r[3];
	memcpy(&x, &a[i], 32);
	memcpy(&y, &b[i], 32);
	memcpy(&z, &c[i], 32);
#if defined(__FMA__)
	r[0] = __builtin_ia32_vfmaddps256(x, y, z);
	r[1] = __builtin_ia32_vfmaddsubps256(x, y, z);
	r[2] = __builtin_ia32_vfmaddps256(-x, y, z);
#else
	for (int k = 0; k < 8; k++) {
		r[0][k] = lane(x[k], y[k], z[k]);
		r[1][k] = lane(x[k], y[k], k & 1 ? z[k] : -z[k]);
		r[2][k] = lane(-x[k], y[k], z[k]);
	}
#endif
	for (int f = 0; f < 3; f++)
		memcpy(&out[7 + f][i], &r[f], 32);
}

/* d = s1 * d + s2 and the rest, per the SDM's 132/213/231, with the
 * subtracting lanes of maddsub even and of msubadd odd. `sub` says which
 * lanes subtract the addend: 0 none, 0xff all, 0x55 even, 0xaa odd. */
#ifdef __FMA__
#define FORM(text, x, y, z, neg, sub, D, S1, S2)	\
	asm(text : [d] "+x"(D) : [s1] "x"(S1), [s2] "x"(S2));
#define FORM_MEM(text, x, y, z, neg, sub, D, S1, M)	\
	asm(text : [d] "+x"(D) : [s1] "x"(S1), [m] "m"(M));
#else
#define FORM(text, x, y, z, neg, sub, D, S1, S2)	\
	for (int k = 0; k < 8; k++)			\
		D[k] = ref(x[k], y[k], z[k], neg, sub, k);
#define FORM_MEM FORM

static float ref(float x, float y, float z, int neg, int sub, int k)
{
	return lane(neg ? -x : x, y, (sub >> k) & 1 ? -z : z);
}
#endif

static void spelled(int i)
{
	v8 a8, b8, c8, d, n8;
	memcpy(&a8, &a[i], 32);
	memcpy(&b8, &b[i], 32);
	memcpy(&c8, &c[i], 32);
	n8 = -c8;
	/* 213: d = s1*d + s2 */
	d = b8;
	FORM("vfmadd213ps %[s2], %[s1], %[d]", a8, b8, c8, 0, 0,
	     d, a8, c8)
	memcpy(&out[10][i], &d, 32);
	/* 231: d = s1*s2 + d */
	d = c8;
	FORM("vfmadd231ps %[s2], %[s1], %[d]", a8, b8, c8, 0, 0,
	     d, a8, b8)
	memcpy(&out[11][i], &d, 32);
	/* 132: d = d*s2 - s1, s1 negated so that it cancels */
	d = a8;
	FORM("vfmsub132ps %[s2], %[s1], %[d]", a8, b8, n8, 0, 0xff,
	     d, n8, b8)
	memcpy(&out[12][i], &d, 32);
	/* 213: d = -(s1*d) + s2 */
	d = b8;
	FORM("vfnmadd213ps %[s2], %[s1], %[d]", a8, b8, n8, 1, 0,
	     d, a8, n8)
	memcpy(&out[13][i], &d, 32);
	/* 231, alternating */
	d = c8;
	FORM("vfmaddsub231ps %[s2], %[s1], %[d]", a8, b8, c8, 0, 0x55,
	     d, a8, b8)
	memcpy(&out[14][i], &d, 32);
	d = b8;
	FORM("vfmsubadd213ps %[s2], %[s1], %[d]", a8, b8, c8, 0, 0xaa,
	     d, a8, c8)
	memcpy(&out[15][i], &d, 32);
	/* and against memory: 231 with s2 in memory, 213 with the addend */
	d = c8;
	FORM_MEM("vfmsubadd231ps %[m], %[s1], %[d]", a8, b8, c8, 0, 0xaa,
	         d, a8, *(const v8 *)&b[i])
	memcpy(&out[16][i], &d, 32);
	d = b8;
	FORM_MEM("vfmadd213ps %[m], %[s1], %[d]", a8, b8, c8, 0, 0,
	         d, a8, *(const v8 *)&c[i])
	memcpy(&out[17][i], &d, 32);
}
#endif

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
	for (int i = 0; i < COUNT; i += 4)
		packed(i);
#ifdef WIDE
	for (int i = 0; i < COUNT; i += 8) {
		wide(i);
		spelled(i);
	}
#endif
	for (int k = 0; k < FORMS; k++)
		printf("form %d: %016llx\n", k,
		       (unsigned long long)hash(out[k], COUNT));
	return 0;
}
