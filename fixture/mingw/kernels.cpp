// Real compiler output for the rewriter, where every other fixture is
// assembled by hand: float, double and integer loops gcc vectorises at -O3,
// switches, qsort and std::sort callbacks, and a C++ exception thrown from
// AVX code and caught two frames up. Every result is printed in %a, so an
// SSE build of the same source is an exact oracle. `make check-mingw`.
// Finding 382.
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <vector>

static unsigned seed = 12345;
static unsigned next_random() { seed = seed * 1103515245u + 12345u; return seed >> 8; }

__attribute__((noinline)) static void saxpy(float *y, const float *x, float a, int n)
{
	for (int i = 0; i < n; i++)
		y[i] = a * x[i] + y[i];
}

__attribute__((noinline)) static double dot(const double *a, const double *b, int n)
{
	double sum = 0;
	for (int i = 0; i < n; i++)
		sum += a[i] * b[i];
	return sum;
}

__attribute__((noinline)) static void matmul(float *c, const float *a, const float *b, int n)
{
	for (int i = 0; i < n; i++)
		for (int j = 0; j < n; j++) {
			float s = 0;
			for (int k = 0; k < n; k++)
				s += a[i * n + k] * b[k * n + j];
			c[i * n + j] = s;
		}
}

__attribute__((noinline)) static unsigned histogram(const unsigned char *p, int n, unsigned *h)
{
	memset(h, 0, 256 * sizeof *h);
	for (int i = 0; i < n; i++)
		h[p[i]]++;
	unsigned x = 0;
	for (int i = 0; i < 256; i++)
		x = x * 31 + h[i];
	return x;
}

__attribute__((noinline)) static void int_kernel(int *out, const int *a, const int *b, int n)
{
	for (int i = 0; i < n; i++) {
		int v = a[i] * 3 - (b[i] >> 2);
		out[i] = v < 0 ? -v : v;
		out[i] = std::max(out[i], b[i] & 1023);
	}
}

__attribute__((noinline)) static float shade(int kind, float x)
{
	switch (kind & 7) {
	case 0: return std::sqrt(x + 1.0f);
	case 1: return x * x - 0.5f;
	case 2: return std::floor(x * 3.25f);
	case 3: return x / (1.0f + std::fabs(x));
	case 4: return (float)(int)(x * 100.0f) / 100.0f;
	case 5: return std::min(x, 0.75f);
	case 6: return std::max(-x, 0.25f);
	default: return (float)std::sqrt((double)x * 2.0 + 3.0);
	}
}

static int compare_double(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;
	return x < y ? -1 : x > y;
}

struct overflow : std::runtime_error {
	float value;
	explicit overflow(float v) : std::runtime_error("overflow"), value(v) {}
};

__attribute__((noinline)) static float accumulate(const float *x, int n, float limit)
{
	float s = 0;
	for (int i = 0; i < n; i++) {
		s = s * 0.5f + x[i] * 1.5f;
		if (s > limit)
			throw overflow(s);
	}
	return s;
}

__attribute__((noinline)) static float guarded(const float *x, int n, float limit)
{
	std::vector<float> scratch(x, x + n);
	for (float &v : scratch)
		v = v * 2.0f + 1.0f;
	return accumulate(scratch.data(), n, limit) + scratch[0];
}

int main()
{
	enum { N = 1000, M = 24 };
	std::vector<float> x(N), y(N);
	std::vector<double> a(N), b(N);
	for (int i = 0; i < N; i++) {
		x[i] = (next_random() % 10000) / 997.0f;
		y[i] = (next_random() % 10000) / 113.0f;
		a[i] = (next_random() % 100000) / 7919.0;
		b[i] = (next_random() % 100000) / 104729.0;
	}
	saxpy(y.data(), x.data(), 1.75f, N);
	float ysum = 0;
	for (float v : y)
		ysum += v;
	printf("saxpy %a\n", ysum);
	printf("dot %a\n", dot(a.data(), b.data(), N));

	std::vector<float> ma(M * M), mb(M * M), mc(M * M);
	for (int i = 0; i < M * M; i++) {
		ma[i] = (next_random() % 1000) / 37.0f;
		mb[i] = (next_random() % 1000) / 53.0f;
	}
	matmul(mc.data(), ma.data(), mb.data(), M);
	float trace = 0;
	for (int i = 0; i < M; i++)
		trace += mc[i * M + i];
	printf("matmul %a %a\n", trace, mc[M * M - 1]);

	std::vector<unsigned char> bytes(4096);
	for (auto &c : bytes)
		c = next_random();
	unsigned h[256];
	printf("histogram %08x\n", histogram(bytes.data(), (int)bytes.size(), h));

	std::vector<int> ia(N), ib(N), io(N);
	for (int i = 0; i < N; i++) {
		ia[i] = (int)next_random() - (1 << 23);
		ib[i] = (int)next_random();
	}
	int_kernel(io.data(), ia.data(), ib.data(), N);
	long long isum = 0;
	for (int v : io)
		isum += v;
	printf("ints %lld\n", isum);

	float shaded = 0;
	for (int i = 0; i < N; i++)
		shaded += shade(i, x[i] - 5.0f);
	printf("shade %a\n", shaded);

	std::vector<double> sorted(a);
	qsort(sorted.data(), sorted.size(), sizeof(double), compare_double);
	std::vector<float> fsorted(x);
	std::sort(fsorted.begin(), fsorted.end(), [](float p, float q) { return p * 1.5f > q * 1.5f; });
	printf("sort %a %a %a\n", sorted[0], sorted[N / 2], fsorted[N / 3]);

	int caught = 0;
	float total = 0;
	for (int t = 0; t < 20; t++) {
		try {
			total += guarded(x.data() + t * 10, 40, 6.0f + t * 0.75f);
		} catch (const overflow &e) {
			caught++;
			total += e.value;
		}
	}
	printf("exceptions %d %a\n", caught, total);
	return 0;
}
