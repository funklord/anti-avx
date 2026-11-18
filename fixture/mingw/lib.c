/* An AVX2 DLL for `make check-mingw`: a vectorised loop around a switch,
 * called from an SSE host that reserves the DLL's preferred base first, so
 * the rewritten image is loaded relocated. Finding 382. */
#include <math.h>
__declspec(dllexport) double kernel(const float *x, const int *v, int n)
{
	double sum = 0;
	long long isum = 0;
	for (int i = 0; i < n; i++) {
		float y = x[i] * 1.25f + 0.5f;
		switch (v[i] & 7) {
		case 0: y = sqrtf(fabsf(y)); break;
		case 1: y = y * y; break;
		case 2: y = floorf(y); break;
		case 3: y = y / (1.0f + fabsf(y)); break;
		case 4: y = -y; break;
		case 5: y = fminf(y, 0.75f); break;
		case 6: y = fmaxf(y, 0.25f); break;
		default: y = y - 1.0f; break;
		}
		sum += y;
		isum += v[i] > 0 ? v[i] : -v[i];
	}
	return sum + (double)isum;
}
