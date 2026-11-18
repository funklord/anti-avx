/* Loads the DLL named on the command line at a base other than its
 * preferred one and prints what its kernel returns. Finding 382. */
#include <stdio.h>
#include <windows.h>
typedef double (*kernel_t)(const float *, const int *, int);
int main(int argc, char **argv)
{
	/* Reserve the DLL's preferred base so the loader has to relocate it. */
	VirtualAlloc((void *)0x6a000000, 0x100000, MEM_RESERVE, PAGE_NOACCESS);
	HMODULE m = LoadLibraryA(argv[1]);
	if (!m) {
		printf("load failed\n");
		return 2;
	}
	kernel_t k = (kernel_t)GetProcAddress(m, "kernel");
	static float x[1000];
	static int v[1000];
	unsigned s = 7;
	for (int i = 0; i < 1000; i++) {
		s = s * 1103515245u + 12345u;
		x[i] = (s >> 8) % 1000 / 37.0f - 10;
		v[i] = (int)(s >> 4) - (1 << 27);
	}
	printf("base %s %a\n",
	       (size_t)m == 0x6a000000 ? "preferred" : "relocated",
	       k(x, v, 1000));
	return 0;
}
