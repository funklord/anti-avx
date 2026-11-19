/* Loads fmadll at a base other than its preferred one, from a thread of
 * its own as well as the first, and checks every result against the
 * multiply and add the default lowering computes: the two must agree bit
 * for bit. Exit 0 on agreement. Findings 386 and 387. */
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define COUNT 4096

typedef void (*fma8_fn)(float *, const float *, const float *, const float *,
                        int);

static float a[COUNT], b[COUNT], c[COUNT], out[COUNT];
static fma8_fn fma8;
static long wrong;

static DWORD WINAPI run(LPVOID unused)
{
	(void)unused;
	memset(out, 0, sizeof out);
	fma8(out, a, b, c, COUNT);
	for (int i = 0; i < COUNT; i++) {
		volatile float p = a[i] * b[i];
		float want = i & 1 ? p + c[i] : p - c[i];
		if (memcmp(&want, &out[i], 4))
			wrong++;
	}
	return 0;
}

int main(int argc, char **argv)
{
	unsigned state = 2463534242u;
	if (argc < 2)
		return 2;
	/* Reserve the preferred base so the loader has to relocate. */
	VirtualAlloc((void *)0x6a000000, 0x100000, MEM_RESERVE, PAGE_NOACCESS);
	HMODULE m = LoadLibraryA(argv[1]);
	if (!m) {
		printf("load failed %lu\n", GetLastError());
		return 3;
	}
	fma8 = (fma8_fn)(void *)GetProcAddress(m, "fma8");
	if (!fma8)
		return 4;
	for (int i = 0; i < COUNT; i++) {
		float *f[3] = {&a[i], &b[i], &c[i]};
		for (int k = 0; k < 3; k++) {
			state ^= state << 13;
			state ^= state >> 17;
			state ^= state << 5;
			unsigned bits = (state & 0x807fffff) | ((120u + state % 16) << 23);
			memcpy(f[k], &bits, 4);
		}
	}
	run(NULL);
	HANDLE t = CreateThread(NULL, 0, run, NULL, 0, NULL);
	WaitForSingleObject(t, INFINITE);
	printf("base %s, %ld wrong\n",
	       (size_t)m == 0x6a000000 ? "preferred" : "relocated", wrong);
	return wrong ? 1 : 0;
}
