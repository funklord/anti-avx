/* A 256-bit FMA loop in a DLL built with no C runtime, for `make
 * check-mingw`: its rewrite stands a per-thread block up, so the index
 * callback must run in an image whose TLS directory the rewrite either
 * added (no EMPTY_TLS) or had to give a callback array of its own (with
 * it). The host loads it relocated. Findings 386 and 387. */
#include <windows.h>

typedef float v8 __attribute__((vector_size(32)));

__declspec(dllexport) void fma8(float *out, const float *a, const float *b,
                                const float *c, int n)
{
	for (int i = 0; i + 8 <= n; i += 8) {
		v8 x, y, z;
		__builtin_memcpy(&x, a + i, 32);
		__builtin_memcpy(&y, b + i, 32);
		__builtin_memcpy(&z, c + i, 32);
		v8 r = __builtin_ia32_vfmaddsubps256(x, y, z);
		__builtin_memcpy(out + i, &r, 32);
	}
}

BOOL WINAPI DllMainCRTStartup(HINSTANCE h, DWORD why, LPVOID r)
{
	(void)h; (void)why; (void)r;
	return TRUE;
}

/* One absolute address, so the image carries base relocations as every
 * real one does. */
__declspec(dllexport) void *anchor = (void *)&DllMainCRTStartup;

#ifdef EMPTY_TLS
/* A TLS directory whose callback array is empty: MSVC's shape when
 * nothing in the image registers a TLS callback, as in nvngx_dlssg.dll. */
ULONG _tls_index;
char _tls_start __attribute__((section(".tls")));
char _tls_end __attribute__((section(".tls$ZZZ")));
PIMAGE_TLS_CALLBACK __xl_a[2] __attribute__((section(".CRT$XLA"))) = {0, 0};
const IMAGE_TLS_DIRECTORY64 _tls_used = {
	(ULONGLONG)&_tls_start, (ULONGLONG)&_tls_end, (ULONGLONG)&_tls_index,
	(ULONGLONG)__xl_a, 0, 0
};
#endif
