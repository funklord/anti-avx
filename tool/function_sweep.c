/* Load a PE image at its preferred base, then call each function named in
 * a list through the Windows ABI on seeded inputs, printing what it
 * returned in rax and xmm0 and a hash of every buffer it could write.
 * Faults and timeouts are caught and printed rather than fatal. Buffers,
 * stack and TEB sit at fixed addresses so that a pointer compares equal
 * across runs. `function_oracle.py` builds this and runs both images under
 * qemu, so that one executor makes any difference the rewrite's. */
#define _GNU_SOURCE
#include <asm/prctl.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <ucontext.h>
#include <unistd.h>

#define BUFFER (1 << 16)
#define BUFFERS 4

uint64_t out_rax, saved_rsp;
/* Fixed addresses, the same under qemu and natively, so a pointer the code
 * stores or returns compares equal when it is the same pointer. */
#define STACK ((unsigned char *)0x20000000)
#define STACK_SIZE (1 << 20)
#define BUFFER_AT ((unsigned char *)0x30000000)
#define TEB_AT ((unsigned char *)0x38000000)
unsigned char out_xmm0[16];
void trampoline(void *call, void *a, void *b, void *c, void *d);
__asm__(
        ".text\n"
        ".globl trampoline\n"
        "trampoline:\n"
        "\tpush %rbp\n"
        "\tmov %rsp, %rbp\n"
        "\tpush %rbx\n"
        "\tpush %r12\n"
        "\tpush %r13\n"
        "\tpush %r14\n"
        "\tpush %r15\n"
        "\tmov %rsp, saved_rsp(%rip)\n"
        "\tmov $0x200ff000, %rsp\n"
        "\tmov %rdi, %r11\n"
        "\tmov %r8, %r9\n"
        "\tmov %rcx, %r8\n"
        "\tmov %rsi, %rcx\n"
        "\tcall *%r11\n"
        "\tmov %rax, out_rax(%rip)\n"
        "\tmovups %xmm0, out_xmm0(%rip)\n"
        "\tmov saved_rsp(%rip), %rsp\n"
        "\tpop %r15\n"
        "\tpop %r14\n"
        "\tpop %r13\n"
        "\tpop %r12\n"
        "\tpop %rbx\n"
        "\tpop %rbp\n"
        "\tret\n");

static uint64_t state;
static sigjmp_buf escape;
static unsigned char *buffers[BUFFERS];

static uint32_t next(void)
{
	state ^= state << 13;
	state ^= state >> 7;
	state ^= state << 17;
	return (uint32_t)state;
}

static uint64_t hash(const unsigned char *p, size_t n)
{
	uint64_t h = 1469598103934665603ULL;
	for (size_t i = 0; i < n; i++)
		h = (h ^ p[i]) * 1099511628211ULL;
	return h;
}

/* mode 0: small floats; 1: raw bits; 2: pointers into the buffers
 * interleaved with small floats, so pointer-chasing code gets somewhere. */
static void fill(unsigned char *p, int mode)
{
	for (size_t i = 0; i < BUFFER / 8; i++) {
		uint32_t r = next(), s = next();
		uint64_t *q = (uint64_t *)p + i;
		if (mode == 1) {
			*q = ((uint64_t)r << 32) | s;
		} else if (mode == 2 && (r & 3) == 0) {
			*q = (uint64_t)(buffers[s % BUFFERS] + BUFFER / 4
			                + (r >> 2) % (BUFFER / 2) / 16 * 16);
		} else {
			float f[2] = { ((int32_t)r % 2000) / 100.0f,
			               ((int32_t)s % 2000) / 100.0f };
			memcpy(q, f, 8);
		}
	}
}

static uint64_t fault_rip, fault_address;

static void caught(int sig, siginfo_t *info, void *context)
{
	ucontext_t *uc = context;
	fault_rip = uc->uc_mcontext.gregs[REG_RIP];
	fault_address = (uint64_t)info->si_addr;
	siglongjmp(escape, sig);
}

static void load(const char *path)
{
	FILE *file = fopen(path, "rb");
	if (!file)
		exit(2);
	fseek(file, 0, SEEK_END);
	long size = ftell(file);
	unsigned char *raw = malloc(size);
	fseek(file, 0, SEEK_SET);
	if (fread(raw, 1, size, file) != (size_t)size)
		exit(2);
	fclose(file);
	uint32_t pe = *(uint32_t *)(raw + 0x3c);
	uint16_t sections = *(uint16_t *)(raw + pe + 6);
	uint16_t optional = *(uint16_t *)(raw + pe + 20);
	uint64_t base = *(uint64_t *)(raw + pe + 24 + 24);
	uint32_t image = *(uint32_t *)(raw + pe + 24 + 56);
	unsigned char *at = mmap((void *)base, image,
	                         PROT_READ | PROT_WRITE | PROT_EXEC,
	                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (at != (void *)base) {
		perror("mmap");
		exit(2);
	}
	memcpy(at, raw, 0x1000);
	for (int i = 0; i < sections; i++) {
		unsigned char *s = raw + pe + 24 + optional + 40 * i;
		uint32_t va = *(uint32_t *)(s + 12);
		uint32_t length = *(uint32_t *)(s + 16);
		uint32_t offset = *(uint32_t *)(s + 20);
		uint32_t virtual_size = *(uint32_t *)(s + 8);
		if (length > virtual_size && virtual_size)
			length = virtual_size;
		memcpy(at + va, raw + offset, length);
	}
	free(raw);
}

int main(int argc, char **argv)
{
	if (argc < 5) {
		fprintf(stderr, "usage: sweep image list trials milliseconds\n");
		return 2;
	}
	load(argv[1]);
	uint64_t *teb = mmap(TEB_AT, 1 << 20, PROT_READ | PROT_WRITE,
	                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	if (mmap(STACK, STACK_SIZE, PROT_READ | PROT_WRITE,
	         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) != STACK)
		return 2;
	uint64_t *slots = teb + (0x80000 / 8);
	for (int i = 0; i < 64; i++)
		slots[i] = (uint64_t)teb + 0x90000 + i * 0x1000;
	teb[0x30 / 8] = (uint64_t)teb;
	teb[0x58 / 8] = (uint64_t)slots;
	if (syscall(SYS_arch_prctl, ARCH_SET_GS, teb) != 0) {
		perror("arch_prctl");
		return 2;
	}
	int trials = atoi(argv[3]);
	long limit = atol(argv[4]);
	for (int i = 0; i < BUFFERS; i++)
		buffers[i] = mmap(BUFFER_AT + i * 2 * BUFFER, BUFFER,
		                  PROT_READ | PROT_WRITE,
		                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
	/* The handler runs on its own stack: a fault may be a stack fault. */
	stack_t alternate = { .ss_sp = malloc(1 << 16), .ss_size = 1 << 16 };
	sigaltstack(&alternate, NULL);
	struct sigaction action = { .sa_sigaction = caught,
	                            .sa_flags = SA_ONSTACK | SA_NODEFER
	                                        | SA_SIGINFO };
	sigaction(SIGSEGV, &action, NULL);
	sigaction(SIGBUS, &action, NULL);
	sigaction(SIGFPE, &action, NULL);
	sigaction(SIGILL, &action, NULL);
	sigaction(SIGALRM, &action, NULL);
	FILE *list = fopen(argv[2], "r");
	char line[64];
	while (list && fgets(line, sizeof line, list)) {
		uint64_t address = strtoull(line, NULL, 16);
		for (int trial = 0; trial < trials; trial++) {
			state = 0x9e3779b97f4a7c15ULL + trial * 7919 + address;
			for (int i = 0; i < BUFFERS; i++)
				fill(buffers[i], trial % 3);
			memset(STACK, 0, STACK_SIZE);
			struct itimerval timer = {
				.it_value = { limit / 1000, limit % 1000 * 1000 } };
			int sig = sigsetjmp(escape, 1);
			if (sig == 0) {
				setitimer(ITIMER_REAL, &timer, NULL);
				trampoline((void *)address,
				           buffers[0] + BUFFER / 2,
				           buffers[1] + BUFFER / 2,
				           buffers[2] + BUFFER / 2,
				           buffers[3] + BUFFER / 2);
			}
			struct itimerval off = { 0 };
			setitimer(ITIMER_REAL, &off, NULL);
			printf("%llx %d", (unsigned long long)address, trial);
			if (sig) {
				if (sig == SIGALRM)
					printf(" timeout\n");
				else
					printf(" fault %d rip %llx at %llx\n", sig,
					       (unsigned long long)fault_rip,
					       (unsigned long long)fault_address);
				continue;
			}
			printf(" %016llx %016llx%016llx",
			       (unsigned long long)out_rax,
			       *(unsigned long long *)(out_xmm0 + 8),
			       *(unsigned long long *)out_xmm0);
			for (int i = 0; i < BUFFERS; i++)
				printf(" %016llx",
				       (unsigned long long)hash(buffers[i], BUFFER));
			printf("\n");
		}
		fflush(stdout);
	}
	return 0;
}
