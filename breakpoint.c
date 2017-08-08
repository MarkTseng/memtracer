#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "breakpoint.h"
#include "ptrace_utils.h"
#include "symtab.h"
#include "minigdb.h"
#include "memblock.h"
#define MAX_BREAKPINT_NUM (7)
struct breakpoint_s g_breakpoints[MAX_BREAKPINT_NUM];

static int bph_malloc(uintptr_t pointer, uintptr_t size, uintptr_t none)
{
	//log_debug("-- malloc pointer:%lx, size: %#lx\n", pointer, size);
	memblock_new(pointer, size);
	return 0;
}

#if 0
static int bph_new(uintptr_t pointer, uintptr_t size, uintptr_t none)
{
	//log_debug("-- new size:%ld ret:%lx\n", size, pointer);

	return 0;
}

static int bph_newa(uintptr_t pointer, uintptr_t size, uintptr_t none)
{
	//log_debug("-- newa size:%ld ret:%lx\n", size, pointer);

	return 0;
}

static int bph_delete(uintptr_t none1, uintptr_t pointer, uintptr_t none2)
{
	//log_debug("-- delete point:%lx\n", pointer);

	return 0;
}

static int bph_deletea(uintptr_t none1, uintptr_t pointer, uintptr_t none2)
{
	//log_debug("-- deletea point:%lx\n", pointer);

	return 0;
}
#endif

static int bph_dlopen(uintptr_t none1, uintptr_t pointer, uintptr_t none2)
{
	//log_debug("-- dlopen ret:%#x, p1:%#x, p2:%#x\n", none1, pointer, none2);

	return 0;
}

static int bph_free(uintptr_t none1, uintptr_t pointer, uintptr_t none2)
{
	//log_debug("-- free point:%lx\n", pointer);
	memblock_delete(memblock_search(pointer));
	return 0;
}

static int bph_realloc(uintptr_t new_pointer, uintptr_t old_pointer, uintptr_t size)
{
	//log_debug("-- realloc pointer:%lx->%lx size:%ld\n", old_pointer, new_pointer, size);
    if (new_pointer == old_pointer) {
        memblock_update_size(memblock_search(old_pointer), size);
    } else {
        memblock_delete(memblock_search(old_pointer));
        memblock_new(new_pointer, size);
    }

	return 0;
}

static int bph_calloc(uintptr_t pointer, uintptr_t nmemb, uintptr_t size)
{
	//log_debug("-- calloc pointer:%lx nmemb:%ld size:%ld\n", pointer, nmemb, size);
	memblock_new(pointer, nmemb * size);
	return 0;
}

static int bph_mmap(uintptr_t ret_map_addr, uintptr_t none1, uintptr_t length)
{
	log_debug("-- mmap addr:%#x, length:%#x", ret_map_addr, length);

	return 0;
}

static int bph_munmap(uintptr_t none1, uintptr_t unmap_addr, uintptr_t length)
{
	log_debug("-- munmap addr:%#x, length:%#x", unmap_addr, length);

	return 0;
}

static void do_breakpoint_init(pid_t pid, struct breakpoint_s *bp,
		const char *name, bp_handler_f handler)
{
	bp->name = name;
	bp->handler = handler;
	bp->entry_address = symtab_by_name(name);
	if (bp->entry_address == 0) {
		fprintf(stderr, "not found api: %s\n", name);
	}

	/* read original code */
	//bp->entry_code = ptrace_get_data(pid, bp->entry_address);
	bp->entry_code = setbreakpoint(pid, bp->entry_address);
	//bp->entry_address &= ~0x1;
    printf("symbol: %s,  entry_code: %#x, entry_address: %#x\n", bp->name, bp->entry_code, bp->entry_address);

	/* write the trap instruction 'int 3' into the address */
	//ptrace_set_int3(pid, bp->entry_address, bp->entry_code);
}

void breakpoint_init(pid_t pid)
{
	do_breakpoint_init(pid, &g_breakpoints[0], "malloc", bph_malloc);
	do_breakpoint_init(pid, &g_breakpoints[1], "free", bph_free);
	do_breakpoint_init(pid, &g_breakpoints[2], "realloc", bph_realloc);
	do_breakpoint_init(pid, &g_breakpoints[3], "calloc", bph_calloc);
	do_breakpoint_init(pid, &g_breakpoints[4], "dlopen", bph_dlopen);
	do_breakpoint_init(pid, &g_breakpoints[5], "mmap", bph_mmap);
	do_breakpoint_init(pid, &g_breakpoints[6], "munmap", bph_munmap);
#if 0
	do_breakpoint_init(pid, &g_breakpoints[7], "_Znwj", bph_new);
	do_breakpoint_init(pid, &g_breakpoints[8], "_Znaj", bph_newa);
	do_breakpoint_init(pid, &g_breakpoints[9], "_ZdlPv", bph_delete);
	do_breakpoint_init(pid, &g_breakpoints[10], "_ZdaPv", bph_deletea);
#endif
}

void breakpoint_cleanup(pid_t pid)
{
	int i;
	for (i = 0; i < MAX_BREAKPINT_NUM; i++) {
		struct breakpoint_s *bp = &g_breakpoints[i];
		ptrace_set_data(pid, bp->entry_address, bp->entry_code);
	}
}

struct breakpoint_s *breakpoint_by_entry(uintptr_t address)
{
	int i;
	for (i = 0; i < MAX_BREAKPINT_NUM; i++) {
		if (address == g_breakpoints[i].entry_address) {
			return &g_breakpoints[i];
		}
	}
	return NULL;
}

void breakpoint_clear_by_entry(uintptr_t address)
{
	int i;
	for (i = 0; i < MAX_BREAKPINT_NUM; i++) {
		if (address == g_breakpoints[i].entry_address) {
			memset(&g_breakpoints[i],0,sizeof(struct breakpoint_s));
		}
	}
}
