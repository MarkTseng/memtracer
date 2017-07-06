/*
 * memory allocation/free API breakpoints
 *
 * Author: Wu Bingzheng
 *   Date: 2016-5
 */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "callstack.h"
#include "memblock.h"
#include "breakpoint.h"
#include "ptr_backtrace.h"
#include "ptrace_utils.h"
#include "symtab.h"
#include "minigdb.h"

struct breakpoint_s g_breakpoints[4];

static int bph_malloc(uintptr_t pointer, uintptr_t size, uintptr_t none)
{
	log_debug("-- malloc size:%ld ret:%lx\n", size, pointer);

	return 0;
}

static int bph_free(uintptr_t none1, uintptr_t pointer, uintptr_t none2)
{
	log_debug("-- free point:%lx\n", pointer);

	return 0;
}

static int bph_realloc(uintptr_t new_pointer, uintptr_t old_pointer, uintptr_t size)
{
	log_debug("-- realloc pointer:%lx->%lx size:%ld\n", old_pointer, new_pointer, size);

	return 0;
}

static int bph_calloc(uintptr_t pointer, uintptr_t nmemb, uintptr_t size)
{
	log_debug("-- calloc pointer:%lx nmemb:%ld size:%ld\n", pointer, nmemb, size);

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
		exit(3);
	}

	/* read original code */
	bp->entry_code = ptrace_get_data(pid, bp->entry_address);
    printf("[%s][%d] symbol: %s,  entry_code: %#x, entry_address: %#x \n", __func__, __LINE__, bp->name, bp->entry_code, bp->entry_address);

	/* write the trap instruction 'int 3' into the address */
	ptrace_set_int3(pid, bp->entry_address, bp->entry_code);
}

void breakpoint_init(pid_t pid)
{
	do_breakpoint_init(pid, &g_breakpoints[0], "malloc", bph_malloc);
	do_breakpoint_init(pid, &g_breakpoints[1], "free", bph_free);
	do_breakpoint_init(pid, &g_breakpoints[2], "realloc", bph_realloc);
	do_breakpoint_init(pid, &g_breakpoints[3], "calloc", bph_calloc);
}

void breakpoint_cleanup(pid_t pid)
{
	int i;
	for (i = 0; i < 4; i++) {
		struct breakpoint_s *bp = &g_breakpoints[i];
		ptrace_set_data(pid, bp->entry_address, bp->entry_code);
	}
}

struct breakpoint_s *breakpoint_by_entry(uintptr_t address)
{
	int i;
	for (i = 0; i < 4; i++) {
		if (address == g_breakpoints[i].entry_address) {
			return &g_breakpoints[i];
		}
	}
	return NULL;
}

void breakpoint_clear_by_entry(uintptr_t address)
{
	int i;
	for (i = 0; i < 4; i++) {
		if (address == g_breakpoints[i].entry_address) {
			memset(&g_breakpoints[i],0,sizeof(struct breakpoint_s));
		}
	}
}
