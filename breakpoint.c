#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "breakpoint.h"
#include "ptrace_utils.h"
#include "symtab.h"
#include "minigdb.h"
#include "memblock.h"
#define MAX_BREAKPINT_NUM (11)
struct breakpoint_s g_breakpoints[MAX_BREAKPINT_NUM];
static int addCnt1 = 0;
static int delCnt1 = 0;
static int bph_malloc(int pid, uintptr_t pointer, uintptr_t size, uintptr_t none)
{
	log_debug("[%d] malloc [%d] pointer:%#lx, size: %#lx\n", pid, addCnt1,pointer, size);
	memblock_new(pointer, size, pid);
	addCnt1++;
   	//do_backtrace(pid, 0, 1);
	return 0;
}

#if 1
static int bph_new(int pid, uintptr_t pointer, uintptr_t size, uintptr_t none)
{
	log_debug("[%d] new pointer:%#lx size:%ld\n", pid, pointer, size);
	addCnt1++;
	memblock_new(pointer, size, pid);
   	//do_backtrace(pid, 0, 1);

	return 0;
}

static int bph_newa(int pid, uintptr_t pointer, uintptr_t size, uintptr_t none)
{
	log_debug("[%d] newa pointer:%#lx size:%ld\n", pid, pointer, size);
	addCnt1++;
	memblock_new(pointer, size, pid);
   	//do_backtrace(pid, 0, 1);

	return 0;
}

static int bph_delete(int pid, uintptr_t none1, uintptr_t pointer, uintptr_t none2)
{
	log_debug("[%d] delete pointer:%#lx\n", pid, pointer);
   	//do_backtrace(pid, 0, 1);
	if((memblock_search(pointer)==NULL))
	{	
		log_debug("[%d] not found delete point:%#lx\n", pid, pointer);
	}

	if((long)pointer == 0)
		return 0;
	memblock_delete(memblock_search(pointer));
	delCnt1++;

	return 0;
}

static int bph_deletea(int pid, uintptr_t none1, uintptr_t pointer, uintptr_t none2)
{
	log_debug("[%d] deletea pointer:%#lx\n", pid, pointer);
   	//do_backtrace(pid, 0, 1);
	if((memblock_search(pointer)==NULL))
	{	
		log_debug("[%d] not found deletea point:%#lx\n", pid, pointer);
	}

	if((long)pointer == 0)
		return 0;
	memblock_delete(memblock_search(pointer));
	delCnt1++;

	return 0;
}
#endif

static int bph_dlopen(int pid, uintptr_t none1, uintptr_t pointer, uintptr_t none2)
{
	log_debug("[%d] dlopen ret:%#x, p1:%#x, p2:%#x\n", pid, none1, pointer, none2);

	return 0;
}

static int bph_free(int pid, uintptr_t none1, uintptr_t pointer, uintptr_t none2)
{
	log_debug("[%d]free [%d] point:%#lx, ret:%#lx, arg2:%#lx", pid, delCnt1, pointer, none1, none2);
	if((memblock_search(pointer)==NULL) && (pointer !=0))
	{	
		log_debug("[%d] not found free point:%#lx\n", pid, pointer);
		//printf("[memblock_dump start]\n");
		//memblock_dump(0);
		//printf("[memblock_dump end]\n");
	}

	if((long)pointer == 0)
    {
		//printf("[free pointer 0 start]\n");
		//do_backtrace(pid, 0, 1);
		//printf("[free pointer 0 end]\n");
		memblock_dump(0);
		memblock_delete(memblock_search(none2 - 0x8));
		delCnt1++;
		return 1;
	}
	memblock_delete(memblock_search(pointer));
	delCnt1++;
	return 0;
}

static int bph_backtrace(int pid, uintptr_t ret, uintptr_t arg1, uintptr_t arg2)
{
	log_debug("[%d] backtrace: ret:%lx, arg1:%#x, arg2:%#x \n", pid, ret, arg1, arg2);
    do_backtrace(pid, 0, 1);
	return 0;
}


static int bph_realloc(int pid, uintptr_t new_pointer, uintptr_t old_pointer, uintptr_t size)
{
	log_debug("[%d] realloc pointer:%#lx->%#lx size:%ld\n", pid, old_pointer, new_pointer, size);
    if (new_pointer == old_pointer) {
        memblock_update_size(memblock_search(old_pointer), size);
    } else {
        memblock_delete(memblock_search(old_pointer));
		delCnt1++;
        memblock_new(new_pointer, size, pid);
		addCnt1++;
    }

	return 0;
}

static int bph_calloc(int pid, uintptr_t pointer, uintptr_t nmemb, uintptr_t size)
{
	if(memblock_search(pointer)==NULL)
	{
		log_debug("[%d] calloc [%d] pointer:%#lx nmemb:%#lx size:%#lx, total:%#lx\n", pid, addCnt1, pointer, nmemb, size, nmemb * size);
		memblock_new(pointer, nmemb * size, pid);
		addCnt1++;
   		//do_backtrace(pid, 0, 1);
	}
	return 0;
}

static int bph_mmap(int pid, uintptr_t ret_map_addr, uintptr_t none1, uintptr_t length)
{
	log_debug("[%d] mmap addr:%#x, length:%#x\n", pid, ret_map_addr, length);

	return 0;
}

static int bph_munmap(int pid, uintptr_t none1, uintptr_t unmap_addr, uintptr_t length)
{
	log_debug("[%d] munmap addr:%#x, length:%#x\n", pid, unmap_addr, length);

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
	bp->entry_code = setbreakpoint(pid, bp->entry_address);
    printf("symbol: %s,  entry_code: %#x, entry_address: %#x", bp->name, bp->entry_code, bp->entry_address);

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
	//do_breakpoint_init(pid, &g_breakpoints[7], "__libc_start_main", bph_backtrace);
	//do_breakpoint_init(pid, &g_breakpoints[7], "__libc_thread_freeres", bph_backtrace);
#if 1
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
    printf("addCnt1:%d\n",addCnt1);
    printf("delCnt1:%d\n",delCnt1);
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
