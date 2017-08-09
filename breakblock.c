#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "list.h"
#include "breakblock.h"

struct breakblock_s {
	struct list_head	list_node;
    long return_addr; 
    long return_opc;   
    long entry_addr; 
    long entry_opc; 
	long arg1;
	long arg2;
    int  pid;
};


static LIST_HEAD(g_breakblock_active);

int breakblock_new(long return_addr, long return_opc, long entry_addr, long entry_opc, long arg1, long arg2, int pid)
{
	if (return_addr == 0) {
		printf("Warning: alloc returns NULL at\n");
		return 0;
	}

	struct breakblock_s *bb = malloc(sizeof(struct breakblock_s));
	if (bb == NULL) {
		return -1;
	}
	bb->return_addr = return_addr;
    bb->return_opc = return_opc;   
    bb->entry_addr = entry_addr; 
    bb->entry_opc = entry_opc; 
    bb->arg1 = arg1;
    bb->arg2 = arg2;
    bb->pid = pid;
	list_add_tail(&bb->list_node, &g_breakblock_active);

	return 0;
}

void breakblock_delete(struct breakblock_s *bb)
{
	if (bb == NULL) {
		return;
	}

	list_del(&bb->list_node);
	free(bb);
}

struct breakblock_s *breakblock_search(uintptr_t return_addr, int pid)
{
	struct list_head *p;
	struct breakblock_s *bb;

	list_for_each(p, &g_breakblock_active) {
		bb = list_entry(p, struct breakblock_s, list_node);
        if( (return_addr == bb->return_addr)&&(pid == bb->pid))
        {
            return bb;
        }
	}
    return NULL;
}

void breakblock_dump(void)
{
	struct list_head *p;
	struct breakblock_s *bb;

	list_for_each(p, &g_breakblock_active) {
		bb = list_entry(p, struct breakblock_s, list_node);
        printf("return_addr:%#lx, pid:%d\n", bb->return_addr, bb->pid);
	}
}

void breakblock_show(struct breakblock_s *bb)
{
    printf("[%d] pc:%#lx\n",bb->pid, bb->return_addr);
}
