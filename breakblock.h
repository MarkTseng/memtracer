#ifndef MLD_BREAKBLOCK_H
#define MLD_BREAKBLOCK_H

#include <unistd.h>
#include <stdint.h>
#include <time.h>

struct breakblock_s {
	struct list_head	list_node;
    long return_addr; 
    long return_opc;   
    long entry_addr; 
    long entry_opc; 
	long arg1;
	long arg2;
    int  pid;
	char symbol[32];
};

int breakblock_new(long return_addr, long return_opc, long entry_addr, long entry_opc, long arg1, long arg2, int pid, char *symbol);
void breakblock_delete(struct breakblock_s *bb);
struct breakblock_s *breakblock_search(uintptr_t pointer, int pid);
void breakblock_dump(int freeall);
void breakblock_show(struct breakblock_s *bb);

#endif
