#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "list.h"
#include "memblock.h"

struct memblock_s {
	struct list_head	list_node;
	long		pointer;
	size_t		size;
    int         pid;
};

static LIST_HEAD(g_memblock_active);

int memblock_new(long pointer, size_t size, int pid)
{
	if (pointer == 0) {
		printf("Warning: alloc returns NULL at\n");
		return 0;
	}

	struct memblock_s *mb = malloc(sizeof(struct memblock_s));
	if (mb == NULL) {
		return -1;
	}
	mb->pointer = pointer;
	mb->size = size;
	mb->pid = pid;

	list_add_tail(&mb->list_node, &g_memblock_active);

	return 0;
}

void memblock_delete(struct memblock_s *mb)
{
	if (mb == NULL) {
		return;
	}

	list_del(&mb->list_node);
	free(mb);
}

void memblock_update_size(struct memblock_s *mb, size_t size)
{
	if (mb != NULL) {
		mb->size = size;
	}
}

struct memblock_s *memblock_search(long pointer)
{
	struct list_head *p;
	struct memblock_s *mb;
    if(pointer == 0)
        return NULL;

   	list_for_each(p, &g_memblock_active) {
		mb = list_entry(p, struct memblock_s, list_node);
        //if( (return_addr == mb->pointer)&&(pid == mb->pid))
        if((pointer == mb->pointer))
        {
            return mb;
        }
	}

	return NULL;
}

void memblock_dump(int freeall)
{
	struct list_head *p,*q;
	struct memblock_s *mb;
    
    if(freeall == 0)
	{
        list_for_each(p, &g_memblock_active) {
	    	mb = list_entry(p, struct memblock_s, list_node);
            printf("[%d] pointer:%#lx, size:%#lx\n", mb->pid, mb->pointer, mb->size);
	    }
    }

    if(freeall == 1)
	{
        list_for_each_safe(p,q,&g_memblock_active) {
	    	mb = list_entry(p, struct memblock_s, list_node);
            printf("[%d] pointer:%#lx, size:%#lx\n", mb->pid, mb->pointer, mb->size);
            memblock_delete(mb);
	    }
    }
}
