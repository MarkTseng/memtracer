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
static int addCnt = 0;
static int delCnt = 0;
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
    //printf("[%s][%d] alloc pointer:%#lx, size:%#lx\n",__func__, mb->pid, mb->pointer, mb->size);
    addCnt++;
	return 0;
}

void memblock_delete(struct memblock_s *mb)
{
	if (mb == NULL) {
		return;
	}

    //printf("[%s][%d] delete pointer:%#lx, size:%#lx\n",__func__, mb->pid, mb->pointer, mb->size);
	list_del(&mb->list_node);
	free(mb);
    delCnt++;
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
        if((pointer == mb->pointer))
        {
            //printf("[%s][%d] pointer:%#lx, mb->pointer:%#lx, mb->size:%#lx\n",__func__, mb->pid, pointer, mb->pointer, mb->size);
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
            printf("[%s][%d] pointer:%#lx, size:%#lx\n", __func__, mb->pid, mb->pointer, mb->size);
	    }
    }

    if(freeall == 1)
	{
        list_for_each_safe(p,q,&g_memblock_active) {
	    	mb = list_entry(p, struct memblock_s, list_node);
            printf("[%s][%d] del pointer:%#lx, size:%#lx\n", __func__, mb->pid, mb->pointer, mb->size);
            memblock_delete(mb);
	    }
        printf("addCnt:%d\n",addCnt);
        printf("delCnt:%d\n",delCnt);
    }
}
