#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "hash.h"
#include "list.h"
#include "memblock.h"

struct memblock_s {
	struct list_head	list_node;
	struct hlist_node	hash_node;
	uintptr_t		pointer;
	size_t			size;
};

static struct hlist_head g_memblock_hash[HASH_SIZE];

static LIST_HEAD(g_memblock_active);

int memblock_new(uintptr_t pointer, size_t size)
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

	hash_add(g_memblock_hash, &mb->hash_node, sizeof(uintptr_t));
	list_add_tail(&mb->list_node, &g_memblock_active);

	return 0;
}

void memblock_delete(struct memblock_s *mb)
{
	if (mb == NULL) {
		return;
	}

	hash_delete(&mb->hash_node);
	list_del(&mb->list_node);
	free(mb);
}

void memblock_update_size(struct memblock_s *mb, size_t size)
{
	if (mb != NULL) {
		mb->size = size;
	}
}

struct memblock_s *memblock_search(uintptr_t pointer)
{
	struct hlist_node *p = hash_search(g_memblock_hash,
			&pointer, sizeof(uintptr_t));
	if (p == NULL) {
        printf("No fount pointer: %#lx\n", pointer);
		return NULL;
	}
	return list_entry(p, struct memblock_s, hash_node);
}

void memblock_dump(void)
{
	struct list_head *p;
	struct memblock_s *mb;

	list_for_each(p, &g_memblock_active) {
		mb = list_entry(p, struct memblock_s, list_node);
        printf("pointer:%#lx, size:%#lx\n", mb->pointer, mb->size);
	}
}
