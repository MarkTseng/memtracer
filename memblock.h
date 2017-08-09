#ifndef MLD_MEMBLOCK_H
#define MLD_MEMBLOCK_H

#include <unistd.h>
#include <time.h>

struct memblock_s;

int memblock_new(long pointer, size_t size, int pid);
void memblock_delete(struct memblock_s *mb);
void memblock_update_size(struct memblock_s *mb, size_t size);
struct memblock_s *memblock_search(long pointer);
void memblock_dump(int freeall);

#endif
