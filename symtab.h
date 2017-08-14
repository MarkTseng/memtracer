#ifndef MLD_SYMTAB_H
#define MLD_SYMTAB_H

#include <stdint.h>
#include <sys/types.h>

void symtab_build(pid_t pid);
const char *symtab_by_address(uintptr_t address, int *offset);
uintptr_t symtab_by_name(const char *name);
uintptr_t symtab_dump();

#define ARCHARM

/* ASLR offsets */
/* These all came from observations so they might be different on other platforms */
#if defined ARCHX86
#define ASLROFFSET 0x80000000

#elif defined ARCHARM
#define ASLROFFSET 0x2a000000

#elif defined ARCHMIPS
#define ASLROFFSET 0x55550000

#endif


#define S_SYMNAME 128
/* struct to hold symbols */
struct symbol
{
	char name[S_SYMNAME];
	unsigned long address;
};


/* elf functions */
int readsyms(struct symbol **symbols, char *filename, int display, int pie);
void display_symbols(struct symbol *symbols, int total);
unsigned long symaddr(struct symbol *symbols, int total, char *name);
int symtab_build_file(const char *path, uintptr_t start, uintptr_t end);


#endif
