#include <sys/ptrace.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <elf.h>
#include <libelf.h>
#include <gelf.h>
#include <libunwind-ptrace.h>
#include <string.h>

#include "array.h"
#include "minigdb.h"
#include "proc_info.h"
#include "debug_file.h"
#include "symtab.h"

struct symbol_s {
	uintptr_t	address;
	size_t		size;
	int8_t		weak;
	char		name[128];
};

static ARRAY(g_symbol_table, struct symbol_s, 1000);

static int symtab_build_section(Elf *elf, Elf_Scn *section,
		uintptr_t offset, uintptr_t base_addr)
{
#if defined(X86_64)
	Elf64_Shdr *shdr = elf64_getshdr(section);
#else
	Elf32_Shdr *shdr = elf32_getshdr(section);
#endif
	if (shdr == NULL) {
		return 0;
	}

	if (shdr->sh_type != SHT_SYMTAB && shdr->sh_type != SHT_DYNSYM) {
		return 0;
	}

	Elf_Data *data = elf_getdata(section, NULL);
	if (data == NULL || data->d_size == 0) {
		return 0;
	}

	int count = 0;
#if defined(X86_64)
	Elf64_Sym *esym = (Elf64_Sym *)data->d_buf;
	Elf64_Sym *lastsym = (Elf64_Sym *)((char*) data->d_buf + data->d_size);
#else
	Elf32_Sym *esym = (Elf32_Sym *)data->d_buf;
	Elf32_Sym *lastsym = (Elf32_Sym *)((char*) data->d_buf + data->d_size);
#endif
	for (; esym < lastsym; esym++) {
		if ((esym->st_value == 0) || (esym->st_size == 0) ||
				(esym->st_shndx == SHN_UNDEF) ||
#if defined(X86_64)
    #ifdef STB_NUM
				(ELF64_ST_BIND(esym->st_info) == STB_NUM) ||
    #endif
				(ELF64_ST_TYPE(esym->st_info) != STT_FUNC)) {
#else
  #ifdef STB_NUM
				(ELF32_ST_BIND(esym->st_info) == STB_NUM) ||
    #endif
				(ELF32_ST_TYPE(esym->st_info) != STT_FUNC)) {
#endif
			continue;
		}

		struct symbol_s *sym = array_push(&g_symbol_table);

		char *name = elf_strptr(elf, shdr->sh_link, (size_t)esym->st_name);
		strncpy(sym->name, name, sizeof(sym->name));
		sym->name[sizeof(sym->name) - 1] = '\0';

		sym->address = esym->st_value - base_addr + offset;
		sym->size = esym->st_size;
		sym->weak = (ELF32_ST_BIND(esym->st_info) == STB_WEAK);
		//printf("[%s] name:%s, addr: %#lx",__func__,  sym->name, sym->address);

		count++;
	}
	return count;
}

static uintptr_t symtab_elf_base(Elf *elf)
{
	size_t i, n;

	elf_getphdrnum(elf, &n);
#if defined(X86_64)
	Elf64_Phdr *headers = elf64_getphdr(elf);
#else
	Elf32_Phdr *headers = elf32_getphdr(elf);
#endif
	if (n == 0 || headers == NULL) {
		return 0;
	}

	for (i = 0; i < n; i ++) {
		if (headers[i].p_type == PT_LOAD) {
			return headers[i].p_vaddr;
		}
	}
	return 0;
}

int symtab_build_file(const char *path, uintptr_t start, uintptr_t end)
{
	/* open file */
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		return -1;
	}
	
	elf_version(EV_CURRENT);
	Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
	if (elf == NULL) {
		close(fd);
		return -1;
	}

	uintptr_t offset = 0, base_addr = 0;
#if defined(X86_64)
	Elf64_Ehdr *hdr = elf64_getehdr(elf);
#else
	Elf32_Ehdr *hdr = elf32_getehdr(elf);
#endif
	if (hdr->e_type == ET_DYN) { /* only for dynamic library, but not executable */
		offset = start; /* offset in process */
		base_addr = symtab_elf_base(elf); /* base address of library */
	}

	/* find symbol section */
	Elf_Scn* section = NULL;
	int count = 0;
	while ((section = elf_nextscn(elf, section)) != NULL) {
		count += symtab_build_section(elf, section, offset, base_addr);
	}

	/* clean up */
	elf_end(elf);
	close(fd);
	return count;
}

static int symbol_cmp(const void *a, const void *b)
{
	const struct symbol_s *sa = a;
	const struct symbol_s *sb = b;
	return sa->address < sb->address ? -1 : 1;
}

void symtab_build(pid_t pid)
{
	const char *path, *debugp;
	size_t start, end;
	int exe_self;
	while ((path = proc_maps(pid, &start, &end, &exe_self)) != NULL) {
		debug_try_init(path, exe_self);
		while ((debugp = debug_try_get()) != NULL) {
			if (symtab_build_file(debugp, start, end) > 0) {
				break;
			}
		}
		if (exe_self && debugp == NULL) {
			printf("Warning: no symbol table found for %s\n", path);
		}
	}

	/* finish */
	array_sort(&g_symbol_table, symbol_cmp);
}

const char *symtab_by_address(uintptr_t address, int *offset)
{
	int min = 0, max = g_symbol_table.item_num - 1;
	struct symbol_s *table = g_symbol_table.data;
	while (min <= max) {
		int mid = (min + max) / 2;
		struct symbol_s *sym = &table[mid];
		if (address < sym->address) {
			max = mid - 1;
		} else if (address > sym->address + sym->size) {
			min = mid + 1;
		} else {
			*offset = address - sym->address;
			return sym->name;
		}
	}
	return NULL;
}

uintptr_t symtab_by_name(const char *name)
{
	uintptr_t address = 0;
	struct symbol_s *sym;
	array_for_each(sym, &g_symbol_table) {
		if (strcmp(sym->name, name) == 0) {
			if (!sym->weak) {
				return sym->address;
			}
			if (address == 0) {
				address = sym->address;
			}
		}
	}
	return address;
}


#define ERR -1
#define E_OK 0
#define E_ARGS 1
#define E_MALLOC 2

/*
** elf functions
*/

/* readsyms reads the function names from the elf executable */
int readsyms(struct symbol **symbols, char *filename, int display, int pie)
{
	int fd;
	struct stat *stats;
	Elf *elf = NULL;				/* Our Elf pointer for libelf */
	Elf_Scn *scn = NULL;		    /* Section Descriptor */
	Elf_Data *edata = NULL; 		/* Data Descriptor */
	GElf_Sym sym;					/* Symbol */
	GElf_Shdr shdr;					/* Section Header */
	int num_symbols = 0;
	int symbol_count = 0;
	int sym_index = 0;
	int i;

	unsigned char *base_ptr = NULL;

	if (!symbols || !filename) {
		printf( "readsyms: invalid parameters\n");
		exit(E_ARGS);
	}
	
	stats = malloc(sizeof(struct stat));
	if (stats == NULL) {
		printf( "readsyms malloc error\n");
		exit(E_MALLOC);
	}

	if ((fd = open(filename, O_RDONLY)) == ERR)
	{
	        printf( "couldn't open %s\n", filename);
	        exit(E_ARGS);
	}

	if ((fstat(fd, stats)))
	{
	        printf( "could not fstat %s\n", filename);
	        close(fd);
	        exit(E_ARGS);
	}

	if ((base_ptr = (unsigned char *) malloc(stats->st_size)) == NULL)
	{
		printf( "readsyms malloc error\n");
		exit(E_MALLOC);
	}

	if ((read(fd, base_ptr, stats->st_size)) < stats->st_size)
	{
		printf( "could not read file");
		free(base_ptr);
		exit(E_ARGS);
	}

	free(base_ptr);

	/* Check libelf version first */
	if (elf_version(EV_CURRENT) == EV_NONE)
	{
		printf( "WARNING Elf Library is out of date!\n");
	}

	elf = elf_begin(fd, ELF_C_READ, NULL);  /* Initialize 'elf' pointer to our file descriptor */

	/* empty the symbol array */
	if (display) {
		*symbols = NULL;
		num_symbols = 0;
		sym_index = 0;
	}

	/* Iterate through section headers and stop when we find symbols */
	while((scn = elf_nextscn(elf, scn)) != NULL)
	{
		gelf_getshdr(scn, &shdr);

		/* When we find a section header marked SHT_SYMTAB stop and get symbols */
		if ((shdr.sh_type == SHT_SYMTAB) || (shdr.sh_type == SHT_DYNSYM))
		{
			/* empty edata */
			edata = 0;

			/* edata points to our symbol table */
			edata = elf_getdata(scn, edata);

			/* how many symbols are there? this number comes from the size of
			   the section divided by the entry size */
			symbol_count = shdr.sh_size / shdr.sh_entsize;

			/* create or extend the array of symbols */
			if (!display) {
				if (*symbols == NULL) {
					/* create array */
					*symbols = (struct symbol *)malloc(symbol_count * sizeof(struct symbol));
					if (*symbols == NULL) {
						printf( "readsyms malloc error\n");
						exit(E_MALLOC);
					}
				} else {
					/* extend array */
					*symbols = (struct symbol *)realloc(*symbols, (symbol_count + num_symbols) * sizeof(struct symbol));
					if (*symbols == NULL) {
						printf( "readsyms realloc error\n");
						exit(E_MALLOC);
					}
					sym_index = num_symbols;
				}
			}

			/* loop through to grab all symbols */
			for(i = 0; i < symbol_count; i++)
			{					  
				/* libelf grabs the symbol data using gelf_getsym() */
				gelf_getsym(edata, i, &sym);

				/* only care about functions */
				if (ELF32_ST_TYPE(sym.st_info) == STT_FUNC)
				{

					/* display == 1 -> print out */
					if (display) {

						/* print out the address */
						printf( "0x%08x ", (Elf32_Addr)(sym.st_value));
		
						/* type of symbol binding */
						switch(ELF32_ST_BIND(sym.st_info))
						{
							case STB_LOCAL: printf( "LOCAL"); break;
							case STB_GLOBAL: printf( "GLOBAL"); break;
							case STB_WEAK: printf( "WEAK"); break;
							case STB_NUM: printf( "NUM"); break;
							case STB_LOOS: printf( "LOOS"); break;
							case STB_HIOS: printf( "HIOS"); break;
							case STB_LOPROC: printf( "LOPROC"); break;
							case STB_HIPROC: printf( "HIPROC"); break;
							default: printf( "UNKNOWN"); break;
						}

						printf( "\t");

						/* the name of the symbol is somewhere in a string table
						   we know which one using the shdr.sh_link member
						   libelf grabs the string using elf_strptr() */
						printf( "%s\n", elf_strptr(elf, shdr.sh_link, sym.st_name));

					} else {

						/* store the symbol */
						strncpy((*symbols)[sym_index].name, elf_strptr(elf, shdr.sh_link, sym.st_name), S_SYMNAME);
						(*symbols)[sym_index].name[S_SYMNAME - 1] = 0x00;
						if (pie) {
							(*symbols)[sym_index].address = (Elf32_Addr)sym.st_value + ASLROFFSET;
						} else {
							(*symbols)[sym_index].address = (Elf32_Addr)sym.st_value;
						}
						sym_index++;

					}
				}
			}
			/* update symbol count */
			if (!display) {
				num_symbols = sym_index;
				*symbols = (struct symbol *)realloc(*symbols, sym_index * sizeof(struct symbol));
			}

		}
	}

	return num_symbols;

}


/* display symbols */
void display_symbols(struct symbol *symbols, int total)
{
	int i;

	if (!symbols) {
		printf( "display_symbols: no symbols\n");
		return;
	}
	
	for (i=0; i<total; i++) {
		printf( "0x%08lx %s\n", symbols[i].address, symbols[i].name);
	}

	printf( "\n");
}


/* symaddr returns the symbol address from the symbol table */
unsigned long symaddr(struct symbol *symbols, int total, char *name)
{
	int i;

	if (!symbols || !name) {
		printf( "symaddr: invalid parameters\n");
		return 0;
	}
	
	for (i=0; i<total; i++) {
		if (strcmp(symbols[i].name, name) == 0) {
			return symbols[i].address;
		}
	}

	return 0;
}


