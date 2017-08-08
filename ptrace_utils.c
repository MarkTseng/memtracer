#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "ptrace_utils.h"
typedef struct user_regs_struct registers_info_t;
#define REG_RAX(ri) (ri).rax
#define REG_RIP(ri) (ri).rip
#define REG_RSI(ri) (ri).rsi
#define REG_RDI(ri) (ri).rdi
#define REG_RSP(ri) (ri).rsp

/* isintbreakpoint checks the supplied int to see if it contains a trap instruction */
int isintbreakpoint(int trapint, int lsb)
{
	if ( ( ((lsb & 0x1) == 0x0) && (trapint == TRAPINT) ) ||
		 ( ((lsb & 0x3) == 0x1) && ( (trapint & 0xffff) == TRAPHALF) ) ||
		 ( ((lsb & 0x3) == 0x3) && ( ((trapint >> 16) & 0xffff) == TRAPHALF) ) ) {
		return 1;
	} else {
		return 0;
	}
}

/* read a word from child process */
unsigned long readchildword(pid_t pid, unsigned long addr)
{
	unsigned long word;

	/* read a word from child process */
	word = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
	if (word == -1) {
		if (errno) {
			printf( "readchildword ptrace_peektext error: %s", strerror(errno));
			exit(E_PTRACE);
		}
	}

	//printf("[%s] read 0x%08lx from addr:%#lx\n", __func__, word, addr);

	return word;
}

/* write a word to child process */
void writechildword(pid_t pid, unsigned long addr, unsigned long word)
{
	unsigned long check;

	/* write word to child process */
	if (ptrace(PTRACE_POKETEXT, pid, addr, word)) {
		printf( "writechildword ptrace_poketext error: %s", strerror(errno));
		exit(E_PTRACE);
	}

	check = readchildword(pid, addr);

	if (check != word) {
		printf( "writechildword word not written error");
		exit(E_PTRACE);
	}

	//printf("[%s] wrote 0x%08lx to addr:0x%#lx\n", __func__, word, addr);
}

/* set breakpoint */
unsigned int setbreakpoint(pid_t exe, unsigned long breakaddr)
{
	unsigned long addr, origdata, data;

	if (!breakaddr || !exe) {
		//printf( "setbreakpoint: invalid parameters");
		return 0;
	}
	
	//printf("[%s] addr: %#lx\n", __func__, breakaddr);

	int thumb = 0;

	addr = breakaddr & ~0x1; /* break function with LSB cleared */

	/* arm addresses are 32bit word aligned */
	origdata = readchildword(exe, addr & ~0x3);

	if (breakaddr & 0x1) {
		thumb = 1;
	}

	if ((!thumb) && (addr & 0x2)) {
		printf( "setbreakpoint: arm, address misalignment, 0x%lx", addr);
		exit(E_UNKNOWN);
	}

	if (thumb) {
		/* thumb */

		if (addr & 0x2) {
			/* odd half */
			/* check if breakpoint already set */
			if (isintbreakpoint(origdata, breakaddr & 0x3)) {
				return origdata;
			}
			data = (origdata & 0xffff) | (TRAPHALF << 16);
		} else {
			/* even half (e.g. word aligned) */
			/* check if breakpoint already set */
			if (isintbreakpoint(origdata, breakaddr & 0x3)) {
				return origdata;
			}
			data = (origdata & ~0xffff) | TRAPHALF;
		}

	} else {
		/* arm or unsure */

		/* check if breakpoint already set */
		if (isintbreakpoint(origdata, 0)) {
			return origdata;
		}
		/* we need to write addr+2 for arm and addr for thumb */
		data = TRAPINT;
	}

	writechildword(exe, addr & ~0x3, data);

	return origdata;

}


/* clear breakpoint */
void clearbreakpoint(pid_t exe, unsigned long breakaddr, unsigned int origint)
{
	unsigned long addr, origdata, data;

	if (!breakaddr || !exe) {
		printf( "clearbreakpoint: invalid parameters");
		return;
	}
	
	//printf("[%s] addr: %#lx\n", __func__, breakaddr);

	int thumb = 0;

	addr = breakaddr & ~0x1; /* break function with LSB cleared */

	/* arm addresses are 32bit word aligned */
	origdata = readchildword(exe, addr & ~0x3);

	if (breakaddr & 0x1) {
		thumb = 1;
	}

	if ((!thumb) && (addr & 0x2)) {
		printf( "clearbreakpoint: arm, address misalignment, 0x%lx", addr);
		exit(E_UNKNOWN);
	}

	if (thumb) {
		/* thumb */

		if (addr & 0x2) {
			/* odd half */

			/* check if breakpoint is set */
			if (!isintbreakpoint(origdata, breakaddr & 0x3)) {
                //printf("non-breakpoint 1\n");
				return;
			}
			data = (origdata & 0xffff) | (origint & ~0xffff);
		} else {
			/* even half */

			/* check if breakpoint is set */
			if (!isintbreakpoint(origdata, breakaddr & 0x3)) {
                //printf("non-breakpoint 2\n");
				return;
			}
			data = (origdata & ~0xffff) | (origint & 0xffff);
		}

	} else {
		/* arm or unsure */

		/* check if breakpoint is set */
		if (!isintbreakpoint(origdata, 0)) {
            //printf("non-breakpoint 3\n");
			return;
		}
		data = origint;
	}

	writechildword(exe, addr & ~0x3, data);
}


void ptrace_get_regs(pid_t pid, struct user_regs_struct *regs)
{
	ptrace(PTRACE_GETREGS, pid, 0, regs);
}
void ptrace_set_regs(pid_t pid, struct user_regs_struct *regs)
{
	ptrace(PTRACE_SETREGS, pid, 0, regs);
}

uintptr_t ptrace_get_data(pid_t pid, uintptr_t address)
{
	return ptrace(PTRACE_PEEKTEXT, pid, address, 0);
}
void ptrace_set_data(pid_t pid, uintptr_t address, uintptr_t data)
{
	ptrace(PTRACE_POKETEXT, pid, address, data);
}
void ptrace_set_int3(pid_t pid, uintptr_t address, uintptr_t code)
{
	ptrace_set_data(pid, address ,  0xe7ffffff);
}

uintptr_t ptrace_get_child(pid_t pid)
{
	uintptr_t child;
	ptrace(PTRACE_GETEVENTMSG, pid, 0, &child);
	return child;
}
int ptrace_new_child(pid_t pid, int status)
{
	return (status >> 16);
}
void ptrace_continue(pid_t pid, int signum)
{
	ptrace(PTRACE_CONT, pid, 0, signum);
}
void ptrace_attach(pid_t pid)
{
	if (ptrace(PTRACE_ATTACH, pid, 0, 0) != 0) {
		perror("== Attach process error:");
		exit(4);
	}
}
void ptrace_trace_child(pid_t pid)
{
	ptrace(PTRACE_SETOPTIONS, pid, 0,
			PTRACE_O_TRACECLONE |
			PTRACE_O_TRACEVFORK |
			PTRACE_O_TRACEFORK);
}
void ptrace_detach(pid_t pid, int signum)
{
	ptrace(PTRACE_DETACH, pid, 0, signum);
}
