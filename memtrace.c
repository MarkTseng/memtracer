#include <cxxabi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wait.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <errno.h>
// libunwind header
#include <libunwind.h>
#include <libunwind-arm.h>
#include <libunwind-ptrace.h>
// ptrace header
#include <sys/ptrace.h>
#include <asm/ptrace.h>
#include <sys/user.h>

#ifdef __cplusplus 
	extern "C" { 
#endif 
#include "breakpoint.h"
#include "symtab.h"
#include "debug_line.h"
#include "proc_info.h"
#include "addr_maps.h"
#include "ptr_backtrace.h"
#ifdef __cplusplus 
    } 
#endif 

// define
#define ARM_UNKONW_INST (0xdeff)
#define ERR -1
#define E_OK 0
#define E_ARGS 1
#define E_MALLOC 2
#define E_FORK 3
#define E_PTRACE 4
#define E_UNKNOWN 5
#define TRAPINT 0xe7ffffff
#define TRAPHALF 0xdeff


// global variable
pid_t g_child;
pid_t g_mainPid;
struct user regs;
static unw_addr_space_t as;
static struct UPT_info *ui;
static int g_readelf = 0;
struct breakpoint_s *bp = NULL;
uintptr_t return_address = 0, return_code = 0;
uintptr_t arg1 = 0, arg2 = 0;
unsigned int breaktrap = 0;

// memleax for compile use
#define BACKTRACE_MAX 50
uintptr_t g_current_entry;
pid_t g_current_thread;
int opt_backtrace_limit = BACKTRACE_MAX;
const char *opt_debug_info_file;

static pid_t g_target_pid;
static int g_signo = 0;


const char* demangle(const char* name)
{
	char buf[1024];
	unsigned int size=1024;
	int status;
	char* res = abi::__cxa_demangle (name,
			0,
			0,
			&status);
    if(res)
        printf("fun name:%s\n", res);
    else
        printf("no demangle fun name:%s\n", name);
	return res;
}
#ifdef __cplusplus 
	extern "C" { 
#endif 

long main_orig_opc = 0;
#define MAIN_ADDRESS (0x8488)
//#define MAIN_ADDRESS (0x41c40)
void set_breakpoint(pid_t child)
{
    int status;
    long orig = ptrace(PTRACE_PEEKTEXT, child, MAIN_ADDRESS, NULL);
    long trap;

    trap = ARM_UNKONW_INST;
    printf("[+] Add breakpoint on 0x%lx, orig_opc=%#x \n", MAIN_ADDRESS, orig);

    main_orig_opc = orig;
    ptrace(PTRACE_POKETEXT, child, MAIN_ADDRESS, trap);
    orig = ptrace(PTRACE_PEEKTEXT, child, MAIN_ADDRESS, NULL);
    printf("[+] new breakpoint on 0x%lx, brk_opc=%#x \n", MAIN_ADDRESS, orig);
    /* save orig opc*/
    //callstack->calldata[callstack->depth].breakpoint.orig_code = orig;
    //callstack->calldata[callstack->depth].breakpoint.vaddr = callstack->calldata[callstack->depth].retaddr;

}

void remove_breakpoint(pid_t child)
{
    int status;
    printf("[-] Removing breakpoint from 0x%lx\n", MAIN_ADDRESS);
    ptrace(PTRACE_POKETEXT, child, MAIN_ADDRESS, main_orig_opc);
}

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
			printf( "readchildword ptrace_peektext error: %s\n", strerror(errno));
			exit(E_PTRACE);
		}
	}

	printf( "read 0x%08lx from %ld:0x%x\n", word, pid, addr);

	return word;
}

/* write a word to child process */
void writechildword(pid_t pid, unsigned long addr, unsigned long word)
{
	unsigned long check;

	printf("wrote 0x%08lx to %ld:0x%x\n", word, pid, addr);
	/* write word to child process */
	if (ptrace(PTRACE_POKETEXT, pid, addr, word)) {
		printf( "writechildword ptrace_poketext error: %s\n", strerror(errno));
		exit(E_PTRACE);
	}

	check = readchildword(pid, addr);

	if (check != word) {
		printf( "writechildword word not written error\n");
		exit(E_PTRACE);
	}

	printf("wrote 0x%08lx to %ld:0x%x\n", word, pid, addr);
}

/* set breakpoint */
unsigned int setbreakpoint(pid_t exe, unsigned long breakaddr)
{
	unsigned long addr, origdata, data;

	if (!breakaddr || !exe) {
		printf( "setbreakpoint: invalid parameters\n");
		return 0;
	}
	
	printf( "setbreakpoint: %ld, 0x%x\n", exe, breakaddr);

	int thumb = 0;

	addr = breakaddr & ~0x1; /* break function with LSB cleared */

	/* arm addresses are 32bit word aligned */
	origdata = readchildword(exe, addr & ~0x3);

	if (breakaddr & 0x1) {
		thumb = 1;
	}

	if ((!thumb) && (addr & 0x2)) {
		printf( "setbreakpoint: arm, address misalignment, 0x%x\n", addr);
		exit(E_UNKNOWN);
	}

	if (thumb) {
		/* thumb */
        printf("thumb unknow inst\n");

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

        printf("arm unknow inst\n");
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
		printf( "clearbreakpoint: invalid parameters\n");
		return;
	}
	
	printf( "clearbreakpoint: %ld, 0x%x\n", exe, breakaddr);

	int thumb = 0;

	addr = breakaddr & ~0x1; /* break function with LSB cleared */

	/* arm addresses are 32bit word aligned */
	origdata = readchildword(exe, addr & ~0x3);

	if (breakaddr & 0x1) {
		thumb = 1;
	}

	if ((!thumb) && (addr & 0x2)) {
		printf( "clearbreakpoint: arm, address misalignment, 0x%x\n", addr);
		exit(E_UNKNOWN);
	}

	if (thumb) {
		/* thumb */

		if (addr & 0x2) {
			/* odd half */
        printf("thumb unknow inst\n");

			/* check if breakpoint is set */
			if (!isintbreakpoint(origdata, breakaddr & 0x3)) {
				return;
			}
			data = (origdata & 0xffff) | (origint & ~0xffff);
		} else {
			/* even half */

			/* check if breakpoint is set */
			if (!isintbreakpoint(origdata, breakaddr & 0x3)) {
				return;
			}
			data = (origdata & ~0xffff) | (origint & 0xffff);
		}

	} else {
		/* arm or unsure */
        printf("arm unknow inst\n");

		/* check if breakpoint is set */
		if (!isintbreakpoint(origdata, 0)) {
			return;
		}
		data = origint;
	}

	writechildword(exe, addr & ~0x3, data);
}


static void dump_regs(struct user const *regs, FILE *outfp)
{
    fprintf(outfp, "cpsr = 0x%08x, pc = 0x%08x\n", regs->regs.ARM_cpsr, regs->regs.ARM_pc);
    fprintf(outfp, "lr   = 0x%08x, sp = 0x%08x\n", regs->regs.ARM_lr, regs->regs.ARM_sp);
    fprintf(outfp, "ip   = 0x%08x, fp = 0x%08x\n", regs->regs.ARM_ip, regs->regs.ARM_fp);
    fprintf(outfp, "r0   = 0x%08x, r1 = 0x%08x\n", regs->regs.ARM_r0, regs->regs.ARM_r1);
    fprintf(outfp, "r2   = 0x%08x, r3 = 0x%08x\n", regs->regs.ARM_r2, regs->regs.ARM_r3);
    fprintf(outfp, "r4   = 0x%08x, r5 = 0x%08x\n", regs->regs.ARM_r4, regs->regs.ARM_r5);
    fprintf(outfp, "r6   = 0x%08x, r7 = 0x%08x\n", regs->regs.ARM_r6, regs->regs.ARM_r7);
    fprintf(outfp, "r8   = 0x%08x, r9 = 0x%08x\n", regs->regs.ARM_r8, regs->regs.ARM_r9);
    fprintf(outfp, "\n");
}

static void do_backtrace(pid_t child) {

	ui = (UPT_info*)_UPT_create(child);
	if (!ui) {
		printf("_UPT_create failed");
	}

	as = unw_create_addr_space(&_UPT_accessors, 0);
	if (!as) {
		printf("unw_create_addr_space failed");
	}

	unw_cursor_t c;
	int backTaceLevel = 0;
	int rc = unw_init_remote(&c, as, ui);
	if (rc != 0) {
		if (rc == UNW_EINVAL) {
			printf("unw_init_remote: UNW_EINVAL");
		} else if (rc == UNW_EUNSPEC) {
			printf("unw_init_remote: UNW_EUNSPEC");
		} else if (rc == UNW_EBADREG) {
			printf("unw_init_remote: UNW_EBADREG");
		} else {
			printf("unw_init_remote: UNKNOWN");
		}
	}

	printf("\n### backtrace start ###\n");
	do {
		unw_word_t  offset, pc;
		char        fname[64];

		unw_get_reg(&c, UNW_REG_IP, &pc);
		fname[0] = '\0';
		(void) unw_get_proc_name(&c, fname, sizeof(fname), &offset);
		printf("%p : (%s+0x%x) [%p]\n", (void *)pc,
				fname,
				(int) offset,
				(void *) pc);
		//demangle(fname);
		backTaceLevel++;
	} while ((unw_step(&c) > 0) && (backTaceLevel < 5));
	printf("### backtrace end ###\n\n");

	unw_destroy_addr_space(as);
	_UPT_destroy(ui);
}

static void signal_handler(int signo)
{
	printf("SIGINT trigger\n");
	ptrace(PTRACE_KILL, g_child,0,0);
	kill(g_mainPid, SIGKILL);
}

int main(int argc __attribute__((unused)), char **argv, char **envp) 
{
	pid_t new_child;

    if(argc == 1)
    {
        fprintf(stderr, "usage memtrace <bin>\n");
        exit(-1);
    }

    const char *path = argv[1];
    const char *name = strrchr(path, '/');
    if(name){
        name += 1;        
    }else{
        name = path;
    }

	signal(SIGINT, signal_handler);

	g_child = fork();
    long newpid = 0;

	if (!g_child) {

		ptrace(PTRACE_TRACEME, g_child,0,0);
		execve(path,
				argv, envp);

		return 0;

	} else {
		g_mainPid = getpid();
        printf("g_child: %d\n", g_child);
        printf("g_mainPid: %d\n", g_mainPid);
			
		int status,w;
        
		new_child = waitpid(-1, &status, __WALL);
		if (WIFSTOPPED(status)) {
			printf("### pid: %ld, stop signal: %d\n", new_child, WSTOPSIG(status));  
			ptrace(PTRACE_SETOPTIONS, new_child, NULL, PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEFORK | PTRACE_O_TRACEEXEC);
            /* breakpoint in main */
            set_breakpoint(g_child);
		}
		ptrace(PTRACE_CONT,new_child, NULL, NULL);

        /* trace pid */
		while(1) {
            new_child = waitpid(-1, &status, __WALL);
            memset(&regs, 0, sizeof(regs));
            ptrace((__ptrace_request)PTRACE_GETREGS, new_child, NULL, &regs);
            dump_regs(&regs, stdout);
            if (WIFSTOPPED(status)) {
                printf("##WIFSTOPPED then PTRACE_CONT, status:%#x , sig:%d \n", status, WSTOPSIG(status));
                if(WSTOPSIG(status)== SIGILL)
                {  
                    if (regs.regs.ARM_pc == return_address -1) {
                        /* -- at function return */
                        printf("### function return\n");
                        clearbreakpoint(new_child, return_address, breaktrap);
                        dump_regs(&regs, stdout);
                        return_address = 0;
                        if (bp->handler(regs.regs.ARM_r0, arg1, arg2) != 0) {
                            printf("\n== Not enough memory.\n");
                            break;
                        }
                        printf("### recovery breakpoint \n\n");
                        breaktrap = setbreakpoint(new_child, bp->entry_address);
                    }else if ((bp = breakpoint_by_entry(regs.regs.ARM_pc)) != NULL)
                    {
                        //regs.regs.ARM_pc-=4;
                        //ptrace((__ptrace_request)PTRACE_SETREGS, new_child, 0, &regs);

                        /* recover entry code */
                        clearbreakpoint(new_child, bp->entry_address, bp->entry_code);

                        /* set breakpoint at return address */
                        return_address = regs.regs.ARM_lr;
                        return_code = ptrace((__ptrace_request)PTRACE_PEEKTEXT, new_child, return_address);
                        //ptrace(PTRACE_POKETEXT, new_child, return_address , ARM_UNKONW_INST);
#if 1
                        breaktrap = setbreakpoint(new_child, return_address);
                        printf("### function entry\n");
                        printf("### pid:%d, entry address: %#x, entry code:%#x, pc: %#x \n", new_child, bp->entry_address, ptrace((__ptrace_request)PTRACE_PEEKTEXT, new_child, bp->entry_address), regs.regs.ARM_pc);
                        printf("### brk in RA: %#x, RA_OPC:%#x, breaktrap:%#x \n", return_address, ptrace((__ptrace_request)PTRACE_PEEKTEXT, new_child, return_address & ~0x3), breaktrap);
                        printf("### RA: %#x, RA_OPC:%#x \n", return_address, ptrace((__ptrace_request)PTRACE_PEEKTEXT, new_child, return_address));
                        /* save arguments */
                        arg1 = regs.regs.ARM_r2;
                        arg2 = regs.regs.ARM_r3;
                        //do_backtrace(new_child);
#endif
                        dump_regs(&regs, stdout);
                    }
                }

                if(WSTOPSIG(status)== SIGTRAP)
                {
                    //memset(&regs, 0, sizeof(regs));
                    //ptrace((__ptrace_request)PTRACE_GETREGS, new_child, NULL, &regs);
                    //dump_regs(&regs, stdout);
                    
                    /* breaking after a function-entry-breakpoint, which means
                     * we are at the function-return-breakpoint, or at another
                     * function-entry-breakpoint. In the latter case, we ignore
                     * the formor function-entry-breakpoint. */
                    if (return_address != 0) {
                        printf("### recovery breakpoint \n\n");
                        dump_regs(&regs, stdout);
                        /* recover return code */
                        ptrace(PTRACE_POKETEXT, new_child, return_address, return_code);
                        /* re-set breakpoint at entry address */
	                    ptrace(PTRACE_POKETEXT, new_child, bp->entry_address, bp->entry_code);
                    }

                    if (regs.regs.ARM_pc == return_address) {
                        /* -- at function return */
                        printf("### function return\n");
                        dump_regs(&regs, stdout);
                        return_address = 0;
                        if (bp->handler(regs.regs.ARM_r0, arg1, arg2) != 0) {
                            printf("\n== Not enough memory.\n");
                            break;
                        }
                    } 
                    else if ((bp = breakpoint_by_entry(regs.regs.ARM_pc -1)) != NULL) 
                    {
                        /* -- at function entry */

                        /* recover entry code */
                        ptrace(PTRACE_POKETEXT, new_child, bp->entry_address, bp->entry_code);

                        /* set breakpoint at return address */
                        return_address = regs.regs.ARM_lr;
                        return_code = ptrace((__ptrace_request)PTRACE_PEEKTEXT, new_child, return_address);
                        //ptrace(PTRACE_POKETEXT, new_child, return_address , ARM_UNKONW_INST);
                        setbreakpoint(new_child, return_address);
                        printf("### function entry\n");
                        printf("### pid:%d, entry address: %#x, entry code:%#x, pc: %#x \n", new_child, bp->entry_address, ptrace((__ptrace_request)PTRACE_PEEKTEXT, new_child, bp->entry_address), regs.regs.ARM_pc);
                        printf("### brk in RA: %#x, RA_OPC:%#x \n", return_address, ptrace((__ptrace_request)PTRACE_PEEKTEXT, new_child, return_address & ~0x3));
                        printf("### RA: %#x, RA_OPC:%#x \n", return_address, ptrace((__ptrace_request)PTRACE_PEEKTEXT, new_child, return_address));
                        /* save arguments */
                        arg1 = regs.regs.ARM_r2;
                        arg2 = regs.regs.ARM_r3;
                        //do_backtrace(new_child);
                        //regs.regs.ARM_pc-=2;
                        //ptrace((__ptrace_request)PTRACE_SETREGS, new_child, 0, &regs);
                        dump_regs(&regs, stdout);
                    }
                }
                if(g_readelf == 0)
                {
                    /* load symbol table*/
                    addr_maps_build(g_child);
                    ptr_maps_build(g_child);
                    symtab_build(g_child);
                    /* malloc .... breakpoint */
                    breakpoint_init(g_child);
                    remove_breakpoint(g_child);
                    g_readelf = 1;

                    //regs.regs.ARM_pc-=2;
                    //ptrace((__ptrace_request)PTRACE_SETREGS, new_child, 0, &regs);
                }

                if(WSTOPSIG(status)== SIGSEGV)
                {
                    do_backtrace(new_child);
                    printf("### [SIGSEGV] pid: %ld, stop signal: %d\n", new_child, WSTOPSIG(status));  
                    dump_regs(&regs, stdout);

                    break;
                }
                //printf("### pid: %ld, stop signal: %d\n", new_child, WSTOPSIG(status));  
                //dump_regs(&regs, stdout);
                //do_backtrace(new_child);
#if 0
                if(regs.regs.ARM_r7 == 0x2d)
                {	
                    //dump_regs(&regs, stdout);
                    union u {
                        long val;
                        char chars[sizeof(long)];
                    }data;
                    data.val = ptrace((__ptrace_request)PTRACE_PEEKUSER, new_child, regs.regs.ARM_r0, 0);
                    printf("brk size= %#lx\n", regs.regs.ARM_r0);
                    if(regs.regs.ARM_r0 > 0)
                        do_backtrace(new_child);
                }
#endif
                ptrace(PTRACE_CONT,new_child, NULL, NULL);
			}
			if (status>>8 == (SIGTRAP | (PTRACE_EVENT_EXEC<<8))) {
				printf("### PTRACE_EVENT_EXEC %ld, \n", new_child);  
			}
			if (status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))) {
				printf("### PTRACE_EVENT_CLONE %ld\n", new_child);  
			}
			if (status>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8))) {
				printf("### PTRACE_EVENT_VLONE %ld\n", new_child);  
			}
			if (status>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK_DONE<<8))) {
				printf("### PTRACE_EVENT_VFORK_DONE %ld\n", new_child);  
			}
			if (status >>8 == PTRACE_EVENT_FORK) {
				printf("### PTRACE_EVENT_FORK %ld\n", new_child);  
			}
			if(WIFEXITED(status)) {
				printf("### new_child %d exited\n", new_child);
				if(new_child == g_child)
					break;
			}
		}
	}

	return 0;
}
#ifdef __cplusplus 
} 
#endif
