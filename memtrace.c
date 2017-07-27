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
//pthread
#include <pthread.h>
//uthash 
#include "uthash.h"

#include "breakpoint.h"
#include "symtab.h"
#include "debug_line.h"
#include "proc_info.h"
#include "addr_maps.h"
#include "ptr_backtrace.h"
#include "list.h"
#include "hash.h"

// define
#define ERR -1
#define E_OK 0
#define E_ARGS 1
#define E_MALLOC 2
#define E_FORK 3
#define E_PTRACE 4
#define E_UNKNOWN 5
#define TRAPINT (0xe7ffffff)
#define TRAPHALF (0xdeff)

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
pthread_mutex_t pid_mutex;
int g_entryCnt = 0;
const int long_size = sizeof(long);
char dlname[128];
char pidName[32];

typedef struct{
    long return_addr; 
    long return_opc;   
    long entry_addr; 
    long entry_opc; 
    UT_hash_handle hh; /*uthash handle*/
}breakPointTable, brpSymbol;
breakPointTable *brptab=NULL, *brp;

struct symbol *symbols = NULL;
int symtot = 0;
unsigned long main_addr = 0;

typedef struct{
    long return_addr; 
	char *backtrace;
    UT_hash_handle hh; /*uthash handle*/
}backTraceCacheTable, btctSymbol;
backTraceCacheTable *btctab=NULL, *btc;

// memleax for compile use
#define BACKTRACE_MAX (5)
uintptr_t g_current_entry;
pid_t g_current_thread;
int opt_backtrace_limit = BACKTRACE_MAX;
const char *opt_debug_info_file;

void getPidName(pid_t pid, char *name)
{
	FILE *filp = NULL;
	char pname[100];
	unsigned long long int x  = 0;

	/* first, init */
	if (filp == NULL) {
		sprintf(pname, "/proc/%d/stat", pid);
		filp = fopen(pname, "r");
		if (filp == NULL) {
			perror("Error in open /proc/pid/stat");
			return;
		}

	}

	fscanf(filp, "%lld ", &x);
	fscanf(filp, "%s ", name);
	fclose(filp);
}

void getdata(pid_t child, long addr, char *str, int len)
{   char *laddr;
    int i, j;
    union u {
            long val;
            char chars[long_size];
    }data;
    
    i = 0;
    j = len / long_size;
    laddr = str;
    while(i < j) {
        data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 4, NULL);
        memcpy(laddr, data.chars, long_size);
        ++i;
        laddr += long_size;
    }
    
    j = len % long_size;
    if(j != 0) {
        data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 4, NULL);
        memcpy(laddr, data.chars, j);
    }
    str[len] = '\0';       
}

long main_orig_opc = 0;
#define MAIN_ADDRESS  main_addr
void set_breakpoint(pid_t child)
{
    long orig = ptrace(PTRACE_PEEKTEXT, child, MAIN_ADDRESS, NULL);
    long trap;

    trap = TRAPINT;
    printf("[+] Add breakpoint on 0x%lx, orig_opc=%#lx \n", MAIN_ADDRESS, orig);

    main_orig_opc = orig;
    ptrace(PTRACE_POKETEXT, child, MAIN_ADDRESS, trap);
    orig = ptrace(PTRACE_PEEKTEXT, child, MAIN_ADDRESS, NULL);

}

void remove_breakpoint(pid_t child)
{
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

	//printf( "read 0x%08lx from %ld:0x%x\n", word, pid, addr);

	return word;
}

/* write a word to child process */
void writechildword(pid_t pid, unsigned long addr, unsigned long word)
{
	unsigned long check;

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

	//printf("wrote 0x%08lx to %ld:0x%x\n", word, pid, addr);
}

/* set breakpoint */
unsigned int setbreakpoint(pid_t exe, unsigned long breakaddr)
{
	unsigned long addr, origdata, data;

	if (!breakaddr || !exe) {
		//printf( "setbreakpoint: invalid parameters\n");
		return 0;
	}
	
	//printf( "setbreakpoint: %ld, 0x%x\n", exe, breakaddr);

	int thumb = 0;

	addr = breakaddr & ~0x1; /* break function with LSB cleared */

	/* arm addresses are 32bit word aligned */
	origdata = readchildword(exe, addr & ~0x3);

	if (breakaddr & 0x1) {
		thumb = 1;
	}

	if ((!thumb) && (addr & 0x2)) {
		printf( "setbreakpoint: arm, address misalignment, 0x%lx\n", addr);
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
		//printf( "clearbreakpoint: invalid parameters\n");
		return;
	}
	
	//printf( "clearbreakpoint: %ld, 0x%x\n", exe, breakaddr);

	int thumb = 0;

	addr = breakaddr & ~0x1; /* break function with LSB cleared */

	/* arm addresses are 32bit word aligned */
	origdata = readchildword(exe, addr & ~0x3);

	if (breakaddr & 0x1) {
		thumb = 1;
	}

	if ((!thumb) && (addr & 0x2)) {
		printf( "clearbreakpoint: arm, address misalignment, 0x%lx\n", addr);
		exit(E_UNKNOWN);
	}

	if (thumb) {
		/* thumb */

		if (addr & 0x2) {
			/* odd half */

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
    fprintf(outfp, "cpsr = 0x%08lx, pc = 0x%08lx\n", regs->regs.ARM_cpsr, regs->regs.ARM_pc);
    fprintf(outfp, "lr   = 0x%08lx, sp = 0x%08lx\n", regs->regs.ARM_lr, regs->regs.ARM_sp);
    fprintf(outfp, "ip   = 0x%08lx, fp = 0x%08lx\n", regs->regs.ARM_ip, regs->regs.ARM_fp);
    fprintf(outfp, "r0   = 0x%08lx, r1 = 0x%08lx\n", regs->regs.ARM_r0, regs->regs.ARM_r1);
    fprintf(outfp, "r2   = 0x%08lx, r3 = 0x%08lx\n", regs->regs.ARM_r2, regs->regs.ARM_r3);
    fprintf(outfp, "r4   = 0x%08lx, r5 = 0x%08lx\n", regs->regs.ARM_r4, regs->regs.ARM_r5);
    fprintf(outfp, "r6   = 0x%08lx, r7 = 0x%08lx\n", regs->regs.ARM_r6, regs->regs.ARM_r7);
    fprintf(outfp, "r8   = 0x%08lx, r9 = 0x%08lx\n", regs->regs.ARM_r8, regs->regs.ARM_r9);
    fprintf(outfp, "\n");
}

static void do_backtrace(pid_t child, long pc,int displayStackFrame) {

	//printf("[%s] pc:%#lx\n",__func__, pc);
	HASH_FIND_INT(btctab, &pc, btc);
	if(btc)
	{
		//printf("[cache] RA:%#lx\n",btc->return_addr);
		//printf("[cache] BT:%s\n",btc->backtrace);
		return;
	}else{
		ui = _UPT_create(child);
		if (!ui) {
			printf("_UPT_create failed");
		}

		unw_cursor_t c;
		int backTaceLevel = 0;
		int rc = unw_init_remote(&c, as, ui);
		if (rc != 0) {
			printf("unw_init_remote: %s\n", unw_strerror(rc));
		}

		if(displayStackFrame==1)
			printf("### backtrace start ###\n");
		
		char backTraceRec[256];
		char *cur = backTraceRec, * const end = backTraceRec + sizeof(backTraceRec);
		memset(backTraceRec,0,sizeof(backTraceRec));
		do {
			unw_word_t  offset, pc;
			char fname[64];
			unw_get_reg(&c, UNW_REG_IP, &pc);
			fname[0] = '\0';
			(void) unw_get_proc_name(&c, fname, sizeof(fname), &offset);
			if(displayStackFrame==1)
				printf("%p : (%s+0x%x)\n", (void *)pc, fname, (int) offset);
			if (cur < end) {
				cur += snprintf(cur, end-cur, "\n%p:(%s+0x%x)\n", (void *)pc, fname, (int) offset);
			}
			backTaceLevel++;
		} while ((unw_step(&c) > 0) && (backTaceLevel < BACKTRACE_MAX));
		if(displayStackFrame==1)
			printf("### backtrace end ###\n\n");

		// do cache
		btc = (btctSymbol*)malloc(sizeof(btctSymbol));
		btc->return_addr = pc;
		btc->backtrace = strdup(backTraceRec);
		HASH_ADD_INT(btctab, return_addr, btc);

		_UPT_destroy(ui);
	}
}

static void signal_handler(int signo)
{
	printf("send SIGINT signal\n");
	//ptrace(PTRACE_KILL, g_child,0,0);
	kill(g_child, SIGINT);
}

int main(int argc __attribute__((unused)), char **argv, char **envp) 
{
	pid_t new_child;
	pid_t clone_child;
	int maxChildPid=0;

    if(argc == 1)
    {
        fprintf(stderr, "usage memtrace <bin>\n");
        exit(-1);
    }

    char *path = argv[1];
    char *name = strrchr(path, '/');
    if(name){
        name += 1;        
    }else{
        name = path;
    }

    symtot = readsyms(&symbols, path, 0, 0);
    //printf("elf symbol:%d\n", symtot);
    //display_symbols(symbols, symtot);
    main_addr = symaddr(symbols, symtot, "main");
    printf("### main addr = %#lx\n", main_addr);

	signal(SIGINT, signal_handler);

	pthread_mutex_init(&pid_mutex,NULL);
	g_child = fork();

    // setup libunwind
	as = unw_create_addr_space(&_UPT_accessors, 0);
	if (!as) {
		printf("unw_create_addr_space failed");
		exit(-1);
	}
	unw_set_caching_policy(as, UNW_CACHE_GLOBAL);

	if (!g_child) {
		ptrace(PTRACE_TRACEME, g_child,0,0);
		execve(path, argv, envp);
		return 0;
	} else {
		g_mainPid = getpid();
        printf("### g_child: %d\n", g_child);
        printf("### g_mainPid: %d\n", g_mainPid);
			
		int status;
      
		new_child = waitpid(-1, &status, __WALL);
		if (WIFSTOPPED(status)) {
			printf("### pid: %d, stop signal: %d\n", new_child, WSTOPSIG(status));  
			ptrace(PTRACE_SETOPTIONS, new_child, NULL, PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEFORK | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT);
            /* breakpoint in main */
            set_breakpoint(g_child);
		}
		ptrace(PTRACE_CONT,new_child, NULL, NULL);
        /* trace pid */
		while(1) {
            new_child = waitpid(-1, &status, __WALL);
			//pthread_mutex_lock(&pid_mutex);
            memset(&regs, 0, sizeof(regs));
            ptrace(PTRACE_GETREGS, new_child, NULL, &regs);
            //dump_regs(&regs, stdout);

            //printf("##[wait] status:%#x , sig:%d, pid:%d \n", status, WSTOPSIG(status), new_child);
			if(new_child == -1)
				break;

            if (WIFSTOPPED(status)) {
                //printf("##[WIFSTOPPED] status:%#x , sig:%d, pid:%d \n", status, WSTOPSIG(status), new_child);
				if(WSTOPSIG(status)== SIGILL)
                {  
					if ((bp = breakpoint_by_entry(regs.regs.ARM_pc)) != NULL)
					{
						g_entryCnt++;
						/* recover entry code */
						clearbreakpoint(new_child, bp->entry_address, bp->entry_code);

						/* set breakpoint at return address */
						return_address = regs.regs.ARM_lr;
						//return_code = ptrace((__ptrace_request)PTRACE_PEEKTEXT, new_child, return_address);
						breaktrap = setbreakpoint(new_child, return_address);
						//printf("### [pid: %d] function entry: symbol = %s, address:%#x, g_entryCnt=%d\n", new_child, bp->name, bp->entry_address, g_entryCnt);
						//printf("### [pid: %d] function return address:%#x\n", new_child, return_address);
						brp = (brpSymbol*)malloc(sizeof(brpSymbol));
						brp->return_addr = return_address;
						brp->return_opc = breaktrap;
						brp->entry_addr = bp->entry_address;
						brp->entry_opc = bp->entry_code;
						HASH_ADD_INT(brptab, return_addr, brp);
						/* save arguments */
						arg1 = regs.regs.ARM_r0;
						arg2 = regs.regs.ARM_r1;
						if(strcmp("dlopen", bp->name) == 0)
						{
							memset(dlname,0,sizeof(dlname));
							getdata(new_child, arg1, dlname, 32);
							printf("#### call dlopen: %s \n", dlname);
						}
						//dump_regs(&regs, stdout);
					} else {
						//printf("##[SIGILL] status:%#x , sig:%d, pid:%d \n", status, WSTOPSIG(status), new_child);
						long pc =  regs.regs.ARM_pc + 1;
						HASH_FIND_INT(brptab, &pc, brp);
						if(brp){
							//dump_regs(&regs, stdout);
							g_entryCnt--;
							HASH_DEL(brptab, brp);

							/* -- at function return */
							//printf("### function return: RA:%#x, g_entryCnt=%d\n", brp->return_addr, g_entryCnt);
							clearbreakpoint(new_child, brp->return_addr, brp->return_opc);
							bp = breakpoint_by_entry( brp->entry_addr);

							g_current_entry = brp->entry_addr;	
							g_current_thread = new_child;

							//printf("## caller:%s, RA:%#lx\n", bp->name, brp->return_addr);
							
							do_backtrace(new_child, brp->return_addr,0);
							//callstack_print(callstack_current());
							if(strcmp("dlopen", bp->name) == 0)
							{
								int i;
								const char *path = NULL;
								size_t start, end;
								for(i=g_child;i<=maxChildPid;i++)
								{
									path = proc_maps_by_name(new_child, dlname,&start, &end);
									if(path != NULL)
									{	
										//printf("#### pid:%d, solib path:%s, start:%#x, end:%#x\n", i,path,start,end);
										//ptr_maps_build_file(path, start, end);
										break;
									}
								}
							}else{
								if (bp->handler(regs.regs.ARM_r0, arg1, arg2) != 0) {
									printf("\n== Not enough memory.\n");
									break;
								}
							}
							/*restore instruction(s)*/
							//printf("### recovery breakpoint: entry_address:%#x \n\n", brp->entry_addr);
							breaktrap = setbreakpoint(new_child, brp->entry_addr);
							free(brp);
						}
					}
				}
				if(WSTOPSIG(status)== SIGTRAP)
				{

				}
				if(WSTOPSIG(status)== SIGINT)
				{
					ptrace(PTRACE_CONT, new_child, NULL, SIGINT);
					//ptrace(PTRACE_KILL, new_child,0,0);
					printf("### kill pid:%d, sig:%d\n", new_child, WSTOPSIG(status));
                }
				if((g_readelf == 0) && (new_child == g_child))
				{
					//printf("### pid:%d, load symbol table, sig:%d\n", new_child, WSTOPSIG(status));
					//addr_maps_build(g_child);
					//ptr_maps_build(g_child);
					symtab_build(g_child);
					/* malloc .... breakpoint */
					breakpoint_init(g_child);
					remove_breakpoint(g_child);
					g_readelf = 1;
				}
				if(WSTOPSIG(status)== SIGSEGV)
                {
					int i;
					for(i=g_child;i<=maxChildPid;i++)
                    {
						printf("### [SIGSEGV] pid: %d, stop signal: %d\n", i, WSTOPSIG(status));  
                    	do_backtrace(i, 0, 1);
                    }
					dump_regs(&regs, stdout);
                    break;
                }
				ptrace(PTRACE_CONT,new_child, NULL, NULL);
			}

			if (status>>8 == (SIGTRAP | (PTRACE_EVENT_EXEC<<8))) {
				ptrace(PTRACE_GETEVENTMSG, new_child, 0, &clone_child);
				//printf("### PTRACE_EVENT_EXEC child %d\n", clone_child);  
				if(maxChildPid < clone_child)
					maxChildPid = clone_child;
			}
			if (status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8))) {
				ptrace(PTRACE_GETEVENTMSG, new_child, 0, &clone_child);
				//printf("### PTRACE_EVENT_CLONE child %d\n", clone_child);  
				if(maxChildPid < clone_child)
					maxChildPid = clone_child;
			}
			if (status>>8 == (SIGTRAP | (PTRACE_EVENT_EXIT<<8))) {
				memset(pidName,0,sizeof(pidName));
				getPidName(new_child, pidName);
				printf("### pid %d %s exit \n", new_child, pidName);
			}	
			if (status>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8))) {
				ptrace(PTRACE_GETEVENTMSG, new_child, 0, &clone_child);
				//printf("### PTRACE_EVENT_VFORK child %d\n", clone_child);  
				if(maxChildPid < clone_child)
					maxChildPid = clone_child;
			}
			if (status>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK_DONE<<8))) {
				ptrace(PTRACE_GETEVENTMSG, new_child, 0, &clone_child);
				//printf("### PTRACE_EVENT_VFORK_DONE child %d\n", clone_child);  
				if(maxChildPid < clone_child)
					maxChildPid = clone_child;
			}
			if (status >>8 == PTRACE_EVENT_FORK) {
				ptrace(PTRACE_GETEVENTMSG, new_child, 0, &clone_child);
				//printf("### PTRACE_EVENT_FORK child %d\n", clone_child);  
				if(maxChildPid < clone_child)
					maxChildPid = clone_child;
			}

			if(WIFEXITED(status)) {
				//printf("### pid %d exited\n", new_child);
				if(new_child==-1)
				{
					break;
				}
				if(new_child==g_child)
				{
					break;
				}
			}
			//pthread_mutex_unlock(&pid_mutex);
		}
	}

	breakpoint_cleanup(g_child);
	pthread_mutex_destroy(&pid_mutex);
	unw_destroy_addr_space(as);
	printf("memtrace exit\n");
	return 0;
}
