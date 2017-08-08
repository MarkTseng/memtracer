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
#include <sched.h>
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
#include "minigdb.h"
#include "breakpoint.h"
#include "symtab.h"
#include "debug_line.h"
#include "proc_info.h"
#include "list.h"
#include "hash.h"
#include "ptrace_utils.h"
#include "memblock.h"

// global variable
pid_t g_child;
pid_t g_mainPid;
struct user regs;
static unw_addr_space_t as;
static struct UPT_info *ui;
static int g_readelf = 0;
struct breakpoint_s *bp = NULL;
uintptr_t return_address = 0, return_code = 0;
unsigned long breaktrap1 = 0;
unsigned long breaktrap2 = 0;
int sig = 0;
int ptrace_event = 0;
int g_entryCnt = 0;
const int long_size = sizeof(long);
char dlname[128];
char pidName[32];

typedef struct{
    long return_addr; 
    long return_opc;   
    long entry_addr; 
    long entry_opc; 
	uintptr_t arg1;
	uintptr_t arg2;
	int pid;
    UT_hash_handle hh; /*uthash handle*/
}breakPointTable, brpSymbol;
breakPointTable *brptab=NULL, *brp;

struct symbol *symbols = NULL;
int symtot = 0;
unsigned long main_addr = 0;
long main_orig_opc = 0;

typedef struct{
    long return_addr; 
	char *backtrace;
    UT_hash_handle hh; /*uthash handle*/
}backTraceCacheTable, btctSymbol;
backTraceCacheTable *btctab=NULL, *btc;

// memleax for compile use
#define BACKTRACE_MAX (10)
int opt_backtrace_limit = BACKTRACE_MAX;
const char *opt_debug_info_file;

void deleteAllList()
{
	btctSymbol *current_btct, *btct_tmp;
	brpSymbol *current_brp, *brp_tmp;

	// free backTraceCacheTable
	HASH_ITER(hh, btctab, current_btct, btct_tmp) {
		HASH_DEL(btctab, current_btct);  /* delete it (users advances to next) */
		free(current_btct->backtrace);
		free(current_btct);             /* free it */
	}

	// free breakPointTable
	HASH_ITER(hh, brptab, current_brp, brp_tmp) {
		HASH_DEL(brptab, current_brp);  /* delete it (users advances to next) */
		free(current_brp);             /* free it */
	}
}

void dumpAllBrkList(pid_t pid)
{
	brpSymbol *current_brp, *brp_tmp;

	// free breakPointTable
	HASH_ITER(hh, brptab, current_brp, brp_tmp) {
		YELLOWprintf("RA:%#lx, opc:%#lx",current_brp->return_addr,  ptrace(PTRACE_PEEKTEXT, pid, current_brp->return_addr & ~0x1));
		YELLOWprintf("EA:%#lx, opc:%#lx",current_brp->entry_addr, ptrace(PTRACE_PEEKTEXT, pid, current_brp->entry_addr & ~0x1));
	}
}

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
			//perror("Error in open /proc/pid/stat");
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

	//printf("[%s] pc:%#lx",__func__, pc);
	HASH_FIND_INT(btctab, &pc, btc);
	if(btc)
	{
		if(displayStackFrame==1)
		{
			printf("[cache] RA:%#lx",btc->return_addr);
			printf("[cache] BT:%s",btc->backtrace);
		}
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
			printf("unw_init_remote: %s", unw_strerror(rc));
		}

		if(displayStackFrame==1)
			printf("backtrace start");
		
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
				printf("%p(%#lx) : (%s+0x%x)\n", (void *)pc, ptrace(PTRACE_PEEKTEXT, child, pc),fname, (int) offset);
			if (cur < end) {
				cur += snprintf(cur, end-cur, "\n%p:(%s+0x%x)\n", (void *)pc, fname, (int) offset);
			}
			backTaceLevel++;
		} while ((unw_step(&c) > 0) && (backTaceLevel < BACKTRACE_MAX));
		if(displayStackFrame==1)
			printf("backtrace end\n");

		// do cache
		if(pc!=0)
		{
			btc = (btctSymbol*)malloc(sizeof(btctSymbol));
			btc->return_addr = pc;
			btc->backtrace = strdup(backTraceRec);
			HASH_ADD_INT(btctab, return_addr, btc);
		}
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
	int status;
	struct sched_param param;

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
    //printf("elf symbol:%d", symtot);
    //display_symbols(symbols, symtot);
    main_addr = symaddr(symbols, symtot, "main");
    printf("main addr = %#lx", main_addr);

	signal(SIGINT, signal_handler);

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
        printf("g_child: %d", g_child);
        printf("g_mainPid: %d", g_mainPid);
		param.sched_priority = sched_get_priority_max(SCHED_FIFO);
		if( sched_setscheduler( 0, SCHED_FIFO, &param ) == -1 ) {
			perror("no permission to get SCHED_FIFO");
			exit(1);
		}
		new_child = waitpid(-1, &status, __WALL);
		if (WIFSTOPPED(status)) {
			printf("pid: %d, stop signal: %d", new_child, WSTOPSIG(status));  
			ptrace(PTRACE_SETOPTIONS, new_child, NULL, PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEFORK | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT);
            /* breakpoint in main */
			main_orig_opc = setbreakpoint(g_child, main_addr);
		}
		ptrace(PTRACE_CONT,new_child, NULL, NULL);
        /* trace pid */
		while(1) {
            new_child = waitpid(-1, &status, __WALL);
			// set all breakpoint
			if((g_readelf == 0) && (new_child == g_child))
			{
				//printf("pid:%d, load symbol table, sig:%d", new_child, WSTOPSIG(status));
				symtab_build(g_child);
				breakpoint_init(g_child);
				clearbreakpoint(g_child, main_addr, main_orig_opc);
				printf("clearbreakpoint main_addr:%#lx", main_addr);
				g_readelf = 1;
			}

            memset(&regs, 0, sizeof(regs));
            ptrace(PTRACE_GETREGS, new_child, NULL, &regs);
			ptrace_event = (status >> 16) & 0xff;
			sig = WSTOPSIG(status);
            //dump_regs(&regs, stdout);
            //printf("[wait] status:%#x , sig:%d, pid:%d ", status, WSTOPSIG(status), new_child);
			if(new_child == -1)
				break;
#ifndef RPI
			long pc =  regs.regs.ARM_pc + 1;
#else
			long pc =  regs.regs.ARM_pc;
#endif
			//printf("pc:%#lx", pc);
			//dumpAllBrkList(new_child);
            if (WIFSTOPPED(status)) {
                //printf("[WIFSTOPPED] status:%#x , sig:%d, pid:%d ", status, WSTOPSIG(status), new_child);
				if(WSTOPSIG(status)== SIGILL)
                {  
					if ((bp = breakpoint_by_entry(pc)) != NULL)
					{
						//printf("pc in brp:%#lx", pc);
						g_entryCnt++;
						/* recover entry code */
						clearbreakpoint(new_child, bp->entry_address, bp->entry_code);
						//YELLOWprintf("pc:%#lx, opc:%#lx,g_entryCnt:%d, pid:%d in hashlist", pc, ptrace(PTRACE_PEEKTEXT, new_child, pc), g_entryCnt, new_child);

						/* set breakpoint at return address */
						breaktrap1 = setbreakpoint(new_child, regs.regs.ARM_lr);
						//printf("RA brp set:%#lx", regs.regs.ARM_lr);
						//printf("[pid: %d] function entry: symbol = %s, address:%#x, g_entryCnt=%d, RA:%#lx", new_child, bp->name, bp->entry_address, g_entryCnt, regs.regs.ARM_lr);
						brp = (brpSymbol*)malloc(sizeof(brpSymbol));
						brp->return_addr = regs.regs.ARM_lr;
						brp->return_opc = breaktrap1;
						brp->entry_addr = bp->entry_address;
						brp->entry_opc = bp->entry_code;
						brp->arg1 = regs.regs.ARM_r0;
						brp->arg2 = regs.regs.ARM_r1;
						HASH_ADD_INT(brptab, return_addr, brp);

						if(strcmp("dlopen", bp->name) == 0)
						{
							memset(dlname,0,sizeof(dlname));
							getdata(new_child, brp->arg1, dlname, 32);
							printf("call dlopen: %s ", dlname);
						}
						//dump_regs(&regs, stdout);
					} else {
						//pc+=1;
						//printf("pc in RA:%#lx", pc);
						HASH_FIND_INT(brptab, &pc, brp);
						if(brp){
							//dump_regs(&regs, stdout);
							g_entryCnt--;
							/* -- at function return */
							//YELLOWprintf("function return address: %#lx", brp->return_addr);
							clearbreakpoint(new_child, brp->return_addr, brp->return_opc);
							bp = breakpoint_by_entry( brp->entry_addr);
							//printf("calle%s, R%#lx", bp->name, brp->return_addr);
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
										//printf("pid:%d, solib path:%s, star%#x, end:%#x", i,path,start,end);
										symtab_build_file(path, start, end);
										break;
									}
								}
							}
							//printf("[%d] caller: %s, ret=%#lx, argv1=%#lx, argv2=%#lx", new_child, bp->name, regs.regs.ARM_r0, brp->arg1, brp->arg2);
                    		do_backtrace(new_child, 0, 1);
							if (bp->handler(regs.regs.ARM_r0, brp->arg1, brp->arg2) != 0) {
								printf("\n== Not enough memory.");
								break;
							}
							
							/*restore instruction(s)*/
							//printf("recovery breakpoin entry_address:%#x", brp->entry_addr);
							breaktrap2 = setbreakpoint(new_child, brp->entry_addr);
							HASH_DEL(brptab, brp);
							free(brp);
						}else{
							//YELLOWprintf("WARNG: Can not found pc:%#lx, opc:%#lx,g_entryCnt:%d, pid:%d in hashlist", pc, ptrace(PTRACE_PEEKTEXT, new_child, pc), g_entryCnt, new_child);
							//dumpAllBrkList(new_child);
							//dump_regs(&regs, stdout);
                    		//do_backtrace(new_child, 0, 1);
						}
					}
				}

				if(WSTOPSIG(status)== SIGTRAP)
				{
					//YELLOWprintf("ptrace_event:%d, sig:%d \n", ptrace_event, sig);
					//YELLOWprintf("pc:%#lx, opc:%#lx,g_entryCnt:%d in hashlist", pc, ptrace(PTRACE_PEEKTEXT, new_child, pc), g_entryCnt);
					if (ptrace_event == PTRACE_EVENT_EXEC) 
					{
						ptrace(PTRACE_GETEVENTMSG, new_child, 0, &clone_child);
						//printf("PTRACE_EVENT_EXEC child %d", clone_child);  
						if(maxChildPid < clone_child)
							maxChildPid = clone_child;
					}

					if (ptrace_event == PTRACE_EVENT_CLONE) 
					{
						ptrace(PTRACE_GETEVENTMSG, new_child, 0, &clone_child);
						//printf("PTRACE_EVENT_CLONE: new_child: %d, clone_child: %d", new_child, clone_child);  
						printf("pid %d create", clone_child);
						if(maxChildPid < clone_child)
							maxChildPid = clone_child;
					}

					if (ptrace_event == PTRACE_EVENT_EXIT) 
					{
						memset(pidName,0,sizeof(pidName));
						getPidName(new_child, pidName);
						printf("pid %d %s exit", new_child, pidName);
					}	

				}

				if(WSTOPSIG(status)== SIGINT)
				{
					ptrace(PTRACE_CONT, new_child, NULL, SIGINT);
					//ptrace(PTRACE_KILL, new_child,0,0);
					printf("kill pid:%d, sig:%d", new_child, WSTOPSIG(status));
                }

				if(WSTOPSIG(status)== SIGSEGV)
                {
					int i;
					breakpoint_cleanup(g_child);
					for(i=g_child;i<=maxChildPid;i++)
                    {
						memset(pidName,0,sizeof(pidName));
						getPidName(i, pidName);
						if(strlen(pidName)!=0)
						{
							printf("[SIGSEGV] pid: %d %s, stop signal: %d", i, pidName, WSTOPSIG(status));  
                    		do_backtrace(i, 0, 1);
						}
                    }
					dump_regs(&regs, stdout);
                    break;
                }
				ptrace(PTRACE_CONT,new_child, NULL, NULL);
			}

			if(WIFEXITED(status)) {
				if(new_child==-1)
				{
					break;
				}
				if(new_child==g_child)
				{
					break;
				}
			}
		}
	}

	breakpoint_cleanup(g_child);
	unw_destroy_addr_space(as);
	deleteAllList();
	memblock_dump();
	printf("memtrace exit");
	return 0;
}
