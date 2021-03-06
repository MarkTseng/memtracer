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
#include "breakblock.h"

// global variable
pid_t g_child;
pid_t g_mainPid;
struct user regs;
static int g_readelf = 0;
struct breakpoint_s *bp = NULL;
uintptr_t return_address = 0, return_code = 0;
unsigned long int breaktrap1 = 0;
unsigned long int breaktrap2 = 0;
int sig = 0;
int ptrace_event = 0;
int g_entryCnt = 0;
const int long_size = sizeof(long);
char dlname[128];
char pidName[32];

typedef struct{
    unsigned long int return_addr; 
    unsigned long int return_opc;   
    unsigned long int entry_addr; 
    unsigned long int entry_opc; 
	unsigned long int arg1;
	unsigned long int arg2;
	int pid;
    UT_hash_handle hh; /*uthash handle*/
}breakPointTable, brpSymbol;
breakPointTable *brptab=NULL, *brp;

struct symbol *symbols = NULL;
int symtot = 0;
unsigned long int main_addr = 0;
unsigned long int main_orig_opc = 0;

const char *opt_debug_info_file;

pthread_t jobqueue_thread;;
int job_queue_exit = 0;
void *jobqueue(void *x_void_ptr)
{
	while(!job_queue_exit)
	{
		printf("do queue\n");
		sleep(1);
	}
	return NULL;
}

void deleteAllList()
{
	brpSymbol *current_brp, *brp_tmp;

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
	backtrace_init();
	
#if 0
	if(pthread_create(&jobqueue_thread, NULL, jobqueue, NULL)) {

		fprintf(stderr, "Error creating thread\n");
		return 1;
	}
	pthread_detach(jobqueue_thread);
#endif
	// fork child
	g_child = fork();
	if (!g_child) {
		ptrace(PTRACE_TRACEME, g_child,0,0);
		execve(path, argv, envp);
		return 0;
	} else {
		g_mainPid = getpid();
        printf("g_child: %d", g_child);
        printf("g_mainPid: %d", g_mainPid);
#if 1
		param.sched_priority = sched_get_priority_max(SCHED_FIFO);
		if( sched_setscheduler( 0, SCHED_FIFO, &param ) == -1 ) {
			perror("no permission to get SCHED_FIFO");
			exit(1);
		}
#endif
		new_child = waitpid(g_child, &status, __WALL);
		if (WIFSTOPPED(status)) {
			printf("pid: %d, stop signal: %d", new_child, WSTOPSIG(status));  
			ptrace(PTRACE_SETOPTIONS, new_child, NULL, PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEFORK | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACESECCOMP | PTRACE_O_TRACEVFORKDONE | PTRACE_O_EXITKILL);
            /* breakpoint in main */
			main_orig_opc = setbreakpoint(g_child, main_addr);
		}
		ptrace(PTRACE_CONT,new_child, NULL, NULL);

        /* trace pid */
		while(1) {
			errno = 0;
            new_child = waitpid(-1, &status, __WALL);

			if (new_child == -1) {
				if (errno == ECHILD) {
					printf("event: No more traced programs: exiting");
					break;
				} else if (errno == EINTR) {
					printf("event: none (wait received EINTR?)");
				}
				perror("wait");
				break;
			}

			// set all breakpoint
			if((g_readelf == 0) && (new_child == g_child))
			{
				symtab_build(g_child);
				breakpoint_init(g_child);
				clearbreakpoint(g_child, main_addr, main_orig_opc);
				printf("clearbreakpoint main_addr:%#lx", main_addr);
				g_readelf = 1;
				ptrace(PTRACE_CONT,new_child, NULL, NULL);
				continue;
			}

            memset(&regs, 0, sizeof(regs));
            ptrace(PTRACE_GETREGS, new_child, NULL, &regs);
			ptrace_event = (status >> 16) & 0xff;
			sig = WSTOPSIG(status);
            //dump_regs(&regs, stdout);
#ifndef RPI
			unsigned long int pc =  regs.regs.ARM_pc + 1;
#else
			unsigned long int pc =  regs.regs.ARM_pc;
#endif
			if(pc == 0x0)
			{
            	//dump_regs(&regs, stdout);
				continue;
			}

			unsigned long int pc_opc =  readchildword(new_child, regs.regs.ARM_pc);
				
            //do_backtrace(new_child, 0, 1);
            if (WIFSTOPPED(status)) {

				bp = breakpoint_by_entry(pc);
				if(bp)
					printf("[%d][STOPPED] status:%#x , sig:%d, pc:%#lx(%s), opc:%#lx, brkp:%d ", new_child, status, WSTOPSIG(status), pc, bp->name, pc_opc,isbreakpoint(pc_opc));
				else
					printf("[%d][STOPPED] status:%#x , sig:%d, pc:%#lx, opc:%#lx, brkp:%d ", new_child, status, WSTOPSIG(status), pc, pc_opc,isbreakpoint(pc_opc));

				if(WSTOPSIG(status)== SIGTRAP)
				{
					//YELLOWprintf("ptrace_event:%d, sig:%d \n", ptrace_event, sig);
					if (ptrace_event == PTRACE_EVENT_EXEC) 
					{
						ptrace(PTRACE_GETEVENTMSG, new_child, 0, &clone_child);
						YELLOWprintf("PTRACE_EVENT_EXEC child %d", clone_child);  
						if(maxChildPid < clone_child)
							maxChildPid = clone_child;
					}

					if (ptrace_event == PTRACE_EVENT_CLONE) 
					{
						ptrace(PTRACE_GETEVENTMSG, new_child, 0, &clone_child);
						//printf("PTRACE_EVENT_CLONE: new_child: %d, clone_child: %d", new_child, clone_child);  
						YELLOWprintf("pid %d create", clone_child);
						ptrace(PTRACE_SETOPTIONS, new_child, NULL, PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEFORK | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACESECCOMP | PTRACE_O_TRACEVFORKDONE | PTRACE_O_EXITKILL);
						if(maxChildPid < clone_child)
							maxChildPid = clone_child;
					}

					if (ptrace_event == PTRACE_EVENT_EXIT) 
					{
						memset(pidName,0,sizeof(pidName));
						getPidName(new_child, pidName);
						YELLOWprintf("pid %d %s exit", new_child, pidName);
						ptrace(PTRACE_CONT,new_child, NULL, NULL);
						continue;
					}	
					if (ptrace_event == PTRACE_EVENT_VFORK) 
					{
						ptrace(PTRACE_GETEVENTMSG, new_child, 0, &clone_child);
						YELLOWprintf("PTRACE_EVENT_VFORK child %d", clone_child);  
						if(maxChildPid < clone_child)
							maxChildPid = clone_child;
					}
					if (ptrace_event == PTRACE_EVENT_FORK) 
					{
						ptrace(PTRACE_GETEVENTMSG, new_child, 0, &clone_child);
						YELLOWprintf("PTRACE_EVENT_FORK child %d", clone_child);  
						if(maxChildPid < clone_child)
							maxChildPid = clone_child;
					}
				}

				if(!isbreakpoint(pc_opc))
				{
					ptrace(PTRACE_CONT,new_child, NULL, NULL);
					continue;
				}

				if(WSTOPSIG(status)== SIGTRAP)
                {  
#if 0
					bp = breakpoint_by_entry(pc);
					if(bp != NULL)
            			printf("[%d][STOP][SIGILL] status:%#x , sig:%d, g_entryCnt:%d, pc:%#lx, symbol:%s", new_child, status, WSTOPSIG(status), g_entryCnt, pc, bmp->name);
					else
            			printf("[%d][STOP][SIGILL] status:%#x , sig:%d, g_entryCnt:%d, pc:%#lx", new_child, status, WSTOPSIG(status), g_entryCnt, pc);
#endif					
					struct breakblock_s *bb = NULL;
					bb = breakblock_search(pc, new_child);
					if(bb!=NULL)
					{
						/* -- at function return */
						clearbreakpoint(new_child, bb->return_addr, bb->return_opc);
						bp = breakpoint_by_entry(bb->entry_addr);
						//do_backtrace(new_child, pc,0);
#if 0
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
#endif
#if 1
						if(bp)
						{
							if(bp->handler(new_child, regs.regs.ARM_r0, bb->arg1, bb->arg2))
							{
								dump_regs(&regs, stdout);
							}
						}else{
							YELLOWprintf("WARN: Can not found bp");
						}
#endif
						/*restore instruction(s)*/
						setbreakpoint(new_child, bb->entry_addr);
						//do_backtrace(new_child, pc,0);
						breakblock_delete(bb);
						g_entryCnt--;
						//printf("[%d] function_return: symbol:%s, RA:%#lx, ret=%#lx, argv1=%#lx, argv2=%#lx, pid:%d, g_entryCnt:%d", new_child, bp->name, bb->return_addr, regs.regs.ARM_r0, bb->arg1, bb->arg2, bb->pid,g_entryCnt);

						ptrace(PTRACE_CONT,new_child, NULL, NULL);
						//kill(new_child, SIGCONT);
						continue;
					}

					// maybe pc in breakpoint
					if ((bp = breakpoint_by_entry(pc)) != NULL)
					{
						/* recover entry code */
						clearbreakpoint(new_child, bp->entry_address, bp->entry_code);

						/* set breakpoint at return address */
						breaktrap1 = setbreakpoint(new_child, regs.regs.ARM_lr);
						g_entryCnt++;
						//printf("[%d] function_entry: symbol = %s, RA:%#lx, g_entryCnt=%d, argv1:%#lx, argv2:%#lx, g_entryCnt:%d", new_child, bp->name, regs.regs.ARM_lr, g_entryCnt, regs.regs.ARM_r0, regs.regs.ARM_r1,g_entryCnt);
#if 0
						brp = (brpSymbol*)malloc(sizeof(brpSymbol));
						brp->return_addr = regs.regs.ARM_lr;
						brp->return_opc = breaktrap1;
						brp->entry_addr = bp->entry_address;
						brp->entry_opc = bp->entry_code;
						brp->arg1 = regs.regs.ARM_r0;
						brp->arg2 = regs.regs.ARM_r1;
						brp->pid = new_child;
						HASH_ADD_INT(brptab, return_addr, brp);
#endif
						breakblock_new(regs.regs.ARM_lr, breaktrap1, bp->entry_address, bp->entry_code, regs.regs.ARM_r0, regs.regs.ARM_r1, new_child, bp->name);

#if 1
						unsigned long int arg1 = regs.regs.ARM_r0;
						if(strcmp("dlopen", bp->name) == 0)
						{
							memset(dlname,0,sizeof(dlname));
							getdata(new_child, arg1, dlname, 32);
							printf("call dlopen: %s ", dlname);
						}
#endif
					}

					ptrace(PTRACE_CONT,new_child, NULL, NULL);
					//kill(new_child, SIGCONT);
					continue;
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
			}

			if(WIFEXITED(status)) {

				if(new_child==-1)
				{
					printf("exit");
					break;
				}
			}
			ptrace(PTRACE_CONT,new_child, NULL, NULL);
            YELLOWprintf("[%d][WARN] status:%#x , sig:%d, pc:%#lx ", new_child, status, WSTOPSIG(status), pc);
		}
	}

	breakpoint_cleanup(g_child);
	deleteAllList();
	memblock_dump(1);
	backtrace_deinit();
	breakblock_dump(1);
	printf("memtrace exit");
	return 0;
}
