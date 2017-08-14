#ifndef MLD_PTRACE_UTILS_H
#define MLD_PTRACE_UTILS_H

#include <sys/ptrace.h>
#include <stdio.h>
#include <libunwind.h>

#include <sys/user.h>
#include <stdint.h>

typedef struct user_regs_struct registers_info_t;
#define REG_RAX(ri) (ri).rax
#define REG_RIP(ri) (ri).rip
#define REG_RSI(ri) (ri).rsi
#define REG_RDI(ri) (ri).rdi
#define REG_RSP(ri) (ri).rsp

// define
#define ERR -1
#define E_OK 0
#define E_ARGS 1
#define E_MALLOC 2
#define E_FORK 3
#define E_PTRACE 4
#define E_UNKNOWN 5
//#define TRAPINT (0xe7ffffff)
#define TRAPINT (0xe7f001f0) //{ 0xf0, 0x01, 0xf0, 0xe7 }
//#define TRAPHALF (0xde01)
#define TRAPHALF (0xde01) //{ 0x01, 0xde }

int isintbreakpoint(int trapint, int lsb);
unsigned long readchildword(pid_t pid, unsigned long addr);
void writechildword(pid_t pid, unsigned long addr, unsigned long word);
unsigned int setbreakpoint(pid_t exe, unsigned long breakaddr);
void clearbreakpoint(pid_t exe, unsigned long breakaddr, unsigned int origint);
void ptrace_get_regs(pid_t pid, struct user_regs_struct *regs);
void ptrace_set_regs(pid_t pid, struct user_regs_struct *regs);
uintptr_t ptrace_get_data(pid_t pid, uintptr_t address);
void ptrace_set_data(pid_t pid, uintptr_t address, uintptr_t data);
void ptrace_set_int3(pid_t pid, uintptr_t address, uintptr_t code);
uintptr_t ptrace_get_child(pid_t pid);
int ptrace_new_child(pid_t pid, int status);
void ptrace_continue(pid_t pid, int signum);
void ptrace_attach(pid_t pid);
void ptrace_trace_child(pid_t pid);
void ptrace_detach(pid_t pid, int signum);
void do_backtrace(pid_t child, long pc,int displayStackFrame);
void deleteCacheList();
void backtrace_init();
void backtrace_deinit();
#endif
