#ifndef MLD_MEMLEAK_H
#define MLD_MEMLEAK_H

#include <stdint.h>

extern pid_t g_current_thread;
extern uintptr_t g_current_entry;
extern int opt_backtrace_limit;
extern const char *opt_debug_info_file;

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"
#define printf(fmt, args...)     printf(ANSI_COLOR_RED "[memtrace] " fmt ANSI_COLOR_RESET "\n", ## args)
#define log_debug(...) printf(__VA_ARGS__)

#endif
