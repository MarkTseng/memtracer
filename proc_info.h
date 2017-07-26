#ifndef MLD_PROC_MAPS_H
#define MLD_PROC_MAPS_H

#include <sys/types.h>
#include <stddef.h>

const char *proc_maps(pid_t pid, size_t *start, size_t *end, int *exe_self);
const char *proc_maps_by_name(pid_t pid, char *libPath,size_t *start, size_t *end);
pid_t proc_tasks(pid_t pid);
int proc_task_check(pid_t pid, pid_t child);

#endif
