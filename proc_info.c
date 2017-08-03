/*
 * read process information, on GNU/Linux and FreeBSD
 *
 * Author: Wu Bingzheng
 *   Date: 2016-5
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "proc_info.h"

#include <dirent.h>
#include <unistd.h>
const char *proc_maps(pid_t pid, size_t *start, size_t *end, int *exe_self)
{
	static FILE *filp = NULL;
	static char exe_name[1024];
	static char ret_path[1024];

	/* first, init */
	if (filp == NULL) {
		char pname[100];
		sprintf(pname, "/proc/%d/maps", pid);
		filp = fopen(pname, "r");
		if (filp == NULL) {
			perror("Error in open /proc/pid/maps");
			exit(3);
		}

		sprintf(pname, "/proc/%d/exe", pid);
		int exe_len = readlink(pname, exe_name, sizeof(exe_name));
		if (exe_len < 0) {
			perror("error in open /proc/pid/exe");
			exit(3);
		}
		exe_name[exe_len] = '\0';
	}

	/* walk through */
	char line[1024];
	char perms[5];
	char deleted[100];
	int ia, ib, ic, id;
	while (fgets(line, sizeof(line), filp) != NULL) {
		int ret = sscanf(line, "%lx-%lx %s %x %x:%x %d %s %s",
				(unsigned long *)start, (unsigned long *)end, perms, &ia, &ib, &ic, &id, ret_path, deleted);
		if (ret == 8 && perms[2] == 'x' && ret_path[0] == '/') {
			if (exe_self != NULL) {
				*exe_self = (strcmp(ret_path, exe_name) == 0);
			}
			return ret_path;
		}
	}

	fclose(filp);
	filp = NULL;
	return NULL;
}

const char *proc_maps_by_name(pid_t pid, char *libPath,size_t *start, size_t *end)
{
	static FILE *filp = NULL;
	static char ret_path[1024];

	/* first, init */
	if (filp == NULL) {
		char pname[100];
		sprintf(pname, "/proc/%d/maps", pid);
		filp = fopen(pname, "r");
		if (filp == NULL) {
			perror("Error in open /proc/pid/maps");
			exit(3);
		}
	}

	/* walk through */
	char line[1024];
	char perms[5];
	char deleted[100];
	int ia, ib, ic, id;
	while (fgets(line, sizeof(line), filp) != NULL) {
		int ret = sscanf(line, "%lx-%lx %s %x %x:%x %d %s %s",
				(unsigned long *)start, (unsigned long *)end, perms, &ia, &ib, &ic, &id, ret_path, deleted);
        if(strstr(ret_path, libPath) != NULL)
        {
		    if (ret == 8 && perms[2] == 'x' && ret_path[0] == '/') {
			    return ret_path;
		    }
        }
	}

	fclose(filp);
	filp = NULL;
	return NULL;
}


pid_t proc_tasks(pid_t pid)
{
	static DIR *dirp = NULL;

	if (dirp == NULL) {
		char tname[100];
		sprintf(tname, "/proc/%d/task", pid);
		dirp = opendir(tname);
		if (dirp == NULL) {
			perror("Error in open /proc/pid/tasks");
			exit(3);
		}
	}

	struct dirent *e;
	while((e = readdir(dirp)) != NULL) {
		pid_t task_id = atoi(e->d_name);
		if (task_id != 0) {
			return task_id;
		}
	}

	closedir(dirp);
	dirp = NULL;
	return 0;
}

int proc_task_check(pid_t pid, pid_t child)
{
	char tname[100];
	sprintf(tname, "/proc/%d/task", pid);
	DIR *dirp = opendir(tname);
	if (dirp == NULL) {
		perror("Error in open /proc/pid/tasks");
		exit(3);
	}

	struct dirent *e;
	while((e = readdir(dirp)) != NULL) {
		if (atoi(e->d_name) == child) {
			closedir(dirp);
			return 1;
		}
	}

	closedir(dirp);
	return 0;
}

