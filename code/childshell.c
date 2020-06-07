/* ns_child_exec.c
 * Copyright 2013, Michael Kerrisk
 * Licensed under GNU General Public License v2 or later
 * Create a child process that executes a shell command in new namespace(s).
 **/
#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#define CLONE_PROT_MV	0x00000002
#define CLONE_PROT_ZIP	0x00000004
#define CLONE_PROT_ENC	0x00000008
#define CLONE_MAND 	0x80000000


/* A simple error-handling function: print an error message based
 * on the value in 'errno' and terminate the calling process */

#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
} while (0)

struct ms {
	char command[50];       
	char args[100];
};

	static int              /* Start function for cloned child */
childFunc(void *arg)
{
	struct ms *var = (struct ms *) arg;
	char *argv_list[2];
	argv_list[0] = var->command;
	argv_list[0] = var->args;
	execvp(var->command,argv_list);
	errExit("execvp");
}

#define STACK_SIZE (1024 * 1024)

static char child_stack[STACK_SIZE];    /* Space for child's stack */

int main(int argc, char *argv[])
{
	pid_t child_pid;
	int myflag = 0, c;
	struct ms var;

	memset(var.args,'\0',100);
	memset(var.command,'\0',50);

	while ((c = getopt (argc, argv, "mzec:a:")) != -1) {
		switch (c) {
			case 'm':
				myflag |= CLONE_PROT_MV;
				break;
			case 'z':   
				myflag |= CLONE_PROT_ZIP;
				break;
			case 'e':      
				myflag |= CLONE_PROT_ENC;
				break;
			case 'c':
				strncpy(var.command, optarg, 50);
				break;
			case 'a':
				strncpy(var.args, optarg, 100);
				break;
			case '?':
				fprintf (stderr,"Unknown option character `\\x%x'.\n",optopt);
				return -1;
		}
	}
	printf("Clone Flags Set - MV : %d ZIP : %d ENC : %d command : %s arguments : %s\n", myflag&CLONE_PROT_MV,
			myflag&CLONE_PROT_ZIP, myflag&CLONE_PROT_ENC, var.command, var.args);

	if((myflag&CLONE_PROT_ZIP) && !(myflag&CLONE_PROT_MV)) {
		printf("Please set move also with compress\n");
		return 0;
	}

	if((myflag&CLONE_PROT_ENC) && !(myflag&CLONE_PROT_MV)) {
		printf("Please set move also with encrypt\n");
		return 0;
	}

	myflag |= CLONE_MAND;
	child_pid = clone(childFunc,
			child_stack + STACK_SIZE,
			myflag | SIGCHLD, (void *)&var);

	if (child_pid == -1)
		errExit("clone");

	/* Parent falls through to here */

	if (waitpid(child_pid, NULL, 0) == -1)      /* Wait for child */
		errExit("waitpid");

	exit(EXIT_SUCCESS);
}
