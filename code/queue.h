#ifndef _QUEUE_H_
#define _QUEUE_H_
struct job {
	unsigned int pid;		/* process id of submitter */
	int recover_flags;	/* MV, ENC, COMP... */
	int status;		/* 1 - in process, 0 - success, -1 - failure */
	char timestamp[27];	/* timestamp is 26 bytes */
	struct inode *dir;
	struct dentry *dentry;
	char file_name[40];
};
struct work {
	struct job *job;	
	struct work *next;
};

struct job_completed {
	char file_name[40];
	int status;
};

extern struct job_completed job_array[];
extern int job_arr_ind;
extern struct mutex wqmutex;
extern struct mutex prmutex;
extern struct work *head;
extern struct task_struct *producer_task;
extern int insert(struct job *job);
extern struct work *remove(void );
extern int process(struct job *job);
extern int producer(void *data); 
extern int sgfs_unlink_(struct inode *dir, struct dentry *dentry, struct job *curr_job);

#endif	/* not _QUEUE_H_ */
