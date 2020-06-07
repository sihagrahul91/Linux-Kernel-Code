#ifndef _EXTRA_H_
#define _EXTRA_H_
struct file_details{
        struct timespec file_time;  /* access / modify / create time */
        struct dentry *file_dentry;
        struct file_details *next;
};

struct getdents_callback_ {
        struct dir_context ctx;
        char *name;             /* name that was found. It already points to a
                                   buffer NAME_MAX+1 is size */
        u64 ino;                /* the inum we are looking for */
        int found;              /* inode matched? */
        int sequence;           /* sequence counter */
        struct dentry *trashbin_dentry;
        struct file_details **file_details_list;        /* list head */
        int *list_len;
};

extern void push(struct file_details **head_ref, struct timespec file_time, struct dentry *file_dentry);
extern int filldir_one(struct dir_context *ctx, const char *name, int len,
                        loff_t pos, u64 ino, unsigned int d_type);
extern int consumer_callback(void *data);
extern int callback(void *data);

extern void bubbleSort(struct file_details *start);
#endif	/* not _EXTRA_H_ */
