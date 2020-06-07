/*
 * Copyright (c) 1998-2015 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2015 Stony Brook University
 * Copyright (c) 2003-2015 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "sgfs.h"
#include "queue.h"
#include "fileop.h"
#include "extra.h"
#include <linux/module.h>

/* Initializations/ Definitions */
struct sgfs_extra *sgfs_extra = NULL;		/* extern variable defn - sgfs.h */
int consumer_thread_count = 0;			/* extern variable defn - sgfs.h */
int producer_thread_count = 0;			/* extern variable defn - sgfs.h */
int jobs_completed_offset = 0;			/* extern variable defn - sgfs.h */ 
struct mutex wqmutex; 				/* extern variable defn - queue.h */
struct mutex prmutex; 				/* extern variable defn - queue.h */
struct work *head = NULL; 			/* extern variable defn - queue.h */
struct task_struct *producer_task = NULL; 	/* extern variable defn - queue.h */
struct file *users_keys_file = NULL; 		/* extern variable defn - sgfs.h */
wait_queue_head_t consumer_queue = __WAIT_QUEUE_HEAD_INITIALIZER(consumer_queue); 	/* extern variable defn - sgfs.h */
wait_queue_head_t producer_queue = __WAIT_QUEUE_HEAD_INITIALIZER(producer_queue); 	/* extern variable defn - sgfs.h */
int MAX_LIST = 2;				/* default job queue length is 10 */
struct job_completed job_array[5];
int job_arr_ind = 0;

/*
 * There is no need to lock the sgfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
static int sgfs_read_super(struct super_block *sb, void *raw_data, int silent)
{
	int err = 0, thread_id, file_err;
	struct super_block *lower_sb;
	struct path lower_path;
	char *dev_name = (char *) raw_data;
	struct inode *inode;
	struct inode *lower_inode;
	struct qstr sg_qstr;
      	struct sgfs_sb_info *sb_info;
 	struct dentry *root_dentry = NULL, *err_dentry = NULL, *sg_dentry = NULL;
	unsigned int sg_mode = 0;
	const char *trash = ".trashbin";
	char *user_keys_file = NULL;
	
	/* Set user keys file string */	
	user_keys_file = (char *) kmalloc(sizeof(char)*PATH_MAX, GFP_KERNEL);
	memset(user_keys_file, '\0', PATH_MAX);
	strncpy(user_keys_file, dev_name, strlen(dev_name));
	strncpy(user_keys_file + strlen(user_keys_file), "/", 1);
	strncpy(user_keys_file + strlen(user_keys_file), ".users.keys", 11);
		
	if (!dev_name) {
		printk(KERN_ERR
		       "sgfs: read_super: missing dev_name argument\n");
		err = -EINVAL;
		goto out;
	}
	/* parse lower path */
	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		printk(KERN_ERR	"sgfs: error accessing "
		       "lower directory '%s'\n", dev_name);
		goto out;
	}

	/* allocate superblock private data */
	sb->s_fs_info = kzalloc(sizeof(struct sgfs_sb_info), GFP_KERNEL);
	if (!SGFS_SB(sb)) {
		printk(KERN_CRIT "sgfs: read_super: out of memory\n");
		err = -ENOMEM;
		goto out_free;
	}
	
	/* set the lower superblock field of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	sgfs_set_lower_super(sb, lower_sb);

	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_op = &sgfs_sops;

	sb->s_export_op = &sgfs_export_ops; /* adding NFS support */

	/* get a new inode and allocate our root dentry */
	inode = sgfs_iget(sb, d_inode(lower_path.dentry));
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}
	sb->s_root = d_make_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_iput;
	}
	d_set_d_op(sb->s_root, &sgfs_dops);

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;

	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	sgfs_set_lower_path(sb->s_root, &lower_path);

	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_make_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);
	if (!silent)
		printk(KERN_INFO
		       "sgfs: mounted on top of %s type %s\n",
		       dev_name, lower_sb->s_type->name);

	root_dentry = dget(sb->s_root);
	sg_qstr.len = strlen(trash);
	sg_qstr.name = trash;
	sg_qstr.hash = full_name_hash(trash,strlen(trash));
	sg_dentry =  d_alloc(root_dentry, &sg_qstr);

	err_dentry = sgfs_lookup(root_dentry->d_inode, sg_dentry, LOOKUP_DIRECTORY);
	err = PTR_ERR(err_dentry);
	if(IS_ERR(err_dentry) && err != -ENOENT) {
		goto out_freeroot;
	}

	if(sg_dentry->d_inode == NULL) {
                 printk(KERN_INFO "Trashbin Folder doesn't exist\n");
		 sg_mode = sg_mode |(S_IFDIR | S_IRWXU | S_IRGRP | S_IXGRP  | S_IROTH | S_IXOTH);
                 err = sgfs_mkdir(root_dentry->d_inode, sg_dentry, sg_mode);
		 if(!err) {
			printk(KERN_INFO "Created a .trashbin dir at root: %d", sg_mode);
			sg_dentry->d_inode->i_mode |= sg_mode;
			lower_inode = sgfs_lower_inode(sg_dentry->d_inode);
			lower_inode->i_mode |= sg_mode;
			set_sg_dentry(sb, sg_dentry);
		 }
		 else {
			goto out_freeroot;
		 }
	}
	else {
		printk(KERN_INFO "Trash Folder Existing\n");
		/* stuffing into private pointer for dentry */
		set_sg_dentry(sb, sg_dentry);
	}

	sb_info = (struct sgfs_sb_info *) sb->s_fs_info;
	sb_info->mythreadinfo = (struct kthread_info *)kzalloc(sizeof(struct kthread_info), GFP_KERNEL);
	if (sb_info->mythreadinfo == NULL) {
                printk(KERN_CRIT "sgfs: read_super: out of memory\n");
                err = -ENOMEM;
                goto out_free;
        }


	/* Creating per user keys file */
        file_err = xcrypt_open(user_keys_file, O_RDWR | O_CREAT, 0777, &users_keys_file);
	if (file_err < 0) {
                printk(KERN_ERR "Error creating users keys file at mount time\n");
        }

	/* Initialise and run background cleaning thread */
	mutex_init(&sb_info->mythreadinfo->lock);
	sb_info->mythreadinfo->my_thread = kthread_run(&callback, (void *)sb_info, "delete_kernel_thread");

	/* Consumer thread. Create at the time of mounting */
	mutex_init(&wqmutex);
	mutex_init(&prmutex);
	for(thread_id = 0; thread_id < NUM_CONSUMERS; thread_id++) {
		printk(KERN_INFO "Creating %d consumer thread\n",thread_id+1);
		sgfs_extra->consumer_thread[thread_id] = kthread_run(&consumer_callback, NULL, "consume %d thread", thread_id+1);	
	}
	sgfs_extra->sup_blk = sb;
	for(thread_id = 0; thread_id < 5; thread_id++) {
		memset(job_array[thread_id].file_name,'\0',40);
		job_array[thread_id].status = 1;
	}
	goto out; /* all is well */

out_freeroot:
	dput(sb->s_root);
out_iput:
	iput(inode);
out_sput:
	/* drop refs we took earlier */
	atomic_dec(&lower_sb->s_active);
	kfree(SGFS_SB(sb));
	sb->s_fs_info = NULL;
out_free:
	path_put(&lower_path);

out:
	dput(root_dentry);
	dput(sg_dentry);
	if(user_keys_file)
		kfree(user_keys_file);
	return err;
}

struct dentry *sgfs_mount(struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{
	void *lower_path_name = (void *) dev_name;
    	int err = 0;
	char buf[128], *ptr; 
	printk(KERN_INFO "Device name: %s Raw Data: %s \n",dev_name,(char *) raw_data);

	sgfs_extra = (struct sgfs_extra *) kmalloc(sizeof(struct sgfs_extra), GFP_KERNEL);
	sgfs_extra->key = NULL;
	sgfs_extra->maxage = NULL;
	sgfs_extra->mountpoint = NULL;
	sgfs_extra->lowerdir = NULL;

	if(!sgfs_extra) {
		err = -ENOMEM;
		printk(KERN_ERR "Memory allocation failed\n"); 
	}
	sgfs_extra->lowerdir = kmalloc(strlen((char *) lower_path_name) + 1, GFP_KERNEL);
	memset(sgfs_extra->lowerdir, '\0', strlen((char *) lower_path_name) + 1);
	strcpy(sgfs_extra->lowerdir, (char *)lower_path_name);
	if(raw_data != NULL) {
		memset(buf, '\0', 128);
		strncpy(buf, (char *) raw_data, strlen((char *) raw_data));
		ptr = &buf[0];
		while(*ptr != '\0' && *ptr != '=') {
			ptr++;
		}
		if(*ptr != '\0') {
			ptr++;
			sgfs_extra->key = kmalloc(strlen(ptr)+1, GFP_KERNEL);
			memset(sgfs_extra->key, '\0', strlen(ptr)+1);
			strcpy(sgfs_extra->key, (char *)ptr);
		}
		if(sgfs_extra->key && !(strlen(sgfs_extra->key)>=1 && strlen(sgfs_extra->key)<=16)) {
			printk(KERN_INFO "Key Length is %d. Key should be greater than eq 1 and less than eq 16 chars\n",(int) strlen(sgfs_extra->key));
			if(sgfs_extra->key)
				kfree(sgfs_extra->key);
			if(sgfs_extra->maxage)
				kfree(sgfs_extra->maxage);
			if(sgfs_extra->mountpoint)
				kfree(sgfs_extra->mountpoint);
			if(sgfs_extra->lowerdir)
				kfree(sgfs_extra->lowerdir);
			kfree(sgfs_extra);
			return ERR_PTR(-EINVAL);
		}
	}

	return mount_nodev(fs_type, flags, lower_path_name,
			sgfs_read_super);
}
void sg_generic_shutdown_super(struct super_block *sb)
{
	int thread_id = 0;
	struct kthread_info *mythreadinfo = NULL;
	
	/* Stop background cleaning thread */
	mythreadinfo = get_sg_thread(sb);
	kthread_stop(mythreadinfo->my_thread);
	if(mythreadinfo)
	kfree(mythreadinfo);

	/* Stop consumer threads */
	consumer_thread_count+=1;
	for(thread_id = 0; thread_id < NUM_CONSUMERS; thread_id++) {
		kthread_stop(sgfs_extra->consumer_thread[thread_id]);
	} 
	
	/* Free DS */  
	dput(get_sg_dentry(sb));
	if(sgfs_extra->key)
		kfree(sgfs_extra->key);
	if(sgfs_extra->maxage)
		kfree(sgfs_extra->maxage);
	if(sgfs_extra->mountpoint)
		kfree(sgfs_extra->mountpoint);
	if(sgfs_extra->lowerdir)
		kfree(sgfs_extra->lowerdir);
	if(sgfs_extra)
		kfree(sgfs_extra);
	xcrypt_close(&users_keys_file);
	generic_shutdown_super(sb);
}


static struct file_system_type sgfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= SGFS_NAME,
	.mount		= sgfs_mount,
	.kill_sb	= sg_generic_shutdown_super,
	.fs_flags	= 0,
};
MODULE_ALIAS_FS(SGFS_NAME);

static int __init init_sgfs_fs(void)
{
	int err;

	pr_info("Registering sgfs " SGFS_VERSION "\n");

	err = sgfs_init_inode_cache();
	if (err)
		goto out;
	err = sgfs_init_dentry_cache();
	if (err)
		goto out;
	err = register_filesystem(&sgfs_fs_type);
out:
	if (err) {
		sgfs_destroy_inode_cache();
		sgfs_destroy_dentry_cache();
	}
	return err;
}

static void __exit exit_sgfs_fs(void)
{
	sgfs_destroy_inode_cache();
	sgfs_destroy_dentry_cache();
	unregister_filesystem(&sgfs_fs_type);
	pr_info("Completed sgfs module unload\n");
}

MODULE_AUTHOR("Erez Zadok, Filesystems and Storage Lab, Stony Brook University"
	      " (http://www.fsl.cs.sunysb.edu/)");
MODULE_DESCRIPTION("Sgfs " SGFS_VERSION
		   " (http://sgfs.filesystems.org/)");
MODULE_LICENSE("GPL");

module_init(init_sgfs_fs);
module_exit(exit_sgfs_fs);
