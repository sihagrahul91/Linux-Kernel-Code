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

#ifndef _SGFS_H_
#define _SGFS_H_

#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <linux/statfs.h>
#include <linux/fs_stack.h>
#include <linux/magic.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/xattr.h>
#include <linux/exportfs.h>

#include <linux/init.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/fsnotify.h>
#include <linux/personality.h>
#include <linux/security.h>
#include <linux/ima.h>
#include <linux/syscalls.h>
#include <linux/mount.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/file.h>
#include <linux/fcntl.h>
#include <linux/device_cgroup.h>
#include <linux/fs_struct.h>
#include <linux/posix_acl.h>
#include <asm/uaccess.h>

#include <linux/mutex.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/rtc.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <generated/autoconf.h>
#include <asm/unistd.h>
#include <linux/err.h>
#include <linux/scatterlist.h>
#include <linux/stat.h>
#include <linux/namei.h>
#include <linux/hash.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/key-type.h>
#include <linux/ceph/decode.h>
#include <crypto/md5.h>
#include <crypto/aes.h>
#include <linux/scatterlist.h>
#include <keys/ceph-type.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/random.h>
#include <linux/compiler.h>
#include <linux/key.h>
#include <linux/namei.h>
#include <linux/file.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <asm/unaligned.h>
#include <linux/crypto.h>


/* the file system name */
#define SGFS_NAME "sgfs"

/* sgfs root inode number */
#define SGFS_ROOT_INO     1

/* useful for tracking code reachability */
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)

#define NUM_CONSUMERS 2
#define CLONE_PROT_MV   0x00000001              /* Clone Move flag - for secure deletion */
#define CLONE_PROT_ZIP  0x00000002              /* Clone ZIP flag - for secure deletion */
#define CLONE_PROT_ENC  0x00000004              /* Clone ENC flag - for secure deletion */
#define MODE_ENCRYPT 0x01
#define MODE_DECRYPT 0x02
#define BUFFER_SIZE PAGE_SIZE
#define PATH_MAX 4096

/* operations vectors defined in specific files */
extern const struct file_operations sgfs_main_fops;
extern const struct file_operations sgfs_dir_fops;
extern const struct inode_operations sgfs_main_iops;
extern const struct inode_operations sgfs_dir_iops;
extern const struct inode_operations sgfs_symlink_iops;
extern const struct super_operations sgfs_sops;
extern const struct dentry_operations sgfs_dops;
extern const struct address_space_operations sgfs_aops, sgfs_dummy_aops;
extern const struct vm_operations_struct sgfs_vm_ops;
extern const struct export_operations sgfs_export_ops;

extern int sgfs_init_inode_cache(void);
extern void sgfs_destroy_inode_cache(void);
extern int sgfs_init_dentry_cache(void);
extern void sgfs_destroy_dentry_cache(void);
extern int new_dentry_private_data(struct dentry *dentry);
extern void free_dentry_private_data(struct dentry *dentry);
extern struct dentry *sgfs_lookup(struct inode *dir, struct dentry *dentry,
				    unsigned int flags);
extern struct inode *sgfs_iget(struct super_block *sb,
				 struct inode *lower_inode);
extern int sgfs_interpose(struct dentry *dentry, struct super_block *sb,
			    struct path *lower_path);
extern int sgfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode);

extern int sgfs_restore(char *filename, struct super_block *sb);

extern int sgfs_unlink_util(struct inode *dir, struct dentry *dentry);
extern int sgfs_unlink(struct inode *dir, struct dentry *dentry);

/* file private data */
struct sgfs_file_info {
	struct file *lower_file;
	const struct vm_operations_struct *lower_vm_ops;
};
extern int consumer_thread_count;
extern int producer_thread_count;
extern wait_queue_head_t consumer_queue;
extern wait_queue_head_t producer_queue;

/* sgfs inode data in memory */
struct sgfs_inode_info {
	struct inode *lower_inode;
	struct inode vfs_inode;
};

/* sgfs dentry data in memory */
struct sgfs_dentry_info {
	spinlock_t lock;	/* protects lower_path */
	struct path lower_path;
};

struct kthread_info {
	struct mutex lock;
	struct task_struct *my_thread;
};
/* sgfs super-block data in memory */
struct sgfs_sb_info {
	struct super_block *lower_sb;
	struct dentry *sg_dentry;
	struct kthread_info *mythreadinfo;
};
/* ds to keep extra info */
struct sgfs_extra {
	char *key;
	char *maxage;
	char *mountpoint;
	char *lowerdir;
	struct task_struct *consumer_thread[NUM_CONSUMERS];
	struct super_block *sup_blk;
	
};
extern struct sgfs_extra *sgfs_extra;
extern struct file *users_keys_file;
extern int MAX_LIST;
extern int jobs_completed_offset;
/*
 * inode to private data
 *
 * Since we use containers and the struct inode is _inside_ the
 * sgfs_inode_info structure, SGFS_I will always (given a non-NULL
 * inode pointer), return a valid non-NULL pointer.
 */
static inline struct sgfs_inode_info *SGFS_I(const struct inode *inode)
{
	return container_of(inode, struct sgfs_inode_info, vfs_inode);
}

/* dentry to private data */
#define SGFS_D(dent) ((struct sgfs_dentry_info *)(dent)->d_fsdata)

/* superblock to private data */
#define SGFS_SB(super) ((struct sgfs_sb_info *)(super)->s_fs_info)

/* file to private Data */
#define SGFS_F(file) ((struct sgfs_file_info *)((file)->private_data))

/* sets the global sg_dentry */
static inline int set_sg_dentry(struct super_block* sb,
					struct dentry* trash_dentry)
{
	if(!trash_dentry)
		return -EINVAL;
	else {
		SGFS_SB(sb)->sg_dentry = dget(trash_dentry);
		return 0;
	}
}

static inline struct dentry* get_sg_dentry(struct super_block * sb)
{
	return SGFS_SB(sb)->sg_dentry;
}

static inline struct kthread_info* get_sg_thread(struct super_block * sb)
{
	return SGFS_SB(sb)->mythreadinfo;
}
/* file to lower file */
static inline struct file *sgfs_lower_file(const struct file *f)
{
	return SGFS_F(f)->lower_file;
}

static inline void sgfs_set_lower_file(struct file *f, struct file *val)
{
	SGFS_F(f)->lower_file = val;
}

/* inode to lower inode. */
static inline struct inode *sgfs_lower_inode(const struct inode *i)
{
	return SGFS_I(i)->lower_inode;
}

static inline void sgfs_set_lower_inode(struct inode *i, struct inode *val)
{
	SGFS_I(i)->lower_inode = val;
}

/* superblock to lower superblock */
static inline struct super_block *sgfs_lower_super(
	const struct super_block *sb)
{
	return SGFS_SB(sb)->lower_sb;
}

static inline void sgfs_set_lower_super(struct super_block *sb,
					  struct super_block *val)
{
	SGFS_SB(sb)->lower_sb = val;
	SGFS_SB(sb)->sg_dentry = NULL;
}

/* path based (dentry/mnt) macros */
static inline void pathcpy(struct path *dst, const struct path *src)
{
	dst->dentry = src->dentry;
	dst->mnt = src->mnt;
}
/* Returns struct path.  Caller must path_put it. */
static inline void sgfs_get_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	spin_lock(&SGFS_D(dent)->lock);
	pathcpy(lower_path, &SGFS_D(dent)->lower_path);
	path_get(lower_path);
	spin_unlock(&SGFS_D(dent)->lock);
	return;
}
static inline void sgfs_put_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	path_put(lower_path);
	return;
}
static inline void sgfs_set_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	spin_lock(&SGFS_D(dent)->lock);
	pathcpy(&SGFS_D(dent)->lower_path, lower_path);
	spin_unlock(&SGFS_D(dent)->lock);
	return;
}
static inline void sgfs_reset_lower_path(const struct dentry *dent)
{
	spin_lock(&SGFS_D(dent)->lock);
	SGFS_D(dent)->lower_path.dentry = NULL;
	SGFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&SGFS_D(dent)->lock);
	return;
}
static inline void sgfs_put_reset_lower_path(const struct dentry *dent)
{
	struct path lower_path;
	spin_lock(&SGFS_D(dent)->lock);
	pathcpy(&lower_path, &SGFS_D(dent)->lower_path);
	SGFS_D(dent)->lower_path.dentry = NULL;
	SGFS_D(dent)->lower_path.mnt = NULL;
	spin_unlock(&SGFS_D(dent)->lock);
	path_put(&lower_path);
	return;
}

/* locking helpers */
static inline struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *dir = dget_parent(dentry);
	inode_lock_nested(d_inode(dir), I_MUTEX_PARENT);
	return dir;
}

static inline void unlock_dir(struct dentry *dir)
{
	inode_unlock(d_inode(dir));
	dput(dir);
}

static inline void fill_qstr(struct qstr * q, char * str)
{
	q->len = strlen(str);
	q->name = str;
	q->hash = full_name_hash(str, strlen(str));

}

#endif	/* not _SGFS_H_ */
