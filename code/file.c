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
#include "fileop.h"
#include "extra.h"
struct dir_context *octx;

#define IORESTORE _IOW('r', 4, char*)
#define ENCRYPTIONKEY _IOW('r', 1, char*)
#define PURGETRASHBIN _IOW('r', 3, char*)
#define DELETE _IOW('r', 2, char*)
#define DELETEFROMQUEUE _IOW('r', 5, char*)

static ssize_t sgfs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = sgfs_lower_file(file);
	err = vfs_read(lower_file, buf, count, ppos);
	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));

	return err;
}

static ssize_t sgfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err;

	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = sgfs_lower_file(file);
	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(d_inode(dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(dentry),
					file_inode(lower_file));
	}

	return err;
}

/* check_user - helper api to sgfs readir to restrict displaying only user's files
 * @name - filename
 * returns 1/0
 */
int check_user(const char *name)
{
	unsigned int uid;
	const struct cred *cred;
	char *ret  = NULL;
	char _uid2str_[13];
	cred = current_cred();
	uid = *(unsigned int *) &(cred->euid);  /* get userid */
	memset(_uid2str_, '\0', 13);
	snprintf(_uid2str_, 13, "_%u_", uid);
	if(strcmp(_uid2str_,"_0_")==0) return 1;
	ret = strstr(name, _uid2str_);
	if(ret != NULL) return 1;
	return 0;
}

/* action_fcn - callback used by readdir. calls check_user to display user specific files only
*/	
int action_fcn(struct dir_context *ctx, const char *name, int len, loff_t offset, u64 a, unsigned b)
{
	if(check_user(name))
	{		
		return octx->actor(octx, name, len, offset, a, b);
	}
	return 0;
}

static int sgfs_readdir(struct file *file, struct dir_context *ctx)
{
	/* printk(KERN_INFO "Checking contects of directory %u\n",(unsigned int)get_current()->pid); */
	int err;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;
	struct dir_context nctx = {.actor = action_fcn, .pos = ctx->pos};
	char *sg = ".trashbin";

	lower_file = sgfs_lower_file(file);
	octx = ctx;
	if(strcmp(sg, dentry->d_name.name) == 0) {
		err = iterate_dir(lower_file, &nctx);
	}
	else
		err = iterate_dir(lower_file, ctx);

	file->f_pos = lower_file->f_pos;
	if (err >= 0)		/* copy the atime */
		fsstack_copy_attr_atime(d_inode(dentry),
					file_inode(lower_file));
	return err;
}

/* purge_trashbin - purge trashbin completely
*/
void purge_trashbin(void)
{
	struct sgfs_sb_info *sb_info = (struct sgfs_sb_info *) sgfs_extra->sup_blk->s_fs_info;
	struct path lower_path;
	struct dentry *sgfs_root_, *file_dentry, *lower_dir_dentry;
	char name_[NAME_MAX+1];
	char *name = (char *) &name_;
	struct dentry *sgfs_root;
	const struct cred *cred;
	struct file *file;
	struct file_details *file_details_list = NULL, *ptr;
	int list_len = 0, err = 0;
	struct getdents_callback_ buffer = {
		.ctx.actor = filldir_one,
	};
	sgfs_root_ = sb_info->sg_dentry;
	sgfs_get_lower_path(sgfs_root_, &lower_path);
	sgfs_root = lower_path.dentry;
	cred = current_cred();
	file = dentry_open(&lower_path, O_RDONLY, cred);

	/* initialise getdent buffer */
	buffer.name = name;
	buffer.trashbin_dentry = sgfs_root_;
	buffer.file_details_list = &file_details_list;
	buffer.list_len = &list_len;
	buffer.sequence = 0;

	err = iterate_dir(file, &buffer.ctx);
	ptr = file_details_list;
	printk(KERN_INFO "Purging trashbin completely. Number of files in trashbin is: %d\n",list_len);
	while(ptr) {
		printk(KERN_INFO "Purging trashbin deleting file with timestamp : %lld.%.9ld \n", (long long)ptr->file_time.tv_sec, ptr->file_time.tv_nsec);
		list_len--;
		file_details_list = ptr->next;
		file_dentry = ptr->file_dentry;
		dget(file_dentry);
		lower_dir_dentry = lock_parent(file_dentry);
		err = vfs_unlink(d_inode(sgfs_root), file_dentry, NULL);
		printk("Removing. Error code is %d\n",err);
		unlock_dir(lower_dir_dentry);
		dput(file_dentry);
		kfree(ptr);
		ptr = file_details_list;
	}
	fput(file);
	sgfs_put_lower_path(sgfs_root_, &lower_path);
	return;
}

static long sgfs_unlocked_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg)
{

	unsigned int uid;
	const struct cred *cred;
	struct super_block *sb_;
	long err = -ENOTTY;
	struct file *lower_file;
	struct dentry *dentry = NULL;
	char *data = NULL;
	struct super_block * sb = file->f_path.dentry->d_sb;
	int len = 0, err_;
	unsigned int sg_mode, lw_mode;
        struct inode *lower_inode;	

	cred = current_cred();
	uid = *(unsigned int *) &(cred->euid);  /* get userid */
	printk("UID of current process %u\n",uid);

	if(!access_ok(VERIFY_READ, (char *) arg, 0)) {
		err = -EFAULT;
		goto out;
	}

	len = strlen_user((char *) arg);
	data = kmalloc(len, GFP_KERNEL);
	if(!data) {
		printk(KERN_ERR "Memory allocation failed\n");
		err = -ENOMEM;
		goto out;
	}
	err_ = strncpy_from_user(data, (char *) arg, len + 1);
	if(err_ < 0) {
		err = -EINVAL;
		printk(KERN_ERR "Input is not proper");
		goto out;
	}
	dentry = file->f_path.dentry;
	switch(cmd) {
		case DELETE:
			printk("IOCTL received. Deleting file\n");
			err = sgfs_unlink(d_inode(dentry->d_parent), dentry);
			break;	
		case IORESTORE:
			printk("IOCTL received. Restoring file %s\n", data);
			err = sgfs_restore(data, sb);
			break;
		case ENCRYPTIONKEY:
			printk("Set the encryption key for the user ID: %u Key: %s\n", uid, data);
			err = set_user_key(data, uid);
			break;
		case PURGETRASHBIN:
			purge_trashbin();
			err = 0;
			break;
		case DELETEFROMQUEUE:
			printk("Removing the job from kernel queue\n");
			err = remove_filename(data, uid);
			break;
		default:

			lower_file = sgfs_lower_file(file);

			/* XXX: use vfs_ioctl if/when VFS exports it */
			if (!lower_file || !lower_file->f_op)
				goto out;
			if (lower_file->f_op->unlocked_ioctl)
				err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

			/* some ioctls can change inode attributes (EXT2_IOC_SETFLAGS) */
			if (!err)
				fsstack_copy_attr_all(file_inode(file),
						file_inode(lower_file));
	}
	if(cmd == IORESTORE && !(err < 0)) {
		sb_ = d_inode(dentry->d_parent)->i_sb; 
		sg_mode = SGFS_SB(sb_)->sg_dentry->d_inode->i_mode;
		lower_inode = sgfs_lower_inode(SGFS_SB(sb_)->sg_dentry->d_inode);
		lw_mode = lower_inode->i_mode;
		printk("Trashbin Mode is currently %u %u\n",sg_mode, lw_mode);
		SGFS_SB(sb_)->sg_dentry->d_inode->i_mode |= (S_IFDIR | S_IRWXU | S_IRWXG| S_IRWXO);
		lower_inode->i_mode |= (S_IFDIR | S_IRWXU | S_IRWXG| S_IRWXO);

		sgfs_unlink_util(d_inode(dentry->d_parent), dentry);

		SGFS_SB(sb_)->sg_dentry->d_inode->i_mode = sg_mode;
		lower_inode->i_mode = lw_mode; 
	}
out:
	if(data)
		kfree(data);
	return err;
}

#ifdef CONFIG_COMPAT
static long sgfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = sgfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int sgfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = sgfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "sgfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!SGFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "sgfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &sgfs_vm_ops;

	file->f_mapping->a_ops = &sgfs_aops; /* set our aops */
	if (!SGFS_F(file)->lower_vm_ops) /* save for our ->fault */
		SGFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}

static int sgfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct path lower_path;

	/* don't open unhashed/deleted files */
	if (d_unhashed(file->f_path.dentry)) {
		err = -ENOENT;
		goto out_err;
	}

	file->private_data =
		kzalloc(sizeof(struct sgfs_file_info), GFP_KERNEL);
	if (!SGFS_F(file)) {
		err = -ENOMEM;
		goto out_err;
	}

	/* open lower object and link sgfs's file struct to lower's */
	sgfs_get_lower_path(file->f_path.dentry, &lower_path);
	lower_file = dentry_open(&lower_path, file->f_flags, current_cred());
	path_put(&lower_path);
	if (IS_ERR(lower_file)) {
		err = PTR_ERR(lower_file);
		lower_file = sgfs_lower_file(file);
		if (lower_file) {
			sgfs_set_lower_file(file, NULL);
			fput(lower_file); /* fput calls dput for lower_dentry */
		}
	} else {
		sgfs_set_lower_file(file, lower_file);
	}

	if (err)
		kfree(SGFS_F(file));
	else
		fsstack_copy_attr_all(inode, sgfs_lower_inode(inode));
out_err:
	return err;
}

static int sgfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = sgfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush) {
		filemap_write_and_wait(file->f_mapping);
		err = lower_file->f_op->flush(lower_file, id);
	}

	return err;
}

/* release all lower object references & free the file info structure */
static int sgfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;

	lower_file = sgfs_lower_file(file);
	if (lower_file) {
		sgfs_set_lower_file(file, NULL);
		fput(lower_file);
	}

	kfree(SGFS_F(file));
	return 0;
}

static int sgfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;

	err = __generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = sgfs_lower_file(file);
	sgfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	sgfs_put_lower_path(dentry, &lower_path);
out:
	return err;
}

static int sgfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = sgfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

/*
 * Sgfs cannot use generic_file_llseek as ->llseek, because it would
 * only set the offset of the upper file.  So we have to implement our
 * own method to set both the upper and lower file offsets
 * consistently.
 */
static loff_t sgfs_file_llseek(struct file *file, loff_t offset, int whence)
{
	int err;
	struct file *lower_file;

	err = generic_file_llseek(file, offset, whence);
	if (err < 0)
		goto out;

	lower_file = sgfs_lower_file(file);
	err = generic_file_llseek(lower_file, offset, whence);

out:
	return err;
}

/*
 * Sgfs read_iter, redirect modified iocb to lower read_iter
 */
ssize_t
sgfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = sgfs_lower_file(file);
	if (!lower_file->f_op->read_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->read_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode atime as needed */
	if (err >= 0 || err == -EIOCBQUEUED)
		fsstack_copy_attr_atime(d_inode(file->f_path.dentry),
					file_inode(lower_file));
out:
	return err;
}

/*
 * Sgfs write_iter, redirect modified iocb to lower write_iter
 */
ssize_t
sgfs_write_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	int err;
	struct file *file = iocb->ki_filp, *lower_file;

	lower_file = sgfs_lower_file(file);
	if (!lower_file->f_op->write_iter) {
		err = -EINVAL;
		goto out;
	}

	get_file(lower_file); /* prevent lower_file from being released */
	iocb->ki_filp = lower_file;
	err = lower_file->f_op->write_iter(iocb, iter);
	iocb->ki_filp = file;
	fput(lower_file);
	/* update upper inode times/sizes as needed */
	if (err >= 0 || err == -EIOCBQUEUED) {
		fsstack_copy_inode_size(d_inode(file->f_path.dentry),
					file_inode(lower_file));
		fsstack_copy_attr_times(d_inode(file->f_path.dentry),
					file_inode(lower_file));
	}
out:
	return err;
}

const struct file_operations sgfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= sgfs_read,
	.write		= sgfs_write,
	.unlocked_ioctl	= sgfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= sgfs_compat_ioctl,
#endif
	.mmap		= sgfs_mmap,
	.open		= sgfs_open,
	.flush		= sgfs_flush,
	.release	= sgfs_file_release,
	.fsync		= sgfs_fsync,
	.fasync		= sgfs_fasync,
	.read_iter	= sgfs_read_iter,
	.write_iter	= sgfs_write_iter,
};

/* trimmed directory options */
const struct file_operations sgfs_dir_fops = {
	.llseek		= sgfs_file_llseek,
	.read		= generic_read_dir,
	.iterate	= sgfs_readdir,
	.unlocked_ioctl	= sgfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= sgfs_compat_ioctl,
#endif
	.open		= sgfs_open,
	.release	= sgfs_file_release,
	.flush		= sgfs_flush,
	.fsync		= sgfs_fsync,
	.fasync		= sgfs_fasync,
};
