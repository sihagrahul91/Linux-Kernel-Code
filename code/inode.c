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

#include "util.h"

static int sgfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry);
static int sgfs_create(struct inode *dir, struct dentry *dentry,
			 umode_t mode, bool want_excl)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_create(d_inode(lower_parent_dentry), lower_dentry, mode,
			 want_excl);
	if (err)
		goto out;
	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_link(struct dentry *old_dentry, struct inode *dir,
		       struct dentry *new_dentry)
{
	struct dentry *lower_old_dentry;
	struct dentry *lower_new_dentry;
	struct dentry *lower_dir_dentry;
	u64 file_size_save;
	int err;
	struct path lower_old_path, lower_new_path;

	file_size_save = i_size_read(d_inode(old_dentry));
	sgfs_get_lower_path(old_dentry, &lower_old_path);
	sgfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_dir_dentry = lock_parent(lower_new_dentry);

	err = vfs_link(lower_old_dentry, d_inode(lower_dir_dentry),
		       lower_new_dentry, NULL);
	if (err || !d_inode(lower_new_dentry))
		goto out;

	err = sgfs_interpose(new_dentry, dir->i_sb, &lower_new_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, d_inode(lower_new_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_new_dentry));
	set_nlink(d_inode(old_dentry),
		  sgfs_lower_inode(d_inode(old_dentry))->i_nlink);
	i_size_write(d_inode(new_dentry), file_size_save);
out:
	unlock_dir(lower_dir_dentry);
	sgfs_put_lower_path(old_dentry, &lower_old_path);
	sgfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

int sgfs_unlink_util(struct inode *dir, struct dentry *dentry)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *lower_dir_inode = sgfs_lower_inode(dir);
	struct dentry *lower_dir_dentry;
	struct path lower_path;
	UDBG;
	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	UDBG;
	dget(lower_dentry);
	UDBG;
	lower_dir_dentry = lock_parent(lower_dentry);
	UDBG;

	UDBG;
	err = vfs_unlink(lower_dir_inode, lower_dentry, NULL);
	UDBG;

	/*
	 * Note: unlinking on top of NFS can cause silly-renamed files.
	 * Trying to delete such files results in EBUSY from NFS
	 * below.  Silly-renamed files will get deleted by NFS later on, so
	 * we just need to detect them here and treat such EBUSY errors as
	 * if the upper file was successfully deleted.
	 */
	UDBG;
	if (err == -EBUSY && lower_dentry->d_flags & DCACHE_NFSFS_RENAMED)
		err = 0;
	if (err)
		goto out;
	UDBG;
	fsstack_copy_attr_times(dir, lower_dir_inode);
	UDBG;
	fsstack_copy_inode_size(dir, lower_dir_inode);
	UDBG;
	set_nlink(d_inode(dentry),
		  sgfs_lower_inode(d_inode(dentry))->i_nlink);
	UDBG;
	d_inode(dentry)->i_ctime = dir->i_ctime;
	UDBG;
	d_drop(dentry); /* this is needed, else LTP fails (VFS won't do it) */
	UDBG;
out:
	unlock_dir(lower_dir_dentry);
	dput(lower_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

/* decompressed_bytes - helper for encryption/ decryption/ compression/ decompression. 
 * Extracts data length to read from file. Data saved as -  len(len(data)len(data)data e.g. abc stored as 13abc
 * @input_file - input file pointer
 * @count - fill in the next file offset to read from
 */
static int decompressed_bytes(struct file *input_file, int *count)
{
	char num[2], bytes[5];
	int ret1, err = 0, num_bytes;

	memset(bytes, '\0', 5);
	ret1 = xcrypt_read(input_file, *count, num, 1);
	if(ret1 <= 0) {
		err = -ENODATA;
		goto out;
	}
	*count = *count + 1;
	num[1] = '\0';
	err = kstrtoint(num, 10, &num_bytes);
	if(err) {
		printk("kstrtoint error\n");
		goto out;
	}
	ret1 = xcrypt_read(input_file, *count, bytes, num_bytes);
	if(ret1 <= 0) {
		err = -ENODATA;
		goto out;
	}
	*count = *count + num_bytes;
	err = kstrtoint(bytes, 10, &num_bytes);
	if(err) {
		printk("kstrtoint error\n");
		goto out;
	}
	return num_bytes;
out:
	return err;


}

/* get_file_name_from_dentry - given dentry get filename
 * @dentry - file dentry
 * @file_name - filename
 */
int get_file_name_from_dentry(struct dentry *dentry, char *file_name)
{
	char *buf = NULL, *res = NULL;
	char *tok = NULL, *end = NULL, *inputfile = NULL;
	int err = 0;
	buf = (char *) kmalloc(PATH_MAX, GFP_KERNEL);
	if(!buf) {
                printk("Memory allocation failed.\n");
                err = -ENOMEM;
		goto last;
        }
	memset(buf, '\0', PATH_MAX);	
	res = dentry_path_raw(dentry, buf, PATH_MAX);
	if (IS_ERR(res)) {
                err = PTR_ERR(res);
                printk("Error in getting path from dentry\n");
		goto last;
        }
	tok = res;
        end = res;
        while(tok != NULL) {
                strsep(&end,"/");
                inputfile = tok;
                tok = end;
        }
	strncpy(file_name, inputfile, strlen(inputfile));
	printk(KERN_INFO "File name from dentry is : |%s|\n", file_name);
	
last:
	if(buf)
		kfree(buf);
	return err;

}

/* sgfs_unlink - modified sgfs_unlink
 * @dir - parent inode
 * @dentry - dentry of file
 */
int sgfs_unlink(struct inode *dir, struct dentry *dentry) 
{

	int err = 0, file_err, ret1, flag; 
	struct job *job = NULL;
	struct timeval t, time;
        struct tm broken;
        unsigned long local_time;
        struct rtc_time tm;
	const struct cred *cred;
	struct inode *inode = d_inode(dentry);
	int file_size = inode->i_size;
	int kernel_queue_size = 0;	/* If the parameter is not set kernel queue size if assumed to be 0 */
	char kqstring[11];
	struct file *kqfptr = NULL;

	/* Finf the clone flags */
	struct task_struct *curr = get_current();
        printk(KERN_INFO "Clone flags set are MV | ZIP | ENC : %d | %d | %d \n",
				curr->recover_flags&CLONE_PROT_MV, curr->recover_flags&CLONE_PROT_ZIP, curr->recover_flags&CLONE_PROT_ENC);

	/* MV flag is not set means direct delete the file.
 	* */
	if(!(curr->recover_flags & CLONE_PROT_MV)) {
		return sgfs_unlink_util(dir, dentry);	
	}

	/* Get the kernel queue size 
	 * */
        file_err = xcrypt_open("/proc/kernel-queue", O_RDONLY, 0, &kqfptr);
        if(file_err < 0) {
                printk(KERN_ERR "Can't open Kernel Queue Proc Entry. Kernel Queue default length is 0. All jobs will be processed synchronously\n");
        }
        else {
		memset(kqstring, '\0', 11);
		ret1 = xcrypt_read(kqfptr, 0, kqstring, 11);
		if(ret1 == 0) {
			ret1 = xcrypt_read(kqfptr, 0, kqstring, 11);
		}
		kqstring[ret1-1] = '\0';
		if(strlen(kqstring) == 0) kernel_queue_size = 10;
		else kernel_queue_size = string_to_int(kqstring);
		printk(KERN_INFO "Kernel Queue size from proc entry is |%s| %d\n",kqstring, kernel_queue_size);	
                xcrypt_close(&kqfptr);
        }
	/* Check if jobs gonna be synchronous asynchronous . Job will be synchronous when:
 	*  1. File size if <= 4KB
 	*  2. Kernel Queue size if 0
 	*  */
	if(file_size <= PAGE_SIZE || kernel_queue_size == 0) {
		printk(KERN_INFO "Job is submitted synchronously. File size : %d, and Kernel Queue size %d\n", file_size, kernel_queue_size);
	        return sgfs_unlink_(dir, dentry, NULL);	
		
	}

	MAX_LIST = kernel_queue_size;
        /* create encrypted - compressed file name string */
        do_gettimeofday(&t);
        time_to_tm(t.tv_sec, 0, &broken);
        do_gettimeofday(&time);
        local_time = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
        rtc_time_to_tm(local_time, &tm);

	job = kmalloc(sizeof(struct job), GFP_KERNEL);
        if (job == NULL) {
                printk(KERN_ERR "Memory not available\n");
                err = -ENOMEM;
                goto out;
        }	
	/* fill in job details */
	job->dir = dir;
	job->dentry = dget(dentry);
        snprintf(job->timestamp, 27, "%04d-%02d-%02d-%02d:%02d:%02d:%ld", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, t.tv_usec);
	job->timestamp[26] = '\0';
	job->status = 1;					/* in process */
        cred = current_cred();
	job->pid = *(unsigned int *) &(cred->euid); 		/* get userid */	
	job->recover_flags = get_current()->recover_flags;	/* deletion flags */
	memset(job->file_name, '\0', 40);
	err = get_file_name_from_dentry(dentry, job->file_name);		
	
	flag = 0;
	mutex_lock(&wqmutex);
	if(consumer_thread_count >= MAX_LIST) {
                printk(KERN_INFO "Producer: Max job limit reached. Producer thread in wait queue");
                mutex_unlock(&wqmutex);
		mutex_lock(&prmutex);
		producer_thread_count++;
		wait_event_interruptible(producer_queue, consumer_thread_count < MAX_LIST);
		consumer_thread_count++;
		flag = 1;
		mutex_lock(&wqmutex);
	}
	mutex_unlock(&wqmutex);

	printk(KERN_INFO "Giving rename job to producer thread\n");
	if(!flag) 
		consumer_thread_count++;
	producer_task = kthread_run(&producer, (void *)job, "producer thread");
	printk(KERN_INFO "Producer thread job is done and it is leaving\n");	
	out:
		return 0;
}

/* decrypt_decompress_file - decrypt and decompress file in one go. reads only once. writes only once
 * @input_file - input file ptr
 * @output_file - output_file ptr
 * @key - encryption key
 * @key_len - encryption key len
 * @write - write offset
 * @read_offset - read offset
 */ 
int decrypt_decompress_file(struct file *input_file, struct file *output_file, char *key, int key_len, int write, int read_offset)
{
        int err = 0, ret1, count = read_offset, num_bytes_read;
        size_t *dst_len = NULL, *dst_len_d = NULL;
        char *src = NULL, *dst = NULL, *decrypted = NULL;
	struct crypto_comp *tfm = NULL;
        const char *alg = "deflate";

        src = kmalloc(sizeof(char)*BUFFER_SIZE, GFP_KERNEL);
	decrypted = kmalloc(sizeof(char)*BUFFER_SIZE, GFP_KERNEL);
        dst = kmalloc(sizeof(char)*BUFFER_SIZE, GFP_KERNEL);
        dst_len = kmalloc(sizeof(size_t), GFP_KERNEL);
	dst_len_d = kmalloc(sizeof(size_t), GFP_KERNEL);
        if(!src || !dst || !dst_len || !dst_len_d || !decrypted) {
                printk(KERN_ERR "Memory allocation failed\n");
                err = -ENOMEM;
                goto last;
        }
	tfm = crypto_alloc_comp(alg, 0, 0);
        if (IS_ERR(tfm)) {
                printk("error in crypto_alloc_comp\n");
                err = PTR_ERR(tfm);
                goto last;
        }
        num_bytes_read = decompressed_bytes(input_file, &count);
        do {
                memset(src, '\0', BUFFER_SIZE);
                ret1 = xcrypt_read(input_file, count, src, num_bytes_read);
                if(ret1 == 0) {
                        printk(KERN_INFO "File end. Read 0 bytes\n");
                        goto last;
                }
                if(ret1 < 0) {
                        xcrypt_close(&input_file);
                        xcrypt_close(&output_file);
                        printk(KERN_ERR "Some issue in reading data from file\n");
                        err = -EIO;
                        goto last;
                }
                memset(dst, '\0', BUFFER_SIZE);
                memset(decrypted, '\0', BUFFER_SIZE);
	
		err = ceph_aes_decrypt(key, key_len, decrypted, dst_len_d, src, ret1);	
		if(err < 0) {
			printk("Decryption error\n");
			goto last;
		}
	 	crypto_comp_decompress(tfm, decrypted, *dst_len_d, dst, (unsigned int *) dst_len);
		count += ret1;
		num_bytes_read = decompressed_bytes(input_file, &count);
		write += xcrypt_write(output_file, write, dst, *dst_len);	
        } while( ret1 > 0 );

last:
        if(src)
                kfree(src);
        if(dst)
                kfree(dst);
        if(dst_len)
                kfree(dst_len);
        if(decrypted)
                kfree(decrypted);
	if(dst_len_d)
		kfree(dst_len_d);

        return err;

}

/* encrypt_compress_file - encrypt and compress file in one go. reads only once. writes only once
 * @input_file - input file ptr
 * @output_file - output_file ptr
 * @key - encryption key
 * @key_len - encryption key len
 * @write - write offset
 * @read_offset - read offset
 */
int encrypt_compress_file(struct file *input_file, struct file *output_file, char *key, int key_len, int write, int read_offset)
{
        int err = 0, ret1, count = 0, XCRYPT_BUF = BUFFER_SIZE - 32;
        size_t *dst_len = NULL, *dst_len_c = NULL;
        char *src = NULL, *dst = NULL, *compressed;
	char num[2], bytes[5];
        struct crypto_comp *tfm = NULL;
        const char *alg = "deflate"; /* Hard coded the compression algorithm */

        src = kmalloc(sizeof(char)*BUFFER_SIZE, GFP_KERNEL);
        compressed = kmalloc(sizeof(char)*BUFFER_SIZE, GFP_KERNEL);
        dst = kmalloc(sizeof(char)*BUFFER_SIZE, GFP_KERNEL);
        dst_len = kmalloc(sizeof(size_t), GFP_KERNEL);
        dst_len_c = kmalloc(sizeof(size_t), GFP_KERNEL);
        if(!src || !dst || !dst_len || !dst_len_c || !compressed) {
                printk(KERN_ERR "Memory allocation failed\n");
                err = -ENOMEM;
                goto last;
        }
	
	tfm = crypto_alloc_comp(alg, 0, 0);
        if(IS_ERR(tfm)) {
                printk("error in crypto_alloc_comp\n");
                err = PTR_ERR(tfm);
                goto last;
        }
	
        do {
                memset(src, '\0', BUFFER_SIZE);
		/* Read input buffer. read_offset is 0 in case of enc */
                ret1 = xcrypt_read(input_file, read_offset + count*(XCRYPT_BUF), src, XCRYPT_BUF);
		printk("Successfully read %d bytes\n",ret1);
                if(ret1 == 0) {
                        printk(KERN_INFO "File end. Read 0 bytes\n");
                        goto last;
                }
                if(ret1 < 0) {
                        xcrypt_close(&input_file);
                        xcrypt_close(&output_file);
                        printk(KERN_ERR "Some issue in reading data from file\n");
                        err = -EIO;
                        goto last;
		}
		memset(dst, '\0', BUFFER_SIZE);
		memset(compressed, '\0', BUFFER_SIZE);
		memset(bytes, '\0', 5);
		memset(num, '\0', 2);
		/* Compression here */
		crypto_comp_compress(tfm, src, ret1, compressed, (unsigned int *) dst_len_c);
		/* Encryption here */
		err = ceph_aes_encrypt(key, key_len, dst, dst_len, compressed, *dst_len_c);
		if(err < 0) {
			printk("Encryption error\n");
			goto last;
		}
		snprintf(bytes, 5, "%u", (unsigned int) *dst_len);
		snprintf(num, 2, "%u", (unsigned int) strlen(bytes));
		
                write += xcrypt_write(output_file, write, num, 1);
                write += xcrypt_write(output_file, write, bytes, strlen(bytes));
                write += xcrypt_write(output_file, write, dst, *dst_len);
		count++;
        } while(ret1 > 0);

last:
        if(src)
                kfree(src);
        if(dst)
                kfree(dst);
        if(compressed)
                kfree(compressed);
        if(dst_len)
                kfree(dst_len);
	if(dst_len_c)
		kfree(dst_len_c);

        return err;

}

/* xcrypt_file - api to encrypt/decrypt file on basis of flag
 * @input_file - input file ptr
 * @output_file - output_file ptr
 * @key - encryption key
 * @key_len - encryption key len
 * @flag - 0x01 (encrypt), 0x02 (decrypt)
 * @write - write offset
 * @read_offset - read offset
 */
int xcrypt_file(struct file *input_file, struct file *output_file, char *key, int key_len, int flag, int write, int read_offset)
{
        int err = 0, ret1, count = 0, XCRYPT_BUF = BUFFER_SIZE;
        size_t *dst_len = NULL;
        char *src = NULL, *dst = NULL;
        src = kmalloc(sizeof(char)*BUFFER_SIZE, GFP_KERNEL);
        dst = kmalloc(sizeof(char)*BUFFER_SIZE, GFP_KERNEL);
        dst_len= kmalloc(sizeof(size_t), GFP_KERNEL);
        if(!src || !dst || !dst_len) {
                printk(KERN_ERR "Memory allocation failed\n");
                err = -ENOMEM;
                goto last;
        }

        if(flag & MODE_ENCRYPT) XCRYPT_BUF = BUFFER_SIZE - 16;
        do {
                memset(src, '\0', BUFFER_SIZE);
                memset(dst, '\0', BUFFER_SIZE);
                ret1 = xcrypt_read(input_file, read_offset + count*(XCRYPT_BUF), src, XCRYPT_BUF);
                if(ret1 == 0) {
                        printk(KERN_INFO "File end. Read 0 bytes\n");
                        goto last;
                }
                if(ret1 < 0) {
                        xcrypt_close(&input_file);
                        xcrypt_close(&output_file);
                        printk(KERN_ERR "Some issue in reading data from file\n");
                        err = -EIO;
                        goto last;
                }
                if(flag & MODE_ENCRYPT)
                        err = ceph_aes_encrypt(key, key_len, dst, dst_len, src, ret1);
                else if(flag & MODE_DECRYPT)
                        err = ceph_aes_decrypt(key, key_len, dst, dst_len, src, ret1);
                if(err < 0) {
                        printk("Encryption error\n");
			goto last;
		}
		if((flag & MODE_ENCRYPT) || (flag & MODE_DECRYPT))
			write += xcrypt_write(output_file, write, dst, *dst_len);
		else
			write += xcrypt_write(output_file, write, src, ret1);
		count++;
        } while( ret1 == XCRYPT_BUF );

last:
        if(src)
                kfree(src);
        if(dst)
                kfree(dst);
        if(dst_len)
                kfree(dst_len);

        return err;

}

/* compress_file - API to compress a file
 * @input_file - input file ptr
 * @output_file - output file ptr
 * returns integer SUCCESS - 0 FAILURE - negative val
 */
int compress_file(struct file *input_file, struct file *output_file, int write)
{
	int err = 0, ret1, count = 0, XCRYPT_BUF = BUFFER_SIZE;
	char *src = NULL, *dst = NULL;
	char num[2], bytes[5];
	struct crypto_comp *tfm = NULL;
	const char *alg = "deflate"; /* Hard coded the compression algorithm */
	size_t *dst_len = NULL;

	dst_len = kmalloc(sizeof(size_t), GFP_KERNEL);
	src = kmalloc(sizeof(char)*BUFFER_SIZE, GFP_KERNEL);
	dst = kmalloc(sizeof(char)*BUFFER_SIZE, GFP_KERNEL);
	if(!src || !dst || !dst_len) {
		printk(KERN_ERR "Memory allocation failed\n");
		err = -ENOMEM;
		goto last;
	}
	tfm = crypto_alloc_comp(alg, 0, 0);
	if (IS_ERR(tfm)) {
		printk("error in crypto_alloc_comp\n");
		err = PTR_ERR(tfm);
		goto last;
	}
	do {
		memset(src, '\0', BUFFER_SIZE);
		memset(dst, '\0', BUFFER_SIZE);
		memset(bytes, '\0', 5);
		ret1 = xcrypt_read(input_file, count*XCRYPT_BUF, src, XCRYPT_BUF);
		if(ret1 == 0) {
			printk(KERN_INFO "File end. Read 0 bytes\n");
			goto last;
		}
		if(ret1 < 0) {
			xcrypt_close(&input_file);
			xcrypt_close(&output_file);
			printk(KERN_ERR "Some issue in reading data from file\n");
			goto last;
		}
		/* Compression here */
		crypto_comp_compress(tfm, src, ret1, dst, (unsigned int *) dst_len);
		snprintf(bytes, 5, "%u", (unsigned int) *dst_len);
		snprintf(num, 2, "%u", (unsigned int) strlen(bytes));

		write += xcrypt_write(output_file, write, num, 1);
		write += xcrypt_write(output_file, write, bytes, strlen(bytes));
		write += xcrypt_write(output_file, write, dst, *dst_len);
		count++;
	} while(ret1 == XCRYPT_BUF);
last:
	if(src)
		kfree(src);
	if(dst)
		kfree(dst);
	if(dst_len)
		kfree(dst_len);
	return err;
}

/* decompress_file - API to decompress a file
 * @input_file - input file ptr
 * @output_file - output file ptr
 * returns integer SUCCESS - 0 FAILURE - negative val
 */
int decompress_file(struct file *input_file, struct file *output_file, int read)
{
	int err = 0, ret1, count = read, write = 0, num_bytes_read;
	char *src = NULL, *dst = NULL;
	struct crypto_comp *tfm = NULL;
	const char *alg = "deflate";
	size_t *dst_len = NULL;
	
	dst_len = kmalloc(sizeof(size_t), GFP_KERNEL);
	src = kmalloc(sizeof(char)*BUFFER_SIZE, GFP_KERNEL);
	dst = kmalloc(sizeof(char)*BUFFER_SIZE, GFP_KERNEL);
	if(!src || !dst || !dst_len) {
		printk(KERN_ERR "Memory allocation failed\n");
		err = -ENOMEM;
		goto last;
	}
	tfm = crypto_alloc_comp(alg, 0, 0);
	if (IS_ERR(tfm)) {
		printk("error in crypto_alloc_comp\n");
		err = PTR_ERR(tfm);
		goto last;
	}
	num_bytes_read = decompressed_bytes(input_file, &count);
	do {
		memset(src, '\0', BUFFER_SIZE);
		memset(dst, '\0', BUFFER_SIZE);
		ret1 = xcrypt_read(input_file, count, src, num_bytes_read);
		if(ret1 == 0) {
			printk(KERN_INFO "File end. Read 0 bytes\n");
			goto last;
		}
		if(ret1 < 0) {
			xcrypt_close(&input_file);
			xcrypt_close(&output_file);
			printk(KERN_ERR "Some issue in reading data from file\n");
			err = ret1;
			goto last;
		}
		/* Decompression here */
		crypto_comp_decompress(tfm, src, ret1, dst, (unsigned int *) dst_len);
		count += ret1;
		num_bytes_read = decompressed_bytes(input_file, &count);        
		write += xcrypt_write(output_file, write, dst, *dst_len);
	} while(ret1 > 0);
last:
	if(src)
		kfree(src);
	if(dst)
		kfree(dst);
	if(dst_len)
		kfree(dst_len);
	return err;
}
/**
 * filename_to_trashfilename - api to add details like timestamp, uid, comp/enc info to filename
 * @uid2str - uid to string in _uid_ format e.g. _1001_
 * @inputfile - input file name
 * @compressed - is compression on?
 * @encrypted - is encrypted on?
 * returns modified filename string or NULL in case of failure
 */
char *filename_to_trashfilename(char *uid2str, char *inputfile, int compressed, int encrypted)
{
	int suffix_len = 0;
	char *timestamp = NULL, *trashfilename = NULL;
	struct timeval t, time;
	struct tm broken;
	unsigned long local_time;
	struct rtc_time tm;

	/* create encrypted - compressed file name string */
	do_gettimeofday(&t);
	time_to_tm(t.tv_sec, 0, &broken);
	do_gettimeofday(&time);
	local_time = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
	rtc_time_to_tm(local_time, &tm);

	/* timestamp - 27(time stamp including _) + uidtostr + 1(_) + inputfile + upto 9(.comp .enc) + 1('/0') */
	suffix_len = compressed*5 + encrypted*4;
	timestamp = (char *) kmalloc(27 + strlen(uid2str) + 1 + strlen(inputfile) + suffix_len + 1, GFP_KERNEL); 
	if(!timestamp) {
		printk(KERN_ERR "Memory allocation failed\n");
		return NULL;
	}

	/* fill in the timestamp data structure with all the details */
	memset(timestamp, '\0', strlen(inputfile) + 27 + 1 + strlen(uid2str) + suffix_len + 1);
	snprintf(timestamp, 27, "%04d-%02d-%02d-%02d:%02d:%02d:%ld", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, t.tv_usec);
	strncpy(timestamp + strlen(timestamp), uid2str, strlen(uid2str));
	strncpy(timestamp + strlen(timestamp), inputfile, strlen(inputfile));
	if(compressed)
		strncpy(timestamp + strlen(timestamp), ".comp", 5);
	if(encrypted)
		strncpy(timestamp + strlen(timestamp), ".enc", 4);
	timestamp[strlen(timestamp)] = '\0';

	printk(KERN_INFO "Time string (as part of enc and comp file name): %s\n",timestamp);

	/* fill the information in output file name ds */
	trashfilename = (char *) kmalloc(PATH_MAX + 96, GFP_KERNEL);
	if(!trashfilename) {
		printk(KERN_ERR "Memory allocation failed\n");
		goto last;
	}
	memset(trashfilename, '\0', PATH_MAX + 96);
	strncpy(trashfilename, sgfs_extra->lowerdir, strlen(sgfs_extra->lowerdir));
	strncpy(trashfilename + strlen(sgfs_extra->lowerdir), "/.trashbin/", 11);
	strncpy(trashfilename + strlen(sgfs_extra->lowerdir) + 11, timestamp, strlen(timestamp));

last:
	if(timestamp)
		kfree(timestamp);
	return trashfilename;

}

/* setup_xcrypt_key - setup user key or mount point key or default key in key buffer
 * @uid - user id
 */
char *setup_xcrypt_key(unsigned int uid)
{
	char *key = NULL, *temp_key = NULL, *key_hash = NULL;
	int i;
	key = (char *) kmalloc(17, GFP_KERNEL);  /* key buffer */
	key_hash = (char *)kmalloc(sizeof(char)*17, GFP_KERNEL);
        if(!key) {
                printk("Memory allocation failed.\n");
                goto last;
        }

	/* setup default key. key priority : user key > mount time key > below given default key */
        strncpy(key, "1234123412341234", 16);
        key[16] = '\0';

	/* setup mount path key */
	for(i = 0; i < strlen(sgfs_extra->key); i++) {
                key[i] = sgfs_extra->key[i];
        }
        memset(key_hash, '\0', 17);
        calculate_md5(key_hash, key, strlen(key));
	if(key)
		kfree(key);
	/* get user key and set it (if any) */
        temp_key = get_user_key(uid);
        printk("Key used for encryption is Mount Key: |%s| User Key: |%s|\n",key_hash, temp_key);
        if(temp_key != NULL)
		goto return_user_key;
	

last:
	if(temp_key)
		kfree(temp_key);
	return key_hash;

return_user_key:
	if(key_hash)
		kfree(key_hash);
	return temp_key;
}

/* sgfs_unlink_ - unlink helper
 * @dir - parent inode
 * @dentry - dentry
 * @curr_job - current job details
 */
int sgfs_unlink_(struct inode *dir, struct dentry *dentry, struct job *curr_job)
{

	int err = 0;
	struct dentry *lower_dentry;
	struct path lower_path;
	char *buf = NULL, *res = NULL, *ret = NULL;
	struct super_block *sb;
	unsigned int uid;
	const struct cred *cred;
	struct file *input_file = NULL, *output_file = NULL;
	int file_err;
	char *file_orig_path = NULL;
	char *buf_o = NULL;
	char *tok = NULL, *end = NULL, *inputfile = NULL, *if_user_file = NULL;
	char *uid2str = NULL, *trashfilename = NULL;
	char *key = NULL;
	int write = 0;
	int enc_flag = 0, zip_flag = 0;
	struct task_struct *curr = NULL;
	int encret;
	int file_orig_path_len = strlen(file_orig_path);
	char fop_lenstr[5];
	int fop_lenstr_len;
	char fop_lenstr_lenstr[2];
	unsigned int sg_mode, lw_mode;	
	struct inode *lower_inode;

	/* get userid and convert uid to str */
	curr = get_current();
	printk("RECOVERY FLAG SET IS %d\n",curr->recover_flags);
	cred = current_cred();
	uid = *(unsigned int *) &(cred->euid);
	enc_flag = curr->recover_flags&CLONE_PROT_ENC;
	zip_flag = curr->recover_flags&CLONE_PROT_ZIP;
	if(curr_job != NULL) {
		printk("Recovery Flag set is %d\n",curr_job->recover_flags);
		uid = curr_job->pid;
		enc_flag = curr_job->recover_flags&CLONE_PROT_ENC;
		zip_flag = curr_job->recover_flags&CLONE_PROT_ZIP;
	}
	printk(KERN_INFO "Submitter User ID : %u and Thread User IDs: %u %u\n",(unsigned int)uid, *(unsigned int *)&(cred->euid), *(unsigned int *)&(cred->uid));
	key = setup_xcrypt_key(uid);	/* gets the encryption key of the user/ mount point / default */	

	/* no .trashbin */	
	sb = dir->i_sb;		/* get superblock */
	if(!(SGFS_SB(sb)->sg_dentry)) {
		printk(KERN_INFO ".trashbin folder doesn't exist");
		err = -ENOENT;	/* no such directory */
		goto last;
	}
	sg_mode = SGFS_SB(sb)->sg_dentry->d_inode->i_mode;
	lower_inode = sgfs_lower_inode(SGFS_SB(sb)->sg_dentry->d_inode);
	lw_mode = lower_inode->i_mode;
	printk("Trashbin Mode is currently %u %u\n",sg_mode, lw_mode);
	SGFS_SB(sb)->sg_dentry->d_inode->i_mode |= (S_IFDIR | S_IRWXU | S_IRWXG| S_IRWXO); 
	lower_inode->i_mode |= (S_IFDIR | S_IRWXU | S_IRWXG| S_IRWXO);	

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;	/* get the lower dentry */
	buf = (char *) kmalloc(PATH_MAX, GFP_KERNEL);	/* path relative to mount pt */
	buf_o = (char*) kmalloc(PATH_MAX, GFP_KERNEL);	/* orig path */
	if(!buf || !buf_o) {
		printk("Memory allocation failed.\n");
		err = -ENOMEM;
		goto last;
	}
	memset(buf, '\0', PATH_MAX);
	memset(buf_o, '\0', PATH_MAX);
	file_orig_path = dentry_path_raw(lower_dentry, buf_o, PATH_MAX);	/* file path - ..../lower/... */
	if(IS_ERR(file_orig_path)) {
		err = PTR_ERR(file_orig_path);
		printk("Error in getting original file path from lower dentry\n");
		goto last;	
	}
	res = dentry_path_raw(dentry, buf, PATH_MAX);
	if (IS_ERR(res)) {
		err = PTR_ERR(res);
		printk("Error in getting path from dentry\n");
		goto last;
	}
	printk("Full name of file from dentry : |%s| and lower dentry : |%s|\n", res, file_orig_path);

	uid2str = (char *) kmalloc(13, GFP_KERNEL);
	if(!uid2str) {
		printk("Memory allocation failed\n");
		err = -ENOMEM;
		goto last;
	}
	memset(uid2str, '\0', 13);	
	snprintf(uid2str, 13, "_%u_", uid);


	/* if file lies in .trashbin folder do a normal unlink */
	ret = strstr(res,".trashbin");
	if(ret != NULL && ret == res+1) {
		/* check if file belongs to user only */
		sgfs_put_lower_path(dentry, &lower_path);
		if_user_file = strstr(res, uid2str);
		if(if_user_file == NULL) {	/* Here root also cant delete user's files. This is an assumption. We can allow root by adding one more condition */
			err = -EPERM;
			goto perm_del;
		}
		printk(KERN_INFO "File to be deleted lies in .trashbin folder. Deleting permanently!\n");
		err = sgfs_unlink_util(dir, dentry);
		goto perm_del;
	}


	file_err = xcrypt_open(file_orig_path, O_RDONLY, 0, &input_file);
	if(file_err < 0) {
		printk("Error opening file to be unlinked %s %d\n", file_orig_path, file_err);
		err = file_err;
		goto last;
	}
	if (!(input_file->f_mode & FMODE_READ)) {
		printk("File to remove can't be read\n");
		err = -EACCES;
		goto last;
	}

	tok = res;
	end = res;
	while(tok != NULL) {
		strsep(&end,"/");
		inputfile = tok;
		tok = end;
	}
	printk("UID2STR %s INPUTFILE %s RES |%s|\n",uid2str,inputfile,res);
	printk("Flags : %d %d ",enc_flag, zip_flag);
	trashfilename = filename_to_trashfilename(uid2str, inputfile, zip_flag, enc_flag);
	if(!trashfilename) {
		goto last;
	}

	printk("####### TRASHFILENAME %s\n",trashfilename);
	file_err = xcrypt_open(trashfilename, O_WRONLY|O_CREAT, input_file->f_path.dentry->d_inode->i_mode, &output_file);
	if (file_err < 0) {
		printk("Error creating temporary file %s %d\n", trashfilename, file_err);
		err = file_err;
		goto last;
	}

	printk("Size of the file %s to be unlinked is %u\n", file_orig_path, (unsigned int) input_file->f_inode->i_size);
	printk("Key used for enc: %s lower mount path: %s \n",sgfs_extra->key, sgfs_extra->lowerdir);
	file_orig_path_len = strlen(file_orig_path);

	memset(fop_lenstr, '\0', 5);
	snprintf(fop_lenstr, 5, "%d", file_orig_path_len);
	fop_lenstr_len = strlen(fop_lenstr);
	memset(fop_lenstr_lenstr, '\0', 2);
	snprintf(fop_lenstr_lenstr, 2, "%d", fop_lenstr_len);

	write += xcrypt_write(output_file, write, fop_lenstr_lenstr, strlen(fop_lenstr_lenstr)); /* write num len */
	write += xcrypt_write(output_file, write, fop_lenstr, strlen(fop_lenstr));		/* write num */
	write += xcrypt_write(output_file, write, file_orig_path, strlen(file_orig_path));	/* file path */
	write += xcrypt_write(output_file, write, key, 16); 					/* write keyhash */

	if(enc_flag && zip_flag)
		encret = encrypt_compress_file(input_file, output_file, key, 16, write, 0);
	else if(enc_flag)
		encret = xcrypt_file(input_file, output_file, key, 16, 0x1, write, 0);
	else if(zip_flag)
		encret = compress_file(input_file, output_file, write);
	else
		encret = xcrypt_file(input_file, output_file, key, 16, 0, write, 0);
	xcrypt_close(&output_file);
	xcrypt_close(&input_file);
	err = sgfs_unlink_util(dir, dentry);

	SGFS_SB(sb)->sg_dentry->d_inode->i_mode = sg_mode;
	lower_inode->i_mode = lw_mode; 
last:
	if(trashfilename)
		kfree(trashfilename);
	if(input_file)
		xcrypt_close(&input_file);
	if(output_file)
		xcrypt_close(&output_file);
	sgfs_put_lower_path(dentry, &lower_path);

perm_del:
	if(uid2str)
		kfree(uid2str);
	if(buf)
		kfree(buf);
	if(buf_o)
		kfree(buf_o);
	if(key)
		kfree(key);
	return err;
}

/* sgfs_restore - restore a file. called by ioctl
 * @filename - name of the file
 * @sb - super block
 */
int sgfs_restore(char *filename, struct super_block *sb)
{
	int err = 0, decret;
	struct dentry *lower_dentry;
	struct path lower_path;
	char *buf = NULL, *fileorigpath = NULL;
	struct dentry *sg_dentry;
	char key[17];
	int origpathlen, iflen, itr, file_err, ret1 = 0, uid2str_ctr, enc_flag = 0, comp_flag = 0, origpathlen_len;
	unsigned char *src = NULL, *dst = NULL;
	char *orig_file_name = NULL, *file_i = NULL;
	const char *sgpath = NULL;
	struct file *input_file = NULL, *output_file = NULL;
	struct dentry *cwd_dentry = NULL;
	char *cwd_orig_path = NULL, *file_o = NULL;
	const struct cred *cred;
	unsigned int uid;
	char *uid2str = NULL, *uid2str_file = NULL, *uid2str_fileptr = NULL, *input_file_name = NULL, *ret = NULL;
	unsigned int sg_mode, lw_mode;	
	struct inode *lower_inode;
	char origpathlen_lenstr[2], origpathlenstr[5];

	/* .trashbin exists ot not */
	if(!(SGFS_SB(sb)->sg_dentry)) {
		printk(KERN_INFO ".trashbin folder doesn't exist. Make sure .trashbin folder exists");
		err = -ENOENT;	/* no such directory */
		goto last;
	}

	sg_mode = SGFS_SB(sb)->sg_dentry->d_inode->i_mode;
	lower_inode = sgfs_lower_inode(SGFS_SB(sb)->sg_dentry->d_inode);
	lw_mode = lower_inode->i_mode;
	printk("Trashbin Mode is currently %u %u\n",sg_mode, lw_mode);
	SGFS_SB(sb)->sg_dentry->d_inode->i_mode |= (S_IFDIR | S_IRWXU | S_IRWXG| S_IRWXO);
	lower_inode->i_mode |= (S_IFDIR | S_IRWXU | S_IRWXG| S_IRWXO);

	ret = strstr(filename,".enc");
	if(ret != NULL)
		enc_flag = 1;
	ret = NULL;
	ret = strstr(filename,".comp");
	if(ret != NULL)
		comp_flag = 1;


	src = kmalloc(sizeof(char)*BUFFER_SIZE, GFP_KERNEL);
	dst = kmalloc(sizeof(char)*BUFFER_SIZE, GFP_KERNEL);
	if(!src || !dst) {
		printk("Memory allocation failed\n");
		err = -ENOMEM;
		goto last;
	}
	input_file_name = kmalloc(sizeof(char)*BUFFER_SIZE, GFP_KERNEL);
	if(!input_file_name) {
		printk("Memory allocation failed\n");
		err = -ENOMEM;
		goto last;
	}
	printk("Restoring filename %s\n",filename);
	memset(input_file_name, '\0', BUFFER_SIZE);
	iflen = strlen(filename)-1;

	/* remove .enc */
	while(iflen>=0 && filename[iflen] != '.')  iflen--;
	iflen--;
	itr = BUFFER_SIZE - 2;
	while(iflen>=0 && filename[iflen] != '_') {
		input_file_name[itr--] = filename[iflen--];
	}

	/* get userid */
	cred = current_cred();
	uid = *(unsigned int *) &(cred->euid);
	uid2str = (char *) kmalloc(11, GFP_KERNEL);
	uid2str_file = (char *) kmalloc(11, GFP_KERNEL);
	if(!uid2str || !uid2str_file) {
		printk("Memory allocation failed\n");
		err = -ENOMEM;
		goto last;
	}
	memset(uid2str, '\0', 11);
	memset(uid2str_file, '\0', 11);
	snprintf(uid2str, 11, "%u", uid);

	uid2str_ctr = 9;
	iflen--;	
	while(iflen>=0 && filename[iflen] != '_') {
		uid2str_file[uid2str_ctr--] = filename[iflen--];
	}
	uid2str_fileptr = &uid2str_file[uid2str_ctr+1];
	if(strlen(uid2str) != strlen(uid2str_fileptr)) {
		err = -EPERM;
		printk("User trying to decrypt another user's file\n");
		goto last;
	}
	else {
		if(strncmp(uid2str, uid2str_fileptr, strlen(uid2str)) != 0) {
			err = -EPERM;
			printk("User trying to decrypt another user's file\n");
			goto last;
		}
	}

	orig_file_name = &input_file_name[itr+1];
	sgpath = sgfs_extra->lowerdir; 
	file_i = kmalloc(sizeof(char)*BUFFER_SIZE, GFP_KERNEL);
	memset(file_i, '\0', BUFFER_SIZE);
	strncpy(file_i, sgpath, strlen(sgpath));
	strncpy(file_i + strlen(sgpath), "/.trashbin/", 11);
	strncpy(file_i + strlen(sgpath) + 11, filename, strlen(filename));
	printk("File name %s and complete file path to decrypt %s\n", orig_file_name, file_i); 


	sg_dentry = dget(SGFS_SB(sb)->sg_dentry);	
	cwd_dentry = dget(current->fs->pwd.dentry);
	buf = (char *) kmalloc(PATH_MAX, GFP_KERNEL);
	if(!buf) {
		printk("Memory allocation failed\n");
		err = -ENOMEM;
		goto out;
	}
	sgfs_get_lower_path(cwd_dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	memset(buf, '\0', PATH_MAX);
	cwd_orig_path = dentry_path_raw(lower_dentry, buf, PATH_MAX);        /* file path - ..../lower/... */
	if(IS_ERR(cwd_orig_path)) {
		err = PTR_ERR(cwd_orig_path);
		printk("Error in getting path from dentry\n");
		goto out;
	}

	file_o = kmalloc(sizeof(char)*BUFFER_SIZE, GFP_KERNEL);
	memset(file_o, '\0', BUFFER_SIZE);
	file_err = xcrypt_open(file_i, O_RDONLY, 0, &input_file);
	if(file_err < 0) {
		printk("Error opening input file \n");
		goto out;
	}

	if (!(input_file->f_mode & FMODE_READ)) {
		printk("Input File can't be read\n");
		goto out;
	}

	memset(origpathlen_lenstr, '\0', 2);
	ret1 += xcrypt_read(input_file, ret1, origpathlen_lenstr, 1);	
	origpathlen_len = origpathlen_lenstr[0]-'0';
	memset(origpathlenstr, '\0', 5);
	ret1 += xcrypt_read(input_file, ret1, origpathlenstr, origpathlen_len);

	origpathlen = string_to_int(origpathlenstr); 

	fileorigpath = (char *) kmalloc(PATH_MAX, GFP_KERNEL);
	if(!fileorigpath) {
		printk(KERN_ERR "Memory allocation failed\n");
		goto out;
	}
	memset(fileorigpath, '\0', PATH_MAX);
	memset(key, '\0', 17);
	ret1 += xcrypt_read(input_file, ret1, fileorigpath, origpathlen);
	strncpy(file_o, fileorigpath, strlen(fileorigpath));
	ret1 += xcrypt_read(input_file, ret1, key, 16);

	file_err = xcrypt_open(file_o, O_WRONLY|O_CREAT, input_file->f_path.dentry->d_inode->i_mode, &output_file);
	if (file_err < 0) {
		printk("Error creating temporary file \n");
		goto out;
	}

	if(enc_flag && comp_flag)
		decret = decrypt_decompress_file(input_file, output_file, key, 16, 0, ret1); 
	else if(enc_flag)
		decret = xcrypt_file(input_file, output_file, key, 16, 0x2, 0, ret1);
	else if(comp_flag)
		decret = decompress_file(input_file, output_file, ret1);
	else
		decret = xcrypt_file(input_file, output_file, key, 16, 0, 0, ret1);

	printk("Returninig from decrypt %d\n",decret);

	xcrypt_close(&input_file);
	xcrypt_close(&output_file);

	SGFS_SB(sb)->sg_dentry->d_inode->i_mode = sg_mode;
	lower_inode->i_mode = lw_mode;; 

out:
	sgfs_put_lower_path(cwd_dentry, &lower_path);
	dput(cwd_dentry);
	dput(sg_dentry);
last:

	if(file_i)
		kfree(file_i);
	if(file_o)
		kfree(file_o);
	if(buf)
		kfree(buf);
	if(uid2str)
		kfree(uid2str);
	if(uid2str_file)
		kfree(uid2str_file);
	if(input_file_name)
		kfree(input_file_name);
	if(src)
		kfree(src);
	if(dst)
		kfree(dst);
	if(input_file)
		xcrypt_close(&input_file);
	if(output_file)
		xcrypt_close(&output_file);
	if(fileorigpath)
		kfree(fileorigpath);

	return err;
}
static int sgfs_symlink(struct inode *dir, struct dentry *dentry,
			  const char *symname)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_symlink(d_inode(lower_parent_dentry), lower_dentry, symname);
	if (err)
		goto out;
	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

int sgfs_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_mkdir(d_inode(lower_parent_dentry), lower_dentry, mode);
	if (err)
		goto out;

	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;

	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));
	/* update number of links on parent directory */
	set_nlink(dir, sgfs_lower_inode(dir)->i_nlink);

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct dentry *lower_dentry;
	struct dentry *lower_dir_dentry;
	int err;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_dir_dentry = lock_parent(lower_dentry);

	err = vfs_rmdir(d_inode(lower_dir_dentry), lower_dentry);
	if (err)
		goto out;

	d_drop(dentry);	/* drop our dentry on success (why not VFS's job?) */
	if (d_inode(dentry))
		clear_nlink(d_inode(dentry));
	fsstack_copy_attr_times(dir, d_inode(lower_dir_dentry));
	fsstack_copy_inode_size(dir, d_inode(lower_dir_dentry));
	set_nlink(dir, d_inode(lower_dir_dentry)->i_nlink);

out:
	unlock_dir(lower_dir_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int sgfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
			dev_t dev)
{
	int err;
	struct dentry *lower_dentry;
	struct dentry *lower_parent_dentry = NULL;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_parent_dentry = lock_parent(lower_dentry);

	err = vfs_mknod(d_inode(lower_parent_dentry), lower_dentry, mode, dev);
	if (err)
		goto out;

	err = sgfs_interpose(dentry, dir->i_sb, &lower_path);
	if (err)
		goto out;
	fsstack_copy_attr_times(dir, sgfs_lower_inode(dir));
	fsstack_copy_inode_size(dir, d_inode(lower_parent_dentry));

out:
	unlock_dir(lower_parent_dentry);
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

/*
 * The locking rules in sgfs_rename are complex.  We could use a simpler
 * superblock-level name-space lock for renames and copy-ups.
 */
static int sgfs_rename(struct inode *old_dir, struct dentry *old_dentry,
			 struct inode *new_dir, struct dentry *new_dentry)
{
	int err = 0;
	struct dentry *lower_old_dentry = NULL;
	struct dentry *lower_new_dentry = NULL;
	struct dentry *lower_old_dir_dentry = NULL;
	struct dentry *lower_new_dir_dentry = NULL;
	struct dentry *trap = NULL;
	struct path lower_old_path, lower_new_path;

	sgfs_get_lower_path(old_dentry, &lower_old_path);
	sgfs_get_lower_path(new_dentry, &lower_new_path);
	lower_old_dentry = lower_old_path.dentry;
	lower_new_dentry = lower_new_path.dentry;
	lower_old_dir_dentry = dget_parent(lower_old_dentry);
	lower_new_dir_dentry = dget_parent(lower_new_dentry);

	trap = lock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	/* source should not be ancestor of target */
	if (trap == lower_old_dentry) {
		err = -EINVAL;
		goto out;
	}
	/* target should not be ancestor of source */
	if (trap == lower_new_dentry) {
		err = -ENOTEMPTY;
		goto out;
	}

	err = vfs_rename(d_inode(lower_old_dir_dentry), lower_old_dentry,
			 d_inode(lower_new_dir_dentry), lower_new_dentry,
			 NULL, 0);
	if (err)
		goto out;

	fsstack_copy_attr_all(new_dir, d_inode(lower_new_dir_dentry));
	fsstack_copy_inode_size(new_dir, d_inode(lower_new_dir_dentry));
	if (new_dir != old_dir) {
		fsstack_copy_attr_all(old_dir,
				      d_inode(lower_old_dir_dentry));
		fsstack_copy_inode_size(old_dir,
					d_inode(lower_old_dir_dentry));
	}

out:
	unlock_rename(lower_old_dir_dentry, lower_new_dir_dentry);
	dput(lower_old_dir_dentry);
	dput(lower_new_dir_dentry);
	sgfs_put_lower_path(old_dentry, &lower_old_path);
	sgfs_put_lower_path(new_dentry, &lower_new_path);
	return err;
}

static int sgfs_readlink(struct dentry *dentry, char __user *buf, int bufsiz)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op ||
	    !d_inode(lower_dentry)->i_op->readlink) {
		err = -EINVAL;
		goto out;
	}

	err = d_inode(lower_dentry)->i_op->readlink(lower_dentry,
						    buf, bufsiz);
	if (err < 0)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry), d_inode(lower_dentry));

out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static const char *sgfs_get_link(struct dentry *dentry, struct inode *inode,
				   struct delayed_call *done)
{
	char *buf;
	int len = PAGE_SIZE, err;
	mm_segment_t old_fs;

	if (!dentry)
		return ERR_PTR(-ECHILD);

	/* This is freed by the put_link method assuming a successful call. */
	buf = kmalloc(len, GFP_KERNEL);
	if (!buf) {
		buf = ERR_PTR(-ENOMEM);
		return buf;
	}

	/* read the symlink, and then we will follow it */
	old_fs = get_fs();
	set_fs(KERNEL_DS);
	err = sgfs_readlink(dentry, buf, len);
	set_fs(old_fs);
	if (err < 0) {
		kfree(buf);
		buf = ERR_PTR(err);
	} else {
		buf[err] = '\0';
	}
	set_delayed_call(done, kfree_link, buf);
	return buf;
}

static int sgfs_permission(struct inode *inode, int mask)
{
	struct inode *lower_inode;
	int err;

	lower_inode = sgfs_lower_inode(inode);
	err = inode_permission(lower_inode, mask);
	return err;
}

static int sgfs_setattr(struct dentry *dentry, struct iattr *ia)
{
	int err;
	struct dentry *lower_dentry;
	struct inode *inode;
	struct inode *lower_inode;
	struct path lower_path;
	struct iattr lower_ia;

	inode = d_inode(dentry);

	/*
	 * Check if user has permission to change inode.  We don't check if
	 * this user can change the lower inode: that should happen when
	 * calling notify_change on the lower inode.
	 */
	err = inode_change_ok(inode, ia);
	if (err)
		goto out_err;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	lower_inode = sgfs_lower_inode(inode);

	/* prepare our own lower struct iattr (with the lower file) */
	memcpy(&lower_ia, ia, sizeof(lower_ia));
	if (ia->ia_valid & ATTR_FILE)
		lower_ia.ia_file = sgfs_lower_file(ia->ia_file);

	/*
	 * If shrinking, first truncate upper level to cancel writing dirty
	 * pages beyond the new eof; and also if its' maxbytes is more
	 * limiting (fail with -EFBIG before making any change to the lower
	 * level).  There is no need to vmtruncate the upper level
	 * afterwards in the other cases: we fsstack_copy_inode_size from
	 * the lower level.
	 */
	if (ia->ia_valid & ATTR_SIZE) {
		err = inode_newsize_ok(inode, ia->ia_size);
		if (err)
			goto out;
		truncate_setsize(inode, ia->ia_size);
	}

	/*
	 * mode change is for clearing setuid/setgid bits. Allow lower fs
	 * to interpret this in its own way.
	 */
	if (lower_ia.ia_valid & (ATTR_KILL_SUID | ATTR_KILL_SGID))
		lower_ia.ia_valid &= ~ATTR_MODE;

	/* notify the (possibly copied-up) lower inode */
	/*
	 * Note: we use d_inode(lower_dentry), because lower_inode may be
	 * unlinked (no inode->i_sb and i_ino==0.  This happens if someone
	 * tries to open(), unlink(), then ftruncate() a file.
	 */
	inode_lock(d_inode(lower_dentry));
	err = notify_change(lower_dentry, &lower_ia, /* note: lower_ia */
			    NULL);
	inode_unlock(d_inode(lower_dentry));
	if (err)
		goto out;

	/* get attributes from the lower inode */
	fsstack_copy_attr_all(inode, lower_inode);
	/*
	 * Not running fsstack_copy_inode_size(inode, lower_inode), because
	 * VFS should update our inode size, and notify_change on
	 * lower_inode should update its size.
	 */

out:
	sgfs_put_lower_path(dentry, &lower_path);
out_err:
	return err;
}

static int sgfs_getattr(struct vfsmount *mnt, struct dentry *dentry,
			  struct kstat *stat)
{
	int err;
	struct kstat lower_stat;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	err = vfs_getattr(&lower_path, &lower_stat);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
	generic_fillattr(d_inode(dentry), stat);
	stat->blocks = lower_stat.blocks;
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int
sgfs_setxattr(struct dentry *dentry, const char *name, const void *value,
		size_t size, int flags)
{
	int err; struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op->setxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_setxattr(lower_dentry, name, value, size, flags);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static ssize_t
sgfs_getxattr(struct dentry *dentry, const char *name, void *buffer,
		size_t size)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op->getxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_getxattr(lower_dentry, name, buffer, size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
				d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static ssize_t
sgfs_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op->listxattr) {
		err = -EOPNOTSUPP;
		goto out;
	}
	err = vfs_listxattr(lower_dentry, buffer, buffer_size);
	if (err)
		goto out;
	fsstack_copy_attr_atime(d_inode(dentry),
				d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}

static int
sgfs_removexattr(struct dentry *dentry, const char *name)
{
	int err;
	struct dentry *lower_dentry;
	struct path lower_path;

	sgfs_get_lower_path(dentry, &lower_path);
	lower_dentry = lower_path.dentry;
	if (!d_inode(lower_dentry)->i_op ||
	    !d_inode(lower_dentry)->i_op->removexattr) {
		err = -EINVAL;
		goto out;
	}
	err = vfs_removexattr(lower_dentry, name);
	if (err)
		goto out;
	fsstack_copy_attr_all(d_inode(dentry),
			      d_inode(lower_path.dentry));
out:
	sgfs_put_lower_path(dentry, &lower_path);
	return err;
}
const struct inode_operations sgfs_symlink_iops = {
	.readlink	= sgfs_readlink,
	.permission	= sgfs_permission,
	.setattr	= sgfs_setattr,
	.getattr	= sgfs_getattr,
	.get_link	= sgfs_get_link,
	.setxattr	= sgfs_setxattr,
	.getxattr	= sgfs_getxattr,
	.listxattr	= sgfs_listxattr,
	.removexattr	= sgfs_removexattr,
};

const struct inode_operations sgfs_dir_iops = {
	.create		= sgfs_create,
	.lookup		= sgfs_lookup,
	.link		= sgfs_link,
	.unlink		= sgfs_unlink,
	.symlink	= sgfs_symlink,
	.mkdir		= sgfs_mkdir,
	.rmdir		= sgfs_rmdir,
	.mknod		= sgfs_mknod,
	.rename		= sgfs_rename,
	.permission	= sgfs_permission,
	.setattr	= sgfs_setattr,
	.getattr	= sgfs_getattr,
	.setxattr	= sgfs_setxattr,
	.getxattr	= sgfs_getxattr,
	.listxattr	= sgfs_listxattr,
	.removexattr	= sgfs_removexattr,
};

const struct inode_operations sgfs_main_iops = {
	.permission	= sgfs_permission,
	.setattr	= sgfs_setattr,
	.getattr	= sgfs_getattr,
	.setxattr	= sgfs_setxattr,
	.getxattr	= sgfs_getxattr,
	.listxattr	= sgfs_listxattr,
	.removexattr	= sgfs_removexattr,
};
