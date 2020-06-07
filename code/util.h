/*
 * Author - Rahul Sihag
 */

#ifndef _UTIL_H_
#define _UTIL_H_

#include "sgfs.h"
#include "queue.h"
#include "fileop.h"
#include "extra.h"
#include "sleeptime.h"

/* string_to_int - convert string to integer
 * @num - char pointer ( should contain only digits
 * return int
 */
int string_to_int(char *num)
{
        int i, len, dec = 0;
        if(!num) return 0;

        len = strlen(num);
        for(i=0; i<len; i++) {
                dec = dec * 10 + ( num[i] - '0' );
        }
        return dec;
}

/* Encryption APIs. Source - http://www.staroceans.org/projects/beagleboard/net/ceph/crypto.c i
 * */

const u8 *aes_iv = (u8 *)CEPH_AES_IV;

/* setup_sgtable - helper API used by ceph_aes_encrypt/ceph_aes_decrypt
 */
int setup_sgtable(struct sg_table *sgt, struct scatterlist *prealloc_sg,
		const void *buf, unsigned int buf_len)
{
	struct scatterlist *sg;
	const bool is_vmalloc = is_vmalloc_addr(buf);
	unsigned int off = offset_in_page(buf);
	unsigned int chunk_cnt = 1;
	unsigned int chunk_len = PAGE_ALIGN(off + buf_len);
	int i;
	int ret;

	if (buf_len == 0) {
		memset(sgt, 0, sizeof(*sgt));
		return -EINVAL;
	}

	if (is_vmalloc) {
		chunk_cnt = chunk_len >> PAGE_SHIFT;
		chunk_len = PAGE_SIZE;
	}

	if (chunk_cnt > 1) {
		ret = sg_alloc_table(sgt, chunk_cnt, GFP_NOFS);
		if (ret)
			return ret;
	} else {
		WARN_ON(chunk_cnt != 1);
		sg_init_table(prealloc_sg, 1);
		sgt->sgl = prealloc_sg;
		sgt->nents = sgt->orig_nents = 1;
	}

	for_each_sg(sgt->sgl, sg, sgt->orig_nents, i) {
		struct page *page;
		unsigned int len = min(chunk_len - off, buf_len);

		if (is_vmalloc)
			page = vmalloc_to_page(buf);
		else
			page = virt_to_page(buf);

		sg_set_page(sg, page, len, off);

		off = 0;
		buf += len;
		buf_len -= len;
	}
	WARN_ON(buf_len != 0);

	return 0;
}

/* teardown_sgtable - helper API used by ceph_aes_encrypt/ceph_aes_decrypt
 */
void teardown_sgtable(struct sg_table *sgt)
{
	if (sgt->orig_nents > 1)
		sg_free_table(sgt);
}


/* ceph_crypto_alloc_cipher - helper API used by ceph_aes_encrypt/ceph_aes_decrypt
 */
struct crypto_blkcipher *ceph_crypto_alloc_cipher(void)
{
	return crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
}

/* ceph_aes_encrypt - API used for encryption
 * @key, key_len - encryption key and its length
 * @dst, dst_len - destination buffer to write to i.e. encrypted text
 * @src, src_len - source buffer to read from i.e. plain text
 * return success/failure value
 */
int ceph_aes_encrypt(const void *key, int key_len,
		void *dst, size_t *dst_len,
		const void *src, size_t src_len)
{
	struct scatterlist sg_in[2], prealloc_sg;
	struct sg_table sg_out;
	struct crypto_blkcipher *tfm = ceph_crypto_alloc_cipher();
	struct blkcipher_desc desc = { .tfm = tfm, .flags = 0 };
	int ret;
	void *iv;
	int ivsize;
	size_t zero_padding = (0x10 - (src_len & 0x0f));
	char pad[16];

	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	memset(pad, zero_padding, zero_padding);

	*dst_len = src_len + zero_padding;

	sg_init_table(sg_in, 2);
	sg_set_buf(&sg_in[0], src, src_len);
	sg_set_buf(&sg_in[1], pad, zero_padding);
	ret = setup_sgtable(&sg_out, &prealloc_sg, dst, *dst_len);
	if (ret)
		goto out_tfm;

	crypto_blkcipher_setkey((void *)tfm, key, key_len);
	iv = crypto_blkcipher_crt(tfm)->iv;
	ivsize = crypto_blkcipher_ivsize(tfm);
	memcpy(iv, aes_iv, ivsize);

	/*
	 * 	print_hex_dump(KERN_ERR, "enc key: ", DUMP_PREFIX_NONE, 16, 1,
	 * 			       key, key_len, 1);
	 * 			       	print_hex_dump(KERN_ERR, "enc src: ", DUMP_PREFIX_NONE, 16, 1,
	 * 			       				src, src_len, 1);
	 * 			       					print_hex_dump(KERN_ERR, "enc pad: ", DUMP_PREFIX_NONE, 16, 1,
	 * 			       								pad, zero_padding, 1);
	 * 			       									*/
	ret = crypto_blkcipher_encrypt(&desc, sg_out.sgl, sg_in,
			src_len + zero_padding);
	if (ret < 0) {
		pr_err("ceph_aes_crypt failed %d\n", ret);
		goto out_sg;
	}
	/*
	 * 	print_hex_dump(KERN_ERR, "enc out: ", DUMP_PREFIX_NONE, 16, 1,
	 * 			       dst, *dst_len, 1);
	 * 			       	*/

out_sg:
	teardown_sgtable(&sg_out);
out_tfm:
	crypto_free_blkcipher(tfm);
	return ret;
}

/* ceph_aes_decrypt - API used for decryption
 * @key, key_len - encryption key and its length
 * @dst, dst_len - destination buffer to write to i.e. decrypted text
 * @src, src_len - source buffer to read from i.e encrypted text
 * return success/failure value
 */
int ceph_aes_decrypt(const void *key, int key_len,
		void *dst, size_t *dst_len,
		const void *src, size_t src_len)
{
	struct sg_table sg_in;
	struct scatterlist sg_out[2], prealloc_sg;
	struct crypto_blkcipher *tfm = ceph_crypto_alloc_cipher();
	struct blkcipher_desc desc = { .tfm = tfm };
	char pad[16];
	void *iv;
	int ivsize;
	int ret;
	int last_byte;

	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	sg_init_table(sg_out, 2);
	sg_set_buf(&sg_out[0], dst, *dst_len);
	sg_set_buf(&sg_out[1], pad, sizeof(pad));
	ret = setup_sgtable(&sg_in, &prealloc_sg, src, src_len);
	if (ret)
		goto out_tfm;

	crypto_blkcipher_setkey((void *)tfm, key, key_len);
	iv = crypto_blkcipher_crt(tfm)->iv;
	ivsize = crypto_blkcipher_ivsize(tfm);
	memcpy(iv, aes_iv, ivsize);

	/*
	 * 	print_hex_dump(KERN_ERR, "dec key: ", DUMP_PREFIX_NONE, 16, 1,
	 * 			       key, key_len, 1);
	 * 			       	print_hex_dump(KERN_ERR, "dec  in: ", DUMP_PREFIX_NONE, 16, 1,
	 * 			       			       src, src_len, 1);
	 * 			       			       	*/
	ret = crypto_blkcipher_decrypt(&desc, sg_out, sg_in.sgl, src_len);
	if (ret < 0) {
		pr_err("ceph_aes_decrypt failed %d\n", ret);
		goto out_sg;
	}

	if (src_len <= *dst_len)
		last_byte = ((char *)dst)[src_len - 1];
	else
		last_byte = pad[src_len - *dst_len - 1];
	if (last_byte <= 16 && src_len >= last_byte) {
		*dst_len = src_len - last_byte;
	} else {
		pr_err("ceph_aes_decrypt got bad padding %d on src len %d\n",
				last_byte, (int)src_len);
		return -EPERM;  /* bad padding */
	}
	/*
	 * 	print_hex_dump(KERN_ERR, "dec out: ", DUMP_PREFIX_NONE, 16, 1,
	 * 			       dst, *dst_len, 1);
	 * 			       	*/

out_sg:
	teardown_sgtable(&sg_in);
out_tfm:
	crypto_free_blkcipher(tfm);
	return ret;
}

/* list_asyncqueue - writes the kernel queue job list to jobs-list proc entry */
int list_asyncqueue(void )
{

	char *inbuf = NULL;
	struct work *curr = head;
	struct job *curr_job;
	struct dentry *dentry;
	char *file_path = NULL;
	char *buf = NULL;
	int err;
	struct file *fptr = NULL;
	int file_err;
	char recovery[15];
	char status[15];

	file_err = xcrypt_open("/proc/jobs-list", O_RDONLY | O_WRONLY, 0, &fptr);
	buf = (char *) kmalloc(PATH_MAX, GFP_KERNEL);   /* path relative to mount pt */
	inbuf = (char *) kmalloc(PATH_MAX, GFP_KERNEL);   /* path relative to mount pt */
	if(!buf || !inbuf) {
		return -ENOMEM;
	}
	memset(inbuf, '\0', PATH_MAX);
	snprintf(inbuf+strlen(inbuf), PATH_MAX - strlen(inbuf), "%-80s\t%-30s\t%-15s\t%-20s\t%-15s\n", "File Path", "Timestamp",  "User ID",  "Clone Flags",  "Status");
	snprintf(inbuf+strlen(inbuf), PATH_MAX - strlen(inbuf), "%-80s\t%-30s\t%-15s\t%-20s\t%-15s\n", "---------", "---------",  "-------",  "-----------",  "------");
	while(curr) {
		memset(recovery, '\0',15);
		memset(status, '\0',15);
		memset(buf, '\0', PATH_MAX);
		curr_job = curr->job;
		dentry = curr_job->dentry;
		file_path = dentry_path_raw(dentry, buf, PATH_MAX);
		if (IS_ERR(file_path)) {
			err = PTR_ERR(file_path);
			printk("Error in getting path from dentry\n");
			goto last;
		}
		if(curr_job->recover_flags == 0) {
			snprintf(recovery + strlen(recovery), 15 - strlen(recovery), "%s", "NA");
		}
		else {
			snprintf(recovery + strlen(recovery), 15 - strlen(recovery), "%s", "MV");
			if(curr_job->recover_flags == 2 || curr_job->recover_flags == 3 || curr_job->recover_flags == 6 || curr_job->recover_flags == 7) {
				snprintf(recovery + strlen(recovery), 15 - strlen(recovery), "%s", " | ZIP");
			}
			if(curr_job->recover_flags >=4) {
				snprintf(recovery + strlen(recovery), 15 - strlen(recovery), "%s", " | ENC");
			}
		}	
		if(curr_job->status == -1) {
			snprintf(status + strlen(status), 15 - strlen(status), "%s", "FAILED");	
		}
		else if(curr_job->status == 0) {
			snprintf(status + strlen(status), 15 - strlen(status), "%s", "COMPLETED");	
		}
		else if(curr_job->status == 1) {
			snprintf(status + strlen(status), 15 - strlen(status), "%s", "INPROCESS");	
		}
		snprintf(inbuf+strlen(inbuf), PATH_MAX - strlen(inbuf), "%-80s\t%-30s\t%-15u\t%-20s\t%-15s\n", file_path, curr_job->timestamp, curr_job->pid, recovery, status);

		curr = curr->next;
	}
	if(file_err < 0) {
		printk("Can't open proc file for putting queue list\n");
		goto last;
	}
	else {
		err = xcrypt_write(fptr, 0, inbuf, strlen(inbuf));
		xcrypt_close(&fptr);
	}


last:	
	if(buf)	
		kfree(buf);
	if(inbuf)
		kfree(inbuf);
	return 0;

}


/* list_asyncqueue - writes the kernel queue job list to jobs-completed proc entry */
int list_completed_asyncqueue(void )
{
	char *inbuf = NULL;
	int i;
	int err;
	struct file *fptr = NULL;
	int file_err;
	char status[15];

	file_err = xcrypt_open("/proc/jobs-completed", O_RDONLY | O_WRONLY, 0, &fptr);
	inbuf = (char *) kmalloc(PATH_MAX, GFP_KERNEL);   /* path relative to mount pt */
	if(!inbuf) {
		return -ENOMEM;
	}
	memset(inbuf, '\0', PATH_MAX);
	snprintf(inbuf+strlen(inbuf), PATH_MAX - strlen(inbuf), "%-80s\t%-15s\n", "File Path", "Status");
	snprintf(inbuf+strlen(inbuf), PATH_MAX - strlen(inbuf), "%-80s\t%-15s\n", "---------", "------");
	/* for(i = (5 + job_arr_ind - 1)%5; i!= job_arr_ind; i = (5 + i-1)%5) 
 	 * Better loop FCFS loop */
	for(i = 0; i < 5; i+=1)
	{
		if(strlen(job_array[i].file_name) == 0) continue;
		memset(status, '\0',15);
		if(job_array[i].status == -1) {
			snprintf(status + strlen(status), 15 - strlen(status), "%s", "FAILED");	
		}
		else if(job_array[i].status == 0) {
			snprintf(status + strlen(status), 15 - strlen(status), "%s", "COMPLETED");	
		}
		else if(job_array[i].status == 1) {
			snprintf(status + strlen(status), 15 - strlen(status), "%s", "INPROCESS");	
		}
		snprintf(inbuf+strlen(inbuf), PATH_MAX - strlen(inbuf), "%-80s\t%-15s\n", job_array[i].file_name, status);
	}
	if(file_err < 0) {
		printk("Can't open proc file for putting queue list\n");
		goto last;
	}
	else {
		printk("Offser of jobs completed is %d\n",jobs_completed_offset);
		err = xcrypt_write(fptr, 0, inbuf, strlen(inbuf));
		xcrypt_close(&fptr);
	}


last:	
	if(inbuf)
		kfree(inbuf);
	return 0;

}
/* insert - inserts a new job to the kernel queue
 * @job - job DS
 * return success/failure
 */
int insert(struct job *job) {

	int err = 0;
	struct work *temp  = NULL;
	temp = kmalloc(sizeof(struct work), GFP_KERNEL);
	if (temp == NULL) {
		printk(KERN_ERR "Memory not available\n");
		err = -ENOMEM;
		goto out;
	}

	temp->job = job;
	temp->next = NULL;

	if(!head) {
		head = temp;
	} else {
		temp->next = head;
		head = temp;
	}
out:
	return err;
}

/* remove - removes a new job from the tail of kernel queue (FCFS)
 * return success/failure
 */
struct work *remove(void ) {
	struct work *prev = NULL, *curr = head;
	while(curr && curr->next) {
		prev = curr;
		curr = curr->next;
	}
	if(prev) {
		prev->next = NULL;
	} else {
		head = NULL;
	}
	
	return curr;
}

/* remove - removes a new job from the tail of kernel queue (FCFS)
 * return success/failure
 */
int remove_filename(char *filename, unsigned int uid ) {

	int success = 1;
        struct work *prev = NULL, *curr = head, *todel = NULL;
	struct job *job = NULL;
	mutex_lock(&wqmutex);
        while(curr) {
		job = curr->job;
		if(strcmp(job->file_name, filename)==0 && job->pid== uid) {
			todel = curr;
			printk("Job to be removed lies in the queue!\n");
			success = 0;	/* 0 indicates success */
			break;		
		}
                prev = curr;
                curr = curr->next;
        }
	if(todel == NULL) {
		mutex_unlock(&wqmutex);
		return success;
	}
	if(prev == NULL) {
		head = todel->next;
		dput(todel->job->dentry);
		kfree(todel);
		consumer_thread_count--;
		mutex_unlock(&wqmutex);
		return success;
	}
	prev->next = todel->next;
	dput(todel->job->dentry);
	kfree(todel);
	consumer_thread_count--;
	mutex_unlock(&wqmutex);
	return success;
}

/* process - process current job
 */
int process(struct job *job)
{
	int err  = 0;
	err = sgfs_unlink_(job->dir, job->dentry, job);
	if(err < 0) {
		job->status = -1;  
	}
	else {
		job->status = 0;  
	}

	mutex_lock(&wqmutex);
	memset(job_array[job_arr_ind].file_name, '\0', 40);
	strncpy(job_array[job_arr_ind].file_name, job->file_name, strlen(job->file_name));
	job_array[job_arr_ind].status = job->status;
	job_arr_ind = (job_arr_ind + 1)%5;
	err = list_completed_asyncqueue();
	mutex_unlock(&wqmutex);
	return err;
}

/* producer - callback function used by producer thread, wakes up a consumer kernel thread
 * @data - job details
 * return success/failure
 */
int producer(void *data) 
{
	int err = 0;
	struct job *job = (struct job *)data;
	UDBG;
	mutex_lock(&wqmutex);

	/*if(consumer_thread_count >= MAX_LIST) {
		printk(KERN_INFO "Procuder: Max job limit reached. Producer thread in wait queue");
		mutex_unlock(&wqmutex);
		producer_thread_count++;
		wait_event_interruptible(producer_queue, consumer_thread_count < MAX_LIST);
		producer_thread_count--;
		mutex_lock(&wqmutex);
	}*/
	insert(job);
	list_asyncqueue();
	/*consumer_thread_count++;*/
	printk("############# JOB SUBMITTED ############## %d\n",consumer_thread_count);
	printk("WAKING UP CONSUMER KERNEL THREAD\n");
	if(consumer_thread_count == 1) {
		printk(KERN_INFO "Producer: Waking up consumer thread\n");
		wake_up_interruptible(&consumer_queue);
	}
	mutex_unlock(&wqmutex);
	return err;

}

/* file_read - wrapper method to read from a file
 * @file - file ptr
 * @offset - offset
 * @data - buffer to store
 * @size - size
 */
int xcrypt_read(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size)
{
	mm_segment_t oldfs;
	int ret;

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	ret = vfs_read(file, data, size, &offset);

	set_fs(oldfs);
	return ret;
}  

/* file_write- wrapper method to write into a file
 */
int xcrypt_write(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size)
{
	mm_segment_t oldfs;
	int ret;

	oldfs = get_fs();
	set_fs(KERNEL_DS);

	ret = vfs_write(file, data, size, &offset);

	set_fs(oldfs);
	return ret;
}


/* file_open - wrapper method to open a file
 * @path: path of the file
 * @flags: open flags as per the open(2) second argument
 * @rights: mode for the new file if O_CREAT is set, else ignored
 * @fileptr: to store pointer to opened file
 */
int xcrypt_open(const char *path, int flags, int rights, struct file **fileptr)
{
	struct file *filp = NULL;
	mm_segment_t oldfs;
	printk("%s %d\n",__FUNCTION__,__LINE__);

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	filp = filp_open(path, flags, rights);
	set_fs(oldfs);
	if (IS_ERR(filp)) {
		*fileptr = NULL;
		return PTR_ERR(filp);
	}
	*fileptr = filp;
	printk("%s %d\n",__FUNCTION__,__LINE__);
	return 0;
}

/* file_close - wrapper method to close a file
 * @fileptr: address of pointer to file
 */
void xcrypt_close(struct file **fileptr)
{
	if(*fileptr != NULL) {
		filp_close(*fileptr, NULL);
	}
	*fileptr = NULL;
}

/* ecryptfs_hash_digest - helper function used by calculate_md5
 */
static int ecryptfs_hash_digest(struct crypto_shash *tfm,
		char *src, int len, char *dst)
{
	SHASH_DESC_ON_STACK(desc, tfm);
	int err;

	desc->tfm = tfm;
	desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;
	err = crypto_shash_digest(desc, src, len, dst);
	shash_desc_zero(desc);
	return err;
}

/* print_md5 - print md5 hash
 * @key_hash - takes key hash
 */
void print_md5(unsigned char *key_hash) 
{
	int i;
	for (i = 0; i < 16; i++) {
		printk("%02x", key_hash[i]);
	}
	printk(KERN_INFO "\n");
}

/* calculate_md5 - calculate md5 hash of a key
 * @dst - dst buffer to write to
 * @src - src buffer to read from
 * @len - len of src buffer
 */
int calculate_md5(char *dst, char *src, int len)
{
	struct crypto_shash *tfm = NULL;
	int rc = 0;

	if (!tfm) {
		tfm = crypto_alloc_shash("md5", 0, 0);
		if (IS_ERR(tfm)) {
			rc = PTR_ERR(tfm);
			printk(KERN_ERR "Error attempting to allocate crypto context; rc = [%d]\n",rc);
			goto out;
		}
	}
	rc = ecryptfs_hash_digest(tfm, src, len, dst);
	if (rc) {
		printk(KERN_ERR
				"%s: Error computing crypto hash; rc = [%d]\n",
				__func__, rc);
		goto out;
	}
out:
	//mutex_unlock(&crypt_stat->cs_hash_tfm_mutex);
	return rc;
}

/* get_user_key - get the key of the user from keys file
 * @uid - user id
 */
char *get_user_key(unsigned int uid)
{
	char uid_str[11], *src = NULL, *key_hash = NULL; 
	int i=0, ret1, count=0, found = 0;

	uid_str[10] = '\0';
	for(;i<10; i++) {
		uid_str[i] = '0';
	}
	i = 9;
	while(uid) {
		uid_str[i] = uid%10 + '0';
		uid/=10;
		i--;
	}
	key_hash = kmalloc(sizeof(char)*17, GFP_KERNEL);
	memset(key_hash, '\0', 17);

	i = users_keys_file->f_inode->i_size;
	src = kmalloc(sizeof(char)*11, GFP_KERNEL);
	while(i>0) {
		memset(src, '\0', 11);
		ret1 = xcrypt_read(users_keys_file, count*26, src, 10);
		if(strcmp(src, uid_str)==0) {
			ret1 = xcrypt_read(users_keys_file, count*26+10, key_hash, 16);
			found = 1;
			break;
		}
		i -= 26;
		count++;
	}
	kfree(src);
	if(!found)
		return NULL;
	return key_hash;
}

/* set_user_key - set the key of the user in keys file
 * @key - key string
 * @uid - user id
 */
int set_user_key(char *key, unsigned int uid)
{
	char uid_str[11], *src = NULL, *key_hash = NULL; 
	int i=0, ret1, found=0, count=0, write=0;
	uid_str[10] = '\0';
	for(;i<10; i++) {
		uid_str[i] = '0';
	}
	i = 9;
	while(uid) {
		uid_str[i] = uid%10 + '0';
		uid/=10;
		i--;	
	}
	key_hash = kmalloc(sizeof(char)*17, GFP_KERNEL);
	memset(key_hash, '\0', 17);
	calculate_md5(key_hash, key, strlen(key));

	printk("In set user key function: %s %s |%s|\n", key, uid_str, key_hash);
	print_md5(key_hash);
	i = users_keys_file->f_inode->i_size;	
	src = kmalloc(sizeof(char)*11, GFP_KERNEL);
	while(i>0) {
		memset(src, '\0', 11);
		ret1 = xcrypt_read(users_keys_file, count*26, src, 10);
		if(ret1 == 0) printk("Can't read in sey user key function\n");
		printk("Comparing these two |%s| |%s| |%d|\n",src,uid_str,ret1);
		if(strcmp(src, uid_str)==0) {
			write += xcrypt_write(users_keys_file, count*26+10, key_hash, 16);
			found = 1;
			break;
		}
		i -= 26;
		count++;
	}
	if(!found) {
		write += xcrypt_write(users_keys_file, count*26, uid_str, strlen(uid_str));
		write += xcrypt_write(users_keys_file, count*26+10, key_hash, 16);
	}
	kfree(src);
	kfree(key_hash);
	return write;	

}

/* swap_file_details - helper function for bubbleSort API
 * @a,b - pointers of list nodes to swap the data
 * returns void
 *  */
void swap_file_details(struct file_details *a, struct file_details *b)
{
	struct timespec temp = a->file_time;
	struct dentry *tdentry = a->file_dentry;
	
	a->file_time = b->file_time;
	b->file_time = temp;

	a->file_dentry = b->file_dentry;
	b->file_dentry = tdentry;
}

/* bubbleSort - API for bubble sorting a linked list (below API taken as it is from geeks for geeks)
 * @start - pointer to the head of the list
 * returns void (just swap the pointers) 
 *  */
void bubbleSort(struct file_details *start)
{
	int swapped = 1;
	struct file_details *ptr1;
	struct file_details *lptr = NULL;

	/* checking for empty list */
	if (start == NULL)
		return;

	do {
		swapped = 0;
		ptr1 = start;

		while (ptr1->next != lptr)
		{
			if(timespec_compare(&(ptr1->file_time), &(ptr1->next->file_time)) > 0)
			{ 
				swap_file_details(ptr1, ptr1->next);
				swapped = 1;
			}
			ptr1 = ptr1->next;
		}
		lptr = ptr1;
	} while (swapped);
}

/* push - push node to the head of linked list
 * @head_ref - double pointer to list head
 * @file_time, file_dentry - data to add to node
 */
void push(struct file_details **head_ref, struct timespec file_time, struct dentry *file_dentry)
{
    /* 1. allocate node */
    struct file_details *new_node = (struct file_details *) kmalloc(sizeof(struct file_details), GFP_KERNEL);
  
    /* 2. put in the data  */
    new_node->file_time = file_time;
    new_node->file_dentry = file_dentry;
    /* 3. Make next of new node as head */
    new_node->next = (*head_ref);
  
    /* 4. move the head to point to the new node */
    (*head_ref)    = new_node;
}

/* filldir_one - callback to iterate dir. fills dentry in linked list
 */
int filldir_one(struct dir_context *ctx, const char *name, int len,
			loff_t pos, u64 ino, unsigned int d_type)
{
	struct getdents_callback_ *buf =
		container_of(ctx, struct getdents_callback_, ctx);
	int result = 0;
	char *buff = NULL, *file_orig_path = NULL;
	struct dentry *err_dentry = NULL, *trashbin_dentry = NULL, *trashbin_lower_dentry = NULL;
	struct path lower_path;
	struct file_details **file_details_list = buf->file_details_list;
	buf->sequence++;
	if(len<=NAME_MAX)
	{
		memcpy(buf->name, name, len);
		buf->name[len] = '\0';
		printk("Name of the file - |%s|\n",buf->name);
		if(strcmp(buf->name, ".") == 0 || strcmp(buf->name, "..") == 0) goto out;
		trashbin_dentry = dget(buf->trashbin_dentry);
		sgfs_get_lower_path(trashbin_dentry, &lower_path);
		buff = (char *) kmalloc(4096, GFP_KERNEL); 
		memset(buff, '\0', PATH_MAX);
	
		trashbin_lower_dentry = dget(lower_path.dentry);
		file_orig_path = dentry_path_raw(trashbin_lower_dentry, buff, 4096); 
		printk("Background cleaning------ %s -------\n",file_orig_path);
		err_dentry =  lookup_one_len(buf->name, trashbin_lower_dentry, strlen(buf->name));
		if(IS_ERR(err_dentry)) {
			printk("In kernel thread cleaning: issue with dentry lookup\n");
		}
		if(err_dentry && err_dentry->d_inode != NULL) {
                        printk("File times : %lld.%.9ld \n", (long long)err_dentry->d_inode->i_mtime.tv_sec, err_dentry->d_inode->i_mtime.tv_nsec);
                        push(file_details_list, err_dentry->d_inode->i_mtime, err_dentry);
			(*(buf->list_len))++;
                }
		buf->found = 1;
		result = -1;
		
	}
	dput(trashbin_dentry);
	dput(trashbin_lower_dentry);
	if(buff)
		kfree(buff);
	out:
	return 0;
}

/* consumer_callback - callback function for consumer thread
 */
int consumer_callback(void *data)
{
	struct work *curr = NULL;
	int err = 0;
	while(1) { 
		printk("I am a consumer thread and am going to sleep now\n");
		wait_event_interruptible(consumer_queue, consumer_thread_count > 0);
		if(kthread_should_stop()) {
			printk("Consumer thread stopping\n");
			break;
		}

		printk("I got woken up and I am a consumer thread\n");
		msleep(CONSSLEEP);
		mutex_lock(&wqmutex);
		curr = remove();
		list_asyncqueue();
		if(!curr) {
			mutex_unlock(&wqmutex);
			continue;
		}
		printk("I am going to do the job now\n");
		consumer_thread_count--;
		if(consumer_thread_count == MAX_LIST-1) {
			printk(KERN_INFO "Consumer: Waking up producer\n");
			wake_up_interruptible(&producer_queue);
		}
		mutex_unlock(&wqmutex);
		err = process(curr->job);
		/* add the entry to a proc filesystem */ 
		dput(curr->job->dentry);
		kfree(curr->job);
		kfree(curr);

		if(producer_thread_count == 1) {
			producer_thread_count--;
			mutex_unlock(&prmutex);
		}

	}
	return err;
}

/* callback - callback funtion for background cleaning thread
 */ 
int callback(void *data)
{
	
	struct sgfs_sb_info *sb_info = (struct sgfs_sb_info *) data;
	struct path lower_path;
	struct dentry *sgfs_root_, *sgfs_root;
	char name_[NAME_MAX+1];
	char *name = (char *) &name_;
	const struct cred *cred;
	struct file *file;
	struct file_details *file_details_list = NULL, *ptr;
	int list_len = 0;
	struct getdents_callback_ buffer = {
		.ctx.actor = filldir_one,
	};
	int TRASHBIN_CLEAN_NO = 10;
	int err = 0, file_err, ret1;
	struct dentry *file_dentry;
	struct dentry *lower_dir_dentry;
	struct file *tmfptr = NULL;
	char tmstring[11];
	while(1) { 
		printk("Background cleaning thread running periodically %d msecs\n", BACKSLEEP);
		if(kthread_should_stop()) {
			break;
		}
		msleep(BACKSLEEP);
		
		/* Get the kernel queue size 
		 **/
		file_err = xcrypt_open("/proc/trashbin-max", O_RDONLY, 0, &tmfptr);
		if(file_err < 0) {
			printk(KERN_ERR "Can't open trashbin max proc entry. Default trashbin max size is 10\n");
		}
		else {
			memset(tmstring, '\0', 11);
			ret1 = xcrypt_read(tmfptr, 0, tmstring, 11);
			if(ret1 == 0) {
				ret1 = xcrypt_read(tmfptr, 0, tmstring, 11);
			}
			tmstring[ret1-1] = '\0';
			if(strlen(tmstring) == 0) TRASHBIN_CLEAN_NO = 10;
			else TRASHBIN_CLEAN_NO = string_to_int(tmstring);
			printk(KERN_INFO "Trashbin max size from proc entry is |%s| %d\n",tmstring, TRASHBIN_CLEAN_NO);
			xcrypt_close(&tmfptr);
		}

		
		memset(name_, '\0', NAME_MAX+1);
		name = (char *) &name_;
		sgfs_root_ = sb_info->sg_dentry;
		sgfs_get_lower_path(sgfs_root_, &lower_path);
		sgfs_root = lower_path.dentry;
		cred = current_cred();
		file = dentry_open(&lower_path, O_RDONLY, cred);
		file_details_list = NULL;
		list_len = 0;
		buffer.name = name;
		buffer.trashbin_dentry = sgfs_root_;
		buffer.file_details_list = &file_details_list;
		buffer.list_len = &list_len;
		buffer.sequence = 0;
		err = iterate_dir(file, &buffer.ctx);
		ptr = file_details_list;
		printk("Length of list is: %d\n",list_len);
		while(ptr) {
			printk("File times 1.: %lld.%.9ld \n", (long long)ptr->file_time.tv_sec, ptr->file_time.tv_nsec);
			ptr = ptr->next;
		}
		ptr = file_details_list;
		bubbleSort(ptr);
		while(ptr && (list_len > TRASHBIN_CLEAN_NO)) {
			printk("Deleting this file 2.: %lld.%.9ld \n", (long long)ptr->file_time.tv_sec, ptr->file_time.tv_nsec);
			list_len--;
			file_details_list = ptr->next;
			file_dentry = ptr->file_dentry;
			dget(file_dentry);		

			lower_dir_dentry = lock_parent(file_dentry);
			err = vfs_unlink(d_inode(sgfs_root), file_dentry, NULL);
			printk("Remove error code is %d\n",err);
			unlock_dir(lower_dir_dentry);
			dput(file_dentry);
			kfree(ptr);
			ptr = file_details_list;

                }
		ptr = file_details_list;
		while(ptr) {
                        printk("File times 2.: %lld.%.9ld \n", (long long)ptr->file_time.tv_sec, ptr->file_time.tv_nsec);
                        ptr = ptr->next;
                }
		
		fput(file);
		sgfs_put_lower_path(sgfs_root_, &lower_path);
	}
	return err;
}


#endif  /* not _UTIL_H_ */

