#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/slab.h>

#define PROCFS_MAX_SIZE		1024*4
#define PROCFS_NAME 		"jobs-completed"

int len, temp;
char *msg;
struct proc_dir_entry *proc_file_entry;
static ssize_t read_proc(struct file *filp, char __user *buf, size_t count, loff_t *offp ) 
{
	unsigned long ret;
	if(count > temp)
	{
		count = temp;
	}
	temp = temp - count;
	ret = copy_to_user(buf, msg, count);
	if(count == 0)
		temp = len;
	return count;
}

static ssize_t write_proc(struct file *filp, const char __user *buf, size_t count, loff_t *offp)
{
	unsigned long ret;
	ret = copy_from_user(msg, buf, count);
	len = count;
	temp = len;
	return count;
}

static const struct file_operations proc_fops = {
	.owner		= THIS_MODULE,
	.read		= read_proc,
	.write		= write_proc,
};

static int __init proc_init(void) {
	proc_file_entry = proc_create(PROCFS_NAME, 0, NULL, &proc_fops);
        if(proc_file_entry == NULL) {
                return -ENOMEM;
        }
        msg = kmalloc(PROCFS_MAX_SIZE * sizeof(char), GFP_KERNEL);
	return 0;
}

static void __exit proc_cleanup(void) {
	remove_proc_entry(PROCFS_NAME, NULL);
	kfree(msg);
}

MODULE_LICENSE("GPL"); 
module_init(proc_init);
module_exit(proc_cleanup);
