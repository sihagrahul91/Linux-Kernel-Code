#ifndef _FILEOP_H_
#define _FILEOP_H_

extern int xcrypt_read(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size);
extern int xcrypt_write(struct file *file, unsigned long long offset, unsigned char *data, unsigned int size);
extern int xcrypt_open(const char *path, int flags, int rights, struct file **fileptr);
extern void xcrypt_close(struct file **fileptr);
extern int calculate_md5(char *dst, char *src, int len);
extern void print_md5(unsigned char *key_hash);
extern int set_user_key(char *key, unsigned int uid);
char *get_user_key(unsigned int uid);
extern int remove_filename(char *filename, unsigned int uid );
#endif  /* not _QUEUE_H_ */
