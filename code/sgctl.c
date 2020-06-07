#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdbool.h>
#include <malloc.h>
#include <string.h>

#define IORESTORE _IOW('r', 4, char*)
#define ENCRYPTIONKEY _IOW('r', 1, char*)
#define PURGETRASHBIN _IOW('r', 3, char*)
#define DELETE _IOW('r',2, char*)
#define DELETEFROMQUEUE _IOW('r', 5, char*)

#define PATH_MAX 4096
int main(int argc, char * const argv[])
{
	int rc = 0;
	int c, fd, flag;
	char filename[PATH_MAX];
	char filename_[PATH_MAX];
	memset(filename,'\0',PATH_MAX);
	memset(filename_,'\0',PATH_MAX);

	while ((c = getopt (argc, argv, "t:u:e:d:p:q:")) != -1) {
		switch (c) {
			case 't':	/* set trashbin path */
				strncpy(filename_, optarg, PATH_MAX);
				break;
			case 'u':	/* restore */
				strncpy(filename, optarg, PATH_MAX);
				flag = 0;
				break;
			case 'e':	/* set encryption key */
				strncpy(filename, optarg, PATH_MAX);
				flag = 1;
				break;
			case 'd':	/* delete file */
				strncpy(filename, optarg, PATH_MAX);
				flag = 2;
				break;
			case 'p':	/* purge trashbin */
				strncpy(filename, "purge", PATH_MAX);
				flag = 3;
				break;
			case 'q':	/* delete job from queue */
				strncpy(filename, optarg, PATH_MAX);
				flag = 4;
				break;
			case '?':
				fprintf (stderr,"Unknown option character `\\x%x'.\n",optopt);
				return -1;
		}
	}
	if(flag == 0 && filename[0] == '\0') {
		printf("Please provide filename to restore\n");
		goto exit;
	}

	if(flag == 0) {
		strncpy(filename_ + strlen(filename_), filename, strlen(filename));	
		printf("Path of the file to restore: %s\n", filename_);
		fd = open(filename_, O_RDONLY);
		if(fd < 0) {
			printf("Can't open the mount point\n");
			rc = fd;
			goto exit;
		}
		rc = ioctl(fd, IORESTORE, filename);
		if(rc < 0) {
			perror("IOCTL error occured\n");
		}
		else {
			printf("File restored succesfully\n");
		}

	}
	else if(flag == 1) {
		fd = open(filename_, O_RDONLY);
		if(fd < 0) {
			printf("Can't open the mount point\n");
			rc = fd;
			goto exit;
		}
		printf("Encryption key: %s\n", filename);
		rc = ioctl(fd, ENCRYPTIONKEY, filename);
		if(rc < 0) {
			perror("IOCTL error occured\n");
		}
		else {
			printf("Encryption key set successfully\n");
		}

	}
	else if(flag == 2) {
		fd = open(filename, O_RDONLY);
		printf("Path of the file to delete: [%s]\n", filename);
		if(fd < 0) {
			printf("Can't open the mount point\n");
			rc = fd;
			goto exit;
		}
		rc = ioctl(fd, DELETE, filename);
		if(rc < 0) {
			perror("IOCTL error occured\n");
		}
		if(rc == 0) {
			printf("Deleted file successfully!\n");
		}

	}
	else if(flag == 3) {
		fd = open(filename_, O_RDONLY);
		if(fd < 0) {
			printf("Can't open the mount point\n");
			rc = fd;
			goto exit;
		}
		rc = ioctl(fd, PURGETRASHBIN, filename);
		if(rc < 0) {
			perror("IOCTL error occured\n");
		}
		if(rc == 0) {
			printf("Purged trashbin completely!\n");
		}
	}
	else if(flag == 4) {
		fd = open(filename_, O_RDONLY);
		if(fd < 0) {
			printf("Can't open the mount point\n");
			rc = fd;
			goto exit;
		}
		rc = ioctl(fd, DELETEFROMQUEUE, filename);
		if(rc < 0) {
			perror("IOCTL error occured\n");
		}
		if(rc == 0) {
			printf("Job deleted from Queue!\n");
		}
		else {
			printf("Job to be deleted is not present in work queue\n");
		}
	}

exit:
	if(fd)
		close(fd);
	exit(rc);


}
