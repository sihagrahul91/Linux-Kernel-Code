SGFS_VERSION="0.1"

EXTRA_CFLAGS += -DSGFS_VERSION=\"$(SGFS_VERSION)\"

obj-$(CONFIG_WRAP_FS) += sgfs.o

sgfs-y := dentry.o file.o inode.o main.o super.o lookup.o mmap.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

