obj-m += jobscompleted.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: xd

xd:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
