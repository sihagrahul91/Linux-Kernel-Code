cd kernel-queue
make clean
make
lsmod
rmmod kernel_queue
insmod kernel_queue.ko
lsmod
cd ..
cd jobs-list
make clean
make
lsmod
rmmod jobslist
insmod jobslist.ko
lsmod
cd ..
cd trashbin-max
make clean
make
lsmod
rmmod trashbin_max
insmod trashbin_max.ko
lsmod
cd ..
cd jobs-completed
make clean
make
lsmod
rmmod jobscompleted
insmod jobscompleted.ko
lsmod
cd ..
