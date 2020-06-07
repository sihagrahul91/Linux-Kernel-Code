a=0
while [ "$a" -lt 1 ]    # this is loop1
do
   make clean
   make
   umount /mnt/sgfs/
   rmmod /usr/src/hw3-rsihag/fs/sgfs/sgfs.ko
   insmod /usr/src/hw3-rsihag/fs/sgfs/sgfs.ko
   mount -t sgfs -o key=RAHULSIHAG4321 /usr/src/alok /mnt/sgfs
   #mount -t sgfs /usr/src/lower/ /mnt/sgfs
   a=`expr $a + 1`
done

