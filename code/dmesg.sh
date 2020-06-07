a=0
while [ "$a" -lt 1000000 ]    # this is loop1
do
   dmesg -c
   a=`expr $a + 1`
   echo "####################################"
done

