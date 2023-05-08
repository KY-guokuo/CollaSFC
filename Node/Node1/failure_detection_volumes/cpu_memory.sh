#!/bin/bash
for i in `seq 33 -2 28`
do
m=`expr $i - 14`
j=`expr ${m} \* 2 + 12`
stress -c ${i} -m 1 --vm-bytes  ${j}G  --vm-keep -t 120
done
