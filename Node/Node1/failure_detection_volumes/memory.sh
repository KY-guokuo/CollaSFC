#!/bin/bash
for i in `seq 88`
do
stress --vm ${i} --vm-bytes 640M  --vm-keep -t 30
sleep 30
done
