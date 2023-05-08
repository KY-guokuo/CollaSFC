#!/bin/bash
for i in `seq 35 -1  28`
do
stress -c ${i} -t 60
done
