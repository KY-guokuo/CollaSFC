#!/bin/bash
stress_pid=`ps -ef | grep stress | grep -v grep | awk '{print $2}'`
for i in $stress_pid
do 
	kill -9 $i
done

