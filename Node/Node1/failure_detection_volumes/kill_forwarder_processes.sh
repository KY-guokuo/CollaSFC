#! /bin/bash
ps -ef | grep vnf | awk '{print $2}' | xargs kill -9
