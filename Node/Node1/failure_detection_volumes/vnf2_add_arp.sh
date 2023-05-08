#!/bin/bash
cat info.txt | sed -e '/\bvnf2\b/d' | awk '{print $8,$7}'| while read line
do 
  arp -s $line
done
