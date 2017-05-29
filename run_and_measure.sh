#!/bin/bash
./natpmp_daemon.py -file > ./performance_output/daemon_output.txt 2>&1 &

genpid=$!
outfile=./performance_output/performance_data.txt

echo $(date "+%F %H:%M:%S") > $outfile

while [ 1 ]
do
ps --no-headers -p $genpid -o %cpu,%mem,cputime,etimes >> $outfile
sleep 1
done
