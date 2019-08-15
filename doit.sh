#!/bin/bash
array=( 490000000 522000000 554000000 578000000 634000000 658000000 )
for i in "${array[@]}"
do
	echo "TUNNIG to $i"
    dvbtune -f $i -qam 64 -m -gi 4 -cr 2_3 -tm 8&
    ./dvbepg_json -n >$i.json
    killall dvbtune
done
for i in "${array[@]}"
do
	echo "TESTING to $i"
    cat $i.json |jq . >/dev/null
    if [ $? -ne 0 ]; then
        echo "$i.json FAILED"
    fi
done
