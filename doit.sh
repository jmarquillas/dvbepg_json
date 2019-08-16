#!/bin/bash
#mongoexport -d epg -c F65800000
#mongoexport --db epg --collection F658000000  | sed '/"_id":/s/"_id":[^,]*,//'

array=( 490000000 522000000 554000000 578000000 634000000 658000000 )
for i in "${array[@]}"
do
	echo "TUNNIG to $i"
    ./dvbtune -f $i -qam 64 -m -gi 4 -cr 2_3 -tm 8&
    ./dvbepg_json -n >$i.json
    killall dvbtune
	echo "TESTING to $i"
    cat $i.json |jq . >/dev/null
    if [ $? -eq 0 ]; then
        mongoimport --db epg --collection F$i --file $i.json --type json --batchSize 1 --drop --upsert
    else
        echo "$i.json FAILED"
    fi
done
