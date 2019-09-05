#!/bin/bash
mkdir -p  /var/www/epg
cd /var/www/epg
while [ 1 ]
do  
# get frequencies avoid dups.
    ES=$(mongo --quiet --eval "db.getSiblingDB('rooms')."es".find({},{_id:0}).forEach(printjson)" | jq ".channels[].frequency")
    EN=$(mongo --quiet --eval "db.getSiblingDB('rooms')."en".find({},{_id:0}).forEach(printjson)" | jq ".channels[].frequency")
    FR=$(mongo --quiet --eval "db.getSiblingDB('rooms')."fr".find({},{_id:0}).forEach(printjson)" | jq ".channels[].frequency")
    A=$(echo $ES $FR $EN)
    array=($(echo "${A[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
    logger -t EPGEER $array
    for i in "${array[@]}"
    do
        echo "TUNNING to $i"
        dvbtune -c 0 -f $i -qam 64 -m -gi 4 -cr 2_3 -tm 8&
        dvbepg_json -n >$i.json
        killall dvbtune
        echo "TESTING to $i"
        cat $i.json |jq . >/dev/null
        if [ $? -eq 0 ]; then
            mongoimport --db epg --collection F$i --file $i.json --type json --batchSize 1 --drop --upsert
        else
            echo "$i.json FAILED"
        fi
    done
done
