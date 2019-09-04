#!/bin/bash
mkdir -p  /var/www/epg
cd /var/www/epg
while [ 1 ]
do  
# get frequencies avoid dups.
    ES=$(cat /var/www/html/es.json |jq ".channels[].frequency")
    EN=$(cat /var/www/html/en.json |jq ".channels[].frequency")
    FR=$(cat /var/www/html/fr.json |jq ".channels[].frequency")
    A=$(echo $ES $FR $EN)
    array=$(echo "${A[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')
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
