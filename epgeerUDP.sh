#!/bin/bash
mkdir -p  /var/www/epg
cd /var/www/epg
#while [ 1 ]
#do  
# get frequencies avoid dups.
#    array=( $(cat /var/www/html/es.json |grep "frequency" |sed 's/.*: //'|sed 's/,//'| sort -u|tr '\n' ' ') )
    arrayIP=($(jq -r '.channels[].ip' /var/www/html/es.json))
    arrayPORT=($(jq -r '.channels[].port' /var/www/html/es.json))
    arraySID=($(jq -r '.channels[].sid' /var/www/html/es.json))
    arrayFREQ=($(jq -r '.channels[].frequency' /var/www/html/es.json))
    for freq in "${arrayFREQ[@]}"
    do
      rm -f $freq.json
    done

    i=0
    for sid in "${arraySID[@]}"
    do
        ip=${arrayIP[$i]}
        let port=${arrayPORT[$i]}
        let freq=${arrayFREQ[$i]}
        touch F$freq.json
        if [ $port -ne 0 ]; then
            echo "UDP RX  from to $ip:$port"
            dvbepg_json -i - -n -s -u $ip:$port -t 5  >$sid.json
            echo "TESTING to $sid"
            jq -n '{ programs: [ inputs.programs ] | add }'  $sid.json F$freq.json | sponge F$freq.json

        else
            echo "TUNNING to $freq"
#            dvbtune -c 1 -f $freq -qam 64 -m -gi 4 -cr 2_3 -tm 8&
#            dvbepg_json -n >$freq.json
#            killall dvbtune
#            echo "TESTING to $i"
#            cat $i.json |jq . >/dev/null
#            if [ $? -eq 0 ]; then
#                mongoimport --db epg --collection F$freq --file $freq.json --type json --batchSize 1 --drop --upsert
#            else
#                echo "$freq.json FAILED"
#            fi
        fi
        let i=i+1;
    done
    for freq in "${arrayFREQ[@]}"
    do
        cat $freq.json |jq . >/dev/null
        if [ $? -eq 0 ]; then
            mongoimport --db epg --collection F$freq --file F$freq.json --type json --batchSize 1 --drop --upsert
        else
            echo "$freq.json FAILED"
        fi
    done

#done
