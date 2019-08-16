#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi
systemctl stop epgeer
apt install dvbtune
make
cp dvbepg_json /usr/local/bin/dvbepg_json
cp epgeer.sh /usr/local/bin/epgeer.sh
rm -fr /var/www/epg
cp epgeer.service /etc/systemd/system/epgeer.service
systemctl daemon-reload 
systemctl start epgeer.service 


