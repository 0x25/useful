#!/bin/bash
# chmod +x

if [ $# -eq 0 ]
  then
    echo "./findRpi.sh <subnet/cidr>"
    exit 1
fi

arp-scan $1 | grep b8:27:eb
