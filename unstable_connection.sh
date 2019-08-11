#!/usr/bin/env bash
date

#for i in `seq 10`; do curl --location --request GET "https://postman-echo.com/get?foo1=bar1&foo2=bar2"; done
#sleep 3
#date
#bash drop_pkts.sh;
#for i in `seq 10`; do curl --location --request GET "https://postman-echo.com/get?foo1=bar1&foo2=bar2"; done
#date
#bash reset_iptables.sh;
#for i in `seq 10`; do curl --location --request GET "https://postman-echo.com/get?foo1=bar1&foo2=bar2"; done

bash drop_pkts.sh;
sudo tcpdump;