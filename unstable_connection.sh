#!/usr/bin/env bash
date
bash get_request.sh;
sleep 3
bash get_request.sh;
sleep 3
bash get_request.sh;
sleep 4
bash get_request.sh;

date
bash drop_pkts.sh;
bash get_request.sh;
sleep 3
bash get_request.sh;
sleep 3
bash get_request.sh;
sleep 4
bash get_request.sh;

date
bash reset_iptables.sh;
bash get_request.sh;
sleep 3
bash get_request.sh;
sleep 3
bash get_request.sh;
sleep 4
bash get_request.sh;