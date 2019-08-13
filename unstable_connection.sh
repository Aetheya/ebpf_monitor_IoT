#!/usr/bin/env bash
bash drop_pkts.sh;
sleep 30
bash reset_iptables.sh;
sleep 30
bash drop_pkts.sh;
sleep 30
bash reset_iptables.sh;