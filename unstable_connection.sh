#!/usr/bin/env bash
bash drop_pkts.sh;
sleep 50
bash reset_iptables.sh;
sleep 50
bash drop_pkts.sh;
sleep 50
bash reset_iptables.sh;