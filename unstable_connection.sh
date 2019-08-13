#!/usr/bin/env bash
date
bash drop_pkts.sh;
sleep 50
date
bash reset_iptables.sh;
sleep 50
date
bash drop_pkts.sh;
sleep 50
date
bash reset_iptables.sh;