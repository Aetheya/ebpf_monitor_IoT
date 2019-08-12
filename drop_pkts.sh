#!/usr/bin/env bash

iptables -A OUTPUT -m statistic --mode random --match multiport --dports 80,443,8888 --probability 0.13 -j DROP
iptables -A INPUT -m statistic --mode random --match multiport --dports 80,443,8888 --probability 0.13 -j DROP
#iptables -A OUTPUT -m statistic --mode random --probability 0.13 -j DROP
#iptables -A INPUT -m statistic --mode random --probability 0.13 -j DROP
iptables -L