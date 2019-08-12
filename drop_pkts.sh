#!/usr/bin/env bash

iptables -A OUTPUT -m statistic --mode random -p tcp --match multiport --dports 32876,33038 --probability 0.13 -j DROP
iptables -A INPUT -m statistic --mode random -p tcp --match multiport --dports 32876,33038 --probability 0.13 -j DROP
#iptables -A OUTPUT -m statistic --mode random --probability 0.13 -j DROP
#iptables -A INPUT -m statistic --mode random --probability 0.13 -j DROP
iptables -L