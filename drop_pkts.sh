#!/usr/bin/env bash

iptables -A OUTPUT -m statistic --mode random --probability 0.15 -j DROP
iptables -A INPUT -m statistic --mode random --probability 0.15 -j DROP
iptables -L