#!/usr/bin/env bash

date
python administrator.py START 192.168.1.49 10000;
sleep 15
date
python administrator.py GET 192.168.1.49 10000;
sleep 11
date
python administrator.py STOP 192.168.1.49 10000;