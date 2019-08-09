#!/usr/bin/env bash

python START 192.168.1.49 10000;
sleep 15
python GET 192.168.1.49 10000;
sleep 15
python STOP 192.168.1.49 10000;