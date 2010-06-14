#!/bin/bash
netcat 192.168.41.113 2000 < ~/core* &
sudo ./impd4e -r 80 -t l p-I 2 -i eth0 -f "tcp src port 2000"

