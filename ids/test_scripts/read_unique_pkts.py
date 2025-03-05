'''
Spire.

The contents of this file are subject to the Spire Open-Source
License, Version 1.0 (the ``License''); you may not use
this file except in compliance with the License.  You may obtain a
copy of the License at:

http://www.dsn.jhu.edu/spire/LICENSE.txt 

or in the file ``LICENSE.txt'' found in this distribution.

Software distributed under the License is distributed on an AS IS basis, 
WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
for the specific language governing rights and limitations under the 
License.

Spire is developed at the Distributed Systems and Networks Lab,
Johns Hopkins University.

Creators:
  Yair Amir             yairamir@cs.jhu.edu
  Trevor Aron           taron1@cs.jhu.edu
  Amy Babay             babay@pitt.edu
  Thomas Tantillo       tantillo@cs.jhu.edu 
  Sahiti Bommareddy     sahiti@cs.jhu.edu

Major Contributors:
  Marco Platania        Contributions to architecture design 
  Daniel Qian           Contributions to Trip Master and IDS 
 

Contributors:

  Samuel Beckley        Contributions to HMIs

Copyright (c) 2017-2025 Johns Hopkins University.
All rights reserved.

Partial funding for Spire research was provided by the Defense Advanced 
Research Projects Agency (DARPA) and the Department of Defense (DoD).
Spire is not necessarily endorsed by DARPA, the DoD or the DoE. 
'''

from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP, icmptypes
from scapy.data import ETHER_TYPES
import sys
sys.path.append('./../db_scripts/')
sys.path.append('./../capture_scripts/')

from dbDaemon import dbDriver

import argparse
import os

from analyzer import PacketAnalyzer, parse_packet

def write(pkt):
    wrpcap('length_pkt.pcap', iter(pkt), append=True)  #appends packet to output file   


db = dbDriver("scada")
# pkt_analyzer = PacketAnalyzer(False)

print("Daemon created\n")
# pkt_raw_list = db.read_all_pkt_raw()
# pkt_features_list =  db.read_all_pkt_features()

id_list = [2]
pkt_raw_list = []
# fp = fopen('length_pkt.pcap')

for id in id_list:
    pkt_raw = db.read_raw_by_id(id)
    print (parse_packet(Ether(pkt_raw[2])))
    pkt_raw_list.append(pkt_raw[2])
    eth_pkt = Ether(pkt_raw[2])
    eth_pkt.show()
    print("IP chk", eth_pkt[IP].chksum)
    print(eth_pkt[UDP].chksum)
    
    #CHange IP
    eth_pkt[IP].dst = "192.168.101.106"
    # Recompute chksum
    del eth_pkt[IP].chksum
    del eth_pkt[UDP].chksum
    eth_pkt.show2(dump=False)
    
    sendp(eth_pkt, iface='eth2', count = 10000, inter=0.001)#, return_packets = True)

# Write the list to pcap
# write(pkt_raw_list)


# def write(pkt):
#     wrpcap('length_pkt.pcap', pkt, append=True)  #appends packet to output file   
"""
for pkt_raw in pkt_raw_list:
    print("Reading one dump\n")
    print(pkt_raw)
    print(Ether(pkt_raw[2]).summary())
    pkt_analyzer = PacketAnalyzer(False)
    print(pkt_analyzer.parse_packet(Ether(pkt_raw[2]), False))

for pkt_raw in pkt_features_list:
    print("Reading one dump\n")
    print(pkt_raw)
    
    #print(Ether(pkt_raw[2]).summary())
    #pkt_analyzer = PacketAnalyzer(False)
    #print(pkt_analyzer.parse_packet(Ether(pkt_raw[2]), False))
"""
# db.close()

