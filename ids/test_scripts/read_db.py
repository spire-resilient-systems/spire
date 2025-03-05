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

from dbDaemon import dbDriver

import argparse
import os
import sys

from analyzer import PacketAnalyzer

db = dbDriver("scada")
print("Daemon created\n")
pkt_raw_list = db.read_all_pkt_raw()
pkt_features_list =  db.read_all_pkt_features()

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

