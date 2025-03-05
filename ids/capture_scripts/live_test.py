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

import sys
sys.path.append('./../db_scripts/')
sys.path.append('./../anomaly_scripts/')
sys.path.append('./../')
sys.path.append('./')

import argparse
import subprocess
import shlex
from scapy.all import *
from analyzer import PacketAnalyzer
import pickle

parser = argparse.ArgumentParser(description='Script to capture traffic and insert into database for training')
parser.add_argument('interface', help='Network interface to monitor')
parser.add_argument('--timeout', default=0, type=int, help='time in seconds to capture packets, default 0 for no timeout')

args = parser.parse_args()

pkt_analyzer = PacketAnalyzer(is_training_mode = False)                           
pkt_filter = ""

# Below is an example of a possible packet filter, that removes traffic for ssh (port 22) 
# and from the monitoring machine (192.168.101.109) itself
# pkt_filter = "src port not 22"
# pkt_filter += " and dst port not 22"
# pkt_filter += " and ip host not 192.168.101.109"

if (args.timeout == 0): 
    sniff(iface=args.interface, store=0, prn=pkt_analyzer.process_packet, filter=pkt_filter)
else:
    sniff(iface=args.interface, store=0, prn=pkt_analyzer.process_packet, timeout = args.timeout, filter=pkt_filter)

print("Exiting\n")
