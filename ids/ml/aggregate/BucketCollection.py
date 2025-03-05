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

import json
import pickle
import numpy
from collections import defaultdict

# define here to allow pickling, default function for default dictionaries
def zero_val():
    return 0


# Class to store counts of differnt types of packets over a specific time period
class Bucket():
    # methods for manipulating the stats of a single period
    def __init__(self):
        self.total = 0

        # define counts that count the number of packets of certain type
        # fields corr to boolean fields in db
        self.pktCounts = {
            'has_ip'   : 0,
            'has_tcp'  : 0,
            'has_udp'  : 0,
            'has_icmp' : 0,
            'has_arp'  : 0,
            'has_ether': 0,
        }

        # define fields we want to count the number of instances of each category
        # correspond to categorical fields in db
        self.categoryCounts = {
            'ip_src' : defaultdict(zero_val),
            'ip_dst' : defaultdict(zero_val),
            'udp_src_port' : defaultdict(zero_val),
            'udp_dst_port' : defaultdict(zero_val),
            'udp_len' : defaultdict(zero_val),
            'mac_src' : defaultdict(zero_val),
            'mac_dst' : defaultdict(zero_val),
        }

        self.flows = {
            ('ip_src', 'ip_dst') : defaultdict(zero_val),
            ('mac_src', 'mac_dst') : defaultdict(zero_val),
        }

    def is_zero(self):
        return self.total == 0

    # Add one packet to stats
    def insert_packet(self, packet):
        self.total += 1
        
        for field in self.pktCounts:
            if (field in packet) and packet[field]:
                self.pktCounts[field] += 1 

        for field, d in self.categoryCounts.items():
            if (field not in packet):
                d[None] += 1
            else:
                label = packet[field]
                d[label] += 1

        for (f1, f2), d in self.flows.items():
            if (f1 not in packet or f2 not in packet): continue
            d[(packet[f1], packet[f2])] += 1

    def __repr__(self):
        return self.__str__()

    def __str__(self):
        ret = "Total packets: %d" % self.total + "\n"
        ret += "ip_src: " +  json.dumps(self.categoryCounts['ip_src'], indent = 4) + "\n"
        ret += "ip_dst: " + json.dumps(self.categoryCounts['ip_dst'], indent = 4) + "\n"
        ret += json.dumps(self.pktCounts, indent = 4) + "\n"
        ret += str(self.flows) + "\n";
        return ret

# Essentially an array of buckets, where each bucket covers `interval` (time in seconds)
class BucketCollection():
    def __init__(self, interval, n):
        self.buckets = [Bucket() for i in range(n)]
        self.interval = interval

    def insert_packet(self, packet, index):
        self.buckets[index].insert_packet(packet)

    def print(self):
        for (i, b) in enumerate(self.buckets): 
            print("------ Bucket {} ------".format(i))
            print(b)

    def save(self, filename):
        with open(filename, 'wb') as f:
            pickle.dump(self, f)
