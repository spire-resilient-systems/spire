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
sys.path.append('./../ml/packet')
sys.path.append('./../ml/aggregate/')

from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP, icmptypes
from scapy.data import ETHER_TYPES

from dbDaemon import db_insertion_daemon
from PerPktDaemon import per_pkt_daemon
from AggregateDaemon import aggregate_daemon
from config import config

from multiprocessing import Process, Queue
import argparse
import pickle
import os



def expand(x):
    yield x.name
    while x.payload:
        x = x.payload
        yield x.name

def extract_ip(parsed_dict, ip_pkt):
    parsed_dict['ip_src'] = ip_pkt.src
    parsed_dict['ip_dst'] = ip_pkt.dst
    parsed_dict['ip_ttl'] = ip_pkt.ttl
    parsed_dict['ip_len'] = ip_pkt.len
    parsed_dict['ip_ver'] = ip_pkt.version
    # TODO: prototype number to name translation
    parsed_dict['proto'] = ip_pkt.proto
    parsed_dict['has_ip'] = True

def extract_ether(parsed_dict, ether_pkt):
    parsed_dict['mac_src'] = ether_pkt.src
    parsed_dict['mac_dst'] = ether_pkt.dst
    parsed_dict['ether_type'] = ether_pkt.type
    parsed_dict['has_ether'] = True
    # https://github.com/secdev/scapy/blob/master/scapy/libs/ethertypes.py
    # print(ETHER_TYPES['IPV4'])

def extract_tcp(parsed_dict, tcp_pkt):
    parsed_dict['tcp_src_port'] = tcp_pkt.sport
    parsed_dict['tcp_dst_port'] = tcp_pkt.dport
    parsed_dict['has_tcp'] = True

def extract_udp(parsed_dict, udp_pkt):
    parsed_dict['udp_src_port'] = udp_pkt.sport
    parsed_dict['udp_dst_port'] = udp_pkt.dport
    parsed_dict['udp_len'] = udp_pkt.len
    parsed_dict['has_udp'] = True

def extract_icmp(parsed_dict, icmp_pkt):
    #print(icmp_pkt.summary())
    parsed_dict['icmp_type'] = icmp_pkt.type  # 0 for request, 8 for reply
    parsed_dict['icmp_code'] = icmp_pkt.code  # code field which gives extra information about icmp type
    parsed_dict['has_icmp'] = True

def extract_arp(parsed_dict, arp_pkt):
    #print(arp_pkt.summary())
    parsed_dict['arp_op'] = arp_pkt.op # 1 who-has, 2 is-at
    parsed_dict['arp_psrc'] = arp_pkt.psrc
    parsed_dict['arp_pdst'] = arp_pkt.pdst
    parsed_dict['arp_hwsrc'] = arp_pkt.hwsrc
    parsed_dict['arp_hwdst'] = arp_pkt.hwdst
    parsed_dict['has_arp'] = True

# Given a raw packet, parse out features in form of a dictionary
def parse_packet(pkt_data):
    parsed_dict = {}
    # Parse arrival time
    parsed_dict['time'] = pkt_data.time

    if pkt_data.haslayer(Ether):
        ether_pkt = pkt_data.getlayer(Ether)
        extract_ether(parsed_dict, ether_pkt)
    
    # TODO: Do we need IPv6 support?
    # IP packet
    if pkt_data.haslayer(IP):
        ip_pkt = pkt_data.getlayer(IP)
        extract_ip(parsed_dict, ip_pkt)
 
    if pkt_data.haslayer(TCP):
        tcp_pkt = pkt_data.getlayer(TCP)
        extract_tcp(parsed_dict, tcp_pkt)

    if pkt_data.haslayer(UDP):
        udp_pkt = pkt_data.getlayer(UDP)
        extract_udp(parsed_dict, udp_pkt)

    if pkt_data.haslayer(ARP):
        arp_pkt = pkt_data.getlayer(ARP)
        extract_arp(parsed_dict, arp_pkt)

    if pkt_data.haslayer(ICMP):
        icmp_pkt = pkt_data.getlayer(ICMP)
        extract_icmp(parsed_dict, icmp_pkt)
    
    return parsed_dict


class PacketAnalyzer:
    def __init__(self, is_training_mode):
        if is_training_mode == False:
            # List of ML prediction queues
            self.prediction_queues = []
            
            # Aggregate based daemon
            self.prediction_queues.append(Queue())
            prediction_process = Process(target=aggregate_daemon, 
                                         args=(self.prediction_queues[0],
                                               config["aggregate"]["models"], 
                                               config["aggregate"]["training_data"], 
                                               config["aggregate"]["output"]))
            prediction_process.daemon = True
            prediction_process.start()
            
            # Per packet Local Outlier Factor
            self.prediction_queues.append(Queue())
            prediction_process2 = Process(target=per_pkt_daemon,
                                          args=(self.prediction_queues[1], 
                                                config["per_pkt"]["model"],
                                                config["per_pkt"]["scaler"],
                                                config["per_pkt"]["output"]))
            
            # print("Creating lor ", prediction_process2.name, prediction_process2.pid)
            prediction_process2.daemon = True
            prediction_process2.start()
            
        else:
            self.insert_queue = Queue()
            db_insertion_process = Process(target=db_insertion_daemon, 
                                           args=(self.insert_queue,))
            print("Creating",  db_insertion_process.name, db_insertion_process.pid)
            db_insertion_process.daemon = True
            db_insertion_process.start()


        self.packet_count = 0
        self.is_training_mode = is_training_mode
    
    def process_packet(self, pkt_data):
        parsed_dict = parse_packet(pkt_data)
        self.packet_count = self.packet_count + 1

        # if self.packet_count % 100 == 0:
        #     print ("******packet_count={}".format(self.packet_count))
        
        # Adding Raw dump
        raw_dump = raw(pkt_data)
        parsed_dict['raw'] = raw_dump
        # Adding training/testing flag
        parsed_dict['is_training'] = self.is_training_mode
        
        # If testing mode, call predict_packet
        if self.is_training_mode:
            # Insert into db
            self.insert_packet(parsed_dict)
        else:
            self.predict_packet(parsed_dict)
    
    # Db insertion queue/class
    def insert_packet(self, parsed_dict):
        self.insert_queue.put(parsed_dict)
        if self.insert_queue.qsize() > 1000:
            print ("DB instertion Queue is too high")
            print("Queue size", self.insert_queue.qsize())
            # exit(-1)

    # Prediction/Anomaly queue/class
    def predict_packet(self, parsed_dict):
        for queue in self.prediction_queues:
            queue.put(parsed_dict)
            if queue.qsize() > 1000:
                print ("Prediction Queue is too high")
                print("Queue size", queue.qsize())
                # exit(-1)


count = 0

# Use main, if you want to read data from pcap, instead of capturing it via live traffic
# NOTE: The aggregate model does not work with reading from pcaps, because the time field is not preserved
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Pcap analyzer')
    parser.add_argument('--pcap', help="provide pcap to analyze", required=True)
    parser.add_argument('--mode', choices=['test', 'train'], help="Run pipeline in training/testing mode", required=True)
    args = parser.parse_args()
    
    pkt_analyzer = PacketAnalyzer(is_training_mode = (args.mode == 'train'))  

    for pkt_data, pkt_metadata in RawPcapReader(args.pcap):
        packet = pkt_analyzer.process_packet(Ether(pkt_data))
