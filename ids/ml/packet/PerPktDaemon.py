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

"""
This daemon , loads Packet Analysis based model and scaler(pathe set in capture_scripts/model_paths.py)
Then uses transform(in ml/packet/init) and gets feature vector.
It baches 100 packets and runs prediction on each, finally outputs only DISTINCT attack packets in that batch.
The attack predictions are written to output_file(capture_scripts/model_paths)

"""

import pickle
from multiprocessing import Queue
from __init__ import *
import psycopg2
from psycopg2.extras import DictCursor
import os, sys
import numpy as np
# import scapy
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP, icmptypes
from scapy.data import ETHER_TYPES

# sys.path.append('./../')

class LOFProcessor():
    def __init__(self, pkl_filename,pkl_scaler,output_file):
        self.out = open(output_file, 'w+')
        self.fields={}
        self.parsed_pkts=[]
        self.X=[]
        for index,col in enumerate(distinct_cols):
            self.fields[index]=col    
        
        print(self.fields.values(),file=self.out,flush=True)
        self.clf = pickle.load(open(pkl_filename, 'rb'))
        self.scaler = pickle.load(open(pkl_scaler, 'rb'))

       
    def process(self, parsed_pkt):
        # TODO: Maybe send transformed packets to these, as all ml models will run this function
        vec=transform(parsed_pkt, self.fields)
        nd_vals = np.asarray(list(vec.values()))#.reshape(1, -1)
        self.parsed_pkts.append(parsed_pkt)
        self.X.append(nd_vals)
        # print(nd_vals)
    
    def predict(self):
        #predictions=self.clf.predict(self.X)
        X_transformed=self.scaler.transform(self.X)
        predictions=self.clf.predict(X_transformed)
        needed=[i for i,val in enumerate(predictions) if val==-1]
        if len(needed)>=1:
            summaries=[]
            for i in needed:
                parsed_pkt=self.parsed_pkts[i]
                if Ether(parsed_pkt['raw']).haslayer(DHCP):
                    continue
                summaries.append(Ether(parsed_pkt['raw']).summary())
                #print(Ether(parsed_pkt['raw']).show())
                #print(self.X[i])
                #print(X_transformed[i])
            
            summaries=np.unique(summaries)
            d="\n"
            d.join(summaries)
            if len(summaries) >0:
                print(summaries,file=self.out,flush=True)
        

def per_pkt_daemon(queue, pkl_filename,pkl_scaler,output_file):
    '''
    conn=psycopg2.connect('dbname={} user=mini'.format("scada"))

    col_cursor = conn.cursor()
    col_query = "select column_name FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'per_packet';"
    col_cursor.execute(col_query)
    columns=col_cursor.fetchall()
    col_cursor.close()
    fields={}
    for index,col in enumerate(columns):
        f=col[0]
        fields[index]=f
    print(fields.values())
    '''
    lof = LOFProcessor(pkl_filename,pkl_scaler,output_file)
    print("LOF Daemon called",file=lof.out,flush=True)

    while True:
        parsed_pkt =queue.get()
        
        lof.process(parsed_pkt)
        if len(lof.X)>100:
            lof.predict()
            lof.X=[]
            lof.parsed_pkts=[]
