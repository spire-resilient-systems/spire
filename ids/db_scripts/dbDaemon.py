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

import psycopg2
from multiprocessing import Process, Queue
import os, signal

query1 = "INSERT INTO packet_raw (raw, time, is_training) VALUES (%s, %s, %s) RETURNING id"

query2 = "WITH row AS ({}) \
          INSERT INTO packet_feat (id, {}) \
          SELECT id, {} FROM row"

query3 = "WITH row AS ({}) \
          INSERT INTO packet_feat (id) \
          SELECT id FROM row"

def bytea2bytes(value, cur):
    m = psycopg2.BINARY(value, cur)
    if m is not None:
        return m.tobytes()

def db_insertion_daemon(queue, dbName="scada"):
    db = dbDriver(dbName)
    print("Daemon created")

    def close_db(*args):
        print("Inserting rest of queue")
        while not queue.empty():
            parsed_pkt = queue.get()
            raw_dump = parsed_pkt.pop('raw')
            db.insert_packet(raw_dump, parsed_pkt)
        print("Closing ")
        db.close()
        exit(0)

    signal.signal(signal.SIGINT, close_db)
    signal.signal(signal.SIGTERM, close_db)
  
    while True:
        parsed_pkt = queue.get()
        raw_dump = parsed_pkt.pop('raw')
        db.insert_packet(raw_dump, parsed_pkt)


class dbDriver():
    def __init__(self, dbName):
        self.conn = psycopg2.connect("dbname={} user='mini' host='localhost'".format(dbName))
        self.cur = self.conn.cursor()
        self.counter = 0
    
    def __del__(self):
        self.close()
    
    # insert packet passed as dictionary, with fields corr. to column names
    def insert_packet(self, raw, features, retry=False):
        try:
            subquery = self.cur.mogrify(query1, (raw, features['time'], features['is_training']))
            subquery = subquery.decode()

            cols = features.keys()
            if (len(cols) > 0):
                col_names = ", ".join(cols)
                vals = ", ".join(["%({0})s".format(col_name) for col_name in cols])
                self.cur.execute(query2.format(subquery, col_names, vals), features)
            else:
                # if the dict is empty, just insert id
                self.cur.execute(query3.format(subquery))
            
            if  self.counter % 1000 == 0:
                self.conn.commit()
            self.counter += 1

        except psycopg2.InterfaceError:
            # Attempt to reopen pointer
            self.cur.close()    
            self.cur = conn.cursor()
            self.insert_packet(raw, features, True)
   
    def read_one_pkt_raw(self):
        self.cur.execute("SELECT * FROM packet_raw")    
        return self.cur.fetchone()
    def read_one_pkt_features(self):
        self.cur.execute("SELECT * FROM packet_feat")    
        return self.cur.fetchone()
    def read_all_pkt_raw(self):
        self.cur.execute("SELECT * FROM packet_raw")    
        return self.cur.fetchall()
    def read_all_pkt_features(self):
        self.cur.execute("SELECT * FROM packet_feat")    
        return self.cur.fetchall()
    
    def read_raw_by_id(self, id):
        self.cur.execute("SELECT * FROM packet_raw where id=" + str(id))
        return self.cur.fetchone()

    def close(self):
        print("*****Closing db connection")
        self.cur.close()
        self.conn.commit()
        self.conn.close()
