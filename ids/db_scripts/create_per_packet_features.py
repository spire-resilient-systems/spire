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
import sys
import argparse

db_name = "scada"

parser = argparse.ArgumentParser(description='create per packet features DB script')
parser.add_argument('--recreate', help="drop and cerate new tables", action='store_true')

args = parser.parse_args()

conn = psycopg2.connect('dbname='+ db_name +' user=mini')
#conn = psycopg2.connect("dbname='scada' user='postgres' host='localhost'")
c = conn.cursor()

if args.recreate: 
    c.execute("DROP TABLE per_packet;")
else:
    c.execute("SELECT * FROM pg_catalog.pg_tables WHERE tablename='per_packet';")
    if (c.fetchone() != None):
        c.execute("SELECT COUNT(*) FROM per_packet")
        print("per_packet exists already exists with {} rows".format(c.fetchone()[0]))
        exit(1)



# TODO columns

c.execute('''
CREATE TABLE per_packet (
    ip_src INTEGER,
    ip_dst INTEGER,
    ip_ttl INTEGER,
    ip_len INTEGER,  
    ip_ver INTEGER,
    proto  INTEGER,

    mac_src    INTEGER,
    mac_dst    INTEGER,

    tcp_src_port INTEGER,
    tcp_dst_port INTEGER,

    udp_src_port INTEGER,
    udp_dst_port INTEGER,
    
    icmp_type     INTEGER,
    icmp_code     INTEGER,
    
    arp_op        INTEGER,
    arp_psrc      INTEGER,
    arp_pdst      INTEGER,
    arp_hwsrc     INTEGER,
    arp_hwdst     INTEGER,

    has_ip          INTEGER DEFAULT 0,
    has_ether       INTEGER DEFAULT 0,
    has_tcp         INTEGER DEFAULT 0,
    has_udp         INTEGER DEFAULT 0,
    has_icmp        INTEGER DEFAULT 0,
    has_arp         INTEGER DEFAULT 0

);
''')

c.close()
conn.commit()
conn.close()
