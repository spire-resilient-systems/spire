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

parser = argparse.ArgumentParser(description='create distinct features DB script')
parser.add_argument('--recreate', help="drop and create new tables", action='store_true')

args = parser.parse_args()

conn = psycopg2.connect('dbname='+ db_name +' user=mini')
#conn = psycopg2.connect("dbname='scada' user='postgres' host='localhost'")
c = conn.cursor()

if args.recreate: 
    c.execute("DROP TABLE features;")
    c.execute("DROP TABLE features_distinct;")
else:
    c.execute("SELECT * FROM pg_catalog.pg_tables WHERE tablename='features_distinct';")
    if (c.fetchone() != None):
        c.execute("SELECT COUNT(*) FROM features_distinct")
        print("features_distinct exists already exists with {} rows".format(c.fetchone()[0]))
        exit(1)



# TODO columns

c.execute('''
create table features as select 
    ip_src, 
    ip_dst, 
    ip_ttl, 
    ip_len, 
    ip_ver, 
    proto, 
    mac_src, 
    mac_dst, 
    tcp_src_port, 
    tcp_dst_port, 
    udp_src_port, 
    udp_dst_port, 
    icmp_type, 
    icmp_code, 
    arp_op, 
    arp_psrc, 
    arp_pdst, 
    arp_hwsrc, 
    arp_hwdst, 
    has_ip, 
    has_ether, 
    has_tcp, 
    has_udp, 
    has_icmp, 
    has_arp
 from packet_feat;
''')
c.execute('''
create table  features_distinct as select distinct * from features;
''')

c.close()
conn.commit()
conn.close()
