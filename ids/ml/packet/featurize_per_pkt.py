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
Selects rows form features_distinct, transforms them and inserts transformed feature vector into per_packet table
"""

import argparse
import psycopg2
import numpy as np
from psycopg2.extras import DictCursor
from __init__ import *
from datetime import datetime
from collections import defaultdict

# Parse command line args
parser = argparse.ArgumentParser(description='Anomaly based intrusion detection baseline generator')
parser.add_argument('--dbName', default='scada', help='name of database to pull statistics from')

args = parser.parse_args();
insertion_query = "INSERT INTO per_packet({}) VALUES ({});"


def insert_into_db(vec,insert_cursor):
    keys=vec.keys()
    column_names= ", ".join(keys)
    
    values=",".join(["{}".format(vec[col]) for col in keys])
    # print(column_names)
    # print(fvalues)

    insert_cursor.execute(insertion_query.format(column_names,values))
    # if insert_cursor.fetchone()[0]!=vec['id']:
    #     print("Insertion error for id=",vec['id'])
        



if __name__=='__main__':
    # set up db
    conn = psycopg2.connect('dbname={} user=mini'.format(args.dbName))
    conn2 = psycopg2.connect('dbname={} user=mini'.format(args.dbName))

    col_cursor = conn.cursor()
    col_query = "select column_name FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'packet_feat';"
    col_cursor.execute(col_query)
    columns=col_cursor.fetchall()
    col_cursor.close()
    fields={}
    for index,col in enumerate(columns):
        f=col[0]
        fields[index]=f
    fields2={}
    for index,col in enumerate(distinct_cols):
        fields2[index]=col

    
    insert_cursor=conn2.cursor()

    cur = conn.cursor('cursor', cursor_factory=DictCursor) # server side cursor
    cur.execute("select distinct * from features_distinct;")
    i=0
    for row in cur:
        i+=1
        print ()
        print(row)
        vec=transform(row,fields2)
        print(vec)
        insert_into_db(vec,insert_cursor)
        if i%10000==0:
            print(i)
            conn2.commit()
    
    conn2.commit()
    insert_cursor.close()
    cur.close()
    conn.close()
    conn2.close()



    
