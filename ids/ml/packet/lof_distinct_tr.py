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
Selects transformed features from per_packet and uses it to train scaler, LocalOutlierFactor model and write them to current folder
"""

import numpy as np
import time
import psycopg2
from psycopg2.extras import DictCursor
from  __init__ import *
import pickle
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import MinMaxScaler




if  __name__=='__main__':
    start=time.time()
    
    conn=psycopg2.connect('dbname={} user=mini'.format("scada"))
    """
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
    """
    fields2={}
    for index,col in enumerate(distinct_cols):
        fields2[index]=col
    print(fields2.values())


    cur = conn.cursor('cursor', cursor_factory=DictCursor) # server side cursor
    cur.execute("SELECT distinct * FROM per_packet;")
    vecs=[]
    for row in cur:
        vec=row
        vecs.append(vec)
        print(vec)
    scaler=StandardScaler()
    #scaler=MinMaxScaler()
    scaler.fit(vecs)
    vecs=scaler.transform(vecs)
    end=time.time()
    conn.close()
    print(end-start)   
    print(len(vecs))
    for vec in vecs:
        print(vec)
    start=time.time()
    clf=LocalOutlierFactor(n_neighbors=1,novelty=True,metric='cosine')
    clf.fit(vecs)
    print("Fitting done")
    pkl_filename = "lof_distinct_model.pkl"
    pickle.dump(clf, open(pkl_filename, 'wb'))
    pkl_scaler = "lof_scaler.pkl"
    pickle.dump(scaler, open(pkl_scaler, 'wb'))
    end=time.time()
    # print(end-start) 
  
    
    X_scores = clf.negative_outlier_factor_
    print(X_scores)
    '''
    plt.title("Local Outlier Factor (LOF)")
    plt.scatter(X[:, 0], X[:, 1], color='k', s=3., label='Data points')
    # plot circles with radius proportional to the outlier scores
    radius = (X_scores.max() - X_scores) / (X_scores.max() - X_scores.min())
    plt.scatter(X[:, 0], X[:, 1], s=1000 * radius, edgecolors='r',facecolors='none', label='Outlier scores')
    plt.axis('tight')
    plt.xlim((-5, 5))
    plt.ylim((-5, 5))
    legend = plt.legend(loc='upper left')
    legend.legendHandles[0]._sizes = [10]
    legend.legendHandles[1]._sizes = [20]
    plt.show()
    '''
       
