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

import pickle
import numpy as np


class MLPredictor():
    def __init__(self, clf, name, use_flows, scaler, pca):
        self.clf = clf
        self.name = name
        self.use_flows = use_flows
        self.scaler = scaler 
        self.pca = pca 
       
    def predict(self, vec, flow_vec):
        if (self.use_flows): vec += flow_vec
        
        vec = np.array(vec).reshape(1, -1)
        
        if (self.scaler is not None):
            vec = self.scaler.transform(vec)

        if (self.pca is not None):
            vec = self.pca.transform(vec)

        prediction = self.clf.predict(vec)
        return prediction


