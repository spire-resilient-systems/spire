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

import argparse
import pickle
import os
import numpy as np

from datetime import datetime
from multiprocessing import Process, Queue

from BucketCollection import Bucket
from MLPredictor import MLPredictor
from featurize_aggregate import featurize, featurize_flows

# Process packets and uses trained models
class AggregateProcessor():

    # Given the filenames of data, creates processor
    #   models      - array of model filenames, i.e. output(s) of train_aggregate.py
    #   data        - filename contiaing the data, i.e. output of featurize_aggregate.py
    #   out         - file that this prints to (can be stdout)
    def __init__(self, models, data, out):
        self.out = open(out, 'w')
        
        print("Aggregate Predictor Started", flush=True, file=self.out)

        # Load training data so we can make comparisons
        (self.interval, self.known, names, data, flow_names, flow_data) = pickle.load(open(data, 'rb'))
        
        # Combine data and flow data for avgs and standard deviation ouputs, even if models don't use it
        data = np.concatenate((data, flow_data), axis = 1)
        self.names = names + flow_names

        self.avg = np.average(data, axis = 0)
        self.std = np.std(data, axis = 0)

        # Initialize current bucket and variables to keep track of it
        self.cur = Bucket()
        self.first_bkt = True
        self.cur_index = -1

        self.predictors = []
        for filename in models:
            self.predictors.append(pickle.load(open(filename, 'rb')))


    def print_diff(self, vec):
        for (field, val, mu, sigma) in zip(self.names, vec, self.avg, self.std):
            # don't print out fields that have small differences
            if (sigma == 0):
                if (abs(val - mu) <= 1):
                    continue
            elif (abs((val - mu) / sigma) <= 2.0):
                continue

            template = "  {0:30} - cur {1:5d}, avg {2:5.0f} ({3:+.0f})"
            template = template.format(field, val, mu, val - mu)
            if (sigma != 0):
                template += " ({0:+.2f} stds)"
                template = template.format((val - mu) / sigma)

            print(template, flush=True, file=self.out)
        

    def process(self, packet):
        time = packet['time']
        index = time // self.interval

        # Very first packet we receive
        if (self.cur_index == -1): self.cur_index = index

        if (index != self.cur_index and index != self.cur_index + 1):
            print("out of order packet")
            return

        # Bucket is completed
        if (index != self.cur_index):
            # Ignore first bucket because it is a partial bucket
            if (not self.first_bkt):
                # Predict using ml algorithms and show the diff if the majority predict abnormal
                features = featurize(self.known, self.cur)
                flow_features = featurize_flows(self.known, self.cur)

                fired_models = []
                
                num_abnormal = 0
                for p in self.predictors:
                    if (p.predict(features, flow_features) == -1):
                        fired_models.append(os.path.basename(p.name))
                        num_abnormal += 1

                if (num_abnormal > len(self.predictors) // 2):
                    print("**** Last minute predicted abnormal ****", flush=True, file=self.out)
                    self.print_diff(features + flow_features)

                else:
                    print("**** Last minute predicted normal ****", flush=True, file=self.out)

                print("Models that predicted abmormal: {}".format(str(fired_models)), flush=True, file=self.out)

            
            self.first_bkt = False
            self.cur = Bucket()

        self.cur.insert_packet(packet)
        self.cur_index = index


# Starts an aggregate daemon
#   data: the pickled data, used for output (output of featurize_aggregate.py)
#   models: list of filenames containing models (output of train_aggregate.py)
#   output_file: file to print results to
# Example usage
# aggregateDaemon(None, "baseline.out", "aggregate_features.pkl", ["aggregate_model.pkl"])
def aggregate_daemon(queue, models, data, output_file):
    p = AggregateProcessor(models, data, output_file)

    while True:
        pkt = queue.get()
        p.process(pkt)
