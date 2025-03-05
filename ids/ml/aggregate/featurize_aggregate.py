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

import argparse
import numpy as np
import pickle

import spire_config

# get the set of known/unknown labels for udp fields by seeing which
# values are common across all buckets
def get_common_labels(baseline):
    labels = {
        'udp_port': set(),
        'udp_len': set()
    }
    
    first = True

    for b in baseline:
        counts = b.categoryCounts
        ports = counts['udp_src_port'].keys() | counts['udp_dst_port'].keys()
        lens = counts['udp_len'].keys()
        
        if (first):
            first = False
            labels['udp_port'] = ports
            labels['udp_len'] = lens
        else:
            labels['udp_port'] &= ports
            labels['udp_len'] &= lens

    return {k : list(v) for k, v in labels.items()}


def place_feature(known, feature, value, row_section):
    if (feature in known):
        row_section[known.index(feature)] = value
    # Other
    else:
        row_section[-1] += value
        
def get_feature_names(known, bucket):
    names = []
    names.append('total')
    names += [field for field in sorted(bucket.pktCounts)]

    for field, counts in sorted(bucket.categoryCounts.items()):
        section = []
        feat = None
        if (field == 'ip_src' or field == 'ip_dst'):
            section = [field + '/' + feat for feat in known['ip']]
        if (field == 'mac_src' or field == 'mac_dst'):
            section = [field + '/' + feat for feat in known['mac']]
        if (field == 'udp_src_port' or field == 'udp_dst_port'):
            section = [field + '/' + str(feat) for feat in known['udp_port']]
        if (field == 'udp_len'):
            section = [field + '/' + str(feat) for feat in known['udp_len']]
        names += section + [field + '/other']
    return names

# Converts a bucket of packet counts into a feature vector, given a list of known
# ips, macs, udp ports and lens. (counts other lengths as 'other')
def featurize(known, bucket):
    row = []

    row.append(bucket.total)
    row += [count for field, count in sorted(bucket.pktCounts.items())]

    for field, counts in sorted(bucket.categoryCounts.items()):
        row_section = None
        known_vals = None

        if (field == 'ip_src' or field == 'ip_dst'):
            known_vals = known['ip']
            row_section = [0 for i in range(len(known['ip']) + 1)]
        if (field == 'mac_src' or field == 'mac_dst'):
            known_vals = known['mac']
            row_section = [0 for i in range(len(known['mac']) + 1)]
        if (field == 'udp_src_port' or field == 'udp_dst_port'):
            known_vals = known['udp_port']
            row_section = [0 for i in range(len(known['udp_port']) + 1)]
        if (field == 'udp_len'):
            known_vals = known['udp_len']
            row_section = [0 for i in range(len(known['udp_len']) + 1)]
        
        if (row_section == None):
            raise Exception('Error: known values for field {} not present!'.format(field))
    
        for feature, cnt in counts.items():
            place_feature(known_vals, feature, cnt, row_section)
        
        row += (row_section)
    return row

def get_flow_feature_names():
    names = [
        'sm_ip -> sm_ip',
        'sm_ip -> client_ip',
        'sm_ip -> other_ip',
        'client_ip -> sm_ip',
        'client_ip -> client_ip',
        'client_ip -> other_ip',
        'other_ip -> sm_ip',
        'other_ip -> client_ip',
        'other_ip -> other_ip',

        'sm_mac -> sm_mac',
        'sm_mac -> client_mac',
        'sm_mac -> other_mac',
        'client_mac -> sm_mac',
        'client_mac -> client_mac',
        'client_mac -> other_mac',
        'other_mac -> sm_mac',
        'other_mac -> client_mac',
        'other_mac -> other_mac'
    ]
    return names

def featurize_flows(known, bucket):
    
    # Add ip_flows
    ip_flows = bucket.flows[('ip_src', 'ip_dst')] 

    row =[]
    row_section = [0] * 9
    for (src, dst), value in ip_flows.items():
        srci = 2 # other
        dsti = 2
        if (src in known['sm_ip']): srci = 0
        if (dst in known['sm_ip']): dsti = 0

        if (src in known['client_ip']): srci = 1
        if (dst in known['client_ip']): dsti = 1
        
        row_section[srci * 3 + dsti] += value

    row += row_section

    # add mac_flows
    mac_flows = bucket.flows[('mac_src', 'mac_dst')] 

    row_section = [0] * 9
    for (src, dst), value in mac_flows.items():
        srci = 2 # other
        dsti = 2
        if (src in known['sm_mac']): srci = 0
        if (dst in known['sm_mac']): dsti = 0

        if (src in known['client_mac']): srci = 1
        if (dst in known['client_mac']): dsti = 1
        row_section[srci * 3 + dsti] += value
    row += row_section

    return row
            

if __name__ == '__main__':

    # Parse command line args
    parser = argparse.ArgumentParser(description='Generate feature vectors from buckets genearted from database')
    parser.add_argument('--buckets', default='./buckets.pkl', help='pickled BucketCollection object')
    parser.add_argument('--output', default='./features.pkl', help='where to output feature vector')

    args = parser.parse_args();

    f = open(args.buckets, 'rb')
    bkt_collection = pickle.load(f)

    # Flatten buckets from baseline
    bkts = []
    for b in bkt_collection.buckets:
        bkts.append(b)

    # remove partial bucket at end (since it doesn't contain a full interval of data)
    bkts.pop(len(bkts) - 1)
    
    # build features
    known = get_common_labels(bkts)
    known['ip'] = spire_config.ips
    known['mac'] = spire_config.macs

    known['sm_ip'] = spire_config.sm_ips
    known['client_ip'] = spire_config.client_ips
    known['sm_mac'] = spire_config.sm_macs
    known['client_mac'] = spire_config.client_macs


    
    # build matrix of training data. Keep flow_data separate
    data = []
    flow_data = []
    for b in bkts:
        data.append(featurize(known, b))
        flow_data.append(featurize_flows(known, b))
    
    data = np.array(data)
    names = get_feature_names(known, bkts[0])
    flow_names = get_flow_feature_names()

    print('number of data points:', len(data))

    # save array and known features
    with open(args.output, 'wb') as f:
        pickle.dump((bkt_collection.interval, known, names, data, flow_names, flow_data), f)
