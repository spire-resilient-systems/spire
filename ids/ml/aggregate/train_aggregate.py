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

import numpy as np
import time
import argparse
import pickle

from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.model_selection import train_test_split
from sklearn import svm
from sklearn.covariance import EllipticEnvelope

from MLPredictor import MLPredictor 

# Parse command line args
parser = argparse.ArgumentParser(description='Train models on aggregate feature data')
parser.add_argument('output_file', help='specifies output file that contains pickled model')
parser.add_argument('algorithm', choices=['lof', 'svm', 'cov'], help='algorithm to train on')
parser.add_argument('--training_data', default='./features.pkl', help='pickled training data, outputted by featurize_aggregate.py')
parser.add_argument('--use_flows', action='store_true', help='whether to use the flow related features in the data')
parser.add_argument('--no_standardize', action='store_false', help='whether to standardize vectors')
parser.add_argument('--pca', default='0', type=int, help='number of components to run PCA on')
parser.add_argument('--test_split', default='0', type=float, help='percentage of data to test on')

args = parser.parse_args();

f = open(args.training_data, "rb")
(_, _, _, data, _, flow_data) = pickle.load(f)

# Concat flow_data to each vector
if (args.use_flows):
    print("Adding flow features...")
    data = np.concatenate((data, flow_data), axis=1)

start = time.time()

# Standardize data (becomes mean 0 variance 1 for each feature)
scaler = None
if (not args.no_standardize):
    print("Standardizing data...")
    scaler = StandardScaler().fit(data)
    data = scaler.transform(data)

# Optionally use PCA to reduce dimensions of feature space
pca = None
if (args.pca > 0):
    print("Applying PCA: Reduce {} dims to {} components".format(data.shape[1], args.pca))
    pca = PCA(n_components=args.pca)
    data = pca.fit_transform(data)
    

# Split data
if (args.test_split == 0):
    train, test = data, None
else:
    train, test = train_test_split(data, test_size=args.test_split)

clf = None
# Fit classifier
if (args.algorithm == 'lof'):
    clf = LocalOutlierFactor(n_neighbors=30,novelty=True)
    clf.fit(train)
    X_scores = clf.negative_outlier_factor_
elif (args.algorithm == 'svm'):
    clf = svm.OneClassSVM(nu=0.1, gamma=0.01)
    clf.fit(train)
elif (args.algorithm == 'cov'):
    clf = EllipticEnvelope(contamination=0.1)
    clf.fit(train)

# Output test results if relevant
if (test is not None):
    results = clf.predict(test)
    num_correct = np.count_nonzero(results + 1)
    print('{}/{} of dev data correct {:.2f}'.format(
        num_correct, 
        len(results), 
        num_correct/len(results)
    ))

# Save model
print('Writing to {}...'.format(args.output_file))
pickle.dump(MLPredictor(clf, args.output_file, args.use_flows, scaler, pca), open(args.output_file, 'wb'))

end=time.time()
print("done, took {:.2f}s".format(end - start))

