## Pre-requisites:
- Python3.6 and above
- Scapy
- Postgresql

## Work flow:
1. Create database to store both raw and parsed packet data
2. Capture data for training and store in said database
3. Analyze, clean, and pre-process data
4. Offline training and tuning
5. Run in real time on current network traffic
6. Simulate attacks for testing

SPAN port is to be setup such that the total traffic on dissemination switch is mirrored/copied to our system.

## 1. Database Setup:
Install postgres
```
sudo apt install postgresql postgresql-contrib
/etc/init.d/postgresql stop
/etc/init.d/postgresql start
```

Then, create a database `scada` for the IDS system, and login to the `psql` prompt
```
sudo -u postgres createdb scada
sudo -u postgres psql 
```

Then, in the psql prompt, create a user for the account you plan to use for the IDS, and give it permissions on the databse
```
create user mini;
grant all privileges on database scada to mini; 
```

Note depending on your operating system, you may also need to adjust the permissions so that you can connect as the `mini`
user.

Then, use our scripts to create the appropriate tables
```
cd db_scripts; 
python3 createDB.py
```

Note: if previous tables already exist, then use `--recreate` option to drop and recreate tables.

## 2. Caputure Data

The following commands capture network traffic over a specified interface (`eth3`) and insert them into the `scada` db we made above. 
Both raw and parsed packets into separate tables. By default, the script will timeout after `1 hour` but you can give
a timeout in seconds by using the `--time` option.

```
cd capture_scripts
sudo python live_capture.py eth3 &
```

In the file, there is also a string called `pkt_filter` that can be used to filter traffic out for training. For example, we removed
any SSH traffic during our training. An example is provided in the file, but more details about the sntax of the filter string can be
found [here](https://biot.com/capstats/bpf.html).

## 3. Explore Data / Configure Models
It is important to analyse the data captured. This will be helpful in feature engineering and parameter tuning


## 4. Training Models
### Traffic Pattern based ML models
The traffic based model is based off the assumption that there is some pattern to the "normal" expected data, e.g. one minute
looks like another minute. So therefore the training data is grouped into "buckets" of a specified time period (defaults to one
minute). Each bucket simply stores the counts of different features and is a single data point for our model. Prediction then
consists of collecting a minute of real time packets, and feeding that bucket to our model for prediction

The scripts in [`ml/aggregate`](ml/aggregate) are used to train such a model. Following is a brief description of each files purpose
- `BucketCollection.py`: Defines class for buckets and BucketCollection, which is a group of buckets with a specified interval
- `generate_aggregate.py`: Reads from database of parsed packets and generates buckets
- `featurize_aggregate.py`: Converts buckets to vectors for training
- `train_aggregate.py`: Trains models
- `AggregateDaemon.py`: Given a source (queue) of parsed packets, and a list of models, performs prediction. This consists of reading from the source, and once a bucket is completed, outputting the result from each model.
- `spire_config.py`: Specifies a list of known ips and macs. When featurizing, the counts of these addresses are recorded separately, and all others are put into an `other` 
category. Thererfore, **you need to edit this file in order for the models to be effective**. Essentially, any machines that have significant traffic on the network should probably be included. See inside for more documentation.

To create models, given there are parsed packets in the database, follow the steps below
```
python generate_aggregate.py
```
This will read from `packet_feat` and output (by default) a file containing the buckets called `buckets.pkl`. These and other parameters can be viewed by running the script with `--help`.
```
python featurize_aggregate.py
```
This will read from a given aggregate file (`buckets.pkl` by default) and output `features.pkl` which is contains the training
data, names for each features, and interval. Again `--help` can be used to see various options.


```
python model.pkl lof
```
Trains a model given a specified output file and an algorithm. The algorith can be any of

- [`lof`](https://scikit-learn.org/stable/modules/generated/sklearn.neighbors.LocalOutlierFactor.html) Local Outlier Factor
- [`svm`](https://scikit-learn.org/stable/modules/generated/sklearn.svm.OneClassSVM.html#sklearn.svm.OneClassSVM) One Class SVM
- [`cov`](https://scikit-learn.org/stable/modules/generated/sklearn.covariance.EllipticEnvelope.html#sklearn.covariance.EllipticEnvelope) Elliptic Envelope/Covariance

Other options are also available to create different models.

Finally, make sure to put the models you wish to use in `config.py` in the prediction stage.

### Packet Analysis based ML models
Extract from packet_feat table unique rows of needed data.

This can be done by cd db_scripts; python create_distinct_features.py;


This extracts distinct packets headers and make training faster.

Now run script -
```
cd ml/packet;
check ips and mac addresses defined in init are correct.These are environment dependent.

python featurize_per_pkt.py (This is feature engineering step, the transformed feature vectors are stored into per_packet table in db. We can use this to train multiple models.)

python lor_distinct_tr.py (This will generate the models and stores in the same directory. This training needs to be done if anycomponent of system changes.)

Current Models for Packet Analysis based ML models-
[`lof`](https://scikit-learn.org/stable/modules/generated/sklearn.neighbors.LocalOutlierFac    tor.html) Local Outlier Factor
['StandardScaler'](https://scikit-learn.org/stable/modules/generated/sklearn.preprocessing.StandardScaler.html)
```

## 5. Real time prediction

The `live_test.py` script is very similar to the `live_capture.py` script described above, except that rather than insert packets
into the database, it passes the packets to the trained models, which then output to log files. Also, by default it does not timeout 
(though this can be changed with the same `--time` option).

Before running, you must also change the `config.py` file, which specifies paths to the models, as well as auxialiary files for
the different model types. Documentation for each parameter is included in the file.

Following is an example of how to run the `live_test.py` script on the `eth3` interface, and also view its output in real time. 
```
cd capture_scripts;
sudo python live_test.py eth3 &
tail -f  perPkt_output.log 
tail -f aggregate_output.log 
```

## 6. Tests and attacks
```
cd dos_scripts
sudo python dos_attack_v2.py --help (This will print available choices of attack combos)
```

Some examples -

Replay attack

    sudo python dos_attack_v2.py --trans_proto UDP --source_ip scada1 --dest_ip mini2 --count 10

DoS attack

    sudo python dos_attack_v2.py --trans_proto UDP --dest_ip mini2/scada1 --count 10

Port Scanning

    sudo python dos_attack_v2.py --trans_proto TCP --count 10





