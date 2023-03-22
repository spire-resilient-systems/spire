Here we provide an example configuration for Confidential Spire. As described
in Confidential Spire's main README_Confidential_spire.txt, Confidential Spire
requires several different configuration files, and parts of Confidential Spire
must currently be recompiled when these files are changed.

The confidential_spire_conf_4+4+3+3 directory includes the following:

scada_def.h           : Main Confidential Spire configuration (common/def.h)
config.json           : PLC/RTU configuration (config/config.json)
prime_def.h           : Prime configuration (prime/src/def.h)
address.config        : Prime replica IP addresses (prime/bin/address.config)
spines_address.config : Prime Spines daemon IP addresses
                        (prime/bin/spines_address.config)
spines_ext.conf       : Configuration for external Spines network
                        (spines/daemon/spines_ext.conf)
spines_int.conf       : Configuration for internal Spines network
                        (spines/daemon/spines_int.conf)

To copy these configuration files to the correct locations with the install.sh
script provided, run, from the example_conf directory (one level up):

./install_conf.sh confidential_spire_conf_4+4+3+3

After copying the configuration files, to recompile, run the following commands
from the top-level directory:
  
  make clean
  make libs
  make conf_spire

Note that if the total number of replicas (or clients) is increased, you will
also need to re-run Confidential Spire's and Prime's gen_keys programs to create
keys for the additional replicas (or clients).

This configuration includes 2 control-center sites and 2 data center sites, for
a total of 4 sites. Each control-center site contains 4 replicas, and each data
center site contains 3 replicas, for a total of 14 replicas.

This supports one compromised replica, one proactive recovery, and one
site-disconnection simultaneously.

In this example configuration, all replicas in a given site run on the same
machine to enable simple benchmarking and testing. In a real deployment, they
should be run on separate machines.

Site 1
------
Replica 1:  192.168.1.101
Replica 5:  192.168.1.101
Replica 9:  192.168.1.101
Replica 13: 192.168.1.101

Site 2
------
Replica 2:  192.168.1.102
Replica 6:  192.168.1.102
Replica 10: 192.168.1.102
Replica 14: 192.168.1.102

Site 3
------
Replica 3:  192.168.1.103
Replica 7:  192.168.1.103
Replica 11: 192.168.1.103

Site 4
------
Replica 4:  192.168.1.104
Replica 8:  192.168.1.104
Replica 12: 192.168.1.104


PLC/RTU Proxy: 192.168.1.105
HMI:           192.168.1.106
