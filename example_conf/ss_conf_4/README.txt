Here we provide example configuration files for Spire for the Substation.

You should update the IP addresses in these files to match your testbed
environment. In this example, we use 5 machines with IP addresses
192.168.101.101-192.168.101.105

To use this configuration, copy the provided files to the correct locations.
That is, copy:

ss_spines_ext.conf -> (top-level Spire dir)/spines/daemon/ss_spines_ext.conf)

ss_spines_int.conf -> (top-level Spire dir)/spines/daemon/ss_spines_int.conf)

ss17.conf -> (top-level Spire dir)/common/ss17.conf)

scada_def.h -> (top-level Spire dir)/common/def.h) 

Then, at the top-level Spire directory, run:

make clean
make libs
make substation


Note that ss17.conf is used to run one substation. For 