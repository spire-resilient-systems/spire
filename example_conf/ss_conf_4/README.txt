Here we provide example configuration files for Spire for the Substation.

Before using them, update the IP addresses in the files to match your testbed
environment. In the provided example, we assume five machines with IP addresses:
192.168.101.101-192.168.101.105

To use this configuration, copy the provided files to the correct locations
using install_conf.sh script
`./install_conf.sh ss_conf_4`

Then, at the top-level Spire directory, run:

make clean 
make libs 
make substation


In this configuration (substation only), commands from the substation HMI or
control center are not supported.  

ss17.conf runs a single substation instance.

To run multiple independent substations simultaneously, use the additional
config files provided in end_to_end_system example config (ss18.conf, ss19.conf,
with their respective spines configurations files). Note that these are not in ss_conf_4.