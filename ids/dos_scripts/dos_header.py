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

# 'machines' is a dictionary which maps machine_names in our SCADA system to their corresponding n/w level properties
# Used by dos_scripts to generate attacks

machines = {
"scada1": {'ip':'192.168.101.101', 'mac':'00:00:00:00:00:01', 'port':8120},
"scada2": {'ip':'192.168.101.102', 'mac':'00:00:00:00:00:02', 'port':8120},
"scada3": {'ip':'192.168.101.103', 'mac':'00:00:00:00:00:03', 'port':8120},
"scada4": {'ip':'192.168.101.104', 'mac':'00:00:00:00:00:04', 'port':8120},
"scada5": {'ip':'192.168.101.105', 'mac':'00:00:00:00:00:05', 'port':8120},
"scada6": {'ip':'192.168.101.106', 'mac':'00:00:00:00:00:06', 'port':8120},
"mini1":  {'ip':'192.168.101.105', 'mac':'00:00:00:00:00:07', 'port':8120},
"mini2":  {'ip':'192.168.101.106', 'mac':'00:00:00:00:00:08', 'port':8120},
"mini3":  {'ip':'192.168.101.107', 'mac':'00:00:00:00:00:09', 'port':8120},
}

# Database query to find the mapppings from packets captured in Database
qeury_machines = "SELECT DISTINCT mac_src, ip_src FROM packet_feat where has_arp=False;"
