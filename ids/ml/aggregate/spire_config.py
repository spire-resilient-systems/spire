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

# Addresses of machines uses to run a 6 machine (f=1,k=1) Spire configuration
# The IDS uses these to distinguish between known and unknown machines
# Edit this!

# The ML model labels all traffic from machines not listed as "other". If there are any machines that
# cause significant traffic in the system, they should be added here

ips = [
    # Scada master replicas
    '192.168.101.101',
    '192.168.101.102', 
    '192.168.101.103', 
    '192.168.101.104',
    '192.168.101.105', 
    '192.168.101.106',
    
    # Client (HMI/Proxy)
    '192.168.101.107',
    '192.168.101.108'

    # Other machines should go here
]

macs = [
    # Scada master replicas
    '00:00:00:00:00:01',
    '00:00:00:00:00:02',
    '00:00:00:00:00:03',
    '00:00:00:00:00:04',
    '00:00:00:00:00:05',
    '00:00:00:00:00:06',

    # Client (HMI/Proxy)
    '00:00:00:00:00:07',
    '00:00:00:00:00:08'

    # Other machines should go here
]


# These sections are only used for calculating "flow features", e.g. the count of scada_master_ip -> client_ip packets
# These features are disabled by default
sm_ips = ips[:6]
client_ips = ips[6:8]
sm_macs = macs[:6]
client_macs = macs[6:9]
