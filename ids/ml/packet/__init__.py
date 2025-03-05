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

"""
If not NN , we need to transform feature vector to be numerical, so below map known/correct IPs, macs, ports.
They will be used by transform function to do feature engineering.
"""

machines = {
    #Scada Masters
    '192.168.101.101': ['00:00:00:00:00:01', 8120],
    '192.168.101.102': ['00:00:00:00:00:02', 8120],
    '192.168.101.103': ['00:00:00:00:00:03', 8120],
    '192.168.101.104': ['00:00:00:00:00:04', 8120],
    '192.168.101.105': ['00:00:00:00:00:05', 8120],
    '192.168.101.106': ['00:00:00:00:00:06', 8120],
    #Minis- plcs, hmis
    '192.168.101.107': ['00:00:00:00:00:07', 8120],
    '192.168.101.108': ['00:00:00:00:00:08', 8120],
    '192.168.101.109': ['00:00:00:00:00:09', 8120],
}
macs = [
    #Macs of above machines
    '00:00:00:00:00:01',
    '00:00:00:00:00:02', 
    '00:00:00:00:00:03', 
    '00:00:00:00:00:04', 
    '00:00:00:00:00:05',
    '00:00:00:00:00:06', 
    '00:00:00:00:00:07', 
    '00:00:00:00:00:08', 
    '00:00:00:00:00:09',
]
ports=[
    #Ports that are authorized to operate
    8120,
    53,
    34489,
    5353,
    68,123,
    34835
]
#maps IPs to known and unknown set
def do_ip(ip):
    val=1
    if ip in machines.keys():
        val=100
    return val

#maps MACs to known and unknown set
def do_mac(ip,mac):
    val=1
    if ip in machines.keys():
        if mac==machines[ip][0]:
            val=100
        else:
            val=-100
    return val

def do_only_mac(mac):
    val=1
    if mac in macs:
        val=100
    return val

#maps Ports to known and unknown set
def do_ports(port):
    val=1
    if port in ports:
        val=100
    return val

#Header features are transformed into vectors used for training
def transform(row,fields):
    #print
    vec={}
     
    for field in fields.values():
        if field not in row.keys():
            row[field]=0
    
    for index,field in fields.items():
        value=row.get(field)
        if value is None:
            value=0
        if type(value) == type(True):
            value=int(value) * 100
        if type(value) == type(False):
            value=int(value)
        
        if value!=0:
            if field=='ip_src':
                value=do_ip(row[field])
            if field=='ip_dst':
                value=do_ip(row[field])
            if field=='mac_src':
                #value=do_only_mac(row[field])
                
                if  row.get('has_arp')==bool(1):
                    value=do_mac(row['arp_psrc'],row[field])
                    #value=do_only_mac(row[field])
                else:
                    value=do_mac(row.get('ip_src',-5),row[field])
                
            if field=='mac_dst':
                
                if  row.get('has_arp')==bool(1):
                    value=do_mac(row['arp_pdst'],row[field])
                    #value=do_only_mac(row[field])
                else:
                    value=do_mac(row.get('ip_dst',-5),row[field])
                    
                #value=do_only_mac(row[field])
            if field=='arp_psrc':
                value=do_ip(row[field])
            if field=='arp_pdst':
                value=do_ip(row[field])
            if field=='arp_hwsrc':
                value=do_mac(row['arp_psrc'],row[field])
            if field=='arp_hwdst':
                value=do_mac(row['arp_pdst'],row[field])
            if field in ['udp_src_port','udp_dst_port']:
                value=do_ports(row[field])
        """
        if field in ['has_ip','has_ether','has_tcp','has_udp','has_icmp','has_arp']:
            if value==-5:
                value=0
        """        
        vec[field]=value
        

        # print("{}, {}: {} , {}".format(index,field,row[field],vec[field]))
        # print(vec)
    return vec

#features selected after feature engineering. If we want to add or delete the field from feature vector we need to change this
#distinct_cols=['ip_src', 'ip_dst', 'ip_ttl', 'ip_len', 'ip_ver', 'proto', 'mac_src', 'mac_dst', 'ether_type', 'tcp_src_port', 'tcp_dst_port', 'udp_src_port', 'udp_dst_port', 'udp_len', 'icmp_type', 'icmp_code', 'arp_op', 'arp_psrc', 'arp_pdst', 'arp_hwsrc', 'arp_hwdst', 'has_ip', 'has_ether', 'has_tcp', 'has_udp', 'has_icmp', 'has_arp']
distinct_cols=['ip_src', 'ip_dst', 'ip_ttl', 'ip_len', 'ip_ver', 'proto', 'mac_src', 'mac_dst',  'tcp_src_port', 'tcp_dst_port', 'udp_src_port', 'udp_dst_port', 'icmp_type', 'icmp_code', 'arp_op', 'arp_psrc', 'arp_pdst', 'arp_hwsrc', 'arp_hwdst', 'has_ip', 'has_ether', 'has_tcp', 'has_udp', 'has_icmp', 'has_arp']
