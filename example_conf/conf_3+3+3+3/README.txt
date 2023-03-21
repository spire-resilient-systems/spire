This configuration includes 2 control-center sites and 2 data center sites, for
a total of 4 sites. Each site contains 3 replicas, for a total of 12 replicas. 

This supports one compromised replica, one proactive recovery, and one
site-disconnection simultaneously.

Site 1
------
Replica 1:  1.1.1.1
Replica 5:  1.1.1.2
Replica 9:  1.1.1.3

Site 2
------
Replica 2:  2.2.2.1
Replica 6:  2.2.2.2
Replica 10: 2.2.2.3

Site 3
------
Replica 3:  3.3.3.1
Replica 7:  3.3.3.2
Replica 11: 3.3.3.3

Site 4
------
Replica 4:  4.4.4.1
Replica 8:  4.4.4.2
Replica 12: 4.4.4.3

Each replica runs a SCADA Master and a Prime daemon. The first replica in each
site -- replicas 1 (1.1.1.1), 2 (2.2.2.1), 3 (3.3.3.1), and 4 (4.4.4.1) -- also
runs the internal and external Spines daemons for its site.

PLC/RTU Proxy: 5.5.5.5

The PLC/RTU proxy runs the proxies for all active PLCs and RTUs and the Spines
daemon on the external network that the proxies access the system through.
(Note that proxies may be distributed over multiple machines -- we just have
them all run on the same machine for simplicity in the default configuration)

Emulated PLCs are run on the same machine as their proxy.

HMI: 6.6.6.6

The HMI runs the HMI(s) for the system(s) being used and the Spines daemon on
the external network that the HMIs access the system through.
