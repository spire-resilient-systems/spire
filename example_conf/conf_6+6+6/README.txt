This configuration includes 2 control-center sites and 1 data center sites, for
a total of 3 sites. Each site contains 6 replicas, for a total of 18 replicas. 

This supports one compromised replica, one proactive recovery, and one
site-disconnection simultaneously.

Site 1
------
Replica 1:   1.1.1.1
Replica 4:   1.1.1.2
Replica 7:   1.1.1.3
Replica 10:  1.1.1.4
Replica 13:  1.1.1.5
Replica 16:  1.1.1.6

Site 2
------
Replica 2:   2.2.2.1
Replica 5:   2.2.2.2
Replica 8:   2.2.2.3
Replica 11:  2.2.2.4
Replica 14:  2.2.2.5
Replica 17:  2.2.2.6

Site 3
------
Replica 3:   3.3.3.1
Replica 6:   3.3.3.2
Replica 9:   3.3.3.3
Replica 12:  3.3.3.4
Replica 15:  3.3.3.5
Replica 18:  3.3.3.6


Each replica runs a SCADA Master and a Prime daemon. The first replica in each
site -- replicas 1 (1.1.1.1), 2 (2.2.2.1), and 3 (3.3.3.1) -- also
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

Note: Each site's 6 replicas can be divided across multiple servers.
