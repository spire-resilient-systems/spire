This configuration includes 4 control-center sites, each containing a single
replica.

This supports one compromised replica.

Site 1
------
Replica 1:  192.168.101.101

Site 2
------
Replica 2:  192.168.101.102

Site 3
------
Replica 3:  192.168.101.103

Site 4
------
Replica 4:  192.168.101.104

Each replica runs a SCADA Master, a Prime daemon, an internal Spines daemon,
and an external Spines daemon.

PLC/RTU Proxy: 192.168.101.107

The PLC/RTU proxy runs the proxies for all active PLCs and RTUs and the Spines
daemon on the external network that the proxies access the system through.
(Note that proxies may be distributed over multiple machines -- we just have
them all run on the same machine for simplicity in the default configuration)

Emulated PLCs are run on the same machine as their proxy.

HMI: 192.168.101.108

The HMI runs the HMI(s) for the system(s) being used and the Spines daemon on
the external network that the HMIs access the system through.
