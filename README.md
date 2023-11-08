# Spire: Intrusion-Tolerant SCADA for the Power grid

For more information, see [www.dsn.jhu.edu/spire/ ](https://www.dsn.jhu.edu/spire/)

---

## Contents:
1. Power Grid Control Systems Architecture
2. Spire Components Overview
    1. Spire
    2. Confidential Spire
    3. Spire for the Substation
3. Prerequisites Overview
4. Component Specific READMEs
5. Version Notes
6. Publications

---

## 1. Power Grid Control Systems Architecture:

Power grid SCADA consists of two levels: a control center level and a
substation level. 

The control-center SCADA monitors and controls many substations and Remote
Terminal Units (RTUs) and/or Programmable Logic Controllers (PLCs). The control-center-level operations typically have a latency requirement of 100ms-200ms. The
substation-level critical protection operations have latency requirements as
low as a quarter-power cycle (For 60Hz, this is 4.167ms). 

We have developed Spire as a toolkit that contains modules to support
intrusion-tolerance for power grid control systems at both the control-center
and substation levels.

---

## 2. Spire Components Overview

Spire consists of three components: **Spire** and **Confidential Spire** for
intrusion-tolerant SCADA at the control-center level, and **Spire for the
Substation** at the substation level.

### Spire
        
Spire is an intrusion-tolerant SCADA system for the power grid. Spire is
designed to withstand attacks and compromises at both the system level and the
network level, while meeting the timeliness requirements of power grid
monitoring and control systems (on the order of 100-200ms update latency).  
        
The Spire system includes a SCADA Master and PLC/RTU proxy designed from
scratch to support intrusion tolerance, as well as several example HMIs based
on [pvbrowser](https://pvbrowser.de/pvbrowser/index.php). The SCADA Master is
replicated using the [Prime intrusion-tolerant replication
engine](http://www.dsn.jhu.edu/prime). Communication between Spire components
is protected using the [Spines intrusion-tolerant
network](http://www.spines.org). The Spire PLC/RTU proxy can interact with any
devices that use the Modbus or DNP3 communication protocols over IP. We use
[OpenPLC](http://www.openplcproject.com/) to emulate PLCs. Finally, it includes
a standalone Machine Learning-based Network Intrusion Detection System that is
built to work with Spire.

Additionally, Version 2.1 (currently in beta release) adds reconfiguration
support to Spire. Reconfiguration can be used to improve the operational
profile of a system. For example: With reconfiguration, if the current system
configuration (say configuration '6+6+6') becomes non-operational due to loss
of a control center and data center but at least one control center remains up,
the system can be reconfigured to that one control center (configuration '6')
and resume operations. It is also possible to reconfigure preemptively when
needed (e.g. if one control center becomes non-operational, it is better to
reconfigure the system to configuration '6' in the remaining control center).
The reconfiguration modules are implemented as part of the Prime replication
engine, and include a configuration network, configuration manager and
configuration agent. The details of the reconfiguration mechanism are in
`README_Spire.md` and README of Prime.

### Confidential Spire
        
Confidential Spire is an intrusion-tolerant SCADA system that provides the same
resilience guarantees as the base Spire. However, Confidential Spire enables
system operators to maintain strong confidentiality guarantees for potentially
sensitive or proprietary system data, while still leveraging commodity data
centers to support cost-effective network-attack resilience. In Confidential
Spire, only replicas hosted in the control centers execute SCADA logic and
process system updates. Data center replicas participate in the replication
protocol, but only process and store encrypted state and updates. No
application logic or unencrypted application data is exposed to the data center
replicas.

Confidential Spire consists of the same modules as Spire (modified to support
confidentiality). The main change is that Spire's SCADA master is replaced by
the Confidential SCADA Master, which additionally performs the needed
encryption/decryption of requests and state, along with generating threshold
signatures on encrypted contents to prove their validity to data center
replicas. 

### Spire for the Substation

Spire for the Substation is built to support the real-time Byzantine resilience
required for power grid substations. The system is designed to withstand both
system-level protective relay intrusions and network attacks on a substation
LAN, while meeting the stringent quarter-of-a-power-cycle latency requirement
(4.167ms).

The Spire for the Substation includes a Trip Master, Relay Proxy and Breaker
Proxy. Additionally, we provide emulated relays to simulate real substation
fault-free and faulty operating conditions. We support substation communication
protocol of IEC61850 using open-source libiec61850.

---

## 3. Prerequisites Overview

We briefly provide an overview of installation prerequisites. 

- OpenSSL development Package
- Lex and Yacc


Spire and Confidential Spire Specific:
- QT development package and webkit (for HMI modules)
- pvbrowser (for HMI modules,included into Spire)
- cmake (for Opendnp3)
- gcc and g++ version 8.3.1 or higher (for Opendnp3)
- Opendnp3 (for DNP3 supporti,included into Spire)
- OpenPLC (for emulated PLCs,included into Spire)

Spire for the Substation Specific:
- libiec61850 (for IEC61850 support,included into Spire)

The commands to install these packages are in the component specific readme
files (section 4)

Note: Because the base Spire and Confidential Spire share certain configuration
files and executables with compiled-in configuration parameters, we do not
currently support running both versions at the same time. To switch between
configurations, you will need to run `make clean` from the top-level Spire
directory, and then follow the instructions for the variant that you would like
to switch to. See the individual README files for additional details.

---

## 4. Component Specific READMEs

Each Spire module has its own independent 'README' file. The files are in
Spire's top-level directory.

Spire File: `README_Spire.md`
Confidential Spire: `README_Confidential_Spire.md`
Spire for the Substation: `README_Spire_Substation.md`
 
---

## 5. Version Notes

Spire 2.1 Beta adds reconfiguration support to Spire.

Spire 2.0 extends the Spire 1.3 to support real-time
Byzantine resilience of power grid substations. This release includes Spire for
the Substation code that successfully withstood a red-team attack conducted by
Sandia National Laboratories in an exercise at Pacific Northwest National
Laboratory (PNNL) in 2022. Furthermore, it includes Confidential Spire, a
system that enables data centers to support the needed resilience without
executing application logic or accessing unencrypted state. Spire for the
Substation is described in the paper "Real-Time Byzantine Resilience for Power
Grid Substations" published at [IEEE SRDS
2022](https://ieeexplore.ieee.org/document/9996955). Confidential Spire is
described in the paper "Toward Intrusion Tolerance as a Service:
Confidentiality in Partially Cloud-Based BFT Systems" published at [IEEE DSN
2021](https://ieeexplore.ieee.org/document/9505127).

Spire 1.3 updates Spire 1.2 to use OpenSSL 1.1.0. Additionally, an Machine
Learning-based Network Intrusion Detection Module is added to Spire.

Spire 1.2  updates Spire 1.1 to use Spines 5.4, fixing a bug in Spines that
could affect Spire in certain configurations. The Spire 1.1 release consists of
the version of the Spire code that was used in a test deployment with the
Hawaiian Electric Company from January 22 to February 1, 2018. This version of
the code was deployed using Prime 3.1 and Spines 5.3.

Spire 1.1 builds on the Spire 1.0 release, which consisted of the version of
the Spire code that successfully withstood a red-team attack conducted by
Sandia National Laboratories in an exercise at Pacific Northwest National
Laboratory (PNNL) from March 27 to April 7, 2017. Spire 1.0 was deployed using
Prime 3.0 and Spines 5.2.

---

## 6. Publications

Babay, Amy, Thomas Tantillo, Trevor Aron, Marco Platania, and Yair Amir. "Network-attack-resilient intrusion-tolerant SCADA for the power grid." In 2018 48th Annual IEEE/IFIP International Conference on Dependable Systems and Networks (DSN), pp. 255-266. IEEE, 2018.

Babay, Amy, John Schultz, Thomas Tantillo, Samuel Beckley, Eamon Jordan, Kevin Ruddell, Kevin Jordan, and Yair Amir. "Deploying intrusion-tolerant SCADA for the power grid." In 2019 49th Annual IEEE/IFIP International Conference on Dependable Systems and Networks (DSN), pp. 328-335. IEEE, 2019.

Khan, Maher, and Amy Babay. "Toward intrusion tolerance as a service: Confidentiality in partially cloud-based BFT systems." In 2021 51st Annual IEEE/IFIP International Conference on Dependable Systems and Networks (DSN), pp. 14-25. IEEE, 2021.

Bommareddy, Sahiti, Daniel Qian, Christopher Bonebrake, Paul Skare, and Yair Amir. "Real-time Byzantine resilience for power grid substations." In 2022 41st International Symposium on Reliable Distributed Systems (SRDS), pp. 213-224. IEEE, 2022.
