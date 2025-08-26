This configuration demonstrates an end-to-end intrusion-tolerant system that
integrates Spire at the control center level with Spire for substations. It
includes 6 control-center replicas, all example PLCs supported by Spire, and 3
substations. This setup supports one compromised replica and one proactive
recovery simultaneously.

### Configuration Overview

Control Center:
- Configuration: `conf_6` (6 control-center sites, each with a single replica)
- Each site runs:
  - 1 SCADA Master
  - 1 Prime daemon
  - 1 internal Spines daemon
  - 1 external Spines daemon

Substations:
- 3 substations are included in this configuration.
- Each substation consists of:
  - 4 relay nodes
  - 1 breaker node
  - 1 substation HMI node
- Substation configuration files:
  - `common/ss17.conf` (Substation 17)
  - `common/ss18.conf` (Substation 18)
  - `common/ss19.conf` (Substation 19)

PLC/RTU Proxy:
- IP Address: `192.168.101.107`
- Runs proxies for all active PLCs and RTUs and the external Spines daemon.

HMI:
- IP Address: `192.168.101.108`
- Runs the HMI(s) for the system and the external Spines daemon.

### Instructions
1. Copy config files for both control center (from conf_6 folder) and substation
(from ss_conf_4) folder as directed in READMEs in those folders

2. Recompile the system:
 ```sh
   make clean
   make libs
   make
```
3.  Refer to README_Spire_Substation.md for detailed run instructions.

Run overview:
Run Spire in conf 6 for control center
Run all 10 Modbus/DNP3 PLCs
Run all 3 substations
Run the control center connectors
