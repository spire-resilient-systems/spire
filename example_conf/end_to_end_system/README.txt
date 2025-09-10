This configuration demonstrates an end-to-end intrusion-tolerant system that
integrates Spire at the control center level with Spire for the Substation. It
includes 6 control-center replicas, all example PLCs supported by Spire, and 3
substations(ss17,ss18,ss19). It can be visualized and demonstrated with HMIs at
control center (cc_hmi) and three substation HMIs(ss1_hmi, ss2_hmi, and ss3_hmi).


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
- Runs proxies for all active PLCs and RTUs and the external Spines daemon.
- Run at IP address defined as `SPINES_RTU_ADDR` in `common/def.h`

Control Center Connectors:
- Run at IP address defined as `CC_CONNECTORS` in `common/def.h`

HMIs:
- control center HMI: run at `SPINES_HMI_ADDR` of `common/def.h` 
- Each substation has HMI defined in their respective conf file 


### Instructions
1. Run ./install_conf.sh end_to_end_system

This will install all the needed conf files correctly

2. Recompile the system:
 ```sh
   make clean
   make libs
   make
   make substation
```
3.  Refer to README_Spire_Substation.md for detailed run instructions.

Run overview:
Run Spire processes  in each of 6 control center sites (Spines ext, Spines int, Prime and SCADA Master)
Run all 10 Modbus/DNP3 PLCs
Run all 3 substations 
Run the control center connectors
Run all HMIs
