# Spire: Intrusion-Tolerant SCADA for the Power grid

For more information see [www.dsn.jhu.edu/spire/](http://www.dsn.jhu.edu/spire/)

Note: Please note that this is README for the standard Spire at control center
level only. See `README_Confidential_Spire.md` for information on running the
confidential variant, and `README_Spire_Substation.md` for information on
running Spire for the Substation.

---

## Contents
1. Spire Overview
2. Deployment Overview
3. Configuration
4. Installation Prerequisites
5. Building
6. Generating Keys
7. Running

---

## Spire Overview

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
[OpenPLC](http://www.openplcproject.com/) to emulate PLCs. Additionally, there is
also an standalone Machine Learning-based Network Intrusion Detection System 
that is built to work with Spire.

Spire supports six different example SCADA systems:

- `jhu`: an example system we created to represent a power distribution system
  with 10 substations, each monitored and controlled by a different PLC or RTU
- `pnnl`: the exact system that was used in the red-team exercise at PNNL,
  where it monitored and controlled a real PLC provided by PNNL
- `heco_3breaker`: the system that was deployed at the Hawaiian Electric
  Company, monitoring and controlling a real PLC that controlled three physical
  breakers
- `heco_5breaker`: a system similar to `heco_3breaker` but including two
  additional breakers
- `heco_timing`: the system used at the Hawaiian Electric Company to measure
  the end-to-end response time of the system by flipping a breaker and
  measuring the time for the HMI to reflect the change
- `ems`: a system modeling an Energy Management System (EMS) that controls
  several different types of generators with different ramp-up rates and
  renewable energy sources that can be connected to the grid or deactivated

Spire's SCADA Master can support all of these systems; we provide a separate
HMI for each system. Note that because the `pnnl` and `heco` systems use the
same underlying infrastructure, only one of the `pnnl`, `heco_3breaker`,
`heco5_breaker`, and `heco_timing` systems can be run at once. However, any one
of these systems can be simultaneously run with both the `jhu` and `ems`
systems.

Spire also supports reconfiguration. A system administrator can initiate
reconfiguration by sending a reconfiguration command on the Configuration
Network using the provided Configuration Manager (see Deployment Overview).

---

## Deployment Overview

A Spire deployment includes: SCADA Master replicas, Prime 
daemons, Spines daemons, PLC/RTU proxies, real or emulated PLCs and/or RTUs, and HMIs. 
These components can be distributed over multiple sites connected by a wide-area
network, over multiple logical sites within a local-area network (with or
without emulated wide-area latency) or as a single site in a local-area
network. To support reconfiguration, we can optionally deploy a Configuration
Manager, Configuration Agents, and a Spines Configuration Network.

We typically deploy Spire with SCADA Master replicas distributed across several
sites. For each SCADA master replica, we also deploy a Prime daemon and 
Configuration Agent that the SCADA master connects to. Each SCADA master is 
located on the same machine as its Prime daemon and configuration agent
and connects to them via IPC.

Communication in the system occurs over three Spines overlay networks: an
external network, an internal network, and a (optional) configuration network.
The external network is used for communication between the SCADA Master
replicas and the PLC/RTU proxies and the HMIs. The internal network is used for
communication among the SCADA Master replicas (and their Prime daemons). The
Configuration Network is used to communicate the current valid configuration to
all SCADA Master replicas and client. The external, internal, and configuration
Spines daemons can all be deployed on the same machines but use different ports.

We distinguish between two types of sites that can contain SCADA Master
replicas: control centers and data centers. This is because power grid control
centers with full capabilities for controlling PLCs and RTUs are generally
expensive, and utility companies are unlikely to deploy more than two. To
support the desired resilience with only two control centers, we allow
additional sites to be added as data-center sites that do not control PLCs or
RTUs. When supporting reconfiguration, all sites run Configuration Spines
daemons and Configuration Agents.

In each site that contains SCADA Master replicas (including both control
centers and data centers), we typically deploy one Spines daemon that
participates in the internal network to connect the replicas in that site to
the other sites. In each control-center site, we additionally deploy a Spines
daemon that participates in the external network to connect the replicas in
that site to the proxies and HMIs.

In the normal flow of the system, there are two main types of events: HMI
commands and PLC/RTU updates. When an HMI command is initiated (e.g. a user
clicks a button to make a change), the command is sent to the control-center
SCADA Master replicas over the external Spines network. The SCADA Master
replicas pass the command to their Prime daemons, which disseminate it to the
data-center Prime daemons and execute a Byzantine-fault-tolerant agreement
protocol to agree on the command. When the Prime daemons have agreed on the
command, they pass it back to their SCADA Masters. The SCADA Masters then
execute a threshold signing procedure on the command (so that the PLC/RTU proxy
can verify that a sufficient number of replicas agreed on the command by
verifying a single signature on a single message). The control-center SCADA
Masters then send the threshold-signed command to the PLC/RTU proxies. The
proxies verify that the command has a valid threshold signature and then pass
it on to the PLC(s) or RTU(s). 

PLCs and RTUs are periodically polled by their proxies. When a proxy has new
PLC/RTU data, it sends the data to the control-center SCADA Master replicas
over the external Spines network to be agreed upon and sent to the HMI. The HMI
verifies the threshold signature on the update and updates its display.


During reconfiguration, the Configuration Manager issues a configuration
message on configuration network. Each Configuration Agent validates it and
then passes it to its local replica or PLC/RTU or HMI to adopt the new
configuration and resume normal flow of the system.

---

## Configuration

There are several configuration files relevant to the Spire system:

1. Main Spire configuration: `common/def.h`
    - See comments within the file for configuration parameters and
      descriptions.

2. PLC/RTU configuration: `config/config.json`
    - This file specifies the PLC/RTU Proxies and the PLCs and RTUs in the
      system. At the top, the total number of proxies in the SCADA system is
      specified. Each individual PLC/RTU proxy then has its own configuration
      settings, including a unique ID (starting at 0) and the protocols of the
      PLCs/RTUs this proxy will need to use (i.e., Modbus and/or DNP3). Then,
      the specification of the individual PLCs and RTUs under the control of
      each Proxy is listed. These settings include which scenario (JHU, PNNL,
      EMS) that device belongs to and then Modbus-specific and DNP3-specific
      settings, such as the IP address and Port on which to connect and the
      various field types and locations of the data stored in the PLC/RTU that
      is collected from equipment.
    - NOTE: the Modbus and DNP3 configuration settings for the PLCs/RTUs must
      match the specification of the real (or emulated) PLC/RTU devices in
      order to properly connect with, monitor, and control those devices.

3. Prime configuration files (`prime/src/def.h`, `prime/bin/address.config`,
   `prime/bin/spines_address.config`) -- see Prime documentation for details

4. Spines configuration (`spines/daemon/spines.conf`) -- see Spines
   documentation for details. Note that internal and external Spines networks
   may use different configuration files.

---

## Installation Prerequisites

### General Prerequisites

- OpenSSL development package
    * e.g. `yum install openssl-devel`, `apt-get install libssl-dev`

### Spines Prerequisites

- Lex and Yacc
	* e.g. `yum install flex byacc`, `apt-get install flex byacc`

### HMI Prerequisites

- QT development package and webkit
    * e.g. `yum install qt5-devel  qt5-qtwebkit-devel`, `apt-get install qt5-sdk`

- [pvbrowser](https://pvbrowser.de/pvbrowser/)
    * pvbrowser is packaged with Spire, located in the `pvb` directory.
    Building Spire (below) will build the pvbrowser.


    * Note that by default Spire looks for pvbrowser files in the `pvb` directory
      packaged with it. If you prefer to use a version of pvbrowser already
      installed on your system, you can modify the `PVB` variable in the
      Makefiles in the hmi directories to point to your installation (e.g.
      `/opt/pvb`)

### DNP3 Support Prerequisites

- cmake (e.g. `yum install cmake`, `apt-get install cmake`)

- gcc and g++ version 8.3.1 or higher

  Note that if your gcc/g++ >= 8.3.1 is not the default system gcc/g++, you will
  need to modify:
    1. The Makefile in the `dnp3` directory (set `CXX` and `CXXLIB` variables
       to point to your installation of g++ 8.3.1 or higher)
    2. The OpenPLC `build.sh` and `core/core-builders/dnp3_enabled/build_normal.sh`
       scripts. (a modified cmake command is provided in the former) 

- [Opendnp3](https://www.automatak.com/opendnp3)
    * Opendnp3 is included as a part of OpenPLC_v2 in the `OpenPLC_v2/dnp3`
      directory. It is built as a part of the build system for OpenPLC.

    * The provided build script installs opendnp3 libraries in
      `OpenPLC_v2/dnp3_build/install`. By default, Spire looks for opendnp3
      files in that directory. If you prefer to use a version of opendnp3
      already installed on your system, you can change the `DNP3_DIR` variable
      in the Makefile in the `dnp3` directory to point to your installation, as
      well as the `DNP3_DIR` variable in
      `OpenPLC_v2/core/core_builders/dnp3_enabled/build_normal.sh`.

### OpenPLC (optional, for PLC emulation/creation)

- [A (slightly modified) version of OpenPLC](https://github.com/dqian3/OpenPLC_v2.git)
  is packaged  with Spire in the `OpenPLC_v2` directory. 
  Building Spire (below) will build these components also.

  Select "Blank" driver (1) to build emulated PLCs that run on Linux

  Changes were made from the [main OpenPLC_v2 branch](https://github.com/thiagoralves/OpenPLC_v2)
  to build Opendnp3 locally and for CentOS-8

---

## Building Spire

Note: Because the base Spire and Confidential Spire share certain configuration
files and executables with compiled-in configuration parameters, we do not
currently support running both versions at the same time. To switch from a
Confidential Spire configuration to a base Spire configuration, first run `make
clean` from the top-level Spire directory, and then follow the instructions
below to build Spire.

1. Build pvbrowser, OpenPLC, dnp3, libiec61850, spines (from top-level Spire directory):

        make libs
   
   Note: Select Y to build DNP3 and select "Blank" driver (1) to build emulated PLCs that run on Linux

2. Build Spire, including SCADA Master, HMIs, PLCs, and Prime (from top-level Spire directory):

        make

### Building for Performance Benchmarks

If you are only conducting performance benchmarks of the core Spire system
(i.e. measuring how long it takes clients to get responses for updates
submitted to the SCADA Master), you can build only the Spines, Prime, SCADA
Master, and benchmark program components.

For that, you can use the command:

```
make core
```

Note that if you are switching from a Confidential Spire configuration, you
still need to run `make clean` before running `make core`.

---

## Generating Keys

All system entities use RSA keys to authenticate messages, so keys must be
generated before the system can run.

1. Spines
    - To generate keys:

            cd spines/daemon; ./gen_keys

    - This creates 10 public-private key pairs in `spines/daemon/keys` (if you
      have more than 10 Spines daemons, you can modify the for loop in the
      script to create more keys)

    - Each Spines daemon should have access to its own private key (i.e. the
      Spines daemon listed as host 1 in the spines.conf file should have the
      key private1.pem) and the public keys of all the Spines daemons.

    - The key size can be set in spines/daemon/gen_keys.sh

2. Prime
    - To generate keys:

            cd prime/bin; ./gen_keys; ./gen_tpm_keys.sh

    - The `gen_keys` command creates the following in `prime/bin/keys`:
       - `NUM_SERVERS` server public-private key pairs (with public keys
          `public_01.key`, `public_02.key`, ... and private keys
          `private_01.key`, `private_02.key`, ...)
        - `NUM_CLIENTS` (default 150) client public-private key pairs (e.g.
          `public_client_01.key`, `private_client_01.key`)
        - 1 public key used by Prime daemons to authenticate threshold-signed
          messages used in the Prime protocol (`pubkey_1.pem`)
        - `NUM_SERVERS` threshold crypto shares used to generate threshold
          signatures in the Prime protocol (`share0_1.pem`, `share1_1.pem`,
          ...)
        - The keysizes can be set in Generate function in prime/src/openssl_rsa.c file.
        - It also generates keys for configuration manager (public_config_mngr.key and
           private_config_mngr.key)
        - Each Prime daemon should have access to its own private key and threshold
          crypto share (i.e. replica 1 should have keys `private_01.key` and
          `share0_1.pem`) and all public keys (including configuration manager).
        - Note that Prime's `gen_keys` program currently generates SCADA Master
          threshold crypto shares as well (see below)
 
    - The `gen_tpm_keys.sh` command generates the following keys in `prime/bin/tpm_keys`:
        - `MAX_NUM_SERVERS` server public-private key pairs (with public keys
          `tpm_public1.key`, `tpm_public2.key`, ... and private keys
          `tpm_private1.key`, `tpm_private2.key`, ...)
        - These keys are used during reconfiguration. Note that these are
	  replacing the permanent hardware-based (TPM) keys. 
        - Each Prime daemon should have access to its own tpm_private key and 
	  public key pf configuration manager (public_config_mngr.key).
        - The Configurtion Manager should have access to its private key
           (private_config_mngr.key)  and tpm public keys of all replicas(tpm_publicX.key).

3. Spire
    - To generate keys:

            cd scada_master; ./gen_keys
    
    - The keysizes can be set in openssl defines section in common/def.h file.

    - Since we consider a SCADA Master + its co-located Prime daemon one
      "replica", each SCADA Master uses the same public-private key pair as its
      Prime daemon (e.g. SCADA Master 1 uses the key pair
      `prime/bin/keys/public_01.key`, `prime/bin/keys/private_01.key`).

    - PLC/RTU proxies and HMIs act as clients of Prime and use Prime client
      keys.
        - Proxies calculate their Prime client ID as `NUM_SM + 1 + ID`, where
          `ID` is the ID of the proxy and ranges from 0 to `NUM_RTU - 1` (so in
          a system with 4 replicas, proxy 0 should have the key pair
          `public_client_05.key`, `private_client_05.key`, proxy 1 should have
          `public_client_06.key`, `private_client_06.key`, etc.).
            * Note that benchmark clients (see "Running" section) use the same
              keys as a proxy with the same ID would
        - HMIs calculate their Prime client ID as `NUM_SM + 1 + MAX_EMU_RTU + ID`,
          where `ID` is 1 for the `jhu_hmi`, 2 for the
          `pnnl_hmi`/`heco_3breaker`/`heco_5breaker`/`heco_timing` HMIs, and 3
          for the `ems_hmi`. `MAX_EMU_RTU` is 100 by default. In a system with
          4 replicas, the `jhu_hmi` would have `public_client_105.key` and
          `private_client_105.key`, and the `pnnl_hmi` would have
          `public_client_106.key`, `private_client_106.key`.

    - SCADA Master replicas execute a separate threshold-signing protocol
      outside of Prime to create threshold signatures that PLC/RTU proxies and
      HMIs can use to verify that the updates/commands they receive were agreed
      upon by enough replicas. For this, the SCADA Masters use their own set of
      threshold crypto shares.
        - These keys are generated by the SCADA Master `gen_keys` script. After
          `scada_master/gen_keys` has been run, these key shares will be located in
          `scada_master/sm_keys`. The `scada_master/sm_keys` directory includes:
            - 1 public key used by PLC/RTU proxies and HMIs to verify threshold
              signatures (`pubkey_1.pem`)
            - `NUM_SERVERS` threshold crypto shares (e.g. `share0_1.pem`,
              `share1_1.pem`, ...)

    - Each SCADA master should have access to its own public-private key pair,
      its own threshold crypto share, all SCADA master public keys, the
      threshold crypto public key, and all client public keys

    - Each PLC/RTU proxy and HMI should have access to its own public-private
      key pair and all SCADA master and client public keys, and the threshold
      crypto public key.

---

## Running

Note that command line parameters in `ALL_CAPS` should match the corresponding
parameters in `common/def.h`

1. Run all Spines daemons (for both the internal and external Spines networks)

    - 1 internal Spines daemon per site containing SCADA master replicas
    - 1 external Spines daemon per control-center site
    - 1 external Spines daemon for PLC/RTU proxies to connect to
    - 1 external Spines daemon for HMI to connect to (can be the same as the
      one the proxies connect to)
    - 1 configuration Spines daemon per site, for PLC/RTU and HMI.
    
   To run (internal Spines network):

        cd spines/daemon; ./spines -p SPINES_INT_PORT -c spines_int.conf -I IP_ADDRESS

   To run (external Spines network):
    
        cd spines/daemon; ./spines -p SPINES_EXT_PORT -c spines_ext.conf -I IP_ADDRESS

   To run (configuration Spines network):

        cd spines/daemon; ./spines -p SPINES_CTRL_PORT -c spines_ctrl.conf -I IP_ADDRESS

   Note: These commands assume that the configuration, internal and external spines
   configuration files are located at`spines/daemon/spines_ctrl.conf`,
    `spines/daemon/spines_int.conf` and `spines/daemon/spines_ext.conf`, respectively


2. Run all SCADA masters

   To run (control center):

        cd scada_master; ./scada_master global_id current_id spines_int_ip:SPINES_INT_PORT spines_ext_ip:SPINES_EXT_PORT

   To run (data center):

        cd scada_master; ./scada_master global_id current_id spines_int_ip:SPINES_INT_PORT

   The `spines_int_ip` and `spines_ext_ip` should be the IP addresses of the
   internal and external Spines daemons this replica connects to. They should
   match addresses specified in `SPINES_INT_SITE_ADDRS` and
   `SPINES_EXT_SITE_ADDRS` in `common/def.h`.

   The `global_id` is the SCADA Master's global ID and ranges from 1 to
   `MAX_NUM_SERVERS`. Each SCADA Master communicates with Prime using IPC and
   the IPC PATH uses this global id. So, each SCADA Master and its
   corresponding Prime daemon with the same `global_id` should be run on same
   machine. 

   The `current_id` should be the current local ID of this replica.
   The `current_id` IDs range from 1 to `NUM_SM`. It changes as configurations vary.
 
   The code assumes replicas are striped across sites; for example,
   for 12 replicas and 4 sites (of which 2 sites are control centers) we have:
    - `NUM_SM` = 12, `NUM_SITES` = 4, `NUM_CC` = 2
    - Site 1 (control center): Replicas 1, 5, 9
    - Site 2 (control center): Replicas 2, 6, 10
    - Site 3 (data center):    Replicas 3, 7, 11
    - Site 4 (data center):    Replicas 4, 8, 12

3. Run all Prime daemons

   To run:

        cd prime/bin; ./prime -i id -g global_id

   The `global_id` of a Prime daemon must match the `global_id` of the SCADA Master that
   connects to it (and is running on the same machine as it).

   The `id` should match `current_id` of the scada_master. This is used to represent
   the ID of the replica in the current configuration and can vary with
   configurations (e.g. it may change after reconfiguration).
 

4. Run PLC/RTU proxies

   To run:

        cd proxy; ./proxy id SPINES_RTU_ADDR:SPINES_EXT_PORT 1

   The `id` should be the ID of this proxy, where IDs range from 0 to
   `NUM_RTU - 1`. This ID is also used to look up information about the PLC/RTU
   in the `config.json` file.

5. Run the HMIs

   To run `jhu`:

        cd hmis/jhu_hmi; ./jhu_hmi SPINES_HMI_ADDR:SPINES_EXT_PORT -port=pv_port_jhu

   To run `pnnl`:

        cd hmis/pnnl_hmi; ./pnnl_hmi SPINES_HMI_ADDR:SPINES_EXT_PORT -port=pv_port_pnnl

   To run `ems`:

        cd hmis/ems_hmi; ./ems_hmi SPINES_HMI_ADDR:SPINES_EXT_PORT -port=pv_port_ems

   `pv_port_*` is the port on which the HMI will accept pvbrowser connections
   to interface with the GUI that reflects the current power grid state and
   allows a human operator to enter commands.

   To connect GUI: Run `pvbrowser` application (located in main `pvb`
   installation folder). In the browser's address bar, give the IP address of
   the HMI and the `pv_port` (e.g. 192.168.101.108:5050).

6. (Optional) Run Configuration Manager and Agents (from `/prime/bin` directory)
   These components are used to support reconfiguration.

   Run a Configuration Agent on each SCADA Master Node, HMI Node, RTU/PLC Node:

   On SCADA Master Node:

        ./config_agent id IP_of_config_spines /tmp/sm_ipc_main s count sm_id_1 sm_id_2 .... sm_id_n

   On RTU/PLC Node:

   - If Benchmarks are run:

        `./config_agent id IP_of_config_spines /tmp/bm_ipc_main p count`

   - If Proxies are run:

        `./config_agent id IP_of_config_spines /tmp/rtu_ipc_main p count`

   On HMI Node:

        ./config_agent id IP_of_config_spines /tmp/hm_ipc_main p count

   - `id` is the configuration agent ID. You should give each configuration
     agent a unique ID, starting from 1, up to the total number of SCADA
     Master, RTU/PLC, and HMI agents.
   - `IP_of_config_spines` is the IP address of control spines deamon to connect to.
   - The `s` or `p` argument indicates the node type as SCADA Master
     (`s`) or benchmark, proxy or HMI (`p`)
   - `count` refers to number of processes running on the node. For example:
        - If there is one SCADA Master (say with `global_id` 5) running on a
          node we can start config agent as:
                `./config_agent 5 /tmp/sm_ipc_main s 1 5`
        - However, if there are multiple SCADA Masters running on the node (say with `global_ids` 1,4,7)
          the we run config agent on that node as:
                `./config_agent 1 /tmp/sm_ipc_main s 3 1 4 7`
        - Similarly, if there are 10 benchmarks or proxies on the node we run
          config agents with `count` as 10
    - The hmi_ids are: 1 for JHU, 2 for PNNL and 3 for EMS scenario (defined in `common/scada_packets.h`). 
      So, count 3 can be used for all 3 scenarios.	

    Run Configuration Manager:

        ./config_manager configuration_dir_path

	- We typically run the Configuration Manager on same node as HMIs and its IP is define in `prime/src/def.h`.
        - The `configuration_dir_path` refers to a directory with two files
          (`conf_def.txt` and `new_conf.txt`) that are used to generate new configuraions.
        - Examples of these files for configs 6+6+6, 6, and 6-6 are provided in
          the `prime/bin` directory.

7. (Optional) Run OpenPLC PLCs

        cd plcs/pnnl_plc; sudo ./openplc -m 502 -d 20000

        cd plcs/jhu0; sudo ./openplc -m 503 -d 20001
        ...
        cd plcs/jhu9; sudo ./openplc -m 512 -d 20010

        cd plcs/ems0; sudo ./openplc -m 513 -d 20011
        cd plcs/ems1; sudo ./openplc -m 514 -d 20012
        cd plcs/ems2; sudo ./openplc -m 515 -d 20013
        cd plcs/ems_hydro; sudo ./openplc -m 516 -d 20014
        cd plcs/ems_solar; sudo ./openplc -m 517 -d 20015
        cd plcs/ems_wind; sudo ./openplc -m 518 -d 20016

   Note: the -m option is the Modbus port, and -d option is the DNP3 port.
   These should match what is specified in the config.json file for each PLC.

   See the [OpenPLC
   documentation](http://www.openplcproject.com/plcopen-editor) for
   instructions on creating your own PLCs

8. (Optional) Run Benchmark Clients

   We also provide a benchmark client that can be used to test and measure the
   core of the system without running an HMI, PLC/RTU proxies, or PLCs/RTUs.
   The benchmark client submits updates to the system. The SCADA Masters agree
   on each of these updates just like they would for a normal PLC/RTU update
   and then send a response back to the benchmark client. The benchmark client
   calculates and prints the latency for processing each update (measured from
   the time it creates the update to the time it receives the corresponding
   response).

   To run:

        cd benchmark; ./benchmark id SPINES_RTU_ADDR:SPINES_EXT_PORT poll_frequency(usec) num_polls

   The benchmark client will send an update every `poll_frequency` microseconds
   and will exit after completing `num_polls` updates. Benchmark client ids
   range from 0 to `NUM_RTU - 1`.

9. (Optional) Setup Intrusion Detection System

   The Intrusion Detection was built as a standalone component. See inside the
   `ids` folder for details on setup and running.

### Example

The default configuration files included with Spire create a system with:

- 6 control-center sites, each consisting of a single machine that runs the
  following six processes:
    - 1 external Spines daemon
    - 1 internal Spines daemon
    - 1 configuration Spines daemon
    - 1 SCADA Master
    - 1 Prime daemon
    - 1 Configuration Agent
- 1 site with a single machine running the PLC/RTU proxy + 17 emulated PLCs (10
  for the `jhu` system, 1 for the `pnnl/heco` system, and 6 for the `ems`
  system)
- 1 site with a single machine running 3 HMIs (1 `jhu_hmi`, 1 `pnnl_hmi` or one
  of the `heco` HMIs, and 1 `ems_hmi`)

To run this example, execute the following:

* Note that you will need to adjust IP addresses in the configuration files and
  commands to match your environment. The instructions below assume the
  following IP addresses:
    - Control center 1 machine: 192.168.101.101
    - Control center 2 machine: 192.168.101.102
    - Control center 3 machine: 192.168.101.103
    - Control center 4 machine: 192.168.101.104
    - Control center 5 machine: 192.168.101.105
    - Control center 6 machine: 192.168.101.106
    - PLC/RTU proxy machine:    192.168.101.107
    - HMI machine:              192.168.101.108

- On control center 1 machine:

        cd spines/daemon; ./spines -p 8900 -c spines_ctrl.conf
        cd spines/daemon; ./spines -p 8100 -c spines_int.conf
        cd spines/daemon; ./spines -p 8120 -c spines_ext.conf
        cd scada_master; ./scada_master 1 1 192.168.101.101:8100 192.168.101.101:8120
        cd prime/bin; ./prime -i 1 -g 1
        cd prime/bin;./config_agent 1 192.168.101.101 /tmp/sm_ipc_main s 1 1

- On control center 2 machine:

        cd spines/daemon; ./spines -p 8900 -c spines_ctrl.conf
        cd spines/daemon; ./spines -p 8100 -c spines_int.conf
        cd spines/daemon; ./spines -p 8120 -c spines_ext.conf
        cd scada_master; ./scada_master 2 2 192.168.101.102:8100 192.168.101.102:8120
        cd prime/bin; ./prime -i 2 -g 2
        cd prime/bin;./config_agent 2 192.168.101.102 /tmp/sm_ipc_main s 1 2

- On control center 3 machine:

        cd spines/daemon; ./spines -p 8900 -c spines_ctrl.conf
        cd spines/daemon; ./spines -p 8100 -c spines_int.conf
        cd spines/daemon; ./spines -p 8120 -c spines_ext.conf
        cd scada_master; ./scada_master 3 3 192.168.101.103:8100 192.168.101.103:8120
        cd prime/bin; ./prime -i 3 -g 3
        cd prime/bin;./config_agent 3 192.168.101.103 /tmp/sm_ipc_main s 1 3

- On control center 4 machine:

        cd spines/daemon; ./spines -p 8900 -c spines_ctrl.conf
        cd spines/daemon; ./spines -p 8100 -c spines_int.conf
        cd spines/daemon; ./spines -p 8120 -c spines_ext.conf
        cd scada_master; ./scada_master 4 4 192.168.101.104:8100 192.168.101.104:8120
        cd prime/bin; ./prime -i 4 -g 4
        cd prime/bin;./config_agent 4 192.168.101.104 /tmp/sm_ipc_main s 1 4

- On control center 5 machine:

        cd spines/daemon; ./spines -p 8900 -c spines_ctrl.conf
        cd spines/daemon; ./spines -p 8100 -c spines_int.conf
        cd spines/daemon; ./spines -p 8120 -c spines_ext.conf
        cd scada_master; ./scada_master 5 5 192.168.101.105:8100 192.168.101.105:8120
        cd prime/bin; ./prime -i 5 -g 5
        cd prime/bin;./config_agent 5 192.168.101.105 /tmp/sm_ipc_main s 1 5

- On control center 6 machine:

        cd spines/daemon; ./spines -p 8900 -c spines_ctrl.conf
        cd spines/daemon; ./spines -p 8100 -c spines_int.conf
        cd spines/daemon; ./spines -p 8120 -c spines_ext.conf
        cd scada_master; ./scada_master 6 6 192.168.101.106:8100 192.168.101.106:8120
        cd prime/bin; ./prime -i 6 -g 6
        cd prime/bin;./config_agent 6 192.168.101.106 /tmp/sm_ipc_main s 1 6

- On the PLC/RTU proxy machine:

        cd spines/daemon; ./spines -p 8900 -c spines_ctrl.conf
        cd spines/daemon; ./spines -p 8120 -c spines_ext.conf
        cd proxy; ./proxy 0 192.168.101.107:8120 1
        ...
        cd proxy; ./proxy 16 192.168.101.107:8120 1
        
        cd plcs/jhu0; sudo ./openplc -m 503 -d 20001
        cd plcs/jhu1; sudo ./openplc -m 504 -d 20002
        ...
        cd plcs/jhu9; sudo ./openplc -m 512 -d 20010
        cd plcs/pnnl_plc; sudo ./openplc -m 502 -d 20000
        cd plcs/ems0; sudo ./openplc -m 513 -d 20011
        cd plcs/ems1; sudo ./openplc -m 514 -d 20012
        cd plcs/ems2; sudo ./openplc -m 515 -d 20013
        cd plcs/ems_hydro; sudo ./openplc -m 516 -d 20014
        cd plcs/ems_solar; sudo ./openplc -m 517 -d 20015
        cd plcs/ems_wind; sudo ./openplc -m 518 -d 20016
        cd prime/bin;./config_agent 7 192.168.101.107 /tmp/rtu_ipc_main p 10

- On the HMI machine:

        cd spines/daemon; ./spines -p 8900 -c spines_ctrl.conf
        cd spines/daemon; ./spines -p 8120 -c spines_ext.conf
        cd jhu_hmi; ./jhu_hmi 192.168.101.108:8120 -port=5051
        cd pnnl_hmi; ./pnnl_hmi 192.168.101.108:8120 -port=5052
        cd ems_hmi; ./ems_hmi 192.168.101.108:8120 -port=5053
        cd prime/bin;./config_agent 8 192.168.101.108 /tmp/hmi_ipc_main p 3

    Connect GUIs by running the pvbrowser application (located in main pvb
    installation folder) three times. In one browser's address bar, type
    `192.168.101.108:5051`, in another type `192.168.101.108:5052`, and in the
    last type `192.168.101.108:5053`.

	This corresponds to the `conf_6` configuration (default) in the `example_conf` directory.
	Three additional example configurations are provided in that directory: `conf_4`
	(4 replicas), `conf_3+3+3+3` (12 replicas divided across 4 sites) and `conf_6+6+6` 
        (18 relicas across 3 sites). See `example_conf/README.txt` for details.

- To perform a simple benchmark, instead of running PLCs/RTUs and HMIs as
  described above, you can run on the PLC/RTU proxy machine:

        cd spines/daemon; ./spines -p 8900 -c spines_ctrl.conf
        cd spines/daemon; ./spines -p 8120 -c spines_ext.conf
        cd benchmark; ./benchmark 1 192.168.101.107:8120 1000000 500

- To perform reconfiguration, you can use the Configuration Manager with the
  following commands on the HMI Machine (from prime/bin directory):

    To change to config 6+6+6:

        cd prime/bin;./config_manager conf_666

    To change to config 6 (CC1):

        cd prime/bin;./config_manager conf_6

    To change to config 6(CC2):

        cd prime/bin;./config_manager 2cc_conf_6


    The `conf_666`, `conf_6` and `2cc_conf_6` are directories with the relevant
    configurations. Examples of these are provided in the
    `prime/bin` directory. Note that the IPs, Ports and ID in
    `new_conf.txt` file of these directories need to be modified to match the
    testbed.

    A simpler example of reconfiguration within a single site is also
    available. If you run the example `conf_6` as the initial configuration, as
    described above, you can reconfigure to the (less resilient) `conf_4`:

        cd prime/bin;./config_manager conf_4

    To return to the original `conf_6`, you can do:

        cd prime/bin;./config_manager conf_6_v2
