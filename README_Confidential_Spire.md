# Confidential Spire: Confidential Intrusion-Tolerant SCADA for the Power grid

For more information see [www.dsn.jhu.edu/spire/](http://www.dsn.jhu.edu/spire/)

Confidential Spire was added to the open source release in Spire 2.0.

Note: Please note that this is README for the confidential variant of Spire at
control center level only. See `README_Spire.md` for information on running the
base variant, and `README_Spire_Substation.md` for information on running Spire
for the Substation.

---

## Contents
1. Confidential Spire Overview
2. Deployment Overview
3. Configuration
4. Installation Prerequisites
5. Building
6. Generating Keys
7. Running

---

## Confidential Spire Overview

Confidential Spire provides the same resilience and similar timeliness
requirements as Spire. However, application logic and data are only exposed to
servers hosted in the Control Centers. Additional offsite servers hosted in
Data Centers can support the needed resilience without executing application
logic or accessing unencrypted data.

Confidential Spire consists of the same modules as Spire (modified to support
confidentiality). The main change is that Spire's standard SCADA master is
replaced by the Confidential SCADA Master, which additionally performs the
needed encryption/decryption of requests and state, along with generating
threshold signatures on encrypted contents to prove their integrity. 

---

## Deployment Overview

A Confidential Spire deployment includes: Confidential SCADA Master replicas,
(Confidential) Prime daemons, Spines daemons, PLC/RTU proxies, real or emulated
PLCs and/or RTUs, and HMIs. These components can be distributed over multiple
sites connected by a wide-area network, over multiple logical sites within a
local-area network (with or without emulated wide-area latency) or as a single
site in a local-area network.

We deploy Confidential Spire with Confidential SCADA Master replicas
distributed across several (real or emulated) sites. For each Confidential
SCADA master replica, we also deploy a Prime daemon that the SCADA master
connects to. Each Confidential SCADA master is located on the same machine as
its Prime daemon and connects to it via IPC.

Communication in the system occurs over two Spines overlay networks: an
external network and an internal network. The external network is used for
communication between the Confidential SCADA Master replicas and the PLC/RTU
proxies and the HMIs. The internal network is used for communication among the
Confidential SCADA Master replicas (and their Prime daemons). External and
internal Spines daemons can be deployed on the same machines but use different
ports.

We distinguish between two types of sites that can contain Confidential SCADA
Master replicas: control centers and data centers. This is because power grid
control centers with full capabilities for controlling PLCs and RTUs are
generally expensive, and utility companies are unlikely to deploy more than
two. To support the desired resilience with only two control centers, we allow
additional sites to be added as data-center sites that do not control PLCs or
RTUs. In Confidential Spire, the data center replicas does not execute
application logic, nor have access to unencrypted data. A typical deployment
for Confidential Spire consists of 2 control centers with 4 replicas each, and
2 data centers with 3 replicas each.

In each site that contains Confidential SCADA Master replicas (including both
control centers and data centers), we typically deploy one Spines daemon that
participates in the internal network to connect the replicas in that site to
the other sites. In each control-center site, we additionally deploy a Spines
daemon that participates in the external network to connect the replicas in
that site to the proxies and HMIs.

In the normal flow of the system, there are two main types of events: HMI
commands and PLC/RTU updates. When an HMI command is initiated (e.g. a user
clicks a button to make a change), the command is sent to the control-center
Confidential SCADA Master replicas over the external Spines network. The
Confidential SCADA Master encrypts the request using symmetric encryption using
the same keys available to all control center replicas (data center replicas do
not have access to these keys). The control center replicas then coordinate
with each other in order to generate a threshold signature for this encrypted
request. Finally, the control center replicas pass the encrypted command (along
with the threshold signature) to their Prime daemons, which disseminate it to
the data-center Prime daemons and execute a Byzantine-fault-tolerant agreement
protocol to agree on the command. When the Prime daemons have agreed on the
command, they pass it back to their Confidential SCADA Masters. The data center
Confidential SCADA Master replicas simply stores the ordered encrypted command
(in case control center replicas need it to recover state in the future), while
the control center Confidential SCADA Master replicas unencrypts the ordered
encrypted command, execute a threshold signing procedure on the command (so
that the PLC/RTU proxy can verify that a sufficient number of replicas agreed
on the command by verifying a single signature on a single message). The
control-center Confidential SCADA Masters then send the threshold-signed
command to the PLC/RTU proxies. The proxies verify that the command has a valid
threshold signature and then pass it on to the PLC(s) or RTU(s). 

PLCs and RTUs are periodically polled by their proxies. When a proxy has new
PLC/RTU data, it sends the data to the control-center Confidential SCADA Master
replicas over the external Spines network to be agreed upon and sent to the
HMI. The HMI verifies the threshold signature on the update and updates its
display.

---

## Configuration

There are several configuration files relevant to the Confidential Spire system:

1. Main Confidential Spire configuration: `common/def.h`
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

We provide example configuration files for a typical Confidential Spire
Deployment in `example_conf/confidential_spire_conf_4+4+3+3`.

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
    * e.g. `yum install qt-devel epel-release qtwebkit-devel`, `apt-get install qt-sdk`

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

## Building Confidential Spire

Note: Because the base Spire and Confidential Spire share certain configuration
files and executables with compiled-in configuration parameters, we do not
currently support running both versions at the same time. To switch from a base
Spire configuration to a Confidential Spire configuration, first run `make
clean` from the top-level Spire directory, and then follow the instructions
below to build Confidential Spire.

1. Build pvbrowser, OpenPLC, dnp3, spines, prime (from top-level Spire directory):

        make libs
   
   Note: Select Y to build DNP3 and select "Blank" driver (1) to build emulated
   PLCs that run on Linux

2. Build Spire (from top-level Spire directory):

        make conf_spire

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

            cd prime/bin; ./gen_keys

    - This creates the following in `prime/bin/keys`:
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

    - Each Prime daemon should have access to its own private key and threshold
      crypto share (i.e. replica 1 should have keys `private_01.key` and
      `share0_1.pem`) and all public keys.
    - Note that Prime's `gen_keys` program currently generates SCADA Master
      threshold crypto shares as well (see below)
    - The keysizes can be set in Generate function in prime/src/openssl_rsa.c file.

3. Spire
    - To generate keys:

            cd scada_master; ./conf_gen_keys
    
    - The keysizes can be set in openssl defines section in the
      common/def.h file.

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
        - These keys are generated by the SCADA Master `conf_gen_keys` script.
          After `scada_master/conf_gen_keys` has been run, these key shares
          will be located in `scada_master/sm_keys`. The `scada_master/sm_keys`
          directory includes:
            - 1 public key used by PLC/RTU proxies and HMIs to verify threshold
              signatures (`pubkey_1.pem`)
            - `NUM_SERVERS` threshold crypto shares (e.g. `share0_1.pem`,
              `share1_1.pem`, ...)

    - Control-center SCADA Master replicas use shared symmetric encryption keys
      to encrypt data sent to the data center replicas.
        - These keys are also generated by the `conf_gen_keys` script and
          placed in the `scada_master/sm_keys` directory. They are named
          encrypt_key1.key and encrypt_key2.key and shared by all
          control-center SCADA Master replicas. 

    - Each SCADA master should have access to its own public-private key pair,
      its own threshold crypto share, all SCADA master public keys, the
      threshold crypto public key, and all client public keys
        - Each control-center replica should additionally have access to the
          two symmetric encryption keys. Data center replicas should not have
          access to encryption keys.

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
    
   To run (internal Spines network):

        cd spines/daemon; ./spines -p SPINES_INT_PORT -c spines_int.conf -I IP_ADDRESS

   To run (external Spines network):
    
        cd spines/daemon; ./spines -p SPINES_EXT_PORT -c spines_ext.conf -I IP_ADDRESS

   Note: These commands assume that the internal and external spines
   configuration files are located at `spines/daemon/spines_int.conf` and
   `spines/daemon/spines_ext.conf`, respectively

2. Run all SCADA masters

   To run (control center):

        cd scada_master; ./conf_scada_master id spines_int_ip:SPINES_INT_PORT spines_ext_ip:SPINES_EXT_PORT

   To run (data center):

        cd scada_master; ./conf_scada_master id spines_int_ip:SPINES_INT_PORT

   The `spines_int_ip` and `spines_ext_ip` should be the IP addresses of the
   internal and external Spines daemons this replica connects to. They should
   match addresses specified in `SPINES_INT_SITE_ADDRS` and
   `SPINES_EXT_SITE_ADDRS` in `common/def.h`.

   The `id` should be the ID of this replica, where IDs range from 1 to
   `NUM_SM`. The code assumes replicas are striped across sites; for example,
   for 14 replicas and 4 sites (of which 2 sites are control centers) we have:
    - `NUM_SM` = 14, `NUM_SITES` = 4, `NUM_CC` = 2
    - Site 1 (control center): Replicas 1, 5, 9,  13
    - Site 2 (control center): Replicas 2, 6, 10, 14
    - Site 3 (data center):    Replicas 3, 7, 11
    - Site 4 (data center):    Replicas 4, 8, 12

3. Run all Prime daemons

   To run:

        cd prime/bin; ./conf_prime -i id

   The `id` of a Prime daemon must match the id of the SCADA Master that
   connects to it (and is running on the same machine as it).

   Prime uses its configuration files to find the location of the internal
   Spines daemon to connect to (see Prime documentation).

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

6. (Optional) Run OpenPLC PLCs

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

7. (Optional) Run Benchmark Clients

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

### (Optional) Setup Intrusion Detection System

The Intrusion Detection was built as a standalone component. See inside the `ids` folder for details
on setup and running.

### Example

The default configuration files included with Spire create a system with:

- 2 control-center sites, each consisting of a single machine that runs the
  following processes:
    - 1 external Spines daemon
    - 1 internal Spines daemon
    - 4 Confidential SCADA Masters
    - 4 Prime daemons
- 2 data-center sites, each consisting of a single machine that runs the
  following processes:
    - 1 external Spines daemon
    - 1 internal Spines daemon
    - 3 Confidential SCADA Masters
    - 3 Prime daemons
- 1 site with a single machine running the PLC/RTU proxy + 17 emulated PLCs (10
  for the `jhu` system, 1 for the `pnnl/heco` system, and 6 for the `ems`
  system)
- 1 site with a single machine running 3 HMIs (1 `jhu_hmi`, 1 `pnnl_hmi` or one
  of the `heco` HMIs, and 1 `ems_hmi`)

Note that in a real deployment, each of the Confidential SCADA Master + Prime
replicas would typically be deployed on a separate physical machine. However,
this configuration is useful for testing the system and benchmarking with a
limited number of machines.

To run this example, execute the following:

* Note that you will need to adjust IP addresses in the configuration files and
  commands to match your environment. The instructions below assume the
  following IP addresses:
    - Control Center 1 machine: 192.168.101.101
    - Control Center 2 machine: 192.168.101.102
    - Data Center 1 machine:    192.168.101.103
    - Data Center 2 machine:    192.168.101.104
    - PLC/RTU proxy machine:    192.168.101.105
    - HMI machine:              192.168.101.106

- On control center 1 machine:

        cd spines/daemon; ./spines -p 8100 -c spines_int.conf
        cd spines/daemon; ./spines -p 8120 -c spines_ext.conf
        cd scada_master; ./conf_scada_master 1 192.168.101.101:8100 192.168.101.101:8120
        cd scada_master; ./conf_scada_master 5 192.168.101.101:8100 192.168.101.101:8120
        cd scada_master; ./conf_scada_master 9 192.168.101.101:8100 192.168.101.101:8120
        cd scada_master; ./conf_scada_master 13 192.168.101.101:8100 192.168.101.101:8120
        cd prime/bin; ./conf_prime -i 1
        cd prime/bin; ./conf_prime -i 5
        cd prime/bin; ./conf_prime -i 9
        cd prime/bin; ./conf_prime -i 13

- On control center 2 machine:

        cd spines/daemon; ./spines -p 8100 -c spines_int.conf
        cd spines/daemon; ./spines -p 8120 -c spines_ext.conf
        cd scada_master; ./conf_scada_master 2 192.168.101.102:8100 192.168.101.102:8120
        cd scada_master; ./conf_scada_master 6 192.168.101.102:8100 192.168.101.102:8120
        cd scada_master; ./conf_scada_master 10 192.168.101.102:8100 192.168.101.102:8120
        cd scada_master; ./conf_scada_master 14 192.168.101.102:8100 192.168.101.102:8120
        cd prime/bin; ./conf_prime -i 2
        cd prime/bin; ./conf_prime -i 6
        cd prime/bin; ./conf_prime -i 10
        cd prime/bin; ./conf_prime -i 14

- On data center 1 machine:

        cd spines/daemon; ./spines -p 8100 -c spines_int.conf
        cd scada_master; ./conf_scada_master 3 192.168.101.103:8100
        cd scada_master; ./conf_scada_master 7 192.168.101.103:8100
        cd scada_master; ./conf_scada_master 11 192.168.101.103:8100
        cd prime/bin; ./conf_prime -i 3
        cd prime/bin; ./conf_prime -i 7
        cd prime/bin; ./conf_prime -i 11

- On data center 2 machine:

        cd spines/daemon; ./spines -p 8100 -c spines_int.conf
        cd scada_master; ./conf_scada_master 4 192.168.101.104:8100
        cd scada_master; ./conf_scada_master 8 192.168.101.104:8100
        cd scada_master; ./conf_scada_master 12 192.168.101.104:8100
        cd prime/bin; ./conf_prime -i 4
        cd prime/bin; ./conf_prime -i 8
        cd prime/bin; ./conf_prime -i 12

- On the PLC/RTU proxy machine:

        cd spines/daemon; ./spines -p 8120 -c spines_ext.conf
        cd proxy; ./proxy 0 192.168.101.105:8120 1
        ...
        cd proxy; ./proxy 16 192.168.101.105:8120 1
        
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

- On the HMI machine:

        cd jhu_hmi; ./jhu_hmi 192.168.101.106:8120 -port=5051
        cd pnnl_hmi; ./pnnl_hmi 192.168.101.106:8120 -port=5052
        cd ems_hmi; ./ems_hmi 192.168.101.106:8120 -port=5053

        Connect GUIs by running the pvbrowser application (located in main pvb
        installation folder) three times. In one browser's address bar, type
        192.168.101.106:5051, in another type 192.168.101.106:5052, and in the
        last type 192.168.101.106:5053.

This corresponds to the `confidential_spire_conf_4+4+3+3` configuration in the `example_conf` directory.
See `example_conf/confidential_spire_conf_4+4+3+3/README.txt` for details.
