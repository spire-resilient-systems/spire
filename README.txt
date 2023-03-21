*************************************
* Contents:
*    Spire Overview
*    Deployment Overview
*    Configuration
*    Installation Prerequisites
*    Building
*    Generating Keys
*    Running
*************************************

******************
* Spire Overview *
******************

Spire is an intrusion-tolerant SCADA system for the power grid. Spire is
designed to withstand attacks and compromises at both the system level and the
network level, while meeting the timeliness requirements of power grid
monitoring and control systems (on the order of 100-200ms update latency).

The Spire system includes a SCADA Master and PLC/RTU proxy designed from
scratch to support intrusion tolerance, as well as two example HMIs based on
pvbrowser (https://pvbrowser.de/pvbrowser/index.php). The SCADA Master is
replicated using the Prime intrusion-tolerant replication engine
(www.dsn.jhu.edu/prime). Communication between Spire components is protected
using the Spines intrusion-tolerant network (www.spines.org). The Spire PLC/RTU
proxy can interact with any devices that use the Modbus or DNP3 communication
protocols over IP. We use OpenPLC (http://www.openplcproject.com/) to emulate
PLCs.

The Spire 1.0 release consists of the version of the Spire code that
successfully withstood a red-team attack conducted by Sandia National
Laboratories in an exercise at Pacific Northwest National Laboratory (PNNL)
from March 27 to April 7, 2017. This version of the code was deployed using
Prime 3.0 and Spines 5.2.

Spire 1.0 includes support for two example SCADA systems, which are referred to
as the "jhu" and "pnnl" systems in the code. The "pnnl" system is the exact
system that was used in the red-team exercise, where it monitored and
controlled a real PLC provided by PNNL. The "jhu" system is an example system
we created to represent a power distribution system with 10 substations, each
monitored and controlled by a different PLC or RTU. The SCADA Master of Spire
1.0 can support both systems simultaneously; we provide a separate HMI for each
system.

***********************
* Deployment Overview *
***********************

A Spire deployment includes: SCADA Master replicas, Prime daemons, Spines
daemons, PLC/RTU proxies, real or emulated PLCs and/or RTUs, and HMIs. These
components can be distributed over multiple sites connected by a wide-area
network, over multiple logical sites within a local-area network (with or
without emulated wide-area latency) or as a single site in a local-area
network.

We typically deploy Spire with SCADA Master replicas distributed across several
sites. For each SCADA master replica, we also deploy a Prime daemon that the
SCADA master connects to. Each SCADA master is located on the same machine as
its Prime daemon and connects to it via IPC.

Communication in the system occurs over two Spines overlay networks: an
external network and an internal network. The external network is used for
communication between the SCADA Master replicas and the PLC/RTU proxies and the
HMIs. The internal network is used for communication among the SCADA Master
replicas (and their Prime daemons). External and internal Spines daemons can be
deployed on the same machines but use different ports.

We distinguish between two types of sites that can contain SCADA Master
replicas: control centers and data centers. This is because power grid control
centers with full capabilities for controlling PLCs and RTUs are generally
expensive, and utility companies are unlikely to deploy more than two. To
support the desired resilience with only two control centers, we allow
additional sites to be added as data-center sites that do not control PLCs or
RTUs.

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
PLC/RTU data, it similarly sends the data to the control-center SCADA Master
replicas over the external Spines network to be agreed upon and sent to the
HMI. The HMI verifies the threshold signature on the update and updates its
display.

*****************
* Configuration *
*****************

There are several configuration files relevant to the Spire system:

1. Main Spire configuration: common/def.h
    - See comments within the file for configuration parameters and
      descriptions.

2. PLC/RTU configuration: config/config.json
    - This file specifies the PLC/RTU Proxies and the PLCs and RTUs in the
      system. At the top, the total number of proxies in the SCADA system is
      specified. Each individual PLC/RTU proxy then has its own configuration
      settings, including a unique ID (starting at 0) and the protocols of the
      PLCs/RTUs this proxy will need to use (i.e., Modbus and/or DNP3). Then,
      the specification of the individual PLCs and RTUs under the control of
      each Proxy is listed. These settings include which scenario (JHU, PNNL)
      that device belongs to and then Modbus-specific and DNP3-specific
      settings, such as the IP address and Port on which to connect with and
      the various field types and locations of the data stored in the PLC/RTU
      that is collected from equipment.
    - NOTE: the Modbus and DNP3 configuration settings for the PLCs/RTUs must
      match the specification of the real (or emulated) PLC/RTU devices in
      order to properly connect with, monitor, and control those devices.

3. Prime configuration files (prime/src/def.h, prime/bin/address.config,
   prime/bin/spines_address.config) -- see Prime documentation for details

4. Spines configuration (spines/daemon/spines.conf) -- see Spines documentation
   for details. Note that internal and external Spines networks may
   use different configuration files.

******************************
* Installation Prerequisites *
******************************

---------------------
General Prerequisites
---------------------

- OpenSSL development package
    * e.g. yum install openssl-devel, apt-get install libssl-dev

--------------------
Spines Prerequisites
--------------------

- Lex and Yacc
	* e.g. yum install flex byacc, apt-get install flex byacc

------------------
HMI Prerequisites
------------------

- pvbrowser (pvb.tar.gz)
    * follow the instructions here: https://pvbrowser.de/pvbrowser/index.php?lang=en&menu=6
- pvbaddon (pvbaddon.tar.gz)
    * follow the instructions here: https://pvbrowser.de/pvbrowser/index.php?lang=en&menu=6&left=9

--------------------------
DNP3 Support Prerequisites
--------------------------

- cmake (e.g. yum install cmake, apt-get install cmake)
- gcc and g++ 4.9 or higher
- Opendnp3
  * Steps that we used, see https://www.automatak.com/opendnp3/docs/guide/current/ for details
	mkdir dnp3;
	cd dnp3; sudo git clone --recursive https://github.com/automatak/dnp3.git
	mkdir dnp3_build; cd dnp3_build;
	cmake ../dnp3 -DSTATICLIBS=ON -DCMAKE_INSTALL_PREFIX=/usr
	make
	chmod -R o+w .
	sudo make install

----------------------------------------------
OpenPLC (optional, for PLC emulation/creation)
----------------------------------------------

git clone https://github.com/TrevorAron/OpenPLC_v2.git
cd OpenPLC_v2; ./build

* Note that the version of OpenPLC above with added DNP3 support will
  eventually be merged with the main OpenPLC branch
  (https://github.com/thiagoralves/OpenPLC_v2,
  main site: http://www.openplcproject.com/)


******************
* Building Spire *
******************

1. Build Spines (from top-level Spire directory):
   cd spines; ./configure; make -C daemon parser; make

2. Build Prime (from top-level Spire directory):
   make -C prime/src

3. Build Spire (from top-level Spire directory):
   make

*******************
* Generating Keys *
*******************

All system entities use RSA keys to authenticate messages, so keys must be
generated before the system can run.

1. Spines
    - To generate keys: cd spines/daemon; ./gen_keys
    - This creates 10 public-private key pairs in spines/daemon/keys (if you
      have more than 10 Spines daemons, you can modify the for loop in the
      script to create more keys)

    - Each Spines daemon should have access to its own private key (i.e. the
      Spines daemon listed as host 1 in the spines.conf file should have the
      key private1.pem) and the public keys of all the Spines daemons.

2. Prime
    - To generate keys: cd prime/bin; ./gen_keys
    - This creates the following in prime/bin/keys:
        - NUM_SERVERS server public-private key pairs (with public keys
          public_01.key, public_02.key, ... and private keys private_01.key,
          private_02.key, ...)
        - NUM_CLIENTS (default 150) client public-private key pairs (e.g.
          public_client_01.key, private_client_01.key)
        - 1 public key used by Prime daemons to authenticate threshold-signed
          messages used in the Prime protocol (pubkey_1.pem)
        - NUM_SERVERS threshold crypto shares used to generate threshold
          signatures in the Prime protocol (share0_1.pem, share1_1.pem, ...)

    - Each Prime daemon should have access to its own private key and threshold
      crypto share (i.e. replica 1 should have keys private_01.key and
      share0_1.pem) and all public keys.
    - Note that Prime's gen_keys program currently generates SCADA Master
      threshold crypto shares as well (see below)

3. Spire
    - Since we consider a SCADA Master + its co-located Prime daemon one
      "replica", each SCADA Master uses the same public-private key pair as its
      Prime daemon (e.g. SCADA Master 1 uses the key pair
      prime/bin/keys/public_01.key, prime/bin/keys/private_01.key).
    - PLC/RTU proxies and HMIs act as clients of Prime and use Prime client
      keys.
        - Proxies calculate their Prime client ID as (NUM_SM + 1 + ID), where
          ID is the ID of the proxy and ranges from 0 to (NUM_RTU - 1) (so in a
          system with 4 replicas, proxy 0 should have the key pair
          public_client_05.key, private_client_05.key, proxy 1 should have
          public_client_06.key, private_client_06.key, etc.).
            * Note that benchmark clients (see "Running" section) use the same
              keys as a proxy with the same ID would
        - HMIs calculate their Prime client ID as (NUM_SM + 1 + MAX_EMU_RTU +
          ID), where ID is 1 for the jhu_hmi and 2 for the pnnl_hmi.
          MAX_EMU_RTU is 100 by default. In a system with 4 replicas, the
          jhu_hmi would have public_client_105.key and private_client_105.key,
          and the pnnl_hmi would have public_client_106.key,
          private_client_106.key.

    - SCADA Master replicas execute a separate threshold-signing protocol
      outside of Prime to create threshold signatures that PLC/RTU proxies and
      HMIs can use to verify that the updates/commands they receive were agreed
      upon by enough replicas. For this, the SCADA Masters use their own set of
      threshold crypto shares.
        - These keys are currently generated by the Prime gen_keys script (but
          this functionality will likely be moved in a later release). After
          prime/bin/gen_keys has been run, these key shares will be located in
          prime/bin/sm_keys. The prime/bin/sm_keys directory includes:
            - 1 public key used by PLC/RTU proxies and HMIs to verify threshold
              signatures (pubkey_1.pem)
            - NUM_SERVERS threshold crypto shares (e.g. share0_1.pem,
              share1_1.pem, ...)

    - Each SCADA master should have access to its own public-private key pair,
      its own threshold crypto share, all SCADA master public keys, the
      threshold crypto public key, and all client public keys
    - Each PLC/RTU proxy and HMI should have access to its own public-private
      key pair and all SCADA master and client public keys, and the threshold
      crypto public key.

***********
* Running *
***********

* Note that command line parameters in ALL_CAPS should match the corresponding
  parameters in common/def.h

1. Run all Spines daemons (for both the internal and external Spines networks)
    - 1 internal Spines daemon per site containing SCADA master replicas
    - 1 external Spines daemon per control-center site
    - 1 external Spines daemon for PLC/RTU proxies to connect to
    - 1 external Spines daemon for HMI to connect to (can be the same as the
      one the proxies connect to)
    
    - To run (internal Spines network): cd spines/daemon; ./spines -p SPINES_INT_PORT -c spines_int.conf
    - To run (external Spines network): cd spines/daemon; ./spines -p SPINES_EXT_PORT -c spines_ext.conf

    * These commands assume that the internal and external spines configuration
      files are located at spines/daemon/spines_int.conf and
      spines/daemon/spines_ext.conf, respectively

2. Run all SCADA masters
    - To run (control center):
        cd scada_master; ./scada_master id spines_int_ip:SPINES_INT_PORT spines_ext_ip:SPINES_EXT_PORT
    - To run (data center):
        cd scada_master; ./scada_master id spines_int_ip:SPINES_INT_PORT

    * The spines_int_ip and spines_ext_ip should be the IP addresses of the
      internal and external Spines daemons this replica connects to. They
      should match addresses specified in SPINES_INT_SITE_ADDRS and
      SPINES_EXT_SITE_ADDRS in common/def.h.
    * The id should be the ID of this replica, where IDs range from 1 to
      NUM_SM. The code assumes replicas are striped across sites; for example,
      for 12 replicas and 4 sites (of which 2 sites are control centers) we
      have:
        - NUM_SM = 12, NUM_SITES = 4, NUM_CC = 2
        - Site 1 (control center): Replicas 1, 5, 9
        - Site 2 (control center): Replicas 2, 6, 10
        - Site 3 (data center):    Replicas 3, 7, 11
        - Site 4 (data center):    Replicas 4, 8, 12

3. Run all Prime daemons
    - To run: cd prime/bin; ./prime -i id

    * The id of a Prime daemon must match the id of the SCADA Master that
      connects to it (and is running on the same machine as it)
    * Prime uses its configuration files to find the location of the internal
      Spines daemon to connect to (see Prime documentation)

4. Run PLC/RTU proxies
    - To run: cd proxy; ./proxy id SPINES_RTU_ADDR:SPINES_EXT_PORT 1

    * The id should be the ID of this proxy, where IDs range from 0 to (NUM_RTU - 1).
      This ID is also used to look up information about the PLC/RTU in the
      config.json file

5. Run the HMIs
    - To run (jhu): cd jhu_hmi; ./jhu_hmi SPINES_HMI_ADDR:SPINES_EXT_PORT -port=pv_port_jhu
    - To run (pnnl): cd pnnl_hmi; ./pnnl_hmi SPINES_HMI_ADDR:SPINES_EXT_PORT -port=pv_port_pnnl

    * pv_port_* is the port on which the HMI will accept pvbrowser connections
      to interface with the GUI that reflects the current power grid state and
      allows a human operator to enter commands.

    - To connect GUI: Run pvbrowser application (located in main pvb
      installation folder). In the browser's address bar, give the IP address
      of the HMI and the pv_port (e.g. 10.0.0.1:5050).

6. (Optional) Run OpenPLC PLCs
    - cd plcs/jhu0; sudo ./openplc -m 503 -d 20001
    - ...
    - cd plcs/jhu9; sudo ./openplc -m 512 -d 20010
    - cd plcs/pnnl_plc; sudo ./openplc -m 502 -d 20000

    * -m option is the Modbus port, and -d option is the DNP3 port. These
      should match what is specified in the config.json file for each PLC.
    * See the OpenPLC documentation for instructions on creating your own PLCs
      (http://www.openplcproject.com/plcopen-editor)

7. (Optional) Run Benchmark Clients
    - We also provide a benchmark client that can be used to test and measure
      the core of the system without running an HMI, PLC/RTU proxies, or
      PLCs/RTUs. The benchmark client submits updates to the system. The SCADA
      Masters agree on each of these updates just like they would for a normal
      PLC/RTU update and then send a response back to the benchmark client. The
      benchmark client calculates and prints the latency for processing each
      update (measured from the time it creates the update to the time it
      receives the corresponding response).

    - To run: cd benchmark; ./benchmark id SPINES_RTU_ADDR:SPINES_EXT_PORT poll_frequency(usec) num_polls

        * The benchmark client will send an update every "poll_frequency"
          microseconds and will exit after completing "num_polls" updates.
          Benchmark client ids range from 0 to (NUM_RTU - 1).

-------
Example
-------

The default configuration files included with Spire create a system with:
    - 4 control-center sites, each consisting of a single machine that runs the
      following four processes:
        - 1 external Spines daemon
        - 1 internal Spines daemon
        - 1 SCADA Master
        - 1 Prime daemon
    - 1 site with a single machine running the PLC/RTU proxy + 11 emulated PLCs
      (10 for the jhu system and 1 for the pnnl system)
    - 1 site with a single machine running 2 HMIs (1 jhu_hmi and 1 pnnl_hmi)

To run this example, execute the following:

    * Note that you will need to adjust IP addresses in the configuration files
      and commands to match your environment. The instructions below assume the
      following IP addresses:
        - HMI machine:              192.168.101.100
        - Control center 1 machine: 192.168.101.101
        - Control center 2 machine: 192.168.101.102
        - Control center 3 machine: 192.168.101.103
        - Control center 4 machine: 192.168.101.104
        - PLC/RTU proxy machine:    192.168.101.105

    On control center 1 machine:
    cd spines/daemon; ./spines -p 8100 -c spines_int.conf
    cd spines/daemon; ./spines -p 8120 -c spines_ext.conf
    cd scada_master; ./scada_master 1 192.168.101.101:8100 192.168.101.101:8120
    cd prime/bin; ./prime -i 1

    On control center 2 machine:
    cd spines/daemon; ./spines -p 8100 -c spines_int.conf
    cd spines/daemon; ./spines -p 8120 -c spines_ext.conf
    cd scada_master; ./scada_master 2 192.168.101.102:8100 192.168.101.102:8120
    cd prime/bin; ./prime -i 2

    On control center 3 machine:
    cd spines/daemon; ./spines -p 8100 -c spines_int.conf
    cd spines/daemon; ./spines -p 8120 -c spines_ext.conf
    cd scada_master; ./scada_master 3 192.168.101.103:8100 192.168.101.103:8120
    cd prime/bin; ./prime -i 3

    On control center 4 machine:
    cd spines/daemon; ./spines -p 8100 -c spines_int.conf
    cd spines/daemon; ./spines -p 8120 -c spines_ext.conf
    cd scada_master; ./scada_master 4 192.168.101.104:8100 192.168.101.104:8120
    cd prime/bin; ./prime -i 4

    On the PLC/RTU proxy machine:
    cd spines/daemon; ./spines -p 8120 -c spines_ext.conf
    cd proxy; ./proxy 0 192.168.101.105:8120 1
	cd plcs/jhu0; sudo ./openplc -m 503 -d 20001
	cd plcs/jhu1; sudo ./openplc -m 504 -d 20002
    ...
    cd plcs/jhu9; sudo ./openplc -m 512 -d 20010
    cd plcs/pnnl_plc; sudo ./openplc -m 502 -d 20000

    On the HMI machine:
    cd jhu_hmi; ./jhu_hmi 192.168.101.100:8120 -port=5051
    cd pnnl_hmi; ./pnnl_hmi 192.168.101.100:8120 -port=5052

    Connect GUIs by running the pvbrowser application (located in main pvb
    installation folder) twice. In one browser's address bar, type
    192.168.101.100:5051. In the other, type 192.168.101.100:5052
