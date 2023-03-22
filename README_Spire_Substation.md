# Spire for the Substation: Real-Time Byzantine Resilience for Power Grid Substation

For more information see [www.dsn.jhu.edu/spire/](http://www.dsn.jhu.edu/spire/)

Spire for the Substation was added to the open source release in Spire 2.0.

Note: Please note that this is README for Spire for the Substation only. See
`README_Spire.md` and `README_Confidential_Spire.md` for information on running
the base and confidential variants of the control-center level Spire.

---

## Contents
1. Spire for the Substation Overview
2. Deployment Overview
3. Configuration
4. Installation Prerequisites
5. Building
6. Generating Keys
7. Running

---

## Spire for the Substation Overview

Spire for the Substation is built to support real-time byzantine resilience
required for power grid substations. The system is designed to withstand both
system-level protective relay intrusions and network attacks on substation LAN,
while meeting the stringent quarter of a power-cycle latency requirement
(4.167ms).

The Spire for the Substation includes a Trip Master, Relay Proxy and Breaker
Proxy designed and developed from scratch. Additionally, we provide emulated
relays to simulate real substation fault-free and faulty situations. We support
substation communication protocol of IEC61850 using open-source libiec61850.
The Trip Masters support real-time Byzantine resilience protocols needed to
tolerate faulty protective relays and provide correct protection functions.
Communication between Spire for the Substation components is protected using
the [Spines intrusion-tolerant network](http://www.spines.org).The Machine
Learning-based Network Intrusion Detection System that is built to work with
Spire can be adopted by retraining for Spire for the Substation.

The Trip Masters implement two protocols (Arbiter and Peer Protocols) with the
same architecture. Specifically, the architecture can tolerate f Byzantine
protective relays with k protective relays undergoing simultaneously with
2f+k+1 protective relays and their Spire for the Substation harness. The
protective relay publish GOOSE messages to their directly connected relay
proxy. The relay proxy sends IPC message about the event to Trip Master on same
machine. We refer to a relay and its attached Spire harness as relay node. The
Trip Master uses the Byzantine protocols to issue trip or close action commands
to the Breaker Proxy through intrusion-tolerant Spines network. The Breaker
Proxy, directly connected to Breaker IED, can in turn verify and issue GOOSE
commands to control the Breaker. We refer to the Breaker IED and its directly
connected Spire harness as Breaker node.

The system can be operated by connecting to physical hardware relays or with
the emulated relays provided.

---

## Deployment Overview

A Spire for the Substation deployment includes: Trip Masters, Relay Proxies,
Breaker Proxy, Spines daemons and real or emulated relays. These components are
typically in a LAN substation setting, connected by process bus in a typical
IEC61850 architecture. The minimal system would involve 4 protective relays and
a Breaker node. The Trip Masters come with their respective Breaker Modules as
the protocols vary.

A good (up and correct) protective relay will issue a trip when the grid needs
it. The Byzantine protocols (implemented in Trip Masters) ensure that a
protective relay under the control of an attacker cannot unilaterally change
the breaker state. While the system configuration remains same, the two
protocols involve running different components described later.

---

## Configuration

The example configuration (in the `spire/example_conf/ss_conf_4 folder`)
includes all configuration files needed for four relay nodes and one Breaker
node to tolerate one Byzantine protective relay and one protective relay
undergoing proactive recovery simultaneously.

There are several configuration files relevant to the Spire for the Substation system:

1. Main Spire configuration: `common/def.h`
    - The parameters needed for Spire for the Substation start from section
      titled "Substation System wide defines".
    - See comments within the file for configuration parameters and
      descriptions. While most parameters can be used unchanged, please edit
      IPs (`SPINES_RELAY_INT_ADDRS`, `SPINES_RELAY_EXT_ADDRS`,
      `SPINES_PROXY_ADDR`).
    - The parameters for Substation and Control Center configurations are
      marked individually and can be manipulated as needed.
    - The example configuration file is
      `spire/example_conf/ss_conf_4/scada_def.h`

2. Spines configuration (`spines/daemon/spines.conf`) -- see Spines
   documentation for details. 
    - Note that internal and external Spines networks use different
      configuration files. 
    - Please ensure that Host IPs are the same as in the `common/def.h` file
    - The example conf files are in `spire/example_conf/ss_conf_4/` as
      `ss_spines_ext.conf` and `ss_spines_int.conf`

3. Relay and Breaker Proxy configuration:
    - Currently all important parameters are configurable from command line.
      (Usage and Running section below explains the details)

---

## Installation Prerequisites

### General Prerequisites

- OpenSSL development package
    * e.g. `yum install openssl-devel`, `apt-get install libssl-dev`

### Spines Prerequisites

- Lex and Yacc
    * e.g. `yum install flex byacc`, `apt-get install flex byacc`

---

## Building Spire for the Substation

1. Build libraries, Spines and Prime (from top-level Spire directory):

    make libs

2. Build Spire for the Substation (from top-level Spire directory):

    make substation

3. Note that we can clean with:

    make clean_substation

---

## Generating Keys

All system entities use RSA keys to authenticate messages, so keys must be
generated and distributed before the system can run.

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

2. Trip Master Keys
    - To generate keys for Peer Protocol:
        
        cd trip_master;./gen_keys

    - This generates the needed threshold signature scheme keys in
      trip_master/tm_keys) for Peer Protocol.
    - Each trip master should have access to its own threshold crypto share and
      public key.
    - The Breaker Proxy should have access to the threshold scheme's public key

3. Trip Master_v2 Keys
    - To generate keys for Arbiter Protocol

        cd trip_master_v2;./gen_keys

    - This generates private-public key pairs for all relay nodes
      (`private_01.key` and `public_01.key`, `private_02.key` and
      `public_02.key`, ...) and the Breaker node (`private_client_01.key` and
      `public_client_01.key`). The keys will be located in trip_master/tm_keys.
    - Each relay node should have access to its own key pair and the Breaker
      node's public key
    - The Breaker node has access to its own key pair and all relay nodes
      public keys

---

## Running Peer Protocol

Note that command line parameters in `ALL_CAPS` should match the corresponding
parameters in `common/def.h`

All instructions are from top-level directory.

1. Run all Spines daemons
    Each relay node needs to run both internal and external Spines networks. 
    The Breaker node needs to run an external Spines network daemon.

    To run (internal Spines network):

        cd spines/daemon; ./spines -p SS_SPINES_INT_PORT -c ss_spines_int.conf -I IP_ADDRESS

   To run (external Spines network):

        cd spines/daemon; ./spines -p SS_SPINES_EXT_PORT -c ss_spines_ext.conf -I IP_ADDRESS

   Note: These commands assume that the internal and external spines
   configuration files are located at `spines/daemon/ss_spines_int.conf` and
   `spines/daemon/ss_spines_ext.conf`, respectively

2. Run all Trip Masters
    cd trip_master; ./trip_master id 

    The `id` should be the id of this relay node, starting from 1. For example,
    with four relay nodes they are 1-4.

3. Run emulated relays

    cd relay_emulator; sudo ./goose_publisher interface id

    - The interface is the network interface to publish on. With emulated
      relays we recommend using `lo` (loopback)
    - `id` same as that of its trip master

4. Run relay proxy

    cd proxy_iec61850;./relay_proxy relay_CB_Ref breaker_CB_Ref sub_interface pub_interface goID dataset trip_loaction_in_relay_goose

    - `relay_CB_Ref`: Relay control block reference that relay proxies
      subscribe to. For example: `simpleIOGenericIO/LLN0$GO$gcbAnalogValues`
    - `breaker_CB_Ref`: control block reference that relay proxies should
      publish with (for their respective relay) to inform about Circuit breaker
      state. For example, `SPMaster/LLN0$GO$GoCB01`. 
    - `sub_interface`: Interface to receive relay GOOSE on. For emulated relays
      it can be `lo`
    - `pub_interface`: Interface to publish Breaker status on. For emulated
      relays it can be `lo`
    - `goID`: for publishing Breaker state. For example, `SPMaster`.
    - `dataset`: For publishing Breaker state. For example,
      `SPMaster/LLN0\$dataset1`
    - `trip_location_in_relay_goose`: Location of goose trip or close payload
      in relay GOOSE of subscriber. For emulated relays the value is `1`


5. Benchmarking the Spire for the Substation
    
    cd benchmarks_ss; ./benchmark -n count

Note: Emulated relays receive input by multicast on 224.1.1.1 and port 8401.
These can be configured in common/def.h file. So, ensure that the testbed has
multicast enabled.

---

## Running Arbiter Protocol

Note that command line parameters in `ALL_CAPS` should match the corresponding
parameters in `common/def.h`

All instructions are from top-level spire directory.

1. Run all Spines daemons
    Each relay node needs to run only external Spines networks. 
    The Breaker node needs to run an external Spines network daemon.

   To run (external Spines network):

        cd spines/daemon; ./spines -p SS_SPINES_EXT_PORT -c ss_spines_ext.conf -I IP_ADDRESS

   Note: These commands assume that the internal and external spines
   configuration files are located at `spines/daemon/ss_spines_int.conf` and
   `spines/daemon/ss_spines_ext.conf`, respectively

2. Run all Trip Masters
    
    cd trip_master_v2; ./trip_master id

    The `id` should be the id of this relay node, starting from 1. For example,
    with four relay nodes they are 1-4.

3. Run emulated relays

    cd relay_emulator; sudo ./goose_publisher interface id

    - The interface is the network interface to publish on. With emulated
      relays we recommend using `lo` (loopback)
    - `id` same as that of its trip master

4. Run relay proxy

    cd proxy_iec61850;./relay_proxy relay_CB_Ref breaker_CB_Ref sub_interface pub_interface goID dataset trip_loaction_in_relay_goose

    - `relay_CB_Ref`: Relay control block reference that relay proxies
      subscribe to. For example: `simpleIOGenericIO/LLN0$GO$gcbAnalogValues`
    - `breaker_CB_Ref`: control block reference that relay proxies should
      publish with (for their respective relay) to inform about Circuit breaker
      state. For example, `SPMaster/LLN0$GO$GoCB01`. 
    - `sub_interface`: Interface to receive relay GOOSE on. For emulated relays
      it can be `lo`
    - `pub_interface`: Interface to publish Breaker status on. For emulated
      relays it can be `lo`
    - `goID`: for publishing Breaker state. For example, `SPMaster`.
    - `dataset`: For publishing Breaker state. For example,
      `SPMaster/LLN0\$dataset1`
    - `trip_location_in_relay_goose`: Location of goose trip or close payload
      in relay GOOSE of subscriber. For emulated relays the value is `1`

5. Benchmarking the Spire for the Substation

    cd benchmarks_ss; ./benchmark2 -n count

Note: Emulated relays receive input by multicast on 224.1.1.1 and port 8401.
These can be configured in common/def.h file. So, ensure that the testbed has
multicast enabled.

Note on Logging: The print level in all main Modules is controlled by enabling
needed type in `Alarm_set_types`. The PRINT level is minimal logging followed
by STATUS and DEBUG levels.

### (Optional) Setup Intrusion Detection System

The Intrusion Detection was built as a standalone component. See inside the `ids` folder for details
on setup and running.

### Example to run Spire for the Substation with Peer Protocol

The default configuration files can support both protocols.It creates a system
with four relay nodes and one Breaker node. Each relay node consists of Spines
daemon(s), Relay Proxy and Trip Master. The Breaker node consists of Spines
daemon and Breaker Proxy.

* Note that you will need to adjust IP addresses in the configuration files and
  commands to match testbed environment.

  Consider 5 machines with IPs (in common/def.h in Substation ADDRs):
    - Relay Node 1: 192.168.101.101
    - Relay Node 2: 192.168.101.102
    - Relay Node 3: 192.168.101.103
    - Relay Node 4: 192.168.101.104
    - Breaker Node: 192.168.101.105

    On 192.168.101.101:

        cd spines/daemon; ./spines -p 10200 -c ss_spines_ext.conf;
        cd spines/daemon; ./spines -p 10000 -c ss_spines_int.conf;
        cd trip_master; ./trip_master 1;
        cd relay_emulator; sudo ./goose_publisher interface 1;
        cd ~/spire/proxy_iec61850; sudo ./relay_proxy simpleIOGenericIO/LLN0$GO$gcbAnalogValues SPNo1Master/LLN0$GO$GoCB01 lo lo SPNo1Master SPNo1Master/LLN0$dataset1 1;

    On 192.168.101.102:

        cd spines/daemon; ./spines -p 10200 -c ss_spines_ext.conf;
        cd spines/daemon; ./spines -p 10000 -c ss_spines_int.conf;
        cd trip_master; ./trip_master 2;
        cd relay_emulator; sudo ./goose_publisher interface 2;
        cd ~/spire/proxy_iec61850; sudo ./relay_proxy simpleIOGenericIO/LLN0$GO$gcbAnalogValues SPNo2Master/LLN0$GO$GoCB01 lo lo SPNo2Master SPNo2Master/LLN0$dataset1 1;

    On 192.168.101.103:

        cd spines/daemon; ./spines -p 10200 -c ss_spines_ext.conf;
        cd spines/daemon; ./spines -p 10000 -c ss_spines_int.conf;
        cd trip_master; ./trip_master 3;
        cd relay_emulator; sudo ./goose_publisher interface 3;
        cd ~/spire/proxy_iec61850; sudo ./relay_proxy simpleIOGenericIO/LLN0$GO$gcbAnalogValues SPNo3Master/LLN0$GO$GoCB01 lo lo SPNo3Master SPNo3Master/LLN0$dataset1 1;

    On 192.168.101.104:

        cd spines/daemon; ./spines -p 10200 -c ss_spines_ext.conf;
        cd spines/daemon; ./spines -p 10000 -c ss_spines_int.conf;
        cd trip_master; ./trip_master 4;
        cd relay_emulator; sudo ./goose_publisher interface 4;
        cd ~/spire/proxy_iec61850; sudo ./relay_proxy simpleIOGenericIO/LLN0$GO$gcbAnalogValues SPNo4Master/LLN0$GO$GoCB01 lo lo SPNo4Master SPNo4Master/LLN0$dataset1 1;

    On 192.168.101.105:

        cd spines/daemon; ./spines -p 10200 -c ss_spines_ext.conf;
        cd  benchmarks_ss; ./benchmark -n 100;
    
### Example to run Spire for the Substation with Arbiter Protocol

The default configuration files included with Spire for the Substation
Protocols creates a system with four relay nodes and one Breaker node. Each
relay node consists of Spines daemon(s), Relay Proxy and Trip Master. The
Breaker node consists of Spines daemon and Breaker Proxy.

* Note that you will need to adjust IP addresses in the configuration files and
  commands to match testbed environment.

  Consider 5 machines with IPs (in common/def.h in Substation ADDRs):
    - Relay Node 1: 192.168.101.101
    - Relay Node 2: 192.168.101.102
    - Relay Node 3: 192.168.101.103
    - Relay Node 4: 192.168.101.104
    - Breaker Node: 192.168.101.105

    On 192.168.101.101:

        cd spines/daemon; ./spines -p 10200 -c ss_spines_ext.conf;
        cd trip_master_v2; ./trip_master 1;
        cd relay_emulator; sudo ./goose_publisher interface 1;
        cd ~/spire/proxy_iec61850; sudo ./relay_proxy simpleIOGenericIO/LLN0$GO$gcbAnalogValues SPNo1Master/LLN0$GO$GoCB01 lo lo SPNo1Master SPNo1Master/LLN0$dataset1 1;

    On 192.168.101.102:

        cd spines/daemon; ./spines -p 10200 -c ss_spines_ext.conf;
        cd trip_master_v2; ./trip_master 2;
        cd relay_emulator; sudo ./goose_publisher interface 2;
        cd ~/spire/proxy_iec61850; sudo ./relay_proxy simpleIOGenericIO/LLN0$GO$gcbAnalogValues SPNo2Master/LLN0$GO$GoCB01 lo lo SPNo2Master SPNo2Master/LLN0$dataset1 1;

    On 192.168.101.103:

        cd spines/daemon; ./spines -p 10200 -c ss_spines_ext.conf;
        cd trip_master_v2; ./trip_master 3;
        cd relay_emulator; sudo ./goose_publisher interface 3;
        cd ~/spire/proxy_iec61850; sudo ./relay_proxy simpleIOGenericIO/LLN0$GO$gcbAnalogValues SPNo3Master/LLN0$GO$GoCB01 lo lo SPNo3Master SPNo3Master/LLN0$dataset1 1;

    On 192.168.101.104:

        cd spines/daemon; ./spines -p 10200 -c ss_spines_ext.conf;
        cd trip_master_v2; ./trip_master 4;
        cd relay_emulator; sudo ./goose_publisher interface 4;
        cd ~/spire/proxy_iec61850; sudo ./relay_proxy simpleIOGenericIO/LLN0$GO$gcbAnalogValues SPNo4Master/LLN0$GO$GoCB01 lo lo SPNo4Master SPNo4Master/LLN0$dataset1 1;

    On 192.168.101.105:

        cd spines/daemon; ./spines -p 10200 -c ss_spines_ext.conf;
        cd  benchmarks_ss; ./benchmark2 -n 100;
 
The benchmark program  generates the relay input (emulated Sampled Values) that
trigger Trip or Close GOOSE. It also runs the Breaker Proxy logic. This enables
end-to-end latency measurements on same machine with same clock. The latency is
measured from Sampled Value issue to Circuit Breaker State change. It is to be
noted that emulated relays react to emulated Sampled Values, hence, their
processing delay is negligible. 

In case real physical relays are used with real Breaker IED, we provide
independent Breaker Proxies for either protocols in the proxy_iec61850 folder
as simple_cb_proxy for Peer Protocol and counting_brkr_proxy for Arbiter
Protocol. 
Please note that when we use real relays, we should not run emulated relays.


The Breaker Proxy can be run with their respective Trip Master modules by commands:
On 192.168.101.105:

        cd spines/daemon; ./spines -p 10200 -c ss_spines_ext.conf;
        cd proxy_iec61850;sudo ./simple_cb_proxy interface;
                            or
        cd proxy_iec61850;sudo ./counting_dst_proxy interface;

Interface should be the interface used to connect to Circuit Breaker IED. For,
emulated relays we recommend using `lo` (loopback).

**Note on operating emulated relays (independently without benchmark program):**

The emulated relays are controlled through emulated Sampled Values. The
emulated Sample values can be generated through the `gen_event` program in
the `emulated_relay` folder. The commands are:

`s 1` - Generate Simple Trip, i.e., all relays will issue Trip action GOOSE immediately.

`s 0` - Generate Simple Close, i.e., all relays will issue Close action GOOSE immediately.

`b relay1_delay relay1_event relay2_delay relay2_event  relay3_delay relay3_event relay4_delay relay4_event` - Relays generate their event(0/1 for close or trip) with the specified delays. This helps generate Byzantine behavior.

Instead of benchmarks program, please run breaker proxy with breaker IED.
