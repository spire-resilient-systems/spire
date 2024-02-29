*************************************
* Contents:
*    Prime Overview and Instructions
*    Software Dependencies
*    Configuration
*    Compiling
*    Running
*    Erasure Codes
*    Attack Scenarios
*    Prime Checklist
*************************************

***********************************
* Prime Overview and Instructions *
*********************************** 
Prime is a Byzantine fault-tolerant state machine replication engine. The
system maintains correctness as long as no more than f servers are Byzantine,
and remains available as long as no more than f servers are Byzantine and no
more than k servers are crashed/paritioned out of the total 3f+2k+1 servers.
Prime is further extended to support reconfiguration.

This implementation is based on the protocols described in:

Y. Amir, B. Coan, J. Kirsch, J. Lane. Byzantine Replication Under Attack. In
Proceedings of the 38th IEEE/IFIP International Conference on Dependable
Systems and Networks (DSN 2008), Anchorage, Alaska, June 2008, pp. 197-206.

M. Platania, D. Obenshain, T. Tantillo, R. Sharma, Y. Amir. Towards a
Practical Surviviable Intrusion Tolerant Replication System. In 
Proceedings of the IEEE International Symposium on Reliable Distributed
Systems (SRDS14), Nara, Japan, October 2014, pp. 242-252

The current release implements the complete Prime protocol as described in the
Byzantine Replication Under Attack paper and J. Kirsch's PhD thesis. This
version provides an ephemeral ordering service that can tolerate f compromised
replicas and k unavailable replicas (due to crashes, partitions, or recovery).
In addition, this version is able to recover from temporary network partitions.
If there are not enough connected replicas to make progress due to a partition,
progress will resume once the partition heals. If some replica(s) are
disconnected from a quorum of replicas that continues to make progress, these
replicas will be caught up and able to rejoin the system once they are
reconnected.

As of version 4.0, the implementation also supports a new out-of-band
reconfiguration capability that can be used to restore system operations in
certain cases where the system's assumptions have been violated. e.g. If the
system experiences more crash faults than the tolerated threshold, it is
possible to reconfigure to a smaller system with the remaining replicas (and to
return to the full system configuration once failures are repaired).

System Overview:

In the replication model used in this version, each replica consists of an
application replica paired with a Prime daemon co-located on the same machine.
The application replicas introduce updates or events into the system for
ordering through their paired Prime daemon. The Prime daemons execute the
Prime Byzantine agreement protocol to assign each update an ordinal in the
global total ordering. The driver program is an example application provided. 

Each application replica receives an ordered stream of updates from its Prime
daemon, including both the updates it introduced and updates introduced by
other application replicas. If the replica pair (application and Prime) miss
messages (e.g., due to crash-recovery or network partition), the Prime daemon
will explicitly notify the application that it should do a state transfer
(applications may vary as to whether or not the application-level state
transfer is necessary). This Prime daemon will reconcile with the other Prime
daemons to rejoin the ordering protocol, and will resume delivering ordered
updates to the application replica starting from the ordinal immediately
following the one that the application will become consistent with after its
state transfer. 

Note that this new replication model is different than that of Prime version
2.0, which treated Prime as both an ordering service and a persistent database
that stored and recovered application state with its own Prime-level
state transfer protocol. 

System Overview during Reconfiguration:

During reconfiguration, the configuration maanger issues a configuration
message on configuration network. Each configuration agent validates the
configuration message and then passes it to its local application (driver). The
application forwards the reconfiguration message to its Prime daemon. The Prime
daemons then reconfigure and will explicitly notify the application of when
reconfiguration is complete. Once Prime adopts new configuration, the regular
flow of the system resumes as described above. 

Note that running the reconfiguration modules (Configuration Manager,
Configuration Agent and Configuration Network) is optional. Only the Prime
daemon and driver application are needed to run the system in a single
configuration and benchmark it.


**************************
* Software Dependencies: *
**************************
Prime uses the OpenSSL cryptographic library. OpenSSL can be downloaded from
www.openssl.org. The Makefile is set up to dynamically link to to OpenSSL. If
necessary, you can modify the Makefile to statically link to the library
libcrypto.a.

The current version of Prime is configured to make use of Spines
(www.spines.org), an overlay messaging toolkit also developed at Johns Hopkins
University. Spines provides an intrusion-tolerant networking foundation that
serves as Prime's communication layer, protecting Prime from attacks and
compromises at the underlying network level. Spines is also helpful for
testing wide-area topologies and placing bandwidth and latency constraints on
the links between Prime servers. 

By default, Prime is setup to use Spines. The latest compatible version is
included in the Prime software package at Prime/spines. We recommend using
Spines because it provides intrusion tolerance at the network level, as well
as resiliency to normal benign network issues (e.g., lossy links). Note that
to use Spines, a Spines network topology and options should be configured in
the spines/daemon/spines.conf file, and then the spines daemons should be
started (see Spines documentation for more details). To work without Spines,
comment the two lines in src/Makefile beginning with SPINES and SPINES_LIB.

Prime also makes use of several other open-source libraries, all of which are
included in the Prime software package. OpenTC provides an implementation of
the Shoup threshold cryptography algorithm, which Prime uses during the View
Change protocol to efficiently challenge the new leader. stdutil provides
efficient C implementations of several common data structures. libspread-util
provides access a suite of functions, including event handling and logging.

******************
* Configuration: *
******************
The bin directory contains a sample address configuration file
(address.config), which tells the servers the IP addresses of all servers
based on server id. The file contains a line for each server with the
following format:

   server_id ip_address

The server_id is a number from 1 to the number of servers in the system. The
ip_address is a standard dotted ipv4 address.

NOTE: The parameters in src/def.h must be written to match the address
configuration file (i.e., if NUM_SERVERS is set to 4, then there must be an
entry for each of the four servers in the bin/address.config file).

NOTE: If you are using Spines (which is the default), please also configure
spines_address.config to indicate which spines daemon each Prime server
connects with.

Prime contains many configurable parameters; the code must be recompiled to
change these parameters. The parameters are contained in src/def.h. Please
refer to this file for details. For reference, the file is organized as
follows:

   a. System-wide Configuration Settings
   b. Networking Settings 
   c. Cryptography Settings
   d. Throttling Settings (to control how much bandwidth is used)
   e. Periodic Sending Settings (to control message flow at certain steps)
   f. Attack Settings 

**************
* Compiling: *
**************
Prime can be compiled by typing make in the src directory. Five executables
will be generated and stored in the bin directory. The programs are gen_keys,
prime, config_manager, config_agent and driver.

Note that in case of changes to parameters in /src/def.h it is necessary to
recompile with make clean and make.

***********************************
* Running without Reconfiguration *
***********************************
The following assumes that you have successfully compiled the Prime server and
driver and carried out the necessary configuration steps discussed above. The
Prime servers can be run as follows:

First make sure you are in the bin directory.

The gen_keys program must be run first:

./gen_keys

This generate RSA keys for the servers and clients. The keys are stored in
bin/keys. The Prime server and client programs must read the keys from the
bin/keys directory. We assume that in a secure deployment the private keys are
accessible only to the server to which they belong. This also generates
threshold cryptography shares for the Prime servers, which are used in the
Prime View Change protocol.
 
Then, the Prime server can be run as follows:

./prime -i SERVER_ID -g GLOBAL_SERVER_ID

where SERVER_ID denotes an integer from 1 to the number of servers in the
current system configuration.

where GLOBAL_SERVER_ID denotes an integer from 1 to the total number of servers
in the system (maximal system configuration).

Normally, the system will be started with same SERVER_ID and GLOBAL_SERVER_ID.
During reconfiguration, a process's SERVER_ID may change as the configuration
is changed, but the GLOBAL_SERVER_ID is static and is used for communication
with application. The SERVER_ID commandline parameter may be used to start the
system in a configuration where only a subset of the servers are running,
allowing it to be reconfigured to a larger system later if desired.

The driver can be run as follows:

./driver -l IP_ADDRESS -i CLIENT_ID -s GLOBAL_SERVER_ID -c BENCHMARK_COUNT

IP_ADDRESS denotes the IP address of the client program, and CLIENT_ID denotes
an integer from 1 to the maximum number of clients in the system. The client
sends its updates through the Prime server with id GLOBAL_SERVER_ID. 

NOTE: Under the current replication model, a replica consists of a paired
application and Prime daemon. Therefore, only one application can connect to
each Prime replica at a given time, and that application must be co-located on
the same machine as the target Prime server.

By default, each driver sends one update at a time through its connected Prime
server, only sending the next update once it has received a response for the
current pending one. By setting the NUM_CLIENTS_TO_EMULATE parameter in
src/driver.c and recompiling, the driver will instead send several updates at
once, maintaining multiple outstanding updates in a pipeline fashion. As soon
as a response is received for one of these pending updates, another one is
sent to the Prime server.

***********************************
* Running with Reconfiguration *
***********************************
The following assumes the configuration modules are also compiled in addition to prime and driver programs.

The tpm_gen_keys program must be run in addition to gen_keys (noted above):

cd /bin; ./gen_tpm_keys.sh

During reconfiguration, the configuration message and its content need to use
permanent hardware-based keys (e.g., TPM Keys) to encrypt and sign the message.
Note that we currently use RSA keys generated above instead of hardware TPM
Keys for simplicity. The generated keys are stored in bin/tpm_keys. We assume
that in a secure deployment the private keys are accessible only to the server
to which they belong. The configuration manager has access to public keys of
all servers. 

The Prime and driver programs need to be run same as above with a driver per
Prime daemon. The system will run in its default configuration and the driver
can be used to benchmark the system until confiuration manager issues a new
configuration message. 

To enable reconfiguration, first run the Configuration Spines network:
	Compile Spines: 
		cd spines; ./configure; make -C daemon parser; make
	Generate Spines Keys: 
		cd spines/daemon; ./gen_keys
	Setup Spines Configuration File: 
		Ensure that IPs are correct in the configuration file located at spines/daemon/spines.conf 
	On the Configuration Manager Node and all Prime Nodes, run Spines: 
		cd spines/daemon; ./spines -p CONFIGURATION_SPINES_PORT -c spines.conf -I ip_address

		- CONFIGURATION_SPINES_PORT is defined in prime/src/def.h and by default it is 8900
		- 'ip_address' is the IP of node on which config_agent is run.


Second, run Configuration Agents as:

 ./config_agent id IP_of_config_spines app_path s count id1 id2 .... idN

    - `id` is the configuration agent ID. You should give each configuration
      agent a unique ID, starting from 1
	- `IP_of_config_spines` is the IP address of control spines deamon to connect to.
    - 'app_path' is the ipc path where the application is running. For driver
      application provided it is /tmp/ca_driver_ipc and is defined in src/def.h
    - s indicates it is a Prime node and configuration agent will send
      configuration messages to ids specified following the Count
	- `count` refers to number of processes running on the node.
        - If there is one Prime (say with `GLOBAL_SERVER_ID` 5) running on a
          node we can start config agent as:
                	`./config_agent 5 <IP_addr> /tmp/ca_driver_ipc s 1 5`
            - However, if there are multiple Prime daemons running on the node
              (say with `GLOBAL_SERVER_ID` 1,4,7) the we run config agent on
              that node as:
                	`./config_agent 1 <IP_addr> /tmp/ca_driver_ipc s 3 1 4 7`
    - The config agent can also support other applications. If the config_agent
      runs on a non-prime node, the agent sends configuration message from 1 to
      count processes at specified path. The command is run with 'p' option as
      below: 
   		./config_agent id IP_of_config_spines app_path p count

Then, we can use the Configuration Manager to generate new configuration
commands.  The Configuration Manager IP is defined in prime/src/def.h
(CONF_MNGR_ADDR). Hence, please edit the IP to match test bed and run
configuration manager from that node as:

 ./config_manager configuration_dir_path

        - The `configuration_dir_path` refers to a directory with two files
          (`conf_def.txt` and `new_conf.txt`) that are used to generate new
          configurations.
        - Examples of these files for three different configurations: 6+6+6, 6,
          and 6-6, are provided in the /bin directory (`conf_666`, `conf_6`,
          and `2cc_conf_6`). Configuration 6+6+6 refers to a configuration with
          18 replicas distributed evenly across 3 sites. Configuration 6 refers
          to a configuration with 6 replicas in a single site. If one of the
          sites in Configuration 6+6+6 becomes unavailable, it can be
          advantageous to reconfigure to Configuration 6 in one of the
          remaining sites. Changing to `conf_6` would reconfigure to 6 replicas
          in the first site, while changing to `2cc_conf_6` would reconfigure
          to 6 replicas in the second site. If the problem is repaired,
          changing back to `conf_666` would restore the system to its original
          state.

During reconfiguration, a driver program can be running benchmarks in current
configuration. On receiving configuration message, it pauses benchmarks and
sends the configuration message to Prime. On reconfiguration, if its prime
daemon is part of new configuration, it resumes benchmarks in new configuration.

******************
* Erasure Codes: *
******************
The Prime protocol makes use of erasure codes to send efficient reconciliation
(RECON) messages. RECON messages keep correct servers up to date despite the
efforts of faulty servers to block execution by failing to properly
disseminate updates.

Prime was developed using Michael Luby's implementation of Cauchy-based
Reed-Solomon erasure codes, which can be downloaded here:

http://www.icsi.berkeley.edu/~luby/

Due to licensing restrictions, we are unable to include this library in the
current release. By default, the current release performs reconciliation
without using erasure codes (i.e., full PO-Request messages are sent rather
than erasure-encoded ones). This is less efficient than using erasure codes
but serves the same functional purpose. Note that the results from the DSN
'08 paper reflect the use of erasure codes, and thus performance obtained from
the current release in bandwidth-constrained environments will be lower than
what is actually achievable.

The current release is set up to use a generic interface to an erasure
encoding library. By default, the interface calls are not invoked, because the
USE_ERASURE_CODES flag is set to 0 (see src/def.h). The Luby library (or some
other erasure encoding library) can be fairly easily integrated into the
current release by setting USE_ERASURE_CODES to 1 and filling in the
implementations of the interface functions (see src/erasure.h and
src/erasure.c).

*********************
* Attack Scenarios: *
*********************
Prime can also be configured to test its performance under certain types of
attacks. Currently, there are two types of attacks that be launched. In the
first attack, the leader can be configured (by setting the DELAY_ATTACK flag
in src/def.h) to attempt to slow down the performance of the ordering protocol
by delaying the transmission of the pre-prepare message. To prevent being
suspected and replaced, the leader must not delay the pre-prepare more than
the threshold determined by the distributed monitoring protocol. 

In the second attack, up to f faulty servers can be configured (by setting the
RECON_ATTACK flag in src/def.h) to only send Preorder requests to a subset of
the correct replicas. This will cause the correct servers to undergo as much
reconciliation as possible, as the correct servers will use bandwidth to help
other servers recover the missing Preorder requests.

********************
* Prime Checklist: *
********************
The following is a short summary of the important things that you must do to
run Prime.

1) Download and compile OpenSSL. Make sure the shared library can be located,
or modify the Makefile to link to the static library libcrypto.a.

2) Decide on the number of servers in the system. Change the parameters in
src/def.h accordingly.  Note that the number of servers must be equal to
3*NUM_F + 2*NUM_K + 1, which are parameters in src.def.h. 

3) If using Spines (which is the default setting), configure the Spines
network (spines/daemon/spines.conf) and configure bin/spines_address.config
accordingly.

4) Type make in the src directory.

5) cd to the bin directory. Run the programs: ./gen_keys ; ./gen_tpm_keys ;

6) Run the spines network (if using Spines)

7) Change the bin/address.config file as described above.

8) The server and driver programs can now be run.

9) For reconfiguration run - Spines Configuration Network, Configuration Agents and Configuration Manager.
