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
In addition, this version is able to recover from temporary network
partitions. If there are not enough connected replicas to make progress due to
a partition, progress will resume once the partition heals. If some replica(s)
are disconnected from a quorum of replicas that continues to make progress,
these replicas will be caught up and able to rejoin the system once they are
reconnected.

In the replication model used in this version, each replica consists of an
application replica paired with a Prime daemon co-located on the same machine.
The application replicas introduce updates or events into the system for
ordering through their paired Prime daemon. The Prime daemons execute the
Prime Byzantine agreement protocol to assign each update an ordinal in the
global total ordering. 

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
Prime can be compiled by typing make in the src directory. Three executables
will be generated and stored in the bin directory. The programs are gen_keys,
prime and client.

***********
* Running *
***********
The following assumes that you have successfully compiled the Prime server and
client and carried out the necessary configuration steps discussed above. The
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

./prime -i SERVER_ID

where SERVER_ID denotes an integer from 1 to the number of servers in the
system.

The client can be run like this:

./client -l IP_ADDRESS -i CLIENT_ID -s SERVER_ID

IP_ADDRESS denotes the IP address of the client program, and CLIENT_ID denotes
an integer from 1 to the maximum number of clients in the system. The client
sends its updates through the Prime server with id SERVER_ID. 

NOTE: With the replication model used in the version, only one client can
connect to each Prime replica at a given time, and that client must be
co-located on the same machine as the target Prime server.

By default, each client sends one update at a time through its connected Prime
server, only sending the next update once it has received a response for the
current pending one. By setting the NUM_CLIENTS_TO_EMULATE parameter in
src/client.c and recompiling, the client will instead send several updates at
once, maintaining multiple outstanding updates in a pipeline fashion. As soon
as a response is received for one of these pending updates, another one is
sent to the Prime server.

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

5) cd to the bin directory. Run the gen_keys program: ./gen_keys

6) Run the spines network (if using Spines)

7) Change the bin/address.config file as described above.

8) The server and client programs can now be run.
