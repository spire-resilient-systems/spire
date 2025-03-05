================================================================================
Compiling the Code
================================================================================

From top level directory run:
$ ./configure
$ make -C daemon parser
$ make

At this point, the "spines" executable should be present in the daemon directory.

As a quick test that everything worked correctly, you can go into the daemon
directory and run "./spines" to test that you can start up a singleton Spines
instance.

Notes:
- As of version 5.5, Spines uses OpenSSL 1.1, and is not compatible with
  earlier versions of OpenSSL. If OpenSSL 1.1 is not your system/default
  OpenSSL installation, you need to specify its location when you run the
  configure script. For example, the following works on CentOS 7 when openssl11
  and openssl11-devel packages are installed:

$ ./configure CFLAGS=-I/usr/include/openssl11 LDFLAGS=-L/usr/lib64/openssl11

- If you are doing development work on the code, you only need to run
  "./configure" and "make -C daemon parser" the first time you build the
  project. After that, if you make code changes and need to recompile, you can
  just run "make". Note that to make sure your changes get picked up, you may
  want to run "make clean" before running "make" to force the whole project to
  rebuild ("make" should normally be able to do this correctly on its own, but
  if you are changing .h files it may not)

================================================================================
Generating Keys
================================================================================

* Note that this step is only required if you plan to use the
  intrusion-tolerant protocols

1. In daemon directory run:
   $ ./gen_keys.sh

   This will generate 10 keys and save them to daemon/keys folder. If more keys
   are needed, you can edit the script to change the number of generated keys
   to the number of Spines nodes in your network. The keys are used by each
   machine for authentication.

================================================================================
Configuring the Spines Network
================================================================================

The recommended way to set up your Spines topology is by using a configuration
file that specifies all the nodes and edges.

An example configuration file is provided in the daemon directory of the spines
distribution. It is recommended that you copy that file to use as the base of
your configuration file.

By default, Spines expects the configuration file to be named spines.conf,
although you can use the -c commandline option when running Spines to change
this.

1. In the daemon directory, copy the example configuration file:
    $ cp example_spines.conf spines.conf

2. Edit the "Hosts" and "Edges" sections (at the bottom of the file) to list
   your nodes and the edges between them.

3. Edit any other parameters that you need. Some useful ones to note:

   - Directed_Edges: By default Directed_Edges=False. However, the
     dissemination-graph-based routing protocols (ICDCS 2017 paper) currently
     required Directed_Edges=True. If you plan to use these protocols, be sure
     to change this parameter. This also requires that in the "Edges" section,
     you list edges in both directions (e.g. if there is a bidirectional link
     between nodes 1 and 2, you need to list edge "1 2" and "2 1").

   - IT_IntrusionToleranceMode: By default IT_IntrusionToleranceMode = No. If
     you are using the intrusion tolerance capabilities, you should set this to
     Yes. Note that setting this to "Yes" will disable the other protocols. If
     you want to use them again, you will need to edit the configuration file
     again.

   - Path_Stamp_Debug: By default Path_Stamp_Debug = False. This is recommended
     for most uses, BUT if you are doing benchmarking with the provided test
     programs sp_bflooder, spines2port/port2spines, you will likely find it
     useful to set Path_Stamp_Debug = True so that you can see the path taken
     through the network. If you are NOT using one of those programs, you MUST
     set this to False, otherwise part of your data will be overwritten.

================================================================================
Running Spines
================================================================================

On each machine in your configuration, go to daemon directory and run:
$ ./spines

At this point, the Spines network is up and running on default ports.

Spines provides some useful commandline options. You can see all of them by running:
$ ./spines usage

A few important commandline options to note:
-p <port>  :  You can specify an alternative base port for Spines to run on.
              This is useful if you need to run multiple Spines networks at the
              same time. Note that Spines uses multiple ports internally, so if
              you are running multiple instances, you should be sure to space
              them by at least 20 ports. The default port is 8100, so you could
              run additional Spines networks on base ports 8120, 8140, 8160,
              etc.

-m         :  This tells Spines to accept monitor commands for setting loss
              rates. If you plan to use Spines capability to emulate different
              loss and/or latency conditions (discussed below), you need to use
              this option

-w <Route_Type> : If you want to use the dissemination-graph-based routing
                  protocol from the ICDCS 2017 paper, you need to use the
                  commandline parameter "-w problem"

================================================================================
Testing
================================================================================

Several test programs are distributed with Spines. To view the commandline
parameters that any given program accepts, you can run that program with the
argument "usage" (e.g. ./sp_bflooder usage)

sp_bflooder provides an easy way to generate traffic and send it through Spines.

To test intrusion tolerance with priority-based flooding mode:
On receiver run: ./sp_bflooder -v -P 8 -D 1 -n <count>
On sender run: ./sp_bflooder -s -v -P 8 -D 1 -a <receiver_ip_addr>  -n <count> -R <rate>

To test dissemination graphs from ICDCS 2017 paper with realtime recovery protocol:
On receiver run: ./sp_bflooder -v -P 2 -D 3 -k 6 -n <count>
On sender run: ./sp_bflooder -s -v -P 2 -D 3 -k 6 -a <receiver_ip_addr>  -n <count> -R <rate>

- Here, <count> is the number of packets to send, and <rate> is the rate to
  send at, in kbps (e.g. to send at a rate of 5 Mbps, use -R 5000)

- The -P and -D options are used to specify the link and dissemination
  protocols to use, respectively. Note that intrusion-tolerant dissemination
  protocols (-D 1 or -D 2) can only be used with the intrusion-tolerant link
  protocol (-P 8).

- The -k option can also be used to specify a number of disjoint paths to use.
  Note that the maximum number of disjoint paths is limited to 5 (i.e. -k 1, -k
  2, ..., -k 5) are valid options.

- The -k option can also be used with -k 6, but this has a special meaning: it
  is used to implement the targeted redundancy dissemination graphs from the
  ICDCS 2017 paper. Note that for this to work correctly, your Spines daemon
  must also be run with the option "-w problem", and your configuration file
  must use Directed_Edges=True

The spines2port and port2spines programs provide a way to funnel external traffic through Spines.
The port2spines program receives traffic on a given port and sends it to
Spines, while the spines2port program receives traffic from Spines and sends to
a given (non-Spines) address and port.

For simple testing, port2spines and spines2port can also be used together with
the u_flooder program. The u_flooder program just generates UDP traffic and
sends it to a given port (or receives on a given port). So, to test this, you
can run sending_uflooder->port2spines->spines->spines2port->receiving_uflooder

Assume you have 2 machines, with IP addresses 10.0.1.1 and 10.0.2.2 (and a
correctly set up spines.conf that includes both of them as Hosts). Run spines
on each machine.

You can run on the 10.0.2.2 machine:
./spines2port -w 65 -P 2 -D 3 -k 6
./u_flooder -r 8400 -n 5000

You can run on the 10.0.1.1 machine: 
./port2spines -a 10.0.2.2 -P 2 -D 3 -k 6
./u_flooder -s -nb -d 8400 -n 5000 -R 5000

- The -P, -D, -k, -n, -R parameters have the same meaning as for sp_bflooder

- The -d/-r options to u_flooder specify the port to send and receive on,
  respectively. By default, port2spines receives packets on port 8400 and
  spines2port sends them to localhost at port 8400, so this matches what we
  specify for u_flooder. You can change the port used by port2spines with the
  -r parameter and by spines2port with its -a parameter (see usage info).

- The -w option to spines2port specifies how long to wait (i.e. buffer) a
  packet before delivering it. This is done to give out of order packets time
  to arrive. Note that by default this requires fairly tight clock sync, as the
  wait time is calculated based on the time the packet was sent (on the
  sender's local clock). To change this, you can pass the -t option to
  spines2port, to instead calculate the time to wait based on the time the
  packet was received at the spines2port program (but if clocks are well
  synchronized we prefer not to use this to minimize jitter).

================================================================================
Loss/Latency Emulation
================================================================================

You can use the setlink program to emulate different network conditions.

For example, to set 25ms latency and 1% loss in both directions on a link
between Spines nodes with IP addresses 10.0.1.1 and 10.0.2.2, you would run:
./setlink 1000000 25 1 0 10.0.1.1 10.0.2.2 10.0.2.2 8100
./setlink 1000000 25 1 0 10.0.2.2 10.0.1.1 10.0.1.1 8100

- The second positional argument (25 here) specifies the latency to add, while
  the third (1 here) specifies the loss rate
- Note that these commands can be run from any machine in your Spines topology

================================================================================
Autoconf / Release Notes
================================================================================

To rebuild the configure script you need to run:

autoconf -I buildtools

If you add new header defines you may also need to run
autoheader -I buildtools
