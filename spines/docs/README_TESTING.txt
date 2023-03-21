To rebuild the configure script you need to run:

autoconf -I buildtools

If you add new header defines you may also need to run
autoheader -I buildtools

Compile spines:

 From top level directory run

1. ./configure
2. make -C daemon parser
3. make

At this point there should be spines executable in daemon directory

Running:

1. In daemon directory run ./gen_keys.sh
   This will generate 10 keys and save them to daemon/keys folder. If more keys are needed, change the count in the script. They are used by each machine for authentication.
2. Set up needed configurations by creating spines.conf file in daemon directory. An example configuration is given in daemon folder.
3. On each machine in your configuration, goto daemon folder and run ./spines

Spines network is up and running on default ports.

Testing:

Various testprogs are given. To test intrusion tolerance with priority based flooding mode -

On receiver run: ./sp_bflooder -v -n <count>
On sender run: /sp_bflooder -s -v -P 8 -D 1 -a <receiver_ip_addr>  -n <count> -R <rate>
