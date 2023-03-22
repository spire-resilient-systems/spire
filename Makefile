 #
 # Spire.
 #
 # The contents of this file are subject to the Spire Open-Source
 # License, Version 1.0 (the ``License''); you may not use
 # this file except in compliance with the License.  You may obtain a
 # copy of the License at:
 #
 # http://www.dsn.jhu.edu/spire/LICENSE.txt 
 #
 # or in the file ``LICENSE.txt'' found in this distribution.
 #
 # Software distributed under the License is distributed on an AS IS basis, 
 # WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
 # for the specific language governing rights and limitations under the 
 # License.
 #
 # Spire is developed at the Distributed Systems and Networks Lab,
 # Johns Hopkins University and the Resilient Systems and Societies Lab,
 # University of Pittsburgh.
 #
 # Creators:
 #   Yair Amir            yairamir@cs.jhu.edu
 #   Trevor Aron          taron1@cs.jhu.edu
 #   Amy Babay            babay@pitt.edu
 #   Thomas Tantillo      tantillo@cs.jhu.edu 
 #   Sahiti Bommareddy    sahiti@cs.jhu.edu
 #   Maher Khan           maherkhan@pitt.edu
 #
 # Major Contributors:
 #   Marco Platania       Contributions to architecture design 
 #   Daniel Qian          Contributions to Trip Master and IDS 
 #
 # Contributors:
 #   Samuel Beckley       Contributions to HMIs 
 #
 # Copyright (c) 2017-2023 Johns Hopkins University.
 # All rights reserved.
 #
 # Partial funding for Spire research was provided by the Defense Advanced 
 # Research Projects Agency (DARPA), the Department of Defense (DoD), and the
 # Department of Energy (DoE).
 # Spire is not necessarily endorsed by DARPA, the DoD or the DoE. 
 #
 #
include Makefile.general

# Tells Makefile.general where we are
base_dir=.

.PHONY: all clean plcs libs clean_libs prime clean_prime spines openplc pvb iec substation clean_substation

SUBDIRS=hmis proxy modbus dnp3 benchmark plcs
SS_SUBDIRS= relay_emulator proxy_iec61850 benchmarks_ss trip_master_v2 trip_master

all: base_prime $(SUBDIRS)
	for dir in $(SUBDIRS); do \
    	( $(MAKE) -C $$dir); \
	done
	cd scada_master; make spire

conf_spire: conf_prime $(SUBDIRS)
	for dir in $(SUBDIRS); do \
    	( $(MAKE) -C $$dir); \
	done
	cd scada_master; make conf_spire



substation: base_prime $(SS_SUBDIRS)
	for dir in $(SS_SUBDIRS); do \
    	( $(MAKE) -C $$dir); \
	done

plcs:
	( $(MAKE) -C plcs )


base_prime:
	make -C prime/src base_prime

conf_prime:
	make -C prime/src conf_base_prime

clean_prime:
	make -C prime/src cleaner

openplc:
	cd OpenPLC_v2; ./build.sh

pvb:
	cd pvb; ./build.sh

spines:
	cd spines; ./configure; make -C daemon parser; make

iec: 
	cd libiec61850; make; make install

# Builds libraries
libs: openplc pvb iec spines 


clean_libs: clean_prime
	cd spines;make distclean
	cd libiec61850; make clean; rm -rf .install


clean_substation: 
	for dir in $(SS_SUBDIRS); do \
    	( $(MAKE) -C $$dir clean); \
	done

clean: clean_libs  clean_substation
	for dir in $(SUBDIRS); do \
    	( $(MAKE) -C $$dir clean); \
	done
	cd scada_master; make clean
