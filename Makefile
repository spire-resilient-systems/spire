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
 # Copyright (c) 2017-2025 Johns Hopkins University.
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

.PHONY: all conf_spire substation core spines prime scada_master benchmark conf_core conf_scada_master libs openplc pvb iec clean_prime clean_libs clean_spire clean_substation clean

SUBDIRS=hmis proxy modbus dnp3 benchmark plcs
SS_SUBDIRS= relay_emulator proxy_iec61850 benchmarks_ss trip_master_v2 trip_master

# Build full Spire system (note: need to build libs separately first)
all: prime $(SUBDIRS)
	for dir in $(SUBDIRS); do \
    	( $(MAKE) -C $$dir); \
	done
	$(MAKE) -C scada_master spire

# Build full Confidential Spire system (note: need to build libs separately first)
conf_spire: prime $(SUBDIRS)
	for dir in $(SUBDIRS); do \
    	( $(MAKE) -C $$dir); \
	done
	$(MAKE) -C scada_master conf_spire

# Build Spire for the Substation (note: need to build libs separately first)
substation: prime $(SS_SUBDIRS)
	for dir in $(SS_SUBDIRS); do \
    	( $(MAKE) -C $$dir); \
	done

# Build core of Spire system for benchmarking (without PLCs and HMIs)
core: spines prime scada_master benchmark

spines:
	cd spines; ./configure; $(MAKE) -C daemon parser; $(MAKE)

prime:
	$(MAKE) -C prime/src

scada_master:
	$(MAKE) -C scada_master spire

benchmark:
	$(MAKE) -C benchmark

# Build core of Confidential Spire system for benchmarking (without PLCs and HMIs)
conf_core: spines prime conf_scada_master benchmark

conf_scada_master:
	$(MAKE) -C scada_master conf_spire

# Build libraries needed for full Spire system (including all SCADA components)
libs: openplc pvb iec spines

openplc:
	cd OpenPLC_v2; ./build.sh

pvb:
	cd pvb; ./build.sh

iec: 
	cd libiec61850; $(MAKE); $(MAKE) install

# Clean
clean_prime:
	$(MAKE) -C prime/src cleaner

clean_libs: clean_prime
	-$(MAKE) -C spines distclean # ignore errors, since this fails if clean is run multiple times
	cd libiec61850; $(MAKE) clean; rm -rf .install

clean_substation: 
	for dir in $(SS_SUBDIRS); do \
    	( $(MAKE) -C $$dir clean); \
	done

clean_spire:
	for dir in $(SUBDIRS); do \
    	( $(MAKE) -C $$dir clean); \
	done
	$(MAKE) -C scada_master clean

clean: clean_libs clean_substation clean_spire
