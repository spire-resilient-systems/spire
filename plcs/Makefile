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
 # Johns Hopkins University.
 #
 # Creators:
 #   Yair Amir            yairamir@cs.jhu.edu
 #   Trevor Aron          taron1@cs.jhu.edu
 #   Amy Babay            babay@cs.jhu.edu
 #   Thomas Tantillo      tantillo@cs.jhu.edu
 #
 # Major Contributors:
 #   Marco Platania       Contributions to architecture design 
 #   Sahiti Bommareddy    Addition of IDS, Contributions to OpenSSL upgrade, latency optimization
 #
 # Contributors:
 #   Samuel Beckley       Contributions to HMIs 
 #   Daniel Qian          Contributions to IDS
 #
 # Copyright (c) 2017-2020 Johns Hopkins University.
 # All rights reserved.
 #
 # Partial funding for Spire research was provided by the Defense Advanced 
 # Research Projects Agency (DARPA) and the Department of Defense (DoD).
 # Spire is not necessarily endorsed by DARPA or the DoD. 
 #
 #
 
SUBDIRS=pnnl_plc jhu0 jhu1 jhu2 jhu3 jhu4 jhu5 jhu6 jhu7 jhu8 jhu9 ems0 ems1 ems2 ems_hydro ems_solar ems_wind

.PHONY: all clean $(SUBDIRS)

OPENPLC_DIR=../OpenPLC_v2

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ -f ../plcs.mk $@

clean:
	for dir in $(SUBDIRS); do \
    	( rm $$dir/openplc ); \
	done
