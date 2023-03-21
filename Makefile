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
 #   Sahiti Bommareddy    Contributions to OpenSSL upgrade, latency optimization, IDS
 #
 # Contributors:
 #   Samuel Beckley       Contributions to HMIs 
 #   Daniel Qian          Contributions to IDS
 #
 # Copyright (c) 2018 Johns Hopkins University.
 # All rights reserved.
 #
 # Partial funding for Spire research was provided by the Defense Advanced 
 # Research Projects Agency (DARPA) and the Department of Defense (DoD).
 # Spire is not necessarily endorsed by DARPA or the DoD. 
 #
 #
 
.PHONY: all clean plcs

SUBDIRS=hmis scada_master proxy modbus dnp3 benchmark

all: $(SUBDIRS)
	for dir in $(SUBDIRS); do \
    	( $(MAKE) -C $$dir); \
	done

plcs:
	( $(MAKE) -C plcs )

clean:
	for dir in $(SUBDIRS); do \
    	( $(MAKE) -C $$dir clean); \
	done
