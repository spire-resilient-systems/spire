#
 # Spire.
 #
 # The contents of this file are subject to the Spire Open-Source
 # License, Version 1.0 (the ``License''); you may not use
 # this file except in compliance with the License.  You may obtain a
 # copy of the License at:
 #
 # https://jhu-dsn.github.io/spire/LICENSE.txt
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
 # Copyright (c) 2017-2026 Johns Hopkins University.
 # All rights reserved.
 #
 # Partial funding for Spire research was provided by the Defense Advanced
 # Research Projects Agency (DARPA), the Department of Defense (DoD), and the
 # Department of Energy (DoE).
 # Spire is not necessarily endorsed by DARPA, the DoD or the DoE.
 #
 #



include ../Makefile.general
base_dir = ..

TARGET=emulated_mu goose_publisher 
INC= -I ../common $(IEC_INC) $(SPREADUTIL_INC) $(SPINES_INC) $(TC_INC) 

EMU_OBJ=emulated_mu.o \
	../common/net_wrapper.o 

all: emulated_mu goose_publisher  


emulated_mu:	$(EMU_OBJ)
	$(CC) $(LDFLAGS) -o emulated_mu $(EMU_OBJ) $(IEC_LIB) $(SPINES_LIB) $(SPREADUTIL_LIB) $(TC_LIB)

goose_publisher:	goose_publisher.o 
	$(CC) $(LDFLAGS) -o goose_publisher goose_publisher.o $(IEC_LIB) $(SPREADUTIL_LIB)

%.o:	%.c
	$(CC) $(CFLAGS) $(INC) -c -o $*.o $*.c

clean:
	rm -f *.o
	rm -f ../common/*.o
	rm -f $(TARGET)
