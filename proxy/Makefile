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
 #   Maher Khan           maher@cs.pitt.edu
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

CC=gcc
CFLAGS+= -Wall -W -g
TARGET=proxy
LIBS=-lpthread ../prime/OpenTC-1.1/TC-lib-1.0/.libs/libTC.a \
           ../spines/libspines/libspines.a ../prime/stdutil/lib/libstdutil.a \
		   -lrt -ldl -lcrypto -lpthread -lm
INC= -I ../prime/stdutil/include -I ../spines/libspines/
OBJECTS=proxy.o \
		../common/scada_packets.o \
		../common/net_wrapper.o \
		../common/openssl_rsa.o \
		../common/tc_wrapper.o \
		../common/itrc.o \
		../common/key_value.o \
		../config/cJSON.o \
		../config/config_helpers.o

all: $(TARGET) 

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)

clean:
	rm -f $(OBJECTS)
	rm -f $(TARGET)

proxy.o: proxy.c ../common/scada_packets.h \
				../common/net_wrapper.h ../common/openssl_rsa.h \
				../common/tc_wrapper.h ../common/itrc.h \
				../common/key_value.h ../config/cJSON.h ../config/config_helpers.h
	$(CC) -c $(CFLAGS) $(INC) -o proxy.o proxy.c 

%.o:	%.c
		$(CC) $(CFLAGS) $(INC) -c -o $*.o $*.c
