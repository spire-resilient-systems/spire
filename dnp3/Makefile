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
 # Major Contributor:
 #   Marco Platania       Contributions to architecture design 
 #
 # Copyright (c) 2017 Johns Hopkins University.
 # All rights reserved.
 #
 # Partial funding for Spire research was provided by the Defense Advanced 
 # Research Projects Agency (DARPA) and the Department of Defense (DoD).
 # Spire is not necessarily endorsed by DARPA or the DoD. 
 #
 #

CC=gcc
CFLAGS= -Wall -W -g
CXX=/toolchains/bin/g++
#CXX=g++   
	#NOTE: if installing newer versions of g++ from scratch, change path accordingly
CXXFLAGS= -std=gnu++11
EXTRA=-fprofile-arcs -ftest-coverage
LINKING= -lasiodnp3 -lasiopal -lopendnp3 -lopenpal -lgcov --coverage -lm
LIBS=-lpthread ../prime/OpenTC-1.1/TC-lib-1.0/.libs/libTC.a \
           ../spines/libspines/libspines.a ../prime/stdutil/lib/libstdutil.a -lrt -ldl -lcrypto
INC= -I ../prime/stdutil/include -I ../spines/libspines/
TARGET=dnp3_master
CXXLIB=-Wl,-rpath,/toolchains/lib64
OBJECTS=main.o \
		callback.o \
		command_sender.o \
		../common/scada_packets.o\
		../common/net_wrapper.o \
		../common/openssl_rsa.o \
		../common/tc_wrapper.o \
		../common/key_value.o \
		../config/cJSON.o \
		../config/config_helpers.o

all: $(TARGET) 

$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJECTS) $(LINKING) $(LIBS) $(CXXLIB)

%.o:	%.cpp
		$(CXX) $(CXXFLAGS) $(INC) -c -o $*.o $*.cpp

%.o:	%.c
		$(CC) $(CFLAGS) $(INC) -c -o $*.o $*.c

clean:
	rm -f $(TARGET)
	rm -f $(OBJECTS)
