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

CC            = gcc
CXX           = g++
CFLAGS        = -m64 -pipe -O2 -Wall -W -fPIE -g $(DEFINES)
CXXFLAGS      = -m64 -pipe -O2 -Wall -W -fPIE -g $(DEFINES)
INCPATH       = -I. -I/opt/pvb/rllib/lib -I../prime/stdutil/include -I../spines/libspines/
LINK          = g++
LFLAGS        = -m64 -Wl,-O1
LIBS          = $(SUBLIBS) -lpthread /usr/lib/librllib.so \
				../prime/OpenTC-1.1/TC-lib-1.0/.libs/libTC.a \
				../spines/libspines/libspines.a ../prime/stdutil/lib/libstdutil.a \
				-lrt -ldl -lm -lcrypto
TARGET    = modbus_master
OBJECTS   = modbus_master.o \
            ../common/scada_packets.o \
            ../common/net_wrapper.o \
            ../common/openssl_rsa.o \
            ../common/tc_wrapper.o \
            ../common/key_value.o \
            ../config/cJSON.o \
            ../config/config_helpers.o

.SUFFIXES: .o .c .cpp

.cpp.o:
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o "$@" "$<"

.c.o:
	$(CC) -c $(CFLAGS) $(INCPATH) -o "$@" "$<"

all: $(TARGET)

$(TARGET): $(OBJECTS)  
	$(LINK) $(LFLAGS) -o $(TARGET) $(OBJECTS) $(LIBS)

clean: 
	rm -f $(OBJECTS) 
	rm -f $(TARGET)

modbus_master.o: modbus_master.cpp /opt/pvb/rllib/lib/rlmodbus.h \
		/opt/pvb/rllib/lib/rldefine.h \
		/opt/pvb/rllib/lib/rlsocket.h \
		/opt/pvb/rllib/lib/rlstring.h \
		/opt/pvb/rllib/lib/rlserial.h \
		/opt/pvb/rllib/lib/rlthread.h \
		/opt/pvb/rllib/lib/rlwthread.h \
		/opt/pvb/rllib/lib/rlinifile.h \
		/opt/pvb/rllib/lib/rlspreadsheet.h \
		../common/scada_packets.h \
		../common/net_wrapper.h \
		../common/openssl_rsa.h \
		../common/tc_wrapper.h \
		../common/def.h \
        ../common/key_value.h \
        ../config/cJSON.h \
        ../config/config_helpers.h
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o modbus_master.o modbus_master.cpp

%.o:    %.c
	$(CC) $(CFLAGS) $(INCPATH) -c -o $*.o $*.c	
