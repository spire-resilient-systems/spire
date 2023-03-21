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
INCPATH       = -I. -I/opt/pvb/pvserver -I../prime/stdutil/include -I../spines/libspines/
LINK          = g++
LFLAGS        = -m64 -Wl,-O1
LIBS          = $(SUBLIBS) /usr/lib/libpvsmt.so -lpthread \
					../prime/OpenTC-1.1/TC-lib-1.0/.libs/libTC.a \
					../spines/libspines/libspines.a ../prime/stdutil/lib/libstdutil.a \
					-lrt -ldl -lcrypto

SOURCES       = jhu_hmi.cpp \
		mask1.cpp \
        master_exec.cpp \
        ../common/scada_packets.c \
        ../common/net_wrapper.c \
        ../common/openssl_rsa.c \
        ../common/tc_wrapper.c \
        ../common/itrc.c \
		../common/key_value.c \
		../config/cJSON.c \
		../config/config_helpers.c 
OBJECTS       = jhu_hmi.o \
		mask1.o \
        master_exec.o \
        ../common/scada_packets.o \
        ../common/net_wrapper.o \
        ../common/openssl_rsa.o \
        ../common/tc_wrapper.o \
        ../common/itrc.o \
		../common/key_value.o \
		../config/cJSON.o \
		../config/config_helpers.o
TARGET        = jhu_hmi


.SUFFIXES: .o .c .cpp .cc .cxx .C

.cpp.o:
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o "$@" "$<"

.c.o:
	$(CC) -c $(CFLAGS) $(INCPATH) -o "$@" "$<"

all: $(TARGET)

$(TARGET):  $(OBJECTS)  
	$(LINK) $(LFLAGS) -o $(TARGET) $(OBJECTS) $(OBJCOMP) $(LIBS)

clean: 
	rm -rf $(OBJECTS)
	rm -rf $(TARGET)

jhu_hmi.o: jhu_hmi.cpp pvapp.h \
		/opt/pvb/pvserver/processviewserver.h \
		/opt/pvb/pvserver/vmsgl.h \
		/opt/pvb/pvserver/vmsglext.h \
		/opt/pvb/pvserver/wthread.h \
		master_exec.h \
		../common/net_wrapper.h \
		../common/openssl_rsa.h \
		../common/tc_wrapper.h \
		../common/def.h \
        ../common/itrc.h \
		../common/key_value.h \
		../config/config_helpers.h \
		../config/cJSON.h 
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o jhu_hmi.o jhu_hmi.cpp

mask1.o: mask1.cpp pvapp.h \
		/opt/pvb/pvserver/processviewserver.h \
		/opt/pvb/pvserver/vmsgl.h \
		/opt/pvb/pvserver/vmsglext.h \
		/opt/pvb/pvserver/wthread.h \
		mask1_slots.h \
		master_exec.h \
        ../common/net_wrapper.h \
        ../common/openssl_rsa.h \
        ../common/tc_wrapper.h \
        ../common/scada_packets.h \
        ../common/itrc.h \
		../common/key_value.h \
		../config/config_helpers.h \
		../config/cJSON.h
	$(CXX) -c $(CXXFLAGS) $(INCPATH) -o mask1.o mask1.cpp
