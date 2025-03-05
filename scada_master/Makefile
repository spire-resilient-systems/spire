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

CC=gcc
CFLAGS+= -Wall -W -g
TARGET=scada_master gen_keys conf_scada_master conf_gen_keys
INC= -I ../prime/stdutil/include -I ../spines/libspines -I ../common

TC_LIB=../prime/OpenTC-1.1/TC-lib-1.0/.libs/libTC.a
LIBSPREAD_UTIL=../prime/stdutil/lib/libstdutil.a
SPINES_LIB=../spines/libspines/libspines.a

SM_OBJ=scada_master.o \
		queue.o \
		../common/scada_packets.o \
        ../common/net_wrapper.o \
        ../common/openssl_rsa.o \
        ../common/tc_wrapper.o \
        ../common/itrc.o \
		../common/key_value.o \
		../config/cJSON.o \
		../config/config_helpers.o
CONF_SM_OBJ=conf_scada_master.o \
        queue.o \
        ../common/conf_scada_packets.o \
        ../common/conf_net_wrapper.o \
        ../common/conf_openssl_rsa.o \
        ../common/conf_tc_wrapper.o \
        ../common/conf_itrc.o \
        ../common/key_value.o \
        ../config/cJSON.o \
        ../config/config_helpers.o
GEN_KEYS_OBJ = generate_keys.o \
		       ../common/openssl_rsa.o \
			   ../common/tc_wrapper.o
CONF_GEN_KEYS_OBJ = conf_generate_keys.o \
               ../common/conf_openssl_rsa.o \
               ../common/conf_tc_wrapper.o

all: scada_master gen_keys conf_scada_master conf_gen_keys

spire: scada_master gen_keys

conf_spire: conf_scada_master conf_gen_keys

scada_master.o: scada_master.c ../common/scada_packets.h \
				../common/net_wrapper.h ../common/def.h ../common/openssl_rsa.h \
				../common/tc_wrapper.h ../common/itrc.h ../common/key_value.h \
				../config/cJSON.h ../config/config_helpers.h
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $(INC) -o scada_master.o scada_master.c 

scada_master: $(SM_OBJ)
		$(CC) $(LDFLAGS) -o scada_master $(SM_OBJ) $(TC_LIB) $(LIBSPREAD_UTIL) $(SPINES_LIB) -lpthread -ldl -lcrypto -lm -lrt

conf_scada_master.o: conf_scada_master.c ../common/conf_scada_packets.h \
                ../common/conf_net_wrapper.h ../common/def.h ../common/conf_openssl_rsa.h \
                ../common/conf_tc_wrapper.h ../common/conf_itrc.h ../common/key_value.h \
                ../config/cJSON.h ../config/config_helpers.h
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $(INC) -o conf_scada_master.o conf_scada_master.c 

conf_scada_master: $(CONF_SM_OBJ)
	$(CC) $(LDFLAGS) -o conf_scada_master $(CONF_SM_OBJ) $(TC_LIB) $(LIBSPREAD_UTIL) $(SPINES_LIB) -lpthread -ldl -lcrypto -lm -lrt

generate_keys.o: generate_keys.c ../common/itrc.h ../common/tc_wrapper.h
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $(INC) -o generate_keys.o generate_keys.c

gen_keys: $(GEN_KEYS_OBJ)
	$(CC) $(LDFLAGS) -o gen_keys $(GEN_KEYS_OBJ) $(LIBSPREAD_UTIL) $(TC_LIB) -lcrypto -ldl -lpthread -lrt

conf_generate_keys.o: conf_generate_keys.c ../common/conf_itrc.h ../common/conf_tc_wrapper.h 
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $(INC) -o conf_generate_keys.o conf_generate_keys.c

conf_gen_keys: $(CONF_GEN_KEYS_OBJ)
	$(CC) $(LDFLAGS) -o conf_gen_keys $(CONF_GEN_KEYS_OBJ) $(LIBSPREAD_UTIL) $(TC_LIB) -lcrypto -ldl -lpthread -lrt

%.o:	%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(INC) -c -o $*.o $*.c

clean:
	rm -f $(GEN_KEYS_OBJ)
	rm -f $(SM_OBJ)
	rm -f $(CONF_GEN_KEYS_OBJ)
	rm -f $(CONF_SM_OBJ)
	rm -f $(TARGET)

distclean: clean
	cd ./sm_keys; rm -f *.pem; rm -f *.key
