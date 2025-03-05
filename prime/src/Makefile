#
# Prime.
#      
#  The contents of this file are subject to the Prime Open-Source
#  License, Version 1.0 (the ``License''); you may not use
#  this file except in compliance with the License.  You may obtain a
#  copy of the License at:
# 
#  http://www.dsn.jhu.edu/prime/LICENSE.txt
# 
#  or in the file ``LICENSE.txt'' found in this distribution.
# 
#  Software distributed under the License is distributed on an AS IS basis, 
#  WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
#  for the specific language governing rights and limitations under the 
#  License.
# 
#  Creators:
#    Yair Amir            yairamir@cs.jhu.edu
#    Jonathan Kirsch      jak@cs.jhu.edu
#    John Lane            johnlane@cs.jhu.edu
#    Marco Platania       platania@cs.jhu.edu
#    Amy Babay            babay@pitt.edu
#    Thomas Tantillo      tantillo@cs.jhu.edu
# 
#  Major Contributors:
#    Brian Coan           Design of the Prime algorithm
#    Jeff Seibert         View Change protocol 
#    Sahiti Bommareddy    Reconfiguration 
#    Maher Khan           Reconfiguration 
#  
#  Copyright (c) 2008-2025
#  The Johns Hopkins University.
#  All rights reserved.
#  
#  Partial funding for Prime research was provided by the Defense Advanced 
#  Research Projects Agency (DARPA) and the National Science Foundation (NSF).
#  Prime is not necessarily endorsed by DARPA or the NSF.  
# 
# 

INC = -I../stdutil/include -I../libspread-util/include -I../libspread-util/src -I../../spines/libspines
STDUTIL_LIB = ../stdutil/lib/libstdutil.a
LIBSPREAD_UTIL = ../libspread-util/src/libspread-util.a
TC_LIB = ../OpenTC-1.1/TC-lib-1.0/.libs/libTC.a

# Prime can be configured to make use of Spines, an overlay network
# developed at Johns Hopkins (see http://spines.org). This can be
# useful for testing wide-area topologies and placing bandwidth and
# latency constraints on the links between servers. By default,
# Prime is set up to use Spines. Spines is included in the
# spines directory. To not use Spines, comment the following two lines:
SPINES = -DSET_USE_SPINES 
SPINES_LIB = ../../spines/libspines/libspines.a

CC = gcc
#CFLAGS = -g -pg -O2 -Wall $(SPINES) $(INC)  
CFLAGS += -g -O2 -Wall -DNDEBUG $(SPINES) $(INC)  

WRAPPER_OBJ = error_wrapper.o openssl_rsa.o

PRIME_OBJ = prime.o data_structs.o utility.o network.o pre_order.o \
	util_dll.o validate.o nm_process.o process.o packets.o order.o  \
	signature.o net_wrapper.o merkle.o suspect_leader.o \
	reliable_broadcast.o view_change.o erasure.o recon.o \
	tc_wrapper.o catchup.o proactive_recovery.o $(WRAPPER_OBJ)


DRIVER_OBJ = driver.o data_structs.o utility.o network.o pre_order.o \
	util_dll.o packets.o nm_process.o process.o order.o \
	signature.o net_wrapper.o erasure.o validate.o suspect_leader.o \
	reliable_broadcast.o view_change.o catchup.o proactive_recovery.o \
	merkle.o recon.o tc_wrapper.o $(WRAPPER_OBJ)

CM_OBJ=config_manager.o data_structs.o utility.o network.o pre_order.o \
        util_dll.o packets.o nm_process.o process.o order.o \
        signature.o net_wrapper.o erasure.o validate.o suspect_leader.o \
        reliable_broadcast.o view_change.o catchup.o proactive_recovery.o \
        merkle.o recon.o tc_wrapper.o $(WRAPPER_OBJ)

CA_OBJ=config_agent.o data_structs.o utility.o network.o pre_order.o \
        util_dll.o packets.o nm_process.o process.o order.o \
        signature.o net_wrapper.o erasure.o validate.o suspect_leader.o \
        reliable_broadcast.o view_change.o catchup.o proactive_recovery.o \
        merkle.o recon.o tc_wrapper.o $(WRAPPER_OBJ)


GEN_KEYS_OBJ =  generate_keys.o tc_wrapper.o data_structs.o utility.o network.o pre_order.o \
        util_dll.o validate.o nm_process.o process.o packets.o order.o  \
        signature.o net_wrapper.o merkle.o suspect_leader.o proactive_recovery.o\
        reliable_broadcast.o view_change.o erasure.o recon.o  catchup.o $(WRAPPER_OBJ)

all: $(STDUTIL_LIB) $(LIBSPREAD_UTIL) $(TC_LIB) prime driver gen_keys config_manager config_agent





$(STDUTIL_LIB):
	cd ../stdutil; ./configure; make

$(LIBSPREAD_UTIL):
	cd ../libspread-util; ./configure --enable-threaded-alarm; make

$(TC_LIB):
	cd ../OpenTC-1.1/TC-lib-1.0/; ./configure; make

gen_keys: $(GEN_KEYS_OBJ)
	$(CC) $(LDFLAGS) -o ../bin/gen_keys $(GEN_KEYS_OBJ) $(LIBSPREAD_UTIL) $(TC_LIB) $(SPINES_LIB) $(STDUTIL_LIB) -lcrypto -ldl -lpthread -lrt

prime: $(PRIME_OBJ)
	$(CC) $(LDFLAGS) $(CPPFLAGS) -o ../bin/prime $(PRIME_OBJ) $(STDUTIL_LIB) $(LIBSPREAD_UTIL) $(TC_LIB) $(SPINES_LIB) -lm -lcrypto -ldl -lpthread -lrt


driver: $(DRIVER_OBJ)
	$(CC) $(LDFLAGS) -o ../bin/driver $(DRIVER_OBJ) $(STDUTIL_LIB) $(LIBSPREAD_UTIL) $(TC_LIB) $(SPINES_LIB) -lm -lcrypto -ldl -lpthread -lrt

config_manager:  $(CM_OBJ)
	 $(CC) $(LDFLAGS) -o ../bin/config_manager $(CM_OBJ) $(STDUTIL_LIB) $(LIBSPREAD_UTIL) $(TC_LIB) $(SPINES_LIB) -lm -lcrypto -ldl -lpthread -lrt

config_agent:  $(CA_OBJ)
	 $(CC) $(LDFLAGS) -o ../bin/config_agent $(CA_OBJ) $(STDUTIL_LIB) $(LIBSPREAD_UTIL) $(TC_LIB) $(SPINES_LIB) -lm -lcrypto -ldl -lpthread -lrt

%.o:	%.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $*.o $*.c

clean:
	rm -f *~
	rm -f *.o
	rm -f core*
	rm -f ../bin/prime
	rm -f ../bin/driver
	rm -f ../bin/gen_keys
	rm -f ../bin/config_manager
	rm -f ../bin/config_agent

# Also cleans up the stdutil, libspread-util, and OpenTC libraries
# Uses - to ignore errors, since these fail if clean is run multiple times
cleaner: clean
	-$(MAKE) -C ../stdutil distclean
	-$(MAKE) -C ../libspread-util distclean
	-$(MAKE) -C ../OpenTC-1.1/TC-lib-1.0/ distclean

# Also removes all key files
distclean: cleaner
	cd ../bin/keys; rm -f *.pem; rm -f *.key
	cd ../bin/tpm_keys; rm -f *.pem; rm -f *.key
