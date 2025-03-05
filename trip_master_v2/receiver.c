/*
 * Spire.
 *
 * The contents of this file are subject to the Spire Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.dsn.jhu.edu/spire/LICENSE.txt
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Spire is developed at the Distributed Systems and Networks Lab,
 * Johns Hopkins University and the Resilient Systems and Societies Lab,
 * University of Pittsburgh.
 *
 * Creators:
 *   Yair Amir            yairamir@cs.jhu.edu
 *   Trevor Aron          taron1@cs.jhu.edu
 *   Amy Babay            babay@pitt.edu
 *   Thomas Tantillo      tantillo@cs.jhu.edu 
 *   Sahiti Bommareddy    sahiti@cs.jhu.edu 
 *   Maher Khan           maherkhan@pitt.edu
 *
 * Major Contributors:
 *   Marco Platania       Contributions to architecture design 
 *   Daniel Qian          Contributions to Trip Master and IDS
 *
 * Contributors:
 *   Samuel Beckley       Contributions to HMIs
 *
 * Copyright (c) 2017-2025 Johns Hopkins University.
 * All rights reserved.
 *
 * Partial funding for Spire research was provided by the Defense Advanced
 * Research Projects Agency (DARPA), the Department of Defense (DoD), and the
 * Department of Energy (DoE).
 * Spire is not necessarily endorsed by DARPA, the DoD or the DoE.
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>

#include "spu_alarm.h"
#include "spu_events.h"
#include "spines_lib.h"

#include "ss_net_wrapper.h"
#include "def.h"
#include "packets.h"
#include "ss_openssl_rsa.h"
#include "data_structs.h"
#include "receiver.h"
#include "utility.h"
#include "decision.h"





void TM_IPC_Recv(int s, int code, void *dummy)
{
    /* This is on the same machine, so no need to do super rigorous checks */
    local_relay_msg relay_mess;
    uint32_t prev_state;
    int ret;

    ret = IPC_Recv(s, &relay_mess, sizeof(local_relay_msg));

    //TODO: Check with Dan - dont exit but return after print
    if (ret != sizeof(local_relay_msg)) {
        Alarm(PRINT, "TM Receiver: Received malformed local_relay_msg\n");
        return;
    }



    // Throw away old messages
    if (relay_mess.dts < DATA.r.dts) {
        Alarm(PRINT, "TM Receiver: Received older local_relay_msg than my state vector relay info\n");
        return;
    }

    //assert(relay_mess.type == LR_TRIP || relay_mess.type == LR_CLOSE);
    if(relay_mess.type != LR_TRIP && relay_mess.type != LR_CLOSE){
        Alarm(PRINT, "Receiver: Received wrong message type.\n");
        return;
    }
    assert(DATA.r.dts <= relay_mess.dts);
    
    STATS.actions_count+=1;
    
    Alarm(STATUS, " ******[%lu] : Received local relay %s with dts= %ld\n",STATS.actions_count,(relay_mess.type == LR_CLOSE ? "CLOSE" : "TRIP"), relay_mess.dts);

    

    prev_state = DATA.tm_state;
    switch (relay_mess.type) {
        case LR_CLOSE:        
            DECISION_Handle_LR_Close(&relay_mess);
            break;

        case LR_TRIP:        
            DECISION_Handle_LR_Trip(&relay_mess);
            break;
        
        default:
            Alarm(PRINT, "Invalid type %d, ignoring\n", relay_mess.type);
            return;
    }

    if (prev_state != DATA.tm_state) {
        Alarm(STATUS, "Transition from %s --> %s\n",UTIL_Get_State_Str(prev_state), UTIL_Get_State_Str(DATA.tm_state));
    }
}

void TM_Spines_Recv(int s, int source, void *dummy)
{
    static byte buff[SPINES_MAX_SIZE];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    int prev_state;
    int ret;
    unsigned char * sign;
    
    tm_msg *mess;

    ret = spines_recvfrom(s, buff, MAX_LEN, 0, (struct sockaddr *) &from_addr, &from_len);
    
    /* Basic checks on size of message */
    if (ret < sizeof(tm_msg)){
        Alarm(PRINT,"TM Receiver: Shorter tm_msg size %d\n",ret);
        return;
    }

    mess = (tm_msg *) buff;

    if (ret != sizeof(tm_msg) + mess->len){
        Alarm(PRINT,"TM Receiver: Shorter tm_msg size %d\n",ret);
        return;
    }

    /* Check claimed sender is consistent with spines addrs (spines does signing) */
    if (mess->m_id != (NUM_REPLICAS+1)) return;
    if (source == SP_EXT_SOURCE && from_addr.sin_addr.s_addr != inet_addr(SPINES_PROXY_ADDR)) {
        Alarm(PRINT, "TM Receiver: Source (External Spines) does not match expected address %s (proxy)", SPINES_PROXY_ADDR );
        return;
    }

    // Throw away old messages
    if (mess->dts < DATA.b.dts) {
        Alarm(DEBUG, "Discard mess with dts=%lu from %lu as curr b.dts=%lu\n",mess->dts,mess->m_id,DATA.b.dts);
        return;
    }
   
    //assert(mess->type == SIGNED_TRIP_ACK || mess->type == SIGNED_CLOSE_ACK);
    if(mess->type != SIGNED_TRIP_ACK && mess->type != SIGNED_CLOSE_ACK){
        Alarm(PRINT,"TM Receiver: Not an Ack message \n");
        return;
    }
    sign=(sig_payload *)(mess+1);
    ret=OPENSSL_RSA_Verify(mess,sizeof(tm_msg),sign,mess->m_id-NUM_REPLICAS,RSA_CLIENT);
    if(!ret){
        Alarm(PRINT,"TM Receiver: RSA Verify failed for ack\n");
        return;
    }

    Alarm(DEBUG, "TM Receiver: Received valid %s mess with dts=%lu from %lu as curr b.dts=%lu\n",mess->type==SIGNED_TRIP_ACK?"TRIP ACK":"CLOSE ACK",mess->dts,mess->m_id,DATA.b.dts);

    prev_state = DATA.tm_state;
    switch (mess->type) {
        case SIGNED_TRIP_ACK:        
            DECISION_Handle_Trip_Ack(mess);
            break;
        case SIGNED_CLOSE_ACK:        
            DECISION_Handle_Close_Ack(mess);
            break;
        
        default:
            Alarm(PRINT, "Invalid type %d, ignoring\n", mess->type);
            return;
    }
    
    if (prev_state != DATA.tm_state) {
        Alarm(STATUS, "Transition from %s --> %s\n", UTIL_Get_State_Str(prev_state), UTIL_Get_State_Str(DATA.tm_state));
    }

}
