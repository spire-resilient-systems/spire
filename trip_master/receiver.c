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
#include "ss_tc_wrapper.h"
#include "ss_openssl_rsa.h"
#include "data_structs.h"
#include "recovery.h"
#include "decision.h"
#include "receiver.h"
#include "utility.h"






void TM_IPC_Recv(int s, int code, void *dummy)
{
    /* This is on the same machine, so no need to do super rigorous checks */
    local_relay_msg relay_mess;
    uint32_t prev_state;
    int ret;

    ret = IPC_Recv(s, &relay_mess, sizeof(local_relay_msg));

    //TODO: Check with Dan - dont exit but return after print
    if (ret != sizeof(local_relay_msg)) {
        Alarm(EXIT, "TM: Received malformed local_relay_msg\n");
    }



    // Throw away old messages
    if (relay_mess.dts < DATA.r.dts) {
        return;
    }
    //Handle stats, increase lr counti, time when event is received, mark that we have not received others share for event 
    STATS.lrCount+=1;
    STATS.lrReceived=E_get_time();
    STATS.otherFirst=0;
    
    Alarm(STATUS, " ******[%lu] : Received local relay %s with dts= %ld\n",STATS.lrCount ,(relay_mess.type == LR_CLOSE ? "CLOSE" : "TRIP"), relay_mess.dts);

    

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
        Alarm(STATUS, "Transition from %s --> %s\n\n",UTIL_Get_State_Str(prev_state), UTIL_Get_State_Str(DATA.tm_state));
    }
}

void TM_Spines_Recv(int s, int source, void *dummy)
{
    static byte buff[SPINES_MAX_SIZE];
    struct sockaddr_in from_addr;
    socklen_t from_len = sizeof(from_addr);

    int prev_state;
    int ret;
    
    tm_msg *mess;

    ret = spines_recvfrom(s, buff, MAX_LEN, 0, (struct sockaddr *) &from_addr, &from_len);
    
    /* Basic checks on size of message */
    if (ret < sizeof(tm_msg)) return;

    mess = (tm_msg *) buff;

    if (ret != sizeof(tm_msg) + mess->len) return;

    /* Check claimed sender is consistent with spines addrs (spines does signing) */
    if (mess->m_id < 1 || mess->m_id > NUM_REPLICAS) return;
    if (source == SP_EXT_SOURCE && from_addr.sin_addr.s_addr != inet_addr(SPINES_PROXY_ADDR)) {
        Alarm(PRINT, "Source (External Spines) does not match expected address %s (proxy)", SPINES_PROXY_ADDR );
        return;
    }
    if (source == SP_INT_SOURCE && from_addr.sin_addr.s_addr != inet_addr(Relay_Int_Addrs[mess->m_id - 1])) {
        Alarm(PRINT, "Machine id %d does not match internal address %s!\n", mess->m_id, Relay_Int_Addrs[mess->m_id - 1]);
        return;
    }

    // Throw away old messages
    if (mess->dts < DATA.b.dts) {
        Alarm(DEBUG, "Discard mess with dts=%lu from %lu as curr b.dts=%lu\n",mess->dts,mess->m_id,DATA.b.dts);
        return;
    }
    


    prev_state = DATA.tm_state;
    switch (mess->type) {
        case TRIP_SHARE:        
            DECISION_Handle_Trip_Share(mess);
            break;
        case CLOSE_SHARE:        
            DECISION_Handle_Close_Share(mess);
            break;
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
        Alarm(STATUS, "Transition from %s --> %s\n\n", UTIL_Get_State_Str(prev_state), UTIL_Get_State_Str(DATA.tm_state));
        if(STATS.lrCount%BENCH_COUNT==0 &&(DATA.tm_state==TRIPPED ||DATA.tm_state==CLOSED)){
            UTIL_Print_Bench_Stats();
        }
    }

}
