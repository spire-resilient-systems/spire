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


#include "recovery.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>

#include "spu_events.h"
#include "spu_alarm.h"
#include "spines_lib.h"

#include "data_structs.h"
#include "decision.h"
#include "utility.h"
#include "receiver.h"


static void RECOVERY_Send_Query(int code, void *dummy);
static void RECOVERY_Done();

static int got_r, got_b;

void RECOVERY_Start()
{
    got_r = 0;
    got_b = 0;

    RECOVERY_Send_Query(0, NULL);
    E_attach_fd(NET.s_relay, READ_FD, RECOVERY_Handle_LR_Msg, NULL, NULL, MEDIUM_PRIORITY);
    E_attach_fd(NET.s_proxy, READ_FD, RECOVERY_Handle_Proxy_Msg, NULL, NULL, MEDIUM_PRIORITY);
    Alarm(DEBUG,"Handled Recovery attachments\n");
    E_handle_events();
    
}

void RECOVERY_Handle_LR_Msg()
{   
    local_relay_msg relay_mess;
    int ret;

    ret = IPC_Recv(NET.s_relay, &relay_mess, sizeof(local_relay_msg));
    if (ret != sizeof(local_relay_msg)) {
        Alarm(EXIT, "Recovery: Received malformed local_relay_msg\n");
    }

    // Throw away old messages
    if (relay_mess.dts < DATA.r.dts) {
        Alarm(PRINT, "Recovery: Received older local_relay_msg than my state vector relay info\n");
        return;
    }

    assert(relay_mess.type == LR_TRIP || relay_mess.type == LR_CLOSE);
    assert(DATA.r.dts <= relay_mess.dts);
        

    DATA.r.state = (relay_mess.type == LR_TRIP) ? STATE_TRIP : STATE_CLOSE;
    DATA.r.dts = relay_mess.dts;
    got_r = 1;
    STATS.lrCount+=1;
    STATS.lrReceived=E_get_time();

    Alarm(PRINT, "Recovery: ****[%lu]:Received LR %s from relay\n",STATS.lrCount,DATA.r.state == STATE_TRIP ? "TRIP" : "CLOSE");

    if (got_r && got_b)
        RECOVERY_Done();
}

void RECOVERY_Handle_Proxy_Msg(int s, int source, void * dummy_p)
{
    
    Alarm(DEBUG,"Recovery_Handle_proxy_Msg\n");
    tm_msg *mess;
    static byte buff[SPINES_MAX_SIZE];
    struct sockaddr_in from_addr;
    socklen_t from_len;
    int ret;
    from_len=sizeof(from_addr);
    
    ret = spines_recvfrom(s, buff, MAX_LEN, 0, (struct sockaddr *) &from_addr, &from_len);
    /* Basic checks on size of message */
    if (ret < sizeof(tm_msg)) {
            Alarm(PRINT,"Recovery: Shorter tm_msg size %d\n",ret);
        return;
    }
    
    mess = (tm_msg *) buff;
    
    if (ret != sizeof(tm_msg) + mess->len){ 
            Alarm(PRINT,"Recovery: Shorter tm_msg size %d\n",ret);
        return;
    }
    
    if (from_addr.sin_addr.s_addr != inet_addr(SPINES_PROXY_ADDR)) {
        Alarm(PRINT, "Recovery: Source %s (from external spines) does not match expected address %s (proxy)", from_addr.sin_addr.s_addr,SPINES_PROXY_ADDR );
        return;
    }

    assert(DATA.b.dts <= mess->dts);
    assert(mess->type == SIGNED_TRIP_ACK || mess->type == SIGNED_CLOSE_ACK);

    DATA.b.state = (mess->type == SIGNED_TRIP_ACK) ? STATE_TRIP : STATE_CLOSE;
    DATA.b.dts = mess->dts;
    got_b = 1;
    if(mess->type==SIGNED_TRIP_ACK)
        DECISION_Send_CB_Status(SIGNED_TRIP_ACK);
    if(mess->type==SIGNED_CLOSE_ACK)
        DECISION_Send_CB_Status(SIGNED_CLOSE_ACK);


    Alarm(PRINT, "Recovery: Received Signed %s ACK from dst_proxy\n", DATA.b.state == STATE_TRIP ? "TRIP" : "CLOSE");

    E_dequeue(RECOVERY_Send_Query, 0, NULL);

    if (got_r && got_b)
        RECOVERY_Done();
}

void RECOVERY_Send_Query(int code, void *dummy)
{
    tm_msg mess;
    sp_time timeout;

    mess.type = RECOVERY_QUERY;
    mess.m_id = DATA.id;
    mess.len  = 0;
    mess.dts  = 0; // This doesn't matter

    Alarm(DEBUG, "Sending RECOVERY_QUERY to dst_proxy\n");

    UTIL_Send_To_Dst_Proxy(&mess);

    // Queue next event
    timeout.sec = RECOVERY_TIMEOUT_SEC;
    timeout.usec = RECOVERY_TIMEOUT_USEC;
    E_queue(RECOVERY_Send_Query, 0, NULL, timeout);
}

void RECOVERY_Done()
{
    if (DATA.r.state == STATE_TRIP && DATA.b.state == STATE_TRIP) {
       DATA.tm_state = TRIPPED; 
    } else if (DATA.r.state == STATE_CLOSE && DATA.b.state == STATE_CLOSE) {
       DATA.tm_state = CLOSED; 
    } else if (DATA.r.state == STATE_TRIP && DATA.b.state == STATE_CLOSE) {
        if (DATA.r.dts >= DATA.b.dts) {
            DATA.tm_state = ATTEMPT_TRIP;
            DECISION_Start_Share_Send(TRIP_SHARE);
        } else {
            DATA.tm_state = WAIT_CLOSE;
        }
    } else if (DATA.r.state == STATE_CLOSE && DATA.b.state == STATE_TRIP) {
        if (DATA.r.dts >= DATA.b.dts) {
            DATA.tm_state = ATTEMPT_CLOSE;
            DECISION_Start_Share_Send(CLOSE_SHARE);
        } else {
            DATA.tm_state = WAIT_TRIP;
        }
    } else {
        assert(false);
    }

    Alarm(PRINT, "Recovery: Recovery complete, moving to ------> %s\n\n", UTIL_Get_State_Str(DATA.tm_state));
    E_detach_fd(NET.s_relay, READ_FD);
    E_detach_fd(NET.s_proxy, READ_FD);
    Alarm(DEBUG, "Recovery: Detached to Recovery functions\n");
    E_attach_fd(NET.s_relay, READ_FD, TM_IPC_Recv, IPC_SOURCE, NULL, MEDIUM_PRIORITY);
    E_attach_fd(NET.s_proxy, READ_FD, TM_Spines_Recv, SP_EXT_SOURCE, NULL, MEDIUM_PRIORITY);
    E_attach_fd(NET.s_coord, READ_FD, TM_Spines_Recv, SP_INT_SOURCE, NULL, MEDIUM_PRIORITY);
    Alarm(DEBUG, "Recovery: Reattached to TM functions\n");
}
