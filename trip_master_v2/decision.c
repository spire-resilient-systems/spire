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

#include <string.h>
#include <assert.h>


#include "spu_alarm.h"
#include "spu_events.h"

#include "data_structs.h"
#include "packets.h"
#include "utility.h"
#include "decision.h"


static void DECISION_Stop_Relay_Send_Periodic(int type);
static void DECISION_Relay_Send_Periodic(int type, void *v_mess);


void DECISION_Handle_LR_Trip(local_relay_msg *mess)
{
    // Note we always update dts and set state (or state is already STATE_TRIP like in TRIPPED)
    DATA.r.state = STATE_TRIP;
    DATA.r.dts = mess->dts;
    switch (DATA.tm_state)
    {
        case TRIPPED:
            break;

        case CLOSED:
            DATA.tm_state = ATTEMPT_TRIP;
            DECISION_Start_Relay_Send(RELAY_TRIP);
            break;

        case ATTEMPT_TRIP:
            break;

        case ATTEMPT_CLOSE:
            DECISION_Stop_Relay_Send_Periodic(RELAY_CLOSE);
            DATA.tm_state = TRIPPED;
            break;

        case WAIT_TRIP:
            DATA.tm_state = TRIPPED;
            break;

        case WAIT_CLOSE:
            DATA.tm_state = ATTEMPT_TRIP;
            DECISION_Start_Relay_Send(RELAY_TRIP);
            break;

        default:
            Alarm(PRINT,"type= LR_TRIP,dts=%lu \n",mess->dts);
            Alarm(EXIT, "DECISION_Handle_LR_Trip:Invalid State %d\n", DATA.tm_state);
    }

}

void DECISION_Handle_LR_Close(local_relay_msg *mess)
{
    DATA.r.state = STATE_CLOSE;
    DATA.r.dts = mess->dts;
    switch (DATA.tm_state)
    {
        case TRIPPED:
            DATA.tm_state = ATTEMPT_CLOSE;
            DECISION_Start_Relay_Send(RELAY_CLOSE);
            break;

        case CLOSED:
            break;

        case ATTEMPT_TRIP:
            DECISION_Stop_Relay_Send_Periodic(RELAY_TRIP);
            DATA.tm_state = CLOSED;
            break;

        case ATTEMPT_CLOSE:
            break;

        case WAIT_TRIP:
            DATA.tm_state = ATTEMPT_CLOSE;
            DECISION_Start_Relay_Send(RELAY_CLOSE);
            break;

        case WAIT_CLOSE:
            DATA.tm_state = CLOSED;
            break;

        default:
            Alarm(PRINT,"type= LR_TRIP,dts=%lu \n",mess->dts);
            Alarm(EXIT, "DECISION_Handle_LR_Close: Invalid State %d\n", DATA.tm_state);
    }

}


void DECISION_Handle_Trip_Ack(tm_msg *mess)
{
    switch (DATA.tm_state)
    {
        case TRIPPED:
            break;

        case CLOSED:
            if (mess->dts > DATA.r.dts) {
                DATA.tm_state = WAIT_TRIP;
            } else {
                DATA.tm_state = ATTEMPT_CLOSE;
                DECISION_Start_Relay_Send(RELAY_CLOSE);
            }
            break;

        case ATTEMPT_TRIP:
            DECISION_Stop_Relay_Send_Periodic(RELAY_TRIP);
            DATA.tm_state = TRIPPED;
            break;

        case ATTEMPT_CLOSE:
            if (mess->dts > DATA.r.dts) {
                DECISION_Stop_Relay_Send_Periodic(RELAY_CLOSE);
                DATA.tm_state = WAIT_TRIP;
            } else {
                return; // So we don't update our b vector
            }
            break;

        case WAIT_TRIP:
            break;

        case WAIT_CLOSE:
            DATA.tm_state = TRIPPED;
            break;

        default:
            Alarm(EXIT, "DECISION_Handle_Trip_Ack: Invalid State %d\n", DATA.tm_state);
    }

    DATA.b.state = STATE_TRIP;
    DATA.b.dts = mess->dts;

    DECISION_Send_CB_Status(SIGNED_TRIP_ACK);

}


void DECISION_Handle_Close_Ack(tm_msg *mess)
{
    switch (DATA.tm_state)
    {
        case TRIPPED:
            if (mess->dts > DATA.r.dts) {
                DATA.tm_state = WAIT_CLOSE;
            } else {
                DATA.tm_state = ATTEMPT_TRIP;
                DECISION_Start_Relay_Send(RELAY_TRIP);
            }
            break;

        case CLOSED:
            break;

        case ATTEMPT_TRIP:
            if (mess->dts > DATA.r.dts) {
                DECISION_Stop_Relay_Send_Periodic(RELAY_TRIP);
                DATA.tm_state = WAIT_CLOSE;
            } else {
                return; // So we don't update our b vector
            }
            break;

        case ATTEMPT_CLOSE:
            DECISION_Stop_Relay_Send_Periodic(RELAY_CLOSE);
            DATA.tm_state=CLOSED;
            break;

        case WAIT_TRIP:
            DATA.tm_state = CLOSED;
            break;

        case WAIT_CLOSE:
            break;

        default:
            Alarm(EXIT, "DECISION_Handle_Close_Ack:Invalid State %d\n", DATA.tm_state);
    }
    DATA.b.state = STATE_CLOSE;
    DATA.b.dts = mess->dts;


    DECISION_Send_CB_Status(SIGNED_CLOSE_ACK);

}

void DECISION_Start_Relay_Send(int type)
{
    assert((DATA.tm_state == ATTEMPT_TRIP && type == RELAY_TRIP) || (DATA.tm_state == ATTEMPT_CLOSE && type == RELAY_CLOSE));
    DATA.cur_relay_msg = PKT_Construct_TM_Message(type, DATA.id, DATA.r.dts, sizeof(sig_payload));
    DECISION_Relay_Send_Periodic(type,(void *) DATA.cur_relay_msg);
    

}

static void DECISION_Relay_Send_Periodic(int type, void *v_mess)
{
    tm_msg *mess;

    sp_time next_send, now;
    uint64_t now_msec;

    mess = (tm_msg *) v_mess;
    //TODO: Sahiti- extract time might help in DoS
    now=E_get_time();
    now_msec=now.sec * 1000 + now.usec / 1000;
    mess->dts = (now_msec / DTS_INTERVAL) * DTS_INTERVAL;
    //Take prefilled packet and sign
    OPENSSL_RSA_Sign(((byte*)mess),sizeof(tm_msg),(byte*)(mess+1));
    //send to dest proxy
    UTIL_Send_To_Dst_Proxy(mess);
    Alarm(DEBUG, "Sending %s  with dts of %ld\n", (type == RELAY_TRIP ? "RELAY TRIP" : "RELAY CLOSE"), mess->dts);
    //Increment dts for next resend
    mess->dts += DTS_INTERVAL;

    //Avoids drift
    next_send.sec = mess->dts / 1000;
    next_send.usec = (mess->dts % 1000) * 1000;
    now = E_get_time();
    if(DOS==DATA.id) return;
    E_queue(DECISION_Relay_Send_Periodic, type, v_mess, E_sub_time(next_send, now));
}

static void DECISION_Stop_Relay_Send_Periodic(int type)
{
    //assert(E_in_queue(DECISION_Relay_Send_Periodic, type, DATA.cur_relay_msg));
    if(E_in_queue(DECISION_Relay_Send_Periodic, type, DATA.cur_relay_msg)){
        E_dequeue(DECISION_Relay_Send_Periodic, type, DATA.cur_relay_msg);
        free(DATA.cur_relay_msg);
        DATA.cur_relay_msg = NULL;
    }
}


void DECISION_Send_CB_Status(int type){
    local_relay_msg relay_mess;

    if(type==SIGNED_TRIP_ACK)
        relay_mess.type=SIGNED_TRIP_ACK;
    else
        relay_mess.type=SIGNED_CLOSE_ACK;
    if(DATA.cb_prev_state!=relay_mess.type){
        UTIL_Send_To_Relay_Proxy(&relay_mess);
        DATA.cb_prev_state=relay_mess.type;
        Alarm(STATUS,"Sending CB status to Relay proxy. Status=%s\n",type==SIGNED_TRIP_ACK?"SIGNED_TRIP_ACK":"SIGNED_CLOSE_ACK");
    }


}
