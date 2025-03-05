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


/* Local Functions to send periodic messages. Note that we use the fact that only one kind of message is sent at a time*/
void DECISION_Start_Share_Send(int type); // Exposed for recovery.c
static void DECISION_Share_Periodic(int type, void *v_mess);
static void DECISION_Stop_Share_Send(int type);

static void DECISION_Signed_Periodic(int code, void *dummy);
static void DECISION_Stop_Signed_Send();

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
            DECISION_Stop_Signed_Send(SIGNED_CLOSE);
            DATA.tm_state = ATTEMPT_TRIP;
            DECISION_Start_Share_Send(TRIP_SHARE);
            break;

        case ATTEMPT_TRIP:
            break; 
            
        case ATTEMPT_CLOSE:
            DECISION_Stop_Share_Send(CLOSE_SHARE);
            DATA.tm_state = TRIPPED;
            break;

        case WAIT_TRIP:
            DATA.tm_state = TRIPPED;
            break;

        case WAIT_CLOSE:
            DATA.tm_state = ATTEMPT_TRIP;
            DECISION_Start_Share_Send(TRIP_SHARE);
            break;

        default:
            Alarm(EXIT, "Invalid State %d\n", DATA.tm_state);
    }

}

void DECISION_Handle_LR_Close(local_relay_msg *mess)
{
    DATA.r.state = STATE_CLOSE;
    DATA.r.dts = mess->dts;
    switch (DATA.tm_state) 
    {
        case TRIPPED:
            DECISION_Stop_Signed_Send(SIGNED_TRIP);
            DATA.tm_state = ATTEMPT_CLOSE;
            DECISION_Start_Share_Send(CLOSE_SHARE);
            break;

        case CLOSED:
            break;

        case ATTEMPT_TRIP:
            DECISION_Stop_Share_Send(TRIP_SHARE);
            DATA.tm_state = CLOSED;
            break; 
            
        case ATTEMPT_CLOSE:
            break;

        case WAIT_TRIP:
            DATA.tm_state = ATTEMPT_CLOSE;
            DECISION_Start_Share_Send(CLOSE_SHARE);
            break;

        case WAIT_CLOSE:
            DATA.tm_state = CLOSED;
            break;

        default:
            Alarm(EXIT, "Invalid State %d\n", DATA.tm_state); 
    }
}

void DECISION_Handle_Trip_Share(tm_msg *mess)
{
    Alarm(STATUS, "Receive TRIP Share from machine %d with dts %ld\n", mess->m_id, mess->dts);
    
    sp_time now;
    if(STATS.otherFirst==0 && mess->m_id!=DATA.id){
	    now=E_get_time();
    	STATS.firstShare[((STATS.lrCount-1)%BENCH_COUNT)+1]=diffTime_usec(now,STATS.lrReceived);
	    STATS.otherFirst=1;
	    Alarm(DEBUG,"Capturing first share duration from other machine \n");
    }
    switch (DATA.tm_state)
    {
        case TRIPPED:
        case CLOSED:
            break;
        
        case ATTEMPT_TRIP:
            UTIL_Store_Trip_Share(mess);

            if (UTIL_Attempt_Combine_Trip())  {
                DATA.b.state = STATE_TRIP;
                // TODO make sure this is right
                DATA.b.dts = DATA.cur_signed->dts; 

                DECISION_Stop_Share_Send(TRIP_SHARE);
                DATA.tm_state = TRIPPED;
		        now=E_get_time();
		        STATS.resolved[((STATS.lrCount-1)%BENCH_COUNT)+1]=diffTime_usec(now,STATS.lrReceived);
                DECISION_Signed_Periodic(0, NULL);
            }
            break;

        case ATTEMPT_CLOSE:
        case WAIT_TRIP:
        case WAIT_CLOSE:
            break;

        default:
            Alarm(EXIT, "Invalid State %d\n", DATA.tm_state);
    }

    Alarm(DEBUG, "Exiting Receive TRIP Share from machine %d with dts %ld\n", mess->m_id, mess->dts);
}

void DECISION_Handle_Close_Share(tm_msg *mess)
{
    Alarm(STATUS, "Receive CLOSE Share from machine %d with dts=%lu\n", mess->m_id,mess->dts);
    sp_time now;
    if(STATS.otherFirst==0 && mess->m_id!=DATA.id){
	    now=E_get_time();
    	STATS.firstShare[((STATS.lrCount-1)%BENCH_COUNT)+1]=diffTime_usec(now,STATS.lrReceived);
	    STATS.otherFirst=1;
	    Alarm(STATUS,"Capturing first share duration from other machine \n");
    }
    switch (DATA.tm_state)
    {
        case TRIPPED:
        case CLOSED:
        case ATTEMPT_TRIP:
            break;
        
        case ATTEMPT_CLOSE:
            UTIL_Store_Close_Share(mess);

            if (UTIL_Attempt_Combine_Close())  {
                DATA.b.state = STATE_CLOSE;
                // TODO make sure this is right
                DATA.b.dts = DATA.cur_signed->dts; 

                DECISION_Stop_Share_Send(CLOSE_SHARE);
                DATA.tm_state = CLOSED;
		        now=E_get_time();
		        STATS.resolved[((STATS.lrCount-1)%BENCH_COUNT)+1]=diffTime_usec(now,STATS.lrReceived);
                DECISION_Signed_Periodic(0, NULL);
            }
            break;

        case WAIT_TRIP:
        case WAIT_CLOSE:
            break;

        default:
            Alarm(EXIT, "Invalid State %d\n", DATA.tm_state);
    }

    Alarm(DEBUG, "Exiting Handle close share on Receive CLOSE Share from machine %d\n", mess->m_id);

}

void DECISION_Handle_Trip_Ack(tm_msg *mess)
{
    Alarm(STATUS, "Receive Trip Ack\n");
    switch (DATA.tm_state)
    {
        case TRIPPED:
            DECISION_Stop_Signed_Send();
            break;
            
        case CLOSED:
            DECISION_Stop_Signed_Send();
            if (mess->dts > DATA.r.dts) {
                DATA.tm_state = WAIT_TRIP;
            } else {
                DATA.tm_state = ATTEMPT_CLOSE;
                DECISION_Start_Share_Send(CLOSE_SHARE);
            }
            break;
        
        case ATTEMPT_TRIP:
            // TODO if (mess->dts > DATA.r.dts)  DQ: Probably not, but should discuss
            DECISION_Stop_Share_Send(TRIP_SHARE);
            DATA.tm_state = TRIPPED;
            break;

        case ATTEMPT_CLOSE:
            if (mess->dts > DATA.r.dts) {
                DECISION_Stop_Share_Send(CLOSE_SHARE);
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
            Alarm(EXIT, "Invalid State %d\n", DATA.tm_state);
    }
    
    
    DATA.b.state = STATE_TRIP;
    DATA.b.dts = mess->dts;

    DECISION_Send_CB_Status(SIGNED_TRIP_ACK);

}

void DECISION_Handle_Close_Ack(tm_msg *mess)
{

    Alarm(STATUS, "Receive Close Ack\n");
    switch (DATA.tm_state)
    {
        case TRIPPED:
            DECISION_Stop_Signed_Send();
            if (mess->dts > DATA.r.dts) {
                DATA.tm_state = WAIT_CLOSE;
            } else {
                DATA.tm_state = ATTEMPT_TRIP;
                DECISION_Start_Share_Send(TRIP_SHARE);
            }
            break;
            
        case CLOSED:
            DECISION_Stop_Signed_Send();
            break;
        
        case ATTEMPT_TRIP:
            if (mess->dts > DATA.r.dts) {
                DECISION_Stop_Share_Send(TRIP_SHARE);
                DATA.tm_state = WAIT_CLOSE;
            } else {
                return; // So we don't update our b vector
            }
            break;

        case ATTEMPT_CLOSE:
            // TODO if (DATA.b.dts > DATA.r.dts)  DQ: Probably not, but should discuss
            DECISION_Stop_Share_Send(CLOSE_SHARE);
            DATA.tm_state = CLOSED;
            break;

        case WAIT_TRIP:
            DATA.tm_state = CLOSED;
            break;

        case WAIT_CLOSE:
            break;

        default:
            Alarm(EXIT, "Invalid State %d\n", DATA.tm_state);
    }

    DATA.b.state = STATE_CLOSE;
    DATA.b.dts = mess->dts;
    DECISION_Send_CB_Status(SIGNED_CLOSE_ACK);
}

void DECISION_Start_Share_Send(int type)
{
    assert(DATA.cur_share == NULL);
    assert((DATA.tm_state == ATTEMPT_TRIP && type == TRIP_SHARE) || (DATA.tm_state == ATTEMPT_CLOSE && type == CLOSE_SHARE));

    /* Reset data structures for shares */
    if (type == TRIP_SHARE) {
        memset(DATA.trips, 0, sizeof(DATA.trips));    
    } else {
        memset(DATA.closes, 0, sizeof(DATA.closes));    
    }

    // TODO should this be local time instead?
    DATA.cur_share = PKT_Construct_TM_Message(type, DATA.id, DATA.r.dts, sizeof(tc_share_msg));
    DATA.cur_dts = 0;


    DECISION_Share_Periodic(type, (void *) DATA.cur_share);
}

void DECISION_Share_Periodic(int type, void *v_mess)
{
    tm_msg *mess;

    sp_time next_send, now;

    mess = (tm_msg *) v_mess;
    PKT_Construct_TC_Share_Msg_Payload(mess, DATA.cur_dts);
    UTIL_Broadcast_To_TM(mess);

    Alarm(STATUS, "Sending %s Share with dts of %ld\n", (type == TRIP_SHARE ? "TRIP" : "CLOSE"), mess->dts);
    
    /* Now, process our own share */
    if (type == TRIP_SHARE) {
        DECISION_Handle_Trip_Share(mess);
    } else {
        DECISION_Handle_Close_Share(mess);
    }

    
    /* If processing our own share changed our state, then don't queue next message */
    if (DATA.tm_state != ATTEMPT_TRIP && DATA.tm_state != ATTEMPT_CLOSE) {
        return;
    }

    // Note this has to be after processing our own share
    mess->dts += DTS_INTERVAL;

    //Avoids drift
    next_send.sec = mess->dts / 1000; 
    next_send.usec = (mess->dts % 1000) * 1000; 
    now = E_get_time();
    if(DATA.id==DOS) return;
    E_queue(DECISION_Share_Periodic, type, v_mess, E_sub_time(next_send, now));
    
}


void DECISION_Stop_Share_Send(int type)
{
    //assert(E_in_queue(DECISION_Share_Periodic, type, DATA.cur_share));
    if(E_in_queue(DECISION_Share_Periodic, type, DATA.cur_share)){
        E_dequeue(DECISION_Share_Periodic, type, DATA.cur_share);
    }

    free(DATA.cur_share);
    DATA.cur_share = NULL;
}

void DECISION_Signed_Periodic(int type, void *dummy)
{
    sp_time next_send = {SIGNED_TIMEOUT_SEC, SIGNED_TIMEOUT_USEC};

    assert(DATA.cur_signed != NULL);
    assert((DATA.cur_signed->type == SIGNED_TRIP && DATA.tm_state == TRIPPED) || (DATA.cur_signed->type == SIGNED_CLOSE && DATA.tm_state == CLOSED));

    Alarm(STATUS, "Sending Signed to proxy\n");
    if(DATA.id==DOS) return;
    UTIL_Send_To_Dst_Proxy(DATA.cur_signed);
    E_queue(DECISION_Signed_Periodic, 0, NULL, next_send);
}

void DECISION_Stop_Signed_Send()
{
    if (!E_in_queue(DECISION_Signed_Periodic, 0, NULL)) return;

    Alarm(STATUS, "Stopping Send Signed to proxy\n");
    E_dequeue(DECISION_Signed_Periodic, 0, NULL);
    free(DATA.cur_signed);
    DATA.cur_signed = NULL;
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
