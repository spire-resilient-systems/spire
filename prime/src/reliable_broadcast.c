/*
 * Prime.
 *     
 * The contents of this file are subject to the Prime Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.dsn.jhu.edu/prime/LICENSE.txt
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis, 
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
 * for the specific language governing rights and limitations under the 
 * License.
 *
 * Creators:
 *   Yair Amir            yairamir@cs.jhu.edu
 *   Jonathan Kirsch      jak@cs.jhu.edu
 *   John Lane            johnlane@cs.jhu.edu
 *   Marco Platania       platania@cs.jhu.edu
 *   Amy Babay            babay@pitt.edu
 *   Thomas Tantillo      tantillo@cs.jhu.edu
 *
 * Major Contributors:
 *   Brian Coan           Design of the Prime algorithm
 *   Jeff Seibert         View Change protocol 
 *   Sahiti Bommareddy    Reconfiguration 
 *   Maher Khan           Reconfiguration 
 *      
 * Copyright (c) 2008-2025
 * The Johns Hopkins University.
 * All rights reserved.
 * 
 * Partial funding for Prime research was provided by the Defense Advanced 
 * Research Projects Agency (DARPA) and the National Science Foundation (NSF).
 * Prime is not necessarily endorsed by DARPA or the NSF.  
 *
 */

#include <assert.h>
#include "utility.h"
#include "signature.h"
#include "reliable_broadcast.h"
#include "process.h"
#include "spu_memory.h"
#include "spu_alarm.h"

/* Globally Accessible Variables */
extern server_variables     VAR;
extern server_data_struct   DATA;

/* Local Functions */
void RB_Clear_Slots(void);

/* TODO - Merge 1st half of each process RB function into a common one,
 * then split off the bottom half with switch statements and count
 * checks to their own functions */

void RB_Initialize_Data_Structure()
{
    int32u i;

    for (i = 1; i <= VAR.Num_Servers; i++) {
        stdhash_construct(&DATA.RB.instances[i], sizeof(int32u), 
                sizeof(rb_slot *), NULL, NULL, 0);
    }

    /* Reset specific data structures on every view change */
    /* PRTODO: moved to when done recovering (or reset) */
    RB_Initialize_Upon_View_Change();
}

void RB_Initialize_Upon_View_Change()
{
    DATA.RB.rb_seq = 1;

    /*      Garbage collecting the slots only upon the new view change
     *      may add a lot of processing time, which will slow down the
     *      view change. Doing it along the way beforehand would be better,
     *      but it is a little tricky to prevent processing an old message
     *      as new. BUT - this may be needed for periodic retrans, or at
     *      least it makes it very convenient */
    RB_Clear_Slots();   
}

void RB_Upon_Reset()
{
    int32u i;

    RB_Clear_Slots();
    for (i = 1; i <= VAR.Num_Servers; i++) {
        stdhash_destruct(&DATA.RB.instances[i]);
    }
}

void RB_Periodic_Retrans(int d1, void *d2)
{
    int32u i;
    stdit it;
    sp_time t;
    rb_slot *r_slot;

    if (DATA.VIEW.executed_ord == 1 && DATA.PR.startup_finished == 1)
        return;

    for (i = 1; i <= VAR.Num_Servers; i++) {
        for (stdhash_begin(&DATA.RB.instances[i], &it); 
            !stdhash_is_end(&DATA.RB.instances[i], &it); stdit_next(&it))
        {
            r_slot = *(rb_slot **)stdit_val(&it);
            if (i == VAR.My_Server_ID && r_slot->rb_init)
                UTIL_Broadcast(r_slot->rb_init);
            if (r_slot->rb_echo[VAR.My_Server_ID])
                UTIL_Broadcast(r_slot->rb_echo[VAR.My_Server_ID]);
            if (r_slot->rb_ready[VAR.My_Server_ID])
                UTIL_Broadcast(r_slot->rb_ready[VAR.My_Server_ID]);
        }
    }

    t.sec  = RETRANS_PERIOD_SEC;
    t.usec = RETRANS_PERIOD_USEC;
    E_queue(RB_Periodic_Retrans, 0, NULL, t);
}

void RB_Process_Init(signed_message *mess)
{
    reliable_broadcast_tag *rb_tag;
    signed_message *payload, *rb;
    rb_slot *r_slot;
    byte msg_digest[DIGEST_SIZE+1];
    int32u payload_size;

    payload = (signed_message *)(mess + 1);
    rb_tag = (reliable_broadcast_tag *)(payload + 1);
    payload_size = UTIL_Message_Size(payload);
    //payload_size = sizeof(signed_message) + mess->len;

    if (rb_tag->view != DATA.View) {
        Alarm(PRINT, "RB_Process_Init: Invalid View %d, ours = %d\n",
                rb_tag->view, DATA.View);
        return;
    }

    r_slot = UTIL_Get_RB_Slot(rb_tag->machine_id, rb_tag->seq_num);

    if (r_slot->rb_init == NULL) {
        inc_ref_cnt(mess);
        r_slot->rb_init = mess;
    }

    if (r_slot->rb_msg == NULL) {
        r_slot->rb_msg = UTIL_New_Signed_Message();
        memcpy(r_slot->rb_msg, payload, payload_size);
        OPENSSL_RSA_Make_Digest(r_slot->rb_msg, payload_size, r_slot->rb_digest);
    } else {
        OPENSSL_RSA_Make_Digest(payload, payload_size, msg_digest);
        if (!OPENSSL_RSA_Digests_Equal(msg_digest, r_slot->rb_digest)) {
            // TODO - Do we need one digest from each server? How to handle case
            // where one replica gets the bad extra message but others already have
            // agreed and delivered the original one?
            // Blacklist(rb_tag->machine_id);
            Alarm(PRINT, "RB_Process_Init: Invalid Digest - Blacklist %d\n", 
                    rb_tag->machine_id);
            return;
        }
    }

    switch (r_slot->state) {
        case INIT:
            r_slot->state = SENT_ECHO;
            rb = RB_Construct_Message(RB_ECHO, r_slot->rb_msg);
            SIG_Add_To_Pending_Messages(rb, BROADCAST, UTIL_Get_Timeliness(RB_ECHO));
            dec_ref_cnt(rb);
            break;
        
        case SENT_ECHO: 
        case SENT_READY:
            break;

        default:
            Alarm(PRINT, "RB_Process_Init: Invalid rb_state! %d\n",
                    r_slot->state);
    }
}

void RB_Process_Echo(signed_message *mess)
{
    reliable_broadcast_tag *rb_tag;
    signed_message *payload, *rb;
    rb_slot *r_slot;
    byte msg_digest[DIGEST_SIZE+1];
    int32u payload_size;

    payload = (signed_message *)(mess + 1);
    rb_tag = (reliable_broadcast_tag *)(payload + 1);
    payload_size = UTIL_Message_Size(payload);
    //payload_size = sizeof(signed_message) + mess->len;

    if (rb_tag->view != DATA.View) {
        Alarm(PRINT, "RB_Process_Echo: Invalid View %d,from %d, ours = %d\n",
                rb_tag->view, mess->machine_id,DATA.View);
        return;
    }

    r_slot = UTIL_Get_RB_Slot(rb_tag->machine_id, rb_tag->seq_num);
    
    if (r_slot->rb_echo[mess->machine_id] == NULL) {
        inc_ref_cnt(mess);
        r_slot->rb_echo[mess->machine_id] = mess;
    }

    if (r_slot->rb_msg == NULL) {
        r_slot->rb_msg = UTIL_New_Signed_Message();
        memcpy(r_slot->rb_msg, payload, payload_size);
        OPENSSL_RSA_Make_Digest(r_slot->rb_msg, payload_size, r_slot->rb_digest);
    } else {
        OPENSSL_RSA_Make_Digest(payload, payload_size, msg_digest);
        if (!OPENSSL_RSA_Digests_Equal(msg_digest, r_slot->rb_digest)) {
            // TODO - Do we need one digest from each server? How to handle case
            // where one replica gets the bad extra message but others already have
            // agreed and delivered the original one?
            // Blacklist(rb_tag->machine_id);
            Alarm(PRINT, "RB_Process_Echo: Invalid Digest - Blacklist %d\n", 
                    rb_tag->machine_id);
            return;
        }
    }

    if (r_slot->echo_received[mess->machine_id] == 1)
        return;

    r_slot->echo_received[mess->machine_id] = 1;
    r_slot->echo_count++;

    if (r_slot->echo_count != 2*VAR.F + VAR.K + 1)  /* 1 + (n+f)/2 */
        return;

    switch (r_slot->state) {
        case INIT:
            r_slot->state = SENT_ECHO;
            rb = RB_Construct_Message(RB_ECHO, r_slot->rb_msg);
            SIG_Add_To_Pending_Messages(rb, BROADCAST, UTIL_Get_Timeliness(RB_ECHO));
            dec_ref_cnt(rb);
        
        case SENT_ECHO: 
            r_slot->state = SENT_READY;
            rb = RB_Construct_Message(RB_READY, r_slot->rb_msg);
            SIG_Add_To_Pending_Messages(rb, BROADCAST, UTIL_Get_Timeliness(RB_READY));
            dec_ref_cnt(rb);
            
        case SENT_READY:
            break;

        default:
            Alarm(PRINT, "RB_Process_Init: Invalid rb_state! %d\n",
                    r_slot->state);
    }
}

void RB_Process_Ready(signed_message *mess)
{
    reliable_broadcast_tag *rb_tag;
    signed_message *payload, *rb;
    rb_slot *r_slot;
    byte msg_digest[DIGEST_SIZE+1];
    int32u payload_size;

    payload = (signed_message *)(mess + 1);
    rb_tag = (reliable_broadcast_tag *)(payload + 1);
    payload_size = UTIL_Message_Size(payload);
    //payload_size = sizeof(signed_message) + mess->len;

    if (rb_tag->view != DATA.View) {
        Alarm(PRINT, "RB_Process_Echo: Invalid View %d from %d, ours = %d\n",
                rb_tag->view, mess->machine_id,DATA.View);
        return;
    }

    r_slot = UTIL_Get_RB_Slot(rb_tag->machine_id, rb_tag->seq_num);

    if (r_slot->rb_ready[mess->machine_id] == NULL) {
        inc_ref_cnt(mess);
        r_slot->rb_ready[mess->machine_id] = mess;
    }

    if (r_slot->rb_msg == NULL) {
        r_slot->rb_msg = UTIL_New_Signed_Message();
        memcpy(r_slot->rb_msg, payload, payload_size);
        OPENSSL_RSA_Make_Digest(r_slot->rb_msg, payload_size, r_slot->rb_digest);
    } else {
        OPENSSL_RSA_Make_Digest(payload, payload_size, msg_digest);
        if (!OPENSSL_RSA_Digests_Equal(msg_digest, r_slot->rb_digest)) {
            // TODO - Do we need one digest from each server? How to handle case
            // where one replica gets the bad extra message but others already have
            // agreed and delivered the original one?
            // Blacklist(rb_tag->machine_id);
            Alarm(PRINT, "RB_Process_Echo: Invalid Digest - Blacklist %d\n", 
                    rb_tag->machine_id);
            return;
        }
    }

    if (r_slot->ready_received[mess->machine_id] == 1)
        return;

    r_slot->ready_received[mess->machine_id] = 1;
    r_slot->ready_count++;

    if (r_slot->ready_count < VAR.F + 1)
        return;

    if (r_slot->ready_count == VAR.F + 1)  /* f+1 */ {
        switch (r_slot->state) {
            case INIT:
                r_slot->state = SENT_ECHO;
                rb = RB_Construct_Message(RB_ECHO, r_slot->rb_msg);
                SIG_Add_To_Pending_Messages(rb, BROADCAST, UTIL_Get_Timeliness(RB_ECHO));
                dec_ref_cnt(rb);
            
            case SENT_ECHO: 
                r_slot->state = SENT_READY;
                rb = RB_Construct_Message(RB_READY, r_slot->rb_msg);
                SIG_Add_To_Pending_Messages(rb, BROADCAST, UTIL_Get_Timeliness(RB_READY));
                dec_ref_cnt(rb);
                
            case SENT_READY:
                break;

            default:
                Alarm(PRINT, "RB_Process_Init: Invalid rb_state! %d\n",
                        r_slot->state);
        }
        return;
    }

    if (r_slot->ready_count != 2*VAR.F + VAR.K + 1)  /* 1 + (n+f)/2 */
        return;

    PROCESS_Message(r_slot->rb_msg);
}

void RB_Clear_Slots()
{
    int32u i, j;
    stdit it;
    rb_slot *r_slot;

    for (i = 1; i <= VAR.Num_Servers; i++) {
        for (stdhash_begin(&DATA.RB.instances[i], &it); 
            !stdhash_is_end(&DATA.RB.instances[i], &it); stdit_next(&it))
        {
            r_slot = *(rb_slot **)stdit_val(&it);
            if (r_slot->rb_msg)
                dec_ref_cnt(r_slot->rb_msg);
            if (r_slot->rb_init)
                dec_ref_cnt(r_slot->rb_init);
            for (j = 1; j <= VAR.Num_Servers; j++) {
                if (r_slot->rb_echo[j])
                    dec_ref_cnt(r_slot->rb_echo[j]);
                if (r_slot->rb_ready[j])
                    dec_ref_cnt(r_slot->rb_ready[j]);
            }
            dec_ref_cnt(r_slot);
        }
        stdhash_clear(&DATA.RB.instances[i]);
    }
}
