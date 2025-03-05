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
#include "validate.h"
#include "process.h"
#include "network.h"
#include "pre_order.h"
#include "order.h"
#include "suspect_leader.h"
#include "view_change.h"
#include "catchup.h"
#include "proactive_recovery.h"

#include "spu_memory.h"
#include "spu_alarm.h"

/* Global Variables */
extern network_variables    NET;
extern server_variables     VAR;
extern server_data_struct   DATA;

/* Local Functions */
void PR_Periodic_Retrans(int d1, void *d2);
void PR_Accept_Incarnation(int32u replica);
void PR_Check_Complete_Pending_State(int32u replica);
void PR_Try_To_Complete_Recovery(int32u recent_replica);

void PR_Execute_Reset_Proposal(void);
void PR_Rotate_Reset_Leader(int d1, void *d2);
void PR_Post_Shares_Delay(int d1, void *d2);
void PR_Start_View_Change(void);
void PR_Check_Complete_VC_State(void);

void PR_Initialize_Data_Structure(void)
{
    int32u i;
    sp_time now;

    now = E_get_time();

    for (i = 1; i <= VAR.Num_Servers; i++) {
        DATA.PR.preinstalled_incarnations[i] = 0;
        DATA.PR.installed_incarnations[i] = 0;

        DATA.PR.last_recovery_time[i] = 0;
        DATA.PR.recovery_status[i] = PR_NORMAL;
        DATA.PR.monotonic_counter[i] = 0;

        DATA.PR.new_incarnation[i] = NULL;
        DATA.PR.new_incarnation_val[i] = 0;
        //DATA.PR.highest_recv_incarnation[i] = NULL;
        DATA.PR.sent_incarnation_ack[i] = NULL;
        DATA.PR.recv_incarnation_ack[i] = NULL;
        DATA.PR.incarnation_cert[i] = NULL;
    
        UTIL_DLL_Initialize(&DATA.PR.outbound_pending_share_dll[i]);
        DATA.PR.jump_message[i] = NULL;
        DATA.PR.pending_state[i] = NULL;
        stdhash_construct(&DATA.PR.pending_shares[i], sizeof(int32u), 
                sizeof(signed_message *), NULL, NULL, 0);
        DATA.PR.complete_pending_state[i] = 0;

        DATA.PR.reset_vote[i] = NULL;
        DATA.PR.reset_share[i] = NULL;
        DATA.PR.reset_prepare[i] = NULL;
        DATA.PR.reset_commit[i] = NULL;

        DATA.PR.reset_newleader[i] = NULL;
        DATA.PR.reset_viewchange[i] = NULL;

        DATA.PR.jump_mismatch[i] = NULL;
    }

    DATA.PR.startup_finished = 0;

    DATA.PR.incarnation_ack_count = 0;

    DATA.PR.catchup_request = NULL;
    DATA.PR.jump_count = 0;
    DATA.PR.complete_recovery_state_count = 0;
    DATA.PR.complete_recovery_state = 0; 

    DATA.PR.reset_vote_count = 0;
    DATA.PR.reset_share_count = 0;
    DATA.PR.reset_proposal = NULL;

    DATA.PR.reset_newleaderproof = NULL;
    DATA.PR.reset_newview = NULL;
    DATA.PR.reset_carry_over_proposal = NULL;

    DATA.PR.reset_certificate = NULL;
    memset(DATA.PR.proposal_digest, 0, DIGEST_SIZE);
    DATA.PR.jump_mismatch_count = 0;

    PR_Clear_Reset_Data_Structures();

    /* PRTODO: set this with the actual TPM monotonic counter */
    //DATA.PR.monotonic_counter[VAR.My_Server_ID] = 

    /* PRTODO - keep these two steps here, or delay to start_recovery? */
    /* Setup my own incarnation as being preinstalled */
    DATA.PR.new_incarnation_val[VAR.My_Server_ID] = now.sec;

    /* I know my own replica is recoverying. This also serves as a flag to only accept (or respond to)
     * certain messages from the network until I am finished recoverying */
    DATA.PR.recovery_status[VAR.My_Server_ID] = PR_STARTUP; 
    DATA.PR.num_startup = 1;

    PR_Periodic_Retrans(0, NULL);
}

/* Function to clear out the contents of the reset data structures that
 * are used to execute the fresh system start case due to a reset. This
 * is called at the beginning of the program and each time a reset round
 * fails due to the leader taking too long */
void PR_Clear_Reset_Data_Structures()
{
    int32u i;

    for (i = 1; i <= VAR.Num_Servers; i++) {

        /* Reset Prepares and Commits */
        if (DATA.PR.reset_prepare[i] != NULL) {
            dec_ref_cnt(DATA.PR.reset_prepare[i]);
            DATA.PR.reset_prepare[i] = NULL;
        }
        if (DATA.PR.reset_commit[i] != NULL) {
            dec_ref_cnt(DATA.PR.reset_commit[i]);
            DATA.PR.reset_commit[i] = NULL;
        }

        /* Reset New Leader messages */
        if (DATA.PR.reset_newleader[i] != NULL) {
            dec_ref_cnt(DATA.PR.reset_newleader[i]);
            DATA.PR.reset_newleader[i] = NULL;
        }

        /* Reset View Change messages */
        if (DATA.PR.reset_viewchange[i] != NULL) {
            dec_ref_cnt(DATA.PR.reset_viewchange[i]);
            DATA.PR.reset_viewchange[i] = NULL;
        }
    }

    if (DATA.PR.reset_proposal != NULL) {
        dec_ref_cnt(DATA.PR.reset_proposal);
        DATA.PR.reset_proposal = NULL;
    }

    if (DATA.PR.reset_newview != NULL) {
        dec_ref_cnt(DATA.PR.reset_newview);
        DATA.PR.reset_newview = NULL;
    }

    if (DATA.PR.reset_carry_over_proposal != NULL) {
        dec_ref_cnt(DATA.PR.reset_carry_over_proposal);
        DATA.PR.reset_carry_over_proposal = NULL;
    }
    
    /* NOTE: Reset_newleaderproof and reset_certificate only get erased when replacing
     * it with the previous version */

    DATA.PR.reset_min_wait_done = 0;
    DATA.PR.reset_prepare_count = 0;
    DATA.PR.reset_sent_prepare = 0;
    DATA.PR.reset_commit_count = 0;
    DATA.PR.reset_sent_commit = 0;
    DATA.PR.reset_viewchange_bitmap = 0;
    DATA.PR.reset_collected_vc_state = 0;
}

/* Re-initialize things that would get reset during a mid-run reset, which
 * occurs when more than the acceptable number of replicas are undergoing
 * recovery (i.e., assumptions breached) */
void PR_Upon_Reset()
{
    int32u i;
    stdit it;
    signed_message *mess;

    for (i = 1; i <= VAR.Num_Servers; i++) {

        if (DATA.PR.new_incarnation[i] != NULL) {
            dec_ref_cnt(DATA.PR.new_incarnation[i]);
            DATA.PR.new_incarnation[i] = NULL;
        }
        
        /* if (DATA.PR.highest_recv_incarnation[i] != NULL) {
            dec_ref_cnt(DATA.PR.highest_recv_incarnation[i]);
            DATA.PR.highest_recv_incarnation[i] = NULL;
        } */

        if (DATA.PR.sent_incarnation_ack[i] != NULL) {
            dec_ref_cnt(DATA.PR.sent_incarnation_ack[i]);
            DATA.PR.sent_incarnation_ack[i] = NULL;
        }
        
        if (DATA.PR.recv_incarnation_ack[i] != NULL) {
            dec_ref_cnt(DATA.PR.recv_incarnation_ack[i]);
            DATA.PR.recv_incarnation_ack[i] = NULL;
        }

        if (DATA.PR.incarnation_cert[i] != NULL) {
            dec_ref_cnt(DATA.PR.incarnation_cert[i]);
            DATA.PR.incarnation_cert[i] = NULL;
        }

        UTIL_DLL_Clear(&DATA.PR.outbound_pending_share_dll[i]);

        if (DATA.PR.jump_message[i] != NULL) {
            dec_ref_cnt(DATA.PR.jump_message[i]);
            DATA.PR.jump_message[i] = NULL;
        }
        
        if (DATA.PR.pending_state[i] != NULL) {
            dec_ref_cnt(DATA.PR.pending_state[i]);
            DATA.PR.pending_state[i] = NULL;
        }

        for (stdhash_begin(&DATA.PR.pending_shares[i], &it); 
            !stdhash_is_end(&DATA.PR.pending_shares[i], &it); stdit_next(&it)) 
        {
            mess = *(signed_message **)stdit_val(&it);
            dec_ref_cnt(mess);
        }
        stdhash_clear(&DATA.PR.pending_shares[i]);
        stdhash_destruct(&DATA.PR.pending_shares[i]);
        
        if (DATA.PR.reset_vote[i] != NULL) {
            dec_ref_cnt(DATA.PR.reset_vote[i]);
            DATA.PR.reset_vote[i] = NULL;
        }

        if (DATA.PR.reset_share[i] != NULL) {
            dec_ref_cnt(DATA.PR.reset_share[i]);
            DATA.PR.reset_share[i] = NULL;
        }

        if (DATA.PR.reset_prepare[i] != NULL) {
            dec_ref_cnt(DATA.PR.reset_prepare[i]);
            DATA.PR.reset_prepare[i] = NULL;
        }

        if (DATA.PR.reset_commit[i] != NULL) {
            dec_ref_cnt(DATA.PR.reset_commit[i]);
            DATA.PR.reset_commit[i] = NULL;
        }

        if (DATA.PR.reset_newleader[i] != NULL) {
            dec_ref_cnt(DATA.PR.reset_newleader[i]);
            DATA.PR.reset_newleader[i] = NULL;
        }

        if (DATA.PR.reset_viewchange[i] != NULL) {
            dec_ref_cnt(DATA.PR.reset_viewchange[i]);
            DATA.PR.reset_viewchange[i] = NULL;
        }

        if (DATA.PR.jump_mismatch[i] != NULL) {
            dec_ref_cnt(DATA.PR.jump_mismatch[i]);
            DATA.PR.jump_mismatch[i] = NULL;
        }
    }

    if (DATA.PR.catchup_request != NULL) {
        dec_ref_cnt(DATA.PR.catchup_request);
        DATA.PR.catchup_request = NULL;
    }

    if (DATA.PR.reset_proposal != NULL) {
        dec_ref_cnt(DATA.PR.reset_proposal);
        DATA.PR.reset_proposal = NULL;
    }

    if (DATA.PR.reset_newleaderproof != NULL) {
        dec_ref_cnt(DATA.PR.reset_newleaderproof);
        DATA.PR.reset_newleaderproof = NULL;
    }

    if (DATA.PR.reset_newview != NULL) {
        dec_ref_cnt(DATA.PR.reset_newview);
        DATA.PR.reset_newview = NULL;
    }

    if (DATA.PR.reset_carry_over_proposal != NULL) {
        dec_ref_cnt(DATA.PR.reset_carry_over_proposal);
        DATA.PR.reset_carry_over_proposal = NULL;
    }

    if (DATA.PR.reset_certificate != NULL) {
        dec_ref_cnt(DATA.PR.reset_certificate);
        DATA.PR.reset_certificate = NULL;
    }
}

void PR_Reset_Prime()
{
    /* First, save (on the side) any messages or data that should carry over the reset */

    /* Dequeue all timed events */
    E_dequeue_all_time_events();

    /* Go through and reset all of the data structures now. Call in the right order */
    PR_Upon_Reset();
    ORDER_Upon_Reset();
    PRE_ORDER_Upon_Reset();
    SIG_Upon_Reset();
    SUSPECT_Upon_Reset();
    RB_Upon_Reset();
    VIEW_Upon_Reset();
    CATCH_Upon_Reset();

    /* Now that data structures are been reset, re-initialize things to start from scratch */
    DAT_Initialize();

    /* Start the recovery process */
    PR_Start_Recovery();
}

void PR_Periodic_Retrans(int d1, void *d2)
{
    int32u i, preinstalled, current;
    sp_time t, now;
    new_incarnation_message *ni;

    preinstalled = DATA.PR.preinstalled_incarnations[VAR.My_Server_ID];
    current      = DATA.PR.new_incarnation_val[VAR.My_Server_ID];

    /* Retransmit the new_incarnation message, with an updated timestamp */
    if (DATA.PR.new_incarnation[VAR.My_Server_ID] != NULL && preinstalled < current) {

        ni = (new_incarnation_message *)(DATA.PR.new_incarnation[VAR.My_Server_ID] + 1);
        now = E_get_time();

        if ((int32u)now.sec - ni->timestamp > (int32u)RECOVERY_UPDATE_TIMESTAMP_SEC) {

            /* Clear out any outstanding incarnation acks for my previous incarnation
             *  that we are giving up on - there should be incarnation_certificate in
             *  this case, and we are going to work on a new one with the updated
             *  timestamp and nonce (but same incarnation). */
            for (i = 1; i <= VAR.Num_Servers; i++) {
                if (DATA.PR.recv_incarnation_ack[i] != NULL) {
                    dec_ref_cnt(DATA.PR.recv_incarnation_ack[i]);
                    DATA.PR.recv_incarnation_ack[i] = NULL;
                }
            }
            DATA.PR.incarnation_ack_count = 0;

            dec_ref_cnt(DATA.PR.new_incarnation[VAR.My_Server_ID]);
            DATA.PR.new_incarnation[VAR.My_Server_ID] = PR_Construct_New_Incarnation_Message();
            SIG_Add_To_Pending_Messages(DATA.PR.new_incarnation[VAR.My_Server_ID], BROADCAST, 
                UTIL_Get_Timeliness(NEW_INCARNATION));
        }
        else {
            UTIL_Broadcast(DATA.PR.new_incarnation[VAR.My_Server_ID]);
        }
    }

    /* Retransmit Incarnation Certificates (from any replica) that has yet to be installed */
    for (i = 1; i <= VAR.Num_Servers; i++) {
        if (DATA.PR.incarnation_cert[i] == NULL)
            continue;

        if (DATA.PR.installed_incarnations[i] < DATA.PR.incarnation_cert[i]->incarnation)
            UTIL_Broadcast(DATA.PR.incarnation_cert[i]);
    }

    /* Retransmit ... */

    /* Renqueue for next time */
    t.sec  = RETRANS_PERIOD_SEC;
    t.usec = RETRANS_PERIOD_USEC;
    E_queue(PR_Periodic_Retrans, 0, NULL, t);
}

void PR_Start_Recovery()
{
    /* DEBUG */
    /* int32u i, j;
    po_seq_pair ps = {0, 0};
    for (i = 1; i <= VAR.Num_Servers; i++) {
        for (j = 0; j < VAR.Num_Servers; j++) {
            if (PRE_ORDER_Seq_Compare(DATA.PO.cum_acks[i].cum_ack.ack_for_server[j], ps) != 0)
                Alarm(PRINT, "Start_Recovery: cum_acks[%u].ack[%u] = (%u,%u) != (0,0)\n", i, j,
                            DATA.PO.cum_acks[i].cum_ack.ack_for_server[j].incarnation,
                            DATA.PO.cum_acks[i].cum_ack.ack_for_server[j].seq_num);
        }
    } */

    PR_Send_Application_Reset();

    /* PRTODO: create new session key here and store private portion of your own */

    /* Create my new incarnation message that kickstarts the recovery */
    DATA.PR.new_incarnation[VAR.My_Server_ID] = PR_Construct_New_Incarnation_Message();

    /* Multicast my new_incarnation message */ 
    SIG_Add_To_Pending_Messages(DATA.PR.new_incarnation[VAR.My_Server_ID], BROADCAST, 
        UTIL_Get_Timeliness(NEW_INCARNATION));
}

void PR_Process_New_Incarnation(signed_message *mess)
{
    signed_message *response;
    new_incarnation_message *ni, *stored_ni = NULL; //, *high_ni = NULL;
    int32u sender, dest_bits, diff;
    sp_time now;

    now = E_get_time();

    /* For now, ignore my own new_incarnation messages */
    sender = mess->machine_id;
    if (sender == VAR.My_Server_ID) {
        //Alarm(DEBUG, "Ignoring my own new_incarnation message\n");
        return;
    }

    /* Grab the specific new_incarnation information */
    ni = (new_incarnation_message *)(mess + 1);
    Alarm(DEBUG, "Received NEW_INCARNATION from %d with incarnation %u and timestamp = %u, and nounce=%lu, config=%lu\n", mess->machine_id, mess->incarnation, ni->timestamp,ni->nonce,mess->global_configuration_number);

    /* Check the monotonic increasing sequence number */
    /*if (ni->monotonic_counter <= DATA.PR.monotonic_counter[sender]) {
        Alarm(DEBUG, "Process_New_Incarnation: monotonic_counter %u too small, have %d\n",
                ni->incarnation, DATA.PR.monotonic_counter[sender]);
        return;
    } */
    /* Store the monotonic_counter from the newer message */
    //DATA.PR.monotonic_counter[sender] = mess->monotonic_counter;

    /* Grab the stored new_incarnation for comparison, if it exists */
    if (DATA.PR.new_incarnation[sender] != NULL)
        stored_ni = (new_incarnation_message *)(DATA.PR.new_incarnation[sender] + 1);

    /* Grab the highest_recv_incarnation for comparison, if it exists */
    /* if (DATA.PR.highest_recv_incarnation[sender] != NULL)
        high_ni = (new_incarnation_message *)(DATA.PR.highest_recv_incarnation[sender] + 1); */

    /* PRTODO: validate the message accordingly
     * Throw away if too old for one of several reasons */
    if (mess->incarnation <= DATA.PR.preinstalled_incarnations[sender]) {
        Alarm(DEBUG, "Old new_incarnation (%u), already Preinstalled %u\n", 
                mess->incarnation, DATA.PR.preinstalled_incarnations[sender]);
        return;
    }
    if (stored_ni != NULL && mess->incarnation < (DATA.PR.new_incarnation[sender])->incarnation) {
        Alarm(DEBUG, "Old new_incarnation (%u), already working on %u\n", 
                mess->incarnation, (DATA.PR.new_incarnation[sender])->incarnation);
        return;
    }
    if (stored_ni != NULL && mess->incarnation == (DATA.PR.new_incarnation[sender])->incarnation) {

        /* Ensure session key matches if you've already recevied this incarnation  */
        if (memcmp(ni->key, stored_ni->key, DIGEST_SIZE) != 0)
        {
            Alarm(PRINT, "Recv Two New_Incarnation with non-matching key! Malicious Proof!\n");
            /* Blacklist */
            return;
        }

        /* See if enough time has passed to give support for this new_incarnation message */
        if (ni->timestamp <= stored_ni->timestamp) {
            Alarm(DEBUG, "ni->timestamp is old %u, already have %u\n", 
                    ni->timestamp, stored_ni->timestamp);
            return;
        }

        diff = ni->timestamp - stored_ni->timestamp;
        if (diff < (int32u)RECOVERY_UPDATE_TIMESTAMP_SEC) {
            Alarm(PRINT, "ni->timestamp from %u is too recent. ni = %u, stored = %u\n",
                    sender, ni->timestamp, stored_ni->timestamp);
            return;
        }
    }

    /* Check that the timestamp on the message is within the necessary bound */
    //if (E_compare_time(now,ni->timestamp) < MIN || E_compare_time(ni->timestamp,now) > MAX) */
    if (abs((int)now.sec - (int)ni->timestamp) > RECOVERY_UPDATE_TIMESTAMP_SEC)
    {
        Alarm(PRINT, "new_incarnation is too old or too far ahead for me to accept\n");
        return;
    }

    /* Check if this is less up-to-date compared with the highest recv so far */
    /* if (high_ni != NULL && 
              (ni->incarnation < high_ni->incarnation || 
              (ni->incarnation == high_ni->incarnation && ni->timestamp <= high_ni->timestamp)))
    {
        Alarm(PRINT, "Old new_incarnation compared with highest_recv so far\n");
        return;
    } */

    /* if (DATA.PR.highest_recv_incarnation[sender] != NULL)
        dec_ref_cnt(DATA.PR.highest_recv_incarnation[sender]);
    inc_ref_cnt(mess);
    DATA.PR.highest_recv_incarnation[sender] = mess; */

    /* Check if this replica is allowed to recover again (from my point of view) */
    if (mess->incarnation > DATA.PR.new_incarnation_val[sender] && 
        ni->timestamp - DATA.PR.last_recovery_time[sender] < (int32u)RECOVERY_PERIOD_SEC) 
    {
        Alarm(PRINT, "Replica %d trying to recover too soon! msg = [%u,%u], previous = [%u,%u]\n", 
                sender, mess->incarnation, ni->timestamp, 
                DATA.PR.new_incarnation_val[sender], DATA.PR.last_recovery_time[sender]);
        /* PRTODO: enqueue a function to process the highest_recv_incarnation that
         * is stored when enough time elapses. For now, just force them to 
         * send a new time-stamped version of the message in the future */
        return;
    }

    /* If we previously did not know they were starting up and they have a higher
     * incarnation, we can mark them as doing startup as long as we are in the 
     * RESET, RECOVERY, or NORMAL case */
    if (DATA.PR.new_incarnation_val[sender] < mess->incarnation &&
        DATA.PR.recovery_status[sender] != PR_STARTUP && 
        DATA.PR.recovery_status[VAR.My_Server_ID] != PR_STARTUP) 
    {
        DATA.PR.num_startup++;
        DATA.PR.recovery_status[sender] = PR_STARTUP;
        Alarm(PRINT, "Num_Startup == %u\n", DATA.PR.num_startup);
        if (DATA.PR.num_startup >= VAR.F + VAR.K + 1) {
            Alarm(PRINT, "SYSTEM ASSUMPTIONS VOLATED: >= f+k+1 in startup\n");
            //PR_Send_Application_Reset();   // REDUNDANT FOR NOW...
            PR_Reset_Prime();
            return;   // PRTODO: This return is new - *should* be correct, need to check more
        }
    }

    /* Accept the message, clear out old new_incarnation messages, 
     * mark down this as the last recovery time */
    if (DATA.PR.new_incarnation[sender] != NULL)
        dec_ref_cnt(DATA.PR.new_incarnation[sender]);
    inc_ref_cnt(mess);
    DATA.PR.new_incarnation[sender] = mess;

    /* Only update last_recovery_time if the incarnation is changing */
    if (DATA.PR.new_incarnation_val[sender] < mess->incarnation) {
        DATA.PR.last_recovery_time[sender] = ni->timestamp;
        DATA.PR.new_incarnation_val[sender] = mess->incarnation;
    }
   
    /* If I am in startup, I answer the new_incarnation with a reset vote for the originating
     * replica. I cannot update my own reset_count based on this message, I need an explicit
     * reset_vote covering my latest new_incarnation message */
    dest_bits = 0;
    UTIL_Bitmap_Set(&dest_bits, sender);
    if (DATA.PR.recovery_status[VAR.My_Server_ID] == PR_STARTUP) {
        Alarm(STATUS,"MS2022: I am PR_STARTUP, so sending reset\n");
        response = PR_Construct_Reset_Vote(mess);
        SIG_Add_To_Pending_Messages(response, dest_bits, UTIL_Get_Timeliness(RESET_VOTE));
        dec_ref_cnt(response);
    }
    /* I'm already a replica with a running system, run the recovery protocol */
    else if (DATA.PR.recovery_status[VAR.My_Server_ID] == PR_NORMAL) {
        /* If we had any previously stored incarnation_ack sent to this replica, remove it */
        Alarm(STATUS,"MS2022: I am PR_NORMAL, so sending inc ack\n");
        if (DATA.PR.sent_incarnation_ack[sender] != NULL) {
            dec_ref_cnt(DATA.PR.sent_incarnation_ack[sender]);
            DATA.PR.sent_incarnation_ack[sender] = NULL;
        }
        DATA.PR.sent_incarnation_ack[sender] = PR_Construct_Incarnation_Ack(mess);
        SIG_Add_To_Pending_Messages(DATA.PR.sent_incarnation_ack[sender], dest_bits, 
                UTIL_Get_Timeliness(INCARNATION_ACK));
    }
    /* recovery_status == PR_RESET || recovery_status == PR_RECOVERY: do not answer */
}

/* === RECOVERY TO WORKING SYSTEM CASE === */
void PR_Process_Incarnation_Ack(signed_message *mess)
{
    int32u sender;
    incarnation_ack_message *iack;
    signed_message *ni_mess;
    new_incarnation_message *ni;
    byte digest[DIGEST_SIZE];

    sender = mess->machine_id;
    iack = (incarnation_ack_message *)(mess + 1);

    Alarm(PRINT, "PR_Process_Incarnation_Ack: recv from %u about [%u,%u]\n",
            mess->machine_id, iack->acked_id, iack->acked_incarnation);
   
    if (DATA.PR.recv_incarnation_ack[sender] != NULL)
        return;

    if (DATA.PR.new_incarnation[VAR.My_Server_ID] == NULL)
        return;
    ni_mess = (signed_message *)(DATA.PR.new_incarnation[VAR.My_Server_ID]);
    ni = (new_incarnation_message *)(ni_mess + 1);
    
    /* Sanity check the incarnation_ack */
    /* PRTODO: check the monotonically increasing sequence number */
    
    if (iack->acked_id != VAR.My_Server_ID)
        return;

    if (iack->acked_incarnation != ni_mess->incarnation)
        return;

    /* Compute the digest of our own new_incarnation message and compare with the
     * ACK. This should ensure the timestamp and nonce on our original new_incarnatiion
     * message is consistent */
    OPENSSL_RSA_Make_Digest((byte*)DATA.PR.new_incarnation[VAR.My_Server_ID], 
            sizeof(signed_message) + sizeof(*ni), digest);
    if (memcmp(digest, iack->digest, DIGEST_SIZE) != 0) {
        Alarm(PRINT, "PR_Process_Incarnation: Digests don't match\n");
        return;
    }

    /* Since they answered with a fresh incarnation_ack, they must be normal */
    /* if (DATA.PR.recovery_status[sender] == PR_STARTUP)
        DATA.PR.num_startup--;
    DATA.PR.recovery_status[sender] = PR_NORMAL; */

    assert(DATA.PR.recv_incarnation_ack[sender] == NULL);
    inc_ref_cnt(mess);
    DATA.PR.recv_incarnation_ack[sender] = mess;
    DATA.PR.incarnation_ack_count++;

    /* Check if we now have 2f+k+1 legitimately formed incarnation acks */
    if (DATA.PR.incarnation_ack_count != 2*VAR.F + VAR.K + 1)
          return;
   
    assert(DATA.PR.incarnation_cert[VAR.My_Server_ID] == NULL);
    DATA.PR.incarnation_cert[VAR.My_Server_ID] = PR_Construct_Incarnation_Cert();
    SIG_Add_To_Pending_Messages(DATA.PR.incarnation_cert[VAR.My_Server_ID], BROADCAST,
            UTIL_Get_Timeliness(INCARNATION_CERT));

    PR_Accept_Incarnation(VAR.My_Server_ID);
}

void PR_Process_Incarnation_Cert(signed_message *mess)
{
    int32u sender, size;
    incarnation_cert_message *icert;
    signed_message *ni;
    /*new_incarnation_message *ni_specific;*/

    sender = mess->machine_id;
    icert = (incarnation_cert_message *)(mess + 1);
    ni = (signed_message *)(icert + 1);
    /*ni_specific = (new_incarnation_message *)(ni + 1);*/
    
    if (sender == VAR.My_Server_ID)
        return;

    Alarm(DEBUG, "Received Incarnation Cert from %u. inc = %u\n", 
            sender, mess->incarnation);

    /* Sanity check this message */
    /* PRTODO: check the monotonic sequence number, and update accordingly */

    if (mess->incarnation <= DATA.PR.preinstalled_incarnations[sender]) {
        Alarm(DEBUG, "PR_Process_Incarnation_Cert: from %u, %u is old, %u is preinstalled\n",
                sender, mess->incarnation, DATA.PR.preinstalled_incarnations[sender]);
        return;
    }
    
    /* Accept and store the incarnation certificate */
    if (DATA.PR.incarnation_cert[sender] != NULL)
        dec_ref_cnt(DATA.PR.incarnation_cert[sender]);
    inc_ref_cnt(mess);
    DATA.PR.incarnation_cert[sender] = mess;

    /* Flood the incarnation certificate immediately the first time you receive it in 
     * case it came from a compromised replica that did not correctly multicast it */
    UTIL_Broadcast(DATA.PR.incarnation_cert[sender]);

    /* Also accept and store the new_incarnation message included in the certificate */
    if (DATA.PR.new_incarnation[sender] != NULL) 
        dec_ref_cnt(DATA.PR.new_incarnation[sender]);
    DATA.PR.new_incarnation[sender] = UTIL_New_Signed_Message();
    size = UTIL_Message_Size(ni);
    memcpy(DATA.PR.new_incarnation[sender], ni, size);

    PR_Accept_Incarnation(sender);
}

void PR_Accept_Incarnation(int32u replica)
{
    int32u inc, ts, i, j, more_to_ack;
    po_seq_pair ps;
    stdit it;
    po_slot *p_slot;
    ord_slot *o_slot;
    incarnation_cert_message *icert_specific;
    signed_message *icert, *ni, *ack, *request, *prepare, *commit;
    new_incarnation_message *ni_specific;
    //po_ack_part *part_specific;
    prepare_message *prepare_specific;
    commit_message *commit_specific;
    sp_time now, t;

    assert(DATA.PR.incarnation_cert[replica] != NULL);
    
    now = E_get_time();

    icert = (signed_message *)(DATA.PR.incarnation_cert[replica]);
    icert_specific = (incarnation_cert_message *)(icert + 1);
    ni = (signed_message *)(icert_specific + 1);
    ni_specific = (new_incarnation_message *)(ni + 1);

    inc = icert->incarnation;
    ts = ni_specific->timestamp;

    Alarm(PRINT, "Accepting (Preinstall) Incarnation %u from %u\n", icert->incarnation, replica);

    /* Update the preinstalled incarnations */
    DATA.PR.preinstalled_incarnations[replica] = inc;
    DATA.PR.new_incarnation_val[replica] = inc;
    DATA.PR.last_recovery_time[replica] = ts;

    /* Update the preordering data structures for the recovering replica */
    ps.incarnation = inc; 
    ps.seq_num = 0;
    DATA.PO.max_acked[replica] = ps;
    DATA.PO.aru[replica] = ps;
    /* DATA.PO.cum_aru[replica] = ps; */

    /* Mark them as recovering, since there are at least 2f+k+1 replicas
     * around that can help this one recover */
    if (DATA.PR.recovery_status[replica] == PR_STARTUP)
        DATA.PR.num_startup--;
    DATA.PR.recovery_status[replica] = PR_RECOVERY;

    /* Only the recovering replica multicasts the jump request */
    if (replica == VAR.My_Server_ID) {
        /* Construct CATCHUP_REQUEST with JUMP flag */
        if (DATA.PR.catchup_request != NULL)
            dec_ref_cnt(DATA.PR.catchup_request);
        t.sec  = CATCHUP_PERIOD_SEC;
        t.usec = CATCHUP_PERIOD_USEC;
        DATA.CATCH.next_catchup_time[VAR.My_Server_ID] = E_add_time(now, t);
        DATA.PR.catchup_request = CATCH_Construct_Catchup_Request(FLAG_RECOVERY);
        SIG_Add_To_Pending_Messages(DATA.PR.catchup_request, BROADCAST, 
                UTIL_Get_Timeliness(CATCHUP_REQUEST));

        /* AB: What if we need to catch up again before we can execute our own
         * first PO request? Added this to allow the recovering replica to try
         * to do catchup while still recovering */
        Alarm(PRINT, "E_queueing Catchup periodically in Accept Incarnation!\n");
        t.sec  = CATCHUP_REQUEST_PERIODICALLY_SEC;
        t.usec = CATCHUP_REQUEST_PERIODICALLY_USEC;
        E_queue(CATCH_Send_Catchup_Request_Periodically, 0, NULL, t);
        return;
    }
    
    /* Below only happens for non-recovering replicas */
    if (DATA.PR.recovery_status[VAR.My_Server_ID] != PR_NORMAL)
        return;

    /* Clear out ALL previously sent PO_Acks from other replicas that are not 
     * part of a complete certificate, but keep the content (PO_Request).
     * Normally, I would also throw away my created PO_Acks and reconstruct
     * them with the new vector, but in this case we are using a clever trick to just
     * update the vector, re-sign, and then send it off */
    for (i = 1; i <= VAR.Num_Servers; i++) {
        stdhash_begin(&DATA.PO.History[i], &it);
        while (!stdhash_is_end(&DATA.PO.History[i], &it)) {
            p_slot = *(po_slot**)stdit_val(&it);

            if (PRE_ORDER_Seq_Compare(p_slot->seq, DATA.PO.cum_aru[i]) > 0) {
                for (j = 1; j <= VAR.Num_Servers; j++) {
                    if (p_slot->ack[j] != NULL) {
                        dec_ref_cnt(p_slot->ack[j]);
                        p_slot->ack[j] = NULL;
                        p_slot->ack_part[j] = NULL;
                        p_slot->ack_received[j] = 0;
                    }
                }
            }
            stdit_next(&it);
        }

        /* NOT NEEDED FOR NOW- since we are sending from cum_aru+1 to present
         * after we just cleared things out */
        /* If I've sent acks for anything above the cum_aru for this replica, 
         * I need to roll back that knowledge in order to resend the acks again
         * with the new preinstalled incarnation vector.
         * NOTE: if we have yet to preorder anything from the new incarnation
         * yet for this replica, cum_aru will have an old incarnation. Do not
         * let the incarnation roll back, just set seq_num to 0 */
        /* if (PRE_ORDER_Seq_Compare(DATA.PO.max_acked[i], DATA.PO.cum_aru[i]) > 0) {
            if (DATA.PO.max_acked[i].incarnation > DATA.PO.cum_aru[i].incarnation)
                DATA.PO.max_acked[i].seq_num = 0;
            else
                DATA.PO.max_acked[i] = DATA.PO.cum_aru[i];
        } */

        /* Since we just cleared out PO_Acks, also roll back our knowledge
         * of what anyone Acked to their latest PO_ARU value? */
        for (j = 1; j <= VAR.Num_Servers; j++) {
            if (PRE_ORDER_Seq_Compare(DATA.PO.cum_max_acked[j][i], 
                DATA.PO.cum_acks[j].cum_ack.ack_for_server[i-1]) > 0) 
            {
                DATA.PO.cum_max_acked[j][i] = DATA.PO.cum_acks[j].cum_ack.ack_for_server[i-1];
            }
        }
    }

    /* Retransmit my PO-Acks that are not yet in certificates (the ones we just changed above) */
    more_to_ack = 1; 
    while(more_to_ack) {
        /* Now construct the Local PO_Ack */
        ack = PRE_ORDER_Construct_PO_Ack(&more_to_ack, 1);

        /* Ack may be NULL if there is no ack to send right now */
        if (ack == NULL)
            break;

        SIG_Add_To_Pending_Messages(ack, BROADCAST, UTIL_Get_Timeliness(PO_ACK));
        dec_ref_cnt(ack);
    }

    /* Clear out ALL previously sent Prepares and Commits from other replicas
     * that are not part of a complete certificate, but keep content (Pre-Prepare) 
     * Normally, I would also throw away my created prepares and commits and reconstruct
     * them with the new vector, but in this case we are using a clever trick to just
     * update the vector, re-sign, and then send it off */
    stdhash_begin(&DATA.ORD.History, &it);
    while (!stdhash_is_end(&DATA.ORD.History, &it)) {
        o_slot = *(ord_slot**)stdit_val(&it);

        if (!o_slot->ordered) {
            for (j = 1; j <= VAR.Num_Servers; j++) {
 
                /* Whether or not we have a prepare certificate, we will be replacing
                 * our "weak" stored prepare (in the slot->prepare array) with a new one
                 * that has the new preinstalled vector on it, in case there are other
                 * replicas that need it to complete their prepare cert. The only
                 * difference is from our point of view is whether we keep or clear
                 * the prepares from others - only clear if we've yet to get a cert */
                if (j != VAR.My_Server_ID && !o_slot->prepare_certificate_ready && 
                      o_slot->prepare[j] != NULL) 
                {
                    dec_ref_cnt(o_slot->prepare[j]);
                    o_slot->prepare[j] = NULL;
                }
                else if (j == VAR.My_Server_ID && o_slot->sent_prepare) {
                    if (o_slot->prepare[j] != NULL) {
                        prepare_specific = (prepare_message *)(o_slot->prepare[j] + 1);
                        memcpy(prepare_specific->preinstalled_incarnations,
                                DATA.PR.preinstalled_incarnations + 1, 
                                sizeof(int32u) * VAR.Num_Servers);
                        SIG_Add_To_Pending_Messages(o_slot->prepare[j], BROADCAST,
                                UTIL_Get_Timeliness(PREPARE));
                    }
                    else {
                        prepare = ORDER_Construct_Prepare(&o_slot->complete_pre_prepare);
                        SIG_Add_To_Pending_Messages(prepare, BROADCAST,
                                UTIL_Get_Timeliness(PREPARE));
                        dec_ref_cnt(prepare);
                    }
                }

                /* if (o_slot->prepare[j] != NULL) {
                    if (j != VAR.My_Server_ID && !o_slot->prepare_certificate_ready) {
                        dec_ref_cnt(o_slot->prepare[j]);
                        o_slot->prepare[j] = NULL;
                    }
                    else if (j == VAR.My_Server_ID) {
                        prepare_specific = (prepare_message *)(o_slot->prepare[j] + 1);
                        memcpy(prepare_specific->preinstalled_incarnations,
                                DATA.PR.preinstalled_incarnations + 1, 
                                sizeof(int32u) * VAR.Num_Servers);
                        SIG_Add_To_Pending_Messages(o_slot->prepare[j], BROADCAST,
                                UTIL_Get_Timeliness(PREPARE));
                    }
                } */

                /* If the slot is not ordered, we always clear out (and edit our own)
                 * commit messages, and resend ours to try to get a certificate with
                 * the new preinstalled vector */
                if (j != VAR.My_Server_ID && o_slot->commit[j] != NULL) 
                {
                    dec_ref_cnt(o_slot->commit[j]);
                    o_slot->commit[j] = NULL;
                }
                else if (j == VAR.My_Server_ID && o_slot->sent_commit) {
                    if (o_slot->commit[j] != NULL) {
                        commit_specific = (commit_message *)(o_slot->commit[j] + 1);
                        memcpy(commit_specific->preinstalled_incarnations,
                                DATA.PR.preinstalled_incarnations + 1, 
                                sizeof(int32u) * VAR.Num_Servers);
                        SIG_Add_To_Pending_Messages(o_slot->commit[j], BROADCAST,
                                UTIL_Get_Timeliness(COMMIT));
                    }
                    else {
                        commit = ORDER_Construct_Commit(&o_slot->complete_pre_prepare);
                        SIG_Add_To_Pending_Messages(commit, BROADCAST,
                                UTIL_Get_Timeliness(COMMIT));
                        dec_ref_cnt(commit);
                    }
                }

                /* if (o_slot->commit[j] != NULL) {
                    if (j != VAR.My_Server_ID) {
                        dec_ref_cnt(o_slot->commit[j]);
                        o_slot->commit[j] = NULL;
                    }
                    else {
                        commit_specific = (commit_message *)(o_slot->commit[j] + 1);
                        memcpy(commit_specific->preinstalled_incarnations,
                                DATA.PR.preinstalled_incarnations + 1, 
                                sizeof(int32u) * VAR.Num_Servers);
                        SIG_Add_To_Pending_Messages(o_slot->commit[j], BROADCAST,
                                UTIL_Get_Timeliness(COMMIT));
                    }
                } */
            }
        }
        stdit_next(&it);
    }

    /* Clear out their previously stored catchup_requests and jump_mismatches */
    /* if (DATA.CATCH.last_catchup_request[replica] != NULL) {
        dec_ref_cnt(DATA.CATCH.last_catchup_request[replica];
        DATA.CATCH.last_cathup_request[replica] = NULL;
    } */

    if (DATA.PR.jump_mismatch[replica] != NULL) {
        dec_ref_cnt(DATA.PR.jump_mismatch[replica]);
        DATA.PR.jump_mismatch[replica] = NULL;
        DATA.PR.jump_mismatch_count--;
    }

    /* Push back the periodic functions if they are enqueued since we 
     * potentially just sent off several po_acks, prepares, and commits */
    t.sec  = RETRANS_PERIOD_SEC;
    t.usec = RETRANS_PERIOD_USEC;
    if (E_in_queue(PRE_ORDER_Periodic_Retrans, 0, NULL))
        E_queue(PRE_ORDER_Periodic_Retrans, 0, NULL, t);
    if (E_in_queue(ORDER_Periodic_Retrans, 0, NULL))
        E_queue(ORDER_Periodic_Retrans, 0, NULL, t);
    
    /* Multicast Catchup Request. This is for the case where some replcias
     * may have finished a certificate on a PO_Ack or Prepare/Commit before
     * this Incarnation Cert was applied, but you did not. They will not
     * resend those items with the new vector because they already have the
     * cert for them. But you will now expect new pieces with the newly
     * updated Preinstalled vectors. Normal Catchup will take care of fixing this,
     * since they will just send you the cert, but we speed up the process
     * here (to limit the slow-down effect of recovering replicas) and 
     * explicitly send a catchup request now (rather than wait for timeout). */
    request = CATCH_Construct_Catchup_Request(FLAG_CATCHUP);
    for (i = 1; i <= VAR.Num_Servers; i++) {
        if (DATA.CATCH.sent_catchup_request[i] != NULL)
            dec_ref_cnt(DATA.CATCH.sent_catchup_request[i]);
        inc_ref_cnt(request);
        DATA.CATCH.sent_catchup_request[i] = request;
    }
    t.sec  = CATCHUP_PERIOD_SEC;
    t.usec = CATCHUP_PERIOD_USEC;
    DATA.CATCH.next_catchup_time[VAR.My_Server_ID] = E_add_time(now, t);
    SIG_Add_To_Pending_Messages(request, BROADCAST, UTIL_Get_Timeliness(CATCHUP_REQUEST));

    /* Push back normal periodic timer if it is already enqueued */
    if (E_in_queue(CATCH_Send_Catchup_Request_Periodically, 0, NULL)) {
        t.sec  = CATCHUP_REQUEST_PERIODICALLY_SEC;
        t.usec = CATCHUP_REQUEST_PERIODICALLY_USEC;
        E_queue(CATCH_Send_Catchup_Request_Periodically, 0, NULL, t);
    }
}

void PR_Process_Jump(signed_message *mess)
{
    int32u sender; 
    jump_message *jm;
    catchup_request_message *cr;
    pending_state_message *psm;

    sender = mess->machine_id;
    jm = (jump_message *)(mess + 1);
    Alarm(PRINT, "PR_Process_Jump. RECOVERY Jump Message from %u\n", sender);

    /* PRTODO: check the incarnation and monotonic counter */

    if (DATA.PR.complete_recovery_state == 1)
        return;

    if (DATA.PR.recovery_status[VAR.My_Server_ID] != PR_RECOVERY)
        return;

    if (DATA.PR.catchup_request == NULL) {
        Alarm(PRINT, "PR_Process_Jump: my stored catchup_request is NULL!\n");
        return;
    }

    cr = (catchup_request_message *)(DATA.PR.catchup_request + 1);
    if (jm->acked_nonce != cr->nonce) {
        Alarm(PRINT, "PR_Process_Jump: jm->acked_nonce %u != my nonce %u\n",
                jm->acked_nonce, cr->nonce);
        return;
    }

    /* Only store one copy of the jump message from each replica per
     * catchup_request I send out */
    if (DATA.PR.jump_message[sender] != NULL)
        return;

    DATA.PR.jump_count++;
    inc_ref_cnt(mess);
    DATA.PR.jump_message[sender] = mess;

    if (DATA.PR.complete_pending_state[sender] && DATA.PR.jump_message[sender]) {
        psm = (pending_state_message *)(DATA.PR.pending_state[sender] + 1);
        jm = (jump_message *)(DATA.PR.jump_message[sender] + 1);
        if (psm->seq_num != jm->seq_num)
            return;
        DATA.PR.complete_recovery_state_count++;
        if (DATA.PR.complete_recovery_state_count >= 2*VAR.F + VAR.K + 1) {
            PR_Try_To_Complete_Recovery(sender);
        }
    }
}

void PR_Process_Pending_State(signed_message *mess)
{
    int32u sender;
    jump_message *jm;
    catchup_request_message *cr;
    pending_state_message *psm;

    sender = mess->machine_id;
    psm = (pending_state_message *)(mess + 1);

    Alarm(PRINT, "PR_Process_Pending_State: Statement from %u. ARU = %u, TOTAL shares = %u\n", 
            sender, psm->seq_num, psm->total_shares);

    if (DATA.PR.complete_recovery_state == 1)
        return;

    /* Make sure we have a catchup_request stored for ourselves that initiated the
     * whole recovery process to begin with */
    if (DATA.PR.catchup_request == NULL) {
        Alarm(PRINT, "PR_Process_Pending_State: recovery catchup_request is NULL\n");
        return;
    }

    cr = (catchup_request_message *)(DATA.PR.catchup_request + 1);
    if (psm->acked_nonce != cr->nonce) {
        Alarm(PRINT, "PR_Process_Pending_State: acked_nonce %u != my nonce %u from %u\n",
                psm->acked_nonce, cr->nonce, sender);
        return;
    }

    /* Only one pending state from each replica per recovery catchup attempt */
    if (DATA.PR.pending_state[sender] != NULL)
        return;

    /* Store the statement */
    inc_ref_cnt(mess);
    DATA.PR.pending_state[sender] = mess;

    PR_Check_Complete_Pending_State(sender);
    if (DATA.PR.complete_pending_state[sender] && DATA.PR.jump_message[sender]) {
        psm = (pending_state_message *)(DATA.PR.pending_state[sender] + 1);
        jm = (jump_message *)(DATA.PR.jump_message[sender] + 1);
        if (psm->seq_num != jm->seq_num)
            return;
        DATA.PR.complete_recovery_state_count++;
        if (DATA.PR.complete_recovery_state_count >= 2*VAR.F + VAR.K + 1) {
            PR_Try_To_Complete_Recovery(sender);
        }
    }
}

void PR_Process_Pending_Share(signed_message *mess)
{
    int32u sender;
    catchup_request_message *cr;
    jump_message *jm;
    pending_state_message *psm;
    pending_share_message *pss;
    stdit it;

    sender = mess->machine_id;
    pss = (pending_share_message *)(mess + 1);

    Alarm(PRINT, "PR_Process_Pending_Share: Share from %u. Type = %u, Index %u\n", 
            sender, pss->type, pss->index);

    if (DATA.PR.complete_recovery_state == 1)
        return;

    /* Make sure we have a catchup_request stored for ourselves that initiated the
     * whole recovery process to begin with */
    if (DATA.PR.catchup_request == NULL) {
        Alarm(PRINT, "PR_Process_Pending_Share: recovery catchup_request is NULL\n");
        return;
    }

    cr = (catchup_request_message *)(DATA.PR.catchup_request + 1);
    if (pss->acked_nonce != cr->nonce) {
        Alarm(PRINT, "PR_Process_Pending_Share: acked_nonce %u != my nonce %u from %u\n",
                pss->acked_nonce, cr->nonce, sender);
        return;
    }

    /* Make sure the pending_share is a valid type */
    if (pss->type != PO_REQUEST && pss->type != PRE_PREPARE) {
        Alarm(PRINT, "PR_Process_Pending_Share: invalid type of share: %u\n", pss->type);
        return;
    }
            
    /* First, make sure we haven't already received this share by looking in
     * the pending shares hash for this sender for this share */
    stdhash_find(&DATA.PR.pending_shares[sender], &it, &pss->index);
    if (!stdhash_is_end(&DATA.PR.pending_shares[sender], &it)) {
        Alarm(PRINT, "PR_Process_Pending_Share: Already have index %u from server %u\n",
                pss->index, sender);
        return;
    }

    /* Store the share in the hash table */
    inc_ref_cnt(mess);
    stdhash_insert(&DATA.PR.pending_shares[sender], &it, &pss->index, &mess);

    PR_Check_Complete_Pending_State(sender);
    if (DATA.PR.complete_pending_state[sender] && DATA.PR.jump_message[sender]) {
        psm = (pending_state_message *)(DATA.PR.pending_state[sender] + 1);
        jm = (jump_message *)(DATA.PR.jump_message[sender] + 1);
        if (psm->seq_num != jm->seq_num)
            return;
        DATA.PR.complete_recovery_state_count++;
        if (DATA.PR.complete_recovery_state_count >= 2*VAR.F + VAR.K + 1) {
            PR_Try_To_Complete_Recovery(sender);
        }
    }
}

void PR_Check_Complete_Pending_State(int32u replica)
{
    int32u i;
    stdit it;
    pending_state_message *psm;

    /* If we don't have the pending_state message from this replica, we cannot
     * proceed to see if we have all of the shares yet */
    if (DATA.PR.pending_state[replica] == NULL)
        return;

    psm = (pending_state_message *)(DATA.PR.pending_state[replica] + 1);

    /* Check the size of the pending_shares hash table to get a peak if it is 
     * even possible to have collected complete pending state yet */
    if (stdhash_size(&DATA.PR.pending_shares[replica]) != psm->total_shares)
        return;

    /* Check if we have each share advertised in the statement */
    for (i = 1; i <= psm->total_shares; i++) {
        stdhash_find(&DATA.PR.pending_shares[replica], &it, &i);
        if (stdhash_is_end(&DATA.PR.pending_shares[replica], &it))
            return;
    }
    
    DATA.PR.complete_pending_state[replica] = 1;
    Alarm(PRINT, "Complete_Pending_State from %u\n", replica);
}


void PR_Try_To_Complete_Recovery(int32u recent_replica)
{
    int32u i, max_ord, jump_targ, size, num_match, recovery_set;
    jump_message *jm;
    signed_message *oc, *rc, *rpo, *up, *mess, *content, *to_process;
    ord_certificate_message *oc_specific;
    reset_certificate_message *rc_specific;
    reset_proposal_message *rpo_specific;
    pending_share_message* pss;
    byte *ptr, digest[DIGEST_SIZE];
    stdit it;

    /* Make sure we have complete state for recent_replica */
    if (DATA.PR.complete_pending_state[recent_replica] == 0)
        return;
    
    if (DATA.PR.jump_message[recent_replica] == 0)
        return;

    /* If we don't have 2f+k+1 jump messages yet, no point to continue */
    if (DATA.PR.jump_count < 2*VAR.F + VAR.K + 1)
        return;

    /* If we don't have enough complete_recovery_state_count, no point to continue */
    if (DATA.PR.complete_recovery_state_count < 2*VAR.F + VAR.K + 1)
        return;

    num_match = 0;
    recovery_set = 0;
    jm = (jump_message *)(DATA.PR.jump_message[recent_replica] + 1);

    memcpy(digest, jm->proposal_digest, DIGEST_SIZE);
    for (i = 1; i <= VAR.Num_Servers; i++) {
        if (DATA.PR.jump_message[i] == NULL)
            continue;

        jm = (jump_message *)(DATA.PR.jump_message[i] + 1);
        if (OPENSSL_RSA_Digests_Equal(digest, jm->proposal_digest)) {
            num_match++;
            UTIL_Bitmap_Set(&recovery_set, i);
        }
    }

    /* If we don't have 2f+k+1 matching digests AKA global incarnations
     * yet, no point in continuing */
    if (num_match < 2*VAR.F + VAR.K + 1)
        return;

    /* Now, go through the at least 2f+k+1 jump messages that match the digest 
     * AKA global incarnation we are interseted in, and find the highest advanced
     * one to jump to */
    max_ord = 0;
    jump_targ = 0;
    for (i = 1; i <= VAR.Num_Servers; i++) {

        if (!UTIL_Bitmap_Is_Set(&recovery_set, i))
            continue;

        jm = (jump_message *)(DATA.PR.jump_message[i] + 1);
        if (jm->seq_num == 0 && jump_targ == 0) {
            jump_targ = i;
        }
        else if (jm->seq_num > 0) {
            oc = (signed_message *)(jm + 1);
            oc_specific = (ord_certificate_message *)(oc + 1);

            if (oc_specific->seq_num > max_ord) {
                max_ord = oc_specific->seq_num;
                jump_targ = i;
            }
        }
    }

    /* Make sure we have a valid jump target */
    if (jump_targ == 0) {
        Alarm(PRINT, "PR_Try_To_Complete_Recovery: No valid jump target in RECOVERY\n");
        return;
    }

    /* We have finished collecting what we need for recovery */
    DATA.PR.complete_recovery_state = 1;

    /* We have the jump message we will use, setup the pointers to the
     * different message parts */
    jm = (jump_message *)(DATA.PR.jump_message[jump_targ] + 1);
    Alarm(PRINT, "PR_Try_To_Complete_Recovery: Moving to ordinal %u\n", max_ord); 
    if (max_ord > 0) {
        oc = (signed_message *)(jm + 1);
        size = UTIL_Message_Size(oc);
        ptr = (byte *)(((byte *)oc) + size);
    }
    else {
        ptr = (byte *)(jm + 1);
    }
    rc = (signed_message *)(ptr);
    rc_specific = (reset_certificate_message *)(rc + 1);
    rpo = (signed_message *)(rc_specific + 1);
    rpo_specific = (reset_proposal_message *)(rpo + 1);

    /* Store the reset proposal as our own */
    assert(DATA.PR.reset_proposal == NULL);
    DATA.PR.reset_proposal = UTIL_New_Signed_Message();
    memcpy(DATA.PR.reset_proposal, rpo, UTIL_Message_Size(rpo));

    /* Store this reset certificate as our own, and compute the proposal digest */
    assert(DATA.PR.reset_certificate == NULL);
    DATA.PR.reset_certificate = UTIL_New_Signed_Message();
    size = UTIL_Message_Size(rc);
    memcpy(DATA.PR.reset_certificate, rc, size);
    memset(DATA.PR.reset_certificate, 0, sizeof(signed_message));
    DATA.PR.reset_certificate->machine_id = VAR.My_Server_ID;
    DATA.PR.reset_certificate->type = RESET_CERT;
    DATA.PR.reset_certificate->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    DATA.PR.reset_certificate->len = rc->len; /* AB: check */
    OPENSSL_RSA_Make_Digest((byte*)rpo_specific, rpo->len, DATA.PR.proposal_digest);

    /* Start by adopting the starting state that everyone else should be in */
    PR_Execute_Reset_Proposal();

    /* Now, jump if there is actual progress that was made in this global incarnation */
    if (max_ord > 0) {
        oc = (signed_message *)(jm + 1);
        CATCH_Jump_Ahead(oc);
    }

    /* Next, go through the replicas that gave us valid Pending state and apply
     * the shares (PO_Requests, Pre_Prepares) to our data structures */
    for (i = 1; i <= VAR.Num_Servers; i++) {
        if (!UTIL_Bitmap_Is_Set(&recovery_set, i))
            continue;

        /* Question: Do we need to validate these messages before processing
         * them? Because we just accepted everyone's current incarnations now
         * (when we jumped), we could not actually check that the incarnations
         * (and signatures) were valid when we initially received these
         * messages */
        for (stdhash_begin(&DATA.PR.pending_shares[i], &it);
            !stdhash_is_end(&DATA.PR.pending_shares[i], &it); stdit_next(&it))
        {
            mess = *(signed_message **)stdit_val(&it);
            pss = (pending_share_message *)(mess + 1);
            assert(pss->index > 0 && pss->index <= ((pending_state_message *)(DATA.PR.pending_state[i] + 1))->total_shares);
            content = (signed_message *)(pss + 1); 
            to_process = UTIL_New_Signed_Message();
            memcpy(to_process, content, UTIL_Message_Size(content));
            PROCESS_Message(to_process);
            dec_ref_cnt(to_process);
        }
    }
    /* PRTODO: cleanup shares memory now? or later? */

    /* Set my state to NORMAL, start up Prime periodic functions */
    //DATA.PR.recovery_status[VAR.My_Server_ID] = PR_NORMAL;
    //PR_Resume_Normal_Operation();

    /* Send my first update, which will also trigger State Xfer at application */
    up = PRE_ORDER_Construct_Update(CLIENT_STATE_TRANSFER);
    PROCESS_Message(up);
    dec_ref_cnt(up);
}

void PR_Send_Pending_State(int32u target, int32u acked_nonce)
{
    int32u dest_bits;
    signed_message *state, *share, *content;
    pending_share_message *pss;

    dest_bits = 0;
    UTIL_Bitmap_Set(&dest_bits, target);

    /* PRTODO: Sanity check here to make sure that the outbound_share_dll is empty
     * for the target. What if its not? Give up on the old pending state xfer and
     * start anew? Make sure we are rate limiting */
    if (!UTIL_DLL_Is_Empty(&DATA.PR.outbound_pending_share_dll[target]))
        UTIL_DLL_Clear(&DATA.PR.outbound_pending_share_dll[target]);

    /* Construct the pending statement message, which will in turn create the DLL
     * queue of the shares that need to be sent. We are sending them below in the
     * single loop, but may want to split the sending up based on flow control  at
     * some point in the future.
     *
     * Note: we are not storing the statement for later since we will just end up
     * responding to the next catchup_request message when time permits and 
     * re-evaluate our yet-to-be executed state and send that fresh version */
    state = PR_Construct_Pending_State(target, acked_nonce);
    SIG_Add_To_Pending_Messages(state, dest_bits, UTIL_Get_Timeliness(PENDING_STATE));
    dec_ref_cnt(state);

    /* Send the shares, one certificate at a time */
    while (!UTIL_DLL_Is_Empty(&DATA.PR.outbound_pending_share_dll[target])) {
        share = UTIL_DLL_Front_Message(&DATA.PR.outbound_pending_share_dll[target]);
        assert(share);
        pss = (pending_share_message *)(share + 1);

        content = (signed_message *)(pss + 1);
        assert(content->type == PO_REQUEST || content->type == PRE_PREPARE);

        UTIL_DLL_Pop_Front(&DATA.PR.outbound_pending_share_dll[target]);
        SIG_Add_To_Pending_Messages(share, dest_bits, UTIL_Get_Timeliness(PENDING_SHARE));
        dec_ref_cnt(share);
    }
}

/* ==== RESET TO FRESH SYSTEM CASE ==== */
void PR_Process_Reset_Vote(signed_message *mess)
{
    signed_message *share;
    reset_vote_message *rv;
    new_incarnation_message *ni;
    int32u sender;
    //sp_time t;

    sender = mess->machine_id;
    rv = (reset_vote_message *)(mess + 1);
    ni = (new_incarnation_message *)(DATA.PR.new_incarnation[VAR.My_Server_ID] + 1);

    Alarm(DEBUG, "PR_Process_Reset_Vote: recv RESET_VOTE from %u\n", sender);

    /* Check that my current incarnation is the one being ACKed */
    if (rv->acked_incarnation != DATA.PR.new_incarnation_val[VAR.My_Server_ID]) {
        Alarm(PRINT, "PR_Process_Reset_Vote: My_Inc (%u) != reset_vote acked (%u)\n", 
            DATA.PR.new_incarnation_val[VAR.My_Server_ID], rv->acked_incarnation);
        return;
    }
    
    /* Check that my nonce is covered, proving freshness */
    if (rv->acked_nonce != ni->nonce) {
        Alarm(PRINT, "PR_Process_Reset_Vote: reset_vote nonce (%u) != my nonce (%u)\n",
            rv->acked_nonce, ni->nonce);
        return;
    }

    /* PRTODO: check that the TPM monotonic counter is in fact larger on this message */
    /* if */

    /* If you're in PR_STARTUP state, use reset votes to get a fresh signal that
     * the sender of the reset_vote is also in the startup case */
    if (DATA.PR.recovery_status[VAR.My_Server_ID] == PR_STARTUP && 
        DATA.PR.recovery_status[mess->machine_id] != PR_STARTUP) {
        DATA.PR.num_startup++;
        DATA.PR.recovery_status[mess->machine_id] = PR_STARTUP;
        /* if (DATA.PR.num_startup >= VAR.F + VAR.K + 1 && 
            DATA.PR.recovery_status[VAR.My_Server_ID] != PR_STARTUP) 
        {
            Alarm(PRINT, "SYSTEM ASSUMPTIONS VOLATED: >= f+k+1 in startup\n");
            PR_Reset_Prime();
        } */
    }

    /* If this is the first time getting a vote from this sender, increase count */
    if (DATA.PR.reset_vote[sender] == NULL)
        DATA.PR.reset_vote_count++;
    /* Otherwise, delete the old version which will be replaced */
    else 
        dec_ref_cnt(DATA.PR.reset_vote[sender]);
    inc_ref_cnt(mess);
    DATA.PR.reset_vote[sender] = mess;

    if (DATA.PR.reset_vote_count == 2*VAR.F + VAR.K) {
        /* if (DATA.PR.recovery_status[VAR.My_Server_ID] == PR_STARTUP)
            DATA.PR.num_startup--;
        DATA.PR.recovery_status[VAR.My_Server_ID] = PR_RESET; */

        /* Enqueue the Rotate leader function in case the current leader doesn't
         * do its job fast enough to get the system up and running */
        /* t.sec  = SYSTEM_RESET_TIMEOUT_SEC;
        t.usec = SYSTEM_RESET_TIMEOUT_USEC;
        E_queue(PR_Rotate_Reset_Leader, 0, NULL, t); */

        /* Each replica constructs their reset share */
	Alarm(DEBUG,"Sahiti****: Sending Reset Share as DATA.PR.reset_vote_count=%d,needed=%d\n",DATA.PR.reset_vote_count,2*VAR.F + VAR.K);
        share = PR_Construct_Reset_Share();
        SIG_Add_To_Pending_Messages(share, BROADCAST, UTIL_Get_Timeliness(RESET_SHARE));
        dec_ref_cnt(share);
    }
	else{
	Alarm(DEBUG,"Sahiti****: DATA.PR.reset_vote_count=%d,needed=%d\n",DATA.PR.reset_vote_count,2*VAR.F + VAR.K);
	}
}

void PR_Process_Reset_Share(signed_message *mess)
{
    int32u sender;
    reset_share_message *stored_rsm = NULL;
    sp_time t;

    sender = mess->machine_id;
    Alarm(DEBUG, "PR_Process_Reset_Share: recvd share from %u\n", sender);

    if (DATA.View > 1 && !UTIL_I_Am_Leader())  {
        Alarm(PRINT, "PR_Process_Reset_Share: Not the leader and recvd share in view > 1\n");
        return;
    }

    /* if (DATA.PR.reset_newview_contains_proposal == 1) {
        Alarm(PRINT, "PR_Process_Reset_Share: Not the leader and recvd share in view > 1\n");
        return;
    } */

    if (DATA.PR.reset_share[sender] != NULL)
        stored_rsm = (reset_share_message *)(DATA.PR.reset_share[sender] + 1);
       
    /* Check if this reset_share message is for an older incarnation than what is stored */
    if (stored_rsm != NULL && mess->incarnation <= (DATA.PR.reset_share[sender])->incarnation) {
        Alarm(DEBUG, "Old reset_share message: %u <= %u (stored)\n", 
                    mess->incarnation, (DATA.PR.reset_share[sender])->incarnation);
        return;
    }   

    if (DATA.PR.reset_share[sender] != NULL)
        dec_ref_cnt(DATA.PR.reset_share[sender]);
    else
        DATA.PR.reset_share_count++;

    /* Store the message */
    inc_ref_cnt(mess);
    DATA.PR.reset_share[sender] = mess;

    /* If I'm not the leader, forward this the first time to the leader */
    if (!UTIL_I_Am_Leader())
        UTIL_Send_To_Server(mess, UTIL_Leader());
    
    if (DATA.PR.reset_share_count != 2*VAR.F + VAR.K + 1 || E_in_queue(PR_Post_Shares_Delay, 0, NULL))
        return;

    /* Enqueue the Rotate leader function in case the current leader doesn't
     * do its job fast enough to get the system up and running */
    t.sec  = SYSTEM_RESET_TIMEOUT_SEC;
    t.usec = SYSTEM_RESET_TIMEOUT_USEC;
    E_queue(PR_Rotate_Reset_Leader, 0, NULL, t);

    /* We have reached the minimum 2f+k+1 shares needed to start the fresh system.
     * But all replicas (leader included) must wait at least the minimum delay
     * to "ensure" enough time elapses to receive all correct replicas' shares.
     *
     * During OOB reconfiguration, we will receive 2f+k+1 shares. But this is different 
     * from above situation. Here, all replicas part of the new configuration 
     * can immediately move to the new configuration and resume operation.
     * */

    if (DATA.View == 1 && UTIL_I_Am_Leader()) {
                t.sec  = 2*SYSTEM_RESET_MIN_WAIT_SEC; 
                t.usec = 2*SYSTEM_RESET_MIN_WAIT_USEC;
     }else {
                t.sec  = SYSTEM_RESET_MIN_WAIT_SEC; 
                t.usec = SYSTEM_RESET_MIN_WAIT_USEC;
    	 }
    
    E_queue(PR_Post_Shares_Delay, 0, NULL, t);
}

void PR_Post_Shares_Delay(int d1, void *d2) 
{
    int32u i;

    Alarm(PRINT, "PR_Post_Shares_Delay: Executing\n");

    /* Draw a line in the sand for this reset case. Any replica that I have a share
     * from and sent to the leader is considered in RESET mode, not startup. We
     * are locking in membership to only what we collect the first view. */
    if (DATA.View == 1) {
        for (i = 1; i <= VAR.Num_Servers; i++) {
            if (DATA.PR.reset_share[i] != NULL) {
                if (DATA.PR.recovery_status[i] == PR_STARTUP)
                    DATA.PR.num_startup--;
                DATA.PR.recovery_status[i] = PR_RESET;
                Alarm(PRINT, "  setting %u to PR_RESET\n", i);
            }
        }
    }

    /* If I am the leader, send my proposal to the group */
    if (UTIL_I_Am_Leader()) {
        DATA.PR.reset_proposal = PR_Construct_Reset_Proposal();
        SIG_Add_To_Pending_Messages(DATA.PR.reset_proposal, BROADCAST, 
            UTIL_Get_Timeliness(RESET_PROPOSAL));
	Alarm(PRINT,"I am leader, so sent Reset Proposal\n");
    }
    /* Otherwise, mark that we can now process any proposal that may have arrived */
    else {
        DATA.PR.reset_min_wait_done = 1;
        if (DATA.PR.reset_proposal != NULL) 
            PR_Process_Reset_Proposal(NULL);
    }
}

void PR_Process_Reset_Proposal(signed_message *mess_param)
{
    int32u i, sender, length, size;
    int32u share_count, valid_for_me, marked_share[MAX_NUM_SERVER_SLOTS];
    signed_message *mess, *ptr, *reset_prepare;
    reset_proposal_message *rpm;
    reset_share_message *rsm, *stored_rsm;
    byte *share_ptr;
    char *ver1, *ver2;

    /* Quick sanity check up front */
    if (mess_param == NULL && DATA.PR.reset_proposal == NULL) {
        Alarm(PRINT, "PR_Process_Reset_Proposal: no valid message passed in or stored\n");
        return;
    }

    /* Make sure I have a reset_share for myself pending for completion */
    if (DATA.PR.reset_share[VAR.My_Server_ID] == NULL) {
        Alarm(PRINT, "PR_Process_Reset_Proposal: proposal before my own share is ready\n");
        return;
    }

    /* We currently only store the first valid (from our perspective) proposal
     * that we get from a leader each round. So in this case, we ignore the
     * next mess_param that we received */
    if (DATA.PR.reset_proposal != NULL && mess_param != NULL) {
        Alarm(PRINT, "PR_Process_Reset_Proposal: already stored valid proposal\n");
        return;
    }

    /* If this is the first time we are getting the reset_proposal this round, check
     * that it is valid */
    if (mess_param != NULL) {
        
        mess = mess_param;
        rpm = (reset_proposal_message *)(mess + 1);

        Alarm(DEBUG, "PR_Process_Reset_Proposal: Recvd from %u\n", mess->machine_id);

        if (mess->machine_id != UTIL_Leader()) {
            Alarm(PRINT, "PR_Process_Reset_Proposal: Came from %u, not the leader %u\n",
                mess->machine_id, UTIL_Leader());
            return;
        }
        if (rpm->view != DATA.View) {
            Alarm(PRINT, "PR_Process_Reset_Proposal: Invalid View %u != my view %u\n",
                rpm->view, DATA.View);
            return;
        }
 
        /* Here, check that the proposal is valid for my own share */
        length = sizeof(reset_proposal_message);
        share_ptr = (byte *)(rpm + 1);
        valid_for_me = 0;

        while (length < mess->len && mess->len - length >= sizeof(signed_message)) {
            ptr = (signed_message *)(share_ptr);
            rsm = (reset_share_message *)(ptr + 1);

            if (ptr->machine_id == VAR.My_Server_ID) {
                stored_rsm = (reset_share_message *)(DATA.PR.reset_share[VAR.My_Server_ID] + 1); 
                if (ptr->incarnation == (DATA.PR.reset_share[VAR.My_Server_ID])->incarnation && 
                    rsm->nonce == stored_rsm->nonce && 
                    memcmp(rsm->key, stored_rsm->key, DIGEST_SIZE) == 0)
                {
                    valid_for_me = 1;
                    break;
                }
            }
            
            size = UTIL_Message_Size(ptr);
            share_ptr += size;
            length += size;
        }
        
        if (!valid_for_me) {
            Alarm(PRINT, "PR_Process_Reset_Proposal: Proposal not valid for me!\n");
            return;
        }

        assert(DATA.PR.reset_proposal == NULL);
        inc_ref_cnt(mess);
        DATA.PR.reset_proposal = mess;
    }

    /* If we haven't waited long enough yet to process the proposal,
     * return for now, and the timed function will call this again when
     * we're ready */
    if (E_in_queue(PR_Post_Shares_Delay, 0, NULL)) {
        Alarm(PRINT, "PR_Process_Reset_Proposal: waiting for min delay to process\n");
        return;
    }

    if (DATA.View > 1 && DATA.PR.reset_collected_vc_state == 0) {
        Alarm(PRINT, "PR_Process_Reset_Proposal: waiting to collect complete vc state\n");
        return;
    }

    mess = DATA.PR.reset_proposal;
    sender = mess->machine_id;
    Alarm(PRINT, "PR_Process_Reset_Proposal: Ready to process proposal originally from %u\n", sender);

    rpm = (reset_proposal_message *)(mess + 1);

    /* If there was no proposal carried over from a previous view, check that the 
     * leader is covering my knowlege */
    if (DATA.PR.reset_carry_over_proposal == NULL) {

        /* Check if the number of shares is less than what I know - in this case the
         * proposal cannot cover everything we have knowledge of */
        if (rpm->num_shares < DATA.PR.reset_share_count) {
            Alarm(PRINT, "Too few shares in proposal (%u) to cover my knowledge (%u)\n",
                        rpm->num_shares, DATA.PR.reset_share_count);
            return;
        }
       
        /* Check that the proposal covers at least my knowledge of the shares */
        for (i = 1; i <= VAR.Num_Servers; i++)
            marked_share[i] = 0;
        length = sizeof(reset_proposal_message);
        share_ptr = (byte *)(rpm + 1);
        share_count = 0;

        while (length < mess->len && mess->len - length >= sizeof(signed_message)) {
            ptr = (signed_message *)(share_ptr);
            rsm = (reset_share_message *)(ptr + 1);

            //printf("  %u = %u\n", ptr->machine_id, ptr->incarnation);
            if (DATA.PR.reset_share[ptr->machine_id] != NULL) {

                stored_rsm = (reset_share_message *)(DATA.PR.reset_share[ptr->machine_id] + 1);

                /* Count this share (and mark it) if we haven't marked a share for this replica
                 * already AND it is either more up-to-date than what I have or matches what
                 * I have stored */
                if (marked_share[ptr->machine_id] == 0 && 
                    ptr->incarnation >= (DATA.PR.reset_share[ptr->machine_id])->incarnation) 
                {
                    marked_share[ptr->machine_id] = 1;
                    share_count++;
                }
                /* PRTODO: Several more actions can be taken:
                 *   1) Alert/Report leader that sends more than one share per replica
                 *   2) If we have 2+ messages from a replica with the same incarnation and different
                 *        keys, that replica is bad, and we could mcast both copies of that message
                 *        to prove to others as well
                 */  
            }
            size = UTIL_Message_Size(ptr);
            share_ptr += size;
            length += size;
        }

        /* Make sure all of our share knowledge was covered */
        if (share_count != DATA.PR.reset_share_count) {
            Alarm(PRINT, "PR_Process_Reset_Proposal: Not enough shares to cover my knowledge\n");
            return;
        }
    }

    /* Else, we carried over a reset_proposal from a previous round due to a prepare
    * certificate for it, check that this matches the previous version */
    else {
        length =  DATA.PR.reset_carry_over_proposal->len;
        length -= sizeof(reset_proposal_message);

        size =  DATA.PR.reset_proposal->len;
        size -= sizeof(reset_proposal_message);

        if (length != size) {
            Alarm(PRINT, "PR_Process_Reset_Proposal: carry_over length (%u) != new proposal len (%u)\n",
                    length, size);
            return;
        }

        ver1 = ((char*)DATA.PR.reset_carry_over_proposal) + sizeof(signed_message) + 
                    sizeof(reset_proposal_message);
        ver2 = ((char*)DATA.PR.reset_proposal) + sizeof(signed_message) + 
                    sizeof(reset_proposal_message);

        if (memcmp(ver1, ver2, size) != 0) {
            Alarm(PRINT, "PR_Process_Reset_Proposal: carry_over content != new proposal content\n");
            return;
        }
    }

    /* Now that we know this proposal validly covers our knowledge, go through and take
     * anything that is more up-to-date than what we know about any replica */
    length = sizeof(reset_proposal_message);
    share_ptr = (byte *)(rpm + 1);

    while (length < mess->len && mess->len - length >= sizeof(signed_message)) {
        ptr = (signed_message *)(share_ptr);
        rsm = (reset_share_message *)(ptr + 1);
        size = UTIL_Message_Size(ptr);

        /* For any reset_shares that are more up-to-date than what we have stored 
         * (incarnation ties are considered more up-to-date), store that */

        /* Here, we create a fresh message since we had nothing stored before */
        if (DATA.PR.reset_share[ptr->machine_id] == NULL) { 
            DATA.PR.reset_share[ptr->machine_id] = UTIL_New_Signed_Message();
            memcpy(DATA.PR.reset_share[ptr->machine_id], ptr, size);
            DATA.PR.reset_share_count++;
        }
        /* Here, we overwrite our copy if it is more up-to-date */
        else {
            stored_rsm = (reset_share_message *)(DATA.PR.reset_share[ptr->machine_id] + 1);
            if (ptr->incarnation >= (DATA.PR.reset_share[ptr->machine_id])->incarnation)
                memcpy(DATA.PR.reset_share[ptr->machine_id], ptr, size);
        }

        /* Also, since we had no knowledge of them resetting, change status accordingly.
         * Here, we add new replicas that we learn about to the RESET membership, even
         * if not in view 1, because its from the leader and everyone must agree. */
        if (DATA.PR.recovery_status[ptr->machine_id] == PR_STARTUP)
            DATA.PR.num_startup--;
        DATA.PR.recovery_status[ptr->machine_id] = PR_RESET;

        share_ptr += size;
        length += size;
    }

    /* Create the RESET_PREPARE message */
    if (!UTIL_I_Am_Leader() && DATA.PR.reset_sent_prepare == 0) {
        reset_prepare = PR_Construct_Reset_Prepare();
        DATA.PR.reset_sent_prepare = 1;
        SIG_Add_To_Pending_Messages(reset_prepare, BROADCAST, UTIL_Get_Timeliness(RESET_PREPARE));
        dec_ref_cnt(reset_prepare);
    }
}

void PR_Process_Reset_Prepare(signed_message *mess)
{
    int32u i, sender, num_match;
    signed_message *reset_commit;
    reset_prepare_message *rpp;
    reset_proposal_message *rpo;
    byte proposal_digest[DIGEST_SIZE];

    sender = mess->machine_id;
    Alarm(DEBUG, "PR_Process_Reset_Prepare: recvd from %u\n", sender);

    rpp = (reset_prepare_message *)(mess + 1);

    /* Check for a valid view */
    if (rpp->view != DATA.View) {
        Alarm(PRINT, "PR_Process_Reset_Prepare: invalid view %u != my view %u\n",
                rpp->view, DATA.View);
        return;
    }

    /* Check if we've already received a reset_prepare from this replica */
    if (DATA.PR.reset_prepare[sender] != NULL) {
        Alarm(PRINT, "PR_Process_Reset_Prepare: already recvd from %u\n", sender);
        return;
    }

    /* PRTODO: Check monotonic counter */

    /* Store the message */
    inc_ref_cnt(mess);
    DATA.PR.reset_prepare[sender] = mess;
    DATA.PR.reset_prepare_count++;

    /* If we don't have a reset_proposal yet or don't have enough prepares, definitely cannot
     *  collect a reset_prepare certificate */
    if (DATA.PR.reset_proposal == NULL || DATA.PR.reset_prepare_count < 2*VAR.F + VAR.K)
        return;
    
    /* If we already collected the prepare certificate and sent our commit, return */
    if (DATA.PR.reset_sent_commit == 1)
        return;

    /* There is potentially a quorum that agree on proposal, check fine-grained content */
    num_match = 0;
    rpo = (reset_proposal_message *)(DATA.PR.reset_proposal + 1);
    OPENSSL_RSA_Make_Digest((byte*)rpo, DATA.PR.reset_proposal->len, proposal_digest);

    for (i = 1; i <= VAR.Num_Servers; i++) {
        if (DATA.PR.reset_prepare[i] == NULL)
            continue;
        
        rpp = (reset_prepare_message *)(DATA.PR.reset_prepare[i] + 1);
        if (rpp->view == rpo->view && OPENSSL_RSA_Digests_Equal(rpp->digest, proposal_digest))
            num_match++;
    }

    if (num_match >= 2*VAR.F + VAR.K) {
        reset_commit = PR_Construct_Reset_Commit();
        DATA.PR.reset_sent_commit = 1;
        SIG_Add_To_Pending_Messages(reset_commit, BROADCAST, UTIL_Get_Timeliness(RESET_COMMIT));
        dec_ref_cnt(reset_commit);
    }
}

void PR_Process_Reset_Commit(signed_message *mess)
{
    int32u i, sender, num_match;
    signed_message *proposal;
    reset_commit_message *rcc;
    reset_proposal_message *rpo;
    byte proposal_digest[DIGEST_SIZE];

    sender = mess->machine_id;
    Alarm(DEBUG, "PR_Process_Reset_Commit: recvd from %u\n", sender);

    rcc = (reset_commit_message *)(mess + 1);

    /* Check for a valid view */
    if (rcc->view != DATA.View) {
        Alarm(PRINT, "PR_Process_Reset_Commit: invalid view %u != my view %u\n",
                rcc->view, DATA.View);
        return;
    }

    /* Check if we've already received a reset_commit from this replica */
    if (DATA.PR.reset_commit[sender] != NULL) {
        Alarm(PRINT, "PR_Process_Reset_Commit: already recvd from %u\n", sender);
        return;
    }

    /* PRTODO: Check monotonic counter */

    /* Store the message */
    inc_ref_cnt(mess);
    DATA.PR.reset_commit[sender] = mess;
    DATA.PR.reset_commit_count++;

    /* If we don't have a reset_proposal yet or don't have enough commits, definitely cannot
     *  collect a reset_commit certificate */
    if (DATA.PR.reset_proposal == NULL || DATA.PR.reset_commit_count < 2*VAR.F + VAR.K + 1)
        return;

    /* If we already collected enough commits and executed the reset, stop here */
    if (DATA.PR.startup_finished == 1)
        return;
    
    /* There is potentially a quorum that agree on proposal, check fine-grained content */
    num_match = 0;
    proposal = (signed_message *)DATA.PR.reset_proposal;
    rpo = (reset_proposal_message *)(proposal + 1);
    OPENSSL_RSA_Make_Digest((byte*)rpo, proposal->len, proposal_digest);

    for (i = 1; i <= VAR.Num_Servers; i++) {
        if (DATA.PR.reset_commit[i] == NULL)
            continue;
        
        rcc = (reset_commit_message *)(DATA.PR.reset_commit[i] + 1);
        if (rcc->view == rpo->view && OPENSSL_RSA_Digests_Equal(rcc->digest, proposal_digest))
            num_match++;
    }

    if (num_match < 2*VAR.F + VAR.K + 1)
        return;

    /* Compute and save the proposal digest */
    memcpy(DATA.PR.proposal_digest, proposal_digest, DIGEST_SIZE);

    /* Create a RESET_CERT to potentially help others that we are expecting
     * to be in the membership and join the system */
    assert(DATA.PR.reset_certificate == NULL);
    DATA.PR.reset_certificate = PR_Construct_Reset_Certificate();
    SIG_Add_To_Pending_Messages(DATA.PR.reset_certificate, BROADCAST, 
            UTIL_Get_Timeliness(RESET_CERT));

    /* Execute the Reset Proposal */
    PR_Execute_Reset_Proposal();
    PR_Resume_Normal_Operation();
    //PR_Resume_Normal_Operation(RESET_APPLICATION);
}

void PR_Execute_Reset_Proposal() 
{
    int32u i, length, size;
    byte *share_ptr;
    po_seq_pair ps;
    signed_message *ptr, *proposal;
    reset_proposal_message *rpo;
    /*reset_share_message *rsm;*/
    
    proposal = (signed_message *)DATA.PR.reset_proposal;
    rpo = (reset_proposal_message *)(proposal + 1);

    DATA.PR.startup_finished = 1;
    Alarm(PRINT, "PR_Process_Reset_Commit: FINISHED RESET!! View = %d\n", DATA.View);

    /* This leader has done its job, dequeue the leader rotate function */
    if (E_in_queue(PR_Rotate_Reset_Leader, 0, NULL))
        E_dequeue(PR_Rotate_Reset_Leader, 0, NULL);

    /* If I was waiting to process the leaders proposal but I have enough commits
     * from others to prove its ok, I can apply the proposal without having to
     * check it myself */
    if (E_in_queue(PR_Post_Shares_Delay, 0, NULL))
        E_dequeue(PR_Post_Shares_Delay, 0, NULL);

    /* Make sure our view matches this reset proposal. This should only actually
     * be changing if I'm recovering and the jump_message I was given was the
     * reset certificate, since no progress (and thus no ORD Cert) was available */
    if (DATA.View < rpo->view)
        DATA.View = rpo->view;

    /* Now, go through the reset proposal from the leader and mark these replicas
     * as having finished recovery and install their incarnations */
    length = sizeof(reset_proposal_message);
    share_ptr = (byte *)(rpo + 1);

    while (length < proposal->len && proposal->len - length >= sizeof(signed_message)) {
        ptr = (signed_message *)(share_ptr);
        /*rsm = (reset_share_message *)(ptr + 1);*/
        size = UTIL_Message_Size(ptr);

        if (!(ptr->machine_id == VAR.My_Server_ID && 
              DATA.PR.recovery_status[VAR.My_Server_ID] == PR_RECOVERY)) 
        {
            if (DATA.PR.recovery_status[ptr->machine_id] == PR_STARTUP)
                DATA.PR.num_startup--;
            DATA.PR.recovery_status[ptr->machine_id] = PR_NORMAL;
        }

        /* Note: these checks are to make sure that the latest incarnation on the
         * leaders proposal message is presintalled/installed in case more than one
         * message is included for a replica */
        printf("%u finished recovery. incarnation = %u\n", ptr->machine_id, ptr->incarnation);
        if (ptr->incarnation > DATA.PR.preinstalled_incarnations[ptr->machine_id])
            DATA.PR.preinstalled_incarnations[ptr->machine_id] = ptr->incarnation;
        if (ptr->incarnation > DATA.PR.installed_incarnations[ptr->machine_id])
            DATA.PR.installed_incarnations[ptr->machine_id] = ptr->incarnation;
        // DATA.PR.session_key = 

        share_ptr += size;
        length += size;
    }

    /* Go through the installed incarnation vector and update the PO information
     * for the non-zero servers */
    for (i = 1; i <= VAR.Num_Servers; i++) {
        if (DATA.PR.installed_incarnations[i] == 0)
            continue;

        ps.incarnation = DATA.PR.installed_incarnations[i];
        ps.seq_num = 0;
        if (PRE_ORDER_Seq_Compare(ps, DATA.PO.max_acked[i]) > 0){
		DATA.PO.max_acked[i] = ps;
                Alarm(DEBUG,"DATA.PO.max_acked[%d].inc=%lu, seq_num=%lu\n",i,DATA.PO.max_acked[i].incarnation,DATA.PO.max_acked[i].seq_num);
	}
        if (PRE_ORDER_Seq_Compare(ps, DATA.PO.aru[i]) > 0){
            Alarm(DEBUG, "aru>0\n");
		DATA.PO.aru[i] = ps;
	}
        if (PRE_ORDER_Seq_Compare(ps, DATA.PO.last_executed_po_reqs[i]) > 0){
            Alarm(DEBUG, "last_executed_po_reqs>0\n");
            DATA.PO.last_executed_po_reqs[i] = ps;
	}
        if (PRE_ORDER_Seq_Compare(ps, DATA.PO.white_line[i]) > 0){ 
            Alarm(DEBUG, "white line>0\n");
            DATA.PO.white_line[i] = ps;
	}
        /* DATA.PO.cum_aru[i] = ps; */
        /* DATA.PO.max_num_sent_in_proof[i] = ps; */
    }
}

void PR_Rotate_Reset_Leader(int d1, void *d2)
{
    signed_message *rnl;

    Alarm(PRINT, "PR_Rotate_Reset_Leader: Leader didn't get proposal executed fast enough\n");

    /* From my perspective, we need to do a view change because the current leader did not
     * get the reset proposal committed + executed fast enough */
    rnl = PR_Construct_Reset_NewLeader();
    //SIG_Add_To_Pending_Messages(rnl, BROADCAST, UTIL_Get_Timeliness(RESET_NEWLEADER));
    UTIL_RSA_Sign_Message(rnl);
    PR_Process_Reset_NewLeader(rnl);
    if (DATA.PR.reset_newleader[VAR.My_Server_ID] != NULL)
        UTIL_Broadcast(DATA.PR.reset_newleader[VAR.My_Server_ID]);
    dec_ref_cnt(rnl);
}

void PR_Process_Reset_NewLeader(signed_message *mess)
{
    int32u i, count;
    signed_message *stored;
    reset_newleader_message *rnl, *stored_specific;

    rnl = (reset_newleader_message *)(mess + 1);

    Alarm(STATUS, "Process Reset New_Leader from %u, new_view = %u, my_view = %u\n", 
            mess->machine_id, rnl->new_view, DATA.View);

    /* Check if the message contains an old view */
    if (rnl->new_view <= DATA.View)
        return;

    /* Check if we already have a reset_newleader message from this replica. If so, 
     * see if this one proposes a higher view number */
    stored = DATA.PR.reset_newleader[mess->machine_id];
    if (stored != NULL) {
        stored_specific = (reset_newleader_message *)(stored + 1);
        if (rnl->new_view <= stored_specific->new_view)
            return;
        dec_ref_cnt(stored);
    }
    inc_ref_cnt(mess);
    DATA.PR.reset_newleader[mess->machine_id] = mess;

    /* Now, count how many stored reset_newleader messages we have that match 
     * the one we just received */
    count = 0;
    for (i = 1; i <= VAR.Num_Servers; i++) {
        if (DATA.PR.reset_newleader[i] == NULL)
            continue;

        stored = DATA.PR.reset_newleader[i];
        stored_specific = (reset_newleader_message *)(stored + 1);

        if (stored_specific->new_view == rnl->new_view)
            count++;
    }

    if (count != 2*VAR.F + VAR.K + 1)
        return;

    /* Preinstall the view, construct and start sending reset_newleaderproof message */
    DATA.View = rnl->new_view;
    Alarm(STATUS, "Process_NL: Preinstalling view %u\n", DATA.View);

    if (DATA.PR.reset_newleaderproof != NULL)
        dec_ref_cnt(DATA.PR.reset_newleaderproof);
    DATA.PR.reset_newleaderproof = PR_Construct_Reset_NewLeaderProof();
    SIG_Add_To_Pending_Messages(DATA.PR.reset_newleaderproof, BROADCAST, 
            UTIL_Get_Timeliness(RESET_NEWLEADERPROOF));

    /* Proceed with the BFT view change */
    PR_Start_View_Change();
}

void PR_Process_Reset_NewLeaderProof(signed_message *mess)
{
    int32u i, count, new_view, size;
    signed_message *rnl;
    reset_newleaderproof_message *rnlp;
    reset_newleader_message *rnl_specific;
    char *ptr;

    /* (1) Validate the reset_newleaderproof message - all must match for new view
     * (2) Preinstall the new view
     * (3) Steal the reset_newleaderproof message, put our own ID, etc. on it
     * (4) Start sending */

    rnlp = (reset_newleaderproof_message *)(mess + 1);
    new_view = rnlp->new_view;
    
    Alarm(DEBUG, "Process_Reset_NewLeaderProof from %u, new_view = %u, my view = %u\n", 
            mess->machine_id, new_view, DATA.View);

    /* If you've already changed to or preinstalled this view, ignore */
    if (new_view <= DATA.View)
        return;

    /* Assuming validate has checked that we have 2f+k+1 NL messages */
    count = 0;
    ptr =  (char *)rnlp + sizeof(reset_newleaderproof_message);

    for (i = 0; i < 2*VAR.F + VAR.K + 1; i++) {
        rnl = (signed_message *)(ptr);
        rnl_specific = (reset_newleader_message *)(rnl + 1);

        /* rnl = (signed_message *)(ptr + 
                i * (sizeof(signed_message) + sizeof(reset_newleader_message)));
        rnl_specific = (reset_newleader_message *)(rnl + 1); */

        if (rnl_specific->new_view != new_view) {
            Alarm(PRINT, "SUSPECT_Process_Reset_NewLeaderProof: Incorrect "
                    "message from %u: view = %u, should be %u\n", mess->machine_id, 
                     rnl_specific->new_view, new_view);
            /* Blacklist(mess->machine_id); */
            return;
        }
        size = UTIL_Message_Size(rnl); 
        ptr += size;
        count++;
    }
    assert(count == 2*VAR.F + VAR.K + 1);

    /* Preinstall the new view and start sending new_leader_proof message */
    DATA.View = new_view;
    Alarm(PRINT, "READY for View Change to %u: Reset_NewLeaderProof Received\n", DATA.View);

    /* INAVLID: If I wasn't already in RESET mode, this is a proof that we are doing a reset view change */
    /* if (DATA.PR.recovery_status[VAR.My_Server_ID] == PR_STARTUP) {
        DATA.PR.num_startup--;
        DATA.PR.recovery_status[VAR.My_Server_ID] = PR_RESET;
    } */

    /* Take this message and claim it as our own */
    if (DATA.PR.reset_newleaderproof != NULL)
        dec_ref_cnt(DATA.PR.reset_newleaderproof);
    DATA.PR.reset_newleaderproof = mess;
    inc_ref_cnt(mess);

    /* Erase just the signed_message header to claim as our own, don't actually
     *      touch the content of the new_leader_proof message */
    size = mess->len;
    memset(DATA.PR.reset_newleaderproof, 0, sizeof(signed_message));
    DATA.PR.reset_newleaderproof->machine_id = VAR.My_Server_ID;
    DATA.PR.reset_newleaderproof->type = RESET_NEWLEADERPROOF;
    DATA.PR.reset_newleaderproof->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    DATA.PR.reset_newleaderproof->len = size;
    SIG_Add_To_Pending_Messages(DATA.PR.reset_newleaderproof, BROADCAST, 
            UTIL_Get_Timeliness(RESET_NEWLEADERPROOF));

    /* Start the view change process */
    PR_Start_View_Change();
}

void PR_Start_View_Change()
{
    signed_message *vc, *rb;
    sp_time t;

    /* Reset the RB protocol */
    RB_Initialize_Upon_View_Change();
    RB_Periodic_Retrans(0, NULL);

    /* Construct the reset_viewchange message, and set up a reliable broadcast instance
     * for it to send to everyone else */
    vc = PR_Construct_Reset_ViewChange();
    UTIL_RSA_Sign_Message(vc);

    rb = RB_Construct_Message(RB_INIT, vc);
    SIG_Add_To_Pending_Messages(rb, BROADCAST, UTIL_Get_Timeliness(RB_INIT));

    dec_ref_cnt(rb);
    dec_ref_cnt(vc);

    /* Reset the data structures at this point for the new round. The
     * reset_viewchange message we sent contains our information from
     * last time, being stored in the RB instance (and eventually 
     * reset_viewchange[My_ID] */
    PR_Clear_Reset_Data_Structures();

    /* Enqueue the Rotate leader function in case the current leader doesn't
     * do its job fast enough to get the system up and running */
    t.sec  = SYSTEM_RESET_TIMEOUT_SEC;
    t.usec = SYSTEM_RESET_TIMEOUT_USEC;
    E_queue(PR_Rotate_Reset_Leader, 0, NULL, t);
}

void PR_Process_Reset_ViewChange(signed_message *mess)
{
    signed_message *nv, *rb;
    reset_viewchange_message *rvc;

    rvc = (reset_viewchange_message *)(mess + 1);
    Alarm(STATUS, "PR_Process_Reset_ViewChange Message. view %u, from %u\n", 
                rvc->rb_tag.view, mess->machine_id);

    /* Check the validity of the message */
    if (rvc->rb_tag.view != DATA.View) {
        Alarm(PRINT, "PR_Process_Reset_ViewChange: rvc view (%u) != ours (%u)\n",
                rvc->rb_tag.view, DATA.View);
        return;
    }

    /* Check that the sequence number is 1 */
    if (rvc->rb_tag.seq_num != 1) {
        Alarm(PRINT, "PR_Process_Reset_ViewChange: seq num (%u) should be 1\n",
                rvc->rb_tag.seq_num);
        return;
    }

    /* Store the message. Since we are using the RB protocol and garbage collect only 
     *   at the start of the next view, there should be no duplicates */
    assert(DATA.PR.reset_viewchange[rvc->rb_tag.machine_id] == NULL);
    inc_ref_cnt(mess);
    DATA.PR.reset_viewchange[rvc->rb_tag.machine_id] = mess;
    UTIL_Bitmap_Set(&DATA.PR.reset_viewchange_bitmap, rvc->rb_tag.machine_id);

    /* If I am the leader and I have 2f+k+1 reset_viewchange messages,
     * create and send my reset_newview message using the RB protocol */
    if (UTIL_I_Am_Leader() && 
        UTIL_Bitmap_Num_Bits_Set(&DATA.PR.reset_viewchange_bitmap) == 2*VAR.F + VAR.K + 1)
    {
        nv = PR_Construct_Reset_NewView();
        UTIL_RSA_Sign_Message(nv);

        rb = RB_Construct_Message(RB_INIT, nv);
        SIG_Add_To_Pending_Messages(rb, BROADCAST, UTIL_Get_Timeliness(RB_INIT));

        dec_ref_cnt(rb);
        dec_ref_cnt(nv);
    }

    /* Now check if I have a reset_viewchange message from each of the replicas referenced in 
     * the reset_newview message list */
    PR_Check_Complete_VC_State();
}

void PR_Process_Reset_NewView(signed_message *mess)
{
    reset_newview_message *rnv;

    rnv = (reset_newview_message *)(mess + 1);
    Alarm(PRINT, "PR_Process_Reset_NewView Message for view %u\n", rnv->rb_tag.view);

    /* Check the message for validity */
    if (rnv->rb_tag.view != DATA.View) {
        Alarm(PRINT, "PR_Process_Reset_NewView: view on message (%u) != ours (%u)\n",
                rnv->rb_tag.view, DATA.View);
        return;
    }

    if (rnv->rb_tag.machine_id != UTIL_Leader()) {
        Alarm(PRINT, "PR_Process_Reset_NewView: not from leader\n");
        return;
    }

    /* We should only receive one reset_newview message each round, so if we already
     * have something stored, do not keep the new one */
    if (DATA.PR.reset_newview != NULL) {
        Alarm(PRINT, "PR_Process_Reset_NewView: already have message stored!\n");
        return;
    }   

    /* Store the message */
    inc_ref_cnt(mess);
    DATA.PR.reset_newview = mess;

    /* Now check if I have a reset_viewchange message from each of the replicas referenced in 
     * the reset_newview message list */
    PR_Check_Complete_VC_State();
}

void PR_Check_Complete_VC_State()
{
    int32u i, size;
    reset_newview_message *rnv;
    reset_viewchange_message *rvc;
    signed_message *rp;
    reset_proposal_message *rp_specific, *stored_specific;
    sp_time t;

    /* Make sure we have the reset_newview message */
    if (DATA.PR.reset_newview == NULL) {
        Alarm(DEBUG, "    Check_Reset_VC_State: newview is NULL\n");
        return;
    }

    rnv = (reset_newview_message *)(DATA.PR.reset_newview + 1);

    /* Make sure we have collected a reset_viewchange message for each replica
     * mentioned in the reset_newview list */
    if (!UTIL_Bitmap_Is_Superset(&rnv->list, &DATA.PR.reset_viewchange_bitmap)) {
        Alarm(DEBUG, "    Check_Reset_VC_State: do not contain complete newview state\n");
        Alarm(DEBUG, "    MINE   NEWVIEW\n");
        for (i = 1; i <= VAR.Num_Servers; i++) {
            Alarm(DEBUG, "[%d]   %u       %u\n", 
                    i, UTIL_Bitmap_Is_Set(&DATA.PR.reset_viewchange_bitmap, i), 
                    UTIL_Bitmap_Is_Set(&rnv->list, i));
        }
        return;
    }

    Alarm(PRINT, "Collected complete reset viewchange state\n");

    /* Now, go through and find the most advanced proposal that had a 
     * legitimate prepare certificate to carry over to this new round */
    for (i = 1; i <= VAR.Num_Servers; i++) {
        if (!UTIL_Bitmap_Is_Set(&rnv->list, i))
            continue;
    
        rvc = (reset_viewchange_message *)(DATA.PR.reset_viewchange[i] + 1);

        /* If no proposal here, continue */
        if (rvc->contains_proposal == 0)
            continue; 
        
        rp = (signed_message *)(rvc + 1);
        rp_specific = (reset_proposal_message *)(rp + 1);
        size = UTIL_Message_Size(rp);

        /* If we have something carried over already, check if this new one is more up to date */
        if (DATA.PR.reset_carry_over_proposal != NULL) {
            stored_specific = (reset_proposal_message *)(DATA.PR.reset_carry_over_proposal + 1);

            /* stored one is more up to date, continue */
            if (rp_specific->view < stored_specific->view)
                continue;

            /* they are equal views, assert they match */
            else if (rp_specific->view == stored_specific->view)
                assert(memcmp(rp, DATA.PR.reset_carry_over_proposal, size) == 0);

            /* new one is more up to date than stored, prepare to save the new one */
            else
                dec_ref_cnt(DATA.PR.reset_carry_over_proposal);
        }

        DATA.PR.reset_carry_over_proposal = UTIL_New_Signed_Message();
        memcpy(DATA.PR.reset_carry_over_proposal, rp, size);
    }

    DATA.PR.reset_collected_vc_state = 1;
    DATA.PR.reset_min_wait_done = 1;
   
    /* If I'm not the leader... */
    if (!UTIL_I_Am_Leader()) {

        /* If there is NO proposal carried over, send to new leader my shares to give
         * them a fair chance to be judged on what I've collected */
        if (DATA.PR.reset_carry_over_proposal == NULL) {
            Alarm(PRINT, "No carry over, forwarding shares to %u\n", UTIL_Leader());
            for (i = 1; i <= VAR.Num_Servers; i++) {
                if (DATA.PR.reset_share[i] != NULL)
                    UTIL_Send_To_Server(DATA.PR.reset_share[i], UTIL_Leader());
            }
        }

        if (DATA.PR.reset_proposal != NULL) {
            Alarm(PRINT, "In Process_NewView. Reset_proposal stored, processing now\n");
            PR_Process_Reset_Proposal(NULL);
        }
    }

    /* If I AM the leader... */
    else {

        /* If there is NO proposal carried over, enqueue a timeout to collect shares
         * we might not know about, then construct the proposal */
        if (DATA.PR.reset_carry_over_proposal == NULL) {
            Alarm(PRINT, "No carry over, leader setting timeout\n");
            t.sec  = SYSTEM_RESET_MIN_WAIT_SEC; 
            t.usec = SYSTEM_RESET_MIN_WAIT_USEC;
            E_queue(PR_Post_Shares_Delay, 0, NULL, t);
        }

        /* If there is carried over proposal, steal it and put our information on it */
        else {
            Alarm(PRINT, "Sending carried over proposal as new leader\n");
            assert(DATA.PR.reset_proposal == NULL);
            DATA.PR.reset_proposal = UTIL_New_Signed_Message();
            size = UTIL_Message_Size(DATA.PR.reset_carry_over_proposal);
            memcpy(DATA.PR.reset_proposal, DATA.PR.reset_carry_over_proposal, size);
            rp_specific = (reset_proposal_message *)(DATA.PR.reset_proposal + 1);
            DATA.PR.reset_proposal->machine_id = VAR.My_Server_ID;
            rp_specific->view = DATA.View;
            (DATA.PR.reset_proposal)->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
            (DATA.PR.reset_proposal)->monotonic_counter = 0;   /* PRTODO: update using TPM */
            SIG_Add_To_Pending_Messages(DATA.PR.reset_proposal, BROADCAST, 
                    UTIL_Get_Timeliness(RESET_PROPOSAL));
        }
    }
}

void PR_Process_Reset_Certificate(signed_message *mess)
{
    int32u sender, size, length, valid_for_me;
    reset_certificate_message *rc;
    signed_message *rpm, *rsm;
    reset_proposal_message *rpm_specific;
    reset_share_message *rsm_specific, *stored_rsm;
    byte *share_ptr;

    /* Based on State Permissions on message types, I should only 
     * receive this type of message if i am in STARTUP or RESET case */

    sender = mess->machine_id;
    if (sender == VAR.My_Server_ID)
        return;

    if (DATA.PR.reset_share[VAR.My_Server_ID] == NULL)
        return;

    rc = (reset_certificate_message *)(mess + 1);

    Alarm(PRINT, "Process_Reset_Certificate. From %u, View = %u\n", 
            sender, rc->view);

    /* Here, check that the proposal is valid for my own share */
    rpm = (signed_message *)(rc + 1);
    rpm_specific = (reset_proposal_message *)(rpm + 1);
    length = sizeof(reset_proposal_message);
    share_ptr = (byte *)(rpm_specific + 1);
    valid_for_me = 0;

    while (length < rpm->len && rpm->len - length >= sizeof(signed_message)) {
        rsm = (signed_message *)(share_ptr);
        rsm_specific = (reset_share_message *)(rsm + 1);

        if (rsm->machine_id == VAR.My_Server_ID) {
            stored_rsm = (reset_share_message *)(DATA.PR.reset_share[VAR.My_Server_ID] + 1); 
            if (rsm->incarnation == (DATA.PR.reset_share[VAR.My_Server_ID])->incarnation && 
                rsm_specific->nonce == stored_rsm->nonce && 
                memcmp(rsm_specific->key, stored_rsm->key, DIGEST_SIZE) == 0)
            {
                valid_for_me = 1;
                break;
            }
        }
        
        size = UTIL_Message_Size(rsm);
        share_ptr += size;
        length += size;
    }
    
    if (!valid_for_me) {
        Alarm(PRINT, "PR_Process_Reset_Cert: Proposal not valid for me!\n");
        return;
    }

    DATA.View = rc->view;

    /* Store the reset proposal */
    if (DATA.PR.reset_proposal == NULL)
        DATA.PR.reset_proposal = UTIL_New_Signed_Message();
    memcpy(DATA.PR.reset_proposal, rpm, UTIL_Message_Size(rpm));

    /* Store the proposal digest */
    OPENSSL_RSA_Make_Digest((byte*)rpm_specific, rpm->len, DATA.PR.proposal_digest);

    /* Steal this certificate as our own, putting our own information and signature on it */
    assert(DATA.PR.reset_certificate == NULL);
    size = mess->len;
    inc_ref_cnt(mess);
    DATA.PR.reset_certificate = mess;
    memset(DATA.PR.reset_certificate, 0, sizeof(signed_message));
    DATA.PR.reset_certificate->machine_id = VAR.My_Server_ID;
    DATA.PR.reset_certificate->type = RESET_CERT;
    DATA.PR.reset_certificate->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    DATA.PR.reset_certificate->len = size;
    SIG_Add_To_Pending_Messages(DATA.PR.reset_certificate, BROADCAST, 
            UTIL_Get_Timeliness(RESET_CERT));

    /* Execute the Reset Proposal */
    PR_Execute_Reset_Proposal();
    PR_Resume_Normal_Operation();
    //PR_Resume_Normal_Operation(RESET_APPLICATION);
}

void PR_Resume_Normal_Operation()
//void PR_Resume_Normal_Operation(int32u reset_app_flag)
{
    /* Send the RESET client message to the application if we are coming
     * from the system reset (or startup) case. Otherwise, we are just
     * completing a recovery, ignore sending this update since normal 
     * STATE TRANSFER will be used */
    //if (reset_app_flag == RESET_APPLICATION)
    //    PR_Send_Application_Reset();

    /* Next, startup all normal Prime periodic functions and timers */
    Alarm(PRINT,"Called PR_Resume_Normal_operations\n");
    if(DATA.NM.OOB_Reconfig_Inprogress){
	 DATA.NM.OOB_Reconfig_Inprogress = 0;
	}
    if (!UTIL_DLL_Is_Empty(&DATA.PO.po_request_dll))
        PRE_ORDER_Send_PO_Request();
    PRE_ORDER_Periodically(0, NULL);
    PRE_ORDER_Periodic_Retrans(0, NULL);
    if (UTIL_I_Am_Leader())
        ORDER_Periodically(0, NULL);
    ORDER_Periodic_Retrans(0, NULL);
    SUSPECT_Restart_Timed_Functions();
    CATCH_Send_Catchup_Request_Periodically(0, NULL);
}

void PR_Send_Application_Reset()
{
    signed_update_message reset, *up;
    signed_message *event, *up_contents;

    memset(&reset, 0, sizeof(signed_update_message));
    event = (signed_message *)&reset;
    up = (signed_update_message *)&reset;
    up_contents = (signed_message *)(up->update_contents);

    event->machine_id = VAR.My_Server_ID;
    event->type = UPDATE;
    event->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    event->len = sizeof(signed_update_message) - sizeof(signed_message);

    up->update.server_id = VAR.My_Server_ID;
    up->header.incarnation = DATA.PO.intro_client_seq[VAR.My_Server_ID].incarnation; 
    up->update.seq_num = 0;

    up_contents->machine_id = VAR.My_Server_ID;
    up_contents->type = CLIENT_SYSTEM_RESET;
    Alarm(PRINT,"MS2022: CLIENT_SYSTEM_RESET\n");
    ORDER_Execute_Event(event, 0, 1, 1);
}
