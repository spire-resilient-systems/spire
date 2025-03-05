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
void CATCH_Attempt_Catchup(int dummy, void *dummyp);
void CATCH_Advance_Catchup_ID(int32u *id);
int CATCH_Compare_Catchup_Request(signed_message *m1, signed_message *m2);
int CATCH_Can_Help_Catchup(signed_message *catchup_request);

void CATCH_Initialize_Data_Structure(void)
{
    int32u i;
    sp_time now;

    DATA.CATCH.catchup_in_progress = 0;
    DATA.CATCH.force_jump = 0;
    DATA.CATCH.starting_catchup_id = 0;
    DATA.CATCH.next_catchup_id = 0;

    now = E_get_time();
    for (i = 1; i <= VAR.Num_Servers; i++) {
        DATA.CATCH.last_ord_cert[i] = NULL;
        DATA.CATCH.last_catchup_request[i] = NULL;
        DATA.CATCH.sent_catchup_request[i] = NULL;
        DATA.CATCH.next_catchup_time[i] = now;
    }

    DATA.CATCH.periodic_catchup_id = (rand() % VAR.Num_Servers) + 1;
    if (DATA.CATCH.periodic_catchup_id == VAR.My_Server_ID)
        CATCH_Advance_Catchup_ID(&DATA.CATCH.periodic_catchup_id);

    /* Starting and next catchup ID initialized at start of each round */
    /* DATA.CATCH.next_catchup_id = VAR.My_Server_ID;
    CATCH_Advance_Catchup_ID(&DATA.CATCH.next_catchup_id); */
}

void CATCH_Reset_View_Change_Catchup(void)
{
    DATA.CATCH.vc_catchup_source = 0;
    DATA.CATCH.vc_catchup_target = 0;
}

void CATCH_Upon_Reset()
{
    int32u i;

    for (i = 1; i <= VAR.Num_Servers; i++) {
        if (DATA.CATCH.last_ord_cert[i] != NULL) {
            dec_ref_cnt(DATA.CATCH.last_ord_cert[i]);
            DATA.CATCH.last_ord_cert[i] = NULL;
        }
        if (DATA.CATCH.last_catchup_request[i] != NULL) {
            dec_ref_cnt(DATA.CATCH.last_catchup_request[i]);
            DATA.CATCH.last_catchup_request[i] = NULL;
        }
        if (DATA.CATCH.sent_catchup_request[i] != NULL) {
            dec_ref_cnt(DATA.CATCH.sent_catchup_request[i]);
            DATA.CATCH.sent_catchup_request[i] = NULL;
        }
    }
}

void CATCH_Schedule_Catchup(void)
{
    sp_time now, epsilon, t;

    /* If the Catchup event is already enqueued, I don't need to worry about
     * scheduling it - it will already trigger next timeout */
    if (E_in_queue(CATCH_Attempt_Catchup, 0, NULL))
        return;

    /* Otherwise, the event is not enqueued. We need to schedule the catchup,
     * but we must make sure we wait long enough, including: (1) not asking
     * for frequently than the timeout, and (2) waiting a small delay to
     * potentially allow late / out-of-order message to make it here. */
    now = E_get_time();
    epsilon.sec  = CATCHUP_EPSILON_SEC;
    epsilon.usec = CATCHUP_EPSILON_USEC;
    if ((E_compare_time(DATA.CATCH.next_catchup_time[VAR.My_Server_ID], now) <= 0) ||
        (E_compare_time(E_sub_time(DATA.CATCH.next_catchup_time[VAR.My_Server_ID], now), epsilon) <= 0)) 
    {
        t = epsilon;
    }
    else {
        t = E_sub_time(DATA.CATCH.next_catchup_time[VAR.My_Server_ID], now);
    }
    E_queue(CATCH_Attempt_Catchup, 0, NULL, t);
    Alarm(DEBUG, "Enqueue CATCH_Attempt_Catchup\n");
}

void CATCH_Process_ORD_Certificate(signed_message *mess)
{
    int32u i, sender;
    signed_message *pp, *commit, *temp; //, *client_op;
    ord_certificate_message *ord_cert;
    pre_prepare_message *pp_specific;
    complete_pre_prepare_message cert_complete_pp;
    commit_message *commit_specific;
    ord_slot *slot, *o_slot;
    stdit it;
    sp_time t;
    byte *ptr, stored_pp_digest[DIGEST_SIZE], cert_pp_digest[DIGEST_SIZE];

    sender = mess->machine_id;

    ord_cert = (ord_certificate_message *)(mess + 1);
    pp = (signed_message *)(ord_cert + 1);
    pp_specific = (pre_prepare_message *)(pp + 1);

    /* Special case for storing my own PO Cert */
    if (sender == VAR.My_Server_ID) {
        slot = UTIL_Get_ORD_Slot_If_Exists(ord_cert->seq_num);
        assert(slot);
        if (!slot->signed_ord_cert) {
            slot->signed_ord_cert = 1;
            dec_ref_cnt(slot->ord_certificate);
            slot->ord_certificate = mess;
            inc_ref_cnt(mess);
        }
        return;
    }

    if (!OPENSSL_RSA_Digests_Equal(pp_specific->proposal_digest, DATA.PR.proposal_digest)) {
        Alarm(PRINT, "Process_ORD_Cert: Non-Matching proposal digest on ORD Cert from %u\n",
                sender);
        return;
    }

    if (ord_cert->type != SLOT_COMMIT) {
        Alarm(PRINT, "Non-Commit ordinal certificates (%u) are not allowed for catchup\n", 
                ord_cert->type);
        return;
    }

    if (ord_cert->seq_num <= DATA.ORD.ARU) {
        Alarm(PRINT, "ORD Cert from %u. Seq = %u. OLD\n", sender, ord_cert->seq_num);
        return;
    }
    
    slot = UTIL_Get_ORD_Slot_If_Exists(ord_cert->seq_num);
    if (slot != NULL && slot->ordered == 1) {
        Alarm(PRINT, "Already ordered ORD %u, ignoring cert\n", ord_cert->seq_num);
        return;
    }

    Alarm(PRINT, "ORD Cert from %u. Seq = %u\n", sender, ord_cert->seq_num);

    /* Special check for when switching views from ordinal certificates */
    slot = UTIL_Get_ORD_Slot_If_Exists(ord_cert->seq_num - 1);
    /* AB: Allow jumping views if this is the next ordinal I'm expecting (one
     * past my ARU, or sequence number 1 if I've never executed anything), and
     * it represents a higher view or view that I'm trying to enter */
    if ( (ord_cert->seq_num == 1 &&
          (DATA.View < ord_cert->view || (DATA.View == ord_cert->view && DATA.VIEW.view_change_done == 0))) || 
         (slot != NULL && DATA.ORD.ARU == slot->seq_num && 
          slot->view < ord_cert->view && 
          (DATA.View == slot->view || (DATA.View == ord_cert->view && DATA.VIEW.view_change_done == 0))))
    {
        Alarm(PRINT, "Setting View to %u in catchup process ORD\n", ord_cert->view);

        /* Cleanup any slots that have an old view compared to the certificate, as those 
         *  slots (if higher) will have to be at least as high as the view in the cert at 
         *  this ordinal */
        stdhash_begin(&DATA.ORD.History, &it);
        while (!stdhash_is_end(&DATA.ORD.History, &it)) {
            o_slot = *(ord_slot **)stdit_val(&it);

            if (o_slot->seq_num >= ord_cert->seq_num && o_slot->view <= DATA.View) {
                Alarm(PRINT, "VC in catchup: erasing ORD slot %u\n", o_slot->seq_num);
                ORDER_Garbage_Collect_ORD_Slot(o_slot, 0);
                stdhash_erase(&DATA.ORD.History, &it);
            }
            else {
                stdit_next(&it);
            }
        }

        DATA.View = ord_cert->view;

        //ORDER_Adjust_High_Committed();
        ORDER_Adjust_High_Prepared();
        ORDER_Adjust_ppARU();

        SUSPECT_Initialize_Upon_View_Change();
        RB_Initialize_Upon_View_Change();
        VIEW_Initialize_Upon_View_Change();
        CATCH_Reset_View_Change_Catchup();
        DATA.VIEW.view_change_done = 1;
        UTIL_Stopwatch_Start(&DATA.ORD.leader_duration_sw);

        /* TODO: need anymore updates here for the view change?? */
    }

    /* Create the ORD slot (if it doesn't already exist) and setup the
     * preinstalled vector snapshot */
    slot = UTIL_Get_ORD_Slot(ord_cert->seq_num);
    if (slot->snapshot == 1)
        return;

    /* We need to clear out the slot of pre-prepare and commits in order to make sure the
     * needed parts coming in from the certificate can be placed in without
     * any issues. It is crucial that this po_cert is first validated, otherwise
     * we are erasing things that we would need. */

    /* First, check if we already have a pre-prepare in this slot, and if so check if it
     * matches the one that is coming from the cert. If not, we need to throw away the
     * one we have stored and adopt the one from the certificate */
    if (slot->collected_all_parts) {
        cert_complete_pp.seq_num = pp_specific->seq_num;
        cert_complete_pp.view = pp_specific->view;
        memcpy(&cert_complete_pp.proposal_digest, &pp_specific->proposal_digest, DIGEST_SIZE);
        memcpy(&cert_complete_pp.last_executed, &pp_specific->last_executed, 
                sizeof(pp_specific->last_executed));
        memcpy(&cert_complete_pp.cum_acks, (byte *)(pp_specific + 1), 
                sizeof(po_aru_signed_message) * pp_specific->num_acks_in_this_message);
        OPENSSL_RSA_Make_Digest((byte *)&cert_complete_pp,
                sizeof(complete_pre_prepare_message), cert_pp_digest);
        OPENSSL_RSA_Make_Digest((byte *)&slot->complete_pre_prepare, 
            sizeof(complete_pre_prepare_message), stored_pp_digest);
        if (!OPENSSL_RSA_Digests_Equal(stored_pp_digest, cert_pp_digest)) {
            ORDER_Garbage_Collect_ORD_Slot(slot, 1);
            slot = UTIL_Get_ORD_Slot(ord_cert->seq_num); 
        }
    }
    /* else if (collected at least something) - clear it out */

    /* Store the preinstall vector from the certificate as the snapshot for this
     * slot in order to correctly process the commits on this message. This assumes
     * that the ORD_Cert validate function made sure all 2f+k+1 commits in this cert
     * have matching preinstall vectors, so we just peek at the first commit to
     * grab the correct vector */
    ptr = (byte *)(((byte *)pp) + UTIL_Message_Size(pp));
    commit = (signed_message *)ptr;
    commit_specific = (commit_message *)(commit + 1);
    memcpy(slot->preinstalled_snapshot+1, commit_specific->preinstalled_incarnations,
            sizeof(int32u) * VAR.Num_Servers);
    slot->snapshot = 1;

    /* Now, clear out the commits to correctly process the ones from the cert */
    for (i = 1; i <= VAR.Num_Servers; i++) {
        /* What about prepares? */
        if (slot->commit[i] != NULL) {
            dec_ref_cnt(slot->commit[i]);
            slot->commit[i] = NULL;
        }
    }

    /* First process the Pre-Prepare */
    temp = UTIL_New_Signed_Message();
    memcpy(temp, pp, UTIL_Message_Size(pp));
    PROCESS_Message(temp);
    dec_ref_cnt(temp);

    /* Then, process the Commits */
    ptr = (byte *)(((byte *)pp) + UTIL_Message_Size(pp));
    for (i = 1; i <= 2*VAR.F + VAR.K + 1; i++) {
        commit = (signed_message *)ptr;
        temp = UTIL_New_Signed_Message();
        memcpy(temp, commit, UTIL_Message_Size(commit));
        PROCESS_Message(temp);
        dec_ref_cnt(temp);
        ptr += UTIL_Message_Size(commit);
    }

    if (!E_in_queue(CATCH_Attempt_Catchup, 0, NULL))
        return;
 
    if (DATA.CATCH.catchup_in_progress == 1) {
        t.sec  = CATCHUP_MOVEON_SEC; 
        t.usec = CATCHUP_MOVEON_USEC;
    }
    else {
        t.sec  = CATCHUP_PERIOD_SEC; 
        t.usec = CATCHUP_PERIOD_USEC;
    }
    E_queue(CATCH_Attempt_Catchup, 0, NULL, t);

    /* OLD */
    /* Special case for now - "jump" to the new ordinal to execute view change */
    /* if (ord_cert->view > DATA.View) {
        CATCH_Jump_Ahead(mess);
        client_op = PRE_ORDER_Construct_Update(CLIENT_STATE_TRANSFER);
        PROCESS_Message(client_op);
        dec_ref_cnt(client_op);
        return;
    } */

#if 0
    if (DATA.CATCH.last_ord_cert[sender]) {
        stored = (ord_certificate_message *)(DATA.CATCH.last_ord_cert[sender] + 1);
    }

    if (stored != NULL && ord_cert->seq_num <= stored->seq_num) {
        Alarm(DEBUG, "Old ORD_Certificate from %u, seq = %u, stored = %u\n", 
            sender, ord_cert->seq_num, stored->seq_num);
            return;
    }

    if (ord_cert->type != SLOT_COMMIT) {
        Alarm(PRINT, "Non-Commit ordinal certificates (%u) are not allowed to be jumped to\n", 
                ord_cert->type);
        return;
    }

    /* Store the new ORD certificate */
    Alarm(DEBUG, "New ORD_Certificate!! sender = %u, seq_num = %u\n", sender, ord_cert->seq_num);
    if (DATA.CATCH.last_ord_cert[sender]) 
        dec_ref_cnt(DATA.CATCH.last_ord_cert[sender]);
    inc_ref_cnt(mess);
    DATA.CATCH.last_ord_cert[sender] = mess;

    /* If we are in fact behind, schedule a catchup (if not already) */
    if (DATA.ORD.ARU < ord_cert->seq_num) {
        Alarm(PRINT, "Scheduling in Process_ORD_Cert: mess from %d, ARU = %d\n", sender, ord_cert->seq_num);
        CATCH_Schedule_Catchup();
    }
#endif
}

void CATCH_Process_PO_Certificate(signed_message *mess)
{
    int32u sender, i, j;
    signed_message *po_req, *po_ack, *temp;
    po_certificate_message *po_cert;
    po_request_message *po_req_specific;
    po_ack_message *po_ack_specific;
    po_ack_part *part;
    po_slot *slot;
    po_seq_pair ps;
    sp_time t;
    byte *ptr, digest[DIGEST_SIZE];

    sender = mess->machine_id;
    po_cert = (po_certificate_message *)(mess + 1);

    /* Special case for storing my own PO Cert */
    if (sender == VAR.My_Server_ID) {
        slot = UTIL_Get_PO_Slot_If_Exists(po_cert->server, po_cert->seq);
        assert(slot);
        if (!slot->signed_po_cert) {
            slot->signed_po_cert = 1;
            dec_ref_cnt(slot->po_cert);
            slot->po_cert = mess;
            inc_ref_cnt(mess);
        }
        return;
    }

    if (PRE_ORDER_Seq_Compare(po_cert->seq, DATA.PO.cum_aru[po_cert->server]) <= 0) {
        Alarm(PRINT, "  PO Cert from %u. PO_Seq = %u @ [%u, %u]. OLD\n", sender, 
            po_cert->server, po_cert->seq.incarnation, po_cert->seq.seq_num);
        return;
    }
    
    Alarm(PRINT, "  PO Cert from %u. PO_Seq = %u @ [%u, %u]\n", sender, po_cert->server,
            po_cert->seq.incarnation, po_cert->seq.seq_num);

    /* Create the po_slot (if it doesn't already exist) and setup the
     * preinstalled vector snapshot */
    slot = UTIL_Get_PO_Slot(po_cert->server, po_cert->seq);
    if (slot->snapshot == 1)
        return;

    /* First, check if this update is actually indicating that the originating replica
     * has went through recovery with a higher incarnation. This is under the realization
     * that this certificate was validated and enough correct replicas have already
     * preinstalled this incarnation and ACKed the request */
    if (po_cert->seq.incarnation > DATA.PR.preinstalled_incarnations[po_cert->server] &&
        po_cert->seq.seq_num == 1) 
    {
        DATA.PR.preinstalled_incarnations[po_cert->server] = po_cert->seq.incarnation;
        ps.incarnation = po_cert->seq.incarnation;
        ps.seq_num = 0;
        DATA.PO.max_acked[po_cert->server] = ps;
        DATA.PO.aru[po_cert->server] = ps;
    }

    /* Clear out the po_slot (po_request + po_acks) that already exist, in order to make 
     * sure that the new po_acks coming in from the certificate can be placed in without
     * any issues. It is crucial that this po_cert is first validated, otherwise
     * we are erasing things that we would need. */

    /* Only clear out the po_request we have stored if it doesn't match the one that
     * is coming from the certificate */
    po_req = (signed_message *)(po_cert + 1);
    po_req_specific = (po_request_message *)(po_req + 1);
    if (slot->po_request != NULL) {
        OPENSSL_RSA_Make_Digest((byte *)po_req, UTIL_Message_Size(po_req), digest);
        if (!OPENSSL_RSA_Digests_Equal(digest, slot->po_request_digest)) {
            dec_ref_cnt(slot->po_request);
            slot->po_request = NULL;
            slot->num_events = 0;
            memset(slot->po_request_digest, 0, DIGEST_SIZE);
        }
    }

    /* Store the preinstall vector from the certificate as the snapshot for this slot in
     * order to correctly process the PO_Acks on this message. This assumes that
     * the PO_Cert validate function already made sure that all 2f+k+1 PO_Acks in this
     * message have matching preinstalled vectors to one another, so we can peek at the
     * first PO_Ack to grab the correct vector. */
    ptr = (byte *)(((byte *)po_req) + UTIL_Message_Size(po_req));
    po_ack = (signed_message *)ptr;
    po_ack_specific = (po_ack_message *)(po_ack + 1);
    memcpy(slot->preinstalled_snapshot+1, po_ack_specific->preinstalled_incarnations,
            sizeof(int32u) * VAR.Num_Servers);
    slot->snapshot = 1;

    /* Clear out the PO_Acks every time, since there is a good chance the preinstalled
     * vectors will not all work out with what you have stored before getting this cert */
    for (i = 1; i <= VAR.Num_Servers; i++) {
        if (slot->ack[i] != NULL) {
            dec_ref_cnt(slot->ack[i]);
            slot->ack[i] = NULL;
            slot->ack_part[i] = NULL;
            slot->ack_received[i] = 0;
        }
    }

    /* Process the PO Request */
    temp = UTIL_New_Signed_Message();
    memcpy(temp, po_req, UTIL_Message_Size(po_req));
    PROCESS_Message(temp);
    dec_ref_cnt(temp);

    /* Process the PO Ack Parts */
    ptr = (byte *)(((byte *)po_req) + UTIL_Message_Size(po_req));
    for (i = 1; i <= 2*VAR.F + VAR.K + 1; i++) {
        po_ack = (signed_message *)ptr;

        temp = UTIL_New_Signed_Message();
        memcpy(temp, po_ack, UTIL_Message_Size(po_ack));

        po_ack_specific = (po_ack_message *)(temp + 1);
        part = (po_ack_part *)(po_ack_specific + 1);
        
        for (j = 0; j < po_ack_specific->num_ack_parts; j++) {
            if (part[j].originator == po_req->machine_id && 
                (PRE_ORDER_Seq_Compare(part[j].seq, po_req_specific->seq) == 0))
            {
                PRE_ORDER_Process_PO_Ack_Part(&part[j], temp);
                break;
            }
        }

        dec_ref_cnt(temp);
        ptr += UTIL_Message_Size(po_ack);
    }

    if (!E_in_queue(CATCH_Attempt_Catchup, 0, NULL))
        return;
 
    if (DATA.CATCH.catchup_in_progress == 1) {
        t.sec  = CATCHUP_MOVEON_SEC; 
        t.usec = CATCHUP_MOVEON_USEC;
    }
    else {
        t.sec  = CATCHUP_PERIOD_SEC; 
        t.usec = CATCHUP_PERIOD_USEC;
    }
    E_queue(CATCH_Attempt_Catchup, 0, NULL, t);
}

void CATCH_Process_Catchup_Request(signed_message *mess)
{
    int32u i, j;
    int32u dest_bits, sender, window;
    catchup_request_message *c_request; //, *stored;
    po_seq_pair ps, *eligible_ptr, tmp_eligible[VAR.Num_Servers];
    sp_time now, t; //, diff_time;
    signed_message *jump;
    ord_slot *o_slot;
    po_slot *p_slot;

    sender = mess->machine_id;
    c_request = (catchup_request_message *)(mess + 1);
    if (sender == VAR.My_Server_ID)
        return;

    Alarm(DEBUG, "CATCH_Process_Catchup_Request from %d. Flag = %u. Their ARU = %u\n", 
            sender, c_request->flag, c_request->aru);

    dest_bits = 0;
    UTIL_Bitmap_Set(&dest_bits, sender);

    /* PRTODO: validate monotonic counter */

    /* Check if this request is more up to date than what I have stored so far */
    /* PRTODO: when we store a new incarnation from a replica, clear out their latest
     * stored catchup_request, rather than what we do here which only replaces the
     * old one when we get the new one? */
    if (OPENSSL_RSA_Digests_Equal(DATA.PR.proposal_digest, c_request->proposal_digest)) {
        if (DATA.CATCH.last_catchup_request[sender] != NULL) {
            if (CATCH_Compare_Catchup_Request(mess, DATA.CATCH.last_catchup_request[sender]) < 0) {
                // In this case, its old - don't do anything with it
                Alarm(PRINT, "OLD CReq from %d. [%d,%d]\n", sender, mess->incarnation, c_request->aru);
                return;
            }
            /* stored = (catchup_request_message *)(DATA.CATCH.last_catchup_request[sender] + 1);
            if (mess->incarnation <= (DATA.CATCH.last_catchup_request[sender])->incarnation && 
                c_request->aru < stored->aru) 
            {
                // In this case, its old - don't do anything with it
                Alarm(PRINT, "OLD CReq from %d. [%d,%d]\n", sender, mess->incarnation, c_request->aru);
                return;
            } */
            dec_ref_cnt(DATA.CATCH.last_catchup_request[sender]);
        }
        inc_ref_cnt(mess);
        DATA.CATCH.last_catchup_request[sender] = mess;
        Alarm(DEBUG, "Storing new CReq from %d. [%d,%d]\n", sender, mess->incarnation, c_request->aru);
    }

    /* If it hasn't been long enough to where I can help this replica,
     * queue up a function for later that will revisit helping this replica */
    now = E_get_time();
    if (E_compare_time(now, DATA.CATCH.next_catchup_time[sender]) <= 0) {
        Alarm(PRINT, "Process_Catchup_Request: Request too soon from %u\n", sender);
        return;
    }
    
    /* Check the proposal digest on the catchup request. If it doesn't match and the replica
     * is not undergoing a periodic recovery, then they are in the wrong global system
     * instantiation - send them a jump message with our digest to inform them. */
    if (!OPENSSL_RSA_Digests_Equal(DATA.PR.proposal_digest, c_request->proposal_digest) &&
        c_request->flag != FLAG_RECOVERY && DATA.PR.recovery_status[sender] != PR_RECOVERY) 
    {
        Alarm(PRINT, "CATCH_Process_Catchup_Request: Digest MISMATCH: Send Jump\n");
        jump = CATCH_Construct_Jump(c_request->nonce);
        SIG_Add_To_Pending_Messages(jump, dest_bits, UTIL_Get_Timeliness(JUMP));
        dec_ref_cnt(jump);
   
        /* Move up the time to next help this replica now that we know we're sending something */
        t.sec  = CATCHUP_PERIOD_SEC; 
        t.usec = CATCHUP_PERIOD_USEC;
        DATA.CATCH.next_catchup_time[sender] = E_add_time(now, t);
        return;
    }

    /* At this point, we know we have matching digests with the replica (or that replica is 
     * undergoing recovery) - let's see if we have knowledge that can help them */
    
    /* If I am no more up-to-date than the replica requesting, I can't help them */
    if (!CATCH_Can_Help_Catchup(mess)) {
        return;
    }

    /* If they are requesting catchup, and I SHOULD have been able to catch them up
     * because they are within the theoretical catchup history, but I personally
     * do not have the history, stay quiet. This gives another correct replica a chance
     * to catchup this replica normally. In the worst case, no one can help, and the
     * requesting replica will do a full cycle, then ask for a jump explicitly */
    (DATA.ORD.ARU < CATCHUP_HISTORY) ? (window = DATA.ORD.ARU) : (window = CATCHUP_HISTORY);
    if (c_request->flag == FLAG_CATCHUP && c_request->aru + 1 >= DATA.ORD.ARU - window && 
        c_request->aru + 1 < DATA.ORD.stable_catchup) 
    {
        Alarm(PRINT, "Missing Catchup History. cr->aru = %u, my_aru = %u, my_stable = %u\n",
                c_request->aru, DATA.ORD.ARU, DATA.ORD.stable_catchup);
        return;
    }

    /* OK - we are more up-to-date than this replica, so we can help them */
    /* Move up the time to next help this replica now that we know we're sending something */
    t.sec  = CATCHUP_PERIOD_SEC; 
    t.usec = CATCHUP_PERIOD_USEC;
    DATA.CATCH.next_catchup_time[sender] = E_add_time(now, t);

    /* Next, we will decide how to help the replica - Normal catchup, a jump,
     * recovery (jump + pending state) */

    /* If they are further behind than we can catch them up, we can 
     * send them a ordinal certificate to help them jump */
    if (c_request->flag == FLAG_JUMP || c_request->flag == FLAG_RECOVERY ||
        (c_request->flag == FLAG_PERIODIC && c_request->aru + 1 < DATA.ORD.stable_catchup) ||
        (DATA.ORD.ARU > CATCHUP_HISTORY && c_request->aru + 1 < DATA.ORD.ARU - CATCHUP_HISTORY))
        /* c_request->aru < DATA.ORD.stable_catchup ||
        (DATA.ORD.ARU > CATCHUP_HISTORY && c_request->aru < DATA.ORD.ARU - CATCHUP_HISTORY) ||
        (DATA.ORD.ARU == 0 && c_request->aru == 0)) */
    {
        Alarm(PRINT, "CATCH_Process_Catchup_Request: Send Jump Message here. My ARU = %u\n",
                DATA.ORD.ARU);

        jump = CATCH_Construct_Jump(c_request->nonce);
        SIG_Add_To_Pending_Messages(jump, dest_bits, UTIL_Get_Timeliness(JUMP));
        dec_ref_cnt(jump);

        if (DATA.PR.recovery_status[sender] == PR_RECOVERY) {
            Alarm(PRINT, "CATCH_Process_Catchup_Request: Sending PENDING Statement + Shares\n");
            PR_Send_Pending_State(sender, c_request->nonce);
        }
    }
    /* They are within my catchup window. I can help them with individual 
     * ORD / PO certificates to help them catch up */
    else {
        Alarm(PRINT, "CATCH_Process_Catchup_Request: Send CATCHUP from %u to %u for server=%d\n", 
                c_request->aru + 1, DATA.ORD.ARU,sender);

        /* I can catch them up to me, so send them everything between their
         * ARU and my ARU, excluding PO Certs that they already claim to have */
        for (i = c_request->aru + 1; i <= DATA.ORD.ARU; i++) {
    
            o_slot = UTIL_Get_ORD_Slot_If_Exists(i);
            assert(o_slot != NULL);

            if (o_slot->type != SLOT_COMMIT) {
                Alarm(PRINT, "CATCH_Process_Catchup_Request: no catchup on non-commit slots yet\n");
                return;
            }
 
            for (j = 0; j < VAR.Num_Servers; j++) {
                assert(PRE_ORDER_Seq_Compare(o_slot->made_eligible[j], 
                    o_slot->complete_pre_prepare.last_executed[j]) >= 0);

                if (o_slot->made_eligible[j].incarnation > 
                    o_slot->complete_pre_prepare.last_executed[j].incarnation) 
                {
                    ps.incarnation = o_slot->made_eligible[j].incarnation;
                    ps.seq_num = 0;
                }
                else {
                    ps = o_slot->complete_pre_prepare.last_executed[j];
                }
                ps.seq_num++;
                
                for (; ps.seq_num <= o_slot->made_eligible[j].seq_num; ps.seq_num++) {
                    
                    /* If the replica that is catching up already has this 
                     * po request pre-ordered, don't send it to them */
                    if (PRE_ORDER_Seq_Compare(c_request->po_aru[j], ps) >= 0)
                        continue;

                    p_slot = UTIL_Get_PO_Slot_If_Exists(j+1, ps);
                    assert(p_slot != NULL);

                    /* If there are more than one incarnation's po_requests here,
                     * perhaps due to recovery in between ordinals, only send
                     * po_certs from the latest incarnation. If the requests from
                     * the older incarnation are needed, a future catchup will help
                     * once they make it into the ordinal stream */
                    //assert(p_slot->po_cert != NULL);
                    if (!p_slot->signed_po_cert) {
                        assert(p_slot->po_cert != NULL);
                        dest_bits = 0;
                        UTIL_Bitmap_Set(&dest_bits, VAR.My_Server_ID);
                        UTIL_Bitmap_Set(&dest_bits, sender);
                        SIG_Add_To_Pending_Messages(p_slot->po_cert, dest_bits,
                                UTIL_Get_Timeliness(PO_CERT));
                    }
                    else {
                        // The PO Certificate is already signed, just send it */
                        UTIL_Send_To_Server(p_slot->po_cert, sender);
                    }
                }
            }

            // The ORD certificate is already signed, just send it */
            if (!o_slot->signed_ord_cert) {
                assert(o_slot->ord_certificate != NULL);
                dest_bits = 0;
                UTIL_Bitmap_Set(&dest_bits, VAR.My_Server_ID);
                UTIL_Bitmap_Set(&dest_bits, sender);
                SIG_Add_To_Pending_Messages(o_slot->ord_certificate, dest_bits,
                        UTIL_Get_Timeliness(ORD_CERT));
            }
            else {
                UTIL_Send_To_Server(o_slot->ord_certificate, sender);
            }
        }

        /* Send them the PO Certs that have yet to be made eligible but we've already
         * preordered that they don't yet claim to have */
        if (DATA.ORD.ARU > 0) {
            o_slot = UTIL_Get_ORD_Slot_If_Exists(DATA.ORD.ARU);
            assert(o_slot);
            eligible_ptr = (po_seq_pair *)o_slot->made_eligible;
        }
        else {
            memset(tmp_eligible, 0, sizeof(int32u) * VAR.Num_Servers);
            eligible_ptr = (po_seq_pair *)tmp_eligible;
        }

        for (i = 1; i <= VAR.Num_Servers; i++) {

            if ( (PRE_ORDER_Seq_Compare(c_request->po_aru[i-1], DATA.PO.cum_aru[i]) < 0) &&
                 (PRE_ORDER_Seq_Compare(eligible_ptr[i-1], DATA.PO.cum_aru[i] ) < 0) ) 
            {
                /* Start from max(their_aru, eligible) */
                if (PRE_ORDER_Seq_Compare(c_request->po_aru[i-1], eligible_ptr[i-1]) >= 0)
                    ps = c_request->po_aru[i-1];
                else
                    ps = eligible_ptr[i-1];

                /* If there are more than one incarnation's po_requests here,
                 * perhaps due to recovery in between ordinals, only send
                 * po_certs from the latest incarnation. If the requests from
                 * the older incarnation are needed, a future catchup will help
                 * once they make it into the ordinal stream */
                if (DATA.PO.cum_aru[i].incarnation > ps.incarnation) {
                    ps.incarnation = DATA.PO.cum_aru[i].incarnation;
                    ps.seq_num = 0;
                }
                ps.seq_num++;

                Alarm(PRINT, "  Sending to %d Unordered PO_Cert from %u. [%u,%u] to [%u,%u]\n",
                        sender,i, ps.incarnation, ps.seq_num, DATA.PO.cum_aru[i].incarnation,
                        DATA.PO.cum_aru[i].seq_num);
                for (; ps.seq_num <= DATA.PO.cum_aru[i].seq_num; ps.seq_num++) {
                    
                    p_slot = UTIL_Get_PO_Slot_If_Exists(i, ps);
                    assert(p_slot != NULL);

                    /* With the change of po_cert to use MT digest sigs, we may have
                     * some downtime between updating cum_aru and sig_finish_pending
                     * to process and store our own po cert for this slot. If this is
                     * the case, the po_cert we need should be in the SIG batch queue,
                     * so lets try to flush that and then see if we have it */
                    //assert(p_slot->po_cert != NULL);
                    if (!p_slot->signed_po_cert) {
                        assert(p_slot->po_cert != NULL);
                        dest_bits = 0;
                        UTIL_Bitmap_Set(&dest_bits, VAR.My_Server_ID);
                        UTIL_Bitmap_Set(&dest_bits, sender);
                        SIG_Add_To_Pending_Messages(p_slot->po_cert, dest_bits,
                                UTIL_Get_Timeliness(PO_CERT));
                    }
                    else {
                        // The PO Certificate is already signed, just send it */
                        UTIL_Send_To_Server(p_slot->po_cert, sender);
                    }
                }
            }
        }
    }

#if 0
    /* NEW: Only send one catchup reply at a time */ 
    for (i = c_request->aru + 1; i <= c_request->aru + 1; i++) {
        slot = UTIL_Get_ORD_Slot_If_Exists(i);
        assert(slot != NULL);

        c_reply = CATCH_Construct_Catchup_Reply(i, slot->type);
        c_reply_specific = (catchup_reply_message *)(c_reply + 1); 
        offset = ((char *)c_reply) + sizeof(signed_message) + 
                    sizeof(catchup_reply_message);
    
        /* Always send pre-prepares - TODO - resolve parts issue */
        size = UTIL_Message_Size(slot->pre_prepare_parts_msg[1]);
        memcpy(offset, slot->pre_prepare_parts_msg[1], size);
        c_reply->len += size;
        offset += size;

        /* If the slot is from a normal COMMIT certificiate, add 2f+k+1 commits */
        if (slot->type == SLOT_COMMIT) {
            /* Next, grab the 2f+k+1 commits */
            ccount = 0;
            for (j = 1; j <= VAR.Num_Servers && ccount < 2*VAR.F + VAR.K + 1; j++) {
                if (slot->commit_certificate.commit[j] == NULL)
                    continue;

                size = UTIL_Message_Size(slot->commit_certificate.commit[j]);
                memcpy(offset, slot->commit_certificate.commit[j], size);
                c_reply->len += size;
                offset += size;
                ccount++;
            }
            assert(ccount == 2*VAR.F + VAR.K + 1);
        }

        /* Now, update caught_up_seq and send this catchup_reply */
        DATA.CATCH.caught_up_seq[mess->machine_id] = i;
        SIG_Add_To_Pending_Messages(c_reply, dest_bits, UTIL_Get_Timeliness(CATCHUP_REPLY));
        dec_ref_cnt(c_reply);
    
        slot->reconciled = 0;
        RECON_Do_Recon(slot);
    }
#endif
}

void CATCH_Process_Jump(signed_message *mess)
{
    int32u sender;
    jump_message *jm;
    signed_message *oc;
    catchup_request_message *cr;
    ord_certificate_message *oc_specific, *stored_oc;

    /* PRTODO: Check incarnation and monotonic counter are checked */

    /* First, determine if we need to direct this message to the PR handler if 
     * we are currently in recovery mode */
    if (DATA.PR.recovery_status[VAR.My_Server_ID] == PR_RECOVERY &&
        DATA.PR.complete_recovery_state == 0) 
    {
        Alarm(PRINT, "JUMP message in RECOVERY\n");
        PR_Process_Jump(mess);
        return;
    }

    sender = mess->machine_id;
    jm = (jump_message *)(mess + 1);
    
    /* Check that this jump message matches my nonce challenge to know that it is
     * fresh, and not something replayed from the past */
    if (DATA.CATCH.sent_catchup_request[sender] == NULL) {
        Alarm(PRINT, "CATCH_Process_Jump: my stored catchup_request[%u] is NULL!\n", sender);
        return;
    }

    cr = (catchup_request_message *)(DATA.CATCH.sent_catchup_request[sender] + 1);

    /* If we are getting answers for our earlier recovery catchup requests, we already
     * finished the recovery by this point, just ignore them */
    if (cr->flag == FLAG_RECOVERY)
        return;

    /* Make sure that we are getting back valid nonce responses for our catchup requests */
    if (jm->acked_nonce != cr->nonce) {
        Alarm(PRINT, "CATCH_Process_Jump: from %u, jm->acked_nonce %u != my nonce %u\n",
                sender, jm->acked_nonce, cr->nonce);
        return;
    }

    /* Check if this jump message matches my digest. If not, count it towards the
     * total f+k+1 mismatches that once seeing will cause me to reset myself
     * in order to join the working system in a different "global incarnation" */
    if (!OPENSSL_RSA_Digests_Equal(DATA.PR.proposal_digest, jm->proposal_digest)) {
        if (DATA.PR.jump_mismatch[sender] != NULL)
            dec_ref_cnt(DATA.PR.jump_mismatch[sender]);
        else
            DATA.PR.jump_mismatch_count++;
        inc_ref_cnt(mess);
        DATA.PR.jump_mismatch[sender] = mess;

        if (DATA.PR.jump_mismatch_count >= VAR.F + VAR.K + 1) {
            Alarm(PRINT, "SYSTEM RESET WITHOUT ME: >= f+k+1 in different global incarnation\n");
            //PR_Send_Application_Reset();
            PR_Reset_Prime();
        }
        return;
    }

    /* Sanity Check - If you have a mismatch stored, but THIS message seemed valid 
     * by the digest, don't accept it from this replica until they recover or I
     * reset/recovery */
    if (DATA.PR.jump_mismatch[sender] != NULL) {
        Alarm(PRINT, "jump_mismatch stored for %u, valid msg this time, still dropping\n", sender);
        return;
    }

    /* Don't even process jump_messages that are not going to help */
    if (jm->seq_num <= DATA.ORD.ARU)
        return;

    oc = (signed_message *)(jm + 1);
    oc_specific = (ord_certificate_message *)(oc + 1);
   
    Alarm(PRINT, "CATCH_Process_Jump: from %u with global seq = %u\n", sender, oc_specific->seq_num);

    /* Calculate based on the jump message and your aru if you SHOULD actually be jumping,
     * or if this is potentially a malicious replica trying to cause you to jump */
    if (cr->flag != FLAG_JUMP && oc_specific->seq_num - DATA.ORD.ARU <= CATCHUP_HISTORY) {
        if (cr->flag == FLAG_CATCHUP) {
            Alarm(PRINT, "Process_Jump: I think I can catch up, ignoring jump. ARU = %u, cert = %u\n",
                DATA.ORD.ARU, oc_specific->seq_num);
            return;
        }
        else if (cr->flag == FLAG_PERIODIC) {

            if (DATA.CATCH.last_ord_cert[sender]) {
                stored_oc = (ord_certificate_message *)(DATA.CATCH.last_ord_cert[sender] + 1);
                if (oc_specific->seq_num <= stored_oc->seq_num)
                    return;
                dec_ref_cnt(DATA.CATCH.last_ord_cert[sender]);
            }
            
            Alarm(PRINT, "Process_Jump: Change from periodic to active catchup. ARU = %u, cert = %u\n",
                DATA.ORD.ARU, oc_specific->seq_num);
            
            DATA.CATCH.last_ord_cert[sender] = UTIL_New_Signed_Message();
            memcpy(DATA.CATCH.last_ord_cert[sender], oc, UTIL_Message_Size(oc));

            CATCH_Schedule_Catchup();

            return;
        }
    }

    /* if (DATA.CATCH.jumped_this_round == 0) {
        DATA.CATCH.jumped_this_round = 1;
    } */

    /* Do we want force_jump to only be set back to 0 when we have caught
     * up to what we know (which is what it is set to now), or should *any*
     * jump that makes progress count as clearing that flag? */

    /* Do we need to do anything about the NO_OP and PC_SET cases? */
    CATCH_Jump_Ahead(oc);

    /* Create a STATE_TRANSFER update, then process it (and eventually
     * send it), then cleanup memory */
    mess = PRE_ORDER_Construct_Update(CLIENT_STATE_TRANSFER);
    PROCESS_Message(mess);
    dec_ref_cnt(mess);

    /* If after the jump we are not behind, no need to keep doing catchup */
    /* if (max_ord <= DATA.ORD.ARU) {
        Alarm(PRINT, "End round because I jumped up to present ARU!\n");
        DATA.CATCH.catchup_in_progress = 0;
        DATA.CATCH.starting_catchup_id = 0;
        DATA.CATCH.next_catchup_id = 0;
        return;
    } */
}

#if 0
void CATCH_Process_Catchup_Reply(signed_message *mess)
{
    catchup_reply_message *c_reply;
    signed_message *pptr, *cptr;
    pre_prepare_message *pp, *stored_pp;
    commit_message *com;
    po_aru_signed_message *cum_acks;
    complete_pre_prepare_message complete_pp;
    commit_certificate_struct com_cert;
    int32u i, msize, sum_len, total_bytes, paru;
    int32u com_count, pp_count;
    ord_slot *slot;
    char *ptr;
    byte new_digest[DIGEST_SIZE], stored_digest[DIGEST_SIZE];

    Alarm(DEBUG, "CATCH_Process_Catchup_Reply from %d\n", mess->machine_id);
    
    c_reply = (catchup_reply_message *)(mess + 1);
    
    Alarm(PRINT, "  CATCHUP: got seq %d from %d\n", c_reply->seq_num, mess->machine_id);

    /* TODO - similar to process_catchup_request, this message type may need 
     * to be view agnostic */
    //if (c_reply->view != DATA.View)
    //    return;

    if (c_reply->seq_num <= DATA.ORD.ARU)
        return;

    ptr = (char *)mess;
    sum_len = sizeof(signed_message) + sizeof(catchup_reply_message);
    total_bytes = sizeof(signed_message) + mess->len;

    /* First, grab the pre-prepare and process it */
    pptr  = (signed_message *)(ptr + sum_len);
    pp    = (pre_prepare_message *)(pptr + 1);
    msize = UTIL_Message_Size(pptr);
    sum_len += msize;

    if (pptr->type != PRE_PREPARE) {
        Alarm(PRINT, "CATCH_Process_Catchup_Reply: Invalid message type, "
                "expected PRE-PREPARE\n");
        return;
    }

    if ((c_reply->type == SLOT_COMMIT || c_reply->type == SLOT_PC_SET) &&
            pp->seq_num != c_reply->seq_num ) 
    {
        Alarm(PRINT, "CATCH_Process_Catchup_Reply: pp seq num %d does not "
            " match c_reply %d\n", pp->seq_num, c_reply->seq_num);
        return;
    }
  
    if (c_reply->type == SLOT_NO_OP || c_reply->type == SLOT_NO_OP_PLUS || c_reply->type == SLOT_PC_SET) {
        /* In the case of NO_OPs, make sure to use the c_reply seq */
        slot = UTIL_Get_ORD_Slot(c_reply->seq_num);
        if (slot->pp_catchup_replies[mess->machine_id] != NULL)
            return;
        inc_ref_cnt(mess);
        slot->pp_catchup_replies[mess->machine_id] = mess;
    
        pp_count = 0;
        OPENSSL_RSA_Make_Digest((byte *)pp, sizeof(pre_prepare_message) +
                pp->num_acks_in_this_message * sizeof(po_aru_signed_message), 
                new_digest);

        for (i = 1; i <= VAR.Num_Servers; i++) {
            if (slot->pp_catchup_replies[i] == NULL)
                continue;

            stored_pp = (pre_prepare_message *)(((char*)slot->pp_catchup_replies[i]) +
                        sizeof(signed_message) + sizeof(catchup_reply_message) +
                        sizeof(signed_message));
            OPENSSL_RSA_Make_Digest((byte *)stored_pp, 
                    sizeof(pre_prepare_message) +
                    stored_pp->num_acks_in_this_message * 
                    sizeof(po_aru_signed_message), 
                    stored_digest);

            if (!OPENSSL_RSA_Digests_Equal(new_digest, stored_digest)) {
                Alarm(PRINT, "  New Digest from %d doesn't match stored "
                        " from %d\n", mess->machine_id, i);
                continue;
            }

            pp_count++;
        }

        if (pp_count != VAR.F + 1)
            return;
    }

    memset(&complete_pp, 0, sizeof(complete_pp));
    complete_pp.seq_num = pp->seq_num;              /* might not be correct for NO_OP */
    complete_pp.view = pp->view;
    memcpy((byte *)(&complete_pp.cum_acks),
            (byte *)(pp + 1), 
            sizeof(po_aru_signed_message) * pp->num_acks_in_this_message);    

    if (c_reply->type == SLOT_COMMIT) {
        /* Next, start grabbing the commits */
        memset(&com_cert, 0, sizeof(com_cert));
        com_count = 0;
        while (sum_len < total_bytes) {
            cptr    = (signed_message *)(ptr + sum_len);
            com     = (commit_message *)(cptr + 1);
            msize   = UTIL_Message_Size(cptr);

            /* Validate Commit Content */
            if (com->seq_num != complete_pp.seq_num) {
                Alarm(PRINT, "CATCH_Process_Catchup_Reply: Invalid commit seq %d "
                    "doesn't match %d\n", com->seq_num, complete_pp.seq_num);
                return;
            }
            if (com->view != complete_pp.view) {
                Alarm(PRINT, "CATCH_Process_Catchup_Reply: Invalid commit view %d "
                    "doesn't match %d\n", com->view, complete_pp.view);
                return;
            }
            if (!ORDER_Commit_Matches_Pre_Prepare(cptr, &complete_pp)) {
                Alarm(PRINT, "CATCH_Process_Catchup_Reply: Invalid commit digest "
                    "doesn't match PP digest\n", com->view, complete_pp.view);
                return;
            }
            if (com_cert.commit[cptr->machine_id] != NULL) {
                Alarm(PRINT, "CATCH_Process_Catchup_Reply: Already got commit for this "
                    "replica %d, bad msg!\n", cptr->machine_id);
                return;
            }
            
            /* Create memory for this commit and store */
            com_cert.commit[cptr->machine_id] = UTIL_New_Signed_Message();
            memcpy(com_cert.commit[cptr->machine_id], cptr, msize);
            
            com_count++;
            sum_len += msize;
        }

        if (com_count != 2*VAR.F + VAR.K + 1) {
            Alarm(PRINT, "CATCH_Process_Catchup_Reply: com_count is only %d, "
                " dropping this catchup message\n", com_count);
            return;
        }
    }

    /******************************************************
            Process the PO_ARUs in the PP
    *****************************************************/
    if (c_reply->type != SLOT_NO_OP) {
        cum_acks = (po_aru_signed_message *)complete_pp.cum_acks;

        /* If we know the leader now has received a PO request from a replica
         * that is greater than what we've sent, update our records so that
         * we don't think we are required to send a PO ARU with it - cause
         * no progress would actually be made if we did. */
        for(i = 1; i <= VAR.Num_Servers; i++) {
            paru = PRE_ORDER_Proof_ARU(i, cum_acks);
            if (paru > DATA.PO.max_num_sent_in_proof[i])
                DATA.PO.max_num_sent_in_proof[i] = paru;
        }

        /* Apply the PO-ARUs contained in the proof matrix, checking for
         *      any inconsistencies. NULL vectors checked in function */
        for(i = 0; i < VAR.Num_Servers; i++) {
            signed_message *m = (signed_message *)&cum_acks[i];
            PRE_ORDER_Process_PO_ARU(m);
        }
    }

    /******************************************************
            Handle Slots - Populate for this Seq Num
    *****************************************************/
    /* First, clean out anything old I have */
    slot = UTIL_Get_ORD_Slot_If_Exists(complete_pp.seq_num);
    if (slot != NULL) {
        ORDER_Garbage_Collect_ORD_Slot(slot, 1);
    }
    
    slot = UTIL_Get_ORD_Slot(complete_pp.seq_num);
    slot->view                         = complete_pp.view;
    slot->type                         = c_reply->type;
    slot->total_parts                  = pp->total_parts;
    slot->complete_pre_prepare.seq_num = slot->seq_num;
    slot->complete_pre_prepare.view    = slot->view;

    slot->pre_prepare_parts[1] = 1;
    slot->pre_prepare_parts_msg[1] = UTIL_New_Signed_Message();
    memcpy(slot->pre_prepare_parts_msg[1], pptr, UTIL_Message_Size(pptr));

    slot->num_parts_collected = slot->total_parts;
    slot->num_forwarded_parts = slot->total_parts;
    slot->collected_all_parts = 1;
    slot->ordered = 1;

    /* Copy over complete_pp and commit certificate into slot */
    memcpy(&slot->complete_pre_prepare, &complete_pp, sizeof(complete_pp));
    if (slot->type == SLOT_COMMIT)
        memcpy(&slot->commit_certificate, &com_cert, sizeof(com_cert));

    /* Execute the slot */
    ORDER_Execute_Commit(slot);
}
#endif

void CATCH_Send_Catchup_Request_Periodically(int dummy, void *dummyp)
{
    int32u id, dest_bits;
    sp_time t;
    //signed_message *request;

    id = DATA.CATCH.periodic_catchup_id;
    dest_bits = 0;
    UTIL_Bitmap_Set(&dest_bits, id);

    Alarm(DEBUG, "Send_Catchup_Periodically to %u. ARU = %u\n", id, DATA.ORD.ARU);

    if (DATA.CATCH.sent_catchup_request[id] != NULL)
        dec_ref_cnt(DATA.CATCH.sent_catchup_request[id]);

    DATA.CATCH.sent_catchup_request[id] = CATCH_Construct_Catchup_Request(FLAG_PERIODIC);
    SIG_Add_To_Pending_Messages(DATA.CATCH.sent_catchup_request[id], dest_bits,
            UTIL_Get_Timeliness(CATCHUP_REQUEST));

    CATCH_Advance_Catchup_ID(&DATA.CATCH.periodic_catchup_id); // advance periodic id 

    /* We are not advancing the next_catchup_time here, because that usually applies
     * to the next time we can do catchup with everyone all at once (like a catchup
     * round, or multicast catchup). In this case, we may have asked ONE replica 
     * too soon, but not all of them, so at most one correct replica won't be willing
     * to work with me */

    t.sec  = CATCHUP_REQUEST_PERIODICALLY_SEC;
    t.usec = CATCHUP_REQUEST_PERIODICALLY_USEC;
    E_queue(CATCH_Send_Catchup_Request_Periodically, 0, NULL, t);

    /* OLD MCAST METHOD */
    /* request = CATCH_Construct_Catchup_Request(FLAG_CATCHUP);

    for (i = 1; i <= VAR.Num_Servers; i++) {
        if (DATA.CATCH.sent_catchup_request[i] != NULL)
            dec_ref_cnt(DATA.CATCH.sent_catchup_request[i]);
        inc_ref_cnt(request);
        DATA.CATCH.sent_catchup_request[i] = request;
    }

    SIG_Add_To_Pending_Messages(request, BROADCAST, UTIL_Get_Timeliness(CATCHUP_REQUEST)); */
}

#if 0
void CATCH_Send_ORD_Cert_Periodically(int dummy, void *dummyp)
{
    sp_time t;

    if (DATA.CATCH.last_ord_cert[VAR.My_Server_ID] == NULL) {
        Alarm(PRINT, "CATCH_Send_ORD_Cert_Periodically: My last ord cert is NULL!\n");
        return;
    }
   
    UTIL_Broadcast(DATA.CATCH.last_ord_cert[VAR.My_Server_ID]);
    /* SIG_Add_To_Pending_Messages(DATA.CATCH.last_ord_cert[VAR.My_Server_ID], 
            BROADCAST, UTIL_Get_Timeliness(ORD_CERT)); */

    t.sec =  ORD_CERT_PERIODICALLY_SEC;
    t.usec = ORD_CERT_PERIODICALLY_USEC;
    E_queue(CATCH_Send_ORD_Cert_Periodically, 0, NULL, t);
}
#endif

void CATCH_Attempt_Catchup(int dummy, void *dummyp)
{
    int32u dest_bits, max_ord, target_replica, flag, i;
    ord_certificate_message *ord_cert;
    sp_time t, now;

    Alarm(PRINT, "CATCH_Attempt_Catchup: Top of function\n");

    /* (1) Checking against ordinal certificates received from other replicas:
     * Loop through all of the other replicas and find the one with the highest
     * valid ordinal certificate to compare against. If we find that we are more
     * than catchup history behind that, we should jump to the highest one */
    max_ord = 0;
    target_replica = 0;

    for (i = 1; i <= VAR.Num_Servers; i++) {

        /* Don't look at my own certificates */
        if (i == VAR.My_Server_ID) 
            continue;

        /* No Cert stored yet from this replica */
        if (DATA.CATCH.last_ord_cert[i] == NULL)
            continue;

        /* Cert stored from this replica is not more up to date than my own state */
        ord_cert = (ord_certificate_message *)(DATA.CATCH.last_ord_cert[i] + 1);
        if (DATA.ORD.ARU >= ord_cert->seq_num)
            continue;

        if (max_ord < ord_cert->seq_num) {
            max_ord = ord_cert->seq_num;
            target_replica = i;
        }
    }
    Alarm(DEBUG, "CATCH Loop: ARU = %d, max_ord = %d, target = %d\n", DATA.ORD.ARU, max_ord, target_replica);

    /* (2) Checking against highest commited (but not yet executed) ordinal */
    if (DATA.ORD.high_committed > DATA.ORD.ARU && DATA.ORD.high_committed > max_ord) {
        Alarm(PRINT, "CATCH_Attempt_Catchup. Catchup due to high_committed\n");
        max_ord = DATA.ORD.high_committed;
        target_replica = (VAR.My_Server_ID + 1) % VAR.Num_Servers;
        if (target_replica == 0) target_replica = VAR.Num_Servers;
    }

    /* (3) Checking if there are any view change report messages telling me to 
     * catchup that are higher than the max so far */
    if (DATA.CATCH.vc_catchup_target > DATA.ORD.ARU && DATA.CATCH.vc_catchup_target > max_ord) {
        Alarm(PRINT, "CATCH_Attempt_Catchup. Catchup due to VC report\n");
        max_ord = DATA.CATCH.vc_catchup_target;
        target_replica = DATA.CATCH.vc_catchup_source;
    }
    
    /* If after all checks we are not behind, no need to keep doing catchup this round */
    if (max_ord <= DATA.ORD.ARU) {
        Alarm(PRINT, "I'm not behind!\n");
        DATA.CATCH.catchup_in_progress = 0;
        DATA.CATCH.force_jump = 0;
        DATA.CATCH.starting_catchup_id = 0;
        DATA.CATCH.next_catchup_id = 0;
        return;
    }

    /* OK - we are behind in some capacity. Let's catchup */
    /* If this is the first time Attempting catchup this round,
     *  reset the state to calculate starting index, etc. */
    if (DATA.CATCH.catchup_in_progress == 0) {
        Alarm(PRINT, "New catchup round!\n");
        DATA.CATCH.catchup_in_progress = 1;
        //DATA.CATCH.jumped_this_round = 0;
        now    = E_get_time();
        t.sec  = CATCHUP_PERIOD_SEC; 
        t.usec = CATCHUP_PERIOD_USEC;
        DATA.CATCH.next_catchup_time[VAR.My_Server_ID] = E_add_time(now, t);
        DATA.CATCH.starting_catchup_id = target_replica;
        DATA.CATCH.next_catchup_id = target_replica;
        Alarm(PRINT, "CATCH_Attempt_Catchup. Start replica is %u\n", DATA.CATCH.starting_catchup_id);
    }

    /* We have the highest ordinal certificate sequence. Now see if we need to jump because
     * it is more than catchup history window size ahead */
    //if (max_ord > DATA.ORD.ARU && max_ord - DATA.ORD.ARU > CATCHUP_HISTORY) {
    if (DATA.CATCH.force_jump == 1 || max_ord - DATA.ORD.ARU > CATCHUP_HISTORY) {
        flag = FLAG_JUMP;
        Alarm(PRINT, "Create Catchup_Request: asking JUMP from %u\n", DATA.CATCH.next_catchup_id);
    }
    else {
        flag = FLAG_CATCHUP;
        Alarm(PRINT, "Create Catchup_Request: asking CATCHUP from %u\n", DATA.CATCH.next_catchup_id);
    }

    /* Still need to catchup, try the next replica in line. Generate a fresh
     * catchup request, send the request */
    Alarm(PRINT, "CATCH_Attempt_Catchup. Generate and send catchup_request message\n");
    dest_bits = 0;
    UTIL_Bitmap_Set(&dest_bits, DATA.CATCH.next_catchup_id);
    if (DATA.CATCH.sent_catchup_request[DATA.CATCH.next_catchup_id] != NULL)
        dec_ref_cnt(DATA.CATCH.sent_catchup_request[DATA.CATCH.next_catchup_id]);
    DATA.CATCH.sent_catchup_request[DATA.CATCH.next_catchup_id] = CATCH_Construct_Catchup_Request(flag);
    SIG_Add_To_Pending_Messages(DATA.CATCH.sent_catchup_request[DATA.CATCH.next_catchup_id], 
            dest_bits, UTIL_Get_Timeliness(CATCHUP_REQUEST));
    CATCH_Advance_Catchup_ID(&DATA.CATCH.next_catchup_id); // advance next_id and handle MOD case
    t.sec  = CATCHUP_REQUEST_PERIODICALLY_SEC;
    t.usec = CATCHUP_REQUEST_PERIODICALLY_USEC;
    E_queue(CATCH_Send_Catchup_Request_Periodically, 0, NULL, t); // push forward timer

    /* Push forward the timer to be a full catchup_period from now */
    now    = E_get_time();
    t.sec  = CATCHUP_PERIOD_SEC; 
    t.usec = CATCHUP_PERIOD_USEC;
    DATA.CATCH.next_catchup_time[VAR.My_Server_ID] = E_add_time(now, t);

    /* If we have cycled all the way around and tried catchup with everyone, stop this round */
    if (DATA.CATCH.next_catchup_id == DATA.CATCH.starting_catchup_id) {
        DATA.CATCH.catchup_in_progress = 0;
        DATA.CATCH.starting_catchup_id = 0;
        DATA.CATCH.next_catchup_id = 0;
        DATA.CATCH.force_jump = 1;
        Alarm(PRINT, "End round because I've tried all replicas!, reenqueue next full TO\n");
        E_queue(CATCH_Attempt_Catchup, 0, NULL, t);
        return;
    }   

    /* Re-enqueue this catchup function with short timer to try the next replica */
    t.sec  = CATCHUP_MOVEON_SEC; 
    t.usec = CATCHUP_MOVEON_USEC;
    E_queue(CATCH_Attempt_Catchup, 0, NULL, t);
}

void CATCH_Jump_Ahead(signed_message *mess)
{
    int32u i, view_updated;
    po_seq_pair ps, ps_key;
    stdit it;
    po_slot *p_slot;
    ord_slot *o_slot, *gc_slot;
    signed_message *pp, *commit;
    po_aru_signed_message *cum_acks;
    pre_prepare_message *pp_specific;
    complete_pre_prepare_message complete_pp;
    ord_certificate_message *ord_cert;
    commit_message *commit_specific;
    byte *ptr;
    sp_time zero_t = {0, 0};
    //sp_time t;

    //mess = DATA.CATCH.last_ord_cert[target_server];
    assert(mess != NULL);
    ord_cert = (ord_certificate_message *)(mess + 1);

    Alarm(PRINT, "Jumping ahead with replica %u, from %u to %u\n", 
                    mess->machine_id, DATA.ORD.ARU, ord_cert->seq_num);

    /* Advance the catchup id for next time */
    CATCH_Advance_Catchup_ID(&DATA.CATCH.next_catchup_id);

    /* Setup the pre-prepare pointers */
    pp  = (signed_message *)(((char *)mess) + sizeof(signed_message) + 
            sizeof(ord_certificate_message));
    pp_specific = (pre_prepare_message *)(pp + 1);

    /***********************************************************
            Perform the Jump, Start with ORD data structures
    ***********************************************************/

    /* First, cleanup any slots that are being jumped over, including the 
     *  one we are landing on. Also, cleanup any slots that have an old
     *  view compared to the certificate, as those slots (if higher) will have to
     *  be at least as high as the view in the certificate at this ordinal */
    stdhash_begin(&DATA.ORD.History, &it);
    while (!stdhash_is_end(&DATA.ORD.History, &it)) {
        o_slot = *(ord_slot **)stdit_val(&it);

        if (o_slot->seq_num > ord_cert->seq_num && o_slot->view >= ord_cert->seq_num) {
            stdit_next(&it);
            continue;
        }

        Alarm(DEBUG, "Jump: erasing ORD slot %u\n", o_slot->seq_num);
        ORDER_Garbage_Collect_ORD_Slot(o_slot, 0);
        stdhash_erase(&DATA.ORD.History, &it);
    }

    /* Update the view, ARU, and create the slot to bootstrap off of going forward */
    view_updated = 0;
    if (ord_cert->view > DATA.View) {
        view_updated = 1;
        DATA.View = ord_cert->view;
    }
    DATA.ORD.ARU = ord_cert->seq_num;

    /* Separate functions take care of this now */
    ORDER_Adjust_High_Committed();
    ORDER_Adjust_High_Prepared();
    ORDER_Adjust_ppARU();
    /* if (DATA.ORD.high_prepared < DATA.ORD.ARU)
        DATA.ORD.high_prepared = DATA.ORD.ARU;
    if (DATA.ORD.high_committed < DATA.ORD.ARU)
        DATA.ORD.high_committed = DATA.ORD.ARU;
    if (ord_cert->seq_num > DATA.ORD.ppARU)
        DATA.ORD.ppARU = ord_cert->seq_num; */
    if (DATA.ORD.stable_catchup < DATA.ORD.ARU)
        DATA.ORD.stable_catchup = DATA.ORD.ARU;

    o_slot = UTIL_Get_ORD_Slot(DATA.ORD.ARU);
    o_slot->view                         = ord_cert->view;
    o_slot->type                         = ord_cert->type;
    o_slot->total_parts                  = pp_specific->total_parts;

    o_slot->pre_prepare_parts[1] = 1;
    o_slot->pre_prepare_parts_msg[1] = UTIL_New_Signed_Message();
    memcpy(o_slot->pre_prepare_parts_msg[1], pp, UTIL_Message_Size(pp));

    o_slot->num_parts_collected = o_slot->total_parts;
    o_slot->num_forwarded_parts = o_slot->total_parts;
    o_slot->collected_all_parts = 1;
    o_slot->sent_prepare = 1;
    o_slot->sent_commit = 1;
    o_slot->ordered = 1;
    o_slot->executed = 1;
    o_slot->reconciled = 1;

    /* Setup temp complete_pp and then copy it into the slot version */
    memset(&complete_pp, 0, sizeof(complete_pp));
    complete_pp.seq_num = ord_cert->seq_num;
    complete_pp.view = ord_cert->view;
    memcpy((byte *)&complete_pp.last_executed, &pp_specific->last_executed, sizeof(pp_specific->last_executed));
    memcpy((byte *)&complete_pp.proposal_digest, &pp_specific->proposal_digest, DIGEST_SIZE);
    memcpy((byte *)(&complete_pp.cum_acks),
            (byte *)(pp_specific + 1), 
            sizeof(po_aru_signed_message) * pp_specific->num_acks_in_this_message);    
    memcpy(&o_slot->complete_pre_prepare, &complete_pp, sizeof(complete_pp));

    /* Setup preinstalled snapshot on the slot */
    ptr = (byte *)(((byte *)pp) + UTIL_Message_Size(pp));
    commit = (signed_message *)ptr;
    commit_specific = (commit_message *)(commit + 1);
    memcpy(o_slot->preinstalled_snapshot+1, commit_specific->preinstalled_incarnations, 
            sizeof(int32u) * VAR.Num_Servers);
    o_slot->snapshot = 1;

    /* Setup made_eligible to correctly calculate and enforce last_executed going forward */
    for (i = 0; i < VAR.Num_Servers; i++) {
        ps = PRE_ORDER_Proof_ARU(i+1, complete_pp.cum_acks);
        if (PRE_ORDER_Seq_Compare(ps, complete_pp.last_executed[i]) > 0) 
            o_slot->made_eligible[i] = ps;
        else 
            o_slot->made_eligible[i] = complete_pp.last_executed[i];
    }
    o_slot->populated_eligible = 1;
    
    /* TODO: Do we need to reconstruct and copy over each individual commit into our own
     *  unique certificate. Can borrow code from above */

    /* Take their ord certificate and repurpose it for ourselves */
    o_slot->ord_certificate = UTIL_New_Signed_Message();
    memcpy(o_slot->ord_certificate, mess, sizeof(signed_message) + mess->len);
    o_slot->ord_certificate->machine_id = VAR.My_Server_ID;
    o_slot->ord_certificate->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    memset(o_slot->ord_certificate->sig, 0, SIGNATURE_SIZE);
    //UTIL_RSA_Sign_Message(o_slot->ord_certificate);

    /* Store this as our latest cert, update flag for periodic,
    *    and start periodic sending (if not already) */
    /*
    if (DATA.CATCH.last_ord_cert[VAR.My_Server_ID] != NULL) {
        dec_ref_cnt(DATA.CATCH.last_ord_cert[VAR.My_Server_ID]);
    }
    DATA.CATCH.last_ord_cert[VAR.My_Server_ID] = UTIL_New_Signed_Message();
    memcpy(DATA.CATCH.last_ord_cert[VAR.My_Server_ID], o_slot->ord_certificate,
            sizeof(signed_message) + o_slot->ord_certificate->len);
    if (!E_in_queue(CATCH_Send_ORD_Cert_Periodically, 0, NULL)) {
        t.sec  = ORD_CERT_PERIODICALLY_SEC;
        t.usec = ORD_CERT_PERIODICALLY_USEC;
        E_queue(CATCH_Send_ORD_Cert_Periodically, 0, NULL, t);
    } */

    if (DATA.ORD.forwarding_white_line < DATA.ORD.ARU)
        DATA.ORD.forwarding_white_line = DATA.ORD.ARU;
    if (DATA.ORD.recon_white_line < DATA.ORD.ARU)
        DATA.ORD.recon_white_line = DATA.ORD.ARU;
    ORDER_Update_Forwarding_White_Line();
    RECON_Update_Recon_White_Line();

    /***********************************************************************
            Process the PO_ARUs in the PP, Update the PO data structures
    ***********************************************************************/
    cum_acks = (po_aru_signed_message *)complete_pp.cum_acks;

    /* If we know the leader now has received a PO request from a replica
     * that is greater than what we've sent, update our records so that
     * we don't think we are required to send a PO ARU with it - cause
     * no progress would actually be made if we did. 
     *
     * In addition, update the other PO data structures */
    for(i = 1; i <= VAR.Num_Servers; i++) {
        ps = o_slot->made_eligible[i-1];
        DATA.PO.max_num_sent_in_proof[i] = ps;
        if (PRE_ORDER_Seq_Compare(ps, DATA.PO.max_acked[i]) > 0)
            DATA.PO.max_acked[i] = ps;
        if (PRE_ORDER_Seq_Compare(ps, DATA.PO.aru[i]) > 0)
            DATA.PO.aru[i] = ps;
        if (PRE_ORDER_Seq_Compare(ps, DATA.PO.cum_aru[i]) > 0) {
            DATA.PO.cum_aru[i] = ps;
            DATA.PO.cum_aru_updated = 1;
        }

        if (PRE_ORDER_Seq_Compare(ps, DATA.PO.last_executed_po_reqs[i]) > 0) {
            if (ps.incarnation > DATA.PO.last_executed_po_reqs[i].incarnation &&
                ps.seq_num > 0)
            {
                if (DATA.PR.recovery_status[i] == PR_STARTUP) {
                    Alarm(PRINT, "STRANGE: Changing %u from STARTUP to NORMAL in catchup.\n", i);
                    DATA.PR.num_startup--;
                }
                if (DATA.PR.preinstalled_incarnations[i] <= ps.incarnation) {
                    DATA.PR.recovery_status[i] = PR_NORMAL;
                    Alarm(PRINT, "Setting %u to PR_NORMAL in Jump_Ahead\n", i);
                    DATA.PR.preinstalled_incarnations[i] = ps.incarnation;
                }
                DATA.PR.installed_incarnations[i] = ps.incarnation;
                if (i == VAR.My_Server_ID && 
                      DATA.PR.preinstalled_incarnations[i] == DATA.PR.installed_incarnations[i])
                {
                    Alarm(PRINT, "RESUME NORMAL from Jump_Ahead\n");
                    PR_Resume_Normal_Operation();
                    //PR_Resume_Normal_Operation(NO_RESET_APPLICATION);
                }
            }
            DATA.PO.last_executed_po_reqs[i] = ps;
        }

        /* Cleanup any Pending Execution slots for old (skipped) PO_Requests */
        stdhash_begin(&DATA.PO.Pending_Execution[i], &it);
        while (!stdhash_is_end(&DATA.PO.Pending_Execution[i], &it)) {
            ps_key = *(po_seq_pair *)stdit_key(&it);
            gc_slot = *(ord_slot **)stdit_val(&it);

            if (PRE_ORDER_Seq_Compare(ps_key, ps) > 0) {
                stdit_next(&it);
                continue;
            }

            Alarm(DEBUG, "Jump: erasing PO pending_slot [%u,%u,%u]\n", i, 
                    ps.incarnation, ps.seq_num);
            dec_ref_cnt(gc_slot);
            stdhash_erase(&DATA.PO.Pending_Execution[i], &it);
        }

        /* Cleanup any lingering PO slots that are now old (but never executed) */
        stdhash_begin(&DATA.PO.History[i], &it);
        while (!stdhash_is_end(&DATA.PO.History[i], &it)) {
            p_slot = *(po_slot **)stdit_val(&it);

            if (PRE_ORDER_Seq_Compare(p_slot->seq, ps) > 0) {
                stdit_next(&it);
                continue;
            }

            Alarm(DEBUG, "Jump: erasing PO slot [%u,%u,%u]\n", i, 
                    p_slot->seq.incarnation, p_slot->seq.seq_num);
            if (i == VAR.My_Server_ID && 
                 PRE_ORDER_Seq_Compare(DATA.PO.po_seq_executed, p_slot->seq) < 0)
            {
                DATA.PO.po_seq_executed = p_slot->seq;
            }
            PRE_ORDER_Garbage_Collect_PO_Slot(i, p_slot->seq, 0);
            stdhash_erase(&DATA.PO.History[i], &it);
        }

        if (PRE_ORDER_Seq_Compare(ps, DATA.PO.white_line[i]) > 0)
            DATA.PO.white_line[i] = ps;

        Alarm(DEBUG,"Catchup DATA.PO.white_line [%d]: inc=%lu, seq=%lu\n",i, DATA.PO.white_line[i].incarnation, DATA.PO.white_line[i].seq_num);
    }

    if (DATA.PO.po_seq.seq_num - DATA.PO.po_seq_executed.seq_num < MAX_PO_IN_FLIGHT) {
#if USE_IPC_CLIENT
        E_attach_fd(NET.from_client_sd, READ_FD, Net_Srv_Recv, IPC_SOURCE, NULL, MEDIUM_PRIORITY);
#else          
        E_attach_fd(NET.from_client_sd, READ_FD, Net_Srv_Recv, TCP_SOURCE, NULL, MEDIUM_PRIORITY);
#endif
    }

    /* Apply the PO-ARUs contained in the proof matrix, checking for
     *      any inconsistencies. NULL vectors checked in function */
    for(i = 0; i < VAR.Num_Servers; i++) {
        signed_message *m = (signed_message *)&cum_acks[i];
        PRE_ORDER_Process_PO_ARU(m);
    }

    /* Send out my updated PO ARU (this will also update my own vector that I
     * will use to send out my next matrix, which ensures forward progress iff
     * I happen to be the leader after jumping */
    PRE_ORDER_Send_PO_ARU();

    /* int32u j;
    printf("++++++++++ JUMPING to MATRIX ++++++++++\n");
    for (i = 0; i < VAR.Num_Servers; i++)
    {
      for (j = 0; j < VAR.Num_Servers; j++)
      {
          printf("(%u, %u) ", cum_acks[i].cum_ack.ack_for_server[j].incarnation, cum_acks[i].cum_ack.ack_for_server[j].seq_num);
      }
      printf("\n");
    } */
    /***********************************************************************
        Send any pending prepares 
    ***********************************************************************/

    ORDER_Send_Prepares();
    Alarm(PRINT, "Finished Send_Prepares after jump\n");

    /***********************************************************************
         Update the SUSP, RB, and VIEW data structs if we changed views
    ***********************************************************************/
    // In this case, we jumped from one view into a new one
    if (view_updated == 1) {
        SUSPECT_Initialize_Upon_View_Change();
        RB_Initialize_Upon_View_Change();
        VIEW_Initialize_Upon_View_Change();
        CATCH_Reset_View_Change_Catchup();
    }

    // In this case, we were in the middle of a view change when we jumped
    if (!DATA.VIEW.view_change_done) {
        // AND this is giving us missing ordinals from the previous view change
        if (ord_cert->view < DATA.View) {
        /* Moving up my ARU during a jump could be the last thing I need to do
         * to collect complete state for an ongoing view change */
            for (i = 1; i <= VAR.Num_Servers; i++) {
                VIEW_Check_Complete_State(i);
            }
        } 
        // OR this is jumping us out of the view change we were trying to do
        else {
        /* I jumped over the view change I was trying to do. Dequeue periodic
         * functions and reset to normal (non-view change) state */
            if (E_in_queue(SUSPECT_New_Leader_Periodically, 0, NULL))
                E_dequeue(SUSPECT_New_Leader_Periodically, 0, NULL);
            if (E_in_queue(SUSPECT_New_Leader_Proof_Periodically, 0, NULL))
                E_dequeue(SUSPECT_New_Leader_Proof_Periodically, 0, NULL);
            if (E_in_queue(RB_Periodic_Retrans, 0, NULL))
                E_dequeue(RB_Periodic_Retrans, 0, NULL);
            if (E_in_queue(VIEW_Periodic_Retrans, 0, NULL))
                E_dequeue(VIEW_Periodic_Retrans, 0, NULL);
            DATA.VIEW.view_change_done = 1;
            DATA.VIEW.executed_ord = 1;
            UTIL_Stopwatch_Stop(&DATA.VIEW.vc_stats_sw);
            UTIL_Stopwatch_Start(&DATA.ORD.leader_duration_sw);
        }
    }

    if (UTIL_I_Am_Leader() && DATA.VIEW.view_change_done == 1) {
        DATA.ORD.should_send_pp = 1; 
        DATA.ORD.seq = DATA.ORD.ARU + 1;
        Alarm(DEBUG, "I'm the Leader! View = %d\n", DATA.View);
        if (!E_in_queue(ORDER_Periodically, 0, NULL))
            E_queue(ORDER_Periodically, 0, NULL, zero_t);
    }

    Alarm(DEBUG, "  Finished Jumping to ARU = %u\n", DATA.ORD.ARU);
    ORDER_Attempt_To_Execute_Pending_Commits(0, 0);
}
   
void CATCH_Advance_Catchup_ID(int32u *id)
{
    *id = (*id + 1) % VAR.Num_Servers;
    if (*id == 0) *id = VAR.Num_Servers;

    if (*id == VAR.My_Server_ID) {
        *id = (*id + 1) % VAR.Num_Servers;
        if (*id == 0) *id = VAR.Num_Servers;
    }
}

/* Compares two catchup_request messages across both ORD aru and PO arus.
 *      if m1 < m2, return -1
 *      if m1 = m2, return  0
 *      if m1 > m2, return  1   */
int CATCH_Compare_Catchup_Request(signed_message *m1, signed_message *m2)
{
    int32u i, higher;
    catchup_request_message *cr1, *cr2;

    cr1 = (catchup_request_message *)(m1 + 1);
    cr2 = (catchup_request_message *)(m2 + 1);

    /* First check the incarnations on the signed_messge */
    if (m1->incarnation < m2->incarnation)
        return -1;
    else if (m1->incarnation > m2->incarnation)
        return 1;

    /* Next, check the ORD arus, which take precedence for progress */
    if (cr1->aru < cr2->aru)
        return -1;
    else if (cr1->aru > cr2->aru)
        return 1;

    /* If the ORD arus are equal, now check the PO arus.
     * NOTE: since these can be crafted from malicious replicas,
     * we COULD check for consistency by making sure no field in
     * the po_aru is going backwards while another is going 
     * forwards. For now, if even one entry is behind, consider the
     * whole catchup_request as older */
    higher = 0;
    for (i = 0; i < VAR.Num_Servers; i++) {
        if (PRE_ORDER_Seq_Compare(cr1->po_aru[i], cr2->po_aru[i]) < 0)
            return -1;
        if (PRE_ORDER_Seq_Compare(cr1->po_aru[i], cr2->po_aru[i]) > 0)
            higher = 1;
    }

    /* We delay returning 1 in the loop above to ensure that if even
     * one po_aru entry is lower, we get the chance to return -1 */
    if (higher == 1)
        return 1;

    /* Equal */
    return 0;
}

/* Returns 1 if I can help the replica with something, whether
 *      it be an ORD or PO cert. Returns 0 if they are at least
 *      as up to date as me across the board */
int CATCH_Can_Help_Catchup(signed_message *catchup_request)
{
    int32u i, sender;
    po_seq_pair *eligible_ptr, tmp_eligible[VAR.Num_Servers];
    ord_slot *slot;
    catchup_request_message *cr_specific;

    sender = catchup_request->machine_id;
    cr_specific = (catchup_request_message *)(catchup_request + 1);

    if (cr_specific->aru < DATA.ORD.ARU)
        return 1;
    else if (cr_specific->aru > DATA.ORD.ARU)
        return 0;

    /* Setup Comparison for PO aru. If our ORD aru == 0, there is no slot
     * available to compare against made_eligible, so we create a dummy
     * array filled with zeros */
    if (DATA.ORD.ARU > 0) {
        slot = UTIL_Get_ORD_Slot_If_Exists(DATA.ORD.ARU);
        assert(slot);
        eligible_ptr = (po_seq_pair *)slot->made_eligible;
    }
    else {
        memset(tmp_eligible, 0, sizeof(int32u) * VAR.Num_Servers);
        eligible_ptr = (po_seq_pair *)tmp_eligible;
    }

    for (i = 1; i <= VAR.Num_Servers; i++) {
        if ( (PRE_ORDER_Seq_Compare(cr_specific->po_aru[i-1], DATA.PO.cum_aru[i]) < 0) &&
             (PRE_ORDER_Seq_Compare(eligible_ptr[i-1], DATA.PO.cum_aru[i]) < 0) )
            return 1;
    }

    /* If I am equal to the catchup_requesting replica, but my ARU is 0 and that replica
     * is recovering, I can help them join an "empty" system (no progress yet) */
    if (DATA.ORD.ARU == 0 && DATA.PR.recovery_status[sender] == PR_RECOVERY)
        return 1;

    return 0;
}
