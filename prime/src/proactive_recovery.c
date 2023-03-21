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
 *   Amy Babay            babay@cs.jhu.edu
 *   Thomas Tantillo      tantillo@cs.jhu.edu
 *
 * Major Contributors:
 *   Brian Coan           Design of the Prime algorithm
 *   Jeff Seibert         View Change protocol
 *      
 * Copyright (c) 2008 - 2017
 * The Johns Hopkins University.
 * All rights reserved.
 * 
 * Partial funding for Prime research was provided by the Defense Advanced 
 * Research Projects Agency (DARPA) and the National Science Foundation (NSF).
 * Prime is not necessarily endorsed by DARPA or the NSF.  
 *
 */

#include <assert.h>
#include "spu_memory.h"
#include "spu_alarm.h"
#include "utility.h"
#include "signature.h"
#include "validate.h"
#include "process.h"
#include "network.h"
#include "pre_order.h"
#include "order.h"
#include "suspect_leader.h"
#include "view_change.h"
#include "proactive_recovery.h"

/* Global Variables */
extern network_variables    NET;
extern server_variables     VAR;
extern server_data_struct   DATA;

/* Local Functions */
void PR_Jump_Ahead();
void PR_Advance_Catchup_ID();

void PR_Initialize_Data_Structure(void)
{
    int32u i;
    sp_time now;

    /* Ensure that the Catchup History size is no greater than GC_LAG */
    assert(CATCHUP_HISTORY <= GC_LAG);

    DATA.PR.recovery_in_progress = 0;
    DATA.PR.catchup_target = 0;
    for (i = 1; i <= NUM_SERVERS; i++)
        DATA.PR.caught_up_seq[i] = 0;

    //PR_Catchup_Periodically(0, NULL);

    now = E_get_time();
    for (i = 1; i <= NUM_SERVERS; i++) {
        DATA.PR.last_ord_cert[i] = NULL;
        DATA.PR.next_catchup_time[i] = now;
    }

    DATA.PR.next_catchup_id = VAR.My_Server_ID;
    PR_Advance_Catchup_ID();
}

void PR_Process_Catchup_Request(signed_message *mess)
{
#if 0
    int32u i, j, size, ccount, dest_bits;
    catchup_request_message *c_request;
    signed_message *c_reply;
    catchup_reply_message *c_reply_specific;
    ord_slot *slot;
    char *offset;

    Alarm(PRINT, "PR_Process_Catchup_Request from %d\n", mess->machine_id);

    c_request = (catchup_request_message *)(mess + 1);
    dest_bits = 0;
    UTIL_Bitmap_Set(&dest_bits, mess->machine_id);

    if (mess->machine_id == VAR.My_Server_ID)
        return;

    /* Ignore this message if not in the same view - they can first catchup
     * to the current view before doing a catchup
     * TODO - this message type may need to be view agnostic */
    //if (c_request->view != DATA.View)
    //    return;

    /* If they are saying their ARU is below something that I already caught
     * them up on, ignore for now - TODO - perhaps at some point send them
     * the difference between caught_up_seq and MY_ARU - not sure if this
     * would help because then they legitimately would be still "missing"
     * those other messages between their aru and caught_up_seq */
    if (c_request->aru < DATA.PR.caught_up_seq[mess->machine_id]) {
        Alarm(PRINT, "PR_Process_Catchup_Request: replica %d claims ARU is %d, "
            "but I've already sent it through %d\n", mess->machine_id, 
            c_request->aru, DATA.PR.caught_up_seq[mess->machine_id]);
        //return;
    }

    /* If they are further behind than we can catch them up, they must
     * do some form of state transfer first, then I can help from there */
    if (DATA.ORD.ARU > GC_LAG && c_request->aru < DATA.ORD.ARU - GC_LAG) {
        Alarm(PRINT, "PR_Process_Catchup_Request: Server %d too far "
                "behind. Their ARU = %d, my oldest slot = %d\n",
                mess->machine_id, c_request->aru, DATA.ORD.ARU - GC_LAG);
        return;
    }

    /* I can catch them up to me, so send them everything */
    //for (i = c_request->aru + 1; i <= DATA.ORD.ARU; i++) {
    
    /* Only send a reply if we can actually catch them up */
    if (c_request->aru + 1 > DATA.ORD.ARU)
        return;
    
    /* NEW: Only send one catchup reply at a time */ 
    for (i = c_request->aru + 1; i <= c_request->aru + 1; i++) {
        slot = UTIL_Get_ORD_Slot_If_Exists(i);
        assert(slot != NULL);

        c_reply = PR_Construct_Catchup_Reply(i, slot->type);
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
            for (j = 1; j <= NUM_SERVERS && ccount < 2*VAR.F + VAR.K + 1; j++) {
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
        DATA.PR.caught_up_seq[mess->machine_id] = i;
        SIG_Add_To_Pending_Messages(c_reply, dest_bits, UTIL_Get_Timeliness(CATCHUP_REPLY));
        dec_ref_cnt(c_reply);
    
        slot->reconciled = 0;
        RECON_Do_Recon(slot);
    }
#endif
}

void PR_Process_ORD_Certificate(signed_message *mess)
{
    int32u sender;
    sp_time t, now, epsilon;
    ord_certificate_message *ord_cert, *stored;

    stored = NULL;
    sender = mess->machine_id;

    if (sender == VAR.My_Server_ID)
        return;

    ord_cert = (ord_certificate_message *)(mess + 1);

    /* TODO - make sure the ord_cert is validated before going forward */

    if (DATA.PR.last_ord_cert[sender]) {
        stored = (ord_certificate_message *)(DATA.PR.last_ord_cert[sender] + 1);
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
    if (DATA.PR.last_ord_cert[sender]) 
        dec_ref_cnt(DATA.PR.last_ord_cert[sender]);
    inc_ref_cnt(mess);
    DATA.PR.last_ord_cert[sender] = mess;

    /* If the Catchup event is already enqueued, I don't need to worry about
     * comparing the Ordinal number against my ARU, it will already be checked
     * at the next timeout of the event */
    if (E_in_queue(PR_Catchup_Periodically, 0, NULL))
        return;

    /* Otherwise, the event is not enqueued. Compare the sequence number (ARU)
     * on the certificate with my own to see if I'm behind. If so, delay the
     * catchup process by just a little bit to possibly allow the message that
     * I'm missing to make it to me */
    if (DATA.ORD.ARU < ord_cert->seq_num) {
        now = E_get_time();
        epsilon.sec  = PR_CATCHUP_EPSILON_SEC;
        epsilon.usec = PR_CATCHUP_EPSILON_USEC;
        if ((E_compare_time(DATA.PR.next_catchup_time[VAR.My_Server_ID], now) <= 0) ||
            (E_compare_time(E_sub_time(DATA.PR.next_catchup_time[VAR.My_Server_ID], now), epsilon) <= 0)) 
        {
            t = epsilon;
        }
        else {
            t = E_sub_time(DATA.PR.next_catchup_time[VAR.My_Server_ID], now);
        }
        E_queue(PR_Catchup_Periodically, 0, NULL, t);
        Alarm(DEBUG, "Enqueue PR_Catchup_Periodically\n");
    }
}

void PR_Process_PO_Certificate(signed_message *mess)
{

}

#if 0
void PR_Process_Catchup_Reply(signed_message *mess)
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

    Alarm(DEBUG, "PR_Process_Catchup_Reply from %d\n", mess->machine_id);
    
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
        Alarm(PRINT, "PR_Process_Catchup_Reply: Invalid message type, "
                "expected PRE-PREPARE\n");
        return;
    }

    if ((c_reply->type == SLOT_COMMIT || c_reply->type == SLOT_PC_SET) &&
            pp->seq_num != c_reply->seq_num ) 
    {
        Alarm(PRINT, "PR_Process_Catchup_Reply: pp seq num %d does not "
            " match c_reply %d\n", pp->seq_num, c_reply->seq_num);
        return;
    }
  
    if (c_reply->type == SLOT_NO_OP || c_reply->type == SLOT_PC_SET) {
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

        for (i = 1; i <= NUM_SERVERS; i++) {
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
                Alarm(PRINT, "PR_Process_Catchup_Reply: Invalid commit seq %d "
                    "doesn't match %d\n", com->seq_num, complete_pp.seq_num);
                return;
            }
            if (com->view != complete_pp.view) {
                Alarm(PRINT, "PR_Process_Catchup_Reply: Invalid commit view %d "
                    "doesn't match %d\n", com->view, complete_pp.view);
                return;
            }
            if (!ORDER_Commit_Matches_Pre_Prepare(cptr, &complete_pp)) {
                Alarm(PRINT, "PR_Process_Catchup_Reply: Invalid commit digest "
                    "doesn't match PP digest\n", com->view, complete_pp.view);
                return;
            }
            if (com_cert.commit[cptr->machine_id] != NULL) {
                Alarm(PRINT, "PR_Process_Catchup_Reply: Already got commit for this "
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
            Alarm(PRINT, "PR_Process_Catchup_Reply: com_count is only %d, "
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
        for(i = 1; i <= NUM_SERVERS; i++) {
            paru = PRE_ORDER_Proof_ARU(i, cum_acks);
            if (paru > DATA.PO.max_num_sent_in_proof[i])
                DATA.PO.max_num_sent_in_proof[i] = paru;
        }

        /* Apply the PO-ARUs contained in the proof matrix, checking for
         *      any inconsistencies. NULL vectors checked in function */
        for(i = 0; i < NUM_SERVERS; i++) {
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

void PR_Send_ORD_Cert_Periodically(int dummy, void *dummyp)
{
    sp_time t;

    if (DATA.PR.last_ord_cert[VAR.My_Server_ID] == NULL) {
        Alarm(PRINT, "PR_Send_ORD_Cert_Periodically: My last ord cert is NULL!\n");
        return;
    }
    
    SIG_Add_To_Pending_Messages(DATA.PR.last_ord_cert[VAR.My_Server_ID], 
            BROADCAST, UTIL_Get_Timeliness(ORD_CERT));

    t.sec =  ORD_CERT_PERIODICALLY_SEC;
    t.usec = ORD_CERT_PERIODICALLY_USEC;
    E_queue(PR_Send_ORD_Cert_Periodically, 0, NULL, t);
}

void PR_Catchup_Periodically(int dummy, void *dummyp)
{
    ord_certificate_message *ord_cert;
    signed_message *mess;
    sp_time t, now;
    int32u i, catchup;

    Alarm(DEBUG, "PR_Catchup_Periodically. Starting with %u\n", DATA.PR.next_catchup_id);

    /* Loop through the other replicas, starting with the current target,
     *      and see if you are behind. If you find a replica that can
     *      help you, either ask to be caught up or jump if too far
     *      behind. If you are not behind from anyone, then just leave
     *      the event */
    catchup = NO_CATCHUP;
    for (i = 1; (i <= NUM_SERVERS-1) && (catchup == NO_CATCHUP); i++) {

        /* No Cert stored yet from this replica */
        if (DATA.PR.last_ord_cert[DATA.PR.next_catchup_id] == NULL) {
            PR_Advance_Catchup_ID();
            continue;
        }

        /* Cert stored from this replica is not more up to date than my own state */
        ord_cert = (ord_certificate_message *)(DATA.PR.last_ord_cert[DATA.PR.next_catchup_id] + 1);
        if (DATA.ORD.ARU >= ord_cert->seq_num) {
            PR_Advance_Catchup_ID();
            continue;
        }

        /* OK, we need to catchup. Check if we are within the Catchup History widow, and
         *  can be caught up ordinal by ordinal, or if we are too far behind and instead
         *  must jump ahead (application state transfer should follow) */
        if (ord_cert->seq_num - DATA.ORD.ARU <= CATCHUP_HISTORY)
            catchup = CATCHUP_SEQ;
        else
            catchup = CATCHUP_JUMP;
    }

    /* Don't allow ourselves to try to catchup again until a full TO from now */
    now    = E_get_time();
    t.sec  = PR_CATCHUP_PERIOD_SEC; 
    t.usec = PR_CATCHUP_PERIOD_USEC;
    DATA.PR.next_catchup_time[VAR.My_Server_ID] = E_add_time(now, t);

    /* If we ran through the whole array of other replicas and we are not behind
     *  from anyone's perspective, then no need to catchup right now */
    if (catchup == NO_CATCHUP) {
        Alarm(DEBUG, "No catchup needed, ended at %u\n", DATA.PR.next_catchup_id);
        return;
    }

    /* If we are doing catchup, requeue this for next time to see if we made
     *  enough progress to fully catchup */
    E_queue(PR_Catchup_Periodically, 0, NULL, t);

    if (catchup == CATCHUP_SEQ) {
        Alarm(DEBUG, "\tCatchup!! Within Catchup_History window!\n");
        Alarm(DEBUG, "\tNot supported yet!!\n");
        /* signed_message *c_request;

        if (DATA.ORD.ARU >= DATA.PR.catchup_target) {
            DATA.PR.recovery_in_progress = 0;
            return;
        }
       
        Alarm(PRINT, "SEND catchup_request: my aru = %d, target = %d\n",
                DATA.ORD.ARU, DATA.PR.catchup_target);

        c_request = PR_Construct_Catchup_Request();
        SIG_Add_To_Pending_Messages(c_request, BROADCAST, UTIL_Get_Timeliness(CATCHUP_REQUEST));
        dec_ref_cnt(c_request); */

        /* t.sec =  PR_CATCHUP_SEC;
        t.usec = PR_CATCHUP_USEC;
        E_queue(PR_Catchup_Periodically, 0, NULL, t); */
    }
    else { /* catchup == CATCHUP_JUMP */
        Alarm(DEBUG, "\tCatchup!! Jumping Ahead!\n");

        // TODO - solve the NO_OP and PC_SET cases
        PR_Jump_Ahead();

        /* Create a STATE_TRANSFER update, then process it (and eventually
         * send it), then cleanup memory */
        mess = PRE_ORDER_Construct_Update(CLIENT_STATE_TRANSFER);
        PROCESS_Message(mess);
        dec_ref_cnt(mess);
    }
}

void PR_Jump_Ahead()
{
    int32u i, view_updated;
    po_seq_pair ps, ps_key;
    stdit it;
    po_slot *p_slot;
    ord_slot *o_slot;
    signed_message *mess, *pp;
    po_aru_signed_message *cum_acks;
    pre_prepare_message *pp_specific;
    complete_pre_prepare_message complete_pp;
    ord_certificate_message *ord_cert, *ord_specific;
    sp_time t;
    sp_time zero_t = {0, 0};

    mess = DATA.PR.last_ord_cert[DATA.PR.next_catchup_id];
    assert(mess != NULL);
    ord_cert = (ord_certificate_message *)(mess + 1);

    Alarm(PRINT, "Trying to catchup with replica %u, from %u to %u\n", 
                    DATA.PR.next_catchup_id, DATA.ORD.ARU, ord_cert->seq_num);

    /* Advance the catchup id for next time */
    PR_Advance_Catchup_ID();

    /* Setup the pre-prepare pointers */
    pp  = (signed_message *)(((char *)mess) + sizeof(signed_message) + 
            sizeof(ord_certificate_message));
    pp_specific = (pre_prepare_message *)(pp + 1);

    /***********************************************************
            Perform the Jump, Start with ORD data structures
    ***********************************************************/

    /* First, cleanup any slots that are being jumped over, including the 
     *  one we are landing on */
    stdhash_begin(&DATA.ORD.History, &it);
    while (!stdhash_is_end(&DATA.ORD.History, &it)) {
        o_slot = *(ord_slot **)stdit_val(&it);

        if (o_slot->seq_num > ord_cert->seq_num) {
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
    if (DATA.ORD.high_seq < DATA.ORD.ARU)
        DATA.ORD.high_seq = DATA.ORD.ARU;
    if (ord_cert->seq_num > DATA.ORD.ppARU)
        DATA.ORD.ppARU = ord_cert->seq_num;

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
    o_slot->ordered = 1;
    o_slot->executed = 1;
    o_slot->reconciled = 1;

    /* Setup temp complete_pp and then copy it into the slot version */
    memset(&complete_pp, 0, sizeof(complete_pp));
    complete_pp.seq_num = ord_cert->seq_num;
    complete_pp.view = ord_cert->view;
    memcpy((byte *)(&complete_pp.cum_acks),
            (byte *)(pp_specific + 1), 
            sizeof(po_aru_signed_message) * pp_specific->num_acks_in_this_message);    
    memcpy(&o_slot->complete_pre_prepare, &complete_pp, sizeof(complete_pp));

    /* TODO: Do we need to reconstruct and copy over each individual commit into our own
     *  unique certificate. Can borrow code from above */

    /* Take their ord certificate and repurpose it for ourselves */
    o_slot->ord_certificate = UTIL_New_Signed_Message();
    memcpy(o_slot->ord_certificate, mess, sizeof(signed_message) + mess->len);
    o_slot->ord_certificate->machine_id = VAR.My_Server_ID;
    ord_specific = (ord_certificate_message *)(o_slot->ord_certificate + 1);
    ord_specific->flag = CERT_CATCHUP;
    memset(o_slot->ord_certificate->sig, 0, SIGNATURE_SIZE);

    /* Store this as our latest cert, update flag for periodic,
    *    and start periodic sending (if not already) */
    if (DATA.PR.last_ord_cert[VAR.My_Server_ID] != NULL) {
        dec_ref_cnt(DATA.PR.last_ord_cert[VAR.My_Server_ID]);
    }
    DATA.PR.last_ord_cert[VAR.My_Server_ID] = UTIL_New_Signed_Message();
    memcpy(DATA.PR.last_ord_cert[VAR.My_Server_ID], o_slot->ord_certificate,
            sizeof(signed_message) + o_slot->ord_certificate->len);
    ord_specific = (ord_certificate_message *)(DATA.PR.last_ord_cert[VAR.My_Server_ID] + 1);
    ord_specific->flag = CERT_PERIODIC;
    if (!E_in_queue(PR_Send_ORD_Cert_Periodically, 0, NULL)) {
        t.sec  = ORD_CERT_PERIODICALLY_SEC;
        t.usec = ORD_CERT_PERIODICALLY_USEC;
        E_queue(PR_Send_ORD_Cert_Periodically, 0, NULL, t);
    }

    if (DATA.ORD.forwarding_white_line < DATA.ORD.ARU)
        DATA.ORD.forwarding_white_line = DATA.ORD.ARU;
    if (DATA.ORD.recon_white_line < DATA.ORD.ARU)
        DATA.ORD.recon_white_line = DATA.ORD.ARU;

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
    for(i = 1; i <= NUM_SERVERS; i++) {
        ps = PRE_ORDER_Proof_ARU(i, cum_acks);
        //if (PRE_ORDER_Seq_Compare(ps, DATA.PO.max_num_sent_in_proof[i]) > 0)
        DATA.PO.max_num_sent_in_proof[i] = ps;
        if (PRE_ORDER_Seq_Compare(ps, DATA.PO.max_acked[i]) > 0)
            DATA.PO.max_acked[i] = ps;
        if (PRE_ORDER_Seq_Compare(ps, DATA.PO.aru[i]) > 0)
            DATA.PO.aru[i] = ps;
        if (PRE_ORDER_Seq_Compare(ps, DATA.PO.cum_aru[i]) > 0) {
            DATA.PO.cum_aru[i] = ps;
            DATA.PO.cum_aru_updated = 1;
        }
        if (PRE_ORDER_Seq_Compare(ps, DATA.PO.last_executed_po_reqs[i]) > 0)
            DATA.PO.last_executed_po_reqs[i] = ps;

        /* Cleanup any Pending Execution slots for old (skipped) PO_Requests */
        stdhash_begin(&DATA.PO.Pending_Execution[i], &it);
        while (!stdhash_is_end(&DATA.PO.Pending_Execution[i], &it)) {
            ps_key = *(po_seq_pair *)stdit_key(&it);
            o_slot = *(ord_slot **)stdit_val(&it);

            if (PRE_ORDER_Seq_Compare(ps_key, ps) > 0) {
                stdit_next(&it);
                continue;
            }

            Alarm(DEBUG, "Jump: erasing PO pending_slot [%u,%u,%u]\n", i, 
                    ps.incarnation, ps.seq_num);
            dec_ref_cnt(o_slot);
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
        DATA.PO.white_line[i] = ps;
    }

    if (DATA.PO.po_seq.seq_num - DATA.PO.po_seq_executed.seq_num < MAX_PO_IN_FLIGHT) {
        //printf("Jump: Reattaching client sd\n");
#if USE_IPC_CLIENT
        E_attach_fd(NET.from_client_sd, READ_FD, Net_Srv_Recv, IPC_SOURCE, NULL, MEDIUM_PRIORITY);
#else          
        E_attach_fd(NET.from_client_sd, READ_FD, Net_Srv_Recv, TCP_SOURCE, NULL, MEDIUM_PRIORITY);
#endif
    }

    /* Apply the PO-ARUs contained in the proof matrix, checking for
     *      any inconsistencies. NULL vectors checked in function */
    for(i = 0; i < NUM_SERVERS; i++) {
        signed_message *m = (signed_message *)&cum_acks[i];
        PRE_ORDER_Process_PO_ARU(m);
    }

    /* Send out my updated PO ARU (this will also update my own vector that I
     * will use to send out my next matrix, which ensures forward progress iff
     * I happen to be the leader after jumping */
    PRE_ORDER_Send_PO_ARU();

    /* int32u j;
    printf("++++++++++ JUMPING to MATRIX ++++++++++\n");
    for (i = 0; i < NUM_SERVERS; i++)
    {
      for (j = 0; j < NUM_SERVERS; j++)
      {
          printf("(%u, %u) ", cum_acks[i].cum_ack.ack_for_server[j].incarnation, cum_acks[i].cum_ack.ack_for_server[j].seq_num);
      }
      printf("\n");
    } */
    /***********************************************************************
        Send any pending prepares 
    ***********************************************************************/

    ORDER_Send_Prepares();

    /***********************************************************************
         Update the SUSP, RB, and VIEW data structs if we changed views
    ***********************************************************************/
    if (view_updated == 1) {
        /*if (E_in_queue(SUSPECT_New_Leader_Periodically, 0, NULL))
            E_dequeue(SUSPECT_New_Leader_Periodically, 0, NULL);
        if (E_in_queue(SUSPECT_New_Leader_Proof_Periodically, 0, NULL))
            E_dequeue(SUSPECT_New_Leader_Proof_Periodically, 0, NULL);*/
        SUSPECT_Initialize_Upon_View_Change();
        
        RB_Initialize_Upon_View_Change();
        /*if (E_in_queue(RB_Periodic_Retrans, 0, NULL))
            E_dequeue(RB_Periodic_Retrans, 0, NULL);*/
        
        VIEW_Initialize_Upon_View_Change();
        /*if (E_in_queue(VIEW_Periodic_Retrans, 0, NULL))
            E_dequeue(VIEW_Periodic_Retrans, 0, NULL);
        DATA.VIEW.view_change_done = 1;
        DATA.VIEW.executed_ord = 1;*/
    }

    if (!DATA.VIEW.view_change_done) {
        if (ord_cert->view < DATA.View) {
        /* Moving up my ARU during a jump could be the last thing I need to do
         * to collect complete state for an ongoing view change */
            for (i = 1; i <= NUM_SERVERS; i++) {
                VIEW_Check_Complete_State(i);
            }
        } else {
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
        }
    }

    if (UTIL_I_Am_Leader()) {
        DATA.ORD.should_send_pp = 1; 
        DATA.ORD.seq = DATA.ORD.ARU + 1;
        Alarm(DEBUG, "I'm the Leader! View = %d\n", DATA.View);
        if (!E_in_queue(ORDER_Periodically, 0, NULL))
            E_queue(ORDER_Periodically, 0, NULL, zero_t);
    }

    Alarm(DEBUG, "  Finished Jumping to ARU = %u\n", DATA.ORD.ARU);
    ORDER_Attempt_To_Execute_Pending_Commits(0, 0);
}
   
void PR_Advance_Catchup_ID()
{
    DATA.PR.next_catchup_id = (DATA.PR.next_catchup_id + 1) % NUM_SERVERS;
    if (DATA.PR.next_catchup_id == 0) DATA.PR.next_catchup_id = NUM_SERVERS;

    if (DATA.PR.next_catchup_id == VAR.My_Server_ID) {
        DATA.PR.next_catchup_id = (DATA.PR.next_catchup_id + 1) % NUM_SERVERS;
        if (DATA.PR.next_catchup_id == 0) DATA.PR.next_catchup_id = NUM_SERVERS;
    }
}
