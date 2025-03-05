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
 *
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
#include "view_change.h"
#include "suspect_leader.h"
#include "reliable_broadcast.h"
#include "pre_order.h"
#include "order.h"
#include "tc_wrapper.h"
#include "catchup.h"

#include "spu_memory.h"
#include "spu_alarm.h"
#include "objects.h"

/* Global Variables */
extern server_variables     VAR;
extern server_data_struct   DATA;

/* Local Functions */
void VIEW_Clear_Data_Structures();
void VIEW_Try_Send_Replay_Prepare();
void VIEW_Try_Send_Replay_Commit();
void VIEW_Try_Execute_Replay();
void VIEW_Execute_Replay();

void VIEW_Initialize_Data_Structure()
{
    int32u i;

    /* Setup one-time initialization */
    for (i = 1; i <= VAR.Num_Servers; i++)
        stdskl_construct(&DATA.VIEW.pc_set[i], sizeof(int32u), 
            sizeof(signed_message *), intcmp);

    stdhash_construct(&DATA.VIEW.unique_vc_list, sizeof(int32u),
            sizeof(signed_message *), NULL, NULL, 0);

    stddll_construct(&DATA.VIEW.pending_vc_list, sizeof(signed_message *));

    stdhash_construct(&DATA.VIEW.unique_partial_sig, sizeof(int32u),
            sizeof(signed_message **), NULL, NULL, 0);
   
    VIEW_Initialize_Upon_View_Change();

    /* Special case for first view (no view change needed to start it) */
    DATA.VIEW.view_change_done = 1;
    DATA.VIEW.executed_ord = 1;
    UTIL_Stopwatch_Start(&DATA.ORD.leader_duration_sw);

}

void VIEW_Initialize_Upon_View_Change()
{
    int32u i;

    for (i = 1; i <= VAR.Num_Servers; i++) {
        DATA.VIEW.max_pc_seq[i] = 0;
    }
    
    VIEW_Clear_Data_Structures();

    for (i = 1; i < MAX_MESS_TYPE; i++) {
        DATA.VIEW.vc_stats_send_size[i] = 0;
        DATA.VIEW.vc_stats_send_count[i] = 0;
    }
    DATA.VIEW.vc_stats_sent_bytes = 0;
    DATA.VIEW.vc_stats_recv_bytes = 0;

    DATA.VIEW.view_change_done      = 0;
    DATA.VIEW.executed_ord          = 0;
    DATA.VIEW.numSeq                = 0;
    DATA.VIEW.complete_state        = 0;
    DATA.VIEW.replay_prepare_count  = 0;
    DATA.VIEW.replay_commit_count   = 0;
    DATA.VIEW.sent_replay_prepare   = 0;
    DATA.VIEW.sent_replay_commit    = 0;
    DATA.VIEW.executed_replay       = 0;
    DATA.VIEW.started_vc_measure    = 0;
    DATA.VIEW.done_vc_measure       = 0;
    
    UTIL_Stopwatch_Start(&DATA.VIEW.vc_stats_sw);
}

void VIEW_Clear_Data_Structures()
{
    int32u i;
    stdit it;
    signed_message *mess;
    signed_message **mess_arr;

    for (i = 1; i <= VAR.Num_Servers; i++) {
        if (DATA.VIEW.report[i] != NULL) {
            dec_ref_cnt(DATA.VIEW.report[i]);
            DATA.VIEW.report[i] = NULL;
        }

        for (stdskl_begin(&DATA.VIEW.pc_set[i], &it);
            !stdskl_is_end(&DATA.VIEW.pc_set[i], &it); stdit_next(&it))
        {
            mess = *(signed_message **)stdit_val(&it);
            dec_ref_cnt(mess);
        }
        stdskl_clear(&DATA.VIEW.pc_set[i]);
    }

    if (DATA.VIEW.my_vc_list) {
        dec_ref_cnt(DATA.VIEW.my_vc_list);
        DATA.VIEW.my_vc_list = NULL;
    }

    for (stdhash_begin(&DATA.VIEW.unique_vc_list, &it); 
        !stdhash_is_end(&DATA.VIEW.unique_vc_list, &it); stdit_next(&it))
    {
        mess = *(signed_message **)stdit_val(&it);
        dec_ref_cnt(mess);
    }
    stdhash_clear(&DATA.VIEW.unique_vc_list);

    for (stddll_begin(&DATA.VIEW.pending_vc_list, &it); 
        !stddll_is_end(&DATA.VIEW.pending_vc_list, &it); stdit_next(&it))
    {
        mess = *(signed_message **)stdit_val(&it);
        dec_ref_cnt(mess);
    }
    stddll_clear(&DATA.VIEW.pending_vc_list);

    for (stdhash_begin(&DATA.VIEW.unique_partial_sig, &it); 
        !stdhash_is_end(&DATA.VIEW.unique_partial_sig, &it); stdit_next(&it))
    {
        mess_arr = *(signed_message ***)stdit_val(&it);
        for (i = 1; i <= VAR.Num_Servers; i++) {
            if (mess_arr[i] != NULL)
                dec_ref_cnt(mess_arr[i]);
        }
        dec_ref_cnt(mess_arr);
    }
    stdhash_clear(&DATA.VIEW.unique_partial_sig);

    if (DATA.VIEW.replay != NULL) {
        dec_ref_cnt(DATA.VIEW.replay);
        DATA.VIEW.replay = NULL;
    }
    memset(DATA.VIEW.replay_digest, 0, DIGEST_SIZE);

    for (i = 1; i <= VAR.Num_Servers; i++) {
        if (DATA.VIEW.replay_prepare[i] != NULL) {
            dec_ref_cnt(DATA.VIEW.replay_prepare[i]);
            DATA.VIEW.replay_prepare[i] = NULL;
        }
        
        if (DATA.VIEW.replay_commit[i] != NULL) {
            dec_ref_cnt(DATA.VIEW.replay_commit[i]);
            DATA.VIEW.replay_commit[i] = NULL;
        }
    }
}

void VIEW_Upon_Reset()
{
    int32u i;

    VIEW_Clear_Data_Structures();

    for (i = 1; i <= VAR.Num_Servers; i++) {
        stdskl_destruct(&DATA.VIEW.pc_set[i]);
    }
    stdhash_destruct(&DATA.VIEW.unique_vc_list);
    stddll_destruct(&DATA.VIEW.pending_vc_list);
    stdhash_destruct(&DATA.VIEW.unique_partial_sig);
}

void VIEW_Periodic_Retrans(int d1, void *d2)
{
    signed_message **mess_arr;
    stdit it;
    sp_time t;

    if (DATA.VIEW.executed_ord == 1)
        return;

    /* If I have the replay, i can just retransmit the replay and any of
     * my own replay_prepare or replay_commits (since other VC messages
     * have been overtaken by this point) */
    if (DATA.VIEW.replay) {
        Alarm(PRINT, "VIEW: resending replay\n");
        UTIL_Broadcast(DATA.VIEW.replay);

        if (DATA.VIEW.replay_prepare[VAR.My_Server_ID])
            UTIL_Broadcast(DATA.VIEW.replay_prepare[VAR.My_Server_ID]);

        if (DATA.VIEW.replay_commit[VAR.My_Server_ID])
            UTIL_Broadcast(DATA.VIEW.replay_commit[VAR.My_Server_ID]);
    }
    /* Otherwise, send the VC list and VC partial sigs to try to generaet
     * a VC Proof to challenge the leader to give a replay response */
    else {
        if (DATA.VIEW.my_vc_list) {
            Alarm(PRINT, "VIEW: resending vc_list and partials\n");
            UTIL_Broadcast(DATA.VIEW.my_vc_list);
        }
        
        for (stdhash_begin(&DATA.VIEW.unique_partial_sig, &it); 
            !stdhash_is_end(&DATA.VIEW.unique_partial_sig, &it); stdit_next(&it))
        {
            mess_arr = *(signed_message ***)stdit_val(&it);
            if (mess_arr[VAR.My_Server_ID])
                UTIL_Broadcast(mess_arr[VAR.My_Server_ID]);
        }
    }

    t.sec  = RETRANS_PERIOD_SEC;
    t.usec = RETRANS_PERIOD_USEC;
    E_queue(VIEW_Periodic_Retrans, 0, NULL, t);
}

void VIEW_Start_View_Change()
{
    int32u i, j, size, pcount;
    ord_slot *slot;
    signed_message *pc, *report, *rb;
    pc_set_message *pc_specific;
    char *offset;
    stdit it;

    Alarm(DEBUG, "Starting view change to view %d\n", DATA.View);

    SUSPECT_Initialize_Upon_View_Change();
    SUSPECT_Restart_Timed_Functions();
    RB_Initialize_Upon_View_Change();
    RB_Periodic_Retrans(0, NULL);
    VIEW_Initialize_Upon_View_Change();
    VIEW_Periodic_Retrans(0, NULL);

    /* Go through slots that have been ordered (we have prepare certificate)
     *      but have not yet been executed (e.g. no PO request) */
    for (i = DATA.ORD.ARU + 1; i <= DATA.ORD.high_prepared; i++) {
        slot = UTIL_Get_ORD_Slot_If_Exists(i);
        if (slot == NULL)  /* Skipping gaps, maybe due to bad leader */
            continue;
        if (!slot->prepare_certificate_ready)
            continue;
        assert(slot->executed == 0);

        pc = VIEW_Construct_PC_Set();
        pc_specific = (pc_set_message *)(pc + 1);
        offset = ((char *)pc) + sizeof(signed_message) + sizeof(pc_set_message);
        
        /* First, grab the pre-prepare - TODO - resolve the parts issue*/
        size = UTIL_Message_Size(slot->pre_prepare_parts_msg[1]);
        memcpy(offset, slot->pre_prepare_parts_msg[1], size);
        pc->len += size;
        offset += size;

        /* Next, grab the 2f+k prepares */
        pcount = 0;
        for (j = 1; j <= VAR.Num_Servers && pcount < 2*VAR.F + VAR.K; j++) {
            if (slot->prepare_certificate.prepare[j] == NULL)
                continue;

            size = UTIL_Message_Size(slot->prepare_certificate.prepare[j]);
            memcpy(offset, slot->prepare_certificate.prepare[j], size);
            pc->len += size;
            offset += size;
            pcount++;
        }

        assert(pcount == 2*VAR.F + VAR.K);
        stdskl_insert(&DATA.VIEW.pc_set[VAR.My_Server_ID], &it, 
                &(pc_specific->rb_tag.seq_num), &pc, STDFALSE);
        DATA.VIEW.numSeq++;
    }

    /* Now that we've calculated our pc set, create the report, sign it
     *  for later forwarding, create the RB_INIT message, and send the whole
     *  thing wrapped up */
    report = VIEW_Construct_Report();
    UTIL_RSA_Sign_Message(report);

    rb = RB_Construct_Message(RB_INIT, report);
    SIG_Add_To_Pending_Messages(rb, BROADCAST, UTIL_Get_Timeliness(RB_INIT));

    dec_ref_cnt(rb);
    dec_ref_cnt(report);

    /* Next, send the pc_set messages that were created earlier. Pull them off
     *  from the DLL one at a time, sign it for later forwarding, then wrapping 
     *  them in a RB_INIT message which is signed and sent 
     *  TODO - Flow Control */
    stdskl_begin(&DATA.VIEW.pc_set[VAR.My_Server_ID], &it);
    while (!stdskl_is_end(&DATA.VIEW.pc_set[VAR.My_Server_ID], &it)) {
        pc = *(signed_message **)stdit_val(&it);
        UTIL_RSA_Sign_Message(pc);

        rb = RB_Construct_Message(RB_INIT, pc);
        SIG_Add_To_Pending_Messages(rb, BROADCAST, UTIL_Get_Timeliness(RB_INIT));

        dec_ref_cnt(rb);
        dec_ref_cnt(pc);
        stdskl_erase(&DATA.VIEW.pc_set[VAR.My_Server_ID], &it);
    }
    UTIL_Stopwatch_Stop(&DATA.VIEW.vc_sw);
    Alarm(DEBUG, "\t[SUSP to Report/PC_Set] = %f\n", UTIL_Stopwatch_Elapsed(&DATA.VIEW.vc_sw));
    Alarm(DEBUG, "\tAdded Report and PC_Set to Pending\n");
}

void VIEW_Process_Report(signed_message *mess)
{
    report_message *report;

    report = (report_message *)(mess + 1);

    /* Check the view of report message - must match */
    if (report->rb_tag.view != DATA.View) {
        Alarm(PRINT, "VIEW_Process_Report: report view (%d) != ours (%d)\n", 
                report->rb_tag.view, DATA.View); 
        return;
    }

    /* Check if we've already finished with the view change into this view */
    if (DATA.VIEW.view_change_done == 1) {
        Alarm(PRINT, "VIEW_Process_Report. From %d. Correct view (%d), but done with VC\n", 
                mess->machine_id, DATA.View);
        return;
    }

    /* Check sequence number of report message - must be 0 */
    if (report->rb_tag.seq_num != 0) {
        Alarm(PRINT, "VIEW_Process_Report: report seq_num != 0 (%d)\n", 
                report->rb_tag.seq_num); 
        return;
    }
 
    Alarm(PRINT, "VIEW_Process_Report: [id, view, seq, execARU, pc_set_size] = "
                " [%d, %d, %d, %d, %d]\n", report->rb_tag.machine_id,
                report->rb_tag.view, report->rb_tag.seq_num, report->execARU,
                report->pc_set_size);

    /* Since we are using the RB protocol and garbage collect only 
     *   at the start of the next view, there should be no duplicates */
    assert(DATA.VIEW.report[report->rb_tag.machine_id] == NULL);
    inc_ref_cnt(mess);
    DATA.VIEW.report[report->rb_tag.machine_id] = mess;
    if (report->execARU > DATA.VIEW.max_pc_seq[report->rb_tag.machine_id])
        DATA.VIEW.max_pc_seq[report->rb_tag.machine_id] = report->execARU;
   
    if (DATA.ORD.ARU < report->execARU) {

        Alarm(PRINT, "Schedule_Catchup from Report message in VC\n");
        CATCH_Schedule_Catchup();

        /* TODO - make sure we reset catchup_target to something we actually executed
        * through to prevent malicious from making it too high for later catchups */
        if (DATA.CATCH.vc_catchup_target < report->execARU) {
            DATA.CATCH.vc_catchup_target = report->execARU;
            DATA.CATCH.vc_catchup_source = report->rb_tag.machine_id;
        }
    }

    VIEW_Check_Complete_State(report->rb_tag.machine_id);
}

void VIEW_Process_PC_Set(signed_message *mess)
{
    pc_set_message *pc;
    stdit it;
    int32u seq, serv;
    signed_message *pp;
    pre_prepare_message *pp_specific;

    pc = (pc_set_message *)(mess + 1);

    /* Check the view of report message - must match */
    if (pc->rb_tag.view != DATA.View) {
        Alarm(PRINT, "VIEW_Process_PC_Set: pc_set view (%d) != ours (%d)\n", 
                pc->rb_tag.view, DATA.View); 
        return;
    }

    if (DATA.VIEW.view_change_done == 1) {
        Alarm(PRINT, "VIEW_Process_PC_Set. From %d. Correct view (%d), but done with VC\n", 
                mess->machine_id, DATA.View);
        return;
    }

    if (pc->rb_tag.seq_num == 0) {
        Alarm(PRINT, "VIEW_Process_PC_Set: pc seq_num == 0!\n");
        return;
    }

    Alarm(DEBUG, "VIEW_Process_PC_Set: [id, view, seq] = "
                " [%d, %d, %d]\n", pc->rb_tag.machine_id,
                pc->rb_tag.view, pc->rb_tag.seq_num);

    serv = pc->rb_tag.machine_id;
    seq  = pc->rb_tag.seq_num;

    /* Since we are using the RB protocol and garbage collect only 
     *   at the start of the next view, there should be no duplicates */
    stdskl_lowerb(&DATA.VIEW.pc_set[serv], &it, &seq);
    assert(stdskl_is_end(&DATA.VIEW.pc_set[serv], &it) || 
                intcmp(&seq, stdit_key(&it)) != 0);

    /* Store the pc_set message */
    inc_ref_cnt(mess);
    stdskl_insert(&DATA.VIEW.pc_set[serv], &it, &seq, &mess, STDTRUE);

    /* Check if the seq number of the pre-prepare corresponding to the
     *  prepare certificate in this pc_set message is the highest
     *  seen from this replica so far */
    pp          = (signed_message *)(pc + 1);
    pp_specific = (pre_prepare_message *)(pp + 1);
    if (pp_specific->seq_num > DATA.VIEW.max_pc_seq[serv])
        DATA.VIEW.max_pc_seq[serv] = pp_specific->seq_num;

    VIEW_Check_Complete_State(serv);
}

void VIEW_Check_Complete_State(int32u serv)
{
    report_message *report;
    signed_message *mess, *vc_list, *vc_psig;
    vc_list_message *vc_list_specific;
    stdit it;

    /* If we've already collected complete state from this server,
     *   quit early */
    if (UTIL_Bitmap_Is_Set(&DATA.VIEW.complete_state, serv))
        return;

    /* We have complete state from a server when:
     *  (1) we received that server's Report Message
     *  (2) we received all PC_Set messages from that server
     *  (3) our ARU is at least as up-to-date as their execARU */

    if (DATA.VIEW.report[serv] == NULL)
        return;

    report = (report_message *)(DATA.VIEW.report[serv] + 1); 
    if (report->pc_set_size != stdskl_size(&DATA.VIEW.pc_set[serv]))
        return;

    if (DATA.ORD.ARU < report->execARU)
        return;

    Alarm(DEBUG, "Complete State from %d\n", serv);
    UTIL_Stopwatch_Stop(&DATA.VIEW.vc_sw);
    Alarm(DEBUG, "\t[SUSP to CS %d] = %f\n", serv, UTIL_Stopwatch_Elapsed(&DATA.VIEW.vc_sw));
    UTIL_Bitmap_Set(&DATA.VIEW.complete_state, serv);

    /* Check if we now have complete state from 2f+k+1 servers for the first time, 
     *  and if so, generate and send a VC-List message */
    if (UTIL_Bitmap_Num_Bits_Set(&DATA.VIEW.complete_state) == 2*VAR.F + VAR.K + 1) {
        /* Create VC-List Message */
        vc_list = VIEW_Construct_VC_List();
        SIG_Add_To_Pending_Messages(vc_list, BROADCAST, UTIL_Get_Timeliness(VC_LIST));
        dec_ref_cnt(vc_list);
    }

    /* Check through the pending_vc_list and see if we now have complete state for
     *   any of them - if so, sending partial sig message and remove from pending */
    for (stddll_begin(&DATA.VIEW.pending_vc_list, &it); 
            !stddll_is_end(&DATA.VIEW.pending_vc_list, &it);)
    {
        mess = *(signed_message **)stdit_val(&it);
        vc_list_specific = (vc_list_message *)(mess + 1);

        /* If we have complete state for this vc_list set, send partial sig */
        if (UTIL_Bitmap_Is_Superset(&vc_list_specific->list, &DATA.VIEW.complete_state)) {
            /* Generate Partial Sig for this VC_List message */
            vc_psig = VIEW_Construct_VC_Partial_Sig(vc_list_specific->list);
            SIG_Add_To_Pending_Messages(vc_psig, BROADCAST, 
                    UTIL_Get_Timeliness(VC_PARTIAL_SIG));
            dec_ref_cnt(vc_psig);
            dec_ref_cnt(mess);
            stddll_erase(&DATA.VIEW.pending_vc_list, &it);
        } 
        else {
            stdit_next(&it);
        }
    }

    /* Check if we can make progress for Replay protocol */
    VIEW_Try_Send_Replay_Prepare();
    VIEW_Try_Execute_Replay();
}

void VIEW_Process_VC_List(signed_message *mess)
{
    vc_list_message        *vc_list;
    signed_message         *vc_psig;
    stdit it;
    
    Alarm(DEBUG, "VIEW_Process_VC_List from %d\n", mess->machine_id);

    vc_list = (vc_list_message *)(mess + 1);

    /* Check the view of report message - must match */
    if (vc_list->view != DATA.View) {
        Alarm(PRINT, "VIEW_Process_VC_List: vc_list view (%d) != ours (%d)\n", 
                vc_list->view, DATA.View); 
        return;
    }
    
    /* Check if we've already finished with the view change into this view */
    if (DATA.VIEW.view_change_done == 1) {
        Alarm(PRINT, "VIEW_Process_VC_List. From %d. Correct view (%d), but done with VC\n", 
                mess->machine_id, DATA.View);
        return;
    }

    /* Store my copy of vc_list that I sent out */
    if (mess->machine_id == VAR.My_Server_ID && DATA.VIEW.my_vc_list == NULL) {
        inc_ref_cnt(mess);
        DATA.VIEW.my_vc_list = mess;
    }

    /* Check if we've already received a copy of this VC_List message,
     *  with the matching list of replicas */
    stdhash_find(&DATA.VIEW.unique_vc_list, &it, &vc_list->list);
    if (!stdhash_is_end(&DATA.VIEW.unique_vc_list, &it))
        return;

    inc_ref_cnt(mess);
    stdhash_insert(&DATA.VIEW.unique_vc_list, &it, &vc_list->list, &mess);

    /* If we have complete state for this set, send partial sig */
    if (UTIL_Bitmap_Is_Superset(&vc_list->list, &DATA.VIEW.complete_state)) {
        /* Generate Partial Sig for this VC_List message */
        vc_psig = VIEW_Construct_VC_Partial_Sig(vc_list->list);
        SIG_Add_To_Pending_Messages(vc_psig, BROADCAST, UTIL_Get_Timeliness(VC_PARTIAL_SIG));
        dec_ref_cnt(vc_psig);
    } 
    /* Otherwise, we need to put this as a pending VC_List message that we will
     *      send a partial signature for later when we have complete state */
    else {
        inc_ref_cnt(mess);
        stddll_push_back(&DATA.VIEW.pending_vc_list, &mess);
    }
}

void VIEW_Process_VC_Partial_Sig(signed_message *mess)
{
    signed_message *stored, *vc_proof;
    signed_message **mess_arr;
    vc_partial_sig_message *v_psig, *stored_specific;
    stdit it;
    int32u i, count, dest_bits;

    v_psig = (vc_partial_sig_message *)(mess + 1);

    Alarm(DEBUG, "VIEW_Process_VC_Partial_Sig from %d: %d\n",
        mess->machine_id, v_psig->list);

    if (v_psig->view != DATA.View) {
        Alarm(PRINT, "VIEW_Process_VC_Partial_Sig: v_psig view (%d) != ours (%d)\n",
                v_psig->view, DATA.View);
        return;
    }
    
    /* Check if we've already finished with the view change into this view */
    if (DATA.VIEW.view_change_done == 1) {
        Alarm(PRINT, "VIEW_Process_Partial_Sig. From %d. Correct view (%d), but done with VC\n", 
                mess->machine_id, DATA.View);
        return;
    }

    /* Check if we've received any partial sig for this set of replicas
     *      yet, if not, create an entry */
    stdhash_find(&DATA.VIEW.unique_partial_sig, &it, &v_psig->list);
    if (stdhash_is_end(&DATA.VIEW.unique_partial_sig, &it)) {
        mess_arr = (signed_message **)new_ref_cnt(MSG_ARRAY_OBJ);
        memset(mess_arr, 0, sizeof(signed_message *) * MAX_NUM_SERVER_SLOTS);
        stdhash_insert(&DATA.VIEW.unique_partial_sig, &it, &v_psig->list, &mess_arr);
    }

    /* Check if we've already received a message for this list of replicas
     *      from the sender */
    mess_arr = *(signed_message ***)stdit_val(&it);
    if (mess_arr[mess->machine_id] != NULL)
        return;

    /* If not, store the message */
    inc_ref_cnt(mess);
    mess_arr[mess->machine_id] = mess;

    /* Now, check if we have 2f+k+1 matching partial sig messages for this list
     * We count how many stored partial sig messages have startSeq that
     * match the new message. We can do this because
     * clearly we don't have enough votes at this point yet, and only
     * this message can potentially hit the threshold at this time */
    count = 0;
    for (i = 1; i <= VAR.Num_Servers; i++) {
        if (mess_arr[i] == NULL)
            continue;

        stored = mess_arr[i];
        stored_specific = (vc_partial_sig_message *)(stored + 1);

        if (stored_specific->startSeq == v_psig->startSeq)
            count++;
    }

    if (count != 2*VAR.F + VAR.K + 1)
        return;

    /* We have exactly 2f+k+1 matching partial sigs for this set for the first
     *      time, so send a VC_Proof */
    vc_proof = VIEW_Construct_VC_Proof(v_psig->list, v_psig->startSeq, mess_arr);
    if (vc_proof == NULL)
        return;

    /* ASAP - We are now challenging the leader with the VC_Proof message, add this
     *  message to the challenge structure */
    if (DATA.VIEW.started_vc_measure == 0) {
        DATA.VIEW.started_vc_measure = 1;
        UTIL_Stopwatch_Start(&DATA.VIEW.vc_tat);
    }

    dest_bits = 0;
    UTIL_Bitmap_Set(&dest_bits, UTIL_Leader());
    SIG_Add_To_Pending_Messages(vc_proof, dest_bits, UTIL_Get_Timeliness(VC_PROOF));
    dec_ref_cnt(vc_proof);
}

void VIEW_Process_VC_Proof(signed_message *mess)
{
    vc_proof_message *vc_proof;
    replay_message *replay_specific;

    vc_proof = (vc_proof_message *)(mess + 1);

    Alarm(DEBUG, "VIEW_Process_VC_Proof from %d\n", mess->machine_id);

    /* Make sure that we only process VC_Proof messages if we're the next leader */
    if (!UTIL_I_Am_Leader()) {
        Alarm(PRINT, "VIEW_Process_VC_Proof: recv vc_proof but I'm not the "
                "leader - from replica %d\n", mess->machine_id);
        return;
    }

    /* Check the View on the message */
    if (vc_proof->view != DATA.View) {
        Alarm(PRINT, "VIEW_Process_VC_Proof: vc_proof view (%d) != ours (%d)\n",
                vc_proof->view, DATA.View);
        return;
    }
    
    /* Check if we've already finished with the view change into this view */
    if (DATA.VIEW.view_change_done == 1) {
        Alarm(PRINT, "VIEW_Process_VC_Proof. From %d. Correct view (%d), but done with VC\n", 
                mess->machine_id, DATA.View);
        return;
    }

    /* Check if we've already sent a replay for this view */
    if (DATA.VIEW.replay != NULL)
        return;

    /* Validate the threshold signature on the vc_proof message */
    /* Moved to validate.c */
    /*OPENSSL_RSA_Make_Digest(vc_proof, 3 * sizeof(int32u), digest);
    if (!TC_Verify_Signature(1, vc_proof->thresh_sig, digest)) {
        Alarm(PRINT, "VIEW_Process_VC_Proof: vc_proof threshold signature failed "
                "verification - from replica %d\n", mess->machine_id);
        return;
    }*/
    
    DATA.VIEW.replay = VIEW_Construct_Replay(vc_proof);
    replay_specific = (replay_message *)(DATA.VIEW.replay + 1);
    OPENSSL_RSA_Make_Digest(replay_specific, sizeof(replay_message), DATA.VIEW.replay_digest);
    SIG_Add_To_Pending_Messages(DATA.VIEW.replay, BROADCAST, UTIL_Get_Timeliness(REPLAY));
}

void VIEW_Process_Replay(signed_message *mess)
{
    replay_message *replay, *stored_replay;
    //byte digest[DIGEST_SIZE];

    replay = (replay_message *)(mess + 1);

    Alarm(DEBUG, "VIEW_Process_Replay from %d\n", mess->machine_id);

    /* We should only get Replays that originate from the leader */
    if (mess->machine_id != UTIL_Leader()) {
        Alarm(PRINT, "VIEW_Process_Replay: got replay from "
            "non-leader (%d), ignoring\n", mess->machine_id);
        return;
    }

    /* Check the View on the message */
    if (replay->view != DATA.View) {
        Alarm(PRINT, "VIEW_Process_Replay: replay view (%d) != ours (%d)\n",
                replay->view, DATA.View);
        return;
    }
    
    /* Check if we've already finished with the view change into this view */
    if (DATA.VIEW.view_change_done == 1) {
        Alarm(PRINT, "VIEW_Process_Replay. From %d. Correct view (%d), but done with VC\n", 
                mess->machine_id, DATA.View);
        return;
    }

    /* Validate the threshold signature on the replay message */
    /* Moved to validate.c */
    //OPENSSL_RSA_Make_Digest(replay, 3 * sizeof(int32u), digest);
    //if (!TC_Verify_Signature, 1, replay->thresh_sig, digest) {
    //    Alarm(PRINT, "VIEW_Process_Replay: replay threshold signature failed "
    //            "verification - from replica %d\n", mess->machine_id);
    //    return;
    //}

    /* If this is NOT the first replay we're getting this view_change, check
     *      a mismatch from a potentially malicious leader */
    if (DATA.VIEW.replay != NULL) {
        stored_replay = (replay_message *)(DATA.VIEW.replay + 1);
        if (stored_replay->list     != replay->list || 
            stored_replay->startSeq != replay->startSeq) 
        {
            Alarm(PRINT, "VIEW_Process_Replay: Leader (%d) is malicious - sent "
                    "two conflicting replay messages - blacklisting\n",
                    UTIL_Leader());
            //Blacklist(UTIL_Leader());
            UTIL_Broadcast(mess);
        }
        return;
    }

    /* Measure the TAT for this valid replay, only the first time though */
    if (DATA.VIEW.done_vc_measure == 0) {
        DATA.VIEW.done_vc_measure = 1;

        if (DATA.VIEW.started_vc_measure == 1) {
            UTIL_Stopwatch_Stop(&DATA.VIEW.vc_tat);
            if (UTIL_Stopwatch_Elapsed(&DATA.VIEW.vc_tat) > (10000/1000000.0)) {
                Alarm(DEBUG, "  ** > Thresh in VC: %f s\n", UTIL_Stopwatch_Elapsed(&DATA.VIEW.vc_tat));
            }
            if (DATA.SUSP.max_tat < UTIL_Stopwatch_Elapsed(&DATA.VIEW.vc_tat)) {
                DATA.SUSP.max_tat = UTIL_Stopwatch_Elapsed(&DATA.VIEW.vc_tat);
                DATA.SUSP.tat_max_change = 1;
            }
        }
        DATA.VIEW.started_vc_measure = 1;
    }

    inc_ref_cnt(mess);
    DATA.VIEW.replay = mess;
    OPENSSL_RSA_Make_Digest(replay, sizeof(replay_message), DATA.VIEW.replay_digest);
    UTIL_Broadcast(mess);

    /* Check if this replay was needed to make progress */
    VIEW_Try_Send_Replay_Prepare();
    VIEW_Try_Send_Replay_Commit();
    VIEW_Try_Execute_Replay();
}

void VIEW_Process_Replay_Prepare(signed_message *mess)
{
    replay_prepare_message *re_prepare;

    re_prepare = (replay_prepare_message *)(mess + 1);
    
    Alarm(DEBUG, "VIEW_Process_Replay_Prepare from %d\n", mess->machine_id);

    /* Check the View on the message */
    if (re_prepare->view != DATA.View) {
        Alarm(PRINT, "VIEW_Process_Replay_Prepare: re_prepare view (%d) != ours (%d)\n",
                re_prepare->view, DATA.View);
        return;
    }
 
    /* Make sure this is not from the new leader - should not count his
     *  messages twice - once for replay and once for replay prepare */
    if (mess->machine_id == UTIL_Leader())
        return;

    /* If we already have a replay prepare from this replica, return */
    if (DATA.VIEW.replay_prepare[mess->machine_id] != NULL)
        return;

    inc_ref_cnt(mess);
    DATA.VIEW.replay_prepare[mess->machine_id] = mess;
    DATA.VIEW.replay_prepare_count++;

    /* Check if we've already finished with the view change into this view */
    if (DATA.VIEW.view_change_done == 1) {
        Alarm(PRINT, "VIEW_Process_Replay_Prepare. From %d. Correct view (%d), but done with VC\n", 
                mess->machine_id, DATA.View);
        return;
    }

    /* Check if we can make progress */
    VIEW_Try_Send_Replay_Commit();
}

void VIEW_Process_Replay_Commit(signed_message *mess)
{
    replay_commit_message *re_commit;

    re_commit = (replay_commit_message *)(mess + 1);
    
    Alarm(DEBUG, "VIEW_Process_Replay_Commit from %d\n", mess->machine_id);

    /* Check the View on the message */
    if (re_commit->view != DATA.View) {
        Alarm(PRINT, "VIEW_Process_Replay_Commit: re_commit view (%d) != ours (%d)\n",
                re_commit->view, DATA.View);
        return;
    }
 
    /* If we already have a replay prepare from this replica, return */
    if (DATA.VIEW.replay_commit[mess->machine_id] != NULL)
        return;

    inc_ref_cnt(mess);
    DATA.VIEW.replay_commit[mess->machine_id] = mess;
    DATA.VIEW.replay_commit_count++;
   
    /* Check if we've already finished with the view change into this view */
    if (DATA.VIEW.view_change_done == 1) {
        Alarm(PRINT, "VIEW_Process_Replay_Commit. From %d. Correct view (%d), but done with VC\n", 
                mess->machine_id, DATA.View);
        return;
    }

    /* Check if we can make progress */
    VIEW_Try_Execute_Replay();
}

void VIEW_Try_Send_Replay_Prepare()
{
    replay_message *replay;
    signed_message *re_prepare;

    /* First, if we already sent the replay prepare, stop here */
    if (DATA.VIEW.sent_replay_prepare == 1)
        return;

    /* We need two things in order to send a Replay Prepare:
     *  (1) Replay Message
     *  (2) Complete state of the set in that replay message */
    
    if (DATA.VIEW.replay == NULL)
        return;
    
    UTIL_Stopwatch_Stop(&DATA.VIEW.vc_sw);
    Alarm(DEBUG, "\t[SUSP to SEND REPLAY PREP] = %f\n", UTIL_Stopwatch_Elapsed(&DATA.VIEW.vc_sw));

    replay = (replay_message *)(DATA.VIEW.replay + 1);
    if (UTIL_Bitmap_Is_Superset(&replay->list, &DATA.VIEW.complete_state)) {
        /* Generate Replay Prepare message */
        DATA.VIEW.sent_replay_prepare = 1;
        re_prepare = VIEW_Construct_Replay_Prepare();
        SIG_Add_To_Pending_Messages(re_prepare, BROADCAST, 
            UTIL_Get_Timeliness(REPLAY_PREPARE));
        dec_ref_cnt(re_prepare);
    }
}

void VIEW_Try_Send_Replay_Commit()
{
    signed_message         *re_commit;
    replay_prepare_message *stored_rp;
    int32u                  i, count;

    /* First, if we already sent the replay commit, stop here */
    if (DATA.VIEW.sent_replay_commit == 1)
        return;

    /* We need two things in order to send a Replay Commit:
     *  (1) Replay Message
     *  (2) at least 2f+k matching Replay Prepare messages (w/ Replay as well) */

    if (DATA.VIEW.replay == NULL || DATA.VIEW.replay_prepare_count < 2*VAR.F + VAR.K)
        return;

    /* If we have >= 2f+k matching replay prepares to the replay, send re_commit */
    count = 0;
    for (i = 1; i <= VAR.Num_Servers; i++) {
        if (DATA.VIEW.replay_prepare[i] == NULL)
            continue;

        stored_rp = (replay_prepare_message *)(DATA.VIEW.replay_prepare[i] + 1);
        if (OPENSSL_RSA_Digests_Equal(stored_rp->digest, DATA.VIEW.replay_digest))
            count++;
    }
    if (count >= 2*VAR.F + VAR.K) {
        re_commit = VIEW_Construct_Replay_Commit();
        DATA.VIEW.sent_replay_commit = 1;
        SIG_Add_To_Pending_Messages(re_commit, BROADCAST, UTIL_Get_Timeliness(REPLAY_COMMIT));
        dec_ref_cnt(re_commit);
    }
}

void VIEW_Try_Execute_Replay()
{
    replay_message        *replay;
    replay_commit_message *stored_rc;
    int32u                 i, count;

    if (DATA.VIEW.executed_replay == 1)
        return;

    /* We need three things in order to execute the Replay:
     *  (1) Replay Message
     *  (2) Complete state from all replicas in the replay message specified set
     *  (3) at least 2f+k+1 matching Replay Commit messages (w/ Replay as well) */

    if (DATA.VIEW.replay == NULL || DATA.VIEW.replay_commit_count < 2*VAR.F + VAR.K + 1)
        return;

    replay = (replay_message *)(DATA.VIEW.replay + 1);

    if (!UTIL_Bitmap_Is_Superset(&replay->list, &DATA.VIEW.complete_state))
        return;

    /* If we have >= 2f+k+1 matching replay commits to the replay, execute */
    count = 0;
    for (i = 1; i <= VAR.Num_Servers; i++) {
        if (DATA.VIEW.replay_commit[i] == NULL)
            continue;

        stored_rc = (replay_commit_message *)(DATA.VIEW.replay_commit[i] + 1);
        if (OPENSSL_RSA_Digests_Equal(stored_rc->digest, DATA.VIEW.replay_digest))
            count++;
    }

    if (count < 2*VAR.F + VAR.K + 1)
        return;

    UTIL_Stopwatch_Stop(&DATA.VIEW.vc_sw);
    Alarm(DEBUG, "\t[SUSP to EXEC] = %f\n", UTIL_Stopwatch_Elapsed(&DATA.VIEW.vc_sw));

    /* OK: We can now execute the replay */    
    Alarm(DEBUG, "VIEW_Try_Execute_Replay: READY TO EXECUTE REPLAY\n");
    DATA.VIEW.executed_replay = 1;
    VIEW_Execute_Replay();

    DATA.VIEW.view_change_done = 1;
    UTIL_Stopwatch_Start(&DATA.ORD.leader_duration_sw);

    /* Reset any stored catchup targets from report messages in this view change */
    CATCH_Reset_View_Change_Catchup();

    if (UTIL_I_Am_Leader()) {
        DATA.ORD.should_send_pp = 1;
        DATA.ORD.seq = replay->startSeq;
        Alarm(PRINT, "I'm the Leader! View = %d\n", DATA.View);
        //printf("replay start seq = %d\n", replay->startSeq);
        //for (i = 1; i <= VAR.Num_Servers; i++)
        //    DATA.PO.max_num_sent_in_proof[i] = 0;
        ORDER_Periodically(0, NULL);
    }
    Alarm(PRINT, "    Finished View Change - Now in View %d\n", DATA.View);

    //printf("---VC Packet Statistics---\n");
    UTIL_Stopwatch_Stop(&DATA.VIEW.vc_stats_sw);
    for (i = 1; i < MAX_MESS_TYPE; i++) {
        if (DATA.VIEW.vc_stats_send_count[i] > 0) {
            /* printf("    %s\tcount = %u, size = %u\n", UTIL_Type_To_String(i),
                    DATA.VIEW.vc_stats_send_count[i], DATA.VIEW.vc_stats_send_size[i]); */
        }
    }
    /* printf("Send BW in VC = %f Mbps. Bytes = %u, Duration = %f\n", 
        (DATA.VIEW.vc_stats_sent_bytes * 8.0 / 1000000) / 
        UTIL_Stopwatch_Elapsed(&DATA.VIEW.vc_stats_sw),
        DATA.VIEW.vc_stats_sent_bytes, UTIL_Stopwatch_Elapsed(&DATA.VIEW.vc_stats_sw));
    printf("Recv BW in VC = %f Mbps. Bytes = %u, Duration = %f\n", 
        (DATA.VIEW.vc_stats_recv_bytes * 8.0 / 1000000) / 
        UTIL_Stopwatch_Elapsed(&DATA.VIEW.vc_stats_sw),
        DATA.VIEW.vc_stats_recv_bytes, UTIL_Stopwatch_Elapsed(&DATA.VIEW.vc_stats_sw)); */
}

void VIEW_Execute_Replay() 
{
    stdhash full_pc_set;
    stdit it, hit;
    int32u i, j, peek;
    po_seq_pair ps, *prev_made_elig;
    signed_message *mess, *pptr, *prev_pp_part, *dummy_pp_part;
    pre_prepare_message *pp;
    complete_pre_prepare_message *complete_pp, *prev_pp;
    complete_pre_prepare_message dmy_pp;
    po_aru_signed_message *cum_acks;
    replay_message *rep;
    ord_slot *slot;

    assert(DATA.VIEW.replay != NULL);
    rep = (replay_message *)(DATA.VIEW.replay + 1);
    Alarm(DEBUG, "Executing replay: start seq == %d\n", rep->startSeq);

    stdhash_construct(&full_pc_set, sizeof(int32u), sizeof(signed_message *),
            NULL, NULL, 0);

    /* Merge the pc_set lists from each replica in Replay-specified set
     * into a single hash table (no duplicates) */
    for (i = 1; i <= VAR.Num_Servers; i++) {
        if (!UTIL_Bitmap_Is_Set(&rep->list, i))
            continue;

        for (stdskl_begin(&DATA.VIEW.pc_set[i], &it);
            !stdskl_is_end(&DATA.VIEW.pc_set[i], &it); stdit_next(&it))
        {
            Alarm(DEBUG, "Loop iteration i (inner loop): %d\n", i);
            mess = *(signed_message **)stdit_val(&it);
            pp = (pre_prepare_message *)(((char *)mess) + 
                sizeof(signed_message) + sizeof(pc_set_message) + 
                sizeof(signed_message));
            Alarm(DEBUG, "i: %d, seq_num: %d\n", i, pp->seq_num);
        
            if (stdhash_contains(&full_pc_set, &pp->seq_num))
                continue;

            Alarm(DEBUG, "Not already present i: %d, seq_num: %d\n", i, pp->seq_num);
            stdhash_insert(&full_pc_set, &hit, &pp->seq_num, &mess);
            Alarm(DEBUG, "Inserted i: %d, seq_num: %d\n", i, pp->seq_num);
        }
    }

    /* Clean out ALL ordering slots EXCEPT the last one we executed (since
     * the latest one is always required) and anything pending for execution.
     * This should be safe becuase this replica is already up-to-date
     * with execARU, and anything after that is covered by the PC set
     * messages (or No-Ops) from the Replay set */
    stdhash_begin(&DATA.ORD.History, &it); 
    while (!stdhash_is_end(&DATA.ORD.History, &it)) {
        slot = *(ord_slot **)stdit_val(&it);
        //if (slot->seq_num == DATA.ORD.ARU) {
        //if (((GC_LAG > DATA.ORD.ARU || slot->seq_num >= DATA.ORD.ARU - GC_LAG) && slot->seq_num <= DATA.ORD.ARU) 
        if ( (slot->seq_num >= DATA.ORD.stable_catchup && slot->seq_num <= DATA.ORD.ARU) || 
             (slot->seq_num >= rep->startSeq && slot->view >= DATA.View) )
        {
            stdit_next(&it);
            continue;
        }
        if (slot->seq_num < DATA.ORD.ARU) {
            Alarm(PRINT, "seq %d < DATA.ORD.ARU %d, fwl %d, rwl %d\n", slot->seq_num, DATA.ORD.ARU, DATA.ORD.forwarding_white_line, DATA.ORD.recon_white_line);
            //continue;
        }
        ORDER_Garbage_Collect_ORD_Slot(slot, 0);
        stdhash_erase(&DATA.ORD.History, &it);
    }

    /* Set up previous pre-prepare in case we need to copy it into no-ops. We
     * copy the pre-prepare from the previous ordinal into no-ops so that we
     * can still compare the matrix of the current pre-prepare to the previous
     * one to determine what has just become eligible for execution when the
     * previous ordinal was a no-op */
    dummy_pp_part = NULL;
    if (DATA.ORD.ARU == 0) {
        memset(&dmy_pp, 0, sizeof(complete_pre_prepare_message));
        prev_pp = &dmy_pp;

        dummy_pp_part = UTIL_New_Signed_Message();
        dummy_pp_part->type = PRE_PREPARE;
        dummy_pp_part->machine_id = VAR.My_Server_ID;

        pp = (pre_prepare_message *)(dummy_pp_part + 1);
        pp->seq_num = 0;
        pp->view = 0;
        pp->part_num = 1;
        pp->total_parts = 1;
        pp->num_acks_in_this_message = VAR.Num_Servers;
        memset(((char*)pp) + sizeof(pre_prepare_message), 0, 
                pp->num_acks_in_this_message * sizeof(po_aru_signed_message));
        
        dummy_pp_part->len = pp->num_acks_in_this_message * 
                                sizeof(po_aru_signed_message);
        prev_pp_part = dummy_pp_part;
        /* Here, we just need a po_seq_pair array of size VAR.Num_Servers
         * that is set to all zeros, so be borrow from last_executed */
        prev_made_elig = (po_seq_pair *)pp->last_executed;
    } else {
        slot = UTIL_Get_ORD_Slot_If_Exists(DATA.ORD.ARU);
        assert(slot != NULL);
        prev_pp = &slot->complete_pre_prepare;
        prev_pp_part = slot->pre_prepare_parts_msg[1];
        prev_made_elig = (po_seq_pair *)slot->made_eligible;
    }

    /* Iterate from execARU to startSeq - 1, creating ordering slots.
     * Look up this Pre-Prepare sequence in the hash table we just
     * generated. If there is a match, fill in this slot with the
     * Pre-prepare and other information. If not, set it as a no-op.
     * After each slot, Execute_Commit it - which means it will either
     * get executed (if we have the PO info) or will be marked as pending.
     * As soon as we finish going through this, view change is done.
     * Roll back ppARU to work for the Execute_Commit on slots */
    DATA.ORD.ppARU = DATA.ORD.ARU;
    for (i = DATA.ORD.ARU + 1; i < rep->startSeq; i++) {
        
        slot = UTIL_Get_ORD_Slot(i);
        stdhash_find(&full_pc_set, &it, &i);
        Alarm(PRINT, "Processing slot: %d, startSeq: %d\n", slot->seq_num, rep->startSeq);

        /* Make it look like we're done with this slot so that garbage
         * collection will happen correctly */
        slot->reconciled = 1;
        slot->pre_prepare_parts[1] = 1;
        slot->pre_prepare_parts_msg[1] = UTIL_New_Signed_Message();

        /* If no match found, this is the No-Op case */
        if (stdhash_is_end(&full_pc_set, &it)) {
            slot->type = SLOT_NO_OP;

            /* setup complete_pp */
            /* first, copy in the previous one */
            memcpy(&slot->complete_pre_prepare, prev_pp, 
                sizeof(complete_pre_prepare_message));

            /* Adjust the seq_num, and make last_executed equal to the 
             * previous slot's made_eligible to indicate no_op */
            slot->complete_pre_prepare.seq_num = slot->seq_num;
            memcpy(&slot->complete_pre_prepare.last_executed, prev_made_elig, 
                sizeof(slot->complete_pre_prepare.last_executed));
            slot->total_parts = 1; 
            slot->num_forwarded_parts = slot->total_parts;

            memcpy(slot->pre_prepare_parts_msg[1], prev_pp_part, 
                    UTIL_Message_Size(prev_pp_part));
            slot->collected_all_parts = 1;
        } else {
            /* Otherwise, We have the PC, populate the slot */
            mess = *(signed_message **)stdit_val(&it);
            pptr = (signed_message *)(((char *)mess) +
                  sizeof(signed_message) + sizeof(pc_set_message));
            pp = (pre_prepare_message *)(pptr + 1);

            slot->type = SLOT_PC_SET;
            slot->view = pp->view;
            slot->total_parts = pp->total_parts;
            slot->num_forwarded_parts = slot->total_parts;
            slot->complete_pre_prepare.seq_num = slot->seq_num;
            slot->complete_pre_prepare.view = slot->view;

            /* Copy in the last_executed and proposal_digest */
            memcpy((byte *)slot->complete_pre_prepare.last_executed, 
                    &pp->last_executed, sizeof(pp->last_executed));
            memcpy((byte *)&slot->complete_pre_prepare.proposal_digest, 
                    &pp->proposal_digest, DIGEST_SIZE);

            /* NOTE: skipping storing the part, not incrementing the
             * reference count, assuming large messages with 1 part
             * for now. If we use multiple parts, we need to copy
             * them over one by one, and make sure we collect all parts. */
            memcpy((byte *)slot->complete_pre_prepare.cum_acks, 
                (byte *)(pp + 1), sizeof(po_aru_signed_message) * 
                pp->num_acks_in_this_message);
            
            memcpy(slot->pre_prepare_parts_msg[1], pptr, UTIL_Message_Size(pptr));
            slot->collected_all_parts = 1;
            
            /* Setup pointers for PO_ARU comparison */
            complete_pp = (complete_pre_prepare_message *)&slot->complete_pre_prepare;
            cum_acks = (po_aru_signed_message *)complete_pp->cum_acks;

            /* If we know the leader now has received a PO request from a replica
             * that is greater than what we've sent, update our records so that
             * we don't think we are required to send a PO ARU with it - cause
             * no progress would actually be made if we did. */
            for (j = 1; j <= VAR.Num_Servers; j++) {
                ps = PRE_ORDER_Proof_ARU(j, cum_acks);
                if (PRE_ORDER_Seq_Compare(ps, DATA.PO.max_num_sent_in_proof[j]) > 0)
                    DATA.PO.max_num_sent_in_proof[j] = ps;
            }

            /* Apply the PO-ARUs contained in the proof matrix, checking for
             *   any inconsistencies. NULL vectors checked in function */
            for (j = 0; j < VAR.Num_Servers; j++) {
                signed_message *m = (signed_message *)&cum_acks[j];
                PRE_ORDER_Process_PO_ARU(m);
            }
        }
        ORDER_Update_Forwarding_White_Line();
        RECON_Update_Recon_White_Line();

        /* NEW: setup the made_eligible for the slot */
        /* This first case is the exception, where this slot is a NO_OP and the
         * next slot is a PC_SET message. Since that PC_Set message was created 
         * with the impression that this slot would be ordered/executed, the
         * next slot's Pre-Prepare will have a last_executed that potentially does
         * not match the made_eligible vector that we were copying across NO_OP
         * slots. We need to peek ahead to grab that PC_Set's last_executed and
         * make it this slot's made_eligible. Since this "NO_OP" is actually
         * making things eligible, we call it a NO_OP_PLUS slot */
        peek = i+1; 
        if (slot->type == SLOT_NO_OP && peek < rep->startSeq &&
            !stdhash_is_end(&full_pc_set, stdhash_find(&full_pc_set, &it, &peek)))
        {
            slot->type = SLOT_NO_OP_PLUS;

            mess = *(signed_message **)stdit_val(&it);
            pptr = (signed_message *)(((char *)mess) +
                  sizeof(signed_message) + sizeof(pc_set_message));
            pp = (pre_prepare_message *)(pptr + 1);

            for (j = 0; j < VAR.Num_Servers; j++)
                slot->made_eligible[j] = pp->last_executed[j];

        }
        /* This is the normal case, where we are just calculting the made_eligible
         * on this slot based on last_executed and the matrix of po_arus */
        else {
            for (j = 0; j < VAR.Num_Servers; j++) {
                ps = PRE_ORDER_Proof_ARU(j+1, slot->complete_pre_prepare.cum_acks);
                if (PRE_ORDER_Seq_Compare(ps, slot->complete_pre_prepare.last_executed[j]) > 0) 
                    slot->made_eligible[j] = ps;
                else 
                    slot->made_eligible[j] = slot->complete_pre_prepare.last_executed[j];
            }
        }
        slot->populated_eligible = 1;

        /* Execute the slot */
        prev_pp = &slot->complete_pre_prepare;
        prev_pp_part = slot->pre_prepare_parts_msg[1];
        prev_made_elig = (po_seq_pair *)slot->made_eligible;
        Alarm(PRINT, "  Executing type %u for slot %u after VC\n", slot->type, slot->seq_num);
        ORDER_Execute_Commit(slot);
    }

    /* Rollback ppARU and high_prepared to be correct for this view after we potentially 
     *  cleaned out old ord slots */
    ORDER_Adjust_High_Prepared();
    ORDER_Adjust_ppARU();
    assert(DATA.ORD.ppARU == rep->startSeq - 1);

    /* Cleanup the function-local hash table, done with it */
    stdhash_clear(&full_pc_set);
    stdhash_destruct(&full_pc_set);

    /* Cleanup pre_prepare_part_msg if first slot was no_op */
    if (dummy_pp_part)
        dec_ref_cnt(dummy_pp_part);
}
