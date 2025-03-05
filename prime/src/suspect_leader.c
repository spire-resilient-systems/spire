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
#include "order.h"
#include "suspect_leader.h"
#include "view_change.h"

#include "spu_memory.h"
#include "spu_alarm.h"

#define MAX_TAT_TIME (10000000.0)

/* Globally Accessible Variables */
extern server_variables     VAR;
extern server_data_struct   DATA;

/* Local Functions */
void SUSPECT_TAT_Measure_Periodically(int dummy, void *dummyp);
void SUSPECT_Ping_Periodically(int dummy, void *dummyp);
void SUSPECT_TAT_UB_Periodically(int dummy, void *dummyp);

/* Ideas:
 *
 * 1) Timeouts of the periodic functions have a direct impact on how
 *      fast we can view change. Maybe we can be more aggressive with
 *      the timeouts (e.g., for TAT_Measure) if we keep knowledge
 *      (using a flag?) of when there is new info to send. Then, only
 *      send messages when there is new info, makes the aggressive
 *      timers more bearable.
 *
 * 2) Suspect_Leader function (final one) SHOULD be made event based - 
 *      when either TAT_acceptable or TAT_leader changes, just check
 *
 * 3) Technically, we could also make computing TAT_acceptable and 
 *      TAT_leader also event-based, but not necessarily needed
 *
 */

void SUSPECT_Initialize_Data_Structure()
{
    /* Init stddll for TAT challenges to leader */
    stddll_construct(&DATA.SUSP.turnaround_times, sizeof(tat_challenge));

    /* Set the new_leader_proof to NULL at the beginning */
    DATA.SUSP.new_leader_proof = NULL;

    SUSPECT_Initialize_Upon_View_Change();

    Alarm(PRINT, "KLAT = %f\n",  VARIABILITY_KLAT);
}

void SUSPECT_Initialize_Upon_View_Change()
{
    int i;

    /* ------ TAT Leader ------ */
    /* Cleanup turnaround_times dll for new view */
    DATA.SUSP.max_tat = 0.0;
    for (i = 1; i <= VAR.Num_Servers; i++)
        DATA.SUSP.reported_tats[i] = 0.0;
    DATA.SUSP.tat_leader = 0.0;
    stddll_clear(&DATA.SUSP.turnaround_times);
    UTIL_Stopwatch_Start(&DATA.SUSP.sent_tatm_sw);
    DATA.SUSP.tat_max_change = 0;

    /* ------ TAT Acceptable ------ */
    DATA.SUSP.ping_seq_num = 1;
    for (i = 0; i < PING_HIST; i++) {
        DATA.SUSP.ping_history[i].seq_num = 0;
    }
    for (i = 1; i <= VAR.Num_Servers; i++) {
        DATA.SUSP.tat_if_leader[i] = MAX_TAT_TIME;
        DATA.SUSP.tat_leader_ubs[i] = MAX_TAT_TIME;
    }
    DATA.SUSP.tat_if_leader[VAR.My_Server_ID] = 0.0;
    DATA.SUSP.alpha = MAX_TAT_TIME;
    DATA.SUSP.tat_acceptable = MAX_TAT_TIME;

    /* ------ New Leader ------ */
    DATA.SUSP.leader_suspected = 0;
    for (i = 1; i <= VAR.Num_Servers; i++) {
        if (DATA.SUSP.new_leader[i] != NULL) {
            dec_ref_cnt(DATA.SUSP.new_leader[i]);
            DATA.SUSP.new_leader[i] = NULL;
        }
    }
}

void SUSPECT_Restart_Timed_Functions()
{
    sp_time t;

    /* Dequeue the SUSP periodic function with normal timeout,
     *  re-enqueue them with the view change specific timeouts */
    t.sec  = 0;
    t.usec = 10000;
    E_dequeue(SUSPECT_TAT_Measure_Periodically, 0, 0);
    E_queue(SUSPECT_TAT_Measure_Periodically, 0, 0, t);

    t.sec  = 0;
    t.usec = 0;
    E_dequeue(SUSPECT_Ping_Periodically, 0, 0);
    E_queue(SUSPECT_Ping_Periodically, 0, 0, t);

    t.sec  = 0;
    t.usec = 20000;
    E_dequeue(SUSPECT_TAT_UB_Periodically, 0, 0);
    E_queue(SUSPECT_TAT_UB_Periodically, 0, 0, t);
}

void SUSPECT_Upon_Reset()
{
    int32u i;

    stddll_clear(&DATA.SUSP.turnaround_times);
    stddll_destruct(&DATA.SUSP.turnaround_times);

    for (i = 1; i <= VAR.Num_Servers; i++) {
         if (DATA.SUSP.new_leader[i] != NULL) {
            dec_ref_cnt(DATA.SUSP.new_leader[i]);
            DATA.SUSP.new_leader[i] = NULL;
        }
    }
    if (DATA.SUSP.new_leader_proof != NULL) {
        dec_ref_cnt(DATA.SUSP.new_leader_proof);
        DATA.SUSP.new_leader_proof = NULL;
    }
}

void SUSPECT_TAT_Measure_Periodically(int dummy, void *dummyp)
{
    signed_message *m;
    tat_challenge *tatc;
    util_stopwatch *sw;
    stdit it;
    sp_time t;
    double diff;

    sw = NULL;
    if (DATA.VIEW.view_change_done == 1) {
        /* If the DLL of TAT challenges is not empty, see if the
         * challenge at the front is now the maximum TAT measured
         * so far this view */
        if (!stddll_empty(&DATA.SUSP.turnaround_times)) {
            stddll_begin(&DATA.SUSP.turnaround_times, &it);
            tatc = (tat_challenge *)stddll_it_val(&it);
            sw = (util_stopwatch *)&tatc->turnaround_time;
        }
    }
    else if (DATA.VIEW.done_vc_measure == 0 && DATA.VIEW.started_vc_measure == 1) 
    {
        /* If we are in the middle of a view change, only check the TAT if 
        * we've started measuring (e.g. sent a VC_Proof) */
        sw = (util_stopwatch *)&DATA.VIEW.vc_tat;
    }

    if (sw != NULL) {
        UTIL_Stopwatch_Stop(sw);
        if (DATA.SUSP.max_tat < UTIL_Stopwatch_Elapsed(sw)) {
            DATA.SUSP.max_tat = UTIL_Stopwatch_Elapsed(sw);
            DATA.SUSP.tat_max_change = 1;
        }
    }

    /* Send TAT Measure message */
    /* NOTE - we could send the TAT_Measure only when the max changes, using a flag
     *  that keeps track of when the max is increased either (1) from processing a
     *  pre-prepare or (2) from this timeout. If we do this, we may also want to
     *  send the value regardless if so much time has elapsed (e.g. 500ms) */
    UTIL_Stopwatch_Stop(&DATA.SUSP.sent_tatm_sw);
    diff = UTIL_Stopwatch_Elapsed(&DATA.SUSP.sent_tatm_sw);
    if (DATA.SUSP.tat_max_change == 1 || 
        diff >= (SUSPECT_SEND_TATM_SEC + SUSPECT_SEND_TATM_USEC/1000000.0)) 
    {
        DATA.SUSP.tat_max_change = 0;
        UTIL_Stopwatch_Start(&DATA.SUSP.sent_tatm_sw);
        m = SUSPECT_Construct_TAT_Measure(DATA.SUSP.max_tat);
        SIG_Add_To_Pending_Messages(m, BROADCAST, UTIL_Get_Timeliness(TAT_MEASURE));
        dec_ref_cnt(m);
    }

    /* Re-enqueue this function for the next timeout */
    t.sec  = SUSPECT_TAT_MEASURE_SEC;
    t.usec = SUSPECT_TAT_MEASURE_USEC;
    
    /* if (DATA.VIEW.view_change_done == 1) {
        t.sec  = SUSPECT_TAT_MEASURE_SEC;
        t.usec = SUSPECT_TAT_MEASURE_USEC;
    }
    else {
        t.sec  = SUSPECT_VC_SEC;
        t.usec = SUSPECT_VC_USEC;
    } */
    E_queue(SUSPECT_TAT_Measure_Periodically, 0, NULL, t);
}

void SUSPECT_Process_TAT_Measure(signed_message *mess)
{
    int i;
    double tats[VAR.Num_Servers+1];
    double prev_leader, accept;
    tat_measure_message *measure;

    measure = (tat_measure_message*)(mess + 1);

    if (measure->view != DATA.View) {
        Alarm(DEBUG, "Process_TAT_Measure: Invalid View %d\n", measure->view);
        return;
    }

    if (measure->max_tat > DATA.SUSP.reported_tats[mess->machine_id]) {
        DATA.SUSP.reported_tats[mess->machine_id] = measure->max_tat;
    }

    for (i = 1; i <= VAR.Num_Servers; i++) {
        tats[i] = DATA.SUSP.reported_tats[i];
    }
    
    qsort((void*)(tats+1), VAR.Num_Servers, sizeof(double), doublecmp);

    prev_leader = DATA.SUSP.tat_leader;
    DATA.SUSP.tat_leader = tats[VAR.F + VAR.K + 1];
    if (DATA.SUSP.tat_leader > prev_leader) {
        accept = DATA.SUSP.tat_acceptable * VARIABILITY_KLAT;
        if (DATA.VIEW.view_change_done == 1)
            accept += (double)PRE_PREPARE_SEC + (double)(PRE_PREPARE_USEC)/1000000.0;
        Alarm(STATUS, "[%u]: L=%f, rtt=%f, A=%f\n", 
                DATA.View, DATA.SUSP.tat_leader, DATA.SUSP.tat_acceptable, accept);
    }
    SUSPECT_Suspect_Leader();
}

void SUSPECT_Ping_Periodically (int dummy, void *dummyp) 
{
    int32u index;
    sp_time t;
    signed_message *ping;
    
    Alarm(DEBUG, "Broadcasting Ping %u\n", DATA.SUSP.ping_seq_num);

    index = DATA.SUSP.ping_seq_num % PING_HIST;
    DATA.SUSP.ping_history[index].seq_num = DATA.SUSP.ping_seq_num;
    UTIL_Stopwatch_Start(&DATA.SUSP.ping_history[index].rtt);
   
    ping = SUSPECT_Construct_RTT_Ping();
    SIG_Add_To_Pending_Messages(ping, BROADCAST, UTIL_Get_Timeliness(RTT_PING));
    dec_ref_cnt(ping);

    /* Re-enqueue this function for the next timeout */
    if (DATA.VIEW.view_change_done == 1) {
        t.sec  = SUSPECT_PING_SEC;
        t.usec = SUSPECT_PING_USEC;
    }
    else {
        t.sec  = SUSPECT_VC_SEC;
        t.usec = SUSPECT_VC_USEC;
    }
    E_queue(SUSPECT_Ping_Periodically, 0, NULL, t);
}

void SUSPECT_Process_RTT_Ping (signed_message *mess)
{
    int32u dest_bits;
    rtt_ping_message *ping;
    signed_message *pong;
    rtt_pong_message *pong_specific;

    ping = (rtt_ping_message*)(mess + 1);

    if (ping->view != DATA.View) {
        Alarm(DEBUG, "Process_RTT_Ping: Old View %d\n", ping->view);
        return;
    }
    Alarm(DEBUG,"Got PING from %d\n",mess->machine_id);
    pong = SUSPECT_Construct_RTT_Pong(mess->machine_id, ping->ping_seq_num);
    pong_specific = (rtt_pong_message *)(pong + 1);

    dest_bits = 0;
    UTIL_Bitmap_Set(&dest_bits, pong_specific->dest);

    Alarm(DEBUG, "Sending Pong %u to %u\n", pong_specific->ping_seq_num, pong_specific->dest);
    SIG_Add_To_Pending_Messages(pong, dest_bits, UTIL_Get_Timeliness(RTT_PONG));
    dec_ref_cnt(pong);
}

void SUSPECT_Process_RTT_Pong (signed_message *mess)
{
    double rtt;
    int32u dest_bits, index;
    signed_message *measure;
    rtt_pong_message *rtt_p;
    rtt_measure_message *measure_specific;

    rtt_p = (rtt_pong_message *)(mess + 1);

    if (rtt_p->view != DATA.View) {
        Alarm(DEBUG, "Process_RTT_Pong: Old View %d\n", rtt_p->view);
        return;
    }

    if (rtt_p->dest != VAR.My_Server_ID) {
        Alarm(PRINT, "Process_RTT_Pong: Bad Dest of Pong %d\n", rtt_p->dest);
        return;
    }

    /* We are using window of pings (ping_history). When we get a pong, we check if
     * the sequence number of that ping in the window matches. If so, measure rtt. If
     * no match, we've already given up on that ping, this rtt SHOULD have been too
     * large anyway to affect the replica's lowest rtt this view */
    index = rtt_p->ping_seq_num % PING_HIST;
    if (DATA.SUSP.ping_history[index].seq_num != rtt_p->ping_seq_num) {
        Alarm(PRINT, "Process_RTT_Pong: Pong (%d) for Ping that expired from %d.\n",
                rtt_p->ping_seq_num, mess->machine_id);
        return;
    }

    UTIL_Stopwatch_Stop(&DATA.SUSP.ping_history[index].rtt);
    rtt = UTIL_Stopwatch_Elapsed(&DATA.SUSP.ping_history[index].rtt);

    measure = SUSPECT_Construct_RTT_Measure(mess->machine_id, rtt);
    measure_specific = (rtt_measure_message *)(measure + 1);

    dest_bits = 0;
    UTIL_Bitmap_Set(&dest_bits, measure_specific->dest);

    Alarm(DEBUG, "Sending Measure %f to %u\n", measure_specific->rtt, measure_specific->dest);
    SIG_Add_To_Pending_Messages(measure, dest_bits, UTIL_Get_Timeliness(RTT_MEASURE));
    dec_ref_cnt(measure);
}

void SUSPECT_Process_RTT_Measure (signed_message *mess)
{
    int i;
    rtt_measure_message *measure;
    double prev_alpha, tats[VAR.Num_Servers+1];

    measure = (rtt_measure_message*)(mess + 1);
    if (measure->view != DATA.View) {
        Alarm(DEBUG, "Process_RTT_Measure: Old View %d\n", measure->view);
        return;
    }

    if (measure->dest != VAR.My_Server_ID) {
        Alarm(PRINT, "Process_RTT_Measure: Bad Dest of Pong %d\n", measure->dest);
        return;
    }

    if (measure->rtt < DATA.SUSP.tat_if_leader[mess->machine_id]) {
        DATA.SUSP.tat_if_leader[mess->machine_id] = measure->rtt;

        /* We got an update to tat_if_leader, re-sort to check if the alpha value
         *   is now changing. Optimization: if this is the first time the alpha
         *   value is less than INF, send it right away (rather than waiting for
         *   the TAT_UB timeout) */
        for (i = 1; i <= VAR.Num_Servers; i++)
            tats[i] = DATA.SUSP.tat_if_leader[i];
        qsort((void*)(tats+1), VAR.Num_Servers, sizeof(double), doublecmp);
        prev_alpha = DATA.SUSP.alpha;
        DATA.SUSP.alpha = tats[(VAR.Num_Servers+1)-(VAR.F + VAR.K + 1)];
        if (DATA.SUSP.alpha < MAX_TAT_TIME && prev_alpha == MAX_TAT_TIME) {
            E_dequeue(SUSPECT_TAT_UB_Periodically, 0, 0);
            SUSPECT_TAT_UB_Periodically(0, 0);
        }
    }
}

void SUSPECT_TAT_UB_Periodically(int dummy, void *dummyp) 
{
    sp_time t;
    signed_message *ub;
    tat_ub_message *ub_specific;

    ub = SUSPECT_Construct_TAT_UB(DATA.SUSP.alpha);
    ub_specific = (tat_ub_message *)(ub + 1);

    Alarm(DEBUG, "Broadcasting TAT_UB %f\n", ub_specific->alpha);
    SIG_Add_To_Pending_Messages(ub, BROADCAST, UTIL_Get_Timeliness(TAT_UB));
    dec_ref_cnt(ub);

    /* Re-enqueue this function for the next timeout */
    if (DATA.VIEW.view_change_done == 1) {
        t.sec  = SUSPECT_TAT_UB_SEC;
        t.usec = SUSPECT_TAT_UB_USEC;
    }
    else {
        t.sec  = SUSPECT_VC_SEC;
        t.usec = SUSPECT_VC_USEC;
    }
    E_queue(SUSPECT_TAT_UB_Periodically, 0, NULL, t);
}

void SUSPECT_Process_TAT_UB (signed_message *mess)
{
    int i;
    double tats[VAR.Num_Servers+1];
    double prev_acceptable, accept;
    tat_ub_message *ub;

    ub = (tat_ub_message*)(mess + 1);

    if (ub->view != DATA.View) {
        Alarm(DEBUG, "Process_TAT_UB: Old View %d\n", ub->view);
        return;
    }

    if (ub->alpha < DATA.SUSP.tat_leader_ubs[mess->machine_id]) {
        ///printf("alpha lower %f for server %d\n", ub->alpha,mess->machine_id);
        DATA.SUSP.tat_leader_ubs[mess->machine_id] = ub->alpha;
    }

    for (i = 1; i <= VAR.Num_Servers; i++) {
        tats[i] = DATA.SUSP.tat_leader_ubs[i];
    }

    //printf("tat_acceptable %f %f %f %f\n", tats[1], tats[2], tats[3], tats[4]);
    qsort((void*)(tats+1), VAR.Num_Servers, sizeof(double), doublecmp);
    prev_acceptable = DATA.SUSP.tat_acceptable;

    //printf("tat_acceptable %f %f %f %f %f\n", tats[6], tats[7], tats[8], tats[9],tats[10]);
    if (tats[(VAR.Num_Servers+1) - (VAR.F + VAR.K + 1)] > MIN_RTT)
        DATA.SUSP.tat_acceptable = tats[(VAR.Num_Servers+1) - (VAR.F + VAR.K + 1)];
    else
        DATA.SUSP.tat_acceptable = MIN_RTT;

    if (DATA.SUSP.tat_acceptable < prev_acceptable) {
        accept = DATA.SUSP.tat_acceptable * VARIABILITY_KLAT;
        if (DATA.VIEW.view_change_done == 1)
            accept += (double)PRE_PREPARE_SEC + (double)(PRE_PREPARE_USEC)/1000000.0;
        Alarm(STATUS, " [%u]: L=%f, rtt=%f, A=%f\n", 
                DATA.View, DATA.SUSP.tat_leader, DATA.SUSP.tat_acceptable, accept);
    }
    SUSPECT_Suspect_Leader();
}

void SUSPECT_Suspect_Leader()
{
    double t;
    signed_message *new_leader;

    Alarm(DEBUG, "ping_seq = %u, tat_leader %f, tat_acceptable %f\n", 
            DATA.SUSP.ping_seq_num, DATA.SUSP.tat_leader, DATA.SUSP.tat_acceptable);

    t = DATA.SUSP.tat_acceptable * VARIABILITY_KLAT;
    if (DATA.VIEW.view_change_done == 1)
        t += (double)PRE_PREPARE_SEC + (double)(PRE_PREPARE_USEC)/1000000.0;

    if (DATA.SUSP.leader_suspected == 0 && DATA.SUSP.tat_leader > t) {
        Alarm(PRINT, "Leader suspicious: tat_leader %f > tat_acceptable %f\n", 
                DATA.SUSP.tat_leader, t);
        struct timeval now;
	gettimeofday(&now,NULL);
	Alarm(PRINT,"Timestamp sec=%lu\n",now.tv_sec);
	DATA.SUSP.leader_suspected = 1;
        UTIL_Stopwatch_Start(&DATA.VIEW.vc_sw);
        new_leader = SUSPECT_Construct_New_Leader();
        //SIG_Add_To_Pending_Messages(new_leader, BROADCAST, UTIL_Get_Timeliness(NEW_LEADER));
        UTIL_RSA_Sign_Message(new_leader);
        SUSPECT_Process_New_Leader(new_leader);
        SUSPECT_New_Leader_Periodically(0, NULL);
        dec_ref_cnt(new_leader);
    }
}

void SUSPECT_Process_New_Leader(signed_message *mess)
{
    int32u i, count;
    signed_message *stored;
    new_leader_message *nlm_specific, *stored_specific;

    nlm_specific = (new_leader_message *)(mess + 1);

    Alarm(DEBUG, "Process_New_Leader from %d, new_view = %d, my view = %d\n", 
            mess->machine_id, nlm_specific->new_view, DATA.View);

    /* If this new_leader message is old, ignore */
    if (nlm_specific->new_view <= DATA.View)
        return;

    /* Check if we already have a new_leader message stored for this
     * replica. If so, see if this new one proposes a higher view number.
     * If yes, cleanup the old one and adopt the new one */
    stored = DATA.SUSP.new_leader[mess->machine_id];
    if (stored != NULL) {
        stored_specific = (new_leader_message *)(stored + 1);
        if (nlm_specific->new_view <= stored_specific->new_view) {
            return;
        }
        dec_ref_cnt(stored);
    }
    inc_ref_cnt(mess);
    DATA.SUSP.new_leader[mess->machine_id] = mess;

    /* Here, we count how many stored new_leader messages have
     * new views that match the new message. We can do this because
     * clearly we don't have enough votes at this point yet, and only
     * this message can potentially hit the threshold at this time */
    count = 0;
    for (i = 1; i <= VAR.Num_Servers; i++) {
        if (DATA.SUSP.new_leader[i] == NULL)
            continue;

        stored = DATA.SUSP.new_leader[i];
        stored_specific = (new_leader_message *)(stored + 1);

        if (stored_specific->new_view == nlm_specific->new_view)
            count++;
    }
    
    /* We only start sending a new_leader_proof the first time we 
     * get enough matching new_leader message view proposals */
    if (count != 2*VAR.F + VAR.K + 1)
        return;

    /* If I just was the leader, dequeue the period ordering function
     *  that sends out pre-prepares */
    if (UTIL_I_Am_Leader() && E_in_queue(ORDER_Periodically, 0, NULL))
        E_dequeue(ORDER_Periodically, 0, NULL);

    /* Preinstall new view and start sending new_leader_proof messages */
    DATA.View = nlm_specific->new_view;
    Alarm(PRINT, "READY for View Change: 2F+K+1 New_Leader View=%d\n",DATA.View);
    struct timeval now;
    gettimeofday(&now,NULL);
    Alarm(PRINT,"Timestamp sec=%lu\n",now.tv_sec);
    
    if (DATA.SUSP.new_leader_proof != NULL) {
        dec_ref_cnt(DATA.SUSP.new_leader_proof);
        DATA.SUSP.new_leader_proof = NULL;
    }
    UTIL_Stopwatch_Stop(&DATA.VIEW.vc_sw);
    Alarm(DEBUG, "\t[SUSP to NLP] = %f\n", UTIL_Stopwatch_Elapsed(&DATA.VIEW.vc_sw));
    DATA.SUSP.new_leader_proof = SUSPECT_Construct_New_Leader_Proof();
    if (E_in_queue(SUSPECT_New_Leader_Periodically, 0, NULL))
        E_dequeue(SUSPECT_New_Leader_Periodically, 0, NULL);
    DATA.VIEW.executed_ord = 0;
    SUSPECT_New_Leader_Proof_Periodically(0, NULL);

    /* Start the view change process */
    VIEW_Start_View_Change();
}

void SUSPECT_New_Leader_Periodically(int dummy, void *dummyp)
{
    sp_time t;

    if (DATA.SUSP.new_leader[VAR.My_Server_ID] == NULL)
        return;

    Alarm(DEBUG, "Sending New Leader msg (to leave view %u)\n", DATA.View);
    UTIL_Broadcast(DATA.SUSP.new_leader[VAR.My_Server_ID]);

    t.sec  = SUSPECT_NEW_LEADER_SEC;
    t.usec = SUSPECT_NEW_LEADER_USEC;
    E_queue(SUSPECT_New_Leader_Periodically, 0, NULL, t);
}

void SUSPECT_New_Leader_Proof_Periodically(int dummy, void *dummyp)
{
    sp_time t;
 
    if (DATA.VIEW.executed_ord == 1)
    {
        Alarm(DEBUG, "Would retransmit NLP but executed first ord of new view\n");
        return;
    }

    /* TODO: we could sign this initially, then just UTIL_Broadcast each
     *   time we need to retransmit this */
    Alarm(DEBUG, "Sending New Leader Proof (to start view %u)\n", DATA.View);
    SIG_Add_To_Pending_Messages(DATA.SUSP.new_leader_proof, BROADCAST, 
        UTIL_Get_Timeliness(NEW_LEADER_PROOF));

    t.sec  = SUSPECT_NEW_LEADER_SEC;
    t.usec = SUSPECT_NEW_LEADER_USEC;
    E_queue(SUSPECT_New_Leader_Proof_Periodically, 0, NULL, t);
}

void SUSPECT_Process_New_Leader_Proof(signed_message *mess)
{
    int32u i, count, new_view, size;
    new_leader_proof_message *nlp;
    signed_message *nl;
    new_leader_message *nl_specific;
    char *ptr;

    /* (1) Validate the new_leader_proof message - all must match for new view
     * (2) Preinstall the new view
     * (3) Steal the new_leader_proof message, put our own ID, etc. on it
     * (4) Start sending periodically */

    nlp = (new_leader_proof_message *)(mess + 1);
    new_view = nlp->new_view;
    
    Alarm(DEBUG, "Process_New_Leader_Proof from %d, new_view = %d, my view = %d\n", 
            mess->machine_id, new_view, DATA.View);

    /* If you've already changed to or preinstalled this view, ignore */
    if (new_view <= DATA.View)
        return;

    /* Assuming validate has checked that we have 2f+k+1 NL messages */
    count = 0;
    ptr =  (char *)nlp + sizeof(new_leader_proof_message);

    for (i = 0; i < 2*VAR.F + VAR.K + 1; i++) {
        nl = (signed_message *)(ptr + 
                i * (sizeof(signed_message) + sizeof(new_leader_message)));
        nl_specific = (new_leader_message *)(nl + 1);

        if (nl_specific->new_view != new_view) {
            Alarm(PRINT, "SUSPECT_Process_New_Leader_Proof: Incorrect "
                    "message from %d: view = %d, should be %d\n", mess->machine_id, 
                     nl_specific->new_view, new_view);
            /* Blacklist(mess->machine_id); */
            return;
        }
        count++;
    }
    assert(count == 2*VAR.F + VAR.K + 1);

    /* If I just was the leader, dequeue the period ordering function
     *  that sends out pre-prepares */
    if (UTIL_I_Am_Leader() && E_in_queue(ORDER_Periodically, 0, NULL))
        E_dequeue(ORDER_Periodically, 0, NULL);

    /* Preinstall the new view and start sending new_leader_proof message */
    UTIL_Stopwatch_Start(&DATA.VIEW.vc_sw);
    DATA.View = new_view;
    Alarm(PRINT, "READY for View Change: New_Leader_Proof Received\n");

    /* Take this message and claim it as our own */
    if (DATA.SUSP.new_leader_proof != NULL) {
        dec_ref_cnt(DATA.SUSP.new_leader_proof);
        DATA.SUSP.new_leader_proof = NULL;
    }
    DATA.SUSP.new_leader_proof = mess;
    inc_ref_cnt(mess);

    /* Erase just the signed_message header to claim as our own, don't actually
     *      touch the content of the new_leader_proof message */
    size = mess->len;
    memset(DATA.SUSP.new_leader_proof, 0, sizeof(signed_message));
    DATA.SUSP.new_leader_proof->machine_id = VAR.My_Server_ID;
    DATA.SUSP.new_leader_proof->type = NEW_LEADER_PROOF;
    DATA.SUSP.new_leader_proof->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    DATA.SUSP.new_leader_proof->len = size;
    if (E_in_queue(SUSPECT_New_Leader_Periodically, 0, NULL))
        E_dequeue(SUSPECT_New_Leader_Periodically, 0, NULL);
    DATA.VIEW.executed_ord = 0;
    SUSPECT_New_Leader_Proof_Periodically(0, NULL);

    /* Start the view change process */
    VIEW_Start_View_Change();
}
