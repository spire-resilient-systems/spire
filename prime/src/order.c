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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "spu_alarm.h"
#include "spu_memory.h"
#include "order.h"
#include "data_structs.h"
#include "process.h"
#include "network.h"
#include "utility.h"
#include "util_dll.h"
#include "def.h"
#include "process.h"
#include "pre_order.h"
#include "error_wrapper.h"
#include "signature.h"
#include "erasure.h"
#include "recon.h"
#include "view_change.h"
#include "proactive_recovery.h"

/* Global variables */
extern server_variables   VAR;
extern network_variables  NET;
extern server_data_struct DATA;
extern benchmark_struct   BENCH;

/* Local functions */
void   ORDER_Periodically                (int dummy, void *dummyp);
void   ORDER_Periodic_Retrans            (int d1, void *d2);
void   ORDER_Execute_Update              (signed_message *mess, int32u ord, 
                                            int32u e_idx, int32u e_tot);
void   ORDER_Flood_Pre_Prepare           (signed_message *mess);
void   ORDER_Update_Forwarding_White_Line(void);
void   ORDER_Send_Commit                 (complete_pre_prepare_message *pp);
int32u ORDER_Ready_To_Execute            (ord_slot *o_slot);

int32u ORDER_Prepare_Certificate_Ready(ord_slot *slot);
void   ORDER_Move_Prepare_Certificate (ord_slot *slot);
int32u ORDER_Prepare_Matches_Pre_Prepare(signed_message *prepare,
                     complete_pre_prepare_message *pp);

int32u ORDER_Commit_Certificate_Ready  (ord_slot *slot);
void   ORDER_Move_Commit_Certificate   (ord_slot *slot);
//int32u ORDER_Commit_Matches_Pre_Prepare(signed_message *commit,
//                    complete_pre_prepare_message *pp);

int32u ORDER_Pre_Prepare_Backward_Progress(complete_pre_prepare_message *pp);

void ORDER_Initialize_Data_Structure()
{
  DATA.ORD.ARU                    = 0;
  DATA.ORD.ppARU                  = 0;
  DATA.ORD.high_seq               = 0;
  DATA.ORD.events_ordered         = 0;
  DATA.ORD.seq                    = 1;
  DATA.ORD.should_send_pp         = 0;

  stdhash_construct(&DATA.ORD.History, sizeof(int32u), 
		    sizeof(ord_slot *), NULL, NULL, 0);
  
  stdhash_construct(&DATA.ORD.Pending_Execution, sizeof(int32u),
		    sizeof(ord_slot *), NULL, NULL, 0);

  UTIL_Stopwatch_Start(&DATA.ORD.pre_prepare_sw);

  Alarm(DEBUG, "Initialized Ordering data structure.\n");

  /* If I'm the leader, try to start sending Pre-Prepares */
  if (UTIL_I_Am_Leader())
    ORDER_Periodically(0, NULL);

  ORDER_Periodic_Retrans(0, NULL);
}

void ORDER_Periodically(int dummy, void *dummyp)
{
  sp_time t;

  ORDER_Send_One_Pre_Prepare(TIMEOUT_CALLER);
  t.sec  = PRE_PREPARE_SEC; 
  t.usec = PRE_PREPARE_USEC;
  E_queue(ORDER_Periodically, 0, NULL, t);
}

int32u ORDER_Send_One_Pre_Prepare(int32u caller)
{
  signed_message *mset[NUM_SERVERS];
  int32u num_parts, i;
  double time;

  /* Make sure enough time has elapsed since we've sent a Pre-Prepare */
  UTIL_Stopwatch_Stop(&DATA.ORD.pre_prepare_sw);
  time = UTIL_Stopwatch_Elapsed(&DATA.ORD.pre_prepare_sw);
  if (time * 1000 < 20)
    Alarm(PRINT, "PP Elapsed Early: %f ms\n", time * 1000);
  //UTIL_Stopwatch_Start(&DATA.ORD.pre_prepare_sw);
  /* if(time < (PRE_PREPARE_USEC / 1000000.0)) {
    Alarm(PRINT, "Send_One_Pre_Prepare not ready. Elapsed = %f ms\n", time * 1000);
    return 0;
  } */

#if DELAY_ATTACK
  while(!UTIL_DLL_Is_Empty(&DATA.PO.proof_matrix_dll) &&
	UTIL_DLL_Elapsed_Front(&DATA.PO.proof_matrix_dll) > DELAY_TARGET) {
    PRE_ORDER_Process_Proof_Matrix(UTIL_DLL_Front_Message(&DATA.PO.proof_matrix_dll));
    UTIL_DLL_Pop_Front(&DATA.PO.proof_matrix_dll);
  }
#endif

  //if (DATA.ORD.seq == 1 && PRE_ORDER_Latest_Proof_Sent())
  //if(PRE_ORDER_Latest_Proof_Sent())
  if (DATA.ORD.should_send_pp == 0)
    return 0;
  
  /* Construct the Pre-Prepare */
  ORDER_Construct_Pre_Prepare(mset, &num_parts);

  Alarm(DEBUG, "SENDING PRE-Prepare!\n");
  /* int32u j;
  pre_prepare_message *pp = (pre_prepare_message *)(mset[1] + 1);
  po_aru_signed_message *cum_acks = (po_aru_signed_message *)(pp + 1);
  printf("++++++++++ SENDING MATRIX %u ++++++++++\n", DATA.ORD.seq - 1);
  for (i = 0; i < NUM_SERVERS; i++)
  {
    for (j = 0; j < NUM_SERVERS; j++)
    {
      printf("(%u, %u) ", cum_acks[i].cum_ack.ack_for_server[j].incarnation, cum_acks[i].cum_ack.ack_for_server[j].seq_num);
    }
    printf("\n");
  } */
 
  PRE_ORDER_Update_Latest_Proof_Sent();
  DATA.ORD.should_send_pp = 0;

  for(i = 1; i <= num_parts; i++) {
    Alarm(DEBUG, "Add: Pre-Prepare part %d \n", i);
    SIG_Add_To_Pending_Messages(mset[i], BROADCAST, 
				UTIL_Get_Timeliness(PRE_PREPARE));
    dec_ref_cnt(mset[i]);
  }

  //UTIL_Stopwatch_Start(&DATA.ORD.pre_prepare_sw);

  return 1;
}

void ORDER_Periodic_Retrans(int d1, void *d2)
{
    int32u i;
    ord_slot *o_slot;
    sp_time t;

    //printf("  ARU = %u, ppARU = %u\n", DATA.ORD.ARU, DATA.ORD.ppARU);
    for (i = DATA.ORD.ARU + 1; i <= DATA.ORD.ppARU; i++) {

        //printf("Slot %u\n", i);
        o_slot = UTIL_Get_ORD_Slot_If_Exists(i);
        assert(o_slot != NULL);

        /* Send Pre-Prepare if I'm the leader */
        if (UTIL_I_Am_Leader()) {
            if (o_slot->pre_prepare_parts_msg[1]) {
                UTIL_Broadcast(o_slot->pre_prepare_parts_msg[1]);
            }
        }
        /* Send Prepare if I'm not the leader */
        else {
            if (o_slot->prepare[VAR.My_Server_ID]) {
                UTIL_Broadcast(o_slot->prepare[VAR.My_Server_ID]);
            }
            /* else {
                printf("   NO PREPARE for %d. Has Pre-Prepare? %u\n", i, o_slot->collected_all_parts); 
            } */
        }

        /* Send Commit (if I have it) */
        if (o_slot->commit[VAR.My_Server_ID]) {
            UTIL_Broadcast(o_slot->commit[VAR.My_Server_ID]);
        }   
    }
 
    t.sec  = RETRANS_PERIOD_SEC;
    t.usec = RETRANS_PERIOD_USEC;
    E_queue(ORDER_Periodic_Retrans, 0, NULL, t);
}

void ORDER_Process_Pre_Prepare(signed_message *mess)
{
  ord_slot *slot, *tslot;
  pre_prepare_message *pp_specific;
  complete_pre_prepare_message *complete_pp;
  po_aru_signed_message *cum_acks;
  int32u covered, lower, higher;
  int32u i, j, index, part_num, num_acks_per_message;
  stdit it;
  tat_challenge *tatc;
  util_stopwatch sw;
  sp_time start;

  Alarm(DEBUG, "%d Process Pre-Prepare\n", VAR.My_Server_ID);

  pp_specific = (pre_prepare_message *)(mess+1);
  part_num    = pp_specific->part_num;

  /* We should only get Pre-Prepares that originate from the leader */
  if (mess->machine_id != UTIL_Leader()) {
    Alarm(PRINT, "ORDER_Process_Pre_Prepare: got pre-prepare from "
            "non-leader (%d), ignoring\n", mess->machine_id);
    return;
  }

  Alarm(DEBUG, "PP info. seq = %d, ARU = %d, forw_white_line = %d\n",
        pp_specific->seq_num, DATA.ORD.ARU, DATA.ORD.forwarding_white_line);
  
  if (!DATA.VIEW.view_change_done) Alarm(PRINT, "Got pre-prepare before finishing view change! seq = %d, aru = %d\n", pp_specific->seq_num, DATA.ORD.ARU);

  /* If we're done forwarding for this slot, and we've already reconciled
   * on this slot and the next, and we've already executed this slot and
   * the next one, then there's no reason to do anything else with this
   * sequence number. */
  if(pp_specific->seq_num <= DATA.ORD.forwarding_white_line &&
     (pp_specific->seq_num+1) <= DATA.ORD.recon_white_line &&
     (pp_specific->seq_num+1) <= DATA.ORD.ARU)
    return;

  /* Check the view on the pre-prepare?  */
  if (pp_specific->view != DATA.View) 
    return;
  
  //slot = UTIL_Get_ORD_Slot_If_Exists(pp_specific->seq_num);
  slot = UTIL_Get_ORD_Slot(pp_specific->seq_num);
  //if (slot == NULL) {
  /* First time we are getting any part of this pre-prepare (but may already
   * have prepares and/or commits waiting that created the slot); set up the
   * pre-prepare */
  if (slot->num_parts_collected == 0) {
    //slot = UTIL_Get_ORD_Slot(pp_specific->seq_num);
    slot->view        = pp_specific->view;
    slot->total_parts = pp_specific->total_parts;
    slot->complete_pre_prepare.seq_num = slot->seq_num;
    slot->complete_pre_prepare.view    = slot->view;
  }
  else if (slot->view != pp_specific->view ||
            slot->total_parts != pp_specific->total_parts)
  {
    Alarm(PRINT, "Malformed PP part. Should Flood it and suspect leader: seq %d, slot view %d, pp view %d, slot parts %d, pp parts %d, cpp seq %d, cpp view %d\n", pp_specific->seq_num, slot->view, pp_specific->view, slot->total_parts, pp_specific->total_parts, slot->complete_pre_prepare.seq_num, slot->complete_pre_prepare.view);
    /* ORDER_Flood_Pre_Prepare(mess);
    Suspect_Leader or New_Leader message; */
  }

  /* If we've already collected all of the parts, ignore */
  if(slot->collected_all_parts)
    return;

  /* If we already have this part, done for now */
  part_num          = pp_specific->part_num;
  if(slot->pre_prepare_parts[part_num] == 1)
    return;

  /* timing tests */
  start.sec  = pp_specific->sec;
  start.usec = pp_specific->usec;
  sw.start = start;
  UTIL_Stopwatch_Stop(&sw);
  //if (UTIL_Stopwatch_Elapsed(&sw) > 0.004)
  //  Alarm(PRINT, "  PP w/ lat = %f ms\n", UTIL_Stopwatch_Elapsed(&sw) * 1000);

  /* Otherwise, we need this part, store it. Then see if we've now collected
   * all of the parts. */
  slot->pre_prepare_parts[part_num] = 1;
  slot->pre_prepare_parts_msg[part_num] = mess;
  inc_ref_cnt(mess);
  Alarm(DEBUG, "Storing Pre-Prepare part %d for seq %d\n",
        part_num, slot->seq_num);

  num_acks_per_message = (PRIME_MAX_PACKET_SIZE -
                   sizeof(signed_message) - sizeof(pre_prepare_message) -
                   (MAX_MERKLE_DIGESTS * DIGEST_SIZE)) /
                   sizeof(po_aru_signed_message);
  index = (part_num - 1) * num_acks_per_message;

  /* Copy the bytes of this Pre-Prepare into the complete PP */
  Alarm(DEBUG, "Copying part %d to starting index %d\n", part_num, index);
  memcpy((byte *)(slot->complete_pre_prepare.cum_acks + index),
           (byte *)(pp_specific + 1),
           sizeof(po_aru_signed_message) *
           pp_specific->num_acks_in_this_message);

  slot->num_parts_collected++;

  assert(slot->forwarded_pre_prepare_parts[part_num] == 0);

  /* If not the leader, flood this part of the PP since its new
   * If I'm the leader, mark that I've forwarded all parts because
   * I never go and forward them. Then, all replicas update the
   * forwarded flag and check if white line should move up. */
  ORDER_Flood_Pre_Prepare(mess);

  if (slot->num_parts_collected < slot->total_parts)
    return;

  slot->collected_all_parts = 1;

  /* A Prepare certificate could be ready if we get some Prepares
   * before we get the Pre-Prepare. */
  if(ORDER_Prepare_Certificate_Ready(slot))
    ORDER_Move_Prepare_Certificate(slot);

  /* We now have the complete Pre-Prepare for the first time, do the 
   * following:
   * 
   *  1. If I'm a non-leader, send a Prepare.
   *
   *  2. Apply the PO-ARUs in the Proof Matrix.
   *
   *  3. Perform reconciliation on this slot.  Also try to perform it on
   *     the next slot, because that slot might not have been able to 
   *     reconcile if we received PP i+1 before PP i. */

  /* Setup pointers for PO_ARU comparison */
  complete_pp = (complete_pre_prepare_message *)&slot->complete_pre_prepare;
  cum_acks = (po_aru_signed_message *)complete_pp->cum_acks;

  /* Apply the PO-ARUs contained in the proof matrix, checking for
   *      any inconsistencies. NULL vectors checked in function */
  for(i = 0; i < NUM_SERVERS; i++) {
    signed_message *m = (signed_message *)&cum_acks[i];
    PRE_ORDER_Process_PO_ARU(m); 
  }

  /* ESTCP: Should only update knowledge of what has made it into a valid
   * pre-prepare and send prepare if I actually have the previous pre-prepare
   * AND can verify that this pre-prepare does not make "backward progress"
   * relative to that one. Means that I may need to send multiple prepares if I
   * fill in a hole */
  if (complete_pp->seq_num != DATA.ORD.ppARU + 1) {
    // Not yet ready to say whether this is valid. Will need to check when I
    // fill in a hole
    Alarm(DEBUG, "ORDER_Process_Pre_Prepare: Don't have valid PP to calculate "
                 "delta for %u\n", complete_pp->seq_num);
    return;
  }
  ORDER_Send_Prepares();
#if 0
  tslot = slot;
  while (tslot != NULL && tslot->collected_all_parts)
  {
      complete_pp = (complete_pre_prepare_message *)&tslot->complete_pre_prepare;
      cum_acks = (po_aru_signed_message *)complete_pp->cum_acks;
      Alarm(DEBUG, "CHECKING Pre-prepare %u, ppARU %u\n", complete_pp->seq_num, DATA.ORD.ppARU);

      if (ORDER_Pre_Prepare_Backward_Progress(complete_pp)) {
        Alarm(PRINT, "ORDER_Process_Pre_Prepare: Pre-prepare (%u) goes backward in "
                     "terms of what is eligible for execution -- refusing to send "
                     "pre-prepare!\n", complete_pp->seq_num);
        // Invalid PP -- don't send prepare
        break;
      }

      /* If we know the leader now has received a PO request from a replica
       * that is greater than what we've sent, update our records so that
       * we don't think we are required to send a PO ARU with it - cause
       * no progress would actually be made if we did. */
      for(i = 1; i <= NUM_SERVERS; i++) {
        ps = PRE_ORDER_Proof_ARU(i, cum_acks);
        if (PRE_ORDER_Seq_Compare(ps, DATA.PO.max_num_sent_in_proof[i]) > 0) 
            DATA.PO.max_num_sent_in_proof[i] = ps;
      }

      /* Non-leaders should send a Prepare */
      if(!UTIL_I_Am_Leader()) {

        /* Construct a Prepare Message based on the Pre-Prepare */
        prepare = ORDER_Construct_Prepare(&tslot->complete_pre_prepare);

        Alarm(DEBUG, "Add: Prepare\n");
        SIG_Add_To_Pending_Messages(prepare, BROADCAST, 
              UTIL_Get_Timeliness(PREPARE));
        dec_ref_cnt(prepare);

      }
      tslot->sent_prepare = 1;
      DATA.ORD.ppARU++;

      /* Try to reconcile on the slot */
      RECON_Do_Recon(tslot);
      if (tslot->reconciled == 0) {
        Alarm(PRINT, "RECON failed! slot->seq_num = %d, slot->view = %d\n", tslot->seq_num, tslot->view);
      }

      tslot = UTIL_Get_ORD_Slot_If_Exists(DATA.ORD.ppARU + 1);
  }
#endif

  tslot = UTIL_Get_ORD_Slot_If_Exists(DATA.ORD.ppARU);
  assert(tslot != NULL);
  complete_pp = (complete_pre_prepare_message *)&tslot->complete_pre_prepare;
  cum_acks = (po_aru_signed_message *)complete_pp->cum_acks;

  /* If this is not the next expected pre-prepare sequence number, don't try to
   *  check for coverage for TAT measurements or RECON, since there is a gap */
  //if (complete_pp->seq_num != DATA.ORD.ARU + 1)
  //  return;

  /* printf("    stddll before = %u,", stddll_size(&DATA.SUSP.turnaround_times)); */
  covered = 1;
  while (!stddll_empty(&DATA.SUSP.turnaround_times) && covered == 1) {
      stddll_begin(&DATA.SUSP.turnaround_times, &it);
      tatc = (tat_challenge *)stddll_it_val(&it);

      for (i = 0; i < NUM_SERVERS && covered == 1; i++) {

        lower = higher = 0;
        for (j = 0; j < NUM_SERVERS; j++) {
          if (PRE_ORDER_Seq_Compare(cum_acks[i].cum_ack.ack_for_server[j], 
                tatc->proof_matrix[i+1].cum_ack.ack_for_server[j]) < 0) 
          {
            lower = 1;
          }
          else if (PRE_ORDER_Seq_Compare(cum_acks[i].cum_ack.ack_for_server[j], 
                 tatc->proof_matrix[i+1].cum_ack.ack_for_server[j]) > 0) 
          {
            higher = 1;
          }
        }

        if (lower && !higher) {
            covered = 0;
        }
        else if (lower && higher) {
            Alarm(PRINT, "Process_Pre_Prepare: Warning - received inconsistent "
                    "vector from leader in PP, but may not be their fault!\n");
        }
      }

      if (covered == 1) {
        /* Stop the stopwatch, measure the TAT, store if new max_tat in this view */
        UTIL_Stopwatch_Stop(&tatc->turnaround_time);
        if (UTIL_Stopwatch_Elapsed(&tatc->turnaround_time) > TAT_PRINT_THRESH) {
            Alarm(DEBUG, "  ** > Thresh in Order: %f s\n", 
                    UTIL_Stopwatch_Elapsed(&tatc->turnaround_time));
        }
        if (DATA.SUSP.max_tat < UTIL_Stopwatch_Elapsed(&tatc->turnaround_time)) {
          DATA.SUSP.max_tat = UTIL_Stopwatch_Elapsed(&tatc->turnaround_time);
          DATA.SUSP.tat_max_change = 1;
        }
        stddll_pop_front(&DATA.SUSP.turnaround_times);
        //printf("      Challenge Covered\n");
      }
  }
  /* printf("    stddll after = %u\n", stddll_size(&DATA.SUSP.turnaround_times)); */

#if 0
  /* Try to reconcile on the current slot, then try to reconcile on the
   * next one in case it was waiting for a Pre-Prepare to fill the hole. */
  RECON_Do_Recon(slot);
  if (slot->reconciled == 0) {
    Alarm(PRINT, "RECON failed! slot->seq_num = %d, slot->view = %d\n", slot->seq_num, slot->view);
  }

  //int seq = pp_specific->seq_num + 1;
  slot = UTIL_Get_ORD_Slot_If_Exists(pp_specific->seq_num + 1);
  //while (slot != NULL)
  //{
  //  RECON_Do_Recon(slot);
  //  seq++;
  //  slot = UTIL_Get_ORD_Slot_If_Exists(seq);
  //  if (!slot->reconciled) {
  //      Alarm(PRINT, "Done trying to reconcile for now...seq %d\n", seq);
  //      break;
  //  }
  //}
  if(slot != NULL)
    RECON_Do_Recon(slot);
#endif
}

void ORDER_Send_Prepares(void)
{
  ord_slot *slot;
  complete_pre_prepare_message *complete_pp;
  po_aru_signed_message *cum_acks;
  signed_message *prepare;
  po_seq_pair ps;
  int32u i;

  slot = UTIL_Get_ORD_Slot_If_Exists(DATA.ORD.ppARU + 1);

  while (slot != NULL && slot->collected_all_parts)
  {
      complete_pp = (complete_pre_prepare_message *)&slot->complete_pre_prepare;
      cum_acks = (po_aru_signed_message *)complete_pp->cum_acks;
      Alarm(DEBUG, "CHECKING Pre-prepare %u, ppARU %u\n", complete_pp->seq_num, DATA.ORD.ppARU);

      if (ORDER_Pre_Prepare_Backward_Progress(complete_pp)) {
        Alarm(PRINT, "ORDER_Send_Prepares: Pre-prepare (%u) goes backward in "
                     "terms of what is eligible for execution -- refusing to send "
                     "pre-prepare!\n", complete_pp->seq_num);
        // Invalid PP -- don't send prepare
        break;
      }

      /* If we know the leader now has received a PO request from a replica
       * that is greater than what we've sent, update our records so that
       * we don't think we are required to send a PO ARU with it - cause
       * no progress would actually be made if we did. */
      for(i = 1; i <= NUM_SERVERS; i++) {
        ps = PRE_ORDER_Proof_ARU(i, cum_acks);
        if (PRE_ORDER_Seq_Compare(ps, DATA.PO.max_num_sent_in_proof[i]) > 0) 
            DATA.PO.max_num_sent_in_proof[i] = ps;
      }

      /* Non-leaders should send a Prepare */
      if(!UTIL_I_Am_Leader()) {

        /* Construct a Prepare Message based on the Pre-Prepare */
        prepare = ORDER_Construct_Prepare(&slot->complete_pre_prepare);

        Alarm(DEBUG, "Add: Prepare for slot %d\n", slot->seq_num);
        SIG_Add_To_Pending_Messages(prepare, BROADCAST, UTIL_Get_Timeliness(PREPARE));
        dec_ref_cnt(prepare);

      }
      slot->sent_prepare = 1;
      DATA.ORD.ppARU++;

      /* Try to reconcile on the slot */
      RECON_Do_Recon(slot);
      if (slot->reconciled == 0) {
        Alarm(PRINT, "RECON failed! slot->seq_num = %d, slot->view = %d\n", slot->seq_num, slot->view);
      }

      slot = UTIL_Get_ORD_Slot_If_Exists(DATA.ORD.ppARU + 1);
  }
}

int32u ORDER_Pre_Prepare_Backward_Progress(complete_pre_prepare_message *pp)
{
  po_seq_pair prev_pop[NUM_SERVER_SLOTS];
  po_seq_pair cur_pop[NUM_SERVER_SLOTS];
  po_seq_pair zero_ps = {0, 0};
  ord_slot *prev_ord_slot;
  complete_pre_prepare_message *prev_pp;
  int32u gseq, i;

  gseq = pp->seq_num;

  /* First check to see if we have the previous pre-prepare */
  prev_ord_slot = UTIL_Get_ORD_Slot_If_Exists(gseq - 1);

  /* Calculate delta between the pre-prepare and the previous one to make sure
   * that nothing "goes backwards" in terms of being eligible for execution */
  if(prev_ord_slot == NULL) {
    /* We ONLY call this if we've already checked that we have a valid previous
     * pre-prepare, so if it's missing, this must be the first ever pre-prepare
     * */
    assert(gseq == 1);

    for(i = 1; i <= NUM_SERVERS; i++)
      prev_pop[i] = zero_ps;
  }
  else {
    if(prev_ord_slot->prepare_certificate_ready)
      prev_pp = &prev_ord_slot->prepare_certificate.pre_prepare;
    else {
      prev_pp = &prev_ord_slot->complete_pre_prepare;
      assert(prev_ord_slot->collected_all_parts);
    }

    /* Set up the Prev_pop array */
    for(i = 1; i <= NUM_SERVERS; i++)
      prev_pop[i] = PRE_ORDER_Proof_ARU(i, prev_pp->cum_acks);
  }

  for(i = 1; i <= NUM_SERVERS; i++)
    cur_pop[i] = PRE_ORDER_Proof_ARU(i, pp->cum_acks);

  for(i = 1; i <= NUM_SERVERS; i++) {

    if (PRE_ORDER_Seq_Compare(cur_pop[i], prev_pop[i]) < 0) {
        Alarm(PRINT, "ORDER_Pre_Prepare_Backward_Progress: (%u, %u) from %u was "
                     "eligible for execution, but now only up to (%u, %u) is "
                     "eligible -- Bad Pre-prepare!!\n",
                     prev_pop[i].incarnation, prev_pop[i].seq_num, i,
                     cur_pop[i].incarnation, cur_pop[i].seq_num);
        return 1;
    }
  }

  return 0;
}

void ORDER_Process_Prepare(signed_message *mess) 
{
  ord_slot *slot;
  prepare_message *prepare_specific;
  signed_message *commit;

  Alarm(DEBUG, "%d ORDER_Prepare\n",VAR.My_Server_ID);

  prepare_specific = (prepare_message*)(mess+1);

  /* If the view does not match, discard */
  if (prepare_specific->view != DATA.View) {
    Alarm(PRINT, "  DROPPING PREPARE: prep->view = %d, seq = %d, My_View = %d\n",
            prepare_specific->view, prepare_specific->seq_num, DATA.View);
    return;
  }

  /* If this is from the leader, ignore - he can't be counted twice, once
   *    for the prepare and pre-prepare */
  if (mess->machine_id == UTIL_Leader())
    return;

  /* If we've already executed this seq, discard */
  if(prepare_specific->seq_num <= DATA.ORD.ARU)
    return;

  /* Get the slot */
  slot = UTIL_Get_ORD_Slot(prepare_specific->seq_num);
  assert(slot->seq_num == prepare_specific->seq_num);

  /* If I don't already have a Prepare from this server, store it */

  /* We compare digests of the prepare compared with the preprepare at the end,
   * since there is no guarantee that we'll have a preprepare to check with 
   * at this point (see ORDER_Prepare_Certificate_Ready).  */
  if(slot->prepare[mess->machine_id] != NULL)
    return;

  inc_ref_cnt(mess);
  slot->prepare[mess->machine_id] = mess;

  Alarm(DEBUG,"PREPARE %d %d \n", mess, get_ref_cnt(mess) );
  Alarm(DEBUG,"%d slot->prepare_certificate_ready %d\n",   VAR.My_Server_ID, slot->prepare_certificate_ready);
  Alarm(DEBUG,"Received Prepare for %u from %u\n", prepare_specific->seq_num, mess->machine_id);

  /* If we've already created the certificate (or committed it), no need to
   *    keep trying to make a prepare certificate */
  if (slot->ordered || slot->prepare_certificate_ready)
    return;

  /* When the Prepare is applied, we call a function to see if a Prepare
   * certificate is ready. */
  if(ORDER_Prepare_Certificate_Ready(slot)) {
    ORDER_Move_Prepare_Certificate(slot);
    assert(slot->collected_all_parts);
    commit = ORDER_Construct_Commit(&slot->prepare_certificate.pre_prepare);
    Alarm(DEBUG, "Add: Commit for %d\n", slot->seq_num);
    SIG_Add_To_Pending_Messages(commit, BROADCAST, UTIL_Get_Timeliness(COMMIT));
    dec_ref_cnt(commit);
  }
}

int32u ORDER_Prepare_Certificate_Ready(ord_slot *slot)
{
  complete_pre_prepare_message *pp;
  signed_message **prepare;
  int32u pcount, sn;

  /* Need a Pre_Prepare for a Prepare Certificate to be ready */
  if(slot->collected_all_parts == 0)
    return 0;

  pp   = (complete_pre_prepare_message *)&(slot->complete_pre_prepare);
  prepare = (signed_message **)slot->prepare;
  pcount = 0;

  for(sn = 1; sn <= NUM_SERVERS; sn++) {
    if(prepare[sn] != NULL) {
      if(ORDER_Prepare_Matches_Pre_Prepare(prepare[sn], pp))
        pcount++;
      else
        Alarm(PRINT,"PREPARE didn't match pre-prepare while "
              "checking for prepare certificate.\n");
    }
  }

  /* If we have the Pre-Prepare and 2f + k Prepares, we're good to go */
  if (pcount >= 2*NUM_F + NUM_K) {   /* (n+f)/2 */
    Alarm(DEBUG,"%d pcount %d\n", VAR.My_Server_ID, pcount);
    return 1;
  }
  
  return 0;
}

int32u ORDER_Prepare_Matches_Pre_Prepare(signed_message *prepare,
					 complete_pre_prepare_message *pp)
{
  int32u seq_num, view;
  prepare_message *prepare_specific;
  byte digest[DIGEST_SIZE+1];

  seq_num = pp->seq_num;
  view    = pp->view;

  prepare_specific = (prepare_message*)(prepare+1);

  if(view != prepare_specific->view) {
    Alarm(DEBUG,"v %d %d %d\n", view, prepare_specific->view,
          prepare_specific->seq_num);
    return 0;
  }

  if(seq_num != prepare_specific->seq_num)
    return 0;

  /* Make a digest of the content of the pre_prepare, then compare it
   * to the digest in the Prepare. */
  OPENSSL_RSA_Make_Digest((byte*)pp, sizeof(*pp), digest);

  /* This compare was commented out */
  if(!OPENSSL_RSA_Digests_Equal(digest, prepare_specific->digest)) {
    Alarm(PRINT, "Digests don't match.\n");
    return 0;
  }

  return 1;
}

void ORDER_Move_Prepare_Certificate(ord_slot *slot)
{
  int32u pcount;
  int32u sn;
  signed_message **prepare_src;

  Alarm(DEBUG, "Made Prepare Certificate\n");
  
  pcount      = 0;
  prepare_src = (signed_message **)slot->prepare;

  /*Copy the completed Pre-Prepare into the Prepare Certificate */
  memcpy(&slot->prepare_certificate.pre_prepare, &slot->complete_pre_prepare,
         sizeof(complete_pre_prepare_message));

  for(sn = 1; sn <= NUM_SERVERS; sn++) {
    if (prepare_src[sn] != NULL) {
      
      if(ORDER_Prepare_Matches_Pre_Prepare(prepare_src[sn],
                                     &slot->prepare_certificate.pre_prepare)) {
        slot->prepare_certificate.prepare[sn] = prepare_src[sn];
        inc_ref_cnt(slot->prepare_certificate.prepare[sn]);
      } else {
        Alarm(PRINT,"PREPARE didn't match pre-prepare while "
              "moving prepare certificate.\n");
        //dec_ref_cnt(prepare_src[sn]);
      }
      //prepare_src[sn] = NULL;
    }
  }

  /* Mark that we have a Prepare Certificate.*/
  slot->prepare_certificate_ready = 1;
  if (DATA.ORD.high_seq < slot->seq_num)
    DATA.ORD.high_seq = slot->seq_num;
}

void ORDER_Process_Commit(signed_message *mess)
{
  ord_slot *slot;
  commit_message *commit_specific;

  Alarm(DEBUG, "%d ORDER_COMMIT\n",VAR.My_Server_ID);

  commit_specific = (commit_message*)(mess+1);

  /* If the view doesn't match ours, discard */
  if (commit_specific->view != DATA.View) {
    Alarm(PRINT, "  DROPPING COMMIT: comm->view = %d, seq = %d, My_View = %d\n",
            commit_specific->view, commit_specific->seq_num, DATA.View);
    return;
  }

  /* If we've already globally executed this seq, discard */
  if(commit_specific->seq_num <= DATA.ORD.ARU)
    return;

  /* Get the slot */
  slot = UTIL_Get_ORD_Slot(commit_specific->seq_num);
 
  /* If I have already received a commit from this server, return */
  if(slot->commit[mess->machine_id] != NULL)
    return;

  /* Otherwise, store it and see if a commit certificate is ready. */
  inc_ref_cnt(mess);
  slot->commit[mess->machine_id] = mess;

  /* If we already ordered it, we already have the certificate */
  if(slot->ordered)
    return;

  if(ORDER_Commit_Certificate_Ready(slot)) {
      ORDER_Move_Commit_Certificate(slot);
     
      /* Execute the commit certificate only the first time that we get it */
      if (slot->seq_num == 0) Alarm(PRINT, "Order process commit: about to execute commit with seq_num 0\n");
      ORDER_Execute_Commit(slot);
  }
}

int32u ORDER_Commit_Certificate_Ready(ord_slot *slot)
{
  complete_pre_prepare_message *pp;
  signed_message **commit;
  int32u pcount;
  int32u sn;

  if(slot->collected_all_parts == 0)
    return 0;

  pp = (complete_pre_prepare_message *)&(slot->complete_pre_prepare);
  commit = (signed_message **)slot->commit;
  pcount = 0;

  for(sn = 1; sn <= NUM_SERVERS; sn++) {
    if(commit[sn] != NULL) {
      if(ORDER_Commit_Matches_Pre_Prepare(commit[sn], pp))
        pcount++;
      else
	    Alarm(PRINT, "COMMIT didn't match Pre-Prepare\n");
    }
  }

  if(pcount >= (2*NUM_F + NUM_K + 1)) {   /* 2f+k+1 */
    Alarm(DEBUG,"%d pcount %d\n", VAR.My_Server_ID, pcount);
    return 1;
  }
  
  return 0;
}

int32u ORDER_Commit_Matches_Pre_Prepare(signed_message *commit,
					complete_pre_prepare_message *pp)
{
  int32u seq_num, view;
  commit_message *commit_specific;
  byte digest[DIGEST_SIZE+1]; 

  seq_num = pp->seq_num;
  view    = pp->view;
  
  commit_specific = (commit_message*)(commit+1);

  if(view != commit_specific->view) {
    Alarm(DEBUG,"v %d %d %d\n", view, commit_specific->view,
          commit_specific->seq_num);
    return 0;
  }

  if(seq_num != commit_specific->seq_num)
    return 0;
  
  /* Make a digest of the content of the pre_prepare. */
  OPENSSL_RSA_Make_Digest((byte*)pp, sizeof(*pp), digest);

  if(!OPENSSL_RSA_Digests_Equal(digest, commit_specific->digest))
    return 0;
  
  return 1;
}

void ORDER_Move_Commit_Certificate(ord_slot *slot)
{
  int32u pcount;
  int32u sn;
  signed_message **commit_src;
  complete_pre_prepare_message *pp;

  Alarm(DEBUG, "Made commit certificate.\n");

  pcount     = 0;
  commit_src = (signed_message **)slot->commit;
  
  for(sn = 1; sn <= NUM_SERVERS; sn++) {
    if((commit_src)[sn] != NULL) {
      Alarm(DEBUG,"ORDER_Move_Commit_Certificate %d\n", commit_src[sn]);

      if(slot->prepare_certificate_ready)
        pp = &slot->prepare_certificate.pre_prepare;
      else
        pp = &slot->complete_pre_prepare;

      if(ORDER_Commit_Matches_Pre_Prepare(commit_src[sn], pp)) {
        slot->commit_certificate.commit[sn] = commit_src[sn];
        inc_ref_cnt(slot->commit_certificate.commit[sn]);
      } else {
        Alarm(PRINT, "Commit didn't match pre-prepare while "
	      "moving commit certificate.\n");
        //dec_ref_cnt(commit_src[sn]);
      }
      //commit_src[sn] = NULL;
    }
  }

  slot->ordered = 1;
}

int32u ORDER_Ready_To_Execute(ord_slot *o_slot)
{
  complete_pre_prepare_message *pp;
  complete_pre_prepare_message *prev_pp;
  ord_slot *prev_ord_slot;
  po_slot *p_slot;
  int32u gseq, i, j;
  po_seq_pair prev_pop[NUM_SERVER_SLOTS];
  po_seq_pair cur_pop[NUM_SERVER_SLOTS];
  po_seq_pair ps, zero_ps = {0, 0};
  stdit it;

  if(o_slot->prepare_certificate_ready)
    pp = &o_slot->prepare_certificate.pre_prepare;
  else
    pp = &o_slot->complete_pre_prepare;
  
  gseq = pp->seq_num;

  /* First check to see if we've globally executed the previous
   * sequence number. */
  prev_ord_slot = UTIL_Get_ORD_Slot_If_Exists(gseq - 1);

  /* The previous slot is allowed to be NULL only if this is the first seq */
  if( (prev_ord_slot == NULL && gseq != 1) ||
      (prev_ord_slot != NULL && prev_ord_slot->executed == 0) ) {

    /* We can't execute this global slot yet because we have not yet
     * executed the previous global slot.  Put it on hold. */
    Alarm(PRINT, "Ordered slot %d but my aru is %d!\n", gseq, DATA.ORD.ARU);
    UTIL_Mark_ORD_Slot_As_Pending(gseq, o_slot);
    return 0;
  }

  /* If we already know there are po-requests missing, we can't execute */
  if(o_slot->num_remaining_for_execution > 0) {
    Alarm(PRINT, "%d requests missing for gseq %d\n", 
	  o_slot->num_remaining_for_execution, gseq);
    UTIL_Mark_ORD_Slot_As_Pending(gseq, o_slot);
    return 0;
  }

  /* See which PO-Requests are now eligible for execution. */
  if(prev_ord_slot == NULL) {
    assert(gseq == 1);

    for(i = 1; i <= NUM_SERVERS; i++)
      prev_pop[i] = zero_ps;
  }
  else {
    if(prev_ord_slot->prepare_certificate_ready)
      prev_pp = &prev_ord_slot->prepare_certificate.pre_prepare;
    else {
      prev_pp = &prev_ord_slot->complete_pre_prepare;
      assert(prev_ord_slot->collected_all_parts);
    }

    /* Set up the Prev_pop array */
    for(i = 1; i <= NUM_SERVERS; i++)
      prev_pop[i] = PRE_ORDER_Proof_ARU(i, prev_pp->cum_acks);
  }

  for(i = 1; i <= NUM_SERVERS; i++)
    cur_pop[i] = PRE_ORDER_Proof_ARU(i, pp->cum_acks);

  for(i = 1; i <= NUM_SERVERS; i++) {

    assert(prev_pop[i].incarnation <= cur_pop[i].incarnation);
    if (prev_pop[i].incarnation < cur_pop[i].incarnation) {
        prev_pop[i].incarnation = cur_pop[i].incarnation;
        prev_pop[i].seq_num = 0;
    }
    ps.incarnation = prev_pop[i].incarnation;

    for(j = prev_pop[i].seq_num + 1; j <= cur_pop[i].seq_num; j++) {
      ps.seq_num = j;
      p_slot = UTIL_Get_PO_Slot_If_Exists(i, ps);

      if(p_slot == NULL || p_slot->po_request == NULL) {
        Alarm(PRINT, "Seq %d not ready, missing: %d %d %d\n", gseq, i, 
                ps.incarnation, ps.seq_num);

        o_slot->num_remaining_for_execution++;
        Alarm(DEBUG, "Setting ord_slots num_remaining to %d\n",
              o_slot->num_remaining_for_execution);

        /* Insert a pointer to (i, j) into the map */
        inc_ref_cnt(o_slot);
        stdhash_insert(&DATA.PO.Pending_Execution[i], &it, &ps, &o_slot);
      }
    }
  }

  /* If any PO-Request was missing, the slot is not ready to be executed. */
  if(o_slot->num_remaining_for_execution > 0) {
    Alarm(PRINT, "Not executing global seq %d, waiting for %d requests\n",
          gseq, o_slot->num_remaining_for_execution);
    UTIL_Mark_ORD_Slot_As_Pending(gseq, o_slot);
    return 0;
  }
  
  return 1;
}

void ORDER_Execute_Commit(ord_slot *o_slot)
{
  complete_pre_prepare_message *prev_pp;
  signed_message *po_request, *up_contents;
  signed_update_message *up, no_op;
  po_request_message *po_request_specific;
  ord_certificate_message *ord_cert;
  ord_slot *prev_ord_slot;
  po_slot *p_slot;
  po_id pid;
  po_seq_pair prev_pop[NUM_SERVER_SLOTS];
  po_seq_pair cur_pop[NUM_SERVER_SLOTS];
  po_seq_pair ps, ps_update, zero_ps = {0, 0};
  int32u gseq, i, j, k, num_events;
  signed_message *event;
  char *p;
  int32u wa_bytes, event_idx, event_tot;
  complete_pre_prepare_message *pp;
  stddll eventq;
  stdit it;
  sp_time t;

  assert(o_slot);

  Alarm(DEBUG, "Trying to execute Commit for Ord seq %d!\n", o_slot->seq_num);

  if(o_slot->prepare_certificate_ready)
    pp = &o_slot->prepare_certificate.pre_prepare;
  else
    pp = &o_slot->complete_pre_prepare;

  gseq = pp->seq_num;

  if (gseq == 0) Alarm(PRINT, "Order Execute commit, seq 0: slot seq == %d!\n", o_slot->seq_num);
  if(!ORDER_Ready_To_Execute(o_slot)) {
    Alarm(DEBUG, "Not yet ready to execute seq %d\n", gseq);
    /*if (gseq > DATA.ORD.ARU + GC_LAG) {
        Alarm(EXIT, "Fell too far behind: seq %d, ARU %d, GC_LAG %d\n", gseq, DATA.ORD.ARU, GC_LAG);
    } 
    if (DATA.PR.catchup_target < DATA.ORD.ARU + 1)
        DATA.PR.catchup_target = DATA.ORD.ARU + 1;
    if (DATA.PR.recovery_in_progress == 0) {
        DATA.PR.recovery_in_progress = 1;
        PR_Catchup_Periodically(0, NULL);
    } */
    return;
  }

  Alarm(DEBUG, "Executing Commit for Ord seq %d!\n", gseq);

  /* Get the previous ord_slot if it exists. If it doesn't exist,
   * then this better be the first sequence number! */
  prev_ord_slot = UTIL_Get_ORD_Slot_If_Exists(gseq - 1);

  if(prev_ord_slot == NULL) {
    assert(gseq == 1);
    
    Alarm(DEBUG, "Gseq was 1, setting all in prev_pop to 0\n");
    for(i = 1; i <= NUM_SERVERS; i++)
      prev_pop[i] = zero_ps;
  }
  else {
    assert(prev_ord_slot->executed);

    if(prev_ord_slot->prepare_certificate_ready)
      prev_pp = &(prev_ord_slot->prepare_certificate.pre_prepare);
    else
      prev_pp = &prev_ord_slot->complete_pre_prepare;
    
    /* Set up the Prev_pop array */
    for(i = 1; i <= NUM_SERVERS; i++)
      prev_pop[i] = PRE_ORDER_Proof_ARU(i, prev_pp->cum_acks);
  }
  
  for(i = 1; i <= NUM_SERVERS; i++)
    cur_pop[i] = PRE_ORDER_Proof_ARU(i, pp->cum_acks);

  /* printf("++++++++++ EXECUTING MATRIX %u++++++++++\n", pp->seq_num);
  for (i = 0; i < NUM_SERVERS; i++)
  {
    for (j = 0; j < NUM_SERVERS; j++)
    {
        printf("(%u, %u) ", pp->cum_acks[i].cum_ack.ack_for_server[j].incarnation, pp->cum_acks[i].cum_ack.ack_for_server[j].seq_num);
    }
    printf("\n");
  } */

#if 0
 Alarm(PRINT, "Prevpop = [ ");
  for(i = 1; i <= NUM_SERVERS; i++)
    Alarm(PRINT, "%d ", prev_pop[i]);
  Alarm(PRINT, "]\n");


  Alarm(PRINT, "Cur_pop = [ ");
  for(i = 1; i <= NUM_SERVERS; i++) {
    Alarm(PRINT, "%d ", cur_pop[i]);
  }  
  Alarm(PRINT, "]\n");

  UTIL_Print_Time();
#endif
 
  //if (VAR.My_Server_ID == 4 && gseq == 100)
  //if (VAR.My_Server_ID == 4 && gseq > 100 && gseq <= 102)
  //  return;

  /* Mark this slot as executed */
  o_slot->executed = 1;
  assert(gseq == (DATA.ORD.ARU + 1));
  DATA.ORD.ARU++;

  if (DATA.ORD.ARU % PRINT_PROGRESS == 0)
    Alarm(PRINT, "Executed through ordinal %u\n", DATA.ORD.ARU);

  event_tot = 0;
  stddll_construct(&eventq, sizeof(signed_message *));

  for(i = 1; i <= NUM_SERVERS; i++) {

    assert(prev_pop[i].incarnation <= cur_pop[i].incarnation);
    if (prev_pop[i].incarnation < cur_pop[i].incarnation) {

        /* Clear out any po slots for this replica that will never be ordered
         * (because they are from an old incarnation and were not ordered
         * before the incarnation change */
        stdhash_begin(&DATA.PO.History[i], &it);
        while (!stdhash_is_end(&DATA.PO.History[i], &it)) {
            p_slot = *(po_slot **)stdit_val(&it);

            if (p_slot->seq.incarnation >= cur_pop[i].incarnation ||
                PRE_ORDER_Seq_Compare(p_slot->seq, prev_pop[i]) <= 0) {
                stdit_next(&it);
                continue;
            }

            Alarm(PRINT, "Cleanup: erasing PO slot [%u,%u,%u]\n", i, 
                          p_slot->seq.incarnation, p_slot->seq.seq_num);
            PRE_ORDER_Garbage_Collect_PO_Slot(i, p_slot->seq, 0);
            stdhash_erase(&DATA.PO.History[i], &it);
        }

        /* Update prev_pop to start at beginning of current incarnation (since
         * we just cleared out everything before that */
        prev_pop[i].incarnation = cur_pop[i].incarnation;
        prev_pop[i].seq_num = 0;
    }
    ps.incarnation = prev_pop[i].incarnation;

    for(j = prev_pop[i].seq_num + 1; j <= cur_pop[i].seq_num; j++) {
      
      ps.seq_num = j;
      p_slot = UTIL_Get_PO_Slot_If_Exists(i, ps);
      assert(p_slot);

      po_request_specific = NULL;
      po_request          = p_slot->po_request;
      assert(po_request);

      po_request_specific = (po_request_message *)(po_request + 1);
      num_events          = po_request_specific->num_events;
      
      DATA.ORD.events_ordered += num_events;
      Alarm(DEBUG, "Set events_ordered to %d\n", 
	    DATA.ORD.events_ordered);

      /* We now need to queue up these events for execution we just ordered. Go 
       * through all of the events in the PO-Request and queue each one. */
      p = (char *)(po_request_specific + 1);
      for(k = 0; k < num_events; k++) {
	    event = (signed_message *)p;
        up = (signed_update_message *)p;
        
        /* If this event corresponds to a new client update that we've never
         * executed (or delivered), enqueue to be sent at the end of this loop.
         * Otherwise, ignore it as duplicate */
        ps_update.incarnation = up->update.incarnation;
        ps_update.seq_num = up->update.seq_num;
        up_contents = (signed_message *)(up->update_contents);
        if (up_contents->type == CLIENT_STATE_TRANSFER) {
            Alarm(DEBUG, "  STATE TRANSFER! [%u,%u]\n", ps_update.incarnation, ps_update.seq_num);
        }
        /* if (PRE_ORDER_Seq_Compare(DATA.PO.exec_client_seq[up->update.server_id],
                    ps_update) < 0)
        { */
        stddll_push_back(&eventq, &event);
        event_tot++;
        //DATA.PO.exec_client_seq[up->update.server_id] = ps_update;
        Alarm(DEBUG, "  ADDING %u [%u, %u] for delivery\n", up->update.server_id, 
                    ps_update.incarnation, ps_update.seq_num);
        //}
        /* else {
            up_contents = (signed_message *)(up->update_contents);
            if (up_contents->type == CLIENT_STATE_TRANSFER) {
                printf("  DROPPING STATE TRANSFER! [%u,%u] , exec = [%u,%u]\n",
                    ps_update.incarnation, ps_update.seq_num,
                    DATA.PO.exec_client_seq[up->update.server_id].incarnation,
                    DATA.PO.exec_client_seq[up->update.server_id].seq_num);
            }
        } */

	    /* If this is a wide-area message, then some digest bytes may 
	    * have been appended.  Take these into consideration. */
	    wa_bytes = 0;
	    p += event->len + sizeof(signed_message) + wa_bytes;
      }

      /* We've executed all of the events in pre-order slot, so clean
       * it up. */
      //PRE_ORDER_Garbage_Collect_PO_Slot(i, j, 1);
      if (i == VAR.My_Server_ID) {
        /* if (j != DATA.PO.po_seq_executed.seq_num + 1)
            printf("uh oh! [%u,%u], po_seq_executed + 1 = %u + 1\n", i, j, DATA.PO.po_seq_executed);
        assert(j == DATA.PO.po_seq_executed + 1); */
        if (DATA.PO.po_seq.incarnation != DATA.PO.po_seq_executed.incarnation)
            Alarm(PRINT, "PO_seq.incarnation (%u) != PO_seq_executed.incarnation (%u)\n");
        if (DATA.PO.po_seq.seq_num - DATA.PO.po_seq_executed.seq_num == MAX_PO_IN_FLIGHT) {
          Alarm(DEBUG, "Execute: Reattaching client sd\n");
#if USE_IPC_CLIENT
          E_attach_fd(NET.from_client_sd, READ_FD, Net_Srv_Recv, IPC_SOURCE, NULL, MEDIUM_PRIORITY);
#else
          E_attach_fd(NET.from_client_sd, READ_FD, Net_Srv_Recv, TCP_SOURCE, NULL, MEDIUM_PRIORITY);
#endif
        }

        DATA.PO.po_seq_executed = ps;
      }
      DATA.PO.last_executed_po_reqs[i] = ps;
      Alarm(DEBUG, "Executed %u %u for %u\n", DATA.PO.last_executed_po_reqs[i].incarnation, 
                DATA.PO.last_executed_po_reqs[i].seq_num, i);

      pid.server_id = i;
      pid.seq = ps;
      stddll_push_back(&o_slot->po_slot_list, &pid);
      //printf("        Executing [%d,%d]\n", i, j);
    }
  }

  /* Now, time to execute (deliver) things to the client. In the case that PO_requests
   * containing client updates were present, simply run through the event queue 
   * and deliver to client. However, if the queue is empty, indicating that this
   * was an "empty" pre-prepare, create a special No-Op message to send to the
   * client to keep sequential delivery in tact. */
  event_idx = 0;
  if (event_tot > 0) {
    for (stddll_begin(&eventq, &it); !stddll_is_end(&eventq, &it); stdit_next(&it)) {
      event = *(signed_message **)stdit_val(&it);
	  ORDER_Execute_Event(event, pp->seq_num, ++event_idx, event_tot);
    }
  }
  else {
    memset(&no_op, 0, sizeof(signed_update_message));
    event = (signed_message *)&no_op;
    up = (signed_update_message *)&no_op;
    up_contents = (signed_message *)(up->update_contents);

    event->machine_id = VAR.My_Server_ID;
    event->type = UPDATE;
    event->len = sizeof(signed_update_message) - sizeof(signed_message);

    up->update.server_id = VAR.My_Server_ID;
    up->update.incarnation = DATA.PO.intro_client_seq[VAR.My_Server_ID].incarnation;
    up->update.seq_num = 0;

    up_contents->machine_id = VAR.My_Server_ID;
    up_contents->type = CLIENT_NO_OP;
    
    ORDER_Execute_Event(event, pp->seq_num, 1, 1); 
  }
  stddll_destruct(&eventq);

  RECON_Do_Recon(o_slot);
  /* Garbage collect gseq-1 when I commit gseq */
  //ORDER_Attempt_To_Garbage_Collect_ORD_Slot(gseq-1);

  /* Create the certificate for this Ordinal */
  o_slot->ord_certificate = PR_Construct_ORD_Certificate(o_slot);

  /* Only replace the periodic ord cert that we send (which
   * replicas may jump to) if its a commit */
  if (o_slot->type == SLOT_COMMIT) {

    /* Store this as our latest cert, update flag for periodic,
     *    and start periodic sending (if not already) */
    if (DATA.PR.last_ord_cert[VAR.My_Server_ID] != NULL) {
      dec_ref_cnt(DATA.PR.last_ord_cert[VAR.My_Server_ID]);
    }
    DATA.PR.last_ord_cert[VAR.My_Server_ID] = UTIL_New_Signed_Message();
    memcpy(DATA.PR.last_ord_cert[VAR.My_Server_ID], o_slot->ord_certificate,
              sizeof(signed_message) + o_slot->ord_certificate->len);
    ord_cert = (ord_certificate_message *)(DATA.PR.last_ord_cert[VAR.My_Server_ID] + 1);
    ord_cert->flag = CERT_PERIODIC;
    if (!E_in_queue(PR_Send_ORD_Cert_Periodically, 0, NULL)) {
      t.sec  = ORD_CERT_PERIODICALLY_SEC;
      t.usec = ORD_CERT_PERIODICALLY_USEC;
      E_queue(PR_Send_ORD_Cert_Periodically, 0, NULL, t);
    }
  }

  /* If we are still working on a view change, check if we now
   *    have collected complete state from any one */
  if (DATA.VIEW.view_change_done == 0)
    for (i = 1; i <= NUM_SERVERS; i++) 
      VIEW_Check_Complete_State(i);

  /* If the view change is done, and this is the first ord that we
   * are about to execute in the view, set the flag, which will 
   * cause some view-change related periodic functions to stop
   * being periodic (until the next view change) */
  if (DATA.VIEW.executed_ord == 0) {
    DATA.VIEW.executed_ord = 1;
  }

  /* Garbage collect gseq-GC_LAG when I commit gseq */
  if (gseq > GC_LAG)
    ORDER_Attempt_To_Garbage_Collect_ORD_Slot(gseq - GC_LAG);
  
  //t.sec = 0;
  //t.usec = 1000;
  //E_queue(ORDER_Attempt_To_Execute_Pending_Local_Commits, 0, 0, t);
  ORDER_Attempt_To_Execute_Pending_Commits(0, 0);
}

void ORDER_Attempt_To_Execute_Pending_Commits(int dummy, void *dummyp)
{
  ord_slot *slot;
  int32u i;
  stdit it;

  i = DATA.ORD.ARU+1;

  stdhash_find(&DATA.ORD.Pending_Execution, &it, &i);

  if(!stdhash_is_end(&DATA.ORD.Pending_Execution, &it)) {
    slot = *((ord_slot **)stdhash_it_val(&it));

    Alarm(DEBUG, "Went back and tried to execute %d\n", i);

    /* If it's not ready, it will be re-added to the hash */ 
    if (slot->seq_num == 0) Alarm(PRINT, "Order Attempt to Execute Pending commit, seq 0, i %d!\n", i);
    ORDER_Execute_Commit(slot);
  }
}

void ORDER_Execute_Event(signed_message *event, int32u ord_num, int32u event_idx, int32u event_tot)
{
  /* There should be one case: we execute an update */
  assert(event->type == UPDATE);

  Alarm(DEBUG, "Executing an update: %d (%d %d)\n",
    ((signed_update_message *)event)->update.server_id,
	((signed_update_message *)event)->update.incarnation,
	((signed_update_message *)event)->update.seq_num);
  ORDER_Execute_Update(event, ord_num, event_idx, event_tot);
}

void ORDER_Execute_Update(signed_message *mess, int32u ord_num, int32u event_idx, int32u event_tot)
{
  signed_update_message *u;

  assert(mess->type == UPDATE);

  BENCH.updates_executed++;
  if(BENCH.updates_executed == 1)
    UTIL_Stopwatch_Start(&BENCH.test_stopwatch);

  //if(BENCH.updates_executed % 50 == 0)
  if(BENCH.updates_executed % (BENCHMARK_END_RUN/100) == 0)
    Alarm(PRINT, "Executed %d updates\n", BENCH.updates_executed);

  u = (signed_update_message *)mess;
  Alarm(DEBUG, "Ordered update with timestamp %d %d\n", 
            u->update.incarnation, u->update.seq_num);

  /* For Benchmarking Prime, we only send ACKs back to clients that
   * are connected to this server, and record ordered updates as
   * they are executed. For SCADA Prime, we are not writing to file
   * and are sending all ordered updates to all clients, MSG included */
  /* if(u->update.server_id == VAR.My_Server_ID)
    UTIL_Respond_To_Client(mess->machine_id, u->update.time_stamp);

  UTIL_State_Machine_Output(u); */

  UTIL_Respond_To_Client(mess->machine_id, u->update.incarnation, 
            u->update.seq_num, ord_num, event_idx, event_tot, 
            u->update_contents);

  if(BENCH.updates_executed == BENCHMARK_END_RUN) {
    ORDER_Cleanup();
    exit(0);
  }
}

void ORDER_Flood_Pre_Prepare(signed_message *mess)
{
  int32u part_num;
  pre_prepare_message *pp_specific;
  ord_slot *slot;

  pp_specific = (pre_prepare_message *)(mess+1);
  part_num    = pp_specific->part_num;
  
  slot = UTIL_Get_ORD_Slot(pp_specific->seq_num);

  if (!UTIL_I_Am_Leader()) {
#if THROTTLE_OUTGOING_MESSAGES
    int32u dest_bits, i;
    /* Send it to all but the leader and myself */
    dest_bits = 0;
    for(i = 1; i <= NUM_SERVERS; i++) {
      if(i == UTIL_Leader() || i == VAR.My_Server_ID)
	continue;
      UTIL_Bitmap_Set(&dest_bits, i);
    }
    /* Note: Can't just get the traffic class from UTIL_Get_Timeliness 
     * because we need to distinguish flooded Pre-Prepares from regular
     * Pre-Prepares. */
    NET_Add_To_Pending_Messages(mess, dest_bits, BOUNDED_TRAFFIC_CLASS);
#else
    UTIL_Broadcast(mess);
    BENCH.num_flooded_pre_prepares++;
#endif
  }

  slot->forwarded_pre_prepare_parts[part_num] = TRUE;
  slot->num_forwarded_parts++;
 
  /* If we've forwarded all parts, try to update the white line */
  if(slot->num_forwarded_parts == slot->total_parts)
    ORDER_Update_Forwarding_White_Line();
}

void ORDER_Update_Forwarding_White_Line()
{
  ord_slot *slot;
  int32u seq;

  while(1) {

    seq = DATA.ORD.forwarding_white_line + 1;

    slot = UTIL_Get_ORD_Slot_If_Exists(seq);
    
    if(slot != NULL && 
       slot->collected_all_parts && 
       slot->num_forwarded_parts == slot->total_parts) {
      
      ORDER_Attempt_To_Garbage_Collect_ORD_Slot(seq);
      DATA.ORD.forwarding_white_line++;
    }
    else
      break;
  }
}

void ORDER_Attempt_To_Garbage_Collect_ORD_Slot(int32u seq)
{
  ord_slot *slot;

  slot = UTIL_Get_ORD_Slot_If_Exists(seq);

  if(slot == NULL)
    return;
  
  /* Need to have received and forwarded all parts of the Pre-Prepare */
  if(slot->collected_all_parts == 0 || DATA.ORD.forwarding_white_line < seq)
  {
    //if (DATA.ORD.forwarding_white_line < seq-1)
        Alarm(DEBUG, "Can't garbage collect slot %d: collected_all_parts = %d, forwarding_white_line = %d\n", seq, slot->collected_all_parts, DATA.ORD.forwarding_white_line);
    return;
  }

  /* Need to have globally ordered this slot and the next one */
  //if(DATA.ORD.ARU < (seq+1))
  if(DATA.ORD.ARU < (seq+GC_LAG))
  {
    Alarm(DEBUG, "Can't garbage collect slot %d: ARU %d < seq+1 %d\n", seq, DATA.ORD.ARU, seq+1);
    return;
  }

  /* Need to have reconciled this slot and the next one */
  if(DATA.ORD.recon_white_line < (seq+1))
  {
    Alarm(PRINT, "Can't garbage collect slot %d: recon_white_line %d < seq+1 %d\n", seq, DATA.ORD.recon_white_line, seq+1);
    return;
  }

  ORDER_Garbage_Collect_ORD_Slot(slot, 1);
}

void ORDER_Garbage_Collect_ORD_Slot(ord_slot *slot, int erase)
{
  int32u i, seq;
  ord_slot *pending_slot;
  stdit it;
  po_id *pid;

  assert(slot != NULL);
  seq = slot->seq_num;

  /* Garbage collect any PO slots made eligible by this ord_slot */
  while (!stddll_empty(&slot->po_slot_list)) {
    stddll_begin(&slot->po_slot_list, &it);
    pid = (po_id *)stddll_it_val(&it);
    PRE_ORDER_Garbage_Collect_PO_Slot(pid->server_id, pid->seq, 1);
    stddll_pop_front(&slot->po_slot_list);
  }
  stddll_destruct(&slot->po_slot_list);

  /* Cleanup any pre_prepare_part message */
  for(i = 1; i <= MAX_PRE_PREPARE_PARTS; i++) {
    if (slot->pre_prepare_parts_msg[i])
      dec_ref_cnt(slot->pre_prepare_parts_msg[i]);
  }

  /* Cleanup the ordinal certificate */
  if (slot->ord_certificate)
    dec_ref_cnt(slot->ord_certificate);

  /* We'll never need or allocate this slot again, so clear it out. */
  for(i = 1; i <= NUM_SERVERS; i++) {
    if(slot->prepare[i])
      dec_ref_cnt(slot->prepare[i]);
    
    if(slot->commit[i])
      dec_ref_cnt(slot->commit[i]);
    
    if(slot->prepare_certificate.prepare[i])
      dec_ref_cnt(slot->prepare_certificate.prepare[i]);
    
    if(slot->commit_certificate.commit[i])
      dec_ref_cnt(slot->commit_certificate.commit[i]);

    if(slot->pp_catchup_replies[i])
      dec_ref_cnt(slot->pp_catchup_replies[i]);
  }

  /* If this slot was pending execution, we can now mark it as not pending */
  pending_slot = UTIL_Get_Pending_ORD_Slot_If_Exists(seq);
  if(pending_slot != NULL) {
    stdhash_erase_key(&DATA.ORD.Pending_Execution, &seq);
    dec_ref_cnt(pending_slot);
  }

  /* Now get rid of the slot itself */
  dec_ref_cnt(slot);
  if (erase)
  {
    stdhash_erase_key(&DATA.ORD.History, &seq);
    if (UTIL_Get_ORD_Slot_If_Exists(seq) != NULL) {
        Alarm(PRINT, " SLOT NOT ERASED!! Seq = %d\n", seq);
    }
  }

  if(seq % 20 == 0)
    Alarm(DEBUG, "Garbage collected Local ORD slot %d\n", seq);
}

void ORDER_Cleanup()
{
  int32u i;
  
  UTIL_Stopwatch_Stop(&BENCH.test_stopwatch);

  Alarm(PRINT, "----------------Statistics----------------------\n");
  Alarm(PRINT, "Average updates per PO-Request: %f\n", 
	(float) BENCH.total_updates_requested / 
	BENCH.num_po_requests_sent);
  
  Alarm(PRINT, "Average acks per PO-Ack: %f\n",
	(float) BENCH.num_acks / BENCH.num_po_acks_sent);
  
  Alarm(PRINT, "Number of flooded Pre-Prepares: %d\n", 
	BENCH.num_flooded_pre_prepares);

  Alarm(PRINT, "Total number of signatures: %d\n", BENCH.num_signatures);
  Alarm(PRINT, "Average signature batch size: %f\n",
	(double)BENCH.total_signed_messages / BENCH.num_signatures);
  Alarm(PRINT, "Maximum signature batch size: %d\n",
	BENCH.max_signature_batch_size);
  
  Alarm(PRINT, "Number of messages sent of type:\n");
  for(i = 1; i < MAX_MESS_TYPE; i++)
    Alarm(PRINT, "  %-15s ---> %d\n", UTIL_Type_To_String(i), 
	  BENCH.signature_types[i]);

  UTIL_DLL_Clear(&DATA.PO.po_request_dll);
  UTIL_DLL_Clear(&DATA.PO.proof_matrix_dll);

  UTIL_DLL_Clear(&DATA.SIG.pending_messages_dll);

  /* for(i = 1; i <= 300; i++) {
    if(NET.client_sd[i] > 2)
      close(NET.client_sd[i]);
  } */
  close(NET.from_client_sd);
  E_detach_fd(NET.from_client_sd, READ_FD);
  NET.from_client_sd = 0;
#if USE_IPC_CLIENT
  close(NET.to_client_sd);
#endif
  NET.to_client_sd = 0;
  Alarm(PRINT, "------------------------------------------------\n");
  Alarm(PRINT, "Throughput = %f updates/sec\n",
	(double) DATA.ORD.events_ordered / 
	UTIL_Stopwatch_Elapsed(&BENCH.test_stopwatch));
  
  /* fclose(BENCH.state_machine_fp); */

  sleep(2);
}
