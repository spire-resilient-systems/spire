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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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
#include "suspect_leader.h"
#include "view_change.h"
#include "catchup.h"
#include "proactive_recovery.h"

#include "spu_alarm.h"
#include "spu_memory.h"

/* Global variables */
extern server_variables   VAR;
extern network_variables  NET;
extern server_data_struct DATA;
extern benchmark_struct   BENCH;

/* Local functions */
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

//int32u ORDER_Pre_Prepare_Backward_Progress(complete_pre_prepare_message *pp);
void ORDER_Flood_PP_Wrapper(int d, void *message);

void ORDER_Initialize_Data_Structure()
{
  DATA.ORD.ARU                    = 0;
  DATA.ORD.ppARU                  = 0;
  DATA.ORD.high_prepared          = 0;
  DATA.ORD.high_committed         = 0;
  DATA.ORD.events_ordered         = 0;
  DATA.ORD.seq                    = 1;
  DATA.ORD.should_send_pp         = 0;
  DATA.ORD.forwarding_white_line  = 0;
  DATA.ORD.recon_white_line       = 0;
  DATA.ORD.stable_catchup         = 0;

  if (CATCHUP_HISTORY > 0)
    DATA.ORD.gc_width = CATCHUP_HISTORY;
  else
    DATA.ORD.gc_width = 1;

  stdhash_construct(&DATA.ORD.History, sizeof(int32u), 
		    sizeof(ord_slot *), NULL, NULL, 0);
  
  stdhash_construct(&DATA.ORD.Pending_Execution, sizeof(int32u),
		    sizeof(ord_slot *), NULL, NULL, 0);

  UTIL_Stopwatch_Start(&DATA.ORD.pre_prepare_sw);

  Alarm(DEBUG, "Initialized Ordering data structure.\n");

  /* If I'm the leader, try to start sending Pre-Prepares */
  /* PRTODO - move these to when finishing recovery (or rest) */
  /* if (UTIL_I_Am_Leader())
    ORDER_Periodically(0, NULL);

  ORDER_Periodic_Retrans(0, NULL); */
}

void ORDER_Upon_Reset()
{
    ord_slot *o_slot;
    stdit it;

    stdhash_begin(&DATA.ORD.History, &it);
    while (!stdhash_is_end(&DATA.ORD.History, &it)) {
        o_slot = *(ord_slot**)stdit_val(&it);
        ORDER_Garbage_Collect_ORD_Slot(o_slot, 0);
        stdhash_erase(&DATA.ORD.History, &it);
    }
    stdhash_destruct(&DATA.ORD.History);

    /* DATA.ORD.Pending_Execution is already cleared in GC, but needs destruction */
    stdhash_destruct(&DATA.ORD.Pending_Execution);
}

void ORDER_Periodically(int dummy, void *dummyp)
{
  sp_time t;
  float elap;

  if (!UTIL_I_Am_Leader())
    return;

  ORDER_Send_One_Pre_Prepare(TIMEOUT_CALLER);
  t.sec  = PRE_PREPARE_SEC; 
  t.usec = PRE_PREPARE_USEC;

  if (DATA.ORD.delay_attack == 1) {
    UTIL_Stopwatch_Stop(&DATA.ORD.leader_duration_sw);
    elap = UTIL_Stopwatch_Elapsed(&DATA.ORD.leader_duration_sw);

    t.usec += ((int)(elap/DATA.ORD.step_duration)) * DATA.ORD.microseconds_delayed;
    if (t.usec >= 1000000) {
      t.sec += (t.usec / 1000000);
      t.usec = (t.usec % 1000000);
    }  
  }

  E_queue(ORDER_Periodically, 0, NULL, t);
}

int32u ORDER_Send_One_Pre_Prepare(int32u caller)
{
  signed_message *mset[VAR.Num_Servers];
  signed_message *pp;
  pre_prepare_message *pp_specific;
  po_aru_signed_message *cum_acks;
  po_seq_pair ps;
  int32u num_parts, i;
  double time;
  ord_slot *slot;

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

  //if(PRE_ORDER_Latest_Proof_Sent())
  //if(!PRE_ORDER_Latest_Proof_Updated())
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
 
  //PRE_ORDER_Update_Latest_Proof_Sent();
  PRE_ORDER_Latest_Proof_Updated();
  DATA.ORD.should_send_pp = 0;

  UTIL_Stopwatch_Stop(&DATA.ORD.leader_duration_sw);
  if (DATA.ORD.inconsistent_pp_attack == 1 &&
        (UTIL_Stopwatch_Elapsed(&DATA.ORD.leader_duration_sw) > DATA.ORD.inconsistent_delay)) 
  {
    int32u dest_bits, cutoff;
    signed_message *attack_mess;

    cutoff = 0;
    if (DATA.ORD.inconsistent_pp_type == 2) {
        Alarm(PRINT, "Launching Inconsistent PP Attack #2. seq = %u\n", DATA.ORD.seq - 1);
        cutoff = VAR.Num_Servers/2;
    }
    else if (DATA.ORD.inconsistent_pp_type == 3) {
        Alarm(PRINT, "Launching Inconsistent PP Attack #3. seq = %u\n", DATA.ORD.seq - 1);
        cutoff = VAR.Num_Servers - 2;
    }
    else {
        Alarm(EXIT, "Invalid PP attack. Must be -a 2 or -a 3 on CMD line\n");
    }

    DATA.ORD.inconsistent_pp_attack = 0;
    DATA.ORD.inconsistent_pp_type = 0;

    attack_mess = UTIL_New_Signed_Message();
    memcpy(attack_mess, mset[1], UTIL_Message_Size(mset[1]));

    pp = (signed_message *)(attack_mess);
    pp_specific = (pre_prepare_message *)(pp + 1);
    cum_acks = (po_aru_signed_message *)(pp_specific + 1);
    /*MS2022: MAX_NUM_SERVERS as this is a packet with MAX_NUM_SERVERS in defines, we need to null the whole struct*/ 
    memset(cum_acks[VAR.My_Server_ID - 1].cum_ack.ack_for_server, 0, sizeof(po_seq_pair) * MAX_NUM_SERVERS);
    UTIL_RSA_Sign_Message(&cum_acks[VAR.My_Server_ID - 1].header);

    dest_bits = 0;
    for (i = 1; i <= cutoff; i++)
        UTIL_Bitmap_Set(&dest_bits, i);
    SIG_Add_To_Pending_Messages(mset[1], dest_bits, UTIL_Get_Timeliness(PRE_PREPARE));

    dest_bits = 0;
    for (i = cutoff + 1; i <= VAR.Num_Servers; i++) 
        UTIL_Bitmap_Set(&dest_bits, i);
    SIG_Add_To_Pending_Messages(attack_mess, dest_bits, UTIL_Get_Timeliness(PRE_PREPARE));

    dec_ref_cnt(mset[1]);
    dec_ref_cnt(attack_mess);
  }
  else {
    for(i = 1; i <= num_parts; i++) {
      Alarm(DEBUG, "Add: Pre-Prepare part %d \n", i);
      SIG_Add_To_Pending_Messages(mset[i], BROADCAST, 
                  UTIL_Get_Timeliness(PRE_PREPARE));
      dec_ref_cnt(mset[i]);
    }
  }

  /* We need to make sure this slot is created with made_eligible filled in. 
   * Most of the time, we will Process our own message after the SIG Batch
   * fires. But it may not. This ensures that at the cost of calling
   * PRE_ORDER_Proof_ARU now, rather than later), made eligible always exists */
  /* Note - this again uses the fact that the whole PP message fits in one
   * large signed message */
  pp = (signed_message *)(mset[1]);
  pp_specific = (pre_prepare_message *)(pp + 1);
  cum_acks = (po_aru_signed_message *)(pp_specific + 1);

  slot = UTIL_Get_ORD_Slot(pp_specific->seq_num);
  if (!slot->populated_eligible) {
    slot->populated_eligible = 1; 
    slot->view = pp_specific->view;
    for (i = 0; i < VAR.Num_Servers; i++) {
      ps = PRE_ORDER_Proof_ARU(i+1, cum_acks);
      if (PRE_ORDER_Seq_Compare(ps, pp_specific->last_executed[i]) > 0) 
        slot->made_eligible[i] = ps;
      else 
        slot->made_eligible[i] = pp_specific->last_executed[i];
    }    
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
  ord_slot *slot, *t_slot;
  pre_prepare_message *pp_specific;
  complete_pre_prepare_message *complete_pp;
  po_aru_signed_message *cum_acks;
  int32u i, index, part_num, num_acks_per_message;
  signed_message *commit, *new_leader;
  //util_stopwatch sw;
  //sp_time start;

  Alarm(STATUS, "%d Process Pre-Prepare\n", VAR.My_Server_ID);
  Alarm(DEBUG, "%d Process Pre-Prepare\n", VAR.My_Server_ID);

  pp_specific = (pre_prepare_message *)(mess+1);
  part_num    = pp_specific->part_num;

  /* We should only get Pre-Prepares that originate from the leader */
  /* if (mess->machine_id != UTIL_Leader()) {
    Alarm(PRINT, "ORDER_Process_Pre_Prepare: got pre-prepare from "
            "non-leader (%d) w/ seq = %u, ignoring\n", 
            mess->machine_id, pp_specific->seq_num);
    return;
  } */

  //Alarm(DEBUG, "PP info. seq = %d, ARU = %d, forw_white_line = %d\n",
  //      pp_specific->seq_num, DATA.ORD.ARU, DATA.ORD.forwarding_white_line);

  /* Check if the digest of the proposal message matches my own */
  if (!OPENSSL_RSA_Digests_Equal(pp_specific->proposal_digest, DATA.PR.proposal_digest)) {
    Alarm(PRINT, "Process_Pre_Prepare: PP proposal digest != My stored version\n");
    return;
  }

  if (!DATA.VIEW.view_change_done && pp_specific->view == DATA.View) 
    Alarm(PRINT, "Got pre-prepare before finishing view change! seq = %d, aru = %d\n", 
        pp_specific->seq_num, DATA.ORD.ARU);

  /* If we're done forwarding for this slot, and we've already reconciled
   * on this slot and the next, and we've already executed this slot and
   * the next one, then there's no reason to do anything else with this
   * sequence number. */
  if(pp_specific->seq_num <= DATA.ORD.forwarding_white_line &&
     (pp_specific->seq_num+1) <= DATA.ORD.recon_white_line &&
     (pp_specific->seq_num+1) <= DATA.ORD.ARU)
    return;

  /* Check the view on the pre-prepare?  */
  /* if (pp_specific->view != DATA.View) 
    return; */
  if (pp_specific->view > DATA.View)
    return;
  else if (pp_specific->view < DATA.View) {
    if (DATA.VIEW.view_change_done == 1)
      return;
    if (DATA.ORD.ARU > 0) {
        t_slot = UTIL_Get_ORD_Slot_If_Exists(DATA.ORD.ARU);
        assert(t_slot);
        if (pp_specific->view < t_slot->view)
          return;
    }
  }

  /* Now that the view is sound, make sure the correct replica who is the leader
   * of that view originated this pre-prepare */
  if (mess->machine_id != UTIL_Leader_Of_View(pp_specific->view)) {
    Alarm(PRINT, "ORDER_Process_PP: View %u. got pre-prepare from "
            "non-leader (%d) w/ seq = %u, ignoring. Should be from %u\n", 
            pp_specific->view, mess->machine_id, pp_specific->seq_num, 
            UTIL_Leader_Of_View(pp_specific->view));
    return;
  }
  
  /* Print statement for debugging */
  if (pp_specific->view < DATA.View)
    Alarm(PRINT, "Process_Pre_Prepare: Accept PP %u from machine_id %d in view %u while installing %u\n",
            pp_specific->seq_num, mess->machine_id,pp_specific->view, DATA.View);

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
    memcpy(&slot->complete_pre_prepare.proposal_digest, &pp_specific->proposal_digest, 
            DIGEST_SIZE);
    memcpy(&slot->complete_pre_prepare.last_executed, &pp_specific->last_executed, 
            sizeof(pp_specific->last_executed));
  }
  else {
    /* If from a different view, just ignore for view. One of us may be behind and
     * are still going through a VC to catch up */
    if (slot->view != pp_specific->view) {
        Alarm(PRINT, "PP already stored from view %u. Ignoring one from view %u\n",
                slot->view, pp_specific->view);
        return;
    }
    
    /* This is from the same leader. Check that tht content is the same. Only check
     * the view that the message is in in also our installed view. */
    if (slot->view == DATA.View && 
        memcmp(slot->pre_prepare_parts_msg[1], mess, UTIL_Message_Size(mess)) != 0) 
    {
        printf(" mess_len = %u, stored_len = %u\n", UTIL_Message_Size(mess), 
                UTIL_Message_Size(slot->pre_prepare_parts_msg[1]));
        Alarm(PRINT, "Inconsistent PP! Suspecting leader! Should flood this proof\n");
        Alarm(PRINT, "  seq %d, view %d, cpp seq %d, cpp view %d\n", 
                        pp_specific->seq_num, pp_specific->view, 
                        slot->complete_pre_prepare.seq_num, slot->complete_pre_prepare.view);

        /* ORDER_Flood_Pre_Prepare(mess); */
        if (DATA.SUSP.leader_suspected == 0) {
            DATA.SUSP.leader_suspected = 1;
            new_leader = SUSPECT_Construct_New_Leader();
            UTIL_RSA_Sign_Message(new_leader);
            SUSPECT_Process_New_Leader(new_leader);
            SUSPECT_New_Leader_Periodically(0, NULL);
            dec_ref_cnt(new_leader);
        }   
        return;
    }
  }

  /* If we've already collected all of the parts, ignore */
  if(slot->collected_all_parts)
    return;

  /* If we already have this part, done for now */
  part_num          = pp_specific->part_num;
  if(slot->pre_prepare_parts[part_num] == 1)
    return;

  /* timing tests */
  //start.sec  = pp_specific->sec;
  //start.usec = pp_specific->usec;
  //sw.start = start;
  //UTIL_Stopwatch_Stop(&sw);
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
  /* sp_time delay;
  delay.sec  = 0;
  delay.usec = 15000;
  E_queue(ORDER_Flood_PP_Wrapper, 0, (void *)mess, delay); */

  if (slot->num_parts_collected < slot->total_parts)
    return;

  slot->collected_all_parts = 1;

  /* A Prepare certificate could be ready if we get some Prepares
   * before we get the Pre-Prepare. */
  if(!slot->prepare_certificate_ready && !slot->ordered && 
      ORDER_Prepare_Certificate_Ready(slot)) 
  {
    ORDER_Move_Prepare_Certificate(slot);
    if (DATA.VIEW.view_change_done == 1) {
        commit = ORDER_Construct_Commit(&slot->prepare_certificate.pre_prepare);
        Alarm(DEBUG, "Add: Commit for %d\n", slot->seq_num);
        SIG_Add_To_Pending_Messages(commit, BROADCAST, UTIL_Get_Timeliness(COMMIT));
        dec_ref_cnt(commit);
        slot->sent_commit = 1;
    }
  }

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
  for(i = 0; i < VAR.Num_Servers; i++) {
    signed_message *m = (signed_message *)&cum_acks[i];
    PRE_ORDER_Process_PO_ARU(m); 
  }

  /* Should only update knowledge of what has made it into a valid
   * pre-prepare and send prepare if I actually have the previous pre-prepare
   * AND can verify that this pre-prepare does not make "backward progress"
   * relative to that one. Means that I may need to send multiple prepares if I
   * fill in a hole */
  if (complete_pp->seq_num != DATA.ORD.ppARU + 1) {
    // Not yet ready to say whether this is valid. Will need to check when I
    // fill in a hole
    Alarm(PRINT, "ORDER_Process_Pre_Prepare: Don't have valid PP to calculate "
                 "delta for %u\n", complete_pp->seq_num);
    return;
  }

  /* Since you have the previous PP, we can update the made_eligible based on
   * the current matrix and last_executed and also send prepares */
  ORDER_Send_Prepares();

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
  ord_slot *slot, *prev_slot;
  complete_pre_prepare_message *complete_pp;
  po_aru_signed_message *cum_acks;
  signed_message *m, *prepare;
  po_seq_pair ps, zero_ps = {0, 0};
  int32u i, j, covered, lower, higher;
  stdit it;
  tat_challenge *tatc;

  slot = UTIL_Get_ORD_Slot_If_Exists(DATA.ORD.ppARU + 1);

  while (slot != NULL && slot->collected_all_parts)
  {
      if (slot->type != SLOT_COMMIT || DATA.VIEW.view_change_done == 0) {
        DATA.ORD.ppARU++;
        slot = UTIL_Get_ORD_Slot_If_Exists(DATA.ORD.ppARU + 1);
        continue;
      }

      complete_pp = (complete_pre_prepare_message *)&slot->complete_pre_prepare;
      cum_acks = (po_aru_signed_message *)complete_pp->cum_acks;
      Alarm(DEBUG, "CHECKING Pre-prepare %u, ppARU %u\n", complete_pp->seq_num, DATA.ORD.ppARU);

      /* Make sure this PP is not making backwards progress. If so we cannot prepare it */
      /* if (ORDER_Pre_Prepare_Backward_Progress(complete_pp)) {
        Alarm(PRINT, "ORDER_Send_Prepares: Pre-prepare (%u) goes backward in "
                     "terms of what is eligible for execution -- refusing to send "
                     "pre-prepare!\n", complete_pp->seq_num);
        // Invalid PP -- don't send prepare
        return;
      } */

      /* For now, we are making the requirement that you only send a prepare if you
       * personally have installed all of the incarnations on the PO_ARUs that 
       * appear in the message. If at least one po_aru is from an incarnation that
       * I have yet to install, do not send a prepare. */
      for (i = 1; i <= VAR.Num_Servers; i++) {
        if (DATA.PR.installed_incarnations[i] < cum_acks[i-1].header.incarnation) {
            Alarm(PRINT, "ORDER_Send_Prepares: po_aru incarnation > my_installed for %u\n", i);
            return;
        }
        /* This may be the first time we got a chance to process this PO_ARU if we recently
         * installed the incarnation it is from. Note that duplicate PO_ARUs are discarded,
         * so there is no harm (other than small processing hit) */
        else {
            m = (signed_message *)&cum_acks[i-1];
            PRE_ORDER_Process_PO_ARU(m); 
        }
      }

      /* Make sure this PP last_executed matches the previous ordinal slot's made_eligible.
       * This is ensuring that there is no backwards progress, as we calculate the
       * delta from last_executed now (rather than the previous slot's matrix), which CAN
       * actually go backwards due to recovering previously compromised replicas */
      prev_slot = UTIL_Get_ORD_Slot_If_Exists(DATA.ORD.ppARU);
      if (prev_slot == NULL) {
        assert(DATA.ORD.ppARU == 0);
        for (i = 0; i < VAR.Num_Servers; i++)
            if (PRE_ORDER_Seq_Compare(complete_pp->last_executed[i], zero_ps) != 0) {
                Alarm(PRINT, "ORDER_Send_Prepares: complete_pp->last_executed != all 0s for first ord\n");
                return;
            }
      }
      else {
        if (memcmp(&prev_slot->made_eligible, &complete_pp->last_executed, 
                sizeof(prev_slot->made_eligible)) != 0)
        {
            Alarm(PRINT, "ORDER_Send_Prepares: prev_slot->made_eligible != complete_pp->last_executed\n");
            return;
        }
      }

      /* Now that the last executed vectors check out, calculate the made eligible for this
       * ordinal slot */
      if (!slot->populated_eligible) {
          slot->populated_eligible = 1;
          for (i = 0; i < VAR.Num_Servers; i++) {
            ps = PRE_ORDER_Proof_ARU(i+1, cum_acks);
            if (PRE_ORDER_Seq_Compare(ps, complete_pp->last_executed[i]) > 0)
                slot->made_eligible[i] = ps;
            else
                slot->made_eligible[i] = complete_pp->last_executed[i];
          }
      }

      /* If we know the leader now has received a PO request from a replica
       * that is greater than what we've sent, update our records so that
       * we don't think we are required to send a PO ARU with it - cause
       * no progress would actually be made if we did. */
      for(i = 1; i <= VAR.Num_Servers; i++) {
        ps = slot->made_eligible[i-1];
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

  slot = UTIL_Get_ORD_Slot_If_Exists(DATA.ORD.ppARU);
  if (slot == NULL) {
    Alarm(PRINT, "ORDER_Send_Prepares: ARU = %u, ppARU = %u, ppARU slot is NULL\n",
            DATA.ORD.ARU, DATA.ORD.ppARU);
    assert(slot);
  }

  /* Don't check for coverage if this slot is during the view change */
  if (slot->type != SLOT_COMMIT || DATA.VIEW.view_change_done == 0)
    return;

  complete_pp = (complete_pre_prepare_message *)&slot->complete_pre_prepare;
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

      for (i = 0; i < VAR.Num_Servers && covered == 1; i++) {

        lower = higher = 0;
        for (j = 0; j < VAR.Num_Servers; j++) {
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
            Alarm(PRINT, "Send_Prepares: Warning - received inconsistent "
                    "vector from leader in PP, but may not be their fault!\n");
        }
      }

      if (covered == 1) {
        /* Stop the stopwatch, measure the TAT, store if new max_tat in this view */
        UTIL_Stopwatch_Stop(&tatc->turnaround_time);
        if (DATA.SUSP.max_tat < UTIL_Stopwatch_Elapsed(&tatc->turnaround_time)) {
          DATA.SUSP.max_tat = UTIL_Stopwatch_Elapsed(&tatc->turnaround_time);
          DATA.SUSP.tat_max_change = 1;
        }
        stddll_pop_front(&DATA.SUSP.turnaround_times);
        //printf("      Challenge Covered\n");
      }
  }
  /* printf("    stddll after = %u\n", stddll_size(&DATA.SUSP.turnaround_times)); */
}

#if 0
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
#endif

void ORDER_Process_Prepare(signed_message *mess) 
{
  int32u *vector_ptr; 
  int i;
  ord_slot *slot, *t_slot;
  prepare_message *prepare_specific;
  signed_message *commit;

  Alarm(STATUS, "%d ORDER_Prepare\n",VAR.My_Server_ID);
  Alarm(DEBUG, "%d ORDER_Prepare\n",VAR.My_Server_ID);

  prepare_specific = (prepare_message*)(mess+1);

  /* TEST: forcing NO_OP and PC_SET messages for testing */
  /* if (DATA.View == 1 && (prepare_specific->seq_num == 96 || prepare_specific->seq_num == 97 ||
        prepare_specific->seq_num == 99))
    return; */

  /* If the view does not match, discard */
  /* if (prepare_specific->view != DATA.View) {
    Alarm(PRINT, "  DROPPING PREPARE: prep->view = %d, seq = %d, My_View = %d\n",
            prepare_specific->view, prepare_specific->seq_num, DATA.View);
    return;
  }  */

  /* If we've already executed this seq, discard */
  if(prepare_specific->seq_num <= DATA.ORD.ARU)
    return;

  if (prepare_specific->view > DATA.View)
    return;
  else if (prepare_specific->view < DATA.View) {
    if (DATA.VIEW.view_change_done == 1)
      return;
    if (DATA.ORD.ARU > 0) {
        t_slot = UTIL_Get_ORD_Slot_If_Exists(DATA.ORD.ARU);
        assert(t_slot);
        if (prepare_specific->view < t_slot->view)
          return;
    }
  }
  
  /* Print statement for debugging */
  if (prepare_specific->view < DATA.View)
    Alarm(PRINT, "Process_Prepare: Prepare from view %u while installing %u\n",
            prepare_specific->view, DATA.View);

  /* If this is from the leader, ignore - he can't be counted twice, once
   *    for the prepare and pre-prepare */
  //if (mess->machine_id == UTIL_Leader())
  if (mess->machine_id == UTIL_Leader_Of_View(prepare_specific->view))
    return;

  /* Get the slot */
  slot = UTIL_Get_ORD_Slot(prepare_specific->seq_num);
  assert(slot->seq_num == prepare_specific->seq_num);

  /* If I already have a Prepare from this server, ignore this one */
  /* We compare digests of the prepare compared with the preprepare at the end,
   * since there is no guarantee that we'll have a preprepare to check with 
   * at this point (see ORDER_Prepare_Certificate_Ready).  */
  if(slot->prepare[mess->machine_id] != NULL)
    return;

  if (slot->snapshot == 0){
    vector_ptr = DATA.PR.preinstalled_incarnations + 1;
    Alarm(STATUS,"slot->snapshot==0\n");
   }
  else{
    vector_ptr = slot->preinstalled_snapshot + 1;
    Alarm(STATUS,"slot->snapshot!=0\n");
  }

  /* Check that the preinstalled vector on this prepare matches
   * my knowledge of the preinstalled incarnations of each of the replicas.
   * Only accept this message if this check succeeds */
  if (memcmp(prepare_specific->preinstalled_incarnations, 
              vector_ptr,
              //DATA.PR.preinstalled_incarnations+1,
              // MAX_NUM_SERVERS * sizeof(int32u)) != 0) 
              VAR.Num_Servers * sizeof(int32u)) != 0) 
  {
      Alarm(DEBUG, "Process_Prepare: mismatch preinstall vector from %u. snap=%u:\n", 
                mess->machine_id, slot->snapshot);
      printf("\t\tmine = [");
      for (i = 1; i <= MAX_NUM_SERVERS; i++) {
          printf("%u, ", DATA.PR.preinstalled_incarnations[i]);
      }
      printf("]\n");
      printf("\t\tprep = [");
      for (i = 0; i < MAX_NUM_SERVERS; i++) {
          printf("%u, ", prepare_specific->preinstalled_incarnations[i]);
      }
      printf("]\n"); 
      return;
  }

  inc_ref_cnt(mess);
  slot->prepare[mess->machine_id] = mess;

  Alarm(DEBUG,"PREPARE %d %d \n", mess, get_ref_cnt(mess) );
  Alarm(DEBUG,"%d slot->prepare_certificate_ready %d, ordered=%d\n",   VAR.My_Server_ID, slot->prepare_certificate_ready,slot->ordered);
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
    if (DATA.VIEW.view_change_done == 1) {
      commit = ORDER_Construct_Commit(&slot->prepare_certificate.pre_prepare);
      Alarm(DEBUG, "Add: Commit for %d\n", slot->seq_num);
      SIG_Add_To_Pending_Messages(commit, BROADCAST, UTIL_Get_Timeliness(COMMIT));
      dec_ref_cnt(commit);
      slot->sent_commit = 1;
    }
  }
}

int32u ORDER_Prepare_Certificate_Ready(ord_slot *slot)
{
  complete_pre_prepare_message *pp;
  signed_message **prepare;
  int32u pcount, sn;

  /* Need a Pre_Prepare for a Prepare Certificate to be ready */
  if(slot->collected_all_parts == 0){
    Alarm(DEBUG, "ORDER_Prepare_Certificate_Ready: slot->collected_all_parts == 0\n");
    return 0;
   }

  pp   = (complete_pre_prepare_message *)&(slot->complete_pre_prepare);
  prepare = (signed_message **)slot->prepare;
  pcount = 0;

  for(sn = 1; sn <= VAR.Num_Servers; sn++) {
    if(prepare[sn] != NULL) {
      if(ORDER_Prepare_Matches_Pre_Prepare(prepare[sn], pp))
        pcount++;
      else
        Alarm(PRINT,"PREPARE didn't match pre-prepare while "
              "checking for prepare certificate.\n");
    }
  }

  /* If we have the Pre-Prepare and 2f + k Prepares, we're good to go */
  //if (pcount >= 2*NUM_F + NUM_K) {   /* (n+f)/2 */
  if (pcount >= 2*VAR.F + VAR.K) {   /* (n+f)/2 */
    Alarm(DEBUG,"%d pcount %d\n", VAR.My_Server_ID, pcount);
    return 1;
  }else{

    Alarm(DEBUG,"%d pcount %d needed =%d\n", VAR.My_Server_ID, pcount,2*VAR.F + VAR.K);
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
    Alarm(PRINT, "v %d: pp view,seq = %d,%d. prep view,seq = %d,%d\n", 
        view, view, seq_num, prepare_specific->view, prepare_specific->seq_num);
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
  int32u sn;
  signed_message **prepare_src;

  Alarm(DEBUG, "Made Prepare Certificate\n");
  
  prepare_src = (signed_message **)slot->prepare;

  /*Copy the completed Pre-Prepare into the Prepare Certificate */
  memcpy(&slot->prepare_certificate.pre_prepare, &slot->complete_pre_prepare,
         sizeof(complete_pre_prepare_message));

  for(sn = 1; sn <= VAR.Num_Servers; sn++) {
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
  if (DATA.ORD.high_prepared < slot->seq_num)
    DATA.ORD.high_prepared = slot->seq_num;
}

void ORDER_Process_Commit(signed_message *mess)
{
  int32u *vector_ptr, i;
  ord_slot *slot, *t_slot;
  commit_message *commit_specific;

  Alarm(STATUS, "%d ORDER_COMMIT\n",VAR.My_Server_ID);
  Alarm(DEBUG, "%d ORDER_COMMIT\n",VAR.My_Server_ID);

  commit_specific = (commit_message*)(mess+1);

  /* If the view doesn't match ours, discard */
  /* if (commit_specific->view != DATA.View) {
    Alarm(PRINT, "  DROPPING COMMIT: comm->view = %d, seq = %d, My_View = %d\n",
            commit_specific->view, commit_specific->seq_num, DATA.View);
    return;
  } */

  /* If we've already globally executed this seq, discard */
  if (commit_specific->seq_num <= DATA.ORD.ARU)
    return;

  if (commit_specific->view > DATA.View)
    return;
  else if (commit_specific->view < DATA.View) {
    if (DATA.VIEW.view_change_done == 1)
      return;
    if (DATA.ORD.ARU > 0) {
        t_slot = UTIL_Get_ORD_Slot_If_Exists(DATA.ORD.ARU);
        assert(t_slot);
        if (commit_specific->view < t_slot->view)
          return;
    }
  }
  
  /* Print statement for debugging */
  if (commit_specific->view < DATA.View)
    Alarm(PRINT, "Process_Commit: Commit from view %u while installing %u\n",
            commit_specific->view, DATA.View);

  /* Get the slot */
  slot = UTIL_Get_ORD_Slot(commit_specific->seq_num);
 
  /* If I have already received a commit from this server, return */
  if(slot->commit[mess->machine_id] != NULL)
    return;

  if (slot->snapshot == 0)
    vector_ptr = DATA.PR.preinstalled_incarnations + 1;
  else
    vector_ptr = slot->preinstalled_snapshot + 1;

  /* Check that the preinstalled vector on this commit matches
   * my knowledge of the preinstalled incarnations of each of the replicas.
   * Only accept this message if this check succeeds */
  if (memcmp(commit_specific->preinstalled_incarnations, 
              vector_ptr,
              //DATA.PR.preinstalled_incarnations+1,
              //MAX_NUM_SERVERS * sizeof(int32u)) != 0) 
              VAR.Num_Servers * sizeof(int32u)) != 0) 
  {
      Alarm(PRINT, "Process_Commit: mismatch preinstall vector from %u. snap=%u:\n", 
                mess->machine_id, slot->snapshot);
      printf("\t\tmine = [");
      for (i = 1; i <= VAR.Num_Servers; i++) {
          //printf("%u, ", DATA.PR.preinstalled_incarnations[i]);
          printf("%u, ", *vector_ptr);
	  vector_ptr+=1;
      }
      printf("]\n");
      printf("\t\tcomm = [");
      for (i = 0; i < VAR.Num_Servers; i++) {
          printf("%u, ", commit_specific->preinstalled_incarnations[i]);
      }
      printf("]\n"); 
      return;
  }

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
      Alarm(DEBUG, "Order process commit: about to execute commit with seq_num 0\n");
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

  for(sn = 1; sn <= VAR.Num_Servers; sn++) {
    if(commit[sn] != NULL) {
      if(ORDER_Commit_Matches_Pre_Prepare(commit[sn], pp))
        pcount++;
      else
	    Alarm(PRINT, "COMMIT didn't match Pre-Prepare\n");
    }
  }

  //if(pcount >= (2*NUM_F + NUM_K + 1)) {   /* 2f+k+1 */
  if(pcount >= (2*VAR.F + VAR.K + 1)) {   /* 2f+k+1 */
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
  int32u sn, i;
  po_seq_pair ps;
  signed_message **commit_src;
  complete_pre_prepare_message *pp;

  Alarm(DEBUG, "Made commit certificate.\n");

  commit_src = (signed_message **)slot->commit;

  if(slot->prepare_certificate_ready)
    pp = &slot->prepare_certificate.pre_prepare;
  else
    pp = &slot->complete_pre_prepare;

  for(sn = 1; sn <= VAR.Num_Servers; sn++) {
    if((commit_src)[sn] != NULL) {
      Alarm(DEBUG,"ORDER_Move_Commit_Certificate %d\n", commit_src[sn]);

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

  /* Create the preinstalled_incarnation snapshot, which should be my own knowledge */
  if (slot->snapshot == 0) {
    for (i = 1; i <= VAR.Num_Servers; i++) 
      slot->preinstalled_snapshot[i] = DATA.PR.preinstalled_incarnations[i];
    slot->snapshot = 1;
  }

  slot->ordered = 1;
  if (DATA.ORD.high_committed < slot->seq_num)
    DATA.ORD.high_committed = slot->seq_num;

  /* If we did not send a prepare personally for this slot yet, we may still need to update
  * the made_eligible vector. This comparison (made_eligible - last_executed)
  * replaces the prior loops that determined what is eligible. We put this now so that
  * all checks can leverage from made_eligible being setup. This is safe to do now, even
  * if we are not ready to execute, since we already have 2f+k+1 commits on the pre-prepare, 
  * so the content will not be changing. */
  if (!slot->populated_eligible) {
    slot->populated_eligible = 1;
    for(i = 0; i < VAR.Num_Servers; i++) {
        ps = PRE_ORDER_Proof_ARU(i+1, pp->cum_acks);
    
        if (PRE_ORDER_Seq_Compare(ps, pp->last_executed[i]) > 0)
            slot->made_eligible[i] = ps;
        else
            slot->made_eligible[i] = pp->last_executed[i];
    }
  }

}

int32u ORDER_Ready_To_Execute(ord_slot *o_slot)
{
  complete_pre_prepare_message *pp;
  //complete_pre_prepare_message *prev_pp;
  ord_slot *prev_ord_slot;
  po_slot *p_slot;
  int32u gseq, i, j;
  po_seq_pair prev_pop[MAX_NUM_SERVER_SLOTS];
  po_seq_pair cur_pop[MAX_NUM_SERVER_SLOTS];
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

  /* See which PO-Requests are now eligible for execution by
   * comparing made_eligible - last_executed. First, setup
   * prev_pop as either last_executed or (0,0) if first ORD */
  if(prev_ord_slot == NULL) {
    assert(gseq == 1);

    for(i = 1; i <= VAR.Num_Servers; i++)
      prev_pop[i] = zero_ps;
  }
  else {
    for(i = 1; i <=  VAR.Num_Servers; i++)
      prev_pop[i] = pp->last_executed[i-1];
  }

  /* Second, setup cur_pop as made_eligible, which should be setup
   * by now either when we sent our prepare or when we ordered 
   * (collected 2f+k+1 commits) */
  for (i = 1; i <=  VAR.Num_Servers; i++)
    cur_pop[i] = o_slot->made_eligible[i-1];

#if 0
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
#endif

  for(i = 1; i <=  VAR.Num_Servers; i++) {

    assert(prev_pop[i].incarnation <= cur_pop[i].incarnation);
    if (prev_pop[i].incarnation < cur_pop[i].incarnation) {
        prev_pop[i].incarnation = cur_pop[i].incarnation;
        prev_pop[i].seq_num = 0;
    }
    ps.incarnation = prev_pop[i].incarnation;

    for(j = prev_pop[i].seq_num + 1; j <= cur_pop[i].seq_num; j++) {
      ps.seq_num = j;
      p_slot = UTIL_Get_PO_Slot_If_Exists(i, ps);

      if(p_slot == NULL || p_slot->po_request == NULL || 
            PRE_ORDER_Seq_Compare(DATA.PO.cum_aru[i], ps) < 0) 
      {
        Alarm(PRINT, "Seq %d not ready, missing: %d [%d,%d], cum_aru = [%u,%u]\n", 
                gseq, i, ps.incarnation, ps.seq_num, DATA.PO.cum_aru[i].incarnation,
                DATA.PO.cum_aru[i].seq_num);

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
  //complete_pre_prepare_message *prev_pp;
  signed_message *po_request, *up_contents;
  signed_update_message *up, no_op;
  po_request_message *po_request_specific;
  ord_slot *prev_ord_slot;
  po_slot *p_slot;
  po_id pid;
  po_seq_pair prev_pop[MAX_NUM_SERVER_SLOTS];
  po_seq_pair cur_pop[MAX_NUM_SERVER_SLOTS];
  po_seq_pair ps, ps_update, zero_ps = {0, 0};
  int32u gseq, i, j, k, num_events;
  signed_message *event;
  char *p;
  int32u wa_bytes, event_idx, event_tot;
  complete_pre_prepare_message *pp;
  stddll eventq;
  stdit it;
  //sp_time t;

  assert(o_slot);

  Alarm(STATUS, "Trying to execute Commit for Ord seq %d!\n", o_slot->seq_num);
  Alarm(DEBUG, "Trying to execute Commit for Ord seq %d!\n", o_slot->seq_num);

  if(o_slot->prepare_certificate_ready)
    pp = &o_slot->prepare_certificate.pre_prepare;
  else
    pp = &o_slot->complete_pre_prepare;

  gseq = pp->seq_num;

  if (gseq == 0) Alarm(PRINT, "Order Execute commit, seq 0: slot seq == %d!\n", o_slot->seq_num);
  if(!ORDER_Ready_To_Execute(o_slot)) {
    Alarm(DEBUG, "Not yet ready to execute seq %d\n", gseq);

    Alarm(PRINT, "Schedule Catchup from Execute_Commit\n");
    CATCH_Schedule_Catchup();
    return;
  }

  Alarm(DEBUG, "Executing Commit for Ord seq %d!\n", gseq);

  /* Get the previous ord_slot if it exists. If it doesn't exist,
   * then this better be the first sequence number! */
  prev_ord_slot = UTIL_Get_ORD_Slot_If_Exists(gseq - 1);

  /* See which PO-Requests are now eligible for execution by
   * comparing made_eligible - last_executed. First, setup
   * prev_pop as either last_executed or (0,0) if first ORD */
  if(prev_ord_slot == NULL) {
    assert(gseq == 1);

    for(i = 1; i <=  VAR.Num_Servers; i++)
      prev_pop[i] = zero_ps;
  }
  else {
    for(i = 1; i <=  VAR.Num_Servers; i++)
      prev_pop[i] = pp->last_executed[i-1];
  }

  /* Second, setup cur_pop as made_eligible, which should be setup
   * by now either when we sent our prepare or when we ordered 
   * (collected 2f+k+1 commits) */
  for (i = 1; i <=  VAR.Num_Servers; i++)
    cur_pop[i] = o_slot->made_eligible[i-1];

#if 0
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
  
  for (i = 1; i <= NUM_SERVERS; i++)
    cur_pop[i] = o_slot->made_eligible[i-1];
#endif
  
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

  /* HACK used for normal exit to profile Prime */
  /* if (DATA.ORD.ARU == 20000 && VAR.My_Server_ID == 4)
    exit(EXIT_SUCCESS); */
  
  /* Special case for initial stable catchup place */
  if (DATA.ORD.ARU == 1)
    DATA.ORD.stable_catchup = 1;

  if (DATA.ORD.ARU % PRINT_PROGRESS == 0)
    Alarm(PRINT, "Executed through ordinal %u\n", DATA.ORD.ARU);
  /* if (DATA.ORD.ARU % (PRINT_PROGRESS*10) == 0) {
    Alarm(PRINT, "Profiling since start!\n");
    Alarm(PRINT, "  Messages with process > 0.002 s\n");
    for (i = 1; i < MAX_MESS_TYPE; i++) {
        printf("    %25s: %8u\n", UTIL_Type_To_String(i), BENCH.profile_count[i]);
    }
  } */

  event_tot = 0;
  stddll_construct(&eventq, sizeof(signed_message *));

  for(i = 1; i <=  VAR.Num_Servers; i++) {

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
        ps_update.incarnation = up->header.incarnation;
        ps_update.seq_num = up->update.seq_num;
        up_contents = (signed_message *)(up->update_contents);
        /* if (up_contents->type == CLIENT_STATE_TRANSFER) {
            Alarm(DEBUG, "  STATE TRANSFER! [%u,%u]\n", ps_update.incarnation, ps_update.seq_num);
        } */
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

      /* Check if we are about to execute the first "special" update from a RECOVERING
       * replica, make them as now being NORMAL state */
      if (ps.incarnation > DATA.PO.last_executed_po_reqs[i].incarnation &&
          ps.seq_num == 1)
      {
            if (DATA.PR.recovery_status[i] == PR_STARTUP) {
                Alarm(PRINT, "STRANGE: Changing %u from STARTUP to NORMAL in execute_commit.\n", i);
                DATA.PR.num_startup--;
            }
            if (DATA.PR.preinstalled_incarnations[i] <= ps.incarnation) {
                DATA.PR.recovery_status[i] = PR_NORMAL;
                Alarm(PRINT, "Setting %u to PR_NORMAL in Execute_Commit\n", i);
                DATA.PR.preinstalled_incarnations[i] = ps.incarnation;
            }
            DATA.PR.installed_incarnations[i] = ps.incarnation;
            if (i == VAR.My_Server_ID && 
                  DATA.PR.preinstalled_incarnations[i] == DATA.PR.installed_incarnations[i])
            {
                Alarm(PRINT, "RESUME NORMAL from Execute_Commit\n");
                PR_Resume_Normal_Operation();
                //PR_Resume_Normal_Operation(NO_RESET_APPLICATION);
            }
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
  DATA.SIG.ipc_send_agg = 0;
  memset(DATA.SIG.ipc_send_msg, 0, sizeof(DATA.SIG.ipc_send_msg));
  DATA.SIG.ipc_count = 0;
  util_stopwatch ipc_timer;
  UTIL_Stopwatch_Start(&ipc_timer);
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
    event->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    event->len = sizeof(signed_update_message) - sizeof(signed_message);

    up->update.server_id = VAR.My_Server_ID;
    up->header.incarnation = DATA.PO.intro_client_seq[VAR.My_Server_ID].incarnation;
    up->update.seq_num = 0;

    up_contents->machine_id = VAR.My_Server_ID;
    up_contents->type = CLIENT_NO_OP;
    
    ORDER_Execute_Event(event, pp->seq_num, 1, 1); 
  }
  stddll_destruct(&eventq);
  UTIL_Stopwatch_Stop(&ipc_timer);
  /* if (UTIL_Stopwatch_Elapsed(&ipc_timer) >= 0.002) {
    Alarm(DEBUG, "%u IPC messages. %f s total, %f s send\n", event_tot,
            UTIL_Stopwatch_Elapsed(&ipc_timer), DATA.SIG.ipc_send_agg);
    Alarm(DEBUG, "Breakdown:\n");
    for (i = 0; i < DATA.SIG.ipc_count; i++) 
        Alarm(DEBUG, "\tipc [%u] --> %f s\n", i, DATA.SIG.ipc_send_msg[i]);
  } */

  RECON_Do_Recon(o_slot);
  /* Garbage collect gseq-1 when I commit gseq */
  //ORDER_Attempt_To_Garbage_Collect_ORD_Slot(gseq-1);

  /* Create the certificate for this Ordinal */
  /* o_slot->ord_certificate = CATCH_Construct_ORD_Certificate(o_slot);
  UTIL_RSA_Sign_Message(o_slot->ord_certificate); */

  /* Use MT Batching for these certs as well */
  /* cert = CATCH_Construct_ORD_Certificate(o_slot);
  dest_bits = 0;
  SIG_Add_To_Pending_Messages(cert, dest_bits, UTIL_Get_Timeliness(ORD_CERT));
  dec_ref_cnt(cert); */

  /* This will be signed later if needed by a replica for catchup */
  o_slot->ord_certificate = CATCH_Construct_ORD_Certificate(o_slot);

  /* Only replace the periodic ord cert that we send (which
   * replicas may jump to) if its a commit */
#if 0
  if (o_slot->type == SLOT_COMMIT) {

    /* Store this as our latest cert, update flag for periodic,
     *    and start periodic sending (if not already) */
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
    }
  }
#endif

  /* If we are still working on a view change, check if we now
   *    have collected complete state from any one */
  if (DATA.VIEW.view_change_done == 0) {
    for (i = 1; i <=  VAR.Num_Servers; i++) 
      VIEW_Check_Complete_State(i);

    /* If we missed some view change messages, but not ORD messages and 
     * others already executed at least one ordinal, they will not be 
     * sending the end of view change messages. But since I cannot
     * send prepares/commits while in a view change, I know this came
     * from at least enough correct replicas. I can finish the view here */
    /* if (o_slot->view == DATA.View) {
        DATA.VIEW.view_change_done = 1;
        Alarm(PRINT, "Finished View Change from Execute_Commit\n");
    } */
  }

  /* If the view change is done, and this is the first ord that we
   * are about to execute in the view, set the flag, which will 
   * cause some view-change related periodic functions to stop
   * being periodic (until the next view change) */
  if (DATA.VIEW.executed_ord == 0) {
    DATA.VIEW.executed_ord = 1;
  }

  /* Send any prepares that we can now send by installing incarnations */
  ORDER_Send_Prepares();

  /* Garbage collect gseq-GC_LAG when I commit gseq */
  /* if (gseq > GC_LAG)
    ORDER_Attempt_To_Garbage_Collect_ORD_Slot(gseq - GC_LAG); */
  ORDER_Attempt_To_Garbage_Collect_ORD_Slots();
  
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
	((signed_update_message *)event)->header.incarnation,
	((signed_update_message *)event)->update.seq_num);
  ORDER_Execute_Update(event, ord_num, event_idx, event_tot);
}

void ORDER_Execute_Update(signed_message *mess, int32u ord_num, int32u event_idx, int32u event_tot)
{
  signed_update_message *u;

  assert(mess->type == UPDATE);
  Alarm(STATUS,"MS2022: Sending to client mess of type %d\n",mess->type);
  Alarm(DEBUG,"MS2022: Sending to client mess of type %d\n",mess->type);
  BENCH.updates_executed++;
  if(BENCH.updates_executed == 1)
    UTIL_Stopwatch_Start(&BENCH.test_stopwatch);

  //if(BENCH.updates_executed % 50 == 0)
  /* if(BENCH.updates_executed % (BENCHMARK_END_RUN/100) == 0)
    Alarm(PRINT, "Executed %d updates\n", BENCH.updates_executed); */

  u = (signed_update_message *)mess;
  Alarm(DEBUG, "Ordered update with timestamp %d %d\n", 
            u->header.incarnation, u->update.seq_num);

  /* For Benchmarking Prime, we only send ACKs back to clients that
   * are connected to this server, and record ordered updates as
   * they are executed. For SCADA Prime, we are not writing to file
   * and are sending all ordered updates to all clients, MSG included */
  /* if(u->update.server_id == VAR.My_Server_ID)
    UTIL_Respond_To_Client(mess->machine_id, u->update.time_stamp);

  UTIL_State_Machine_Output(u); */

  UTIL_Respond_To_Client(mess->machine_id, u->header.incarnation, 
            u->update.seq_num, ord_num, event_idx, event_tot, 
            u->update_contents);

  /* if(BENCH.updates_executed == BENCHMARK_END_RUN) {
    ORDER_Cleanup();
    exit(0);
  } */
}

void ORDER_Flood_PP_Wrapper(int d1, void *message)
{
    ORDER_Flood_Pre_Prepare((signed_message *)message);
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
    for(i = 1; i <=  VAR.Num_Servers; i++) {
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

void ORDER_Adjust_High_Committed()
{
    if (DATA.ORD.high_committed < DATA.ORD.ARU)
        DATA.ORD.high_committed = DATA.ORD.ARU;
}

void ORDER_Adjust_High_Prepared()
{
    int32u seq;
    ord_slot *slot;

    if (DATA.ORD.high_prepared <= DATA.ORD.ARU) {
        DATA.ORD.high_prepared = DATA.ORD.ARU;
        return;
    }

    for (seq = DATA.ORD.high_prepared; seq > DATA.ORD.ARU; seq--) {

        slot = UTIL_Get_ORD_Slot_If_Exists(seq);
        if (slot != NULL && slot->prepare_certificate_ready == 1)
            break;
    }

    /* This should result in high_prepared getting set >= ARU */
    DATA.ORD.high_prepared = seq;
}

void ORDER_Adjust_ppARU()
{
    int32u seq;
    ord_slot *slot;

    if (DATA.ORD.ppARU <= DATA.ORD.ARU) {
        DATA.ORD.ppARU = DATA.ORD.ARU;
        return;
    }

    for (seq = DATA.ORD.ppARU; seq > DATA.ORD.ARU; seq--) {

        slot = UTIL_Get_ORD_Slot_If_Exists(seq);
        if (slot != NULL && slot->sent_prepare == 1)
            break;
    }

    /* This should result in ppARU getting set >= ARU */
    DATA.ORD.ppARU = seq;
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
      
      DATA.ORD.forwarding_white_line++;
      //ORDER_Attempt_To_Garbage_Collect_ORD_Slot(seq);
    }
    else
      break;
  }
}

void ORDER_Attempt_To_Garbage_Collect_ORD_Slots()
{
  ord_slot *slot;
  int32u i;

  /* First, check if we have enough of a catchup history to clear out a chunk */
  if (DATA.ORD.ARU - DATA.ORD.stable_catchup < 2 * DATA.ORD.gc_width) {
    Alarm(DEBUG, "Can't garbage collect yet: ARU %d < stable %u + 2*CatchupHistory %u\n", 
            DATA.ORD.ARU, DATA.ORD.stable_catchup, 2 * DATA.ORD.gc_width);
    return;
  }

  /* Success: Remove the fixed-size chunk */
  for (i = DATA.ORD.stable_catchup; i < DATA.ORD.ARU - DATA.ORD.gc_width; i++) {
    slot = UTIL_Get_ORD_Slot(i);
    Alarm(DEBUG, "ORD GC slot %u\n", i);

    /* 2 Sanity Checks */
    /* Make sure we got all of the pre-prepare parts and flooded them */
    if (slot->collected_all_parts == 0 || DATA.ORD.forwarding_white_line < slot->seq_num) {
        Alarm(EXIT, "ORD GC issue: can't gc slot %d: collected_all_parts = %d, forwarding_white_line = %d\n", 
                slot->seq_num, slot->collected_all_parts, DATA.ORD.forwarding_white_line);
    }
    /* Make sure we did recon on this slot as well */
    if(DATA.ORD.recon_white_line < (slot->seq_num+1)) {
        Alarm(EXIT, "ORD gc issue: Can't gc slot %d: recon_white_line %d < seq+1 %d\n", 
                slot->seq_num, DATA.ORD.recon_white_line, slot->seq_num+1);
    }
    ORDER_Garbage_Collect_ORD_Slot(slot, 1);
  }

  /* Set the new stable catchup ordinal */
  DATA.ORD.stable_catchup = DATA.ORD.ARU - DATA.ORD.gc_width;
}

#if 0
void ORDER_Attempt_To_Garbage_Collect_ORD_Slot(int32u seq)
{
  ord_slot *slot;
  int32u i;

  slot = UTIL_Get_ORD_Slot_If_Exists(seq);

  if(slot == NULL)
    return;
  
  /* Need to have received and forwarded all parts of the Pre-Prepare */
  if(slot->collected_all_parts == 0 || DATA.ORD.forwarding_white_line < seq)
  {
        Alarm(DEBUG, "Can't garbage collect slot %d: collected_all_parts = %d, forwarding_white_line = %d\n", seq, slot->collected_all_parts, DATA.ORD.forwarding_white_line);
    return;
  }

  /* Need to have globally ordered this slot and the next one */
  //if(DATA.ORD.ARU < (seq+1))
  if(DATA.ORD.ARU < (seq+GC_LAG))
  {
    Alarm(DEBUG, "Can't garbage collect slot %d: ARU %d < seq+1 %d\n", seq, DATA.ORD.ARU, seq+1);
    //Alarm(PRINT, "Can't garbage collect slot %d: ARU %d < stable %u + 2*CatchupHistory %u\n", 
    //            seq, DATA.ORD.ARU, DATA.ORD.stable_catchup, 2 * CATCHUP_HISTORY);
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
#endif

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
  for(i = 1; i <=  VAR.Num_Servers; i++) {
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
  UTIL_DLL_Clear(&DATA.PO.ack_batch_dll);

  UTIL_DLL_Clear(&DATA.SIG.pending_messages_dll);

  /* for(i = 1; i <= 300; i++) {
    if(NET.client_sd[i] > 2)
      close(NET.client_sd[i]);
  } */
  close(NET.from_client_sd);
  E_detach_fd(NET.from_client_sd, READ_FD);
  NET.from_client_sd = 0;
  Alarm(PRINT,"&&&&&&&MS2022: order.c 2201 clsing fron_client_sd\n");
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
