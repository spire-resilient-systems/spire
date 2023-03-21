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

#include <string.h>
#include <assert.h>
#include "spu_alarm.h"
#include "spu_memory.h"
#include "packets.h"
#include "utility.h"
#include "data_structs.h"
#include "pre_order.h"
#include "order.h"
#include "proactive_recovery.h"
#include "merkle.h"
#include "validate.h"
#include "recon.h"
#include "tc_wrapper.h"

extern server_data_struct DATA; 
extern server_variables   VAR;
extern benchmark_struct   BENCH;

signed_message* PRE_ORDER_Construct_PO_Request()
{
  signed_message *po_request;
  po_request_message *po_request_specific;
  int32u bytes, this_mess_len, num_events, wa_bytes, cutoff;
  signed_message *mess;
  char *p;

  /* Construct new message */
  po_request          = UTIL_New_Signed_Message();
  po_request_specific = (po_request_message *)(po_request + 1);

  /* Fill in the message based on the event. We construct a message
   * that contains the event by copying the event (which may or may
   * not be a signed message) into the PO Request message. */
  
  po_request->machine_id       = VAR.My_Server_ID;
  po_request->type             = PO_REQUEST;
  DATA.PO.po_seq.seq_num++;
  po_request_specific->seq     = DATA.PO.po_seq;

  /* We'll be adding to at least this many bytes */
  bytes = sizeof(signed_message) + sizeof(po_request_message);
  
  num_events = 0;

  /* When we copy, we'll be starting right after the PO request */
  p = (char *)(po_request_specific+1);
  
  cutoff = PRIME_MAX_PACKET_SIZE - (DIGEST_SIZE * MAX_MERKLE_DIGESTS);

  while(bytes < cutoff) {

    wa_bytes = 0;

    /* If there are no more messages, stop. Otherwise grab one and see
     * if it will fit. */
    if((mess = UTIL_DLL_Front_Message(&DATA.PO.po_request_dll)) == NULL)
      break;

    this_mess_len = mess->len + sizeof(signed_message) + wa_bytes;

    if((bytes + this_mess_len) < cutoff) {
      num_events++;
      bytes += this_mess_len;

      /* Copy it into the packet */
      memcpy(p, mess, this_mess_len);
      p += this_mess_len;

      UTIL_DLL_Pop_Front(&DATA.PO.po_request_dll);
    }
    else {
      Alarm(DEBUG, "Won't fit: this_mess_len = %d, type = %d, wa = %d\n", 
	    this_mess_len, mess->type, wa_bytes);
      break;
    }
  }

  
  po_request_specific->num_events = num_events;
  /* Subtract sizeof(signed_message) because even though we send out
   * that many bytes, the len field is just the content, not the signed
   * message part. */
  po_request->len = bytes - sizeof(signed_message);
  
  BENCH.num_po_requests_sent++;
  BENCH.total_updates_requested += num_events;

  return po_request;
}

signed_message* PRE_ORDER_Construct_PO_Ack(int32u *more_to_ack, int32u send_all_non_exec)
{
  signed_message *po_ack;
  po_ack_message *po_ack_specific;
  po_ack_part *ack_part;
  int32u nparts;
  int32u sm;
  po_slot *slot;
  int32u po_request_len;
  po_seq_pair ps;

  /* Construct new message */
  po_ack          = UTIL_New_Signed_Message();
  po_ack_specific = (po_ack_message*)(po_ack + 1);
  
  po_ack->machine_id = VAR.My_Server_ID;
  po_ack->type       = PO_ACK;
  
  /* we must ack all of the unacked po request messages, received
   * contiguously */
  
  ack_part = (po_ack_part*)(po_ack_specific+1);
  
  nparts     = 0;
  
  for(sm = 1; sm <= NUM_SERVERS; sm++) {
    
    if (send_all_non_exec) {
        ps = DATA.PO.last_executed_po_reqs[sm];
        if (ps.incarnation < DATA.PO.max_acked[sm].incarnation) {
            ps.incarnation = DATA.PO.max_acked[sm].incarnation;
            ps.seq_num = 0;
        }
    } else {
        ps = DATA.PO.max_acked[sm];
    }
    ps.seq_num += 1;

    //assert(DATA.PO.max_acked[sm] <= DATA.PO.aru[sm]);
    //assert(PRE_ORDER_Seq_Compare(DATA.PO.max_acked[sm], DATA.PO.aru[sm]) <= 0);
    
    for(; ps.seq_num <= DATA.PO.aru[sm].seq_num; ps.seq_num++) {
      /* If my new incarnation is still pending (i.e. not yet executed) I am
       * ONLY allowed to ack PO-Requests that are also incarnation change
       * messages */
      if (DATA.PO.po_seq.incarnation > DATA.PO.last_executed_po_reqs[VAR.My_Server_ID].incarnation &&
          ps.seq_num != 1)
      {
        Alarm(DEBUG, "My Incarnation is still pending -- holding off on acking "
                     "%u %u from %u\n", DATA.PO.max_acked[sm].incarnation, ps.seq_num, sm);
        break;
      }
      //if (sm == 1 && i == 2 && DATA.View < 3)
      //  break;

      if (ps.seq_num > DATA.PO.max_acked[sm].seq_num)
        DATA.PO.max_acked[sm].seq_num = ps.seq_num;
      slot = UTIL_Get_PO_Slot_If_Exists(sm, ps);
      
      if(slot == NULL) {
        /* We received a PO-Request but decided not to ack yet due to 
         * aggregation.  Then we order the PO-Request using acks from 
         * the other servers.  Now we're ready to send the ack but we've
         * already garbage collected!  This is ok.  Just pretend like
         * we're acking; everyone else will execute eventually. */
        Alarm(DEBUG, "Continuing locally on %d %d %d\n", sm, 
                ps.incarnation, ps.seq_num);
        assert(PRE_ORDER_Seq_Compare(DATA.PO.white_line[sm], 
                    ps) >= 0);
        continue;
      }
  
#if RECON_ATTACK
      /* Faulty servers don't ack anyone else's stuff */
      if (UTIL_I_Am_Faulty() && sm > NUM_F)
	continue;
#endif

      /* Create the ack_part */
      ack_part[nparts].originator = sm;
      ack_part[nparts].seq        = ps;
      
      /* Modified this.  Includes possible appended digest bytes and
       * does not subtract the signature_size. */
      po_request_len = (sizeof(signed_message) + slot->po_request->len +
			MT_Digests_(slot->po_request->mt_num) * DIGEST_SIZE);

      /* Now compute the digest of the event and copy it into the
       * digest field */
      OPENSSL_RSA_Make_Digest((byte *)(slot->po_request), po_request_len,
			      ack_part[nparts].digest);      
      nparts++;

      if(nparts == MAX_ACK_PARTS)
        goto finish;
    }
  }
  
 finish:

  po_ack_specific->num_ack_parts = nparts;
  
  if (nparts == 0) {
    /* There is nothing in the ack -- we will not send it */
    *more_to_ack = 0;
    dec_ref_cnt( po_ack );
    return NULL;
  }

  if (nparts > MAX_ACK_PARTS) { 
    Alarm(EXIT,"%d BIG LOCAL ACK nparts = %d\n", VAR.My_Server_ID, nparts); 
  }

  po_ack->len = (sizeof(po_ack_message) + 
		 sizeof(po_ack_part) * po_ack_specific->num_ack_parts);
  
  if(nparts == MAX_ACK_PARTS) {
    Alarm(DEBUG, "There may be more to ack!\n");
    *more_to_ack = 1;
  }
  else {
    *more_to_ack = 0;
    Alarm(DEBUG, "Acked %d parts\n", nparts);
  }
  
  BENCH.num_po_acks_sent++;
  BENCH.num_acks += nparts;

  return po_ack;
}

signed_message* PRE_ORDER_Construct_PO_ARU()
{
  int32u s;
  signed_message *po_aru;
  po_aru_message *po_aru_specific;

  /* Construct new message */
  po_aru          = UTIL_New_Signed_Message();
  po_aru_specific = (po_aru_message*)(po_aru + 1);

  po_aru->machine_id = VAR.My_Server_ID;
  po_aru->type       = PO_ARU;
  po_aru->len        = sizeof(po_aru_message);
  
  po_aru_specific->num         = ++DATA.PO.po_aru_num;
  po_aru_specific->incarnation = DATA.PO.po_seq.incarnation;

  /* Fill in vector of cumulative pre order acks */
  for (s = 0; s < NUM_SERVERS; s++)
    po_aru_specific->ack_for_server[s] = DATA.PO.cum_aru[s+1];

#if 0
  /* Compute a standard RSA signature. */
  Alarm(PRINT, "Signature: Local PO-ARU\n");
  UTIL_RSA_Sign_Message(po_aru);
#endif  

  return po_aru;
}

void PRE_ORDER_Construct_Proof_Matrix(signed_message **mset,
				      int32u *num_parts)
{
    signed_message *mess;
    proof_matrix_message *pm_specific;
    int32u curr_part, index, length, remaining_vectors, num_acks;

    /* TODO: Possibly create a generic large-message handler
    * for all of Prime's message */
    curr_part = 0;
    index = 1;
    remaining_vectors = NUM_SERVERS;    
    /*num_acks = (PRIME_MAX_PACKET_SIZE - sizeof(signed_message) - 
               sizeof(proof_matrix_message) - 
               (MAX_MERKLE_DIGESTS * DIGEST_SIZE)) / 
               sizeof(po_aru_signed_message);*/
    num_acks = (PRIME_MAX_PACKET_SIZE - sizeof(signed_message) - 
               sizeof(proof_matrix_message)) / 
               sizeof(po_aru_signed_message);

    while (remaining_vectors > 0) {
        curr_part++;
        mset[curr_part] = UTIL_New_Signed_Message();
        mess = (signed_message *)mset[curr_part];

        mess->type       = PROOF_MATRIX;
        mess->machine_id = VAR.My_Server_ID;
        mess->len        = 0; /* Set below */

        pm_specific      = (proof_matrix_message *)(mess+1);

        /* timing tests */
        pm_specific->sec  = E_get_time().sec; 
        pm_specific->usec = E_get_time().usec;

        if (remaining_vectors >= num_acks) {
            pm_specific->num_acks_in_this_message = num_acks;
            remaining_vectors -= num_acks;
        }
        else {
            pm_specific->num_acks_in_this_message = remaining_vectors;
            remaining_vectors = 0;
        }
    
        length = (sizeof(po_aru_signed_message) * 
                pm_specific->num_acks_in_this_message);
    
        memcpy((byte *)(pm_specific + 1), (byte *)(DATA.PO.cum_acks+index),
                length);
        mset[curr_part]->len = sizeof(proof_matrix_message) + length;
        index += pm_specific->num_acks_in_this_message;
    }

    *num_parts = curr_part;
}

signed_message* PRE_ORDER_Construct_Update(int32u type)
{
    signed_message *mess, *up_contents;
    update_message *up;

    /* Create the client update for my incarnation change */
    mess = UTIL_New_Signed_Message();
    up = (update_message *)(mess + 1); 
    up_contents = (signed_message *)(up + 1); 

    mess->machine_id = VAR.My_Server_ID;
    mess->type = UPDATE;
    mess->len = sizeof(signed_update_message) - sizeof(signed_message);
    
    up->server_id = VAR.My_Server_ID;
    
    up_contents->machine_id = VAR.My_Server_ID;
    up_contents->type = type;

    Alarm(DEBUG, "Construct Update: type=%u, [%d, %d, %d] using timestamp %u %u\n", 
            type, VAR.My_Server_ID, DATA.PO.po_seq.incarnation, 
            DATA.PO.po_seq.seq_num + 1, up->incarnation, up->seq_num);

    /* Sign the update using (using server key) */
    UTIL_RSA_Sign_Message(mess);

    return mess;
}

void ORDER_Construct_Pre_Prepare(signed_message **mset,int32u *num_parts)
{
    signed_message *mess;
    pre_prepare_message *pp_specific;
    int32u curr_part, total_parts, i, index, length, remaining_vectors, num_acks;

    /* TODO: Possibly create a generic large-message handler
    * for all of Prime's message */
    curr_part = 0;
    index = 1;
    remaining_vectors = NUM_SERVERS;
    /*num_acks = (PRIME_MAX_PACKET_SIZE - sizeof(signed_message) - 
               sizeof(pre_prepare_message) - 
               (MAX_MERKLE_DIGESTS * DIGEST_SIZE)) / 
               sizeof(po_aru_signed_message);*/
    num_acks = (PRIME_MAX_PACKET_SIZE - sizeof(signed_message) - 
               sizeof(proof_matrix_message)) / 
               sizeof(po_aru_signed_message);

    while (remaining_vectors > 0) {
        curr_part++;
        if (curr_part > MAX_PRE_PREPARE_PARTS)
            Alarm(EXIT, "Message too large, exceeded MAX_PRE_PREPARE+PARTS\n");

        mset[curr_part] = UTIL_New_Signed_Message();
        mess = (signed_message *)mset[curr_part];
        memset(mset[curr_part], 0, PRIME_MAX_PACKET_SIZE);

        mess->type       = PRE_PREPARE;
        mess->machine_id = VAR.My_Server_ID;
        mess->len        = 0; /* Set below */

        pp_specific              = (pre_prepare_message *)(mess+1);
        //if (DATA.View <= NUM_SERVERS)
        //    DATA.ORD.seq++;
        pp_specific->seq_num     = DATA.ORD.seq;
        pp_specific->view        = DATA.View;
        pp_specific->part_num    = curr_part;
        pp_specific->total_parts = 0; /* Set at the end of loop */

        /* timing tests */
        pp_specific->sec  = E_get_time().sec; 
        pp_specific->usec = E_get_time().usec;

        if (remaining_vectors >= num_acks) {
            pp_specific->num_acks_in_this_message = num_acks;
            remaining_vectors -= num_acks;
        }
        else {
            pp_specific->num_acks_in_this_message = remaining_vectors;
            remaining_vectors = 0;
        }
    
        length = (sizeof(po_aru_signed_message) * 
                pp_specific->num_acks_in_this_message);
        // ESTCP: MALICIOUS TEST!!
        //if (pp_specific->seq_num == 100 && pp_specific->view < 6) {
        //    memcpy((byte *)(pp_specific + 1), (byte *)(DATA.PO.cum_acks+index), length - (2*sizeof(po_aru_signed_message)));
        //} else {
            memcpy((byte *)(pp_specific + 1), (byte *)(DATA.PO.cum_acks+index),
                    length);
        //}
        mset[curr_part]->len = sizeof(pre_prepare_message) + length;
        index += pp_specific->num_acks_in_this_message;
    }

    total_parts = curr_part;
    for (i = 1; i <= total_parts; i++) {
        pp_specific = (pre_prepare_message *)(mset[i] + 1);
        pp_specific->total_parts = total_parts;
    }
        
    DATA.ORD.seq++;
    *num_parts = total_parts;
}

signed_message* ORDER_Construct_Prepare(complete_pre_prepare_message *pp)
{
  signed_message *prepare;
  prepare_message *prepare_specific;

  /* Construct new message */
  prepare          = UTIL_New_Signed_Message();
  prepare_specific = (prepare_message *)(prepare + 1);

  prepare->machine_id = VAR.My_Server_ID;
  prepare->type       = PREPARE;
  prepare->len        = sizeof(prepare_message);
    
  prepare_specific->seq_num = pp->seq_num;
  prepare_specific->view    = pp->view;
  
  /* Now compute the digest of the content and copy it into the digest field */
  OPENSSL_RSA_Make_Digest((byte*)pp, sizeof(*pp), prepare_specific->digest);
  
  return prepare;
}

signed_message *ORDER_Construct_Commit(complete_pre_prepare_message *pp)
{
  signed_message *commit;
  commit_message *commit_specific;
  
  /* Construct new message */
  commit          = UTIL_New_Signed_Message();
  commit_specific = (commit_message*)(commit + 1);

  commit->machine_id = VAR.My_Server_ID;
  commit->type       = COMMIT;
  commit->len        = sizeof(commit_message);

  commit_specific->seq_num = pp->seq_num;
  commit_specific->view    = pp->view;
  
  OPENSSL_RSA_Make_Digest((byte*)pp, sizeof(*pp), commit_specific->digest);

  return commit;
}

signed_message *ORDER_Construct_Client_Response(int32u client_id, int32u incarnation,
        int32u seq_num, int32u ord_num, int32u event_idx, int32u event_tot, 
        byte content[UPDATE_SIZE])
{
  signed_message *response;
  client_response_message *response_specific;
  byte *buf;

  /* Construct new message */
  response = UTIL_New_Signed_Message();

  response_specific = (client_response_message*)(response + 1);

  response->machine_id = VAR.My_Server_ID;
  response->type       = CLIENT_RESPONSE;
  response->len        = sizeof(client_response_message) + UPDATE_SIZE;
  //response->len        = sizeof(client_response_message);

  response_specific->machine_id   = client_id;
  response_specific->incarnation  = incarnation;
  response_specific->seq_num      = seq_num;
  response_specific->ord_num      = ord_num;
  response_specific->event_idx    = event_idx;
  response_specific->event_tot    = event_tot;
  response_specific->PO_time      = 0; 
        //UTIL_Stopwatch_Elapsed(&DATA.PO.po_duration_sw);

  buf = (byte *)(response_specific + 1);
  memcpy(buf, content, UPDATE_SIZE);

  return response;
}

signed_message *SUSPECT_Construct_TAT_Measure(double max_tat)
{
  signed_message *measure;
  tat_measure_message *measure_specific;

  /* Construct new message */
  measure = UTIL_New_Signed_Message();

  measure_specific = (tat_measure_message*)(measure + 1);

  measure->machine_id = VAR.My_Server_ID;
  measure->type       = TAT_MEASURE;
  measure->len        = sizeof(tat_measure_message);

  measure_specific->max_tat = max_tat;
  measure_specific->view    = DATA.View;

  return measure;
}

signed_message *SUSPECT_Construct_RTT_Ping()
{
  signed_message *ping;
  rtt_ping_message *ping_specific;

  /* Construct new message */
  ping = UTIL_New_Signed_Message();

  ping_specific = (rtt_ping_message*)(ping + 1);

  ping->machine_id = VAR.My_Server_ID;
  ping->type       = RTT_PING;
  ping->len        = sizeof(rtt_ping_message);

  ping_specific->ping_seq_num = DATA.SUSP.ping_seq_num++;
  ping_specific->view         = DATA.View;

  return ping;
}

signed_message *SUSPECT_Construct_RTT_Pong(int32u server_id, int32u seq_num)
{
  signed_message *pong;
  rtt_pong_message *pong_specific;

  /* Construct new message */
  pong = UTIL_New_Signed_Message();

  pong_specific = (rtt_pong_message*)(pong + 1);

  pong->machine_id = VAR.My_Server_ID;
  pong->type       = RTT_PONG;
  pong->len        = sizeof(rtt_pong_message);

  pong_specific->dest         = server_id;
  pong_specific->ping_seq_num = seq_num;
  pong_specific->view         = DATA.View;

  return pong;
}

signed_message *SUSPECT_Construct_RTT_Measure(int32u server_id, double rtt)
{
  signed_message *measure;
  rtt_measure_message *measure_specific;

  /* Construct new message */
  measure = UTIL_New_Signed_Message();

  measure_specific = (rtt_measure_message*)(measure + 1);

  measure->machine_id = VAR.My_Server_ID;
  measure->type       = RTT_MEASURE;
  measure->len        = sizeof(rtt_measure_message);

  measure_specific->dest = server_id;
  measure_specific->rtt  = rtt;
  measure_specific->view = DATA.View;

  return measure;
}

signed_message *SUSPECT_Construct_TAT_UB(double alpha)
{
  signed_message *ub;
  tat_ub_message *ub_specific;

  /* Construct new message */
  ub = UTIL_New_Signed_Message();

  ub_specific = (tat_ub_message*)(ub + 1);

  ub->machine_id = VAR.My_Server_ID;
  ub->type       = TAT_UB;
  ub->len        = sizeof(tat_ub_message);

  ub_specific->alpha = alpha;
  ub_specific->view  = DATA.View;

  return ub;
}

signed_message *SUSPECT_Construct_New_Leader()
{
  signed_message *new_leader;
  new_leader_message *new_leader_specific;

  /* Construct new message */
  new_leader = UTIL_New_Signed_Message();

  new_leader_specific = (new_leader_message*)(new_leader + 1);

  new_leader->machine_id = VAR.My_Server_ID;
  new_leader->type       = NEW_LEADER;
  new_leader->len        = sizeof(new_leader_message);

  new_leader_specific->new_view = DATA.View + 1;

  return new_leader;
}

signed_message *SUSPECT_Construct_New_Leader_Proof()
{
    int32u i, count, size;
    signed_message *new_leader_proof, *stored;
    new_leader_proof_message *nlm_specific;
    new_leader_message *stored_specific;
    char *next_leader_msg;

    /* Construct new message */
    new_leader_proof = UTIL_New_Signed_Message();
    nlm_specific = (new_leader_proof_message *)(new_leader_proof + 1);

    new_leader_proof->machine_id = VAR.My_Server_ID;
    new_leader_proof->type       = NEW_LEADER_PROOF;
    new_leader_proof->len        = sizeof(new_leader_proof_message);

    nlm_specific->new_view = DATA.View; /* We already preinstalled new view */

    count = 0;
    next_leader_msg = (char *)(nlm_specific + 1);

    for (i = 1; i <= NUM_SERVERS; i++) 
    {
        stored = DATA.SUSP.new_leader[i];
        if (stored == NULL)
            continue;

        stored_specific = (new_leader_message *)(stored + 1);
    
        if (stored_specific->new_view != DATA.View)
            continue;

        //size = UTIL_Message_Size(stored);
        size = sizeof(signed_message) + sizeof(new_leader_message);
        //printf("size = %d\n", size);
        memcpy(next_leader_msg, stored, size);
        next_leader_msg += size;
        new_leader_proof->len += size;
        count++;
    }

    assert(count == 2*VAR.F + VAR.K + 1);

    /*char *ptr = (char *)new_leader_proof + sizeof(signed_message) + sizeof(new_leader_proof_message);
    for (i = 0; i < 2*VAR.F + VAR.K + 1; i++) {
        stored = (signed_message *)(ptr +
                i * (sizeof(signed_message) + sizeof(new_leader_message)));
        stored_specific = (new_leader_message *)(stored + 1);

        if (stored_specific->new_view != DATA.View) {
            Alarm(EXIT, "SUSPECT_Process_New_Leader_Proof: Incorrect "
                    "message from ME. my view = %d, stored->machine_id = %d\n", 
                    DATA.View, stored->machine_id);
        }
    }*/

    return new_leader_proof;
}

signed_message *RB_Construct_Message(int32u type, signed_message *mess)
{
    signed_message *rb_msg, *payload;
    int32u payload_size;
    
    payload_size = sizeof(signed_message) + mess->len;

    /* Construct new message */
    rb_msg = UTIL_New_Signed_Message();

    rb_msg->machine_id = VAR.My_Server_ID;
    rb_msg->type       = type;
    rb_msg->len        = payload_size;

    payload = (signed_message *)(rb_msg + 1);
    memcpy(payload, (void *)mess, payload_size);

    return rb_msg;
}

signed_message *VIEW_Construct_Report(void) 
{
    signed_message *report;
    report_message *report_specific;

    /* Construct new message */
    report = UTIL_New_Signed_Message();

    report_specific = (report_message *)(report + 1);

    report->machine_id = VAR.My_Server_ID;
    report->type       = REPORT;
    report->len        = sizeof(report_message);

    report_specific->rb_tag.machine_id = VAR.My_Server_ID;
    report_specific->rb_tag.view       = DATA.View;
    report_specific->rb_tag.seq_num    = 0;

    report_specific->execARU = DATA.ORD.ARU;
    report_specific->pc_set_size = DATA.VIEW.numSeq;

    return report;
}

signed_message *VIEW_Construct_PC_Set(void) 
{
    signed_message *pc_set;
    pc_set_message *pc_set_specific;

    /* Construct new message */
    pc_set = UTIL_New_Signed_Message();

    pc_set_specific = (pc_set_message *)(pc_set + 1);

    pc_set->machine_id = VAR.My_Server_ID;
    pc_set->type       = PC_SET;
    pc_set->len        = sizeof(pc_set_message);

    pc_set_specific->rb_tag.machine_id = VAR.My_Server_ID;
    pc_set_specific->rb_tag.view       = DATA.View;
    pc_set_specific->rb_tag.seq_num    = DATA.RB.rb_seq;

    assert(pc_set_specific->rb_tag.seq_num > 0);
    DATA.RB.rb_seq++;
    
    return pc_set;
}

signed_message *VIEW_Construct_VC_List(void)
{
    signed_message *vc_list;
    vc_list_message *vc_list_specific;

    /* Construct new message */
    vc_list          = UTIL_New_Signed_Message();
    vc_list_specific = (vc_list_message *)(vc_list + 1);

    vc_list->machine_id = VAR.My_Server_ID;
    vc_list->type       = VC_LIST;
    vc_list->len        = sizeof(vc_list_message);

    vc_list_specific->view = DATA.View;
    vc_list_specific->list = DATA.VIEW.complete_state;

    return vc_list;
}

signed_message *VIEW_Construct_VC_Partial_Sig(int32u list)
{
    signed_message         *vc_psig;
    vc_partial_sig_message *vc_psig_specific;
    int32u i, max_seq;
    byte digest[DIGEST_SIZE];

    /* Construct new message */
    vc_psig          = UTIL_New_Signed_Message();
    vc_psig_specific = (vc_partial_sig_message *)(vc_psig + 1);

    vc_psig->machine_id = VAR.My_Server_ID;
    vc_psig->type       = VC_PARTIAL_SIG;
    vc_psig->len        = sizeof(vc_partial_sig_message);

    vc_psig_specific->view = DATA.View;
    vc_psig_specific->list = list;
    memset(vc_psig_specific->partial_sig, 0, SIGNATURE_SIZE);

    /* Calculate startSeq from stored report messages of the
     *  servers in this list */
    max_seq = 0;
    for (i = 1; i <= NUM_SERVERS; i++) {
        if (UTIL_Bitmap_Is_Set(&list, i) && DATA.VIEW.max_pc_seq[i] > max_seq)
            max_seq = DATA.VIEW.max_pc_seq[i];
    }
    vc_psig_specific->startSeq = max_seq + 1;

    /* Generate partial signature over this message */
    OPENSSL_RSA_Make_Digest(vc_psig_specific, 3 * sizeof(int32u), digest);
    TC_Generate_Sig_Share(vc_psig_specific->partial_sig, digest);

    return vc_psig;
}

signed_message *VIEW_Construct_VC_Proof(int32u list, int32u startSeq, signed_message **m_arr)
{
    signed_message         *vc_proof;
    vc_proof_message       *vc_proof_specific;
    vc_partial_sig_message *vc_psig;
    int32u i;
    byte digest[DIGEST_SIZE];
    
    /* Construct new message */
    vc_proof          = UTIL_New_Signed_Message();
    vc_proof_specific = (vc_proof_message *)(vc_proof + 1);

    vc_proof->machine_id = VAR.My_Server_ID;
    vc_proof->type       = VC_PROOF;
    vc_proof->len        = sizeof(vc_proof_message);

    vc_proof_specific->view     = DATA.View;
    vc_proof_specific->list     = list;
    vc_proof_specific->startSeq = startSeq;
    memset(vc_proof_specific->thresh_sig, 0, SIGNATURE_SIZE);

    TC_Initialize_Combine_Phase(NUM_SERVERS + 1);

    for (i = 1; i <= NUM_SERVERS; i++) {
        if (m_arr[i] == NULL)
            continue;

        vc_psig = (vc_partial_sig_message *)(m_arr[i] + 1);
        if (vc_psig->startSeq != startSeq)
            continue;

        TC_Add_Share_To_Be_Combined(i, vc_psig->partial_sig);
    }
    
    OPENSSL_RSA_Make_Digest(vc_proof_specific, 3 * sizeof(int32u), digest);
    TC_Combine_Shares(vc_proof_specific->thresh_sig, digest);
    TC_Destruct_Combine_Phase(NUM_SERVERS + 1);

    if (!TC_Verify_Signature(1, vc_proof_specific->thresh_sig, digest)) {
      Alarm(PRINT, "Construct_VC_Proof: combined TC signature failed to verify!\n");
      Alarm(PRINT, "  Someone is malicious, and we can identify and prove it!\n");
      Alarm(PRINT, "  Proof check not yet invoked from TC library\n");
      dec_ref_cnt(vc_proof);
      return NULL;
    }
   
    return vc_proof;
}

signed_message *VIEW_Construct_Replay(vc_proof_message *vc_proof)
{
    signed_message      *replay;
    replay_message      *replay_specific;

    /* Construct new message */
    replay          = UTIL_New_Signed_Message();
    replay_specific = (replay_message *)(replay + 1);

    replay->machine_id  = VAR.My_Server_ID;
    replay->type        = REPLAY;
    replay->len         = sizeof(replay_message);

    replay_specific->view       = vc_proof->view;
    replay_specific->list       = vc_proof->list;
    replay_specific->startSeq   = vc_proof->startSeq;
    memcpy(replay_specific->thresh_sig, vc_proof->thresh_sig, SIGNATURE_SIZE);

    return replay;
}

signed_message *VIEW_Construct_Replay_Prepare(void)
{
    signed_message          *re_prepare;
    replay_prepare_message  *re_prepare_specific;
    replay_message          *replay;

    /* Construct new message */
    re_prepare          = UTIL_New_Signed_Message();
    re_prepare_specific = (replay_prepare_message *)(re_prepare + 1);
    replay              = (replay_message *)(DATA.VIEW.replay + 1);

    re_prepare->machine_id = VAR.My_Server_ID;
    re_prepare->type       = REPLAY_PREPARE;
    re_prepare->len        = sizeof(replay_prepare_message);

    re_prepare_specific->view = replay->view;
    memcpy(re_prepare_specific->digest, DATA.VIEW.replay_digest, DIGEST_SIZE);

    return re_prepare;
}

signed_message *VIEW_Construct_Replay_Commit(void)
{
    signed_message         *re_commit;
    replay_commit_message  *re_commit_specific;
    replay_message         *replay;

    /* Construct new message */
    re_commit          = UTIL_New_Signed_Message();
    re_commit_specific = (replay_commit_message *)(re_commit + 1);
    replay             = (replay_message *)(DATA.VIEW.replay + 1);

    re_commit->machine_id = VAR.My_Server_ID;
    re_commit->type       = REPLAY_COMMIT;
    re_commit->len        = sizeof(replay_commit_message);

    re_commit_specific->view = replay->view;
    memcpy(re_commit_specific->digest, DATA.VIEW.replay_digest, DIGEST_SIZE);

    return re_commit;
}

signed_message *PR_Construct_ORD_Certificate(struct dummy_ord_slot *slot)
{
    signed_message          *oc;
    ord_certificate_message *oc_specific;
    char                    *offset;
    int32u                   i, size, ccount;

    /* Construct new message */
    oc          = UTIL_New_Signed_Message();
    oc_specific = (ord_certificate_message *)(oc + 1);

    oc->machine_id = VAR.My_Server_ID;
    oc->type       = ORD_CERT;
    oc->len        = sizeof(ord_certificate_message);

    oc_specific->view    = slot->view;
    oc_specific->seq_num = slot->seq_num;
    oc_specific->type    = slot->type;
    oc_specific->flag    = CERT_CATCHUP;

    offset = ((char *)oc) + sizeof(signed_message) + sizeof(ord_certificate_message);

    /* Always send pre-prepares - TODO - resolve parts issue */
    size = UTIL_Message_Size(slot->pre_prepare_parts_msg[1]);
    memcpy(offset, slot->pre_prepare_parts_msg[1], size);
    oc->len += size;
    offset += size;

    /* If the slot is NO_OP or PC_SET, stop here */
    if (slot->type == SLOT_NO_OP || slot->type == SLOT_PC_SET)
        return oc;

    /* Otherwise, this is a normal COMMIT certificate, we need to add the 2f+k+1 commits */
    assert(slot->type == SLOT_COMMIT);

    /* Next, grab the 2f+k+1 commits */
    ccount = 0;
    for (i = 1; i <= NUM_SERVERS && ccount < 2*VAR.F + VAR.K + 1; i++) {
        if (slot->commit_certificate.commit[i] == NULL)
            continue;

        size = UTIL_Message_Size(slot->commit_certificate.commit[i]);
        memcpy(offset, slot->commit_certificate.commit[i], size);
        oc->len += size;
        offset += size;
        ccount++;
    }   
    assert(ccount == 2*VAR.F + VAR.K + 1); 

    return oc;
}

signed_message *PR_Construct_PO_Certificate()
{
    return NULL;
}

signed_message *PR_Construct_Catchup_Request(void)
{
    signed_message              *cr;
    catchup_request_message     *cr_specific;

    /* Construct new message */
    cr          = UTIL_New_Signed_Message();
    cr_specific = (catchup_request_message *)(cr + 1);

    cr->machine_id = VAR.My_Server_ID;
    cr->type       = CATCHUP_REQUEST;
    cr->len        = sizeof(catchup_request_message);

    //cr_specific->view = DATA.View;
    cr_specific->aru  = DATA.ORD.ARU;
    
    return cr;
}

#if 0
signed_message *PR_Construct_Catchup_Reply( int32u seq_num, int32u slot_type )
{
    signed_message            *cr;
    catchup_reply_message     *cr_specific;

    /* Construct new message */
    cr          = UTIL_New_Signed_Message();
    cr_specific = (catchup_reply_message *)(cr + 1);

    cr->machine_id = VAR.My_Server_ID;
    cr->type       = CATCHUP_REPLY;
    cr->len        = sizeof(catchup_reply_message);

    cr_specific->view    = DATA.View;
    cr_specific->seq_num = seq_num;
    cr_specific->type    = slot_type;
    
    return cr;
}
#endif

signed_message *RECON_Construct_Recon_Erasure_Message(dll_struct *list,
						      int32u *more_to_encode)
{
  signed_message *mess;
  erasure_part *part;
  erasure_part_obj *ep;
  recon_message *r;
  recon_part_header *rph;
  int32u cutoff, bytes;
  char *p;

  mess = UTIL_New_Signed_Message();

  mess->type       = RECON;
  mess->machine_id = VAR.My_Server_ID;
  mess->len        = 0; /* Set below when we add parts */

  r = (recon_message *)(mess + 1);

  r->num_parts = 0; /* Updated as we add parts */

  /* This message may have local Merkle tree digests, and it needs to 
   * fit into a local PO-Request to be ordered, which might have 
   * digests of its own, along with a signed message and a po_request. */
  cutoff = (PRIME_MAX_PACKET_SIZE - (DIGEST_SIZE * MAX_MERKLE_DIGESTS));
  
  bytes = sizeof(signed_message) + sizeof(recon_message);

  /* Start writing parts right after the recon_message */
  p = (char *)(r+1);

  assert(!UTIL_DLL_Is_Empty(list));

  /* Go through as many message on the list as we can.  Encode each one,
   * then write the part you're supposed to send into the packet. */
  while(bytes < cutoff) {
    UTIL_DLL_Set_Begin(list);

    /* If there are no more messages to encode, stop.  Otherwise, grab one, 
     * see if the part will fit in the message, and encode it. */
    if((ep = (erasure_part_obj *)UTIL_DLL_Front_Message(list)) == NULL) {
      *more_to_encode = 0;
      break;
    }    

    if((bytes + sizeof(recon_part_header) + ep->part_len) < cutoff) {

      /* Write the preorder id of the part being encoded */
      rph = (recon_part_header *)p;
      rph->originator = ep->originator;
      rph->seq        = ep->seq;

      /* Write the length of the part being encoded, including the erasure
       * part, which contains the message length. This is how many bytes
       * follows the rph. */
      rph->part_len = ep->part_len;

      /* Write the part itself right after the header, and write the 
       * length of the message being encoded. */
      part = (erasure_part *)(rph + 1);
      part->mess_len = ep->part.mess_len;
      
      /* Skip past the erasure_part */
      p = (char *)(part+1);
      
      /* Now write the part itself */
      memcpy(p, ep->buf, ep->part_len - sizeof(erasure_part));
      p += (ep->part_len - sizeof(erasure_part));
      
      /* We wrote this many bytes to the packet */
      bytes += sizeof(recon_part_header) + ep->part_len;

      r->num_parts++;
      UTIL_DLL_Pop_Front(list);
    }
    else {
      *more_to_encode = 1;
      break;
    }
  }
  
  assert(bytes <= cutoff);
  assert(r->num_parts > 0);
  mess->len = bytes - sizeof(signed_message);

  return mess;
}
