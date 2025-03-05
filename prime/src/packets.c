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

#include <string.h>
#include <assert.h>
#include "packets.h"
#include "utility.h"
#include "data_structs.h"
#include "signature.h"
#include "pre_order.h"
#include "order.h"
#include "catchup.h"
#include "merkle.h"
#include "validate.h"
#include "recon.h"
#include "tc_wrapper.h"
#include "proactive_recovery.h"

#include "spu_alarm.h"
#include "spu_memory.h"

extern server_data_struct DATA; 
extern server_variables   VAR;
extern benchmark_struct   BENCH;

signed_message* PRE_ORDER_Construct_PO_Request()
{
  signed_message *po_request;
  po_request_message *po_request_specific;
  update_message *up;
  int32u bytes, this_mess_len, num_events, wa_bytes, cutoff, special_first;
  signed_message *mess;
  char *p;

  /* Check for special case: If I am a recovering replica, the first PO_Request
   * I send must be TPM-signed, containing a single update that was generated
   * by my own Prime replica (also signed by TPM) */
  special_first = 0;

    if (DATA.PR.recovery_status[VAR.My_Server_ID] == PR_RECOVERY && DATA.PO.po_seq.seq_num == 0) {
    if ((mess = UTIL_DLL_Front_Message(&DATA.PO.po_request_dll)) == NULL)
        return NULL;
    up = (update_message *)(mess + 1);
    if (mess->machine_id != VAR.My_Server_ID || up->seq_num != 1)
        return NULL;
    special_first = 1;
  }

  /* Construct new message */
  po_request          = UTIL_New_Signed_Message();
  po_request_specific = (po_request_message *)(po_request + 1);

  /* Fill in the message based on the event. We construct a message
   * that contains the event by copying the event (which may or may
   * not be a signed message) into the PO Request message. */
  
  po_request->machine_id       = VAR.My_Server_ID;
  po_request->incarnation      = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
  po_request->type             = PO_REQUEST;
  DATA.PO.po_seq.seq_num++;
  po_request_specific->seq     = DATA.PO.po_seq;
  //printf("Construct_PO_Request: inc=%lu, seq=%lu\n",po_request_specific->seq.incarnation,po_request_specific->seq.seq_num);
  /* Special Case - If I am recovering and this is my first po_request,
   * it will be TPM-signed. Setup accordingly */
  /* special_first = 0;
  if (DATA.PR.recovery_status[VAR.My_Server_ID] == PR_RECOVERY &&
        po_request_specific->seq.seq_num == 1) 
  {
    Alarm(PRINT, "Creating First po_request TPM-signed Messsage\n");
    po_request->monotonic_counter = 1;
    special_first = 1;
  } */

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

    /* if (special_first) {
      up = (update_message *)(mess + 1);
      assert(up->seq_num == 1);
    } */
      
    this_mess_len = mess->len + sizeof(signed_message) + wa_bytes;

    if((bytes + this_mess_len) < cutoff) {
      num_events++;
      bytes += this_mess_len;

      /* Copy it into the packet */
      memcpy(p, mess, this_mess_len);
      p += this_mess_len;

      UTIL_DLL_Pop_Front(&DATA.PO.po_request_dll);

      if (special_first) {
        Alarm(PRINT, "Creating First po_request TPM-signed Messsage\n");
        po_request->monotonic_counter = 1;
        break;
      }
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

signed_message* PRE_ORDER_Construct_PO_Ack(int32u *more_to_ack, int32u send_all_non_preordered)
{
  signed_message *po_ack;
  po_ack_message *po_ack_specific;
  po_ack_part *ack_part;
  int32u nparts;
  int32u sm, i;
  po_slot *slot;
  int32u po_request_len;
  po_seq_pair ps;

  /* Construct new message */
  po_ack          = UTIL_New_Signed_Message();
  po_ack_specific = (po_ack_message*)(po_ack + 1);
  
  po_ack->machine_id  = VAR.My_Server_ID;
  po_ack->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
  po_ack->type        = PO_ACK;
  po_ack->len         = sizeof(po_ack_message);   // updated later with ack_parts
          
  /* Write in the latest preinstalled incarnation for each server */
  for (i = 0; i < VAR.Num_Servers; i++) 
    po_ack_specific->preinstalled_incarnations[i] = DATA.PR.preinstalled_incarnations[i+1];

  /* we must ack all of the unacked po request messages, received contiguously */
  ack_part = (po_ack_part *)(po_ack_specific + 1);
  nparts = 0;

  /* Use the placeholder to start off at the correct server */
  if (DATA.PO.po_ack_start_server == 0)
    sm = 1;
  else
    sm = DATA.PO.po_ack_start_server;

  for(; sm <= VAR.Num_Servers; sm++) {

    DATA.PO.po_ack_start_server = sm;
    
    if (send_all_non_preordered) {
        if (PRE_ORDER_Seq_Compare(DATA.PO.po_ack_start_seq, DATA.PO.cum_aru[sm]) >= 0){
            //printf("ps set to po_ack_start_seq =%lu\n",DATA.PO.po_ack_start_seq.seq_num);
	    ps = DATA.PO.po_ack_start_seq;
	}
        else{
            //printf("ps set to cum_aru =%lu\n",DATA.PO.po_ack_start_seq.seq_num);
            ps = DATA.PO.cum_aru[sm];
	}
        if (ps.incarnation < DATA.PR.preinstalled_incarnations[sm]) {
            //printf("ps set to 0\n");
            ps.incarnation = DATA.PR.preinstalled_incarnations[sm];
            ps.seq_num = 0;
        }
    	} else {
           // printf("ps set to max_acked=%lu\n",DATA.PO.max_acked[sm].seq_num);
        ps = DATA.PO.max_acked[sm];
    }
    ps.seq_num += 1;
    Alarm(DEBUG,"PRE_ORDER_Construct_PO_Ack seq_num=%lu\n",ps.seq_num);
    //assert(DATA.PO.max_acked[sm] <= DATA.PO.aru[sm]);
    //assert(PRE_ORDER_Seq_Compare(DATA.PO.max_acked[sm], DATA.PO.aru[sm]) <= 0);
    assert(ps.incarnation == DATA.PO.aru[sm].incarnation);
    
    Alarm(DEBUG,"Before for loop DATA.PO.aru[%d].seq_num=%d\n",sm,DATA.PO.aru[sm].seq_num);
    for(; ps.seq_num <= DATA.PO.aru[sm].seq_num; ps.seq_num++) {

    Alarm(DEBUG,"\t\tDATA.PO.aru[%d].seq_num=%d\n",sm,DATA.PO.aru[sm].seq_num);
      DATA.PO.po_ack_start_seq = ps;

      if (ps.seq_num > DATA.PO.max_acked[sm].seq_num)
        DATA.PO.max_acked[sm].seq_num = ps.seq_num;
      slot = UTIL_Get_PO_Slot_If_Exists(sm, ps);
      
      if(slot == NULL) {
        /* We received a PO-Request but decided not to ack yet due to 
         * aggregation.  Then we order the PO-Request using acks from 
         * the other servers.  Now we're ready to send the ack but we've
         * already garbage collected!  This is ok.  Just pretend like
         * we're acking; everyone else will execute eventually. */
        Alarm(DEBUG, "Continuing locally on %d (%d,%d). WL = %d\n", sm, 
                ps.incarnation, ps.seq_num, DATA.PO.white_line[sm]);
        assert(PRE_ORDER_Seq_Compare(DATA.PO.white_line[sm], ps) >= 0);
        continue;
      }

  
#if RECON_ATTACK
      /* Faulty servers don't ack anyone else's stuff */
      if (UTIL_I_Am_Faulty() && sm > VAR.F)
        continue;
#endif

      memset(ack_part, 0, sizeof(po_ack_part));
      ack_part->originator = sm;
      ack_part->seq        = ps;

      /* Now compute the digest of the event and copy it into the
       * digest field */
      po_request_len = UTIL_Message_Size(slot->po_request);
      OPENSSL_RSA_Make_Digest((byte *)(slot->po_request), po_request_len, ack_part->digest);      

      /* Advance the pointers to get ready for the next part on the next loop iteration */
      po_ack->len += sizeof(po_ack_part);
      ack_part = (po_ack_part *)(ack_part + 1);

      /* Increase the number of parts thus far in the po_ack message */
      nparts++;

      if(nparts == MAX_ACK_PARTS)
        goto finish;
    }

    DATA.PO.po_ack_start_seq.incarnation = 0;
    DATA.PO.po_ack_start_seq.seq_num = 0;

  }

  DATA.PO.po_ack_start_server = 0;
  
 finish:

  po_ack_specific->num_ack_parts = nparts;
  Alarm(DEBUG, "nparts=%d, more_to_ack=%d\n",nparts,*more_to_ack); 
  if (nparts == 0) {
    /* There is nothing in the ack -- we will not send it */
    *more_to_ack = 0;
    dec_ref_cnt( po_ack );
    return NULL;
  }

  if (nparts > MAX_ACK_PARTS) { 
    Alarm(EXIT,"%d BIG LOCAL ACK nparts = %d\n", VAR.My_Server_ID, nparts); 
  }

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

#if 0
signed_message* PRE_ORDER_Construct_PO_Ack(int32u *more_to_ack, int32u send_all_non_preordered)
{
  signed_message *po_ack, *ack_part;
  po_ack_message *po_ack_specific;
  po_ack_part *ack_part_specific;
  byte *ptr, *proot = NULL;
  byte signature[SIGNATURE_SIZE];
  int32u nparts;
  int32u sm, i, size;
  po_slot *slot;
  int32u po_request_len;
  po_seq_pair ps;

  /* Construct new message */
  po_ack          = UTIL_New_Signed_Message();
  po_ack_specific = (po_ack_message*)(po_ack + 1);
  
  po_ack->machine_id  = VAR.My_Server_ID;
  po_ack->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
  po_ack->type        = PO_ACK;
  po_ack->len         = sizeof(po_ack_message);   // updated later with ack_parts
  
  /* we must ack all of the unacked po request messages, received
   * contiguously */
  
  ptr = (byte *)(po_ack_specific + 1);
  //ack_part = (signed_message *)(po_ack_specific + 1);
  //ack_part_specific = (po_ack_part *)(ack_part + 1);
  nparts = 0;

  /* Use the placeholder to start off at the correct server */
  if (DATA.PO.po_ack_start_server == 0)
    sm = 1;
  else
    sm = DATA.PO.po_ack_start_server;

  for(; sm <= NUM_SERVERS; sm++) {

    DATA.PO.po_ack_start_server = sm;
    
    if (send_all_non_preordered) {
        //if (PRE_ORDER_Seq_Compare(DATA.PO.po_ack_start_seq, DATA.PO.last_executed_po_reqs[sm]) >= 0)
        if (PRE_ORDER_Seq_Compare(DATA.PO.po_ack_start_seq, DATA.PO.cum_aru[sm]) >= 0)
            ps = DATA.PO.po_ack_start_seq;
        else
            //ps = DATA.PO.last_executed_po_reqs[sm];
            ps = DATA.PO.cum_aru[sm];

        if (ps.incarnation < DATA.PR.preinstalled_incarnations[sm]) {
            ps.incarnation = DATA.PR.preinstalled_incarnations[sm];
            ps.seq_num = 0;
        }
    } else {
        ps = DATA.PO.max_acked[sm];
    }
    ps.seq_num += 1;

    //assert(DATA.PO.max_acked[sm] <= DATA.PO.aru[sm]);
    //assert(PRE_ORDER_Seq_Compare(DATA.PO.max_acked[sm], DATA.PO.aru[sm]) <= 0);
    assert(ps.incarnation == DATA.PO.aru[sm].incarnation);
    
    for(; ps.seq_num <= DATA.PO.aru[sm].seq_num; ps.seq_num++) {

      DATA.PO.po_ack_start_seq = ps;

      /* If my new incarnation is still pending (i.e. not yet executed) I am
       * ONLY allowed to ack PO-Requests that are also incarnation change
       * messages */
      /* if (DATA.PO.po_seq.incarnation > DATA.PO.last_executed_po_reqs[VAR.My_Server_ID].incarnation &&
          ps.seq_num != 1)
      {
        Alarm(DEBUG, "My Incarnation is still pending -- holding off on acking "
                     "%u %u from %u\n", DATA.PO.max_acked[sm].incarnation, ps.seq_num, sm);
        break;
      } */
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
        Alarm(DEBUG, "Continuing locally on %d (%d,%d). WL = %d\n", sm, 
                ps.incarnation, ps.seq_num, DATA.PO.white_line[sm]);
        assert(PRE_ORDER_Seq_Compare(DATA.PO.white_line[sm], ps) >= 0);
        continue;
      }

  
#if RECON_ATTACK
      /* Faulty servers don't ack anyone else's stuff */
      if (UTIL_I_Am_Faulty() && sm > NUM_F)
        continue;
#endif

      /* Create the po_ack_part message if it hasn't been created before,
       * or just copy the part if it is sitting around */
      if (slot->ack_received[VAR.My_Server_ID] == 0) {
          ack_part              = UTIL_New_Signed_Message();
          ack_part->machine_id  = VAR.My_Server_ID;
          ack_part->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
          ack_part->type        = PO_ACK_PART;
          ack_part->len         = sizeof(po_ack_part);

          ack_part_specific             = (po_ack_part *)(ack_part + 1);
          ack_part_specific->originator = sm;
          ack_part_specific->seq        = ps;

          /* Modified this.  Includes possible appended digest bytes and
           * does not subtract the signature_size. */
          /* po_request_len = (sizeof(signed_message) + slot->po_request->len +
                MT_Digests_(slot->po_request->mt_num) * DIGEST_SIZE); */
          po_request_len = UTIL_Message_Size(slot->po_request);

          /* Now compute the digest of the event and copy it into the
           * digest field */
          OPENSSL_RSA_Make_Digest((byte *)(slot->po_request), po_request_len,
                      ack_part_specific->digest);      

          /* Write in the latest preinstalled incarnation for each server */
          for (i = 0; i < NUM_SERVERS; i++) 
            ack_part_specific->preinstalled_incarnations[i] = DATA.PR.preinstalled_incarnations[i+1];

          /* Sign the po_ack_part message so it can be used independently in certificates later */
          //UTIL_RSA_Sign_Message(ack_part);

          /* Add to the PO_Ack Specific batch queue */
          UTIL_DLL_Add_Data(&DATA.PO.ack_batch_dll, ack_part);

          /* Free our pointer to the message, as now the DLL will store it */
          dec_ref_cnt(ack_part);
      }
      else {
          //memcpy(ack_part, slot->ack[VAR.My_Server_ID], UTIL_Message_Size(slot->ack[VAR.My_Server_ID]));
          size = UTIL_Message_Size(slot->ack[VAR.My_Server_ID]);
          memcpy(ptr, slot->ack[VAR.My_Server_ID], size);
          ptr += size;
          po_ack->len += size;
      }
      
      /* Advance the pointers to get ready for the next part on the next loop iteration */
      //ack_part = (signed_message *)(ack_part_specific + 1);
      //ack_part_specific = (po_ack_part *)(ack_part + 1);

      /* Increase the number of parts thus far in the po_ack message */
      nparts++;

      if(nparts == MAX_ACK_PARTS)
        goto finish;
    }

    DATA.PO.po_ack_start_seq.incarnation = 0;
    DATA.PO.po_ack_start_seq.seq_num = 0;

  }

  DATA.PO.po_ack_start_server = 0;
  
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

  /* Now, finish making the batch signatures on the po_ack_parts since we now
   * have a valid number of ack_parts 
   *
   * NOTE: while going through the loop, if we already signed an ack_part, we
   * just copied it into onto the message. ptr should be setup to the spot in the
   * po_ack to start copying in the parts that are about to be batch signed */
  proot = MT_Make_Digest_From_List(&DATA.PO.ack_batch_dll);
  memset(signature, 0, SIGNATURE_SIZE);
  OPENSSL_RSA_Make_Signature(proot, signature);

  i = 1;
  MT_Set_Num(DATA.PO.ack_batch_dll.length);
  while((ack_part = (signed_message *)UTIL_DLL_Front_Message(&DATA.PO.ack_batch_dll)) != NULL) 
  {
    /* Copy the signature onto the message */
    memcpy((byte *)ack_part, signature, SIGNATURE_SIZE);

    /* Generate Digests and append them to the message */
    MT_Extract_Set(i, ack_part);
    if(ack_part->mt_index > ack_part->mt_num) {
        Alarm(PRINT, "sn = %d, i = %d, index = %d, mt_num = %d\n",
            DATA.PO.ack_batch_dll.length, i, ack_part->mt_index, ack_part->mt_num);
        assert(0);
    }
    i++;

    /* Copy the message into the overarching po_ack message */
    size = UTIL_Message_Size(ack_part);
    memcpy(ptr, ack_part, size);
    ptr += size;
    po_ack->len += size;

    /* Pop this message off of the ack_batch_dll */
    UTIL_DLL_Pop_Front(&DATA.PO.ack_batch_dll);
  }
  
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
#endif

#if 0
signed_message* PRE_ORDER_Construct_PO_Ack(int32u *more_to_ack, int32u send_all_non_exec)
{
  signed_message *po_ack, *ack_part;
  po_ack_message *po_ack_specific;
  po_ack_part *ack_part_specific;
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
      /* if (DATA.PO.po_seq.incarnation > DATA.PO.last_executed_po_reqs[VAR.My_Server_ID].incarnation &&
          ps.seq_num != 1)
      {
        Alarm(DEBUG, "My Incarnation is still pending -- holding off on acking "
                     "%u %u from %u\n", DATA.PO.max_acked[sm].incarnation, ps.seq_num, sm);
        break;
      } */
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
#endif

signed_message* PRE_ORDER_Construct_PO_ARU()
{
  int32u s;
  signed_message *po_aru;
  po_aru_message *po_aru_specific;

  /* Construct new message */
  po_aru          = UTIL_New_Signed_Message();
  po_aru_specific = (po_aru_message*)(po_aru + 1);

  po_aru->machine_id  = VAR.My_Server_ID;
  po_aru->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
  po_aru->type        = PO_ARU;
  po_aru->len         = sizeof(po_aru_message);
  
  po_aru_specific->num         = ++DATA.PO.po_aru_num;

  for (s = 0; s < VAR.Num_Servers; s++) {
    /* Fill in vector of cumulative pre order acks */
    po_aru_specific->ack_for_server[s] = DATA.PO.cum_aru[s+1];
  }

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
    remaining_vectors = VAR.Num_Servers;    
    num_acks = (PRIME_MAX_PACKET_SIZE - sizeof(signed_message) - 
               sizeof(proof_matrix_message) - 
               (MAX_MERKLE_DIGESTS * DIGEST_SIZE)) / 
               sizeof(po_aru_signed_message);

    if (num_acks <  VAR.Num_Servers)
        Alarm(EXIT, "Proof_Matrix needs space! %u bytes needed\n",
            sizeof(signed_message) + sizeof(proof_matrix_message) +
            (MAX_MERKLE_DIGESTS * DIGEST_SIZE) +
            (VAR.Num_Servers * sizeof(po_aru_signed_message)));

    while (remaining_vectors > 0) {
        curr_part++;
        mset[curr_part] = UTIL_New_Signed_Message();
        mess = (signed_message *)mset[curr_part];

        mess->type        = PROOF_MATRIX;
        mess->machine_id  = VAR.My_Server_ID;
        mess->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
        mess->len         = 0; /* Set below */

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

    /* Tom: Check added for PR logic size increase to PO_ARU */
    if (*num_parts > 1) {
        Alarm(EXIT, "PM: num_parts too large, increase PRIME_MAX_PACKET_SIZE\n");
    }
}

signed_message* PRE_ORDER_Construct_Update(int32u type)
{
    signed_message *mess, *up_contents;
    update_message *up;
    po_seq_pair ps;

    /* Create the client update for my incarnation change */
    mess = UTIL_New_Signed_Message();
    up = (update_message *)(mess + 1); 
    up_contents = (signed_message *)(up + 1); 

    mess->machine_id = VAR.My_Server_ID;
    mess->type = UPDATE;
    mess->len = sizeof(signed_update_message) - sizeof(signed_message);

    //mess->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID]; 
      // ^ filled in Process_Update
    ps = DATA.PO.intro_client_seq[VAR.My_Server_ID];
    ps.seq_num++;
    mess->incarnation = ps.incarnation;

    /* Special Case - If I am recovering and this is my first po_request,
    * it will be TPM-signed. Setup accordingly */
    if (DATA.PR.recovery_status[VAR.My_Server_ID] == PR_RECOVERY &&
        ps.seq_num == 1) 
    {
        Alarm(PRINT, "Creating First Update TPM-signed Messsage\n");
        mess->monotonic_counter = 1;
    }

    up->server_id = VAR.My_Server_ID;
    /* * */ up->seq_num = ps.seq_num;
    
    up_contents->machine_id = VAR.My_Server_ID;
    up_contents->type = type;

    Alarm(DEBUG, "Construct Update: type=%u, [%d, %d, %d] using timestamp %u %u\n", 
            type, VAR.My_Server_ID, DATA.PO.po_seq.incarnation, 
            DATA.PO.po_seq.seq_num + 1, mess->incarnation, up->seq_num);

    /* Sign the update (using server key) */
    /* PRTODO - eventually replace this with TPM sign for the first update */
    UTIL_RSA_Sign_Message(mess);

    return mess;
}

void ORDER_Construct_Pre_Prepare(signed_message **mset,int32u *num_parts)
{
    signed_message *mess;
    pre_prepare_message *pp_specific;
    int32u curr_part, total_parts, i, index, length, remaining_vectors, num_acks;
    ord_slot *oslot;

    /* TODO: Possibly create a generic large-message handler
    * for all of Prime's message */
    curr_part = 0;
    index = 1;
    remaining_vectors =  VAR.Num_Servers;
    num_acks = (PRIME_MAX_PACKET_SIZE - sizeof(signed_message) - 
               sizeof(pre_prepare_message) - 
               (MAX_MERKLE_DIGESTS * DIGEST_SIZE)) / 
               sizeof(po_aru_signed_message);

    if (num_acks <  VAR.Num_Servers)
        Alarm(EXIT, "Proof_Matrix needs space! %u bytes needed\n",
            sizeof(signed_message) + sizeof(pre_prepare_message) +
            (MAX_MERKLE_DIGESTS * DIGEST_SIZE) +
            ( VAR.Num_Servers * sizeof(po_aru_signed_message)));

    /* TEST - forcing View Change for testing NO_OP and PC_SET messages */
    /* if (DATA.View == 1 && DATA.ORD.seq == 100)
        Alarm(EXIT, "TESTING ATTACK for NO_OP + PC_SET\n"); */
   
    while (remaining_vectors > 0) {
        curr_part++;
        if (curr_part > MAX_PRE_PREPARE_PARTS)
            Alarm(EXIT, "Message too large, exceeded MAX_PRE_PREPARE+PARTS\n");

        mset[curr_part] = UTIL_New_Signed_Message();
        mess = (signed_message *)mset[curr_part];
        memset(mset[curr_part], 0, PRIME_MAX_PACKET_SIZE);

        mess->type        = PRE_PREPARE;
        mess->machine_id  = VAR.My_Server_ID;
        mess->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
        mess->len         = 0; /* Set below */
        mess->global_configuration_number = DATA.NM.global_configuration_number;

        pp_specific              = (pre_prepare_message *)(mess+1);
        pp_specific->seq_num     = DATA.ORD.seq;
        pp_specific->view        = DATA.View;
        pp_specific->part_num    = curr_part;
        pp_specific->total_parts = 0; /* Set at the end of loop */

        Alarm(STATUS,"ORDER_Construct_Pre_Prepare with global config=%u\n",mess->global_configuration_number);
        /* timing tests */
        //pp_specific->sec  = E_get_time().sec; 
        //pp_specific->usec = E_get_time().usec;
       
        /* Copy the proposal digest into the Pre_Prepare */
        memcpy(&pp_specific->proposal_digest, &DATA.PR.proposal_digest, DIGEST_SIZE);

        /* Last executed vector. Special case for the first ordinal, since there
         * is no previous ordinal slot to carry over the made_eligible vector from */
        oslot = UTIL_Get_ORD_Slot_If_Exists(DATA.ORD.seq - 1);
        if (DATA.ORD.seq == 1) {
            memset(&pp_specific->last_executed, 0, sizeof(pp_specific->last_executed));
        }
        else {
            if (oslot == NULL)
                Alarm(EXIT, "ASSERT: ord_slot %u is NULL when creating PP for slot %u\n",
                        DATA.ORD.seq - 1, DATA.ORD.seq);
            memcpy(&pp_specific->last_executed, &oslot->made_eligible, sizeof(oslot->made_eligible));
        }

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
       
        memcpy((byte *)(pp_specific + 1), (byte *)(DATA.PO.cum_acks+index), length);

        UTIL_Stopwatch_Stop(&DATA.ORD.leader_duration_sw);
        if (DATA.ORD.inconsistent_pp_attack == 1 && DATA.ORD.inconsistent_pp_type == 1 &&
                oslot != NULL && oslot->collected_all_parts == 1 && 
                (UTIL_Stopwatch_Elapsed(&DATA.ORD.leader_duration_sw) > DATA.ORD.inconsistent_delay)) 
        {
            Alarm(PRINT, "Launching Inconsistent PP attack #1. seq = %u\n", pp_specific->seq_num);
            DATA.ORD.inconsistent_pp_attack = 0;
            DATA.ORD.inconsistent_pp_type = 0;
           
            po_aru_signed_message *cacks;
            cacks = (po_aru_signed_message *)(pp_specific + 1);
            cacks[0].cum_ack.ack_for_server[1].seq_num++;
        }

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

    /* Tom: Check added for PR logic size increase to PO_ARU */
    if (*num_parts > 1) {
        Alarm(EXIT, "PP: num_parts too large, increase PRIME_MAX_PACKET_SIZE\n");
    }
}

signed_message* ORDER_Construct_Prepare(complete_pre_prepare_message *pp)
{
  int32u i;
  signed_message *prepare;
  prepare_message *prepare_specific;

  /* Construct new message */
  prepare          = UTIL_New_Signed_Message();
  prepare_specific = (prepare_message *)(prepare + 1);

  prepare->machine_id  = VAR.My_Server_ID;
  prepare->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
  prepare->type        = PREPARE;
  prepare->len         = sizeof(prepare_message);
    
  prepare_specific->seq_num = pp->seq_num;
  prepare_specific->view    = pp->view;
  
  /* Now compute the digest of the content and copy it into the digest field */
  OPENSSL_RSA_Make_Digest((byte*)pp, sizeof(*pp), prepare_specific->digest);

  /* Write in the latest preinstalled incarnation for each server */
  for (i = 0; i <  VAR.Num_Servers; i++) 
    prepare_specific->preinstalled_incarnations[i] = DATA.PR.preinstalled_incarnations[i+1];
  
  return prepare;
}

signed_message *ORDER_Construct_Commit(complete_pre_prepare_message *pp)
{
  int32u i;
  signed_message *commit;
  commit_message *commit_specific;
  
  /* Construct new message */
  commit          = UTIL_New_Signed_Message();
  commit_specific = (commit_message*)(commit + 1);

  commit->machine_id  = VAR.My_Server_ID;
  commit->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
  commit->type        = COMMIT;
  commit->len         = sizeof(commit_message);

  commit_specific->seq_num = pp->seq_num;
  commit_specific->view    = pp->view;
  
  OPENSSL_RSA_Make_Digest((byte*)pp, sizeof(*pp), commit_specific->digest);

  /* Write in the latest preinstalled incarnation for each server */
  for (i = 0; i <  VAR.Num_Servers; i++) 
    commit_specific->preinstalled_incarnations[i] = DATA.PR.preinstalled_incarnations[i+1];

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

  response->machine_id  = VAR.My_Server_ID;
  response->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
  response->type        = CLIENT_RESPONSE;
  response->len         = sizeof(client_response_message) + UPDATE_SIZE;

  response_specific->machine_id   = client_id;      /* Original client ID */
  response_specific->incarnation  = incarnation;    /* Original client incarnation */
  response_specific->seq_num      = seq_num;
  response_specific->ord_num      = ord_num;
  response_specific->event_idx    = event_idx;
  response_specific->event_tot    = event_tot;
  response_specific->PO_time      = 0; 

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

  measure->machine_id  = VAR.My_Server_ID;
  measure->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
  measure->type        = TAT_MEASURE;
  measure->len         = sizeof(tat_measure_message);

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

  ping->machine_id  = VAR.My_Server_ID;
  ping->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
  ping->type        = RTT_PING;
  ping->len         = sizeof(rtt_ping_message);

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

  pong->machine_id  = VAR.My_Server_ID;
  pong->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
  pong->type        = RTT_PONG;
  pong->len         = sizeof(rtt_pong_message);

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

  measure->machine_id  = VAR.My_Server_ID;
  measure->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID]; 
  measure->type        = RTT_MEASURE;
  measure->len         = sizeof(rtt_measure_message);

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

  ub->machine_id  = VAR.My_Server_ID;
  ub->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
  ub->type        = TAT_UB;
  ub->len         = sizeof(tat_ub_message);

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

  new_leader->machine_id  = VAR.My_Server_ID;
  new_leader->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
  new_leader->type        = NEW_LEADER;
  new_leader->len         = sizeof(new_leader_message);

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

    new_leader_proof->machine_id  = VAR.My_Server_ID;
    new_leader_proof->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    new_leader_proof->type        = NEW_LEADER_PROOF;
    new_leader_proof->len         = sizeof(new_leader_proof_message);

    nlm_specific->new_view = DATA.View; /* We already preinstalled new view */

    count = 0;
    next_leader_msg = (char *)(nlm_specific + 1);

    for (i = 1; i <=  VAR.Num_Servers; i++) 
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
    int32u payload_size, sig_type;
    
    payload_size = sizeof(signed_message) + mess->len;

    /* Construct new message */
    rb_msg = UTIL_New_Signed_Message();

    rb_msg->machine_id  = VAR.My_Server_ID;
    rb_msg->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    rb_msg->type        = type;
    rb_msg->len         = payload_size;

    sig_type = VAL_Signature_Type(mess);
    if (sig_type == VAL_SIG_TYPE_TPM_SERVER || sig_type == VAL_SIG_TYPE_TPM_MERKLE)
        rb_msg->monotonic_counter = 1; //PRTODO: use TPM for this 

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

    report->machine_id  = VAR.My_Server_ID;
    report->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    report->type        = REPORT;
    report->len         = sizeof(report_message);

    report_specific->rb_tag.machine_id = VAR.My_Server_ID;
    report_specific->rb_tag.view       = DATA.View;
    report_specific->rb_tag.seq_num    = 0;

    report_specific->execARU = DATA.ORD.ARU;
    report_specific->pc_set_size = DATA.VIEW.numSeq;
#if 0
	Alarm(PRINT,"VIEW_Construct_Report:machine_id=%d, inc=%lu, rb_tag.view=%lu, execARU=%lu, pc_set_size=%d\n",report->machine_id, report->incarnation, report_specific->rb_tag.view,report_specific->execARU, report_specific->pc_set_size);
#endif
    return report;
}

signed_message *VIEW_Construct_PC_Set(void) 
{
    signed_message *pc_set;
    pc_set_message *pc_set_specific;

    /* Construct new message */
    pc_set = UTIL_New_Signed_Message();

    pc_set_specific = (pc_set_message *)(pc_set + 1);

    pc_set->machine_id  = VAR.My_Server_ID;
    pc_set->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    pc_set->type        = PC_SET;
    pc_set->len         = sizeof(pc_set_message);

    pc_set_specific->rb_tag.machine_id = VAR.My_Server_ID;
    pc_set_specific->rb_tag.view       = DATA.View;
    pc_set_specific->rb_tag.seq_num    = DATA.RB.rb_seq;

    assert(pc_set_specific->rb_tag.seq_num > 0);
    DATA.RB.rb_seq++;
#if 0
    Alarm(PRINT,"VIEW_Construct_PC_Set: inc=%lu, machine_id=%lu, view=%lu, seq_num=%d\n",pc_set->incarnation, pc_set_specific->rb_tag.machine_id, pc_set_specific->rb_tag.view, pc_set_specific->rb_tag.seq_num);
#endif 
    return pc_set;
}

signed_message *VIEW_Construct_VC_List(void)
{
    signed_message *vc_list;
    vc_list_message *vc_list_specific;

    /* Construct new message */
    vc_list          = UTIL_New_Signed_Message();
    vc_list_specific = (vc_list_message *)(vc_list + 1);

    vc_list->machine_id  = VAR.My_Server_ID;
    vc_list->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    vc_list->type        = VC_LIST;
    vc_list->len         = sizeof(vc_list_message);

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

    vc_psig->machine_id  = VAR.My_Server_ID;
    vc_psig->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    vc_psig->type        = VC_PARTIAL_SIG;
    vc_psig->len         = sizeof(vc_partial_sig_message);

    vc_psig_specific->view = DATA.View;
    vc_psig_specific->list = list;
    memset(vc_psig_specific->partial_sig, 0, SIGNATURE_SIZE);

    /* Calculate startSeq from stored report messages of the
     *  servers in this list */
    max_seq = 0;
    for (i = 1; i <=  VAR.Num_Servers; i++) {
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

    vc_proof->machine_id  = VAR.My_Server_ID;
    vc_proof->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    vc_proof->type        = VC_PROOF;
    vc_proof->len         = sizeof(vc_proof_message);

    vc_proof_specific->view     = DATA.View;
    vc_proof_specific->list     = list;
    vc_proof_specific->startSeq = startSeq;
    memset(vc_proof_specific->thresh_sig, 0, SIGNATURE_SIZE);

    TC_Initialize_Combine_Phase( VAR.Num_Servers + 1);

    for (i = 1; i <=  VAR.Num_Servers; i++) {
        if (m_arr[i] == NULL)
            continue;

        vc_psig = (vc_partial_sig_message *)(m_arr[i] + 1);
        if (vc_psig->startSeq != startSeq)
            continue;

        TC_Add_Share_To_Be_Combined(i, vc_psig->partial_sig);
    }
    
    OPENSSL_RSA_Make_Digest(vc_proof_specific, 3 * sizeof(int32u), digest);
    TC_Combine_Shares(vc_proof_specific->thresh_sig, digest);
    TC_Destruct_Combine_Phase( VAR.Num_Servers + 1);

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
    replay->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
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

    re_prepare->machine_id  = VAR.My_Server_ID;
    re_prepare->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    re_prepare->type        = REPLAY_PREPARE;
    re_prepare->len         = sizeof(replay_prepare_message);

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

    re_commit->machine_id  = VAR.My_Server_ID;
    re_commit->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    re_commit->type        = REPLAY_COMMIT;
    re_commit->len         = sizeof(replay_commit_message);

    re_commit_specific->view = replay->view;
    memcpy(re_commit_specific->digest, DATA.VIEW.replay_digest, DIGEST_SIZE);

    return re_commit;
}

signed_message *CATCH_Construct_ORD_Certificate(struct dummy_ord_slot *slot)
{
    signed_message          *oc;
    ord_certificate_message *oc_specific;
    commit_message          *commit_specific;
    char                    *offset;
    int32u                   i, size, ccount;

    /* Construct new message */
    oc          = UTIL_New_Signed_Message();
    oc_specific = (ord_certificate_message *)(oc + 1);

    oc->machine_id  = VAR.My_Server_ID;
    oc->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    oc->type        = ORD_CERT;
    oc->len         = sizeof(ord_certificate_message);

    oc_specific->view    = slot->view;
    oc_specific->seq_num = slot->seq_num;
    oc_specific->type    = slot->type;

    offset = ((char *)oc) + sizeof(signed_message) + sizeof(ord_certificate_message);

    /* Always send pre-prepares - TODO - resolve parts issue */
    size = UTIL_Message_Size(slot->pre_prepare_parts_msg[1]);
    memcpy(offset, slot->pre_prepare_parts_msg[1], size);
    oc->len += size;
    offset += size;

    /* If the slot is NO_OP or PC_SET, stop here */
    if (slot->type == SLOT_PC_SET || slot->type == SLOT_NO_OP || slot->type == SLOT_NO_OP_PLUS)
        return oc;

    /* Otherwise, this is a normal COMMIT certificate, we need to add the 2f+k+1 commits */
    assert(slot->type == SLOT_COMMIT);

    /* Next, grab the 2f+k+1 commits */
    ccount = 0;
    for (i = 1; i <=  VAR.Num_Servers && ccount < 2*VAR.F + VAR.K + 1; i++) {
        if (slot->commit_certificate.commit[i] == NULL)
            continue;

        /* Sanity check on the preinstalled incarnations vectors */
        commit_specific = (commit_message *)(slot->commit_certificate.commit[i] + 1);
        if (memcmp(commit_specific->preinstalled_incarnations, 
                   slot->preinstalled_snapshot+1, 
                    VAR.Num_Servers * sizeof(int32u)) != 0) {
            Alarm(PRINT, "Construct_ORD_Cert: memcmp for commit %u failed, ignoring\n", i);
            continue;
        }

        size = UTIL_Message_Size(slot->commit_certificate.commit[i]);
        memcpy(offset, slot->commit_certificate.commit[i], size);
        oc->len += size;
        offset += size;
        ccount++;
    }   
    assert(ccount == 2*VAR.F + VAR.K + 1); 

    return oc;
}

signed_message *CATCH_Construct_PO_Certificate(int32u rep, struct dummy_po_slot *slot)
{
    signed_message          *pc, *po_ack;
    po_certificate_message  *pc_specific;
    po_ack_message          *po_ack_specific;
    char                    *offset;
    int32u                   i, size, count;

    /* Construct new message */
    pc          = UTIL_New_Signed_Message();
    pc_specific = (po_certificate_message *)(pc + 1);

    pc->machine_id  = VAR.My_Server_ID;
    pc->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    pc->type        = PO_CERT;
    pc->len         = sizeof(po_certificate_message);

    pc_specific->server  = rep;
    pc_specific->seq     = slot->seq;

    offset = ((char *)pc) + sizeof(signed_message) + sizeof(po_certificate_message);

    /* Always send po_request */
    size = UTIL_Message_Size(slot->po_request);
    memcpy(offset, slot->po_request, size);
    pc->len += size;
    offset += size;

    /* Next, grab the 2f+k+1 po_acks */
    count = 0;
    for (i = 1; i <=  VAR.Num_Servers && count < 2*VAR.F + VAR.K + 1; i++) {
        if (slot->ack[i] == NULL)
            continue;

        po_ack = (signed_message *)(slot->ack[i]);
        po_ack_specific = (po_ack_message *)(po_ack + 1);

        /* Sanity check on the preinstalled incarnations vectors */
        if (memcmp(po_ack_specific->preinstalled_incarnations, 
                   slot->preinstalled_snapshot+1, 
                    VAR.Num_Servers * sizeof(int32u)) != 0) {
            Alarm(PRINT, "Construct_PO_Cert: memcmp for ack_part %u failed, ignoring\n", i);
            continue;
        }

        size = UTIL_Message_Size(po_ack);

        if (offset + size - ((char *)(pc)) >= PRIME_MAX_PACKET_SIZE) {
            Alarm(EXIT, "PO CERT too big! Last part is %u. #parts = %u \n", 
                    size, po_ack_specific->num_ack_parts);
        }

        memcpy(offset, slot->ack[i], size);
        pc->len += size;
        offset += size;
        count++;
    }
    if(count!=2*VAR.F + VAR.K + 1){
	Alarm(DEBUG,"CATCH_Construct_PO_Certificate: count=%d, f=%d, k=%d\n",count,VAR.F,VAR.K);
	}   
    assert(count == 2*VAR.F + VAR.K + 1); 

    return pc;
}

signed_message *CATCH_Construct_Catchup_Request(int32u catchup_flag)
{
    int32u                      i;
    signed_message              *cr;
    catchup_request_message     *cr_specific;

    /* Construct new message */
    cr          = UTIL_New_Signed_Message();
    cr_specific = (catchup_request_message *)(cr + 1);

    cr->machine_id        = VAR.My_Server_ID;
    cr->incarnation       = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    cr->type              = CATCHUP_REQUEST;
    cr->len               = sizeof(catchup_request_message);
    cr->monotonic_counter = 1;  // PRTODO: use TPM for this

    cr_specific->flag        = catchup_flag;
    cr_specific->nonce       = rand();   /* PRTODO: make sure this is enough entropy */
    cr_specific->aru         = DATA.ORD.ARU;
    for (i = 1; i <=  VAR.Num_Servers; i++)
        cr_specific->po_aru[i-1] = DATA.PO.cum_aru[i];
    memcpy(&cr_specific->proposal_digest, &DATA.PR.proposal_digest, DIGEST_SIZE);
    
    return cr;
}

signed_message *CATCH_Construct_Jump(int32u sender_nonce)
{
    signed_message              *jm;
    jump_message                *jm_specific;
    int32u                      size, i, dest_bits;
    ord_slot                    *oslot;
    byte                        *ptr;
    byte                        zero_sig[SIGNATURE_SIZE];

    /* Construct new message */
    jm          = UTIL_New_Signed_Message();
    jm_specific = (jump_message *)(jm + 1);

    jm->machine_id        = VAR.My_Server_ID;
    jm->incarnation       = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    jm->type              = JUMP;
    jm->len               = sizeof(jump_message);
    jm->monotonic_counter = 1;  // PRTODO: use TPM for this

    jm_specific->seq_num = DATA.ORD.ARU;
    jm_specific->acked_nonce = sender_nonce;
    memcpy(&jm_specific->proposal_digest, &DATA.PR.proposal_digest, DIGEST_SIZE);

    for (i = 1; i <=  VAR.Num_Servers; i++)
        jm_specific->installed_incarn[i-1] = DATA.PR.installed_incarnations[i];

    ptr = (byte *)(jm_specific + 1);
    if (DATA.ORD.ARU > 0) {
        /* Copy the ORD Cert @ DATA.ORD.ARU onto the message */
        oslot = UTIL_Get_ORD_Slot_If_Exists(DATA.ORD.ARU);
        assert(oslot);

        /* Force ord_certificate to be signed/processed */
        if (!oslot->signed_ord_cert) {
            assert(oslot->ord_certificate != NULL);
            dest_bits = 0;
            UTIL_Bitmap_Set(&dest_bits, VAR.My_Server_ID);
            SIG_Add_To_Pending_Messages(oslot->ord_certificate, dest_bits, 
                    UTIL_Get_Timeliness(ORD_CERT));
            SIG_Make_Batch(0, NULL);
            Alarm(DEBUG, "Force Make Batch when construct Jump ORD_Cert\n");
            assert(oslot->signed_ord_cert == 1);
	   
        }
        
        size = UTIL_Message_Size(oslot->ord_certificate);
        memcpy(ptr, oslot->ord_certificate, size);
        jm->len += size;
        ptr += size;
    }

    /* Copy the N new_incarnation messages onto the message */

    /* Copy the reset certificate here */
    /* First, force reset cert to be signed if needed */
    memset(zero_sig, 0, SIGNATURE_SIZE);
    if (memcmp(DATA.PR.reset_certificate->sig, zero_sig, SIGNATURE_SIZE) == 0) {
        SIG_Add_To_Pending_Messages(DATA.PR.reset_certificate, BROADCAST,
            UTIL_Get_Timeliness(RESET_CERT));
        SIG_Make_Batch(0, NULL);
        Alarm(DEBUG, "Force Make Batch for reset cert when constructing Jump\n");
    }
    size = UTIL_Message_Size(DATA.PR.reset_certificate);
    Alarm(DEBUG, "JUMP: Reset cert size %u\n", size);
    memcpy(ptr, DATA.PR.reset_certificate, size);
    jm->len += size;

    Alarm(DEBUG, "Constructed JUMP: size (pre Merkle) = %u\n", UTIL_Message_Size(jm));

    return jm;
}

signed_message *PR_Construct_New_Incarnation_Message()
{
    signed_message              *ni;
    new_incarnation_message     *ni_specific;
    sp_time now;

    /* Construct new message */
    ni          = UTIL_New_Signed_Message();
    ni_specific = (new_incarnation_message *)(ni + 1);

    ni->machine_id        = VAR.My_Server_ID;
    ni->incarnation       = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    ni->type              = NEW_INCARNATION;
    ni->len               = sizeof(new_incarnation_message);
    ni->monotonic_counter = 1;   // PRTODO: use TPM for monotonic counter

    now = E_get_time();
    ni_specific->timestamp = now.sec;
    ni_specific->nonce = rand();   /* PRTODO: make sure this is enough entropy */
    //printf("Generated New Incarnation with nonce : %lu,id=%d, conf=%lu\n",ni_specific->nonce,ni->machine_id,ni->global_configuration_number);
    /* PRTODO: Setup the public portion of the session key */
    memset(ni_specific->key, 0, DIGEST_SIZE);

    return ni;
}

signed_message *PR_Construct_Incarnation_Ack(signed_message *ni_mess)
{
    int32u                      sender;
    signed_message              *ia;
    incarnation_ack_message     *ia_specific;
    new_incarnation_message     *ni;

    sender = ni_mess->machine_id;
    ni = (new_incarnation_message *)(ni_mess + 1);

    /* Construct new message */
    ia          = UTIL_New_Signed_Message();
    ia_specific = (incarnation_ack_message *)(ia + 1);

    ia->machine_id        = VAR.My_Server_ID;
    ia->incarnation       = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    ia->type              = INCARNATION_ACK;
    ia->len               = sizeof(incarnation_ack_message);
    ia->monotonic_counter = 1;   // PRTODO: fix using TPM

    ia_specific->acked_id = sender;
    ia_specific->acked_incarnation = ni_mess->incarnation;

    /* Now compute the digest of the content and copy it into the digest field */
    OPENSSL_RSA_Make_Digest((byte*)ni_mess, sizeof(signed_message) + sizeof(*ni), ia_specific->digest);

    return ia;
}

signed_message *PR_Construct_Incarnation_Cert()
{
    int32u                          i, count, size;
    signed_message                  *ic;
    incarnation_cert_message        *ic_specific;
    byte                            *ptr;

    /* Construct new message */
    ic              = UTIL_New_Signed_Message();
    ic_specific     = (incarnation_cert_message *)(ic + 1);
    ptr             = (byte *)(ic_specific + 1);

    ic->machine_id        = VAR.My_Server_ID;
    ic->incarnation       = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    ic->type              = INCARNATION_CERT;
    ic->len               = sizeof(incarnation_cert_message);   /* increased below */
    ic->monotonic_counter = 1;  // PRTODO: update with TPM counter

    /* Copy in the new_incarnation message */
    size = UTIL_Message_Size(DATA.PR.new_incarnation[VAR.My_Server_ID]);
    memcpy(ptr, DATA.PR.new_incarnation[VAR.My_Server_ID], size);
    ic->len += size;
    ptr += size;

    count = 0;
    for (i = 1; i <=  VAR.Num_Servers && count < 2*VAR.F + VAR.K + 1; i++) {

        if (DATA.PR.recv_incarnation_ack[i] == NULL) 
            continue;

        size = UTIL_Message_Size(DATA.PR.recv_incarnation_ack[i]);
        memcpy(ptr, DATA.PR.recv_incarnation_ack[i], size);
        ic->len += size;;
        ptr += size;
        count++;
    }
    
    assert(count == 2*VAR.F + VAR.K + 1);
    return ic;
}

signed_message* PR_Construct_Pending_State(int32u target, int32u acked_nonce)
{
    signed_message              *psm, *share;
    pending_state_message       *psm_specific;
    int32u                      i, tot_shares, tot_po, tot_ord;
    stdit                       it;
    po_seq_pair                 ps;
    po_slot                     *pslot;
    ord_slot                    *oslot;

    /* Construct new message */
    psm          = UTIL_New_Signed_Message();
    psm_specific = (pending_state_message *)(psm + 1);

    psm->machine_id        = VAR.My_Server_ID;
    psm->incarnation       = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    psm->type              = PENDING_STATE;
    psm->len               = sizeof(pending_state_message);
    psm->monotonic_counter = 1;  // PRTODO: fix with TPM

    /* Calculate the number of total po_requests that we have received that 
     * have yet to be eligible for execution based on the matrix we have
     * at the ord_slot corresponding to our ARU */
    tot_shares = 0;
    tot_po = 0;
    oslot = UTIL_Get_ORD_Slot_If_Exists(DATA.ORD.ARU);
    if (oslot == NULL)
        assert(DATA.ORD.ARU == 0);

    for (i = 1; i <=  VAR.Num_Servers; i++) {
        if (oslot != NULL)
            ps = oslot->made_eligible[i-1];
        else {
            ps.incarnation = 0;
            ps.seq_num = 0;
        }
        stdhash_begin(&DATA.PO.History[i], &it);
        while (!stdhash_is_end(&DATA.PO.History[i], &it)) {
            pslot = *(po_slot **)stdit_val(&it);

            if (PRE_ORDER_Seq_Compare(pslot->seq, ps) > 0 && pslot->po_request != NULL) {
                /* Create the share and store it in the DLL for later */
                tot_shares++;
                tot_po++;
                share = PR_Construct_Pending_Share(tot_shares, pslot->po_request, acked_nonce);
                UTIL_DLL_Add_Data(&DATA.PR.outbound_pending_share_dll[target], share);
            }
            stdit_next(&it);
        }
    }

    /* Calculate the number of total pre_prepares that we have received
     * that have yet to be ordered above our ARU */
    tot_ord = 0;
    stdhash_begin(&DATA.ORD.History, &it);
    while (!stdhash_is_end(&DATA.ORD.History, &it)) {
        oslot = *(ord_slot **)stdit_val(&it);
        
        if (oslot->seq_num > DATA.ORD.ARU && oslot->collected_all_parts) {
            /* Create the share and store it in the DLL for later - TODO - resolve parts issue */
            tot_shares++;
            tot_ord++;
            share = PR_Construct_Pending_Share(tot_shares, oslot->pre_prepare_parts_msg[1], acked_nonce);
            UTIL_DLL_Add_Data(&DATA.PR.outbound_pending_share_dll[target], share);
        }
        stdit_next(&it);
    }

    psm_specific->seq_num = DATA.ORD.ARU;
    psm_specific->acked_nonce = acked_nonce;
    psm_specific->total_shares = tot_shares;

    Alarm(DEBUG, "Construct_Pending_State: ARU = %u, %u TOTAL shares: %u PO, %u ORD\n",
                DATA.ORD.ARU, tot_shares, tot_po, tot_ord);

    return psm;
}

signed_message* PR_Construct_Pending_Share(int32u index, signed_message *mess, int32u acked_nonce)
{
    signed_message              *pss;
    pending_share_message       *pss_specific;
    byte                        *ptr;
    int32u                      size;

    /* Construct new message */
    pss                = UTIL_New_Signed_Message();
    pss_specific       = (pending_share_message *)(pss + 1);

    pss->machine_id        = VAR.My_Server_ID;
    pss->incarnation       = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    pss->type              = PENDING_SHARE;
    pss->len               = sizeof(pending_share_message);

    /* Create this ORD/PO share based on what we have left to send */
    pss_specific->acked_nonce = acked_nonce;
    pss_specific->type  = mess->type;
    pss_specific->index = index;
    ptr = (byte *)(pss_specific + 1);
    size = UTIL_Message_Size(mess);
    memcpy(ptr, mess, size);
    pss->len += size;

    return pss;
}

signed_message *PR_Construct_Reset_Vote(signed_message *ni_mess)
{
    signed_message              *rv;
    reset_vote_message          *rv_specific;
    new_incarnation_message     *ni;

    ni = (new_incarnation_message *)(ni_mess + 1);

    /* Construct new message */
    rv          = UTIL_New_Signed_Message();
    rv_specific = (reset_vote_message *)(rv + 1);

    rv->machine_id        = VAR.My_Server_ID;
    rv->incarnation       = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    rv->type              = RESET_VOTE;
    rv->len               = sizeof(reset_vote_message);
    rv->monotonic_counter = 1;  // PRTODO: update with TPM counter

    rv_specific->acked_incarnation = ni_mess->incarnation;
    rv_specific->acked_nonce = ni->nonce;
    //printf("reset vote msg nonce=%lu, rv->machine_id=%d \n",rv_specific->acked_nonce,rv->machine_id);
    return rv;
}

signed_message *PR_Construct_Reset_Share()
{
    signed_message              *rs;
    reset_share_message         *rs_specific;
    new_incarnation_message     *ni;

    /* Construct new message */
    rs          = UTIL_New_Signed_Message();
    rs_specific = (reset_share_message *)(rs + 1);

    rs->machine_id        = VAR.My_Server_ID;
    rs->incarnation       = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    rs->type              = RESET_SHARE;
    rs->len               = sizeof(reset_share_message);
    rs->monotonic_counter = 1;  // PRTODO: update with TPM counter

    ni = (new_incarnation_message *)(DATA.PR.new_incarnation[VAR.My_Server_ID] + 1);
    rs_specific->view = DATA.View;
    rs_specific->nonce = ni->nonce;
    memcpy(rs_specific->key, ni->key, DIGEST_SIZE);

    return rs;
}

signed_message *PR_Construct_Reset_Proposal()
{
    int32u                      i, share_len, count;
    signed_message              *rp;
    reset_proposal_message      *rp_specific;
    byte                        *share_ptr;

    /* Construct the new message */
    rp          = UTIL_New_Signed_Message();
    rp_specific = (reset_proposal_message *)(rp + 1);
    share_ptr       = (byte *)(rp_specific + 1);

    rp->machine_id        = VAR.My_Server_ID;
    rp->incarnation       = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    rp->type              = RESET_PROPOSAL;
    rp->len               = sizeof(reset_proposal_message);   /* increased below */
    rp->monotonic_counter = 1;  // PRTODO: update with TPM counter

    rp_specific->view = DATA.View;
    rp_specific->num_shares = DATA.PR.reset_share_count;
    
    count = 0;
    for (i = 1; i <=  VAR.Num_Servers; i++) {

        if (DATA.PR.reset_share[i] == NULL) 
            continue;

        share_len = UTIL_Message_Size(DATA.PR.reset_share[i]);
        memcpy(share_ptr, DATA.PR.reset_share[i], share_len);
        rp->len += share_len;
        share_ptr += share_len;
        count++;
    }
    assert(count == rp_specific->num_shares);

    return rp;
}

signed_message *PR_Construct_Reset_Prepare()
{
    signed_message              *rp;
    reset_prepare_message       *rp_specific;
    reset_proposal_message      *rpm;

    /* Construct new message */
    rp          = UTIL_New_Signed_Message();
    rp_specific = (reset_prepare_message *)(rp + 1);

    rp->machine_id        = VAR.My_Server_ID;
    rp->incarnation       = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    rp->type              = RESET_PREPARE;
    rp->len               = sizeof(reset_prepare_message);
    rp->monotonic_counter = 1; // PRODO: fix with TPM counter
    
    rp_specific->view = DATA.View;

    /* Now compute the digest of the content and copy it into the digest field */
    rpm = (reset_proposal_message *)(DATA.PR.reset_proposal + 1);
    OPENSSL_RSA_Make_Digest((byte*)rpm, DATA.PR.reset_proposal->len, rp_specific->digest);

    return rp;
}

signed_message *PR_Construct_Reset_Commit()
{
    signed_message              *rc;
    reset_commit_message        *rc_specific;
    reset_proposal_message      *rpm;

    /* Construct new message */
    rc          = UTIL_New_Signed_Message();
    rc_specific = (reset_commit_message *)(rc + 1);

    rc->machine_id        = VAR.My_Server_ID;
    rc->incarnation       = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    rc->type              = RESET_COMMIT;
    rc->len               = sizeof(reset_commit_message);
    rc->monotonic_counter = 1; // PRODO: fix with TPM counter
    
    rc_specific->view = DATA.View;

    /* Now compute the digest of the content and copy it into the digest field */
    rpm = (reset_proposal_message *)(DATA.PR.reset_proposal + 1);
    OPENSSL_RSA_Make_Digest((byte*)rpm, DATA.PR.reset_proposal->len, rc_specific->digest);

    return rc;
}

signed_message *PR_Construct_Reset_NewLeader()
{
    signed_message           *rnl;
    reset_newleader_message  *rnl_specific;

    /* Construct new message */
    rnl             = UTIL_New_Signed_Message();
    rnl_specific    = (reset_newleader_message *)(rnl + 1);

    rnl->machine_id        = VAR.My_Server_ID;
    rnl->incarnation       = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    rnl->type              = RESET_NEWLEADER;
    rnl->len               = sizeof(reset_newleader_message);
    rnl->monotonic_counter = 1; // PRTODO: fix with TPM

    rnl_specific->new_view = DATA.View + 1;
    
    return rnl;
}

signed_message *PR_Construct_Reset_NewLeaderProof()
{
    int32u                          i, count, size;
    signed_message                  *rnlp, *stored;
    reset_newleader_message         *stored_specific;        
    reset_newleaderproof_message    *rnlp_specific;
    char                            *next_leader_msg;

    /* Construct new message */
    rnlp             = UTIL_New_Signed_Message();
    rnlp_specific    = (reset_newleaderproof_message *)(rnlp + 1);

    rnlp->machine_id        = VAR.My_Server_ID;
    rnlp->incarnation       = DATA.PR.new_incarnation_val[VAR.My_Server_ID]; 
    rnlp->type              = RESET_NEWLEADERPROOF;
    rnlp->len               = sizeof(reset_newleaderproof_message);
    rnlp->monotonic_counter = 1; // PRTODO: fix with TPM

    rnlp_specific->new_view = DATA.View; /* We already preinstalled new view */

    count = 0;
    next_leader_msg = (char *)(rnlp_specific + 1);

    for (i = 1; i <=  VAR.Num_Servers; i++) 
    {
        stored = DATA.PR.reset_newleader[i];
        if (stored == NULL)
            continue;

        stored_specific = (reset_newleader_message *)(stored + 1);
    
        if (stored_specific->new_view != DATA.View)
            continue;

        size = UTIL_Message_Size(stored);
        //size = sizeof(signed_message) + sizeof(reset_newleader_message);
        memcpy(next_leader_msg, stored, size);
        next_leader_msg += size;
        rnlp->len += size;
        count++;
    }

    assert(count == 2*VAR.F + VAR.K + 1);
    
    return rnlp;
}

signed_message *PR_Construct_Reset_ViewChange()
{
    signed_message              *rvc;
    reset_viewchange_message    *rvc_specific;
    reset_proposal_message      *rpo;
    reset_prepare_message       *rpp;
    char                        *offset;
    int32u                      i, size, ccount;
    byte                        proposal_digest[DIGEST_SIZE];

    /* Construct new message */
    rvc = UTIL_New_Signed_Message();
    rvc_specific = (reset_viewchange_message *)(rvc + 1);

    rvc->machine_id        = VAR.My_Server_ID;
    rvc->incarnation       = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    rvc->type              = RESET_VIEWCHANGE;
    rvc->len               = sizeof(reset_viewchange_message);
    rvc->monotonic_counter = 1; //PRTODO: fix with TPM

    rvc_specific->rb_tag.machine_id = VAR.My_Server_ID;
    rvc_specific->rb_tag.view       = DATA.View;
    rvc_specific->rb_tag.seq_num    = DATA.RB.rb_seq;
    DATA.RB.rb_seq++;

    /* If we have no prepare certificate for the proposal in the previous round */
    if (DATA.PR.reset_sent_commit == 0) {
        rvc_specific->contains_proposal = 0;
        return rvc;
    }

    /* Otherwise, we have a prepare certificate, include it here */
    rvc_specific->contains_proposal = 1;

    offset = (char *)(rvc_specific + 1);
    assert(DATA.PR.reset_proposal != NULL);
    size = UTIL_Message_Size(DATA.PR.reset_proposal);
    memcpy(offset, DATA.PR.reset_proposal, size);
    rvc->len += size;
    offset += size;

    rpo = (reset_proposal_message *)(DATA.PR.reset_proposal + 1);
    OPENSSL_RSA_Make_Digest((byte*)rpo, DATA.PR.reset_proposal->len, proposal_digest);

    /* Next, grab the 2f+k prepares */
    ccount = 0;
    for (i = 1; i <=  VAR.Num_Servers && ccount < 2*VAR.F + VAR.K; i++) {
        if (DATA.PR.reset_prepare[i] == NULL)
            continue;
        
        rpp = (reset_prepare_message *)(DATA.PR.reset_prepare[i] + 1);
        if (OPENSSL_RSA_Digests_Equal(rpp->digest, proposal_digest)) {
            size = UTIL_Message_Size(DATA.PR.reset_prepare[i]);
            memcpy(offset, DATA.PR.reset_prepare[i], size);
            rvc->len += size;
            offset += size;
            ccount++;
        }
    }   
    assert(ccount == 2*VAR.F + VAR.K); 

    return rvc;
}

signed_message *PR_Construct_Reset_NewView()
{
    signed_message              *rnv;
    reset_newview_message       *rnv_specific;

    /* Construct new message */
    rnv             = UTIL_New_Signed_Message();
    rnv_specific    = (reset_newview_message *)(rnv + 1);

    rnv->machine_id        = VAR.My_Server_ID;
    rnv->incarnation       = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    rnv->type              = RESET_NEWVIEW;
    rnv->len               = sizeof(reset_newview_message);
    rnv->monotonic_counter = 1; // PRTODO: fix with TPM

    rnv_specific->rb_tag.machine_id = VAR.My_Server_ID;
    rnv_specific->rb_tag.view       = DATA.View;
    rnv_specific->rb_tag.seq_num    = DATA.RB.rb_seq;    
    DATA.RB.rb_seq++;

    assert(UTIL_Bitmap_Num_Bits_Set(&DATA.PR.reset_viewchange_bitmap) == 2*VAR.F + VAR.K + 1);
    rnv_specific->list = DATA.PR.reset_viewchange_bitmap;

    return rnv;
}

signed_message *PR_Construct_Reset_Certificate()
{
    signed_message              *rc;
    reset_certificate_message   *rc_specific;
    char                        *offset;
    int32u                      i, size, count;

    /* Construct new message */
    rc          = UTIL_New_Signed_Message();
    rc_specific = (reset_certificate_message *)(rc + 1);

    rc->machine_id        = VAR.My_Server_ID;
    rc->incarnation       = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    rc->type              = RESET_CERT;
    rc->len               = sizeof(reset_certificate_message);
    rc->monotonic_counter = 1; // PRTODO: fix with TPM

    rc_specific->view = DATA.View;

    offset = (char *)(rc_specific + 1);
    
    /* Always send pre-prepares - TODO - resolve parts issue */
    size = UTIL_Message_Size(DATA.PR.reset_proposal);
    memcpy(offset, DATA.PR.reset_proposal, size);
    rc->len += size;
    offset += size;

    /* Next, grab the 2f+k+1 commits */
    count = 0;
    for (i = 1; i <=  VAR.Num_Servers && count < 2*VAR.F + VAR.K + 1; i++) {
        if (DATA.PR.reset_commit[i] == NULL)
            continue;

        size = UTIL_Message_Size(DATA.PR.reset_commit[i]);
        memcpy(offset, DATA.PR.reset_commit[i], size);
        rc->len += size;
        offset += size;
        count++;
    }   
    assert(count == 2*VAR.F + VAR.K + 1); 

    return rc;
}



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

  mess->type        = RECON;
  mess->machine_id  = VAR.My_Server_ID;
  mess->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
  mess->len         = 0; /* Set below when we add parts */

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
