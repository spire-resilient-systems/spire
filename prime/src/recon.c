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
#include "recon.h"
#include "spu_alarm.h"
#include "spu_memory.h"
#include "utility.h"
#include "pre_order.h"
#include "erasure.h"
#include "recon.h"
#include "order.h"
#include "process.h"
#include "signature.h"

extern server_variables   VAR;
extern server_data_struct DATA;

int32u RECON_Do_I_Send_Erasure(int32u machine_id, 
			       po_aru_signed_message *cum_acks);
void RECON_Update_Recon_White_Line (void);

void RECON_Process_Recon (signed_message *recon)
{
  int32u i, index, *ip;
  recon_message *r;
  recon_part_header *rph;
  erasure_part *part;
  recon_slot *slot;
  po_slot *po_slot;
  char *p;

  r = (recon_message *)(recon + 1);
  p = (char *)(r + 1);

  for(i = 0; i < r->num_parts; i++) {

    rph  = (recon_part_header *)p;
    part = (erasure_part *)(rph + 1);
    p = (char *)part;
    p += rph->part_len;

    /* If we've already contiguously collected PO-Requests for this or higher,
     * then we must already have it. Or if I've already garbage collected
     * this one, I must have it already*/
    if( (PRE_ORDER_Seq_Compare(rph->seq, DATA.PO.aru[rph->originator]) <= 0) ||
        (PRE_ORDER_Seq_Compare(rph->seq, DATA.PO.white_line[rph->originator]) <= 0)) 
    {
      Alarm(DEBUG, "Discarding Recon for %d %d %d from %d\n",
	    rph->originator, rph->seq.incarnation, rph->seq.seq_num, recon->machine_id);

      /* Move to the next part and continue */
      continue;
    }

    /* Even though I haven't collected contiguously, I may have the PO
     * request being reconciled.  Skip it in this case. */
    po_slot = UTIL_Get_PO_Slot_If_Exists(rph->originator, rph->seq);
    if(po_slot && po_slot->po_request) {
      /* Move to the next part and continue */
      continue;
    }
    
    /* We want to process this part.  Store a copy of it in the slot if
     * we need it. */
    slot = UTIL_Get_Recon_Slot(rph->originator, rph->seq);

    /* If we've already decoded this one, continue */
    if(slot->decoded) {
      Alarm(DEBUG, "Ignoring part for %d %d %d, already decoded\n",
	    rph->originator, rph->seq.incarnation, rph->seq.seq_num);
      continue;
    }

    /* We've already collected this part from this machine */
    if(slot->part_collected[recon->machine_id] != 0)
        continue;

    /* Mark that we now have the part from this server */
    slot->part_collected[recon->machine_id] = 1;
    slot->num_parts_collected++;
      
    Alarm(DEBUG, "Stored Local Recon for (%d, %d, %d) from %d\n", 
        rph->originator, rph->seq.incarnation, rph->seq.seq_num, recon->machine_id);

    /* Copy the part into the buffer */
    memcpy(slot->parts[recon->machine_id], part, rph->part_len);
      
    ip = (int32u *)(part + 1);
    index = ip[0];
    Alarm(DEBUG, "Part had index %d\n", index);

    /* If we have enough parts, we should decode */
    //if(slot->num_parts_collected < (NUM_F + 1))
    if(slot->num_parts_collected < (VAR.F + 1))
        continue;
        
    /* Make sure we need this one */
    assert(PRE_ORDER_Seq_Compare(DATA.PO.white_line[rph->originator], rph->seq) < 0);
    Alarm(DEBUG, "DATA.PO.aru[%d] = %d %d\n",
          rph->originator, DATA.PO.aru[rph->originator].incarnation,
          DATA.PO.aru[rph->originator].seq_num);

    slot->decoded = 1;
    RECON_Decode_Recon(slot);

    /* Note: Garbage collection is done at local execution time */
  }      
}

void RECON_Do_Recon (ord_slot *o_slot)
{
  complete_pre_prepare_message *pp;
  //complete_pre_prepare_message *prev_pp;
  ord_slot *prev_ord_slot;
  po_slot *p_slot;
  signed_message *req;
  po_request_message *rs;
  int32u gseq, i, j, k, should_send;
  po_seq_pair prev_pop[MAX_NUM_SERVER_SLOTS];
  po_seq_pair cur_pop[MAX_NUM_SERVER_SLOTS];
  po_seq_pair ps, zero_ps = {0, 0};
  int32u dest_bits, added_to_queue;
  dll_struct message_list, node_list;
  dll_struct erasure_server_dll[MAX_NUM_SERVER_SLOTS];

  /* If we've already reconciled this slot, don't do it again */
  if(o_slot->reconciled)
    return;

  /* We need to have a complete Pre-Prepare for this slot */
  if(o_slot->collected_all_parts == 0)
    return;
  
  pp   = &o_slot->complete_pre_prepare;
  gseq = pp->seq_num;
  
  /* First check to see if we've locally executed the previous global
   * sequence number. */
  prev_ord_slot = UTIL_Get_ORD_Slot_If_Exists(gseq - 1);

  /* The previous slot is allowed to be NULL only if this is the first seq.
   * Otherwise, it means we can't have a complete Pre-Prepare for that one
   * yet and should return. */
  if(prev_ord_slot == NULL && gseq != 1)
    return;
  
  /* We have a slot for the previous seq but not a complete Pre-Prepare */
  if(prev_ord_slot && prev_ord_slot->collected_all_parts == 0)
    return;

  /*-----If we get here, we're good to reconcile.-------*/

  /* See which PO-Requests are now eligible for execution by
   * comparing made_eligible - last_executed. First, setup
   * prev_pop as either last_executed or (0,0) if first ORD */
  if(prev_ord_slot == NULL) {
    assert(gseq == 1);

    for(i = 1; i <= VAR.Num_Servers; i++) 
      prev_pop[i] = zero_ps;
  }
  else {
    for(i = 1; i <= VAR.Num_Servers; i++) 
      prev_pop[i] = pp->last_executed[i-1];
  }

  /* Second, setup cur_pop as made_eligible, which should be setup
   * by now either when we sent our prepare or when we ordered 
   * (collected 2f+k+1 commits) */
  for (i = 1; i <= VAR.Num_Servers; i++) 
    cur_pop[i] = o_slot->made_eligible[i-1];

  UTIL_DLL_Initialize(&message_list);
  for(i = 1; i <= VAR.Num_Servers; i++) {

    assert(prev_pop[i].incarnation <= cur_pop[i].incarnation);
    if (prev_pop[i].incarnation < cur_pop[i].incarnation) {
         prev_pop[i].incarnation = cur_pop[i].incarnation;
         prev_pop[i].seq_num = 0;
    }
    ps.incarnation = prev_pop[i].incarnation;

    for(j = prev_pop[i].seq_num + 1; j <= cur_pop[i].seq_num; j++) {
      
      ps.seq_num = j; 
      p_slot = UTIL_Get_PO_Slot_If_Exists(i, ps);

      /* If I have this po_slot and its po_request, see if I'm supposed
       * to send a reconciliation message for it. */
      if(p_slot && (req = p_slot->po_request) != NULL) {

        rs = (po_request_message *)(req + 1);

	    dest_bits      = 0;
	    added_to_queue = 0;

        should_send = 
          RECON_Do_I_Send_Erasure(req->machine_id, pp->cum_acks);

        if(should_send) {

          for(k = 1; k <= VAR.Num_Servers; k++) {
            
            if(PRE_ORDER_Seq_Compare(DATA.PO.cum_max_acked[k][req->machine_id], 
                                        rs->seq) < 0 && k != req->machine_id)
            {
                //&& DATA.PO.Recon_Max_Sent[k][i] < rs->seq_num) {	      

              /* if(rs->seq_num % 1 == 0 && !UTIL_I_Am_Faulty())
                Alarm(DEBUG,"RECON: Server %d found %d needs (%d, %d) "
                  "and will send\n", VAR.My_Server_ID, k, i, j); 
                Alarm(DEBUG, "LastPOARU[%d][%d] = %d, rs->seq_num = %d\n",
                k, req->machine_id, 
                DATA.PO.cum_max_acked[k][req->machine_id], 
                rs->seq_num); */
              
              /* Add the message to the list only the first time
               * someone needs it */
              if(!added_to_queue) {

                if(USE_ERASURE_CODES == 0)  {
                  /* If we're throttling, add the PO-Request to the queue of
                  * pending messages directly, without signing it first. */

                  if(THROTTLE_OUTGOING_MESSAGES) {
                    int32u dest_bits = 0;
                    UTIL_Bitmap_Set(&dest_bits, k);
                    if(!UTIL_I_Am_Faulty()) {
                      NET_Add_To_Pending_Messages(req, dest_bits, 
                              UTIL_Get_Timeliness(RECON));
                    }
                  }
                  else {
                    /* If we're not throttling, just send it immediately */
                    if(!UTIL_I_Am_Faulty())
                      UTIL_Send_To_Server(req, k);
                  }
                }
                else { /* We're using erasure codes! */
                  /* We're using erasure codes!  Add request to the queue of 
                   * messages that need to be encoded.*/
                  UTIL_DLL_Add_Data(&message_list, req);
                  added_to_queue = 1;
                  Alarm(DEBUG, "Added (%d, %d, %d) to message list\n", i,
                            ps.incarnation, j);
                  //DATA.PO.Recon_Max_Sent[k][i] = j;
                }
              }	      

              /* Mark k as the server that needs it */
              UTIL_Bitmap_Set(&dest_bits, k);
              UTIL_DLL_Set_Last_Extra(&message_list, DEST, dest_bits);
            }
          }
        }
      }
    }
  }

  /* Mark that we've reconciled this slot and try to update the white
   * line. Also try to garbage collect the ord_slot. */
  o_slot->reconciled = 1;
  RECON_Update_Recon_White_Line();
  //ORDER_Attempt_To_Garbage_Collect_ORD_Slot(gseq);

  /* Return if nothing to do */
  if(UTIL_DLL_Is_Empty(&message_list))
    return;

  /* We now have a (potentially empty) message list containing the messages
   * I need to encode, along with their destinations. Encode each message
   * once (regardless of how many destinations there are). */
  UTIL_DLL_Initialize(&node_list);
  RECON_Create_Nodes_From_Messages(&message_list, &node_list);

  /* Now allocate the parts to each server that it needs */
  for(i = 1; i <= VAR.Num_Servers; i++)
    UTIL_DLL_Initialize(&erasure_server_dll[i]);

  RECON_Allocate_Recon_Parts_From_Nodes(&node_list, erasure_server_dll);
  
  /* Now build the packets for each server and add them to list of messages
   * awaiting a signature. */
  RECON_Build_Recon_Packets(erasure_server_dll);
}

int32u RECON_Do_I_Send_Erasure(int32u machine_id,
			       po_aru_signed_message *cum_acks)
{
  int32u s;
  po_seq_pair cack[ MAX_NUM_SERVER_SLOTS ];
  po_seq_pair scack[ MAX_NUM_SERVER_SLOTS ];
  bool could_send[ MAX_NUM_SERVER_SLOTS ];
  int32u sender_count;
  
  for(s = 1; s <= VAR.Num_Servers; s++) {
    cack[s]  = cum_acks[s-1].cum_ack.ack_for_server[machine_id-1];
    scack[s] = cum_acks[s-1].cum_ack.ack_for_server[machine_id-1];
  }
  
  /* sort the values */
  qsort((void*)(scack+1), VAR.Num_Servers, sizeof(po_seq_pair), poseqcmp);
  
  for(s = 1; s <= VAR.Num_Servers; s++)
    Alarm(DEBUG," (%d,%d,%d) ", s, cack[s].incarnation, cack[s].seq_num);  
  Alarm(DEBUG,"\n");
  
  for(s = 1; s <= VAR.Num_Servers; s++) 
    could_send[s] = (PRE_ORDER_Seq_Compare(cack[s],scack[VAR.F + VAR.K + 1]) >= 0) ? TRUE : FALSE;
    //could_send[s] = (PRE_ORDER_Seq_Compare(cack[s],scack[NUM_F + NUM_K + 1]) >= 0) ? TRUE : FALSE;
  sender_count = 0;

  if(could_send[VAR.My_Server_ID] == TRUE) {
    for(s = 1; s <= VAR.Num_Servers; s++) {
      if(could_send[s] == TRUE) 
	    sender_count++;
      if(s == VAR.My_Server_ID) {

#if 0
	if(s == machine_id) {
	  int i;

	  Alarm(PRINT, "Cack: [ ");
	  for(i = 1; i <= VAR.Num_Servers_IN_SITE; i++)
	    Alarm(PRINT, "%d ", cack[i]);
	  Alarm(PRINT, "]\n");

	  Alarm(PRINT, "Scack: [ ");
	  for(i = 1; i <= VAR.Num_Servers_IN_SITE; i++)
	    Alarm(PRINT, "%d ", scack[i]);
	  Alarm(PRINT, "]\n");
	  
	  //assert(0);
	}
#endif
	
	    return TRUE;
      }

      if(sender_count == (2*VAR.F + VAR.K + 1))   /* 2f+k+1 */
	    return FALSE;
    }
  }
  
  return FALSE;
}

void RECON_Update_Recon_White_Line()
{
  ord_slot *slot;
  int32u seq;

  while(1) {
    
    seq = DATA.ORD.recon_white_line + 1;

    slot = UTIL_Get_ORD_Slot_If_Exists(seq);
    if(slot != NULL && slot->reconciled) {
      //ORDER_Attempt_To_Garbage_Collect_ORD_Slot(seq);
      DATA.ORD.recon_white_line++;
    }
    else {
      if (seq <= DATA.ORD.ARU) Alarm(PRINT, "Update Recon white line failed for %d (white line = %d)\n", seq, DATA.ORD.recon_white_line);
      if (slot == NULL && seq <= DATA.ORD.ARU) {
        Alarm(PRINT, "Slot == NULL (seq %d, white line %d)\n", seq, DATA.ORD.recon_white_line);
      } else if (seq <= DATA.ORD.ARU) {
        Alarm(PRINT, "slot->reconciled: %d, slot->seq_num %d, slot->view %d, slot->complete_pp->seq_num %d, slot->executed %d\n", slot->reconciled, slot->seq_num, slot->view, slot->complete_pre_prepare.seq_num, slot->executed);
      }
      break;
    }
  }
}

void RECON_Decode_Recon(recon_slot *slot)
{
  signed_message *mess;
  erasure_part *part;
  int32u i, message_len, ret;
  int32u mpackets, rpackets;
  int32u initialized;
  /*po_request_message *req;*/
  
  initialized = 0;
  message_len = 0;
  ERASURE_Clear();
  
  for(i = 1; i <= VAR.Num_Servers; i++) {
    /* We have a part from this server.  */
    if(slot->part_collected[i]) {
      
      part = (erasure_part *)slot->parts[i];
      
      /* If we have not yet initialized the decoding, do so */
      if(initialized == 0) {
        initialized = 1;
        
        assert(part->mess_len != 0);
        message_len = part->mess_len;
        Alarm(DEBUG, "Initialized decoding with len %d\n", message_len);
        
        /* Message was encoded into 3f+1 parts, f+1 of which are
           needed to decode. */
        mpackets = (VAR.F + 1);
        rpackets = (2*VAR.F + 2*VAR.K);
        
        ERASURE_Initialize_Decoding(message_len, mpackets, rpackets);
      }
      else {
        if(part->mess_len != message_len) {
          Alarm(PRINT, "Decode Recon: "
            "Part->mess_len = %d, message_len = %d, i = %d\n",
            part->mess_len, message_len, i);
          assert(0);
        }
      }
      
      assert(initialized);
      ERASURE_Set_Encoded_Part(part);
    }
  }
   
  /* Now decode the message */
  mess = UTIL_New_Signed_Message();
  if((ret = ERASURE_Decode(mess)) != 0) {
    Alarm(EXIT, "Could not decode local recon!\n");
  }
  
  /* Sanity check */
  if(message_len != UTIL_Message_Size(mess)) {
    Alarm(PRINT, "Decode Local Recon: Message_len = %d, expected %d\n",
	  message_len, UTIL_Message_Size(mess));
    Alarm(PRINT, "Type = %d, Len = %d\n", mess->type, mess->len);
    assert(0);
  }
  
#if 0
  if(VAL_Validate_Message(mess, message_len) == 0)
    Alarm(EXIT, "Validate failed in Erasure_Decode_Local_Recon\n");
#endif    
  
  assert(mess->type == PO_REQUEST);

/* #if 1
  req = (po_request_message *)(mess+1);
  
  if(req->seq_num % 250 == 0)
    Alarm(PRINT, "Decoded %d %d\n", mess->machine_id, req->seq_num);
#endif */
  
  PROCESS_Message(mess);
  dec_ref_cnt(mess);
}

void RECON_Create_Nodes_From_Messages(dll_struct *source_list, 
					dll_struct *dest_list)
{
  signed_message *mess;
  int32u dest_bits, part_len, mess_len;
  erasure_node *n;
  int32u mpackets, rpackets;
  po_request_message *req;

  while(!UTIL_DLL_Is_Empty(source_list)) {
    UTIL_DLL_Set_Begin(source_list);
      
    mess      = UTIL_DLL_Front_Message(source_list);
    dest_bits = UTIL_DLL_Front_Extra(source_list, DEST);

    /* We encode the message into 3f+1 parts, f+1 of which will be 
     * needed to decode. */
    mpackets = (VAR.F + 1);
    rpackets = (2*VAR.F + 2*VAR.K);
    
    ERASURE_Clear();

#if 0
    /* Sanity check */
    if(VAL_Validate_Message(mess, UTIL_Message_Size(mess)) == 0)
      Alarm(EXIT, "Validate failed in Erasure_Create_Nodes\n");
#endif

    ERASURE_Initialize_Encoding(mess, mpackets, rpackets);
      
    /* Length = # encoded bytes + index + size of meta information */
    part_len = ERASURE_Get_Total_Part_Length() + sizeof(erasure_part);
    mess_len = UTIL_Message_Size(mess);
      
    /* Set up a new erasure node to store the encoded parts */
    n = UTIL_New_Erasure_Node(dest_bits, mess->type, part_len, mess_len);
    
    req = (po_request_message *)(mess + 1);
      
    n->originator = mess->machine_id;
    n->seq        = req->seq;
    
    /* Encode the message and store it into the buffer */
    ERASURE_Encode(n->buf);
    
    /* Store the node in the Erasure List */
    UTIL_DLL_Add_Data(dest_list, n);
    dec_ref_cnt(n);
    assert(get_ref_cnt(n) == 1);
    
    /* Remove the full messsage from the non-broadcast list */
    UTIL_DLL_Pop_Front(source_list);
  }
}

void RECON_Allocate_Recon_Parts_From_Nodes(dll_struct *node_list, 
					   dll_struct *dest_lists)
{
  erasure_node *n;
  erasure_part_obj *ep;
  int32u i, index, target, id;

  /* Iterate over the node list.  For each erasure node (message), add
   * my part to server list server_id if bit is set in dest_bits. */
  while(!UTIL_DLL_Is_Empty(node_list)) {
    UTIL_DLL_Set_Begin(node_list);
    
    n = (erasure_node *)UTIL_DLL_Front_Message(node_list);

    /* Sanity check: this should have some destination */
    assert(n->dest_bits != 0);

    target = VAR.Num_Servers;
    
    for(i = 1; i <= target; i++) {

      if(UTIL_Bitmap_Is_Set(&n->dest_bits, i)) {

        /* Build a new object and initialize it with encoding information */
        ep = UTIL_New_Erasure_Part_Obj();
        ep->part.mess_len = n->mess_len;
        ep->mess_type     = n->mess_type;
        ep->part_len      = n->part_len;
        ep->originator    = n->originator;
        ep->seq           = n->seq;

        /* Copy my part into the object */
        id = VAR.My_Server_ID;

        index = (id - 1) *	
          ((ep->part_len - sizeof(erasure_part))/sizeof(int32u));
        memcpy(ep->buf, &n->buf[index], n->part_len - sizeof(erasure_part));
            
        /* Add the part to the list and maintain the destination info */
        UTIL_DLL_Add_Data(&dest_lists[i], ep);
        UTIL_DLL_Set_Last_Extra(&dest_lists[i], DEST, n->dest_bits);
        dec_ref_cnt(ep);
        assert(get_ref_cnt(ep) == 1);
      }
    }
    UTIL_DLL_Pop_Front(node_list);
  }
}

void RECON_Build_Recon_Packets(dll_struct *dest_lists)
{
  int32u i, target, more_to_encode, bits;
  signed_message *m;

  target = VAR.Num_Servers;

  for(i = 1; i <= target; i++) {
  
    if(UTIL_DLL_Is_Empty(&dest_lists[i]))
      continue;

    while(1) {
      bits = 0;
      
      /* Build the actual packet */
      m = RECON_Construct_Recon_Erasure_Message(&dest_lists[i], 
						  &more_to_encode);
      UTIL_Bitmap_Set(&bits, i);
      if(UTIL_Bitmap_Num_Bits_Set(&bits) != 1) {
        Alarm(PRINT, "Tried to set bit %d but num_bits_set = %d\n",
              i, UTIL_Bitmap_Num_Bits_Set(&bits));
        assert(0);
      }

      /* The message needs to be RSA signed.  It is sent to those that
       * need it. */
      SIG_Add_To_Pending_Messages(m, bits, UTIL_Get_Timeliness(RECON));
      dec_ref_cnt(m);
      
      if(more_to_encode == 0) {
        assert(UTIL_DLL_Is_Empty(&dest_lists[i]));
        break;
      }
    }
  }
}
