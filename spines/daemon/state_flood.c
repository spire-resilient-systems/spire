/*
 * Spines.
 *
 * The contents of this file are subject to the Spines Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.spines.org/LICENSE.txt
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Creators of Spines are:
 *  Yair Amir, Claudiu Danilov, John Schultz, Daniel Obenshain,
 *  Thomas Tantillo, and Amy Babay.
 *
 * Copyright (c) 2003-2020 The Johns Hopkins University.
 * All rights reserved.
 *
 * Major Contributor(s):
 * --------------------
 *    John Lane
 *    Raluca Musaloiu-Elefteri
 *    Nilo Rivera 
 * 
 * Contributor(s): 
 * ----------------
 *    Sahiti Bommareddy 
 *
 */

/* FUTURE TODO: a lot of this serialization code assumes a char* can be
   freely cast to a struct pointer that might have byte alignment
   requirements that are not enforced.  On picky platforms this will
   cause bus faults if the structures don't all have the same byte
   alignments.  Otherwise, this code is fragile if any of the the
   packet types or cells add a new field that throws off the alignment.
*/

/* FUTURE TODO: all spines timeouts should probably be exported to a single
   file so they can be messed with from a central place.
*/

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#ifdef ARCH_PC_WIN95
#  include <winsock2.h>
#endif

#include "arch.h"
#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_data_link.h"
#include "spu_memory.h"
#include "stdutil/stdhash.h"

#include "objects.h"
#include "net_types.h"
#include "node.h"
#include "link.h"
#include "network.h"
#include "reliable_datagram.h"
#include "state_flood.h"
#include "link_state.h"
#include "hello.h"
#include "protocol.h"
#include "route.h"
#include "multicast.h"
#include "kernel_routing.h"

#include "spines.h"

/* Local variables */

static const sp_time zero_timeout        = {     0,    0};
static const sp_time flood_timeout       = {     0,    0};
static const sp_time short_timeout       = {     0,    5000};
static const sp_time wireless_timeout    = {     0,    15000};
static const sp_time state_resend_time   = { 30000,    0};
static const sp_time resend_call_timeout = {  3000,    0}; 
static const sp_time resend_fast_timeout = {     1,    0};
static const sp_time gb_collect_remove   = { 90000,    0};
static const sp_time gb_collect_timeout  = { 10000,    0};

void Flip_state_header(State_Packet *pkt)
{
  pkt->source    = Flip_int32(pkt->source);
  pkt->num_cells = Flip_int16(pkt->num_cells);
  pkt->src_data  = Flip_int16(pkt->src_data);
}

void Flip_state_cell(State_Cell *s_cell)
{
  s_cell->dest           = Flip_int32(s_cell->dest);
  s_cell->timestamp_sec  = Flip_int32(s_cell->timestamp_sec);
  s_cell->timestamp_usec = Flip_int32(s_cell->timestamp_usec);
  s_cell->value          = Flip_int16(s_cell->value);
  s_cell->age            = Flip_int16(s_cell->age);
}

/***********************************************************/
/* Sends an entire state to a neighbor                     */
/***********************************************************/

void Net_Send_State_All(int   lk_id,   /* id of control link to neighbor */
			void *p_data)  /* protocol definition to send */
{
  sp_time       now        = E_get_time();
  Prot_Def     *p_def      = (Prot_Def*) p_data;
  stdhash      *states     = p_def->All_States();
  int16         linkid     = (int16) lk_id;
  char         *buff       = (char*) new_ref_cnt(PACK_BODY_OBJ);
  int           pack_bytes = 0;
  State_Chain  *s_chain;
  State_Data   *s_data;
  State_Packet *pkt;
  State_Cell   *state_cell;
  stdit         outer_it;
  stdit         inner_it;
  int           ret;

  assert(Links[linkid] != NULL && Links[linkid]->link_type == CONTROL_LINK && Links[linkid]->leg->status == CONNECTED_LEG);

  if (buff == NULL) {
    Alarm(EXIT, "Net_Send_State_All(): Cannot allocte pack_body object\r\n");
  }

  for (stdhash_begin(states, &outer_it); !stdhash_is_end(states, &outer_it); stdhash_it_next(&outer_it)) {
  
    s_chain = *(State_Chain**) stdhash_it_val(&outer_it);

    if (stdhash_is_end(&s_chain->states, stdhash_begin(&s_chain->states, &inner_it))) {
      /* TODO: can this legally happen? */
      continue;
    }

    s_data = *(State_Data**) stdhash_it_val(&inner_it);
	    
    /* flush the packet if it is too full for another state packet and state cell */
    
    if (pack_bytes > (int) (sizeof(packet_body) - sizeof(reliable_tail) -
			    p_def->State_header_size() - p_def->Cell_packet_size())) {
      
      ret = Reliable_Send_Msg(linkid, buff, (int16u) pack_bytes, p_def->State_type());
      dec_ref_cnt(buff);
      
      if ((buff = (char*) new_ref_cnt(PACK_BODY_OBJ)) == NULL) {
	Alarm(EXIT, "Net_Send_State_All(): Cannot allocte pack_body object\r\n");
      }
      
      pack_bytes = 0;
    }

    /* set up a state packet and first state cell to send */

    pkt                        = (State_Packet*) (buff + pack_bytes);
    pkt->source                = s_data->source_addr;
    pkt->num_cells             = 1;
    pack_bytes                += sizeof(State_Packet);
    
    pack_bytes                += p_def->Set_state_header(s_data, buff + pack_bytes);
    
    state_cell                 = (State_Cell*) (buff + pack_bytes);
    state_cell->dest           = s_data->dest_addr;
    state_cell->timestamp_sec  = s_data->timestamp_sec;
    state_cell->timestamp_usec = s_data->timestamp_usec;
    state_cell->age            = s_data->age + (now.sec - s_data->my_timestamp_sec) / 10;
    state_cell->value          = s_data->value; 
    pack_bytes                += sizeof(State_Cell);

    pack_bytes                += p_def->Set_state_cell(s_data, buff + pack_bytes);
	   
    /* add any other state cells from this source */

    for (stdhash_it_next(&inner_it); !stdhash_is_end(&s_chain->states, &inner_it); stdhash_it_next(&inner_it)) {

      s_data = *(State_Data**) stdhash_it_val(&inner_it);

      /* flush the packet if it is too full for another state cell */

      if (pack_bytes > (int) (sizeof(packet_body) - sizeof(reliable_tail) - p_def->Cell_packet_size())) {
	
	ret = Reliable_Send_Msg(linkid, buff, (int16u) pack_bytes, p_def->State_type());    
	dec_ref_cnt(buff);
	
	if ((buff = (char*) new_ref_cnt(PACK_BODY_OBJ)) == NULL) {
	  Alarm(EXIT, "Net_Send_State_all(): Cannot allocte pack_body object\n");
	}

	pkt            = (State_Packet*) buff;
	pkt->source    = s_data->source_addr;
	pkt->num_cells = 0;		    
	pack_bytes     = sizeof(State_Packet);
	
	pack_bytes += p_def->Set_state_header(s_data, buff+pack_bytes);
      }

      ++pkt->num_cells;

      state_cell                 = (State_Cell*) (buff + pack_bytes);
      state_cell->dest           = s_data->dest_addr;
      state_cell->timestamp_sec  = s_data->timestamp_sec;
      state_cell->timestamp_usec = s_data->timestamp_usec;
      state_cell->age            = s_data->age + (now.sec - s_data->my_timestamp_sec) / 10;
      state_cell->value          = s_data->value; 
      pack_bytes                += sizeof(State_Cell);

      pack_bytes                += p_def->Set_state_cell(s_data, buff + pack_bytes);  	    
    }
  }

  if (pack_bytes != 0) {
    ret = Reliable_Send_Msg(linkid, buff, (int16u) pack_bytes, p_def->State_type());
  }

  dec_ref_cnt(buff);
}

/***********************************************************/
/* Sends the new state updates to all the neighbors        */
/***********************************************************/

void Send_State_Updates(int   dummy_int, 
			void *p_data)     /* protocol definition to send */
{
  Prot_Def *p_def = (Prot_Def*) p_data;
  int       flag  = 0;
  int16     i;
  
  for (i = 0; i < Num_Neighbors; ++i) {

    if (Neighbor_Nodes[i] != NULL && 
	Is_Connected_Neighbor2(Neighbor_Nodes[i]) &&
	Net_Send_State_Updates(p_def, i) < 0) { 

      flag = 1;  /* changes only partially queued / sent; call again */
    }
  }

  if (flag == 1) {
    E_queue(Send_State_Updates, 0, p_data, zero_timeout);

  } else {
    Empty_Changed_States(p_def->Changed_States());
  }
}

/***********************************************************/
/* Sends a portion of new state updates to a neighbor      */
/* Returns 1 if everything sent, else -1                   */
/***********************************************************/

int Net_Send_State_Updates(Prot_Def *p_def,        /* protocol definition to send */
			   int16     neighbor_id)  /* index of neighbor in Neighbor_Nodes to send to */
{
  sp_time        now        = E_get_time();
  stdhash       *changes    = p_def->Changed_States();
  Node          *nbr        = Neighbor_Nodes[neighbor_id];
  int32u         node_index = neighbor_id / 32;             /* see state_flood.h for explanation */
  int32u         node_mask  = (0x1 << (neighbor_id % 32));  /* see state_flood.h for explanation */
  char          *buff       = (char*) new_ref_cnt(PACK_BODY_OBJ);
  int            pack_bytes = 0;
  int            pkt_cnt    = 0;
  int16          linkid;
  stdhash        done_srcs;            /* tracks processed update sources */
  Changed_State *cg_state;
  State_Data    *s_data;
  State_Packet  *pkt;
  State_Cell    *state_cell;
  stdit          outer_it;
  stdit          inner_it;
  stdit          tmp_it;
  int            ret;

  assert(nbr != NULL && Is_Connected_Neighbor2(nbr) && nbr->edge->leg != NULL && nbr->edge->leg->status == CONNECTED_LEG);
  UNUSED(nbr);

  linkid = Neighbor_Nodes[neighbor_id]->edge->leg->links[CONTROL_LINK]->link_id;

  if (buff == NULL || stdhash_construct(&done_srcs, sizeof(Node_ID), 0, NULL, NULL, 0) != 0) {
    Alarm(EXIT, "Net_Send_State_Update: Couldn't allocate!\r\n");
  }

  for (stdhash_begin(changes, &outer_it); !stdhash_is_end(changes, &outer_it); stdhash_it_next(&outer_it)) {

    cg_state = *(Changed_State**) stdhash_it_val(&outer_it);
    s_data   = (State_Data*) cg_state->state;

    if (stdhash_contains(&done_srcs, &s_data->source_addr)) {
      continue;  /* already processed this source */
    }

    /* NOTE: we have to do a find here to ensure we get all entries
       from this source when we do our stdhash_keyed_next iteration;
       'outer_it' is probably in the middle of a keyed iteration.
    */

    stdhash_find(changes, &inner_it, &s_data->source_addr);  /* can't fail */
    cg_state = *(Changed_State**) stdhash_it_val(&inner_it);

    /* find the first state change from this source we need to send to this node */

    if (cg_state->mask[node_index] & node_mask) {  /* set bit -> doesn't need this one; find the first one he does */
      
      for (stdhash_keyed_next(changes, &inner_it); !stdhash_is_end(changes, &inner_it); stdhash_keyed_next(changes, &inner_it)) {

	cg_state = *(Changed_State**) stdhash_it_val(&inner_it);

	if (!(cg_state->mask[node_index] & node_mask)) {  
	  break;  /* he needs this one */
	}
      }

      if (stdhash_is_end(changes, &inner_it)) {  /* no updates from this source were needed */

	if (stdhash_insert(&done_srcs, &tmp_it, &s_data->source_addr, NULL) != 0) {
	  Alarm(EXIT, "Net_Send_State_Update: Couldn't insert into done_srcs!\r\n");
	}

	continue;
      }
    }

    s_data = (State_Data*) cg_state->state;

    /* flush the packet if it is too full for another state packet and state cell */

    if (pack_bytes > (int) (sizeof(packet_body) - sizeof(reliable_tail) -
			    p_def->State_header_size() - p_def->Cell_packet_size())) {
	        
      ret = Reliable_Send_Msg(linkid, buff, (int16u) pack_bytes, p_def->State_type());
      dec_ref_cnt(buff);
		
      if (++pkt_cnt > 5) {  /* limit the # of packets we send to any given neighbor so we don't starve the rest of the daemon */
	stdhash_destruct(&done_srcs);
	return -1;
      }

      if ((buff = (char*) new_ref_cnt(PACK_BODY_OBJ)) == NULL) {
	Alarm(EXIT, "Net_Send_State_updates(): Cannot allocte pack_body object\r\n");
      }

      pack_bytes = 0;
    }

    /* set up a state packet and first state cell to send */

    pkt                        = (State_Packet*) (buff + pack_bytes);
    pkt->source                = s_data->source_addr;
    pkt->num_cells             = 1;
    pack_bytes                += sizeof(State_Packet);

    pack_bytes                += p_def->Set_state_header(s_data, buff + pack_bytes);

    state_cell                 = (State_Cell*) (buff + pack_bytes);
    state_cell->dest           = s_data->dest_addr;
    state_cell->timestamp_sec  = s_data->timestamp_sec;
    state_cell->timestamp_usec = s_data->timestamp_usec;
    state_cell->age            = s_data->age + (now.sec - s_data->my_timestamp_sec) / 10;
    state_cell->value          = s_data->value;
    pack_bytes                += sizeof(State_Cell);

    pack_bytes                += p_def->Set_state_cell(s_data, buff + pack_bytes);

    /* record that we are about to reliably send this state change to this neighbor */

    cg_state->mask[node_index] |= node_mask;

    Alarm(DEBUG, "Upd: Packing state: " IPF " -> " IPF " | %d:%d\r\n", 
	  IP(pkt->source), IP(state_cell->dest), state_cell->timestamp_sec, state_cell->timestamp_usec); 
	   
    /* add any other state cells from this source */

    for (stdhash_keyed_next(changes, &inner_it); !stdhash_is_end(changes, &inner_it); stdhash_keyed_next(changes, &inner_it)) {

      cg_state = *(Changed_State**) stdhash_it_val(&inner_it);
      s_data   = (State_Data*) cg_state->state;

      if (cg_state->mask[node_index] & node_mask) {
	continue;  /* not needed */
      }

      /* flush the packet if it is too full for another state cell */

      if (pack_bytes > (int) (sizeof(packet_body) - sizeof(reliable_tail) - p_def->Cell_packet_size())) {
		  
	ret = Reliable_Send_Msg(linkid, buff, (int16u)pack_bytes, p_def->State_type());
	dec_ref_cnt(buff);

	if (++pkt_cnt > 5) {  /* limit the # of packets we send to any given neighbor so we don't starve the rest of the daemon */
	  stdhash_destruct(&done_srcs);
	  return -1;
	}

	if ((buff = (char*) new_ref_cnt(PACK_BODY_OBJ)) == NULL) {
	  Alarm(EXIT, "Net_Send_State_Updates(): Cannot allocte pack_body object\n");
	}

	pkt            = (State_Packet*)buff;
	pkt->source    = s_data->source_addr;
	pkt->num_cells = 0;		    
	pack_bytes     = sizeof(State_Packet);
	pack_bytes    += p_def->Set_state_header(s_data, buff + pack_bytes);
      }

      ++pkt->num_cells;

      state_cell                 = (State_Cell*) (buff + pack_bytes);
      state_cell->dest           = s_data->dest_addr;
      state_cell->timestamp_sec  = s_data->timestamp_sec;
      state_cell->timestamp_usec = s_data->timestamp_usec;
      state_cell->age            = s_data->age + (now.sec - s_data->my_timestamp_sec) / 10;
      state_cell->value          = s_data->value; 
      pack_bytes                += sizeof(State_Cell);

      pack_bytes                += p_def->Set_state_cell(s_data, buff+pack_bytes);  

      /* record that we are about to send this change to this neighbor */

      cg_state->mask[node_index] |= node_mask;
    }

    /* record this source, so we don't consider it again */

    if (stdhash_insert(&done_srcs, &tmp_it, &s_data->source_addr, NULL) != 0) {
      Alarm(EXIT, "Net_Send_State_Updates: Couldn't insert into done_srcs!\r\n");
    }
  }

  if (pack_bytes != 0) {
    ret = Reliable_Send_Msg(linkid, buff, (int16u) pack_bytes, p_def->State_type());
  }

  dec_ref_cnt(buff);
  stdhash_destruct(&done_srcs);
    
  return 1;
}

/***********************************************************/
/* Processes a state flood packet                          */
/***********************************************************/

void Process_state_packet(Link  *lk,        /* link on which packet came in */
			  char  *buf,       /* pointer to the message */
			  int16u data_len,  /* data length in the packet */
			  int16u ack_len,   /* ack length in the packet */
			  int32u type,      /* first four bytes of the message */
			  int    mode)      /* type of link on which the message was received */
{
  Node          *sender_nd          = lk->leg->edge->dst;
  Node_ID        sender             = sender_nd->nid;
  Reliable_Data *r_data             = lk->r_data;
  int            my_endianess_type  = (!Same_endian(type) ? Flip_int32(type) : type);
  Prot_Def      *p_def              = Get_Prot_Def(my_endianess_type);
  int            processed_bytes    = 0;
  int            changed_route_flag = 0;
  State_Packet  *pkt;
  State_Cell    *state_cell;
  State_Data    *s_data;
  reliable_tail *r_tail;
  Changed_State *cg_state;
  int            flag;
  int            i;

  assert(mode == CONTROL_LINK && lk->link_type == CONTROL_LINK);

  if (r_data->flags & CONNECTED_LINK) {  /* process the ack part of msg */

    r_tail = (reliable_tail*) (buf + data_len);
    flag   = Process_Ack(lk->link_id, (char*) r_tail, ack_len, type);
    
    if (flag == -1) { /* Ack packet... */
      Alarm(PRINT, "Warning !!! Ack packets should be treated differently !\n");
      return;
    }

    /* we should send an acknowledgement for this message */

    if (!E_in_queue(Send_Ack, (int)lk->link_id, NULL)) {
      r_data->scheduled_ack = 1;
      E_queue(Send_Ack, (int)lk->link_id, NULL, short_timeout);
    }

    if (flag == 0) {  /* already processed */
      return;
    }

  } else {
    /* Got a reliable packet from an existing link that is not
     * connected yet. This is because the other guy got my hello msgs,
     * validated the link, but I lost his hello msgs, therefore on my
     * part, the link is not available yet.  Because we don't ack it,
     * it will be resent by our partner some time in the future. */ 
    /* Send a request for a hello message */
    
    E_queue(Send_Hello_Request, (int) lk->link_id, NULL, zero_timeout);
    return;
  }

  /* process the data in the packet */

  /* TODO: The way we process the state headers and state cells is a
     bit asymmetrical and confusing.  We allow the protocol
     definitions to add *extra* header fields onto the end of
     State_Packet (headers).  However, when we process received
     packets we hand ALL the headers off to the protocol to process
     (e.g. - endian flip) rather than just the extra ones.  Whereas,
     when we process an individual cell we process (e.g. - endian
     flip) the state cell portion here and then allow the protocol to
     do any additional processing as necessary.
     
     We should probably at least endian flip the state headers here
     and then allow the Process_state_header fcn to only do anything
     extra to be more symmetrical in our treatment.  We might want to
     additionally then have things like State_header_size() and
     Cell_packet_size() from the protocols only add any extra fields.
  */

  while (processed_bytes < data_len) {

    pkt = (State_Packet*) (buf + processed_bytes);

    p_def->Process_state_header(buf + processed_bytes, type);
    processed_bytes += p_def->State_header_size();

    for (i = 0; i < pkt->num_cells; ++i) {

      state_cell = (State_Cell*) (buf + processed_bytes);
	    
      if (!Same_endian(type)) {
	Flip_state_cell(state_cell);
      }

      if ((s_data = Find_State(p_def->All_States(), pkt->source, state_cell->dest)) == NULL ||
	  s_data->timestamp_sec < state_cell->timestamp_sec ||
	  (s_data->timestamp_sec == state_cell->timestamp_sec && s_data->timestamp_usec < state_cell->timestamp_usec)) {

	/* newer update */

	if ((s_data = p_def->Process_state_cell(pkt->source, sender, buf + processed_bytes, type)) != NULL) {  /* NULL -> don't propagate this flood */
	  Add_to_changed_states(p_def, sender, s_data);
	  changed_route_flag = 1;
	}

      } else if (s_data->timestamp_sec == state_cell->timestamp_sec && s_data->timestamp_usec == state_cell->timestamp_usec) {

	/* NOTE: this is a major change (improvement) wrt spines'
	   state flooding; previously we would state flood it
	   regardless; instead, we now swallow things we already know
	   bc I'm already synchronized(ing) with my neighbors */

	/* if we have a change state waiting to go out; this sender is already aware; mark him as such */

	if ((cg_state = Find_Changed_State(p_def->Changed_States(), s_data->source_addr, s_data->dest_addr)) != NULL) {
	  cg_state->mask[sender_nd->neighbor_id / 32] |= (0x1 << sender_nd->neighbor_id % 32);
	}

      } /* else already have newer knowledge about this state; swallow it */

      processed_bytes += p_def->Cell_packet_size();
    }
  }

  if (changed_route_flag && p_def->Is_route_change()) {
    Schedule_Routes();
  }
}

/***********************************************************/
/* Resends the valid states to all the neighbors for       */
/* garbage collection purposes                             */
/***********************************************************/

void Resend_States(int dummy_int, 
		   void *p_data)  /* protocol definition to resend */
{
  sp_time      now    = E_get_time();
  Prot_Def    *p_def  = (Prot_Def*) p_data;
  stdhash     *states = p_def->All_States();
  int          cnt    = 0;
  State_Data  *s_data;
  State_Chain *s_chain;
  sp_time      state_time;
  sp_time      diff;
  stdit        tit;

  if (!stdhash_is_end(states, stdhash_find(states, &tit, &My_Address))) {

    s_chain = *(State_Chain**) stdhash_it_val(&tit);

    for (stdhash_begin(&s_chain->states, &tit); !stdhash_is_end(&s_chain->states, &tit); stdhash_it_next(&tit)) {

      s_data = *(State_Data**) stdhash_it_val(&tit);
	    
      state_time.sec  = s_data->my_timestamp_sec;
      state_time.usec = s_data->my_timestamp_usec;
      diff            = E_sub_time(now, state_time);
	    
      assert(diff.sec >= 0 && diff.usec >= 0);

      if (E_compare_time(diff, state_resend_time) >= 0 &&              /* its time to refresh */
	  p_def->Is_state_relevant((void*)s_data)) {

	if(++s_data->timestamp_usec >= 1000000) {
	  ++s_data->timestamp_sec;
	  s_data->timestamp_usec = 0;
	}

	Add_to_changed_states(p_def, My_Address, s_data);              /* updates my_timestamp_* */
	
	if (++cnt > 500) {
	  E_queue(Resend_States, 0, p_data, resend_fast_timeout);
	  return;
	}
      }
    }
  }

  E_queue(Resend_States, 0, p_data, resend_call_timeout);
}

/***********************************************************/
/* Remove the unnecessary (expired) states from memory     */
/***********************************************************/

void State_Garbage_Collect(int   dummy_int, 
			   void *p_data)     /* protocol definition to clean */
{
  sp_time      now           = E_get_time();
  Prot_Def    *p_def         = (Prot_Def*) p_data;
  stdhash     *states        = p_def->All_States();
  stdhash     *states_by_dst = p_def->All_States_by_Dest();
  State_Chain *s_chain_src;
  State_Data  *s_data;
  sp_time      state_time;
  sp_time      diff;
  State_Chain *s_chain_dst;
  stdit        outer_it;
  stdit        inner_it;
  stdit        dst_it;
  stdit        src_it;

  for (stdhash_begin(states, &outer_it); !stdhash_is_end(states, &outer_it); ) {

    s_chain_src = *(State_Chain**) stdhash_it_val(&outer_it);

    for (stdhash_begin(&s_chain_src->states, &inner_it); !stdhash_is_end(&s_chain_src->states, &inner_it); ) {

      s_data          = *(State_Data**) stdhash_it_val(&inner_it);
      state_time.sec  = s_data->my_timestamp_sec - s_data->age * 10;
      state_time.usec = s_data->my_timestamp_usec;
      diff            = E_sub_time(now, state_time);

      assert(state_time.sec >= 0 && diff.sec >= 0 && diff.usec >= 0);

      if (E_compare_time(diff, gb_collect_remove) >= 0) {  /* ok, this is a very old state that should be removed */

	stdhash_erase(&s_chain_src->states, &inner_it);  /* NOTE: this safely "advances" (can reset to begin if shrinks) inner_it */

	/* remove it from states_by_dst structure */

	if (states_by_dst != NULL) {
	  
	  if (stdhash_is_end(states_by_dst, stdhash_find(states_by_dst, &dst_it, &s_data->dest_addr))) {
	    Alarm(EXIT, "Garbage collect: no entry in the by_dest hash\r\n");
	  }
	  
	  s_chain_dst = *(State_Chain**) stdhash_it_val(&dst_it);
	  	  
	  if (stdhash_is_end(&s_chain_dst->states, stdhash_find(&s_chain_dst->states, &src_it, &s_data->source_addr))) {
	    Alarm(EXIT, "Garbage collect: no entry in the state_chain hash\r\n");
	  }

	  stdhash_erase(&s_chain_dst->states, &src_it);

	  if (stdhash_empty(&s_chain_dst->states)) {
	    stdhash_destruct(&s_chain_dst->states);
	    stdhash_erase(states_by_dst, &dst_it);
	    dispose(s_chain_dst);
	  }
	}

	if (p_def->State_type() & LINK_STATE_TYPE) {  /* see if we need to delete the nodes of the edge also */
		    
	  if (Try_Remove_Node(s_data->source_addr) < 0) {
	    Alarm(EXIT, "Garbage_Collector(): Error removing node\r\n");
	  }

	  if (Try_Remove_Node(s_data->dest_addr) < 0) {
	    Alarm(EXIT, "Garbage_Collector(): Error removing node2\r\n");
	  }
	}

	p_def->Destroy_State_Data(s_data);
	dispose(s_data);

      } else {
	stdhash_it_next(&inner_it);
      }
    }

    if (stdhash_empty(&s_chain_src->states)) {
      stdhash_destruct(&s_chain_src->states);
      stdhash_erase(states, &outer_it);        /* NOTE: this safely "advances" (can reset to begin if shrinks) outer_it */  
      dispose(s_chain_src);

    } else {
      stdhash_it_next(&outer_it); 
    }
  }

  E_queue(State_Garbage_Collect, 0, p_data, gb_collect_timeout);
}

/***********************************************************/
/* Returns a protocol state; NULL if no such state         */
/***********************************************************/

State_Data *Find_State(stdhash  *h,     /* set of states to search */
		       Spines_ID prim,  /* primary key */
		       Spines_ID scnd)  /* secondary key */
{
  State_Data  *ret = NULL;
  State_Chain *s_chain;
  stdit        tit;

  if (!stdhash_is_end(h, stdhash_find(h, &tit, &prim))) {
    
    s_chain = *(State_Chain**) stdhash_it_val(&tit);

    if (!stdhash_is_end(&s_chain->states, stdhash_find(&s_chain->states, &tit, &scnd))) {
      ret = *(State_Data**) stdhash_it_val(&tit);
    }
  }

  return ret;
}

/***********************************************************/
/* Adds a state to the buffer of changed states to be sent */
/* to neighbors                                            */
/***********************************************************/

void Add_to_changed_states(Prot_Def   *p_def,   /* protocol definition to use */
			   Node_ID     sender,  /* id of sender of change */
			   State_Data *s_data)  /* updated state */
{
  sp_time        now = E_get_time();
  Node          *nd;
  Changed_State *cg_state;
  stdit          tit;

  if ((nd = Get_Node(sender)) == NULL || (nd != This_Node && !Is_Connected_Neighbor2(nd))) {
    Alarm(EXIT, "Add_to_changed_states(): unknown or unconnected sender node?!\r\n");
  }

  s_data->my_timestamp_sec  = (int32) now.sec;
  s_data->my_timestamp_usec = (int32) now.usec;	
    
  if (stdhash_empty(p_def->Changed_States())) {

    if (Wireless) {
      E_queue(Send_State_Updates, 0, p_def, wireless_timeout);

    } else {
      E_queue(Send_State_Updates, 0, p_def, flood_timeout);
    }
  }

  if (p_def == &Groups_Prot_Def) {               /* multicast change */
    
    Discard_Mcast_Neighbors(s_data->dest_addr);  /* rebuild mcast neighbors on demand for this group */
    
#ifndef ARCH_PC_WIN95
    /* Schedule kernel route change if necessary; Always schedule after Send_State_Updates */
  
    if (Is_valid_kr_group(s_data->dest_addr) && !E_in_queue(KR_Set_Group_Route, s_data->dest_addr, NULL)) {
      /* TODO: If I am a member, I should update right away. Should
	 use eucl distance to determine delay, to decrease unstable interval,
	 say my_eucl_dist*wireless_timeout */
      E_queue(KR_Set_Group_Route, s_data->dest_addr, NULL, zero_timeout);
    } 
#endif

  } /* else: topology change; all mcast routing discarded in route.c when we update routing */

  if ((cg_state = Find_Changed_State(p_def->Changed_States(), s_data->source_addr, s_data->dest_addr)) == NULL) {

    if ((cg_state = (Changed_State*) new(CHANGED_STATE)) == NULL) {
      Alarm(EXIT, "Add_to_changed_states: Cannot allocte state object!\r\n");
    }

    cg_state->state = s_data;

    if (stdhash_insert(p_def->Changed_States(), &tit, &s_data->source_addr, &cg_state) != 0) {
      Alarm(EXIT, "Add_to_changed_states: Couldn't insert into changed states!\r\n");
    }
  }

  memset(cg_state->mask, 0, sizeof(cg_state->mask));  /* all neighbors need to know: 0 in mask -> neighbor still needs it */

  if (sender != My_Address) {  /* I'm not in the mask of a changed state */
    cg_state->mask[nd->neighbor_id / 32] |= (0x1 << nd->neighbor_id % 32);  /* except the sender who told me */
  }
}

/***********************************************************/
/* Returns a state from the buffer of changed states       */
/***********************************************************/

Changed_State *Find_Changed_State(stdhash  *h,       /* changed states hash to search */
				  Spines_ID src_id,  /* first search key */
				  Spines_ID dst_id)  /* second search key */
{
  Changed_State *ret = NULL;
  Changed_State *cg_state;
  State_Data    *s_data;
  stdit          tit;
  
  for (stdhash_find(h, &tit, &src_id); !stdhash_is_end(h, &tit); stdhash_keyed_next(h, &tit)) {
    
    cg_state = *(Changed_State**) stdhash_it_val(&tit);
    s_data   = (State_Data*) cg_state->state;
    
    if (s_data->dest_addr == dst_id) {
      ret = cg_state;
      break;
    }
  }

  return ret;
}

/***********************************************************/
/* Empties the buffer of changed states                    */
/***********************************************************/

void Empty_Changed_States(stdhash *h)  /* changed states hash */
{
  Changed_State *cg_state;
  stdit          tit;

  for (stdhash_begin(h, &tit); !stdhash_is_end(h, &tit); stdhash_it_next(&tit)) {
    cg_state = *(Changed_State**) stdhash_it_val(&tit);
    dispose(cg_state);
  } 

  stdhash_clear(h);
}

/***********************************************************/
/* Returns the definition of protocol functions based on   */
/* the type of a message                                   */
/***********************************************************/

Prot_Def *Get_Prot_Def(int32u t)  /* type of message */
{
  if (Is_link_state(t)) {
    return &Edge_Prot_Def;

  } else if (Is_group_state(t)) {
    return &Groups_Prot_Def;
  }

  return NULL;
}
