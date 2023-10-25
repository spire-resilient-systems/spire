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

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#ifdef ARCH_PC_WIN95
#include <winsock2.h>
#endif

#include "arch.h"
#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_memory.h"
#include "spu_data_link.h"
#include "stdutil/stdhash.h"
#include "stdutil/stdcarr.h"

#include "objects.h"
#include "net_types.h"
#include "node.h"
#include "link.h"
#include "network.h"
#include "reliable_datagram.h"
#include "link_state.h"
#include "hello.h"
#include "udp.h"
#include "reliable_udp.h"
#include "realtime_udp.h"
#include "protocol.h"
#include "route.h"
#include "session.h"
#include "state_flood.h"
#include "multicast.h"

/* Global variables */

extern Node     *This_Node;
extern Node_ID   My_Address;
extern stdhash   All_Nodes;
extern Link*     Links[MAX_LINKS];
extern int       network_flag;
extern stdhash   All_Groups_by_Node; 
extern stdhash   All_Groups_by_Name; 
extern stdhash   Neighbors;
extern int       Security;
extern int       Unicast_Only;

/* Local constants */

static const sp_time zero_timeout  = {     0,    0};

/***********************************************************/
/* Processes a Realtime UDP data packet                    */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* sender_id: IP of the node that gave me the message      */
/* scat:      a sys_scatter containing the message         */
/* type:      type of the packet                           */
/* mode:      mode of the link the packet arrived on       */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Process_RT_UDP_data_packet(Link *lk, sys_scatter *scat,
				int32u type, int mode)
{
    packet_header  *phdr;
    int16u          data_len, ack_len;
    udp_header     *hdr;
    char           *buff;
    Realtime_Data *rt_data;
    rt_seq_type    seq_no;
    int32          diff;
    sp_time        now;
    rt_seq_type    i;
    int            routing;

    if (scat->num_elements != 2) {
        Alarm(PRINT, "Process_RT_UDP_data_packet: Dropping packet because "
            "scat->num_elements == %d instead of 2\r\n", scat->num_elements);
        return;
    }

    if (scat->elements[1].len < sizeof(udp_header))
    {
        Alarmp(SPLOG_WARNING, PRINT, "Process_RT_UDP_data_packet: Dropping packet because too small!\n");
        return;
    }
    
    phdr     = (packet_header*) scat->elements[0].buf;
    hdr      = (udp_header*) scat->elements[1].buf;
    
    routing  = (hdr->routing << ROUTING_BITS_SHIFT);
    data_len = phdr->data_len; 
    ack_len  = phdr->ack_len - Dissemination_Header_Size(routing);
    buff     = (char*) scat->elements[1].buf;

    if (!Same_endian(type)) {
      Flip_udp_hdr(hdr);
    }
    
    /* if (hdr->len + sizeof(udp_header) != data_len) {
      Alarm(PRINT, "Process_RT_UDP_data_packet: Packed data not available yet!\r\n");
      return;
    } */
  
    rt_data = (Realtime_Data*) lk->prot_data;
    seq_no  = *(rt_seq_type*)(buff+data_len);

    if(!Same_endian(type)) {
	seq_no = Flip_int64(seq_no);
    }

    if(seq_no < rt_data->recv_tail) {
	/* This is an old packet. Ignore it. */
	return;
    }
    if((seq_no < rt_data->recv_head)&&
       (rt_data->recv_window[seq_no%MAX_HISTORY].flags != EMPTY_CELL)) {
	/* This is a duplicate. Ignore it. */
	return;
    }

    now = E_get_time();

    /* Advance the receive tail if possible */

    while(rt_data->recv_tail < rt_data->recv_head) {
	i = rt_data->recv_tail;
	while((rt_data->recv_window[i%MAX_HISTORY].flags == EMPTY_CELL)&&
	      (i < rt_data->recv_head)) {
	    i++;
	}
	if(i == rt_data->recv_head) {
	    /* No packets since the last tail. Keep it there as we wait for them */
	    break;
	}

	/* Check whether the oldest packet is old or new */
	diff = now.sec - rt_data->recv_window[i%MAX_HISTORY].timestamp.sec;
	diff *= 1000000;
	diff += now.usec - rt_data->recv_window[i%MAX_HISTORY].timestamp.usec;
	if(diff <= HISTORY_TIME) {
	    /* This is a a recent packet. Keep it the tail */
	    break;
	}

	/* The oldest packet is old. Move the tail up */
	
	rt_data->recv_window[i%MAX_HISTORY].flags = EMPTY_CELL;
	rt_data->recv_tail = i+1;
    }
    
    if(seq_no >= rt_data->recv_head) {
	/* This is a new (and higher) packet. If we don't have room for 
	 it in the history, advance the tail */
	while(seq_no - rt_data->recv_tail >= MAX_HISTORY) {
	    rt_data->recv_window[rt_data->recv_tail%MAX_HISTORY].flags = EMPTY_CELL;
	    rt_data->recv_tail++;
	}
	for(i = rt_data->recv_head; i < seq_no; i++) {
	    rt_data->recv_window[i%MAX_HISTORY].flags = EMPTY_CELL;
	    /* Add lost packet to the retransm. request */
	    
	    if(rt_data->num_nacks*sizeof(rt_seq_type) + 2*sizeof(rt_seq_type)< 
	       sizeof(packet_body) - sizeof(udp_header))
            {
		*(rt_seq_type*)(rt_data->nack_buff+rt_data->num_nacks*sizeof(rt_seq_type)) = i;
		rt_data->num_nacks++;
	    }
	}
	if(rt_data->num_nacks > 0) {
	    E_queue(Send_RT_Nack, (int)lk->link_id, NULL, zero_timeout);
	}
	rt_data->recv_head = seq_no+1;;
    }
    
    rt_data->recv_window[seq_no%MAX_HISTORY].flags = RECVD_CELL;
    rt_data->recv_window[seq_no%MAX_HISTORY].timestamp = now;
    
    Alarm(DEBUG, "recv_tail: %llu; diff: %d\n", rt_data->recv_tail, 
	  rt_data->recv_head - rt_data->recv_tail);
   
    /* REG ROUTING HACK */
    scat->elements[1].len = phdr->data_len;

    scat->elements[2].buf = new_ref_cnt(PACK_BODY_OBJ);
    memcpy(scat->elements[2].buf, scat->elements[1].buf + data_len + ack_len,
            Dissemination_Header_Size(routing));
    scat->elements[2].len = Dissemination_Header_Size(routing);
    scat->num_elements++;

    Deliver_and_Forward_Data(scat, mode, lk);

    /* REG ROUTING HACK */
    dec_ref_cnt(scat->elements[2].buf);
    scat->num_elements--;

    scat->elements[1].len = sizeof(packet_body);
}

/***********************************************************/
/* int Forward_RT_UDP_data(Node *next_hop,                 */
/*                         sys_scatter *msg_scat)          */
/*                                                         */
/*                                                         */
/*                                                         */
/* Forward a UDP data packet                               */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* next_hop:  the next node on the path                    */
/* scat:  sys_scatter containing the message               */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int) the status of the packet (see udp.h)              */
/*                                                         */
/***********************************************************/

int Forward_RT_UDP_Data(Node *next_hop, sys_scatter *scat)
{
    Link *lk;
    packet_header *hdr;
    udp_header *uhdr;
    Realtime_Data *rt_data;
    History_Cell *h_cell;
    int ret, diff, routing;
    int16u dh_size, lh_size;
    sp_time now;
    
    /* if (scat->num_elements != 2) {
        Alarm(PRINT, "Forward_RT_UDP_Data: Malformed sys_scatter: num_elements == %d\r\n",
                    scat->num_elements);
        return BUFF_DROP;
    } */

    if (next_hop == This_Node) {
        Process_udp_data_packet(NULL, scat, UDP_DATA_TYPE, UDP_LINK);
	    return BUFF_EMPTY;
    }

    if ((lk = Get_Best_Link(next_hop->nid, REALTIME_UDP_LINK)) == NULL) {
	    return BUFF_DROP;
    }

    rt_data = (Realtime_Data*) lk->prot_data;
    now     = E_get_time();

    /* Clean the history window of old packets */
    while(rt_data->tail < rt_data->head) {
	h_cell = &rt_data->window[rt_data->tail%MAX_HISTORY];
	diff = (now.usec - h_cell->timestamp.usec) +
	    1000000*(now.sec - h_cell->timestamp.sec);
	if(diff > HISTORY_TIME) {
	    dec_ref_cnt(rt_data->window[rt_data->tail%MAX_HISTORY].buff);
	    rt_data->window[rt_data->tail%MAX_HISTORY].buff = NULL;
	    rt_data->tail++;
	    Alarm(DEBUG, "Forward_RT_UDP_Data: History time limit reached\n");
	}
	else {
	    break;
	}
    }
    
    /* Drop the last packet if there is no more room in the window */
    if(rt_data->head - rt_data->tail >= MAX_HISTORY){
        assert(rt_data->head - rt_data->tail == MAX_HISTORY); /* AB: shouldn't it be impossible to get > MAX_HISTORY? */
	dec_ref_cnt(rt_data->window[rt_data->tail%MAX_HISTORY].buff);
	rt_data->window[rt_data->tail%MAX_HISTORY].buff = NULL;
	rt_data->tail++;
	Alarm(DEBUG, "Forward_RT_UDP_Data: History window limit reached (tail %d, head %d)\n", rt_data->tail, rt_data->head);
    }

    hdr = (packet_header*) scat->elements[0].buf;
    uhdr = (udp_header *) scat->elements[1].buf;
    routing = (uhdr->routing << ROUTING_BITS_SHIFT);
    dh_size = Dissemination_Header_Size(routing);
    lh_size = sizeof(rt_seq_type);

    hdr->type             = REALTIME_DATA_TYPE;
    hdr->type             = Set_endian(hdr->type);

    hdr->sender_id        = My_Address;
    hdr->ctrl_link_id     = lk->leg->ctrl_link_id;
    hdr->data_len         = scat->elements[1].len;
    hdr->ack_len          = lh_size + dh_size;
    hdr->seq_no           = Set_Loss_SeqNo(lk->leg, REALTIME_UDP_LINK);

    /* Set the sequence number of the packet */
    *(rt_seq_type*)(scat->elements[1].buf + scat->elements[1].len) = rt_data->head;

    /* Save the packet in the window */
    rt_data->window[rt_data->head%MAX_HISTORY].buff = scat->elements[1].buf;
    inc_ref_cnt(scat->elements[1].buf);
    /* AB: adding sizeof(int32) to len is a fix to work with source-based routing */
    /* rt_data->window[rt_data->head%MAX_HISTORY].len = scat->elements[1].len; */
    rt_data->window[rt_data->head%MAX_HISTORY].len = scat->elements[1].len + lh_size;
    rt_data->window[rt_data->head%MAX_HISTORY].timestamp = now;
    /* AB: modifications to work with source-based dissemination: copy
     * dissemination bitmask into the buffer that we are storing, so that we
     * can use the dissemination bitmask for retransmissions too */
    if (scat->num_elements > 2)
    {
        assert(hdr->data_len + lh_size + dh_size < sizeof(packet_body));
        memcpy(scat->elements[1].buf + hdr->data_len + lh_size, scat->elements[2].buf, dh_size);
        rt_data->window[rt_data->head%MAX_HISTORY].len += dh_size;
    }
  
    scat->elements[1].len += lh_size;

    /* Advance the head of the window */
    rt_data->head++;

    if(rt_data->bucket < MAX_BUCKET) {
	rt_data->bucket++;
    }

    if(network_flag == 1) {
      ret = Link_Send(lk, scat);

      if(ret < 0) {
        scat->elements[1].len -= lh_size;
	    return BUFF_DROP;
      }
    }

    scat->elements[1].len -= lh_size;
    return BUFF_EMPTY;
}

/***********************************************************/
/* Request Resources to forward a Realtime UDP data packet */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* next_hop:  the next node on the path                    */
/* callback:  function to call when resources are availble */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* 1 - Resources available                                 */
/* 0 - Resources not available                             */
/*                                                         */
/***********************************************************/
int Request_Resources_RT_UDP(Node *next_hop, int (*callback)(Node*, int))
{
    (*callback)(next_hop, REALTIME_UDP_LINK);
    return 1;
}

/***********************************************************/
/* void Clean_RT_history((Node *neighbor)                  */
/*                                                         */
/* Advances the history tail discarding old packets        */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* neighbor:  the neighbor node                            */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Clean_RT_history(Link *lk)
{
    Realtime_Data *rt_data;
    sp_time        now;
    History_Cell  *h_cell;
    int            diff;

    if (lk == NULL) {
	return;
    }
    
    rt_data = lk->prot_data;
    now     = E_get_time();
    
    /* Clean the history window of old packets */

    while(rt_data->tail < rt_data->head) {
	h_cell = &rt_data->window[rt_data->tail%MAX_HISTORY];
	diff = (now.usec - h_cell->timestamp.usec) +
	    1000000*(now.sec - h_cell->timestamp.sec);
	if(diff > HISTORY_TIME) {
	    dec_ref_cnt(rt_data->window[rt_data->tail%MAX_HISTORY].buff);
	    rt_data->window[rt_data->tail%MAX_HISTORY].buff = NULL;
	    rt_data->tail++;
	    Alarm(DEBUG, "Clean_RT_history: History cleaned\n");
	}
	else {
	    break;
	}
    }
}

/***********************************************************/
/* void Send_RT_Nack(int16 linkid, void* dummy)            */
/*                                                         */
/* Sends an Realtime NACK                                  */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* linkid:    ID of the link to send on                    */
/* dummy:     Not used                                     */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Send_RT_Nack(int linkid, void* dummy) 
{
    Link          *lk;
    Realtime_Data *rt_data;
    sys_scatter    scat;
    packet_header  hdr;
    int            ret;

    if ((lk = Links[linkid]) == NULL || lk->link_type != REALTIME_UDP_LINK || (rt_data = (Realtime_Data*) lk->prot_data) == NULL) {
	Alarm(EXIT, "Send_RT_nack(): link not valid\n");
	return;
    }

    scat.num_elements    = 2;			  
    scat.elements[0].len = sizeof(packet_header);
    scat.elements[0].buf = (char *)(&hdr);
    scat.elements[1].len = rt_data->num_nacks*sizeof(rt_seq_type);
    scat.elements[1].buf = rt_data->nack_buff;
	
    hdr.type             = REALTIME_NACK_TYPE;
    hdr.type             = Set_endian(hdr.type);

    hdr.sender_id        = My_Address;
    hdr.ctrl_link_id     = lk->leg->ctrl_link_id;
    hdr.data_len         = 0; 
    hdr.ack_len          = rt_data->num_nacks*sizeof(rt_seq_type);
    hdr.seq_no           = Set_Loss_SeqNo(lk->leg, REALTIME_UDP_LINK);
    
    rt_data->num_nacks = 0;
    
    /* Sending the ack*/
    if(network_flag == 1) {
      ret = Link_Send(lk, &scat);
    }
}

/***********************************************************/
/* void Send_RT_Retransm(int16 linkid, void* dummy)        */
/*                                                         */
/* Sends an Realtime retransmission                        */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* linkid:    ID of the link to send on                    */
/* dummy:     Not used                                     */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Send_RT_Retransm(int linkid, void* dummy) 
{
    Link *lk;
    packet_header hdr;
    udp_header *uhdr;
    sys_scatter scat;
    Realtime_Data *rt_data;
    History_Cell *h_cell;
    int diff, i, ret, routing;
    sp_time now;
    rt_seq_type seq_no;
    char *buff;
    int16u buf_len;
   
    if ((lk = Links[linkid]) == NULL || lk->link_type != REALTIME_UDP_LINK || (rt_data = (Realtime_Data*) lk->prot_data) == NULL) {
	Alarm(EXIT, "Send_RT_nack(): link not valid\n");
	return;
    }

    if(rt_data->retransm_buff == NULL) {
	return;
    }

    now = E_get_time();

    /* Clean the history window of old packets */
    while(rt_data->tail < rt_data->head) {
	h_cell = &rt_data->window[rt_data->tail%MAX_HISTORY];
	diff = (now.usec - h_cell->timestamp.usec) +
	    1000000*(now.sec - h_cell->timestamp.sec);
	if(diff > HISTORY_TIME) {
	    dec_ref_cnt(rt_data->window[rt_data->tail%MAX_HISTORY].buff);
	    rt_data->window[rt_data->tail%MAX_HISTORY].buff = NULL;
	    rt_data->tail++;
	    Alarm(DEBUG, "Clean_RT_history: History cleaned\n");
	}
	else {
	    break;
	}
    }

    /* Resend the packets here... */

    for(i=0; i < rt_data->num_retransm; i++) {
	seq_no = *(rt_seq_type*)(rt_data->retransm_buff+i*sizeof(rt_seq_type));
	if(seq_no >= rt_data->head) {
	    Alarm(DEBUG, "Request RT retransm for a message that wasn't sent\n");
	    continue;
	}
	if(seq_no >= rt_data->tail) {
	    if(rt_data->bucket < RT_RETRANSM_TOK) {
		break;
	    }
	    rt_data->bucket -= RT_RETRANSM_TOK;

	    buff = rt_data->window[seq_no%MAX_HISTORY].buff;
	    buf_len = rt_data->window[seq_no%MAX_HISTORY].len;
	    
	    Alarm(DEBUG, "resending %d\n", seq_no);

	    /* Send the retransm. */	    
	    scat.num_elements = 2;
	    scat.elements[0].len = sizeof(packet_header);
	    scat.elements[0].buf = (char *) &hdr;
            /* AB: changed so that the buffer we store already includes the
             * extra int32 for the sequence number (plus dissemination header
             * size) */
            /*scat.elements[1].len = buf_len+sizeof(int32);*/
	    scat.elements[1].len = buf_len;
	    scat.elements[1].buf = buff;

            uhdr = (udp_header*) scat.elements[1].buf;
            routing = (uhdr->routing << ROUTING_BITS_SHIFT);
	    
	    hdr.type    = REALTIME_DATA_TYPE;
	    hdr.type    = Set_endian(hdr.type);

	    hdr.sender_id    = My_Address;
	    hdr.ctrl_link_id = lk->leg->ctrl_link_id;
	    hdr.ack_len      = sizeof(rt_seq_type) + Dissemination_Header_Size(routing);
	    hdr.data_len     = buf_len - hdr.ack_len;
	    hdr.seq_no       = Set_Loss_SeqNo(lk->leg, REALTIME_UDP_LINK);

	    /* Set the sequence number of the packet */
	    *(rt_seq_type*)(buff+hdr.data_len) = seq_no;
    
	    if(network_flag == 1) {
	      ret = Link_Send(lk, &scat);

	      if(ret < 0) {
		break;
	      }
            }
	}
    }
    
    dec_ref_cnt(rt_data->retransm_buff);
    rt_data->retransm_buff = NULL;
    rt_data->num_retransm = 0;

    Alarm(DEBUG, "Send_RT_Retransm\n");
}

/***********************************************************/
/* void Process_RT_nack_packet(Node_ID sender,             */
/*                  sys_scatter *scat, int32u type,        */
/*                  int mode)                              */         
/*                                                         */
/* Processes an ACK packet                                 */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* sender:    IP of the sender                             */
/* scat:      sys_scatter containing the ACK               */
/* type:      type of the packet, containing endianess     */
/* mode:      mode of the link                             */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Process_RT_nack_packet(Link *lk, sys_scatter *scat, int32u type, int mode)
{
    int16u ack_len;
    char *buff;
    packet_header *phdr;
    Realtime_Data *rt_data;
    rt_seq_type *tmp;
    int i;

    if (scat->num_elements != 2) {
        Alarm(PRINT, "Proces_RT_nack_packet: Dropping packet because "
            "scat->num_elements == %d instead of 2\r\n", scat->num_elements);
        return;
    }

    phdr     = (packet_header*) scat->elements[0].buf;
    ack_len  = phdr->ack_len;
    buff     = (char*) scat->elements[1].buf;

    rt_data = lk->prot_data;

    if (rt_data->retransm_buff != NULL) {
      dec_ref_cnt(rt_data->retransm_buff);
    }

    tmp = (rt_seq_type*)scat->elements[1].buf;
	
    if (!Same_endian(type)) {

      for (i = 0; i < ack_len / sizeof(rt_seq_type); ++i) {
	*tmp = Flip_int64(*tmp);
	tmp++;
      }
    }

    rt_data->retransm_buff = scat->elements[1].buf;
    inc_ref_cnt(scat->elements[1].buf);
    rt_data->num_retransm = ack_len / sizeof(rt_seq_type);

    E_queue(Send_RT_Retransm, (int)lk->link_id, NULL, zero_timeout);
}
