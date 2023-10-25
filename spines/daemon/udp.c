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

#ifdef ARCH_PC_WIN95
#  include <winsock2.h>
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
#include "protocol.h"
#include "route.h"
#include "session.h"
#include "state_flood.h"
#include "multicast.h"
#include "configuration.h"

/* Global vriables */

extern Node     *This_Node;
extern Node_ID   My_Address;
extern stdhash   All_Nodes;
extern Link*     Links[MAX_LINKS];
extern int       network_flag;
extern stdhash   All_Groups_by_Node; 
extern stdhash   All_Groups_by_Name; 
extern stdhash   Neighbors;
extern int       Unicast_Only;
extern int       Security;
extern int16u    My_ID;

void Flip_udp_hdr(udp_header *udp_hdr)
{
    udp_hdr->source	  = Flip_int32( udp_hdr->source );
    udp_hdr->dest	  = Flip_int32( udp_hdr->dest );
    udp_hdr->source_port  = Flip_int16( udp_hdr->source_port );
    udp_hdr->dest_port	  = Flip_int16( udp_hdr->dest_port );
    udp_hdr->len	  = Flip_int16( udp_hdr->len );
    udp_hdr->seq_no	  = Flip_int16( udp_hdr->seq_no );
    udp_hdr->sess_id	  = Flip_int16( udp_hdr->sess_id );
}

void Copy_udp_header(udp_header *from_udp_hdr, udp_header *to_udp_hdr)
{
    to_udp_hdr->source	    = from_udp_hdr->source;
    to_udp_hdr->dest	    = from_udp_hdr->dest;
    to_udp_hdr->source_port = from_udp_hdr->source_port;
    to_udp_hdr->dest_port   = from_udp_hdr->dest_port;
    to_udp_hdr->len	    = from_udp_hdr->len;
    to_udp_hdr->seq_no	    = from_udp_hdr->seq_no;
    to_udp_hdr->sess_id	    = from_udp_hdr->sess_id;
    to_udp_hdr->frag_num    = from_udp_hdr->frag_num;
    to_udp_hdr->frag_idx    = from_udp_hdr->frag_idx;
    to_udp_hdr->ttl         = from_udp_hdr->ttl;
    to_udp_hdr->routing     = from_udp_hdr->routing;
}

/***********************************************************/
/* Processes a UDP data packet                             */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* lk:        link upon which this packet was recvd        */
/* scat:      a sys_scatter containing the message         */
/* type:      type of the packet                           */
/* mode:      mode of the link the packet arrived on       */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Process_udp_data_packet(Link *lk, sys_scatter *scat, int32u type, int mode)
{
  int32u routing, data_len, ack_len;
  packet_header *phdr;
  udp_header *hdr;

  /* NOTE: lk can be NULL -> self delivery */

  /* The first element in the scat is the spines header */

  if (scat->num_elements != 2) {
    Alarm(PRINT, "Process_udp_data_packet: Dropping packet because "
        "scat->num_elements == %d instead of 2\r\n", scat->num_elements);
    return;
  }

  if (scat->elements[1].len < sizeof(udp_header))
  {
    Alarmp(SPLOG_WARNING, PRINT, "Process_udp_data_packet: Dropping packet because packet too small!\n");
    return;
  }
  
  phdr = (packet_header*) scat->elements[0].buf;
  hdr = (udp_header*) scat->elements[1].buf;

  if (!Same_endian(type)) {
    Flip_udp_hdr(hdr);
  }

  /* ADJUSTING ACK_LEN */
  routing = (hdr->routing << ROUTING_BITS_SHIFT);
  data_len = phdr->data_len;
  ack_len  = phdr->ack_len - Dissemination_Header_Size(routing);

   /* REG ROUTING HACK */
  scat->elements[1].len = ((packet_header*)scat->elements[0].buf)->data_len;

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
/* Forward a UDP data packet                               */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* next_hop:  the next node on the path                    */
/* scat:      sys_scatter containing the message           */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int) the status of the packet (see udp.h)              */
/*                                                         */
/***********************************************************/

int Forward_UDP_Data(Node *next_hop, sys_scatter *scat)
{
  Link          *lk;
  packet_header *hdr;
  udp_header    *uhdr;
  int           ret, routing;
  /* int           i;
  unsigned char *path = NULL;
  unsigned char temp_path_index; */

  /* if (scat->num_elements != 2) {
    Alarm(PRINT, "Forward_UDP_Data: Malformed sys_scatter: num_elements == %d\r\n",
                    scat->num_elements);
    return BUFF_DROP;
  } */

  if (next_hop == This_Node) {
    Process_udp_data_packet(NULL, scat, UDP_DATA_TYPE, UDP_LINK);
    return BUFF_EMPTY;
  }

  if ((lk = Get_Best_Link(next_hop->nid, UDP_LINK)) == NULL) {
    return BUFF_DROP;
  }

  /* if (Path_Stamp_Debug == 1) {
    path = ((unsigned char *)scat->elements[1].buf) + sizeof(udp_header) + 16;
    temp_path_index = 8;
    for (i = 0; i < 8; i++) {
      if (temp_path_index == 8 && path[i] == 0)
        temp_path_index = i;
    }
    if (temp_path_index != 8)
      path[temp_path_index] = (unsigned char) My_ID;
  } */

  hdr = (packet_header*) scat->elements[0].buf;
  uhdr = (udp_header *) scat->elements[1].buf;
  routing = (uhdr->routing << ROUTING_BITS_SHIFT);

  hdr->type             = UDP_DATA_TYPE;
  hdr->type             = Set_endian(hdr->type);

  hdr->sender_id        = My_Address;
  hdr->ctrl_link_id     = lk->leg->ctrl_link_id;
  hdr->data_len         = scat->elements[1].len;
  hdr->ack_len          = 0 + Dissemination_Header_Size(routing);
  hdr->seq_no           = Set_Loss_SeqNo(lk->leg, UDP_LINK);

  if(network_flag == 1) {
    ret = Link_Send(lk, scat);

    if (ret < 0) {
      return BUFF_DROP;
    }
  }

  return BUFF_EMPTY;
}


/***********************************************************/
/* Request Resources to forward a UDP data packet          */
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
int Request_Resources_UDP(Node *next_hop, int (*callback)(Node*, int))
{
    (*callback)(next_hop, UDP_LINK);
    return 1;
}
