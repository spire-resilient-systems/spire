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

#include "objects.h"
#include "net_types.h"
#include "node.h"
#include "route.h"
#include "reliable_datagram.h"
#include "udp.h"
#include "link.h"
#include "session.h"
#include "reliable_udp.h"
#include "state_flood.h"
#include "multicast.h"
#include "protocol.h"

/* Global vriables */

extern Node     *This_Node;
extern Node_ID   My_Address;
extern stdhash   All_Nodes;
extern stdhash   All_Groups_by_Node; 
extern stdhash   All_Groups_by_Name; 
extern stdhash   Neighbors;
extern int       Unicast_Only;

/* Local variables */
static const sp_time zero_timeout        = {     0,     0};
static const sp_time short_timeout       = {     0, 10000};


/***********************************************************/
/* void Process_rel_udp_data_packet(Node_ID sender_id,       */
/*                              char *buff,                */
/*                              int16u data_len,           */
/*                              int16u ack_len,            */
/*                              int32u type, int mode)     */
/*                                                         */
/* Processes a reliable UDP data packet                    */
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

void Process_rel_udp_data_packet(Link *lk, sys_scatter *scat,
				 int32u type, int mode)
{

  packet_header  *phdr;
  int16u          data_len, ack_len;
  char           *buff;
  udp_header     *hdr;
  reliable_tail  *r_tail;
  Reliable_Data  *r_data;
  int             flag, routing;
  
  if (scat->num_elements != 2) {
    Alarm(PRINT, "Process_rel_udp_data_packet: Dropping packet because "
        "scat->num_elements == %d instead of 2\r\n", scat->num_elements);
    return;
  }

  if (scat->elements[1].len < sizeof(udp_header))
  {
    Alarmp(SPLOG_WARNING, PRINT, "Process_rel_udp_data_packet: Dropping packet because too small!\n");
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
    Alarm(PRINT, "Process_rel_udp_data_packet: Packed data not available yet!\r\n");
    return;
  } */
  
  r_data = (Reliable_Data*) lk->r_data;

  if (!(r_data->flags & CONNECTED_LINK)) {
    return;
  }

  /* Get the reliable tail from the packet */
  r_tail = (reliable_tail*)(buff+data_len);

  /* Process the ack part. 
   * If the packet is not needed (we processed it earlier) just return */ 
  flag = Process_Ack(lk->link_id, (char*)r_tail, ack_len, type);
	
  /* We should send an acknowledge for this message. 
   * So, let's schedule it 
   */
  if(flag == -1) {
    /* This is just an ack packet */
    Alarm(PRINT, "Warning !!! Ack packets should be treated differently !\n");
    return;
  }

  if(r_data->scheduled_ack == 1) {
    E_queue(Send_Ack, (int)lk->link_id, NULL, zero_timeout);
  }
  else {	    
    r_data->scheduled_ack = 1;
    E_queue(Send_Ack, (int)lk->link_id, NULL, short_timeout);
  }

  if(flag == 0) {
    /* This is an old packet (retrans), and therefore not useful */
    return;
  }
	    
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
/* int Forward_Rel_UDP_Data((Node *next_hop,               */
/*                  sys_scatter *msg_scat, int32u type)    */
/*                                                         */
/*                                                         */
/*                                                         */
/* Forwards a reliable UDP data packet                     */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* next_hop:  the next node on the path                    */
/* msg_scat:  a sys_scatter containing the message         */
/* type:      type of the message                          */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int) the status of the packet (see udp.h)              */
/*                                                         */
/***********************************************************/

int Forward_Rel_UDP_Data(Node *next_hop, sys_scatter *scat, int32u type)
{
    Link   *lk;

    /* if (scat->num_elements !=  2) {
        Alarm(PRINT, "Forward_Rel_UDP_Data: Malformed sys_scatter: num_elements == %d\r\n",
                    scat->num_elements);
        return BUFF_DROP;
    } */

    if (type & DATA_MASK) {
      Alarm(EXIT, "Forward_Rel_UDP_Data: Data type already set?!\r\n");
    }
    
    if (next_hop == This_Node) {
      Process_udp_data_packet(NULL, scat, (type | UDP_DATA_TYPE), UDP_LINK);
      return BUFF_EMPTY;
    }

    if ((lk = Get_Best_Link(next_hop->nid, RELIABLE_UDP_LINK)) == NULL) {
      return BUFF_DROP;
    }

    Reliable_Send_Msg(lk->link_id, scat->elements[1].buf, scat->elements[1].len, (type | REL_UDP_DATA_TYPE));

    return BUFF_OK;
}

/***********************************************************/
/* Request Resources to forward a Reliable UDP data packet */
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
int Request_Resources_Rel_UDP(Node *next_hop, int (*callback)(Node*, int))
{
    (*callback)(next_hop, RELIABLE_UDP_LINK);
    return 1;
}
