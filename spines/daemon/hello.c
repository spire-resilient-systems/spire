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

#ifndef	ARCH_PC_WIN95
#  include <netdb.h>
#  include <sys/socket.h>
#else
#  include <winsock2.h>
#endif

#include <stdlib.h>
#include <math.h>

#include "stdutil/stdutil.h"
#include "stdutil/stdhash.h"

#include "arch.h"
#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_data_link.h"

#include "objects.h"
#include "net_types.h"
#include "node.h"
#include "link.h"
#include "network.h"
#include "reliable_datagram.h"
#include "hello.h"
#include "link_state.h"
#include "protocol.h"
#include "udp.h"
#include "realtime_udp.h"
#include "route.h"
#include "state_flood.h"
#include "multipath.h"
#include "configuration.h"

#include "spines.h"

/* Configuration File Variables */
extern char        Config_File_Found;
extern stdhash     Node_Lookup_Addr_to_ID;
extern int16u      My_ID;
extern int32u      *Neighbor_Addrs[];
extern int16u      *Neighbor_IDs[];

/* Local variables */

static const sp_time zero_timeout   = {     0,    0};
/* Default Values */
static       sp_time cnt_timeout    = {     0,    100000};
             sp_time hello_timeout  = {     0,    100000};
/* For simulating Internet rerouting */
/*static       sp_time cnt_timeout    = {     0,    999999};
             sp_time hello_timeout  = {     0,    999999};*/

/* AB: Reduced ad_timeout from 6 seconds to 1 second. Note that ad_timeout is
 * currently used both for sending hello pings on a disconnected link and for
 * sending out (wireless broadcast?) pings to try to automatically discover
 * links that may or may not exist. For a future version, we may want to
 * separate these into two different timeouts (with reconnection attempts on
 * known links being more frequent than auto-discovery attempts on potential
 * links. For now we are just reducing the single timeout to be more reasonable
 * for reconnection since we aren't actively using the wireless capabilities */
static       sp_time ad_timeout     = {     1,    0};
/* static       sp_time ad_timeout     = {     6,    0}; */

int          hello_cnt_start        = (int) (0.5 + 0.7 * DEAD_LINK_CNT); 
int          stable_delay_flag      = 1;
/*int          stable_delay_flag      = 0;*/
double       stable_timeout         = 0.0;

void Flip_hello_pkt( hello_packet *hello_pkt )
{
    hello_pkt->seq_no          = Flip_int32(hello_pkt->seq_no);
    hello_pkt->my_time_sec     = Flip_int32(hello_pkt->my_time_sec);
    hello_pkt->my_time_usec    = Flip_int32(hello_pkt->my_time_usec);
    hello_pkt->response_seq_no = Flip_int32(hello_pkt->response_seq_no);
    hello_pkt->diff_time       = Flip_int32(hello_pkt->diff_time);
    hello_pkt->loss_rate       = Flip_int32(hello_pkt->loss_rate);
}

/***********************************************************/
/* Init_Connections(void)                                  */
/*                                                         */
/* Starts hello protocol on all the known links,           */
/* initializing the protocols on these links               */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Init_Connections(void)
{
  if (Wireless) {
    hello_timeout.sec = 2;
    cnt_timeout.usec = 200000;
    hello_cnt_start = (int) (0.5 + 0.3 * DEAD_LINK_CNT); 
    stable_delay_flag = 1;
  } 

  /* Start the link recover protocol (hello ping) */

  if (!Wireless || (Wireless && Num_Discovery_Addresses == 0)) {
    Send_Hello_Ping(0, NULL); 
  }

  /* Start Discovery of neighbors if requested */

  if (Num_Discovery_Addresses > 0) {
    Send_Discovery_Hello_Ping(0, NULL);
  }

  if (stable_delay_flag) {
    stable_timeout = 2.0 * DEAD_LINK_CNT * (hello_timeout.sec + hello_timeout.usec / 1000000.0);
  } 
}

/***********************************************************
 * Call back function to disconnect a leg.
 ***********************************************************/

static void Dead_Leg(int linkid, void *dummy)
{
  Link   *lk;
  sp_time t;
    
  if ((lk = Links[linkid]) == NULL || lk->link_type != CONTROL_LINK) {
    Alarm(DEBUG, "Dead_Leg: invalid control link!\r\n");
    return;
  }

  if (lk->leg->hellos_out < DEAD_LINK_CNT)
    return;

  t = E_sub_time(E_get_time(), lk->leg->last_recv_hello);

  Alarm(PRINT, "Dead_Leg: sent %d hellos with no response; it's been %.6f seconds since last receipt; DISCONNECTING!\n", 
	lk->leg->hellos_out, t.sec + t.usec / 1.0e6);

  Disconnect_Network_Leg(lk->leg);
}

/***********************************************************/
/* Send_Hello(int linkid, void *dummy)                     */
/*                                                         */
/* Called periodically by the event system.                */
/* Sends a hello message on a link and declares the link   */
/* dead if a number of hello msgs hav already been sent    */
/* without an ack                                          */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* linkid - the id of the link in the global array         */
/*                                                         */
/***********************************************************/

void Send_Hello(int linkid, void *dummy)
{
  Link   *lk;
  sp_time dead_timeout;  /* NOTE: 50% of hello_timeout -- give last hello a little extra time to arrive b4 declaring dead link */
    
  if ((lk = Links[linkid]) == NULL || lk->link_type != CONTROL_LINK) {
    Alarm(EXIT, "Send_Hello: invalid control link!\r\n");
  }

  if (lk->leg->hellos_out > 1) {
    dead_timeout = E_sub_time(E_get_time(), lk->leg->last_recv_hello);  /* just tmp used for following print */

    Alarm(DEBUG, "Send_Hello: sent %d hellos (" IPF " -> " IPF ") with no response; it's been %.6f seconds since last receipt\n", 
	  lk->leg->hellos_out + 1, IP(lk->leg->local_interf->net_addr), IP(lk->leg->remote_interf->net_addr), dead_timeout.sec + dead_timeout.usec / 1.0e6);
  }

  if (lk->leg->hellos_out == hello_cnt_start) {
    E_queue(Send_Hello_Request_Cnt, linkid, NULL, cnt_timeout);
  }

  if (lk->leg->hellos_out == DEAD_LINK_CNT) {

    if (hello_timeout.sec == 0) {
      dead_timeout.sec  = 0;
      dead_timeout.usec = hello_timeout.usec / 2;

    } else {
      dead_timeout.usec = (hello_timeout.sec * 1000000L + hello_timeout.usec) / 2;
      dead_timeout.sec  = dead_timeout.usec / 1000000L;
      dead_timeout.usec = dead_timeout.usec % 1000000L;
    }

    E_queue(Dead_Leg, linkid, NULL, dead_timeout);
  }

  Net_Send_Hello((int16u) linkid, 0);
  ++lk->leg->hellos_out;

  Clean_RT_history(lk->leg->links[REALTIME_UDP_LINK]);     /* TODO: move to realtime_udp.c where it belongs */
  E_queue(Send_Hello, linkid, NULL, hello_timeout);	
}

/***********************************************************/
/* Send_Hello_Request(int linkid, void *dummy)             */
/*                                                         */
/* Called by the event system.                             */
/* Sends a hello message on a link and requests an         */
/* immediate response (another hello message) from the     */
/* receiver                                                */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* linkid: the ID of the link in the global array          */
/*                                                         */
/***********************************************************/

void Send_Hello_Request(int linkid, void *dummy)
{ 
  Net_Send_Hello((int16u) linkid, 1);
}

/***********************************************************/
/* Send_Hello_Request_Cnt(int linkid, void *dummy)         */
/*                                                         */
/* Called by the event system.                             */
/* Sends a hello message on a link and requests an         */
/* immediate response (another hello message) from the     */
/* receiver.                                               */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* linkid: the ID of the link in the global array          */
/*                                                         */
/***********************************************************/

void Send_Hello_Request_Cnt(int linkid, void *dummy)
{
  Link *lk;
    
  if ((lk = Links[linkid]) == NULL || lk->link_type != CONTROL_LINK) {
    Alarm(EXIT, "Send_Hello_Request_Cnt: invalid control link!\r\n");
  }

  Net_Send_Hello((int16u) linkid, 1);
  E_queue(Send_Hello_Request_Cnt, linkid, NULL, cnt_timeout);
}

/***********************************************************/
/* Send_Discovery(int linkid, void *dummy)                 */
/*                                                         */
/* Called periodically by the event system.                */
/* Sends a hello message on autodiscovery channels         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Send_Discovery_Hello_Ping(int dummy_int, void *dummy)
{ 
  stdit tit;
  int   i;

  for (stdhash_begin(&This_Node->interfaces, &tit); !stdhash_is_end(&This_Node->interfaces, &tit); stdhash_it_next(&tit)) {

    Interface *interf = *(Interface**) stdhash_it_val(&tit);

    for (i = 0; i < Num_Discovery_Addresses && i < interf->num_discovery; ++i) {
      Net_Send_Hello_Ping(interf->discovery[i], Discovery_Address[i]);
    }
  }

  E_queue(Send_Discovery_Hello_Ping, 0, NULL, ad_timeout);
}

/***********************************************************/
/* Send_Hello_Ping(int linkid, void *dummy)                */
/*                                                         */
/* Called periodically by the event system.                */
/* Sends a hello message on dead links and requests a      */
/* response (another hello message) from the receiver      */
/* It is used to determine if a crashed/partitioned        */
/* node recovered                                          */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Send_Hello_Ping(int dummy_int, void* dummy)
{
  stdit tit;

  for (stdhash_begin(&Network_Legs, &tit); !stdhash_is_end(&Network_Legs, &tit); stdhash_it_next(&tit)) {

    Network_Leg *leg = *(Network_Leg**) stdhash_it_val(&tit);

    if (leg->status == DISCONNECTED_LEG) {

      Alarm(DEBUG, "Send_Hello_Ping: pinging on edge (" IPF " -> " IPF "); leg (" IPF " -> " IPF "); net (" IPF " -> " IPF")\r\n",
	    IP(leg->edge->src_id), IP(leg->edge->dst_id), 
	    IP(leg->local_interf->iid), IP(leg->remote_interf->iid),
	    IP(leg->local_interf->net_addr), IP(leg->remote_interf->net_addr));

      Net_Send_Hello_Ping(leg->local_interf->channels[CONTROL_LINK], leg->remote_interf->net_addr);
    }
  }

  E_queue(Send_Hello_Ping, 0, NULL, ad_timeout);
}

/***********************************************************/
/* Net_Send_Hello(int16 linkid, int mode)                  */
/*                                                         */
/* Sends a hello message on a given link.                  */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* linkid: the ID of the link in the global array          */
/*                                                         */
/* mode: 1 if an immediate response is requested,          */
/*       0 otherwise                                       */
/*                                                         */
/***********************************************************/

void Net_Send_Hello(int16 linkid, int mode) 
{
  sp_time       now = E_get_time();
  Link         *link;
  Control_Data *c_data;
  sys_scatter   scat;
  packet_header hdr;
  hello_packet  pkt;
  int           ret;

  if ((link = Links[linkid]) == NULL || link->link_type != CONTROL_LINK) {
    Alarm(EXIT, "Net_Send_Hello: control link invalid\r\n");
    return;
  }

  c_data               = (Control_Data*) link->prot_data;

  scat.num_elements    = 2;
  scat.elements[0].len = sizeof(packet_header);
  scat.elements[0].buf = (char*) &hdr;
  scat.elements[1].len = sizeof(hello_packet);
  scat.elements[1].buf = (char*) &pkt;

  hdr.type             = (mode == 0 ? HELLO_TYPE : HELLO_REQ_TYPE);
  hdr.type             = Set_endian(hdr.type);

  hdr.sender_id        = My_Address;
  hdr.ctrl_link_id     = link->leg->ctrl_link_id;
  hdr.data_len         = sizeof(hello_packet);
  hdr.ack_len          = 0;
  hdr.seq_no           = Set_Loss_SeqNo(link->leg, CONTROL_LINK);

  pkt.seq_no           = c_data->hello_seq++;
  pkt.my_time_sec      = (int32) now.sec;
  pkt.my_time_usec     = (int32) now.usec;
  pkt.response_seq_no  = c_data->other_side_hello_seq;
  pkt.diff_time        = c_data->diff_time;
  pkt.loss_rate        = Compute_Loss_Rate(link->leg);
    
  if(network_flag == 1) {
    ret = Link_Send(link, &scat);
  }
}

/***********************************************************/
/* Sends a hello message on a dead link.                   */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* address: the IP address of the destination              */
/*                                                         */
/***********************************************************/

void Net_Send_Hello_Ping(channel chan, Network_Address addr) 
{
  sp_time       now = E_get_time();
  sys_scatter   scat;
  packet_header hdr;
  hello_packet  pkt;
  int           ret;

  scat.num_elements    = 2;
  scat.elements[0].len = sizeof(packet_header);
  scat.elements[0].buf = (char*) &hdr;
  scat.elements[1].len = sizeof(hello_packet);
  scat.elements[1].buf = (char*) &pkt;

  hdr.type             = HELLO_PING_TYPE;	
  hdr.type             = Set_endian(hdr.type);

  hdr.sender_id        = My_Address;
  hdr.ctrl_link_id     = 0;
  hdr.data_len         = sizeof(hello_packet);
  hdr.ack_len          = 0;
  hdr.seq_no           = 0;

  pkt.seq_no           = 2;                 /* TODO: JLS: Figure out why this is 2 and document? */
  pkt.my_time_sec      = (int32) now.sec;
  pkt.my_time_usec     = (int32) now.usec;
  pkt.diff_time        = 0;

  if(network_flag == 1) {
    ret = DL_send(chan, addr, Port + CONTROL_LINK, &scat);
  }
}

/***********************************************************/
/* Processes a hello message.                              */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* lk: link on which hello message was recvd               */
/* buf: a pointer to the message itself                    */
/* remaining bytes: length of the message in the buffer    */
/* type: first byte in the actual packet received, giving  */
/*       the type of the message, endianess, etc.          */
/*                                                         */
/***********************************************************/

void Process_hello_packet(Link *lk, packet_header *pack_hdr, char *buf,
                          int remaining_bytes, int32u type)
{
  Control_Data *c_data      = (Control_Data*) lk->prot_data;
  Network_Leg  *leg         = lk->leg;
  Edge         *edge        = leg->edge;
  sp_time       now         = E_get_time();
  hello_packet *pkt         = (hello_packet*) buf;
  int           update_cost = 0;
  int16u        ngbr_id;
  int32         rtt_int;
  stdit         it;
  Edge_Key      key;
  Loss_Data     *l_data;
  int           i;

  if (remaining_bytes != sizeof(hello_packet))
  {
    Alarmp(SPLOG_WARNING, PRINT, "Process_hello_packet: Wrong # of bytes for "
                                 "hello: %d\n", remaining_bytes);
    return;
  }

  if (!Same_endian(type)) {
    Flip_hello_pkt(pkt);
  }

  /* Check if other side crashed and came back up before I disconnected it */
  if (pack_hdr->ctrl_link_id != leg->other_side_ctrl_link_id) {  /* packet's ctrl link id doesn't match what we expected */

    if (leg->other_side_ctrl_link_id == 0) {                     /* other side initalizing his session link id */

      Alarm(DEBUG, "Process_hello_packet: sender ("IPF") initializing ctrl id to 0x%x!\n", 
	    IP(leg->remote_interf->net_addr), pack_hdr->ctrl_link_id);

      /* Reset loss detection sequence numbers when the link resets */
      leg->other_side_ctrl_link_id = pack_hdr->ctrl_link_id;
      l_data = &((Control_Data*) leg->links[CONTROL_LINK]->prot_data)->l_data;
      for (i = 0; i < MAX_LINKS_4_EDGE; i++)
      {
        l_data->recvd_seqs[i] = PACK_MAX_SEQ + 1;
      }
      l_data->recvd_seqs[CONTROL_LINK] = pack_hdr->seq_no;
    } else {                                                     /* other side previously set his session link id */ 
      Alarm(DEBUG, "Process_hello_packet: sender's ("IPF") ctrl id 0x%x doesn't match expected ctrl id 0x%x! Dropping!\n", 
	    IP(leg->remote_interf->net_addr), pack_hdr->ctrl_link_id, leg->other_side_ctrl_link_id);
      Disconnect_Network_Leg(leg);
      Send_Hello( Create_Link(leg, CONTROL_LINK), NULL );
      return;
    }
  }

  /* Check for loss */
  Check_Link_Loss(leg, pack_hdr->seq_no, CONTROL_LINK);

  /* Make sure that this is not an old hello that took too long to get here */
  if (c_data->other_side_hello_seq > pkt->seq_no + 3) { 
    return;
  }

  c_data->other_side_hello_seq = pkt->seq_no;

  /* compute round trip time + clock offset */
  /* TODO: inspect this code a bit closer to understand it (i.e. - how does diff_time work?) */
  {
    sp_time remote, my_diff;

    remote.sec  = pkt->my_time_sec;
    remote.usec = pkt->my_time_usec;
      
    my_diff     = E_sub_time(now, remote);
    rtt_int     = my_diff.sec * 1000000 + my_diff.usec + pkt->diff_time * 100;
      
    if (rtt_int < 0) { /* This can be because of the precision of 0.1ms in pkt->diff_time */	
      rtt_int = 100;   /* The precision value */
    }
      
    c_data->diff_time = my_diff.sec * 10000 + my_diff.usec / 100;
  }

  /* update round trip time */

  /* The line below ignores hello packets with response sequence
   * numbers sufficiently less than the current hello sequence
   * number. NOTE: The maximum latency that can be measured depends
   * on this line and the number of hello packets sent per second. 
   * If response_seq_no == 0, then the node that sent this hello did
   * not yet receive any hellos from this node since the link was
   * created -- thus, pkt->diff_time is possibly out-of-date, and the
   * rtt should not be computed. 
   */

  if (c_data->hello_seq <= pkt->response_seq_no + 20 && pkt->response_seq_no != 0) {

    c_data->rtt = 0.95 * c_data->rtt + 0.05 * (rtt_int / 1000.0);

    if (c_data->rtt < 1.0) {
      c_data->rtt = 1.0;
    }

    /*update_cost     = 1;*/
    lk->r_data->rtt = c_data->rtt;
  }

  /* update loss rate */

  if (pkt->loss_rate != UNKNOWN) {
    c_data->est_loss_rate = (float) pkt->loss_rate / LOSS_RATE_SCALE;
    /*update_cost           = 1;*/
  }

  /*Alarm(PRINT, "Process_hello_packet: edge(" IPF " -> " IPF "); leg(" IPF " -> " IPF "); est_loss = %f, rtt = %f\r\n", 
     IP(edge->src_id), IP(edge->dst_id), IP(leg->local_interf->iid), IP(leg->remote_interf->iid), c_data->est_loss_rate, c_data->rtt);*/

  /* reset any hello escalation */

  lk->leg->hellos_out = 0;
  lk->leg->last_recv_hello = now;
  E_dequeue(Send_Hello_Request_Cnt, lk->link_id, NULL); 

  /* answer requests immediately */
			
  if (Is_hello_req(type)) {
    E_queue(Send_Hello, lk->link_id, NULL, zero_timeout);
  }

  if (leg->status == CONNECTED_LEG) {

    /* See if we need to update the leg cost: We set update_cost to 0 by
     * default. If we're using something other than DISTANCE_ROUTE, check
     * whether this update should trigger a cost update */

    if (Route_Weight == PROBLEM_ROUTE) {
        /* Always try to update cost for problem type routing -- logic for
         * checking whether there is a real change is in
         * Network_Leg_Update_Cost */
        update_cost = 1;
    } else if (Route_Weight != DISTANCE_ROUTE) {

      /* TODO: this randomization is a bit weird: we should
	 probably randomly pick once and schedule a callback for
	 that time.  By repeatedly picking uniform random times
	 since the last update, the more often this code is
	 triggered (e.g. - fast hello's) the sooner we are likely
	 to pass this test -- that is, the chosen announcment times
	 will be much denser towards 30 than evenly distributed.
      */

      /* TODO: Should the % difference be different for increases
	 vs. decreases to be symmetrical?  For example, if we
	 require a 100% difference, then on the high side we need
	 to double the metric in question, but on the low side the
	 metric has to go to zero.  It probably should be half
	 instead?  However, doing that might cause you to be more
	 sensitive to tiny changes when the metric is near the
	 resolution (e.g. - rtt is at 2ms then goes to 1ms).
	 Don't know if that is undesirable or not.
      */

      int time_rnd = (int) (30.0 * rand() / (RAND_MAX + 1.0));

      if (now.sec > edge->my_timestamp_sec + 30 + time_rnd) {  /* refuse to update edge + legs costs again for 30-60 seconds */

	if (Route_Weight == LATENCY_ROUTE || Route_Weight == AVERAGE_ROUTE) {

	  update_cost = (c_data->reported_rtt == UNKNOWN || 
			 (fabs(c_data->reported_rtt - c_data->rtt) > NET_UPDATE_THRESHOLD * c_data->reported_rtt &&
			  fabs(c_data->reported_rtt - c_data->rtt) >= 2));  /* 1 ms accuracy one-way*/
	}

	if (update_cost == 0 &&
            (Route_Weight == LOSSRATE_ROUTE || Route_Weight == AVERAGE_ROUTE)) {

	  float diff = c_data->reported_loss_rate - c_data->est_loss_rate;

	  if (diff < 0.0) {
	    diff = -diff;
	  }

	  update_cost = (diff > NET_UPDATE_THRESHOLD * c_data->reported_loss_rate);
	}

      }
    }

    if (update_cost && Network_Leg_Update_Cost(leg) > 0) {
      c_data->reported_rtt       = c_data->rtt;
      c_data->reported_loss_rate = c_data->est_loss_rate;
      c_data->reported_ts        = now;
    }

  } else if (leg->status == NOT_YET_CONNECTED_LEG) {

    if (++leg->connect_cnter >= CONNECT_LINK_CNT) {

      leg->status = CONNECTED_LEG;

      Network_Leg_Set_Cost(leg, Network_Leg_Initial_Cost(leg));
      c_data->reported_rtt       = c_data->rtt;
      c_data->reported_loss_rate = c_data->est_loss_rate;
      c_data->reported_ts        = now;

      Create_Link(leg, UDP_LINK);
      Create_Link(leg, RELIABLE_UDP_LINK);
      Create_Link(leg, REALTIME_UDP_LINK);

      if (Config_File_Found == 1) {
        stdhash_find(&Node_Lookup_Addr_to_ID, &it, &(leg->remote_interf->net_addr));
        if (!stdhash_is_end(&Node_Lookup_Addr_to_ID,  &it)) {
            ngbr_id = *(int16u *)stdhash_it_val(&it);

            if (Directed_Edges == 0 && My_ID > ngbr_id) {
                key.src_id = ngbr_id;
                key.dst_id = My_ID;
            }
            else {
                key.src_id = My_ID;
                key.dst_id = ngbr_id;
            }

            stdskl_find(&Sorted_Edges, &it, &key);
            if (!stdskl_is_end(&Sorted_Edges, &it))
                Create_Link(leg, INTRUSION_TOL_LINK);
        }
      }

      lk->r_data->flags                            = CONNECTED_LINK;
      leg->links[RELIABLE_UDP_LINK]->r_data->flags = CONNECTED_LINK;

      /* TODO: do we quickly want to send an extra hello and synchronize our hello sending w/ the other side? */

      E_queue(Send_Hello,  leg->links[CONTROL_LINK]->link_id,      NULL, zero_timeout);  
      E_queue(Try_to_Send, leg->links[CONTROL_LINK]->link_id,      NULL, zero_timeout);
      E_queue(Try_to_Send, leg->links[RELIABLE_UDP_LINK]->link_id, NULL, zero_timeout);	
    }

  } else {
    Alarm(EXIT, "Bad leg status %d!\r\n", leg->status);
  }
}

/***********************************************************/
/* Processes receiving a hello type packet.                */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* pack_hdr: packet header                                 */
/* from_addr: net addr of sender                           */
/* local_interf: local interface on which msg recvd        */
/* remote_interf: remote interface from which msg came     */
/* leg: leg on which msg recvd                             */
/* link link on which msg recvd                            */
/*                                                         */
/***********************************************************/

void Process_hello_ping(packet_header *pack_hdr, Network_Address from_addr, 
			Interface *local_interf, Interface **remote_interf, Network_Leg **leg, Link **link)
{
  Node *remote_node;

  if ((remote_node = Get_Node(pack_hdr->sender_id)) == NULL) {
    remote_node = Create_Node(pack_hdr->sender_id);
  }

  if (*remote_interf == NULL) {
    *remote_interf = Create_Interface(pack_hdr->sender_id, from_addr, from_addr);  /* TODO: put send side interface_id in packet? */
  }

  if (*leg == NULL) {
    *leg = Create_Network_Leg(local_interf->iid, (*remote_interf)->iid);
  }

  if (*link == NULL) {

    sp_time now       = E_get_time();
    double  nowf      = now.sec + now.usec / 1000000.0;
    double  last_conn = (*leg)->last_connected.sec + (*leg)->last_connected.usec / 1000000.0;

    if (stable_delay_flag && nowf - last_conn < stable_timeout) {
      Alarm(PRINT, "Process_hello_ping: stable delay disallowing ctrl link creation to ("IPF")! Stable delay is %.03f; diff is %.03f; now is %.03f, last_conn is %.03f\n", 
	    IP((*leg)->remote_interf->net_addr), stable_timeout, nowf - last_conn, nowf, last_conn);
      return;
    }
  
    Alarm(DEBUG, "Process_hello_packet from "IPF"\n", IP((*leg)->remote_interf->net_addr));

#ifdef SPINES_WIRELESS
    if (Wireless_monitor && (*leg)->w_data.rssi < Wireless_ts) {  /* signal not strong enough */
      return;
    }
#endif
 
    *link = Links[Create_Link(*leg, CONTROL_LINK)];
    (*leg)->last_recv_hello = E_get_time();

  } else {
    Alarm(DEBUG, "Process_hello_ping: already have a ctrl link for sender ("IPF").\n", IP((*leg)->remote_interf->net_addr));
  }
}
