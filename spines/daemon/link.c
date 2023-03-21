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

#include <string.h>
#include <assert.h>

#ifdef ARCH_PC_WIN95
#  include <winsock2.h>
#endif

#include "arch.h"
#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_memory.h"
#include "spu_data_link.h"
#include "stdutil/stdhash.h"

#include "objects.h"
#include "node.h"
#include "link.h"
#include "protocol.h"
#include "network.h"
#include "reliable_datagram.h"
#include "link_state.h"
#include "hello.h"
#include "route.h"
#include "udp.h"
#include "realtime_udp.h"
#include "intrusion_tol_udp.h"
#include "session.h"
#include "state_flood.h"
#include "link_state.h"

#include "spines.h"

extern char Config_File_Found;

/* SUICIDE VARIABLES */
/* static int Suicide_Count = 0;
static sp_time Suicide_Timer = {0, 0}; */
static sp_time zero_timeout = {0, 0};

/***********************************************************/
/* Creates a link between the current node and some        */
/* neighbor                                                */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* leg: the leg across which this link should run          */
/* mode: mode of the link (CONTROL, UDP, etc.)             */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int16) the ID of the link in the global Link array     */
/*                                                         */
/***********************************************************/

int16 Create_Link(Network_Leg *leg,
		  int16        mode) 
{
  Edge           *edge;
  Node           *nd;
  int16           linkid;
  Link           *lk;
  Reliable_Data  *r_data;
  Control_Data   *c_data;
  Realtime_Data  *rt_data;
  Int_Tol_Data   *it_data;
  sp_time         now;
  int             i;
  double          rolling_decay = 1;

  /* validation */

  if (leg->local_interf->owner != This_Node) {
    Alarm(EXIT, "Create_Link: This_Node isn't owner of local interface?!\r\n");
  }

  edge = leg->edge;
  nd   = leg->remote_interf->owner;

  if (leg->links[mode] != NULL) {
    switch(mode) {
        case INTRUSION_TOL_LINK:
            Alarm(DEBUG, "Create_Link: Int_Tol_Link already exists\r\n");
            return leg->links[mode]->link_id;
            break;
        case CONTROL_LINK: 
        case RELIABLE_UDP_LINK:
        case REALTIME_UDP_LINK:
        default:
            Alarm(EXIT, "Create_Link: This type of link already exists on this leg?!\r\n");
    }
  }

  /* ISOLATING FROM HELLO:
   *    Don't check this condition if we are in intrusion tolerance mode */
  if (Conf_IT_Link.Intrusion_Tolerance_Mode == 0 && 
        mode != CONTROL_LINK && (leg->links[CONTROL_LINK] == NULL || leg->status != CONNECTED_LEG || leg->cost == -1)) {
    Alarm(EXIT, "Create_Link: Creating a non-control link on a leg before connected?!\r\n");
  }

  /* Only create INTRUSION_TOL_LINK if a configuration file exists */
  if (mode == INTRUSION_TOL_LINK && Config_File_Found == 0) {
    Alarm(PRINT, "Create_Link: Cannot create INTRUSION_TOL_LINK without configuration file\r\n");
    return 0;
  }

  /* Find an empty spot in the Links array */

  for (linkid = 0; linkid < MAX_LINKS && Links[linkid] != NULL; ++linkid);

  if (linkid == MAX_LINKS) {
    Alarm(EXIT, "Create_Link() No link IDs available; too many open links\r\n");
  }

  /* Create and initialize the link structure */

  if ((lk = (Link*) new(DIRECT_LINK)) == NULL) {
    Alarm(EXIT, "Create_Link: Cannot allocate link object\r\n");
  }

  memset(lk, 0, sizeof(*lk));

  Links[linkid]    = lk;
  leg->links[mode] = lk;

  lk->link_id      = linkid;
  lk->link_type    = mode;
  lk->r_data       = NULL;
  lk->prot_data    = NULL;
  lk->leg          = leg;

  /* Create the reliable_data structure */

  if (mode == CONTROL_LINK || mode == RELIABLE_UDP_LINK) {  

    if ((r_data = (Reliable_Data*) new(RELIABLE_DATA)) == NULL) {
      Alarm(EXIT, "Create_Link: Cannot allocate reliable_data object\r\n");
    }

    memset(r_data, 0, sizeof(*r_data));

    r_data->flags = UNAVAILABLE_LINK;
    r_data->seq_no = 0;
    stdcarr_construct(&r_data->msg_buff, sizeof(Buffer_Cell*), 0);

    for (i = 0; i < MAX_WINDOW; ++i) {
      r_data->window[i].buff      = NULL;
      r_data->window[i].data_len  = 0;
      r_data->recv_window[i].flag = EMPTY_CELL;
    }

    r_data->head = 0;
    r_data->tail = 0;
    r_data->recv_head = 0;
    r_data->recv_tail = 0;
    r_data->nack_buff = NULL;
    r_data->nack_len = 0;
    r_data->scheduled_ack = 0;
    r_data->scheduled_timeout = 0;
    r_data->timeout_multiply = 1;
    r_data->rtt = 0;
    r_data->congestion_flag = 0;
    r_data->connect_state = AVAILABLE_LINK;
    r_data->cong_flag = 1;
    r_data->last_tail_resent = 0;
    r_data->padded = 1;

    /* Congestion control */
    if (TCP_Fairness) {
        r_data->window_size = (float)Minimum_Window; 
    } else {
        r_data->window_size = MAX_CG_WINDOW;
    }
    r_data->max_window = MAX_CG_WINDOW;
    r_data->ssthresh = MAX_CG_WINDOW;
      
    lk->r_data = r_data;
  }

  /* Create the control_data structure */

  if (mode == CONTROL_LINK) {

    /* update leg status */

    assert(leg->status == DISCONNECTED_LEG && leg->cost == -1);

    leg->status              = NOT_YET_CONNECTED_LEG;
    leg->cost                = -1;

    while ((leg->ctrl_link_id = rand()) == 0);  /* NOTE: 0 is a reserved ctrl link id indicating that no ctrl link has yet been created */
    leg->other_side_ctrl_link_id = 0;

    leg->hellos_out          = 0;
    leg->connect_cnter       = 0;

    if ((c_data = (Control_Data*) new(CONTROL_DATA)) == NULL) {
      Alarm(EXIT, "Create_Link: Cannot allocate ctrl_data object\r\n");
    }

    memset(c_data, 0, sizeof(*c_data));

    c_data->hello_seq            = 0;
    c_data->other_side_hello_seq = 0;
    c_data->diff_time            = 0;
    c_data->rtt                  = 1000;     /* NOTE: we initially assume a new link has bad characteristics for routing purposes */
    c_data->est_loss_rate        = UNKNOWN;
    c_data->est_tcp_rate         = UNKNOWN;
    c_data->reported_rtt         = UNKNOWN;
    c_data->reported_loss_rate   = UNKNOWN;
    c_data->reported_ts.sec = 0;
    c_data->reported_ts.usec = 0;

    /* For determining loss_rate */
    c_data->l_data.my_seq_no = PACK_MAX_SEQ;
    c_data->l_data.other_side_tail = 0;
    c_data->l_data.other_side_head = 0;
    c_data->l_data.received_packets = 0;
    for (i = 0; i < MAX_LINKS_4_EDGE; i++)
    {
        c_data->l_data.recvd_seqs[i] = 0;
        c_data->l_data.my_seqs[i] = PACK_MAX_SEQ;
    }

    for(i=0; i<MAX_REORDER; i++) {
      c_data->l_data.recv_flags[i] = 0;
    }

    for(i=0; i<LOSS_HISTORY; i++) {
      c_data->l_data.loss_interval[i].received_packets = 0;
      c_data->l_data.loss_interval[i].lost_packets = 0;
    }

    c_data->l_data.loss_event_idx = 0;	
    c_data->l_data.loss_rate = 0;

    lk->prot_data = c_data;

    /* ensure this guy is in Neighbor_Nodes */

    if (nd->neighbor_id == -1) {

      for (nd->neighbor_id = 0; nd->neighbor_id != MAX_LINKS / MAX_LINKS_4_EDGE && Neighbor_Nodes[nd->neighbor_id] != NULL; ++nd->neighbor_id);

      if (nd->neighbor_id == MAX_LINKS / MAX_LINKS_4_EDGE) {
	Alarm(EXIT, "Create_Link: Too many neighbors!\r\n");
      }

      if (nd->neighbor_id + 1 > Num_Neighbors) {
	Num_Neighbors = nd->neighbor_id + 1;
      }

      Neighbor_Nodes[nd->neighbor_id] = nd;
    }

    /* set up hello's on this link at a random offset to avoid synchronizing all hello's */
    {
      sp_time rand_hello_TO;

      rand_hello_TO.sec  = 0;
      rand_hello_TO.usec = (long) ((1.0e6 * hello_timeout.sec + hello_timeout.usec) * (rand() / (RAND_MAX + 1.0)) + 0.5);

      if (rand_hello_TO.usec > 1000000L) {
	rand_hello_TO.sec  = rand_hello_TO.usec / 1000000L;
	rand_hello_TO.usec = rand_hello_TO.sec  % 1000000L;
      }

      E_queue(Send_Hello, lk->link_id, NULL, rand_hello_TO);
    }
  }

  /* Create the realtime_udp_data structure */

  if (mode == REALTIME_UDP_LINK) {

    if ((rt_data = (Realtime_Data*) new(REALTIME_DATA)) == NULL) {
      Alarm(EXIT, "Create_Link: Cannot allocte realtime_udp_data object\n");
    }

    memset(rt_data, 0, sizeof(*rt_data));

    rt_data->head = 0;
    rt_data->tail = 0;
    rt_data->recv_head = 0;
    rt_data->recv_tail = 0;
      
    for (i = 0; i < MAX_HISTORY; ++i) {
      rt_data->recv_window[i].flags = EMPTY_CELL;
    }
      
    rt_data->num_nacks = 0;
    rt_data->retransm_buff = NULL;
    rt_data->num_retransm = 0;
      
    rt_data->bucket = 0;
      
    lk->prot_data = rt_data;
  }

  /* Create the intrusion_tol_udp_data structure */
  /* NOTE: This gets created once (first time) and never gets destroyed */
  if (mode == INTRUSION_TOL_LINK) {
        if ((it_data = (Int_Tol_Data*) new(INTRUSION_TOL_DATA)) == NULL) {
            Alarm(EXIT, "Create_Link: Cannot allocate int_tol_udp_data object\n");
        }
        
        memset(it_data, 0, sizeof(*it_data));

        it_data->out_head_seq     = LINK_START_SEQ;
        it_data->out_tail_seq     = LINK_START_SEQ;
        it_data->in_head_seq      = LINK_START_SEQ;
        it_data->in_tail_seq      = LINK_START_SEQ;
        it_data->aru_nonce_digest = 0;

        it_data->out_message = NULL;
        it_data->out_frag_idx = 0;
        it_data->out_frag_total = 0;

        /* we create an empty sys_scatter to receive messages */
        if ( (it_data->in_message = (sys_scatter*) new_ref_cnt (SYS_SCATTER)) == NULL)
            Alarm(EXIT, "Create_Link: Cannot allocate sys_scatter object\r\n");
        it_data->in_message->num_elements = 0;
        it_data->in_frag_idx = 1;
        it_data->in_frag_total = 0;

        /* should be figured out w/ config file? loading? reading
         * from some global state? */
        it_data->incoming_msg_count = Conf_IT_Link.Msg_Per_SAA - 1; 
        
        for (i = 0; i < MAX_SEND_ON_LINK; i++) {
            it_data->outgoing[i].pkt = NULL;
            it_data->outgoing[i].resent = 0;
            it_data->outgoing[i].nacked = 0;
            it_data->out_nonce[i] = 0;
            it_data->out_nonce_digest[i] = 0;
            it_data->incoming[i].flags = EMPTY_CELL;
            it_data->incoming[i].pkt = NULL; 
            it_data->incoming[i].pkt_len = 0;
            it_data->in_nonce[i] = 0;
        }

        now = E_get_time();
        it_data->my_incarnation         = now.sec;
        it_data->ngbr_incarnation       = 0;
        it_data->incarnation_response   = E_sub_time(now,it_incarnation_timeout);

        it_data->tcp_head_seq      = LINK_START_SEQ;
        it_data->ssthresh          = MAX_SEND_ON_LINK;
        if (Conf_IT_Link.TCP_Fairness == 1)
            it_data->cwnd          = (float)Minimum_Window;
        else
            it_data->cwnd          = MAX_SEND_ON_LINK;
        it_data->loss_detected     = 0;
        it_data->loss_detected_aru = 0;

        it_data->rtt                      = Conf_IT_Link.Default_RTT;
        it_data->next_ping_seq            = 1;
        it_data->last_pong_seq_recv       = 0;

        it_data->pong_freq.sec = 0;
        it_data->pong_freq.usec = 0;
        
        it_data->it_reliable_timeout.sec  = Conf_IT_Link.Reliable_Timeout_Factor *
                                            Conf_IT_Link.Default_RTT / 1000;
        it_data->it_reliable_timeout.usec = (Conf_IT_Link.Reliable_Timeout_Factor *
                                            Conf_IT_Link.Default_RTT * 1000) % 1000000;
        
        it_data->it_nack_timeout.sec      = Conf_IT_Link.NACK_Timeout_Factor *
                                            Conf_IT_Link.Default_RTT / 1000;
        it_data->it_nack_timeout.usec     = (Conf_IT_Link.NACK_Timeout_Factor *
                                             Conf_IT_Link.Default_RTT * 1000) % 1000000;
        
        it_data->it_initial_nack_timeout.sec = Conf_IT_Link.Init_NACK_Timeout_Factor *
                                                Conf_IT_Link.Default_RTT / 1000;
        it_data->it_initial_nack_timeout.usec = ((int)(Conf_IT_Link.Init_NACK_Timeout_Factor *
                                                Conf_IT_Link.Default_RTT * 1000)) % 1000000;


        /* Setup the link loss calculation variables */
        it_data->link_status = LINK_DEAD;
        for (i = 0; i <= HISTORY_SIZE; i++) {
            it_data->loss_history_retransmissions[i] = 0;
            it_data->loss_history_unique_packets[i] = 0;
        }
        /* We calculate the specific decay value for each bucket */
        for (i = 1; i <= HISTORY_SIZE; i++) {
            rolling_decay *= Conf_IT_Link.Loss_Calc_Decay;
            it_data->loss_history_decay[i] = rolling_decay;
        }
        
        for (i = 0; i < MAX_PING_HIST; i++) {
            it_data->ping_history[i].ping_seq       = 0;
            it_data->ping_history[i].ping_nonce     = 0;
            it_data->ping_history[i].ping_sent.sec  = 0;
            it_data->ping_history[i].ping_sent.usec = 0;
            it_data->ping_history[i].answered       = 1;
        }

        it_data->last_filled = E_get_time();
        it_data->bucket = 0;
        it_data->needed_tokens = 0;

        E_queue(Fill_Bucket_IT, lk->link_id, 0, it_bucket_to);

        it_data->dh_key = (unsigned char*) Mem_alloc(DH_Key_Len);
        it_data->dh_local = NULL;
        it_data->dh_established = 0;
        it_data->dh_key_computed = 0;
        
        it_data->dh_pkt.num_elements = 2;
        it_data->dh_pkt.elements[0].buf = NULL;
        it_data->dh_pkt.elements[0].len = 0;
        it_data->dh_pkt.elements[1].buf = NULL;
        it_data->dh_pkt.elements[1].len = 0;
        
        /* it_data->dh_pkt.frag = NULL;
        it_data->dh_pkt.resent = 0;
        it_data->dh_pkt.nacked = 0; */

        /* If crypto is on, pings will be queued once a DH key can be computed */
        if (Conf_IT_Link.Crypto == 0) { 
            E_queue(Ping_IT_Timeout, (int)lk->link_id, NULL, zero_timeout );
            E_queue(Loss_Calculation_Event, (int)lk->link_id, NULL, loss_calc_timeout);
        }
        else { /* (Conf_IT_Link.Crypto == 1) { */
            /* TODO: IT_Link is never destroyed in normal operation, so these
             * CTX structures don't cause a leak today, but would be nice to
             * add cleanup code (e.g. to make memory leak detection easier) */
            it_data->dh_local = PEM_read_DHparams(fopen("keys/dhparam.pem", "r"), NULL, NULL, NULL);
            it_data->encrypt_ctx = EVP_CIPHER_CTX_new();
            if(it_data->encrypt_ctx == NULL){
                Alarm(EXIT, "EVP_CIPHER_CTX_new returned NULL trying to init encrypt_ctx\n");
            }
            it_data->decrypt_ctx = EVP_CIPHER_CTX_new();
            if(it_data->decrypt_ctx == NULL){
                Alarm(EXIT, "EVP_CIPHER_CTX_new returned NULL trying to init decrypt_ctx\n");
            }
            it_data->hmac_ctx = HMAC_CTX_new();
            if(it_data->hmac_ctx == NULL){
                Alarm(EXIT, "HMAC_CTX_new returned NULL trying to init hmac_ctx\n");
            }
        }

        it_data->dissem_head.dissemination = (RESERVED_ROUTING_BITS >> ROUTING_BITS_SHIFT);
        it_data->dissem_head.callback = NULL;
        it_data->dissem_head.next = NULL;
        it_data->dissem_tail = &it_data->dissem_head;

        for (i = 0; i < (RESERVED_ROUTING_BITS >> ROUTING_BITS_SHIFT); i++)
            it_data->in_dissem_queue[i] = 0;

        /* TODO: THIS SHOULD GO AWAY WITH LEAKY BUCKET */
        Burst_Count = 0;
        Burst_Timeout = now;
        /* end TODO */

        lk->prot_data = it_data;

        if (Conf_IT_Link.Crypto == 1)
            Key_Exchange_IT((int)lk->link_id, NULL);
  }

  {
    const char * str;

    switch (mode) {

    case CONTROL_LINK:
      str = "Control";
      break;

    case UDP_LINK:
      str = "UDP";
      break;

    case RELIABLE_UDP_LINK:
      str = "Reliable";
      break;

    case REALTIME_UDP_LINK:
      str = "RealTime";
      break;

    case INTRUSION_TOL_LINK:
      str = "Intrusion Tolerant";
      break;

    default:
      str = "Unknown";
      break;
    }

    Alarm(DEBUG, "Create_Link: edge = (" IPF " -> " IPF "); leg = (" IPF " -> " IPF "); linkid = %d; type = %s\r\n",
	  IP(edge->src_id), IP(edge->dst_id), IP(leg->local_interf->iid), IP(leg->remote_interf->iid), 
	  (int) linkid, str);
  }

  return linkid;
}

/***********************************************************/
/* void Destroy_Link(int16 linkid)                         */
/*                                                         */
/* Destroys a link between the current node and some       */
/* neighbor                                                */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* linkid: the ID of the link in the global Link array     */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Destroy_Link(int16 linkid)
{
    Link *lk;
    Network_Leg *leg;
    Edge *edge;
    int32u i;
    Control_Data  *c_data;
    Reliable_Data *r_data;
    Realtime_Data *rt_data;
    stdit it;
    Buffer_Cell *buf_cell;
    char* msg;

    if ((lk = Links[linkid]) == NULL) {
      Alarm(EXIT, "Destroy_Link: no link %hd!\r\n", linkid);
    }

    switch (lk->link_type) {
       case INTRUSION_TOL_LINK:
            Alarm(DEBUG, "Create_Link: Int_Tol_Link will not be destroyed\r\n");
            return;
            break;
        case CONTROL_LINK: 
        case RELIABLE_UDP_LINK:
        case REALTIME_UDP_LINK:
        default:
            Alarm(DEBUG, "Destroying regular link...%d\r\n", lk->link_type);
            break;
    }

    leg  = lk->leg;
    edge = leg->edge;
    
    /* Take care about the reliability stuff */
    if(lk->r_data != NULL) {
	r_data = lk->r_data;

	/* Remove data from the window */
	for(i=r_data->tail; i<=r_data->head; i++) {
	    if(r_data->window[i%MAX_WINDOW].buff != NULL) {
		dec_ref_cnt(r_data->window[i%MAX_WINDOW].buff);
	    }
	    r_data->window[i%MAX_WINDOW].buff = NULL;
	}

	for(i=r_data->recv_tail; i<=r_data->recv_head; i++) {
	    if(r_data->recv_window[i%MAX_WINDOW].data.buff != NULL) {
		dec_ref_cnt(r_data->recv_window[i%MAX_WINDOW].data.buff);
		r_data->recv_window[i%MAX_WINDOW].data.buff = NULL;
	    }
	}
	
	/* Remove data from the queue */
	while(!stdcarr_empty(&(r_data->msg_buff))) {
	    stdcarr_begin(&(r_data->msg_buff), &it);
	    
	    buf_cell = *((Buffer_Cell **)stdcarr_it_val(&it));
	    msg = buf_cell->buff;
	    dec_ref_cnt(msg);
	    dispose(buf_cell);
	    stdcarr_pop_front(&(r_data->msg_buff));
	}
	stdcarr_destruct(&(r_data->msg_buff));

	if(r_data->nack_buff != NULL) {
	    E_dequeue(Send_Nack_Retransm, (int)linkid, NULL);
	    dispose(r_data->nack_buff);
	    r_data->nack_len = 0;
	}

	if(r_data->scheduled_timeout == 1) {
	    E_dequeue(Reliable_timeout, (int)linkid, NULL);
	}
	r_data->scheduled_timeout = 0;

	if(r_data->scheduled_ack == 1) {
	    E_dequeue(Send_Ack, (int)linkid, NULL);
	}
	r_data->scheduled_ack = 0;

	E_dequeue(Try_to_Send, (int)linkid, NULL);

	if (lk->link_type == CONTROL_LINK) {
	    E_dequeue(Send_Hello, (int)linkid, NULL);
	    E_dequeue(Send_Hello_Request, (int)linkid, NULL);
	    E_dequeue(Send_Hello_Request_Cnt, (int) linkid, NULL);
	    E_dequeue(Net_Send_State_All, (int)linkid, &Edge_Prot_Def);
	    E_dequeue(Net_Send_State_All, (int)linkid, &Groups_Prot_Def);
	}
	dispose(r_data);

	if(Link_Sessions_Blocked_On == linkid) {
            Alarm(DEBUG, "Resuming sessions\n");
	    Resume_All_Sessions();
	    Link_Sessions_Blocked_On = -1;
	}
    }

    /* Protocol data */

    if(lk->prot_data != NULL) {
        if(lk->link_type == CONTROL_LINK) {
	    c_data = (Control_Data*)lk->prot_data;
	    dispose(c_data);
	}
        else if(lk->link_type == REALTIME_UDP_LINK) {
	    rt_data = (Realtime_Data*)lk->prot_data;
	    for(i=rt_data->tail; i<rt_data->head; i++) {
		if(rt_data->window[i%MAX_HISTORY].buff != NULL) {
		    dec_ref_cnt(rt_data->window[i%MAX_HISTORY].buff);
		    rt_data->window[i%MAX_HISTORY].buff = NULL;
		}
	    }	
	    E_dequeue(Send_RT_Nack, (int)linkid, NULL);
	    E_dequeue(Send_RT_Retransm, (int)linkid, NULL);

	    if(rt_data->retransm_buff != NULL) {
		dec_ref_cnt(rt_data->retransm_buff);
		rt_data->retransm_buff = NULL;
	    }

	    dispose(rt_data);
	    Alarm(DEBUG, "Destroyed Realtime UDP link\n");
	}
    }

    lk->leg->links[lk->link_type] = NULL;
    Links[linkid] = NULL;

  {
    const char * str;

    switch (lk->link_type) {

    case CONTROL_LINK:
      str = "Control";
      break;

    case UDP_LINK:
      str = "UDP";
      break;

    case RELIABLE_UDP_LINK:
      str = "Reliable";
      break;

    case REALTIME_UDP_LINK:
      str = "RealTime";
      break;

    default:
      str = "Unknown";
      break;
    }

    Alarm(DEBUG, "Destroy_Link: edge = (" IPF " -> " IPF "); leg = (" IPF " -> " IPF "); linkid = %d; type = %s\r\n",
	  IP(edge->src_id), IP(edge->dst_id), IP(leg->local_interf->iid), IP(leg->remote_interf->iid), 
	  (int) linkid, str);
  }

    dispose(lk);
}

Link *Get_Best_Link(Node_ID node_id, int mode)
{
  Link *link = NULL;
  Edge *edge;

  if ((edge = Get_Edge(My_Address, node_id)) != NULL &&
    (edge->cost != -1 || mode == INTRUSION_TOL_LINK))
  {
  /*if ((edge = Get_Edge(My_Address, node_id)) != NULL && edge->cost != -1) {*/
    link = edge->leg->links[mode];
  }

  return link;
}

int Link_Send(Link *lk, sys_scatter *scat)
{
  Network_Leg *leg;
  Leg_Buf_Cell cell;
  int total_bytes;
  int ret = 0;
  int i;
  /* sp_time diff;
  sp_time delta = {1,0}; */

  /* AB: added for cost accounting */
  packet_header *hdr;
  udp_header *uhdr;
  Client_ID cid;
  int32 cost_count, *cost_count_ptr;
  stdit it;

  /* ret = DL_send(lk->leg->local_interf->channels[lk->link_type], 
		 lk->leg->remote_interf->net_addr,
		 Port + lk->link_type,
		 scat); */

  leg = lk->leg;

  /* Calculate size of this packet */
  for (i = 0, total_bytes = 0; i < scat->num_elements; i++)
  {
    total_bytes += scat->elements[i].len;
  }

  /* If we don't have space to buffer this packet, drop it */
  if (Leg_Rate_Limit_kbps >= 0 && stdcarr_size(&leg->bucket_buf) >= Leg_Max_Buffered) {
    return ret;
  }

  /* AB: added for cost accounting */
  if (Print_Cost) {
    hdr = (packet_header *)scat->elements[0].buf;
    if (Is_data_type(hdr->type)) {
      /* Update packet counts for this flow for cost accounting */
      assert(scat->num_elements > 1);
      assert(scat->elements[1].len >= sizeof(udp_header));
      uhdr = (udp_header *)scat->elements[1].buf;
      cid.daemon_id = uhdr->dest;
      cid.client_port = uhdr->dest_port;
      stdskl_find(&Client_Cost_Stats, &it, &cid);
      if (stdskl_is_end(&Client_Cost_Stats, &it)) {
          Alarm(DEBUG, "ADDING NEW FLOW! cid.daemon_id %x, cid.client_port %u\n", cid.daemon_id, cid.client_port);
          cost_count = 1;
          if (stdskl_insert(&Client_Cost_Stats, &it, &cid, &cost_count, TRUE) != 0) {
              Alarm(EXIT, "Failed to insert into Client_Cost_Stats\n");
          }
      } else {
          cost_count_ptr = (int32 *)stdskl_it_val(&it);
          *cost_count_ptr += 1;
      }
    }
  }

  /* If no packets are currently waiting and we have the available bandwidth
   * (subject to rate limiting), just go ahead and send now */
  if (Leg_Rate_Limit_kbps < 0 || 
     (stdcarr_empty(&leg->bucket_buf) && total_bytes <= leg->bucket_bytes))
  {
    Alarm(DEBUG, "Link_Send: sending %d bytes directly, %d bytes available\n", total_bytes, leg->bucket_bytes);
    ret = DL_send(lk->leg->local_interf->channels[lk->link_type], 
           lk->leg->remote_interf->net_addr,
           Port + lk->link_type,
           scat);
    leg->bucket_bytes -= total_bytes;
    return ret;
  }

  /* Otherwise, we add this packet to the end of the queue of waiting packets
   * and then try to send from the front of the queue if possible */
  Alarm(DEBUG, "Link_Send: buffering packet, total_bytes = %d, available bytes = %d\n", total_bytes, leg->bucket_bytes);
  cell.link_type = lk->link_type;
  cell.scat.num_elements = scat->num_elements;
  cell.total_bytes = total_bytes;
  for (i = 0; i < scat->num_elements; i++)
  {
    cell.scat.elements[i].len = scat->elements[i].len;
    cell.scat.elements[i].buf = new_ref_cnt(PACK_OBJ);
    if (cell.scat.elements[i].buf == NULL) {
        Alarm(EXIT, "Link_Send: failed to allocate buffer\n");
    }
    if (scat->elements[i].len > MAX_PACKET_SIZE) {
        Alarm(EXIT, "Link_Send: invalid buffer size. For element %d, len is %d, "
                    "should be <= %d\n", i, scat->elements[i].len,
                    MAX_PACKET_SIZE);
    }
    memcpy(cell.scat.elements[i].buf, scat->elements[i].buf, scat->elements[i].len);
  }
  stdcarr_push_back(&leg->bucket_buf, &cell);

  Leg_Try_Send_Buffered(leg);

  /* Suicide_Count += ret; */
  /* if (Suicide_Count > 16000000) {
    diff = E_sub_time(E_get_time(),Suicide_Timer); */
    /* printf("\tSuicide_Count = %d, Suicide_Timer = %ld.%.6ld, Diff = %ld.%.6ld\n", Suicide_Count, 
                    Suicide_Timer.sec, Suicide_Timer.usec, diff.sec, diff.usec); */
   /* if (E_compare_time(delta, diff) > 0) {
        Alarm(EXIT, "Link_Send: Suicide Conditions Met\r\n"); 
    }
    Suicide_Count = 0;
    Suicide_Timer = E_get_time();
  }*/

  return ret;
}

int Leg_Try_Send_Buffered(Network_Leg *leg)
{
  Leg_Buf_Cell *cell;
  stdit it;
  int ret = 0;
  int i;

  while (!stdcarr_empty(&leg->bucket_buf))
  {
    stdcarr_begin(&leg->bucket_buf, &it);
    cell = (Leg_Buf_Cell *)stdcarr_it_val(&it);

    /* If we can't send the next packet, stop */
    if (cell->total_bytes > leg->bucket_bytes)
        break;

    Alarm(DEBUG, "Leg_Try_Send_Buffered: sending %d bytes from buffer, %d bytes available\n", cell->total_bytes, leg->bucket_bytes);
    ret = DL_send(leg->local_interf->channels[cell->link_type], 
           leg->remote_interf->net_addr,
           Port + cell->link_type,
           &cell->scat);
    leg->bucket_bytes -= cell->total_bytes;

    for (i = 0; i < cell->scat.num_elements; i++)
    {
        dec_ref_cnt(cell->scat.elements[i].buf);
    }

    stdcarr_pop_front(&leg->bucket_buf);
  }

  return ret;

}

/***********************************************************/
/* int32 Relative_Position(int32 base, int32 seq)          */
/*                                                         */
/* Computes the relative position between two sequence     */
/* numbers in a circular array.                            */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* base: base sequence number                              */
/* seq_no: sequence number of offset                       */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int32) offset                                          */
/*                                                         */
/***********************************************************/

int32 Relative_Position(int32 base, int32 seq) {
    if(seq >= base) {
	if(seq - base < PACK_MAX_SEQ/2) {
            return(seq - base);
	}
	else {
            /* this is an old packet */
            return(seq - base - PACK_MAX_SEQ);
	}
    }
    else {
	if(base - seq > PACK_MAX_SEQ/2) {
            return(seq + PACK_MAX_SEQ - base);
	}
	else {
            /* this is an old packet */
            return(seq - base);
	}
    }
}

/***********************************************************/
/* Checks the link loss probability on link                */
/* between two neighbours                                  */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* sender: IP of the neighbour                             */
/* seq_no: sequence number of the packet received          */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Check_Link_Loss(Network_Leg *leg, int16u seq_no, int link_type) 
{
  Loss_Data *l_data;
  int16u     i;
  int16     *seq_ptr;

  /* DT: bug due to race condition? Possibily caused by hello protocol
   *    not finishing in time when IT_Mode is off */
  if (leg->links[CONTROL_LINK] == NULL) {
    Alarm(PRINT, "Check_Link_Loss: control link == NULL...returning\n");
    return;
  }

  l_data = &((Control_Data*) leg->links[CONTROL_LINK]->prot_data)->l_data;

  if (seq_no == 0xffff) {  /* special sequence # used by hello pings (hello sent on dead legs) */
    return;              /* ignore */
  }

  /* Ignore intrusion tolerant link since it sets everything to 0 (IT link does
   * its own monitoring of loss anyway) */
  if (link_type == INTRUSION_TOL_LINK) {
    return;
  }

  /* Get the last sequence number received for this link type */
  seq_ptr = &l_data->recvd_seqs[link_type];
  Alarm(DEBUG, "Recvd Seq no %d, head %d, type %d\n", seq_no, *seq_ptr, link_type);

  /* Flag for reset connection: just go ahead and accept whatever sequence
   * number they give me  */
  if (*seq_ptr == PACK_MAX_SEQ + 1) {
    Alarm(PRINT, "Reset connection, seq was: %d, now %d, type %d\n", *seq_ptr, seq_no, link_type);
    *seq_ptr = seq_no;
    return;
  }

  if ((seq_no <= *seq_ptr && *seq_ptr - seq_no < PACK_MAX_SEQ - *seq_ptr + seq_no) ||
      (seq_no > *seq_ptr && PACK_MAX_SEQ - seq_no + *seq_ptr < seq_no - *seq_ptr)) {
    /* reordered or duplicate packet: we potentially already counted this
     * packet as lost, may want to consider reducing the loss rate */
    Alarm(PRINT, "Reordered packet: seq_no %d, head %d, type %d\n", seq_no, *seq_ptr, link_type);
    return;
  } 

  for (i = (*seq_ptr + 1) % PACK_MAX_SEQ; i != seq_no; i = (i+1) % PACK_MAX_SEQ) {
    Alarm(DEBUG, "GAP: %d\n", i);
    l_data->loss_rate = (l_data->loss_rate * LOSS_DECAY_FACTOR) + (1.0 - LOSS_DECAY_FACTOR);
  }
  l_data->loss_rate = (l_data->loss_rate * LOSS_DECAY_FACTOR);
  Alarm(DEBUG, "Reset loss rate: %lf\n", l_data->loss_rate);

  *seq_ptr = seq_no;
}

/***********************************************************/
/* Computes the average loss rate from a neighbor          */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* nd: The neighbor node                                   */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int32) average loss rate multiplied by LOSS_RATE_SCALE */
/*                                                         */
/***********************************************************/

int32 Compute_Loss_Rate(Network_Leg *leg) 
{
  Loss_Data *l_data;

  assert(leg->links[CONTROL_LINK] != NULL);

  l_data = &((Control_Data*) leg->links[CONTROL_LINK]->prot_data)->l_data;

  return (int32) (LOSS_RATE_SCALE * l_data->loss_rate);
}

/***********************************************************/
/* Sets the sequence number of a packet                    */
/*             (for detecting loss rate)                   */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* nd: The neighbor node                                   */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int16) Sequence number                                 */
/*                                                         */
/***********************************************************/

int16u Set_Loss_SeqNo(Network_Leg *leg, int link_type) 
{
  Loss_Data *l_data;
  int16 *seq_ptr;

  assert(leg->links[CONTROL_LINK] != NULL);

  l_data = &((Control_Data*) leg->links[CONTROL_LINK]->prot_data)->l_data;

  seq_ptr = &l_data->my_seqs[link_type];

  *seq_ptr = *seq_ptr + 1;
  if (*seq_ptr >= PACK_MAX_SEQ) {
    *seq_ptr = 0;
  }

  Alarm(DEBUG, "Seq no %d, type %d\n", *seq_ptr, link_type);
  return *seq_ptr;
}

/***********************************************************/
/* void Fill_Leg_Bucket(int dummy, void* input_leg)        */
/*                                                         */
/* Method that refills the bucket for this leg             */
/*  at the specified rate and up to the specified          */
/*  capacity                                               */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* dummy:      not used                                    */
/* input_leg:  network leg                                 */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/
void Fill_Leg_Bucket(int dummy, void* input_leg)
{
    sp_time now, delta;
    unsigned int to_add;
    Network_Leg *leg;

    UNUSED(dummy);
    assert(Leg_Rate_Limit_kbps >= 0);
    
    leg = (Network_Leg *)input_leg;

    E_queue(Fill_Leg_Bucket, 0, input_leg, leg_bucket_to);

    if (leg == NULL) {
        Alarm(PRINT, "Fill_Leg_Bucket: trying to look at NULL leg\r\n");
        return;
    }

    if (leg->bucket_bytes > Leg_Bucket_Cap)
        Alarm(EXIT, "Fill_Leg_Bucket(): Bucket grew larger than max capacity\r\n");

    if (leg->bucket_bytes == Leg_Bucket_Cap) {
        Alarm(DEBUG, "Fill_Leg_Bucket(): bucket was full!!\r\n");
        return;
    }

    now = E_get_time();
    delta = E_sub_time(now, leg->bucket_last_filled);
    
    to_add = (Leg_Rate_Limit_kbps / 8000.0) * (delta.sec * 1000000 + delta.usec);
    leg->bucket_bytes += to_add;
    leg->bucket_last_filled = now;
    Alarm(DEBUG, "Fill_Leg_Bucket(): filled bucket to %d bytes, adding %d bytes\r\n", leg->bucket_bytes, to_add);

    if (leg->bucket_bytes > Leg_Bucket_Cap)
        leg->bucket_bytes = Leg_Bucket_Cap;

    if (!stdcarr_empty(&leg->bucket_buf) && leg->bucket_bytes > 0)
    {
        /* try to send any pkts we can */
        Leg_Try_Send_Buffered(leg);
    }
}
