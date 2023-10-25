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

#define ext_network
#include "network.h"
#undef  ext_network

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <float.h>

#ifndef ARCH_PC_WIN95
#  include <netdb.h>
#  include <sys/socket.h>
#  include <sys/ioctl.h>
#  include <unistd.h>
#  include <netinet/in.h>
#else
#  include <winsock2.h>
#endif

#include "arch.h"
#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_data_link.h"
#include "spu_memory.h"
#include "stdutil/stdhash.h"
#include "stdutil/stddll.h"

#include "objects.h"
#include "net_types.h"
#include "node.h"
#include "link.h"
#include "reliable_datagram.h"
#include "state_flood.h"
#include "link_state.h"
#include "hello.h"
#include "protocol.h"
#include "session.h"
#include "multicast.h"
#include "route.h"
#include "intrusion_tol_udp.h"
#include "priority_flood.h"
#include "reliable_flood.h"
#include "multipath.h"
#include "dissem_graphs.h"

#ifndef ARCH_PC_WIN95
#  include "kernel_routing.h"
#  include "wireless.h"
#endif

#include "spines.h"

#define MAX_LATENCY 600

extern char Config_File_Found;

/* Message delay */

typedef struct Delayed_Packet_d 
{
  char               *header;
  char               *buff;
  int16u              header_len;
  int16u              buf_len;
  int32u              type;
  sp_time             schedule_time;
  struct Interface_d *local_interf;
  int                 mode;
  Network_Address     remote_addr;
  int16u              remote_port;

} Delayed_Packet;

static stdhash Delay_Queue;
static int32u  Delay_Index;

static const sp_time zero_timeout  = {0, 0};

/* After a problem is detected, do not allow it to be resolved for at least 30 seconds */
static const sp_time Problem_Route_Stable_Time = {30, 0};

float Expected_Latency(float rtt, float loss_rate);

void Flip_pack_hdr(packet_header *pack_hdr)
{
  pack_hdr->type	  = Flip_int32(pack_hdr->type);
  pack_hdr->sender_id	  = Flip_int32(pack_hdr->sender_id);
  pack_hdr->ctrl_link_id  = Flip_int32(pack_hdr->ctrl_link_id);
  pack_hdr->data_len	  = Flip_int16(pack_hdr->data_len);
  pack_hdr->ack_len	  = Flip_int16(pack_hdr->ack_len);
  pack_hdr->seq_no	  = Flip_int16(pack_hdr->seq_no);
}

int Flip_rel_tail(char *buff, int ack_len)
{
  reliable_tail *r_tail = (reliable_tail*) buff;
  int32         *nack;
  int            i;

  if (ack_len < (int) sizeof(reliable_tail))
    return -1;
    
  r_tail->seq_no          = Flip_int32(r_tail->seq_no);
  r_tail->cummulative_ack = Flip_int32(r_tail->cummulative_ack);

  for (i = sizeof(reliable_tail); i + sizeof(int32) <= ack_len; i += sizeof(int32))
  {
    nack = (int32*) (buff + i);
    *nack = Flip_int32(*nack);
  }

  return i != ack_len;
}

void Init_Network(void) 
{
  /* int i, k; */ /* Added for testing purposes */
  stdit it;
  Network_Leg *leg;

  network_flag = 1;
  total_received_bytes = 0;
  total_received_pkts = 0;
  total_udp_pkts = 0;
  total_udp_bytes = 0;
  total_rel_udp_pkts = 0;
  total_rel_udp_bytes = 0;
  total_link_ack_pkts = 0;
  total_link_ack_bytes = 0;
  total_intru_tol_pkts = 0;
  total_intru_tol_bytes = 0;
  total_intru_tol_ack_pkts = 0;
  total_intru_tol_ack_bytes = 0;
  total_intru_tol_ping_pkts = 0;
  total_intru_tol_ping_bytes = 0;
  total_hello_pkts = 0;
  total_hello_bytes = 0;
  total_link_state_pkts = 0;
  total_link_state_bytes = 0;
  total_group_state_pkts = 0;
  total_group_state_bytes = 0;

  /* Rate limit variable init (Leg_Rate_Limit_kpbs set in spine.c based on
   * commandline params) */
  if (Leg_Rate_Limit_kbps >= 0) {
    Leg_Bucket_Cap = ((Leg_Rate_Limit_kbps / 8000.0) * LEG_BUCKET_FILL_USEC + MAX_PACKET_SIZE);
    Leg_Max_Buffered = Leg_Bucket_Cap;
  } else {
    Leg_Bucket_Cap = -1;
    Leg_Max_Buffered = -1; 
  }

  /* Num_Nodes = 0; */
  All_Routes = NULL;

#ifndef ARCH_PC_WIN95
  KR_Init();
#endif

  /* Init_My_Node(); */
  Init_Nodes();
  /* ISOLATING FROM HELLO:
   *   Don't call Init_Connections, which starts hello pings */
  if (Conf_IT_Link.Intrusion_Tolerance_Mode == 0)
    Init_Connections();
  else { /* Intrusion_Tolerance_Mode == 1 */
    for (stdhash_begin(&Network_Legs, &it); !stdhash_is_end(&Network_Legs, &it); stdhash_it_next(&it)) {
      leg = *(Network_Leg**) stdhash_it_val(&it);
      if (Config_File_Found == 1) {
        leg->status = CONNECTED_LEG;
        Create_Link(leg, INTRUSION_TOL_LINK);
      }
      /* Update_Leg_Cost ?? */
    }
    /* Schedule_Routes ?? */
  }
  Init_Session();
  Init_MultiPath();
  Init_Priority_Flooding();
  Init_Reliable_Flooding();

  if (Conf_IT_Link.Intrusion_Tolerance_Mode == 0) {
    Resend_States(0, &Edge_Prot_Def);
    /*State_Garbage_Collect(0, &Edge_Prot_Def); JLS: potential reconnection bug; fix: don't forget about edges + nodes */
    Resend_States(0, &Groups_Prot_Def);
    /*State_Garbage_Collect(0, &Groups_Prot_Def); JLS: need to examine groups garbage collection */
  }

  /* Uncomment next line to print periodical route updates */
  /* Print_Edges(0, NULL); 
  Print_Mcast_Groups(0, NULL); */

#ifdef SPINES_WIRELESS
  Wireless_Init();
#endif

  Delay_Index = 0;

  if (stdhash_construct(&Delay_Queue, sizeof(int32u), sizeof(Delayed_Packet), NULL, NULL, 0) != 0) {
    Alarm(EXIT, "Init_Network: Couldn't allocate Delay_Queue!\r\n");
  }
}

/***********************************************************/
/* Create_Interface: Creates an interface                  */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* nid: ID of node that owns this interface                */
/* iid: ID of interface                                    */
/* interf_addr: network address of interface               */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* The created interface                                   */
/*                                                         */
/***********************************************************/

Interface *Create_Interface(Node_ID         nid, 
			    Interface_ID    iid,
			    Network_Address interf_addr)
{
  Node      *node;
  Interface *interf;
  Link_Type  link_type;
  stdit      tit;
  int        j, priority;

  if ((node = Get_Node(nid)) == NULL) {
    Alarm(EXIT, "Create_Interface: Unknown node " IPF "!\r\n", IP(nid));
  }

  if (Get_Interface(iid) != NULL) {
    Alarm(EXIT, "Create_Interface: Interface " IPF " already exists!\r\n", IP(iid));
  }

  if (Get_Interface_by_Addr(interf_addr) != NULL) {
    Alarm(EXIT, "Create_Interface: Address " IPF " is already mapped to an existing interface!\r\n", IP(interf_addr));
  }
  
  if ((interf = (Interface*) new(INTERFACE)) == NULL) {
    Alarm(EXIT, "Create_Interface: Could not allocate interfact object!\r\n");
  }

  memset(interf, 0, sizeof(*interf));

  interf->iid      = iid;
  interf->net_addr = interf_addr;
  interf->owner    = node;

  if (stdhash_insert(&node->interfaces, &tit, &iid, &interf) != 0) {
    Alarm(EXIT, "Create_Interface: insert of interface into node failed!\r\n");
  }

  if (stdhash_insert(&Known_Interfaces, &tit, &iid, &interf) != 0) {
    Alarm(EXIT, "Create_Interface: insert of interface into Known_Interfaces failed!\r\n");
  }

  if (stdhash_insert(&Known_Addresses, &tit, &interf_addr, &interf) != 0) {
    Alarm(EXIT, "Create_Interface: insert of interface address into Known_Addresses failed!\r\n");
  }

  /* if this interface is on the local daemon -> set up necessary sockets + callbacks for this interface */

  if (node == This_Node) {

    /* set up the link protocol sockets on this interface */

    for (link_type = (Link_Type) 0; link_type != MAX_LINKS_4_EDGE; ++link_type) {

      priority = MEDIUM_PRIORITY;

      switch (link_type) {
      case CONTROL_LINK:
	    priority = HIGH_PRIORITY;
	    /* NOTE: break missing -> intentional fall through */

      case UDP_LINK:
      case RELIABLE_UDP_LINK:
      case REALTIME_UDP_LINK:
        /* ISOLATING FROM HELLO:  
         *      If Intrusion Tolerance mode is on, only create socket, bind, and attach listening event
         *      to the Intrusion_Tolerant_Link, skip all others */
        if (Conf_IT_Link.Intrusion_Tolerance_Mode == 1)
            break;
      case INTRUSION_TOL_LINK:
	
	if ((interf->channels[link_type] = DL_init_channel(RECV_CHANNEL, (int16) (Port + link_type), 0, interf_addr)) < 0) {
	  Alarm(EXIT, "Init_Recv_Channel: DL_init_channel failed with %d; errno %d says %s\r\n", interf->channels[link_type], errno, strerror(errno));
	}
	
	if (E_attach_fd(interf->channels[link_type], READ_FD, Net_Recv, link_type, interf, priority) != 0) {
	  Alarm(EXIT, "Init_Recv_Channel: E_attach_fd failed!\r\n");
	}
	break;

      case RESERVED0_LINK:
      case RESERVED1_LINK:
	break;

      case MAX_LINKS_4_EDGE:
      default:
	Alarm(EXIT, "Create_Interface: Unhandled link type?!\r\n");
	break;    
      }  
    }

    /* set up multicast discovery sockets on this interface */

    if (Num_Discovery_Addresses > 0) {

      if ((interf->discovery = (channel*) malloc(Num_Discovery_Addresses * sizeof(channel))) == NULL) {
	Alarm(EXIT, "Create_Interface: Unable to allocate discovery channels array!\r\n");
      }

      for (j = 0; j != Num_Discovery_Addresses; ++j) {

	if ((interf->discovery[j] = DL_init_channel(RECV_CHANNEL, (int16) (Port + CONTROL_LINK), Discovery_Address[j], interf_addr)) < 0) {
	  Alarm(EXIT, "Init_Recv_Channel: discovery - DL_init_channel failed with %d; errno %d says %s\r\n", interf->discovery[j], errno, strerror(errno));
	}
	
	if (E_attach_fd(interf->discovery[j], READ_FD, Net_Recv, CONTROL_LINK, interf, HIGH_PRIORITY) != 0) {
	  Alarm(EXIT, "Init_Recv_Channel: discovery - E_attach_fd failed!\r\n");
	}
      }

      interf->num_discovery = Num_Discovery_Addresses;

    } else {
      interf->discovery = NULL;
    }
  }

  Alarm(PRINT, "Create_Interface: nid = " IPF "; iid = " IPF "; net_addr = " IPF "\r\n", IP(node->nid), IP(interf->iid), IP(interf->net_addr));
  
  return interf;
}

Interface *Get_Interface(Interface_ID iid)
{
  Interface *ret = NULL;
  stdit      tit;

  if (!stdhash_is_end(&Known_Interfaces, stdhash_find(&Known_Interfaces, &tit, &iid))) {
    ret = *(Interface**) stdhash_it_val(&tit);
  }

  return ret;
}

Interface *Get_Interface_by_Addr(Network_Address interf_addr)
{
  Interface *ret = NULL;
  stdit      tit;

  if (!stdhash_is_end(&Known_Addresses, stdhash_find(&Known_Addresses, &tit, &interf_addr))) {
    ret = *(Interface**) stdhash_it_val(&tit);
  }

  return ret;
}

/***********************************************************/
/* Create_Network_Leg: creates a communication connection  */
/*     from the local node to another node. Note, that the */
/*     relevant nodes and interfaces must already exist.   */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* local_interf: local interface to use for connection     */
/* remote_interf: remote interface to use for connection   */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* Pointer to created network leg                          */
/*                                                         */
/***********************************************************/

Network_Leg *Create_Network_Leg(Interface_ID local_interf_id,
				Interface_ID remote_interf_id)
{
  Interface   *local_interf;
  Interface   *remote_interf;
  Edge        *edge;
  Network_Leg *leg;
  stdit        tit;
  int          i;

  if ((local_interf = Get_Interface(local_interf_id)) == NULL) {
    Alarm(EXIT, "Create_Network_Leg: unknown local interface id " IPF "!\r\n", IP(local_interf_id));
  }

  if (local_interf->owner != This_Node) {
    Alarm(EXIT, "Create_Network_Leg: local interface id " IPF " is not local!\r\n", IP(local_interf_id));
  }

  if ((remote_interf = Get_Interface(remote_interf_id)) == NULL) {
    Alarm(EXIT, "Create_Network_Leg: unknown remote interface id " IPF "!\r\n", IP(remote_interf_id));
  }

  if (remote_interf->owner == This_Node) {
    Alarm(EXIT, "Create_Network_Leg: remote interface id " IPF " is local!\r\n", IP(remote_interf_id));
  }

  if (Get_Network_Leg(local_interf_id, remote_interf_id) != NULL) {
    Alarm(EXIT, "Create_Network_Leg: network leg " IPF " -> " IPF " already exists!\r\n", IP(local_interf_id), IP(remote_interf_id));
  }

  if ((edge = Get_Edge(local_interf->owner->nid, remote_interf->owner->nid)) == NULL) {
    /* AB: I decided to give edges that aren't known from the configuration
     * file a base cost of -1 and index of USHRT_MAX to indicate that we don't
     * have a real cost or index for them */
    edge = Create_Edge(local_interf->owner->nid, remote_interf->owner->nid, -1, -1, USHRT_MAX);
  } 

  if (edge->leg != NULL) {
    Alarm(EXIT, "Create_Network_Leg: edge " IPF " -> " IPF " already has a network leg!\r\n", IP(local_interf->owner->nid), IP(remote_interf->owner->nid));
  }

  /* Create the network leg */

  if ((leg = (Network_Leg*) new(NETWORK_LEG)) == NULL) {
    Alarm(EXIT, "Create_Network_Leg: Allocation of leg failed!\r\n");
  }

  memset(leg, 0, sizeof(*leg));

  leg->leg_id.src_interf_id = local_interf_id;
  leg->leg_id.dst_interf_id = remote_interf_id;
  leg->local_interf         = local_interf;
  leg->remote_interf        = remote_interf;
  leg->edge                 = edge;
  
  /* Rate limiting set up */
  if (Leg_Rate_Limit_kbps >= 0) {
    leg->bucket_bytes = Leg_Bucket_Cap;
    leg->bucket_last_filled = E_get_time();
    stdcarr_construct(&leg->bucket_buf, sizeof(Leg_Buf_Cell), 0);
    E_queue(Fill_Leg_Bucket, 0, leg, leg_bucket_to);
  }

  for (i = 0; i != MAX_LINKS_4_EDGE; ++i) {
    leg->links[i] = NULL;
  }

  leg->status = DISCONNECTED_LEG;
  leg->cost   = -1;

  /* insert into appropriate collections */

  if (stdhash_insert(&Network_Legs, &tit, &leg->leg_id, &leg) != 0) {
    Alarm(EXIT, "Create_Network_Leg: Couldn't insert into Network_Legs!\r\n"); 
  }

  edge->leg = leg;

  Alarm(PRINT, "Create_Network_Leg: edge = (" IPF " -> " IPF"); local iid = " IPF "; remote iid = " IPF "; remote addr = " IPF "\r\n",
	IP(edge->src_id), IP(edge->dst_id), IP(local_interf_id), IP(remote_interf_id), IP(remote_interf->net_addr));

  return leg;
}

void Disconnect_Network_Leg(Network_Leg *leg)
{
  Edge *edge = leg->edge;
  int   i;

  Alarm(PRINT, "Disconnect_Network_Leg: edge = (" IPF " -> " IPF "); leg = (" IPF " -> " IPF ")\r\n",
	IP(edge->src_id), IP(edge->dst_id), IP(leg->local_interf->iid), IP(leg->remote_interf->iid));
  
  if (leg->status == DISCONNECTED_LEG) {
    Alarm(EXIT, "Disconnect_Network_Leg: Leg already disconnected?!\r\n");
  }

  leg->status                  = DISCONNECTED_LEG;
  leg->ctrl_link_id            = 0;
  leg->other_side_ctrl_link_id = 0;
  leg->last_connected          = E_get_time();

  for (i = 0; i != MAX_LINKS_4_EDGE; ++i) {
    
    if (leg->links[i] != NULL) {
      Destroy_Link(leg->links[i]->link_id);
    }
  }

  Network_Leg_Set_Cost(leg, -1);
}

Network_Leg *Get_Network_Leg(Interface_ID local_interf_id,
			     Interface_ID remote_interf_id)
{
  Network_Leg   *ret = NULL;
  Network_Leg_ID leg_id;
  stdit          tit;

  memset(&leg_id, 0, sizeof(leg_id));
  leg_id.src_interf_id = local_interf_id;
  leg_id.dst_interf_id = remote_interf_id;

  if (!stdhash_is_end(&Network_Legs, stdhash_find(&Network_Legs, &tit, &leg_id))) {
    ret = *(Network_Leg**) stdhash_it_val(&tit);
  }

  return ret;
}

Network_Leg *Get_Best_Network_Leg(Node_ID nid)
{
  Network_Leg *ret = NULL;
  Node        *nd  = Get_Node(nid);
  
  if (nd != NULL && Is_Connected_Neighbor2(nd)) {
    ret = nd->edge->leg;
  }

  return ret;
}

int16 Network_Leg_Initial_Cost(const Network_Leg *leg)
{
  int16 cost;

  switch (Route_Weight) {

  case DISTANCE_ROUTE:
  case LOSSRATE_ROUTE:
    cost = 1;
    break;
  case PROBLEM_ROUTE:
    cost = -1 * MAX_LATENCY;
    break;

  case LATENCY_ROUTE:
  case AVERAGE_ROUTE:
    cost = MAX_LATENCY;
    break;

  default:
    Alarm(EXIT, "Unknown routing algorithm!\r\n");
    return -1;
  }

  return cost;
}

void Network_Leg_Set_Cost(Network_Leg *leg, int16 new_leg_cost)
{
  int16        old_leg_cost  = leg->cost;
  Edge        *edge          = leg->edge;
  Node        *nd            = edge->dst;

  Alarm(PRINT, "Network_Leg_Set_Cost: edge = (" IPF " -> " IPF "); leg = (" IPF " -> " IPF "); leg cost %d -> %d\r\n",
	IP(edge->src_id), IP(edge->dst_id), IP(leg->local_interf->iid), IP(leg->remote_interf->iid), 
	(int) old_leg_cost, (int) new_leg_cost);

  /* AB: Changed to use negative weights for problem-type routing */
  /*if (new_leg_cost < 0 && new_leg_cost != -1) {
    Alarm(EXIT, "Network_Leg_Set_Cost: Invalid leg cost %d!\r\n", new_leg_cost);
  }*/

  if ((new_leg_cost != -1 && leg->status != CONNECTED_LEG) ||
      (new_leg_cost == -1 && leg->status != DISCONNECTED_LEG && leg->status != NOT_YET_CONNECTED_LEG)) {
    Alarm(EXIT, "Network_Leg_Set_Cost: New cost (%d) and leg status (%d) mismatch!\r\n", (int) new_leg_cost, leg->status);
  }

  if (new_leg_cost == old_leg_cost) {  /* no change */
    return;
  }

  /* update leg and edge cost */

  leg->cost = new_leg_cost;

  Alarm(PRINT, "Network_Leg_Set_Cost: edge = (" IPF " -> " IPF "); leg = (" IPF " -> " IPF "); EDGE cost %d -> %d!!!\r\n",
	IP(edge->src_id), IP(edge->dst_id), IP(leg->local_interf->iid), IP(leg->remote_interf->iid), 
	(int) old_leg_cost, (int) new_leg_cost);

  /* Check whether dissemination graphs need to be updated */
  DG_Process_Edge_Update(edge, new_leg_cost);

  edge->cost = new_leg_cost;

  /* Clear the cache used for K-Paths routing */
  MultiPath_Clear_Cache();

  if (++edge->timestamp_usec >= 1000000) {
    edge->timestamp_usec = 0;
    edge->timestamp_sec++;
  }

  edge->lts = Link_State_LTS_inc();

  if (old_leg_cost == -1) {  /* we've become connected to this node */
      
    assert(leg->status == CONNECTED_LEG);

    /* queue up the state sync fcns */

    E_queue(Net_Send_State_All, leg->links[CONTROL_LINK]->link_id, &Edge_Prot_Def,   zero_timeout);
    E_queue(Net_Send_State_All, leg->links[CONTROL_LINK]->link_id, &Groups_Prot_Def, zero_timeout);

  } else if (new_leg_cost == -1) {  /* we've disconnected from this node */

    Neighbor_Nodes[nd->neighbor_id] = NULL;
    nd->neighbor_id                 = -1;

    for (; Num_Neighbors > 0 && Neighbor_Nodes[Num_Neighbors - 1] == NULL; --Num_Neighbors);

  } /* else edge/node was already connected + cost has changed */

  Add_to_changed_states(&Edge_Prot_Def, My_Address, (State_Data*) edge);
  Schedule_Routes();
}

/***********************************************************
 * Updates the cost of a local
 * leg based on the new characteristics of its ctrl link   
 * 
 * Returns 1 if the cost was updated successfully; -1 if not       
 ***********************************************************/

int Network_Leg_Update_Cost(Network_Leg *leg)
{
  Link         *lk;
  Control_Data *c_data;
  sp_time       now, diff_time;
  float         tmp, cost;
  int16         prev_cost, abs_prev_cost, abs_diff;
  int16         cost16;
  float         latency_thresh, latency_np_thresh;
  int           problem_flag;

  now = E_get_time();

  if ((lk = leg->links[CONTROL_LINK]) == NULL || lk->link_type != CONTROL_LINK || (c_data = (Control_Data*) lk->prot_data) == NULL) {
    Alarm(EXIT, "Leg_Update_Cost: Invalid control link on leg!\r\n");
    return -1;
  }

  prev_cost = leg->cost;

  if (Route_Weight == DISTANCE_ROUTE) {
    return -1;

  } else if (Route_Weight == LATENCY_ROUTE) {

    tmp = c_data->rtt / 2.0;  /* One way delay */

    if (tmp < 1) {
      tmp = 1;
    }

    tmp += 4.0;

    if (tmp < 300) {
      cost = tmp;

    } else {
      cost = 300.0;
    }
	
    if (abs((int) (prev_cost - cost)) < (int) (0.1 * prev_cost)) {
      return -1;
    }

    cost16 = (short) (cost + 0.5);

  } else if (Route_Weight == LOSSRATE_ROUTE) {

    tmp  = (float) log(1 - c_data->est_loss_rate);
    tmp *= 10000;

    if (1 - tmp < 30000) {
      cost16 = (int16) (1 - tmp + 0.5);

    } else {
      cost16 = 30000;
    }	

  } else if (Route_Weight == AVERAGE_ROUTE) {

    cost = Expected_Latency(c_data->rtt, c_data->est_loss_rate);

    if (prev_cost > cost && prev_cost - cost < prev_cost * NET_UPDATE_THRESHOLD) {
      return -1;
    } else if (prev_cost <= cost && cost - prev_cost < prev_cost * NET_UPDATE_THRESHOLD) {
      return -1;
    }
	
    Alarm(DEBUG, "@\tupdate\t%d: delay: %5.3f loss: %5.3f; new_cost: %5.3f; old_cost: %d\n",
	  now.sec, c_data->rtt / 2.0, c_data->est_loss_rate, cost, prev_cost);
	
    cost16 = (int16) (cost + 0.5);

  } else if (Route_Weight == PROBLEM_ROUTE) {

    /* Cost is negative if we are above the threshold for detecting a problem,
     * and positive if we are below the threshold for detecting that there is
     * no problem -- in between these two thresholds, we stick with our
     * previous problem-state to increase routing stability. The absolute value
     * of the cost is the expected latency.
     */

    /* Calculate latency thresholds for deciding whether there is a problem,
     * based on the base case latency. Note that if this is an edge that we
     * don't have a base-case latency for, we don't consider latency in
     * determining whether there is a problem (any latency is okay) */
    if (leg->edge->base_cost == -1) {
        latency_thresh = FLT_MAX;
        latency_np_thresh = FLT_MAX;
    } else {
        latency_thresh = (float) leg->edge->base_cost * LATENCY_PROB_THRESH;
        latency_np_thresh = (float) leg->edge->base_cost * LATENCY_NO_PROB_THRESH;

        if (latency_thresh < leg->edge->base_cost + LATENCY_ABS_PROB_THRESH)
            latency_thresh = leg->edge->base_cost + LATENCY_ABS_PROB_THRESH;
        if (latency_np_thresh < leg->edge->base_cost + LATENCY_ABS_NO_PROB_THRESH)
            latency_np_thresh = leg->edge->base_cost + LATENCY_ABS_NO_PROB_THRESH;
    }

    /* Now check to see if we are learning about a new problem starting or
     * stopping. Set problem_flag to 0 for no change, -1 for newly detected
     * problem, and 1 for newly resolved problem */
    problem_flag = 0;

    if (c_data->est_loss_rate > LOSS_PROB_THRESH ||
        c_data->rtt > latency_thresh)
    {
        if (prev_cost >= 0) {
            /* New problem detected: update cost */
            problem_flag = -1;
        }
    } else if (c_data->est_loss_rate < LOSS_NO_PROB_THRESH &&
               c_data->rtt < latency_np_thresh)
    {
        if (prev_cost < 0) {
            /* Problem resolved: try to update cost (will check that it is not
             * too soon for this below) */
            problem_flag = 1;
        }
    }

    /* Get link weight value (expected latency */
    cost = Expected_Latency(c_data->rtt, c_data->est_loss_rate);
    cost16 = (int16) (cost + 0.5);

    /* If there is no significant change (in value or problem state), no need
     * to update everyone else */
    abs_prev_cost = abs(prev_cost);
    abs_diff = abs(abs_prev_cost - cost16);
    if (problem_flag == 0 && (abs_diff < NET_UPDATE_THRESHOLD_ABS ||
                              abs_diff < abs_prev_cost * NET_UPDATE_THRESHOLD))
    {
          return -1;
    }

    /* We have something new to report -- set the cost to be negative to
     * indicate a problem if necessary */
    if (problem_flag == -1 || (problem_flag == 0 && prev_cost < 0)) {
        cost16 *= -1;
    }

    /* Check that is not too soon to report link improvement */
    if (problem_flag == 1 || abs(cost16) < abs_prev_cost) {
        diff_time = E_sub_time(now, c_data->reported_ts);
        if (E_compare_time(diff_time, Problem_Route_Stable_Time) < 0) {
            Alarm(DEBUG, "Link improved (%hd -> %hd), but not enough time "
                         "has passed since last report (diff_time = %lu "
                         "%lu)\n", prev_cost, cost16, diff_time.sec, diff_time.usec);
            return -1;
        }
    }

    if (problem_flag == 1)
        Alarm(PRINT, "Problem resolved on my link! %f %f\n", c_data->est_loss_rate, c_data->rtt);
    else if (problem_flag == -1)
        Alarm(PRINT, "Problem detected on my link! %f %f\n", c_data->est_loss_rate, c_data->rtt);

  } else {
    Alarm(EXIT, "Network_Leg_Update_Cost: Unknown routing scheme %d!\r\n", Route_Weight);
    return -1;
  }

  Alarm(PRINT, "Network_Leg_Update_Cost: setting cost %hd, loss %f, latency %f\n", cost16, c_data->est_loss_rate, c_data->rtt);
  Network_Leg_Set_Cost(leg, cost16);

  return 1;
}

float Expected_Latency(float rtt, float loss_rate)
{
    float tmp, tmp1, tmp2, cost;
    float loss_squared, loss_cubed;
    float recovery_latency;

    tmp = rtt / 2.0;  /* one way delay */

    if (loss_rate > 0.0) {
        loss_squared = loss_rate * loss_rate;
        loss_cubed = loss_squared * loss_rate;

        recovery_latency = tmp * 3.0 + 10.0;
        if (recovery_latency > MAX_LATENCY) recovery_latency = MAX_LATENCY;

        /* 2*p^2 * max_latency (lost even after recovery) */
        tmp1 = (float) ((2.0 * loss_squared - loss_cubed)  * MAX_LATENCY);

        /* (p - 2*p^2)(3*delay + delta) */
        tmp2 = (float) ((tmp * 3.0 + 10.0) * (loss_rate - 2.0 * loss_squared + loss_cubed));

        /* (1-p)*delay + (p - 2*p^2)(3*delay + delta) + 2*p^2 * max_latency */
        tmp  = (float) (tmp * (1.0 - loss_rate) + tmp1 + tmp2);
    }

    /* Because we use -1 for disconnected links, we prevent latency
     * measurements < 2 to avoid ambiguity */
    if (tmp < 2) {
        tmp = 2;
    }

    if (tmp < MAX_LATENCY) {
        cost = tmp;
    } else {
        cost = MAX_LATENCY;
    }

    return cost;
}

void Net_Recv(channel sk,              /* socket on which to recv */
	      int     mode,            /* type of port of the socket */
	      void   *local_interf_p)  /* socket on which the Interface exists */
{
  Read_UDP((Interface*) local_interf_p, sk, mode, &Recv_Pack[mode]);
}

void Init_My_Node(void) 
{
  struct hostent * host_ptr;
  char             machine_name[256] = { 0 };

  if (My_Address == 0) { /* No local id was given in the command line */

    gethostname(machine_name, sizeof(machine_name)); 
    host_ptr = gethostbyname(machine_name);
	
    if (host_ptr == NULL) {
      Alarm(EXIT, "Init_My_Node: could not get my ip address (my name is %s)!\r\n", machine_name);
    }

    if (host_ptr->h_addrtype != AF_INET) {
      Alarm(EXIT, "Init_My_Node: Sorry, cannot handle addr types other than IPv4!\r\n");
    }

    if (host_ptr->h_length != 4) {
      Alarm(EXIT, "Init_My_Node: Bad IPv4 address length!\r\n");
    }
	
    memcpy(&My_Address, host_ptr->h_addr, sizeof(struct in_addr));
    My_Address = ntohl(My_Address);
  }

  Alarm(PRINT, "Init_My_Node: Local identifier = " IPF "\r\n", IP(My_Address));
  assert(My_Address != 0);
}

/***********************************************************/
/* void Read_UDP(channel sk, int mode, sys_scatter *scat)  */
/*                                                         */
/* Receives data from a socket                             */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* sk:      socket                                         */
/* mode:    type of the link                               */
/* scat:    scatter to receive data into                   */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* Number of bytes received from network if msg is         */
/* processed, 0 if it is dropped at this level, negative   */
/* on OS error.                                            */
/*                                                         */
/***********************************************************/

int Read_UDP(Interface *local_interf, channel sk, int mode, sys_scatter *scat)
{
  int   ret = 0;
  int	received_bytes;
  int   stripped_bytes;
  int   remaining_bytes;
  packet_header *pack_hdr;
  sp_time now = {0, 0};
  sp_time diff;
  stdit it;
  double chance = 100.0;
  double test = 0.0;
  double p1, p01, p11;
  Lk_Param *lkp = NULL;
  Delayed_Packet dpkt;
  stdit delay_it;
  long long tokens;
  int total_pkt_bytes;
  int32 pack_type;

  int32u     remote_addr = 0;
  int16u     remote_port = 0;
  Interface *remote_interf;

  if (scat->num_elements != 2 || scat->elements[0].len != sizeof(packet_header) || scat->elements[1].len != sizeof(packet_body))
      Alarm(EXIT, "Read_UDP: unexpected recv scat layout!\n");

  received_bytes = DL_recvfrom(sk, scat, (int*) &remote_addr, (unsigned short*) &remote_port);

  if (received_bytes < 0)
  {
      Alarmp(SPLOG_ERROR, (sock_errno == EINTR || sock_errno == EAGAIN || sock_errno == EWOULDBLOCK ? NETWORK : EXIT),
            "Read_UDP: unexpected error on socket %d, local interf = " IPF ":%d, err = %d, errno = %d : '%s', sock_errno = %d : '%s'!\n",
            sk, IP(local_interf->net_addr), Port + mode, received_bytes, errno, strerror(errno), sock_errno, sock_strerror(sock_errno));
      ret = -1;
      goto FAIL;
  }

  if (received_bytes < (int) sizeof(packet_header))
  {
      Alarmp(SPLOG_INFO, NETWORK, "Read_UDP: too small packet of %d bytes received on socket %d, local interf = " IPF ":%d from " IPF ":%d! Dropping!\n",
            received_bytes, sk, IP(local_interf->net_addr), Port + mode, IP(remote_addr), (int) remote_port);
      goto FAIL;
  }

  if (received_bytes > (int) (sizeof(packet_header) + sizeof(packet_body)))
  {
      Alarmp(SPLOG_INFO, NETWORK, "Read_UDP: partial receive of too big packet of %d bytes received on socket %d, local interf = " IPF ":%d from " IPF ":%d! Dropping!\n",
            received_bytes, sk, IP(local_interf->net_addr), Port + mode, IP(remote_addr), (int) remote_port);
      goto FAIL;
  }

  if (remote_port != Port + mode)
  {
      Alarmp(SPLOG_INFO, NETWORK, "Read_UDP: recvd a msg on port %d from an unequal remote port %d! Dropping!\n", Port + mode, (int) remote_port);
      goto FAIL;
  }

  /* NOTE: trim scatter to reflect received size (restored at bottom) */
  
  scat->elements[1].len = received_bytes - sizeof(packet_header);

  /*Alarm(PRINT, "Read_UDP: Recvd %d bytes from " IPF ":%d on interface " IPF " (addr = " IPF ")\n",
	received_bytes, IP(remote_addr), (int) remote_port, IP(local_interf->iid), IP(local_interf->net_addr)); */

  /* NOTE: Authenticating and decrypting the message upon receipt will
   * mess with the built-in latency generator slightly (e.g. - packet
   * authentication may pass/fail differently than if done later). */

  if (mode == INTRUSION_TOL_LINK && Conf_IT_Link.Crypto)
  {
      stripped_bytes = Preprocess_intru_tol_packet(scat, received_bytes, local_interf, remote_addr, remote_port);

      if (stripped_bytes < 0 || stripped_bytes < (int) sizeof(packet_header) || stripped_bytes > received_bytes)  /* NOTE: we assume no compression */
      {
          Alarmp(SPLOG_INFO, NETWORK, "Read_UDP: socket %d, local interf = " IPF ":%d, remote interf = " IPF ":%d, recvd_size = %d, new_size = %d: IT link rejected unauthenticated msg! Dropping!\n",
                sk, IP(local_interf->net_addr), Port + mode, IP(remote_addr), (int) remote_port, received_bytes, stripped_bytes);
          goto FAIL;
      }
      
      /* NOTE: trim scatter to reflect stripped size (restored at bottom) */
      
      scat->elements[1].len = stripped_bytes - sizeof(packet_header);
  }
  else
      stripped_bytes = received_bytes;
  
  pack_hdr        = (packet_header *) scat->elements[0].buf;
  remaining_bytes = stripped_bytes - sizeof(packet_header);
  
  if (!Same_endian(pack_hdr->type))
      Flip_pack_hdr(pack_hdr);

  pack_type = pack_hdr->type;
  
  if (Conf_IT_Link.Intrusion_Tolerance_Mode == 1 &&
      !(Is_intru_tol_data(pack_type) || Is_intru_tol_ack(pack_type) || Is_intru_tol_ping(pack_type) || Is_diffie_hellman(pack_type)))
  {
      Alarmp(SPLOG_INFO, NETWORK, "Read_UDP: Invalid pack_type 0x%x for Intrusion Tolerance Mode! Dropping!\n", pack_type);
      goto FAIL;
  }

  if (remaining_bytes != (int) pack_hdr->data_len + (int) pack_hdr->ack_len)
  {
      Alarmp(SPLOG_INFO, NETWORK, "Read_UDP: socket %d, local interf = " IPF ":%d, remote interf = " IPF ":%d, strip_size = %d: remaining bytes (%d) != data_len (%d) + ack_len (%d)! Dropping!\n",
            sk, IP(local_interf->net_addr), Port + mode, IP(remote_addr), (int) remote_port, stripped_bytes, remaining_bytes, (int) pack_hdr->data_len, (int) pack_hdr->ack_len);
      goto FAIL;
  }

  /* AB: This seems problematic? I think we frequently have ack_len >=
   * reliable_tail when we aren't actually using the reliable_tail */
  if (!Same_endian(pack_type) && pack_hdr->ack_len >= sizeof(reliable_tail))             /* TODO: this should probably be moved to a more specific spot? */
      if (Flip_rel_tail(scat->elements[1].buf + pack_hdr->data_len, pack_hdr->ack_len))  /* the packet has a reliable tail */
          goto FAIL;

  if (Num_Discovery_Addresses != 0 && pack_hdr->sender_id == My_Address)    
      goto FAIL;  /* I can hear my own discovery packets.  Discard */  /* TODO: should we have a network based filter like this one? Or make it more general / broader? */

  if (Accept_Monitor == 1 && (remote_interf = Get_Interface_by_Addr(remote_addr)) != NULL) {
    Network_Leg_ID lid;

    memset(&lid, 0, sizeof(lid));
    lid.src_interf_id = remote_interf->iid;
    lid.dst_interf_id = local_interf->iid;

    /* Check for monitor injected losses */

    if (!stdhash_is_end(&Monitor_Params, stdhash_find(&Monitor_Params, &it, &lid))) {
	    
      lkp = (Lk_Param*)stdhash_it_val(&it);
	   
       /*dt debugging */
      /* Alarm(PRINT, "mode = %d   UDP_LINK = %d\n", mode, UDP_LINK);

      if (mode == UDP_LINK) 
      Alarm(PRINT, "loss: %d; burst: %d; was_loss %d; test: %5.3f; chance: %5.3f\n",
	    lkp->loss_rate, lkp->burst_rate, lkp->was_loss, test, chance); */
	    
      Alarm(DEBUG, "loss: %d; burst: %d; was_loss %d; test: %5.3f; chance: %5.3f\n",
	    lkp->loss_rate, lkp->burst_rate, lkp->was_loss, test, chance);
	    
      now = E_get_time();

      if(lkp->bandwidth > 0) {
	diff = E_sub_time(now, lkp->last_time_add);
	if(diff.sec > 10) {
	  tokens = 10000000;
	}
	else {
	  tokens = diff.sec*1000000;
	}
	tokens += diff.usec;
	tokens *=lkp->bandwidth;
	tokens /= 1000000;
	tokens += lkp->bucket;
	if(tokens > BWTH_BUCKET) {
	  tokens = BWTH_BUCKET;
	}
	lkp->bucket = (int32)tokens;
	lkp->last_time_add = now;
	/* Emulate mbuf size */
	total_pkt_bytes = received_bytes + received_bytes%256;
	/* 64 bytes for UDP header */
	total_pkt_bytes += 64; 

	if(lkp->bucket <= MAX_PACKET_SIZE) {
	  Alarm(DEBUG, "Read_UDP: Dropping message: "IPF" -> "IPF"\n", IP(pack_hdr->sender_id), IP(My_Address));
          goto FAIL;
	}
	else {
	  lkp->bucket -= total_pkt_bytes*8;
	}
      }

      chance = rand();
      chance /= RAND_MAX;
	    
      p1  = lkp->loss_rate;
      p1  = p1/1000000.0;
	    
      if(lkp->burst_rate == 0) {
	p01 = p11 = p1;
      }
      else if((lkp->burst_rate == 1000000)|| /* burst rate of 100% or */
	      (lkp->loss_rate == 1000000)) { /* loss rate of 100% */
	p01 = p11 = 1.0;
      }
      else {
	p11 = lkp->burst_rate;
	p11 = p11/1000000.0;
	p01 = p1*(1-p11)/(1-p1);	      
      }
	    
      if(lkp->was_loss > 0) {
	test = p11;
      }
      else {
	test = p01;
      }
    }
  }

  if (network_flag == 1 && chance >= test) {

    if (lkp == NULL || (lkp->delay.sec == 0 && lkp->delay.usec == 0)) {

      Prot_process_scat(scat, stripped_bytes, local_interf, mode, pack_type, remote_addr, remote_port);

    } else {

      /* TODO: Individually E_queue'ing each delayed packet is
	 expensive unless event system can handle lots of timer
	 events very efficiently (e.g. - original event system does
	 not).  Probably should keep a queue (e.g. - stddll or
	 stdskl) per link and schedule only the head of each queue.
      */

      memset(&dpkt, 0, sizeof(dpkt));

      dpkt.header        = scat->elements[0].buf;
      dpkt.header_len    = scat->elements[0].len;
      dpkt.buff          = scat->elements[1].buf;
      dpkt.buf_len       = stripped_bytes - scat->elements[0].len;
      dpkt.type          = pack_type;
      dpkt.schedule_time = E_add_time(now, lkp->delay);
      dpkt.local_interf  = local_interf;
      dpkt.mode          = mode;
      dpkt.remote_addr   = remote_addr;
      dpkt.remote_port   = remote_port;
	
      if (stdhash_insert(&Delay_Queue, &delay_it, &Delay_Index, &dpkt) != 0) {
	Alarm(EXIT, "Read_UDP: Couldn't queue delayed packet!\n");
      }

      scat->elements[0].buf = (char*) new_ref_cnt(PACK_HEAD_OBJ);
      scat->elements[1].buf = (char*) new_ref_cnt(PACK_BODY_OBJ);
      E_queue(Proc_Delayed_Pkt, Delay_Index, NULL, lkp->delay);
      Delay_Index++;
    }

    total_received_bytes += received_bytes;
    total_received_pkts++;

    if (lkp != NULL) {
      lkp->was_loss = 0;
    }

    ret = received_bytes;

  } else {
    if (lkp != NULL) {
      lkp->was_loss = 1;
    }
  }

FAIL:
  scat->elements[1].len = sizeof(packet_body);
  
  return ret;
}

void Up_Down_Net(int dummy_int, void *dummy_p)
{
  network_flag = 1 - network_flag;
  E_queue(Up_Down_Net, 0, NULL, Up_Down_Interval);
}

void Graceful_Exit(int dummy_int, void *dummy_p)
{
  Alarm(PRINT, "\n\n\nUDP\t%9lld\t%9lld\n", total_udp_pkts, total_udp_bytes);
  Alarm(PRINT, "REL_UDP\t%9lld\t%9lld\n", total_rel_udp_pkts, total_rel_udp_bytes);
  Alarm(PRINT, "ACK\t%9lld\t%9lld\n", total_link_ack_pkts, total_link_ack_bytes);
  Alarm(PRINT, "HELLO\t%9lld\t%9lld\n", total_hello_pkts, total_hello_bytes);
  Alarm(PRINT, "LINK_ST\t%9lld\t%9lld\n", total_link_state_pkts, total_link_state_bytes);
  Alarm(PRINT, "GRP_ST\t%9lld\t%9lld\n", total_group_state_pkts, total_group_state_bytes);
  Alarm(PRINT,  "TOTAL\t%9lld\t%9lld\n", total_received_pkts, total_received_bytes);
  exit(1);
}

void Proc_Delayed_Pkt(int idx, void *dummy_p)
{
  int             received_bytes;
  sys_scatter     scat;
  stdit           pkt_it;
  Delayed_Packet *dpkt;
  sp_time         now, diff;

  stdhash_find(&Delay_Queue, &pkt_it, &idx);
  if(stdhash_is_end(&Delay_Queue, &pkt_it)) {
    return;
  }
  dpkt = (Delayed_Packet *)stdhash_it_val(&pkt_it);

  now = E_get_time();
  diff = E_sub_time(now, dpkt->schedule_time);

  if (diff.usec > 5000 || diff.sec > 0) {
    Alarm(DEBUG, "\n\nDelay error: %d.%06d sec\n\n", diff.sec, diff.usec);
  }

  scat.num_elements    = 2;
  scat.elements[0].len = dpkt->header_len;
  scat.elements[0].buf = dpkt->header;
  scat.elements[1].len = dpkt->buf_len;
  scat.elements[1].buf = dpkt->buff;
    
  received_bytes = scat.elements[0].len + scat.elements[1].len;

  Prot_process_scat(&scat, received_bytes, dpkt->local_interf, dpkt->mode, dpkt->type, dpkt->remote_addr, dpkt->remote_port);

  dec_ref_cnt(scat.elements[0].buf);
  dec_ref_cnt(scat.elements[1].buf);

  stdhash_erase(&Delay_Queue, &pkt_it);
}
