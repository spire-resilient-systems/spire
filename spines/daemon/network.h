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
 *  Yair Amir, Claudiu Danilov, John Schultz, Daniel Obenshain, and Thomas Tantillo.
 *
 * Copyright (c) 2003 - 2017 The Johns Hopkins University.
 * All rights reserved.
 *
 * Major Contributor(s):
 * --------------------
 *    John Lane
 *    Raluca Musaloiu-Elefteri
 *    Nilo Rivera
 *
 */

#ifndef NETWORK_H
#define NETWORK_H

#include <netinet/in.h>

#include "arch.h"
#include "spu_scatter.h"
#include "spu_events.h"

#include "net_types.h"
#include "link.h"
#include "node.h"
#include "link_state.h"

#define CONNECTED_LEG_THRESHOLD 5

struct Node_d;
struct Edge_d;
struct Interface_d;
struct Network_Leg_d;
struct Link_d;

typedef int32 Network_Address;                   /* TODO: redefine me to support both IPv4 and IPv6: struct sockaddr? */

typedef struct Interface_d
{
  Interface_ID    iid;                           /* globally unique virtual ID of this interface in the system */
  Network_Address net_addr;                      /* network address of this interface */
  struct Node_d * owner;                         /* Node to which this Interface belongs */
  
  channel         channels[MAX_LINKS_4_EDGE];    /* if local -> the channels bound to this interface */
  sys_scatter     recv_scats[MAX_LINKS_4_EDGE];  /* if local -> recv buffers for channels */

  int             num_discovery;                 /* if local -> # of multicast discovery channels bound to this interface */
  channel *       discovery;                     /* if local -> multicast discovery channels bound to this interface */

} Interface;

typedef struct
{
  Interface_ID    src_interf_id;
  Interface_ID    dst_interf_id;

} Network_Leg_ID;

typedef enum 
{
  DISCONNECTED_LEG,
  NOT_YET_CONNECTED_LEG,
  CONNECTED_LEG,

} Network_Leg_Status;

typedef struct Network_Leg_d
{
  Network_Leg_ID     leg_id;                   /* id of this leg: (local, remote) */
  Interface         *local_interf;             /* local interface of this leg (src) */
  Interface         *remote_interf;            /* remote interface of this leg (dst) */
  struct Edge_d     *edge;                     /* Edge to which this leg belongs */

  struct Link_d     *links[MAX_LINKS_4_EDGE];  /* links running on this leg */
  Network_Leg_Status status;                   /* status of this leg (NOT_YET_CONNECTED_LEG, etc.) */
  int16              cost;                     /* routing cost of this leg */

  int32u             ctrl_link_id;             /* ctrl link "session" id that marks every packet that goes out this leg */
  int32u             other_side_ctrl_link_id;  /* ctrl link "session" id that marks every packet that comes in this leg */

  int16              hellos_out;               /* number of outstanding hello msgs on this leg */  
  sp_time            last_recv_hello;          /* time at which we last recvd a hello from other side */

  int16              connect_cnter;            /* hello counter used to establish connection */
  sp_time            last_connected;           /* TS of most recent time this leg was connected */

#ifdef SPINES_WIRELESS
  struct Wireless_Data_d w_data;
#endif

} Network_Leg;

void Init_Network(void);
void Init_My_Node(void);

Interface *Create_Interface(Node_ID nid, Interface_ID iid, Network_Address interf_addr);
Interface *Get_Interface(Interface_ID iid);
Interface *Get_Interface_by_Addr(Network_Address interf_addr);

Network_Leg *Create_Network_Leg(Interface_ID local_iid, Interface_ID remote_iid);
void         Disconnect_Network_Leg(Network_Leg *leg);
Network_Leg *Get_Network_Leg(Interface_ID local_iid, Interface_ID remote_iid);
Network_Leg *Get_Best_Network_Leg(Node_ID node_id);

int16 Network_Leg_Initial_Cost(const Network_Leg *leg);
void  Network_Leg_Set_Cost(Network_Leg *leg, int16 new_cost);
int   Network_Leg_Update_Cost(Network_Leg *leg);

void Net_Recv(channel sk, int mode, void * dummy_p);
int  Read_UDP(Interface *inter, channel sk, int mode, sys_scatter *scat);
void Up_Down_Net(int dummy_int, void *dummy_p);
void Graceful_Exit(int dummy_int, void *dummy_p);
void Proc_Delayed_Pkt(int idx, void *dummy_p);

#endif
