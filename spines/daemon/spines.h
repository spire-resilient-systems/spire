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

#ifndef SPINES_H
#define SPINES_H

#include "stdutil/stdhash.h"

#include "spu_events.h"

#include "net_types.h"
#include "link.h"
#include "node.h"
#include "link_state.h"
#include "network.h"
#include "state_flood.h"
#include "route.h"

/* Startup */

extern Node            *This_Node;
extern Node_ID          My_Address;
extern int16u	        Port;
extern char             My_Host_Name[];

extern int16u           Num_Local_Interfaces;
extern Interface_ID     My_Interface_IDs[];
extern Network_Address  My_Interface_Addresses[];

extern int16            Num_Legs;
extern Network_Address  Remote_Interface_Addresses[];
extern Interface_ID     Remote_Interface_IDs[];
extern Node_ID          Remote_Node_IDs[];
extern Interface_ID     Local_Interface_IDs[];

extern int16            Num_Discovery_Addresses;
extern Node_ID          Discovery_Address[];

extern stdhash          Ltn_Route_Weights;

/* Status Message Variables */

extern char server_type[];

/* Nodes and direct links */

extern Node*    Neighbor_Nodes[];  /* nodes to which I have a ctrl link */
extern int16    Num_Neighbors;
extern int16    Num_Nodes;

extern stdhash  All_Nodes;         /* <Node_ID -> Node*> */
extern stdskl   All_Nodes_by_ID;   /* <Node_ID -> Node*> sorted by Node_ID */
extern stdhash  Known_Interfaces;  /* <Interface_ID -> Interface*> */
extern stdhash  Known_Addresses;   /* <Network_Address -> Interface*> */
extern stdhash  Network_Legs;      /* <Network_Leg_ID -> Network_Leg*> */
extern Link*    Links[];
extern channel  Ses_UDP_Channel;   /* For udp client connections */
extern sys_scatter Recv_Pack[];
extern Route*   All_Routes;
extern stdskl  Client_Cost_Stats; /* AB: added for cost accounting */

extern stdhash  Monitor_Params;
extern int      Accept_Monitor;
extern int      Wireless;
extern int      Wireless_ts;
extern char     Wireless_if[];
extern int      Wireless_monitor;

extern char     Log_Filename[];
extern int      Use_Log_File;

/* Configuration File Variables */
extern char        Config_File_Found;
extern char        Unix_Domain_Prefix[];
extern char        Unix_Domain_Use_Default;
extern stdhash     Node_Lookup_Addr_to_ID;
extern stdhash     Node_Lookup_ID_to_Addr;
extern int16u      My_ID;
extern int32u      *Neighbor_Addrs[];
extern int16u      *Neighbor_IDs[];

/* Sessions */

extern stdhash  Sessions_ID;
extern stdhash  Sessions_Port;
extern stdhash  Rel_Sessions_Port;
extern stdhash  Sessions_Sock;
extern int16    Link_Sessions_Blocked_On; 
extern stdhash  Neighbors;

/* Link State */

extern stdhash  All_Edges;             /* <Node_ID -> State_Chain*>:   Edge source -> Edge destinations -> Edge* */
extern stdhash  Changed_Edges;         /* <Node_ID -> Changed_State*>: Publisher -> tracking structure */
extern Prot_Def Edge_Prot_Def;

/* Multicast */

extern stdhash  All_Groups_by_Node;    /* <Node_ID -> State_Chain*>:   Node Participant -> Groups -> Group_State */
extern stdhash  All_Groups_by_Name;    /* <Group_ID -> State_Chain*>:  Group name -> Node Participants -> Group_State */
extern stdhash  Changed_Group_States;  /* <Node_ID -> Changed_State*>: Publisher -> tracking structure */
extern Prot_Def Groups_Prot_Def;

/* Params */

extern int      network_flag;
extern int      Route_Weight;
extern sp_time  Up_Down_Interval;
extern sp_time  Time_until_Exit;
extern int      Minimum_Window;
extern int      Fast_Retransmit;
extern int      Stream_Fairness;
extern int      TCP_Fairness;
extern int      Print_Cost;
extern int      Unicast_Only;
extern int      Memory_Limit;
extern int16    KR_Flags;

/* Statistics */

extern int64_t total_received_bytes;
extern int64_t total_received_pkts;
extern int64_t total_udp_pkts;
extern int64_t total_udp_bytes;
extern int64_t total_rel_udp_pkts;
extern int64_t total_rel_udp_bytes;
extern int64_t total_link_ack_pkts;
extern int64_t total_link_ack_bytes;
extern int64_t total_intru_tol_pkts;
extern int64_t total_intru_tol_bytes;
extern int64_t total_intru_tol_ack_pkts;
extern int64_t total_intru_tol_ack_bytes;
extern int64_t total_intru_tol_ping_pkts;
extern int64_t total_intru_tol_ping_bytes;
extern int64_t total_hello_pkts;
extern int64_t total_hello_bytes;
extern int64_t total_link_state_pkts;
extern int64_t total_link_state_bytes;
extern int64_t total_group_state_pkts;
extern int64_t total_group_state_bytes;

extern int64u Injected_Messages;

#endif
