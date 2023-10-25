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

#ifndef ROUTE_H
#define ROUTE_H

#include <stdio.h>

#include "net_types.h"
#include "node.h"
#include "link.h"

#define REMOTE_ROUTE    0
#define LOCAL_ROUTE     1

#define DISTANCE_ROUTE  0
#define LATENCY_ROUTE   1
#define LOSSRATE_ROUTE  2
#define AVERAGE_ROUTE   3
#define RESERVED1_ROUTE 4
#define IT_PRIORITY_ROUTE 5
#define RELIABLE_FLOOD_ROUTE 6
#define PROBLEM_ROUTE   7

typedef struct Route_d 
{
  int16   distance;              /* Number of hops on this route */
  int32   cost;                  /* Cost of sending on this route */
  
  Node   *forwarder;             /* Neighbor of local node that will forward towards dst */
  Node_ID predecessor;           /* Node on path: src -> predecessor -> dst */

} Route;

/* typedef struct Min_Weight_Belly_d {
  int16u data_len;
  char   *buff;
} Min_Weight_Belly; */

#define RR_CRYPTO 1

typedef struct CONF_RR_d {
    unsigned char Crypto;
} CONF_RR;

#undef  ext
#ifndef ext_route
#define ext extern
#else
#define ext
#endif

ext CONF_RR Conf_RR;
ext int32u My_Source_Seq;
ext int32u My_Source_Incarnation;

void     Init_Routes(void);
void     Schedule_Routes(void);
void     Set_Routes(int dummy_int, void *dummy);  /* NOTE: forces immediate routes computation; typically Schedule_Routes should be called instead */

Route   *Find_Route(Node_ID source, Node_ID dest); 
Node    *Get_Route(Node_ID source, Node_ID dest);
void     Trace_Route(Node_ID src, Node_ID dst, spines_trace *spines_tr);
void     Print_Routes(FILE *fp);

stdhash *Get_Mcast_Neighbors(Node_ID sender, Group_ID mcast_address);
void     Discard_Mcast_Neighbors(Group_ID mcast_address);

/* int      Reg_Routing_Send_One(Node *next_hop, int mode); */
int      Forward_Data(Node *next_hop, sys_scatter *scat, int mode);
int      Request_Resources(int dissemination, Node *next_hop, int mode, int (*callback)(Node *next_hop, int mode));
/* int      Deliver_and_Forward_Data(char *buff, int16u data_len, int mode, Link *src_lnk); */
int      Deliver_and_Forward_Data(sys_scatter *scat, int mode, Link *src_lnk);
int      Fill_Packet_Header( char* hdr, int routing, int16u num_paths );

void     RR_Pre_Conf_Setup();
void     RR_Post_Conf_Setup();
int      RR_Conf_hton(unsigned char *buff);

#endif
