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

#ifndef NODE_H
#define NODE_H

#include "stdutil/stdhash.h"
#include "stdutil/stdskl.h"

#include "spu_events.h"

#include "net_types.h"
#include "link.h"
#include "link_state.h"
#include "network.h"

#ifdef SPINES_WIRELESS
#  include "wireless.h"
#endif

struct Node_d;
struct Edge_d;
struct Interface_d;
struct Network_Leg_d;
struct Link_d;

typedef struct Node_d 
{
  Node_ID             nid;               /* node identifier */
  stdhash             interfaces;        /* known interfaces of this node: <Interface_ID -> Interface*> */
  struct Edge_d      *edge;              /* the edge to this node from This_Node (can be NULL) */
  int16               neighbor_id;       /* index in Neighbor_Nodes array if Is_Connected_Neighbor() */

  /* Routing Variables */

  int16               node_no;           /* ordered id of all the nodes in the system */
  int                 cost;
  int                 distance;

  struct Node_d      *forwarder;

  struct Node_d      *prev;
  struct Node_d      *next;

  char               *device_name;       /* device name to reach this node, if Is_Connected_Neighbor() */ 

} Node;

/* AB: added for cost accounting */
typedef struct Client_ID_d {
    Node_ID daemon_id;
    int16u  client_port;
} Client_ID;

int   Node_ID_cmp(const void *l, const void *r);

void  Init_Nodes(void);

Node *Create_Node(Node_ID nid);
Node *Get_Node(Node_ID nid);
int   Is_Connected_Neighbor(Node_ID nid);
int   Is_Connected_Neighbor2(Node *nd);
void  Disconnect_Node(Node_ID nid);
int   Try_Remove_Node(Node_ID nid);

#endif
