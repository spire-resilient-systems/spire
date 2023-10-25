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
#else
#  include <netinet/in.h>
#endif

#include "arch.h"
#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_memory.h"
#include "stdutil/stdhash.h"
#include "stdutil/stddll.h"

#include "objects.h"
#include "link.h"
#include "node.h"
#include "route.h"
#include "state_flood.h"
#include "link_state.h"
#include "route.h"
#include "multicast.h"
#include "kernel_routing.h"
#include "configuration.h"
#include "multipath.h"

#include "spines.h"

static sp_time Client_Cost_Stats_Timeout = {30, 0};
static sp_time Client_Cost_Print_Target = {0, 0};

void Print_Client_Cost_Stats(int dummy, void *dummy_ptr);

int Node_ID_cmp(const void *l, const void *r)
{
  Node_ID left  = *(Node_ID*) l;
  Node_ID right = *(Node_ID*) r;

  return (left < right ? -1 : (left != right ? 1 : 0));
}

int Client_ID_cmp(const void *l, const void *r)
{
    Client_ID left = *(Client_ID*) l;
    Client_ID right = *(Client_ID*) r;

    if (left.daemon_id < right.daemon_id) {
        return -1;
    } else if (left.daemon_id > right.daemon_id) {
        return 1;
    } else {
        if (left.client_port < right.client_port)
            return -1;
        if (right.client_port < left.client_port)
            return 1;
        else
            return 0;
    }
}

/***********************************************************/
/* void Init_Nodes(void)                                   */
/*                                                         */
/* Initializes/creates the node structures                 */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Init_Nodes(void) 
{
    Node        *node;
    Interface   *interf;
    int16        i, tmp;
    Edge        *edge;
    stdit        it;
    Edge_Key     key;
    Edge_Value  *val_ptr;
    int16u       index;
    sp_time      now, wait_time;
    long int     target_sec;

    Num_Neighbors = 0;

    for(i = 0; i < MAX_LINKS / MAX_LINKS_4_EDGE; ++i) {
        Neighbor_Nodes[i] = NULL;
    }

    stdhash_construct(&All_Nodes,            sizeof(Node_ID),         sizeof(Node*),             NULL, NULL, 0);
    stdskl_construct(&All_Nodes_by_ID,       sizeof(Node_ID),         sizeof(Node*),             Node_ID_cmp);
    stdhash_construct(&Known_Interfaces,     sizeof(Interface_ID),    sizeof(Interface*),        NULL, NULL, 0);
    stdhash_construct(&Known_Addresses,      sizeof(Network_Address), sizeof(Interface*),        NULL, NULL, 0);
    stdhash_construct(&Network_Legs,         sizeof(Network_Leg_ID),  sizeof(Network_Leg*),      NULL, NULL, 0);
    stdhash_construct(&All_Edges,            sizeof(Node_ID),         sizeof(State_Chain*),      NULL, NULL, 0);
    stdhash_construct(&Changed_Edges,        sizeof(Node_ID),         sizeof(Changed_State*),    NULL, NULL, 0);
    stdhash_construct(&All_Groups_by_Node,   sizeof(Node_ID),         sizeof(State_Chain*),      NULL, NULL, 0);
    stdhash_construct(&All_Groups_by_Name,   sizeof(Group_ID),        sizeof(State_Chain*),      NULL, NULL, 0);
    stdhash_construct(&Changed_Group_States, sizeof(Node_ID),         sizeof(Changed_State*),    NULL, NULL, 0);
    stdhash_construct(&Monitor_Params,       sizeof(Network_Leg_ID),  sizeof(struct Lk_Param_d), NULL, NULL, 0);
    /* AB: added for cost accounting */
    stdskl_construct(&Client_Cost_Stats,     sizeof(Client_ID),       sizeof(int32),             Client_ID_cmp);

    for (i = 0; i < MAX_LINKS; ++i) {
      Links[i] = NULL;
    }

    for (i = 0; i < MAX_LINKS_4_EDGE; ++i) {
      Recv_Pack[i].num_elements = 2;
      Recv_Pack[i].elements[0].len = sizeof(packet_header);
      Recv_Pack[i].elements[0].buf = (char*) new_ref_cnt(PACK_HEAD_OBJ);
      Recv_Pack[i].elements[1].len = sizeof(packet_body);
      Recv_Pack[i].elements[1].buf = (char*) new_ref_cnt(PACK_BODY_OBJ);
    }

    /* instantiate this node and its local interfaces specified on command line */

    This_Node = Create_Node(My_Address);

    if (Num_Local_Interfaces == 0) {           /* if no interfaces specified set up an INADDR_ANY one; uses reserved 0 ID for interface ID */

      My_Interface_IDs[Num_Local_Interfaces]       = 0;           /* NOTE: these entries are already 0 (global arrays); this is just for clarity */
      /* My_Interface_Addresses[Num_Local_Interfaces] = INADDR_ANY; */
      My_Interface_Addresses[Num_Local_Interfaces] = My_Address;
      assert(INADDR_ANY == 0);

      ++Num_Local_Interfaces;
    }

    for (i = 0; i != Num_Local_Interfaces; ++i) {

      if (My_Interface_IDs[i] == 0) {
	My_Interface_IDs[i] = My_Interface_Addresses[i];
      }

      Create_Interface(My_Address, My_Interface_IDs[i], My_Interface_Addresses[i]);
    }

    /* Create all nodes that we know from config file */
    for (i = 1; i <= MAX_NODES; i++) {
        if (temp_node_ip[i] != 0) {
            if (Get_Node(temp_node_ip[i]) == NULL)
                Create_Node(temp_node_ip[i]);
        }
    }

    /* Create all edges that we know from config file (we also label each edge
     * with its index, which is used for source-based routing bitmasks)*/
    index = 0;
    stdskl_begin(&Sorted_Edges, &it);
    while (!stdskl_is_end(&Sorted_Edges, &it)) {
        key = *(Edge_Key*)stdskl_it_key(&it);
        val_ptr = (Edge_Value*)stdskl_it_val(&it);
        val_ptr->index = index++;
        tmp = -1;
   
        if (Get_Edge(temp_node_ip[key.src_id], temp_node_ip[key.dst_id]) == NULL)
            edge = Create_Edge(temp_node_ip[key.src_id], temp_node_ip[key.dst_id], tmp, val_ptr->cost, val_ptr->index);
        if (Directed_Edges == 0) {
            if (Get_Edge(temp_node_ip[key.dst_id], temp_node_ip[key.src_id]) == NULL)
                edge = Create_Edge(temp_node_ip[key.dst_id], temp_node_ip[key.src_id], tmp, val_ptr->cost, val_ptr->index);
        }

        stdskl_it_next(&it);
    }

    /* instantiate remote nodes, remote interfaces, edges and network legs specified on command line */

    for (i = 0; i != Num_Legs; ++i) {

      /* fill in default values */

      if (Remote_Interface_IDs[i] == 0) {
	Remote_Interface_IDs[i] = Remote_Interface_Addresses[i];  /* use remote address as remote interface ID */
      }

      if (Remote_Node_IDs[i] == 0) {
	Remote_Node_IDs[i] = Remote_Interface_Addresses[i];  /* use remote address as remote node ID */
      }

      if (Local_Interface_IDs[i] == 0) {
	
	if (Num_Local_Interfaces != 1) {
	  Alarm(EXIT, "-a specification ambiguous as to which local interface should be used!\r\n");
	}

	Local_Interface_IDs[i] = My_Interface_IDs[0];  /* use default local interface */
      }

      /* check if this remote node already exists */

      if ((node = Get_Node(Remote_Node_IDs[i])) == NULL) {
	    node = Create_Node(Remote_Node_IDs[i]);
      }

      /* check if this remote interface already exists */

      if ((interf = Get_Interface(Remote_Interface_IDs[i])) == NULL) {
	    interf = Create_Interface(Remote_Node_IDs[i], Remote_Interface_IDs[i], Remote_Interface_Addresses[i]);

      } else if (interf->owner != node) {
	    Alarm(EXIT, "-a remapped an interface ID " IPF " to a different node " IPF "; should be " IPF "\r\n", 
	      IP(Remote_Interface_IDs[i]), IP(Remote_Node_IDs[i]), IP(interf->owner->nid));
      }

      Create_Network_Leg(Local_Interface_IDs[i], Remote_Interface_IDs[i]);
    }

    Init_Routes();
    Print_Routes(NULL);
    if (Print_Cost) {
      now = E_get_time();
      target_sec = now.sec / 30;
      target_sec = (target_sec + 1) * 30;
      Client_Cost_Print_Target.sec = target_sec;
      Client_Cost_Print_Target.usec = 0;
      wait_time = E_sub_time(Client_Cost_Print_Target, now);
      E_queue(Print_Client_Cost_Stats, 0, NULL, wait_time);
    }
}

/***********************************************************/
/* Create_Node: Creates a new node structure               */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* nid:  identifier of the node                            */
/* mode: type of the node                                  */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* Pointer to created node                                 */
/*                                                         */
/***********************************************************/

Node *Create_Node(Node_ID nid)
{
  Node *nd;
  stdit tit;

  if (Get_Node(nid) != NULL) {
    Alarm(EXIT, "Create_Node: Node " IPF " already exists!\r\n", IP(nid));
  }

  if ((nd = (Node*) new(TREE_NODE)) == NULL) {
    Alarm(EXIT, "Create_Node: Cannot allocte node object!\r\n");
  }

  memset(nd, 0, sizeof(*nd));

  nd->nid = nid;

  if (stdhash_construct(&nd->interfaces, sizeof(Interface_ID), sizeof(Interface*), NULL, NULL, 0) != 0) {
    Alarm(EXIT, "Create_Node: Cannot allocate interfaces object!\r\n");
  }

  nd->edge        = NULL;
  nd->neighbor_id = -1;

  nd->node_no     = -1;
  nd->cost        = -1;
  nd->distance    = -1;

  nd->forwarder   = NULL;
  nd->prev        = NULL;
  nd->next        = NULL;
  nd->device_name = NULL;

  if (stdhash_insert(&All_Nodes, &tit, &nid, &nd) != 0 ||
      stdskl_insert(&All_Nodes_by_ID, &tit, &nid, &nd, STDFALSE) != 0) {
    Alarm(EXIT, "Create_Node: Couldn't insert into All_Nodes!\r\n");
  }

#ifndef ARCH_PC_WIN95
  if (KR_Flags & KR_OVERLAY_NODES) {
    KR_Create_Overlay_Node(nid);
  }
#endif

  Alarm(PRINT, "Create_Node(): Node " IPF " created\r\n", IP(nid));

  return nd;
}

/***********************************************************/
/* Node *Get_Node(Node_ID id)                              */
/*                                                         */
/* Get a node structure by its ID                          */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* id: identifier of the node                              */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* Pointer to Node if it exists, else NULL                 */
/*                                                         */
/***********************************************************/

Node *Get_Node(Node_ID id)
{
  Node *ret = NULL;
  stdit tit;

  if (!stdhash_is_end(&All_Nodes, stdhash_find(&All_Nodes, &tit, &id))) {
    ret = *(Node**) stdhash_it_val(&tit);
  }

  return ret;
}

int Is_Connected_Neighbor(Node_ID nid)
{
  int   ret = 0;
  Node *nd  = Get_Node(nid);

  if (nd != NULL) {
    ret = Is_Connected_Neighbor2(nd);
  }

  return ret;
}

int Is_Connected_Neighbor2(Node *nd)
{
  int ret = (nd->edge != NULL && nd->edge->cost != -1);

  assert(!ret ||
	 (nd->neighbor_id >= 0 && nd->neighbor_id < Num_Neighbors &&
	  nd->edge->src == This_Node && nd->edge->dst != This_Node && 
	  nd->edge->leg != NULL && nd->edge->leg->cost == nd->edge->cost));

  return ret;
}

/***********************************************************/
/* void Disconnect_Node(Node_ID address)                   */
/*                                                         */
/* Disconnects a neighbor node                             */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* address: IP address of the node                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Disconnect_Node(Node_ID address) 
{
  Edge *edge;

  if ((edge = Get_Edge(My_Address, address)) == NULL) {
    Alarm(EXIT, "Disconnect_Node: No local edge to " IPF "!\r\n", IP(address));
  }

  Disconnect_Network_Leg(edge->leg);

  assert(edge->cost == -1);
}

/***********************************************************/
/* int Try_Remove_Node(Node_ID address)                    */
/*                                                         */
/* Garbage collect of orphan nodes (not attached to edges) */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* address: IP address of the node                         */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/*  1 if the node was removed                              */
/*  0 if it wasn't                                         */
/* -1 if error                                             */
/*                                                         */
/***********************************************************/

int Try_Remove_Node(Node_ID address)
{
    stdit it, node_it, src_it;
    int flag;
    State_Chain *s_chain;
    Node* nd;
   
    if(address == My_Address)
	return(0);

    /* See if the  node is the source of an existing edge */
    stdhash_find(&All_Edges, &src_it, &address);
    if(stdhash_is_end(&All_Edges, &src_it)) {
	/* it's not, so let's see if the node is a destination */
	stdhash_begin(&All_Edges, &src_it);
	
	flag = 0;
	while(!stdhash_is_end(&All_Edges, &src_it)) {
	    s_chain = *((State_Chain **)stdhash_it_val(&src_it));
	    stdhash_find(&s_chain->states, &it, &address);
	    if(!stdhash_is_end(&s_chain->states, &it)) {
		flag = 1;
		break;
	    }
	    stdhash_it_next(&src_it); 
	}
		    
	if(flag == 0) {
	    /* The node is not a destination either. Delete the node */ 

	    Alarm(PRINT, "Deleting node: %d.%d.%d.%d\n",
		  IP1(address), IP2(address), IP3(address), IP4(address));

	    stdhash_find(&All_Nodes, &node_it, &address);
	    if(stdhash_is_end(&All_Nodes, &node_it)) { 
		Alarm(PRINT, "Try_Remove_Node(): No node structure !\n");
		return(-1);
	    }
			
	    nd = *((Node **)stdhash_it_val(&node_it));
			
	    stdhash_erase(&All_Nodes, &node_it);
	    stdskl_erase_key(&All_Nodes_by_ID, &address);
	    
	    dispose(nd);

#ifndef ARCH_PC_WIN95
        /* If kernel routing enabled, delete route */
        if (KR_Flags & KR_OVERLAY_NODES) {
            KR_Delete_Overlay_Node(address);
        }
#endif

	    return(1);
	}
    }
    return 0;
}

void Print_Client_Cost_Stats(int dummy, void *dummy_ptr)
{
    stdit it;
    Client_ID *cid;
    int32u *count;
    sp_time now, wait_time;

    Alarm(PRINT, "--- CLIENT COST STATS ---\n");
    for (stdskl_begin(&Client_Cost_Stats, &it); !stdskl_is_end(&Client_Cost_Stats, &it); stdskl_it_next(&it)) {
        cid = (Client_ID *)stdskl_it_key(&it);
        count = (int32u *)stdskl_it_val(&it);
        Alarm(PRINT, "Client ID: (%d.%d.%d.%d, %u), %d msgs\n",
              IP1(cid->daemon_id), IP2(cid->daemon_id), IP3(cid->daemon_id),
              IP4(cid->daemon_id), cid->client_port, *count);
    }
    Alarm(PRINT, "\n");

    Client_Cost_Print_Target = E_add_time(Client_Cost_Print_Target, Client_Cost_Stats_Timeout);
    now = E_get_time();
    wait_time = E_sub_time(Client_Cost_Print_Target, now);
    E_queue(Print_Client_Cost_Stats, 0, NULL, wait_time);
}
