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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#ifdef ARCH_PC_WIN95
#  include <winsock2.h>
#endif

#include "arch.h"
#include "spu_alarm.h"
#include "spu_memory.h"
#include "spu_events.h"
#include "stdutil/stdhash.h"

#define ext_route
#include "route.h"
#undef ext_route

#include "net_types.h"
#include "node.h"
#include "link.h"
#include "objects.h"
#include "state_flood.h"
#include "link_state.h"
#include "kernel_routing.h"
#include "multicast.h"
#include "udp.h"
#include "reliable_udp.h"
#include "realtime_udp.h"
#include "intrusion_tol_udp.h"
#include "priority_flood.h"
#include "reliable_flood.h"

#include "spines.h"

/*********************************************************************
 * Routing_Regime represents the routing state of the system at a
 * particular point in time from the local node's POV.
 ********************************************************************/

typedef struct
{
  int               Num_Nodes;     /* Number of nodes in this route state */
  Node_ID          *Node_IDs;      /* Node_ID Node_IDs[Num_Nodes]: maps a 0-based routing table index to a Node_ID */
  stdhash           Node_Indexes;  /* (Node_ID -> int): maps a Node_Id to its 0-based index in the routing table */

  Route            *Routes;        /* Route Routes[Num_Nodes * Num_Nodes]: routing map in matrix form */

  /* forwarding table for multicast groups; maps a (group, origin) to the set of nodes to forward to */

  stdhash           Groups;        /* (Group_ID -> stdhash(Node_ID -> stdhash(Node_ID -> Node*))): group -> (source -> (neighbor id -> neighbor *)) */

} Routing_Regime;

typedef struct
{
  double start;
  double duration;
  double cubed_part;
  
} Routing_Compute_Duration;

static Routing_Regime          *Current_Routing = NULL;

static int                      Schedule_Set_Route = 0;
static const sp_time            Reroute_Timeout    = { 0, 100 };
/* static Min_Weight_Belly         Reg_Route_Pkt; */

#define NUM_ROUTING_COMPUTE_DURATIONS 20

static long                     Route_Compute_Duration;
static Routing_Compute_Duration Routing_Compute_Durations[NUM_ROUTING_COMPUTE_DURATIONS];

#define SOURCE_HIST_SIZE 100000
typedef struct dummy_seq_pair {
    int32u seq;
    int32u incarnation;
} seq_pair;

static seq_pair Source_Seq_Hist[MAX_NODES+1][SOURCE_HIST_SIZE] = {{{0,0}}};

/*********************************************************************
 * Lookup a node's routing index based on its Node_ID
 *********************************************************************/

static int RR_Get_Node_Index(const Routing_Regime *rr, 
			     Node_ID               nid,
			     int                   exit_on_failure)
{
  int   ret = -1;
  stdit tit;

  if (!stdhash_is_end(&rr->Node_Indexes, stdhash_find(&rr->Node_Indexes, &tit, &nid))) {
    ret = *(int*) stdhash_it_val(&tit);
    assert(ret >= 0 && ret < rr->Num_Nodes);

  } else if (exit_on_failure) {
    Alarm(EXIT, "RR_Get_Node_Index: Lookup of node's (" IPF ") routing table index failed illegally!\n", IP(nid));
  }

  return ret;
}

#if 0
/*********************************************************************
 * Lookup a node's Node_ID based on its routing index
 *********************************************************************/

static Node_ID RR_Get_Node_ID(const Routing_Regime *rr,
			      int                   rindex,
			      int                   exit_on_failure)
{
  Node_ID ret = 0;

  if (rindex >= 0 && rindex < rr->Num_Nodes) {
    ret = rr->Node_IDs[rindex];

  } else if (exit_on_failure) {
    Alarm(EXIT, "RR_Get_Node_ID: Lookup of routing index %d failed illegally!\n", rindex);
  }

  return ret;
}
#endif

/*********************************************************************
 * Lookup a route based on (src, dst) Node_IDs
 *********************************************************************/

static Route *RR_Find_Route(Routing_Regime *rr,
			    Node_ID         src_id,
			    Node_ID         dst_id,
			    int             exit_on_failure)
{
  Route *ret       = NULL;
  int    src_index = RR_Get_Node_Index(rr, src_id, 0);
  int    dst_index = RR_Get_Node_Index(rr, dst_id, 0);

  if (src_index != -1 && dst_index != -1) {
    ret = &rr->Routes[src_index * rr->Num_Nodes + dst_index];

  } else if (exit_on_failure) {
    Alarm(EXIT, "RR_Find_Route: Lookup of route (" IPF ", " IPF ") failed illegally!\n", IP(src_id), IP(dst_id));
  }

  return ret;
}

/*********************************************************************
 * If the local node is on the path from src to dst, then return the
 * neighbor that is next on the path after the local node (if any)
 *********************************************************************/

static Node *RR_Get_Next_Hop(Routing_Regime *rr,
			     Node_ID         src_id,
			     Node_ID         dst_id)
{
  Node  *ret = NULL;
  Route *route;

  if ((route = RR_Find_Route(rr, src_id, dst_id, 0)) != NULL && route->forwarder != NULL) {
    ret = route->forwarder;
  }

  return ret;
}

/*********************************************************************
 * Initializes a Routing_Regime based off current link state info
 * using Floyd-Warshall
 *********************************************************************/

static double RR_Init(Routing_Regime *rr)
{
  int          num_nodes;
  State_Chain *s_chain;
  Edge        *edge;
  Node        *nd;
  Route       *rt;
  stdit        outer_it;
  stdit        inner_it;
  int          src_index;
  int          dst_index;
  Route       *i_k_route;
  Route       *k_j_route;
  Route       *i_j_route;
  int          i;
  int          j;
  int          k;
  sp_time      start;
  sp_time      stop;

  assert(!stdhash_empty(&All_Nodes) && This_Node != NULL && stdhash_size(&All_Nodes) == stdskl_size(&All_Nodes_by_ID));

  memset(rr, 0, sizeof(*rr));

  rr->Num_Nodes = num_nodes = (int) stdhash_size(&All_Nodes);
  
  /* NOTE: we assign route indexes by increasing IDs to ensure routers
     w/ same replicated state will compute in same manner: we all
     choose same routes even for equal cost paths 
  */
  
  if (stdhash_construct(&rr->Node_Indexes, sizeof(Node_ID), sizeof(int), NULL, NULL, 0) != 0) {
    Alarm(EXIT, "RR_Init_Routes: construction of Node_Indexes failed!\n");
  }

  if ((rr->Node_IDs = (Node_ID*) malloc(sizeof(Node_ID) * num_nodes)) == NULL) {
    Alarm(EXIT, "RR_Init_Routes: construction of Node_IDs failed!\n");
  }

  for (i = 0, stdskl_begin(&All_Nodes_by_ID, &outer_it); !stdskl_is_end(&All_Nodes_by_ID, &outer_it); stdskl_it_next(&outer_it), ++i) {

    nd = *(Node**) stdskl_it_val(&outer_it);
    
    if (stdhash_insert(&rr->Node_Indexes, &inner_it, &nd->nid, &i) != 0) {
      Alarm(EXIT, "RR_Init_Routes: insertion into Node_Route_Indexes failed!\n");
    }

    rr->Node_IDs[i] = nd->nid;
  }

  /* allocate + initialize Routes */

  if ((rr->Routes = (Route*) malloc(sizeof(Route) * num_nodes * num_nodes)) == NULL) {
    Alarm(EXIT, "RR_Init_Routes: allocation of Routes failed!\n");    
  }

  for (i = 0; i != num_nodes; ++i) {

    for (j = 0; j != num_nodes; ++j) {

      rt = &rr->Routes[i * num_nodes + j];

      if (i != j) {
	    rt->cost      = -1;
	    rt->distance  = -1;
	
      } else {
	    rt->cost      = 0;
	    rt->distance  = 0;
      }

      rt->forwarder   = NULL;
      rt->predecessor = 0;
    }
  }

  /* fill in known edge information */
  
  for (stdhash_begin(&All_Edges, &outer_it); !stdhash_is_end(&All_Edges, &outer_it); stdhash_it_next(&outer_it)) {

    s_chain = *(State_Chain**) stdhash_it_val(&outer_it);
    
    for (stdhash_begin(&s_chain->states, &inner_it); !stdhash_is_end(&s_chain->states, &inner_it); stdhash_it_next(&inner_it)) {

      edge = *(Edge**) stdhash_it_val(&inner_it);

      if (edge->cost == -1)
        continue;

      /* if (edge->cost < 0) {
	    assert(edge->cost == -1);
	    continue; 
      } */
      
      src_index       = RR_Get_Node_Index(rr, edge->src->nid, 1);
      dst_index       = RR_Get_Node_Index(rr, edge->dst->nid, 1);

      rt              = &rr->Routes[src_index * num_nodes + dst_index];
      /* AB: Made it legal to have negative weight edges for problem type
       * routing, so want to take the absolute value here */
      /*rt->cost        = edge->cost;*/
      rt->cost        = abs(edge->cost);
      rt->distance    = 1;
      rt->predecessor = edge->src->nid;
      rt->forwarder   = (edge->src != This_Node ? NULL : edge->dst);
    }
  }

  /* initialize Groups */

  if (stdhash_construct(&rr->Groups, sizeof(Group_ID), sizeof(stdhash), NULL, NULL, 0) != 0) {
    Alarm(EXIT, "RR_Init_Routes: construction of Groups failed!\n");
  }

  /* compute new routing */

  start = E_get_time();

  for (k = 0; k != num_nodes; ++k) {

    /* for all pairs of nodes (i, j) see if there is a cheaper path
       connecting them through node k */

    for (i = 0; i != num_nodes; ++i) {

      /* NOTE: We skip cases where i_k and/or k_j are disconnected.
	 We skip i == k and j == k cases because i_i + i_j or i_j +
	 j_j paths can't cost less than i_j path.  We skip i == j
	 case because i_i already has 0 cost.  We rely on (x, x)
	 being initialized (and remaining) 0 and all valid costs
	 being non-negative.
      */

      if (i == k || (i_k_route = &rr->Routes[i * num_nodes + k])->cost < 0) {  /* no cheaper path through k */
	continue;
      }

      for (j = 0; j != num_nodes; ++j) {

	if (i == j || j == k ||
	    (k_j_route = &rr->Routes[k * num_nodes + j])->cost < 0) {          /* no cheaper path through k */
	  continue;
	}

	if ((i_j_route = &rr->Routes[i * num_nodes + j])->cost < 0 || 
	    i_k_route->cost + k_j_route->cost < i_j_route->cost) {             /* found a cheaper path through k */

	  i_j_route->cost        = i_k_route->cost + k_j_route->cost;
	  i_j_route->distance    = i_k_route->distance + k_j_route->distance;
	  i_j_route->predecessor = rr->Node_IDs[k];
	  i_j_route->forwarder   = (k_j_route->forwarder != NULL ? k_j_route->forwarder : i_k_route->forwarder);
	}
      }
    }
  }

  stop = E_get_time();

  return (stop.sec - start.sec) + (stop.usec - start.usec) / 1.0e6;
}

/*********************************************************************
 * RR_Fini: Destroys a Routing_Regime + reclaims its resources.
 *********************************************************************/

static void RR_Fini(Routing_Regime *rr)
{
  stdit    outer_it;
  stdhash *inner;
  stdit    inner_it;

  for (stdhash_begin(&rr->Groups, &outer_it); !stdhash_is_end(&rr->Groups, &outer_it); stdhash_it_next(&outer_it)) {

    inner = (stdhash*) stdhash_it_val(&outer_it);

    for (stdhash_begin(inner, &inner_it); !stdhash_is_end(inner, &inner_it); stdhash_it_next(&inner_it)) {

      stdhash_destruct((stdhash*) stdhash_it_val(&inner_it));
    }

    stdhash_destruct(inner);
  }

  stdhash_destruct(&rr->Groups);

  free(rr->Routes);
  stdhash_destruct(&rr->Node_Indexes);
  free(rr->Node_IDs);
  /* AB: added to fix memory leak */
  free(rr);
}

/*********************************************************************
 * Returns a stdhash of Node's to which the local node should forward
 * a source based multicast.
 *********************************************************************/

static stdhash *RR_Get_Mcast_Neighbors(Routing_Regime *rr,
				       Node_ID         sender,         /* originator of send */
				       Group_ID        mcast_address)  /* destination group */
{
  stdhash     *neighbors     = NULL;
  Node        *best_next_hop = NULL;
  State_Chain *s_chain_grp;
  stdhash     *groups;
  stdhash     *sources;
  Group_State *g_state;
  Node        *next_hop;
  stdit        grp_it;
  stdit        src_it;
  stdit        ngb_it;
  stdit        st_it;
  stdhash      dmy;

  /* look up the group in the multicast group state */

  if (stdhash_is_end(&All_Groups_by_Name, stdhash_find(&All_Groups_by_Name, &grp_it, &mcast_address))) {
    return NULL;
  }

  s_chain_grp = *(State_Chain**) stdhash_it_val(&grp_it);

  /* look up the group in the routing state */

  groups = &rr->Groups;

  if (stdhash_is_end(groups, stdhash_find(groups, &grp_it, &mcast_address))) {

    if (stdhash_insert(groups, &grp_it, &mcast_address, &dmy) != 0 ||
	stdhash_construct((stdhash*) stdhash_it_val(&grp_it), sizeof(Node_ID), sizeof(stdhash), NULL, NULL, 0) != 0) {
      Alarm(EXIT, "RR_Get_Mcast_Neighbors(): Cannot allocate memory\n");
    }
  }

  /* return any cached forwarding we already have for this (group, source) */
  /* NOTE: the cached forwarding for a group is wiped out each time the group changes (see multicast.c) */

  sources = (stdhash*) stdhash_it_val(&grp_it);

  if (!stdhash_is_end(sources, stdhash_find(sources, &src_it, &sender))) {

    neighbors = (stdhash*) stdhash_it_val(&src_it);

  } else {  /* build an answer on demand and store in the cache */
    
    if (stdhash_insert(sources, &src_it, &sender, &dmy) != 0 ||
	stdhash_construct((stdhash*) stdhash_it_val(&src_it), sizeof(Node_ID), sizeof(Node*), NULL, NULL, 0) != 0) {
      Alarm(EXIT, "RR_Get_Mcast_Neighbors(): Cannot allocate memory 2\n");
    }

    neighbors = (stdhash*) stdhash_it_val(&src_it);

    for (stdhash_begin(&s_chain_grp->states, &st_it); !stdhash_is_end(&s_chain_grp->states, &st_it); stdhash_it_next(&st_it)) {

      g_state = *(Group_State**) stdhash_it_val(&st_it);

      if (g_state->status & ACTIVE_GROUP) {

	/* if its any acast and I'm registered, then I am the final destination -> empty neighbors */

	if (Is_acast_addr(mcast_address) && g_state->node_nid == My_Address) {
	  best_next_hop = NULL;
	  break;
	}
      
	if ((next_hop = RR_Get_Next_Hop(rr, sender, g_state->node_nid)) != NULL) {

	  if (Is_mcast_addr(mcast_address)) { 

	    if (stdhash_put(neighbors, &ngb_it, &next_hop->nid, &next_hop) != 0) {
	      Alarm(EXIT, "RR_Get_Mcast_Neighbors: Couldn't insert into neighbors!\r\n");
	    }

	  } else if (Is_acast_addr(mcast_address)) {

	    if (best_next_hop == NULL || next_hop->cost < best_next_hop->cost) {
	      best_next_hop = next_hop;
	    }
	  }
	}
      }
    }

    if (Is_acast_addr(mcast_address) && best_next_hop != NULL && 
	stdhash_insert(neighbors, &ngb_it, &best_next_hop->nid, &best_next_hop) != 0) {
      Alarm(EXIT, "RR_Get_Mcast_Neighbors: Couldn't insert into neighbors 2!\n");
    }
  }

  return neighbors;
}

/*********************************************************************
 * Discard any cached source based multicast forwarding tables for a group
 *********************************************************************/

static void RR_Discard_Mcast_Neighbors(Routing_Regime *rr,
				       Group_ID        mcast_address) 
{
  stdhash *sources;
  stdhash *neighbors;
  stdit    grp_it;
  stdit    src_it;
    
  if (!stdhash_is_end(&rr->Groups, stdhash_find(&rr->Groups, &grp_it, &mcast_address))) {

    sources = (stdhash*) stdhash_it_val(&grp_it);

    for (stdhash_begin(sources, &src_it); !stdhash_is_end(sources, &src_it); stdhash_it_next(&src_it)) {

      neighbors = (stdhash*) stdhash_it_val(&src_it);
      stdhash_destruct(neighbors);
    }

    stdhash_destruct(sources);
    stdhash_erase(&rr->Groups, &grp_it);
  }
}

/*********************************************************************
 * Initializes routing subsystem; call after nodes + edges init'ed
 *********************************************************************/

void Init_Routes(void)
{
  assert(Current_Routing == NULL);
  Set_Routes(0, NULL);
  My_Source_Seq = 0;
  My_Source_Incarnation = E_get_time().sec;
}

/*********************************************************************
 * Schedule routing computation to be done
 *********************************************************************/

void Schedule_Routes(void)
{
  if (!Schedule_Set_Route) {    
    E_queue(Set_Routes, 0, NULL, Reroute_Timeout);
    Schedule_Set_Route = 1;
  }
}

/*********************************************************************
 * Computes all-pairs shortest paths based on current link state
 *********************************************************************/

void Set_Routes(int dummy_int, void *dummy_ptr) 
{
  sp_time           start = E_get_time();
  sp_time           stop;
  double            duration;
  double            cubed_part;
  int               i;

  Schedule_Set_Route = 0;
  E_dequeue(Set_Routes, 0, NULL);

  memmove(Routing_Compute_Durations + 1, Routing_Compute_Durations, (NUM_ROUTING_COMPUTE_DURATIONS - 1) * sizeof(Routing_Compute_Duration));
    
  /* try to force any pending state floods to go out b4 we incorporate them into our routing state */

  Send_State_Updates(0, &Edge_Prot_Def);

  /* allocate + initialize new Routing_Regime */

  if (Current_Routing != NULL) {
    RR_Fini(Current_Routing);
  }

  if ((Current_Routing = (Routing_Regime*) malloc(sizeof(Routing_Regime))) == NULL) {
    Alarm(EXIT, "Set_Routes: Failed allocating Current_Routing!\n");
  }

  cubed_part = RR_Init(Current_Routing);

  stop                                    = E_get_time();
  duration                                = (stop.sec - start.sec) + (stop.usec - start.usec) / 1.0e6;
  Routing_Compute_Durations[0].start      = start.sec + start.usec / 1.0e6;
  Routing_Compute_Durations[0].duration   = duration;
  Routing_Compute_Durations[0].cubed_part = cubed_part;

  for (i = 1; i < NUM_ROUTING_COMPUTE_DURATIONS && Routing_Compute_Durations[0].start - Routing_Compute_Durations[i].start <= 1.0; ++i) {
    duration   += Routing_Compute_Durations[i].duration;
    cubed_part += Routing_Compute_Durations[i].cubed_part;
  }

  if (duration >= 0.001) {
    Alarm(PRINT, "Set_Routes: *** WARNING *** Spent %f seconds (%f seconds in N^3 portion) computing routes over the last second!!!\n", duration, cubed_part);
  }

  Route_Compute_Duration  = (stop.sec - start.sec) * 1000000;
  Route_Compute_Duration += stop.usec - start.usec;
  
#ifndef ARCH_PC_WIN95
  if (KR_Flags != 0) {
    KR_Update_All_Routes();
  }
#endif
}

/*********************************************************************
 * Returns a route from the Current_Routing (if it exists)
 *********************************************************************/

Route *Find_Route(Node_ID src_id, Node_ID dst_id)
{
  return RR_Find_Route(Current_Routing, src_id, dst_id, 0);
}

/*********************************************************************
 * If the local node is on the path from src to dst, then return the
 * neighbor that is next on the path after the local node (if any)
 *********************************************************************/

Node *Get_Route(Node_ID src_id, Node_ID dst_id)
{
  return RR_Get_Next_Hop(Current_Routing, src_id, dst_id);
}

/*********************************************************************
 * Returns a traceroute from src_id to dst_id
 *********************************************************************/

static int Trace_Route_Rcrsv(Node_ID src_id, Node_ID dst_id, spines_trace *spines_tr, int i)
{
  Route *route;

  /* NOTE: When you look up the Route from src_id to dst_id, the
     predecessor marked on the route is one node somewhere on the path
     between them.  So, now you need to recurse on the src_id to
     predecessor and predecessor to dst_id paths to fill in all the
     nodes on the path. Each level down you learn of a new node on the
     overall path (the predecessor) and you need to recurse down both
     to the "left" and "right" sides of the new predecessor until you
     get to self loops.

     Finally, we want to number the hops along the overall path from
     the original src to dst with an increasing index, which is the
     purpose of 'i.'

     If you think of the path as a binary tree then we are doing an
     in-order traversal where i acts as a counter of visitation /
     recording the hops starting from the overall src and ending with
     the overall dst.
  */

  if (src_id == dst_id || i == MAX_COUNT) {
    return i;
  }

  if ((route = Find_Route(src_id, dst_id)) == NULL || route->predecessor == 0) {
    Alarm(EXIT, "Trace_Route_Rcrsv: Routing BUG!!!\n");
  }

  i = Trace_Route_Rcrsv(src_id, route->predecessor, spines_tr, i);

  spines_tr->address[i]  = route->predecessor;
  spines_tr->cost[i]     = route->cost;
  spines_tr->distance[i] = route->distance;
  
  i = Trace_Route_Rcrsv(route->predecessor, dst_id, spines_tr, i + 1);

  return i;
}

void Trace_Route(Node_ID src_id, Node_ID dst_id, spines_trace *spines_tr)
{
  Route *route;

  if ((route = Find_Route(src_id, dst_id)) == NULL) {      /* protect against "malicious" user input */

    if (src_id != dst_id && route->predecessor != 0) {     /* there is something to trace */

      spines_tr->count = Trace_Route_Rcrsv(src_id, dst_id, spines_tr, 0);

    } else {                                               /* loop back or no route */
      spines_tr->address[0]  = src_id;
      spines_tr->cost[0]     = route->cost;
      spines_tr->distance[0] = route->distance;
      spines_tr->count       = 1;
    }

  } else {
    spines_tr->count = 0;
  }
}

/*********************************************************************
 * Prints current routes (optionally to a file as well) 
 *********************************************************************/

void Print_Routes(FILE *fp) 
{
  char   line[256];
  Node  *nd;
  Route *route;
  stdit  tit;

  sprintf(line, "ROUTES: F-W compute time was %ld (us)", Route_Compute_Duration);
  Alarm(PRINT, "%s\n\n", line);
  if (fp != NULL) fprintf(fp, "%s\n\n", line);

  for (stdhash_begin(&All_Nodes, &tit); !stdhash_is_end(&All_Nodes, &tit); stdhash_it_next(&tit)) {

    if ((nd = *(Node**) stdhash_it_val(&tit)) == This_Node) {

      sprintf(line, IPF " LOCAL NODE", IP(My_Address));
      Alarm(PRINT, "%s\n", line);
      if (fp != NULL) fprintf(fp, "%s\n", line);

    } else if ((route = Find_Route(My_Address, nd->nid)) != NULL &&
	       route->forwarder != NULL) {

      sprintf(line, IPF " via: " IPF " cost: %d; dist: %d", 
	      IP(nd->nid), IP(route->forwarder->nid), route->cost, route->distance);
      
      Alarm(PRINT, "%s\n", line);
      if (fp != NULL) fprintf(fp, "%s\n", line);

    } else {
      sprintf(line, IPF " NO ROUTE!!!", IP(nd->nid));
      Alarm(PRINT, "%s\n", line);
      if (fp != NULL) fprintf(fp, "%s\n", line);
    }
  }

  Alarm(PRINT, "\n\n");
  if (fp != NULL) fprintf(fp, "\n\n");
}

/***********************************************************/
/* Returns a hash with neighbors to which the mcast or     */
/* acast packet needs to be forwarded                      */
/***********************************************************/

stdhash *Get_Mcast_Neighbors(Node_ID  sender,         /* originator of send */
			     Group_ID mcast_address)  /* destination group */
{
  return RR_Get_Mcast_Neighbors(Current_Routing, sender, mcast_address);
}

/***********************************************************/
/* Discards the hash with neighbors to which the a group's */
/* mcast packets are forwarded                              */
/***********************************************************/
 
void Discard_Mcast_Neighbors(Group_ID mcast_address) 
{
  RR_Discard_Mcast_Neighbors(Current_Routing, mcast_address);
}

/*********************************************************************
 * Forward message to all neighbors that are marked to get this message
 *  on the bitmask
 *********************************************************************/

int Source_Based_Disseminate(Link *src_link, sys_scatter *scat, int mode)
{
    int32u i, last_hop_ip, src_id, seq_index;
    stdit it;
    udp_header *hdr;
    sb_header *s_hdr;
    Node *nd;
    unsigned char *routing_mask, *path;
    seq_pair prev_seq;

    hdr = (udp_header *)scat->elements[1].buf;
    s_hdr = (sb_header *)scat->elements[scat->num_elements-1].buf;
    routing_mask = (unsigned char*)((char*)s_hdr + sizeof(sb_header));

    /* Look up source to see if this is a duplicate source sequence */
    stdhash_find(&Node_Lookup_Addr_to_ID, &it, &hdr->source);
    if (stdhash_is_end(&Node_Lookup_Addr_to_ID,  &it)) {
        Alarm(PRINT, "Source_Based_Disseminate: Source node %d not in config file\n", hdr->source);
        return NO_ROUTE;
    }
    src_id = *(int32u *)stdhash_it_val(&it);

    /* Check whether we have already seen this packet; if so, don't forward again */
    seq_index = s_hdr->source_seq % SOURCE_HIST_SIZE;
    prev_seq = Source_Seq_Hist[src_id][seq_index];
    if (prev_seq.seq == s_hdr->source_seq && prev_seq.incarnation == s_hdr->source_incarnation) {
        Alarm(DEBUG, "Source_Based_Disseminate: Duplicate Packet with source seq %u, %u...dropping\n", s_hdr->source_seq, s_hdr->source_incarnation);
        return NO_ROUTE;
    }

     /* If the packet is so old we can't tell whether it is a duplicate or not,
      * just throw it away.
      * NOTE: check whether this breaks the reliable link protocol (but
      * reliable links don't currently work with source based routing
      * anyway...) */
    if (prev_seq.incarnation > s_hdr->source_incarnation ||
       (prev_seq.seq > s_hdr->source_seq && prev_seq.incarnation == s_hdr->source_incarnation)) {
        Alarm(PRINT, "Source_Based_Disseminate: got very old packet (past "
                     "deduplication window) from %u with source seq %u, %u; already "
                     "had %u, %u...dropping\n", src_id, s_hdr->source_seq, s_hdr->source_incarnation,
                     prev_seq.seq, prev_seq.incarnation);
        return NO_ROUTE;
    }

    Source_Seq_Hist[src_id][seq_index].seq = s_hdr->source_seq;
    Source_Seq_Hist[src_id][seq_index].incarnation = s_hdr->source_incarnation;

    if (src_link == NULL)
        last_hop_ip = My_Address;
    else
        last_hop_ip = src_link->leg->remote_interf->net_addr;

    /* If we are doing Path stamping, do it now */
    if (Path_Stamp_Debug == 1) {
        path = ((unsigned char *) scat->elements[1].buf) + sizeof(udp_header) + 16;
        for (i = 0; i < 8; i++) {
            if (path[i] == 0) {
                path[i] = (unsigned char) My_ID;
                break;
            }
        }
    }

    /* Loop through all neighbors, sending to those that are marked on
     *  the bitmask */
    for (i = 1; i <= Degree[My_ID]; i++) {

        /* If this is the neighbor that sent me the message, or this neighbor is
         *   creator of the message, or I'm the destination, or this neighbor is
         *   not set to receive this message, just do nothing */
        if ( (Neighbor_Addrs[My_ID][i] == last_hop_ip) ||
             (Neighbor_Addrs[My_ID][i] == hdr->source) ||
             (My_Address == hdr->dest) ||
             (!MultiPath_Neighbor_On_Path(routing_mask, i)) )
        {
            continue;
        }

        /* We send the message to this neighbor, grab the Node object for
         * this neigbor and forward data */
        stdhash_find(&All_Nodes, &it, &Neighbor_Addrs[My_ID][i]);
        if (stdhash_is_end(&All_Nodes, &it))
            continue;

        /* Forward the data to this node */
        nd = *((Node **)stdhash_it_val(&it)); 
        Forward_Data(nd, scat, mode);
    }

    return BUFF_OK;
}

/*********************************************************************
 * Forward a data packet using a protocol
 *********************************************************************/

int Forward_Data(Node *next_hop, sys_scatter *scat, int mode)
{
  int ret = -1;

  if (next_hop == This_Node) {
    Alarm(EXIT, "Forward_Data: BUG!!! Trying to forward to myself?!\n");
  }

  switch (mode) {

  case UDP_LINK:
    ret = Forward_UDP_Data(next_hop, scat);
    break;

  case RELIABLE_UDP_LINK:
    ret = Forward_Rel_UDP_Data(next_hop, scat, 0);
    break;

  case REALTIME_UDP_LINK:
    ret = Forward_RT_UDP_Data(next_hop, scat);
    break;

  case INTRUSION_TOL_LINK:
    ret = Forward_Intru_Tol_Data(next_hop, scat);
    break;

  case CONTROL_LINK:
    Alarm(EXIT, "Forward_Data: CONTROL_LINK traffic should not be routed + forwarded?!\r\n");
    break;

  case RESERVED0_LINK:
  case RESERVED1_LINK:
  case MAX_LINKS_4_EDGE:
  default:
    Alarm(EXIT, "Forward_Data: Unrecognized link type 0x%x!\r\n", mode);
    break;
  }

  return ret;
}


/*********************************************************************
 * Request Resources from the lower level to send a packet.
 *********************************************************************/

int Request_Resources(int dissemination, Node* next_hop, int mode, 
                            int (*callback)(Node* next_hop, int mode))
{
    int ret = 0;

    /* Check if callback is NULL */
    /* if ( ) */

    switch(mode) {
        
        case UDP_LINK:
            ret = Request_Resources_UDP(next_hop, callback);
            break;

        case RELIABLE_UDP_LINK:
            ret = Request_Resources_Rel_UDP(next_hop, callback);
            break;

        case REALTIME_UDP_LINK:
            ret = Request_Resources_RT_UDP(next_hop, callback);
            break;

        case INTRUSION_TOL_LINK:
            ret = Request_Resources_IT(dissemination, next_hop, callback);
            break;

        case CONTROL_LINK:
        case RESERVED0_LINK:
        case RESERVED1_LINK:
        case MAX_LINKS_4_EDGE:
        default:
            Alarm(EXIT, "Request_Resources: Unrecognized link type 0x%x!\r\n", mode);
            break;
    }

    return ret;
}

/*********************************************************************
 * Deliver and Forward a data packet as appropriate.
 *********************************************************************/

int Deliver_and_Forward_Data(sys_scatter *scat, int mode, Link *src_lnk)
{
  int             forwarded = 0;
  int             ret = NO_ROUTE;
  udp_header     *hdr = (udp_header*) scat->elements[1].buf;
  int             routing = ((int) hdr->routing << ROUTING_BITS_SHIFT);
  Routing_Regime *rr;
  Node           *next_hop;
  stdhash        *neighbors;
  stdit           ngb_it;
  Group_State    *gstate;

  if (hdr->ttl <= 0) {
    /* printf("src_port = %u, dst_port = %u, routing = %d\n", hdr->source_port, 
                hdr->dest_port, routing); */
    Alarm(PRINT, "Deliver_and_Forward_Data: Non-positive TTL before decrement?!\r\n");
    return ret;
  }

  --hdr->ttl;

  switch (routing) {

  case MIN_WEIGHT_ROUTING:
    rr = Current_Routing;
    assert(rr != NULL);

    if (!Is_mcast_addr(hdr->dest) && !Is_acast_addr(hdr->dest)) {        /* point-to-point traffic */
  
        if (hdr->dest != My_Address && hdr->ttl > 0 && 
            (next_hop = RR_Get_Next_Hop(rr, hdr->source, hdr->dest)) != NULL) {
                assert(next_hop != This_Node);
                ret = Forward_Data(next_hop, scat, mode);
                Alarm(DEBUG, "Deliver_and_Forward_Data: Forwarding unicast traffic to " IPF " %d!\r\n", 
                    IP(next_hop->nid), ret);
        }
    } else {                                                             /* multicast traffic */

        if (hdr->ttl > 0 && (neighbors = RR_Get_Mcast_Neighbors(rr, hdr->source, hdr->dest)) != NULL) {

            for (stdhash_begin(neighbors, &ngb_it); !stdhash_is_end(neighbors, &ngb_it); 
                stdhash_it_next(&ngb_it)) {
              next_hop = *(Node**) stdhash_it_val(&ngb_it);
	          assert(next_hop != This_Node);

	          if (Is_Connected_Neighbor2(next_hop)) {  /* might have disconnected since that routing regime */
	              ret = Forward_Data(next_hop, scat, mode);
	              forwarded = 1;
	              Alarm(DEBUG, "Deliver_and_Forward_Data: Forwarding multicast traffic to " IPF " %d!\r\n", 
                      IP(next_hop->nid), ret);
	          }
            }
        } else {
            Alarm(DEBUG, "Deliver_and_Forward_Data: Not forwarding multicast traffic!\r\n");
        }
    }
    break;

  case SOURCE_BASED_ROUTING:
    ret = Source_Based_Disseminate(src_lnk, scat, mode);
    if (ret == NO_ROUTE)
        goto END;
    break;

  case IT_PRIORITY_ROUTING:
    ret = Priority_Flood_Disseminate(src_lnk, scat, mode);
    if (ret == NO_ROUTE) 
        goto END;
    break;

  case IT_RELIABLE_ROUTING:
    ret = Reliable_Flood_Disseminate(src_lnk, scat, mode);
    if (ret == NO_ROUTE) 
        goto END;
    break;

  default:
    Alarm(PRINT, "Deliver_and_Forward_Data: Unknown routing (%d) requested! Ignoring!\r\n", routing);
    goto END;
  }

  /* IT Site Multicast: If this message is destined for me (daemon/site) and is marked
   * for Site Multicast (Port range 65280 to 65535), change the destination address to 
   * the multicast group that will be delivered to all clients connected to this daemon 
   * that have joined this group */
  if (hdr->dest == My_Address && 
        (routing == IT_RELIABLE_ROUTING || routing == IT_PRIORITY_ROUTING) && 
        hdr->dest_port >= 0xFF00 && hdr->dest_port <= 0xFFFF) 
  {
    Alarm(DEBUG,"hdr->source = "IPF", hdr->source_port = %d, hdr->dest = "IPF", hdr->dest_port = %d\n", 
            IP(hdr->source), hdr->source_port, IP(hdr->dest), hdr->dest_port);
    hdr->dest = 0xFEFF0000 | (hdr->dest_port & 0x00FF);
    Alarm(DEBUG, "  converted to "IPF"\n", IP(hdr->dest));
  }

  /* COMMON FUNCTIONALITY --> DELIVER_UDP TO CLIENTS */
  if (!Is_mcast_addr(hdr->dest) && !Is_acast_addr(hdr->dest)) {        /* point-to-point traffic */

    if (hdr->dest == My_Address) {
      ret = Deliver_UDP_Data(scat, routing);
      Alarm(DEBUG, "Deliver_and_Forward_Data: Delivering unicast traffic locally! %d\r\n", ret);

    } else {
      Alarm(DEBUG, "Deliver_and_Forward_Data: Swallowing unicast traffic!\r\n");
    }

  } else {                                                             /* multicast traffic */

    if ((gstate = (Group_State*) Find_State(&All_Groups_by_Node, My_Address, hdr->dest)) != NULL &&
	(gstate->status & ACTIVE_GROUP)) {                                 /* i'm an active member of the group */
      ret = Deliver_UDP_Data(scat, routing);
      forwarded = 1;
      Alarm(DEBUG, "Deliver_and_Forward_Data: Delivering multicast traffic locally %d!\r\n", ret);
    }
    if (!forwarded && src_lnk != NULL) {
        Alarm(DEBUG, "Deliver_and_Foward_Data: Blackhole for multicast!!!\n");
    }
  }

 END:
  return ret;
}

int Fill_Packet_Header( char* hdr, int routing, int16u num_paths ) {
   
    switch(routing) {
        case IT_PRIORITY_ROUTING:
            return Fill_Packet_Header_Best_Effort_Flood(hdr);
            break;
        case IT_RELIABLE_ROUTING:
            return Fill_Packet_Header_Reliable_Flood(hdr,num_paths);
            break;
        default:
            return 0;
    }
}


/***********************************************************/
/* void RR_Pre_Conf_Setup()                                */
/*                                                         */
/* Setup configuration file defaults for Regular Routing   */
/*                                                         */
/* Return: NONE                                            */
/*                                                         */
/***********************************************************/
void     RR_Pre_Conf_Setup() 
{
    Conf_RR.Crypto = RR_CRYPTO;
}

/***********************************************************/
/* void RR_Post_Conf_Setup()                               */
/*                                                         */
/* Sets up timers and data structures after reading from   */
/* the configuration file for Priority Flooding            */
/*                                                         */
/* Return: NONE                                            */
/*                                                         */
/***********************************************************/
void     RR_Post_Conf_Setup()
{
    
}

/***********************************************************/
/* int RR_Conf_hton(unsigned char *buff)                   */
/*                                                         */
/* Converts host storage of configuration parameters into  */
/* network format and writes to buff.                      */
/*                                                         */
/* Return: # of bytes written                              */
/*                                                         */
/***********************************************************/
int      RR_Conf_hton(unsigned char *buff)
{
    unsigned char *write = (unsigned char*)buff;

    *(unsigned char*)write = Conf_RR.Crypto;
        write += sizeof(unsigned char);

    return sizeof(CONF_RR);
}
