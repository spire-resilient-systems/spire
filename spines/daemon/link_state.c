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
#include <math.h>
#include <assert.h>

#ifdef ARCH_PC_WIN95
#  include <winsock2.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>

#include "arch.h"
#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_memory.h"

#include "stdutil/stdhash.h"

#include "objects.h"
#include "link.h"
#include "node.h"
#include "route.h"
#include "link_state.h"
#include "state_flood.h"
#include "net_types.h"
#include "hello.h"
#include "kernel_routing.h"
#include "multipath.h"
#include "dissem_graphs.h"
#include "spines.h"

#define MAX_RETR_DELAY 30

static Link_State_LTS Link_State_Update_LTS = 0;

/***********************************************************/
/* Returns the hash containing all the known edges         */
/***********************************************************/

stdhash *Edge_All_States(void)
{
  return &All_Edges;
}

/***********************************************************/
/* Returns the hash containing all the known edges         */
/*         indexed by destination. Not used.               */
/***********************************************************/

stdhash *Edge_All_States_by_Dest(void)
{
  return NULL;
}

/***********************************************************/
/* Returns the hash containing the buffer of changed edges */
/***********************************************************/

stdhash *Edge_Changed_States(void)
{
  return &Changed_Edges;
}

/***********************************************************/
/* Returns the packet header type for link-state msgs.     */
/***********************************************************/

int Edge_State_type(void)
{
  return LINK_STATE_TYPE;
}

/***********************************************************/
/* Returns the size of the link_state header               */
/***********************************************************/

int Edge_State_header_size(void)
{
  return (int) sizeof(link_state_packet);
}

/***********************************************************/
/* Returns the size of the link_state cell                 */
/***********************************************************/

int Edge_Cell_packet_size(void)
{
  return (int) sizeof(edge_cell_packet);
}

/***********************************************************/
/* Returns true, link state changes affect routing ...     */
/***********************************************************/

int Edge_Is_route_change(void) 
{
  return 1;
}

/***********************************************************/
/* Returns true if the edge is not deleted, else false     */
/* so that the edge will not be resent, and eventually     */
/* will be garbage-collected                               */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* state: pointer to the edge structure                    */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int) 1 if edge is up                                   */
/*       0 otherwise                                       */
/***********************************************************/

int Edge_Is_state_relevant(void *state)
{
  return ((Edge*) state)->cost >= 0;
}

/***********************************************************/
/* Sets the link_state_packet header additional fields     */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* state: pointer to the edge structure                    */
/* pos: pointer to where to set the fields in the packet   */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int) Number of bytes set                               */
/***********************************************************/

int Edge_Set_state_header(void *state, char *pos)
{
  return 0;  /* Nothing for now ... */
}

/***********************************************************/
/* Sets the link_state cell additional fields              */
/* (cost, maybe loss rate, etc.)                           */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* state: pointer to the edge structure                    */
/* pos: pointer to where to set the fields in the packet   */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int) Number of bytes set                               */
/***********************************************************/

int Edge_Set_state_cell(void *state, char *pos)
{
  Edge *edge = (Edge*) state;

  memcpy(pos, &edge->lts, sizeof(Link_State_LTS));
  
  /* TODO: the way additional headers are added onto packets and cells
     is ripe for error.  Because we use sizeof(struct X) and cast
     pointers to buffers to those structs we have to account for all
     structure padding in any of our math.  At the very least we
     should check on serialization that how many bytes we write out
     matches up with how many bytes we would expect to read out. */

  return (int) (sizeof(edge_cell_packet) - sizeof(State_Cell));
}

/***********************************************************/
/* Process the link_state_packet header additional fields  */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* pos: pointer to where to set the fields in the packet   */
/* type: contains the endianess of the message             */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int) Number of bytes processed                         */
/***********************************************************/

void Edge_Process_state_header(char *pos, int32 type)
{
  link_state_packet *lk_st_pkt = (link_state_packet*) pos; 

  if (!Same_endian(type)) {
    lk_st_pkt->source    = Flip_int32(lk_st_pkt->source);
    lk_st_pkt->num_edges = Flip_int16(lk_st_pkt->num_edges);
    lk_st_pkt->src_data  = Flip_int16(lk_st_pkt->src_data);
  }
}

/***********************************************************/
/* Destroys specific info from the edge structure          */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* state: edge                                             */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int)  1 if ok; -1 if not                               */
/***********************************************************/

int Edge_Destroy_State_Data(void *state)
{
  return 1;
}

/***********************************************************/
/* Processes the link_state cell additional fields         */
/* (cost, maybe loss rate, etc.)                           */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* source: Origin of the edge                              */
/* sender: Sender of the edge                              */
/* pos: pointer to the begining of the cell                */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (void*) pointer to the edge processed (new or old)      */
/***********************************************************/

void *Edge_Process_state_cell(Node_ID source, Node_ID sender, char *pos, int32 type)
{
  edge_cell_packet *edge_cell = (edge_cell_packet*) pos; 
  Node             *nd_source;
  Node             *nd_dest;
  Edge             *edge;

  if (!Same_endian(type)) {
    edge_cell->lts = Flip_int16(edge_cell->lts);
  }

  if ((nd_source = Get_Node(source)) == NULL) {
    nd_source = Create_Node(source);
  }

  if ((nd_dest = Get_Node(edge_cell->dest)) == NULL) {
    nd_dest = Create_Node(edge_cell->dest);
  }
  
  if ((edge = Get_Edge(nd_source->nid, nd_dest->nid)) == NULL) {

    /* AB: I decided to give edges that aren't known from the configuration
     * file a base cost of -1 and index of USHRT_MAX to indicate that we don't
     * have a real cost or index for them */
    edge = Create_Edge(nd_source->nid, nd_dest->nid, -1, -1, USHRT_MAX);

    if (nd_source == This_Node) {
      /* TODO: figure out what to do with this situation (e.g. - just rely on remote hellos to create correct leg?) */
      Alarm(PRINT, "Edge_Process_state_cell: informed of an unknown local outbound edge, "
	    "but I don't know the right network leg(s) to use?!\r\n");
    }
  }

  /* update link state lts */

  if (Link_State_LTS_cmp(edge_cell->lts, Link_State_Update_LTS) > 0) {
    Link_State_Update_LTS = edge_cell->lts;
  }

  /* update replicated entry */

  edge->timestamp_sec  = edge_cell->timestamp_sec;
  edge->timestamp_usec = edge_cell->timestamp_usec;

  /* check if this edge is one of my outbound edges */

  if (source != My_Address) {  /* nope */

    Alarm(DEBUG, "Updating edge (from state flood) (LTS = %u): " IPF " -> " IPF "; %hd -> %hd\r\n", 
	  edge_cell->lts, IP(edge->src->nid), IP(edge->dst->nid), edge->cost, edge_cell->cost);

    DG_Process_Edge_Update(edge, edge_cell->cost);

    edge->age  = edge_cell->age;
    edge->cost = edge_cell->cost;
    edge->lts  = edge_cell->lts;

    /* Clear the cache stored for the K-paths calculation */
    MultiPath_Clear_Cache();

    return edge;

  } else {  /* I will publish my own edges' costs and ages thank you very much! */

    if (++edge->timestamp_usec >= 1000000) {
      ++edge->timestamp_sec;
      edge->timestamp_usec = 0;
    }

    edge->lts = Link_State_LTS_inc();

    Add_to_changed_states(&Edge_Prot_Def, My_Address, (State_Data*) edge);
    
    return NULL;  /* don't propagate this update */
  }
}

int int16u_sklcmp(const void *a1, const void *a2)
{
  const int16u *arg1 = (const int16u*) a1;
  const int16u *arg2 = (const int16u*) a2;

  return (*arg1 < *arg2 ? -1 : (*arg1 == *arg2 ? 0 : 1));
}

/***********************************************************/
/* Creates an edge                                         */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* source: IP address of the source                        */
/* dest:   IP address of the destination                   */
/* cost:   starting cost of this edge                      */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (Edge*) a pointer to the Edge structure                 */
/*                                                         */
/***********************************************************/

Edge* Create_Edge(Node_ID src_id, Node_ID dst_id, int16 cost, int16 base_cost, int16u index) 
{
  sp_time      now = E_get_time();
  Node        *src_nd;
  Node        *dst_nd;
  Edge        *edge;
  State_Chain *s_chain;
  stdit        tit;
 
  Alarm(DEBUG, "Create edge: " IPF " -> " IPF "\r\n", IP(src_id), IP(dst_id));
    
  if ((src_nd = Get_Node(src_id)) == NULL) {
    Alarm(EXIT, "Create_Edge(): Non existent source: " IPF "!\r\n", IP(src_id));
  }

  if ((dst_nd = Get_Node(dst_id)) == NULL) {
    Alarm(EXIT, "Create_Edge(): Non existent destination: " IPF "!\r\n", IP(dst_id));
  }

  if (Get_Edge(src_id, dst_id) != NULL) {
    Alarm(EXIT, "Create_Edge(): Edge " IPF " -> " IPF " already exists!\r\n", IP(src_id), IP(dst_id));
  }

  if ((edge = (Edge*) new(OVERLAY_EDGE)) == NULL) {
    Alarm(EXIT, "Create_Edge: Cannot allocte edge object!\r\n");
  }

  memset(edge, 0, sizeof(*edge));

  if (src_nd == This_Node) {
    dst_nd->edge = edge;
  }

  edge->src_id = src_id;
  edge->dst_id = dst_id;

  if (src_nd == This_Node) {
    edge->timestamp_sec  = (int32) now.sec;
    edge->timestamp_usec = (int32) now.usec;
    edge->lts            = Link_State_LTS_inc();  /* NOTE: we want each source to use unique lts's for each of its state cells */

  } else {
    edge->timestamp_sec  = 0;
    edge->timestamp_usec = 0;
  }
    
  edge->my_timestamp_sec    = (int32) now.sec;
  edge->my_timestamp_usec   = (int32) now.usec;	    
  edge->cost                = cost;
  edge->age                 = 0;

  edge->src                 = src_nd;
  edge->dst                 = dst_nd;

  edge->base_cost           = base_cost;
  edge->index               = index;

  edge->leg                 = NULL;

  /* insert the edge into the global data structures */
    
  if (stdhash_is_end(&All_Edges, stdhash_find(&All_Edges, &tit, &src_id))) {

    if ((s_chain = (State_Chain*) new(STATE_CHAIN)) == NULL) {
      Alarm(EXIT, "Create_Edge: Cannot allocte state chain!\r\n");
    }

    memset(s_chain, 0, sizeof(*s_chain));
    s_chain->address = src_id;

    if (stdhash_construct(&s_chain->states, sizeof(Node_ID), sizeof(Edge*), NULL, NULL, 0) != 0 ||
	stdhash_insert(&All_Edges, &tit, &src_id, &s_chain) != 0) {
      Alarm(EXIT, "Create_Edge: Cannot init state chain object!\r\n");
    }

    stdhash_find(&All_Edges, &tit, &src_id);
  }
    
  s_chain = *(State_Chain**) stdhash_it_val(&tit);
  stdhash_insert(&s_chain->states, &tit, &dst_id, &edge);

  Alarm(PRINT, "Create_Edge: " IPF " -> " IPF " created!\r\n", IP(edge->src_id), IP(edge->dst_id));

  /* NOTE: we do not state flood or update routing because adding an unconnected edge can't have any routing effect */
    
  return edge;
}

Edge *Get_Edge(Node_ID src, Node_ID dst)
{
  return (Edge*) Find_State(&All_Edges, src, dst);
}

/* For debugging or logging purpose. 
 * The snapshot will write the current spines route every
 * print_timeout, overwriting the previous file.  So the 
 * latest state of Spines can be found in SNAPSHOT_FILE     
 */
#define PRINT_EDGES 1
#define PRINT_KERNEL_ROUTES 0
#define PRINT_WIRELESS_STATUS 1
#define SNAPSHOT 1
#define SNAPSHOT_FILE "/tmp/spines.%d.snapshot"

void Print_Edges(int dummy_int, void* dummy) 
{
    sp_time print_timeout = {   600,    0};
    FILE *fp = NULL;
    char line[256];
    char file_name[50];

    sprintf(file_name, SNAPSHOT_FILE, Port);

    if (SNAPSHOT) { 
	fp = fopen(file_name, "w"); 
	if (fp == NULL) { 
	    perror("Could not open spines snapshot file\n");
	    Alarm(PRINT,"\nWill continue without attempting to write to snapshot file\n");
	} else { 
#ifndef ARCH_PC_WIN95
		/* we dont know what to set it on win32 systems */
	    chmod(file_name, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
#endif
	    fprintf(fp, "\n\n"); 
	}
    }

    if (PRINT_EDGES) { 
	stdit it, c_it; 
	Edge *edge; 
	State_Chain *s_chain; 
	
	sprintf(line, "Available edges:\n"); 
	Alarm(PRINT, "%s", line); 
	if (fp != NULL) fprintf(fp, "%s", line); 
	stdhash_begin(&All_Edges, &it); 
	while(!stdhash_is_end(&All_Edges, &it)) { 
	    s_chain = *((State_Chain **)stdhash_it_val(&it)); 
	    stdhash_begin(&s_chain->states, &c_it); 
	    while(!stdhash_is_end(&s_chain->states, &c_it)) { 
		edge = *((Edge **)stdhash_it_val(&c_it)); 
		sprintf(line, "\t\t%d.%d.%d.%d -> %d.%d.%d.%d :: %d | %d:%d\n", 
			IP1(edge->src->nid), IP2(edge->src->nid), 
			IP3(edge->src->nid), IP4(edge->src->nid), 
			IP1(edge->dst->nid), IP2(edge->dst->nid), 
			IP3(edge->dst->nid), IP4(edge->dst->nid), 
			edge->cost, edge->timestamp_sec, edge->timestamp_usec); 
		stdhash_it_next(&c_it); 
		Alarm(PRINT, "%s", line); 
		if (fp != NULL) fprintf(fp, "%s", line); 
	    } 
	    stdhash_it_next(&it); 
	} 
    }
    
    sprintf(line, "\n");
    Alarm(PRINT, "%s", line);
    if (fp != NULL) fprintf(fp, "%s", line);

    Print_Routes(fp);

#ifdef SPINES_WIRELESS
    if (Wireless_monitor && PRINT_WIRELESS_STATUS) {
        Wireless_Print_Status(fp);
    }
#endif

#ifndef ARCH_PC_WIN95
    if (KR_Flags && PRINT_KERNEL_ROUTES) {
        KR_Print_Routes(fp);
    }
#endif

    if (fp != NULL) { 
	fclose(fp);
	fp = NULL;
    }

    E_queue(Print_Edges, 0, NULL, print_timeout);
}

Link_State_LTS Link_State_LTS_get(void)
{
  return Link_State_Update_LTS;
}

Link_State_LTS Link_State_LTS_inc(void)
{
  return ++Link_State_Update_LTS;
}

#define LTS_QUARTER_RANGE       ((((Link_State_LTS) ~0) >> 2) + 1)
#define LTS_THREE_QUARTER_RANGE (LTS_QUARTER_RANGE + LTS_QUARTER_RANGE + LTS_QUARTER_RANGE) 

int Link_State_LTS_cmp(Link_State_LTS left, Link_State_LTS right)
{
  int ret;

  /* NOTE: we want the LTS counter to wrap around intelligently: an increment should always make the LTS be "higher" than it was, even on roll over */
  /* NOTE: special case when one param is in top quarter of unsigned range and the other in the bottom quarter -> the latter is "higher" */

  if (left < right) {
    ret = -1;

    if (left < LTS_QUARTER_RANGE && right >= LTS_THREE_QUARTER_RANGE) {  /* check special case */
      ret = 1;
    }

  } else if (left != right) {  /* left > right */
    ret = 1;

    if (right < LTS_QUARTER_RANGE && left >= LTS_THREE_QUARTER_RANGE) {  /* check special case */
      ret = -1;
    }

  } else {
    ret = 0;
  }

  return ret;
}

int Link_State_LTS_cmp2(const void *left_lts_ptr, const void *right_lts_ptr)
{
  return Link_State_LTS_cmp(*(const Link_State_LTS*) left_lts_ptr, *(const Link_State_LTS*) right_lts_ptr);
}
