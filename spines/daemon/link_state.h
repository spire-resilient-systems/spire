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

#ifndef LINK_STATE_H
#define LINK_STATE_H

#include "stdutil/stdskl.h"

#include "net_types.h"
#include "link.h"
#include "node.h"
#include "network.h"

struct Node_d;
struct Edge_d;
struct Interface_d;
struct Network_Leg_d;
struct Link_d;

typedef struct Edge_d 
{
    /* NOTE: the following 8 members must remain in this order at the top of this struct so that we can safely cast to a State_Data* */

    Node_ID        src_id;                 /* Source identifier */
    Node_ID        dst_id;                 /* Destination idenifier */
    int32          timestamp_sec;          /* Original timestamp of the last change (seconds) */
    int32          timestamp_usec;         /* ...microseconds */
    int32          my_timestamp_sec;       /* Local timestamp of the last update (seconds) */
    int32          my_timestamp_usec;      /* ...microseconds */
    int16          cost;                   /* cost of the edge */
    int16          age;                    /* Life of the state (in tens of seconds) */

    int16          base_cost;              /* base cost of edge (from configuration file) */
    int16u         index;                  /* index of edge (used for bitmask construction in source-based routing) */

    Link_State_LTS lts;                    /* lamport time stamp of most recent link state update on this Edge */

    struct Node_d *src;                    /* Source node */
    struct Node_d *dst;                    /* Destination node */

    struct Network_Leg_d   *leg;           /* the underlying communication leg */
  
} Edge;

typedef struct Edge_Key_d
{
    Node_ID        src_id;                 /* Source identifier */
    Node_ID        dst_id;                 /* Destination idenifier */

} Edge_Key;

typedef struct Edge_Value_d
{
    int16          cost;                   /* Edge Cost */
    int16u         index;                  /* Index in Bitmask */
} Edge_Value;

stdhash *Edge_All_States(void); 
stdhash *Edge_All_States_by_Dest(void); 
stdhash *Edge_Changed_States(void); 
int      Edge_State_type(void);
int      Edge_State_header_size(void);
int      Edge_Cell_packet_size(void);
int      Edge_Is_route_change(void);
int      Edge_Is_state_relevant(void *state);
int      Edge_Set_state_header(void *state, char *pos);
int      Edge_Set_state_cell(void *state, char *pos);
void     Edge_Process_state_header(char *pos, int32 type);
void    *Edge_Process_state_cell(Node_ID source, Node_ID sender, char *pos, int32 type);
int      Edge_Destroy_State_Data(void *state);

Edge    *Create_Edge(Node_ID source, Node_ID dest, int16 cost, int16 base_cost, int16u index);
Edge    *Get_Edge(Node_ID src, Node_ID dst);
Edge    *Destroy_Edge(Node_ID source, Node_ID dest, int local_call);
/*int      Edge_Update_Cost(int link_id, int mode);*/
void     Print_Edges(int dummy_int, void* dummy); 

Link_State_LTS Link_State_LTS_get(void);
Link_State_LTS Link_State_LTS_inc(void);
int            Link_State_LTS_cmp(Link_State_LTS left, Link_State_LTS right);
int            Link_State_LTS_cmp2(const void *left_lts_ptr, const void *right_lts_ptr);

#endif
