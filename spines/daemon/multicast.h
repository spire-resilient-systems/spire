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

#ifndef MULTICAST_H
#define MULTICAST_H

#include "node.h"

#define ACTIVE_GROUP 0x0001

typedef struct Group_State_d 
{
  /* NOTE: the following 8 members must remain in this order at the top of this struct so that we can safely cast to a State_Data* */

  Node_ID  node_nid;              /* ID of the node that joins / leaves */
  Group_ID mcast_gid;             /* Group ID to which the node has joined / left */
  int32    timestamp_sec;         /* Original timestamp of the last change (seconds) */
  int32    timestamp_usec;        /* ...microseconds */
  int32    my_timestamp_sec;      /* Local timestamp of the last update (seconds) */
  int32    my_timestamp_usec;     /* ...microseconds */
  int16    status;                /* Group status (ACTIVE_GROUP, etc.) */
  int16    age;                   /* Life of the state (in tens of seconds) */

  stdhash  joined_sessions;       /* Local sessions that joined the group */

} Group_State;

stdhash* Groups_All_States(void); 
stdhash* Groups_All_States_by_Name(void); 
stdhash* Groups_Changed_States(void); 
int Groups_State_type(void);
int Groups_State_header_size(void);
int Groups_Cell_packet_size(void);
int Groups_Is_route_change(void);
int Groups_Is_state_relevant(void *state);
int Groups_Set_state_header(void *state, char *pos);
int Groups_Set_state_cell(void *state, char *pos);
void Groups_Process_state_header(char *pos, int32 type);
void* Groups_Process_state_cell(Node_ID source, Node_ID sender, char *pos, int32 type);
int Groups_Destroy_State_Data(void *state);

int Join_Group(Group_ID mcast_address, Session *ses);
int Leave_Group(Group_ID mcast_address, Session *ses);
Group_State* Create_Group(Node_ID node_address, Node_ID mcast_address);
void Trace_Group(Group_ID mcast_address, spines_trace *spines_tr);
int Get_Group_Members(Group_ID mcast_address, spines_trace *spines_tr);
void Print_Mcast_Groups(int dummy_int, void* dummy);

#endif
