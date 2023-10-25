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

#ifndef STATE_FLOOD_H
#define STATE_FLOOD_H

#include "link.h"

typedef struct Prot_Def_d 
{
  stdhash *(*All_States)(void); 
  stdhash *(*All_States_by_Dest)(void); 
  stdhash *(*Changed_States)(void); 
  int      (*State_type)(void);
  int      (*State_header_size)(void);
  int      (*Cell_packet_size)(void);
  int      (*Is_route_change)(void);
  int      (*Is_state_relevant)(void *state);
  int      (*Set_state_header)(void *state, char *pos);
  int      (*Set_state_cell)(void *state, char *pos);
  void     (*Process_state_header)(char *pos, int32 type);
  void    *(*Process_state_cell)(Node_ID source, Node_ID sender, char *pos, int32 type);
  int      (*Destroy_State_Data)(void *state);

} Prot_Def;

/* Represents a state update to be sent. It refers to a state
   and the mask is set to which nodes sould not hear about 
   this update (b/c they already know it) */

/* NOTE: mask is a bit vector w/ one bit for each possible neighbor.
   A neighbor's bit state is accessed as 

   bit = ((mask[id / 32] & (0x1 << id % 32)) != 0);

   The 32's come from the fact that we are using 32b ints for the
   array.  

   A set bit indicates we've sent the changed state to that
   neighbor, whereas an unset bit means we still need to send it to
   them.
*/

typedef struct Changed_State_d 
{
  void  *state;
  int32u mask[MAX_LINKS/(MAX_LINKS_4_EDGE*32)];

} Changed_State;

/* This is the beginning of any state type (e.g. - Edge and Group_State) */

typedef struct State_Data_d 
{
  Spines_ID source_addr;           /* primary key of state */
  Spines_ID dest_addr;             /* secondary key of state */
  int32     timestamp_sec;         /* Original timestamp of the last change (secnds) */
  int32     timestamp_usec;        /* ...microseconds */
  int32     my_timestamp_sec;      /* Local timestamp of the last upadte (seconds) */
  int32     my_timestamp_usec;     /* ...microseconds */
  int16     value;                 /* Value of the state */
  int16     age;                   /* Life of the state (in tens of seconds) */

} State_Data;

typedef struct State_Chain_d 
{
  Node_ID  address;
  stdhash  states;
  
} State_Chain;

/* This is the begining of any state packet */

typedef struct  State_Packet_d 
{
  Node_ID source;
  int16u  num_cells;
  int16   src_data;  /* Data about the source source itself. 
			Not used yet */
} State_Packet;

/* This is the begining of any state cell */

typedef struct  State_Cell_d 
{
  Node_ID dest;
  int32   timestamp_sec;
  int32   timestamp_usec;
  int16   value;
  int16   age;

} State_Cell;

void           Process_state_packet(Link *lk, char *buf, 
				    int16u data_len, int16u ack_len, 
				    int32u type, int mode);

void           Net_Send_State_All(int lk_id, void *p_data); 
int            Net_Send_State_Updates(Prot_Def *p_def, int16 node_id);
void           Send_State_Updates(int dummy_int, void *p_data /* protocol definition to send */);     

Prot_Def      *Get_Prot_Def(int32u type);

void           Add_to_changed_states(Prot_Def *p_def, Node_ID source, 
				     State_Data *s_data);

State_Data    *Find_State(stdhash *hash_struct, Node_ID source, 
			  Node_ID dest); 

Changed_State *Find_Changed_State(stdhash *hash_struct, 
				  Node_ID source, Node_ID dest);

void           Empty_Changed_States(stdhash *states);
void           Resend_States(int sync_up, void* p_data);
void           State_Garbage_Collect(int dummy_int, void* p_data);

#endif

