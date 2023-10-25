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

#ifdef ARCH_PC_WIN95
#  include <winsock2.h>
#endif

#include "arch.h"
#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_memory.h"
#include "stdutil/stdhash.h"

#include "objects.h"
#include "link.h"
#include "node.h"
#include "route.h"
#include "state_flood.h"
#include "net_types.h"
#include "hello.h"
#include "session.h"
#include "multicast.h"
#include "spines.h"

#ifdef ARCH_PC_WIN95
#  define MCAST_SNAPSHOT_FILE "groups.%d.snapshot"
#else
#  define MCAST_SNAPSHOT_FILE "/tmp/groups.%d.snapshot"
#endif

/***********************************************************/
/* Returns the hash containing all known groups            */
/***********************************************************/

stdhash *Groups_All_States(void)
{
  return &All_Groups_by_Node;
}

/***********************************************************/
/* Returns the hash containing all known groups by name    */
/***********************************************************/

stdhash *Groups_All_States_by_Name(void)
{
  return &All_Groups_by_Name;
}

/***********************************************************/
/* Returns the hash containing the changed groups          */
/***********************************************************/

stdhash *Groups_Changed_States(void)
{
  return &Changed_Group_States;
}

/***********************************************************/
/* Returns the packet header type for group msgs           */
/***********************************************************/

int Groups_State_type(void)
{
  return GROUP_STATE_TYPE;
}

/***********************************************************/
/* Returns the size of the group header                    */
/***********************************************************/

int Groups_State_header_size(void)
{
  return (int) sizeof(group_state_packet);
}

/***********************************************************/
/* Returns the size of the group cell                      */
/***********************************************************/

int Groups_Cell_packet_size(void)
{
  return (int) sizeof(group_cell_packet);
}

/***********************************************************/
/* Returns false, groups does not change routing...        */
/***********************************************************/

int Groups_Is_route_change(void) 
{
  return 0;
}

/***********************************************************/
/* Returns true if the group is not removed, false         */
/* otherwise so that the group will not be resent, and     */
/* eventually will be garbage-collected                    */
/***********************************************************/

int Groups_Is_state_relevant(void *state)
{
  return (((Group_State*) state)->status & ACTIVE_GROUP) != 0;
}

/***********************************************************/
/* Sets the join/leave packet header additional fields     */
/***********************************************************/

int Groups_Set_state_header(void *state, char *pos)
{
  UNUSED(state);
  UNUSED(pos);
  return 0;  /* Nothing for now... */
}

/***********************************************************/
/* Sets the link_state cell additional fields              */
/***********************************************************/

int Groups_Set_state_cell(void *state, char *pos)
{
  UNUSED(state);
  UNUSED(pos);
  return 0;  /* Nothing for now... */
}

/***********************************************************/
/* Destroys specific info from the group structure         */
/***********************************************************/

int Groups_Destroy_State_Data(void *state)
{
  Group_State *g_state = (Group_State*) state;
  
  if (g_state->node_nid == My_Address) {
    stdhash_destruct(&g_state->joined_sessions);
  }

  return 1;  /* always successful; -1 -> failure */
}

/***********************************************************/
/* Process the groups packet header fields                 */
/***********************************************************/

void Groups_Process_state_header(char *pos,  /* pointer to pkt */
				int32 type)  /* endianness */
{
  group_state_packet *g_st_pkt = (group_state_packet*) pos;
    
  if (!Same_endian(type)) {
    g_st_pkt->source = Flip_int32(g_st_pkt->source);
    g_st_pkt->num_cells = Flip_int16(g_st_pkt->num_cells);
    g_st_pkt->src_data = Flip_int16(g_st_pkt->src_data);
  }
}

/***********************************************************/
/* Processes a groups cell                                 */
/***********************************************************/

void *Groups_Process_state_cell(Node_ID source,  /* originator of join/leave */
				Node_ID sender,  /* sender of this update to us */
				char   *pos,     /* pointer to cell */
				int32   type)
{
  group_cell_packet *group_cell = (group_cell_packet*) pos;
  Group_State       *g_state;

  UNUSED(sender);
  UNUSED(type);

  if ((g_state = (Group_State*) Find_State(&All_Groups_by_Node, source, group_cell->dest)) == NULL) {
    g_state = Create_Group(source, group_cell->dest);
  }

  /* update replicated entry */

  g_state->timestamp_sec  = group_cell->timestamp_sec;
  g_state->timestamp_usec = group_cell->timestamp_usec;

  /* check if this one of my group memberships */

  if (source != My_Address) {  /* nope */

    g_state->age    = group_cell->age;
    g_state->status = group_cell->flags;

  } else {  /* I will publish my own up-to-date group memberships thank you very much! */

    if (++g_state->timestamp_usec >= 1000000) {
      ++g_state->timestamp_sec;
      g_state->timestamp_usec = 0;
    }

    Add_to_changed_states(&Groups_Prot_Def, My_Address, (State_Data*) g_state);	
    g_state = NULL;  /* don't propagate this update */
  }

  return g_state;
}

/***********************************************************/
/* Joins a group locally                                   */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int)  2 if created/activated a new group               */ 
/*        1 if this overlay node already joined the group, */
/*       -1 if failure                                     */
/***********************************************************/

int Join_Group(Group_ID mcast_address,  /* group to join */
	       Session *ses)            /* session registering interest */
{
  int          ret = 1;
  Group_State *g_state;
  stdit        tit;
  
  if (!Is_mcast_addr(mcast_address) && !Is_acast_addr(mcast_address)) {
    return -1;		
  }
      
  if (ses->type != UDP_SES_TYPE) {
    return -1;
  }

  if (!stdhash_is_end(&ses->joined_groups, stdhash_find(&ses->joined_groups, &tit, &mcast_address))) { 
    return 1;  /* this session already joined that group */
  }

  if ((g_state = (Group_State*) Find_State(&All_Groups_by_Node, My_Address, mcast_address)) == NULL) {
    g_state = Create_Group(My_Address, mcast_address);
  }

  if (!(g_state->status & ACTIVE_GROUP)) {

    g_state->status |= ACTIVE_GROUP;

    if (++g_state->timestamp_usec >= 1000000) {
      ++g_state->timestamp_sec;
      g_state->timestamp_usec = 0;
    }

    Add_to_changed_states(&Groups_Prot_Def, My_Address, (State_Data*) g_state);
    ret = 2;
  }

  if (stdhash_insert(&ses->joined_groups, &tit, &mcast_address, &g_state) != 0 ||
      stdhash_insert(&g_state->joined_sessions, &tit, &ses->sess_id, &ses) != 0) {
    Alarm(EXIT, "Create_Group: insertion failed!\r\n");
  }

  return ret;
}

/***********************************************************/
/* Leaves a group locally                                  */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int)  1 if leave was successful                        */
/*       -1 if not                                         */
/***********************************************************/

int Leave_Group(Group_ID mcast_address,  /* group address */
		Session *ses)            /* session unregistering interest */
{
  Group_State *g_state;
  stdit        tit;
   
  if (!Is_mcast_addr(mcast_address) && !Is_acast_addr(mcast_address)) {
    return -1;
  }

  if (stdhash_is_end(&ses->joined_groups, stdhash_find(&ses->joined_groups, &tit, &mcast_address))) {      
    return 1;  /* session did not join that group */
  }

  g_state = *(Group_State**) stdhash_it_val(&tit);
  stdhash_erase(&ses->joined_groups, &tit);
    
  if (stdhash_is_end(&g_state->joined_sessions, stdhash_find(&g_state->joined_sessions, &tit, &ses->sess_id))) {
    Alarm(EXIT, "BUG Leave_Group(): Session not in the group array?!\r\n");

  } else {
    stdhash_erase(&g_state->joined_sessions, &tit);
  }

  if (stdhash_empty(&g_state->joined_sessions)) {  /* there are no more local sessions joining this group */
	
    g_state->status &= ~ACTIVE_GROUP;

    if(++g_state->timestamp_usec >= 1000000) {
      ++g_state->timestamp_sec;
      g_state->timestamp_usec = 0;
    }

    Add_to_changed_states(&Groups_Prot_Def, My_Address, (State_Data*) g_state);	  
  } 

  return 1;
}

/***********************************************************/
/* Creates an inactive group                               */
/***********************************************************/

Group_State *Create_Group(Node_ID  nid,            /* node that joined the group */
			  Group_ID mcast_address)  /* the group the node joined */
{
  sp_time      now = E_get_time();
  Group_State *g_state;
  State_Chain *s_chain_addr;
  State_Chain *s_chain_grp;
  stdit        tit;

  if (Find_State(&All_Groups_by_Node, nid, mcast_address) != NULL) {
    Alarm(EXIT, "Create_Group(): Group already exists\r\n");
  }

  if ((g_state = (Group_State*) new(MULTICAST_GROUP)) == NULL) {
    Alarm(EXIT, "Create_Group: Cannot allocte group object\r\n");
  }

  memset(g_state, 0, sizeof(*g_state));
  
  g_state->node_nid          = nid;
  g_state->mcast_gid         = mcast_address;

  if (My_Address == nid) {
    g_state->timestamp_sec   = (int32) now.sec;
    g_state->timestamp_usec  = (int32) now.usec;

    if (stdhash_construct(&g_state->joined_sessions, sizeof(int32), sizeof(Session*), 
			  NULL, NULL, 0) != 0) {
      Alarm(EXIT, "Create_Group: cannot create joined_sessions!\r\n");
    }

  } else {
    g_state->timestamp_sec   = 0;
    g_state->timestamp_usec  = 0;
  }

  g_state->my_timestamp_sec  = (int32) now.sec;
  g_state->my_timestamp_usec = (int32) now.usec;	
  g_state->status            = 0;
  g_state->age               = 0;

  /* Insert the group in the global data structures */
  /* All_Groups_by_Node */
    
  if (stdhash_is_end(&All_Groups_by_Node, stdhash_find(&All_Groups_by_Node, &tit, &nid))) {

    if ((s_chain_addr = (State_Chain*) new(STATE_CHAIN)) == NULL) {
      Alarm(EXIT, "Create_Group: Cannot allocate object\r\n");
    }

    s_chain_addr->address = nid;
    
    if (stdhash_construct(&s_chain_addr->states, sizeof(Group_ID), sizeof(Group_State*), 
			  NULL, NULL, 0) != 0 ||
	stdhash_put(&All_Groups_by_Node, &tit, &nid, &s_chain_addr) != 0) {
      Alarm(EXIT, "Create_Group: Couldn't init state_chain!\r\n");
    }
  }    

  s_chain_addr = *(State_Chain**) stdhash_it_val(&tit);

  if (stdhash_put(&s_chain_addr->states, &tit, &mcast_address, &g_state) != 0) {
    Alarm(EXIT, "Create_Group: Couldn't insert into s_chain!\r\n");
  }

  /* All_Groups_by_Name */
    
  if (stdhash_is_end(&All_Groups_by_Name, stdhash_find(&All_Groups_by_Name, &tit, &mcast_address))) {

    if ((s_chain_grp = (State_Chain*) new(STATE_CHAIN)) == NULL) {
      Alarm(EXIT, "Create_Group: Cannot allocte object\r\n");
    }

    s_chain_grp->address = mcast_address;

    if (stdhash_construct(&s_chain_grp->states, sizeof(Spines_ID), sizeof(Group_State*), 
			  NULL, NULL, 0) != 0 || 
	stdhash_put(&All_Groups_by_Name, &tit, &mcast_address, &s_chain_grp) != 0) {
      Alarm(EXIT, "Create_Group: Couldn't insert!\r\n");
    }
  }

  s_chain_grp = *(State_Chain**) stdhash_it_val(&tit);

  if (stdhash_put(&s_chain_grp->states, &tit, &nid, &g_state) != 0) {
    Alarm(EXIT, "Create_Group: Couldn't insert!\r\n");
  }

  return g_state;
}

void Trace_Group(Group_ID mcast_address, spines_trace *spines_tr) 
{
    stdit nd_it;
    Node *nd;
    Route *route;
    spines_trace spt;
    int i, j, current_ed, is_reachable;

    /* Get all active group members */
    memset(&spt, 0, sizeof(spt));
    Get_Group_Members(mcast_address, &spt);

    /* For each possible source, what is the maximum distance to any
       of the group members (Group Euclidean Distance) */
    i = 0;
    stdhash_begin(&All_Nodes, &nd_it); 
    while(!stdhash_is_end(&All_Nodes, &nd_it)) {
        nd = *((Node **)stdhash_it_val(&nd_it));

        /* Is this node at all reachable */
        is_reachable = 0;
        if (nd->nid == My_Address) {
            is_reachable = 1;
        } else {
            route = Find_Route(My_Address, nd->nid);
            if (route != NULL) {
                if(route->forwarder != NULL) {
                    is_reachable = 1;
                }
            }
        }
        if (is_reachable == 0) {
	    stdhash_it_next(&nd_it);
            continue;
        }

        current_ed = 0;
        for (j=0;j<spt.count;j++) {
	    route = Find_Route(nd->nid, spt.address[j]);
            if (route != NULL) {
                if (route->distance >=0 && route->cost >=0) {
                    if (route->distance > current_ed) {
                        current_ed = route->distance;
                    }
                }
            }
            /* TODO: How many links need to be crossed to reach
               all of the grouop members (Group Euclidean Cost) */
        }
        spines_tr->address[i]=nd->nid;
        spines_tr->distance[i]=current_ed;
        spines_tr->cost[i]=0;
        i++;
	stdhash_it_next(&nd_it);
    }
    spines_tr->count = i;
}

int Get_Group_Members(Group_ID mcast_address, spines_trace *spines_tr)
{
    stdit grp_it, st_it;
    State_Chain *s_chain_grp;
    Route *route;
    Group_State *g_state;
    int i;

    stdhash_find(&All_Groups_by_Name, &grp_it, &mcast_address);
    if(stdhash_is_end(&All_Groups_by_Name, &grp_it)) {
	return 0;
    }
    s_chain_grp = *((State_Chain **)stdhash_it_val(&grp_it));

    i=0;
    stdhash_begin(&s_chain_grp->states, &st_it);
    while(!stdhash_is_end(&s_chain_grp->states, &st_it)) {
	g_state = *((Group_State **)stdhash_it_val(&st_it));
	if(g_state->status & ACTIVE_GROUP) {
            if (g_state->node_nid == My_Address) {
                spines_tr->address[i] = g_state->node_nid;
                spines_tr->distance[i] = 0;
                spines_tr->cost[i] = 0;
                i++;
            } else {
                route = Find_Route(My_Address, g_state->node_nid);
	        if (route != NULL) {
                    if (route->distance >= 0 && route->cost >= 0) {
                        spines_tr->address[i] = g_state->node_nid;
                        spines_tr->distance[i] = route->distance;
                        spines_tr->cost[i] = route->cost;
                        i++;
                    }
                }
            } 
        }
        if (i == MAX_COUNT) {
            break;
        }
        stdhash_it_next(&st_it);
    }
    spines_tr->count = i;
    return 1;
}

void Print_Mcast_Groups(int dummy_int, void* dummy)
{
    const sp_time print_timeout = {    180,    0};
    FILE *fp = NULL;
    stdit grp_it, ngb_it;
    State_Chain *s_chain_grp;
    Node *next_hop;
    stdhash *neighbors;
    spines_trace spt;
    int i;
    char file_name[50];

    UNUSED(dummy_int);
    UNUSED(dummy);

    sprintf(file_name, MCAST_SNAPSHOT_FILE, Port);

    stdhash_begin(&All_Groups_by_Name, &grp_it);
    fp = fopen(file_name, "w");
    if (fp == NULL) {
	perror("Could not open mcast snapshot file\n");
	return;
    }
    while(!stdhash_is_end(&All_Groups_by_Name, &grp_it)) {
	s_chain_grp = *((State_Chain **)stdhash_it_val(&grp_it));

        /* Print Group */
	fprintf(fp, "\n\n\n"IPF, IP(s_chain_grp->address));
       
        /* Print Current Membership */
        memset(&spt, 0, sizeof(spt));
        Get_Group_Members(s_chain_grp->address, &spt);
        fprintf(fp, "\n\n\tOverlay Membership: %d\n", spt.count); 
        for (i=0;i<spt.count;i++) {
            fprintf(fp, "\n\t\t"IPF": %d: %d", 
                    IP((int)(spt.address[i])), spt.distance[i], spt.cost[i]);
        }

        /* Print Forwarding Rule */
        neighbors = Get_Mcast_Neighbors(My_Address, s_chain_grp->address);
        fprintf(fp, "\n\n\tForwarding Table, Source=ME\n"); 
	if(neighbors != NULL) {
	    stdhash_begin(neighbors, &ngb_it);
	    while(!stdhash_is_end(neighbors, &ngb_it)) {
		next_hop = *((Node **)stdhash_it_val(&ngb_it));
                if (next_hop != NULL) {
		    fprintf(fp, "\n\t\t-->"IPF, IP(next_hop->nid));
		}
		stdhash_it_next(&ngb_it);
	    }
	}
	fprintf(fp, "\n");
	stdhash_it_next(&grp_it);
    }
    fclose(fp);
    E_queue(Print_Mcast_Groups, 0, NULL, print_timeout);
}
