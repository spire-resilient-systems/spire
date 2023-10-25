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

#ifndef MULTIPATH_H
#define MULTIPATH_H

#include <stdio.h>

#include "arch.h"
#include "spines.h"
#include "objects.h"
#include "node.h"
#include "configuration.h"

#include "spu_alarm.h"
#include "spu_memory.h"

#define MULTIPATH_BITMASK_SIZE_DEFAULT 64   /* in Bits */
#define MULTIPATH_MAX_K                5    /* Max # of node-disjoint paths supported */
#define DIRECTED_EDGES_DEFAULT         0    /* Bidirectional edges by default */

#define DG_K_FLAG (MULTIPATH_MAX_K + 1) /* If number of disjoint paths
                                           requested == DG_K_FLAG, use
                                           dissemination graphs with src/dst
                                           redundancy */

struct Flow_Node_d;
struct Flow_Edge_d;

typedef struct Flow_Node_d {
    /* Node *nd; */
    struct Flow_Edge_d  **outgoing;
    struct Flow_Edge_d  **incoming;
    struct Flow_Node_d   *twin;
    struct Flow_Edge_d   *previous_edge;
    unsigned char         inbound_node; 
    int16u                outgoing_num;
    int16u                incoming_num;
    int16u                distance;
        /* True if all edges to other real nodes are incoming to this node 
             (one outgoing edge to twin), 
           False if all edges to other real nodes are outgoing from this 
             node (one incoming edge from twin) */
} Flow_Node;

typedef struct Flow_Edge_d {
    int16u                flow;
    int16u                capacity;
    Edge                 *edge;
    Edge                 *reverse_edge;
    Flow_Node            *start;
    Flow_Node            *end;
    int16u                index;
    unsigned char         residual; /* True if edge is residual, False if real */
    struct Flow_Edge_d   *twin;
    struct Flow_Edge_d   *next;
} Flow_Edge;

#undef  ext
#ifndef ext_multipath
#define ext extern
#else
#define ext
#endif

ext int16u MultiPath_Bitmask_Size;
ext unsigned char Directed_Edges;
ext Flow_Node *Flow_Nodes_Inbound[MAX_NODES+1];
ext Flow_Node *Flow_Nodes_Outbound[MAX_NODES+1];
ext Flow_Edge Flow_Edge_Head;

void   MultiPath_Pre_Conf_Setup(void);
void   Init_MultiPath(void);
void   MultiPath_Clear_Cache(void);
int    MultiPath_Compute(int16u dest_id, int16u k, unsigned char **ret_mask, int use_base_cost, int require_reverse); 
int    MultiPath_Stamp_Bitmask(int16u dest_id, int16u k, unsigned char *mask);
int    MultiPath_Neighbor_On_Path(unsigned char* mask, int16u ngbr_iter);
int    MultiPath_Is_Superset(unsigned char* old_mask, unsigned char* new_mask);
void   MultiPath_Create_Superset(unsigned char* old_mask, unsigned char* new_mask);
int    MultiPath_Is_Equal(unsigned char* old_mask, unsigned char* new_mask);

#endif /* MULTIPATH_H */
