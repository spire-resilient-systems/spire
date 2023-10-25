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

#define ext_multipath
#include "multipath.h"
#undef ext_multipath

#include <string.h>
#include <float.h>
#include "dissem_graphs.h"

extern int16u *Neighbor_IDs[];

unsigned char  *MP_Cache[MAX_NODES+1][MULTIPATH_MAX_K+1];
unsigned char  *MP_Flooding_Bitmask;
unsigned char **MP_Neighbor_Mask;

void MultiPath_Pre_Conf_Setup()
{
    int i, j;
    Flow_Edge *fe;

    MultiPath_Bitmask_Size = MULTIPATH_BITMASK_SIZE_DEFAULT / 8;
    Directed_Edges = DIRECTED_EDGES_DEFAULT;

    for (i = 0; i <= MAX_NODES; i++) {
        Flow_Nodes_Inbound[i]  = NULL;
        Flow_Nodes_Outbound[i] = NULL;

        for (j = 0; j <= MULTIPATH_MAX_K; j++)
            MP_Cache[i][j] = NULL;
    }

    MP_Flooding_Bitmask = NULL;

    fe = &Flow_Edge_Head;
    fe->flow = 0;
    fe->capacity = 0;
    fe->edge = NULL;
    fe->reverse_edge = NULL;
    fe->start = NULL;
    fe->end = NULL;
    fe->index = USHRT_MAX;
    fe->residual = 0;
    fe->twin = NULL;
    fe->next = NULL;
}

void Init_MultiPath()
{
    int i;
    int16u index = 0;
    stdit it;
    Flow_Node *a, *b;
    Flow_Edge *real, *resid;
    Edge_Key key;
    Edge_Value val;
    int16u s, d;

    /* ~~~~~~~~ INIT FLOODING AND NEIGHBOR BITMASKS ~~~~~~~~ */

    /* Initialize the Flooding and Neighbor Masks */
    MultiPath_Clear_Cache();
   
    /* Setup Flooding Bitmask (which should be all 1's) */
    MP_Flooding_Bitmask = new(MP_BITMASK);
    if (MP_Flooding_Bitmask == NULL)
        Alarm(EXIT, "MultiPath_Post_Conf_Setup: could not allocate memory for "
                "MP_Flooding_Bitmask object\r\n");
    memset(MP_Flooding_Bitmask, 0xFF, MultiPath_Bitmask_Size);

    /* Allocate and Initialize the Bitmask for each neighbor */
    MP_Neighbor_Mask = Mem_alloc(sizeof(unsigned char*) * (Degree[My_ID] + 1));
    MP_Neighbor_Mask[0] = NULL;
    for (i = 1; i <= Degree[My_ID]; i++) {
        MP_Neighbor_Mask[i] = new(MP_BITMASK);
        if (MP_Neighbor_Mask[i] == NULL)
            Alarm(EXIT, "Multipath_Post_Conf_Setup: could not allocate memory "
                    "for MP_Neighbor_Mask\r\n");
        memset(MP_Neighbor_Mask[i], 0x00, MultiPath_Bitmask_Size);
    
        if (Directed_Edges == 0) {
            if (Neighbor_IDs[My_ID][i] < My_ID) {
                key.src_id = Neighbor_IDs[My_ID][i];
                key.dst_id = My_ID;
            }
            else {
                key.src_id = My_ID;
                key.dst_id = Neighbor_IDs[My_ID][i];
            }
        }
        else {
            key.src_id = My_ID;
            key.dst_id = Neighbor_IDs[My_ID][i];
        }

        stdskl_find(&Sorted_Edges, &it, &key);
        if (stdskl_is_end(&Sorted_Edges, &it))
            Alarm(EXIT, "MultiPath_Post_Conf_Setup: Edge from config file not"
                        " in Sorted_Edges skip list (%d,%d)\r\n", key.src_id, key.dst_id);

        index = ((Edge_Value*)stdskl_it_val(&it))->index;
        *(MP_Neighbor_Mask[i] + (index / 8)) = 0x80 >> (index % 8);
    }

    /* ~~~~~~~~ MIN COST MAX FLOW INITIALIZATION ~~~~~~~~ */
    
    /* Create Nodes - one inbound and one outbound for each real node */ 
    for (i = 1; i <= MAX_NODES; i++) { 
        if (temp_node_ip[i] != 0) {

            /* Create inbound and initialize */
            Flow_Nodes_Inbound[i] = Mem_alloc(sizeof(Flow_Node));
            a = Flow_Nodes_Inbound[i];
            a->incoming = Mem_alloc(sizeof(Flow_Edge*) * (Degree[i] + 1));
            a->outgoing = Mem_alloc(sizeof(Flow_Edge*) * (Degree[i] + 1));
            a->inbound_node = 1;
            a->incoming_num = 0;
            a->outgoing_num = 0;

            /* Create outbound and initialize */
            Flow_Nodes_Outbound[i] = Mem_alloc(sizeof(Flow_Node));
            b = Flow_Nodes_Outbound[i];
            b->incoming = Mem_alloc(sizeof(Flow_Edge*) * (Degree[i] + 1));
            b->outgoing = Mem_alloc(sizeof(Flow_Edge*) * (Degree[i] + 1));
            b->inbound_node = 0;
            b->incoming_num = 0;
            b->outgoing_num = 0;

            /* Point nodes to each other */
            a->twin = b;
            b->twin = a;

            /* Create real edge between node pair */
            real = Mem_alloc(sizeof(Flow_Edge));
            real->flow = 0;
            real->capacity = 1;
            real->edge = NULL;
            real->reverse_edge = NULL;
            real->start = a;
            real->end = b;
            real->index = USHRT_MAX;
            real->residual = 0;
            /* Add to the Flow_Edge Linked List */
            real->next = Flow_Edge_Head.next;
            Flow_Edge_Head.next = real;
            a->outgoing[a->outgoing_num] = real;
            a->outgoing_num++;
            b->incoming[b->incoming_num] = real;
            b->incoming_num++;
            
            /* Create residual edge between node pair */
            resid = Mem_alloc(sizeof(Flow_Edge));
            resid->flow = 1;
            resid->capacity = 1;
            resid->edge = NULL;
            resid->reverse_edge = NULL;
            resid->start = b;
            resid->end = a;
            resid->index = USHRT_MAX;
            resid->residual = 1;
            /* Add to the Flow_Edge Linked List */
            resid->next = Flow_Edge_Head.next;
            Flow_Edge_Head.next = resid;
            b->outgoing[b->outgoing_num] = resid;
            b->outgoing_num++;
            a->incoming[a->incoming_num] = resid;
            a->incoming_num++;

            /* Point the edges to each other */
            real->twin = resid;
            resid->twin = real;
        }
    }

    /* Create Edges - four edges from an undirected edge OR two edges from a directed edge */
    stdskl_begin(&Sorted_Edges, &it);
    while(!stdskl_is_end(&Sorted_Edges, &it)) {
        key = *(Edge_Key*)stdskl_it_key(&it); 
        val = *(Edge_Value*)stdskl_it_val(&it);
        s = key.src_id;
        d = key.dst_id;

        /* Always create this edge, regardless of directed/undirected */
        a = Flow_Nodes_Outbound[s];
        b = Flow_Nodes_Inbound[d];

        /* Create real edge between node pair */
        real = Mem_alloc(sizeof(Flow_Edge));
        real->flow = 0;
        real->capacity = 1;
        real->edge = Get_Edge(temp_node_ip[s], temp_node_ip[d]);
        if (real->edge == NULL)
            Alarm(EXIT, "Init_MultiPath: Unable to find edge between %hu and %hu\r\n", s, d);
        real->reverse_edge = Get_Edge(temp_node_ip[d], temp_node_ip[s]);
        if (real->reverse_edge == NULL)
            Alarm(EXIT, "Init_MultiPath: Unable to find edge between %hu and %hu\r\n", d, s);
        real->start = a;
        real->end = b;
        real->index = val.index;
        real->residual = 0;
        /* Add to the Flow_Edge Linked List */
        real->next = Flow_Edge_Head.next;
        Flow_Edge_Head.next = real;
        a->outgoing[a->outgoing_num] = real;
        a->outgoing_num++;
        b->incoming[b->incoming_num] = real;
        b->incoming_num++;
        
        /* Create residual edge between node pair */
        resid = Mem_alloc(sizeof(Flow_Edge));
        resid->flow = 1;
        resid->capacity = 1;
        resid->edge = real->edge;
        resid->reverse_edge = real->reverse_edge;
        resid->start = b;
        resid->end = a;
        resid->index = USHRT_MAX;
        resid->residual = 1;
        /* Add to the Flow_Edge Linked List */
        resid->next = Flow_Edge_Head.next;
        Flow_Edge_Head.next = resid;
        b->outgoing[b->outgoing_num] = resid;
        b->outgoing_num++;
        a->incoming[a->incoming_num] = resid;
        a->incoming_num++;

        /* Point the edges to each other */
        real->twin = resid;
        resid->twin = real;

        /* Only create this pair if undirected is set to TRUE */
        if (Directed_Edges == 0) {
            a = Flow_Nodes_Outbound[d];
            b = Flow_Nodes_Inbound[s];

            /* Create real edge between node pair */
            real = Mem_alloc(sizeof(Flow_Edge));
            real->flow = 0;
            real->capacity = 1;
            real->edge = Get_Edge(temp_node_ip[d], temp_node_ip[s]);
            if (real->edge == NULL)
                Alarm(EXIT, "Init_MultiPath: Unable to find edge between %hu and %hu\r\n", d, s);
            real->reverse_edge = Get_Edge(temp_node_ip[s], temp_node_ip[d]);
            if (real->reverse_edge == NULL)
                Alarm(EXIT, "Init_MultiPath: Unable to find edge between %hu and %hu\r\n", s, d);
            real->start = a;
            real->end = b;
            real->index = val.index;
            real->residual = 0;
            /* Add to the Flow_Edge Linked List */
            real->next = Flow_Edge_Head.next;
            Flow_Edge_Head.next = real;
            a->outgoing[a->outgoing_num] = real;
            a->outgoing_num++;
            b->incoming[b->incoming_num] = real;
            b->incoming_num++;
            
            /* Create residual edge between node pair */
            resid = Mem_alloc(sizeof(Flow_Edge));
            resid->flow = 1;
            resid->capacity = 1;
            resid->edge = real->edge;
            resid->reverse_edge = real->reverse_edge;
            resid->start = b;
            resid->end = a;
            resid->index = USHRT_MAX;
            resid->residual = 1;
            /* Add to the Flow_Edge Linked List */
            resid->next = Flow_Edge_Head.next;
            Flow_Edge_Head.next = resid;
            b->outgoing[b->outgoing_num] = resid;
            b->outgoing_num++;
            a->incoming[a->incoming_num] = resid;
            a->incoming_num++;

            /* Point the edges to each other */
            real->twin = resid;
            resid->twin = real;
        }

        stdskl_it_next(&it);
    }

    /* Init Static Dissemination Graphs */
    DG_Compute_Graphs();
}

void MultiPath_Clear_Cache()
{
    int i, j;

    for (i = 0; i <= MAX_NODES; i++) {
        for (j = 0; j <= MULTIPATH_MAX_K; j++) {
            if (MP_Cache[i][j] != NULL)
                dispose(MP_Cache[i][j]);
            MP_Cache[i][j] = NULL;
        }
    }
}

int MultiPath_Compute(int16u dest_id, int16u k, unsigned char **ret_mask, int use_base_cost, int require_reverse)
{
    int i, path_index, progress = 0; /* total_cost; */
    unsigned char *mask;
    stdhash bag_of_edges;
    int16 cost = 0, c1, c2;
    Flow_Edge *e;
    Flow_Node *t;
    stdit it;
    sp_time start, stop;

    start = E_get_time();

    /* Special case for myself: don't need to send anywhere else, so just set
     * bitmask to all zeros */
    if (dest_id == My_ID) {
        /*MP_Cache[dest_id][k] = mask;*/
        if (ret_mask != NULL) {
            mask = new(MP_BITMASK);
            memset(mask, 0x00, MultiPath_Bitmask_Size);
            *ret_mask = mask;
        }

        return k;
    }

    /* Iterate through Flow_Edges to initalize flow on each edge, 
     *      real edges get flow = 0, residual get flow = capacity */
    e = Flow_Edge_Head.next;
    while (e != NULL) {
        if (e->residual == 0)
            e->flow = 0;
        else
            e->flow = e->capacity;
        e = e->next;
    }

    /* Construct the hash table which will keep track of the edges
     *      traversed by the Bellman-Ford iterations */
    stdhash_construct(&bag_of_edges, sizeof(Flow_Edge*), 0, NULL, NULL, 0);

    /* FORD-FULKERSON START */
    for (path_index = 1; path_index <= k; path_index++) {

        /* BELLMAN-FORD START */
        /* Step 1: Initialize the graph: 
         *      Each vertex gets distance = "INF" and predecessor = NULL */
        for (i = 1; i <= MAX_NODES; i++) {
            if (Flow_Nodes_Inbound[i] != NULL) {
                Flow_Nodes_Inbound[i]->previous_edge = NULL;
                Flow_Nodes_Inbound[i]->distance = USHRT_MAX;
            }
            if (Flow_Nodes_Outbound[i] != NULL) {
                Flow_Nodes_Outbound[i]->previous_edge = NULL;
                Flow_Nodes_Outbound[i]->distance = USHRT_MAX;
            }
        }
        Flow_Nodes_Outbound[My_ID]->distance = 0;

        /* Step 2: Relax edges repeatedly */
        for (i = 1; i <= Num_Nodes * 2 + 1; i++) {
            progress = 0;
            e = Flow_Edge_Head.next;
            while (e != NULL) {
                if (e->edge == NULL && e->reverse_edge == NULL)
                    cost = 0;
                else if (e->edge == NULL || e->reverse_edge == NULL)
                    Alarm(EXIT, "Multipath_Compute: Edge or Reverse is NULL\n");
                else {
                    if (use_base_cost) {
                        c1 = e->edge->base_cost;
                        c2 = e->reverse_edge->base_cost;
                    } else {
                        c1 = e->edge->cost;
                        c2 = e->reverse_edge->cost;
                        /* link is considered broken if either is -1 */
                        if (c1 == -1 || (require_reverse && c2 == -1)) {
                            e = e->next;
                            continue;
                        }
                        /* AB: negative costs are legal now */
                        c1 = abs(e->edge->cost);
                        c2 = abs(e->reverse_edge->cost);
                    }
                    if (require_reverse)
                        cost = (c1 > c2) ? c1 : c2;
                    else
                        cost = c1;
                }
                /* if edge is residual, flip cost */
                if (e->residual == 1)
                    cost = -cost;
                if (e->flow < e->capacity &&
                    e->end->distance > e->start->distance + cost) 
                {
                    e->end->distance = e->start->distance + cost;
                    e->end->previous_edge = e;
                    progress = 1;
                }
                e = e->next;
            }
            if (progress == 0)
                break;
        }

        /* Step 3: Modified (using Progress variable) way to check for
         *      negative cycles */
        if (progress == 1)
            Alarm(EXIT, "MultiPath_Compute: Negative Cycle Found\r\n");

        /* BELLMAN-FORD END */

        if (Flow_Nodes_Inbound[dest_id]->distance == USHRT_MAX)
            break;
        
        /* Path Augmentation and Add Edges to Bag */
        t = Flow_Nodes_Inbound[dest_id];
        while (t != Flow_Nodes_Outbound[My_ID]) {
            if (t->previous_edge->residual == 1) {
                stdhash_find(&bag_of_edges, &it, &(t->previous_edge->twin));
                stdhash_erase(&bag_of_edges, &it);
            }
            else
                stdhash_insert(&bag_of_edges, &it, &(t->previous_edge), 0);
            t->previous_edge->flow = t->previous_edge->capacity;
            t->previous_edge->twin->flow = 0;
            t = t->previous_edge->start;
        }

    } /* FORD-FULKERSON END */

    /* Construct bitmask */
    if (ret_mask != NULL) {
        mask = new(MP_BITMASK);
        memset(mask, 0x00, MultiPath_Bitmask_Size);

        stdhash_begin(&bag_of_edges, &it);
        /* j = 0; */ /* Added for testing */
        /* total_cost = 0; */ /* Added for testing */
        /*printf("Edges: ");*/
        while(!stdhash_is_end(&bag_of_edges, &it)) {
            e = *((Flow_Edge**)stdhash_it_key(&it));
            if (e->edge != NULL && ret_mask != NULL) {
                *(mask + (e->index / 8)) |= 0x80 >> (e->index % 8);
                /* j++; */ /* Added for testing */
                /* printf("  %d  ", e->index); *//* Added for testing */
                /* total_cost += e->edge->cost; */ /* Added for testing */
            }
            stdhash_erase(&bag_of_edges, &it);
        }
        /* printf("\n"); */

        /* Return the computed mask as ret_mask */
        *ret_mask = mask;
    }

    if (path_index - 1 > k)
        Alarm(EXIT, "MultiPath_Compute: paths found (%d) > k (%d) !!!\r\n",
                path_index - 1, k);

    /* Cleanup the hash table */
    stdhash_destruct(&bag_of_edges);
   
    stop = E_get_time();

    Alarm(DEBUG, "Computation took %f seconds.\r\n",
        (stop.sec - start.sec) + (stop.usec - start.usec) / 1.0e6);

    return path_index - 1;
}

int MultiPath_Stamp_Bitmask(int16u dest_id, int16u k, unsigned char *mask)
{
    int i, ret;
    int64u *tmp_msk, *tmp_dg_msk;
    DG_Dst *dg_dst;

    if ((dest_id == 0 && k > 0) || dest_id > MAX_NODES) {
        Alarm(PRINT, "Multipath_Stamp_Bitmask: invalid destination ID "
            "specified (%hu)\r\n", dest_id);
        return 0;
    }
 
    if (k > MULTIPATH_MAX_K && k != DG_K_FLAG) {
        Alarm(PRINT, "Multipath_Stamp_Bitmask: Requested K (%d) is"
                " larger than max supported K (%d), defaulting to"
                " max supported K value\r\n", k, MULTIPATH_MAX_K);
        k = MULTIPATH_MAX_K;
    }
   
    /* Overlay Flooding */
    if (k == 0) {
        memcpy(mask, MP_Flooding_Bitmask, MultiPath_Bitmask_Size);
        return 1;
    }

    /* Dissemination Graphs (Targeted redundancy) */
    if (k == DG_K_FLAG) {
        dg_dst = &DG_Destinations[dest_id];

        if (dg_dst->current_graph_type == DG_SRC_GRAPH || 
            dg_dst->current_graph_type == DG_DST_GRAPH)
        {
            memcpy(mask, dg_dst->bitmasks[dg_dst->current_graph_type], MultiPath_Bitmask_Size);
            return 1;
        } else if (dg_dst->current_graph_type == DG_K2_GRAPH ||
                   dg_dst->current_graph_type == DG_SRC_DST_GRAPH)
        {
            if (MP_Cache[dest_id][2] == NULL) {
                Alarm(PRINT, "COMPUTING [%u,%u] for k = %u\r\n", My_ID, dest_id, 2);

                /* Amy: Note that "require_reverse" option to MultiPath_Compute was
                 * previously always set to 1. This may matter for the
                 * intrusion-tolerant protocols. Should revisit how to unify. */
                ret = MultiPath_Compute(dest_id, 2, &MP_Cache[dest_id][2], 0, 0);
                if (ret == 0) {
                    Alarm(PRINT, "MultiPath_Stamp_Bitmask: Warning! Compute returned 0, "
                        "no paths found with current network conditions\r\n");
                    /* This is not necessarily an error: If a message is destined to
                     * myself, I can still deliver it with a bitmask of all 0s */
                    /*return 0;*/
                }
            }
            memcpy(mask, MP_Cache[dest_id][2], MultiPath_Bitmask_Size);

            if (dg_dst->current_graph_type == DG_SRC_DST_GRAPH)
            {
                tmp_msk = (int64u *) mask;
                tmp_dg_msk = (int64u *) dg_dst->bitmasks[DG_SRC_DST_GRAPH];

                for (i = 0; i < MultiPath_Bitmask_Size/sizeof(int64u); i++)
                    *tmp_msk++ |= *tmp_dg_msk++;
            }
            return 1;
        } else { /* DG_NONE_GRAPH */ 
            /* Default to 2 paths if static graphs are not given */
            Alarm(PRINT, "Dissem graphs specified, but mask is NULL...defaulting to k = 2\n");
            k = 2;
        }
    }

    /* K Node Disjoint Paths */
    if (MP_Cache[dest_id][k] == NULL) {
        Alarm(PRINT, "COMPUTING [%u,%u] for k = %u\r\n", My_ID, dest_id, k);

        /* Amy: Note that "require_reverse" option to MultiPath_Compute was
         * previously always set to 1. This may matter for the
         * intrusion-tolerant protocols. Should revisit how to unify. */
        ret = MultiPath_Compute(dest_id, k, &MP_Cache[dest_id][k], 0, 0);
        if (ret == 0) {
            Alarm(PRINT, "MultiPath_Stamp_Bitmask: Warning! Compute returned 0, "
                "no paths found with current network conditions\r\n");
            /* This is not necessarily an error: If a message is destined to
             * myself, I can still deliver it with a bitmask of all 0s */
            /*return 0;*/
        }
        else if (ret < k) {
            /* If we didn't find all the paths we requested, update cache for
             * all higher numbers of paths as well (since we won't be able to
             * compute the requested number for those either) */
            for (i = ret; i <= MULTIPATH_MAX_K; i++) {
                if (i == k) continue;

                if (MP_Cache[dest_id][i] != NULL)
                    dispose(MP_Cache[dest_id][i]);
                MP_Cache[dest_id][i] = new(MP_BITMASK);
                memcpy(MP_Cache[dest_id][i], MP_Cache[dest_id][k], MultiPath_Bitmask_Size);
            }
                
            Alarm(PRINT, "MultiPath_Stamp_Bitmask: Requested K = %d, "
                "Compute found %d\r\n", k, ret);
        }
    }

    memcpy(mask, MP_Cache[dest_id][k], MultiPath_Bitmask_Size);
    return 1;
}

int MultiPath_Neighbor_On_Path(unsigned char *mask, int16u ngbr_iter)
{
    int64u temp = 0;
    int64u *mask_ptr = (int64u*) mask;
    int64u *ngbr_ptr = (int64u*) MP_Neighbor_Mask[ngbr_iter];
    int64u i;

    for (i = 0; i < MultiPath_Bitmask_Size/sizeof(int64u); i++)
        temp = temp | (*(mask_ptr+i) & *(ngbr_ptr+i));

    if (temp)
        return 1;
    return 0;
}

int MultiPath_Is_Superset(unsigned char *old_mask, unsigned char *new_mask)
{
    int64u *old_mask_ptr = (int64u*) old_mask;
    int64u *new_mask_ptr = (int64u*) new_mask;
    unsigned char tmp1[MultiPath_Bitmask_Size];
    unsigned char tmp2[MultiPath_Bitmask_Size];
    int64u *tmp1_ptr = (int64u*) tmp1; 
    int64u *tmp2_ptr = (int64u*) tmp2;
    int64u tmp1_val = 0;
    int64u tmp2_val = 0;
    int16u i;
    
    for (i = 0; i < MultiPath_Bitmask_Size/sizeof(int64u); i++)
        *(tmp1_ptr + i) = *(old_mask_ptr+i) ^ *(new_mask_ptr+i);
    
    for (i = 0; i < MultiPath_Bitmask_Size/sizeof(int64u); i++)
        *(tmp2_ptr + i) = *(old_mask_ptr+i) & *(tmp1_ptr+i);
    
    /* When this for loop is finished:
     *  tmp1_val is 0 if and only if all bits in tmp1 are 0 
     *  tmp2_val is 0 if and only if all bits in tmp2 are 0 */
    for (i = 0; i < MultiPath_Bitmask_Size/sizeof(int64u); i++) {
        tmp1_val = tmp1_val | *(tmp1_ptr + i);
        tmp2_val = tmp2_val | *(tmp2_ptr + i);
    }

    if (tmp1_val != 0 && tmp2_val == 0)
        return 1;
    else
        return 0;
}

void MultiPath_Create_Superset(unsigned char *old_mask, unsigned char *new_mask)
{
    int64u *old_mask_ptr = (int64u*) old_mask;
    int64u *new_mask_ptr = (int64u*) new_mask;
    int16u i;
    
    for (i = 0; i < MultiPath_Bitmask_Size/sizeof(int64u); i++)
        *(old_mask_ptr + i) = *(old_mask_ptr+i) | *(new_mask_ptr+i);
}

int MultiPath_Is_Equal(unsigned char *old_mask, unsigned char *new_mask)
{
    int64u *old_mask_ptr = (int64u*) old_mask;
    int64u *new_mask_ptr = (int64u*) new_mask;
    int16u i;
    
    for (i = 0; i < MultiPath_Bitmask_Size/sizeof(int64u); i++) {
        if (*(old_mask_ptr+i) != *(new_mask_ptr+i))
            return 0;
    }
    /* If all parts of the masks matched, the masks are equal (return 1) */
    return 1;
}
