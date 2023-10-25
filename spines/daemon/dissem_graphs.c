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
#include <float.h>
#include <string.h>
#include "stdutil/stdskl.h"
#include "stdutil/stdhash.h"
#include "spu_alarm.h"
#include "configuration.h"

#define ext_dg
#include "dissem_graphs.h"
#undef ext_dg

/* Data types used for representing graphs during dissemination graph
 * computation */
typedef struct DG_Node {
    Node_ID id;
} DG_Node;

typedef struct DG_Edge
{
    stdit  src_it;
    stdit  dst_it;
    double cost;
    int16u index;
} DG_Edge;

typedef struct Graph {
    stdskl Nodes;
    stdskl Edges;
} Graph;

typedef struct SP_Node {
    Node_ID         id;
    struct SP_Node *prev;
    DG_Edge        *prev_edge;
    double          prev_dist;
    double          src_dist;
    stdskl          nghbrs; /* list of adjacent nodes, sorted by cost of connecting edge */
} SP_Node;

typedef struct Steiner_Node {
    Node_ID id;
    int     target;
    double  max_dist;
    int     optional_index;
} Steiner_Node;

typedef struct Steiner_Edge {
    Steiner_Node *src;
    Steiner_Node *dst;
    double        cost;
    DG_Edge      *edge_ref;
} Steiner_Edge;

/* Used for checking that source-dest graph includes two disjoint paths */
typedef struct SD_Edge {
    Edge *edge;
    int   in_sd_graph;
} SD_Edge;

/* Variables for maintaining state about source/destination problems for my
 * flows */
static DG_Src  DG_Source;
static stdskl  DG_Problem_List;

/* Basic graph construction functions */
static void Graph_Init(Graph *g);
static void Graph_Finish(Graph *g);
static void Graph_add_edge(Graph *g, int src, int dst, double cost, int16u index);
static stdit Graph_add_node(Graph *g, Node_ID id);
static int Edge_Ptr_Cmp(const void *l, const void *r);
static int Node_Cmp(const void *l, const void *r);
static int DG_Edge_Cmp(const void *l, const void *r);
static int DG_Edge_In_Graph(int16u edge_index, unsigned char *graph_mask);

/* Shortest path functions */
static double Shortest_Path(Graph *g, Node_ID src, Node_ID dst);
static Graph *Shortest_Path_Tree(Graph *g, Node_ID src);
static stdit SP_Add_Node(stdskl *skl, Node_ID id);
static void SP_Add_Edge(stdskl *skl, Node_ID src_id, Node_ID dst_id, DG_Edge *e);

/* Source and/or Destination problem Steiner Tree functions */
static unsigned char *Source_Destination_Problem_Bitmask_from_SDP_Graphs(Node_ID src_id,
    Node_ID dst_id, double max_latency, Graph *src_graph, Graph *dst_graph,
    int available_paths, stdskl *k2_edges);
static Graph *Source_Problem_Graph(Graph *g, Node_ID src_id, Node_ID dst_id, double max_latency);
static Graph *Destination_Problem_Graph(Graph *g, Node_ID src_id, Node_ID dst_id, double max_latency);
static Graph *Minimum_SP_Steiner_Tree(Graph *g, stdskl *Steiner_nodes, stdskl *Steiner_edges, Node_ID src_id, Node_ID dst_id);
static stdit Steiner_Add_Node(stdskl *nodes, Node_ID id, int target, double max_dist);
static stdit Steiner_Add_Edge(stdskl *nodes, stdskl *edges, DG_Edge *e, double cost);

static unsigned char *Graph_to_Bitmask(Graph *g);
void Set_Edges_to_Base_Cost(Graph *g);

/* Converts graph to bitmask */
static unsigned char *Graph_to_Bitmask(Graph *g)
{
    unsigned char *ret_mask;
    stdit it;
    Edge_Key e_key;
    DG_Edge *dg_edge;

    if ((ret_mask = new(MP_BITMASK)) == NULL) {
        Alarm(EXIT, "Graph_to_Bitmask: could not allocate bitmask\n");
    }
    memset(ret_mask, 0x00, MultiPath_Bitmask_Size);

    if (g != NULL) {
        for (stdskl_begin(&g->Edges, &it); !stdskl_is_end(&g->Edges, &it); stdit_next(&it))
        {
            e_key = *(Edge_Key *)stdskl_it_key(&it);
            dg_edge = (DG_Edge *)stdskl_it_val(&it);
            *(ret_mask + (dg_edge->index / 8)) |= 0x80 >> (dg_edge->index % 8);
        }
    }

    return ret_mask;
}

static void Graph_Init(Graph *g)
{
    if (g == NULL) return;

    stdskl_construct(&g->Edges, sizeof(Edge_Key), sizeof(DG_Edge), DG_Edge_Cmp);
    stdskl_construct(&g->Nodes, sizeof(Node_ID), sizeof(DG_Node), Node_Cmp);
}

static void Graph_Finish(Graph *g)
{
    if (g == NULL) return;

    stdskl_destruct(&g->Edges);
    stdskl_destruct(&g->Nodes);
}

void Graph_add_edge(Graph *g, int h1, int h2, double c, int16u index) 
{
    stdit it;
    Edge_Key key;
    DG_Edge val;

    Alarm(DEBUG, "Graph_add_edge invoked between %d and %d\n", h1, h2);
 
    if (h1 == h2) {
        Alarm(PRINT, "Graph_add_edge: Ignoring edge (%d, %d) since both"
                " endpoints are the same node\r\n", h1, h2);
        return;
    }

    /* Set up key: for undirected edges, always make lower node index "src" and
     * higher node index "dst" for consistency */
    if (Directed_Edges == 0) {
        if (h1 < h2) {
            key.src_id = h1;
            key.dst_id = h2;
        }
        else {
            key.src_id = h2;
            key.dst_id = h1;
        }
    }
    else { /* Directed_Edges == 1 */
        key.src_id = h1;
        key.dst_id = h2;
    }

    /* Check that the key doesn't already exist */
    stdskl_lowerb(&g->Edges, &it, &key);
    if (!stdskl_is_end(&g->Edges, &it) && DG_Edge_Cmp(&key, (Edge_Key *)stdit_key(&it)) == 0)
        return;

    /* Key wasn't present, so insert it now */
    val.src_it = Graph_add_node(g, key.src_id);
    val.dst_it = Graph_add_node(g, key.dst_id);
    val.cost = c;
    val.index = index;

    stdskl_insert(&g->Edges, &it, &key, &val, STDTRUE);

    return;
}

static stdit Graph_add_node(Graph *g, Node_ID id)
{
    stdit it;
    DG_Node *node_ptr;
    DG_Node new_node;

    stdskl_lowerb(&g->Nodes, &it, &id);
    node_ptr = (DG_Node *)stdit_val(&it);

    /* Relevant node already exists */
    if (!stdskl_is_end(&g->Nodes, &it) && node_ptr->id == id) return it;

    /* If ID doesn't already exist, insert new node */
    new_node.id = id;
    stdskl_insert(&g->Nodes, &it, &new_node.id, &new_node, STDTRUE);

    return it;
}

int DG_Edge_Cmp(const void *l, const void *r)
{
    Edge_Key *left  = (Edge_Key*)l;
    Edge_Key *right = (Edge_Key*)r;

    if (left->src_id < right->src_id)
        return -1; 
    else if (left->src_id > right->src_id)
        return 1;
    else {
        if (left->dst_id < right->dst_id)
            return -1; 
        else if (left->dst_id > right->dst_id)
            return 1;
        else
            return 0;
    }   
}

static int Node_Cmp(const void *l, const void *r)
{
    if (*(Node_ID *) l < *(Node_ID *)r)
        return -1;
    else if (*(Node_ID *) l > *(Node_ID *)r)
        return 1;
    else
        return 0;
}

static Graph *Destination_Problem_Shortest_Path_Tree(Graph *g, Node_ID src, Node_ID dst, double max_latency)
{
    stdskl sp_nodes;
    stdhash finished_sp_nodes;
    SP_Node *min;
    SP_Node *n;
    DG_Edge *e;
    Edge_Key *e_key;
    Edge_Key search_key;
    DG_Edge *search_val;
    Graph *result_g;
    stdit it, nit, min_it, sit;
    double cost;

    Alarm(DEBUG, "Destination_Problem_Shortest_Path_Tree called for source %lu\n", src);

    /* Initialize result graph */
    if ((result_g = malloc(sizeof(Graph))) == NULL) {
        Alarm(EXIT, "ERROR: failed to allocate graph\n");
    }
    Graph_Init(result_g);

    /* Build list of SP_Nodes and start building result */
    stdskl_construct(&sp_nodes, sizeof(Node_ID), sizeof(SP_Node *), Node_Cmp);
    stdhash_construct(&finished_sp_nodes, sizeof(Node_ID), sizeof(SP_Node *), Node_Cmp, 0, 0);
    SP_Add_Node(&sp_nodes, src);
    for (stdskl_begin(&g->Edges, &it); !stdskl_is_end(&g->Edges, &it); stdskl_it_next(&it))
    {
        e = (DG_Edge *)stdskl_it_val(&it);
        e_key = (Edge_Key *)stdskl_it_key(&it);

        /* Don't include edges adjacent to the destination, since we don't want
         * to use those in our tree to the target neighbors */
        if (e_key->src_id == dst || e_key->dst_id == dst)
            continue;

        SP_Add_Edge(&sp_nodes, e_key->src_id, e_key->dst_id, e);
    }

    /* Initialize source to distance 0 */
    stdskl_find(&sp_nodes, &it, &src);
    if (stdskl_is_end(&sp_nodes, &it)) {
        Alarm(DEBUG, "Shortest_Path_Tree: Error: source does not appear in graph\n");
        goto end;
    }
    n = *(SP_Node **) stdit_val(&it);
    n->src_dist = 0;

    /* Find shortest path from source to all other nodes */
    while (!stdskl_empty(&sp_nodes))
    {
        /* Find the node at the shortest distance from the source */
        min = NULL;
        for (stdskl_begin(&sp_nodes, &it); !stdskl_is_end(&sp_nodes, &it); stdit_next(&it))
        {
            n = *(SP_Node **) stdit_val(&it);
            if (min == NULL || n->src_dist < min->src_dist) {
                min = n;
                min_it = it;
            }
        }

        /* If no node was reachable from the source, there is no path and we're done */
        if (min->src_dist == DBL_MAX) {
            break;
        }

        /* Otherwise, we found some node, so update its neighbors' distances from the source */
        for (stdskl_begin(&min->nghbrs, &nit); !stdskl_is_end(&min->nghbrs, &nit); stdskl_it_next(&nit))
        {
            n = *(SP_Node **)stdskl_it_val(&nit);
            e = *(DG_Edge **)stdskl_it_key(&nit);
            cost = e->cost;

            /* See if you can update distance */
            if (min->src_dist + cost < n->src_dist) {
                if (n->src_dist == DBL_MAX) n->src_dist = -1;
                Alarm(DEBUG, "Updated %lu's distance from %f to %f\n", n->id, n->src_dist, min->src_dist + cost);
                n->src_dist = min->src_dist + cost;
                n->prev = min;
                n->prev_dist = cost;
                n->prev_edge = e;
            }
        }

        /* Move handled node to finished list */
        stdskl_erase(&sp_nodes, &min_it);
        stdhash_insert(&finished_sp_nodes, &nit, &min->id, &min);
    }

    /* Add relevant paths to result graph */
    /* Make sure src always appears, to handle case of single-node graph */
    Graph_add_node(result_g, src); 
    for (stdhash_begin(&finished_sp_nodes, &it); !stdhash_is_end(&finished_sp_nodes, &it); stdit_next(&it))
    {
        n = *(SP_Node **)stdit_val(&it);

        /* Check and see if this node is a viable target neigbor of the
         * destination. If not, we don't care about it so just continue */
        search_key.src_id = n->id;
        search_key.dst_id = dst;
        /* Not a neighbor of the destination */
        stdskl_find(&g->Edges, &sit, &search_key);
        if (stdskl_is_end(&g->Edges, &sit))
            continue;
        /* Not reachable within the time constraint */
        search_val = (DG_Edge *) stdskl_it_val(&sit);
        if (search_val->cost + n->src_dist > max_latency)
            continue;

        /* add in the edge connecting this node to the destination */
        Alarm(DEBUG, "Adding edge (%d, %d): %f, %hu\n", n->id, dst, search_val->cost, search_val->index);
        Graph_add_edge(result_g, n->id, dst, search_val->cost, search_val->index);

        /* This is a viable target! Add its path from the source to our graph
         * */
        Alarm(DEBUG, "Target destination neighbor %d for (%d,%d)\t:\t%f + %f = %f < %f\n", n->id, src, dst, search_val->cost, n->src_dist, search_val->cost + n->src_dist, max_latency);
        while (n->id != src)
        {
            Alarm(DEBUG, "Adding edge (%d, %d): %f, %hu\n", n->prev->id, n->id, n->prev_dist, n->prev_edge->index);
            Graph_add_edge(result_g, n->prev->id, n->id, n->prev_dist, n->prev_edge->index);
            n = n->prev;
        }
    }

    /* Warn if not all nodes were reachable */
    if (!stdskl_empty(&sp_nodes)) {
        Alarm(DEBUG, "Shortest_Path_Tree: Not all nodes were reachable from source %lu!\n", src);
    }

    /* Clean up */
end:
    for (stdskl_begin(&sp_nodes, &it); !stdskl_is_end(&sp_nodes, &it); stdit_next(&it))
    {
        stdskl_destruct(&(*(SP_Node **)stdit_val(&it))->nghbrs);
        free(*(SP_Node **)stdit_val(&it));
    }
    for (stdhash_begin(&finished_sp_nodes, &it); !stdhash_is_end(&finished_sp_nodes, &it); stdit_next(&it))
    {
        stdskl_destruct(&(*(SP_Node **)stdit_val(&it))->nghbrs);
        free(*(SP_Node **)stdit_val(&it));
    }
    stdskl_destruct(&sp_nodes);
    stdhash_destruct(&finished_sp_nodes);

    return result_g;
}

static Graph *Shortest_Path_Tree(Graph *g, Node_ID src)
{
    stdskl sp_nodes;
    stdhash finished_sp_nodes;
    SP_Node *min;
    SP_Node *n;
    DG_Edge *e;
    Edge_Key *e_key;
    Graph *result_g;
    stdit it, nit, min_it;
    double cost;

    Alarm(DEBUG, "Shortest_Path_Tree called for source %lu\n", src);

    /* Initialize result graph */
    if ((result_g = malloc(sizeof(Graph))) == NULL) {
        Alarm(EXIT, "ERROR: failed to allocate graph\n");
    }
    Graph_Init(result_g);

    /* Build list of SP_Nodes and start building result */
    stdskl_construct(&sp_nodes, sizeof(Node_ID), sizeof(SP_Node *), Node_Cmp);
    stdhash_construct(&finished_sp_nodes, sizeof(Node_ID), sizeof(SP_Node *), Node_Cmp, 0, 0);
    SP_Add_Node(&sp_nodes, src);
    for (stdskl_begin(&g->Edges, &it); !stdskl_is_end(&g->Edges, &it); stdskl_it_next(&it))
    {
        e = (DG_Edge *)stdskl_it_val(&it);
        e_key = (Edge_Key *)stdskl_it_key(&it);
        SP_Add_Edge(&sp_nodes, e_key->src_id, e_key->dst_id, e);
    }

    /* Initialize source to distance 0 */
    stdskl_find(&sp_nodes, &it, &src);
    if (stdskl_is_end(&sp_nodes, &it)) {
        Alarm(DEBUG, "Shortest_Path_Tree: Error: source does not appear in graph\n");
        goto end;
    }
    n = *(SP_Node **) stdit_val(&it);
    n->src_dist = 0;

    /* Find shortest path from source to all other nodes */
    while (!stdskl_empty(&sp_nodes))
    {
        /* Find the node at the shortest distance from the source */
        min = NULL;
        for (stdskl_begin(&sp_nodes, &it); !stdskl_is_end(&sp_nodes, &it); stdit_next(&it))
        {
            n = *(SP_Node **) stdit_val(&it);
            if (min == NULL || n->src_dist < min->src_dist) {
                min = n;
                min_it = it;
            }
        }

        /* If no node was reachable from the source, there is no path and we're done */
        if (min->src_dist == DBL_MAX) {
            break;
        }

        /* Otherwise, we found some node, so update its neighbors' distances from the source */
        for (stdskl_begin(&min->nghbrs, &nit); !stdskl_is_end(&min->nghbrs, &nit); stdskl_it_next(&nit))
        {
            n = *(SP_Node **)stdskl_it_val(&nit);
            e = *(DG_Edge **)stdskl_it_key(&nit);
            cost = e->cost;

            /* See if you can update distance */
            if (min->src_dist + cost < n->src_dist) {
                if (n->src_dist == DBL_MAX) n->src_dist = -1;
                Alarm(DEBUG, "Updated %lu's distance from %f to %f\n", n->id, n->src_dist, min->src_dist + cost);
                n->src_dist = min->src_dist + cost;
                n->prev = min;
                n->prev_dist = cost;
                n->prev_edge = e;
            }
        }

        /* Move handled node to finished list */
        stdskl_erase(&sp_nodes, &min_it);
        stdhash_insert(&finished_sp_nodes, &nit, &min->id, &min);
    }

    /* Add relevant paths to result graph */
    /* Make sure src always appears, to handle case of single-node graph */
    Graph_add_node(result_g, src); 
    for (stdhash_begin(&finished_sp_nodes, &it); !stdhash_is_end(&finished_sp_nodes, &it); stdit_next(&it))
    {
        n = *(SP_Node **)stdit_val(&it);
        while (n->id != src)
        {
            Graph_add_edge(result_g, n->prev->id, n->id, n->prev_dist, n->prev_edge->index);
            n = n->prev;
        }
    }

    /* Warn if not all nodes were reachable */
    if (!stdskl_empty(&sp_nodes)) {
        Alarm(DEBUG, "Shortest_Path_Tree: Not all nodes were reachable from source %lu!\n", src);
    }

    /* Clean up */
end:
    for (stdskl_begin(&sp_nodes, &it); !stdskl_is_end(&sp_nodes, &it); stdit_next(&it))
    {
        stdskl_destruct(&(*(SP_Node **)stdit_val(&it))->nghbrs);
        free(*(SP_Node **)stdit_val(&it));
    }
    for (stdhash_begin(&finished_sp_nodes, &it); !stdhash_is_end(&finished_sp_nodes, &it); stdit_next(&it))
    {
        stdskl_destruct(&(*(SP_Node **)stdit_val(&it))->nghbrs);
        free(*(SP_Node **)stdit_val(&it));
    }
    stdskl_destruct(&sp_nodes);
    stdhash_destruct(&finished_sp_nodes);

    return result_g;
}

static double Shortest_Path(Graph *g, Node_ID src, Node_ID dst)
{
    stdskl sp_nodes, finished_sp_nodes;
    SP_Node *min;
    SP_Node *n;
    DG_Edge *e;
    Edge_Key *e_key;
    stdit it, nit, min_it;
    double cost, ret;

    Alarm(DEBUG, "Shortest_Path called for source %lu, destination %lu\n", src, dst);

    ret = DBL_MAX;

    if (g == NULL) {
        Alarm(PRINT, "Shortest_Path: Input graph is NULL\n");
        goto end;
    }

    /* Build list of SP_Nodes and start building result */
    stdskl_construct(&sp_nodes, sizeof(Node_ID), sizeof(SP_Node *), Node_Cmp);
    SP_Add_Node(&sp_nodes, src);
    for (stdskl_begin(&g->Edges, &it); !stdskl_is_end(&g->Edges, &it); stdskl_it_next(&it))
    {
        e = (DG_Edge *)stdskl_it_val(&it);
        e_key = (Edge_Key *)stdskl_it_key(&it);
        SP_Add_Edge(&sp_nodes, e_key->src_id, e_key->dst_id, e);
    }

    /* Initialize source to distance 0 */
    stdskl_find(&sp_nodes, &it, &src);
    if (stdskl_is_end(&sp_nodes, &it)) {
        Alarm(PRINT, "Shortest_Path: Error: source does not appear in graph\n");
        goto end_destruct_sp_nodes;
    }
    n = *(SP_Node **) stdit_val(&it);
    n->src_dist = 0;

    /* Find shortest path from source to all other nodes */
    stdskl_construct(&finished_sp_nodes, sizeof(Node_ID), sizeof(SP_Node *), Node_Cmp);
    while (!stdskl_empty(&sp_nodes))
    {
        /* Find the node at the shortest distance from the source */
        min = NULL;
        for (stdskl_begin(&sp_nodes, &it); !stdskl_is_end(&sp_nodes, &it); stdit_next(&it))
        {
            n = *(SP_Node **) stdit_val(&it);
            if (min == NULL || n->src_dist < min->src_dist) {
                min = n;
                min_it = it;
            }
        }

        /* If no node was reachable from the source, there is no path and we're done */
        if (min->src_dist == DBL_MAX) {
            break;
        }

        /* If our target destination is now the closest to the source, we're
         * done, since we will never improve it */
        if (min->id == dst) {
            ret = min->src_dist;
            goto end_destruct_finished_nodes;
        }

        /* Otherwise, we found some node, so update its neighbors' distances from the source */
        for (stdskl_begin(&min->nghbrs, &nit); !stdskl_is_end(&min->nghbrs, &nit); stdskl_it_next(&nit))
        {
            n = *(SP_Node **)stdskl_it_val(&nit);
            e = *(DG_Edge **)stdskl_it_key(&nit);
            cost = e->cost;

            /* See if you can update distance */
            if (min->src_dist + cost < n->src_dist) {
                if (n->src_dist == DBL_MAX) n->src_dist = -1;
                Alarm(DEBUG, "Updated %lu's distance from %f to %f\n", n->id, n->src_dist, min->src_dist + cost);
                n->src_dist = min->src_dist + cost;
                n->prev = min;
                n->prev_edge = e;
            }
        }

        /* Move handled node to finished list */
        stdskl_erase(&sp_nodes, &min_it);
        stdskl_insert(&finished_sp_nodes, &nit, &min->id, &min, STDFALSE);
    }

    /* Finished, clean up */
end_destruct_finished_nodes:
    for (stdskl_begin(&finished_sp_nodes, &it); !stdskl_is_end(&finished_sp_nodes, &it); stdit_next(&it))
    {
        stdskl_destruct(&(*(SP_Node **)stdit_val(&it))->nghbrs);
        free(*(SP_Node **)stdit_val(&it));
    }
    stdskl_destruct(&finished_sp_nodes);

end_destruct_sp_nodes:
    for (stdskl_begin(&sp_nodes, &it); !stdskl_is_end(&sp_nodes, &it); stdit_next(&it))
    {
        stdskl_destruct(&(*(SP_Node **)stdit_val(&it))->nghbrs);
        free(*(SP_Node **)stdit_val(&it));
    }
    stdskl_destruct(&sp_nodes);

end:
    return ret;
}

static stdit SP_Add_Node(stdskl *skl, Node_ID id)
{
    stdit it;
    SP_Node *new_node;

    stdskl_lowerb(skl, &it, &id);

    /* If the node already exists, just return iterator to it */
    if (!stdskl_is_end(skl, &it) && (*(SP_Node **)stdit_val(&it))->id == id)
        return it;

    /* Set up new node */
    if ((new_node = malloc(sizeof(SP_Node))) == NULL)
        Alarm(EXIT, "ERROR: failed to allocate SP_Node\n");
    new_node->id = id;
    new_node->prev = NULL;
    new_node->prev_dist = DBL_MAX;
    new_node->src_dist = DBL_MAX;
    stdskl_construct(&new_node->nghbrs, sizeof(DG_Edge *), sizeof(SP_Node *), Edge_Ptr_Cmp);

    stdskl_insert(skl, &it, &id, &new_node, STDTRUE);

    return it;
}

static void SP_Add_Edge(stdskl *skl, Node_ID src_id, Node_ID dst_id, DG_Edge *e)
{
    stdit src_it;
    stdit dst_it;
    SP_Node *src_ptr;
    SP_Node *dst_ptr;
    stdit it;

    src_it = SP_Add_Node(skl, src_id);
    dst_it = SP_Add_Node(skl, dst_id);

    src_ptr = *(SP_Node **)stdit_val(&src_it);
    dst_ptr = *(SP_Node **)stdit_val(&dst_it);

    stdskl_insert(&src_ptr->nghbrs, &it, &e, &dst_ptr, STDFALSE);
    if (!Directed_Edges)
        stdskl_insert(&dst_ptr->nghbrs, &it, &e, &src_ptr, STDFALSE);
}

static int Edge_Ptr_Cmp(const void *l, const void *r)
{
    DG_Edge *left  = *(DG_Edge **) l;
    DG_Edge *right = *(DG_Edge **) r;

    if (left->cost < right->cost)
        return -1; 
    else if (left->cost > right->cost)
        return 1;
    else
        return 0;
}

/* Set all edge costs to base costs for edges in our graph and leave edges
 * not in our graph as disconnected so that we can use MultiPath_Compute
 * function directly */
void Set_Edges_to_Base_Cost(Graph *g)
{
    Edge_Key *e_key;
    Edge *edge_ptr;
    stdit it;

    for (stdskl_begin(&g->Edges, &it); !stdskl_is_end(&g->Edges, &it); stdskl_it_next(&it))
    {
        e_key = (Edge_Key *)stdskl_it_key(&it);

        edge_ptr = Get_Edge(temp_node_ip[e_key->src_id], temp_node_ip[e_key->dst_id]);
        Alarm(DEBUG, "Setting cost for edge (%d, %d): %d -> %d\n",
              e_key->src_id, e_key->dst_id, edge_ptr->cost, edge_ptr->base_cost);
        edge_ptr->cost = edge_ptr->base_cost;
    }
}

static unsigned char *Source_Destination_Problem_Bitmask_from_SDP_Graphs(Node_ID src_id,
    Node_ID dst_id, double max_latency, Graph *src_g, Graph *dst_g,
    int available_paths, stdskl *k2_edges)
{
    unsigned char *ret_mask;
    Graph *ret_g;
    stdit it;
    DG_Edge *e;
    Edge_Key *e_key;
#if 0
    int num_paths;
    SD_Edge *path1, *path2, *tmp_path;
    int path1_count, path2_count, tmp_count, i;
    int32u next_id;
    Edge *edge_ptr;
#endif

    if (src_g == NULL || dst_g == NULL)
        return Graph_to_Bitmask(NULL);

    if ((ret_g = malloc(sizeof(Graph))) == NULL) {
        Alarm(EXIT, "Source_Destination_Problem_Bitmask_from_SDP_Graphs: malloc "
                    "failed when allocating graph to return\n");
    }

    /* Populate result graph by taking the union of the source and destination graphs */
    Graph_Init(ret_g);
    for (stdskl_begin(&src_g->Edges, &it); !stdskl_is_end(&src_g->Edges, &it); stdskl_it_next(&it))
    {
        e = (DG_Edge *)stdskl_it_val(&it);
        e_key = (Edge_Key *)stdskl_it_key(&it);

        Graph_add_edge(ret_g, e_key->src_id, e_key->dst_id, e->cost, e->index);
    }
    for (stdskl_begin(&dst_g->Edges, &it); !stdskl_is_end(&dst_g->Edges, &it); stdskl_it_next(&it))
    {
        e = (DG_Edge *)stdskl_it_val(&it);
        e_key = (Edge_Key *)stdskl_it_key(&it);

        Graph_add_edge(ret_g, e_key->src_id, e_key->dst_id, e->cost, e->index);
    }

    /* Set up mask to return */
    ret_mask = Graph_to_Bitmask(ret_g);

#if 0
    /* Check that we actually have two disjoint paths */
    Set_Edges_to_Base_Cost(ret_g);

    num_paths = MultiPath_Compute(dst_id, 2, NULL, 0, 0);
    Alarm(DEBUG, "Destination %d, num_paths: %d\n", dst_id, num_paths);

    if (num_paths < 2 && available_paths >= 2)
    {
        /* Initialize paths */
        if ((path1 = malloc(sizeof(SD_Edge)*stdskl_size(k2_edges))) == NULL)
            Alarm(EXIT, "ERROR, failed to allocate memory for path1\n");
        if ((path2 = malloc(sizeof(SD_Edge)*stdskl_size(k2_edges))) == NULL)
            Alarm(EXIT, "ERROR, failed to allocate memory for path2\n");
        path1_count = 0;
        path2_count = 0;

        /* Get first path from two-paths edge list */
        next_id = src_id;
        while (next_id != dst_id)
        {
            for (stdskl_begin(k2_edges, &it); !stdskl_is_end(k2_edges, &it); stdskl_it_next(&it))
            {
                e_key = (Edge_Key*)stdskl_it_key(&it);

                if (e_key->src_id == next_id) {
                    path1[path1_count].edge = Get_Edge(temp_node_ip[e_key->src_id], temp_node_ip[e_key->dst_id]);
                    if (path1[path1_count].edge->cost != -1)
                        path1[path1_count].in_sd_graph = 1;
                    else
                        path1[path1_count].in_sd_graph = 0;

                    path1_count++;
                    next_id = e_key->dst_id;
                    break; /* from for loop, but not outer while loop */
                }
            }
        }
        printf("PATH 1: ");
        for (i = 0; i < path1_count; i++)
        {
            printf("(%d.%d.%d.%d -> %d.%d.%d.%d)\t", 
                IP1(path1[i].edge->src->nid), IP2(path1[i].edge->src->nid), 
                IP3(path1[i].edge->src->nid), IP4(path1[i].edge->src->nid), 
                IP1(path1[i].edge->dst->nid), IP2(path1[i].edge->dst->nid), 
                IP3(path1[i].edge->dst->nid), IP4(path1[i].edge->dst->nid)); 
        }
        printf("\n");

        /* Get second path from two-paths edge list */
        next_id = src_id;
        while (next_id != dst_id)
        {
            for (stdskl_begin(k2_edges, &it); !stdskl_is_end(k2_edges, &it); stdskl_it_next(&it))
            {
                e_key = (Edge_Key*)stdskl_it_key(&it);

                if (e_key->src_id == next_id) {
                    path2[path2_count].edge = Get_Edge(temp_node_ip[e_key->src_id], temp_node_ip[e_key->dst_id]);

                    /* We want to get the second path now, so make sure we
                     * start out with a different first edge */
                    if (path2_count == 0 && path2[path2_count].edge == path1[0].edge) continue;

                    if (path2[path2_count].edge->cost != -1)
                        path2[path2_count].in_sd_graph = 1;
                    else
                        path2[path2_count].in_sd_graph = 0;

                    path2_count++;
                    next_id = e_key->dst_id;
                    break; /* from for loop, but not outer while loop */
                }
            }
        }
        printf("PATH 2: ");
        for (i = 0; i < path2_count; i++)
        {
            printf("(%d.%d.%d.%d -> %d.%d.%d.%d)\t", 
                IP1(path2[i].edge->src->nid), IP2(path2[i].edge->src->nid), 
                IP3(path2[i].edge->src->nid), IP4(path2[i].edge->src->nid), 
                IP1(path2[i].edge->dst->nid), IP2(path2[i].edge->dst->nid), 
                IP3(path2[i].edge->dst->nid), IP4(path2[i].edge->dst->nid)); 
        }
        printf("\n");

        /* We want to try adding the shorter path first, so if path 2 is
         * shorter than path 1, swap them */
        if (path2_count < path1_count) {
            tmp_count = path1_count;
            path1_count = path2_count;
            path2_count = tmp_count;

            tmp_path = path1;
            path1 = path2;
            path2 = tmp_path;
        }

        /* Set edges in shorter path to their base cost and check to see if that
         * is enough to give us two disjoint paths */
        for (i = 0; i < path1_count; i++)
        {
            path1[i].edge->cost = path1[i].edge->base_cost;
        }
        num_paths = MultiPath_Compute(dst_id, 2, NULL, 0, 0);
        Alarm(DEBUG, "Destination %d, num_paths: %d\n", dst_id, num_paths);

        if (num_paths == 2) {
            /* We have 2 paths now, so update the bitmask and we're done */
            for (i = 0; i < path1_count; i++)
            {
                *(ret_mask + (path1[i].edge->index / 8)) |= 0x80 >> (path1[i].edge->index % 8);
            }
        } else {
            /* We still don't have 2 paths, so try again with the longer path */

            /* Reset everything in the shorter path to disconnected state */
            for (i = 0; i < path1_count; i++)
            {
                if (!path1[i].in_sd_graph)
                    path1[i].edge->cost = -1;
            }

            /* Set everything in longer path to base cost */
            for (i = 0; i < path2_count; i++)
            {
                path2[i].edge->cost = path2[i].edge->base_cost;
            }
            num_paths = MultiPath_Compute(dst_id, 2, NULL, 0, 0);
            Alarm(DEBUG, "Destination %d, num_paths: %d\n", dst_id, num_paths);

            /* At this point, we want to add the longer path to the bitmask no matter what. */
            for (i = 0; i < path2_count; i++)
            {
                *(ret_mask + (path2[i].edge->index / 8)) |= 0x80 >> (path2[i].edge->index % 8);
            }

            /* If the longer path didn't give us 2 disjoint paths, we also need
             * to add the shorter path */
            if (num_paths < 2) {
                for (i = 0; i < path1_count; i++)
                {
                    *(ret_mask + (path1[i].edge->index / 8)) |= 0x80 >> (path1[i].edge->index % 8);
                }
            }
        }

        /* Free paths */
        free(path1);
        free(path2);
    }

    /* Set all edges back to disconnected state (cost -1) */
    for (stdskl_begin(&ret_g->Edges, &it); !stdskl_is_end(&ret_g->Edges, &it); stdskl_it_next(&it))
    {
        e_key = (Edge_Key *)stdskl_it_key(&it);

        edge_ptr = Get_Edge(temp_node_ip[e_key->src_id], temp_node_ip[e_key->dst_id]);
        edge_ptr->cost = -1;
    }
#endif

    Graph_Finish(ret_g);
    free(ret_g);

    return ret_mask;
}

static Graph *Source_Problem_Graph(Graph *g, Node_ID src_id, Node_ID dst_id, double max_latency)
{
    Graph tmp_g;
    Graph *dst_g;
    Graph *ret_g;
    stdit it;
    DG_Edge *e;
    Edge_Key *e_key;

    /* For undirected edges, we can directly use the Destination_Problem_Graph
     * calculation (reversing src and dst) */
    if (!Directed_Edges)
        return Destination_Problem_Graph(g, dst_id, src_id, max_latency);

    /* If we are using directed edges, build graph in which all edges are
     * reversed and solve the destination problem on that */
    Graph_Init(&tmp_g);
    for (stdskl_begin(&g->Edges, &it); !stdskl_is_end(&g->Edges, &it); stdskl_it_next(&it))
    {
        e = (DG_Edge *)stdskl_it_val(&it);
        e_key = (Edge_Key *)stdskl_it_key(&it);

        /* adding edge in reverse (src as dst and dst as src) */
        Graph_add_edge(&tmp_g, e_key->dst_id, e_key->src_id, e->cost, e->index);
    }

    /* Find destination problem graph for reversed graph */
    dst_g = Destination_Problem_Graph(&tmp_g, dst_id, src_id, max_latency);
    Graph_Finish(&tmp_g);

    /* If result was NULL just return now */
    if (dst_g == NULL)
        return dst_g;

    /* Otherwise, we have some result graph, so flip it back */
    if ((ret_g = malloc(sizeof(Graph))) == NULL)
        Alarm(EXIT, "Source_Problem_Graph: malloc failed when allocating graph to return\n");

    Graph_Init(ret_g);
    for (stdskl_begin(&dst_g->Edges, &it); !stdskl_is_end(&dst_g->Edges, &it); stdskl_it_next(&it))
    {
        e = (DG_Edge *)stdskl_it_val(&it);
        e_key = (Edge_Key *)stdskl_it_key(&it);

        /* adding edge in reverse (src as dst and dst as src) to return to
         * original orientation */
        Graph_add_edge(ret_g, e_key->dst_id, e_key->src_id, e->cost, e->index);
    }

    Graph_Finish(dst_g);
    free(dst_g);

    return ret_g;
}

static Graph *Destination_Problem_SLST_Graph(Graph *g, Node_ID src_id, Node_ID dst_id, double max_latency)
{
    stdskl Steiner_edges;
    stdskl Steiner_nodes;
    DG_Edge *e;
    DG_Node *src_n, *dst_n;
    Steiner_Node *sn;
    stdit it, sit;
    Graph *ret_g;
    double dist;
    int dst_edge_count;
    Graph tmp_g;

    Alarm(DEBUG, "Destination_Problem_Graph called for Source %lu, Destination %lu\n", src_id, dst_id);

    stdskl_construct(&Steiner_edges, sizeof(Edge_Key), sizeof(Steiner_Edge), DG_Edge_Cmp);
    stdskl_construct(&Steiner_nodes, sizeof(Node_ID), sizeof(Steiner_Node), Node_Cmp);
    ret_g = NULL;

    /* Set up graph excluding edges touching the destination, since we want to
     * check distances to potential target nodes WITHOUT the possibility of
     * going through the destination */
    Graph_Init(&tmp_g);
    for (stdskl_begin(&g->Edges, &it); !stdskl_is_end(&g->Edges, &it); stdskl_it_next(&it))
    {
        e = (DG_Edge *)stdskl_it_val(&it);
        src_n = (DG_Node *)stdskl_it_val(&e->src_it);
        dst_n = (DG_Node *)stdskl_it_val(&e->dst_it);

        if (src_n->id != dst_id && dst_n->id != dst_id)
            Graph_add_edge(&tmp_g, src_n->id, dst_n->id, e->cost, e->index);
    }

    /* Set up target nodes (source + anything adjacent to the destination that
     * is reachable within the latency constraint in the graph we just created)
     * */
    for (stdskl_begin(&g->Edges, &it); !stdskl_is_end(&g->Edges, &it); stdskl_it_next(&it))
    {
        e = (DG_Edge *)stdskl_it_val(&it);
        src_n = (DG_Node *)stdskl_it_val(&e->src_it);
        dst_n = (DG_Node *)stdskl_it_val(&e->dst_it);

        /* Ignore edges that are too long */
        if (e->cost > max_latency) continue;

        /* Our targets are anything adjacent to the destination that is
         * reachable within our latency constraint */
        if (dst_n->id == dst_id &&
            (dist = Shortest_Path(&tmp_g, src_id, src_n->id) <= max_latency - e->cost))
        {
            Steiner_Add_Node(&Steiner_nodes, src_n->id, 1, max_latency - e->cost);
        } else if (!Directed_Edges &&
                   src_n->id == dst_id &&
                   (dist = Shortest_Path(&tmp_g, src_id, dst_n->id) <= max_latency - e->cost))
        {
            Steiner_Add_Node(&Steiner_nodes, dst_n->id, 1, max_latency - e->cost);
        }
    }
    Graph_Finish(&tmp_g);

    /* Check whether we actually have valid targets...no point in continuing if
     * we don't. This means that none of the destination's neighbors provide a
     * valid path within the latency constraint */
    if (stdskl_empty(&Steiner_nodes)) {
        Alarm(DEBUG, "Destination_Problem_Graph: no valid targets (src %u, dst %u)\n", src_id, dst_id);
        goto end;
    }

    /* If the source is not adjacent to the destination, go ahead and add it in
     * as one of our targets */
    Steiner_Add_Node(&Steiner_nodes, src_id, 1, 0);

    /* Set up input graph to Minimum Steiner Tree */
    for (stdskl_begin(&g->Edges, &it); !stdskl_is_end(&g->Edges, &it); stdskl_it_next(&it))
    {
        e = (DG_Edge *)stdskl_it_val(&it);
        src_n = (DG_Node *)stdskl_it_val(&e->src_it);
        dst_n = (DG_Node *)stdskl_it_val(&e->dst_it);

        if (dst_n->id != dst_id && src_n->id != dst_id) {
            Steiner_Add_Edge(&Steiner_nodes, &Steiner_edges, e, 1);
        } 
    }

    /* Calculate Minimum Steiner Tree */
    ret_g = Minimum_SP_Steiner_Tree(g, &Steiner_nodes, &Steiner_edges, src_id, dst_id);
    if (ret_g == NULL) {
        /* Not an error: it's possible that we just have a direct edge from the
         * source to the destination, with no intermediate tree, so initialize
         * an empty graph in this case (we'll add the relevant edge below) */
        Alarm(DEBUG, "Destination problem graph: Minimum_SP_Steiner_Tree result is NULL\n");
        if ((ret_g = malloc(sizeof(Graph))) == NULL) {
            Alarm(EXIT, "ERROR: failed to allocate graph\n");
        }
        Graph_Init(ret_g);
    }

    /* Add edges going into the destination from target nodes back into the result graph */
    dst_edge_count = 0;
    for (stdskl_begin(&g->Edges, &it); !stdskl_is_end(&g->Edges, &it); stdskl_it_next(&it))
    {
        e = (DG_Edge *)stdskl_it_val(&it);
        src_n = (DG_Node *)stdskl_it_val(&e->src_it);
        dst_n = (DG_Node *)stdskl_it_val(&e->dst_it);

        sn = NULL;
        if (dst_n->id == dst_id) {
            if (!stdskl_is_end(&Steiner_nodes, stdskl_find(&Steiner_nodes, &sit, &src_n->id))) 
                sn = (Steiner_Node *) stdit_val(&sit);
        } else if (!Directed_Edges && src_n->id == dst_id) {
            if (!stdskl_is_end(&Steiner_nodes, stdskl_find(&Steiner_nodes, &sit, &dst_n->id))) 
                sn = (Steiner_Node *) stdit_val(&sit);
        }
        if (sn != NULL && sn->target) {
            Graph_add_edge(ret_g, src_n->id, dst_n->id, e->cost, e->index);
            dst_edge_count++;
            /*Alarm(PRINT, "%lu -> %lu: %f\n", sn->id, dst_id, e->cost);*/
        }
    }
    if (dst_edge_count == 0)
    {
        Alarm(DEBUG, "Destination Problem Graph: destination %lu is not reachable\n", dst_id);
        Graph_Finish(ret_g);
        free(ret_g);
        ret_g = NULL;
    }

    /* Clean up */
end:
    stdskl_destruct(&Steiner_edges);
    stdskl_destruct(&Steiner_nodes);

    /* Return the result graph we've constructed */
    return ret_g;
}

static Graph *Destination_Problem_Graph(Graph *g, Node_ID src_id, Node_ID dst_id, double max_latency)
{
    Graph *ret_g;

    ret_g = Destination_Problem_Shortest_Path_Tree(g, src_id, dst_id, max_latency);
    if (stdskl_size(&ret_g->Edges) == 0) {
        Alarm(PRINT, "Failed to find destination problem graph for %d->%d\n", src_id, dst_id);
        Graph_Finish(ret_g);
        free(ret_g);
        ret_g = NULL;
    }

    return ret_g;
}

/* Assumes input graph has been correctly marked as to which nodes are targets
 * and which are optional */
static Graph *Minimum_SP_Steiner_Tree(Graph *g, stdskl *Steiner_nodes, stdskl *Steiner_edges, Node_ID src_id, Node_ID dst_id)
{
    Steiner_Node *n;
    Steiner_Edge *e;
    Node_ID optional_ids[MAX_NODES];
    unsigned long included_array[MAX_NODES];
    unsigned long num_optional, num_target, i, c;
    Graph tmp_g;
    Graph *ret_g;
    stdit it, rit;
    Graph *min_g;
    double dist, dist_sum, min_dist_sum = DBL_MAX;
    int has_zero, changed_index, num_ones;

    Alarm(DEBUG, "Minimum_SP_Steiner_Tree called for Source %lu, Destination %lu\n", src_id, dst_id);

    /* Find set of non-target (optional) nodes */
    num_optional = 0;
    num_target = 0;
    for (stdskl_begin(Steiner_nodes, &it); !stdskl_is_end(Steiner_nodes, &it); stdskl_it_next(&it))
    {
        n = (Steiner_Node *)stdit_val(&it);

        /* If this node was not a target, add it to optional set */
        if (!n->target) {
            n->optional_index = num_optional;
            optional_ids[num_optional] = n->id;
            num_optional++;
        } else {
            n->optional_index = -1;
            num_target++;
        }
    }

    /* Consider every possible combination of optional nodes to find the
     * minimum cost combination that meets our latency targets */
    min_g = NULL;
    for (c = 0; c <= num_optional; c++)
    {
        /* If we already found a graph (with a smaller number of nodes than
         * anything we will consider in the future) we are done */
        if (min_g != NULL) {
            //Alarm(PRINT, "Can quit...found graph with %d nodes\n", c -1);
            break;
        }

        /* Initialize included_array to include the first c optional nodes (and
         * nothing else) */
        for (i = 0; i < c; i++)
        {
            included_array[i] = 1;
        }
        for (i = c; i < num_optional; i++)
        {
            included_array[i] = 0;
        }

        changed_index = num_optional;
        while (changed_index >= 0)
        {
            /*for (i = 0; i < num_optional; i++)
            {
                printf("%d\t", included_array[i]);
            }
            printf("\n");*/

            /* Set up input graph with all targets + the optional nodes currently
             * being considered */
            Graph_Init(&tmp_g);
            Graph_add_node(&tmp_g, src_id);
            for (stdskl_begin(Steiner_edges, &it); !stdskl_is_end(Steiner_edges, &it); stdskl_it_next(&it))
            {
                e = (Steiner_Edge *)stdskl_it_val(&it);

                /* If both source and destination appear in this configuration, add the edge */
                if ((e->src->target || included_array[e->src->optional_index]) &&
                    (e->dst->target || included_array[e->dst->optional_index]))
                {
                    Graph_add_edge(&tmp_g, e->src->id, e->dst->id,
                                   e->edge_ref->cost, e->edge_ref->index);
                }
            }

            /* Compute the shortest path tree for this combination of nodes (will
             * give us lowest latency tree possible with these nodes. Note that any
             * tree on these nodes will have the same number of edges, and since
             * our edges all have the same cost, optimizing latency only is fine
             * here. */
            ret_g = Shortest_Path_Tree(&tmp_g, src_id);
            Graph_Finish(&tmp_g);
            if (ret_g == NULL) continue;

            /* Check for validity (make sure all targets actually appear and are
             * reachable within specified delay) */
            dist_sum = 0;
            for (stdskl_begin(Steiner_nodes, &it); !stdskl_is_end(Steiner_nodes, &it); stdskl_it_next(&it))
            {
                n = (Steiner_Node *)stdit_val(&it);

                if (n->target) {
                    if (stdskl_is_end(&ret_g->Nodes, stdskl_find(&ret_g->Nodes, &rit, &n->id))) {
                        Alarm(DEBUG, "Invalid combination %lu: target %lu does not"
                              " appear\n", i, n->id);
                        break;
                    }

                    dist = Shortest_Path(ret_g, src_id, n->id);
                    if (dist > n->max_dist) {
                        Alarm(DEBUG, "Invalid combination %lu: exceeds max_dist %f"
                              " for target %lu (%f)\n", i, n->max_dist, n->id, dist);
                        break;
                    }
                    dist_sum += dist;
                }
            }
            Alarm(DEBUG, "Valid graph!\n");

            /* If the graph was valid and smaller than anything we've seen so far
             * (or the same size but with lower overall latencies), update min */
            if (stdskl_is_end(Steiner_nodes, &it) && 
                (min_g == NULL || stdskl_size(&ret_g->Edges) < stdskl_size(&min_g->Edges) ||
                 (stdskl_size(&ret_g->Edges) == stdskl_size(&min_g->Edges) && dist_sum < min_dist_sum))) {
                if (min_g != NULL) {
                    Graph_Finish(min_g);
                    free(min_g);
                }
                min_g = ret_g;
                min_dist_sum = dist_sum;
                Alarm(DEBUG, "Updated graph: min_dist_sum = %d\n", min_dist_sum);
            } else {
                Graph_Finish(ret_g);
                free(ret_g);
            }

            /* Adjust array of included nodes. Find first spot where we can
             * "move over" a 1 and then reset all spots after that so that the
             * 1s from that point on are contiguous */
            has_zero = 0;
            num_ones = 0;
            for (changed_index = num_optional - 1; changed_index >= 0; changed_index--)
            {
                if (included_array[changed_index] == 0) {
                    has_zero = 1;
                }
                else {
                    num_ones++;
                    if (has_zero) {
                        included_array[changed_index] = 0;
                        for (i = 1; i <= num_ones; i++)
                        {
                            included_array[changed_index+i] = 1;
                        }
                        for (i = changed_index + num_ones + 1; i < num_optional; i++)
                        {
                            included_array[i] = 0;
                        }
                        break;
                    }
                }
            }
        }
    }

    return min_g;
}

static stdit Steiner_Add_Node(stdskl *nodes, Node_ID id, int target, double max_dist)
{
    stdit it;
    Steiner_Node new_node;

    stdskl_lowerb(nodes, &it, &id);

    /* If the node already exists, just return iterator to it */
    if (!stdskl_is_end(nodes, &it) && (*(Node_ID*)stdit_key(&it)) == id)
        return it;

    /* Set up new node */
    new_node.id = id;
    new_node.target = target;
    new_node.optional_index = -1;
    new_node.max_dist = max_dist;

    stdskl_insert(nodes, &it, &id, &new_node, STDTRUE);

    return it;
}

static stdit Steiner_Add_Edge(stdskl *nodes, stdskl *edges, DG_Edge *e, double cost)
{
    stdit src_it;
    stdit dst_it;
    Steiner_Edge new_edge;
    Edge_Key key;
    stdit it;

    src_it = Steiner_Add_Node(nodes, ((DG_Node*)stdit_val(&e->src_it))->id, 0, DBL_MAX);
    dst_it = Steiner_Add_Node(nodes, ((DG_Node*)stdit_val(&e->dst_it))->id, 0, DBL_MAX);

    new_edge.src = (Steiner_Node *)stdit_val(&src_it);
    new_edge.dst = (Steiner_Node *)stdit_val(&dst_it);
    new_edge.cost = cost;
    new_edge.edge_ref = e;

    key.src_id = new_edge.src->id;
    key.dst_id = new_edge.dst->id;

    stdskl_insert(edges, &it, &key, &new_edge, STDFALSE);
    return it;
}

void DG_Compute_Graphs(void)
{
    stdit it, eit, lit;
    Node_ID dest_id;
    Edge_Key key;
    Edge_Value val;
    int16u index;
    int i, j;
    unsigned char *zero_mask;
    Graph base_graph;
    Graph *dst_graph, *src_graph;
    sp_time start, stop;
    long duration = 0;
    int num_paths;
    
    zero_mask = new(MP_BITMASK);
    memset(zero_mask, 0x00, MultiPath_Bitmask_Size);

    /* Initialize */
    for (i = 0; i <= MAX_NODES; i++)
    {
        DG_Destinations[i].current_graph_type = DG_NONE_GRAPH;
        for (j = 0; j <= DG_NUM_GRAPHS; j++)
        {
            DG_Destinations[i].bitmasks[j] = NULL;
            stdskl_construct(&DG_Destinations[i].edge_lists[j],
                sizeof(Edge_Key), sizeof(index), DG_Edge_Cmp);
        }
        for (j = 0; j <= MAX_NODES; j++)
        {
            DG_Destinations[i].problems[j] = 0;
        }
        DG_Destinations[i].problem_count = 0;

        DG_Source.problems[i] = 0;
    }
    DG_Source.problem_count = 0;
    stdskl_construct(&DG_Problem_List, sizeof(Edge_Key), sizeof(index), DG_Edge_Cmp);

    if (!Directed_Edges) {
        Alarm(PRINT, "WARNING: Dissemination graphs do not work with undirected "
                     "edges. Will default to dynamic two disjoint paths\n");
        return;
    }

    /* Initialize base graph to be used for dissemination graph computations */
    Graph_Init(&base_graph);
    for (stdskl_begin(&Sorted_Edges, &it); !stdskl_is_end(&Sorted_Edges, &it); stdit_next(&it))
    {
        key = *(Edge_Key *)stdskl_it_key(&it);
        val = *(Edge_Value *)stdskl_it_val(&it);
        Graph_add_edge(&base_graph, key.src_id, key.dst_id, val.cost, val.index);
    }

    /* Compute graphs from myself to  each destination */
    for (stdhash_begin(&Node_Lookup_ID_to_Addr, &it);
         !stdhash_is_end(&Node_Lookup_ID_to_Addr, &it);
         stdhash_it_next(&it))
    {
        dest_id = *(Node_ID*) stdit_key(&it);

        Alarm(PRINT, "DG_Compute_Graphs: Computing for destination node %d\n", dest_id);

        start = E_get_time();

        /* Compute static 2 paths bitmask */
        num_paths = MultiPath_Compute(dest_id, 2,
                      &DG_Destinations[dest_id].bitmasks[DG_K2_GRAPH], 1, 0);
        if (num_paths < 2) {
            Alarm(PRINT, "Warning: failed to find 2 disjoint paths for destination %d\n", dest_id);
        }

        /* Fill in edge list for static 2 paths based on computed bitmask
         * (needs to happen before we calculate source/destination graph, since
         * we'll use this to add 2 disjoint paths to that graph if needed */
        for (stdskl_begin(&Sorted_Edges, &eit); !stdskl_is_end(&Sorted_Edges, &eit); stdskl_it_next(&eit))
        {
            key = *(Edge_Key*)stdskl_it_key(&eit);
            val = *(Edge_Value*)stdskl_it_val(&eit);

            if (DG_Edge_In_Graph(val.index, DG_Destinations[dest_id].bitmasks[DG_K2_GRAPH])) {
                stdskl_insert(&DG_Destinations[dest_id].edge_lists[DG_K2_GRAPH],
                              &lit, &key, &val.index, STDFALSE);
            }
        }

        /* Compute source/destination problem bitmasks */
        src_graph = Source_Problem_Graph(&base_graph, My_ID, dest_id, DG_LATENCY_REQ);
        dst_graph = Destination_Problem_Graph(&base_graph, My_ID, dest_id, DG_LATENCY_REQ);

        DG_Destinations[dest_id].bitmasks[DG_SRC_GRAPH] = Graph_to_Bitmask(src_graph);
        DG_Destinations[dest_id].bitmasks[DG_DST_GRAPH] = Graph_to_Bitmask(dst_graph);

        DG_Destinations[dest_id].bitmasks[DG_SRC_DST_GRAPH] =
                    Source_Destination_Problem_Bitmask_from_SDP_Graphs(My_ID, dest_id,
                    DG_LATENCY_REQ, src_graph, dst_graph, num_paths,
                    &DG_Destinations[dest_id].edge_lists[DG_K2_GRAPH]);

        if (src_graph != NULL) {
            Graph_Finish(src_graph);
            free(src_graph);
        }
        if (dst_graph != NULL) {
            Graph_Finish(dst_graph);
            free(dst_graph);
        }

        /* Initialize current bitmask to k = 2 */
        DG_Destinations[dest_id].current_graph_type = DG_K2_GRAPH;

        /* If we failed to find src/dst graphs for the destination (i.e.
         * because it is not reachable within the chosen latency constraint),
         * just use two paths for everything */
        for (j = 1; j <= DG_NUM_GRAPHS; j++)
        {
            if (j != DG_K2_GRAPH && MultiPath_Is_Equal(zero_mask, DG_Destinations[dest_id].bitmasks[j]))
            {
                memcpy(DG_Destinations[dest_id].bitmasks[j],
                       DG_Destinations[dest_id].bitmasks[DG_K2_GRAPH],
                       MultiPath_Bitmask_Size);
            }
        }

        /* Fill in edge lists based on computed bitmasks */
        for (stdskl_begin(&Sorted_Edges, &eit); !stdskl_is_end(&Sorted_Edges, &eit); stdskl_it_next(&eit))
        {
            key = *(Edge_Key*)stdskl_it_key(&eit);
            val = *(Edge_Value*)stdskl_it_val(&eit);

            for (j = 1; j <= DG_NUM_GRAPHS; j++)
            {
                /* Skip DG_K2_GRAPH, since we calculate that above */
                if (j == DG_K2_GRAPH) continue;

                if (DG_Edge_In_Graph(val.index, DG_Destinations[dest_id].bitmasks[j])) {
                    stdskl_insert(&DG_Destinations[dest_id].edge_lists[j], &lit, &key, &val.index, STDFALSE);
                }
            }
        }

        stop = E_get_time();
        duration += (stop.sec - start.sec) * 1000000;
        duration += stop.usec - start.usec;

        /* Print graphs */
        for (j = 1; j <= DG_NUM_GRAPHS; j++)
        {
            Alarm(PRINT, "Printing graph %d\n", j);
            for (stdskl_begin(&DG_Destinations[dest_id].edge_lists[j], &eit);
                 !stdskl_is_end(&DG_Destinations[dest_id].edge_lists[j], &eit);
                 stdskl_it_next(&eit))
            {
                key = *(Edge_Key*)stdskl_it_key(&eit);
                index = *(int16u*)stdskl_it_val(&eit);

                Alarm(PRINT, "\t[%2d, %2d] (%02d)\n", key.src_id, key.dst_id, index);
            }
        }
    }

    /* Clean up */
    Graph_Finish(&base_graph);
    dispose(zero_mask);

    Alarm(PRINT, "Dissemination graphs computation took %ld usec\n", duration);
}

int DG_Edge_In_Graph(int16u edge_index, unsigned char *graph_mask)
{
    unsigned char *edge_mask;
    int64u *tmp_mask, *edge_mask_ptr;
    int64u temp, j;

    edge_mask = new(MP_BITMASK);
    memset(edge_mask, 0x00, MultiPath_Bitmask_Size);
    *(edge_mask + (edge_index / 8)) = 0x80 >> (edge_index % 8);

    tmp_mask      = (int64u*) graph_mask;
    edge_mask_ptr = (int64u*) edge_mask;
    temp          = 0;
    for (j = 0; j < MultiPath_Bitmask_Size/sizeof(int64u); j++)
        temp = temp | (*(tmp_mask+j) & *(edge_mask_ptr+j));

    dispose(edge_mask);

    if (temp)
        return 1;
    else
        return 0;
}

int DG_Problem_On_Graph(stdskl *edge_list, Edge_Key edge_key, int type)
{
    stdit it, prob_it;
    Edge_Key *tmp_key;

    /* Iterate over edges in this graph and check to see if any are currently
     * in the list of problematic edges (note that we ignore destination
     * problems when checking a destination-problem graph and ignore source
     * problems when checking a source-problem graph */
    for (stdskl_begin(edge_list, &it); !stdskl_is_end(edge_list, &it); stdskl_it_next(&it))
    {
        tmp_key = (Edge_Key *) stdit_key(&it);
        if ((type == DG_SRC_GRAPH && tmp_key->src_id == edge_key.src_id) ||
            (type == DG_DST_GRAPH && tmp_key->dst_id == edge_key.dst_id))
        {
            continue;
        }
            
        stdskl_find(&DG_Problem_List, &prob_it, tmp_key);
        if (!stdskl_is_end(&DG_Problem_List, &prob_it)) {
            return 1;
        }
    }

    return 0;
}

void DG_Process_Edge_Update(Edge *edge, int16 new_cost)
{
    DG_Dst *dg_dst, *tmp_dst;
    Edge_Key edge_key, tmp_edge_key;
    stdit it;
    int16u edge_index;
    int i;

    /* Dissemination graph-based routing only works with problem-type routing
     * (as it requires identifying problems at the source and/or destination of
     * each flow to select dissemination graphs) */
    if (Route_Weight != PROBLEM_ROUTE)
        return;

    /* No status change */
    if ((new_cost == -1 && edge->cost == -1) ||
        (new_cost < -1 && edge->cost < -1) ||
        (new_cost >= 0 && edge->cost >= 0)) {
        return;
    }

    /* Get src and dst indexes */
    stdhash_find(&Node_Lookup_Addr_to_ID, &it, &edge->dst_id);
    if (stdhash_is_end(&Node_Lookup_Addr_to_ID,  &it)) {
        Alarm(PRINT, "DG_Process_Edge_Update: destination not in config file\r\n");
        return;
    }
    edge_key.dst_id = *(int32u *)stdhash_it_val(&it);
    dg_dst = &DG_Destinations[edge_key.dst_id];

    stdhash_find(&Node_Lookup_Addr_to_ID, &it, &edge->src_id);
    if (stdhash_is_end(&Node_Lookup_Addr_to_ID,  &it)) {
        Alarm(PRINT, "DG_Process_Edge_Update: source not in config file\r\n");
        return;
    }
    edge_key.src_id = *(int32u *)stdhash_it_val(&it);

    edge_index = edge->index;

    Alarm(PRINT, "DG_Process_Edge_Update: Processing update for (%u, %u) = %d, cost "
                 "%d -> %d\n", edge_key.src_id, edge_key.dst_id, edge_index, edge->cost, new_cost);

    /* Update problem counts and graphs based on this update */
    if (new_cost < 0) { /* PROBLEM STARTED */
        /* If we already knew about this problem, nothing more to do */
        stdskl_lowerb(&DG_Problem_List, &it, &edge_key);
        if (!stdskl_is_end(&DG_Problem_List, &it) && DG_Edge_Cmp(&edge_key, (Edge_Key *)stdit_key(&it)) == 0)
            return;

        /* Otherwise, a problem just started on this edge, add to problem list */
        stdskl_insert(&DG_Problem_List, &it, &edge_key, &edge_index, STDTRUE);

        /* Check whether we need to switch any destinations currently using a
         * source or destination graph to the more robust source-destination graph
         * due to a new problem on this edge */
        for (i = 1; i <= MAX_NODES; i++)
        {
            tmp_dst = &DG_Destinations[i];
            if (tmp_dst->current_graph_type == DG_NONE_GRAPH) continue;

            /* Check whether newly problematic edge is on the current graph for
             * this destination: if we are currently using source graph, ignore
             * additional source issues; if we are currently using dest graph,
             * ignore additional dest issues */
            if ((tmp_dst->current_graph_type == DG_SRC_GRAPH && edge_key.src_id != My_ID) ||
                (tmp_dst->current_graph_type == DG_DST_GRAPH && edge_key.dst_id != i))
            {
                if (DG_Edge_In_Graph(edge_index, tmp_dst->bitmasks[tmp_dst->current_graph_type])) {
                    Alarm(PRINT, "DG_Process_Edge_Update: switching dest %d to source-dest graph from %d\n", i, tmp_dst->current_graph_type);
                    tmp_dst->current_graph_type = DG_SRC_DST_GRAPH;
                }
            }
        }

        /* NEW DESTINATION PROBLEM */

        /* only need to update if we have dissemination graphs for this
         * destination and we don't know about this problem already */
        if (dg_dst->current_graph_type != DG_NONE_GRAPH && dg_dst->problems[edge_key.src_id] == 0) {

            dg_dst->problems[edge_key.src_id] = 1;
            dg_dst->problem_count++;
            Alarm(PRINT, "New problem on (%d, %d) prob_count %d\n",
                         edge_key.src_id, edge_key.dst_id,
                         dg_dst->problem_count);

            /* Check if we need to switch to dst or src-dst graph */
            if (dg_dst->problem_count == DG_PROB_COUNT_THRESH)
            {
                /* New destination problem detected */
                Alarm(PRINT, "DG_Process_Edge_Update: DETECTED destination problem on "
                             "edge (%u, %u) %d %d\n", edge_key.src_id,
                             edge_key.dst_id, edge->cost, new_cost);

                if (dg_dst->current_graph_type == DG_SRC_GRAPH) {
                    /* We were using src graph, so switch to src-dst */
                    dg_dst->current_graph_type = DG_SRC_DST_GRAPH;
                    Alarm(PRINT, "Now using src-dst mask (from src)\n");
                } else if (dg_dst->current_graph_type == DG_K2_GRAPH) {
                    /* We were using kpaths: Check for existing problems on
                     * the dst graph before switching to it */
                    if (DG_Problem_On_Graph(&dg_dst->edge_lists[DG_DST_GRAPH], edge_key, DG_DST_GRAPH)) {
                        dg_dst->current_graph_type = DG_SRC_DST_GRAPH;
                        Alarm(PRINT, "Now using src-dst mask (from other)\n");
                    } else {
                        dg_dst->current_graph_type = DG_DST_GRAPH;
                        Alarm(PRINT, "Now using dst mask\n");
                    }
                }
            }
        }

        /* NEW SOURCE PROBLEM */
        if (edge_key.src_id == My_ID && DG_Source.problems[edge_key.dst_id] == 0) {
            /* Update general problem count for myself (i.e. the source) */
            DG_Source.problems[edge_key.dst_id] = 1;
            DG_Source.problem_count++;

            if (DG_Source.problem_count == DG_PROB_COUNT_THRESH)
            {
                Alarm(PRINT, "DG_Process_Edge_Update: DETECTED source problem on "
                             "edge (%u, %u) %d %d\n", edge_key.src_id,
                             edge_key.dst_id, edge->cost, new_cost);

                for (i = 1; i <= MAX_NODES; i++)
                {
                    tmp_dst = &DG_Destinations[i];

                    /* ignore if we don't have dissem graphs for this dst */
                    if (tmp_dst->current_graph_type == DG_NONE_GRAPH) continue;

                    /* Check if we should switch to a source or src-dst graph
                     * for this destination */

                    if (tmp_dst->current_graph_type == DG_DST_GRAPH) {
                        /* We were using dst graph, so switch to src-dst */
                        tmp_dst->current_graph_type = DG_SRC_DST_GRAPH;
                        Alarm(PRINT, "Now using src-dst mask for %d (from dst)\n", i);
                    } else if (tmp_dst->current_graph_type == DG_K2_GRAPH) {
                        /* We were using kpaths: Check for existing problems on
                         * the source graph before switching to it */
                        if (DG_Problem_On_Graph(&tmp_dst->edge_lists[DG_SRC_GRAPH], edge_key, DG_SRC_GRAPH)) {
                            tmp_dst->current_graph_type = DG_SRC_DST_GRAPH;
                            Alarm(PRINT, "Now using src-dst mask for %d (from other)\n", i);
                        } else {
                            tmp_dst->current_graph_type = DG_SRC_GRAPH;
                            Alarm(PRINT, "Now using src mask for %d\n", i);
                        }
                    }
                }
            }
        }
    } else { /* PROBLEM RESOLVED */
        /* If we don't have a problem currently marked on this edge, nothing to do */
        if (stdskl_is_end(&DG_Problem_List, stdskl_find(&DG_Problem_List, &it, &edge_key)))
            return;

        /* Otherwise, a problem just ended on this edge, remove from  problem
         * list */
        stdskl_erase(&DG_Problem_List, &it);

        /* RESOLVED DESTINATION PROBLEM */
        if (dg_dst->current_graph_type != DG_NONE_GRAPH && dg_dst->problems[edge_key.src_id] == 1) {
            /* Update problem counts */
            dg_dst->problems[edge_key.src_id] = 0;

            /* Switch back to kpaths graph or src graph if we can (from
             * destination or src-dst) */
            if (dg_dst->problem_count == DG_PROB_COUNT_THRESH)
            {
                if (dg_dst->current_graph_type == DG_DST_GRAPH)
                {
                    Alarm(PRINT, "DG_Process_Edge_Update: RESOLVED destination problem on "
                                 "edge (%u, %u) %d %d (from dst to k2)\n", edge_key.src_id,
                                 edge_key.dst_id, edge->cost, new_cost);
                    dg_dst->current_graph_type = DG_K2_GRAPH;
                } else if (dg_dst->current_graph_type == DG_SRC_DST_GRAPH) {
                    tmp_edge_key.src_id = My_ID;
                    tmp_edge_key.dst_id = edge_key.dst_id;
                    if (DG_Source.problem_count < DG_PROB_COUNT_THRESH) {
                        Alarm(PRINT, "DG_Process_Edge_Update: RESOLVED destination problem on "
                                     "edge (%u, %u) %d %d (from src-dst to k2)\n", edge_key.src_id,
                                     edge_key.dst_id, edge->cost, new_cost);
                        dg_dst->current_graph_type = DG_K2_GRAPH;
                    } else if (!DG_Problem_On_Graph(&dg_dst->edge_lists[DG_SRC_GRAPH], tmp_edge_key, DG_SRC_GRAPH)) {
                        Alarm(PRINT, "DG_Process_Edge_Update: RESOLVED destination problem on "
                                     "edge (%u, %u) %d %d (from src-dst to src)\n", edge_key.src_id,
                                     edge_key.dst_id, edge->cost, new_cost);
                        dg_dst->current_graph_type = DG_SRC_GRAPH;
                    }
                    /* If there is still a non-source problem on the source
                     * graph, stick with the src-dst graph */
                }
            }

            /* Update count */
            dg_dst->problem_count--;
        }

        /* RESOLVED SOURCE PROBLEM */
        if (edge_key.src_id == My_ID && DG_Source.problems[edge_key.dst_id] == 1) {
            DG_Source.problems[edge_key.dst_id] = 0;

            if (DG_Source.problem_count == DG_PROB_COUNT_THRESH)
            {
                for (i = 1; i <= MAX_NODES; i++)
                {
                    tmp_dst = &DG_Destinations[i];

                    /* ignore if we don't have dissem graphs for this dst */
                    if (tmp_dst->current_graph_type == DG_NONE_GRAPH) continue;

                    /* Alarm(PRINT, "Evaluating source problem resolution for %d\n", i);
                    Alarm(PRINT, "\tsrc prob count: %d\n", DG_Source.problem_count);
                    Alarm(PRINT, "\tdst prob count: %d\n", tmp_dst->problem_count);
                    Alarm(PRINT, "\tcurrent graph: %d\n", tmp_dst->current_graph_type); */

                    if (tmp_dst->current_graph_type == DG_SRC_GRAPH) {
                        Alarm(PRINT, "DG_Process_Edge_Update: RESOLVED source problem on "
                                     "edge (%u, %u) %d %d for %d (from src to k2)\n", edge_key.src_id,
                                     edge_key.dst_id, edge->cost, new_cost, i);
                        tmp_dst->current_graph_type = DG_K2_GRAPH;
                    } else if (tmp_dst->current_graph_type == DG_SRC_DST_GRAPH) {
                        tmp_edge_key.src_id = My_ID;
                        tmp_edge_key.dst_id = i;

                        if (tmp_dst->problem_count < DG_PROB_COUNT_THRESH) {
                            Alarm(PRINT, "DG_Process_Edge_Update: RESOLVED source problem on "
                                         "edge (%u, %u) %d %d for %d (from src-dst to k2)\n", edge_key.src_id,
                                         edge_key.dst_id, edge->cost, new_cost, i);
                            tmp_dst->current_graph_type = DG_K2_GRAPH;
                        } else if (!DG_Problem_On_Graph(&tmp_dst->edge_lists[DG_DST_GRAPH], tmp_edge_key, DG_DST_GRAPH)) {
                            Alarm(PRINT, "DG_Process_Edge_Update: RESOLVED source problem on "
                                         "edge (%u, %u) %d %d for %d (from src-dst to dst)\n", edge_key.src_id,
                                         edge_key.dst_id, edge->cost, new_cost, i);
                            tmp_dst->current_graph_type = DG_DST_GRAPH;
                        }
                        /* If there is still a non-dest problem on the dst
                         * graph, stick with the src-dst graph */
                    }
                }
            }

            DG_Source.problem_count--;
        }

        /* Check for resolution of middle of network problems */
        for (i = 1; i <= MAX_NODES; i++)
        {
            tmp_dst = &DG_Destinations[i];

            /* See if resolution of "middle-of-network" problem allows us
             * to go from src-dst graph to just source or just destination
             * */
            if (tmp_dst->current_graph_type == DG_SRC_DST_GRAPH)
            {
                if (DG_Source.problem_count < DG_PROB_COUNT_THRESH &&
                    tmp_dst->problem_count < DG_PROB_COUNT_THRESH) {
                       Alarm(EXIT, "ERROR!: No source OR destination problem "
                             "when using src-dst graph for destination %d. Source "
                             "prob count %d, Dest prob count %d\n",
                             i, DG_Source.problem_count, tmp_dst->problem_count);
                }

                tmp_edge_key.src_id = My_ID;
                tmp_edge_key.dst_id = i;

                if (DG_Source.problem_count < DG_PROB_COUNT_THRESH) {
                    if (!DG_Problem_On_Graph(&tmp_dst->edge_lists[DG_DST_GRAPH], tmp_edge_key, DG_DST_GRAPH)) {
                        Alarm(PRINT, "DG_Process_Edge_Update: RESOLVED mid-net problem on "
                                     "edge (%u, %u) %d %d (from src-dst to dst) for %d\n", edge_key.src_id,
                                     edge_key.dst_id, edge->cost, new_cost, i);
                        tmp_dst->current_graph_type = DG_DST_GRAPH;
                    }
                } else if (tmp_dst->problem_count < DG_PROB_COUNT_THRESH) {
                    if (!DG_Problem_On_Graph(&tmp_dst->edge_lists[DG_SRC_GRAPH], tmp_edge_key, DG_SRC_GRAPH)) {
                        Alarm(PRINT, "DG_Process_Edge_Update: RESOLVED mid-net problem on "
                                     "edge (%u, %u) %d %d (from src-dst to src) for %d\n", edge_key.src_id,
                                     edge_key.dst_id, edge->cost, new_cost, i);
                        tmp_dst->current_graph_type = DG_SRC_GRAPH;
                    }
                }
            }
        }
    }
}
