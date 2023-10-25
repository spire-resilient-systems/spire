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

#ifndef DISSEMGRAPHS_H
#define DISSEMGRAPHS_H

/* Round-trip latency requirement for dissemination graphs routing (all
 * dissemination graphs must connect the source and destination with latency no
 * more than DG_LATENCY_REQ). As a fallback, we use the static two disjoint
 * paths graph for all 4 graph types -- might be better to default to dynamic
 * two disjoint paths in this case */
#define DG_LATENCY_REQ          130

/* Switch to source/destination graph if number of source/destination problems
 * exceeds this threshold */
#define DG_PROB_COUNT_THRESH     2

/* Total number of pre-computed dissemination graphs for each flow */
#define DG_NUM_GRAPHS    4

/* Defining the four graph types */
#define DG_NONE_GRAPH    0
#define DG_K2_GRAPH      1
#define DG_SRC_GRAPH     2
#define DG_DST_GRAPH     3
#define DG_SRC_DST_GRAPH 4

/* Data structures for maintaining information about source/destination
 * problems for my flows */
typedef struct DG_Dst_d {
    unsigned char *bitmasks[DG_NUM_GRAPHS+1];   /* Includes 2-path, src-problem, dst-problem, and src-dst-problem bitmasks */
    stdskl         edge_lists[DG_NUM_GRAPHS+1]; /* Contains edge keys and indexes corresponding to the bitmasks */
    int            current_graph_type;          /* Which graph are we currently using for this dest? (2path, src, dst, src-dst */
    int            problem_count;               /* How many edge problems do we know about for this destination? */
    int            problems[MAX_NODES + 1];     /* Which neighbors are currently problematic for this dst? */
} DG_Dst;

typedef struct DG_Src_d {
    int problem_count;                          /* How many of my outgoing links are currently problematic? */
    int problems[MAX_NODES + 1];                /* Which neighbors am I currently having problems with? */
} DG_Src;

#undef ext
#ifndef ext_dg
#define ext extern
#else
#define ext
#endif

ext DG_Dst  DG_Destinations[MAX_NODES+1];

void DG_Compute_Graphs(void);
void DG_Process_Edge_Update(Edge *edge, int16 new_cost);

#endif /* DISSEMGRAPHS_H */
