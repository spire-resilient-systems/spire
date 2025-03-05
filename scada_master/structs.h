/*
 * Spire.
 *
 * The contents of this file are subject to the Spire Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.dsn.jhu.edu/spire/LICENSE.txt 
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis, 
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
 * for the specific language governing rights and limitations under the 
 * License.
 *
 * Spire is developed at the Distributed Systems and Networks Lab,
 * Johns Hopkins University and the Resilient Systems and Societies Lab,
 * University of Pittsburgh.
 *
 * Creators:
 *   Yair Amir            yairamir@cs.jhu.edu
 *   Trevor Aron          taron1@cs.jhu.edu
 *   Amy Babay            babay@pitt.edu
 *   Thomas Tantillo      tantillo@cs.jhu.edu 
 *   Sahiti Bommareddy    sahiti@cs.jhu.edu 
 *   Maher Khan           maherkhan@pitt.edu
 *
 * Major Contributors:
 *   Marco Platania       Contributions to architecture design 
 *   Daniel Qian          Contributions to Trip Master and IDS 
 *
 * Contributors:
 *   Samuel Beckley       Contributions to HMIs
 *
 * Copyright (c) 2017-2025 Johns Hopkins University.
 * All rights reserved.
 *
 * Partial funding for Spire research was provided by the Defense Advanced 
 * Research Projects Agency (DARPA), the Department of Defense (DoD), and the
 * Department of Energy (DoE).
 * Spire is not necessarily endorsed by DARPA, the DoD or the DoE. 
 *
 */

#ifndef STRUCTS
#define STRUCTS

#define MAX_SWITCHES 10
#define MAX_LINES 10

typedef struct p_switch_d {
    int id;
    char status;
} p_switch;

typedef struct p_link_d {
    int id;
    char status;
    p_switch *src_sw;
    int src_sw_id;
    p_switch *dest_sw;
    int dest_sw_id;
    int src_sub;
    int dest_sub;
} p_link;

typedef struct p_tx_d {
    int id;
    char status;
} p_tx;

typedef struct sub_d {
    int id;
    char status;
    int num_switches;
    int num_lines;
    int num_in_lines;
    p_switch * sw_list[MAX_SWITCHES];
    p_link * out_lines[MAX_LINES];
    p_link * in_lines[MAX_LINES];
    p_tx * tx;
} sub;

#endif /* STRUCTS */
