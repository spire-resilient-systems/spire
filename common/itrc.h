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

#ifndef ITRC_H
#define ITRC_H

#include "scada_packets.h"

/* 
#include "def.h"
#define MAX_SHARES (3*NUM_F + 2*NUM_K + 1)
#define REQ_SHARES (NUM_F + 1)

typedef struct itrc_data_d {
    char ipc_local[100];
    char ipc_remote[100];
    char spines_int_addr[32];
    int spines_int_port;
    char spines_ext_addr[32];
    int spines_ext_port;
} itrc_data;

typedef struct itrc_queue_node_d {
    uint32_t seq_num;
    char buf[MAX_LEN];
    int len;
    struct itrc_queue_node_d *next;
} itrc_queue_node;

typedef struct itrc_queue_d {
    itrc_queue_node head;
    itrc_queue_node *tail;
} itrc_queue;

typedef struct tc_data_d {
    unsigned int count;
    unsigned int done;
    tc_share_msg shares[MAX_SHARES];
} tc_data;
*/

void *ITRC_Client(void *data);
void *ITRC_Prime_Inject(void *data);
void *ITRC_Master(void *data);

#endif /* ITRC_H */
