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

#ifndef DATA_STRUCTS_H
#define DATA_STRUCTS_H

#include "def.h"
#include "packets.h"

#define BENCH_COUNT 10
#define BENCH_STATS 1
// if 0 - no DoS, else set any value of  1-4
// replica whode id==DoS will attack replica  of id = (DoS % N) +1 
// Eg 1 will attack 2, 4 will attack 1 etc.  
#define DOS 0 

enum TM_State {
    RECOVERY,
    TRIPPED,
    CLOSED,
    ATTEMPT_TRIP,
    ATTEMPT_CLOSE,
    WAIT_TRIP,
    WAIT_CLOSE
};

#define IPC_SOURCE      1
#define SP_EXT_SOURCE   2


typedef struct dummy_server_data {
    uint32_t id;
    uint32_t tm_state;
    uint32_t cb_prev_state;
    
    tc_payload r;
    tc_payload b;


    /* Messages that are currently being sent periodically */
    tm_msg *cur_relay_msg;
    /* Current dts (i.e. time last published by myself) */
    uint64_t cur_dts;

} server_data;


typedef struct dummy_bench_stats {
    uint64_t actions_count;
} bench_stats;

typedef struct dummy_network_vars {
    int sock_relay_ipc; // IPC socket for relay proxy
    int s_relay_in;

    int sock_spines_ext; // Spines external socket for communcation with proxy

} network_vars;

extern server_data  DATA;
extern network_vars NET;
extern bench_stats STATS;

void Init_Server_Data();
void Init_Network();
void Init_Bench_Stats();

#endif
