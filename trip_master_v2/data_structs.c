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

#include "data_structs.h"
#include "spu_alarm.h"
#include "ss_net_wrapper.h"

#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

server_data  DATA;
network_vars NET;
bench_stats STATS;

void Init_Server_Data(int id)
{
    DATA.id = id;
    DATA.tm_state = RECOVERY;
    DATA.cb_prev_state =RECOVERY_QUERY;//CB_CLOSE=9, CB_TRIP=8
    
    memset(&DATA.r, 0, sizeof(DATA.r));
    memset(&DATA.b, 0, sizeof(DATA.b));
    DATA.cur_relay_msg = NULL;
    DATA.cur_dts = 0;

}

void Init_Network(int id)
{
    char *sp_ext_addr = Relay_Ext_Addrs[id - 1];
    struct sockaddr_un tm_ipc_addr;

    NET.sock_relay_ipc = IPC_DGram_Sock(TM_IPC_IN);
    NET.sock_spines_ext = Spines_Sock(sp_ext_addr, SS_SPINES_EXT_PORT, SPINES_PRIORITY, TM_PROXY_PORT);


    if (NET.sock_relay_ipc < 0) {
        Alarm(EXIT, "TM: Error setting up ipc with relay for relay input, exiting");
    }
    if (NET.sock_spines_ext < 0) {
        Alarm(EXIT, "TM: Error setting up spines dissemination socket, exiting");
    }
    NET.s_relay_in = IPC_DGram_SendOnly_Sock();
    memset(&tm_ipc_addr, 0, sizeof(tm_ipc_addr));
    tm_ipc_addr.sun_family=AF_UNIX;
    strncpy(tm_ipc_addr.sun_path,TM_IPC_OUT,sizeof(tm_ipc_addr.sun_path));
    if (NET.s_relay_in < 0) {
        Alarm(EXIT, "Error setting up IPC relay Breaker GOOSE communication, exiting\n");
    }

    /* TODO try reconnecting? */
}

void Init_Bench_Stats()
{
    STATS.actions_count=0 ;

}
