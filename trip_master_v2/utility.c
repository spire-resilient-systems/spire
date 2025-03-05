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

#include "utility.h"

#include "def.h"
#include "ss_net_wrapper.h"
#include "ss_openssl_rsa.h"
#include "data_structs.h"
#include "packets.h"

#include "spines_lib.h"
#include "spu_alarm.h"

#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <assert.h>




void UTIL_Print_Bench_Stats()
{
    //Dont print if BENCH_STATS flag is not set
    if(!BENCH_STATS){
        Alarm(DEBUG, "BENCH_STATS flag not set, so not printing stats");
        return;
    }
    //TODO: define Buffer size with BENCH_COUNT and choose to rewirte or only capture initial N
    //In a long run what is best?
    Alarm(PRINT,"Events so far=%lu\n",STATS.actions_count);
}

void UTIL_Send_To_Relay_Proxy(local_relay_msg *mess)
{

    int s;
    int ret;

    s = NET.s_relay_in;


    ret = IPC_Send(s,mess,sizeof(local_relay_msg),(char *)TM_IPC_OUT);

    if (ret < 0) {
        perror("util send to dst proxy sendto error: ");
        // TODO attempt to reconnect?
    }
}

void UTIL_Send_To_Dst_Proxy(tm_msg *mess)
{

    int s;
    int ret,j;
    struct sockaddr_in addr;
    tm_msg *msg;

    s = NET.sock_spines_ext;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(TM_PROXY_PORT);
    addr.sin_addr.s_addr = inet_addr(SPINES_PROXY_ADDR);

     /*If DOS flag is set with your ID send shares to all a thoussand times*/
    if(DOS==DATA.id){
        //corrupt the packet
        msg=(tm_msg *) mess;
        msg->dts-=100;
        for (j=0;j<5;j++){

                ret = spines_sendto(s, mess, sizeof(tm_msg) + mess->len,
                        0, (struct sockaddr *) &addr, sizeof(addr));

                if (ret < 0) {
                    perror("util broad cast sendto error: \n");
                    // TODO attempt to reconnect?
                }

        }
    }
    
    ret = spines_sendto(s, mess, sizeof(tm_msg) + mess->len,
        0, (struct sockaddr *) &addr, sizeof(addr));
    
    if (ret < 0) {
        perror("util send to dst proxy sendto error: \n");
        // TODO attempt to reconnect?
    }
}


const char *UTIL_Get_State_Str(int state)
{
    switch(state)
    {
        case TRIPPED:       return "TRIPPED";
        case CLOSED:        return "CLOSED";
        case ATTEMPT_TRIP:  return "ATTEMPT_TRIP";
        case ATTEMPT_CLOSE: return "ATTEMPT_CLOSE";
        case WAIT_TRIP:     return "WAIT_TRIP";
        case WAIT_CLOSE:    return "WAIT_CLOSE";
    } 

    assert(false);
}
