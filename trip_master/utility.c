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

static void UTIL_Store_Share(tm_msg *mess, tc_share sh_arr[]);
static bool UTIL_Attempt_Combine(int type, tc_share sh_arr[]);


/* Recursively check al/recl combinations of keys that are possible (i.e. n - 1 choose k - 1) 
 * Each call means that we have count shares after looking at index i */
static bool UTIL_Check_Comb_Rec(byte *dst, tc_share *slot, bool used[NUM_REPLICAS], int count, int i);
/* Helper to call with correct initial vals */
static bool UTIL_Check_Comb(byte *dst, tc_share *slot);

void UTIL_Print_Bench_Stats()
{
    uint64_t i;
    //Dont print if BENCH_STATS flag is not set
    if(!BENCH_STATS){
        Alarm(DEBUG, "BENCH_STATS flag not set, so not printing stats");
        return;
    }
    //TODO: define Buffer size with BENCH_COUNT and choose to rewirte or only capture initial N
    //In a long run what is best?
    Alarm(PRINT,"Events so far=%lu\n",STATS.lrCount);
    Alarm(PRINT,"\nseq\tFirst other share \tTC round time \n");
    for (i=1;i<=BENCH_COUNT;i++){
        Alarm(PRINT,"[%06lu]\t%06lu\t%06lu\n",i,STATS.firstShare[i],STATS.resolved[i]);
        if(STATS.resolved[i]!=0 && STATS.resolved[i]<STATS.minResolved)
            STATS.minResolved=STATS.resolved[i];
        if(STATS.resolved[i]!=0 && STATS.resolved[i]>STATS.maxResolved)
            STATS.maxResolved=STATS.resolved[i];
    }
    Alarm(PRINT,"Min so far=%lu\n",STATS.minResolved);
    Alarm(PRINT,"Max so far=%lu\n",STATS.maxResolved);
    memset(STATS.firstShare,0,sizeof(STATS.firstShare));
    memset(STATS.resolved,0,sizeof(STATS.resolved));
}


void UTIL_Broadcast_To_TM(tm_msg *mess)
{
    int s;
    uint32_t i,j; 
    int ret;
    struct sockaddr_in addr;
    tm_msg *msg;

    s = NET.s_coord;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(TM_TC_PORT);

    /*If DOS flag is set with your ID send shares to all a thoussand times*/
    if(DOS==DATA.id){
        //corrupt the packet
        msg=(tm_msg *) mess;
        msg->type=(msg->type ==TRIP_SHARE ? CLOSE_SHARE:TRIP_SHARE);
        Alarm(DEBUG,"DOS with dts=%lu, share=%d\n",msg->dts,msg->type);
        for (j=0;j<5;j++){
            for (i = 0; i < NUM_REPLICAS; i++) {
  
                // Skip sending to myself, shares should be processed myself separately 
                if (i == DATA.id - 1) continue; 

                addr.sin_addr.s_addr = inet_addr(Relay_Int_Addrs[i]);
        
                ret = spines_sendto(s, mess, sizeof(tm_msg) + mess->len,
                        0, (struct sockaddr *) &addr, sizeof(addr));
        
                if (ret < 0) {
                    perror("util broad cast sendto error: \n");
                    // TODO attempt to reconnect?
                }
    
            }
        }
        Alarm(DEBUG,"DOS ended with dts=%lu, share=%d\n",msg->dts,msg->type);
        //correct corrupt packet for own processing

        msg->type=(msg->type ==TRIP_SHARE ? CLOSE_SHARE:TRIP_SHARE);
    }
    
    for (i = 0; i < NUM_REPLICAS; i++) {
        // Skip sending to myself, shares should be processed myself separately 
        if (i == DATA.id - 1) continue; 

        addr.sin_addr.s_addr = inet_addr(Relay_Int_Addrs[i]);
        
        ret = spines_sendto(s, mess, sizeof(tm_msg) + mess->len,
            0, (struct sockaddr *) &addr, sizeof(addr));
        
        if (ret < 0) {
            perror("util broad cast sendto error: \n");
            // TODO attempt to reconnect?
        }
        

    }
    
}

void UTIL_Send_To_Dst_Proxy(tm_msg *mess)
{

    int s;
    int ret;
    struct sockaddr_in addr;

    s = NET.s_proxy;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(TM_PROXY_PORT);
    addr.sin_addr.s_addr = inet_addr(SPINES_PROXY_ADDR);

    ret = spines_sendto(s, mess, sizeof(tm_msg) + mess->len,
        0, (struct sockaddr *) &addr, sizeof(addr));
    
    if (ret < 0) {
        perror("util send to dst proxy sendto error: ");
        // TODO attempt to reconnect?
    }
}
void UTIL_Send_To_Relay_Proxy(local_relay_msg *mess)
{

    int s;
    int ret;

    s = NET.s_relay_in;


    ret = IPC_Send(s,mess,sizeof(local_relay_msg),(char *)TM_IPC_OUT);
    
    if (ret < 0) {
        perror("util send to relay proxy sendto error: ");
        // TODO attempt to reconnect?
    }
}
void UTIL_Store_Trip_Share(tm_msg *mess)
{
    assert(mess->type == TRIP_SHARE);
    UTIL_Store_Share(mess, DATA.trips);
}


void UTIL_Store_Close_Share(tm_msg *mess)
{
    assert(mess->type == CLOSE_SHARE);
    UTIL_Store_Share(mess, DATA.closes);
}

bool UTIL_Attempt_Combine_Trip()
{
    assert(DATA.tm_state == ATTEMPT_TRIP);
    return UTIL_Attempt_Combine(SIGNED_TRIP, DATA.trips);
}

bool UTIL_Attempt_Combine_Close()
{
    assert(DATA.tm_state == ATTEMPT_CLOSE);
    return UTIL_Attempt_Combine(SIGNED_CLOSE, DATA.closes);
}



bool UTIL_Attempt_Combine(int type, tc_share sh_arr[])
{
    int i, j, dts_index;
    uint64_t dts;
    bool ret;
    tm_msg *mess;
    tc_final_msg *tcf_mess;
    byte digest[DIGEST_SIZE];

    for (i = SHARES_PER_MSG - 1; i >= 0; i--)
    {
        dts = DATA.cur_dts + i * DTS_INTERVAL;
        dts_index = (dts / DTS_INTERVAL) % SHARES_PER_MSG;
        
        if (sh_arr[dts_index].count <= SS_NUM_F) {
	        Alarm(DEBUG,"Too few shares in dts=%lu to combine\n",dts);
            continue;
        }

        Alarm(DEBUG,"Trying to combine shares at dts=%lu\n",dts);
        
        mess = PKT_Construct_TM_Message(type, DATA.id, dts, sizeof(tc_final_msg));
        tcf_mess = (tc_final_msg *)(mess + 1);
 
        if (UTIL_Check_Comb(tcf_mess->thresh_sig, &sh_arr[dts_index])) {
            DATA.cur_signed = mess;
            return true;
        } else {
            free(mess);
        }
    }

    return false;

}

bool UTIL_Check_Comb(byte *dst, tc_share *slot) {
    bool used[NUM_REPLICAS];
    memset(used, 0, sizeof(used));
    return UTIL_Check_Comb_Rec(dst, slot, used, 0, 0);
}

bool UTIL_Check_Comb_Rec(byte *dst, tc_share *slot, bool used[NUM_REPLICAS], int count, int i)
{
    static byte digest[DIGEST_SIZE];
    int j, num_shares,k;

    if (i >= NUM_REPLICAS) {
        return false;
    }
    
    // Don't count ourselves
    if (i == DATA.id - 1) {
        return UTIL_Check_Comb_Rec(dst, slot, used, count, i + 1);
    }

    // Haven't received
    if (!slot->recvd[i]) {
        return UTIL_Check_Comb_Rec(dst, slot, used, count, i + 1);
    }


    // Adding this share should give us enough with our own share (NUM_F + 1 required)
    // Try combining it    
    used[i] = true;
    if (count + 1 == SS_NUM_F) {
        TC_Initialize_Combine_Phase(NUM_REPLICAS);
    
        num_shares = 0;

        for (j = 0; j < NUM_REPLICAS; j++) {
            if (!(used[j] || j == DATA.id - 1)) continue;

            Alarm(DEBUG, "adding %d\n", j + 1);
            // TC stuff is 1 indexed for some reason
            TC_Add_Share_To_Be_Combined(j + 1, slot->shares[j].share);
            num_shares++;
        }
        assert(num_shares == NUM_F + 1);
        
        OPENSSL_RSA_Make_Digest(&slot->payload, sizeof(tc_payload), digest);

        if (TC_Combine_Shares(dst, digest))
            return true;
        else{
            Alarm(PRINT,"Failed for dts=%lu, state=%ld used=",DATA.cur_signed->dts,DATA.cur_signed->type);
            for(k=0;k<NUM_REPLICAS;k++)
                Alarm(PRINT,"\t%d",used[k]);
            Alarm(PRINT,"\n");
        }
    } else {
        // Adding this share does not give us enough, try more combinations with this share
        if (UTIL_Check_Comb_Rec(dst, slot, used, count + 1, i + 1)) return true;

    }

    // Try without this share
    used[i] = false;
    if (UTIL_Check_Comb_Rec(dst, slot, used, count, i + 1)) return true;

    return false;
}


void UTIL_Store_Share(tm_msg *mess, tc_share sh_arr[])
{
    int i, dts_index;
    uint64_t dts;
    tc_share_msg *tc_mess;

    tc_mess = (tc_share_msg *)(mess + 1);

    assert((mess->type == TRIP_SHARE && sh_arr == DATA.trips) || (mess->type == CLOSE_SHARE && sh_arr == DATA.closes));

    if (mess->m_id == DATA.id) {
        assert(mess->dts > DATA.cur_dts);

        DATA.cur_dts = mess->dts;
        
        /* Clear out shares from older/empty timestamps and repalce with newer ones */
        for (i = 0; i < SHARES_PER_MSG; i++) {
            dts = DATA.cur_dts + i * DTS_INTERVAL;

            dts_index = (dts / DTS_INTERVAL) % SHARES_PER_MSG;

            if (sh_arr[dts_index].payload.dts != dts) {
                Alarm(DEBUG, "dts_index=%d sh_arr[dts_index].payload.dts= %ld,dts= %ld\n", dts_index, sh_arr[dts_index].payload.dts, dts);
                assert(sh_arr[dts_index].payload.dts < dts);
                
                sh_arr[dts_index].payload.dts = dts;
                sh_arr[dts_index].payload.state = (mess->type == TRIP_SHARE ? STATE_TRIP : STATE_CLOSE); 
                Alarm(DEBUG, "After dts_index=%d sh_arr[dts_index].payload.dts= %ld,dts= %ld\n", dts_index, sh_arr[dts_index].payload.dts, dts);
                sh_arr[dts_index].count = 0; 
                
                memset(sh_arr[dts_index].recvd, 0, sizeof(sh_arr[dts_index].recvd));
                memset(sh_arr[dts_index].shares, 0, sizeof(sh_arr[dts_index].shares));

                Alarm(DEBUG, "Creating slot for dts %ld\n", dts); 
            }
        }     
    }

    for (i = 0; i < SHARES_PER_MSG; i++) {
        dts = mess->dts + i * DTS_INTERVAL;

        //Too old
        if (dts < DATA.cur_dts){
            Alarm(DEBUG,"Too old dts=%lu so not storing\n",dts);
            continue; 
        }
        // Too far in the future
        if (dts - DATA.cur_dts >= SHARES_PER_MSG * DTS_INTERVAL){ 
            Alarm(DEBUG,"Too future dts=%lu so not storing\n",dts);
            break;
        }

        dts_index = (dts / DTS_INTERVAL) % SHARES_PER_MSG;

        if (!sh_arr[dts_index].recvd[mess->m_id - 1]) {
            sh_arr[dts_index].count++;
        }

        sh_arr[dts_index].recvd[mess->m_id - 1] = true;
        
        sh_arr[dts_index].shares[mess->m_id - 1] = tc_mess->shares[i];
        Alarm(DEBUG, "Storing share from %d for dts %ld (count %d)\n", mess->m_id, dts, sh_arr[dts_index].count); 
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
