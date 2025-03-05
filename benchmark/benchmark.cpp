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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>

#include <sys/un.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <signal.h>


extern "C" {
  #include "../common/openssl_rsa.h"
  #include "../common/scada_packets.h"
  #include "../common/net_wrapper.h"
  #include "../common/def.h"
  #include "../common/itrc.h"
#include "spu_events.h"
#include "spines_lib.h"
}

/* Local Defines */
#define NUM_BUCKETS 500    /* # of buckets used for latency histogram */
#define BUCKET_SIZE 1      /* size (milliseconds latency) of each bucket */

int ctrl_spines;
int               ipc_sock;
seq_pair          seq;
itrc_data         itrc_main, itrc_thread;
int               Histogram[NUM_BUCKETS];
double            Sum_Lat, Count_Lat, Min_Lat, Max_Lat;
struct timeval    Poll_Period;
int32u            Num_Polls;
struct sockaddr_in name;
struct ip_mreq mreq;

struct timeval reconf_st, reconf_end;
int print_reconf;

extern int32u My_Global_Configuration_Number;


/* Local Functions */
void Print_Statistics();
void Process_Config_Msg(signed_message * conf_mess,int mess_size);

void Process_Config_Msg(signed_message * conf_mess,int mess_size){

    
    config_message *c_mess;
    int ret;
    
    gettimeofday(&reconf_st, NULL);
    print_reconf=1;

    if (mess_size!= sizeof(signed_message)+sizeof(config_message)){
        printf("Config message is %d ,not expected size of %d\n",mess_size, sizeof(signed_message)+sizeof(config_message));
        return;
    }

    if(!OPENSSL_RSA_Verify((unsigned char*)conf_mess+SIGNATURE_SIZE,
                sizeof(signed_message)+conf_mess->len-SIGNATURE_SIZE,
                (unsigned char*)conf_mess,conf_mess->machine_id,RSA_CONFIG_MNGR)){
        printf("Benchmark: Config message signature verification failed\n");

        return;
    }
    if(conf_mess->global_configuration_number<=My_Global_Configuration_Number){
        printf("Got config=%u and I am already in %u config\n",conf_mess->global_configuration_number,My_Global_Configuration_Number);
        return;
    }
    My_Global_Configuration_Number=conf_mess->global_configuration_number;
    c_mess=(config_message *)(conf_mess+1);
    //Reset SM
    Reset_SM_def_vars(c_mess->N,c_mess->f,c_mess->k,c_mess->num_cc_replicas, c_mess->num_cc,c_mess->num_dc);
    Reset_SM_Replicas(c_mess->tpm_based_id,c_mess->replica_flag,c_mess->spines_ext_addresses,c_mess->spines_int_addresses);
        ret = IPC_Send(ipc_sock, (void *)conf_mess, mess_size, itrc_main.ipc_remote);
    if (ret!=mess_size) printf("Conf msg to ITRC Remote: IPC_Send error!\n");
    sleep(My_ID * 0.1);
}


void Gen_Msg() 
{
    int ret, nBytes;
    signed_message *mess;

    mess = PKT_Construct_Benchmark_Msg(seq);
    mess->global_configuration_number = My_Global_Configuration_Number; 
    nBytes = sizeof(signed_message) + mess->len;
    seq.seq_num++;
    ret = IPC_Send(ipc_sock, (void *)mess, nBytes, itrc_main.ipc_remote);
    if (ret < 0) printf("Gen_Msg: IPC_Send error!\n");
    free(mess);
}

void Process_Msg()
{
    char buf[MAX_LEN];
    int ret, index,ret2; 
    double latency;
    signed_message *mess;
    benchmark_msg *ben;
    struct timeval now, rtt, ping; //, pong; //, apx_oneway;

    ret = IPC_Recv(ipc_sock, buf, MAX_LEN);
    if (ret < 0) printf("Process_Msg: IPC_Recv error!\n");
    mess = (signed_message *)buf;
    if(mess->type ==  PRIME_OOB_CONFIG_MSG){
        //printf("*****************CONF_MSG*****************\n");
	Process_Config_Msg((signed_message *)buf,ret);
        return;
    }
    
    ben = (benchmark_msg *)(mess + 1);

    //printf("BENCHMARK MSG [%d,%u]:\n", ben->sender, ben->seq.seq_num);
    
    ping.tv_sec  = ben->ping_sec;
    ping.tv_usec = ben->ping_usec;

    gettimeofday(&now, NULL);
    rtt = diffTime(now, ping);
    //printf("\trtt = %lu s %lu us\n", rtt.tv_sec, rtt.tv_usec);
    printf("%d\t%d\t%lu\t%lu\t%lu\t%lu\n", ben->sender, ben->seq.seq_num,
            now.tv_sec, now.tv_usec, rtt.tv_sec, rtt.tv_usec);

    if(print_reconf){
        gettimeofday(&reconf_end,NULL);
        print_reconf=0;
        struct timeval reconf_dur=diffTime(reconf_end,reconf_st);
        //printf("*******Reconf time=%lu \t %lu********\n",reconf_dur.tv_sec,reconf_dur.tv_usec);
    }

    // Bookkeeping for Statistics
    latency = rtt.tv_sec + rtt.tv_usec / 1000000.0;
    index = latency * 1000.0 / BUCKET_SIZE;
    if (index >= NUM_BUCKETS)
        index = NUM_BUCKETS - 1;
    Histogram[index]++;

    Sum_Lat += latency;
    Count_Lat++;

    if (latency < Min_Lat)
        Min_Lat = latency;
    if (latency > Max_Lat)
        Max_Lat = latency;

    if (ben->seq.seq_num >= Num_Polls) 
        Print_Statistics();
}

void Print_Statistics()
{
    int i;

    printf("--------------------------------\n");
    printf("Benchmark Program: #%d\n", My_ID);

    for (i = 0; i < NUM_BUCKETS; i++)
        printf("\t[%3u - %3u]:\t%u\n", i*BUCKET_SIZE, (i+1)*BUCKET_SIZE, Histogram[i]);
    printf("Average / Min / Max Latency = %f sec / %f sec / %f sec\n",
                (Sum_Lat / Count_Lat), Min_Lat, Max_Lat);

    //fclose(fw);
    exit(EXIT_SUCCESS);
}

void clean_exit(int signum)
{
    printf("Received Signal %d\n", signum);
    fflush(stdout);
    Print_Statistics();
}

// Intialize Data Structures
static void init(int ac, char **av)
{
    char *ip_ptr;
    int poll_freq;
    //char filename[128];
    struct timeval now;

    if(ac != 5) {
        printf("Usage: %s ID spinesAddr:spinesPort Poll_Frequency(usec) Num_Polls\n", av[0]);
        exit(EXIT_FAILURE);
    }

    My_Global_Configuration_Number=0;
    Init_SM_Replicas();


    // Net Setup
    seq.seq_num = 1;
    gettimeofday(&now, NULL);
    seq.incarnation = now.tv_sec;
    Type = RTU_TYPE;
    sscanf(av[1], "%d", &My_ID);
    Prime_Client_ID = MAX_NUM_SERVER_SLOTS + My_ID;
    My_IP = getIP();

    // Setup IPC for the RTU Proxy main thread
    memset(&itrc_main, 0, sizeof(itrc_data));
    sprintf(itrc_main.ipc_local, "%s%d", (char *)BM_IPC_MAIN, My_ID);
    sprintf(itrc_main.ipc_remote, "%s%d", (char *)BM_IPC_ITRC, My_ID);
    sprintf(itrc_main.prime_keys_dir, "%s", (char *)PROXY_PRIME_KEYS);
    sprintf(itrc_main.sm_keys_dir, "%s", (char *)PROXY_SM_KEYS);
    ipc_sock = IPC_DGram_Sock(itrc_main.ipc_local);

    printf("MS2022: Bm itrc main  %s(ipc_sock)\n",itrc_main.ipc_local);
    printf("MS2022: Bm itrc main ipc_remote is %s\n",itrc_main.ipc_remote);

    // Setup IPC for the Worker Thread (running the ITRC Client)
    memset(&itrc_thread, 0, sizeof(itrc_data));
    sprintf(itrc_thread.ipc_local, "%s%d", (char *)BM_IPC_ITRC, My_ID);
    sprintf(itrc_thread.ipc_remote, "%s%d", (char *)BM_IPC_MAIN, My_ID);
    sprintf(itrc_thread.prime_keys_dir, "%s", (char *)PROXY_PRIME_KEYS);
    sprintf(itrc_thread.sm_keys_dir, "%s", (char *)PROXY_SM_KEYS);
    ip_ptr = strtok(av[2], ":");
    sprintf(itrc_thread.spines_ext_addr, "%s", ip_ptr);
    ip_ptr = strtok(NULL, ":");
    sscanf(ip_ptr, "%d", &itrc_thread.spines_ext_port);
    printf("MS2022: Bm iterc thread ipc_remote is %s\n",itrc_thread.ipc_remote);

    // Grab the Timeout frequency 
    memset(&Poll_Period, 0, sizeof(struct timeval));
    sscanf(av[3], "%d", (int *)&poll_freq);
    Poll_Period.tv_sec  = poll_freq / 1000000;
    Poll_Period.tv_usec = poll_freq % 1000000;

    // Grab the Number of Polls
    sscanf(av[4], "%d", &Num_Polls);

    // Setup Signal Handlers
    signal(SIGINT,  clean_exit);
    signal(SIGTERM, clean_exit);
    signal(SIGKILL, clean_exit);
    signal(SIGQUIT, clean_exit);
    signal(SIGHUP,  clean_exit);
    signal(SIGTSTP, clean_exit);
    signal(SIGTTOU, clean_exit);
    signal(SIGTTIN, clean_exit);
    signal(SIGPIPE, clean_exit);

    // Setup Statistics Variables
    Sum_Lat = 0;
    Count_Lat = 0;
    Min_Lat = 9999;
    Max_Lat = 0;
    memset(Histogram, 0, sizeof(int) * NUM_BUCKETS);
}

/* Main Function */
int main(int argc,char *argv[])
{
    int num;
    struct timeval timeout, now, topoll;
    fd_set mask, tmask;
    pthread_t tid;

    setlinebuf(stdout);

    init(argc, argv);
    
        
    pthread_create(&tid, NULL, &ITRC_Client, (void *)&itrc_thread);

    // FIX THIS - Have the thread set some flag when it is done initializing
    sleep(1);

    // Setup the FD_SET for use in select
    FD_ZERO(&mask);
    FD_SET(ipc_sock, &mask);
    // Initial timeout setup
    gettimeofday(&topoll, NULL);

    printf("All network setup done \n");
    // run the daemon forever
    while (1) {

        gettimeofday(&now, NULL);
        if (compTime(now, topoll) >= 0) {
            timeout.tv_sec = 0;
            timeout.tv_usec = 0;
        } 
        else {
            timeout = diffTime(topoll, now);
        }

        tmask = mask;
        num = select(FD_SETSIZE, &tmask, NULL, NULL, &timeout);

        if (num > 0) {
            if(FD_ISSET(ipc_sock, &tmask))
                Process_Msg();
        } 
        else {
            gettimeofday(&topoll, NULL);
            topoll = addTime(topoll, Poll_Period);
            Gen_Msg();
        }
    }

    pthread_exit(NULL);
}
