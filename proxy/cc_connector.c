/*
 * Spire.
 *
 * The contents of this file are subject to the Spire Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * https://jhu-dsn.github.io/spire/LICENSE.txt 
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
 * Copyright (c) 2017-2024 Johns Hopkins University.
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

#include <netinet/in.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include "spines_lib.h"


#include "../common/net_wrapper.h" 
#include "../common/def.h"
#include "../common/openssl_rsa.h"
#include "../common/tc_wrapper.h"
#include "../common/itrc.h"
#include "../common/scada_packets.h"
#include "../common/key_value.h"
#include "../config/cJSON.h"
#include "../config/config_helpers.h"

#define MAX_PATH 1000
char* cc_addrs[NUM_CC_CONNECTORS] = CC_CONNECTORS;
char relay_addrs[NUM_REPLICAS][32];

void Load_SS_Conf(char *filename);

void Load_SS_Conf(char *filename){
    FILE *fp;
    char line[255];
    int i=0;
    fp = fopen(filename,"r");
    while( i<NUM_REPLICAS)
    {
	
	if(fgets(line, sizeof(line), fp)!=NULL){
	    const char * val1=strtok(line, " ");
	    const char * val2=strtok(NULL, " ");
	    strcpy(relay_addrs[i],val2);
	    i+=1;
	}
	else{
	printf("Empty line in conf file ; please check.\n");	
	exit(1);
	}

    }
}

int main(int argc, char *argv[])
{
    int i, num, ret, nBytes, sub, ret2,cc_id,ret3;
    int ipc_sock,mu_sock;
    struct timeval now;
    struct sockaddr_in dest,mu_send_addr;
    fd_set mask, tmask;
    char buff[MAX_LEN];
    signed_message *mess;
    rtu_data_msg *rtud;
    itrc_data itrc_main, itrc_thread;
    seq_pair *ps;
    char *ip_ptr;
    int pid;
    char *buffer;
    char path[MAX_PATH];
    pthread_t tid;
    int ss_ext_spines;
    setlinebuf(stdout);
    char conf_file[50];

    /* Parse args */
    if(argc != 3) {
        printf("HELP: proxy <subsattion_id> <connector_id>\n");
        return 0;
    }
    /*Load CC SM details*/ 
    Init_SM_Replicas();
    /* My ID and args*/
    gettimeofday(&now, NULL);
    My_Incarnation = now.tv_sec;
    sub = atoi(argv[1]);
    My_ID = sub;
    cc_id=atoi(argv[2]);
    cc_id-=1;
    /*Load SS Conf*/ 
    sprintf(conf_file,"../common/ss%d.conf",My_ID);
    printf("My substation configuration file is %s\n",conf_file);
    for(i=0;i<NUM_REPLICAS;i++){
	memset(relay_addrs[i],0,32);
	}
    Load_SS_Conf(conf_file);
    for(i=0;i<NUM_REPLICAS;i++){
	printf("relay addr[%d]=%s\n",i,relay_addrs[i]);
	}
    /* Calculate CC spines ext port and SS spines ext port*/ 
    int ss_spines_ext_port=SS_SPINES_EXT_BASE_PORT+((My_ID-16)*10);
    int relay_ss_port=RELAY_SUBSTATION_BASE_PORT+((My_ID-16)*10);
    printf("spines ext=%d, relay ss port =%d \n",ss_spines_ext_port,relay_ss_port); 
    /*Net Setup*/
    Type = RTU_TYPE;
    //Prime_Client_ID = (NUM_SM + 1) + My_ID;
    Prime_Client_ID = MAX_NUM_SERVER_SLOTS + My_ID;
    My_IP = getIP();
    printf("My Prime Client ID is %d\n", Prime_Client_ID); 

    /*Setup IPC for the RTU Proxy main thread */
    memset(&itrc_main, 0, sizeof(itrc_data));
    sprintf(itrc_main.prime_keys_dir, "%s", (char *)PROXY_PRIME_KEYS);
    sprintf(itrc_main.sm_keys_dir, "%s", (char *)PROXY_SM_KEYS);
    sprintf(itrc_main.ipc_local, "%s%d", (char *)RTU_IPC_MAIN, My_ID);
    sprintf(itrc_main.ipc_remote, "%s%d", (char *)RTU_IPC_ITRC, My_ID);
    ipc_sock = IPC_DGram_Sock(itrc_main.ipc_local);
    printf("My itrc main local is %s\n",itrc_main.ipc_local);
    fflush(stdout);
    // Setup IPC for the Worker Thread (running the ITRC Client)
    memset(&itrc_thread, 0, sizeof(itrc_data));
    sprintf(itrc_thread.prime_keys_dir, "%s", (char *)PROXY_PRIME_KEYS);
    sprintf(itrc_thread.sm_keys_dir, "%s", (char *)PROXY_SM_KEYS);
    sprintf(itrc_thread.ipc_local, "%s%d", (char *)RTU_IPC_ITRC, My_ID);
    sprintf(itrc_thread.ipc_remote, "%s%d", (char *)RTU_IPC_MAIN, My_ID);
   
    if(cc_id<0 && cc_id>=NUM_CC_CONNECTORS){
    	perror("Invalid connector id\n");
    }

    printf("My spines addr is %s and port is %d\n", cc_addrs[cc_id],SPINES_EXT_PORT);

    sprintf(itrc_thread.spines_ext_addr, "%s", cc_addrs[cc_id]);
    //sprintf(itrc_thread.spines_ext_port, "%d",(int) SPINES_EXT_PORT);
    itrc_thread.spines_ext_port=SPINES_EXT_PORT;
    printf("PROXY: Setting up ITRC CC_Proxy thread\n");
    fflush(stdout);
    pthread_create(&tid, NULL, &ITRC_CC_Connector, (void *)&itrc_thread);
    /*Connect to SS dissemination network*/
    ss_ext_spines=Spines_Sock(cc_addrs[cc_id], ss_spines_ext_port, SPINES_PRIORITY, relay_ss_port);
    if(ss_ext_spines<0){
        printf("Cannot connect to substation dissemination Spines\n");
        fflush(stdout);
    }
    if(MU_EMULATE){
	    mu_sock=-1;
	    //mu_sock = Spines_SendOnly_Sock(cc_addrs[cc-id], SPINES_EXT_PORT, SPINES_PRIORITY);
	    mu_sock = Spines_Mcast_SendOnly_Sock(cc_addrs[cc_id], SPINES_EXT_PORT, SPINES_PRIORITY);
	    if (mu_sock < 0) {
      		printf("spines socket error: cannt set up MU mcast port\n");
      		exit(0);
    	}
	    
	    int ttl = 255;
	    if(spines_setsockopt(mu_sock, 0, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) != 0) {
      		printf("spines setsocket error: cannt set up MU mcast port\n");
		exit(0);
          }
	  
	  printf("Successfully set up MU MCAST \n");
    	
    
    }


    printf("Connected to ss_ext_spines on %s and %d\n",cc_addrs[cc_id], relay_ss_port);
    fflush(stdout);
    FD_ZERO(&mask);
    FD_SET(ipc_sock, &mask);
    FD_SET(ss_ext_spines,&mask);

    while (1) {
        tmask = mask;
        num = select(FD_SETSIZE, &tmask, NULL, NULL, NULL);

        if (num > 0) {
            
            /* Message from ITRC */
            if (FD_ISSET(ipc_sock, &tmask)) {
                ret = IPC_Recv(ipc_sock, buff, MAX_LEN);
                if (ret <= 0) {
                    printf("Error in IPC_Recv: ret = %d, dropping!\n", ret);
                    continue;
                }
                mess = (signed_message *)buff;
                    //put it on substation dissemination network
                for(int j=0;j<NUM_REPLICAS;j++){
                    dest.sin_family = AF_INET;
                    dest.sin_port = htons(relay_ss_port);
                    dest.sin_addr.s_addr = inet_addr(relay_addrs[j]);
                    ret2=spines_sendto(ss_ext_spines,mess,ret,0,(struct sockaddr *)&dest, sizeof(struct sockaddr));
                    if(ret2!=ret){
                        printf("Cannot send on ss_ext_spines\n");
                    }else{
                    //printf("PROXY: Delivering msg to substation dissemination network\n");
		    }
                } 

            }
	    /*SS Mesage to be sent to CC and simulator*/
            else if (FD_ISSET(ss_ext_spines,&tmask)){
                 struct sockaddr_in  from_addr;
                 socklen_t  from_len = sizeof(from_addr);
                 ret = spines_recvfrom(ss_ext_spines, buff, MAX_LEN, 0, (struct sockaddr *) &from_addr, &from_len);
                 signed_message * test;
                 test = (signed_message *)buff;
                 printf("Sending to CC mess type %lu from client %lu\n",test->type,test->machine_id);
                 
                 if(ret==sizeof(signed_update_message)){
                    printf("Received feedback message on substation dissemination network size=%d\n",ret);
                    ret2 = IPC_Send(ipc_sock, buff, ret, itrc_main.ipc_remote);   
                    if(ret2!=ret){
                        printf("Error sending to ITRC_CC\n");
                    }
                    else{
                        printf("Sent %d RTU DATA to CC\n",test->machine_id);
                    }
                 if(MU_EMULATE){
			printf("Preparing to Multicast event to all MUs\n");
	    		mu_send_addr.sin_family = AF_INET;
	    		mu_send_addr.sin_addr.s_addr=htonl(MU_EMULATOR_MCAST_ADDR);
	    		mu_send_addr.sin_port = htons(MU_EMULATOR_MCAST_PORT);
			ret3 = spines_sendto(mu_sock, buff,ret,0, (struct sockaddr*) &mu_send_addr,sizeof(struct sockaddr));
			if(ret3!=ret){
				printf("Error sending to emulated MUs\n");
			}else{
				printf("Sent on MCAST to emulate MUs\n");	
			}
		
		}}

		
                

            }
            
        }
    }
    pthread_exit(NULL);
    return 0;
}
