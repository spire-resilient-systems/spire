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

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>

#include "spu_alarm.h"
#include "spu_events.h"
#include "spines_lib.h"

#include "def.h"
#include "packets.h"
#include "scada_packets.h"
#include "net_wrapper.h"

int My_SS_ID;
char* cc_addrs[NUM_CC_CONNECTORS]=CC_CONNECTORS;
void usage(int argc, char **argv);
int ss_ids[3];
uint64_t cb_curr_dts[3];

void error_and_exit(const char* msg, int ecode)
{
    perror(msg);
    exit(ecode);
}

int main(int argc, char **argv)
{
    struct sockaddr_in send_addr,name;
    unsigned char      ttl_val;
    int                s,sr,num;
    struct ip_mreq     mreq;
    int                i;
    int                ret,ret2;
    fd_set             mask;
    fd_set             read_mask, write_mask, except_mask;
    int mu_proxy_in;
    char mu_proxy_ipc_path[128];
    sv_msg             payload;
    struct timeval     now;
    int                trip;
    int                sleep_ms;
    struct timeval     sleep_timeout;
    char buff[MAX_LEN];
    char               input[20];
    signed_message *mess;
    update_message *up;
    signed_message *rtu_mess_header;
    rtu_data_msg *rtu_data;
    substation_fields *sf;

    setlinebuf(stdout);
    Alarm_enable_timestamp_high_res("%m/%d/%y %H:%M:%S");
    Alarm_set_types(PRINT);
    //Alarm_set_types(PRINT|STATUS|DEBUG);

    usage(argc, argv);

    /* Setup socket for multicasting SV */
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        Alarm(EXIT,"EVENT / SV :Mcast socket\n");
    }

    ttl_val = 1;
    if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, (void *)&ttl_val,
        sizeof(ttl_val)) < 0)
    {
        Alarm(PRINT,"EVENT / SV : problem in setsockopt of multicast ttl %d - ignore in WinNT or Win95\n", ttl_val );
    }

    send_addr.sin_family = AF_INET;
    send_addr.sin_addr.s_addr = htonl(EMULATOR_MCAST_ADDR);
    send_addr.sin_port = htons(EMULATOR_MCAST_PORT);

    for (i = 0; i < NUM_REPLICAS; i++) {
        payload.delay_ms[i] = 0;
        payload.trip[i] = 0;
    }

    Alarm(PRINT, "Set up MCAST sock to send SV\n");

    /*Join a group to receive all substation status  updates*/
    
    sr=-1;

    Alarm(PRINT,"Spines addr=%s, port=%d,my_port=%d\n",cc_addrs[0],SPINES_EXT_PORT,MU_SUBSTATION_BASE_PORT+My_SS_ID);
    sr = Spines_Sock(cc_addrs[0],SPINES_EXT_PORT, SPINES_PRIORITY,MU_EMULATOR_MCAST_PORT+My_SS_ID);
  //  sr = Spines_SendOnly_Sock(cc_addrs[0],SPINES_EXT_PORT, SPINES_PRIORITY);
    if(sr<0){
    	Alarm(EXIT,"Error setting up mcast receiving port for all SS status updates\n" );
    }
    else{
    	Alarm(PRINT, "Spines INET sock created\n");
    }
 /*
    memset(&name, 0 , sizeof(name));
    name.sin_family = AF_INET;
    name.sin_addr.s_addr = htonl(INADDR_ANY);
    name.sin_port = htons(MU_EMULATOR_MCAST_PORT);

    if ( spines_bind( sr, (struct sockaddr *)&name, sizeof(name) ) < 0 ) {
        Alarm(EXIT,"Mcast: bind\n");
        
    }
    */
    mreq.imr_multiaddr.s_addr = htonl( MU_EMULATOR_MCAST_ADDR );
    mreq.imr_interface.s_addr = htonl( INADDR_ANY );

    if (spines_setsockopt(sr, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *)&mreq,sizeof(mreq)) < 0)
    {
        Alarm(EXIT,"Mcast: problem in setsockopt to join multicast address\n" );
    }
    /*IPC set up for MU Proxy*/
    mu_proxy_in = IPC_DGram_SendOnly_Sock();
    if(mu_proxy_in<0){
    	Alarm(EXIT, "IPC sock error for proxy\n");
    }
    memset(mu_proxy_ipc_path,0,sizeof(mu_proxy_ipc_path));
    sprintf(mu_proxy_ipc_path,"%s%d",(char *)MU_IPC_OUT,My_SS_ID);
    ss_ids[0]=48;
    ss_ids[1]=49;
    ss_ids[2]=50;
    cb_curr_dts[0]=0;
    cb_curr_dts[1]=0;
    cb_curr_dts[2]=0;


    FD_ZERO( &mask );
    FD_ZERO( &write_mask );
    FD_ZERO( &except_mask );
    FD_SET( sr, &mask );
    FD_SET( (long)0, &mask );    /* stdin */

    /* multicast a timestamp in ms (for debugging) and 0/1 for CLOSE/TRIP*/
    while (1) {
	read_mask=mask;
	num=select(FD_SETSIZE,&read_mask,&write_mask,&except_mask,NULL);
	if(num>0){
		if(FD_ISSET(sr,&read_mask)){
			printf("Spines msg\n");
			memset(buff,0,MAX_LEN);
			ret = spines_recvfrom(sr,buff,MAX_LEN,0,NULL,0);
			if(ret==sizeof(signed_update_message)){
				mess=(signed_message *) buff;
				up = (update_message *)(mess+ 1);
    				rtu_mess_header = (signed_message *)(up+1);
    				rtu_data=(rtu_data_msg *) (rtu_mess_header+1);
				sf=(substation_fields *)rtu_data->data;
				printf("Message from ss=%d state=%d ts=%lu\n",sf->ss_id, sf->breaker_state,sf->dts);
				for(int i=0;i<3;i++){
				if(ss_ids[i]==sf->ss_id && cb_curr_dts[i]<sf->dts){
				  ret2= IPC_Send(mu_proxy_in, buff,ret,mu_proxy_ipc_path);
				  cb_curr_dts[i]=sf->dts;
				  }
				}
			
			
			}
		
		}//num>0 and ss event 
		else if(FD_ISSET(0,&read_mask)){
			for (i = 0; i < NUM_REPLICAS; i++) {
        			payload.delay_ms[i] = 0;
        			payload.trip[i] = 0;
			}

        		printf("> ");
        		fflush(stdout);
        		if (scanf("%19s", input) != 1) break;

        		if (input[0] == 's' || input[0] == 'b') {
            			if (input[0] == 's') {
                			if (scanf("%d", &trip) != 1)
                    				error_and_exit("Expected an int as argument\n", 1);

                		for (i = 0; i < NUM_REPLICAS; i++) {
                    			payload.delay_ms[i] = 0;
                    			payload.trip[i] = trip;
                		}

                		payload.type = SV_SIMPLE;
            		} else {
                		for (i = 0; i < NUM_REPLICAS; i++) {
                    			if (scanf("%lu", &payload.delay_ms[i]) != 1)
                        			error_and_exit("Expected a long as argument\n", 1);
                    			if (scanf("%d", &trip) != 1)
                        			error_and_exit("Expected an int as argument\n", 1);
                    			payload.trip[i] = trip;
                		}

                		payload.type = SV_BYZ;
            		}

    			for (i = 0; i < NUM_REPLICAS; i++) {
		    		Alarm(PRINT,"i=%d \tdelay=%lu, \ttrip=%d\n",i,payload.delay_ms[i],payload.trip[i]);
    			}
            		gettimeofday(&now, NULL);
            		payload.time_ms = now.tv_sec * 1000 + now.tv_usec / 1000;
	    		payload.ss_id=My_SS_ID;

            		ret = sendto(s, &payload, sizeof(payload), 0, (struct sockaddr *)&send_addr, sizeof(send_addr));

            		if (ret < 0)
                		error_and_exit("Mcast: sendto\n", 1);
            		printf("\nSimulator: Sent event\n");

			} else {
            		printf("Invalid input \n");
        		}//process stdin SV cmd	
		}//num>0 and stdin	
	
	}//num>0


    	
    }
    return 0;
}

void usage(int argc, char **argv) {
    if (argc < 2){
        Alarm(EXIT, "Usage: ./emulated_mu SS_ID\n");
	return;
    }
    
    sscanf(argv[1], "%d", &My_SS_ID);

    if (strcmp(argv[1], "-h") == 0) {
        printf("Commands:\n");
        printf("d <n> : Delay for <n> miliseconds\n");
        printf("s <t> : Send simple message with trip = <t>\n");
        printf("b (<n> <t>) * NUM_OF_RELAYS : Send a byzantine message. Input NUM_REPLICAS pairs of delay = <n> and trip = <t>\n");
    }
}

