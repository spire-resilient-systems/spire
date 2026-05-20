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
/*
 * master_exec.c contains the implementation of the 
 * methods used for the execution of the SCADA 
 * master server.
 *
 * Creator: Marco
 * Created: 3/27/2015
 * Last modified: 4/20/2015
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <stdarg.h>
#include <netinet/in.h>
#include "master_exec.h"
#include <arpa/inet.h>

extern "C" {
    #include "scada_packets.h"
    #include "net_wrapper.h"
    #include "def.h"
    #include "openssl_rsa.h"
    #include "itrc.h"
    #include "spu_events.h"
    #include "spines_lib.h"
}

extern int ss_ext_spines;
extern int My_SS_Id;
extern char Relay_Ext_Addrs[NUM_REPLICAS][32];
void Process_Message(signed_message *);
void Clear_All_Buttons();
void Push_Buttons(int btype);
void Button_Event(int dummy1, void *dummy2);

void Read_From_Master(int s, int dummy1, void *dummy2) 
{
    int ret; 
    char buf[MAX_LEN];
    struct sockaddr_in from_addr;
    socklen_t from_len=sizeof(from_addr);

    UNUSED(dummy1);
    UNUSED(dummy2);

    ret = spines_recvfrom(ss_ext_spines, buf, MAX_LEN, 0, (struct sockaddr *) &from_addr, &from_len);
    if (ret < 0) {
	    printf("Read_From_Master: Spines_recvfrom failed\n");
    }
    printf("Read_From_Master: Spines_recvfrom size=%d\n",ret);
    Process_Message((signed_message *)buf);
}

void Process_Message(signed_message *mess) 
{
    int i, len, expected_size;
    struct timeval now, then, diff;
    update_message *up;
    signed_message *rtu_mess_header;
    rtu_data_msg *rtu_data;
    data_model *d;
    substation_fields *sf;

    up = (update_message *)(mess + 1);
    rtu_mess_header = (signed_message *)(up+1);
    rtu_data=(rtu_data_msg *) (rtu_mess_header+1);

    if (rtu_data->scen_type != INTEGRATED_CC) {
        printf("Process_Message: INVALID SCENARIO: %d\n", rtu_data->scen_type);
        return;
    }
    

    expected_size=sizeof(signed_update_message)-sizeof(signed_message);
    if (mess->len != expected_size) {
        printf("Process_Message: INVALID LENGTH: %d, expected %d\n", len, expected_size);
        return;
    }

    sf=(substation_fields *)rtu_data->data;

    d = &the_model;
    if(d == NULL) {
        printf("No browser connected\n");
        return;
    }

    printf("************************************Msg from SSID %d**********\n",sf->ss_id);
    if(sf->ss_id==SS1_PRIME_ID){//SS1
    if(sf->breaker_state==1){//trip
        if(d->br_read_arr[0].value==0){
    		printf("Received SUBSTATION HMI UPDATE MESSAGE state=%lu, ts= %lu\n",sf->breaker_state,sf->dts);
    		gettimeofday(&now, NULL);
    		printf("********CB TRIP Ack received at %u sec %u usec\n",now.tv_sec,now.tv_usec);
		Append_History("CB Status - Opened");
	}
        d->br_read_arr[0].value = 1;
        d->br_read_arr[1].value = 0;
	d->point_arr[0].value=1;
	d->point_arr[1].value=1;
	d->point_arr[2].value=1;
	d->point_arr[3].value=1;
    
    }else{//close
        if(d->br_read_arr[0].value==1){
    		printf("Received SUBSTATION HMI UPDATE MESSAGE state=%lu, ts= %lu\n",sf->breaker_state,sf->dts);
    		gettimeofday(&now, NULL);
    		printf("********CB CLOSE Ack received at %u sec %u usec\n",now.tv_sec,now.tv_usec);
		Append_History("CB Status - Closed");
	}
        d->br_read_arr[0].value = 0;
        d->br_read_arr[1].value = 1;
        //d->br_write_arr[1].value = 0;
	d->point_arr[0].value=0;
	d->point_arr[1].value=0;
	d->point_arr[2].value=0;
	d->point_arr[3].value=0;
    
    }
    }else if(sf->ss_id==SS2_PRIME_ID){//SS2
	    printf("SS2 status update state=%d,ts=%lu\n",sf->breaker_state,sf->dts);
	    Append_History("SS2 Update - %s",sf->breaker_state==0? "Close":"Open");
    
    } else if(sf->ss_id==SS3_PRIME_ID){//SS3
	    printf("SS3 status update state=%d,ts=%lu\n",sf->breaker_state,sf->dts);
	    Append_History("SS3 Update - %s",sf->breaker_state==0? "Close":"Open");
    }else{
         printf("Received from unexpected substation\n");
    }
    
}

void Execute_Script(int s, int dummy1, void *dummy2)
{

}

void Clear_All_Buttons()
{
    
}

void Push_Buttons(int btype)
{
   
}

void Button_Event(int dummy1, void *dummy2)
{
  }

void Append_History(const char *m, ...)
{

  va_list ap;

    struct tm *tm_info;
    struct timeval tv;
    int time_len;
    char buff[100];

    gettimeofday(&tv,NULL);
    tm_info=localtime(&tv.tv_sec);
    time_len=0;
    time_len+=(int) strftime(buff,sizeof(buff),"%H:%M:%S",tm_info);
    time_len+=snprintf(buff+time_len,sizeof(buff-time_len),".%03ld : ",tv.tv_usec/1000);

    va_start(ap, m);
    vsnprintf(buff + time_len, sizeof(buff) - time_len, m, ap);
    va_end(ap);

    //stdcarr_push_back(&Script_History, time_str);
    stdcarr_push_back(&Script_History, buff);
    Script_History_Seq++;

    if (stdcarr_size(&Script_History) > 25)
        stdcarr_pop_front_n(&Script_History, stdcarr_size(&Script_History) - 25);
}


void send_to_ss(signed_message *mess, int nBytes){
    int ret;
    struct sockaddr_in dest;
    //char * relay_addrs[NUM_REPLICAS]=SPINES_RELAY_EXT_ADDRS;
    //char relay_addrs[NUM_REPLICAS][32];
    signed_message *ss_mess;
    hmi_command_msg *hmi_command;
    update_message *up;
    hmi_command = (hmi_command_msg *)(mess+1);

    ss_mess= PKT_Construct_Signed_Message(sizeof(signed_update_message)-sizeof(signed_message));
    ss_mess->machine_id=Prime_Client_ID;
    ss_mess->len = sizeof(signed_update_message) - sizeof(signed_message);
    ss_mess->type = UPDATE;
    ss_mess->incarnation=hmi_command->seq.incarnation;

    up=(update_message *)(ss_mess+1);
    up->server_id=Prime_Client_ID;
    up->seq_num = hmi_command->seq.seq_num;
    memcpy((unsigned char*)(up+1),mess,nBytes);
    printf("Sending Update from Prime client id %d : [%u]\n", ss_mess->machine_id,up->seq_num);
    
     /* SIGN Message */
     OPENSSL_RSA_Sign( ((byte*)ss_mess) + SIGNATURE_SIZE,
                        sizeof(signed_message) + ss_mess->len - SIGNATURE_SIZE,
                        (byte*)ss_mess );

    for(int j=0;j<NUM_REPLICAS;j++){
        dest.sin_family = AF_INET;
        int relay_ss_port=RELAY_SUBSTATION_BASE_PORT+((My_SS_Id-16)*10);
	dest.sin_port = htons(relay_ss_port);
        dest.sin_addr.s_addr = inet_addr(Relay_Ext_Addrs[j]);
        ret = spines_sendto(ss_ext_spines,ss_mess,sizeof(signed_update_message),0,(struct sockaddr *)&dest, sizeof(struct sockaddr));
        if(ret!=sizeof(signed_update_message)){
            printf("Cannot send on ss_ext_spines\n");
           }else{
     printf("PROXY: Delivering msg to substation dissemination network to %s ret=%d\n",Relay_Ext_Addrs[j],ret);
     	}
     }
}
