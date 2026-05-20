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
#include "spu_alarm.h"
#include "spu_events.h"

#include "def.h"
#include "scada_packets.h"
#include "ss_net_wrapper.h"

int ipc_sock,My_SS_ID,hmi_send_sock;
char ipc_buff[MAX_LEN], mu_proxy_ipc_path[128];
struct sockaddr_in dest;
int relay_ss_port;

static void process_msg(int source, void *dummy);

int main(int argc, char *argv[])
{

  Alarm_enable_timestamp_high_res("%m/%d/%y %H:%M:%S");
  setlinebuf(stdout);
  Alarm_set_types(PRINT);
  Alarm_set_types(STATUS);
  Alarm_set_types(DEBUG);

  if(argc<2){
    Alarm(EXIT,"Usage: ./mu_proxy SS_ID\n");
  }
  sscanf(argv[1],"%d",&My_SS_ID);
  int ss_spines_ext_port=SS_SPINES_EXT_BASE_PORT+((My_SS_ID-16)*10);
  Load_SS_Conf(My_SS_ID);
  memset(mu_proxy_ipc_path,0,sizeof(mu_proxy_ipc_path));
  sprintf(mu_proxy_ipc_path,"%s%d",(char *)MU_IPC_OUT,My_SS_ID);
  /*IPC to receive from MU*/ 
  ipc_sock = IPC_DGram_Sock(mu_proxy_ipc_path);
  if(ipc_sock<0){
  	Alarm(EXIT,"Error setting up ipc sock");
  }else{
  	Alarm(PRINT,"Set up IPC - Done !\n");
  }
  /*Spines sock to send to SS  HMI*/
  char * addr=Breaker_Addr;
  Alarm(PRINT,"sp_addr=%s, port=%d\n",addr,ss_spines_ext_port);
  hmi_send_sock = Spines_SendOnly_Sock(addr,ss_spines_ext_port,SPINES_PRIORITY);
  if(hmi_send_sock<0){
    Alarm(EXIT,"hmi_sed_Sock error\n");
  }
  dest.sin_family= AF_INET;
  relay_ss_port=RELAY_SUBSTATION_BASE_PORT+((My_SS_ID-16)*10);
  dest.sin_port = htons(relay_ss_port);
  dest.sin_addr.s_addr = inet_addr(HMI_Addr);


  E_init();
  E_attach_fd(ipc_sock,READ_FD,process_msg,NULL,NULL,MEDIUM_PRIORITY);
  E_handle_events();

}

void process_msg(int source, void *dummy){
    signed_message *mess;
    update_message *up;
    signed_message *rtu_mess_header;
    rtu_data_msg *rtu_data;
    substation_fields *sf;
    int mess_len,sent_len;

    mess_len=0;
    sent_len=0;
    mess_len=IPC_Recv(ipc_sock,ipc_buff,MAX_LEN);

    if(mess_len==sizeof(signed_update_message)){
    	mess=(signed_message *) ipc_buff;
        up = (update_message *)(mess+ 1);
        rtu_mess_header = (signed_message *)(up+1);
        rtu_data=(rtu_data_msg *) (rtu_mess_header+1);
        sf=(substation_fields *)rtu_data->data;
        Alarm(PRINT,"Message from ss=%d state=%d ts=%lu\n",sf->ss_id, sf->breaker_state,sf->dts);
	sent_len=spines_sendto(hmi_send_sock,mess,sizeof(signed_update_message),0,(struct sockaddr *)&dest, sizeof(struct sockaddr));
	if(sent_len!=mess_len){
	  Alarm (PRINT, "error sending to HMI\n");
	}else{
	  Alarm(PRINT,"sent to HMI %s: %d\n",HMI_Addr,relay_ss_port);
	}
    
    }

}
