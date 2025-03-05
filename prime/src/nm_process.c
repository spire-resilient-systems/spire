/*
 * Prime.
 * 
 * The contents of this file are subject to the Prime Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.dsn.jhu.edu/prime/LICENSE.txt
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 * 
 * Software distributed under the License is distributed on an AS IS basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Creators:
 *   Yair Amir            yairamir@cs.jhu.edu
 *   Jonathan Kirsch      jak@cs.jhu.edu
 *   John Lane            johnlane@cs.jhu.edu
 *   Marco Platania       platania@cs.jhu.edu
 *   Amy Babay            babay@pitt.edu
 *   Thomas Tantillo      tantillo@cs.jhu.edu
 *
 * Major Contributors:
 *   Brian Coan           Design of the Prime algorithm
 *   Jeff Seibert         View Change protocol 
 *   Sahiti Bommareddy    Reconfiguration 
 *   Maher Khan           Reconfiguration
 *
 * Copyright (c) 2008-2025
 * The Johns Hopkins University.
 * All rights reserved.
 *
 * Partial funding for Prime research was provided by the Defense Advanced
 * Research Projects Agency (DARPA) and the National Science Foundation (NSF).
 * Prime is not necessarily endorsed by DARPA or the NSF.
 *
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "order.h"
#include "data_structs.h"
#include "process.h"
#include "network.h"
#include "utility.h"
#include "util_dll.h"
#include "def.h"
#include "process.h"
#include "pre_order.h"
#include "error_wrapper.h"
#include "signature.h"
#include "erasure.h"
#include "recon.h"
#include "suspect_leader.h"
#include "view_change.h"
#include "catchup.h"
#include "proactive_recovery.h"
#include "tc_wrapper.h"

#ifdef SET_USE_SPINES
#include "spines_lib.h"
#endif

#include "spu_alarm.h"
#include "spu_memory.h"
#include "spu_data_link.h"

/* Global variables */
extern server_variables   VAR;
extern network_variables  NET;
extern server_data_struct DATA;
extern benchmark_struct   BENCH;

int32u prev_inc;

void bypass_PR();
void process_oob_config(signed_message *mess);
void process_inband_config(signed_message *mess);
void write_to_file_server_addresses(nm_message *conf_msg_content);
void write_to_file_spines_addresses(nm_message *conf_msg_content);
void reset_server_addresses(nm_message *conf_msg_content);
void reset_spines_addresses(nm_message *conf_msg_content);
void Close_Existing_Network();
void NM_Send_Application_OOB_Update();

void Process_OOB_NM_MSG(signed_message *mess)
{
	

	//validate TS here
	if(mess->global_configuration_number<=DATA.NM.global_configuration_number){
		Alarm(PRINT,"Received NM Message with %u but my own global incarnation number is %u\n",mess->global_configuration_number,DATA.NM.global_configuration_number);
		return;
		}
    struct timeval now; 
    gettimeofday(&now,NULL);
    printf("**********Started processing  config msg at timestamp sec=%lu,usec=%lu \n",now.tv_sec,now.tv_usec);
    //Adapt global_configuration_number
    prev_inc = DATA.NM.global_configuration_number;
    DATA.NM.global_configuration_number=mess->global_configuration_number;
    process_oob_config(mess);
	
    
}

void process_oob_config(signed_message *mess)
{
    nm_message *conf_msg_content;
    int new_server_ID;
    char load_filename[100];

    Alarm(DEBUG,"My TPM ID is %d\n",VAR.My_Tpm_ID);
    conf_msg_content=(nm_message *)(mess+1);

    Alarm(DEBUG,"prev_config =%lu\n",prev_inc);

    /* I am not part of the new configuration */
    if (conf_msg_content->tpm_based_id[VAR.My_Tpm_ID-1] == 0){
        //TODO: We are only exiting now. We need to send kill message to scada master too.
        DATA.NM.PartOfConfig = 0;
        E_dequeue_all_time_events();
        Close_Existing_Network();
        return;
    }

    /* I am part of the new configuration */
    Alarm(DEBUG, "Part of config %lu\n",DATA.NM.global_configuration_number);
    DATA.NM.PartOfConfig = 1;
    DATA.NM.OOB_Reconfig_Inprogress = 1;
    Close_Existing_Network();
    
    /* Dequeue all timed events */
    E_dequeue_all_time_events();

    /* reset all data structures same order as in DAT_Initialize */
    PR_Clear_Reset_Data_Structures();
    ORDER_Upon_Reset();
    PRE_ORDER_Upon_Reset();
    SIG_Upon_Reset();
    SUSPECT_Upon_Reset();
    RB_Upon_Reset();
    VIEW_Upon_Reset();
    CATCH_Upon_Reset();
    Alarm(STATUS,"Reset all DS - PR, PRE_ORDER, ORDER,SIG, SUSPECT, RB, VIEW, CATCH\n");

    /* Set up new configuration parameters */
    DATA.NM.global_configuration_number = mess->global_configuration_number;
    conf_msg_content = (nm_message *)(mess+1);
    VAR.F = conf_msg_content->f;
    VAR.K = conf_msg_content->k;
    VAR.Num_Servers = conf_msg_content->N;

    if(VAR.Num_Servers < (3*VAR.F + 2*VAR.K + 1)) {
        Alarm(PRINT, "Configuration error: NUM_SERVERS is less than 3f+2k+1\n");
        exit(0);
    }
    
    new_server_ID = conf_msg_content->tpm_based_id[VAR.My_Tpm_ID-1];
    VAR.My_Server_ID = new_server_ID;
    Alarm(PRINT, "My new server ID is %d\n",VAR.My_Server_ID);

        
    /* Update Server addresses */
    reset_server_addresses(conf_msg_content);
    Alarm(DEBUG,"Reset server address done\n");

#ifdef SET_USE_SPINES
    printf("Update Spines addresses\n");
    reset_spines_addresses(conf_msg_content);
#endif

    Alarm(DEBUG, "Finished changing server and spine addresses new N= %d, my id= %d , new f=%d\n",VAR.Num_Servers,VAR.My_Server_ID,VAR.F);

    //TODO: Replace to read keys from different dir
    OPENSSL_RSA_Read_Keys(VAR.My_Server_ID, RSA_SERVER,"/tmp/test_keys/prime");
    TC_Read_Public_Key("/tmp/test_keys/prime");
    TC_Read_Partial_Key(VAR.My_Server_ID, 1,"/tmp/test_keys/prime");
    Alarm(DEBUG, "Finished reading keys.\n");

    //Update NET. all 3 addr
    sprintf(load_filename,"./%d_address_%d.config",VAR.My_Tpm_ID,DATA.NM.global_configuration_number);
    Load_Addrs_From_File(load_filename,NET.server_address);    
    sprintf(load_filename,"./%d_spines_address_%d.config",VAR.My_Tpm_ID,DATA.NM.global_configuration_number);
    UTIL_Load_Spines_Addresses(load_filename);

    //Checked with Amy
    DAT_Reinitialize();

    //reconnect
    Reconfig_Reset_Network();
    NM_Send_Application_OOB_Update();

    /*New Incarnation*/
    if (prev_inc==0){ 
        DATA.PR.new_incarnation[VAR.My_Server_ID] = PR_Construct_New_Incarnation_Message();
    	/* Multicast my new_incarnation message */
    	SIG_Add_To_Pending_Messages(DATA.PR.new_incarnation[VAR.My_Server_ID], BROADCAST,UTIL_Get_Timeliness(NEW_INCARNATION));
    }else{
        bypass_PR();
        PR_Resume_Normal_Operation();
	}

    struct timeval now; 
    gettimeofday(&now,NULL);
    printf("**********Done processing  config msg at timestamp sec=%lu,usec=%lu \n",now.tv_sec,now.tv_usec);
}

void bypass_PR(){
    
    po_seq_pair ps;
    int replica;

    ps.incarnation = DATA.NM.global_configuration_number;
    ps.seq_num = 0;
    
    for(replica=1;replica<=VAR.Num_Servers;replica ++){
	 /* Update the preinstalled incarnations */
    	DATA.PR.preinstalled_incarnations[replica] = DATA.NM.global_configuration_number;
    	DATA.PR.installed_incarnations[replica] = DATA.NM.global_configuration_number;
    	//DATA.PR.new_incarnation[replica] = DATA.NM.global_configuration_number;
    	DATA.PR.new_incarnation_val[replica] = DATA.NM.global_configuration_number;
    	DATA.PR.last_recovery_time[replica] = DATA.NM.global_configuration_number;
	/* Update the preordering data structures for the recovering replica */
    	DATA.PO.max_acked[replica] = ps;
    	DATA.PO.aru[replica] = ps;
	DATA.PO.po_seq=ps;
	/*No catchup */
	/* PO Acks, ARUs and Prepares and OCMMIts will be empty*/
    	DATA.PR.recovery_status[replica] = PR_NORMAL;
    	//DATA.PR.recovery_status[replica] = PR_RECOVERY;
	}
}



void process_inband_config(signed_message * mess){}

void write_to_file_server_addresses(nm_message *conf_msg_content){
    char filename[100];
    sprintf(filename,"../bin/%d_address_%d.config",VAR.My_Tpm_ID,DATA.NM.global_configuration_number);
    FILE *f=fopen(filename,"w");
    if (f==NULL)
        Alarm(EXIT, "Error opening server addresses config file\n");
    
    for(int id=1;id<=conf_msg_content->N;id++){
        for(int i=0;i<MAX_NUM_SERVER_SLOTS;i++){
                if(conf_msg_content->tpm_based_id[i]==id){
                    char line[125];
                    sprintf(line, "%d %s\n",id,conf_msg_content->prime_addresses[i]);
                    fputs(line,f);
                }
                }
        }
        fclose(f);
        Alarm(PRINT, "Finished writing server addresses.\n");
        fflush(stdout);
        //sleep(1);
}

void write_to_file_spines_addresses(nm_message *conf_msg_content){
    #ifdef SET_USE_SPINES
    char filename[100];
    sprintf(filename,"../bin/%d_spines_address_%d.config",VAR.My_Tpm_ID,DATA.NM.global_configuration_number);

    FILE *f = fopen(filename,"w");
    if (f == NULL)
        Alarm(EXIT, "Error opening spines addresses config file\n");
    
    for (int id=1;id<=conf_msg_content->N;id++)
    {
        for(int i=0;i<MAX_NUM_SERVER_SLOTS;i++)
        {
                if(conf_msg_content->tpm_based_id[i]==id){
                    char line[125];
                    sprintf(line, "%d %s\n",id,conf_msg_content->spines_int_addresses[i]);
                    fputs(line,f);
                }
        }
    }
    fclose(f);
    Alarm(PRINT, "Finished writing spines addresses.\n");
    fflush(stdout);
    //sleep(1);
    #endif
}


void reset_spines_addresses(nm_message *conf_msg_content)
{
    int32u server;

    /* Reset data structure with 0s */
    for (server = 0; server < MAX_NUM_SERVER_SLOTS; server++) {
        NET.spines_daemon_address[server] = 0;
    }

    write_to_file_spines_addresses(conf_msg_content);
}


void reset_server_addresses(nm_message *conf_msg_content)
{
    int server;

    /* Reset data structure with 0s */
    for (server = 0; server < MAX_NUM_SERVER_SLOTS; server++)
    {
        NET.server_address[server] = 0;
    }
   
    write_to_file_server_addresses(conf_msg_content);
}


void Close_Existing_Network()
{
#if USE_IPC_CLIENT
    //int ret;
    //struct sockaddr_un conn;
#endif

    //Close and detach the following
#if USE_IPC_CLIENT
    /* 
    E_detach_fd(NET.from_client_sd,READ_FD);
    ret=close(NET.from_client_sd);
    if(ret!=0)
        Alarm(EXIT,"Error closing NET.from_client_sd\n");
    memset(&conn, 0, sizeof(struct sockaddr_un));
    conn.sun_family = AF_UNIX;
    sprintf(conn.sun_path, "%s%d", (char *)REPLICA_IPC_PATH, VAR.My_Tpm_ID);
    if (remove(conn.sun_path) == -1 && errno != ENOENT) {
      perror("Network Cleanup- removing previous path binding on replica IPC path");
      exit(EXIT_FAILURE);
    }
    Alarm(PRINT,"Cleaned up NET.from_client_sd\n");
    */
    //NET.to_client_sd
    /* 
    ret=close(NET.to_client_sd);
    if(ret!=0)
        Alarm(EXIT,"Error closing NET.to_client_sd\n");
    memset(&conn, 0, sizeof(struct sockaddr_un));
    conn.sun_family = AF_UNIX;
    sprintf(conn.sun_path, "%s%d", (char *)CLIENT_IPC_PATH, VAR.My_Tpm_ID);
    if (remove(conn.sun_path) == -1 && errno != ENOENT) {
      perror("Network Cleanup- removing previous path binding on client IPC path");
      exit(EXIT_FAILURE);
    }
    Alarm(PRINT,"Cleaned up NET.to_client_sd\n");
    */
#endif

#if !USE_IPC_CLIENT
    //NET.listen_sd
    Alarm(PRINT,"About to clean NET.listen_sd\n");
    E_detach_fd(NET.listen_sd,READ_FD);
    close(NET.listen_sd);
    NET.listen_sd=0;
    Alarm(PRINT,"Cleaned up NET.listen_sd\n");
#endif

    //NET.Bounded_channel , NET.Timely_Channel, NET.Recon_Channel DL_Init??
    if(NET.Bounded_Channel){
    	Alarm(PRINT,"About to clean NET.Bounded_Channel\n");
    	E_detach_fd(NET.Bounded_Channel, READ_FD);
    	DL_close_channel(NET.Bounded_Channel);
    	NET.Bounded_Channel=0;
        Alarm(DEBUG,"Cleaned up NET.Bounded_Channel\n");
	}

    if(NET.Timely_Channel){
    	Alarm(PRINT,"About to clean NET.Timely_Channel\n");
    	E_detach_fd(NET.Timely_Channel, READ_FD);
    	DL_close_channel(NET.Timely_Channel);
        NET.Timely_Channel=0;
        Alarm(DEBUG,"Cleaned up Timely_Channel\n");
	}

    if(NET.Recon_Channel){
    	Alarm(PRINT,"About to clean NET.Recon_Channel\n");
    	E_detach_fd(NET.Recon_Channel, READ_FD);
    	DL_close_channel(NET.Recon_Channel);
        NET.Recon_Channel=0;
        Alarm(DEBUG,"Cleaned up Recon_Channel\n");
	}

    if(USE_IP_MULTICAST) {
#if  !SET_USE_SPINES
        if(NET.Bounded_Mcast_Channel){
            DL_close_channel(NET.Bounded_Mcast_Channel);
            NET.Bounded_Mcast_Channel=0;
        }
        if(NET.Timely_Mcast_Channel){
            DL_close_channel(NET.Timely_Mcast_Channel);
            NET.Timely_Mcast_Channel=0;
        }
        Alarm(DEBUG,"Cleaned up NET.Bounded_Mcast_Channel, Timely_Mcast_Channel\n");
#endif
    }

#if SET_USE_SPINES
    //NET.Spines_Channel, NET.spines_mcast_addr - E_detach
    if(NET.Spines_Channel){
    	Alarm(DEBUG,"About to clean NET.Spines_Channel\n");
    	E_detach_fd(NET.Spines_Channel,READ_FD);
    	spines_close(NET.Spines_Channel);
    	NET.Spines_Channel = 0;
    	Alarm(DEBUG,"Cleaned up NET.Spines_Channel\n");
	}
#endif
}


void NM_Send_Application_OOB_Update()
{
    signed_update_message reset, *up;
    signed_message *event, *up_contents;

    memset(&reset, 0, sizeof(signed_update_message));
    event = (signed_message *)&reset;
    up = (signed_update_message *)&reset;
    up_contents = (signed_message *)(up->update_contents);

    event->machine_id = VAR.My_Server_ID;
    event->type = UPDATE;
    event->incarnation = DATA.PR.new_incarnation_val[VAR.My_Server_ID];
    event->len = sizeof(signed_update_message) - sizeof(signed_message);

    up->update.server_id = VAR.My_Server_ID;
    up->header.incarnation = DATA.PO.intro_client_seq[VAR.My_Server_ID].incarnation;
    up->update.seq_num = 0;

    up_contents->machine_id = VAR.My_Server_ID;
    //up_contents->type = CLIENT_SYSTEM_RESET;
    up_contents->type = CLIENT_SYSTEM_RECONF;
    Alarm(PRINT,"MS2022: RECONF_SYSTEM_RESET\n");
    ORDER_Execute_Event(event, 0, 1, 1);
}
