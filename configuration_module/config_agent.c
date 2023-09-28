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
 * Copyright (c) 2017-2023 Johns Hopkins University.
 * All rights reserved.
 *
 * Partial funding for Spire research was provided by the Defense Advanced
 * Research Projects Agency (DARPA), the Department of Defense (DoD), and the
 * Department of Energy (DoE).
 * Spire is not necessarily endorsed by DARPA, the DoD or the DoE.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <assert.h>
#include <signal.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <errno.h>
#include <arpa/inet.h>
#include <signal.h>

#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_memory.h"
#include "spu_data_link.h"
#include "spines_lib.h"

#include "../common/scada_packets.h"
#include "../common/openssl_rsa.h"
#include "../common/net_wrapper.h"
#include "../common/def.h"

int ctrl_spines,config_ipc_inject;
int SM_Flag, BMcount,ProxiesCount,HMI_flag;
int sm_node_ids[MAX_NUM_SERVER_SLOTS];
int needed_keys_ids[MAX_NUM_SERVER_SLOTS];
sp_time timeout;
signed_message *mess;
char sm_addr[32];
struct sockaddr_in name;
struct ip_mreq mreq;
int32u curr_config;
int total_key_frags,recvd_key_frags_count;
int recvd_key_frags[10];
signed_message * curr_config_msg;
char *key;
int send_config;
int My_ID,counter;
signed_message *key_messages[10];

void Usage(int argc, char **argv);
void Init_Network();
void full_decrypt(int decrypt_id,int32u key_parts,int32u key_part_size,int32u unenc_size,char *enc_key, char *dec_key);
void send_to_sm(int code, void *dummy);
void repeat_broadcast(int code, void *dummy);
void write_to_file(int32u key_type, int32u key_id,int32u key_size,char *currkey);
void Handle_Config_Msg(int s, int source, void * dummy_p);




void full_decrypt(int decrypt_id,int32u key_parts,int32u key_part_size,int32u unenc_size,char *enc_key, char *dec_key){
    char dec_filename[250];
    char pvtkeyfilename[250];
    char *dec_chunk;
    dec_chunk=malloc(key_part_size);
    int i;

    memset(pvtkeyfilename,0,sizeof(pvtkeyfilename));
    sprintf(pvtkeyfilename,"../prime/bin/tpm_keys/tpm_private%d.pem",decrypt_id);
    Alarm(DEBUG,"Pvt decryption key file is %s\n",pvtkeyfilename);
    for(i =0; i< key_parts; i++){
        memset(dec_chunk,0,key_part_size);
        OPENSSL_RSA_Decrypt(pvtkeyfilename,enc_key,key_part_size,dec_chunk);
        if(unenc_size>=key_part_size){
	    memcpy(dec_key,dec_chunk,key_part_size);
	    //memcpy(dec_key,enc_key,key_part_size);
            dec_key+=key_part_size;
        }
        else{
	    memcpy(dec_key,dec_chunk,unenc_size);
	    //memcpy(dec_key,enc_key,unenc_size);
            dec_key+=unenc_size;
        }
        enc_key+=key_part_size;
        if(unenc_size>=key_part_size)
            unenc_size-=key_part_size;
        else
            unenc_size-=unenc_size;
    Alarm(DEBUG,"remaining key len=%lu\n",unenc_size);
    }
}


void send_to_sm(int code, void *dummy){
    char ipc_config[100];
    int ret2,i,repeat;

    if(!send_config){
        Alarm(DEBUG,  "Not sending as send_config flag is not set\n");
	return;
	}
    repeat =0;
    if (send_config){
        if(SM_Flag){
		for(i=1;i<MAX_NUM_SERVER_SLOTS;i++){
			if(sm_node_ids[i]==0)
			      continue;
                	sprintf(ipc_config, "%s%d", (char *)SM_IPC_MAIN, i);
                	//sprintf(ipc_config, "%s%d", (char *)CONFIG_AGENT, i);
                	ret2=IPC_Send(config_ipc_inject,curr_config_msg,sizeof(signed_message)+sizeof(config_message), ipc_config);
                	if (ret2!=sizeof(curr_config_msg)){
                    		Alarm(PRINT, "Config Agent: Error sending to %s\n",ipc_config);
				repeat=1;
			}
                	Alarm(DEBUG,"Sent to %s mesage of size%d\n",ipc_config,ret2);
		}
            }
            if(BMcount>0){
                for(int Curr_ID=1;Curr_ID<=BMcount;Curr_ID++){
                    sprintf(ipc_config, "%s%d", (char *)BM_IPC_MAIN, Curr_ID);
                    ret2=IPC_Send(config_ipc_inject,curr_config_msg,sizeof(signed_message)+sizeof(config_message),ipc_config);
                    if (ret2!=sizeof(curr_config_msg)){
                        Alarm(PRINT, "Config Agent: Error sending to Benchmark\n");
			repeat=1;
			}
                    Alarm(DEBUG,"Sent to %s\n",ipc_config);
                }
            }
            if(ProxiesCount>0){
                for(int Curr_ID=1;Curr_ID<=ProxiesCount;Curr_ID++){
                    sprintf(config_ipc_inject, "%s%d", (char *)RTU_IPC_MAIN, Curr_ID);
                    ret2=IPC_Send(ipc_config,curr_config_msg,sizeof(signed_message)+sizeof(config_message), ipc_config);
                    if (ret2!=sizeof(curr_config_msg)){
                        Alarm(PRINT, "Config Agent: Error sending to Proxy\n");
			repeat=1;
			}
                Alarm(DEBUG,"Sent to %s\n",ipc_config);
                }
            }
            if(HMI_flag>0){
                sprintf(ipc_config, "%s%d", (char *)HMI_IPC_MAIN, HMI_flag);
                ret2=IPC_Send(config_ipc_inject,curr_config_msg,sizeof(signed_message)+sizeof(config_message), ipc_config);
                if (ret2!=sizeof(curr_config_msg)){
                    Alarm(PRINT, "Config Agent: Error sending to Proxy\n");
		    repeat=1;
		}
                Alarm(DEBUG,"Sent to %s\n",ipc_config);
            }
        //TODO: Fool proof : Run if not running and if running repeat if not delivered
        if(!repeat)
            send_config=0;
        Alarm(DEBUG,"Handled Config Msg\n");
    }
}

void repeat_broadcast(int code, void *dummy){
    int ret=0;
    int Num_bytes=0;
    struct sockaddr_in dest;
    struct hostent     h_ent;
    int i;
    sp_time timeout;

    memcpy(&h_ent, gethostbyname(CTRL_SPINES_MCAST_IP), sizeof(h_ent));
    memcpy( &dest.sin_addr, h_ent.h_addr, sizeof(dest.sin_addr) );

    dest.sin_family = AF_INET;
    dest.sin_port   = htons(CTRL_SPINES_MCAST_PORT);

    Num_bytes=sizeof(signed_message)+curr_config_msg->len;
    ret = spines_sendto(ctrl_spines, curr_config_msg, Num_bytes, 0, (struct sockaddr *)&dest, sizeof(struct sockaddr));
    if(ret!=Num_bytes){
        Alarm(PRINT,"Config Agent: Spines sendto ret != message size\n");
	return;
    }
    for(i =0 ; i < 10;i++){
	if(key_messages[i]==NULL)
		continue;
        Num_bytes=sizeof(signed_message)+key_messages[i]->len;

        ret = spines_sendto(ctrl_spines, key_messages[i], Num_bytes, 0, (struct sockaddr *)&dest, sizeof(struct sockaddr));
        if(ret!=Num_bytes){
            Alarm(PRINT,"Config Agen: Spines sendto ret != keys message size\n");
	    return;
        }
        Alarm(DEBUG,"****Config Agent: sent key message %d bytes to dest addr=%s\n",Num_bytes,inet_ntoa(dest.sin_addr));
    }
    timeout.sec=10;
    timeout.usec=0;
    E_queue(repeat_broadcast,0,NULL,timeout);

}

void write_to_file(int32u key_type, int32u key_id,int32u key_size,char *currkey){
    char filename[250],dirname[250];
    FILE *fp;
    int ret;
    struct stat st = {0};

    Alarm(DEBUG,"Write to file\n");
    memset(filename,0,sizeof(filename));
    memset(dirname,0,sizeof(dirname));
    //VCreate dir of format MyID_test_keys
    sprintf(dirname,"%s","/tmp/test_keys");
    if (stat(dirname, &st) == -1) {
        ret=mkdir(dirname, 0755);
        if(ret<0)
            Alarm(PRINT,"Error creating %s\n",dirname);
    }
    
    //Create dir of format MyID_test_keys/sm or  MyID_test_keys/prime
    memset(dirname,0,sizeof(dirname));
    if(key_type==SM_TC_PUB){
        sprintf(dirname,"%s","/tmp/test_keys/sm");
        if (stat(dirname, &st) == -1) {
            ret=mkdir(dirname, 0755);
            if(ret<0)
                Alarm(PRINT,"Error creating %s\n",dirname);
        }
        sprintf(&filename,"%s/%s",dirname,"pubkey_1.pem");
        }
    if(key_type==PRIME_TC_PUB){
        sprintf(dirname,"%s","/tmp/test_keys/prime");
        if (stat(dirname, &st) == -1) {
            ret=mkdir(dirname, 0755);
            if(ret<0)
                Alarm(PRINT,"Error creating %s\n",dirname);
        }
        sprintf(&filename,"%s/%s",dirname,"pubkey_1.pem");
        }
   if(key_type==PRIME_RSA_PUB){
        sprintf(dirname,"%s","/tmp/test_keys/prime");
        if (stat(dirname, &st) == -1) {
            ret=mkdir(dirname, 0755);
            if(ret<0)
                Alarm(PRINT,"Error creating %s\n",dirname);
        }
        sprintf(&filename,"%s/public_%02d.key",dirname,key_id);
        }
    if(key_type==SM_TC_PVT){
        sprintf(dirname,"%s","/tmp/test_keys/sm");
        if (stat(dirname, &st) == -1) {
            ret=mkdir(dirname, 0755);
            if(ret<0)
                Alarm(PRINT,"Error creating %s\n",dirname);
        }
        sprintf(&filename,"%s/share%d_1.pem",dirname,key_id);
        }
    if(key_type==PRIME_TC_PVT){
        sprintf(dirname,"%s","/tmp/test_keys/prime");
        if (stat(dirname, &st) == -1) {
            ret=mkdir(dirname, 0755);
            if(ret<0)
                Alarm(PRINT,"Error creating %s\n",dirname);
        }
        sprintf(&filename,"%s/share%d_1.pem",dirname,key_id);
        }

    if(key_type==PRIME_RSA_PVT){
        sprintf(dirname,"%s","/tmp/test_keys/prime");
        if (stat(dirname, &st) == -1) {
            ret=mkdir(dirname, 0755);
            if(ret<0)
                Alarm(PRINT,"Error creating %s\n",dirname);
        }
        sprintf(&filename,"%s/private_%02d.key",dirname,key_id);
        }

    Alarm(DEBUG,"filename is %s\n",filename); 
    fp = fopen(filename,"w");
    if(!fp){
        Alarm(PRINT, "Error opening file %s\n",filename);
    }
    else{
        Alarm(PRINT, "Opened file %s\n",filename);
    }
    ret=fwrite(currkey, 1,key_size,fp);
    
    if(ret!=key_size)
        Alarm(PRINT,"Error writing to %s\n",filename);
    
    fclose(fp);

}


int main(int argc, char **argv)
{
    setlinebuf(stdout);
    Alarm_set_types(PRINT|STATUS|DEBUG|EVENTS);
    Usage(argc,argv);
    OPENSSL_RSA_Init();
    OPENSSL_RSA_Read_Keys(0,RSA_CONFIG_AGENT,SM_PRIME_KEYS);
    Init_Network();
     
    E_init();
    E_attach_fd(ctrl_spines, READ_FD, Handle_Config_Msg,NULL,NULL,HIGH_PRIORITY);
    E_handle_events();
    
}//main


void Handle_Config_Msg(int s, int source, void * dummy_p){
    int ret,ret2,dec_key_id,id,i;
    byte buff[50000];
    struct sockaddr_in from_addr;
    socklen_t from_len=sizeof(from_addr);
    signed_message *mess;
    config_message *c_mess;

    ret=spines_recvfrom(ctrl_spines, buff, 50000, 0, (struct sockaddr *) &from_addr, &from_len);
    if(ret>0){
        Alarm(DEBUG, "Config Agent %d: Received spines message of size=%d\n",counter,ret);
        if (ret < sizeof(signed_message)){
            Alarm(PRINT,"Config Agent: Config Message size smaller than signed message\n");
            return;
        }
        mess = (signed_message*)buff;
        
        if (ret < (sizeof(signed_message)+mess->len)){
            Alarm(PRINT,"Config Agent: Config Message size smaller than expected\n");
            return;
        }
        /*
	if (from_addr.sin_addr.s_addr != inet_addr(SPINES_HMI_ADDR)) {
            Alarm(PRINT, "Config Agent: Message is not from Config Manager Address\n");
            return;
        }
        */
        if(mess->type!=PRIME_OOB_CONFIG_MSG && mess->type!=CONFIG_KEYS_MSG){
            Alarm(PRINT,"Config Agent: Message type is not config message\n");
            return;
        }
        if(!OPENSSL_RSA_Verify((unsigned char*)mess+SIGNATURE_SIZE,
                    sizeof(signed_message)+mess->len-SIGNATURE_SIZE,
                    (unsigned char*)mess,mess->machine_id,RSA_CONFIG_MNGR)){
            Alarm(PRINT,"Config Agent: Config message signature verification failed\n");

            return;
        }
        Alarm(DEBUG,"Verified Config Message\n");
        if(mess->type == PRIME_OOB_CONFIG_MSG){
            counter+=1;
            if(mess->global_configuration_number<=curr_config)
                return;
            curr_config = mess->global_configuration_number;
            c_mess=(config_message *)(mess+1);
    	    memset(needed_keys_ids,0,sizeof(needed_keys_ids));
            
	    for (id=1;id<=MAX_NUM_SERVER_SLOTS;id++){
		if(sm_node_ids[id]==1){
		     if(c_mess->tpm_based_id[id-1]!=0){
			needed_keys_ids[c_mess->tpm_based_id[id-1]]=1;	
			}	
		    }
		}
	    //free old keys and to save new keys when we get them
	    if(total_key_frags>0){
		for (i=0;i<10;i++){
			if(key_messages[i]!=NULL)
				free(key_messages[i]);
			key_messages[i]=NULL;
		}
	    }
            //store config message for SM and repeat
	    total_key_frags= c_mess->frag_num;
            recvd_key_frags_count = 0;
            memset(recvd_key_frags,0,sizeof(recvd_key_frags));
            memcpy(curr_config_msg, mess, ret);
    	    counter=0; 
        }
        else if(mess->type ==CONFIG_KEYS_MSG){
        if(mess->global_configuration_number!=curr_config ){
            Alarm(DEBUG, "Keys conf=%lu but expected conf=%lu\n",mess->global_configuration_number,curr_config);
            return;
        }
        if(total_key_frags>0 && recvd_key_frags_count==total_key_frags){
            Alarm(DEBUG, "Already have all Keys\n");
            return;
        }
	
        Alarm(DEBUG,"mess_conf=%lu, curr_conf=%lu, total_key_frags=%d,recvd_key_frags_count=%d\n",mess->global_configuration_number,curr_config,total_key_frags,recvd_key_frags_count);
	 key_msg_header *km_header;
         km_header=(key_msg_header *)(mess+1);

         pvt_key_header *pvt_header;
         pub_key_header *pub_header;
         if(recvd_key_frags[km_header->frag_idx]==1)
             return;
	 //save keys for repeat
         key_messages[km_header->frag_idx-1]=malloc(ret);
	 memset(key_messages[km_header->frag_idx-1],0,ret);
	 memcpy(key_messages[km_header->frag_idx-1],mess,ret);

	 recvd_key_frags[km_header->frag_idx] =1;
         recvd_key_frags_count+=1;
         int curr_idx =0;
         int max_idx=mess->len - sizeof(key_msg_header);
         char *key_buff=malloc(max_idx);
         memset(key_buff,0,max_idx);
         memcpy(key_buff,km_header+1,max_idx);
         while(curr_idx<max_idx){
            int32u type=key_buff[curr_idx];
            if(type==SM_TC_PUB || type == PRIME_TC_PUB || type == PRIME_RSA_PUB){
                Alarm(DEBUG,"key_type=%d curr_idx=%d\t",type,curr_idx);
                pub_header = (pub_key_header *)&(key_buff[curr_idx]);
                curr_idx+=sizeof(pub_key_header);
                Alarm(DEBUG,"tyep=%lu, id=%lu, size=%lu\n",pub_header->key_type, pub_header->id,pub_header->size);
                write_to_file(pub_header->key_type, pub_header->id,pub_header->size,pub_header+1);
                curr_idx+= pub_header->size;
            }
            else if(type==SM_TC_PVT || type == PRIME_TC_PVT || type == PRIME_RSA_PVT){
                pvt_header = (pvt_key_header *)&(key_buff[curr_idx]);
                if(SM_Flag==0){
                    curr_idx+=sizeof(pvt_key_header);
                    curr_idx+= pvt_header->pvt_key_parts*pvt_header->pvt_key_part_size;
                    continue;
		}
		if(type==SM_TC_PVT || type == PRIME_TC_PVT){
                    if(needed_keys_ids[pvt_header->id +1 ]!= 1){
                        curr_idx+=sizeof(pvt_key_header);
                        curr_idx+= pvt_header->pvt_key_parts*pvt_header->pvt_key_part_size;
                        continue;
                    }else{
			dec_key_id=pvt_header->id +1;	
		    }
                }
                if(type == PRIME_RSA_PVT){
                    if(needed_keys_ids[pvt_header->id] != 1){
                        curr_idx+=sizeof(pvt_key_header);
                        curr_idx+= pvt_header->pvt_key_parts*pvt_header->pvt_key_part_size;
                        continue;
                    }else{
		    	dec_key_id=pvt_header->id;
			}
                }
                curr_idx+=sizeof(pvt_key_header);
                char *curr_dec_key;
                curr_dec_key=malloc(pvt_header->unenc_size);
                full_decrypt(dec_key_id,pvt_header->pvt_key_parts,pvt_header->pvt_key_part_size,pvt_header->unenc_size,pvt_header+1,curr_dec_key);
                write_to_file(pvt_header->key_type,pvt_header->id,pvt_header->unenc_size,curr_dec_key);
                free(curr_dec_key);
                curr_idx+= pvt_header->pvt_key_parts*pvt_header->pvt_key_part_size;
            
            }
            else{
                Alarm(DEBUG,"Unexpected key type %d\n",type);
            }
         }
         if(recvd_key_frags_count==total_key_frags){
               Alarm(DEBUG,"set send_config flag\n");
		send_config =1;
	}
         if(send_config){
		sp_time timeout;
		timeout.sec=1;
		timeout.usec=0;
             	E_queue(send_to_sm,0,NULL,timeout);
		timeout.sec=10;
		timeout.usec=0;
             	E_queue(repeat_broadcast,0,NULL,timeout);
		}
    }
    else{
        Alarm(DEBUG, "mess type %d on ctrl spines - not expected\n",mess->type);
    }
    //if(send_config)
        //send_to_sm();

    } //ret>0 on ctrl spines
}

void Init_Network()
{
    char *ctrl_spines_addr=sm_addr;

    ctrl_spines=Spines_Sock(ctrl_spines_addr, SPINES_CTRL_PORT, SPINES_PRIORITY,CTRL_BASE_PORT+My_ID);
    if (ctrl_spines < 0 ) {
        Alarm(EXIT, "Config Angent: Error setting up control spines network, exiting\n");
    }
    
    Alarm(PRINT, "Config Agent: Connected to control spines\n");
   /* 
   name.sin_family = AF_INET;
    name.sin_addr.s_addr = htonl(INADDR_ANY);
    name.sin_port = htons(CTRL_SPINES_MCAST_PORT);
    if(spines_bind(ctrl_spines, (struct sockaddr *)&name, sizeof(name) ) < 0) {
      Alarm(EXIT,"Config Agent: bind error \n");
    }
   */
   mreq.imr_multiaddr.s_addr = inet_addr(CTRL_SPINES_MCAST_IP);
   mreq.imr_interface.s_addr = htonl(INADDR_ANY);

   if(spines_setsockopt(ctrl_spines, IPPROTO_IP, SPINES_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq)) < 0) {
        Alarm(EXIT,"Mcast: problem in setsockopt to join multicast address");
      }
    Alarm(PRINT, "Mcast setup done\n");
    config_ipc_inject=IPC_DGram_SendOnly_Sock();
       if(config_ipc_inject<0)
            Alarm(EXIT, "Config Agent: failed to set up IPC to inject config message\n");

       Alarm(PRINT, "Config Agent: Set up IPC to inject config message\n");

}


void Usage(int argc, char **argv)
{
    int i,id,id_loc,sm_node_count;
    counter=0; 
    if(argc <5) {
        printf("Usage for Scada Master node: config_agent id MyCtrlSpineAddr s Count sm_id1 sm_id2 .... sm_idN\n"
		"Usage for Benchmarks Node: config_agent id MyCtrlSpineAddr b Count\n"
		"Usage for Proxies node: config_agent id MyCtrlSpineAddr p Count\n"
		"Usage for HMI nnode: config_agent id MyCtrlSpineAddr h 1 hmi_id\n"
		"Note: id is just for control agent, it is unique 1...N");
        exit(EXIT_FAILURE);
    }

    curr_config = 0;
    total_key_frags = 0;
    send_config = 0;
    SM_Flag = 0;
    BMcount = 0;
    ProxiesCount = 0;
    HMI_flag = 0;
    memset(sm_node_ids,0,sizeof(sm_node_ids));
    memset(needed_keys_ids,0,sizeof(needed_keys_ids));
    curr_config_msg = PKT_Construct_Signed_Message(sizeof(config_message));
    sscanf(argv[1],"%d",&My_ID);
    sprintf(sm_addr, "%s", argv[2]);
    printf("sm_addr=%s\n",sm_addr);
    printf("type=%c\n",*argv[3]);
    for (i=0;i<10;i++){
	key_messages[i]=NULL;
	}
    if(*argv[3]=='s'){
	Alarm(DEBUG,"Config agent is running on Scada Master node\n");
	SM_Flag =1;
        sscanf(argv[4],"%d",&sm_node_count);
	assert(sm_node_count>0 && sm_node_count< MAX_NUM_SERVER_SLOTS);
	Alarm(PRINT,"I run %d SMs",sm_node_count);
	id_loc=5;	
        for(i=1;i<=sm_node_count;i++){
	    sscanf(argv[id_loc],"%d",&id);
	    id_loc+=1;
	    sm_node_ids[id]=1;
	    Alarm(PRINT,"My node runs sm_id =%d\n",id);
	}
    }else if(*argv[3]=='b'){
    	sscanf(argv[4], "%d", &BMcount);
	Alarm(PRINT,"Benchmarks count=%d\n",BMcount);
    }else if(*argv[3]=='p'){
        sscanf(argv[4], "%d", &ProxiesCount);
    }else if(*argv[3]=='h'){
        sscanf(argv[5], "%d", &HMI_flag);
    }else{
   	Alarm(EXIT,"Unknown node type %c\n",*argv[3]); 
	}
}


