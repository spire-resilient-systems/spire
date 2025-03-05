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

#include "packets.h"
#include "openssl_rsa.h"
#include "net_wrapper.h"
#include "def.h"
#include "data_structs.h"
#include "tc_wrapper.h"

#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_memory.h"
#include "spu_data_link.h"
#include "spines_lib.h"

#define KEY_PAYLOAD_MAXSIZE 40000 

int counter;
char conf_dir[100];
char key_buff[KEY_PAYLOAD_MAXSIZE];
int ctrl_spines;
int32u curr_idx;
sp_time timeout;
signed_message *mess;
sp_time repeat_timeout;
struct sockaddr_in dest;
struct hostent     h_ent;
static int ttl;
int total_key_frags;
int32u new_global_conf_num;
signed_message *key_messages[10];
extern server_variables    VAR;

void Usage(int argc, char **argv);
void Init_CM_Network();
void generate_keys(int curr_n, int curr_f, int curr_k, char * base_dir);
void construct_keys_messages(int curr_server_count,char *based_dir); 
void new_broadcast_configuration_message(int code, void *dummy);
void repeat_broadcast_configuration_message(int code, void *dummy);
void test_encrypt_decrypt();

void construct_key_message();
void read_pub_key(const char * filename,int type,int id);
void read_pvt_key(const char * filename,int type,int id);

void generate_keys(int curr_n, int curr_f, int curr_k, char * base_dir){

    char sm_keys_dir[100];
    char prime_keys_dir[100];
    struct stat st = {0};
    int ret;

    memset(sm_keys_dir,0,sizeof(sm_keys_dir));
    memset(prime_keys_dir,0,sizeof(prime_keys_dir));

    sprintf(sm_keys_dir,"./%s/keys",base_dir);
    sprintf(prime_keys_dir,"./%s/prime_keys",base_dir);
    
    if (stat(sm_keys_dir, &st) == -1) {
        ret=mkdir(sm_keys_dir, 0755);
        if(ret<0)
            Alarm(PRINT,"Error creating %s\n",sm_keys_dir);
	}
    if (stat(prime_keys_dir, &st) == -1) {
        ret=mkdir(prime_keys_dir, 0755);
        if(ret<0)
            Alarm(PRINT,"Error creating %s\n",prime_keys_dir);
    }


    TC_with_args_Generate(curr_f+1,sm_keys_dir,curr_f,curr_k,1);
    TC_with_args_Generate(curr_f+1,prime_keys_dir,curr_f,curr_k,1);
    OPENSSL_RSA_Generate_Keys_with_args(curr_n, prime_keys_dir );
    

}
void construct_key_message(){
    signed_message *pkt_header;
    key_msg_header *km_header;
    char * new_keys; 
        
    Alarm(DEBUG,"construct_key_message called for total_key_frags=%d\n",total_key_frags);
    key_messages[total_key_frags] = (signed_message *) malloc(sizeof(signed_message)+sizeof(key_msg_header)+(curr_idx*sizeof(char)));
    
    //Fill main header
    pkt_header = key_messages[total_key_frags];
    memset(pkt_header,0,sizeof(signed_message)+sizeof(key_msg_header)+(curr_idx*sizeof(char)));
    pkt_header->machine_id = 0;
    pkt_header->len = sizeof(key_msg_header)+curr_idx;
    pkt_header->global_configuration_number=new_global_conf_num;
    pkt_header->type=CONFIG_KEYS_MSG;

    //Fill key header
    km_header = (key_msg_header *)(pkt_header +1);
    km_header->frag_idx = total_key_frags+1;
    //Copy keys
    new_keys=(char*)(km_header+1);
    memcpy(new_keys,key_buff, curr_idx*sizeof(char));
    //sign
    OPENSSL_RSA_Sign( ((byte*)pkt_header) + SIGNATURE_SIZE, sizeof(signed_message) + pkt_header->len - SIGNATURE_SIZE, (byte*)pkt_header);
    
    
    //empty key_buff
    memset(key_buff,0,KEY_PAYLOAD_MAXSIZE);
    curr_idx = 0;
    //inc total_key_frags
    total_key_frags +=1;
    Alarm(DEBUG,"Post construct_key_message now total_key_frags=%d\n",total_key_frags);
}


void read_pub_key(const char * filename, int type, int id){
    FILE *fp;
    int keysize = 0;
    pub_key_header *pub_header;
    
    fp=fopen(filename,"r");
    if(!fp){
        Alarm(EXIT,"Error opening %s\n",filename);
    }
    keysize=getFileSize(filename);
    Alarm(DEBUG, "%s keysize=%d\n",filename,keysize);
    if(curr_idx+sizeof(pub_key_header)+keysize >= KEY_PAYLOAD_MAXSIZE){
        //Full
        Alarm(DEBUG,"One key payload ready*****\n");
        //create new msg and store
        construct_key_message();
        fflush(stdout);
    }
    pub_header = (pub_key_header *)&key_buff[curr_idx];
    pub_header->id= id;
    pub_header->key_type = type;
    pub_header->size=keysize;
    curr_idx+=sizeof(pub_key_header);
    fread(&key_buff[curr_idx], keysize,1,fp);
    fclose(fp);
    curr_idx += keysize;
    Alarm(PRINT,"after pubkey curr_idx=%d, header=%d, keysize=%d\n",curr_idx,sizeof(pub_key_header),keysize);
}

void read_pvt_key(const char * filename,int type, int id){
    FILE *fp;
    char enc_key_filename[250];
    int keysize,enc_key_size,key_parts,ret,rem_data_len = 0;
    pvt_key_header *pvt_header;
    char *enc_buff;
    char *data_buff;
    //Get enc key size, pvt key and cal parts to enc 
    memset(enc_key_filename,0,sizeof(enc_key_filename));
    if (type==PRIME_RSA_PVT){
    	sprintf(enc_key_filename,"./tpm_keys/tpm_public%d.pem",id);
    }
    if(type==SM_TC_PVT || type == PRIME_TC_PVT){
	sprintf(enc_key_filename,"./tpm_keys/tpm_public%d.pem",id+1);
    }
    enc_key_size = OPENSSL_RSA_Get_KeySize(enc_key_filename);
    enc_buff= malloc(enc_key_size);
    data_buff= malloc(enc_key_size);
    fp=fopen(filename,"r");
    if(!fp){
        Alarm(EXIT,"Error opening %s\n",filename);
    }
    keysize=getFileSize(filename);
    Alarm(DEBUG, "%s keysize=%d\n",filename,keysize);
    rem_data_len=keysize;
    key_parts = (int) keysize / enc_key_size ;
    if(keysize % enc_key_size >0)
        key_parts+=1;
    
    //Alarm(DEBUG, "%s keysize=%d, enc_key_size=%d, parts=%d\n",filename,keysize,enc_key_size,key_parts);
      
    //Make sure adding next key will not exceed desired packet size. If full handle
    if(curr_idx+sizeof(pvt_key_header)+(key_parts*enc_key_size) >= KEY_PAYLOAD_MAXSIZE){
    //Full
        Alarm(DEBUG,"One key payload ready\n");
        //create new msg and store
        construct_key_message();
	fflush(stdout);
    }
    //Construct pvt_key_header
    pvt_header = (pvt_key_header *)&key_buff[curr_idx];
    pvt_header->key_type = type;
    pvt_header->id= id;
    pvt_header->unenc_size= keysize;
    pvt_header->pvt_key_parts=key_parts;
    pvt_header->pvt_key_part_size=enc_key_size;
    curr_idx+=sizeof(pvt_key_header);
   /* 
    fread(&key_buff[curr_idx], keysize,1,fp);
   */
    int data_len=0;
    //Fill encrypted key chunks after header
    for(int j=0; j<key_parts;j++){
        memset(enc_buff,0,enc_key_size);
        memset(data_buff,0,enc_key_size);
        //read from file in chunks
        //Alarm(DEBUG,"About to read from file rem_data_len=%d\n",rem_data_len);
        if (rem_data_len >= enc_key_size){
            ret=fread(data_buff,enc_key_size,1,fp);
            rem_data_len-=enc_key_size;
	    data_len=enc_key_size;
        }
        else{
            ret=fread(data_buff,rem_data_len,1,fp);
	    data_len=rem_data_len;;
            rem_data_len-=rem_data_len;
        }
        //Alarm(DEBUG,"Read from file chunck =%d , rem_data_len=%d\n",ret,rem_data_len);
        //encrypt the chunk and write
        //OPENSSL_RSA_Encrypt(enc_key_filename,data_buff,data_len,enc_buff);
        OPENSSL_RSA_Encrypt(enc_key_filename,data_buff,enc_key_size,enc_buff);
        memcpy(&key_buff[curr_idx],enc_buff,enc_key_size);
        //memcpy(&key_buff[curr_idx],data_buff,enc_key_size);
        //inc curr_idx
        curr_idx+=enc_key_size;
    }
    
    fclose(fp);
    Alarm(PRINT,"after %s pvtkey curr_idx=%d, header=%d, keysize=%d\n",filename,curr_idx,sizeof(pvt_key_header),key_parts*enc_key_size);
    
}

void construct_keys_messages(int curr_server_count,char *base_dir){
    char filename[100];

    //sm_tc_pub
    memset(filename,0,sizeof(filename));
    sprintf(filename, "./%s/keys/pubkey_1.pem",base_dir);
    Alarm(PRINT,"start before sm_tc_pub curr_idx=%d\n",curr_idx);
    read_pub_key(filename, SM_TC_PUB,1);
    //prime_tc_pub
    memset(filename,0,sizeof(filename));
    sprintf(filename, "./%s/prime_keys/pubkey_1.pem",base_dir);
    Alarm(PRINT,"start before prime_tc_pub curr_idx=%d\n",curr_idx);
    read_pub_key(filename, PRIME_TC_PUB,1);
    //prime_rsa_pub
    for(int i=1; i<= curr_server_count;i++){
    	Alarm(PRINT,"start before prime_rsa_pub curr_idx=%d\n",i);
        memset(filename,0,sizeof(filename));
        sprintf(filename, "./%s/prime_keys/public_%02d.key",base_dir,i);
        read_pub_key(filename, PRIME_RSA_PUB,i);
    } 
    //sm_tc_shares
    for(int i=0; i < curr_server_count;i++){
    	Alarm(PRINT,"start before sm_tc_shares curr_idx=%d\n",i);
        memset(filename,0,sizeof(filename));
        sprintf(filename, "./%s/keys/share%d_1.pem",base_dir,i);
        read_pvt_key(filename,SM_TC_PVT,i);
    }
    //prime_tc_shares
    for(int i=0; i < curr_server_count;i++){
    	Alarm(PRINT,"start before prime_tc_shares curr_idx=%d\n",i);
        memset(filename,0,sizeof(filename));
        sprintf(filename, "./%s/prime_keys/share%d_1.pem",base_dir,i);
        read_pvt_key(filename,PRIME_TC_PVT,i);
    }
    //prime_rsa_pvt
    for(int i=1; i <= curr_server_count;i++){
    	Alarm(PRINT,"start before prime_rsa_pvt curr_idx=%d\n",i);
        memset(filename,0,sizeof(filename));
        sprintf(filename, "./%s/prime_keys/private_%02d.key",base_dir,i);
        read_pvt_key(filename,PRIME_RSA_PVT,i);
    }
} 

 

int main(int argc, char **argv)
{
    setlinebuf(stdout);
    Alarm_set_types(PRINT);
    //Alarm_set_types(STATUS|DEBUG);
    Usage(argc,argv);
    OPENSSL_RSA_Init();
    OPENSSL_RSA_Read_Keys(0,RSA_CONFIG_MNGR,"./keys");
    Init_CM_Network();
    repeat_timeout.sec=1;
    repeat_timeout.usec=0;
    E_init();
    E_queue(new_broadcast_configuration_message,NULL,NULL,repeat_timeout);
    E_handle_events(); 


}


void Usage(int argc, char**argv){
    ctrl_spines=-1;
    ttl=255;
    counter=0;
    VAR.Num_Servers= (3*NUM_F) + (2*NUM_K) + 1;
    if(argc <2){
	printf("Usage: %s configuration_dir_path\n",argv[0]);
	exit(EXIT_FAILURE);
	}
     memset(conf_dir,0,100);
     sprintf(conf_dir,"%s",argv[1]);

}
void Init_CM_Network()
{
    ctrl_spines=Spines_Mcast_SendOnly_Sock(CONF_MNGR_ADDR, CONFIGUATION_SPINES_PORT, SPINES_PRIORITY);

    if (ctrl_spines < 0 ) {
    /* TODO try reconnecting? */
        Alarm(EXIT, "Error setting up control spines network, exiting\n");
    }
    
    memcpy(&h_ent, gethostbyname(CONF_SPINES_MCAST_ADDR), sizeof(h_ent));
    memcpy( &dest.sin_addr, h_ent.h_addr, sizeof(dest.sin_addr) );
    
    dest.sin_family = AF_INET;
    dest.sin_port   = htons(CONF_SPINES_MCAST_PORT);
    if(spines_setsockopt(ctrl_spines, 0, SPINES_IP_MULTICAST_TTL, &ttl, sizeof(ttl)) != 0) {
        Alarm(EXIT, "Spines setsockopt error\n");
      }
    Alarm(PRINT,"MCAST set up done\n");
    

}



void new_broadcast_configuration_message(int code, void *dummy)
{
    
    nm_message *conf_msg;
    char filename[200];
    int ret,i;
    FILE * fp1;
    FILE * fp2;
    char * line = NULL;
    char * line2 = NULL;
    size_t len = 0;
    ssize_t read;
    char seps[]   = " ";
    char *token;
    char *prev_token;
    sp_time now;
    
    total_key_frags =0;
    memset(key_buff,0,KEY_PAYLOAD_MAXSIZE);
    curr_idx=0;

    Alarm(DEBUG,"New Config Msg\n");
    
    mess=(signed_message *)malloc(sizeof(signed_message) + sizeof(nm_message));
    memset(mess, 0, sizeof(signed_message) + sizeof(nm_message)); 
    //signed mess header
    mess->machine_id = 0;
    mess->len = sizeof(nm_message);
    mess->type = CLIENT_OOB_CONFIG_MSG;
    now=E_get_time();
    //Fill new conf number
    new_global_conf_num=now.sec;
    mess->global_configuration_number=now.sec;
    //Fill config_message by reading config defines from conf_dir/conf_def.txt
    conf_msg=(nm_message *)(mess+1);
    memset(filename,0,sizeof(filename));
    sprintf(filename,"./%s/conf_def.txt",conf_dir);
    fp1 = fopen(filename, "r");
    if (!fp1){
        printf("Error opening %s\n",filename);
	exit(1);
	}

    while ((read = getline(&line, &len, fp1)) != -1) {
        Alarm(DEBUG,"read line is : %s", line);
        prev_token=NULL;
        token = strtok( line, seps );
        while( token != NULL )
        {
            /* While there are tokens in "string" */
            //printf( " %s\n", token );
            if(prev_token && (strcmp(prev_token,"N")==0)){
                conf_msg->N=atoi(token);
                Alarm(DEBUG,"New N=%u\n",conf_msg->N);
            }
            if(prev_token && (strcmp(prev_token,"f")==0))
                conf_msg->f=atoi(token);
            if(prev_token && (strcmp(prev_token,"k")==0))
                conf_msg->k=atoi(token);
            if(prev_token && (strcmp(prev_token,"s")==0))
                conf_msg->num_sites=atoi(token);
            if(prev_token && (strcmp(prev_token,"c")==0))
                conf_msg->num_cc=atoi(token);
            if(prev_token && (strcmp(prev_token,"d")==0))
                conf_msg->num_dc=atoi(token);
            if(prev_token && (strcmp(prev_token,"cr")==0))
                conf_msg->num_cc_replicas=atoi(token);
            if(prev_token && (strcmp(prev_token,"dr")==0))
                conf_msg->num_dc_replicas=atoi(token);
            /* Get next token: */
            prev_token=token;
            token = strtok( NULL, seps );
        }
    }
    fclose(fp1);
    if (line)
        free(line);
    Alarm(DEBUG,"N=%u, f=%u, k=%u, s=%u\n",conf_msg->N,conf_msg->f,conf_msg->k,conf_msg->num_sites); 
    //Generate new conf keys
    generate_keys(conf_msg->N, conf_msg->f, conf_msg->k, conf_dir);
    /*Compose seperate conf_key_messages, sign and store them for repeat broadcast*/ 
   
    /* We will construct config_keys messages and fill the fragments count into config_message*/ 
    construct_keys_messages(conf_msg->N,conf_dir); 
    if(curr_idx>0){
	Alarm(DEBUG,"After key constructs , key+buff has content\n");
        construct_key_message(); 
    } 
	
    conf_msg->frag_num = total_key_frags; 
    /*We will fill in IPs and Ports of config_message by reading from conf_dir/new_conf.txt file*/
    memset(filename,0,200);
    sprintf(filename,"./%s/new_conf.txt",conf_dir);
    Alarm(DEBUG,"Opening %s\n",filename);
    //fp1 = fopen("new_conf.txt", "r");
    fp1 = fopen(filename, "r");
    if (fp1 == NULL){
        Alarm(EXIT,"error opening new_conf file \n");
	fflush(stdout);
	}
   len=0;
    while ((read = getline(&line2, &len, fp1)) != -1) {
        //printf("***read=%lu, %s", read, line2);
        const char* t_id = strtok(line2, " ");
        int tpm_id_curr=atoi(t_id);
        const char* l_id = strtok(NULL, " ");
        int local_id_curr=atoi(l_id);
        const char* m_name = strtok(NULL, " ");
        const char* sp_ext_ip = strtok(NULL, " ");
        const char* sp_int_ip = strtok(NULL, " ");
        const char* sm_ip = strtok(NULL, " ");
        const char* prime_ip = strtok(NULL, " ");
        const char* flag = strtok(NULL, " ");
        int dc_cc_flag=atoi(flag);

        conf_msg->tpm_based_id[tpm_id_curr-1]=local_id_curr;
        conf_msg->replica_flag[tpm_id_curr-1]=dc_cc_flag;
        sprintf(conf_msg->sm_addresses[tpm_id_curr-1],"%s",sm_ip);
        sprintf(conf_msg->spines_ext_addresses[tpm_id_curr-1],"%s",sp_ext_ip);
        sprintf(conf_msg->spines_int_addresses[tpm_id_curr-1],"%s",sp_int_ip);
        sprintf(conf_msg->prime_addresses[tpm_id_curr-1],"%s",prime_ip);
        Alarm(PRINT, "t_id=%d , l_id=%d, sm_ip=%s\n",tpm_id_curr-1,conf_msg->tpm_based_id[tpm_id_curr-1],conf_msg->spines_ext_addresses[tpm_id_curr-1]);
    }
    conf_msg->spines_ext_port=SPINES_EXT_PORT;
    conf_msg->spines_ext_port=SPINES_PORT;
    fclose(fp1);
    if (line2){
        Alarm(DEBUG,"Free line2\n");
	fflush(stdout);
	free(line2);
	}
     Alarm(DEBUG, "Composed Configuration Message of len=%u\n",mess->len);
     fflush(stdout);
    //Sign message
    OPENSSL_RSA_Sign( ((byte*)mess) + SIGNATURE_SIZE, sizeof(signed_message) + mess->len - SIGNATURE_SIZE, (byte*)mess );
    
    
    Alarm(DEBUG, "Composed Configuration Message of len=%u\n",mess->len);
    fflush(stdout);
    counter=0;
    repeat_broadcast_configuration_message(0, NULL);
}

void repeat_broadcast_configuration_message(int code, void *dummy)
{
    int ret=0;
    int Num_bytes=0;

    //broadcast on ctrl spines config_message
 
    Num_bytes=sizeof(signed_message)+mess->len;
    ret = spines_sendto(ctrl_spines, mess, Num_bytes, 0, (struct sockaddr *)&dest, sizeof(struct sockaddr)); 
    if(ret!=Num_bytes){
        Alarm(EXIT,"Control manager: Spines sendto ret != message size\n");
    }
    Alarm(DEBUG,"$$$$Config Manager %d: sent conf message %d bytes to dest addr=%s\n",counter,Num_bytes,inet_ntoa(dest.sin_addr));
    //broadcast on ctrl spines key_messages
    
    for(int i =0 ; i < total_key_frags;i++){
        Num_bytes=sizeof(signed_message)+key_messages[i]->len;

        ret = spines_sendto(ctrl_spines, key_messages[i], Num_bytes, 0, (struct sockaddr *)&dest, sizeof(struct sockaddr)); 
        if(ret!=Num_bytes){
            Alarm(EXIT,"****Control manager: Spines sendto ret != keys message size\n");
        }
        Alarm(DEBUG,"****Config Manager %d: sent key message %d bytes to dest addr=%s\n",counter,Num_bytes,inet_ntoa(dest.sin_addr));
    }
    counter+=1;
    
    
    E_queue(repeat_broadcast_configuration_message,0,NULL,repeat_timeout);
}
