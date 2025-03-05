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
#include <unistd.h>
#include <sys/time.h>
#include "master_exec.h"

extern "C" {
    #include "scada_packets.h"
    #include "net_wrapper.h"
    #include "def.h"
    #include "itrc.h"
    #include "openssl_rsa.h"
}

void Process_Message(signed_message *);
void Process_Config_Msg(signed_message * conf_mess,int mess_size);

DATA *d = NULL;

void Init_Master(DATA *dd) 
{
    d = dd;
}

void Process_Config_Msg(signed_message * conf_mess,int mess_size){
    config_message *c_mess;

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
    printf("Verified Config Message\n");
    if(conf_mess->global_configuration_number<=My_Global_Configuration_Number){
        printf("Got config=%u and I am already in %u config\n",conf_mess->global_configuration_number,My_Global_Configuration_Number);
        return;
    }
    My_Global_Configuration_Number=conf_mess->global_configuration_number;
//    My_curr_global_config_num = conf_mess->global_configuration_number;
    c_mess=(config_message *)(conf_mess+1);
    //Reset SM
    Reset_SM_def_vars(c_mess->N,c_mess->f,c_mess->k,c_mess->num_cc_replicas, c_mess->num_cc,c_mess->num_dc);
    Reset_SM_Replicas(c_mess->tpm_based_id,c_mess->replica_flag,c_mess->spines_ext_addresses,c_mess->spines_int_addresses);
    printf("Reconf done \n");
}


int Read_From_Master(int s) 
{
    int ret; //, remaining_bytes; 
    char buf[MAX_LEN];
    //signed_message *mess;
    signed_message *cmess;

    /* ret = TCP_Read(s, buf, sizeof(signed_message));
    if(ret <= 0) {
        perror("Reading error 1");
        close(s);
        exit(EXIT_FAILURE);
    }
  
    printf("Sucessfully read signed message\n");    
    mess = ((signed_message *)buf);
    remaining_bytes = (int)mess->len;
    printf("Remaining bytes: %d\n", remaining_bytes);
    
    ret = TCP_Read(s, &buf[sizeof(signed_message)], remaining_bytes);
    if(ret <= 0) {
        perror("Reading error 2");
        close(s);
        exit(EXIT_FAILURE);
    } */

    ret = IPC_Recv(s, buf, MAX_LEN);
    if (ret < 0) printf("Read_From_Master: IPC_Rev failed\n");
    //printf("MESS RECIEVED \n");
    cmess=(signed_message *)buf;
    if(cmess->type ==  PRIME_OOB_CONFIG_MSG){
        Process_Config_Msg((signed_message *)buf,ret);
        return ret;
    }
    Process_Message((signed_message *)buf);

    return ret;
}

void Process_Message(signed_message *mess) 
{
    char * stat_ptr;
    int len;
    int i;
    struct timeval now, then, diff;
    hmi_update_msg *hmi_up;

    hmi_up = (hmi_update_msg *)(mess + 1);

    if (hmi_up->scen_type != JHU) {
        printf("Process_Message: INVALID SCENARIO: %d\n", hmi_up->scen_type);
        return;
    }
        
    len = hmi_up->len;
    stat_ptr = (char *)(hmi_up + 1);

    gettimeofday(&now, NULL);
    then.tv_sec  = hmi_up->sec;
    then.tv_usec = hmi_up->usec;
    diff = diffTime(now, then);
    printf("NET time = %lu sec, %lu usec\n", diff.tv_sec, diff.tv_usec);

    if(d == NULL or d->status == NULL) {
        printf("No browser connected\n");
        return;
    }
    for(i = 0; i < len; i++) {
        d->status[i] = stat_ptr[i];
    }
}
