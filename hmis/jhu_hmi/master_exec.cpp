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
 * Johns Hopkins University.
 *
 * Creators:
 *   Yair Amir            yairamir@cs.jhu.edu
 *   Trevor Aron          taron1@cs.jhu.edu
 *   Amy Babay            babay@cs.jhu.edu
 *   Thomas Tantillo      tantillo@cs.jhu.edu
 *
 * Major Contributors:
 *   Marco Platania       Contributions to architecture design 
 *   Sahiti Bommareddy    Addition of IDS, Contributions to OpenSSL upgrade, latency optimization
 *
 * Contributors:
 *   Samuel Beckley       Contributions to HMIs
 *   Daniel Qian          Contributions to IDS
 *
 * Copyright (c) 2017-2020 Johns Hopkins University.
 * All rights reserved.
 *
 * Partial funding for Spire research was provided by the Defense Advanced 
 * Research Projects Agency (DARPA) and the Department of Defense (DoD).
 * Spire is not necessarily endorsed by DARPA or the DoD. 
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
}

void Process_Message(signed_message *);
DATA *d = NULL;

void Init_Master(DATA *dd) 
{
    d = dd;
}

int Read_From_Master(int s) 
{
    int ret; //, remaining_bytes; 
    char buf[MAX_LEN];
    //signed_message *mess;

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
