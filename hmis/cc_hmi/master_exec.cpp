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
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <stdarg.h>
#include "master_exec.h"

extern "C" {
    #include "scada_packets.h"
    #include "net_wrapper.h"
    #include "def.h"
    #include "itrc.h"
    #include "spu_events.h"
    #include "openssl_rsa.h"
}

void Process_CC_Message(signed_message *);
void Process_Message(signed_message *);
void Clear_All_Buttons();
void Push_Buttons(int btype);
void Button_Event(int dummy1, void *dummy2);
void Process_Config_Msg(signed_message * conf_mess,int mess_size);

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


void Read_From_Master(int s, int dummy1, void *dummy2) 
{
    int ret; 
    char buf[MAX_LEN];
    signed_message *cmess;
    hmi_update_msg *hmi_up;

    UNUSED(dummy1);
    UNUSED(dummy2);

    ret = IPC_Recv(s, buf, MAX_LEN);
    if (ret < 0) printf("Read_From_Master: IPC_Rev failed\n");
    cmess=(signed_message *)buf; 
    if(cmess->type ==  PRIME_OOB_CONFIG_MSG){
        Process_Config_Msg((signed_message *)buf,ret);
        return;
    }
    hmi_up = (hmi_update_msg *)(cmess + 1);
    if(hmi_up->scen_type==PNNL){
    Process_Message((signed_message *)buf);
    }else if (hmi_up->scen_type==INTEGRATED_CC){
     Process_CC_Message((signed_message *)buf);
        }
    else{
    printf("Invalid Scenario Type=%d\n",hmi_up->scen_type);

        }
}

void Process_CC_Message(signed_message *mess)
{
    int i, len, expected_size;
    struct timeval now, then, diff;
    hmi_update_msg *hmi_up;
    data_model *d;
    substation_fields *sf;

    hmi_up = (hmi_update_msg *)(mess + 1);

    if (hmi_up->scen_type != INTEGRATED_CC) {
        printf("Process_Message: INVALID SCENARIO: %d\n", hmi_up->scen_type);
        return;
    }

    len = hmi_up->len;
    expected_size=sizeof(substation_fields);
    if (len != expected_size) {
        printf("Process_Message: INVALID LENGTH: %d, expected %d\n", len, expected_size);
        return;
    }

    sf=(substation_fields *)(hmi_up+1);
    printf("Received SUBSTATION (machine id %d) HMI UPDATE MESSAGE state=%lu, ts= %lu\n",sf->ss_id,sf->breaker_state,sf->dts);

    d = &the_model;
    if(d == NULL) {
        printf("No browser connected\n");
        return;
    }
     if(sf->ss_id==48){//SS1
    if(sf->breaker_state==1){//trip
	if(d->ss_read_arr[0].value==0){
	   Append_SS_History("SS1 CB Status-Opened");
	}
        printf("Set status of SS1 to trip\n");
        d->ss_read_arr[0].value = 1;
        d->ss_read_arr[1].value = 0;
        d->ss_arr[0].value=0;
        d->load_dial_arr[0].value=0;

    }//trip
    else{//close
	if(d->ss_read_arr[0].value==1){
	   Append_SS_History("SS1 CB Status-Closed");
	}
        printf("Set status of SS1 to close\n");
        d->ss_read_arr[0].value = 0;
        d->ss_read_arr[1].value = 1;
                }//close
    }//SS1
   if(sf->ss_id==49){//SS2
    if(sf->breaker_state==1){//trip
	if(d->ss_read_arr[2].value==0){
	   Append_SS_History("SS2 CB Status-Opened");
	}
        printf("Set status of SS2 to trip\n");
        d->ss_read_arr[2].value = 1;
        d->ss_read_arr[3].value = 0;
        d->ss_arr[0].value=0;
        d->ss_arr[1].value=0;
        d->load_dial_arr[0].value=0;
        d->load_dial_arr[1].value=0;

    }//trip
    else{//close
	if(d->ss_read_arr[2].value==1){
	   Append_SS_History("SS2 CB Status-Closed");
	}
        printf("Set status of SS2 to close\n");
        d->ss_read_arr[2].value = 0;
        d->ss_read_arr[3].value = 1;
                }//close
    }//SS2
   if(sf->ss_id==50){//SS3
    if(sf->breaker_state==1){//trip
	if(d->ss_read_arr[4].value==0){
	   Append_SS_History("SS3 CB Status-Opened");
	}
        printf("Set status of SS3 to trip\n");
        d->ss_read_arr[4].value = 1;
        d->ss_read_arr[5].value = 0;
        d->ss_arr[1].value=0;
        d->ss_arr[2].value=0;
        d->load_dial_arr[1].value=0;
        d->load_dial_arr[2].value=0;

    }//trip
    else{//close
	if(d->ss_read_arr[4].value==1){
	   Append_SS_History("SS3 CB Status-Closed");
	}
        printf("Set status of SS3 to close\n");
        d->ss_read_arr[4].value = 0;
        d->ss_read_arr[5].value = 1;
                }//close
    }//SS3

   if((d->ss_read_arr[0].value==0 && d->ss_read_arr[1].value==1)&&(d->ss_read_arr[2].value==0 && d->ss_read_arr[3].value==1)){
        d->ss_arr[0].value=75;
        d->load_dial_arr[0].value=75;
   }//l1=75 if ss1 and ss2 are closed

   if((d->ss_read_arr[2].value==0 && d->ss_read_arr[3].value==1)&&(d->ss_read_arr[4].value==0 && d->ss_read_arr[5].value==1)){
        d->ss_arr[1].value=50;
        d->load_dial_arr[1].value=50;
   }//l2=50 if ss3 and ss2 are closed
   if((d->ss_read_arr[4].value==0 && d->ss_read_arr[5].value==1)){
        d->ss_arr[2].value=50;
        d->load_dial_arr[2].value=50;
   }////l3=50 if ss3 is closed

}


void Process_Message(signed_message *mess) 
{
    int32u *s_arr;
    char *r_arr, *w_arr;
    int i, len, expected_size;
    struct timeval now, then, diff;
    hmi_update_msg *hmi_up;
    data_model *d;
    
    

    hmi_up = (hmi_update_msg *)(mess + 1);

    if (hmi_up->scen_type != PNNL) {
        printf("Process_Message: INVALID SCENARIO: %d\n", hmi_up->scen_type);
        return;
    }
    
    len = hmi_up->len;
    expected_size = (sizeof(int32u) * NUM_POINT) + (2 * NUM_BREAKER * sizeof(char));
    if (len != expected_size) {
        printf("Process_Message: INVALID LENGTH: %d, expected %d\n", len, expected_size);
        return;
    }

    s_arr = (int32u *)(hmi_up + 1);
    r_arr = (char *)(s_arr + NUM_POINT);
    w_arr = (char *)(r_arr + NUM_BREAKER);

    gettimeofday(&now, NULL);
    then.tv_sec  = hmi_up->sec;
    then.tv_usec = hmi_up->usec;
    diff = diffTime(now, then);
    printf("NET time = %lu sec, %lu usec\n", diff.tv_sec, diff.tv_usec);

    d = &the_model;
    if(d == NULL) {
        printf("No browser connected\n");
        return;
    }

    for(i = 0; i < NUM_POINT; i++) {
        d->point_arr[i].value = s_arr[i];
    }
    for (i = 0; i < NUM_BREAKER; i++) {
        d->br_read_arr[i].value = r_arr[i];
        d->br_write_arr[i].value = w_arr[i];
    }
}

void Execute_Script(int s, int dummy1, void *dummy2)
{
    char buf[1024];
    int ret;
    sp_time zero_t = {0, 0};

    UNUSED(dummy1);
    UNUSED(dummy2);

    while ( (ret = read(s, buf, sizeof(buf))) > 0);
    if ( ret != -1 || (errno != EAGAIN && errno != EINTR))
        printf("read error\n"), exit(EXIT_FAILURE);

    printf("Script_Button_Pushed = %d\n", Script_Button_Pushed);
    switch(Script_Button_Pushed) {

        case RESTART_SCRIPT:
            Script_Running = 1;
            Clear_All_Buttons();
            usleep(min_wait.tv_sec*1000000 + min_wait.tv_usec);
            Push_Buttons(BR_CLOSE);
            usleep(min_wait.tv_sec*1000000 + min_wait.tv_usec);
            Clear_All_Buttons();
            Script_Breaker_Index = 0;
            Script_Breaker_Val = BREAKER_ON;
            E_queue(Button_Event, 0, NULL, zero_t);
            break;

        case PAUSE_SCRIPT:
            if (E_in_queue(Button_Event, 0, NULL))
                E_dequeue(Button_Event, 0, NULL);
            Clear_All_Buttons();
            Script_Running = 0;
            break;

        case CONTINUE_SCRIPT:
            Script_Running = 1;
            Clear_All_Buttons();
            E_queue(Button_Event, 0, NULL, zero_t);
            break;

        default:
            break;        
    }

    Script_Button_Pushed = NO_BUTTON;
}

void Clear_All_Buttons()
{
    signed_message *mess;
    seq_pair ps;
    int nbytes, i;

    for(i = 0; i < NUM_BREAKER; i++) {
      ps.incarnation = My_Incarnation;
      ps.seq_num = Seq_Num;
      mess = PKT_Construct_HMI_Command_Msg(ps, MAX_EMU_RTU + My_ID, PNNL, BREAKER_OFF, i);
      mess->global_configuration_number=My_Global_Configuration_Number;
      nbytes = sizeof(signed_message) + mess->len;
      Seq_Num++;
      IPC_Send(ipc_sock, (void *)mess, nbytes, itrc_in.ipc_remote);
      free(mess);
    }
}

void Push_Buttons(int btype)
{
    data_model *d = &the_model;
    signed_message *mess;
    seq_pair ps;
    int nbytes, i;

    for(i = 0; i < NUM_BREAKER; i++) {
      if (d->br_write_arr[i].type != btype)
        continue;
        
      ps.incarnation = My_Incarnation;
      ps.seq_num = Seq_Num;
      mess = PKT_Construct_HMI_Command_Msg(ps, MAX_EMU_RTU + My_ID, PNNL, BREAKER_ON, i);
      mess->global_configuration_number=My_Global_Configuration_Number;
      nbytes = sizeof(signed_message) + mess->len;
      Seq_Num++;
      IPC_Send(ipc_sock, (void *)mess, nbytes, itrc_in.ipc_remote);
      free(mess);
    }
}

void Button_Event(int dummy1, void *dummy2)
{
    data_model *d = &the_model;
    signed_message *mess;
    seq_pair ps;
    int nbytes, val;
    sp_time t;

    UNUSED(dummy1);
    UNUSED(dummy2);

    ps.incarnation = My_Incarnation;
    ps.seq_num = Seq_Num;
    mess = PKT_Construct_HMI_Command_Msg(ps, MAX_EMU_RTU + My_ID, PNNL, Script_Breaker_Val, Script_Breaker_Index);
    mess->global_configuration_number=My_Global_Configuration_Number;
    nbytes = sizeof(signed_message) + mess->len;
    Seq_Num++;
    IPC_Send(ipc_sock, (void *)mess, nbytes, itrc_in.ipc_remote);
    free(mess);

    if (Script_Breaker_Val == BREAKER_ON)
        val = 1;
    else 
        val = 0;

    Append_History("Set %s to %d", d->br_write_arr[Script_Breaker_Index].to_str, val);

    if (Script_Breaker_Val == BREAKER_ON) {
        t = Button_Pressed_Duration;
        Script_Breaker_Val = BREAKER_OFF;
    }
    else { /* (Script_Breakerval == BREAKER_OFF) */
        t = Next_Button;
        Script_Breaker_Val = BREAKER_ON;
        Script_Breaker_Index = (Script_Breaker_Index + 1) % NUM_BREAKER;
    }

    E_queue(Button_Event, 0, NULL, t);
}

void Append_History(const char *m, ...)
{
    char time_str[80];
    int ts_len;
    struct tm tm_now;
    time_t t_now;
    va_list ap;

    va_start(ap, m);
    t_now = time(0);
    gmtime_r(&t_now, &tm_now);
    ts_len = (int) strftime(time_str, sizeof(time_str), "%H:%M:%S: ", &tm_now);
    vsnprintf(time_str + ts_len, sizeof(time_str) - ts_len, m, ap);
    va_end(ap);

    stdcarr_push_back(&Script_History, time_str);
    Script_History_Seq++;

    if (stdcarr_size(&Script_History) > 25)
        stdcarr_pop_front_n(&Script_History, stdcarr_size(&Script_History) - 25);
}

void Append_SS_History(const char *m, ...)
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

    stdcarr_push_back(&Script_History, buff);
    Script_History_Seq++;

    if (stdcarr_size(&Script_History) > 25)
        stdcarr_pop_front_n(&Script_History, stdcarr_size(&Script_History) - 25);
}
