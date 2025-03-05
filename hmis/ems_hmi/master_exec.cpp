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


/* Can't be int because its used elsewhere that requires void */
void Read_From_Master(int s, int dummy1, void *dummy2)
{
    char buf[MAX_LEN];
    int ret;
    signed_message *cmess;


    UNUSED(dummy1);
    UNUSED(dummy2);

    ret = IPC_Recv(s, buf, MAX_LEN);
    if (ret < 0) printf("Read_From_Master: IPC_Rev failed\n");
    cmess=(signed_message *)buf;
    if(cmess->type ==  PRIME_OOB_CONFIG_MSG){
        Process_Config_Msg((signed_message *)buf,ret);
        return;
    }
    
    Process_Message((signed_message *)buf);
}

void Process_Message(signed_message *mess)
{
    ems_fields *ems_up;
    int pp_id;
    int len, expected_size;
    struct timeval now, then, diff;
    hmi_update_msg *hmi_up;
    data_model *model;

    hmi_up = (hmi_update_msg *)(mess + 1);

    if (hmi_up->scen_type != EMS) {
        printf("Process_Message: INVALID SCENARIO: %d\n", hmi_up->scen_type);
        return;
    }

    len = hmi_up->len;
    expected_size = sizeof(ems_fields);
    if (len != expected_size) {
        printf("Process_Message: INVALID LENGTH: %d, expected %d\n", len, expected_size);
        return;
    }

    ems_up = (ems_fields *)(hmi_up + 1);

    gettimeofday(&now, NULL);
    then.tv_sec  = hmi_up->sec;
    then.tv_usec = hmi_up->usec;
    diff = diffTime(now, then);

    model = &the_model;
    if(model == NULL) {
        printf("No browser connected\n");
        return;
    }

    // Mark the model as dirty so the UI updates
    model->dirty = 1;

    // Only the HMI has a concept of powerplants, this is where we translate
    // from the nonpowerplant part of the code to the powerplant part
    if (ems_up->id < 3) {
        pp_id = 0;
    } else {
        pp_id = 1;
    }
    model->pp_arr[pp_id].gen_arr[ems_up->id].current = ems_up->curr_generation;
    model->pp_arr[pp_id].gen_arr[ems_up->id].max = ems_up->max_generation;
    model->pp_arr[pp_id].gen_arr[ems_up->id].target = ems_up->target_generation;
}

void Execute_Script(int s, int dummy1, void *dummy2)
{
    //char buf[1024];
    //int ret;
    //sp_time zero_t = {0, 0};

    UNUSED(s);
    UNUSED(dummy1);
    UNUSED(dummy2);

    /* Voiding this function for now */
    return;
    //while ( (ret = read(s, buf, sizeof(buf))) > 0);
    //if ( ret != -1 || (errno != EAGAIN && errno != EINTR))
    //printf("read error\n"), exit(EXIT_FAILURE);

    //printf("Script_Button_Pushed = %d\n", Script_Button_Pushed);
    //switch(Script_Button_Pushed) {

    //case RESTART_SCRIPT:
    //Script_Running = 1;
    //Clear_All_Buttons();
    //usleep(min_wait.tv_sec*1000000 + min_wait.tv_usec);
    //Push_Buttons(BR_CLOSE);
    //usleep(min_wait.tv_sec*1000000 + min_wait.tv_usec);
    //Clear_All_Buttons();
    //Script_Breaker_Index = 0;
    //Script_Breaker_Val = BREAKER_ON;
    //E_queue(Button_Event, 0, NULL, zero_t);
    //break;

    //case PAUSE_SCRIPT:
    //if (E_in_queue(Button_Event, 0, NULL))
    //E_dequeue(Button_Event, 0, NULL);
    //Clear_All_Buttons();
    //Script_Running = 0;
    //break;

    //case CONTINUE_SCRIPT:
    //Script_Running = 1;
    //Clear_All_Buttons();
    //E_queue(Button_Event, 0, NULL, zero_t);
    //break;

    //default:
    //break;
    //}

    //Script_Button_Pushed = NO_BUTTON;
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
    UNUSED(btype);
    /*data_model *d = &the_model;
      signed_message *mess;
      seq_pair ps;
      int nbytes, i;

      for(i = 0; i < NUM_BREAKER; i++) {
      if (d->br_write_arr[i].type != btype)
      continue;

      ps.incarnation = My_Incarnation;
      ps.seq_num = Seq_Num;
      mess = PKT_Construct_HMI_Command_Msg(ps, MAX_EMU_RTU + My_ID, PNNL, BREAKER_ON, i);
      nbytes = sizeof(signed_message) + mess->len;
      Seq_Num++;
      IPC_Send(ipc_sock, (void *)mess, nbytes, itrc_in.ipc_remote);
      free(mess);
      }*/
}

void Button_Event(int dummy1, void *dummy2)
{
    UNUSED(dummy1);
    UNUSED(dummy2);
    /*data_model *d = &the_model;
      signed_message *mess;
      seq_pair ps;
      int nbytes, val;
      sp_time t;

      UNUSED(dummy1);
      UNUSED(dummy2);

      ps.incarnation = My_Incarnation;
      ps.seq_num = Seq_Num;
      mess = PKT_Construct_HMI_Command_Msg(ps, MAX_EMU_RTU + My_ID, PNNL, Script_Breaker_Val, Script_Breaker_Index);
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
      else { // (Script_Breakerval == BREAKER_OFF)
      t = Next_Button;
      Script_Breaker_Val = BREAKER_ON;
      Script_Breaker_Index = (Script_Breaker_Index + 1) % NUM_BREAKER;
      }

      E_queue(Button_Event, 0, NULL, t);*/
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

int demand_delta = 5;

int Advance_Demand(DATA *data) {
    data->dm->current_demand += demand_delta;
    /* If the demand is above our cap or at 0 we want to reverse the direction of change */
    if (data->dm->current_demand >= 1500 || data->dm->current_demand == 0) {
        demand_delta *= -1;
    }
    data->dm->dirty = 1;
    return 0;
}

int Record_History(DATA *data) {
    data_model *dm;
    history_model *hm;
    int pp_id;
    int gen_total = 0;
    int pp_total = 0;
    int current_gen = 0;

    dm = data->dm;
    hm = data->hm;

    /* Advance the head */
    ++hm->current_head;
    hm->current_head = hm->current_head%EMS_HISTORY_LENGTH;

    /* Copy out current generator information */
    for (int i = 0; i < EMS_NUM_GENERATORS; ++i) {
        // Only the HMI has a concept of powerplants, this is where we translate
        // from the nonpowerplant part of the code to the powerplant part
        if (i < 3) {
            pp_id = 0;
            current_gen = dm->pp_arr[pp_id].gen_arr[i].current;
        } else {
            pp_id = 1;
            if (renewable_active[i-3] == 1) {
                current_gen = dm->pp_arr[pp_id].gen_arr[i].current;
            } else {
                current_gen = 0;
            }
        }

        // Update this generator's list
        hm->generator_histories[i][hm->current_head] = current_gen;
        gen_total += current_gen;
        pp_total += current_gen;

        // If we've reached the end of a PP, update its list
        if (i == 2 || i == 5) {
            hm->generator_histories[EMS_NUM_GENERATORS + pp_id][hm->current_head] = pp_total;
            pp_total = 0;
        }
    }

    /* Save the total generation so we don't have to constantly recompute later */
    hm->generator_totals[hm->current_head] = gen_total;

    /* Copy over the current demand */
    hm->demand_history[hm->current_head] = dm->current_demand;

    /* Faking this for now */
    hm->timestamps[hm->current_head] = hm->current_head;

    return 0;
}
