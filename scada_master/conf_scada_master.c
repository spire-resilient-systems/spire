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
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <assert.h>

#include "../common/conf_scada_packets.h"
#include "../common/conf_net_wrapper.h"
#include "../common/def.h"
#include "../common/conf_itrc.h"
#include "structs.h"
#include "queue.h"

int ipc_sock;
itrc_data itrc_main, itrc_thread;

//Arrays
char * stat;
p_switch * sw_arr;
p_link * pl_arr;
sub * sub_arr;
p_tx * tx_arr;

// Storage for PNNL
pnnl_fields pnnl_data;

// Storage for EMS
ems_fields ems_data[EMS_NUM_GENERATORS];

//size info
int stat_len;
int sw_arr_len;
int pl_arr_len;
int sub_arr_len;
int tx_arr_len;
int32u num_jhu_sub;

/*Functions*/
void Usage(int, char **);
void init();
void err_check_read(char * ret);
void process();
int read_from_rtu(signed_message *, struct timeval *);
void read_from_hmi(signed_message *);
void package_and_send_checkpoint(signed_message *); // MK: Needed for checkpointing
void apply_state(signed_message *);
void print_state();

int main(int argc, char **argv)
{
    int nbytes, id, i, ret;
    char buf[MAX_LEN];
    char *ip;
    struct timeval t, now;
    signed_message *mess;
    fd_set mask, tmask;
    rtu_data_msg *rtud;
    benchmark_msg *ben;
    pthread_t m_tid, pi_tid;
    /*int remove_me;*/

    setlinebuf(stdout);
    Init_SM_Replicas(); // call before usage to check that we get the right args for our type

    Usage(argc, argv);

    printf("INIT\n");
    init();

    // NET Setup
    gettimeofday(&now, NULL);
    My_Incarnation = now.tv_sec;
    Prime_Client_ID = My_ID;
    if (Is_CC_Replica(My_ID))
        Type = CC_TYPE;
    else
        Type = DC_TYPE;
    My_IP = getIP();

    // Setup the signal handler for ITRC_Master
    sigemptyset(&signal_mask);
    sigaddset(&signal_mask, SIGPIPE);
    ret = pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
    if (ret != 0) {
        printf("SM_main: error in pthread_sigmask\n");
        return EXIT_FAILURE;
    }

    // initalize the IPC communication with the ITRC
    memset(&itrc_main, 0, sizeof(itrc_data));
    sprintf(itrc_main.prime_keys_dir, "%s", (char *)SM_PRIME_KEYS);
    sprintf(itrc_main.sm_keys_dir, "%s", (char *)SM_SM_KEYS);
    sprintf(itrc_main.ipc_local, "%s%d", (char *)SM_IPC_MAIN, My_ID);
    sprintf(itrc_main.ipc_remote, "%s%d", (char *)SM_IPC_ITRC, My_ID);
    ipc_sock = IPC_DGram_Sock(itrc_main.ipc_local);

    memset(&itrc_thread, 0, sizeof(itrc_data));
    sprintf(itrc_thread.prime_keys_dir, "%s", (char *)SM_PRIME_KEYS);
    sprintf(itrc_thread.sm_keys_dir, "%s", (char *)SM_SM_KEYS);
    sprintf(itrc_thread.ipc_local, "%s%d", (char *)SM_IPC_ITRC, My_ID);
    sprintf(itrc_thread.ipc_remote, "%s%d", (char *)SM_IPC_MAIN, My_ID);
    ip = strtok(argv[2], ":");
    sprintf(itrc_thread.spines_int_addr, "%s", ip);
    ip = strtok(NULL, ":");
    sscanf(ip, "%d", &itrc_thread.spines_int_port);
    if (Type == CC_TYPE) {
        ip = strtok(argv[3], ":");
        sprintf(itrc_thread.spines_ext_addr, "%s", ip);
        ip = strtok(NULL, ":");
        sscanf(ip, "%d", &itrc_thread.spines_ext_port);
    }

    // Setup and spawn the main itrc thread
    pthread_create(&m_tid, NULL, &ITRC_Master, (void *)&itrc_thread);

    // Create the Prime_Inject thread for all types of replicas (not only
    // control-center replicas). Only control-center replicas introduce client
    // (HMI/Proxy) updates, but all replicas can request a state transfer if
    // the first ordinal received is further ahead than what is expected
    
    // MK Todo: Do we need to decouple CC and DC here?
    pthread_create(&pi_tid, NULL, &ITRC_Prime_Inject, (void *)&itrc_thread);
    
    // Setup the FD_SET
    FD_ZERO(&mask);
    FD_SET(ipc_sock, &mask);

    while(1) {

        tmask = mask;
        select(FD_SETSIZE, &tmask, NULL, NULL, NULL);

        /* 
            MK: Decoupling Control Center and Data Center replicas.
                DC does not need to do anything in the local application.
        */
        if(Type == DC_TYPE)
        {
            continue;
        }

        if (FD_ISSET(ipc_sock, &tmask)) {
            ret = IPC_Recv(ipc_sock, buf, MAX_LEN);
            mess = (signed_message *)buf;

            if (mess->type == RTU_DATA) {
                id = read_from_rtu(mess, &t);

                /* Separate sending correct HMI update for each scenario */
                rtud = (rtu_data_msg *)(mess + 1);
                if (rtud->scen_type == JHU) {
                    mess = PKT_Construct_HMI_Update_Msg(rtud->seq, rtud->scen_type,
                                    stat_len, stat, t.tv_sec, t.tv_usec);
                }
                else if (rtud->scen_type == PNNL) {
                    mess = PKT_Construct_HMI_Update_Msg(rtud->seq, rtud->scen_type,
                                RTU_DATA_PAYLOAD_LEN - PNNL_DATA_PADDING,
                                (char *)(((char *)&pnnl_data) + PNNL_DATA_PADDING),
                                t.tv_sec, t.tv_usec);
                }
                else if (rtud->scen_type == EMS) {
                    mess = PKT_Construct_HMI_Update_Msg(rtud->seq, rtud->scen_type,
                                RTU_DATA_PAYLOAD_LEN,
                                (char *)((char *)&ems_data[id]),
                                t.tv_sec, t.tv_usec);
                    /*for(remove_me = 0; remove_me < EMS_NUM_GENERATORS; ++remove_me) {
                        printf("ID: %d Current: %d Target: %d Max: %d\n", remove_me, ems_data[remove_me].curr_generation, ems_data[remove_me].target_generation, ems_data[remove_me].max_generation);
                    }*/
                }
                nbytes = sizeof(signed_message) + mess->len;
                IPC_Send(ipc_sock, (void *)mess, nbytes, itrc_main.ipc_remote);
                free(mess);
            }
            else if (mess->type == HMI_COMMAND) {
                read_from_hmi(mess);
            }
            else if (mess->type == BENCHMARK) {
                ben = (benchmark_msg *)(mess + 1);
                gettimeofday(&now, NULL);
                ben->pong_sec = 0; //now.tv_sec;
                ben->pong_usec = 0; //now.tv_usec;
                //printf("SM_MAIN: Sending back reply to benchmark message...\n");
                IPC_Send(ipc_sock, (void *)mess, ret, itrc_main.ipc_remote);
            }
            else if (mess->type == STATE_XFER) {
                apply_state(mess);
            }
            else if (mess->type == CREATE_CHECKPOINT) {
                package_and_send_checkpoint(mess);
            }
            else if (mess->type == SYSTEM_RESET) {
                printf("Resetting State @ SM!!\n");
                for(i = 0; i < sw_arr_len; i++)
                    sw_arr[i].status = 1;
                for(i = 0; i < tx_arr_len; i++)
                    tx_arr[i].status = 1;
                for(i = 0; i < sub_arr_len; i++)
                    sub_arr[i].status = 1;
                for(i = 0; i < pl_arr_len; i++)
                    pl_arr[i].status = 1;
                for(i = 0; i < stat_len; i++)
                    stat[i] = 1;

                /* Initialize PNNL Scenario */
                memset(&pnnl_data, 0, sizeof(pnnl_fields));
            }
            else {
                printf("SM_MAIN: invalid message type %d\n", mess->type);
            }
        }
    }

    pthread_exit(NULL);
}

// Usage
void Usage(int argc, char **argv)
{
    My_ID = 0;

    if (argc < 3 || argc > 4) {
        printf("Usage: %s ID spinesIntAddr:spinesIntPort [spinesExtAddr:spinesExtPort]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    sscanf(argv[1], "%d", &My_ID);
    if (My_ID < 1 || My_ID > NUM_SM) {
        printf("Invalid My_ID: %d\n", My_ID);
        exit(EXIT_FAILURE);
    }

    if (Is_CC_Replica(My_ID) && argc != 4) {
        printf("Invalid arguments...\n");
        printf("Control Center Replicas must have internal and external spines networks specified!\n");
        exit(EXIT_FAILURE);
    }
    else if (Is_CC_Replica(My_ID) > NUM_CC_REPLICA && argc != 3) {
        printf("Invalid arguments...\n");
        printf("Data Center Replicas should only have internal spines network specified!\n");
        exit(EXIT_FAILURE);
    }


    /*if (My_ID == 0) {
        printf("No Server ID. Please specify the ID using -i\n");
        exit(EXIT_FAILURE);
    } */
}

// Set everything up
void init()
{
    FILE *fp;
    int line_size = 100;
    char line[100];
    int sw_cur = 0;
    int pl_cur = 0;
    int tx_cur = 0;
    int i, j, num_switches, num_lines;

    fp = fopen("../init/ini", "r");
    if(fp == NULL) {
        fprintf(stderr, "problems opening file. abort");
        exit(1);
    }
    //find size of tooltip array
    err_check_read(fgets(line, line_size, fp)); //ignore this line (comment #SIZE OF TOOLTIP ARRAY)
    err_check_read(fgets(line, line_size, fp));
    stat_len = atoi(line);

    // get lengths
    sw_arr_len = 0;
    pl_arr_len = 0;
    sub_arr_len = 0;
    tx_arr_len = 0;

    err_check_read(fgets(line, line_size, fp)); //ignore this line (comment #TOOLTIP ARRAY)
    for(i = 0; i < stat_len; i++) {
        err_check_read(fgets(line, line_size, fp));
        switch(line[0]) {
            case '0': {
                sub_arr_len++;
                break;
            }
            case '1': {
                tx_arr_len++;
                break;
            }
            case '2': {
                sw_arr_len++;
                break;
            }
            case '3': {
                pl_arr_len++;
                break;
            }
        }
    }
    stat = malloc(sizeof(char) * stat_len);
    sw_arr = malloc(sizeof(p_switch) * sw_arr_len);
    pl_arr = malloc(sizeof(p_link) * pl_arr_len);
    sub_arr = malloc(sizeof(sub) * sub_arr_len);
    tx_arr = malloc(sizeof(p_tx) * tx_arr_len);

    memset(sub_arr, 0, sizeof(sub) * sub_arr_len);
    num_jhu_sub = sub_arr_len;

    //start filling arrays
    err_check_read(fgets(line, line_size, fp)); //ignore (comment #_____________________)
    err_check_read(fgets(line, line_size, fp)); //ignore (10?)
    for(i = 0; i < sub_arr_len; i++) {
        err_check_read(fgets(line, line_size, fp)); //ignore (comment #SUB ID)
        err_check_read(fgets(line, line_size, fp));
        sub_arr[i].id = atoi(line);
        //set up tx
        err_check_read(fgets(line, line_size, fp)); //ignore (comment #TX ID)
        err_check_read(fgets(line, line_size, fp));
        tx_arr[tx_cur].id = atoi(line);
        sub_arr[i].tx = tx_arr + tx_cur;
        tx_cur++;
        //set up switches
        err_check_read(fgets(line, line_size, fp)); //ignore (#NUMBER OF SWITCHES)
        err_check_read(fgets(line, line_size, fp));
        num_switches = atoi(line);
        sub_arr[i].num_switches = num_switches;
        err_check_read(fgets(line, line_size, fp)); //ignore (#SWITCH_IDS)
        for(j = 0; j < num_switches; j++) {
            err_check_read(fgets(line, line_size, fp));
            sw_arr[sw_cur].id = atoi(line);
            sub_arr[i].sw_list[j] = sw_arr + sw_cur;
            sw_cur++;
        }
        //set up lines
        err_check_read(fgets(line, line_size, fp)); //ignore (#NUMBER OF LINES)
        err_check_read(fgets(line, line_size, fp));
        num_lines = atoi(line);
        sub_arr[i].num_lines = num_lines;
        for(j = 0; j < num_lines; j++) {
            err_check_read(fgets(line, line_size, fp)); //ignore (#LINE INFO)
            // line id, src switch id, dest switch id, dest sub id
            err_check_read(fgets(line, line_size, fp));
            pl_arr[pl_cur].id = atoi(line);
            err_check_read(fgets(line, line_size, fp));
            pl_arr[pl_cur].src_sw_id = atoi(line);
            err_check_read(fgets(line, line_size, fp));
            pl_arr[pl_cur].dest_sw_id = atoi(line);
            err_check_read(fgets(line, line_size, fp));
            pl_arr[pl_cur].dest_sub = atoi(line);
            pl_arr[pl_cur].src_sub = i;
            sub_arr[i].out_lines[j] = pl_arr + pl_cur;
            //to support bi directional links between substations only
            int dest_sub = pl_arr[pl_cur].dest_sub;
            if( i >= 1 && i <= 4 && dest_sub >=1 && dest_sub <= 4) {
                int cur_lines;
                //printf("Reverse Line\n");
                //printf("Src Sub: %d, Dest Sub: %d\n", i, dest_sub);
                cur_lines = sub_arr[dest_sub].num_in_lines;
                sub_arr[dest_sub].in_lines[cur_lines] = pl_arr + pl_cur;
                sub_arr[dest_sub].num_in_lines ++;
            }
            pl_cur++;
        }
    }
    fclose(fp);
    //finish up setting up lines
    for(i = 0; i < pl_arr_len; i++) {
        for(j = 0; j < sw_arr_len; j++) {
            if(sw_arr[j].id == pl_arr[i].src_sw_id)
                pl_arr[i].src_sw = sw_arr + j;
            if(sw_arr[j].id == pl_arr[i].dest_sw_id)
                pl_arr[i].dest_sw = sw_arr + j;
        }
    }

    for(i = 0; i < sw_arr_len; i++) {
        sw_arr[i].status = 1;
    }
    for(i = 0; i < tx_arr_len; i++) {
        tx_arr[i].status = 1;
    }
    for(i = 0; i < sub_arr_len; i++){
        sub_arr[i].status = 1;
    }
    for(i = 0; i < pl_arr_len; i++){
        pl_arr[i].status = 1;
    }
    for(i = 0; i < stat_len; i++) {
        stat[i] = 1;
    }

    /* Initialize PNNL Scenario */
    memset(&pnnl_data, 0, sizeof(pnnl_fields));
}

void err_check_read(char * ret)
{
    if(ret == NULL) {
        fprintf(stderr, "read issue");
        exit(1);
    }
}

//Figure out which substations have power
void process()
{
    int i, j;

    /*initialize data*/
    queue_init();
    sub_arr[0].status = 1;
    for(j = 1; j < sub_arr_len; j++)
        sub_arr[j].status = 0;
    for(j = 0; j < pl_arr_len; j++)
        pl_arr[j].status = 0;
    enqueue(0);

    //run bfs
    while(!queue_is_empty()) {
        sub * c_sub = sub_arr + dequeue();
        if(c_sub->tx->status == 0)
            continue;
        for(i = 0; i < c_sub->num_lines; i++){
            p_link * c_link = c_sub->out_lines[i];
            if(c_link->src_sw->status == 1 && c_link->dest_sw->status == 1) {
                c_link->status = 1;
                if(sub_arr[c_link->dest_sub].status == 0) {
                    sub_arr[c_link->dest_sub].status = 1;
                    enqueue(c_link->dest_sub);
                }
            }
        }
        for(i = 0; i < c_sub->num_in_lines; i++){
            p_link * c_link = c_sub->in_lines[i];
            if(c_link->src_sw->status == 1 && c_link->dest_sw->status == 1) {
                c_link->status = 1;
                if(sub_arr[c_link->src_sub].status == 0) {
                    sub_arr[c_link->src_sub].status = 1;
                    enqueue(c_link->src_sub);
                }
            }
        }
    }

    //check if links are broken
    for(i = 0; i < pl_arr_len; i++){
        if(pl_arr[i].src_sw->status == 2) {
            //tripped line, raise alarm
            pl_arr[i].status=2;
        }
    }

    //put new data into status array
    for(i = 0; i < sw_arr_len; i++)
        stat[sw_arr[i].id] = sw_arr[i].status;
    for(i = 0; i < pl_arr_len; i++)
        stat[pl_arr[i].id] = pl_arr[i].status;
    for(i = 0; i < sub_arr_len; i++)
        stat[sub_arr[i].id] = sub_arr[i].status;
    for(i = 0; i < tx_arr_len; i++)
        stat[tx_arr[i].id] = tx_arr[i].status;
    queue_del();
}

//Read from RTU, and update data structures
int read_from_rtu(signed_message *mess, struct timeval *t)
{
    int i;
    rtu_data_msg *payload;
    jhu_fields *jhf;
    pnnl_fields *pf;
    ems_fields *ems;

    payload = (rtu_data_msg *)(mess + 1);

    // Only send updates from Real RTUs (ID = 0 to NUM_RTU - 1) to HMI
    // We don't actually check this return value anywhere...should move to itrc
    // validate_message function?
    if (payload->rtu_id >= NUM_RTU || payload->seq.seq_num == 0)
        return -1;

    t->tv_sec  = payload->sec;
    t->tv_usec = payload->usec;

    if (payload->scen_type == JHU) {
        /* If we got an invalid id, we don't want to try to use it to update
         * the sub_arr. Note that we will still send an HMI update (keeping all
         * of the ordinal accounting happy), but it won't actually reflect any
         * state change. It would be better to be able to identify this message
         * as invalid at the itrc level, but we don't know how many substation
         * we have until we read the configuration file at the SCADA Master
         * level today */
        if (payload->rtu_id >= num_jhu_sub) return 0;

        jhf = (jhu_fields *)(payload->data);

        for(i = 0; i < sub_arr[payload->rtu_id].num_switches; i++) {
            if(jhf->sw_status[i] == 1 || jhf->sw_status[i] == 0 ||
                    jhf->sw_status[i] == 2) {
                sub_arr[payload->rtu_id].sw_list[i]->status = jhf->sw_status[i];
            }
        }

        if(jhf->tx_status == 1 || jhf->tx_status == 0)
            sub_arr[payload->rtu_id].tx->status = jhf->tx_status;
        process();
    }
    else if (payload->scen_type == PNNL) {
        pf = (pnnl_fields *)(payload->data);
        memcpy(&pnnl_data, pf, sizeof(pnnl_data));
    }
    else if (payload->scen_type == EMS) {
        ems = (ems_fields *)(payload->data);
        memcpy(&ems_data[ems->id], ems, sizeof(ems_fields));
        return ems->id;
    }
    return 0;
}

//Read PVS message, send message to DAD saying what to write
void read_from_hmi(signed_message *mess)
{
    //printf("READ FROM HMI\n");
    //char buf[MAX_LEN];
    int val = 0;
    int found = 0;
    int nbytes = 0;
    int i, z;
    //signed_message *mess;
    //client_response_message *res;
    //update_message *up;
    hmi_command_msg *payload;
    signed_message *dad_mess = NULL;

    //IPC_Recv(ipc_hmi_sock, buf, MAX_LEN);
    //mess = ((signed_message *) buf);
    //res = (client_response_message *)(mess + 1);
    //up = (update_message *)(mess + 1);
    //payload = (hmi_command_msg *)(res + 1);
    payload = (hmi_command_msg *)(mess + 1);

    if (payload->scen_type == JHU) {
        switch(payload->type){
            case TRANSFORMER: {
                //figure out what substation the transformer belongs to
                for(i = 0; i < sub_arr_len; i++) {
                    if(payload->ttip_pos == sub_arr[i].tx->id) {
                        found = 1;
                        val = (sub_arr[i].tx->status == 0)? 1:0;
                        dad_mess = PKT_Construct_RTU_Feedback_Msg(payload->seq,
                                    payload->scen_type, TRANSFORMER, i, i, 0, val);
                        break;
                    }
                }
                break;
            }
            case SWITCH: {
                for(i = 0; i < sub_arr_len; i++) {
                    for(z = 0; z < sub_arr[i].num_switches; z++) {
                        if(payload->ttip_pos == sub_arr[i].sw_list[z]->id) {
                            found = 1;
                            //dont change anything if tripped
                            if(sub_arr[i].sw_list[z]->status == 2)
                                return;
                                //return 1;
                            val = (sub_arr[i].sw_list[z]->status==0)?1:0;
                            dad_mess = PKT_Construct_RTU_Feedback_Msg(payload->seq,
                                        payload->scen_type, SWITCH, i, i, z, val);
                            break;
                        }
                    }
                    if(found == 1)
                        break;
                }
                break;
            }
        }
        if(found == 0) {
            perror("ID from PVS not found\n");
            // Are we still required to create some kind of feedback message in
            // this case?
        }
    }
    else if (payload->scen_type == PNNL) {
        // We should probably make sure the validate function is actually
        // ensuring this before asserting it
        assert(payload->ttip_pos >= 0 && payload->ttip_pos < NUM_BREAKER);

        if (payload->type == BREAKER_FLIP) {
            val = (pnnl_data.breaker_write[payload->ttip_pos]==0)?1:0;
        }
        else if (payload->type == BREAKER_ON) {
            val = 1;
        }
        else if (payload->type == BREAKER_OFF) {
            val = 0;
        }

        dad_mess = PKT_Construct_RTU_Feedback_Msg(payload->seq, payload->scen_type,
                        BREAKER, PNNL_RTU_ID, PNNL_RTU_ID, payload->ttip_pos, val);
    }
    else if (payload->scen_type == EMS) {
        /* payload->type is the updated Target value
         * payload->ttip_pos is the generator ID*/
        // Need to validate payload0>ttip_pos < NUM_EMS_GENERATORS
        ems_data[payload->ttip_pos].target_generation = payload->type;
        printf("EMS message, gen: %d target: %d\n", payload->ttip_pos, payload->type);

        dad_mess = PKT_Construct_RTU_Feedback_Msg(payload->seq,
                        payload->scen_type,
                        EMS_TARGET_SET,
                        (EMS_RTU_ID_BASE+payload->ttip_pos),
                        (EMS_RTU_ID_BASE+payload->ttip_pos),
                        0, // Hardcode to 0 b/c we always write to the target, which is the first R/W Int
                        ems_data[payload->ttip_pos].target_generation);
    }

    /* With the message constructed (from either scenario), send it on */
    if(dad_mess != NULL){
        nbytes = sizeof(signed_message) + sizeof(rtu_feedback_msg);
        IPC_Send(ipc_sock, (void *)dad_mess, nbytes, itrc_main.ipc_remote);
        free(dad_mess);
    }
}

// MK: Creates checkpoint and sends it back to itrc
void package_and_send_checkpoint(signed_message *mess)
{
    int32u i, nBytes, state_size;
    int j;
    checkpoint_msg *sr_specific;
    signed_message *sx;
    checkpoint_msg *sx_specific;
    sm_state *slot_ptr;
    char *field_ptr;
    char state[MAX_STATE_SIZE];

    sr_specific = (checkpoint_msg *)(mess + 1);
    //assert(sr_specific->target > 0 && sr_specific->target <= NUM_SM);

    /* Fill in the state from the sub_arr data structure */
    state_size = 0;
    slot_ptr = (sm_state *)state;

    /* Package up the JHU State */
    for (i = 0; i < num_jhu_sub; i++) {
        slot_ptr->client = i;
        slot_ptr->num_fields = 1 + sub_arr[i].num_switches;   // 1 for the transformer
        field_ptr = (char *)(slot_ptr + 1);
        field_ptr[0] = sub_arr[i].tx->status;                 // copy in tx status
        for (j = 1; j <= sub_arr[i].num_switches; j++) {
            field_ptr[j] = sub_arr[i].sw_list[j-1]->status;   // copy in each sw status
        }
        state_size += sizeof(sm_state) + sizeof(char)*slot_ptr->num_fields;
        slot_ptr = (sm_state *)(((char *)slot_ptr) + sizeof(sm_state) + sizeof(char)*slot_ptr->num_fields);
    }

    /* Package up the PNNL State */
    slot_ptr->client = PNNL_RTU_ID;
    slot_ptr->num_fields = 0;            /* Handled in special way for now */
    field_ptr = (char *)(slot_ptr + 1);
    memcpy(field_ptr, (char *)(((char *)&pnnl_data) + PNNL_DATA_PADDING),
            RTU_DATA_PAYLOAD_LEN - PNNL_DATA_PADDING);
    state_size += sizeof(sm_state) + (RTU_DATA_PAYLOAD_LEN - PNNL_DATA_PADDING);

    /* pf = (pnnl_fields *)(&pnnl_data);
    for (i = 0; i < NUM_POINT; i++)
        sh_ptr[i] = pf->point[i];
    field_ptr = (char *)(sh_ptr + NUM_POINT);
    for (i = 0; i < NUM_BREAKER; i++)
        field_ptr[i] = pf->breaker_read[i];
    field_ptr = (char *)(field_ptr + NUM_BREAKER);
    for (i = 0; i < NUM_BREAKER; i++)
        field_ptr[i] = pf->breaker_write[i]; */

    /* Construct the State Xfer message from the state */
    /* sx = PKT_Construct_State_Xfer_Msg(sr_specific->target, NUM_RTU, sr_specific->latest_update,
                                        state, state_size); */
    sx = PKT_Construct_Checkpoint_Msg(sr_specific->ord, num_jhu_sub + 1, sr_specific->latest_update,
                                        state, state_size);
    sx_specific = (checkpoint_msg *)(sx + 1);
    nBytes = sizeof(signed_message) + sizeof(checkpoint_msg);

    // Make sure the state we are sending is not too large (for the time being)
    assert(nBytes == sizeof(signed_message) + sizeof(checkpoint_msg));
    assert(nBytes <= MAX_LEN);

    // Send this message back to the ITRC
    IPC_Send(ipc_sock, (void* )sx, nBytes, itrc_main.ipc_remote);
    free(sx);
    //print_state();
}

void apply_state(signed_message *mess)
{
    int32u i, j, size;
    state_xfer_msg *st;
    sm_state *slot_ptr;
    char *field_ptr;

    printf("\t\tAPPLYING STATE @ SM MAIN\n");
    st = (state_xfer_msg *)(mess + 1);

    if (st->target != (int32u)My_ID) {
        printf("Recv state that is for %u, not my id\n", st->target);
        return;
    }

    if (sizeof(signed_message) + mess->len > MAX_LEN) {
        printf("Recv message that tried to be larger than MAX_LEN = %u, dropping!\n", MAX_LEN);
        return;
    }

    /* Go through and grab each piece of state and apply it */
    size = 0;
    slot_ptr = (sm_state *)(st + 1);

    /* Handle first set of clients for JHU scenario */
    for (i = 0; i < st->num_clients - 1; i++) {
        field_ptr = (char *)(slot_ptr + 1);
        sub_arr[slot_ptr->client].tx->status = field_ptr[0];
        for (j = 1; j <= (slot_ptr->num_fields-1); j++) {
            sub_arr[slot_ptr->client].sw_list[j-1]->status = field_ptr[j];
        }
        size += sizeof(sm_state) + sizeof(char)*slot_ptr->num_fields;
        slot_ptr = (sm_state *)(((char *)slot_ptr) + sizeof(sm_state) + sizeof(char)*slot_ptr->num_fields);
    }

    /* Handle the PNNL scenario - Last client*/
    field_ptr = (char *)(slot_ptr + 1);
    memcpy((char *)(((char *)&pnnl_data) + PNNL_DATA_PADDING), field_ptr,
            RTU_DATA_PAYLOAD_LEN - PNNL_DATA_PADDING);
    size += sizeof(sm_state) + (RTU_DATA_PAYLOAD_LEN - PNNL_DATA_PADDING);

    assert(size == st->state_size);
    process();
    //print_state();
}

void print_state()
{
    int32u i;
    int j;
    pnnl_fields *pf;

    printf("=== SM STATE ===\n");

    /* Print out JHU state */
    printf("   JHU SCENARIO   \n");
    for (i = 0; i < num_jhu_sub; i++) {
        printf("    [%u]: tx=%d sw=[", i, sub_arr[i].tx->status);
        for (j = 0; j < sub_arr[i].num_switches; j++)
            printf("%d ", sub_arr[i].sw_list[j]->status);
        printf("]\n");
    }

    /* print out PNNL State */
    printf("   PNNL SCENARIO   \n");
    pf = (pnnl_fields *)(&pnnl_data);
    printf("Latest Values:\n");
    printf("  IR: ");
    for (i = 0; i < NUM_POINT; i++)
        printf("%d ", pf->point[i]);
    printf("\n");
    printf("  IS: ");
    for (i = 0; i < NUM_BREAKER; i++)
        printf("%d ", pf->breaker_read[i]);
    printf("\n");
    printf("  CS: ");
    for (i = 0; i < NUM_BREAKER; i++)
        printf("%d ", pf->breaker_write[i]);
    printf("\n");

    /* print out EMS State */
    for (i = 0; i < EMS_NUM_GENERATORS; ++i) {
        printf("EMS Generator #%d, id: %d\n", i, ems_data[i].id);
        printf("    Max Generation: %d\n", ems_data[i].max_generation);
        printf("    Current Generation: %d\n", ems_data[i].curr_generation);
        printf("    Target Generation: %d\n", ems_data[i].target_generation);
    }
}
