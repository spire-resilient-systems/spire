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
#include <sys/time.h>
#include "conf_scada_packets.h"
#include "conf_openssl_rsa.h"
#include "conf_tc_wrapper.h"

signed_message *PKT_Construct_Signed_Message(int size) {
    signed_message *mess;
  
    mess = (signed_message *)malloc(sizeof(signed_message) + size);
    memset(mess, 0, sizeof(signed_message) + size);

    return mess;
}


/* signed_message *PKT_Construct_RTU_Data_Msg(seq_pair seq, int32u rtu_id, 
        int num_switches, int32_t *sw_status, int32_t tx_status) */
signed_message *PKT_Construct_RTU_Data_Msg(rtu_data_msg* r)
{
    struct timeval now;
    signed_message *mess;
    rtu_data_msg *rtu_data;;

    mess = PKT_Construct_Signed_Message(sizeof(rtu_data_msg));
    mess->len = sizeof(rtu_data_msg);
    mess->type = RTU_DATA;

    rtu_data = (rtu_data_msg *)(mess + 1);
    rtu_data->seq = r->seq;
    rtu_data->rtu_id = r->rtu_id;
    rtu_data->scen_type = r->scen_type;

    gettimeofday(&now, NULL);
    rtu_data->sec  = now.tv_sec;
    rtu_data->usec = now.tv_usec; 

    memcpy(rtu_data->data, r->data, sizeof(rtu_data->data));
    
    /* rtu_data->tx_status = tx_status;
    for(i = 0; i < num_switches; i++) {
        rtu_data->sw_status[i] = sw_status[i];
    } */

    return mess;
}

signed_message *PKT_Construct_RTU_Feedback_Msg(seq_pair seq, int32u scen_type, 
                                               int32u type, int32u sub, int32u rtu, 
                                               int32u offset, int32_t val)
{
    signed_message *mess;
    rtu_feedback_msg *rtu_feedback;

    mess = PKT_Construct_Signed_Message(sizeof(rtu_feedback_msg));
    mess->len = sizeof(rtu_feedback_msg);
    mess->type = RTU_FEEDBACK;

    rtu_feedback = (rtu_feedback_msg *)(mess + 1);
    rtu_feedback->seq = seq;
    //rtu_feedback->hmi_id = hmi;
    rtu_feedback->scen_type = scen_type;
    rtu_feedback->type = type;
    rtu_feedback->val = val;
    rtu_feedback->rtu = rtu;
    rtu_feedback->offset = offset;
    rtu_feedback->sub = sub;
    return mess;
}

signed_message *PKT_Construct_HMI_Update_Msg(seq_pair seq, int32u scen_type, int32u size, 
                                             char* stat, int32u sec, int32u usec)
{
    signed_message *mess = NULL;
    hmi_update_msg *hmi_update = NULL;
    char *a_pt;

    mess = PKT_Construct_Signed_Message(sizeof(hmi_update_msg) + (size * sizeof(char)));
    mess->len = sizeof(hmi_update_msg) + (size * sizeof(char));
    mess->type = HMI_UPDATE;

    hmi_update = (hmi_update_msg *)(mess + 1);
    hmi_update->seq = seq;
    hmi_update->scen_type = scen_type;
    hmi_update->sec = sec;
    hmi_update->usec = usec;
    hmi_update->len = size;

    /* Write status array */
    a_pt = (char *)(hmi_update + 1);
    memcpy(a_pt, stat, size);

    /* for(i = 0; i < size; i++) {
        a_pt[i] = stat[i];
    } */

    return mess;
}

signed_message *PKT_Construct_HMI_Command_Msg(seq_pair seq, int32u hmi_id,
            int32u scen_type, int32_t type, int32_t ttip_pos)
{
    signed_message *mess;
    hmi_command_msg *hmi_command;

    mess = PKT_Construct_Signed_Message(sizeof(hmi_command_msg));
    mess->len = sizeof(hmi_command_msg);
    mess->type = HMI_COMMAND;

    hmi_command = (hmi_command_msg *)(mess + 1);
    hmi_command->seq = seq;
    hmi_command->hmi_id  = hmi_id;
    hmi_command->scen_type = scen_type;
    hmi_command->ttip_pos = ttip_pos;
    hmi_command->type = type;

    return mess;
}

signed_message *PKT_Construct_TC_Share_Msg(ordinal o, char *payload, int32u len)
{
    signed_message *mess;
    tc_share_msg *tc;
    byte digest[DIGEST_SIZE];

    mess = PKT_Construct_Signed_Message(sizeof(tc_share_msg));
    mess->machine_id = My_ID;
    mess->len = sizeof(tc_share_msg);
    mess->type = TC_SHARE;

    tc = (tc_share_msg *)(mess + 1);
    tc->ord = o;
    memset(tc->payload, 0, sizeof(tc->payload));
    memcpy(tc->payload, payload, len); 
    memset(tc->partial_sig, 0, SIGNATURE_SIZE);

    /* Generate partial signature over this message */
    OPENSSL_RSA_Make_Digest(tc, sizeof(tc->ord) + sizeof(tc->payload), digest);
    TC_Generate_Sig_Share(tc->partial_sig, digest);

    return mess;
}

signed_message *PKT_Construct_TC_Final_Msg(ordinal o, tc_node *tcn)
{
    int32u i, count;
    char copied_payload;
    signed_message *mess;
    tc_share_msg *tc;
    tc_final_msg *tcf;
    byte digest[DIGEST_SIZE];

    if (tcn->count < REQ_SHARES) {
        printf("TC_Final: too little shares (%u), required = %u\n", tcn->count, REQ_SHARES);
        return NULL;
    }

    mess = PKT_Construct_Signed_Message(sizeof(tc_final_msg));
    mess->machine_id = My_ID;
    mess->len = sizeof(tc_final_msg);
    mess->type = TC_FINAL;

    tcf = (tc_final_msg *)(mess + 1);
    tcf->ord = o;
    memset(tcf->thresh_sig, 0, SIGNATURE_SIZE);

    TC_Initialize_Combine_Phase(NUM_SM + 1, TC_MODE_POST_PRIME);

    copied_payload = 0;
    count = 0;
    for (i = 1; i <= NUM_SM; i++) {
        if (tcn->recvd[i] == 0)
            continue;

        tc = (tc_share_msg *) &tcn->shares[i];
        if (memcmp(&tc->ord, &o, sizeof(ordinal))) {
            printf("TC_Final: tc->ord [%u, %u of %u] doesn't match ord [%u, %u of %u]\n",
                    tc->ord.ord_num, tc->ord.event_idx, tc->ord.event_tot,
                    o.ord_num, o.event_idx, o.event_tot);
            continue;
        }

        /* Compare digests? May be helpful to pass in the latest digest that
         *   led to this call, since only it has the chance to have reached 
         *   REQ_SHARES */

        if (copied_payload == 0) {
            memcpy(tcf->payload, tc->payload, sizeof(tcf->payload));
            copied_payload = 1;
        }

        TC_Add_Share_To_Be_Combined(i, tc->partial_sig, TC_MODE_POST_PRIME);
        count++;
    }

    /* Make sure the local count in the function for OK shares made it to REQ_SHARES */
    if (count < REQ_SHARES) {
        printf("Error: enough shares, but not enough matching content on [%u, %u of %u]\n",
                o.ord_num, o.event_idx, o.event_tot);
        free(mess);
        return NULL;
    }

    OPENSSL_RSA_Make_Digest(tcf, sizeof(tcf->ord) + sizeof(tcf->payload), digest);
    TC_Combine_Shares(tcf->thresh_sig, digest, TC_MODE_POST_PRIME);
    TC_Destruct_Combine_Phase(NUM_SM + 1, TC_MODE_POST_PRIME);

    if (!TC_Verify_Signature(1, tcf->thresh_sig, digest)) {
        printf("Construct_TC_Final: combined TC signature failed to verify on [%u, %u of %u]!\n",
                    o.ord_num, o.event_idx, o.event_tot);
        free(mess);
        return NULL;
    }

    return mess;
}

// MK: Adding this for Scada Master Encrytpion TC verification
signed_message *PKT_Construct_TC_Share_Msg_SMEncrypt(seq_pair *ps, int32u* idx, char *payload, int32u len)
{
    signed_message *mess;
    tc_share_msg_smencrypt *tc;
    byte digest[DIGEST_SIZE];

    mess = PKT_Construct_Signed_Message(sizeof(tc_share_msg_smencrypt));
    mess->machine_id = My_ID;
    mess->len = sizeof(tc_share_msg_smencrypt);
    mess->type = TC_SHARE_SMENCRYPT;

    tc = (tc_share_msg_smencrypt *)(mess + 1);
    tc->seq = *ps;
    tc->client_id = *idx;
    memset(tc->payload, 0, sizeof(tc->payload));
    memcpy(tc->payload, payload, len); 
    memset(tc->partial_sig, 0, SIGNATURE_SIZE);

    /* Generate partial signature over this message */
    OPENSSL_RSA_Make_Digest(((tc->payload)+SIGNATURE_SIZE), sizeof(signed_update_message) - SIGNATURE_SIZE, digest); // MK: Only payload without signature, we will need to verify id and seq 
    TC_Generate_Sig_Share(tc->partial_sig, digest);

    // printf("tc->partial_sig\n%s\n", tc->partial_sig);
    // printf("digest\n%s\n", digest);

    return mess;
}

// MK: Adding this for Scada Master Encrytpion TC verification
signed_message *PKT_Construct_TC_Final_Msg_SMEncrypt(seq_pair seq, int32u client_id, tc_node_smencrypt *tcn, int32u sender)
{
    int32u i, count;
    char copied_payload;
    signed_message *mess;
    tc_share_msg_smencrypt *tc, *tcm;
    byte digest[DIGEST_SIZE], sender_digest[DIGEST_SIZE], shared_digest[DIGEST_SIZE];

    if (tcn->count < REQ_SHARES) {
        printf("TC_Final: too little shares (%u), required = %u\n", tcn->count, REQ_SHARES);
        return NULL;
    }

    mess = PKT_Construct_Signed_Message(sizeof(signed_update_message) 
                            - sizeof(signed_message));

    TC_Initialize_Combine_Phase(NUM_SM + 1, TC_MODE_PRE_PRIME); //MK TODO: Should this be F?

    copied_payload = 0;
    count = 0;

    // MK: We need to make sure the digests match with the one from the sender who just added the latest share
    tcm = (tc_share_msg_smencrypt *) &tcn->shares[sender];
    OPENSSL_RSA_Make_Digest(tcm, sizeof(tc_share_msg_smencrypt) - SIGNATURE_SIZE, sender_digest);

    for (i = 1; i <= NUM_SM; i++) {
        if (tcn->recvd[i] == 0)
            continue;

        tc = (tc_share_msg_smencrypt *) &tcn->shares[i];
        if (tc->client_id != client_id || memcmp(&tc->seq, &seq, sizeof(seq_pair))) {
            // MK TODO: Fix the print statement from ordinal to seq
            printf("TC_Final_SMEncrypt: tc->seq [%u, %u of %u] doesn't match seq [%u, %u of %u]\n",
                    tc->seq.incarnation, tc->seq.seq_num, tc->client_id,
                    seq.incarnation, seq.seq_num, client_id);
            continue;
        }

        /* Old Comment: Compare digests? May be helpful to pass in the latest digest that
         *   led to this call, since only it has the chance to have reached 
         *   REQ_SHARES */

        OPENSSL_RSA_Make_Digest(tc, sizeof(tc_share_msg_smencrypt) - SIGNATURE_SIZE, 
                                    shared_digest);
        if (OPENSSL_RSA_Digests_Equal(sender_digest, shared_digest))
        {
            if (copied_payload == 0) {
                memcpy(mess, tc->payload, sizeof(signed_update_message)); // MK: Copy payload to mess directly
                copied_payload = 1;
            }

            // printf("i, tc->partial_sig\n%d\n%s\n", i, tc->partial_sig);

            TC_Add_Share_To_Be_Combined(i, tc->partial_sig, TC_MODE_PRE_PRIME);
            count++;
        }


        
    }

    /* Make sure the local count in the function for OK shares made it to REQ_SHARES */
    if (count < REQ_SHARES) {
        // MK TODO: Fix the print statement from ordinal to seq
        printf("Error: enough shares, but not enough matching content on seq, client_id [%u, %u of %u]\n",
                seq.incarnation, seq.seq_num, client_id);
        free(mess);
        return NULL;
    }

    // MK: Make digest on the entire signed_update_message structure except signature and place it in the beginning
    OPENSSL_RSA_Make_Digest(((byte*)mess)+SIGNATURE_SIZE, sizeof(signed_update_message) - SIGNATURE_SIZE, digest);
    TC_Combine_Shares(mess->sig, digest, TC_MODE_PRE_PRIME);
    TC_Destruct_Combine_Phase(NUM_SM + 1, TC_MODE_PRE_PRIME);

    if (!TC_Verify_Signature(1, mess->sig, digest)) {
        // MK TODO: Fix the print statement from ordinal to seq
        printf("Construct_TC_Final_SMEncrypt: combined TC signature failed to verify on seq, client_id [%u, %u of %u]!\n",
                    seq.incarnation, seq.seq_num, client_id);
        printf("mess->sig\n%s\n", mess->sig);
        printf("digest\n%s\n", digest);
        free(mess);
        return NULL;
    }

    return mess;
}


/* MK: Needed for checkpointing */
signed_message *PKT_Construct_Create_Checkpoint_Msg(ordinal o, seq_pair *latest)
{
    signed_message *mess;
    checkpoint_msg *sr;

    mess = PKT_Construct_Signed_Message(sizeof(checkpoint_msg));
    mess->machine_id = My_ID;
    mess->len = sizeof(checkpoint_msg);
    mess->type = CREATE_CHECKPOINT;

    sr = (checkpoint_msg *)(mess + 1);
    memcpy(&sr->ord, &o, sizeof(ordinal));
    memcpy(sr->latest_update, latest, (MAX_EMU_RTU + NUM_HMI + 1) * sizeof(seq_pair));
    return mess;
}


signed_message *PKT_Construct_Checkpoint_Msg(ordinal o, int32u num_clients, 
                                                seq_pair *latest_update,
                                                char *state, int32u state_size)
{
    signed_message *mess;
    checkpoint_msg *sx;

    mess = PKT_Construct_Signed_Message(sizeof(checkpoint_msg));
    mess->machine_id = My_ID;
    mess->len = sizeof(checkpoint_msg);
    mess->type = CHECKPOINT;

    sx = (checkpoint_msg *)(mess + 1);
    memcpy(&sx->ord, &o, sizeof(ordinal));
    memcpy(sx->latest_update, latest_update, (MAX_EMU_RTU + NUM_HMI + 1) * sizeof(seq_pair));
    sx->num_clients = num_clients;
    sx->state_size = state_size;
    memcpy(sx->payload, state, state_size);

    return mess;
} 

signed_message *PKT_Construct_State_Xfer_Msg(int32u targ, int32u num_clients, 
                                                seq_pair *latest_update,
                                                char *state, int32u state_size)
{
    signed_message *mess;
    state_xfer_msg *sx;
    char *dest;

    mess = PKT_Construct_Signed_Message(sizeof(state_xfer_msg) + state_size);
    mess->machine_id = My_ID;
    mess->len = sizeof(state_xfer_msg) + state_size;
    mess->type = STATE_XFER;

    sx = (state_xfer_msg *)(mess + 1);
    memset(&sx->ord, 0, sizeof(ordinal));    // Will be filled in later by itrc
    sx->target = targ;
    memcpy(sx->latest_update, latest_update, (MAX_EMU_RTU + NUM_HMI + 1) * sizeof(seq_pair));
    sx->num_clients = num_clients;
    sx->state_size = state_size;
    dest = (char *)(sx + 1);
    memcpy(dest, state, state_size);

    return mess;
}

signed_message *PKT_Construct_Benchmark_Msg(seq_pair seq)
{
    signed_message *mess;
    benchmark_msg *ben;
    struct timeval now;

    mess = PKT_Construct_Signed_Message(sizeof(benchmark_msg));
    mess->machine_id = My_ID;
    mess->len = sizeof(benchmark_msg);
    mess->type = BENCHMARK;

    ben = (benchmark_msg *)(mess + 1);
    ben->seq = seq;
    ben->sender = My_ID;
    gettimeofday(&now, NULL);
    ben->ping_sec = now.tv_sec;
    ben->ping_usec = now.tv_usec;

    return mess;
}

int Var_Type_To_Int(char var[]) {
    if(strcmp(var, "inputRegisters") == 0) return INPUT_REGISTERS;
    else if(strcmp(var, "holdingRegisters") == 0) return HOLDING_REGISTERS;
    else if(strcmp(var, "inputStatus") == 0) return INPUT_STATUS;
    else if(strcmp(var, "coilStatus") == 0) return COIL_STATUS;
    else return -1;
}

char* Var_Type_To_String(int var) {
    char *str = (char *)malloc(30 * sizeof(char));

    switch(var) {
        case 0:
            sprintf(str, "inputRegisters");
            break;
        case 1:
            sprintf(str, "holdingRegisters");
            break;
        case 2:
            sprintf(str, "inputStatus");
            break;
        case 3:
            sprintf(str, "coilStatus");
            break;
        default:
            sprintf(str, "Invalid message");
            break;
  }

  return str;
}

int Seq_Pair_Compare(seq_pair p1, seq_pair p2)
{
    if (p1.incarnation < p2.incarnation)
        return -1;
    else if (p1.incarnation > p2.incarnation)
        return 1;
    else if (p1.seq_num < p2.seq_num)
        return -1;
    else if (p1.seq_num > p2.seq_num)
        return 1;
    return 0;
}

void Print_State(ordinal o, update_history *uh)
{
    int i, j;
    signed_message *m;
    rtu_data_msg *r;
    jhu_fields *jhf;
    
    printf("Printing State @ ordinal [%u,%u/%u]\n", o.ord_num, o.event_idx, o.event_tot);

    for (i = 0; i < NUM_RTU; i++) {
        m = (signed_message *)(uh[i].buff);
        r = (rtu_data_msg *)(m + 1);

        printf("[%d]: Ord=[%u,%u/%u], rtu=%d, seq=[%d,%d] - ", i, uh[i].ord.ord_num, 
                uh[i].ord.event_idx, uh[i].ord.event_tot, r->rtu_id, r->seq.incarnation,
                r->seq.seq_num);
                
        if (r->scen_type == JHU) {
            jhf = (jhu_fields *)(r->data);
            printf("tx=%d, sw=[", jhf->tx_status);
            for (j = 0; j < MAX_SWITCHES; j++) {
                printf("%d", jhf->sw_status[j]);
            }
            printf("]\n");
        }
        else if (r->scen_type == PNNL) {
            printf("\n");
        }
    }
}
