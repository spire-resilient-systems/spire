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

#include <netinet/in.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <assert.h>
#include <pthread.h>
//#include <signal.h>
#include <fcntl.h>

#include "conf_net_wrapper.h"
#include "conf_openssl_rsa.h"
#include "conf_tc_wrapper.h"
#include "def.h"
#include "conf_itrc.h"
#include "spines_lib.h"
#include "../config/cJSON.h"
#include "../config/config_helpers.h"
#include "key_value.h"
#include "stdutil/stddll.h"

/* These are flags used in the TC queue */
#define NORMAL_ORD 1
#define SKIP_ORD   2

/* These are flags used in the TC queue SMEncrypt */
#define NORMAL_SEQ 1
#define SKIP_SEQ   2  

/* These are the stages used for state collection */
#define FROM_CLIENT   1
#define FROM_EXTERNAL 2
#define FROM_PRIME    3
#define FROM_SM_MAIN  4
#define FROM_INTERNAL 5
#define TO_CLIENT     6

#define SPINES_CONNECT_SEC  2
#define SPINES_CONNECT_USEC 0


/* Global Variables */

update_history up_hist[MAX_EMU_RTU + NUM_HMI + 1];
tc_queue tcq_pending;
st_queue stq_pending;
ordinal applied_ord;
ordinal recvd_ord;
ordinal recovery_ord;
stddll ord_queue, pending_updates, pending_transfers;
int32u collecting_signal;
int32u completed_transfer;
int32u print_target;
seq_pair progress[MAX_EMU_RTU + NUM_HMI + 1];
tc_queue_smencrypt tcq_pending_smencrypt[MAX_EMU_RTU + NUM_HMI + 1]; //MK: Needed for SM Encrypt
int32u tc_queue_smencrypt_idx = 0;
seq_pair applied_seq_smencrypt[MAX_EMU_RTU + NUM_HMI + 1];

/* 
    checkpoints: Queue for storing checkpoints.
    MK: Typically, this should contain a stable checkpoint in the beginning,
        followed by more checkpoints which are not stable yet. Stable means
        at least 2f+k+1 total replicas agreed on the content of the checkpoint.
*/
checkpoint_queue checkpoints;

/* 
    updates: Queue for storing ordered requests (updates)
    MK: Typically, this will store ordered requests after a stable checkpoint 
*/
updates_queue updates;

/*  update_transfers: Queue for storing ordered requests (updates)
    MK: Typically, this will store ordered requests sent by other replicas
        when the current replica is recovering or catching up 
*/
update_transfer_queue update_transfers;

pthread_mutex_t wait_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t wait_condition = PTHREAD_COND_INITIALIZER;
int master_ready = 0;
int inject_ready = 0;


/* Local Functions */
void ITRC_Reset_Master_Data_Structures(int startup);
void ITRC_Insert_TC_ID(tc_share_msg* tcm, int32u sender, int32u flag);
int ITRC_TC_Ready_Deliver(signed_message **to_deliver, net_sock *ns);
int ITRC_Send_TC_Final(int sp_ext_sk, signed_message *mess);

void ITRC_Process_Prime_Ordinal(ordinal o, signed_message *m, net_sock *ns);

int ITRC_Ord_Compare(ordinal o1, ordinal o2);
int ITRC_Ord_Consec(ordinal o1, ordinal o2);
int ITRC_Valid_Type(signed_message *mess, int32u stage);
int ITRC_Validate_Message(signed_message *mess);

void ITRC_Insert_TC_ID_SMEncrypt(tc_share_msg_smencrypt *tcm, int32u sender, int32u flag);
int ITRC_TC_Ready_Deliver_SMEncrypt(signed_message **to_deliver);
int ITRC_Send_TC_Final_SMEncrypt(int prime_sock, signed_message *mess, const char *prime_path);
int ITRC_Seq_Consec(seq_pair s1, seq_pair s2);

/* MK: Helper functions for checkpointing and/or recovering/catching up */
void ITRC_Process_Prime_Ordinal_Update_Transfer(ordinal o, signed_message *mess, net_sock *ns);
int ITRC_Ord_Checkpoint_Check(ordinal o);
int ITRC_Insert_CHECKPOINT(signed_message *mess);
int ITRC_Check_CHECKPOINT(ordinal o, net_sock *ns);
void ITRC_Remove_Old_Checkpoints(ordinal o);
int ITRC_Insert_Update(ordinal o, signed_message *mess);
void ITRC_Remove_Old_Updates(ordinal o);
int ITRC_Insert_UPDATE_TRANSFER(signed_message *mess);
int ITRC_Check_Checkpoint_Updates_Ready();
void ITRC_Apply_Checkpoint_Updates(net_sock *ns);
void ITRC_Discard_IPC_Messages(net_sock *ns);


/* Intrusion Tolerant Reliable Channel Client (HMI, RTU) Implementation */
void *ITRC_Client(void *data)
{
    int i, num, ret, nBytes, rep;
    int proto, my_port;
    struct sockaddr_in dest;
    fd_set mask, tmask;
    char buff[MAX_LEN];
    signed_message *mess, *tcf;
    tc_final_msg *tcf_specific;
    update_message *up;
    net_sock ns;
    itrc_data *itrcd;
    seq_pair *ps;
    ordinal applied, *ord;
    byte digest[DIGEST_SIZE];
    struct timeval spines_timeout, *t;

    /* Initialize the receiving data structures */
    memset(&applied, 0, sizeof(ordinal));
    
    FD_ZERO(&mask);
    
    /* Grab the IPC information and NET information from data */
    itrcd = (itrc_data *)data;
    printf("local = %s, remote = %s, spines_ext_addr = %s, spines_ext_port = %d\n", 
            itrcd->ipc_local, itrcd->ipc_remote, itrcd->spines_ext_addr, itrcd->spines_ext_port);
    ns.ipc_s = IPC_DGram_Sock(itrcd->ipc_local);
    memcpy(ns.ipc_remote, itrcd->ipc_remote, sizeof(ns.ipc_remote));
    FD_SET(ns.ipc_s, &mask);

    /* Setup Keys. For TC, only Public here for verification of TC Signed Messages */
    OPENSSL_RSA_Init();
    OPENSSL_RSA_Read_Keys(Prime_Client_ID, RSA_CLIENT, itrcd->prime_keys_dir);
    TC_Read_Public_Key(itrcd->sm_keys_dir);
   
    /* Setup the spines timeout frequency - if disconnected, will try to reconnect
     *  this often */
    spines_timeout.tv_sec  = SPINES_CONNECT_SEC;
    spines_timeout.tv_usec = SPINES_CONNECT_USEC;

    /* Connect to spines */
    ns.sp_ext_s = -1;
    if (Type == RTU_TYPE) {
        proto = SPINES_PRIORITY;
        my_port = RTU_BASE_PORT + My_ID;
    }
    else {
        proto = SPINES_PRIORITY;
        my_port = HMI_BASE_PORT + My_ID;
    }
    ns.sp_ext_s = Spines_Sock(itrcd->spines_ext_addr, itrcd->spines_ext_port, 
                    proto, my_port);
    if (ns.sp_ext_s < 0) {
        printf("ITRC_Client: Unable to connect to Spines, trying again soon\n");
        t = &spines_timeout; 
    }
    else {
        FD_SET(ns.sp_ext_s, &mask);
        t = NULL;
    }

    while (1) {

        tmask = mask;
        num = select(FD_SETSIZE, &tmask, NULL, NULL, t);

        if (num > 0) {
            
            /* Message from Spines */
            if (ns.sp_ext_s >= 0 && FD_ISSET(ns.sp_ext_s, &tmask)) {
                ret = spines_recvfrom(ns.sp_ext_s, buff, MAX_LEN, 0, NULL, 0);
                if (ret <= 0) {
                    printf("Error in spines_recvfrom: ret = %d, dropping!\n", ret);
                    spines_close(ns.sp_ext_s);
                    FD_CLR(ns.sp_ext_s, &mask);
                    ns.sp_ext_s = -1;
                    t = &spines_timeout; 
                    continue;
                }
               
                tcf          = (signed_message *)buff;
                tcf_specific = (tc_final_msg *)(tcf + 1);

                /* VERIFY RSA Signature over whole message */
                ret = OPENSSL_RSA_Verify((unsigned char*)tcf + SIGNATURE_SIZE,
                            sizeof(signed_message) + tcf->len - SIGNATURE_SIZE,
                            (unsigned char *)tcf, tcf->machine_id, RSA_SERVER);
                if (!ret) {
                    printf("RSA_Verify Failed of Client Update from %d\n", tcf->machine_id);
                    continue;
                }

                /* Verify TC Signature */
                OPENSSL_RSA_Make_Digest(tcf_specific, 
                    sizeof(tcf_specific->ord) + sizeof(tcf_specific->payload), digest);
                if (!TC_Verify_Signature(1, tcf_specific->thresh_sig, digest)) {
                    printf("ITRC_Client: TC verify failed from CC replica %d\n", tcf->machine_id);
                    continue;
                }

                /* Extract SCADA Message */
                mess = (signed_message *)(tcf_specific->payload);
                if (!ITRC_Valid_Type(mess, TO_CLIENT)) {
                    printf("ITRC_Client: Invalid message type received from CCs, type = %d\n", mess->type);
                    continue;
                }

                ps = (seq_pair *)(mess + 1);
                nBytes = sizeof(signed_message) + (int)mess->len;
                
                /* TODO: Another sanity check on the the message type being 
                 *  appropriate for the type of client I am */
               
                ord = (ordinal *)&tcf_specific->ord;
                if (ITRC_Ord_Compare(*ord, applied) <= 0)
                    continue;
                applied = *ord;
                //printf("Applying [%u, %u of %u]\n", ord->ord_num, ord->event_idx, ord->event_tot);
                IPC_Send(ns.ipc_s, (char *)mess, nBytes, ns.ipc_remote);
            }

            /* Message from IPC Client */
            if (FD_ISSET(ns.ipc_s, &tmask)) {
                nBytes = IPC_Recv(ns.ipc_s, buff, MAX_LEN);
                if (nBytes > UPDATE_SIZE) {
                    printf("ITRC_Client: error! client message too large %d\n", nBytes);
                    continue;
                }

                if (ns.sp_ext_s == -1)
                    continue;

                ps = (seq_pair *)&buff[sizeof(signed_message)];
                mess = PKT_Construct_Signed_Message(sizeof(signed_update_message) 
                            - sizeof(signed_message));
                mess->machine_id = Prime_Client_ID;
                mess->len = sizeof(signed_update_message) - sizeof(signed_message);
                mess->type = UPDATE;
                mess->incarnation = ps->incarnation;
                up = (update_message *)(mess + 1);
                up->server_id = Prime_Client_ID;
                up->seq_num = ps->seq_num;

                memcpy((unsigned char*)(up + 1), buff, nBytes);
                /* printf("Sending Update: [%u, %u]\n", up->seq.incarnation, 
                            up->seq.seq_num); */

                /* MK: SIGN Client Update Message. Redundant, can be discarded*/
                OPENSSL_RSA_Sign( ((byte*)(up + 1)) + SIGNATURE_SIZE,
                        nBytes - SIGNATURE_SIZE,
                        (byte*)(up + 1));

                /* SIGN Message */
                OPENSSL_RSA_Sign( ((byte*)mess) + SIGNATURE_SIZE,
                        sizeof(signed_message) + mess->len - SIGNATURE_SIZE,
                        (byte*)mess );
                /*
                    MK: Currently we send to all Control Center replicas,
                    TODO: send to min(2f + k + 1, 2*(2f+2)) and test
                */
                rep = NUM_CC_REPLICA;
                for (i = 1; i <= rep; i++) {
                    dest.sin_family = AF_INET;
                    dest.sin_port = htons(SM_EXT_BASE_PORT + CC_Replicas[i-1]);
                    dest.sin_addr.s_addr = inet_addr(Ext_Site_Addrs[CC_Sites[i-1]]);
                    ret = spines_sendto(ns.sp_ext_s, mess, sizeof(signed_update_message),
                            0, (struct sockaddr *)&dest, sizeof(struct sockaddr));
                    if (ret != sizeof(signed_update_message)) {
                        printf("ITRC_Client: spines_sendto error!\n");
                        spines_close(ns.sp_ext_s);
                        FD_CLR(ns.sp_ext_s, &mask);
                        ns.sp_ext_s = -1;
                        t = &spines_timeout; 
                        break;
                    }
                }
                free(mess);
            }
        }
        else {
            ns.sp_ext_s = Spines_Sock(itrcd->spines_ext_addr, itrcd->spines_ext_port, 
                            proto, my_port);
            if (ns.sp_ext_s < 0) {
                printf("ITRC_Client: Unable to connect to Spines, trying again soon\n");
                spines_timeout.tv_sec  = SPINES_CONNECT_SEC;
                spines_timeout.tv_usec = SPINES_CONNECT_USEC;
                t = &spines_timeout; 
            }
            else {
                FD_SET(ns.sp_ext_s, &mask);
                t = NULL;
            }
        }
    }
    return NULL;
}


void *ITRC_Prime_Inject(void *data)
{
    int num, ret, nBytes, i;
    int prime_sock;
    int16u val;
    net_sock ns;
    fd_set mask, tmask;
    char buff[MAX_LEN], buff2[UPDATE_SIZE], prime_path[128];
    signed_message *mess, *mess2, *payload, *tc_final;
    signed_update_message *mess3;
    update_message *up;
    itrc_data *itrcd;
    int32u *idx;
    seq_pair *ps;
    tc_share_msg_smencrypt *tc_mess;
    tc_share_msg_smencrypt *tc_mess_smencrypt;
    struct timeval spines_timeout, *t;
    struct sockaddr_in dest;
    unsigned char enc_iv[DIGEST_SIZE_IV]; 

    /* Make sure everything is set up first */
    pthread_mutex_lock(&wait_mutex);
    while (master_ready == 0) {
        pthread_cond_wait(&wait_condition, &wait_mutex);
    }
    pthread_mutex_unlock(&wait_mutex); 

    FD_ZERO(&mask);

    /* Grab IPC info */
    itrcd = (itrc_data *)data;

    OPENSSL_RSA_Init();
    OPENSSL_RSA_Read_Keys(My_ID, RSA_SERVER, itrcd->prime_keys_dir);
    TC_Read_Public_Key(itrcd->sm_keys_dir);
    TC_Read_Partial_Key(My_ID, 1, itrcd->sm_keys_dir); /* only "1" site */

    if (Type == CC_TYPE) {
        OPENSSL_RSA_Read_Encrypt_Keys(itrcd->sm_keys_dir);
    }

    /* Connect to spines external network if CC */
    if (Type == CC_TYPE) {
        ns.sp_ext_s = ret = -1;
        while (ns.sp_ext_s < 0 || ret < 0) {

            ns.sp_ext_s = Spines_Sock(itrcd->spines_ext_addr, itrcd->spines_ext_port,
                        SPINES_PRIORITY, SM_EXT_BASE_PORT + My_ID);
            if (ns.sp_ext_s < 0) {
                sleep(SPINES_CONNECT_SEC);
                continue;
            }

            val = 2;
            ret = spines_setsockopt(ns.sp_ext_s, 0, SPINES_SET_DELIVERY, (void *)&val, sizeof(val));
            if (ret < 0) {
                spines_close(ns.sp_ext_s);
                ns.sp_ext_s = -1;
                sleep(SPINES_CONNECT_SEC);
                continue;
            }
        }
        FD_SET(ns.sp_ext_s, &mask);
    }

    /* Create a socket to receive state transfer requests from the ITRC_Master
     *  thread */
    sprintf(ns.inject_path, "%s%d", (char *)SM_IPC_INJECT, My_ID);
    ns.inject_s = IPC_DGram_Sock(ns.inject_path);
    ret = fcntl(ns.inject_s, F_SETFL, fcntl(ns.inject_s, F_GETFL, 0) | O_NONBLOCK); 
    if (ret == -1) {
        printf("Failure setting inject socket to non-blocking\n");
        exit(EXIT_FAILURE);
    }
    FD_SET(ns.inject_s, &mask);

    /* Connect to Prime */
    if (USE_IPC_CLIENT) {
        prime_sock = IPC_DGram_SendOnly_Sock();
        sprintf(prime_path, "%s%d", (char *)PRIME_REPLICA_IPC_PATH, My_ID);
        printf("Connecting to %s\n", prime_path);
    }
    else {
        // TODO - resolve TCP connection across 2 threads now. Perhaps create 2 TCP
        //      connections with Prime (similar to IPC)
        printf("TCP connections to Prime currenty not supported. Fixing soon!\n");
        exit(EXIT_FAILURE);
        /*print_addr.s_addr = My_IP;
        printf("Connecting to %s:%d\n", inet_ntoa(print_addr), PRIME_PORT + My_ID);
        prime_sock = clientTCPsock(PRIME_PORT + My_ID, My_IP); */
    }

    pthread_mutex_lock(&wait_mutex);
    inject_ready = 1;
    pthread_cond_signal(&wait_condition);
    pthread_mutex_unlock(&wait_mutex);

    while (1) {

        tmask = mask;
        num = select(FD_SETSIZE, &tmask, NULL, NULL, NULL);

        if (num > 0) {

            /* Incoming NET message External spines network */
            // MK: CC and DC are decoupled in the following code.

            if (Type == CC_TYPE && ns.sp_ext_s >= 0 && FD_ISSET(ns.sp_ext_s, &tmask)) {
                nBytes = spines_recvfrom(ns.sp_ext_s, buff, MAX_LEN, 0, NULL, 0);
                if (nBytes <= 0) {
                    printf("Disconnected from Spines?\n");
                    FD_CLR(ns.sp_ext_s, &mask);
                    spines_close(ns.sp_ext_s);

                    /* Reconnect to spines external network if CC */
                    ns.sp_ext_s = ret = -1;
                    while (ns.sp_ext_s < 0 || ret < 0) {
                        printf("Prime_Inject: Trying to reconnect to external spines\n");
                        ns.sp_ext_s = Spines_Sock(itrcd->spines_ext_addr, itrcd->spines_ext_port,
                                    SPINES_PRIORITY, SM_EXT_BASE_PORT + My_ID);
                        if (ns.sp_ext_s < 0) {
                            sleep(SPINES_CONNECT_SEC);
                            continue;
                        }

                        val = 2;
                        ret = spines_setsockopt(ns.sp_ext_s, 0, SPINES_SET_DELIVERY, (void *)&val, sizeof(val));
                        if (ret < 0) {
                            spines_close(ns.sp_ext_s);
                            ns.sp_ext_s = -1;
                            sleep(SPINES_CONNECT_SEC);
                            continue;
                        }
                    }
                    FD_SET(ns.sp_ext_s, &mask);
                    continue;
                }

                /* VERIFY Client signature on message */
                mess = (signed_message *)buff;

                

                /* Incoming Spines External Message - TC Crypto shares SMEncrypt */
                if (Type == CC_TYPE && mess->type == TC_SHARE_SMENCRYPT)
                {
                    /* Validate Message */
                    if (!ITRC_Valid_Type(mess, FROM_EXTERNAL)) {
                        printf("Prime_Inject: invalid message type (%d) from server\n", mess->type);
                        continue;
                    }

                    ret = OPENSSL_RSA_Verify((unsigned char*)mess + SIGNATURE_SIZE,
                                sizeof(signed_message) + mess->len - SIGNATURE_SIZE,
                                (unsigned char *)mess, mess->machine_id, RSA_SERVER);
                    if (!ret) {
                        printf("RSA_Verify Failed of Server TC_SHARE_SMENCRYPT from %d\n", mess->machine_id);
                        continue;
                    }

                    // printf("Prime_Inject: TC_SHARE_SMENCRYPT from %d\n", mess->machine_id);

                    tc_mess_smencrypt = (tc_share_msg_smencrypt *)(mess + 1);

                    /* 
                        MK TODO: Verify client message with client sig, if client is not sending to all CC replicas, 
                                 After verifying client message with sig, we can safely count the current replica
                                 as having received the client message. Of course, we will need to decrypt the
                                 client message first. Also, Cross check seq and client_id with what's inside the payload.
                    */
                    

                    /* Store your own share, possibly delivering afterwards if you
                     *  have enough matching TC shares to create a final signature */

                    ITRC_Insert_TC_ID_SMEncrypt(tc_mess_smencrypt, mess->machine_id, NORMAL_SEQ);
                    while (ITRC_TC_Ready_Deliver_SMEncrypt(&tc_final)) {
                        //printf("Sending stuff to prime!\n");
                        ITRC_Send_TC_Final_SMEncrypt(prime_sock, tc_final, prime_path);
                        
                        // if (ITRC_Send_TC_Final_SMEncrypt(ns.sp_ext_s, tc_final) < 0) {
                        //     printf("ITRC_Master: External spines error, try to reconnect soon\n");
                        //     free(tc_final);
                        //     spines_close(ns.sp_ext_s);
                        //     ns.sp_ext_s = -1;
                        //     t = &spines_timeout;
                        //     break;
                        // }
                        free(tc_final);
                    }

                }

                // MK: Incoming external message is a client request
                else
                {

                    /* Validate Message */
                    if (!ITRC_Valid_Type(mess, FROM_EXTERNAL)) {
                        printf("Prime_Inject: invalid message type (%d) from client\n", mess->type);
                        continue;
                    }

                    ret = OPENSSL_RSA_Verify((unsigned char*)mess + SIGNATURE_SIZE,
                                sizeof(signed_message) + mess->len - SIGNATURE_SIZE,
                                (unsigned char *)mess, mess->machine_id, RSA_CLIENT);
                    if (!ret) {
                        printf("RSA_Verify Failed of Client Update from %d\n", mess->machine_id);
                        continue;
                    }

                    // printf("Prime_Inject: NOT TC_SHARE_SMENCRYPT from %d\n", mess->machine_id);
                    
                    /*
                        MK: Perform threshold cryptography here and IPC_Send
                            should happen after TC is confirmed
                     */
                    
                    // MK: Get the update_message
                    up = (update_message *)(mess + 1);

                    // MK: Get the payload which is immediately after update_message
                    memset(buff2, 0, UPDATE_SIZE);
                    memcpy(buff2, (char *)(up + 1), UPDATE_SIZE); 
                    // buff2 = (char *)(up + 1);

                    // MK: Get the seq_pair which is after the signed_message portion of the payload 
                    ps = (seq_pair *)&buff2[sizeof(signed_message)];
                    
                    // MK: Client id immediately follows the seq_pair in RTU_DATA, HMI_COMMAND and BENCHMARK message types
                    idx = (int32u *)(ps + 1);

                    memset(mess, 0, SIGNATURE_SIZE); // MK: Reset the outer client signature

                    //MK TODO: Random Encryption
                    mess3 = (signed_update_message*) PKT_Construct_Signed_Message(sizeof(signed_update_message) - sizeof(signed_message));
                    memcpy(&mess3->header, mess, sizeof(signed_message));
                    memcpy(&mess3->update, up, sizeof(update_message));
                    memcpy(mess3->update_contents, buff2, sizeof(signed_message));
                    
                    ret = OPENSSL_RSA_IV(&buff2[sizeof(signed_message)], ((signed_message*)buff2)->len, enc_iv);

                    if(ret == -1)
                    {
                        printf("Prime_Inject: IV creation error. Dropping request...\n");
                        continue;
                    }

                    // MK: Copy the IV to the beginning of the payload and then the encrypted content
                    memcpy(&((mess3->update_contents)[sizeof(signed_message)]), enc_iv, DIGEST_SIZE_IV);

                    ret = OPENSSL_RSA_Encrypt(&buff2[sizeof(signed_message)], ((signed_message*)buff2)->len,
                        enc_iv, &((mess3->update_contents)[sizeof(signed_message)+DIGEST_SIZE_IV]));
                    
                    if(ret == -1)
                    {
                        printf("Prime_Inject: Encryption error. Dropping request...\n");
                        continue;
                    }

                    // MK: Client message length should be size of encrypted payload and size of iv
                    ((signed_message*)(mess3->update_contents))->len = ret + DIGEST_SIZE_IV;

                    // MK TODO: Simple Encryption
                    // In the following code, we will use mess3 instead of mess
                    
                    mess2 = PKT_Construct_TC_Share_Msg_SMEncrypt(ps, idx, (char *)mess3, 
                               mess3->header.len + sizeof(signed_message));
                    tc_mess = (tc_share_msg_smencrypt *)(mess2 + 1);

                    // memcpy((unsigned char*)(up + 1), mess2, mess2->len);

                    /* SIGN TC Share Message */
                    OPENSSL_RSA_Sign( ((byte*)mess2) + SIGNATURE_SIZE,
                            sizeof(signed_message) + mess2->len - SIGNATURE_SIZE,
                            (byte*)mess2);

                    /* If a CC, store your own share, possibly delivering afterwards if you
                     *  have enough matching TC shares to create a final signature */
                    if (Type == CC_TYPE) {
                        ITRC_Insert_TC_ID_SMEncrypt(tc_mess, My_ID, NORMAL_SEQ);
                        while (ITRC_TC_Ready_Deliver_SMEncrypt(&tc_final)) {
                            //printf("Sending stuff to prime!\n");
                            ITRC_Send_TC_Final_SMEncrypt(prime_sock, tc_final, prime_path);
                            
                            // if (ITRC_Send_TC_Final_SMEncrypt(ns.sp_ext_s, tc_final) < 0) {
                            //     printf("ITRC_Master: External spines error, try to reconnect soon\n");
                            //     free(tc_final);
                            //     spines_close(ns.sp_ext_s);
                            //     ns.sp_ext_s = -1;
                            //     t = &spines_timeout;
                            //     break;
                            // }
                            free(tc_final);
                        }
                    }

                    if (ns.sp_ext_s == -1)
                        continue;

                    /* CC replicas send their shares to the CC replicas */
                    for (i = 1; i <= NUM_CC_REPLICA; i++) {
                        if (CC_Replicas[i-1] == My_ID)
                            continue;
                        dest.sin_family = AF_INET;
                        dest.sin_port = htons(SM_EXT_BASE_PORT + CC_Replicas[i-1]);
                        dest.sin_addr.s_addr = inet_addr(Ext_Site_Addrs[CC_Sites[i-1]]);
                        ret = spines_sendto(ns.sp_ext_s, mess2, sizeof(signed_message) + sizeof(tc_share_msg_smencrypt),
                                    0, (struct sockaddr *)&dest, sizeof(struct sockaddr));
                        if (ret != sizeof(signed_message) + sizeof(tc_share_msg_smencrypt)) {
                            printf("ITRC_Master: spines_sendto error on TC_SHARE msg smencrypt! ret: %d \n", ret);
                            spines_close(ns.sp_ext_s);
                            FD_CLR(ns.sp_ext_s, &mask);
                            ns.sp_ext_s = -1;
                            t = &spines_timeout;
                            break;
                            /* Reconnect to spines external network if CC */
                            // ns.sp_ext_s = ret = -1;
                            // while (ns.sp_ext_s < 0 || ret < 0) {
                            //     printf("Prime_Inject: Trying to reconnect to external spines\n");
                            //     ns.sp_ext_s = Spines_Sock(itrcd->spines_ext_addr, itrcd->spines_ext_port,
                            //                 SPINES_PRIORITY, SM_EXT_BASE_PORT + My_ID);
                            //     if (ns.sp_ext_s < 0) {
                            //         sleep(SPINES_CONNECT_SEC);
                            //         continue;
                            //     }

                            //     val = 2;
                            //     ret = spines_setsockopt(ns.sp_ext_s, 0, SPINES_SET_DELIVERY, (void *)&val, sizeof(val));
                            //     if (ret < 0) {
                            //         spines_close(ns.sp_ext_s);
                            //         ns.sp_ext_s = -1;
                            //         sleep(SPINES_CONNECT_SEC);
                            //         continue;
                            //     }
                            // }
                            // FD_SET(ns.sp_ext_s, &mask);
                            // continue;
                        }
                    }
                    free(mess2);
                }

            }

            /* Message from the ITRC_Master - request for state transfer */
            if (ns.inject_s >= 0 && FD_ISSET(ns.inject_s, &tmask)) {

                /* As of now, the state transfer request from SM -> Prime only
                 * happens if the first received ordinal from Prime is ahead
                 * of what this SM was expecting. In that case, an IPC message
                 * is sent to this thread to signal Prime. If this is the only
                 * spot that the request happens in this direction, we should
                 * really have a message sent in both cases. A "1" represents
                 * that Prime should be signaled, a "0" represents that we
                 * are OK, not need for transfer - but in both cases it would
                 * allow us to cleanup the FD_SET and potentially close down
                 * this thread (in the DC case) that is no longer needed */
                
                /* Currently, just receive all of the message, but its just used
                 * as a indicator to wake up this thread and construct a state
                 * transfer request to give to Prime */
                nBytes = IPC_Recv(ns.inject_s, buff, sizeof(buff));

                /* Construct the state transfer update. Note: details get filled
                 * in later by my Prime replica */
                mess = PKT_Construct_Signed_Message(sizeof(signed_update_message) 
                            - sizeof(signed_message));
                mess->machine_id = My_ID;
                mess->len = sizeof(signed_update_message) - sizeof(signed_message);
                mess->type = UPDATE;
                up = (update_message *)(mess + 1);
                up->server_id = My_ID;
                payload = (signed_message *)(up + 1);
                payload->machine_id = My_ID;
                payload->type = PRIME_STATE_TRANSFER;
                //printf("Sending down STATE TRANSFER request!\n");

                /* SIGN Message */
                OPENSSL_RSA_Sign( ((byte*)mess) + SIGNATURE_SIZE,
                        sizeof(signed_message) + mess->len - SIGNATURE_SIZE,
                        (byte*)mess );

                /* would get blocked here if Prime stops reading */
                ret = IPC_Send(prime_sock, mess, sizeof(signed_message) + mess->len, prime_path);
                if(ret <= 0) {
                    perror("ITRC_Prime_Inject: Prime Writing error");
                    continue;
                }
                free(mess);
                FD_CLR(ns.inject_s, &mask);
                close(ns.inject_s);
                ns.inject_s = -1;
                memset(ns.inject_path, 0, sizeof(ns.inject_path));
            }
        }
    }

    return NULL;
}



void ITRC_Reset_Master_Data_Structures(int startup)
{
    int32u i;
    stdit it;
    tc_node *t_ptr, *t_del;
    st_node *s_ptr, *s_del;
    signed_message *mess;
    tc_node_smencrypt *t_ptr_smencrypt, *t_del_smencrypt; // MK TODO: Check this
    checkpoint_node *c_ptr, *c_del;
    update_node *u_ptr, *u_del;
    update_transfer_node *ut_ptr, *ut_del;

    /* Cleanup any leftover in the TC queue, then reset to init values */
    if (!startup) {
        t_ptr = &tcq_pending.head;
        while (t_ptr->next != NULL) {
            t_del = t_ptr->next;
            t_ptr->next = t_del->next;
            tcq_pending.size--;
            free(t_del);
        } 
    }
    memset(&tcq_pending, 0, sizeof(tc_queue));
    tcq_pending.tail = &tcq_pending.head;
   
    /* Cleanup any leftover in the ST queue, then reset to init values */
    if (!startup) {
        s_ptr = &stq_pending.head;
        while (s_ptr->next != NULL) {
            s_del = s_ptr->next;
            s_ptr->next = s_del->next;
            stq_pending.size--;
            free(s_del);
        }
    }
    memset(&stq_pending, 0, sizeof(st_queue));
    stq_pending.tail = &stq_pending.head;

    /* MK: Cleanup any leftover in the Checkpoints queue, then reset to init values */
    if (!startup) {
        c_ptr = &checkpoints.head;
        while (c_ptr->next != NULL) {
            c_del = c_ptr->next;
            c_ptr->next = c_del->next;
            checkpoints.size--;
            free(c_del);
        }
    }
    memset(&checkpoints, 0, sizeof(checkpoint_queue));
    checkpoints.tail = &checkpoints.head;

    /* MK: Cleanup any leftover in the Updates queue, then reset to init values */
    if (!startup) {
        u_ptr = &updates.head;
        while (u_ptr->next != NULL) {
            u_del = u_ptr->next;
            u_ptr->next = u_del->next;
            updates.size--;
            free(u_del);
        }
    }
    memset(&updates, 0, sizeof(updates_queue));
    updates.tail = &updates.head;

    /* MK: Cleanup any leftover in the Updates Transfers queue, then reset to init values */
    if (!startup) {
        ut_ptr = &update_transfers.head;
        while (ut_ptr->next != NULL) {
            ut_del = ut_ptr->next;
            ut_ptr->next = ut_del->next;
            update_transfers.size--;
            free(ut_del);
        }
    }
    memset(&update_transfers, 0, sizeof(update_transfer_queue));
    update_transfers.tail = &update_transfers.head;


    // MK TODO: Check this
    for(i=0; i <= MAX_EMU_RTU + NUM_HMI + 1; i++)
    {
        /* Cleanup any leftover in the TC queue, then reset to init values */
        if (!startup) {
            t_ptr_smencrypt = &tcq_pending_smencrypt[i].head;
            while (t_ptr_smencrypt->next != NULL) {
                t_del_smencrypt = t_ptr_smencrypt->next;
                t_ptr_smencrypt->next = t_del_smencrypt->next;
                tcq_pending_smencrypt[i].size--;
                free(t_del_smencrypt);
            } 
        }
        memset(&tcq_pending_smencrypt[i], 0, sizeof(tc_queue_smencrypt));
        tcq_pending_smencrypt[i].tail = &tcq_pending_smencrypt[i].head;
    }


    /* Cleanup any leftover in the ord_queue, then destruct and reconstruct. Here, the
     * values stored are just copies of ordinal information, so the memory does not 
     * need to be free'd (like with the pending updates below) */
    if (!startup) {
        stddll_clear(&ord_queue);
        stddll_destruct(&ord_queue);
    }
    stddll_construct(&ord_queue, sizeof(ordinal));

    /* Cleanup any leftover in the pending_updates, then destruct and reconstruct */ 
    if (!startup) {
        for (stddll_begin(&pending_updates, &it); !stddll_is_end(&pending_updates, &it); stdit_next(&it)) {
            mess = *(signed_message **)stdit_val(&it);
            free(mess);
        }
        stddll_clear(&pending_updates);
        stddll_destruct(&pending_updates);
    }
    stddll_construct(&pending_updates, sizeof(signed_message*));

    /* Cleanup any leftover in the pending_transfers, then destruct and reconstruct */ 
    if (!startup) {
        for (stddll_begin(&pending_transfers, &it); !stddll_is_end(&pending_transfers, &it); stdit_next(&it)) {
            mess = *(signed_message **)stdit_val(&it);
            free(mess);
        }
        stddll_clear(&pending_transfers);
        stddll_destruct(&pending_transfers);
    }
    stddll_construct(&pending_transfers, sizeof(signed_message*));

    memset(&applied_ord, 0, sizeof(ordinal));
    memset(&recvd_ord, 0, sizeof(ordinal));
    memset(&recovery_ord, 0, sizeof(ordinal));
    collecting_signal = 0;
    completed_transfer = 0;
    print_target = PRINT_PROGRESS;

    /* Initialize SCADA State (latest updates) */
    for (i = 0; i <= MAX_EMU_RTU + NUM_HMI; i++) {
        memset(&up_hist[i], 0, sizeof(update_history));
    }
}

/* Intrusion Tolerant Reliable Channel Master (SCADA Master) Implementation */
void *ITRC_Master(void *data) 
{
    int i, j, num, ret, nBytes, pending_ut_count, target;
    int prime_sock;
    seq_pair zero_ps = {0, 0};
    net_sock ns;
    fd_set mask, tmask;
    char buff[MAX_LEN], buff2[MAX_LEN], prime_client_path[128];
    struct sockaddr_in dest;
    signed_message *mess, *scada_mess, *tc_final, *mess2, *checkpoint_req;
    update_message * up;
    client_response_message *res;
    itrc_data *itrcd;
    tc_share_msg *tc_mess;
    tc_share_msg_smencrypt *tc_mess_smencrypt;
    state_xfer_msg *st_mess;
    checkpoint_msg *cp_mess;
    update_transfer_msg *up_mess;
    stdit it;
    ordinal ord_save;
    int32u recvd_first_ordinal;
    struct timeval spines_timeout, *t;
    int32u *idx;
    seq_pair *ps;
    char ciphertext[CHECKPOINT_PAYLOAD_SIZE];
    unsigned char enc_iv[DIGEST_SIZE_IV];

    // Trying to ignore SIGPIP error
    //signal(SIGPIPE, SIG_IGN);

    /* Parse JSON to make ds for corresponding sub for rtu */
    key_value_init();
    char * buffer = config_into_buffer();
    cJSON * root = cJSON_Parse(buffer);
    free(buffer);
    cJSON * locations = cJSON_GetObjectItem(root, "locations");
    for(i = 0; i < cJSON_GetArraySize(locations); i++) {
        cJSON * loc = cJSON_GetArrayItem(locations, i);
        int loc_num = cJSON_GetObjectItem(loc, "ID")->valueint;
        cJSON * rtus = cJSON_GetObjectItem(loc, "rtus");
        for(j = 0; j < cJSON_GetArraySize(rtus); j++) {
            cJSON * rtu = cJSON_GetArrayItem(rtus, j);
            int rtu_id = cJSON_GetObjectItem(rtu, "ID")->valueint;
            //printf("Adding %d, %d to KEY_VALUE STORE\n", rtu_id, loc_num);
            key_value_insert(rtu_id, loc_num);
        }
    }

    FD_ZERO(&mask);

    /* Grab IPC info */
    itrcd = (itrc_data *)data;
    ns.ipc_s = IPC_DGram_Sock(itrcd->ipc_local);
    memcpy(ns.ipc_remote, itrcd->ipc_remote, sizeof(ns.ipc_remote));
    FD_SET(ns.ipc_s, &mask);

    /* Read Keys */
    OPENSSL_RSA_Init();
    OPENSSL_RSA_Read_Keys(My_ID, RSA_SERVER, itrcd->prime_keys_dir);
    TC_Read_Public_Key(itrcd->sm_keys_dir);
    TC_Read_Partial_Key(My_ID, 1, itrcd->sm_keys_dir); /* only "1" site */

    if (Type == CC_TYPE) {
        OPENSSL_RSA_Read_Encrypt_Keys(itrcd->sm_keys_dir);
    }

    spines_timeout.tv_sec  = SPINES_CONNECT_SEC;
    spines_timeout.tv_usec = SPINES_CONNECT_USEC;

    // MK: Modifying this remove optimization and check update_transfers regularly
    spines_timeout.tv_sec  = 0;
    spines_timeout.tv_usec = 10000;
    t = &spines_timeout;

    // All replicas connect to internal network as send/recv for state transfer
    ns.sp_int_s = -1;
    ns.sp_int_s = Spines_Sock(itrcd->spines_int_addr, itrcd->spines_int_port,
                        SPINES_PRIORITY, SM_INT_BASE_PORT + My_ID);
    if (ns.sp_int_s < 0) {
        printf("ITRC_Master: Unable to connect to internal Spines, trying again soon\n");
        t = &spines_timeout;
    }
    else {
        FD_SET(ns.sp_int_s, &mask);
    }

    /* Connect to spines external network if CC */
    if (Type == CC_TYPE) {
        ns.sp_ext_s = -1;
        ns.sp_ext_s = Spines_SendOnly_Sock(itrcd->spines_ext_addr, itrcd->spines_ext_port,
                    SPINES_PRIORITY);
        if (ns.sp_ext_s < 0) {
            printf("ITRC_Master: Unable to connect to external Spines, trying again soon\n");
            t = &spines_timeout;
        }
    }

    /* Setup RTUs/HMIs/Benchmarks */
    for (i = 0; i <= MAX_EMU_RTU + NUM_HMI; i++) {
        progress[i] = zero_ps;
        //dup_bench[i] = 0;
    }

    /* Create a socket to send state transfer requests to the inject thread */
    ns.inject_s = IPC_DGram_SendOnly_Sock();
    sprintf(ns.inject_path, "%s%d", (char *)SM_IPC_INJECT, My_ID);
    ret = fcntl(ns.inject_s, F_SETFL, fcntl(ns.inject_s, F_GETFL, 0) | O_NONBLOCK); 
    if (ret == -1) {
        printf("Failure setting inject socket to non-blocking\n");
        exit(EXIT_FAILURE);
    }

    /* Connect to Prime */
    if (USE_IPC_CLIENT) {
        sprintf(prime_client_path, "%s%d", (char *)PRIME_CLIENT_IPC_PATH, My_ID);
        prime_sock = IPC_DGram_Sock(prime_client_path);
    }
    else {
        // TODO - resolve TCP connection across 2 threads now. Perhaps create 2 TCP
        //      connections with Prime (similar to IPC)
        printf("TCP connections to Prime currenty not supported. Fixing soon!\n");
        exit(EXIT_FAILURE);
        /*print_addr.s_addr = My_IP;
        printf("Connecting to %s:%d\n", inet_ntoa(print_addr), PRIME_PORT + My_ID);
        prime_sock = clientTCPsock(PRIME_PORT + My_ID, My_IP); */
   }
   if (prime_sock <= 0) {
        printf("Could not connect to Prime replica!\n");
        exit(EXIT_FAILURE);
    }
    FD_SET(prime_sock, &mask);

    ITRC_Reset_Master_Data_Structures(1);
    recvd_first_ordinal = 0;

    /* Keys are read, connections are established -- wake up the Prime injector */
    pthread_mutex_lock(&wait_mutex);
    master_ready = 1;
    pthread_cond_signal(&wait_condition);
    pthread_mutex_unlock(&wait_mutex);

    while (inject_ready == 0) {
        pthread_cond_wait(&wait_condition, &wait_mutex);
    }
    pthread_mutex_unlock(&wait_mutex); 

    while (1) {

        // MK: Check and send a portion of the update transfers first
        /* Replay any queued pending update_transfers */
        pending_ut_count = 0;
        for (stddll_begin(&pending_transfers, &it); !stddll_is_end(&pending_transfers, &it) && (pending_ut_count < 3);) {
            
            pending_ut_count += 1;

            mess = *(signed_message **)stdit_val(&it);
            target = mess->machine_id;
            mess->machine_id = My_ID;

            //send the update to the target
            dest.sin_family = AF_INET;
            dest.sin_port = htons(SM_INT_BASE_PORT + target);
            dest.sin_addr.s_addr = inet_addr(Int_Site_Addrs[All_Sites[target-1]]);
            ret = spines_sendto(ns.sp_int_s, mess, sizeof(signed_message) + mess->len,
                        0, (struct sockaddr *)&dest, sizeof(struct sockaddr));
            if (ret != (int)(sizeof(signed_message) + mess->len)) {
                printf("ITRC_Master: spines_sendto error on UPDATE_TRANSFER msg in pending_transfers!\n");

                // MK TODO: need the following?
                // spines_close(ns.sp_int_s);
                // FD_CLR(ns.sp_int_s, &mask);
                // ns.sp_int_s = -1;
                // t = &spines_timeout;
            }

            free(mess);
            stddll_erase(&pending_transfers, &it);
        }

        tmask = mask;
        num = select(FD_SETSIZE, &tmask, NULL, NULL, t);

        if (num > 0) {

            /* Message from Prime (Post Ordering) */
            if (FD_ISSET(prime_sock, &tmask)) {
                nBytes = IPC_Recv(prime_sock, buff, sizeof(buff));
                if (nBytes <= 0) {
                    perror("ITRC_Master: Prime Reading error");
                    close(prime_sock);
                    FD_CLR(prime_sock, &mask);
                    exit(EXIT_FAILURE);
                }
                mess = (signed_message *)buff;
                res = (client_response_message *)(mess + 1);
                scada_mess = (signed_message *)(res + 1);

                //printf("Prime [%d]: %d of %d\n", res->ord_num, res->event_idx, res->event_tot);

                /* Check for valid message type */
                /* We don't validate messages from Prime at this level, since
                 * even if the content of the message is invalid (and we don't
                 * want to apply it), we still want to advance our received
                 * Prime ordinal correctly. Instead, we'll do this in
                 * Process_Prime_Ordinal and treat it as no-op if it turns out
                 * to be invalid. Note that we should be checking that the
                 * signed_message and client_response headers are valid before
                 * getting to this point though. */

                /*if (!ITRC_Valid_Type(scada_mess, FROM_PRIME)) {
                    printf("ITRC_Master: Invalid message from Prime, type = %d\n", scada_mess->type);
                    continue;
                }*/
                
                /* Grab the ordinal information */
                ord_save.ord_num   = res->ord_num;
                ord_save.event_idx = res->event_idx;
                ord_save.event_tot = res->event_tot;

                /* Check if we received a SYSTEM RESET message from Prime, which occurs on
                 * the initial startup or when system assumptions are violated */
                if (scada_mess->type == PRIME_SYSTEM_RESET) {
                    assert(ord_save.ord_num == 0);

                    printf("Processed PRIME_SYSTEM_RESET @ ITRC\n");
                    
                    /* Reset data structures */
                    ITRC_Reset_Master_Data_Structures(0);

                    if(Type==CC_TYPE)
                    {
                        /* Send the SYSTEM RESET message to the Scada Master */
                        scada_mess = PKT_Construct_Signed_Message(0);
                        scada_mess->machine_id = My_ID;
                        scada_mess->len = 0;
                        scada_mess->type = SYSTEM_RESET;
                        IPC_Send(ns.ipc_s, (void *)scada_mess, sizeof(signed_message), ns.ipc_remote);
                    }

                    
                    continue;
                }

                /* If this is the first ordinal you get from Prime and its further ahead than
                 * you were expecting, request a state transfer */
                if (recvd_first_ordinal == 0 && !ITRC_Ord_Consec(recvd_ord, ord_save)) {
                    IPC_Send(ns.inject_s, (void *)&ns.inject_s, sizeof(ns.inject_s), ns.inject_path);
                }
                recvd_first_ordinal = 1;

                /* Check if duplicate/old ordinal coming from Prime. Maybe all of Prime was 
                 * restarted from ordinal 1 - if so, we need to restart this to sync back up 
                 * and accept the restarted Prime ordinals */
                if (ITRC_Ord_Compare(ord_save, recvd_ord) <= 0) {
                    printf("ITRC_Master: Old Prime ordinal - did Prime start from scratch?\n");
                    continue;
                }
                
                ITRC_Process_Prime_Ordinal(ord_save, mess, &ns);
                if (ns.sp_ext_s == -1) {
                    t = &spines_timeout;
                }

                /* If we completed a state transfer from this ordinal, see if there are any
                 * pending updates that can now be applied */
                if (completed_transfer == 1) {
                    assert(collecting_signal == 0);
                    completed_transfer = 0;

                    /* Replay any queued pending messages now that we're done collecting anything */
                    for (stddll_begin(&pending_updates, &it); !stddll_is_end(&pending_updates, &it) && !collecting_signal;) {
                        mess = *(signed_message **)stdit_val(&it);
                        res = (client_response_message *)(mess + 1);
                        scada_mess = (signed_message *)(res + 1);
    
                        ord_save.ord_num   = res->ord_num;
                        ord_save.event_idx = res->event_idx;
                        ord_save.event_tot = res->event_tot;
                        
                        if (ITRC_Ord_Compare(ord_save, recvd_ord) > 0)  {
                            ITRC_Process_Prime_Ordinal(ord_save, mess, &ns);
                            if (ns.sp_ext_s == -1) {
                                t = &spines_timeout;
                            }
                        }
                        free(mess);
                        stddll_erase(&pending_updates, &it);
                    }
                }

                /* MK:  New checkpoint is created by Control Center replicas after processing 
                        prime ordinal and after applying updates. This is OK as long as prime 
                        and scada master are not separated. Data Center replicas only check
                        the checkpoints queue for garbage collection.
                */
                if(ITRC_Ord_Checkpoint_Check(recvd_ord) && (Type == CC_TYPE))
                {
                    stddll_push_back(&ord_queue, &recvd_ord); // MK: Why do we need to do this here?
                    checkpoint_req = PKT_Construct_Create_Checkpoint_Msg(recvd_ord, progress);
                    nBytes = sizeof(signed_message) + checkpoint_req->len;
                    IPC_Send(ns.ipc_s, (void *)checkpoint_req, nBytes, ns.ipc_remote);
                    free(checkpoint_req);
                }
                else if (ITRC_Ord_Checkpoint_Check(recvd_ord) && (Type == DC_TYPE))
                {
                    // update applied ord, otherwise checkpoints will not be checked correctly
                    // memcpy($applied_ord, $recvd_ord, sizeof(ordinal));

                    // MK: check the checkpoints queue
                    ITRC_Check_CHECKPOINT(recvd_ord, &ns);
                }

            }

            /* Incoming IPC message */
            // MK: Decoupling CC and DC
            if ((Type == CC_TYPE) && FD_ISSET(ns.ipc_s, &tmask)) {
                nBytes = IPC_Recv(ns.ipc_s, buff, MAX_LEN);
                scada_mess = (signed_message *)buff;
                //seq_no = (int32u *)(scada_mess + 1);
                
                if (!ITRC_Valid_Type(scada_mess, FROM_SM_MAIN)) {
                    printf("ITRC_Master: invalid type %d from SM_MAIN\n", scada_mess->type);
                    continue;
                }

                /* Could check that we haven't already sent a share for this message ID, but
                 * this is coming from ourselves, ok for now */

                /* Get the saved ordinal from the queue */
                assert(stddll_size(&ord_queue) > 0);
                stddll_begin(&ord_queue, &it);
                ord_save = *(ordinal *)stdit_val(&it);
                stddll_pop_front(&ord_queue);

                /* MK: If popped ordinal is smaller than recovery_ord, then we are in 
                 recovering mode. So, ignore it */
                if (ITRC_Ord_Compare(ord_save, recovery_ord) <= 0)
                {
                        continue;
                }

                /* printf("popped off ord: [%u, %u of %u]\n", ord_save.ord_num, ord_save.event_idx, 
                          ord_save.event_tot); */

                /* TODO - is it possible that we got a message back from the SM after we already
                 * jumped past this ordinal? If so, should we throw away message and ordinal that
                 * we pulled off the queue? */

                if (scada_mess->type == CHECKPOINT) {
                   
                    if (ns.sp_int_s == -1)
                        continue;

                    cp_mess = (checkpoint_msg *)(scada_mess + 1);
                    cp_mess->ord = ord_save;

                    // MK: update the applied ordinal, otherwise this checkpoint cannot be inserted
                    //memcpy($applied_ord, $ord_save, sizeof(ordinal));

                    memset(ciphertext, 0, CHECKPOINT_PAYLOAD_SIZE);

                    ret = OPENSSL_RSA_IV(cp_mess->payload, cp_mess->state_size, enc_iv);

                    if(ret == -1)
                    {
                        printf("ITRC_Master: IV creation error. Dropping request...\n");
                        continue;
                    }

                    ret = OPENSSL_RSA_Encrypt(cp_mess->payload, cp_mess->state_size,
                            enc_iv, ciphertext);
                    if(ret == -1)
                    {
                        printf("ITRC_Master: Encrypting checkpoint failed...\n");
                        continue;
                    }

                    // MK TODO: Encrypt latest_updates and client_idx in cp_mess when we separate DC from CC.
                    memset(cp_mess->payload, 0, CHECKPOINT_PAYLOAD_SIZE);
                    // MK: Copy the iv first and then the ciphertext, then set state_size to sum of both sizes
                    memcpy(cp_mess->payload, enc_iv, DIGEST_SIZE_IV);
                    memcpy(&((cp_mess->payload)[DIGEST_SIZE_IV]), ciphertext, ret);
                    cp_mess->state_size = ret + DIGEST_SIZE_IV;

                    /* printf("  POP ord: [%u, %u of %u] for ST to %u\n", ord_save.ord_num, ord_save.event_idx, 
                          ord_save.event_tot, st_mess->target); */

                    /* Sign Checkpoint Message */ 
                    OPENSSL_RSA_Sign( ((byte*)scada_mess) + SIGNATURE_SIZE,
                                      sizeof(signed_message) + scada_mess->len - SIGNATURE_SIZE,
                                      (byte*)scada_mess);

                    /* printf("  sending ST to %d on ord [%u,%u/%u]\n", st_mess->target,
                            st_mess->ord.ord_num, st_mess->ord.event_idx, st_mess->ord.event_tot); */

                    // MK: Enter the checkpoint to my queue
                    ITRC_Insert_CHECKPOINT(scada_mess);

                    // MK: Check if we can correct checkpoint
                    ITRC_Check_CHECKPOINT(cp_mess->ord, &ns);
                    
                    /* Send the checkpoint message to all the replicas */
                    for (i = 1; i <= NUM_SM; i++) {
                        if (i == My_ID)
                            continue;
                        //printf("ITRC_Master: sending checkpoint from %d to %d\n", (int32u)My_ID, i);
                        dest.sin_family = AF_INET;
                        dest.sin_port = htons(SM_INT_BASE_PORT + i);
                        dest.sin_addr.s_addr = inet_addr(Int_Site_Addrs[All_Sites[i-1]]);
                        ret = spines_sendto(ns.sp_int_s, scada_mess, sizeof(signed_message) + scada_mess->len,
                                    0, (struct sockaddr *)&dest, sizeof(struct sockaddr));
                        if (ret != sizeof(signed_message) + scada_mess->len) {
                            printf("ITRC_Master: spines_sendto error on CHECKPOINT msg!\n");
                            spines_close(ns.sp_int_s);
                            FD_CLR(ns.sp_int_s, &mask);
                            ns.sp_int_s = -1;
                            t = &spines_timeout;
                            break;
                        }
                    }
                    continue;
                }

               
                /* Otherwise, this is a normal SCADA message for a client */
                mess = PKT_Construct_TC_Share_Msg(ord_save, (char *)scada_mess, nBytes);
                tc_mess = (tc_share_msg *)(mess + 1);

                /* SIGN TC Share Message */
                OPENSSL_RSA_Sign( ((byte*)mess) + SIGNATURE_SIZE,
                        sizeof(signed_message) + mess->len - SIGNATURE_SIZE,
                        (byte*)mess);

                /* If a CC, store your own share, possibly delivering afterwards if you
                 *  have enough matching TC shares to create a final signature */
                if (Type == CC_TYPE) {
                    ITRC_Insert_TC_ID(tc_mess, My_ID, NORMAL_ORD);
                    while (ITRC_TC_Ready_Deliver(&tc_final, &ns)) {
                        if (ITRC_Send_TC_Final(ns.sp_ext_s, tc_final) < 0) {
                            printf("ITRC_Master: External spines error, try to reconnect soon\n");
                            free(tc_final);
                            spines_close(ns.sp_ext_s);
                            ns.sp_ext_s = -1;
                            t = &spines_timeout;
                            break;
                        }
                        free(tc_final);
                    }
                }

                if (ns.sp_int_s == -1)
                    continue;

                /* Both CC and DC replicas send their shares to the CC replicas */
                for (i = 1; i <= NUM_CC_REPLICA; i++) {
                    if (CC_Replicas[i-1] == My_ID)
                        continue;
                    dest.sin_family = AF_INET;
                    dest.sin_port = htons(SM_INT_BASE_PORT + CC_Replicas[i-1]);
                    dest.sin_addr.s_addr = inet_addr(Int_Site_Addrs[CC_Sites[i-1]]);
                    ret = spines_sendto(ns.sp_int_s, mess, sizeof(signed_message) + sizeof(tc_share_msg),
                                0, (struct sockaddr *)&dest, sizeof(struct sockaddr));
                    if (ret != sizeof(signed_message) + sizeof(tc_share_msg)) {
                        printf("ITRC_Master: spines_sendto error on TC_SHARE msg!\n");
                        spines_close(ns.sp_int_s);
                        FD_CLR(ns.sp_int_s, &mask);
                        ns.sp_int_s = -1;
                        t = &spines_timeout;
                        break;
                    }
                }
                free(mess);
            }

            /* Incoming Spines Internal Message - TC Crypto shares or State Xfer */
            if (ns.sp_int_s >= 0 && FD_ISSET(ns.sp_int_s, &tmask)) {
                nBytes = spines_recvfrom(ns.sp_int_s, buff, MAX_LEN, 0, NULL, 0);
                if (nBytes <= 0) {
                    printf("Error in spines_recvfrom: nBytes = %d, dropping!\n", nBytes);
                    spines_close(ns.sp_int_s);
                    FD_CLR(ns.sp_int_s, &mask);
                    ns.sp_int_s = -1;
                    t = &spines_timeout; 
                    continue;
                }

                mess = (signed_message *)buff;

                if (!ITRC_Valid_Type(mess, FROM_INTERNAL)) {
                    printf("ITRC_Master: invalid type %u from internal network\n", mess->type);
                    continue;
                }

                /* VERIFY Message */
                ret = OPENSSL_RSA_Verify((unsigned char*)mess + SIGNATURE_SIZE,
                        sizeof(signed_message) + mess->len - SIGNATURE_SIZE,
                        (unsigned char *)mess, mess->machine_id, RSA_SERVER);
                if (!ret) {
                    printf("RSA_Verify of Internal Spines Msg (type %d) Failed from %d\n", 
                                mess->type, mess->machine_id);
                    continue;
                }

                if (Type == CC_TYPE && mess->type == TC_SHARE) {
                    tc_mess = (tc_share_msg *)(mess + 1);
                    
                    /* Try to insert the TC share from this replica */
                    ITRC_Insert_TC_ID(tc_mess, mess->machine_id, NORMAL_ORD);
                    while (ITRC_TC_Ready_Deliver(&tc_final, &ns)) {
                        if (ITRC_Send_TC_Final(ns.sp_ext_s, tc_final) < 0) {
                            printf("ITRC_Master: External spines error, try to reconnect soon\n");
                            free(tc_final);
                            spines_close(ns.sp_ext_s);
                            ns.sp_ext_s = -1;
                            t = &spines_timeout;
                            break;
                        }
                        free(tc_final);
                    }
                }
                else if (mess->type == CHECKPOINT) {

                    cp_mess = (checkpoint_msg *)(mess + 1);

                    /* Try to insert the checkpoint from this replica */
                    // printf("Recv CHECKPOINT message from %d about [%u:%u/%u]\n", 
                    //         mess->machine_id, cp_mess->ord.ord_num, cp_mess->ord.event_idx, 
                    //         cp_mess->ord.event_tot);

                    // MK: Message already verified above, so we can just insert it in the queue
                    ITRC_Insert_CHECKPOINT(mess);
                    ITRC_Check_CHECKPOINT(cp_mess->ord, &ns);
                    if(collecting_signal == 1 && ITRC_Check_Checkpoint_Updates_Ready())
                    {
                        assert(completed_transfer == 0);
                        ITRC_Apply_Checkpoint_Updates(&ns);
                        /* If we completed a state transfer from this share, see if there are any
                         * pending updates that can now be applied */
                        if (completed_transfer == 1) {
                            assert(collecting_signal == 0);
                            completed_transfer = 0;

                            /* Replay any queued pending messages now that we're done collecting anything */
                            for (stddll_begin(&pending_updates, &it); !stddll_is_end(&pending_updates, &it) && !collecting_signal;) {
                                mess = *(signed_message **)stdit_val(&it);
                                res = (client_response_message *)(mess + 1);
                                scada_mess = (signed_message *)(res + 1);
            
                                ord_save.ord_num   = res->ord_num;
                                ord_save.event_idx = res->event_idx;
                                ord_save.event_tot = res->event_tot;
                                
                                if (ITRC_Ord_Compare(ord_save, recvd_ord) > 0)  {
                                    //printf("  Process Pending on %d,%d/%d\n",
                                    //            ord_save.ord_num, ord_save.event_idx, ord_save.event_tot);
                                    ITRC_Process_Prime_Ordinal(ord_save, mess, &ns);
                                    if (ns.sp_ext_s == -1) {
                                        t = &spines_timeout;
                                    }
                                }
                                free(mess);
                                stddll_erase(&pending_updates, &it);
                            }
                        }
                        printf("ITRC_Master: State Transfer completed up to applied_ord [%u:%u/%u] and recvd_ord [%u:%u/%u]\n", 
                            applied_ord.ord_num, applied_ord.event_idx, applied_ord.event_tot,
                            recvd_ord.ord_num, recvd_ord.event_idx, recvd_ord.event_tot);
                    }

                }
                else if (mess->type == UPDATE_TRANSFER) {
                    up_mess = (update_transfer_msg *)(mess + 1);
                    /* Try to insert update from this replica */
                    // printf("Recv UPDATE_TRANSFER message from %d about [%u:%u/%u]\n", 
                    //         mess->machine_id, up_mess->ord.ord_num, up_mess->ord.event_idx, 
                    //         up_mess->ord.event_tot);

                    // MK: Message already verified above, so we can just insert it in the queue
                    ITRC_Insert_UPDATE_TRANSFER(mess);
                    if(collecting_signal == 1 && ITRC_Check_Checkpoint_Updates_Ready())
                    {
                        assert(completed_transfer == 0);
                        ITRC_Apply_Checkpoint_Updates(&ns);
                        /* If we completed a state transfer from this share, see if there are any
                         * pending updates that can now be applied */
                        if (completed_transfer == 1) {
                            assert(collecting_signal == 0);
                            completed_transfer = 0;

                            /* Replay any queued pending messages now that we're done collecting anything */
                            for (stddll_begin(&pending_updates, &it); !stddll_is_end(&pending_updates, &it) && !collecting_signal;) {
                                // printf("ITRC_Master: Looping in pending_updates...\n");
                                mess = *(signed_message **)stdit_val(&it);
                                res = (client_response_message *)(mess + 1);
                                scada_mess = (signed_message *)(res + 1);
            
                                ord_save.ord_num   = res->ord_num;
                                ord_save.event_idx = res->event_idx;
                                ord_save.event_tot = res->event_tot;
                                
                                if (ITRC_Ord_Compare(ord_save, recvd_ord) > 0)  {
                                    //printf("  Process Pending on %d,%d/%d\n",
                                    //            ord_save.ord_num, ord_save.event_idx, ord_save.event_tot);
                                    ITRC_Process_Prime_Ordinal(ord_save, mess, &ns);
                                    if (ns.sp_ext_s == -1) {
                                        t = &spines_timeout;
                                    }
                                }
                                free(mess);
                                stddll_erase(&pending_updates, &it);
                            }
                        }
                        printf("ITRC_Master: State Transfer completed up to applied_ord [%u:%u/%u] and recvd_ord [%u:%u/%u]\n", 
                            applied_ord.ord_num, applied_ord.event_idx, applied_ord.event_tot,
                            recvd_ord.ord_num, recvd_ord.event_idx, recvd_ord.event_tot);
                    }

                }

                else {
                    printf("Invalid message on spines_internal. rep_type = %d, "
                            "mess_type = %d\n", Type, mess->type);
                }
            }
        }
        else {
            // MK: Removing this optimization so that we check update_transfers regularly
            spines_timeout.tv_sec  = 0;
            spines_timeout.tv_usec = 10000;
            t = &spines_timeout;

            if (ns.sp_int_s == -1) {
                // All replicas connect to internal network as send/recv
                ns.sp_int_s = Spines_Sock(itrcd->spines_int_addr, itrcd->spines_int_port,
                                SPINES_PRIORITY, SM_INT_BASE_PORT + My_ID);
                if (ns.sp_int_s < 0) {
                    printf("ITRC_Master: Unable to connect to internal Spines, trying again soon\n");
                    spines_timeout.tv_sec  = 0; //SPINES_CONNECT_SEC;
                    spines_timeout.tv_usec = 10000; //SPINES_CONNECT_USEC;
                    t = &spines_timeout;
                }
                else {
                    FD_SET(ns.sp_int_s, &mask);
                }
            }
            
            if (ns.sp_ext_s == -1) {
                /* Connect to spines external network if CC */
                if (Type == CC_TYPE) {
                    ns.sp_ext_s = Spines_SendOnly_Sock(itrcd->spines_ext_addr, itrcd->spines_ext_port,
                                SPINES_PRIORITY);
                    if (ns.sp_ext_s < 0) {
                        printf("ITRC_Master: Unable to connect to external Spines, trying soon\n");
                        spines_timeout.tv_sec  = 0; // SPINES_CONNECT_SEC;
                        spines_timeout.tv_usec = 10000; //SPINES_CONNECT_USEC;
                        t = &spines_timeout;
                    }
                }
            }
        }
    }
  
    /* Should do some cleanup if we ever close gracefully, even if from
     * catching interrupt signal */
    stddll_destruct(&ord_queue);
    return NULL;
}


void ITRC_Process_Prime_Ordinal(ordinal o, signed_message *mess, net_sock *ns)
{
    int nBytes, i, ret;
    char duplicate, valid_content;
    int32u *idx;
    seq_pair *ps;
    client_response_message *res;
    signed_message *scada_mess, *encrypted_scada_mess, *tc_final, *state_req, *pend_mess;
    tc_share_msg tc_skip_msg;
    state_xfer_msg st_dummy_msg;
    update_transfer_msg *cp_ut_mess;
    st_node *s_ptr, *s_del;
    checkpoint_node *c_ptr;
    update_node *u_ptr;
    struct sockaddr_in dest;
    char buff[UPDATE_SIZE];

    encrypted_scada_mess = NULL;

    res = (client_response_message *)(mess + 1);
    scada_mess = (signed_message *)(res + 1);

    // MK: Unencryption of scada message
    // MK: Decoupling CC and DC
    if(scada_mess->len > 0 && (Type == CC_TYPE))
    {
        memset(buff, 0, UPDATE_SIZE);
        memcpy(buff, scada_mess, sizeof(signed_message));
        /*
            MK: Start of enc payload is ((char*)(scada_mess+1))+DIGEST_SIZE_IV
                IV (enc_iv) is at (unsigned char*)(scada_mess+1)
                scada_mess->len contains both sizes
        */
        ret = OPENSSL_RSA_Decrypt(((char*)(scada_mess+1))+DIGEST_SIZE_IV, 
                                  scada_mess->len - DIGEST_SIZE_IV,
                                  (unsigned char*)(scada_mess+1), 
                                  &buff[sizeof(signed_message)]);
        if(ret == -1)
        {
            printf("ITRC_Process_Prime_Ordinal: Decryption failed...\n");
            return;
        }
        encrypted_scada_mess = scada_mess;
        scada_mess = (signed_message*) buff;
        scada_mess->len = ret; 
    }

    /* If we are collecting state, buffer these messages for later in the
     * pending messages queue */
    if (collecting_signal) {
        pend_mess = PKT_Construct_Signed_Message(sizeof(client_response_message) + UPDATE_SIZE);
        memcpy(pend_mess, mess, sizeof(signed_message) + mess->len);
        stddll_push_back(&pending_updates, &pend_mess);
        printf("  Adding [%u,%u/%u] to pending\n", o.ord_num, o.event_idx, o.event_tot);
        return;
    }

    /* If this message is not the next expected one, and it is not a state
     * transfer for me, throw it away (we'll need to get caught up with a state
     * transfer later) */
    // MK: Not needed when applying transferred update
    if (!ITRC_Ord_Consec(recvd_ord, o) && 
        !(scada_mess->type == PRIME_STATE_TRANSFER && scada_mess->machine_id == (int32u) My_ID)) {
        printf("ITRC_Process_Prime_Ordinal: Gap in prime ordinal (had %u, %u/%u, "
               "just recvd %u, %u/%u)\n", recvd_ord.ord_num,
                recvd_ord.event_idx, recvd_ord.event_tot,
                o.ord_num, o.event_idx, o.event_tot);
        return;
    }

    /* Validate the content of the message -- if it is not valid, we will treat
     * it as a no-op */
    // MK: we are already doing this check with our round of TC for the client message before sending to prime
    // // MK: Not needed when applying transferred update
    valid_content = 1;
    if (!ITRC_Valid_Type(scada_mess, FROM_PRIME)) {
        printf("ITRC_Process_Prime_Ordinal: Invalid message from Prime, type = %d\n", scada_mess->type);
        valid_content = 0;
    }

    /* First, if this is a real SCADA client message, see if its a duplicate */    
    duplicate = 0;
    //MK: Decoupling CC and DC
    if ((Type == CC_TYPE)
        && valid_content 
        && (scada_mess->type == HMI_COMMAND ||
                          scada_mess->type == RTU_DATA ||
                          scada_mess->type == BENCHMARK))
    {
        ps = (seq_pair *)(scada_mess + 1);
        idx = (int32u *)(ps + 1);
        if (Seq_Pair_Compare(*ps, progress[*idx]) <= 0) {
            /* printf("Duplicate!! [%u,%u] from %d, and I have [%u,%u]\n", 
                    ps->incarnation, ps->seq_num, *idx, 
                    progress[*idx].incarnation, progress[*idx].seq_num); */
            duplicate = 1;
        }
    }

    /* Treat PRIME_NO_OP, PRIME_STATE_TRANSFER, PRIME_SYSTEM_RESET, and duplicate client
     *  messages as NO_OPs that don't do a real TC - just skip over them */
    // MK: Not needed when applying transferred update
    if (!valid_content || scada_mess->type == PRIME_NO_OP ||
        scada_mess->type == PRIME_STATE_TRANSFER ||
        scada_mess->type == PRIME_SYSTEM_RESET || duplicate == 1) 
    {
        /* Create empty slot in the TC queue for both no_op and state xfer */
        if (Type == CC_TYPE) {
            memset(&tc_skip_msg, 0, sizeof(tc_share_msg));
            tc_skip_msg.ord = o;
            ITRC_Insert_TC_ID(&tc_skip_msg, My_ID, SKIP_ORD);
            while (ITRC_TC_Ready_Deliver(&tc_final, ns)) {
                if (ITRC_Send_TC_Final(ns->sp_ext_s, tc_final) < 0) {
                    printf("Process_Prime_Ordinal: External spines error, try to reconnect soon\n");
                    free(tc_final);
                    spines_close(ns->sp_ext_s);
                    ns->sp_ext_s = -1;
                    break;
                }
                free(tc_final);
            }
        }
    }

    /* For state transfer messages for MYSELF, first see if I even needed this state transfer,
     *  it could be the case that both myself and Prime thought I needed a state transfer
     *  at the same time, so I only need to do one of them. */
    if (scada_mess->type == PRIME_STATE_TRANSFER && scada_mess->machine_id == (int32u)My_ID) {
        
        /* If I need the state transfer, setup the appropriate state transfer slot and set the
         * flag, then see if I can actually apply it (I was the last missing piece) */
        if (!ITRC_Ord_Consec(recvd_ord,o)) {
        
            /* Insert a slot in the state transfer queue (if not already) and 
             *      make sure its marked as having received a signal from Prime */
            collecting_signal = 1;
            memcpy(&recovery_ord, &o, sizeof(ordinal));

            // MK: Apply the checkpoint and update transfers if I am the last one to receive the PRIME_STATE_TRANSFER
            if(collecting_signal == 1 && ITRC_Check_Checkpoint_Updates_Ready())
            {
                assert(completed_transfer == 0);
                ITRC_Apply_Checkpoint_Updates(ns);
                printf("State Transfer Completed up to applied_ordinal [%u:%u/%u] and received_ordinal [%u:%u/%u]\n", 
                    applied_ord.ord_num, applied_ord.event_idx, applied_ord.event_tot,
                    recvd_ord.ord_num, recvd_ord.event_idx, recvd_ord.event_tot);
            }
            
        }
        /* I don't need state transfer - cleanup any memory that may be lying around up
         * to and including this ST slot */
        else {
            // MK TODO: Clean out the Update Transfer queue.
        }
    }

    if (ITRC_Ord_Consec(recvd_ord,o))
    {
        // MK: Add the scada_mess to the updates queue
        if(encrypted_scada_mess != NULL){
            ITRC_Insert_Update(o, encrypted_scada_mess);
        }
        else{
            ITRC_Insert_Update(o, scada_mess);
        }
    }

    recvd_ord = o;
    

    /* These are messages that were dummy TC instances, so we are done here, don't need
     *  to give anything to the SM */
    if (!valid_content || scada_mess->type == PRIME_NO_OP || scada_mess->type == PRIME_SYSTEM_RESET ||
            (scada_mess->type == PRIME_STATE_TRANSFER && scada_mess->machine_id == (int32u)My_ID) ||
            duplicate == 1) 
    {
        return;
    }
    else
    {
        // MK: Decoupling CC and DC
        // Since DC replicas do not maintain any state, we can just set the applied_ord to recvd_ord
        if((Type==DC_TYPE) && (scada_mess->type != PRIME_STATE_TRANSFER))
        {
            applied_ord = recvd_ord;
        }
    }

    if (scada_mess->type != PRIME_STATE_TRANSFER) {

        // MK: Decoupling CC and DC
        if(Type == CC_TYPE)
        {
            /* Put the ordinal at the back of the ordinal queue for later use with returning SM msg */
            stddll_push_back(&ord_queue, &o);

            /* Store the latest update from this client, update progress, and send
             *  to the SM*/
            ps = (seq_pair *)(scada_mess + 1);
            idx = (int32u *)(ps + 1);
            progress[*idx] = *ps;
        
            nBytes = sizeof(signed_message) + scada_mess->len;
            memcpy(up_hist[*idx].buff, scada_mess, nBytes);
            up_hist[*idx].ord = o;
            IPC_Send(ns->ipc_s, (void *)scada_mess, nBytes, ns->ipc_remote);
        }
        
    }
    else {

        // MK: State Transfer Code
        
        //First send correct checkpoint messages if available
        
        c_ptr = &(checkpoints.head);
        while (c_ptr->next != NULL)
        {
            c_ptr = c_ptr->next;
            if((c_ptr->correct==1) && (c_ptr->recvd[My_ID] == 1))
            {
                mess = (signed_message*) (c_ptr->results);
                dest.sin_family = AF_INET;
                dest.sin_port = htons(SM_INT_BASE_PORT + scada_mess->machine_id);
                dest.sin_addr.s_addr = inet_addr(Int_Site_Addrs[All_Sites[scada_mess->machine_id-1]]);
                ret = spines_sendto(ns->sp_int_s, mess, sizeof(signed_message) + mess->len,
                            0, (struct sockaddr *)&dest, sizeof(struct sockaddr));
                if (ret != (int)(sizeof(signed_message) + mess->len)) {
                    printf("ITRC_Process_Prime_Ordinal: spines_sendto error on CHECKPOINT msg!\n");

                    //MK TODO: need the following?
                    // spines_close(ns->sp_int_s);
                    // FD_CLR(ns->sp_int_s, &mask);
                    // ns->sp_int_s = -1;
                    // t = &spines_timeout;
                }
                printf("ITRC_Process_Prime_Ordinal: Sent CHECKPOINT at [%u,%u/%u] to target %d\n", 
                c_ptr->ord.ord_num, c_ptr->ord.event_idx, c_ptr->ord.event_tot, scada_mess->machine_id);
            }
        }

        //Next, send the updates after the checkpoint up to the requested ordinal
        u_ptr = &updates.head;
        while (u_ptr->next != NULL && (ITRC_Ord_Compare(u_ptr->next->ord, o) <= 0))
        {
            u_ptr = u_ptr->next;
            mess = PKT_Construct_Signed_Message(sizeof(update_transfer_msg));
            mess->machine_id = My_ID;
            mess->len = sizeof(update_transfer_msg);
            mess->type = UPDATE_TRANSFER;

            cp_ut_mess = (update_transfer_msg *)(mess + 1);
            memcpy(&cp_ut_mess->ord, &u_ptr->ord, sizeof(ordinal));
            memcpy(cp_ut_mess->payload, u_ptr->payload, MAX_PAYLOAD_SIZE);

            /* SIGN Message */
            OPENSSL_RSA_Sign( ((byte*)mess) + SIGNATURE_SIZE,
                    sizeof(signed_message) + mess->len - SIGNATURE_SIZE,
                    (byte*)mess );

            // MK: Temporarily store the target in the machine id. This will be changed to My_ID just before sending
            mess->machine_id = scada_mess->machine_id;

            // MK: Store the update transfer msg in the pending_transfers queue and then send in batches in ITRC_Master
            stddll_push_back(&pending_transfers, &mess);

            if((ITRC_Ord_Compare(u_ptr->ord, o) == 0))
            {
                printf("ITRC_Process_Prime_Ordinal: Sent all UPDATE TRANSFERs upto [%u,%u/%u] to target %d\n", 
                     u_ptr->ord.ord_num, u_ptr->ord.event_idx, u_ptr->ord.event_tot, scada_mess->machine_id);
            }
            
        }
        
    }
}

void ITRC_Process_Prime_Ordinal_Update_Transfer(ordinal o, signed_message *scada_mess, net_sock *ns)
{
    int nBytes, ret;
    char duplicate, valid_content;
    int32u *idx;
    seq_pair *ps;
    signed_message *encrypted_scada_mess, *tc_final, *state_req, *pend_mess;
    tc_share_msg tc_skip_msg;
    state_xfer_msg st_dummy_msg;
    st_node *s_ptr, *s_del;

    char buff[UPDATE_SIZE];

    encrypted_scada_mess = NULL;

    // MK: Unencryption of scada message
    // // MK: Decoupling CC and DC
    if((scada_mess->len > 0) && (Type == CC_TYPE))
    {
        memset(buff, 0, UPDATE_SIZE);
        memcpy(buff, scada_mess, sizeof(signed_message));
        // MK: Start of enc payload is ((char*)(scada_mess+1))+DIGEST_SIZE_IV
        // MK: IV (enc_iv) is at (unsigned char*)(scada_mess+1)
        // MK: scada_mess->len contains both sizes
        ret = OPENSSL_RSA_Decrypt(((char*)(scada_mess+1))+DIGEST_SIZE_IV, 
                                  scada_mess->len - DIGEST_SIZE_IV,
                                  (unsigned char*)(scada_mess+1), 
                                  &buff[sizeof(signed_message)]);
        if(ret == -1)
        {
            printf("ITRC_Process_Prime_Ordinal: Decryption failed...\n");
            return;
        }
        encrypted_scada_mess = scada_mess;
        scada_mess = (signed_message*) buff;
        scada_mess->len = ret; 
    }

    // MK: Add the scada_mess to the updates queue
    if(encrypted_scada_mess != NULL){
        ITRC_Insert_Update(o, encrypted_scada_mess);
    }
    else{
        ITRC_Insert_Update(o, scada_mess);
    }

    /* First, if this is a real SCADA client message, see if its a duplicate */    
    duplicate = 0;
    if ((Type == CC_TYPE)
        && (scada_mess->type == HMI_COMMAND ||
            scada_mess->type == RTU_DATA ||
            scada_mess->type == BENCHMARK))
    {
        ps = (seq_pair *)(scada_mess + 1);
        idx = (int32u *)(ps + 1);
        if (Seq_Pair_Compare(*ps, progress[*idx]) <= 0) {
            /* printf("Duplicate!! [%u,%u] from %d, and I have [%u,%u]\n", 
                    ps->incarnation, ps->seq_num, *idx, 
                    progress[*idx].incarnation, progress[*idx].seq_num); */
            duplicate = 1;
        }
        // SAM EMS // MK: What is this?? We can just delete this
        if (scada_mess->type == RTU_DATA) {
            rtu_data_msg *rtud = (rtu_data_msg *)(scada_mess + 1);
            if (rtud->scen_type == EMS) {
                /*printf("SM ITRC has received EMS update: [%d,%d]\n", */
                            /*rtud->seq.incarnation, rtud->seq.seq_num);*/
                //duplicate = 1;
            }
        }
    }

    /* These are messages that were dummy TC instances, so we are done here, don't need
     *  to give anything to the SM */
    if (scada_mess->type == PRIME_NO_OP || scada_mess->type == PRIME_SYSTEM_RESET ||
        (scada_mess->type == PRIME_STATE_TRANSFER) ||
        duplicate == 1) 
    {
        return;
    }

    // MK: Decoupling CC and DC
    if (Type == CC_TYPE)
    {
        //Put the ordinal at the back of the ordinal queue for later use with returning SM msg 
        stddll_push_back(&ord_queue, &o);
        
        /* Store the latest update from this client, update progress, and send
         *  to the SM*/
        ps = (seq_pair *)(scada_mess + 1);
        idx = (int32u *)(ps + 1);
        progress[*idx] = *ps;

        // MK: applied seq needs to be updated so that the recovered replica will accept future client requests.
        applied_seq_smencrypt[*idx] = *ps;

        nBytes = sizeof(signed_message) + scada_mess->len;
        memcpy(up_hist[*idx].buff, scada_mess, nBytes);
        up_hist[*idx].ord = o; //MK TODO: What to do with up_hist when applying update transfers?

        // printf("ITRC_Process_Prime_Ordinal_Update_Transfer: Sending message for ordinal [%u,%u/%u]\n",
        //        o.ord_num, o.event_idx, o.event_tot);
        IPC_Send(ns->ipc_s, (void *)scada_mess, nBytes, ns->ipc_remote);
    }



}

void ITRC_Insert_TC_ID(tc_share_msg *tcm, int32u sender, int32u flag)
{
    ordinal o;
    tc_queue *tcq;
    tc_node *n, *ptr; // *del;
    char new_entry;

    if (ITRC_Ord_Compare(tcm->ord, applied_ord) <= 0)
        return;

    o = tcm->ord;
    tcq = &tcq_pending;
    ptr = NULL;
    new_entry = 0;

    /* If new_entry is 1 (true), insert new node as ptr next.
     * If new_entry is 0 (false), ptr will point at matching node */

    /* First, check if this is a new entry */
    /* If the queue is empty, or this ord is greater than the tail, insert this after
     * the tail. We already checked that the ord has not yet been completed */
       //(tcq->head.next != NULL && 
    if (tcq->head.next == NULL || (ITRC_Ord_Compare(o, tcq->tail->ord) > 0))
    {
        ptr = tcq->tail;
        new_entry = 1;
        //printf("Will insert after tail - ");
    }
    /* else if (tcq->head.next != NULL && tcq->size < TC_HISTORY && seq < tcq->head.next->seq_num) {
        ptr = &tcq->head;
        new_entry = 1;
        printf("Will insert before head - ");
    } */
    else {
        ptr = &tcq->head;
        while (ptr->next != NULL && (ITRC_Ord_Compare(o, ptr->next->ord) > 0))
            ptr = ptr->next;

        if (ptr->next != NULL && (ITRC_Ord_Compare(o, ptr->next->ord) == 0))
            ptr = ptr->next;
        else {
            new_entry = 1;
            //printf("Will insert in middle of queue - ");
        }
    }

    /* Create the new entry, if applicable */
    if (new_entry == 1) {
        //printf("New TCQ: [%u, %u of %u]\n", o.ord_num, o.event_idx, o.event_tot);

        n = (tc_node *)malloc(sizeof(tc_node));
        memset(n, 0, sizeof(tc_node));
        n->ord = tcm->ord;
        n->next = ptr->next;
        ptr->next = n;

        if (ptr == tcq->tail)
            tcq->tail = n;
        ptr = n;
    
        /* Increase the size, and if we exceed the history size, jump ahead and readjust */
        tcq->size++;

        /* if (tcq->size > TC_HISTORY) {
            del = tcq->head.next;
            tcq->head.next = del->next;
            printf("Jumping from %d to (and through) %d\n", tcq->completed, del->seq_num);
            tcq->completed = del->seq_num;
            free(del);
            tcq->size--;
            assert(tcq->size == TC_HISTORY);
        } */
    }
    /* At this point, ptr points to the current tc_node */

    /* Check if we've already finished this tc_node instance, and are just waiting to deliver it */
    if (ptr->done == 1) {
        /* printf("\tinstance [%u,%u/%u] is already done!\n", ptr->ord.ord_num, 
                    ptr->ord.event_idx, ptr->ord.event_tot); */
        return;
    }

    if (ptr->recvd[sender] == 1)
        return;

    ptr->recvd[sender] = 1;
    ptr->count++;

    /* Special case for NO_OPs and STATE_TRANSFER, which don't do TC */
    if (flag == SKIP_ORD) {
        ptr->done = 1;
        ptr->skip = 1;
        return;
    }

    memcpy(&ptr->shares[sender], tcm, sizeof(tc_share_msg));
    if (ptr->count >= REQ_SHARES && ptr->recvd[My_ID] == 1) {
        /* TODO: actually compare and check digests, find culprit if the TC
         *      shares don't work out, report them, clear their share, wait
         *      for more correct ones... */
        ptr->tcf = PKT_Construct_TC_Final_Msg(tcm->ord, ptr);
        if (ptr->tcf != NULL) {
            /* SIGN TC Final Message */
             OPENSSL_RSA_Sign( ((byte*)ptr->tcf) + SIGNATURE_SIZE,
                    sizeof(signed_message) + ptr->tcf->len - SIGNATURE_SIZE,
                    (byte*)ptr->tcf);
        }
        else {
            ptr->skip = 1;
        }
        ptr->done = 1;
    }
}

// MK: Adding this for Scada Master Encrytpion TC verification
void ITRC_Insert_TC_ID_SMEncrypt(tc_share_msg_smencrypt *tcm, int32u sender, int32u flag)
{
    seq_pair seq;
    int32u client_id;
    tc_queue_smencrypt *tcq;
    tc_node_smencrypt *n, *ptr; // *del;
    char new_entry;
    int32u i, match_count;
    tc_share_msg_smencrypt *shared_tc;
    byte digest[DIGEST_SIZE], shared_digest[DIGEST_SIZE];

    seq = tcm->seq;
    client_id = tcm->client_id;

    if (Seq_Pair_Compare(seq, applied_seq_smencrypt[client_id]) <= 0)
        return;

    tcq = &tcq_pending_smencrypt[client_id];
    ptr = NULL;
    new_entry = 0;

    /* If new_entry is 1 (true), insert new node as ptr next.
     * If new_entry is 0 (false), ptr will point at matching node */

    /* First, check if this is a new entry */
    /* If the queue is empty, or this ord is greater than the tail, insert this after
     * the tail. We already checked that the ord has not yet been completed */
       //(tcq->head.next != NULL && 
    if (tcq->head.next == NULL || (Seq_Pair_Compare(seq, tcq->tail->seq) > 0))
    {
        ptr = tcq->tail;
        new_entry = 1;
        //printf("Will insert after tail - ");
    }
    else {
        ptr = &tcq->head;
        while (ptr->next != NULL && (Seq_Pair_Compare(seq, ptr->next->seq) > 0))
            ptr = ptr->next;

        if (ptr->next != NULL && (Seq_Pair_Compare(seq, ptr->next->seq) == 0))
            ptr = ptr->next;
        else {
            new_entry = 1;
            //printf("Will insert in middle of queue - ");
        }
    }

    /* Create the new entry, if applicable */
    if (new_entry == 1) {
        //printf("New TCQ: [%u, %u of %u]\n", o.ord_num, o.event_idx, o.event_tot);

        n = (tc_node_smencrypt *)malloc(sizeof(tc_node_smencrypt));
        memset(n, 0, sizeof(tc_node_smencrypt));
        n->seq = tcm->seq;
        n->next = ptr->next;
        ptr->next = n;

        if (ptr == tcq->tail)
            tcq->tail = n;
        ptr = n;
    
        /* Increase the size, and if we exceed the history size, jump ahead and readjust */
        tcq->size++;
    }
    /* At this point, ptr points to the current tc_node */

    /* Check if we've already finished this tc_node instance, and are just waiting to deliver it */
    if (ptr->done == 1) {
        /* printf("\tinstance [%u,%u/%u] is already done!\n", ptr->ord.ord_num, 
                    ptr->ord.event_idx, ptr->ord.event_tot); */
        return;
    }

    if (ptr->recvd[sender] == 1)
        return;

    ptr->recvd[sender] = 1;
    ptr->count++;

    /* Special case for NO_OPs and STATE_TRANSFER, which don't do TC */
    if (flag == SKIP_ORD) {
        ptr->done = 1;
        return;
    }

    // printf("ITRC_Insert_TC_ID_SMEncrypt: %d [%d,%d]\n", client_id, seq.incarnation, seq.seq_num);

    memcpy(&ptr->shares[sender], tcm, sizeof(tc_share_msg_smencrypt));
    if (ptr->count >= REQ_SHARES && ptr->recvd[My_ID] == 1) {
        /* MK TODO: actually compare and check digests, find culprit if the TC
         *      shares don't work out, report them, clear their share, wait
         *      for more correct ones... */
        /* See if we now have F+1 (aka REQ_SHARES) number of matching
             *  state xfer messages in order to finish this off */
        OPENSSL_RSA_Make_Digest(tcm, sizeof(tc_share_msg_smencrypt) - SIGNATURE_SIZE, digest);
        match_count = 0;
        for (i = 1; i <= NUM_SM; i++) {
            if (ptr->recvd[i] == 0)
                continue;
                   
            shared_tc = (tc_share_msg_smencrypt *)(&ptr->shares[i]);
            if (shared_tc->client_id != client_id || memcmp(&shared_tc->seq, &seq, sizeof(seq_pair)))
                continue;
            
            OPENSSL_RSA_Make_Digest(shared_tc, sizeof(tc_share_msg_smencrypt) - SIGNATURE_SIZE, 
                                        shared_digest);
            
            if (OPENSSL_RSA_Digests_Equal(digest, shared_digest))
                match_count++;
        }
        if (match_count >= REQ_SHARES) {
            ptr->tcf = PKT_Construct_TC_Final_Msg_SMEncrypt(seq, client_id, ptr, sender);
            // if (ptr->tcf != NULL) {
            //     // MK TODO: Can't sign anymore here since no space for signature...
            //     /* SIGN TC Final Message */
            //      // OPENSSL_RSA_Sign( ((byte*)ptr->tcf) + SIGNATURE_SIZE,
            //      //        sizeof(signed_message) + ptr->tcf->len - SIGNATURE_SIZE,
            //      //        (byte*)ptr->tcf);
            // }
            // else {
            //     ptr->skip = 1;
            // }
            ptr->done = 1;
        }
        else
        {
            printf("ITRC_Insert_TC_ID_SMEncrypt: too little correct shares (%u), required = %u\n", match_count, REQ_SHARES);
        }
        
    }
}

/* Check if we can make progress and deliver a message. Remove message from queue, store it in
 * to_deliver, and return 1 is success. Otherwise, return 0. */
int ITRC_TC_Ready_Deliver(signed_message **to_deliver, net_sock *ns)
{
    int ready, prog;
    tc_queue *tcq;
    tc_node  *ptr, *delete;

    tcq = &tcq_pending;
    ready = 0;
    prog = 0;
    *to_deliver = NULL;

    ptr = &tcq->head;
    while (ready == 0 && ptr->next != NULL && ptr->next->done == 1 && 
            ptr->next->recvd[My_ID] == 1 && ITRC_Ord_Consec(applied_ord, ptr->next->ord)) 
    {
        if (ptr->next->skip == 0) {
            /* printf("  [%u, %u of %u](OK)", ptr->next->ord.ord_num, 
                        ptr->next->ord.event_idx, ptr->next->ord.event_tot); */
            *to_deliver = ptr->next->tcf;
            ready = 1;
            prog = 1;
        }
        else {
            /* printf("  [%u, %u of %u](SKIP)", ptr->next->ord.ord_num, 
                        ptr->next->ord.event_idx, ptr->next->ord.event_tot); */
            prog = 1;
        }

        /* TODO - need to keep CATCHUP_WINDOW number of these TCs around for retransmissions,
         *  so only delete them if they are beyond the window */
        delete = ptr->next;
        applied_ord = delete->ord;

        //MK TODO: Call ITRC Checkpoint Check here
        ITRC_Check_CHECKPOINT(delete->ord, ns);
        
        ptr->next = delete->next;
        tcq->size--;
        if (tcq->size == 0)
            assert(tcq->head.next == NULL);
        if (tcq->tail == delete)
            tcq->tail = &tcq->head;
        free(delete);
    }

    if (prog && applied_ord.ord_num > print_target) {
        printf("Executed Through Ordinal %u\n", applied_ord.ord_num);
        print_target = (((applied_ord.ord_num - 1) / PRINT_PROGRESS) + 1) * PRINT_PROGRESS;
    }
    
    return ready;
}

/* Check if we can make progress and deliver a message. Remove message from queue, store it in
 * to_deliver, and return 1 is success. Otherwise, return 0. */
int ITRC_TC_Ready_Deliver_SMEncrypt(signed_message **to_deliver)
{
    int ready, prog;
    tc_queue_smencrypt *tcq;
    tc_node_smencrypt  *ptr, *delete;
    int32u i, client_id;

    ready = 0;
    prog = 0;
    *to_deliver = NULL;

    // MK: To avoid starvation, start looping from last checked client
    for (i = tc_queue_smencrypt_idx; i <= MAX_EMU_RTU + NUM_HMI; i++)
    {
        client_id = i;
        tcq = &tcq_pending_smencrypt[client_id];

        // MK: Removing the hard limit of client requests to be consecutive, instead just enforce greater.
        ptr = &tcq->head;

        while (ready == 0 && ptr->next != NULL)
        {
            if(ptr->next->done == 1 && 
                ptr->next->recvd[My_ID] == 1 && Seq_Pair_Compare(applied_seq_smencrypt[client_id], ptr->next->seq) < 0)
            {
                // continue;
            }
            else
            {
                ptr = ptr->next;
                continue;
            }
            
            *to_deliver = ptr->next->tcf;
            ready = 1;
            prog = 1;
            tc_queue_smencrypt_idx = i;

            /* TODO - need to keep CATCHUP_WINDOW number of these TCs around for retransmissions,
             *  so only delete them if they are beyond the window */
            delete = ptr->next;
            applied_seq_smencrypt[client_id] = delete->seq;
            ptr->next = delete->next;
            tcq->size--;
            if (tcq->size == 0)
                assert(tcq->head.next == NULL);
            if (tcq->tail == delete)
                tcq->tail = &tcq->head;
            free(delete);
        }
          
    }

    for (i = 0; i <= tc_queue_smencrypt_idx; i++)
    {
        client_id = i;
        tcq = &tcq_pending_smencrypt[client_id];


        ptr = &tcq->head;

        while (ready == 0 && ptr->next != NULL)
        {
            if(ptr->next->done == 1 && 
                ptr->next->recvd[My_ID] == 1 && Seq_Pair_Compare(applied_seq_smencrypt[client_id], ptr->next->seq) < 0)
            {
                // continue;
            }
            else
            {
                ptr = ptr->next;
                continue;
            }

            *to_deliver = ptr->next->tcf;
            ready = 1;
            prog = 1;
            tc_queue_smencrypt_idx = i;

            /* TODO - need to keep CATCHUP_WINDOW number of these TCs around for retransmissions,
             *  so only delete them if they are beyond the window */
            delete = ptr->next;
            applied_seq_smencrypt[client_id] = delete->seq;
            ptr->next = delete->next;
            tcq->size--;
            if (tcq->size == 0)
                assert(tcq->head.next == NULL);
            if (tcq->tail == delete)
                tcq->tail = &tcq->head;
            free(delete);
        }
          
    }

    return ready; 
    
}

int ITRC_Send_TC_Final(int sp_ext_sk, signed_message *mess)
{
    int ret, loc, in_list;
    struct sockaddr_in dest;
    signed_message *scada_mess;
    tc_final_msg *tcf;
    rtu_feedback_msg *rtuf;
    hmi_update_msg *hmiu;
    benchmark_msg *ben;

    tcf = (tc_final_msg *)(mess + 1);
    scada_mess = (signed_message *)(tcf->payload);

    /* Toward RTU Proxy */
    if (scada_mess->type == RTU_FEEDBACK) { 
        rtuf = (rtu_feedback_msg *)(scada_mess + 1);
        in_list = key_value_get(rtuf->sub, &loc); 
        if(!in_list) {
            printf("\nrtu:%d has no loc, dropping msg\n", rtuf->sub);
            return 0;
        }
        dest.sin_port = htons(RTU_BASE_PORT + loc);
        dest.sin_addr.s_addr = inet_addr(SPINES_RTU_ADDR);
        dest.sin_family = AF_INET;
    }
    /* Toward HMI */
    else if (scada_mess->type == HMI_UPDATE) {
        hmiu = (hmi_update_msg *)(scada_mess + 1);
        dest.sin_family = AF_INET;
        dest.sin_port = htons(HMI_BASE_PORT + hmiu->scen_type);
        dest.sin_addr.s_addr = inet_addr(SPINES_HMI_ADDR);
    }
    /* BENCHMARK */
    else if (scada_mess->type == BENCHMARK) {
        ben = (benchmark_msg *)(scada_mess + 1);
        dest.sin_family = AF_INET;
        dest.sin_port = htons(RTU_BASE_PORT + ben->sender);
        dest.sin_addr.s_addr = inet_addr(SPINES_RTU_ADDR);
    }
    else {
        printf("Invalid mess type = %d\n", mess->type);
        return 0;
    }
    ret = spines_sendto(sp_ext_sk, mess, sizeof(signed_message) + sizeof(tc_final_msg),        
                0, (struct sockaddr *)&dest, sizeof(struct sockaddr));
    if ((int32u)ret != sizeof(signed_message) + sizeof(tc_final_msg)) {
        printf("ITRC_Send_TC_Final: spines_sendto error!\n");
        return -1;
    }

    return 1;
}

int ITRC_Send_TC_Final_SMEncrypt(int prime_sock, signed_message *mess, const char *prime_path)
{
    int ret;
    ret = IPC_Send(prime_sock, mess, sizeof(signed_update_message), prime_path); 
    if(ret <= 0) {
        perror("ITRC_Prime_Inject: Prime Writing error");
        // continue;
        /* close(prime_sock);
        FD_CLR(prime_sock, &mask); */
    }
    return ret;
}


int ITRC_Insert_CHECKPOINT(signed_message *mess)
{
    int32u i, match_count, sender;
    ordinal o;
    checkpoint_queue *ctq;
    checkpoint_node *n, *ptr;
    signed_message *stored_cp;
    char new_entry;
    byte digest[DIGEST_SIZE], stored_digest[DIGEST_SIZE];
    checkpoint_msg *cp_mess; 

    sender = mess->machine_id;
    cp_mess = (checkpoint_msg *)(mess + 1);

    o = cp_mess->ord;
    ctq = &checkpoints;
    ptr = NULL;
    new_entry = 0;

    /* If new_entry is 1 (true), insert new node as ptr next.
     * If new_entry is 0 (false), ptr will point at matching node */

    /* First, check if this is a new entry */
    /* If the queue is empty, or this ord is greater than the tail, insert this after
     * the tail. We already checked that the ord has not yet been completed */
    if (ctq->head.next == NULL || (ITRC_Ord_Compare(o, ctq->tail->ord) > 0)) {
        ptr = ctq->tail;
        new_entry = 1;
        //printf("ST: After tail - ");
    }
    else if(ITRC_Ord_Compare(o, ctq->head.next->ord) < 0){
        /* MK: This entry is older than the head, so just drop it */
        return 0;
    }
    else {
        ptr = &ctq->head;
        while (ptr->next != NULL && (ITRC_Ord_Compare(o, ptr->next->ord) > 0))
            ptr = ptr->next;

        if (ptr->next != NULL && (ITRC_Ord_Compare(o, ptr->next->ord) == 0))
            ptr = ptr->next;
        else {
            new_entry = 1;
            //printf("ST: Middle - ");
        }
    }

    /* Create the new entry, if applicable */
    if (new_entry == 1) {
        //printf("New ST: [%u, %u of %u]\n", o.ord_num, o.event_idx, o.event_tot);

        n = (checkpoint_node *)malloc(sizeof(checkpoint_node));
        memset(n, 0, sizeof(checkpoint_node));
        n->ord = o;
        n->next = ptr->next;
        ptr->next = n;

        if (ptr == ctq->tail)
            ctq->tail = n;
        ptr = n;
    
        /* Increase the size, and if we exceed the history size, jump ahead and readjust */
        ctq->size++;
    }
    /* At this point, ptr points to the current checkpoint_node */

    if (ptr->recvd[sender] == 1)
        return 0;

    // printf("\tcheckpoint from %d on ord [%u,%u/%u]\n", sender, o.ord_num, o.event_idx, o.event_tot);
    ptr->recvd[sender] = 1;
    ptr->count++;
    memcpy(&ptr->checkpoint_messages[sender], mess, sizeof(signed_message) + mess->len);

    return 1;
}


int ITRC_Check_CHECKPOINT(ordinal o, net_sock *ns)
{
    int32u i, j, match_count;
    int ret;
    checkpoint_queue *ctq;
    checkpoint_node *ptr;
    signed_message *stored_cp, *current_cp;
    char new_entry;
    byte digest[DIGEST_SIZE], stored_digest[DIGEST_SIZE];
    char temp[sizeof(signed_message)+sizeof(checkpoint_msg)];
    struct sockaddr_in dest;

    ctq = &checkpoints;
    ptr = NULL;
    new_entry = 0;

    /* If new_entry is 1 (true), then we don't have any checkpoints yet
     * If new_entry is 0 (false), ptr will point at matching node with at least one checkpoint */

    /* First, check if this is a new entry */
    if (ctq->head.next == NULL || (ITRC_Ord_Compare(o, ctq->tail->ord) > 0)) {
        ptr = ctq->tail;
        new_entry = 1;
        //printf("ST: After tail - ");
    }
    else if(ITRC_Ord_Compare(o, ctq->head.next->ord) < 0){
        /* MK: This entry is older than the head, so just drop it */
        return 0;
    }
    else {
        ptr = &ctq->head;
        while (ptr->next != NULL && (ITRC_Ord_Compare(o, ptr->next->ord) > 0))
            ptr = ptr->next;

        if (ptr->next != NULL && (ITRC_Ord_Compare(o, ptr->next->ord) == 0))
            ptr = ptr->next;
        else {
            new_entry = 1;
        }
    }


    if (new_entry == 1) {
        // MK: No checkpoints collected yet. So, no need to do anything...
        return 0;
    }

    /* At this point, ptr points to the current checkpoint_node */

    /*
        MK: We should not check for correctness if it is already correct,
            or required number of count is not yet received,
            or if in recovery mode and checkpoint ordinal is greater than recovery ordinal
     */
    if ((ptr->stable == 0) 
        && (ptr->count >= REQ_SHARES)
        && (((collecting_signal == 1) && (ITRC_Ord_Compare(ptr->ord, recovery_ord) <= 0))
            || ((collecting_signal == 0) && (ITRC_Ord_Compare(ptr->ord, applied_ord) <= 0)))
        ) 
    {
        
        /* See if we now have F+1 (aka REQ_SHARES) number of matching
         *  state xfer messages in order to finish this off */

        //MK TODO: We can compare the messages directly, and not make digests
        
        for (j = 1; j <= NUM_SM-1; j++) 
        {
            if (ptr->recvd[j] == 0)
                    continue;

            match_count = 0;
            current_cp = (signed_message *)(&ptr->checkpoint_messages[j]);
            // OPENSSL_RSA_Make_Digest(((byte*)(current_cp + 1)), 
            //                         current_cp->len, 
            //                         digest);

            for (i = j; i <= NUM_SM; i++) {
                if (ptr->recvd[i] == 0)
                    continue;
                       
                stored_cp = (signed_message *)(&ptr->checkpoint_messages[i]);
                // OPENSSL_RSA_Make_Digest( ((byte*)(stored_cp + 1)), 
                //                         stored_cp->len, 
                //                         stored_digest);
                //if (OPENSSL_RSA_Digests_Equal(digest, stored_digest))
                if(strcmp((char*)(current_cp + 1), (char*)(stored_cp + 1)) == 0)
                {
                    match_count++;
                }
            }
            if (match_count >= REQ_SHARES) {


                // OPENSSL_RSA_Make_Digest(((byte*)(current_cp + 1)), 
                //                         current_cp->len, 
                //                         ptr->digest);

                /*
                    If DC replica and my own message placeholder is empty, then create my own
                    checkpoint and enter it
                 */
                
                if((Type == DC_TYPE || (collecting_signal==1 && (ITRC_Ord_Compare(ptr->ord, recovery_ord)<=0))) 
                    && (ptr->recvd[My_ID] != 1))
                {
                    memcpy(temp, current_cp, sizeof(signed_message) + current_cp->len);

                    memset(temp, 0, SIGNATURE_SIZE);

                    current_cp = (signed_message *)temp;
                    current_cp->machine_id = My_ID;

                    /* Sign Checkpoint Message */ 
                    OPENSSL_RSA_Sign( ((byte*)current_cp) + SIGNATURE_SIZE,
                                      sizeof(signed_message) + current_cp->len - SIGNATURE_SIZE,
                                      (byte*)current_cp);

                    /* printf("  sending ST to %d on ord [%u,%u/%u]\n", st_mess->target,
                            st_mess->ord.ord_num, st_mess->ord.event_idx, st_mess->ord.event_tot); */

                    // MK: Enter the checkpoint to my queue
                    ITRC_Insert_CHECKPOINT(current_cp);

                    // MK: Broadcast checkpoint to everyone else.
                    /* Send the checkpoint message to all the replicas */
                    for (i = 1; i <= NUM_SM; i++) {
                        if (i == My_ID)
                            continue;
                        //printf("ITRC_Check_CHECKPOINT: sending checkpoint from %d to %d\n", (int32u)My_ID, i);
                        dest.sin_family = AF_INET;
                        dest.sin_port = htons(SM_INT_BASE_PORT + i);
                        dest.sin_addr.s_addr = inet_addr(Int_Site_Addrs[All_Sites[i-1]]);
                        ret = spines_sendto(ns->sp_int_s, current_cp, sizeof(signed_message) + current_cp->len,
                                    0, (struct sockaddr *)&dest, sizeof(struct sockaddr));
                        if (ret != sizeof(signed_message) + current_cp->len) {
                            printf("ITRC_Check_CHECKPOINT: spines_sendto error on CHECKPOINT msg!\n");
                            // spines_close(ns->sp_int_s);
                            // FD_CLR(ns->sp_int_s, &mask);
                            // ns->sp_int_s = -1;
                            // t = &spines_timeout;
                            // break;
                        }
                    }

                    match_count++;
                }

                if((ptr->recvd[My_ID] == 1) && ptr->correct != 1)
                {
                    ptr->correct = 1;

                    current_cp = (signed_message *)(&ptr->checkpoint_messages[My_ID]);

                    memcpy(&ptr->results, current_cp, sizeof(signed_message) + current_cp->len);
                }
                

                // MK: Check if we can set it as a stable checkpoint
                if((match_count >= ((2*NUM_F) + NUM_K + 1)) && (ptr->recvd[My_ID] == 1))
                {
                    ptr->stable = 1;
                }

                break;
            }
        }
        

        /* See if we've now collected enough matching state 
         *  from below.  */
        // if (ptr->correct == 1) {
        //     printf("ITRC_Insert_CHECKPOINT: Completed collecting a correct checkpoint: [%u,%u/%u]\n", o.ord_num, o.event_idx, o.event_tot);
        // }

        if(ptr->stable == 1){

            printf("ITRC_Insert_CHECKPOINT: Completed collecting a stable checkpoint: [%u,%u/%u]\n", o.ord_num, o.event_idx, o.event_tot);

            // MK: Make this pointer the head and remove earlier nodes
            ITRC_Remove_Old_Checkpoints(ptr->ord);
            ITRC_Remove_Old_Updates(ptr->ord);

            // MK: DC replicas jump since they do not need to reply back to client
            // MK: Decoupling CC and DC
            // if((Type==DC_TYPE)
            //     && (collecting_signal == 1)
            //     && (ITRC_Ord_Compare(ptr->ord, recovery_ord)==1))
            // {
            //     memcpy(&recovery_ord, &(ptr->ord), sizeof(ordinal));
            //     memcpy(&recvd_ord, &(ptr->ord), sizeof(ordinal));
            // }

            return 1;
        }
    }
    return 0;
}


void ITRC_Remove_Old_Checkpoints(ordinal o)
{
    checkpoint_node *s_ptr, *s_del;

    /* Cleanup the checkpoints queue if there is any old checkpoint
     * prior to the new one (at ordinal o) */
    s_ptr = &checkpoints.head;
    while (s_ptr->next != NULL && (ITRC_Ord_Compare(s_ptr->next->ord, o) < 0)) {
        s_del = s_ptr->next;
        s_ptr->next = s_del->next;
        checkpoints.size--;

        //if (s_del->stable != NULL)
        //    free(s_del->result);
        free(s_del);
    }

    if (checkpoints.size == 0)
        checkpoints.tail = &checkpoints.head;
}


int ITRC_Insert_Update(ordinal o, signed_message *scada_mess)
{   
    updates_queue *utq;
    update_node *n, *ptr;

    utq = &updates;
    ptr = NULL;

    /* MK: Add to the queue only if the queue is empty or the tail of the queue is less 
       than the inserting ordinal */
    /*
        MK: o should be consecutive from last update in updates queue, 
        or if updates queue is empty, then should be consecutive to the correct checkpoint, 
        if no correct checkpoint, then it must be the first ordinal
    */
   

    if ((ITRC_Ord_Consec(utq->tail->ord, o)==1)
        || (utq->head.next == NULL 
            && checkpoints.head.next != NULL
            && checkpoints.head.next->stable == 1
            && ITRC_Ord_Consec(checkpoints.head.next->ord, o)==1)
        || (utq->head.next == NULL
            && (checkpoints.head.next == NULL || checkpoints.head.next->stable != 1) 
            && ITRC_Ord_Consec(utq->head.ord, o)==1)) 
    {
        ptr = utq->tail;
        n = (update_node *)malloc(sizeof(update_node));
        memset(n, 0, sizeof(update_node));
        memcpy(&n->ord, &o, sizeof(ordinal));
        memcpy(n->payload, scada_mess, sizeof(signed_message) + scada_mess->len);

        // MK Todo: Separate system_reset, and maybe the others as well.
        if(scada_mess->type == PRIME_NO_OP || scada_mess->type == PRIME_SYSTEM_RESET ||
           scada_mess->type == PRIME_STATE_TRANSFER)
        {
            memset(n->payload, 0, MAX_PAYLOAD_SIZE);
            ((signed_message*)(n->payload))->type = PRIME_NO_OP;

        }

        n->next = ptr->next;
        ptr->next = n;
        if (ptr == utq->tail)
            utq->tail = n;
        //ptr = n;
        /* Increase the size, and (MK TODO) if we exceed the max updates queue size, request checkpoint transfer */
        utq->size++;

        return 1;
    }
    else
    {
        printf("ITRC_Insert_Update failed: [%u,%u/%u]\n", o.ord_num, o.event_idx, o.event_tot);
    }

    return 0;
}

// MK: Check OK
void ITRC_Remove_Old_Updates(ordinal o)
{
    update_node *s_ptr, *s_del;

    /* Cleanup the updates queue if there is any older update
     * prior to the new checkpoint (at ordinal o) */
    s_ptr = &updates.head;
    while (s_ptr->next != NULL && (ITRC_Ord_Compare(s_ptr->next->ord, o) <= 0)) {
        s_del = s_ptr->next;
        s_ptr->next = s_del->next;
        updates.size--;

        free(s_del);
    }

    if (updates.size == 0)
        updates.tail = &updates.head;
}

int ITRC_Insert_UPDATE_TRANSFER(signed_message *mess)
{
    int32u i, match_count, sender;
    ordinal o;
    update_transfer_queue *utq;
    update_transfer_node *n, *ptr;
    update_transfer_msg *stored_upt;
    char new_entry;
    byte digest[DIGEST_SIZE], stored_digest[DIGEST_SIZE];
    update_transfer_msg *upt_mess; 

    sender = mess->machine_id;
    upt_mess = (update_transfer_msg *)(mess + 1);

    o = upt_mess->ord;
    utq = &update_transfers;
    ptr = NULL;
    new_entry = 0;

    /* If new_entry is 1 (true), insert new node as ptr next.
     * If new_entry is 0 (false), ptr will point at matching node */

    /* First, check if this is a new entry */
    /* If the queue is empty, or this ord is greater than the tail, insert this after
     * the tail. We already checked that the ord has not yet been completed */
    if (utq->head.next == NULL || (ITRC_Ord_Compare(o, utq->tail->ord) > 0)) {
        ptr = utq->tail;
        new_entry = 1;
        //printf("ST: After tail - ");
    }
    else {
        ptr = &utq->head;
        while (ptr->next != NULL && (ITRC_Ord_Compare(o, ptr->next->ord) > 0))
            ptr = ptr->next;

        if (ptr->next != NULL && (ITRC_Ord_Compare(o, ptr->next->ord) == 0))
            ptr = ptr->next;
        else {
            new_entry = 1;
            //printf("ST: Middle - ");
        }
    }

    /* Create the new entry, if applicable */
    if (new_entry == 1) {
        //printf("New ST: [%u, %u of %u]\n", o.ord_num, o.event_idx, o.event_tot);

        n = (update_transfer_node *)malloc(sizeof(update_transfer_node));
        memset(n, 0, sizeof(update_transfer_node));
        n->ord = o;
        n->next = ptr->next;
        ptr->next = n;

        if (ptr == utq->tail)
            utq->tail = n;
        ptr = n;
    
        /* Increase the size, and if we exceed the history size, jump ahead and readjust */
        utq->size++;
    }
    /* At this point, ptr points to the current update_transfer_node */

    if (ptr->recvd[sender] == 1)
        return 0;

    // printf("\tupdate transfer from %d on ord [%u,%u/%u]\n", sender, o.ord_num, o.event_idx, o.event_tot);
    ptr->recvd[sender] = 1;
    ptr->count++;
    memcpy(&ptr->update_transfer_messages[sender], upt_mess, sizeof(update_transfer_msg));

    if (ptr->correct == 0 && ptr->count >= REQ_SHARES) {
        
        /* See if we now have F+1 (aka REQ_SHARES) number of matching
         *  update transfer messages in order to finish this off */
        OPENSSL_RSA_Make_Digest( upt_mess,
                                sizeof(update_transfer_msg),
                                digest);
        match_count = 0;
        for (i = 1; i <= NUM_SM; i++) {
            if (ptr->recvd[i] == 0)
                continue;
                   
            stored_upt = (update_transfer_msg *)(&ptr->update_transfer_messages[i]);
            OPENSSL_RSA_Make_Digest( stored_upt, 
                                    sizeof(update_transfer_msg), 
                                    stored_digest);
            if (OPENSSL_RSA_Digests_Equal(digest, stored_digest))
            {
                match_count++;
            }
        }
        if (match_count >= REQ_SHARES) {
            ptr->correct = 1;
            ptr->result = (update_transfer_msg *)(&ptr->update_transfer_messages[sender]);

        }

        /* See if we've now collected enough matching update transfer messages
         *  from below.  */
        if (ptr->correct == 1) {
            //printf("COMPLETED COLLECTING A CORRECT UPDATE TRANSFER: [%u,%u/%u]\n", o.ord_num, o.event_idx, o.event_tot);

            return 1;
        }
    }
    return 0;
}

int ITRC_Check_Checkpoint_Updates_Ready()
{

    ordinal o;
    update_transfer_queue *utq;
    update_transfer_node *ptr;

    utq = &update_transfers;

    // MK: Instead of setting it to zero, set it to applied ordinal, since upto applied ordinal, state should be correct.
    memcpy(&o, &applied_ord, sizeof(ordinal));

    /*
        If checkpoints is empty or the first checkpoint is not correct, then check all the update transfers from the beginning.
        Else, the first checkpoint is correct, so check if that checkpoint + the update transfers after that make up to the ordinal.
        Also, check if checkpoint is newer than current state.
     */
    if (checkpoints.head.next != NULL 
        && checkpoints.head.next->correct == 1
        && ITRC_Ord_Compare(checkpoints.head.next->ord, applied_ord) > 0)
    {
        memcpy(&o, &checkpoints.head.next->ord, sizeof(ordinal));
    }

    // ptr is initially set to the start of the queue
    ptr = utq->head.next;

    /* 
        If recovery_ord is greater than o, then
        we need to check if the correct update transfers make
        up to (and including) the recovery_ord 
    */
    //printf("CHECKPOINT_UPDATES_READY: Starting o: [%u,%u/%u]\n", o.ord_num, o.event_idx, o.event_tot);
    while (ITRC_Ord_Compare(o, recovery_ord) <= 0)
    {
        if(ITRC_Ord_Compare(o, recovery_ord) == 0)
        {
            /* 
                we are not missing any needed correct update transfer,
                so return true.
            */
            // printf("o: [%u,%u/%u]\n", o.ord_num, o.event_idx, o.event_tot);
            // printf("recovery_ord: [%u,%u/%u]\n", recovery_ord.ord_num, recovery_ord.event_idx, recovery_ord.event_tot);
            // printf("Returning True\n");
            return 1;
        }
        else if (ptr == NULL)
        {
            // We do not have any update transfers yet, so return false
            // printf("o: [%u,%u/%u]\n", o.ord_num, o.event_idx, o.event_tot);
            // printf("recovery_ord: [%u,%u/%u]\n", recovery_ord.ord_num, recovery_ord.event_idx, recovery_ord.event_tot);
            // printf("ptr == NULL\n");
            return 0;
        }
        else
        {
            // printf("ptr->ord == [%u,%u/%u]\n", ptr->ord.ord_num, ptr->ord.event_idx, ptr->ord.event_tot);
            if (ITRC_Ord_Compare(ptr->ord, o) <= 0)
            {
                /* o starts later in the update transfers queue, 
                   so skip to the next */
                ptr = ptr->next;
                // printf("Skip\n");
            }
            else
            {
                if(ITRC_Ord_Consec(o, ptr->ord) != 1 || ptr->correct != 1)
                {
                    /*
                        ptr must be consecutive to o, and must be verified
                        to be correct. Otherwise, we are missing correct
                        update transfers, so return false.
                    */
                    // printf("o: [%u,%u/%u]\n", o.ord_num, o.event_idx, o.event_tot);
                    // printf("recovery_ord: [%u,%u/%u]\n", recovery_ord.ord_num, recovery_ord.event_idx, recovery_ord.event_tot);
                    // printf("Not consecutive(%d) or not correct(%d)\n", ITRC_Ord_Consec(o, ptr->ord), ptr->correct);
                    return 0;
                }
                else
                {
                    /* 
                        we are good here, so advance by 1 for each and check 
                        them in the next loop
                    */
                    o = ptr->ord;
                    ptr = ptr->next;
                }
            }
        }
    }
    
    /*
        we are missing one or more correct update transfers, 
        so return false
     */
    // printf("o: [%u,%u/%u]\n", o.ord_num, o.event_idx, o.event_tot);
    // printf("recovery_ord: [%u,%u/%u]\n", recovery_ord.ord_num, recovery_ord.event_idx, recovery_ord.event_tot);
    // printf("Returning False\n");
    return 0;   
    
}

void ITRC_Apply_Checkpoint_Updates(net_sock *ns)
{
    int ret;
    signed_message *mess;
    signed_message *scada_mess;
    checkpoint_msg *cp_mess;
    state_xfer_msg *st;
    ordinal o;
    checkpoint_node *cp;
    update_transfer_node *ptr;
    update_node *u_ptr, *u_del;
    update_transfer_node *ut_ptr, *ut_del;
    tc_node *t_ptr, *t_del;
    char plaintext[CHECKPOINT_PAYLOAD_SIZE];

    mess = NULL;
    memcpy(&o, &applied_ord, sizeof(ordinal));


    /* Cleanup the TC queue */
    t_ptr = &tcq_pending.head;
    while (t_ptr->next != NULL && (ITRC_Ord_Compare(t_ptr->next->ord, recovery_ord) <= 0)) {
        //printf("ITRC_Apply_Checkpoint_Updates: Looping in tcq_pending\n");
        t_del = t_ptr->next;
        t_ptr->next = t_del->next;
        tcq_pending.size--;
        free(t_del);
    }
    if (tcq_pending.size == 0)
        tcq_pending.tail = &tcq_pending.head;
    

    if (checkpoints.head.next != NULL 
        && checkpoints.head.next->correct == 1
        && ITRC_Ord_Compare(checkpoints.head.next->ord, applied_ord) > 0)
    {
        memcpy(&o, &checkpoints.head.next->ord, sizeof(ordinal));

        // MK: Decoupling CC and DC
        if(Type==CC_TYPE)
        {
            cp = checkpoints.head.next;
            mess = (signed_message *) cp->results;
            cp_mess = (checkpoint_msg *)(mess + 1);

            memset(plaintext, 0, CHECKPOINT_PAYLOAD_SIZE);

            ret = OPENSSL_RSA_Decrypt(&((cp_mess->payload)[DIGEST_SIZE_IV]), 
                                      cp_mess->state_size - DIGEST_SIZE_IV,
                                      (unsigned char*)(cp_mess->payload), 
                                      plaintext);
            if(ret == -1)
            {
                printf("ITRC_Apply_Checkpoint_Updates: Decrypting checkpoint failed...\n");
            }

            memset(cp_mess->payload, 0, CHECKPOINT_PAYLOAD_SIZE);
            memcpy(cp_mess->payload, plaintext, ret);
            cp_mess->state_size = ret;

            mess = PKT_Construct_State_Xfer_Msg((int32u)My_ID, cp_mess->num_clients, cp_mess->latest_update,
                                                cp_mess->payload, cp_mess->state_size);

            /* Apply the state to my progress and the SM */
            st = (state_xfer_msg *)(mess + 1);
            memcpy(progress, st->latest_update, (MAX_EMU_RTU + NUM_HMI + 1) * sizeof(seq_pair));

            // MK TODO: Update applied_seq_smencrypt here, otherwie recovered CC replica will not process client requests
            memcpy(applied_seq_smencrypt, st->latest_update, (MAX_EMU_RTU + NUM_HMI + 1) * sizeof(seq_pair));

            assert(mess != NULL);
            IPC_Send(ns->ipc_s, (void *)mess, sizeof(signed_message) + mess->len, ns->ipc_remote);
            free(mess); 
        }
        
    }

    // MK: Cleaning up updates queue
    u_ptr = &updates.head;

    // MK: Loop to o first (any updates before checkpoint must already be deleted)
    while ((u_ptr->next != NULL) && (ITRC_Ord_Compare(u_ptr->next->ord, o) <= 0))
    {
        //printf("ITRC_Apply_Checkpoint_Updates: Looping in updates before o\n");
        //MK: Infinite loop was here! ut_ptr instead of u_ptr :(
        u_ptr = u_ptr->next;
    }

    // MK: Delete everything after o
    while (u_ptr->next != NULL) {
        //printf("ITRC_Apply_Checkpoint_Updates: Looping in updates after o\n");
        u_del = u_ptr->next;
        u_ptr->next = u_del->next;
        updates.size--;
        free(u_del);
    }
    if (updates.size == 0)
    {
        updates.tail = &updates.head;
    }
    
    
    // ptr is initially set to the start of the queue
    ptr = update_transfers.head.next;

    /* 
        If recovery_ord is greater and not consecutive to o, then
        we apply correct update transfers
        up to (and including) the recovery_ord 
    */
    while (ITRC_Ord_Compare(o, recovery_ord) <= 0)
    {
        //printf("ITRC_Apply_Checkpoint_Updates: Checking o [%u,%u/%u], recovery_ord [%u,%u/%u]\n", 
            // o.ord_num, o.event_idx, o.event_tot,
            // recovery_ord.ord_num, recovery_ord.event_idx, recovery_ord.event_tot);

        if(ITRC_Ord_Compare(o, recovery_ord) == 0)
        {
            /* 
                we are not missing any needed correct update transfer,
                so break.
            */
            break;
        }
        else if (ptr == NULL)
        {
            // This should not happen. Print error if needed.
            printf("ITRC_Apply_Checkpoint_Updates: Error: ptr == NULL\n");
            break;
        }
        else
        {
            if (ITRC_Ord_Compare(ptr->ord, o) <= 0)
            {
                /* o starts later in the update transfers queue, 
                   so skip to the next */
                ptr = ptr->next;
            }
            else
            {
                if(ITRC_Ord_Consec(o, ptr->ord) != 1 || ptr->correct != 1)
                {
                    /*
                        ptr must be consecutive to o, and must be verified
                        to be correct. Otherwise, we are missing correct
                        update transfers. This should not happen.
                    */
                    printf("ITRC_Apply_Checkpoint_Updates: Error: not consecutive or correct\n");
                    break;
                }
                else
                {
                    // MK: Discard messages from SM that are part of recovery
                    // MK : Decoupling CC and DC
                    if(Type==CC_TYPE)
                    {
                        ITRC_Discard_IPC_Messages(ns);
                    }


                    // MK: Apply the update transfer message here. It will be added to my updates queue
                    
                    scada_mess = (signed_message *) ptr->result->payload;
                    ITRC_Process_Prime_Ordinal_Update_Transfer(ptr->ord, scada_mess, ns); //Will this work? Conflict with recvd_ord?

                    /* 
                        we are good here, so advance by 1 for each and check 
                        them in the next loop
                    */
                    o = ptr->ord;
                    ptr = ptr->next;
                }
            }
        }
    }

    // MK: Discard messages from SM that are part of recovery
    // MK : Decoupling CC and DC
    if(Type==CC_TYPE)
    {
        ITRC_Discard_IPC_Messages(ns);
    }
    

    /* MK: Cleanup any leftover in the Updates Transfers queue, then reset to init values */

    ut_ptr = &update_transfers.head;
    while (ut_ptr->next != NULL && (ITRC_Ord_Compare(ut_ptr->next->ord, o) <= 0)) {
        //printf("ITRC_Apply_Checkpoint_Updates: Looping in update_transfers\n");
        ut_del = ut_ptr->next;
        ut_ptr->next = ut_del->next;
        update_transfers.size--;
        free(ut_del);
    }

    if (update_transfers.size == 0)
    {
        update_transfers.tail = &update_transfers.head;
    }

    /* Move up the applied ordinal */
    applied_ord = o;
    // ITRC Checkpoint Check function here. Do we need one here?
    ITRC_Check_CHECKPOINT(o, ns);
    
    if (applied_ord.ord_num > print_target) {
        printf("State Transfer Through Ordinal %u\n", applied_ord.ord_num);
        print_target = (((applied_ord.ord_num - 1) / PRINT_PROGRESS) + 1) * PRINT_PROGRESS;
    }
    collecting_signal = 0;
    completed_transfer = 1;

    //printf("ITRC_Apply_Checkpoint_Updates: ALL DONE!!!!!!!! \n");

}


void ITRC_Discard_IPC_Messages(net_sock *ns)
{
    int running, num, nBytes;
    fd_set mask, tmask;
    struct timeval ipc_timeout;
    char buff[MAX_LEN];
    signed_message *scada_mess;
    ordinal ord_save;
    stdit it;

    FD_ZERO(&mask);
    FD_SET(ns->ipc_s, &mask);

    // MK: timeout set to 1 millisecond (1000 microseconds)
    ipc_timeout.tv_sec  = 0;
    ipc_timeout.tv_usec = 1000;

    running = 1;

    while(running == 1)
    {
        //printf("ITRC_Discard_IPC_Messages: Looping...\n");
        tmask = mask;
        num = select(FD_SETSIZE, &tmask, NULL, NULL, &ipc_timeout);

        if (num > 0)
        {
            /* Message from IPC Client */
            if (FD_ISSET(ns->ipc_s, &tmask)) 
            {
                nBytes = IPC_Recv(ns->ipc_s, buff, MAX_LEN);
                scada_mess = (signed_message *)buff;
                //seq_no = (int32u *)(scada_mess + 1);
                
                if (!ITRC_Valid_Type(scada_mess, FROM_SM_MAIN)) {
                    printf("ITRC_Discard_IPC_Messages: invalid type %d from SM_MAIN\n", scada_mess->type);
                    continue;
                }

                /* Get the saved ordinal from the queue */
                assert(stddll_size(&ord_queue) > 0);
                stddll_begin(&ord_queue, &it);
                ord_save = *(ordinal *)stdit_val(&it);
                stddll_pop_front(&ord_queue);

                /* MK: If popped ordinal is smaller than recovery_ord, then we are in 
                 recovering mode. Otherwise, there is an error */
                if (ITRC_Ord_Compare(ord_save, recovery_ord) <= 0)
                {
                    // printf("ITRC_Discard_IPC_Messages: Discarding message with ordinal: [%u:%u/%u]\n",
                    //        ord_save.ord_num, ord_save.event_idx, ord_save.event_tot);
                    continue;
                }
                else
                {
                    printf("ITRC_Discard_IPC_Messages: ord_save [%u:%u/%u] is greater than recovery_ord [%u:%u/%u]\n", 
                           ord_save.ord_num, ord_save.event_idx, ord_save.event_tot,
                            recovery_ord.ord_num, recovery_ord.event_idx, recovery_ord.event_tot);
                    return;
                }
            }
        }
        else
        {
            running = 0;
        }
    }
}


/* Helper function
 * Compares two ordinals, returning:
 *     -1 if o1 < o2
 *      0 if o1 == o2
 *      1 if o1 > o2
 */
int ITRC_Ord_Compare(ordinal o1, ordinal o2)
{
    if (o1.ord_num < o2.ord_num)
        return -1;
    else if (o1.ord_num > o2.ord_num)
        return 1;
    else if (o1.event_idx < o2.event_idx)
        return -1;
    else if (o1.event_idx > o2.event_idx)
        return 1;
    return 0;
}

/* Helper function
 * Determines if o2 is exactly one greater (consecutive) than o1 */
int ITRC_Ord_Consec(ordinal o1, ordinal o2)
{
    if ((o1.ord_num == o2.ord_num && o2.event_idx == o1.event_idx + 1) ||
         (o2.ord_num == o1.ord_num + 1 && o1.event_idx == o1.event_tot && o2.event_idx == 1))
    {
        return 1;
    }
    return 0;
}

/* MK: Determines if the ordinal number is at a checkpoint period */
int ITRC_Ord_Checkpoint_Check(ordinal o)
{
    // Create checkpoint after we reach the end of the batch matrix for that ordinal number
    if(o.ord_num % CHECKPOINT_PERIOD == 0 && o.event_idx == o.event_tot)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

/* Helper function
 * Determines if s2 is exactly one greater (consecutive) than s1 */
int ITRC_Seq_Consec(seq_pair s1, seq_pair s2)
{   
    // MK: When incarnation number increases, seq num returns back to 1
    if ((s2.incarnation == s1.incarnation && s2.seq_num == s1.seq_num + 1) || 
        (s2.incarnation > s1.incarnation && s2.seq_num == 1))
    {
        return 1;
    }
    return 0;
}

int ITRC_Valid_Type(signed_message *mess, int32u stage)
{
    switch(stage) {

        case FROM_CLIENT:
        case FROM_EXTERNAL:
            switch(mess->type) {
                case UPDATE:
                case TC_SHARE_SMENCRYPT:
                    return 1;
                /* case HMI_COMMAND:
                case RTU_DATA:
                case BENCHMARK:
                    return ITRC_Validate_Message(mess); */
                default:
                    return 0;
            }
            break;

        case FROM_PRIME:
            switch(mess->type) {
                case PRIME_NO_OP:
                case PRIME_STATE_TRANSFER:
                case PRIME_SYSTEM_RESET:
                case HMI_COMMAND:
                case RTU_DATA:
                case BENCHMARK:
                    return ITRC_Validate_Message(mess);
                default:
                    return 0;
            }
            break;

        case FROM_SM_MAIN:
            switch(mess->type) {
                case HMI_UPDATE:
                case RTU_FEEDBACK:
                case BENCHMARK:
                case CHECKPOINT:
                    return ITRC_Validate_Message(mess);
                default:
                    return 0;
            }
            break;

        case TO_CLIENT:
            switch(mess->type) {
                case HMI_UPDATE:
                case RTU_FEEDBACK:
                case BENCHMARK:
                    return ITRC_Validate_Message(mess);
                default:
                    return 0;
            }
            break;
        
        case FROM_INTERNAL:
            switch(mess->type) {
                case TC_SHARE:
                case CHECKPOINT:
                case UPDATE_TRANSFER:
                    return ITRC_Validate_Message(mess);
                default:
                    return 0;
            }
            break;

        default:
            return 0;
    }

    return 1;
}

int ITRC_Validate_Message(signed_message *mess)
{
    rtu_data_msg *rtu_mess;
    ems_fields *ems_data;

    switch (mess->type) {
        case RTU_DATA:
            // TODO: Validate message should take in received bytes so we can
            // check length
            // rtu_bytes = recvd_bytes - sizeof(signed_message);
            // if (rtu_bytes < sizeof(rtu_data_msg)) return 0;
            if (Type == CC_TYPE) {
                rtu_mess = (rtu_data_msg *)(mess + 1);
                if (rtu_mess->rtu_id >= NUM_RTU || rtu_mess->seq.seq_num == 0)
                    return 0;

                switch (rtu_mess->scen_type) {
                    case JHU:
                    case PNNL:
                        break;
                    case EMS:
                        ems_data = (ems_fields *)&rtu_mess->data;
                        if (ems_data->id >= EMS_NUM_GENERATORS) return 0;
                        break;
                    default:
                        return 0;
                }
            }
            break;

        case RTU_FEEDBACK:
        case HMI_UPDATE:
        case HMI_COMMAND:
        case TC_SHARE:
        case TC_FINAL:
        case CHECKPOINT:
        case UPDATE_TRANSFER:
        case BENCHMARK:
            break;

        case PRIME_NO_OP:
            //printf("  PRIME_NO_OP\n");
            if (mess->machine_id != (int32u)My_ID) {
                printf("Prime No_Op not from my own Prime (instead from %u)!\n", 
                            mess->machine_id);
                return 0;
            }
            break;

        case PRIME_STATE_TRANSFER:
            printf("  PRIME_STATE_TRANSFER for %d\n", mess->machine_id);
            if (mess->machine_id > NUM_SM) {
                printf("Prime State Xfer from non-Prime replica (instead from %u)\n",
                            mess->machine_id);
                return 0;
            }
            break;
        
        case PRIME_SYSTEM_RESET:
            printf("  PRIME_SYSTEM_RESET\n");
            if (mess->machine_id != (int32u)My_ID) {
                printf("Prime System Reset not from my own Prime (instead from %u)\n",
                            mess->machine_id);
                return 0;
            }
            break;

        default:
            return 0;
    }

    return 1;
}
