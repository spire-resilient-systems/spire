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

#include "net_wrapper.h"
#include "openssl_rsa.h"
#include "tc_wrapper.h"
#include "def.h"
#include "itrc.h"
#include "spines_lib.h"
#include "../config/cJSON.h"
#include "../config/config_helpers.h"
#include "key_value.h"
#include "stdutil/stddll.h"

/* These are flags used in the TC queue */
#define NORMAL_ORD 1
#define SKIP_ORD   2  

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
//itrc_queue msgq;
//int32u applied_seq;

extern int Curr_num_f;
extern int Curr_num_k;



update_history up_hist[MAX_EMU_RTU + NUM_HMI + 1];
tc_queue tcq_pending;
st_queue stq_pending;
ordinal applied_ord;
ordinal recvd_ord;
stddll ord_queue, pending_updates;
int32u collecting_signal;
int32u completed_transfer;
int32u print_target;
seq_pair progress[MAX_EMU_RTU + NUM_HMI + 1];

pthread_mutex_t wait_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t wait_condition = PTHREAD_COND_INITIALIZER;
int master_ready = 0;
int inject_ready = 0;

/* Local Functions */
void ITRC_Reset_Master_Data_Structures(int startup);
//int ITRC_Valid_ORD_ID(ordinal o);
void ITRC_Insert_TC_ID(tc_share_msg* tcm, int32u sender, int32u flag);
int ITRC_TC_Ready_Deliver(signed_message **to_deliver);
int ITRC_Send_TC_Final(int sp_ext_sk, signed_message *mess);

void ITRC_Process_Prime_Ordinal(ordinal o, signed_message *m, net_sock *ns);
//void ITRC_Handle_Prime_State_Transfer(ordinal o, signed_message *m, net_sock ns);
int ITRC_Insert_ST_ID(state_xfer_msg *st, int32u sender);
void ITRC_Apply_State_Transfer(ordinal o, net_sock ns);
void oob_reconfigure(signed_message *mess,void * data);

int ITRC_Ord_Compare(ordinal o1, ordinal o2);
int ITRC_Ord_Consec(ordinal o1, ordinal o2);
int ITRC_Valid_Type(signed_message *mess, int32u stage);
int ITRC_Validate_Message(signed_message *mess);

#if 0
/* Intrusion Tolerant Reliable Channel - Enqueue */
void ITRC_Enqueue(int32u seq, char *msg, int len, int ipc_s, char *ipc_remote)
{
    itrc_queue_node *n, *ptr = NULL;

    /* Sanity check on sequence number first */
    if (seq <= applied_seq) {
        // printf("Old Msg (%u) has arrived: applied_seq = %u\n", seq, applied_seq);
        return;
    }

    /* Find the spot to insert the message */
    if (msgq.head.next != NULL && msgq.tail->seq_num < seq) {
        printf("Will place after tail\n");
        ptr = msgq.tail;
    }
    else {
        ptr = &msgq.head;
        while(ptr->next != NULL && ptr->next->seq_num < seq)
            ptr = ptr->next;
        if (ptr->next != NULL && ptr->next->seq_num == seq)
            return;
    }
   
    /* Insert the message */
    printf("Enqueue message (%u)\n", seq);
    n = (itrc_queue_node *)malloc(sizeof(itrc_queue_node));
    n->seq_num = seq;
    memcpy(n->buf, msg, len);
    n->len = len;
    n->next = ptr->next;
    ptr->next = n;
    if (ptr == msgq.tail)
        msgq.tail = n;

    /* Check if we can make progress and deliver message */
    ptr = &msgq.head;
    while (ptr->next != NULL && ptr->next->seq_num == applied_seq + 1) {
        printf("Delivering msg (%u)\n", ptr->next->seq_num);
        IPC_Send(ipc_s, ptr->next->buf, ptr->next->len, ipc_remote);
        applied_seq++;
        n = ptr->next;
        ptr->next = n->next;
        if (msgq.tail == n)
            msgq.tail = &msgq.head;
        free(n);
    }
}
#endif

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
    //msgq.head.next = NULL;
    //msgq.tail = &msgq.head;
    /* for (i = 0; i <= MAX_EMU_RTU; i++) {
        applied[i] = 0;
    } */
    
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
        printf("ITRC_Client: Connected to Spines\n");
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
                    printf("MS2022 Error in spines_recvfrom with ns.sp_ext_s>0 and : ret = %d, dropping!\n", ret);
                    spines_close(ns.sp_ext_s);
                    FD_CLR(ns.sp_ext_s, &mask);
                    ns.sp_ext_s = -1;
                    t = &spines_timeout; 
                    continue;
                }
		//printf("Received %d on ext_spines\n",ret);
               
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
		//printf("verified scada mess seq=%lu\n",ps->seq_num);
                nBytes = sizeof(signed_message) + (int)mess->len;
                //ITRC_Enqueue(*seq_no, (char *)mess, nBytes, ns.ipc_s, itrcd->ipc_remote);
                /* if (*seq_no <= applied[*idx])
                    continue;
                applied[*idx] = *seq_no; */
                
                /* TODO: Another sanity check on the the message type being 
                 *  appropriate for the type of client I am */
               
                ord = (ordinal *)&tcf_specific->ord;
                if (ITRC_Ord_Compare(*ord, applied) <= 0){
                        //printf("Continue called\n");
			continue;
		}
                applied = *ord;
                //printf("Applying [%u, %u of %u]\n", ord->ord_num, ord->event_idx, ord->event_tot);
                IPC_Send(ns.ipc_s, (char *)mess, nBytes, ns.ipc_remote);
            }

            /* Message from IPC Client */
            if (FD_ISSET(ns.ipc_s, &tmask)) {
                nBytes = IPC_Recv(ns.ipc_s, buff, MAX_LEN);
                signed_message *test_config=(signed_message*)buff;
                if(test_config->type == PRIME_OOB_CONFIG_MSG){
			//printf("ITRC_Client: Received PRIME_OOB_CONFIG_MSG\n");
			config_message *c_mess=(config_message *)(test_config+1);
			//Reload RSA and TC Pub Keys
                        OPENSSL_RSA_Reload_Prime_Keys(Prime_Client_ID, RSA_CLIENT, "/tmp/test_keys/prime",c_mess->N);
			//TC_cleanup();
			TC_Read_Public_Key("/tmp/test_keys/sm");			
			//TC_Reload_Public_Key("/tmp/test_keys/sm");			
    			memset(&applied, 0, sizeof(ordinal));
			/*
			spines_close(ns.sp_ext_s);
                        FD_CLR(ns.sp_ext_s, &mask);
                        ns.sp_ext_s = -1;
                        //t = &spines_timeout; 
                        //printf("Closing spines due to reconf\n");
                        ns.sp_ext_s = Spines_Sock(itrcd->spines_ext_addr, itrcd->spines_ext_port, proto, my_port);
            if (ns.sp_ext_s < 0) {
                //printf("MS2022 ITRC_Client: Unable to connect to Spines, trying again soon\n");
                spines_timeout.tv_sec  = SPINES_CONNECT_SEC;
                spines_timeout.tv_usec = SPINES_CONNECT_USEC;
                t = &spines_timeout; 
            }
            else {
                //printf("$$$$$$$$$MS2022 ITRC_Client: Reconnected to ext spines\n");
                FD_SET(ns.sp_ext_s, &mask);
                t = NULL;
            }
*/
		continue;
                     
                }
                 
                if (nBytes > UPDATE_SIZE) {
                    printf("ITRC_Client: error! client message too large %d\n", nBytes);
                    continue;
                }

                //printf("ITRC_Client: client message of size %d\n", nBytes);
                if (ns.sp_ext_s == -1){
                        printf("Spines not connected , so not sending benchmark\n");
                        continue;
                }

                ps = (seq_pair *)&buff[sizeof(signed_message)];
                mess = PKT_Construct_Signed_Message(sizeof(signed_update_message) 
                            - sizeof(signed_message));
                mess->machine_id = Prime_Client_ID;
                mess->len = sizeof(signed_update_message) - sizeof(signed_message);
                mess->type = UPDATE;
                mess->incarnation = ps->incarnation;
                mess->global_configuration_number=My_Global_Configuration_Number;
                up = (update_message *)(mess + 1);
                up->server_id = Prime_Client_ID;
                up->seq_num = ps->seq_num;
                //up->seq = *ps;
                memcpy((unsigned char*)(up + 1), buff, nBytes);
                //printf("Sending Update[%u]: [%u, %u]\n", mess->global_configuration_number,mess->incarnation, up->seq_num); 

                /* SIGN Message */
                OPENSSL_RSA_Sign( ((byte*)mess) + SIGNATURE_SIZE,
                        sizeof(signed_message) + mess->len - SIGNATURE_SIZE,
                        (byte*)mess );

                rep = MIN(Curr_num_f + Curr_num_k + 1, 2 * (Curr_num_f + 2)); 
                for (i = 1; i <= rep; i++) {
                    dest.sin_family = AF_INET;
                    dest.sin_port = htons(SM_EXT_BASE_PORT + Curr_CC_Replicas[i-1]);
                    dest.sin_addr.s_addr = inet_addr(Curr_Ext_Site_Addrs[Curr_CC_Sites[i-1]]);
                    //printf("dest port=%d, dest addr=%s\n",SM_EXT_BASE_PORT + Curr_CC_Replicas[i-1],Curr_Ext_Site_Addrs[Curr_CC_Sites[i-1]]);
                    //dest.sin_port = htons(SM_EXT_BASE_PORT + CC_Replicas[i-1]);
                    //dest.sin_addr.s_addr = inet_addr(Ext_Site_Addrs[CC_Sites[i-1]]);
                    ret = spines_sendto(ns.sp_ext_s, mess, sizeof(signed_update_message),
                            0, (struct sockaddr *)&dest, sizeof(struct sockaddr));
                    if(ret != sizeof(signed_update_message)) {
                        printf("*******ITRC_Client: spines_sendto error!\n");
                        spines_close(ns.sp_ext_s);
                        FD_CLR(ns.sp_ext_s, &mask);
                        ns.sp_ext_s = -1;
                        t = &spines_timeout; 
                        break;
                        

                    //printf("dest port=%d, dest addr=%s\n",SM_EXT_BASE_PORT + Curr_CC_Replicas[i-1],Curr_Ext_Site_Addrs[Curr_CC_Sites[i-1]]);
                    }
                }
                free(mess);
            }
        }
        else {
                        ns.sp_ext_s = Spines_Sock(itrcd->spines_ext_addr, itrcd->spines_ext_port, proto, my_port);
            if (ns.sp_ext_s < 0) {
                //printf("MS2022 ITRC_Client: Unable to connect to Spines, trying again soon\n");
                spines_timeout.tv_sec  = SPINES_CONNECT_SEC;
                spines_timeout.tv_usec = SPINES_CONNECT_USEC;
                t = &spines_timeout; 
            }
            else {
                //printf("$$$$$$$$$MS2022 ITRC_Client: Reconnected to ext spines\n");
                FD_SET(ns.sp_ext_s, &mask);
                t = NULL;
            }
        }
    }
    return NULL;
}

/* Intrusion Tolerant Reliable Channel - Receive NET Message */
/* int ITRC_Receive_NET_Message(int s, char *buff)
{
    int ret, nBytes;
    signed_message *mess;

    ret = NET_Read(s, buff, sizeof(signed_message));
    if(ret <= 0) {
        perror("ITRC_Receive_NET_Message: Reading error @ 1");
        return -1;
    }
    mess = (signed_message *)buff;
    nBytes = sizeof(signed_message) + (int)mess->len;
    ret = NET_Read(s, &buff[sizeof(signed_message)], (int)mess->len);
    if(ret <= 0) {
        perror("ITRC_Receive_NET_Message: Reading error @ 2");
        return -1;
    }

    return nBytes;
} */

void *ITRC_Prime_Inject(void *data)
{
    int num, ret, nBytes;
    int prime_sock;
    int16u val;
    //unsigned int dup_bench[MAX_EMU_RTU];
    net_sock ns;
    fd_set mask, tmask;
    char buff[MAX_LEN], prime_path[128];
    signed_message *mess, *payload;
    update_message *up;
    itrc_data *itrcd;

    /* Make sure everything is set up first */
    pthread_mutex_lock(&wait_mutex);
    while (master_ready == 0) {
        pthread_cond_wait(&wait_condition, &wait_mutex);
    }
    pthread_mutex_unlock(&wait_mutex); 

    FD_ZERO(&mask);

    /* Grab IPC info */
    itrcd = (itrc_data *)data;

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
    /*MS2022: Create ipc to receive Config Agent messages*/
    /*
    printf("receiving from config agent on %s \n",itrcd->ipc_config);
    ns.ipc_config_s = IPC_DGram_Sock(itrcd->ipc_config);
    ret = fcntl(ns.ipc_config_s, F_SETFL, fcntl(ns.ipc_config_s, F_GETFL, 0) | O_NONBLOCK); 
    if (ret == -1) {
        printf("Failure setting config agent ipc socket to non-blocking\n");
        exit(EXIT_FAILURE);
    }
    FD_SET(ns.ipc_config_s, &mask);
    */
    /* Create a socket to receive state transfer requests from the ITRC_Master
     *  thread */
    sprintf(ns.inject_path, "%s%d", (char *)SM_IPC_INJECT, My_Global_ID);
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
        sprintf(prime_path, "%s%d", (char *)PRIME_REPLICA_IPC_PATH, My_Global_ID);
        printf("MS2022:Connecting to %s\n", prime_path);
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
                    printf("Prime Inject: Connected to ext spines\n");
                    continue;
                }

                /* VERIFY Client signature on message */
                mess = (signed_message *)buff;

                /* Validate Message */
                if (!ITRC_Valid_Type(mess, FROM_EXTERNAL)) {
                    printf("Prime_Inject: invalid message type (%d) from client\n", mess->type);
                    continue;
                }

                    //printf("Prime_Inject: valid message type (%d) from client\n", mess->type);
                ret = OPENSSL_RSA_Verify((unsigned char*)mess + SIGNATURE_SIZE,
                            sizeof(signed_message) + mess->len - SIGNATURE_SIZE,
                            (unsigned char *)mess, mess->machine_id, RSA_CLIENT);
                if (!ret) {
                    printf("Prime Inject: RSA_Verify Failed for Client Update from %d with message type (%d)\n", mess->machine_id, mess->type);
                    continue;
                }

                /* signed_message *aa = (signed_message *)buff;
                update_message *bb = (update_message *)(aa+1);
                if (  bb->time_stamp <= dup_bench[bb->server_id] ) {
                    printf("dup [%d,%d]\n", bb->server_id, bb->time_stamp);
                    continue;
                }
                dup_bench[bb->server_id] = bb->time_stamp; */
                
                //ret = NET_Write(prime_sock, buff, nBytes);

                /* would get blocked here if Prime stops reading */
                ret = IPC_Send(prime_sock, buff, nBytes, prime_path);
                if(ret <= 0) {
                    perror("ITRC_Prime_Inject: Prime Writing error");
                    continue;
                    /* close(prime_sock);
                    FD_CLR(prime_sock, &mask); */
                }
                //printf("Sent to prime mess type %d from %d\n",mess->type, mess->machine_id);
            }
            /*MS2022: Message from Config Agent*/
            /*
            if (ns.ipc_config_s>=0 && FD_ISSET(ns.ipc_config_s,&tmask)){
                nBytes = IPC_Recv(ns.ipc_config_s, buff, sizeof(buff));
                mess=(signed_message *)buff;
                ret = IPC_Send(prime_sock, mess, sizeof(signed_message) + mess->len, prime_path);
                if(ret <= 0) {
                    perror("ITRC_Prime_Inject: Prime Writing error");
                    continue;
                }
            }
            */

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
                signed_message * test_config=(signed_message *)buff;
                if (test_config->type == PRIME_OOB_CONFIG_MSG){
                    printf("Prime Inject, during reconf disconnecting from Spines\n");
                    spines_close(ns.sp_ext_s);
                    FD_CLR(ns.sp_ext_s, &mask);
                    /* Reconnect to spines external network if CC */
                    ns.sp_ext_s = ret = -1;
		    //TODO: If not part of config do not connect
		    config_message *c_mess;
		    c_mess=(config_message *)test_config;
                    if(c_mess->tpm_based_id[My_Global_ID-1]==0){
			//printf("As not part of conf, not connecting to ext spines\n");
			continue;
			}
                    while (ns.sp_ext_s < 0 || ret < 0) {
			if(Type==DC_TYPE){
				break;
				}
                        printf("Prime_Inject: Trying to reconnect to external spines during reconf\n");
                        ns.sp_ext_s = Spines_Sock(itrcd->spines_ext_addr, itrcd->spines_ext_port,
                                    SPINES_PRIORITY, SM_EXT_BASE_PORT + My_ID);
                        while (ns.sp_ext_s < 0) {
                            sleep(SPINES_CONNECT_SEC);
                            ns.sp_ext_s = Spines_Sock(itrcd->spines_ext_addr, itrcd->spines_ext_port,
                                    SPINES_PRIORITY, SM_EXT_BASE_PORT + My_ID);
                            //continue;
                        }

                        val = 2;
                        ret = spines_setsockopt(ns.sp_ext_s, 0, SPINES_SET_DELIVERY, (void *)&val, sizeof(val));
                        if (ret < 0) {
                            spines_close(ns.sp_ext_s);
                            ns.sp_ext_s = -1;
                            sleep(SPINES_CONNECT_SEC);
                            continue;
                        }
                    	FD_SET(ns.sp_ext_s, &mask);
                    	printf("Prime Inject reconnected to ext spines\n");
                    	continue;
                    	}
                    }
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
                //FD_CLR(ns.inject_s, &mask);
                //close(ns.inject_s);
                //ns.inject_s = -1;
                //memset(ns.inject_path, 0, sizeof(ns.inject_path));
            }//ns_inject_s
        }//if num >0
    }//while

    return NULL;
}

void ITRC_Reset_Master_Data_Structures(int startup)
{
    int32u i;
    stdit it;
    tc_node *t_ptr, *t_del;
    st_node *s_ptr, *s_del;
    signed_message *mess;

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

    memset(&applied_ord, 0, sizeof(ordinal));
    memset(&recvd_ord, 0, sizeof(ordinal));
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
    int i, j, num, ret, nBytes;
    int prime_sock,prime_send_sock;
    seq_pair zero_ps = {0, 0};
    //int32u *seq_no;
    //unsigned int rtu_seq[MAX_EMU_RTU], hmi_seq;            /* highest seq sent to each rtu/hmi */
    //unsigned int progress_rtu[MAX_EMU_RTU], progress_hmi;  /* highest seq sent to master from rtu/hmi */
    //unsigned int progress_benchmark[MAX_EMU_RTU];
    //unsigned int dup_bench[MAX_EMU_RTU];
    net_sock ns;
    fd_set mask, tmask;
    char buff[MAX_LEN], prime_client_path[128],prime_path[128];
    struct sockaddr_in dest;
    signed_message *mess, *scada_mess, *tc_final;
    client_response_message *res;
    //rtu_feedback_msg *rtuf;
    //rtu_data_msg *rtud;
    //hmi_update_msg *hmiu;
    //hmi_command_msg *hmic;
    //benchmark_msg *ben;
    itrc_data *itrcd;
    //struct in_addr print_addr;
    tc_share_msg *tc_mess;
    state_xfer_msg *st_mess;
    stdit it;
    ordinal ord_save;
    int32u recvd_first_ordinal;
    struct timeval spines_timeout, *t;

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
    
    //MS2022: Config agent to sm ipc set up 
    printf("receiving from itrc main on %s \n",itrcd->ipc_config);
    ns.ipc_config_s = IPC_DGram_Sock(itrcd->ipc_config);
    /*
    ret = fcntl(ns.ipc_config_s, F_SETFL, fcntl(ns.ipc_config_s, F_GETFL, 0) | O_NONBLOCK);
    if (ret == -1) {
        printf("Failure setting config agent ipc socket to non-blocking\n");
        exit(EXIT_FAILURE);
    }
    */
    FD_SET(ns.ipc_config_s, &mask);
    
    /* Read Keys */
    OPENSSL_RSA_Init();
    OPENSSL_RSA_Read_Keys(My_ID, RSA_SERVER, itrcd->prime_keys_dir);
    TC_Read_Public_Key(itrcd->sm_keys_dir);
    TC_Read_Partial_Key(My_ID, 1, itrcd->sm_keys_dir); /* only "1" site */

    spines_timeout.tv_sec  = SPINES_CONNECT_SEC;
    spines_timeout.tv_usec = SPINES_CONNECT_USEC;
    t = NULL;

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
    sprintf(ns.inject_path, "%s%d", (char *)SM_IPC_INJECT, My_Global_ID);
    ret = fcntl(ns.inject_s, F_SETFL, fcntl(ns.inject_s, F_GETFL, 0) | O_NONBLOCK); 
    if (ret == -1) {
        printf("Failure setting inject socket to non-blocking\n");
        exit(EXIT_FAILURE);
    }

    /* Connect to Prime */
    if (USE_IPC_CLIENT) {
        sprintf(prime_client_path, "%s%d", (char *)PRIME_CLIENT_IPC_PATH, My_Global_ID);
        prime_sock = IPC_DGram_Sock(prime_client_path);
        prime_send_sock = IPC_DGram_SendOnly_Sock();
        sprintf(prime_path, "%s%d", (char *)PRIME_REPLICA_IPC_PATH, My_Global_ID);
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

                // REMOVE THIS - just for checking
                //continue;
                //MS2022 - Comment this print in actual runs
                struct timeval prime_t;
                gettimeofday(&prime_t,NULL);
                //printf("Received message of type %d from prime_sock at %lu, %lu\n",mess->type,prime_t.tv_sec,prime_t.tv_usec);
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
                    struct timeval reset_t;
                    gettimeofday(&reset_t,NULL);
                    //printf("MS2022:*****Processing prime system reset received at %lu   %lu \n",reset_t.tv_sec,reset_t.tv_usec);
                    /* Reset data structures */
                    ITRC_Reset_Master_Data_Structures(0);

                    /* Send the SYSTEM RESET message to the Scada Master */
                    scada_mess = PKT_Construct_Signed_Message(0);
                    scada_mess->machine_id = My_ID;
                    scada_mess->len = 0;
                    scada_mess->type = SYSTEM_RESET;
                    IPC_Send(ns.ipc_s, (void *)scada_mess, sizeof(signed_message), ns.ipc_remote);
                    continue;
                }
                /* Check if we received a SYSTEM RECONF message from Prime, which occurs on
                 * the initial startup or when system is reconfigured */
                if (scada_mess->type == PRIME_SYSTEM_RECONF) {
                    assert(ord_save.ord_num == 0);

                    printf("Processed PRIME_SYSTEM_RECONF @ ITRC\n");
                    struct timeval reset_t;
                    gettimeofday(&reset_t,NULL);
                    //printf("MS2022:*****Processing prime system reconf received at %lu   %lu \n",reset_t.tv_sec,reset_t.tv_usec);
                    /* Reset data structures */
                    ITRC_Reset_Master_Data_Structures(0);

                    /* Send the SYSTEM RESET message to the Scada Master */
                    scada_mess = PKT_Construct_Signed_Message(0);
                    scada_mess->machine_id = My_ID;
                    scada_mess->len = 0;
                    scada_mess->type = SYSTEM_RESET;
                    IPC_Send(ns.ipc_s, (void *)scada_mess, sizeof(signed_message), ns.ipc_remote);
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
                       //printf("Sahiti*****: t set to spines timeout\n");
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
            }

            if (FD_ISSET(ns.ipc_config_s,&tmask)){
                    printf("Received on ipc_config_s\n");
                    nBytes = IPC_Recv(ns.ipc_config_s, buff, MAX_LEN);
                    printf("Received message of size=%d\n",nBytes);
                    scada_mess = (signed_message *)buff;
		    if(scada_mess->global_configuration_number<=My_Global_Configuration_Number){
			printf("Ignoring config message %lu, as my My_Global_Configuration_Number is %lu\n",scada_mess->global_configuration_number,My_Global_Configuration_Number);
			continue;
		    }
                    printf("Received OOB config message of size=%d, new conf=%lu\n",scada_mess->len,scada_mess->global_configuration_number);
                    ret = IPC_Send(prime_send_sock, scada_mess, sizeof(signed_message) + scada_mess->len, prime_path);
                    if(ret <= 0) {
                        perror("ITRC_Main: Config Message Prime Writing error");
                        continue;
                    }
                    printf("Sent OOB Config Msg to prime; total size=%d, mess->len=%d and sizeof signed message=%d\n",ret,scada_mess->len,sizeof(signed_message));
                    
                    //Reset?
                    if(scada_mess->type==PRIME_OOB_CONFIG_MSG)
                        oob_reconfigure(scada_mess,data);
                    FD_CLR(ns.sp_int_s, &mask);
                    spines_close(ns.sp_int_s);
                    ns.sp_int_s = -1;
                    spines_close(ns.sp_ext_s);
                    FD_CLR(ns.sp_ext_s, &mask);
                    ns.sp_ext_s = -1;
                    //spines_timeout.tv_sec  = SPINES_CONNECT_SEC;
                    //spines_timeout.tv_usec = SPINES_CONNECT_USEC;
                    //t = &spines_timeout;
                    t=NULL;
                    int inject_ret=IPC_Send(ns.inject_s, (void *)mess, nBytes, ns.inject_path);
                    if(inject_ret!=nBytes){
                        printf("Error sending to prime inject ns.inject_s=%d\n",ns.inject_s);
                    }
                    else{
                        printf("Sent to prime inject to reconnect to spines ext\n");
                    }

                   if (ns.sp_int_s == -1 && PartOfConfig==1) {
                            // All replicas connect to internal network as send/recv
                            ns.sp_int_s = Spines_Sock(itrcd->spines_int_addr, itrcd->spines_int_port,
                                SPINES_PRIORITY, SM_INT_BASE_PORT + My_ID);
                    	if (ns.sp_int_s < 0) {
                            printf("ITRC_Master: Unable to connect to internal Spines during reconf, trying again soon\n");
                            spines_timeout.tv_sec  = SPINES_CONNECT_SEC;
                            spines_timeout.tv_usec = SPINES_CONNECT_USEC;
                            t = &spines_timeout;
                    	}
                	else {
                    		FD_SET(ns.sp_int_s, &mask);
                    		printf("ITRC_Master: set mask on spines int\n");
                	}
            	}

                if (ns.sp_ext_s == -1 && PartOfConfig==1) {
                /* Connect to spines external network if CC */
                	if (Type == CC_TYPE) {
                    		ns.sp_ext_s = Spines_SendOnly_Sock(itrcd->spines_ext_addr, itrcd->spines_ext_port,
                                SPINES_PRIORITY);
                    		if (ns.sp_ext_s < 0) {
                        		printf("ITRC_Master: Unable to connect to external Spines during reconf, trying soon\n");
                        		spines_timeout.tv_sec  = SPINES_CONNECT_SEC;
                        		spines_timeout.tv_usec = SPINES_CONNECT_USEC;
                        		t = &spines_timeout;
                    		}
                    		else{
                        		printf("ITRC_Master: Reconnected to spines ext during reconf\n");
                    		}
                	}
            	}


                    //continue;
            }//ipc_config_s

            /* Incoming IPC message */
            if (FD_ISSET(ns.ipc_s, &tmask)) {
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

                /* printf("popped off ord: [%u, %u of %u]\n", ord_save.ord_num, ord_save.event_idx, 
                          ord_save.event_tot); */

                /* TODO - is it possible that we got a message back from the SM after we already
                 * jumped past this ordinal? If so, should we throw away message and ordinal that
                 * we pulled off the queue? */

                if (scada_mess->type == STATE_XFER) {
                   
                    if (ns.sp_int_s == -1)
                        continue;

                    st_mess = (state_xfer_msg *)(scada_mess + 1);
                    st_mess->ord = ord_save;

                    /* printf("  POP ord: [%u, %u of %u] for ST to %u\n", ord_save.ord_num, ord_save.event_idx, 
                          ord_save.event_tot, st_mess->target); */

                    /* Sign State Xfer Message */ 
                    OPENSSL_RSA_Sign( ((byte*)scada_mess) + SIGNATURE_SIZE,
                                      sizeof(signed_message) + scada_mess->len - SIGNATURE_SIZE,
                                      (byte*)scada_mess);

                    /* printf("  sending ST to %d on ord [%u,%u/%u]\n", st_mess->target,
                            st_mess->ord.ord_num, st_mess->ord.event_idx, st_mess->ord.event_tot); */

                    /* Send the state transfer message to the target replica that needs it */
                    dest.sin_family = AF_INET;
                    dest.sin_port = htons(SM_INT_BASE_PORT + st_mess->target);
                    dest.sin_addr.s_addr = inet_addr(Curr_Int_Site_Addrs[All_Sites[st_mess->target-1]]);
                    //dest.sin_addr.s_addr = inet_addr(Int_Site_Addrs[All_Sites[st_mess->target-1]]);
                    ret = spines_sendto(ns.sp_int_s, scada_mess, sizeof(signed_message) + scada_mess->len,
                                0, (struct sockaddr *)&dest, sizeof(struct sockaddr));
                    if (ret != (int)(sizeof(signed_message) + scada_mess->len)) {
                        printf("ITRC_Master: spines_sendto error on STATE_TRANSFER msg!\n");
                        spines_close(ns.sp_int_s);
                        FD_CLR(ns.sp_int_s, &mask);
                        ns.sp_int_s = -1;
                        t = &spines_timeout;
                    }
                    continue;
                }
               
                /* Otherwise, this is a normal SCADA message for a client */
                mess = PKT_Construct_TC_Share_Msg(ord_save, (char *)scada_mess, nBytes);
                tc_mess = (tc_share_msg *)(mess + 1);
                //printf("Construct TC share message My_ID=%u \n",My_ID);
                /* SIGN TC Share Message */
                OPENSSL_RSA_Sign( ((byte*)mess) + SIGNATURE_SIZE,
                        sizeof(signed_message) + mess->len - SIGNATURE_SIZE,
                        (byte*)mess);

                /* If a CC, store your own share, possibly delivering afterwards if you
                 *  have enough matching TC shares to create a final signature */
                if (Type == CC_TYPE) {
                    ITRC_Insert_TC_ID(tc_mess, My_ID, NORMAL_ORD);
                    while (ITRC_TC_Ready_Deliver(&tc_final)) {
                        if (ITRC_Send_TC_Final(ns.sp_ext_s, tc_final) < 0) {
                            printf("ITRC_Master: External spines error, try to reconnect soon\n");
                            free(tc_final);
                            spines_close(ns.sp_ext_s);
                            ns.sp_ext_s = -1;
                            t = &spines_timeout;
                            break;
                        }
                        //printf("1. ITRC Master: ITRC_Send_TC_Final sent\n");
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
                    dest.sin_port = htons(SM_INT_BASE_PORT + Curr_CC_Replicas[i-1]);
                    dest.sin_addr.s_addr = inet_addr(Curr_Int_Site_Addrs[CC_Sites[i-1]]);
                    //dest.sin_port = htons(SM_INT_BASE_PORT + CC_Replicas[i-1]);
                    //dest.sin_addr.s_addr = inet_addr(Int_Site_Addrs[CC_Sites[i-1]]);
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
                    //printf("Sent my TC share my id=%u on %d\n",My_ID,SM_INT_BASE_PORT + Curr_CC_Replicas[i-1]);

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
                    while (ITRC_TC_Ready_Deliver(&tc_final)) {
                        if (ITRC_Send_TC_Final(ns.sp_ext_s, tc_final) < 0) {
                            printf("ITRC_Master: External spines error, try to reconnect soon\n");
                            free(tc_final);
                            spines_close(ns.sp_ext_s);
                            ns.sp_ext_s = -1;
                            t = &spines_timeout;
                            break;
                        }
                        free(tc_final);
                        //printf("2. ITRC_Send_TC_Final  sent\n");
                    }
                }
                else if (mess->type == STATE_XFER) {
                    st_mess = (state_xfer_msg *)(mess + 1);

                    /* Try to insert the ST state from this replica */
                    printf("Recv STATE_XFER message from %d about [%u:%u/%u]\n", 
                            mess->machine_id, st_mess->ord.ord_num, st_mess->ord.event_idx, 
                            st_mess->ord.event_tot);
                    if (ITRC_Insert_ST_ID(st_mess, mess->machine_id)) {
                        ITRC_Apply_State_Transfer(st_mess->ord, ns);
                    }

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
                }
                else {
                    printf("Invalid message on spines_internal. rep_type = %d, "
                            "mess_type = %d\n", Type, mess->type);
                }
            }

            
        }// if num >0
        else {

	   //printf("ITRC num=%d\n",num);
            if (FD_ISSET(prime_sock, &tmask)) {
		printf("num=%d and prime_sock is set\n",num);
		}
            if (FD_ISSET(ns.ipc_config_s, &tmask)) {
		printf("num=%d and ipc_config_s is set\n",num);
		}
            if (FD_ISSET(ns.ipc_s, &tmask)) {
		printf("num=%d and ipc_s is set\n",num);
		}
            if (ns.sp_int_s>0 && FD_ISSET(ns.sp_int_s, &tmask)) {
		printf("num=%d and ipc_s is set\n",num);
		}

            t = NULL;
            if (ns.sp_int_s == -1 && PartOfConfig==1) {
                // All replicas connect to internal network as send/recv
                ns.sp_int_s = Spines_Sock(itrcd->spines_int_addr, itrcd->spines_int_port,
                                SPINES_PRIORITY, SM_INT_BASE_PORT + My_ID);
                if (ns.sp_int_s < 0) {
                    printf("ITRC_Master: Unable to connect to internal Spines, trying again soon\n");
                    spines_timeout.tv_sec  = SPINES_CONNECT_SEC;
                    spines_timeout.tv_usec = SPINES_CONNECT_USEC;
                    t = &spines_timeout;
                }
                else {
                    printf("&&&&&&&&MS2022: Reconnected to spines int\n");
                    FD_SET(ns.sp_int_s, &mask);
                    //printf("&&&&&&&&MS2022: set mask on spines int\n");
                }
            }
		
            if (ns.sp_ext_s == -1 && PartOfConfig==1) {
                /* Connect to spines external network if CC */
                if (Type == CC_TYPE) {
                    ns.sp_ext_s = Spines_SendOnly_Sock(itrcd->spines_ext_addr, itrcd->spines_ext_port,
                                SPINES_PRIORITY);
                    if (ns.sp_ext_s < 0) {
                        printf("ITRC_Master: Unable to connect to external Spines, trying soon\n");
                        spines_timeout.tv_sec  = SPINES_CONNECT_SEC;
                        spines_timeout.tv_usec = SPINES_CONNECT_USEC;
                        t = &spines_timeout;
                    }
                    else{
                        printf("&&&&&&&&MS2022: Reconnected to spines ext\n");
                    }
                }
            }
		
        }//while else i.e., num<=0
    }//while
  
    /* Should do some cleanup if we ever close gracefully, even if from
     * catching interrupt signal */
    stddll_destruct(&ord_queue);
    return NULL;
}


void oob_reconfigure(signed_message *mess,void *data)
{
    config_message * c_mess;
    itrc_data *itrcd;
    
    c_mess=(config_message *)(mess+1);
    itrcd=(itrc_data *)data;
    My_Global_Configuration_Number=mess->global_configuration_number;
    //Close Network
    int new_id= c_mess->tpm_based_id[My_Global_ID-1];
    if (new_id==0){
	printf("Not part of new configuration %lu \n",mess->global_configuration_number);
        PartOfConfig=0;
        //TC_cleanup();
        return;
	//perror("Not part of new configuration\n");
        //exit(0);
    }
    PartOfConfig=1;
    //Update defs
    Reset_SM_def_vars(c_mess->N,c_mess->f,c_mess->k,c_mess->num_cc_replicas,c_mess->num_cc,c_mess->num_dc);

    //Update My_ID
    My_ID=new_id;
    Prime_Client_ID = My_ID;
    printf("Part of new configuration %lu my ID=%d\n",mess->global_configuration_number,My_ID);
    if (c_mess->replica_flag[My_Global_ID-1]==1)
        Type = CC_TYPE;
    else
        Type = DC_TYPE;

    //Update keys dir
    
    //Reload Keys
    OPENSSL_RSA_Reload_Prime_Keys(My_ID, RSA_SERVER, "/tmp/test_keys/prime",c_mess->N);
    //TC_cleanup();
    sprintf(itrcd->sm_keys_dir,"%s","/tmp/test_keys/sm");
    TC_Read_Public_Key(itrcd->sm_keys_dir);
    TC_Read_Partial_Key(My_ID, 1, itrcd->sm_keys_dir); /* only "1" site */
    //Update Server addresses
    Reset_SM_Replicas(c_mess->tpm_based_id,c_mess->replica_flag,c_mess->spines_ext_addresses,c_mess->spines_int_addresses);
    printf("Reset SM Replica Addresses\n");
    //Reply to config agent
}

void ITRC_Process_Prime_Ordinal(ordinal o, signed_message *mess, net_sock *ns)
{
    int nBytes;
    char duplicate, valid_content;
    int32u *idx;
    seq_pair *ps;
    client_response_message *res;
    signed_message *scada_mess, *tc_final, *state_req, *pend_mess;
    tc_share_msg tc_skip_msg;
    state_xfer_msg st_dummy_msg;
    st_node *s_ptr, *s_del;

    res = (client_response_message *)(mess + 1);
    scada_mess = (signed_message *)(res + 1);

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
    valid_content = 1;
    if (!ITRC_Valid_Type(scada_mess, FROM_PRIME)) {
        printf("ITRC_Process_Prime_Ordinal: Invalid message from Prime, type = %d\n", scada_mess->type);
        valid_content = 0;
    }

    /* First, if this is a real SCADA client message, see if its a duplicate */    
    duplicate = 0;
    if (valid_content && (scada_mess->type == HMI_COMMAND ||
                          scada_mess->type == RTU_DATA ||
                          scada_mess->type == BENCHMARK))
    {
        ps = (seq_pair *)(scada_mess + 1);
        idx = (int32u *)(ps + 1);
        //printf("received=%u\n",ps->seq_num);
        if (Seq_Pair_Compare(*ps, progress[*idx]) <= 0) {
            /*printf("Duplicate!! [%u,%u] from %d, and I have [%u,%u]\n", 
                    ps->incarnation, ps->seq_num, *idx, 
                    progress[*idx].incarnation, progress[*idx].seq_num);*/ 
            duplicate = 1;
        }
        // SAM EMS
        if (scada_mess->type == RTU_DATA) {
            rtu_data_msg *rtud = (rtu_data_msg *)(scada_mess + 1);
            if (rtud->scen_type == EMS) {
                /*printf("SM ITRC has received EMS update: [%d,%d]\n", */
                            /*rtud->seq.incarnation, rtud->seq.seq_num);*/
                //duplicate = 1;
            }
        }
    }

    /* Treat PRIME_NO_OP, PRIME_STATE_TRANSFER, PRIME_SYSTEM_RESET, and duplicate client
     *  messages as NO_OPs that don't do a real TC - just skip over them */
    if (!valid_content || scada_mess->type == PRIME_NO_OP ||
        scada_mess->type == PRIME_STATE_TRANSFER ||
        scada_mess->type == PRIME_SYSTEM_RESET || duplicate == 1) 
    {
        /* Create empty slot in the TC queue for both no_op and state xfer */
        // TODO: Figure out how to make DC keep history
        if (Type == CC_TYPE) {
            memset(&tc_skip_msg, 0, sizeof(tc_share_msg));
            tc_skip_msg.ord = o;
            ITRC_Insert_TC_ID(&tc_skip_msg, My_ID, SKIP_ORD);
            while (ITRC_TC_Ready_Deliver(&tc_final)) {
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
            
            /* Just to be safe, zero out my own local state in my version of the msg */
            //memset(st_specific->up_hist, 0, sizeof(st_specific->up_hist));
           
            memset(&st_dummy_msg, 0, sizeof(state_xfer_msg));
            st_dummy_msg.ord = o;
            if (ITRC_Insert_ST_ID(&st_dummy_msg, My_ID)) {
                ITRC_Apply_State_Transfer(o, *ns);
            }
        }
        /* I don't need state transfer - cleanup any memory that may be lying around up
         * to and including this ST slot */
        else {
            //printf("Skipping over unneeded ST for [%d,%d/%d]\n", o.ord_num, o.event_idx, o.event_tot);
            s_ptr = &stq_pending.head;
            while (s_ptr->next != NULL && (ITRC_Ord_Compare(s_ptr->next->ord, o) <= 0)) {
                s_del = s_ptr->next;
                s_ptr->next = s_del->next;
                stq_pending.size--;
                free(s_del);
            }
            if (stq_pending.size == 0)
                stq_pending.tail = &stq_pending.head;
            if (Type == DC_TYPE)
                applied_ord = o;
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

    /* Put the ordinal at the back of the ordinal queue for later use with returning SM msg */
    stddll_push_back(&ord_queue, &o);

    if (scada_mess->type != PRIME_STATE_TRANSFER) {

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
    else {
        /* Pass in my latest seq_pair from each client to be included in the
         *  State Xfer message, and send to SM */
        //printf("ST should be on ord: [%u, %u of %u]\n", o.ord_num, o.event_idx, o.event_tot);
        state_req = PKT_Construct_State_Request_Msg(scada_mess->machine_id, progress);
        nBytes = sizeof(signed_message) + state_req->len;
        IPC_Send(ns->ipc_s, (void *)state_req, nBytes, ns->ipc_remote);
        free(state_req);
    }
//printf("Returning from ITRC_Process_Prime_Ordinal\n");

}

#if 0
int ITRC_Valid_ORD_ID(ordinal o)
{
    /* Check if this ord is older than what we've already applied */
    if (ITRC_Ord_Compare(o, applied_ord) <= 0)
        return 0;

    /* May want to check size of the queues (TC or ST) against HISTORY */ 

    return 1;
}
#endif

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
        //printf("\tinstance [%u,%u/%u] is already done!\n", ptr->ord.ord_num, 
        //            ptr->ord.event_idx, ptr->ord.event_tot); 
        return;
    }

    if (ptr->recvd[sender] == 1){
        //printf("Return as ptr->recvd[%d]==1\n",sender);
        return;
    }

    ptr->recvd[sender] = 1;
    ptr->count++;

    /* Special case for NO_OPs and STATE_TRANSFER, which don't do TC */
    if (flag == SKIP_ORD) {
        //printf("SKIP_ORD set\n");
        ptr->done = 1;
        ptr->skip = 1;
        return;
    }

    memcpy(&ptr->shares[sender], tcm, sizeof(tc_share_msg));
    //printf("sender=%d, count=%d, req shares=%d received_own=%d\n",sender,ptr->count,REQ_SHARES,ptr->recvd[My_ID]);
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
            //printf("Signing TC Final\n");
        }
        else {
            ptr->skip = 1;
        }
        ptr->done = 1;
    }
}

/* Check if we can make progress and deliver a message. Remove message from queue, store it in
 * to_deliver, and return 1 is success. Otherwise, return 0. */
int ITRC_TC_Ready_Deliver(signed_message **to_deliver)
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
    //printf("ITRC_TC_Ready_Deliver ready flag = %d\n",ready); 
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
        //printf("\nSENT benchmark response on %s \n",SPINES_RTU_ADDR);
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
     //printf("\nSENT response of %d on ext spines \n",ret);

    return 1;
}

int ITRC_Insert_ST_ID(state_xfer_msg *st, int32u sender)
{
    int32u i, match_count;
    ordinal o;
    st_queue *stq;
    st_node *n, *ptr;
    state_xfer_msg *stored_st;
    char new_entry;
    byte digest[DIGEST_SIZE], stored_digest[DIGEST_SIZE];

    if ( (ITRC_Ord_Compare(st->ord, recvd_ord) < 0) || (ITRC_Ord_Compare(st->ord, applied_ord) <= 0)) {
        printf("Old ST ID: [%u:%u/%u]\n", st->ord.ord_num, st->ord.event_idx, st->ord.event_tot);
        return 0;
    }

    o = st->ord;
    stq = &stq_pending;
    ptr = NULL;
    new_entry = 0;

    /* If new_entry is 1 (true), insert new node as ptr next.
     * If new_entry is 0 (false), ptr will point at matching node */

    /* First, check if this is a new entry */
    /* If the queue is empty, or this ord is greater than the tail, insert this after
     * the tail. We already checked that the ord has not yet been completed */
    if (stq->head.next == NULL || (ITRC_Ord_Compare(o, stq->tail->ord) > 0)) {
        ptr = stq->tail;
        new_entry = 1;
        //printf("ST: After tail - ");
    }
    else {
        ptr = &stq->head;
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

        n = (st_node *)malloc(sizeof(st_node));
        memset(n, 0, sizeof(st_node));
        n->ord = o;
        n->next = ptr->next;
        ptr->next = n;

        if (ptr == stq->tail)
            stq->tail = n;
        ptr = n;
    
        /* Increase the size, and if we exceed the history size, jump ahead and readjust */
        stq->size++;
    }
    /* At this point, ptr points to the current st_node */

    /* If this is from myself (my Prime), mark the slot as signaled */
    if (sender == (int32u)My_ID) {
        ptr->signaled = 1;
        //printf("  Signal from Prime below for ST on %d,%d/%d\n", o.ord_num, o.event_idx, o.event_tot);
    }
    /* Otherwise, this is from one of the other replicas */
    else {
        if (ptr->recvd[sender] == 1)
            return 0;

        printf("\tstate from %d on ord [%u,%u/%u]\n", sender, o.ord_num, o.event_idx, o.event_tot);
        ptr->recvd[sender] = 1;
        ptr->count++;
        memcpy(&ptr->state[sender], st, sizeof(state_xfer_msg) + st->state_size);

        if (ptr->collected == 0 && ptr->count >= REQ_SHARES) {
            
            /* See if we now have F+1 (aka REQ_SHARES) number of matching
             *  state xfer messages in order to finish this off */
            OPENSSL_RSA_Make_Digest(st, sizeof(state_xfer_msg) + st->state_size, digest);
            match_count = 0;
            for (i = 1; i <= Curr_num_SM; i++) {
                if (ptr->recvd[i] == 0)
                    continue;
                       
                stored_st = (state_xfer_msg *)(&ptr->state[i]);
                OPENSSL_RSA_Make_Digest(stored_st, sizeof(state_xfer_msg) + stored_st->state_size, 
                                            stored_digest);
                if (OPENSSL_RSA_Digests_Equal(digest, stored_digest))
                    match_count++;
            }
            if (match_count >= REQ_SHARES) {
                ptr->result = (state_xfer_msg *)(&ptr->state[sender]);
                    //malloc(sizeof(state_xfer_msg) + st->state_size);
                    //memcpy(ptr->result, st, sizeof(state_xfer_msg) + st->state_size);
                //printf("  Collected f+1 matching for %d,%d/%d\n", o.ord_num, o.event_idx, o.event_tot);
                ptr->collected = 1;
            }
        }
    }

    /* See if we've now collected enough matching state AND have been signaled 
     *  from below.  */
    if (ptr->collected == 1 && ptr->signaled == 1) {
        printf("COMPLETED A STATE TRANSFER: [%u,%u/%u]\n", o.ord_num, o.event_idx, o.event_tot);
        return 1;
    }

    return 0;
}

void ITRC_Apply_State_Transfer(ordinal o, net_sock ns)
{
    signed_message *mess;
    state_xfer_msg *st;
    st_node *s_ptr, *s_del;
    tc_node *t_ptr, *t_del;

    mess = NULL;

    /* Cleanup the ST queue if there is any pending state transfers
     * prior to the target one (at ordinal o) */
    s_ptr = &stq_pending.head;
    while (s_ptr->next != NULL && (ITRC_Ord_Compare(s_ptr->next->ord, o) <= 0)) {
        s_del = s_ptr->next;
        s_ptr->next = s_del->next;
        stq_pending.size--;

        if (ITRC_Ord_Compare(s_del->ord, o) == 0) {
            st = s_del->result;
            assert(st != NULL);
            mess = PKT_Construct_State_Xfer_Msg(st->target, st->num_clients, st->latest_update,
                                                ((char *)(st + 1)), st->state_size);
        }

        //if (s_del->result != NULL)
        //    free(s_del->result);
        free(s_del);
    }
    if (stq_pending.size == 0)
        stq_pending.tail = &stq_pending.head;

    /* Cleanup the TC queue */
    t_ptr = &tcq_pending.head;
    while (t_ptr->next != NULL && (ITRC_Ord_Compare(t_ptr->next->ord, o) <= 0)) {
        t_del = t_ptr->next;
        t_ptr->next = t_del->next;
        tcq_pending.size--;
        free(t_del);
    }
    if (tcq_pending.size == 0)
        tcq_pending.tail = &tcq_pending.head;

    /* Apply the state to my progress and the SM */
    //printf("INSIDE APPLY STATE\n");
    //Print_State(o, up_hist);
    st = (state_xfer_msg *)(mess + 1);
    memcpy(progress, st->latest_update, (MAX_EMU_RTU + NUM_HMI + 1) * sizeof(seq_pair));
    assert(mess != NULL);
    IPC_Send(ns.ipc_s, (void *)mess, sizeof(signed_message) + mess->len, ns.ipc_remote);
    free(mess);

    /* Move up the applied ordinal */
    applied_ord = o;
    if (applied_ord.ord_num > print_target) {
        printf("State Transfer Through Ordinal %u\n", applied_ord.ord_num);
        print_target = (((applied_ord.ord_num - 1) / PRINT_PROGRESS) + 1) * PRINT_PROGRESS;
    }
    collecting_signal = 0;
    completed_transfer = 1;
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

int ITRC_Valid_Type(signed_message *mess, int32u stage)
{
    switch(stage) {

        case FROM_CLIENT:
        case FROM_EXTERNAL:
            switch(mess->type) {
                case UPDATE:
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
                case STATE_XFER:
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
                case STATE_XFER:
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
            break;

        case RTU_FEEDBACK:
        case HMI_UPDATE:
        case HMI_COMMAND:
        case TC_SHARE:
        case TC_FINAL:
        case STATE_XFER:
        case BENCHMARK:
        case PRIME_OOB_CONFIG_MSG:
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
            if (mess->machine_id > Curr_num_SM) {
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
