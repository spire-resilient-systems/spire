/*
 * Spines.
 *
 * The contents of this file are subject to the Spines Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.spines.org/LICENSE.txt
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Creators of Spines are:
 *  Yair Amir, Claudiu Danilov, John Schultz, Daniel Obenshain,
 *  Thomas Tantillo, and Amy Babay.
 *
 * Copyright (c) 2003-2020 The Johns Hopkins University.
 * All rights reserved.
 *
 * Major Contributor(s):
 * --------------------
 *    John Lane
 *    Raluca Musaloiu-Elefteri
 *    Nilo Rivera 
 * 
 * Contributor(s): 
 * ----------------
 *    Sahiti Bommareddy 
 *
 */

#ifndef IT_UDP_H
#define IT_UDP_H

#ifdef ARCH_PC_WIN95
#include <winsock2.h>
#endif

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/bio.h>

#include <stdlib.h>
#include "assert.h"
#include "arch.h"
#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_memory.h"
#include "spu_data_link.h"
#include "stdutil/stdhash.h"
#include "stdutil/stdcarr.h"

#include "objects.h"
#include "net_types.h"
#include "node.h"
#include "link.h"
#include "network.h"
#include "link_state.h"
#include "hello.h"
#include "protocol.h"
#include "route.h"           /* Dissemination method 0 */
#include "priority_flood.h"  /* Dissemination method 1 */
#include "reliable_flood.h"  /* Dissemination method 2 */
#include "session.h"
#include "state_flood.h"
#include "multicast.h"
#include "udp.h"
#include "configuration.h"

/* MAX defines */
#define RATE_LIMIT_KBPS     250000      /* Bandwidth allocated on each link for leaky bucket for 
                                            sending original (first-time) messages */
#define BUCKET_CAP          (200000 + MAX_PACKET_SIZE) /* default 2000 */
#define BUCKET_FILL_USEC    300
#define FLOW_CTRL_KBPS      25000       /* Bandwidth allocated to retransmissions (across all links) */ 

/* Parameters of Intrusion Tolerant Link */ 
#define IT_CRYPTO                    0
#define IT_ENCRYPT                   0
#define ORDERED_DELIVERY             1
#define REINTRODUCE_MSGS             0
#define TCP_FAIRNESS                 1
#define SESSION_BLOCKING             0 
#define MSG_PER_SAA                 10
#define SEND_BATCH_SIZE             15
#define INTRUSION_TOLERANCE_MODE     0
#define RELIABLE_TIMEOUT_FACTOR     10 /* 10 round trip times per reliable timeout */
#define NACK_TIMEOUT_FACTOR          2 /* 2 round trip time between re-resending or re-requesting nacks */
#define ACK_TO                   10000 /*  10 ms */
#define PING_TO                 200000 /* 200 ms */
#define DH_TO                   999999 /* 999 ms */
#define INCARNATION_TO          999999 /* 999 ms */
#define MIN_RTT_MS                   2 /* 2 ms */
#define IT_DEFAULT_RTT              10  /* in milliseconds */
#define INIT_NACK_TO_FACTOR       0.25 /* 0.25 round trip time before FIRST asking for nack */

/* Parameters of Reroute Calculations */
#define LOSS_THRESHOLD          0.02
#define LOSS_CALC_DECAY         0.8
#define LOSS_CALC_TIME_TRIGGER  10000000
#define LOSS_CALC_PKT_TRIGGER   1000
#define LOSS_PENALTY            10000    
#define PING_THRESHOLD          10

/* this is how often we will refill the leaky-bucket */
static const sp_time it_bucket_to = {0, BUCKET_FILL_USEC};

typedef struct CONF_IT_LINK_d {
    unsigned char Crypto;
    unsigned char Encrypt;
    unsigned char Ordered_Delivery;
    unsigned char Reintroduce_Messages;
    unsigned char TCP_Fairness;
    unsigned char Session_Blocking;
    unsigned char Msg_Per_SAA;
    unsigned char Send_Batch_Size;
    unsigned char Intrusion_Tolerance_Mode;
    int32u        Reliable_Timeout_Factor;
    int32u        NACK_Timeout_Factor;
    int32u        ACK_Timeout;
    int32u        PING_Timeout;
    int32u        DH_Timeout;
    int32u        Incarnation_Timeout;
    int32u        Min_RTT_milliseconds;
    int32u        Default_RTT;
    double        Init_NACK_Timeout_Factor;
    double        Loss_Threshold;
    double        Loss_Calc_Decay;
    int32u        Loss_Calc_Time_Trigger;
    int32u        Loss_Calc_Pkt_Trigger;
    int32u        Loss_Penalty;
    int32u        Ping_Threshold;
} CONF_IT_LINK;

/* TODO: ALL OF BELOW SHOULD BECOME LEAKY BUCKET */

#undef  ext
#ifndef ext_intru_tol_udp
#define ext extern
#else
#define ext
#endif

ext CONF_IT_LINK Conf_IT_Link;
ext int Burst_Count;

/* this is how often we will send standalone acks */
ext sp_time it_ack_timeout;           
/* this is how often we will send pings */
ext sp_time it_ping_timeout;       
/* this is how often we will resend the highest sequence packet */
ext sp_time it_incarnation_timeout; 
/* this is how often we will resend the Diffie-Hellman packet */
ext sp_time it_dh_timeout; 
/* this is how often we will recalculate the loss rate */
ext sp_time loss_calc_timeout; 

ext sp_time Burst_Timeout;
static const sp_time flow_control_timeout = {0, 
            SEND_BATCH_SIZE * MAX_PACKET_SIZE * 8 * 1000 / FLOW_CTRL_KBPS};
/* end TODO */

/* Configuration File Functions */
void IT_Link_Pre_Conf_Setup();
void IT_Link_Post_Conf_Setup();
int  IT_Link_Conf_hton(unsigned char *buff);

/* Functions that interact with higher level */

int  Preprocess_intru_tol_packet(sys_scatter *scat, int received_bytes, Interface *local_interf, Network_Address src, int16u src_port);

void Process_intru_tol_data_packet(Link *lk, sys_scatter *scat,
                    int32u type, int mode);
void Process_intru_tol_ack_packet(Link *lk, sys_scatter *scat,
                    int32u type, int mode);
void Process_intru_tol_ping(Link *lk, sys_scatter *scat,
                    int32u type, int mode);
void Process_DH_IT(Link *lk, sys_scatter *scat, 
                    int32u type, int mode);
int Forward_Intru_Tol_Data(Node *next_hop, sys_scatter *scat);
int Full_Link_IT(Node *next_hop);
void Fill_Bucket_IT(int link_id, void* dummy);
int Request_Resources_IT(int dissem, Node *next_hop, 
                    int (*callback)(Node*, int));
void Ping_IT_Timeout(int link_id, void *dummy);
void Key_Exchange_IT(int link_id, void *dummy);
void Loss_Calculation_Event(int link_id, void *dummy);

#endif
