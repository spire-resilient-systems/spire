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

#ifndef REL_FLOOD_H
#define REL_FLOOD_H

#include "arch.h"
#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_memory.h"
#include "spu_data_link.h"
#include "stdutil/stdhash.h"
#include "stdutil/stdcarr.h"

#include "node.h"
#include "net_types.h"
#include "objects.h"
#include "link.h"
#include "network.h"
#include "reliable_datagram.h"
#include "hello.h"
#include "reliable_udp.h"
#include "protocol.h"
#include "session.h"
#include "udp.h"
#include "intrusion_tol_udp.h"
#include "state_flood.h"
#include "multicast.h"
#include "route.h"
#include "multipath.h"

/* MAX defines */
#define MAX_MESS_PER_FLOW           1000    /* default = 500, low-bandwidth = 10*/

#define HBH_ACK_TO                  100000  /* 100 ms */
#define E2E_ACK_TO                  150000  /* 150 ms */
#define STATUS_CHANGE_TO            150000  /* 150 ms */
#define REL_CRYPTO                  0
#define REL_FLOOD_SAA_THRESHOLD     10      /* Default = 10, low-bandwidth = 3 */
#define HBH_ADVANCE                 0
#define HBH_OPT                     1
#define E2E_OPT                     1

typedef struct CONF_REL_d {
    int32u        HBH_Ack_Timeout;
    int32u        E2E_Ack_Timeout;
    int32u        Status_Change_Timeout;
    unsigned char Crypto;
    unsigned char SAA_Threshold;
    unsigned char HBH_Advance;
    unsigned char HBH_Opt;
    unsigned char E2E_Opt;
    unsigned char dummy1;
    unsigned char dummy2;
    unsigned char dummy3;
} CONF_REL;

/* Reliable Flood Packet Types */
#define REL_FLOOD_DATA      1
#define REL_FLOOD_SAA       2
#define REL_FLOOD_E2E       3
#define STATUS_CHANGE       4

/* ----------Per Node Data Structures---------- */
typedef struct Flow_Buffer_d {
    /* Storage for the message */
    sys_scatter *msg[MAX_MESS_PER_FLOW];
    /* Status of this message toward each neighbor - see Message_Sending_Status in link.h 
     *      There are Degree + 1 of these, malloc'd at initialization */
    unsigned char *status[MAX_MESS_PER_FLOW];
    /* The number of K paths at the time this message was injected into the 
     *      network, if this message originated here. 0 = flooding */
    int16u  num_paths[MAX_MESS_PER_FLOW];
    /* This is the first one we haven't received acknowledgement for yet. */
    int64u  sow;
    /* This is the first one we haven't sent yet.
     *      There are Degree + 1 of these, malloc'd at initialization */
    int64u  *next_seq;
    /* This is the first one we haven't received yet (aru + 1). */
    int64u  head_seq;
    /* This is the highest source epoch seen on a data message for this flow */
    int32u  src_epoch;
} Flow_Buffer;

typedef struct All_Flow_Buffers_d {
    struct Flow_Buffer_d flow[MAX_NODES + 1][MAX_NODES + 1];
} All_Flow_Buffers;

typedef rel_flood_e2e_ack End_To_End_Ack;

typedef struct Session_Obj_d {
    int32 sess_id;
    struct Session_Obj_d *next;
} Session_Obj;

typedef struct Session_Manage_d {
    unsigned char   size;
    Session_Obj     head;
    Session_Obj     *tail;
} Session_Manage;

/* -------Per Neighbor/Link Data Structures-------- */
typedef struct Rel_Fl_Neighbor_Status_d {
    /* The highest received packet (aru) */
    int64u flow_aru[MAX_NODES + 1][MAX_NODES + 1]; 
    int64u flow_sow[MAX_NODES + 1][MAX_NODES + 1];
} Rel_Fl_Neighbor_Status;

typedef struct Rel_Fl_E2E_Status_d {
    sp_time timeout;
    char    flow_block[MAX_NODES + 1];
    char    unsent;
} Rel_Fl_E2E_Status;

typedef struct Status_Change_Status_d {
    sp_time timeout;
    char    unsent;
} Status_Change_Status;

typedef struct Flow_Queue_d {
    int32u src_id;
    int32u dest_id;
    int16u penalty;
    struct Flow_Queue_d *next;
} Flow_Queue;

typedef struct Rel_Flood_Link_Data_d {
    Rel_Fl_Neighbor_Status  ns_matrix;
    Flow_Queue              norm_head;
    Flow_Queue              *norm_tail;
    Flow_Queue              urgent_head;
    Flow_Queue              *urgent_tail;
    unsigned char           in_flow_queue[MAX_NODES + 1]
                                                [MAX_NODES + 1];
    
    Rel_Fl_E2E_Status       e2e_stats[MAX_NODES + 1];
    Status_Change_Status    status_change_stats[MAX_NODES + 1];
    Flow_Queue              hbh_unsent_head;
    Flow_Queue              *hbh_unsent_tail;
    unsigned char           unsent_state[MAX_NODES + 1]
                                                [MAX_NODES + 1];
    
    int32u                  saa_trigger;
    int32u                  unsent_state_count;
    unsigned char           e2e_ready;
    stdskl                  e2e_skl;
    unsigned char           status_change_ready;
    stdskl                  status_change_skl;

    int64u                  total_pkts_sent;
} Rel_Flood_Link_Data;

#undef  ext
#ifndef ext_rel_flood
#define ext extern
#else
#define ext
#endif

ext int64u                   Flow_Seq_No[MAX_NODES + 1];
ext int32u                   Flow_Source_Epoch[MAX_NODES + 1];
ext unsigned char            Handshake_Complete[MAX_NODES + 1];
ext Rel_Flood_Link_Data     *RF_Edge_Data;
ext All_Flow_Buffers        *FB;
ext End_To_End_Ack           E2E[MAX_NODES + 1];
ext unsigned char           *E2E_Sig[MAX_NODES + 1];
ext status_change            Status_Change[MAX_NODES + 1];
ext unsigned char           *Status_Change_Sig[MAX_NODES + 1];
ext Session_Manage           Sess_List[MAX_NODES + 1];

ext int16u Rel_Signature_Len;
ext CONF_REL Conf_Rel;

/* this is how often we will send a standalone Hop-by-Hop ack if no other 
 *      data has been sent in this direction */
ext sp_time rel_fl_hbh_ack_timeout;
/* this is how often we will send a new End-to-End ack that we've received
 *      about a destination */
ext sp_time rel_fl_e2e_ack_timeout;
/* this is how often we will send a new Link Status Change we've received
 *      about a link in the network */
ext sp_time status_change_timeout;

/* Configuration File Functions */
void Rel_Pre_Conf_Setup();
void Rel_Post_Conf_Setup();
int  Rel_Conf_hton(unsigned char *buff);

/* Initialization and Utility Functions */
void Flip_rel_flood_hdr( rel_flood_header *r_hdr );
void Copy_rel_flood_header( rel_flood_header *from_flood_hdr, 
        rel_flood_header *to_flood_hdr );
void Init_Reliable_Flooding();
int Fill_Packet_Header_Reliable_Flood( char* hdr, int16u num_paths );
int Reliable_Flood_Can_Flow_Send( Session *ses, int32u dst_id );
int Reliable_Flood_Block_Session( Session *ses, int32u dst_id );
int E2E_TO_cmp(const void *l, const void *r);

/* Dissemination and Sending Functions */
int Reliable_Flood_Disseminate(Link *src_link, sys_scatter *scat, int mode); 
int Reliable_Flood_Send_One(Node *next_hop, int mode);
void Reliable_Flood_Neighbor_Transfer  (int mode, Link *lk);
void Generate_Link_Status_Change( int32 ngbr_addr, unsigned char status);
void Apply_Link_Status_Change( int16u id1, int16u id2, int16 cost);

#endif
