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

#ifndef PRIO_FLOOD_H
#define PRIO_FLOOD_H

#include <openssl/engine.h>
#include <openssl/evp.h>

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

/* Parameters of Priority-Based Flooding */
#define PRIO_CRYPTO                 0
#define MAX_PRIORITY                10
#define MAX_MESS_STORED             500
#define MIN_BELLY_SIZE              1000000
#define PRIO_DEFAULT_PLVL           1
#define PRIO_DEFAULT_EXPIRE_SEC     600  /* 10 min */
#define PRIO_DEFAULT_EXPIRE_USEC    0
#define GARB_COLL_TO                60  /* 1 min */

typedef struct CONF_PRIO_d {
    unsigned char Crypto;
    unsigned char Default_Priority;
    unsigned char dummy1;
    unsigned char dummy2;
    int32u        Max_Mess_Stored;
    int32u        Min_Belly_Size;
    int32u        Default_Expire_Sec;
    int32u        Default_Expire_USec;
    int32u        Garbage_Collection_Sec;
} CONF_PRIO;

/* Message status */
#define NEED_MSG            1
#define RECV_MSG            2
#define ON_LINK_MSG         3
#define DROPPED_MSG         4
#define EXPIRED_MSG         5
#define NOT_IN_MASK         6

/* ----------Per Node Data Structures---------- */
typedef struct Prio_Flood_Key_d {
    int64u incarnation; /* Must maintain variable order here */
    int64u seq_num;
} Prio_Flood_Key;

typedef struct Prio_Neighbor_Status_d {
    int32u flag;
    struct Prio_PQ_Node_d *ngbr;
} Prio_Neighbor_Status;

typedef struct Prio_Flood_Value_d {
    sp_time arrival;
    sp_time expire;
    sp_time origin_time;
    int64u seq_num;
    int32u priority;
    int32u need_count;
    int32u degree;
    sys_scatter *msg_scat;
    int32u msg_len;
    int link_mode; /* The mode of the link from which this message was recieved */
    Prio_Neighbor_Status *ns;
} Prio_Flood_Value;

/* -------Per Neighbor/Link Data Structures-------- */
typedef struct Send_Fair_Queue_d {
    int32u src_id;
    int16u penalty;
    struct Send_Fair_Queue_d *next;
} Send_Fair_Queue;

typedef struct Prio_PQ_Node_d {
    sp_time timestamp;
    struct Prio_PQ_Node_d *prev;
    struct Prio_PQ_Node_d *next;
    Prio_Flood_Value *entry;
} Prio_PQ_Node;

typedef struct Prio_PQ_d {
    Prio_PQ_Node  head[MAX_PRIORITY + 1];
    Prio_PQ_Node *tail[MAX_PRIORITY + 1];
} Prio_PQ;

typedef struct Prio_Link_Data_d {
    int32u              total_msg;
    int32u              msg_count[MAX_NODES + 1];
    unsigned char       in_send_queue[MAX_NODES + 1];
    int32u              max_pq[MAX_NODES + 1];
    int32u              min_pq[MAX_NODES + 1];
    Prio_PQ             pq[MAX_NODES + 1];
    Send_Fair_Queue     norm_head;
    Send_Fair_Queue     *norm_tail;
    Send_Fair_Queue     urgent_head;
    Send_Fair_Queue     *urgent_tail;
    int64u              sent_messages;
} Prio_Link_Data;

#undef  ext
#ifndef ext_prio_flood
#define ext extern
#else
#define ext
#endif

ext stdhash                 *Belly;
ext int64u                   Seq_No;
ext int64u                  *Node_Incarnation;
ext Prio_Link_Data          *Edge_Data;
ext int32u                   Bytes_Since_Checkpoint;
ext sp_time                  Time_Since_Checkpoint;

ext int16u Prio_Signature_Len;
ext CONF_PRIO Conf_Prio;

/* this is how often we will do garbage collection */
ext sp_time prio_garb_coll_timeout; 

/* Configuration File Functions */
void Prio_Pre_Conf_Setup();
void Prio_Post_Conf_Setup();
int  Prio_Conf_hton(unsigned char *buff);

/* Initialization and Utility Functions */
void Flip_prio_flood_hdr( prio_flood_header *f_hdr );
void Copy_prio_flood_header( prio_flood_header *from_flood_hdr, 
        prio_flood_header *to_flood_hdr );
void Init_Priority_Flooding();
int Fill_Packet_Header_Best_Effort_Flood( char* hdr );

/* Dissemination and Sending Functions */
int Priority_Flood_Disseminate(Link *src_link, sys_scatter *scat, int mode); 
int Priority_Flood_Send_One(Node *next_hop, int mode);

#endif
