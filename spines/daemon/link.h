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

#ifndef LINK_H
#define LINK_H

/* Window (for reliability) */
#define MAX_WINDOW       20000
#define MAX_CG_WINDOW    20000
#define CTRL_WINDOW      10 
#define MAX_HISTORY      1000

/* Packet (unreliable) window for detecting loss rate */
#define PACK_MAX_SEQ     30000

/* Loss rate calculation constants */
#define LOSS_RATE_SCALE  1000000  /* For conversion from float to int*/
#define UNKNOWN             (-1)
#define LOSS_HISTORY        50
#define LOSS_DECAY_FACTOR   0.99

/* Link types */
typedef enum 
{
  CONTROL_LINK,
  UDP_LINK,
  RELIABLE_UDP_LINK,
  REALTIME_UDP_LINK,

  RESERVED0_LINK,      /* MN */
  RESERVED1_LINK,      /* TCP */
  INTRUSION_TOL_LINK,  /* Low-Level Intrusion-Tolerant Reliable UDP Link */

  MAX_LINKS_4_EDGE,

} Link_Type;

typedef enum {
    LINK_DEAD,
    LINK_LIVE,
    LINK_LOSSY,
} Link_Status;

typedef enum {
    EMPTY,
    NEW_UNSENT,
    NEW_SENT,
    RESTAMPED_UNSENT,
    RESTAMPED_SENT,
} Message_Sending_Status;

#define MAX_NEIGHBORS        256
#define MAX_LOCAL_INTERFACES 5
#define MAX_NETWORK_LEGS     (MAX_NEIGHBORS * MAX_LOCAL_INTERFACES)

/* TODO: examine all instances of MAX_LINKS / MAX_LINKS_4_EDGE; replace with MAX_NEIGHBORS? */
/* TODO: redefine MAX_LINKS to be (MAX_LOCAL_LEGS * (int) MAX_LINKS_4_EDGE) */
/* TODO: actually change MAX_LINKS_4_EDGE to be MAX_LINKS_4_LEG -> all over the code */

#define MAX_LINKS            (MAX_NEIGHBORS * (int) MAX_LINKS_4_EDGE)

#define MAX_DISCOVERY_ADDR  10

/* Ports to listen to for sessions */
#define SESS_PORT           ( MAX_LINKS_4_EDGE     )
#define SESS_UDP_PORT       ( MAX_LINKS_4_EDGE + 1 )
#define SESS_CTRL_PORT      ( MAX_LINKS_4_EDGE + 2 )

/* Updates */
#define OLD_CHANGE       1
#define NEW_CHANGE       2

/* Update actions */
#define NEW_ACT          1
#define UPDATE_ACT       2
#define DELETE_ACT       3

/* Flags */
#define UNAVAILABLE_LINK   0x0001
#define AVAILABLE_LINK     0x0002
#define CONNECTED_LINK     0x0004
#define CONNECT_WAIT_LINK  0x0008
#define ACCEPT_WAIT_LINK   0x0010
#define DISCONNECT_LINK    0x0020

#define EMPTY_CELL       0
#define RECVD_CELL       1
#define NACK_CELL        2
#define SENT_CELL        3
#define RETRANS_CELL     4

#define MAX_BUFF_LINK    10000
#define MAX_REORDER      10
#define MAX_SEND_ON_LINK 500 /* default used to be 100 */
#define LINK_START_SEQ   1   /* test wrap-around case: (2147483648-90) */
#define MAX_PING_HIST    5
#define HISTORY_SIZE     10

#define MAX_BUCKET       500
#define RT_RETRANSM_TOK  2   /* 1/2 = 50% max retransmissions */

#define BWTH_BUCKET      536064 /* 64K + 1.472K for one packet*/

#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>

#include "stdutil/stddefines.h"
#include "stdutil/stdit.h"
#include "stdutil/stddll.h"
#include "stdutil/stdcarr.h"

#include "net_types.h"
#include "node.h"
#include "link_state.h"
#include "network.h"

#include "session.h"

struct Node_d;
struct Edge_d;
struct Interface_d;
struct Network_Leg_d;
struct Link_d;

typedef struct Lk_Param_d {
    int32 loss_rate;
    int32 burst_rate;
    int   was_loss;
    int32 bandwidth;
    int32 bucket;
    sp_time last_time_add;
    sp_time delay;
} Lk_Param;

typedef struct Leg_Buf_Cell_d {
  Link_Type   link_type;  /* type for specific link the packet should be sent on */
  sys_scatter scat;       /* packet to send */
  int32u      total_bytes;
} Leg_Buf_Cell;

typedef struct Buffer_Cell_d {
    int32u seq_no;
    char*  buff;
    int32u pack_type;
    int16u data_len;
    sp_time timestamp;
    int resent;
} Buffer_Cell;

typedef struct UDP_Cell_d {
    char*  buff;
    int16u len;
    int32u total_len;
} UDP_Cell;

typedef struct Recv_Cell_d {
    char flag;                    /* Received, empty, not received yet, etc. */
    sp_time nack_sent;            /* Last time I sent a NACK */
    struct UDP_Cell_d data;       /* For FIFO ordering, it keeps the 
				     unordered data */
} Recv_Cell;

typedef struct History_Cell_d {
    char*     buff;
    int16u    len;
    sp_time   timestamp;
} History_Cell;

typedef struct History_Recv_Cell_d {
    int flags;
    sp_time timestamp;
} History_Recv_Cell;

typedef struct Reliable_Data_d {
    int16 flags;                  /* Link status */
    int16 connect_state;          /* Connect state */
    int32u seq_no;                /* Sequence number */
    stdcarr msg_buff;             /* Sending buffer in front of the link */
    float window_size;            /* Congestion window. */
    int32u max_window;            /* Maximum congestion window */
    int32u ssthresh;              /* Slow-start threshold */

    struct Buffer_Cell_d window[MAX_WINDOW]; /* Sending window 
						(keeps actual pakets) */
    int32u head;                  /* 1 + highest message sent */
    int32u tail;                  /* Lowest message that is not acked */
    struct Recv_Cell_d  recv_window[MAX_WINDOW]; /* Receiving window */
    int32u recv_head;             /* 1 + highest packet received */
    int32u recv_tail;             /* 1 + highest received packet in order 
				     (first hole)*/    
    int32u adv_win;               /* advertised window set by the receiver */
    char *nack_buff;              /* Nacks to be parsed */
    int16u nack_len;              /* Length of the above buffer */ 
    int16 scheduled_ack;          /* Set to be 1 if I have an ack scheduled, 
				   * to send, 0 otherwise*/
    int16 scheduled_timeout;      /* Set to be 1 if I have a timeout scheduled
				   * for retransmission, 0 otherwise */
    int16 timeout_multiply;       /* Subsequent timeouts increase exponentially */
    int32 rtt;                    /* Round trip time of the link. */    
    int32u congestion_flag;       /* ECN flag */
    int16u ack_window;
    int16u cong_flag;
    int32u last_tail_resent;
    int16u unacked_msgs;
    int32u last_ack_sent;
    int32u last_seq_sent;
    int  padded;
} Reliable_Data;

typedef struct Loss_Event_d {
    int32 received_packets;
    int32 lost_packets;
} Loss_Event;

typedef struct Loss_Data_d {
    int16  my_seq_no;             /* My packet sequence number */
    int16  other_side_tail;       /* Last packet received in order from the other side */
    int16  other_side_head;       /* Highest packet received from the other side */
    int32  received_packets;      /* Received packets since it's been reset */
    char   recv_flags[MAX_REORDER];/* Window of flags for received packets */
    Loss_Event loss_interval[LOSS_HISTORY]; /* History of loss events */      
    int32  loss_event_idx;        /* Index in the loss event array */
    double  loss_rate;             /* Locally estimated loss rate */
    int16   recvd_seqs[MAX_LINKS_4_EDGE]; /* Highest sequence received from other side for each link type */
    int16   my_seqs[MAX_LINKS_4_EDGE]; /* My last sequence number for each link type */
} Loss_Data;

typedef struct Control_Data_d {
    int32u hello_seq;             /* My hello sequence */
    int32u other_side_hello_seq;  /* Remote hello sequence */
    int32  diff_time;             /* Used for computing round trip time */
    float  rtt;                   /* Round trip time of the link */
    Loss_Data l_data;             /* For determining loss_rate */
    float  est_loss_rate;         /* Estimated loss rate */
    float  est_tcp_rate;          /* Estimated available TCP rate */

    int32  reported_rtt;          /* RTT last reported in a link_state (if any) */
    float  reported_loss_rate;    /* Loss rate last reported in a link_state (if any) */
    sp_time reported_ts;          /* Time at which we last sent an update for this link */
} Control_Data;

typedef int64u rt_seq_type;

typedef struct Realtime_Data_d {
    rt_seq_type    head;
    rt_seq_type    tail;
    struct History_Cell_d window[MAX_HISTORY]; /* Sending window history
						(keeps actual packets for a while) */    
    rt_seq_type    recv_head;
    rt_seq_type    recv_tail;
    struct History_Recv_Cell_d recv_window[MAX_HISTORY]; /* Receiving window history    
							    Only flags here, no packets */
    char nack_buff[MAX_PACKET_SIZE];
    int num_nacks;
    char *retransm_buff;
    int num_retransm;
    int bucket;
} Realtime_Data;

typedef struct IT_Recv_Cell_d {
    int flags; /* RECVD, NACK, EMPTY */
    sp_time nack_expire; /* time until a nack should be sent */
    char *pkt; /* holds pkt if ordered delivery is turned on*/
    int16u pkt_len; /* len of stored pkt if ordered delivery */
    /* char *msg;
    int16u msg_len; */
} IT_Recv_Cell;

typedef struct IT_Buffer_Cell_d {
    sys_scatter *pkt; /* all the fragments of the message that fit into this packet */
    int16u data_len;
    sp_time timestamp;
    unsigned char resent;
    unsigned char nacked;
} IT_Buffer_Cell;

typedef struct IT_Ping_Cell_d {
    int64u ping_seq;
    int64u ping_nonce;
    sp_time ping_sent;    
    unsigned char answered;
} IT_Ping_Cell;

typedef struct Dissem_Fair_Queue_d {
    int32u dissemination;
    int (*callback) (struct Node_d*, int);
    struct Dissem_Fair_Queue_d *next;
} Dissem_Fair_Queue;

typedef struct Int_Tol_Data_d {
    /* outbound data structures */
    IT_Buffer_Cell          outgoing[MAX_SEND_ON_LINK];
    int64u                  out_nonce[MAX_SEND_ON_LINK];
    int64u                  out_nonce_digest[MAX_SEND_ON_LINK];
    int64u                  out_head_seq;
    int64u                  out_tail_seq;
    int32u                  my_incarnation;
    sys_scatter            *out_message;
    unsigned char           out_frag_idx;   /* next fragment to process */
    unsigned char           out_frag_total;
    /* inbound data structures */
    IT_Recv_Cell            incoming[MAX_SEND_ON_LINK];
    int64u                  in_nonce[MAX_SEND_ON_LINK];
    int64u                  aru_nonce_digest;
    int64u                  in_head_seq;
    int64u                  in_tail_seq;
    int32u                  incoming_msg_count;
    int32u                  ngbr_incarnation;
    sp_time                 incarnation_response;
    sys_scatter            *in_message;
    unsigned char           in_frag_idx; /* next fragment to receive */
    unsigned char           in_frag_total;
    /* TCP Fairness variables */
    int64u                  loss_detected_aru;
    int64u                  tcp_head_seq;
    float                   cwnd;
    int16u                  ssthresh;
    unsigned char           loss_detected;
    /* RTT variables */
    double                  rtt;
    IT_Ping_Cell            ping_history[MAX_PING_HIST];
    int64u                  next_ping_seq;
    int64u                  last_pong_seq_recv;
    sp_time                 pong_freq;
    sp_time                 it_nack_timeout;
    sp_time                 it_initial_nack_timeout;
    sp_time                 it_reliable_timeout;
    /* Reroute & Link Status Change variables */
    unsigned char           link_status;  /* 0 = dead, 1 = live, 2 = lossy */
    int32u                  loss_history_retransmissions[HISTORY_SIZE+1];
    int32u                  loss_history_unique_packets[HISTORY_SIZE+1];
    double                  loss_history_decay[HISTORY_SIZE+1];
    /* Crypto Variables */
    EVP_CIPHER_CTX          *encrypt_ctx;
    EVP_CIPHER_CTX          *decrypt_ctx;
    HMAC_CTX                *hmac_ctx;
    unsigned char          *dh_key;
    unsigned char           dh_established;
    unsigned char           dh_key_computed; /* 0, 1, or 2 */
    /* 0 if neither half present, 1 if only local half present, 2 if both halves present */
    DH                     *dh_local;
    sys_scatter             dh_pkt;
    /* leaky bucket variables */
    sp_time                 last_filled;
    int64                   bucket;
    unsigned char           needed_tokens;
    /* Callback Function variables */
    Dissem_Fair_Queue       dissem_head;
    Dissem_Fair_Queue      *dissem_tail;
    unsigned char           in_dissem_queue[RESERVED_ROUTING_BITS >> ROUTING_BITS_SHIFT];
} Int_Tol_Data;

typedef struct Link_d {

  int16     link_id;               /* Index of the link in the global link array */ 
  Link_Type link_type;             /* Type of link this is */

  struct Network_Leg_d *leg;       /* Leg across which this link is running */
  
  struct Reliable_Data_d *r_data;  /* Reliablility specific data. 
				      * If the link does not need reliability,
				      * this is NULL */
  void *prot_data;                 /* Link Protocol specific data */

} Link;

int16   Create_Link(struct Network_Leg_d *leg, int16 mode);
void    Destroy_Link(int16 linkid);

Link   *Get_Best_Link(Node_ID node_id, int mode);
int     Link_Send(Link *lk, sys_scatter *scat);

int32   Relative_Position(int32 base, int32 seq);

void    Check_Link_Loss(struct Network_Leg_d *leg, int16u seq_no, int link_type);
int32   Compute_Loss_Rate(struct Network_Leg_d *leg);
int16u  Set_Loss_SeqNo(struct Network_Leg_d *leg, int link_type);
void    Fill_Leg_Bucket(int dummy, void* input_leg);
int     Leg_Try_Send_Buffered(struct Network_Leg_d *leg);

#endif
