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

#ifndef	NET_TYPES
#define	NET_TYPES

#include "arch.h"
#include "spu_data_link.h"

/* Don't forget that 0x80000080 is kept for endianness */

#define         ENDIAN_TYPE             0x80000080

#define         Get_endian(t)           ((t) & ENDIAN_TYPE)
#define         Set_endian(t)           (((t) & ~ENDIAN_TYPE) | ARCH_ENDIAN)
#define         Same_endian(t)          (((t) & ENDIAN_TYPE) == ARCH_ENDIAN)
#define         Clear_endian(t)         ((t) & ~ENDIAN_TYPE)

/* First byte */
#define         RELIABLE_TYPE           0x40000000
/* Unreliable msgs will not have 1 on the second bit */   

#define		HELLO_TYPE		0x10000000
#define		HELLO_REQ_TYPE		0x20000000
#define         HELLO_DISCNCT_TYPE      0x20000000 /* Same value as req */
#define		HELLO_PING_TYPE		0x30000000
#define         HELLO_CLOSE_TYPE        0x30000000 /* Same value as ping */
#define         HELLO_MASK              0x30000000

#define		LINK_STATE_TYPE		0x01000000
#define		GROUP_STATE_TYPE	0x02000000
#define         ROUTE_MASK              0x0f000000

/* Second byte */
/* Nothing here yet... */

/* Third byte */
#define         ECN_DATA_T1             0x00000100
#define         ECN_DATA_T2             0x00000200
#define         ECN_DATA_T3             0x00000300
#define         ECN_DATA_MASK           0x00000300

#define         ECN_ACK_T1              0x00000400
#define         ECN_ACK_T2              0x00000800
#define         ECN_ACK_T3              0x00000c00
#define         ECN_ACK_MASK            0x00000c00

#define         ACK_INTERVAL_MASK       0x0000f000 

/* Fourth byte */
#define         LINK_ACK_TYPE           0x00000001
#define         UDP_DATA_TYPE           0x00000002
#define         REL_UDP_DATA_TYPE       0x00000003
#define         REALTIME_DATA_TYPE      0x00000004
#define         REALTIME_NACK_TYPE      0x00000005
#define         RESERVED_TYPE0          0x00000006
#define         RESERVED_TYPE1          0x00000007
#define         RESERVED_TYPE2          0x00000008  /* SC2 */
#define         RESERVED_TYPE3          0x00000009  /* SC2 */
#define         INTRU_TOL_DATA_TYPE     0x0000000A 
#define         INTRU_TOL_ACK_TYPE      0x0000000B 
#define         INTRU_TOL_PING_TYPE     0x0000000C 
#define         DIFFIE_HELLMAN_TYPE     0x0000000D 

#define         DATA_MASK               0x0000007f

/* Type macros */
#define		Is_reliable(t)       (((t) & RELIABLE_TYPE) != 0)

#define    Is_hello_type(t)     (((t) & HELLO_MASK) != 0)
#define    Is_hello(t)          (((t) & HELLO_MASK) == HELLO_TYPE)
#define    Is_hello_req(t)      (((t) & HELLO_MASK) == HELLO_REQ_TYPE)
#define    Is_hello_ping(t)     (((t) & HELLO_MASK) == HELLO_PING_TYPE)
#define    Is_hello_discnct(t)  (((t) & HELLO_MASK) == HELLO_DISCNCT_TYPE)
#define    Is_hello_close(t)    (((t) & HELLO_MASK) == HELLO_CLOSE_TYPE)

#define    Is_link_state(t)     (((t) & ROUTE_MASK) == LINK_STATE_TYPE)
#define    Is_group_state(t)    (((t) & ROUTE_MASK) == GROUP_STATE_TYPE)

#define    Is_udp_data(t)       (((t) & DATA_MASK) == UDP_DATA_TYPE)
#define    Is_rel_udp_data(t)   (((t) & DATA_MASK) == REL_UDP_DATA_TYPE)
#define    Is_realtime_data(t)  (((t) & DATA_MASK) == REALTIME_DATA_TYPE)
#define    Is_realtime_nack(t)  (((t) & DATA_MASK) == REALTIME_NACK_TYPE)
#define    Is_link_ack(t)       (((t) & DATA_MASK) == LINK_ACK_TYPE)
#define    Is_intru_tol_data(t) (((t) & DATA_MASK) == INTRU_TOL_DATA_TYPE)
#define    Is_intru_tol_ack(t)  (((t) & DATA_MASK) == INTRU_TOL_ACK_TYPE)
#define    Is_intru_tol_ping(t) (((t) & DATA_MASK) == INTRU_TOL_PING_TYPE)
#define    Is_diffie_hellman(t) (((t) & DATA_MASK) == DIFFIE_HELLMAN_TYPE)

#define    Is_data_type(t)      (Is_udp_data(t) || Is_rel_udp_data(t) || Is_realtime_data(t))

#define     SPINES_TTL_MAX  255

#define     PING 1
#define     PONG 2

#define     MAX_NODES            50
#define     MAX_PKTS_PER_MESSAGE 45
#define     MAX_MESSAGE_SIZE     (MAX_PACKET_SIZE * MAX_PKTS_PER_MESSAGE)

typedef int32u         Spines_ID;  /* a logical Spines ID -- can be a node id, a group id or a network interface id */
typedef Spines_ID      Node_ID;
typedef Spines_ID      Group_ID;
typedef Spines_ID      Interface_ID;

typedef int16u         Link_State_LTS;  /* NOTE: must be an unsigned type: see Link_State_LTS_cmp */

/* Spines ID Class Check */

#ifndef Is_mcast_addr
#  define  Is_mcast_addr(x) ((((x) & 0xF0000000) == 0xE0000000) || (((x) & 0xFFFFFF00) == 0xFEFF0000))
#  define  Is_acast_addr(x) ((((x) & 0xF0000000) == 0xF0000000) && (((x) & 0xFFFFFF00) != 0xFEFF0000))
#  define  Is_node_addr(x)  (!Is_mcast_addr(x) && !Is_acast_addr(x))
#endif
/* #  define  Is_mcast_addr(x) (((x) & 0xF0000000) == 0xE0000000) */
/* #  define  Is_acast_addr(x) (((x) & 0xF0000000) == 0xF0000000) */

/* Generic union to hold different families of sockaddr structures */
typedef union {
    unsigned short          family;
    struct sockaddr_in      inet_addr;
#ifdef IPV6_SUPPORT
    struct sockaddr_in6     inet6_addr;
#endif
    struct sockaddr_storage stor_addr;
#ifndef ARCH_PC_WIN95
    struct sockaddr_un      unix_addr;
#endif
} spines_sockaddr;

/* This goes in front of each packet (any kind), as it is sent on the network */
typedef	struct	dummy_packet_header {
    int32u          type;          /* type of the message */
    Node_ID         sender_id;     /* Sender of this network packet, and NOT
			              the originator of the message */
    int32u          ctrl_link_id;  /* sender's control link "session" identifier */
    int16u          data_len;      /* Length of the data */
    int16u          ack_len;       /* Length of the acknowledgement tail */
    int16u          seq_no;        /* Sequence number of the packet for link loss_rate */
} packet_header;

typedef	char       packet_body[MAX_PACKET_SIZE - sizeof(packet_header)];

/* elements are arranged in for tight packing + byte alignment issues */
typedef	struct	dummy_udp_pkt_header {
    Node_ID           source;
    Spines_ID         dest;
    int32u            reserved32;
    int16u            source_port;
    int16u            dest_port;
    int16u            len;
    int16u            seq_no;
    int16u            sess_id;
    char              frag_num;   /* For fragmented packets: total num of fragments */
    char              frag_idx;   /* Fragment index */
    unsigned char     ttl;        /* used for both unicast and multicast packets */
    unsigned char     routing;
    /* ### int16u - DO WE NEED PADDING? */
} udp_header;

typedef struct dummy_sb_header {
    int32u            source_incarnation;
    int32u            source_seq;    /* Used together with source_incarnation
                                        to identify duplicates for source-based
                                        routing */
} sb_header;

typedef struct dummy_rel_udp_pkt_add {
    int32u type;
    int16u data_len;
    int16u ack_len;
} rel_udp_pkt_add;

typedef struct dummy_rel_flood_header {
    int16u          src;        /* Source of this flow (logical ID) */ 
    int16u          dest;       /* Destination of this flow (logical ID) */
    int32u          src_epoch;  /* Source's current epoch for this flow */
    int64u          seq_num;    /* Seq_Num on this flow */
    unsigned char   type;       /* Type: Data, E2E, Standalone Ack */
    unsigned char   dummy1;     /* Included only for padding reasons */
    unsigned char   dummy2;     /* Included only for padding reasons */
    unsigned char   dummy3;     /* Included only for padding reasons */
} rel_flood_header;

typedef struct dummy_rel_flood_tail {
    int32u          ack_len;    /* Length (in bytes) of piggy-backed HBH acks */
} rel_flood_tail;

typedef struct dummy_rel_flood_hbh_ack {
    int16u          src;        /* This is a logical ID, not an IP address */
    int16u          dest;       /* This is a logical ID, not an IP address */
    int32u          src_epoch;  /* Source's current epoch */
    int64u          aru;
    int64u          sow;
} rel_flood_hbh_ack;

typedef struct dummy_e2e_cell {
    int32u src_epoch; 
    int32u dest_epoch;
    int64u aru;
} e2e_cell;

typedef struct dummy_rel_flood_e2e_ack {
    int32u          dest;
    e2e_cell        cell[MAX_NODES+1];
} rel_flood_e2e_ack;

typedef struct dummy_status_change_cell {
    int64u          seq;
    int16           cost;
    int16u          dummy1; /* Padding */
    int16u          dummy2; /* Padding */
    int16u          dummy3; /* Padding */
} status_change_cell;

typedef struct dummy_status_change {
    int32u              epoch;
    int16u              creator;
    int16u              dummy; /* Padding */
    status_change_cell  cell[MAX_NODES+1];
} status_change;

typedef struct dummy_prio_flood_header {
    /* Do not separate seq_num and incarnation, these
     * are used as the key for the hash tables */
    int64u          incarnation;    /* high-level incarnation of src node */
    int64u          seq_num;        /* seq num of pkt in this incarnation */
    int32u          priority;       /* client-defined priority on this pkt */
    int32u          origin_sec;     /* time pkt was received at src node */
    int32u          origin_usec;    /* time pkt was received at src node */
    int32u          expire_sec;     /* time pkt should be discarded */
    int32u          expire_usec;    /* time pkt should be discarded */
    /*unsigned char   path[8];*/
} prio_flood_header;

typedef struct dummy_fragment_header {
    int16u frag_length;       /* Length of the fragment */
    unsigned char frag_idx;   /* Fragment index of this packet in the message */
    unsigned char frag_total; /* Total number of fragments in the message */
} fragment_header;

typedef struct dummy_intru_tol_pkt_tail {
    int64u link_seq;        /* This is 0 for stand-alone ACKS */
    int64u seq_nonce;       /* Random number associated with this pkt */
    int64u aru;             /* ARU that sender of this pkt has for dest */
    int64u aru_nonce;       /* Digest of all nonces up to and including ARU */
    int32u incarnation;     /* Sender's incarnation number */
    int32u aru_incarnation; /* The incarnation that the sender thinks the
                                    dest is currently on */
    int32u dummy;           /* Padding */
} intru_tol_pkt_tail;

typedef struct dummy_intru_tol_ping {
    int64u ping_seq;
    int64u ping_nonce;
    int32u incarnation;
    int32u aru_incarnation;
    unsigned char ping_type;
} intru_tol_ping;

typedef	struct	dummy_ses_hello_packet {
    int32u          type;
    int32u          seq_no;
    int32           my_sess_id;
    int16u          my_port;
    int16u          orig_port;
} ses_hello_packet;

typedef	struct	dummy_hello_packet {
    int32u          seq_no;
    int32           my_time_sec;
    int32           my_time_usec;
    int32u          response_seq_no;
    int32           diff_time;
    int32           loss_rate;   /* estimated loss rate of data */
                                 /* (from 0 to LOSS_RATE_SCALE for 0% to 100%) */
} hello_packet;

typedef	struct	dummy_link_state_packet {
    Node_ID    source;
    int16u     num_edges;
    int16      src_data; /* Data about the source itself. 
                            Not used yet */
} link_state_packet;

typedef	struct	dummy_edge_cell_packet {
    Node_ID         dest;
    int32           timestamp_sec;
    int32           timestamp_usec;
    int16           cost;
    int16 	    age;
    Link_State_LTS  lts;
} edge_cell_packet;

typedef	struct	dummy_group_state_packet {
    Node_ID 	    source;
    int16u	    num_cells;
    int16           src_data; /* Data about the source itself. 
				 Not used yet */
} group_state_packet;

typedef	struct	dummy_group_cell_packet {
    Group_ID        dest;  /* This is actually the multicast address */
    int32           timestamp_sec;
    int32           timestamp_usec;
    int16           flags;
    int16 	    age;
} group_cell_packet;

typedef struct dummy_reliable_tail {
    int32u          seq_no;            /* seq no of this reliable message */ 
    int32u          cummulative_ack;   /* cummulative in order ack */
} reliable_tail;

typedef struct dummy_reliable_ses_tail {
    int32u          seq_no;            /* seq no of this reliable message */ 
    int32u          cummulative_ack;   /* cummulative in order ack */
    int32u          adv_win;           /* advertised window for flow control */
} reliable_ses_tail;

/* join acknowledgement */
typedef struct dummy_reliable_mcast_ack {
    int32           type;	    /* the type of the message */
    Group_ID        mcast_address;  /* the group address */
    int32           timestamp_sec;  /* time stamp of request */
    int32           timestamp_usec;
    int32           flags;          /* flags of the group state */
    int32u          seq_no;         /* Sequence number */
    int16	    dummy;	    /* not used currently */
    int16u	    len;	    /* length of subsequent buffer */
    int32u          next_seq_no;    /* the next seq no that will be sent */
} reliable_mcast_ack;

/* data acknowledgement */
typedef struct dummy_reliable_mcast_data_ack {
    int32           type;	    /* the type of the message */
    int32u          seq_no;         /* Sequence number */
    Group_ID        group;          /* The group for which the g_aru is sent */
    int32u          g_aru;          /* The cummulative ack for the group */
    int16u	    num_nacks;	    /* number of nacks */
  /* A list of unsigned ints follows this structure. Each of these is a nack. The
   * number of nacks is equivalent to num_nacks */
} reliable_mcast_data_ack;

/* congestion ack */
typedef struct dummy_reliable_mcast_cg_ack {
    int32	    type;	    /* type of the message */    
    int32u          seq_no;         /* Sequence number */
    Group_ID        group;          /* The group for which the ack is sent */
    Node_ID         new_acker;      /* New congestion acker (if it changed) */
} reliable_mcast_cg_ack;

#endif	/* NET_TYPES */
