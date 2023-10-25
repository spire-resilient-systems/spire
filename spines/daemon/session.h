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

#include "spines_lib.h"
#include "net_types.h"
#include "security.h"

#ifndef SESSION_H
#define SESSION_H


#define READY_LEN           1
#define READY_DATA          2
#define READY_CTRL_SK       3
#define READY_ENDIAN        4


#define READ_DESC           1
#define EXCEPT_DESC         2
#define WRITE_DESC          4

#define SOCK_ERR            0
#define PORT_IN_USE         1
#define SES_BUFF_FULL       2
#define SES_DISCONNECT      3
#define SES_DELAY_CLOSE     4

#define UDP_SES_TYPE        1
#define LISTEN_SES_TYPE     2
#define RELIABLE_SES_TYPE   3

#define SESS_DATA           1
#define SESS_CTRL           2

#define BIND_TYPE_MSG       1
#define CONNECT_TYPE_MSG    2
#define LISTEN_TYPE_MSG     3
#define ACCEPT_TYPE_MSG     4
#define JOIN_TYPE_MSG       5
#define LEAVE_TYPE_MSG      6
#define LINKS_TYPE_MSG      7
#define REL_JOIN_TYPE_MSG   8
#define SETLINK_TYPE_MSG    9
#define FLOOD_SEND_TYPE_MSG 10
#define FLOOD_RECV_TYPE_MSG 11
#define ADD_NEIGHBOR_MSG    12
#define LOOP_TYPE_MSG       13
#define TRACEROUTE_TYPE_MSG 21
#define EDISTANCE_TYPE_MSG  22
#define MEMBERSHIP_TYPE_MSG 23
#define DELIVERY_FLAG_MSG   24
#define PRIORITY_TYPE_MSG   25
#define EXPIRATION_TYPE_MSG 26
#define DIS_PATHS_TYPE_MSG  27
#define SETDISSEM_TYPE_MSG  28

#define SES_CLIENT_ON       1
#define SES_CLIENT_OFF      2
#define SES_CLIENT_ORPHAN   3

#define MAX_BUFF_SESS    9000
#define MAX_PKT_SEQ     10000

/*#define MAX_SPINES_MSG 1400 */ /* (packet_body ) 1456 - ( (udp_header) 28 + (rel_ses_pkt_add) 8 + (reliable_ses_tail) 12 + (reliable_tail) 8 ) = 1456 - 56 */

/* NOTE: Need to be careful here.  The MTU has some dependence on what
   link and end-to-end protocols are used.  The above line seems to
   assume reliable link w/ a reliable end-to-end session would have
   the highest header overhead.  If we were to add additional
   protocols that could have more header overhead, then we'd need to
   use that one (basically we need the worst case of all the possible
   protocol combinations)  
*/

#if 0
#define MAX_SPINES_MSG (MAX_PACKET_SIZE /* ethernet - IP - UDP */ - sizeof(packet_header) - (sizeof(udp_header) + sizeof(rel_udp_pkt_add) + sizeof(reliable_ses_tail) + sizeof(reliable_tail)))
#endif

/* Worst case is: packet_body - spines_hdr - udp_hdr - IT_link_tail - IT_link_ack - IT_link_IV - IT_link_PKCS_padding - IT_HMAC 
 *                                  - Prio_hdr - Bitmask (64-bit) - RSA_sig (1024-bit) */
/* TODO: Make this dynamic to account for different size HMAC, bitmask, and signature from config file */
#define MAX_SPINES_MSG (MAX_PACKET_SIZE /* ethernet - IP - UDP */ - (sizeof(packet_header) + sizeof(udp_header) + sizeof(intru_tol_pkt_tail) + sizeof(int64u) + 2 * SECURITY_MAX_BLOCK_SIZE + SECURITY_MAX_HMAC_SIZE + sizeof(prio_flood_header) + 8 + 128))

#define MAX_CTRL_SK_REQUESTS 10

#include "stdutil/stdcarr.h"
#include "link.h" /* For Reliable_Data */

typedef struct Frag_Packet_d {
    sys_scatter scat;
    int16u recv_elements;
    int16u sess_id;
    int16u seq_no;
    int16u snd_port;
    Node_ID sender;
    int32 timestamp_sec;
    struct Frag_Packet_d *next;
    struct Frag_Packet_d *prev;
} Frag_Packet;

typedef struct Session_d {
    int32u sess_id;
    channel sk;
    channel ctrl_sk;
    int32  endianess_type;
    int16  type;
    int32  links_used;
    int32  routing_used;
    int32  session_semantics;
    int    deliver_flag;
    int32  rnd_num;
    int32  udp_addr;
    int32  udp_port;
    char   client_stat;
    int16u port;
    int32 total_len;
    int32 read_len;
    int32 received_len;
    int32 partial_len;
    int16u seq_no;
    int32 frag_num;
    int32 frag_idx;
    udp_header save_hdr; 
    int16  state;
    char   fd_flags;    
    char   *data;
    char   multicast_loopback;    
    stdcarr rel_deliver_buff;  /* Sending buffer to be delivered for E2E reliability*/
    Frag_Packet *frag_pkts;
    int16u sent_bytes;
    struct Reliable_Data_d *r_data;
    int32  rel_otherside_addr;
    int32  rel_otherside_port;
    int32  rel_otherside_id;
    int32  rel_orig_port;
    int    rel_hello_cnt;
    int    rel_blocked;
    stdhash joined_groups;
    int close_reason;

    /* Priority Flooding Settings */
    int16u priority_lvl;
    sp_time expire;
    int16u disjoint_paths;

    /* Reliable Flooding Settings */
    char blocked;
    sys_scatter* scat;

    /* Sender Flooder */
    int Rate;
    sp_time Start_time;
    int Num_packets;
    int Sent_packets;
    int32 Sendto_address;
    int32 Sendto_port;
    int Packet_size;

    /*Receiver Flooder*/
    int recv_fd_flag;
    int fd;
} Session;

void Session_Flooder_Send(int sesid, void *dummy);

void Init_Session(void);
void Session_Finish(void);
void Session_Accept(int sk_local, int dummy, void *dummy_p);
void Session_Read(int sk, int dummy, void *dummy_p);
void Session_Close(int sesid, int reason);
int  Process_Session_Packet(struct Session_d *ses);
int  Session_Send_Message(struct Session_d *ses);
int  Deliver_UDP_Data(sys_scatter *scat, int32u type);
int  Session_Deliver_Data(Session *ses, char* buff, int16u buf_len, int32u type, int flags);
void Session_Write(int sk, int sess_id, void *dummy_p);
void Ses_Send_ID(struct Session_d *ses);
void Ses_Send_ERR(int address, int port);
void Block_Session(struct Session_d *ses);
void Resume_Session(struct Session_d *ses);
void Block_All_Sessions(void);
void Resume_All_Sessions(void);
void Try_Close_Session(int sesid, void *dummy); 
void Session_UDP_Read(int sk, int dmy, void * dmy_p);

#endif
