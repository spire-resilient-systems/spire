/*
 * Prime.
 *     
 * The contents of this file are subject to the Prime Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.dsn.jhu.edu/prime/LICENSE.txt
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis, 
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
 * for the specific language governing rights and limitations under the 
 * License.
 *
 * Creators:
 *   Yair Amir            yairamir@cs.jhu.edu
 *   Jonathan Kirsch      jak@cs.jhu.edu
 *   John Lane            johnlane@cs.jhu.edu
 *   Marco Platania       platania@cs.jhu.edu
 *   Amy Babay            babay@cs.jhu.edu
 *   Thomas Tantillo      tantillo@cs.jhu.edu
 *
 * Major Contributors:
 *   Brian Coan           Design of the Prime algorithm
 *   Jeff Seibert         View Change protocol
 *      
 * Copyright (c) 2008 - 2017
 * The Johns Hopkins University.
 * All rights reserved.
 * 
 * Partial funding for Prime research was provided by the Defense Advanced 
 * Research Projects Agency (DARPA) and the National Science Foundation (NSF).
 * Prime is not necessarily endorsed by DARPA or the NSF.  
 *
 */

#ifndef PRIME_PACKETS_H
#define PRIME_PACKETS_H

#include "arch.h"
#include "spu_events.h"
#include "def.h"
#include "openssl_rsa.h"
#include "util_dll.h"
//#include "data_structs.h"

/* NOTE: PO_ARU is PO_SUMMARY and PROOF_MATRIX is SUMMARY_MATRIX in Kirsch's thesis */

enum packet_types {DUMMY, 
		   PO_REQUEST,  PO_ACK,  PO_ARU, PROOF_MATRIX,
		   PRE_PREPARE, PREPARE, COMMIT, RECON,
           TAT_MEASURE, RTT_PING, RTT_PONG, RTT_MEASURE, TAT_UB,
           NEW_LEADER, NEW_LEADER_PROOF,
           RB_INIT, RB_ECHO, RB_READY,
           REPORT, PC_SET, VC_LIST, VC_PARTIAL_SIG, VC_PROOF,
           REPLAY, REPLAY_PREPARE, REPLAY_COMMIT,
           CATCHUP_REQUEST, ORD_CERT, PO_CERT, //CATCHUP_REPLY,
		   UPDATE, CLIENT_RESPONSE, 
           MAX_MESS_TYPE};

/* Defines to help with SCADA application */
#define CLIENT_NO_OP 101
#define CLIENT_STATE_TRANSFER 102
#define NEW_INCARNATION 103

/* Forward declaration */
struct dummy_ord_slot;

typedef byte packet_body[PRIME_MAX_PACKET_SIZE];

typedef struct dummy_signed_message {
  byte sig[SIGNATURE_SIZE];
  int16u mt_num;
  int16u mt_index;

  int32u site_id;
  int32u machine_id; 
  
  int32u len;        /* length of the content */
  int32u type;       /* type of the message */
  
  /* int32u seq_num; */

  /* Content of message follows */
} signed_message;

/* Update content. Note that an update message has almost the same
 * structure as a signed message. It has an additional content
 * structure that contains the time stamp. Therefore, an update
 * message is actually a signed_message with content of update_content
 * and the actual update data */
typedef struct dummy_update_message {
  int32u server_id;
  int32  address;
  int16  port;
  int32u incarnation;
  int32u seq_num;
  /* the update content follows */
} update_message;

typedef struct dummy_signed_update_message {
  signed_message header;
  update_message update;
  byte update_contents[UPDATE_SIZE];
} signed_update_message;

/* Struct used to handle (incarnation, seq) tuples that
 *  are used everywhere for the preordering information */
typedef struct dummy_po_seq_pair {
    int32u incarnation;
    int32u seq_num;
} po_seq_pair;

typedef struct dummy_po_request {
  po_seq_pair seq;        
  int32u num_events;
  /* Event(s) follows */
} po_request_message;

/* Structure for batching acks */
typedef struct dummy_po_ack_part {
  int32u originator;                /* originating entity (server) */
  po_seq_pair seq;
  byte digest[DIGEST_SIZE];         /* a digest of the update      */
} po_ack_part;

typedef struct dummy_po_ack_message {
    int32u num_ack_parts;             /* Number of Acks */
    /* a list of po_ack_parts follows */
} po_ack_message;

/* Messages for Pre-Ordering */
typedef struct dummy_po_aru_message {
  int32u incarnation;
  int32u num;
  /* Cumulative ack for each server */
  po_seq_pair ack_for_server[NUM_SERVERS]; 
} po_aru_message;

/* a struct containing pre-order proof messages */
typedef struct dummy_po_cum_ack_signed_message {
  signed_message header;
  po_aru_message cum_ack;
} po_aru_signed_message;

typedef struct dummy_proof_matrix_message {
  int32u num_acks_in_this_message;

  /* timing tests */
  int32u sec;
  int32u usec;

  /* The content follows: some number of po_aru_signed_messages */
} proof_matrix_message;

typedef struct dummy_pre_prepare_message {
  /* Ordering sequence number */
  int32u seq_num;          
  
  /* View number */
  int32u view;

  /* timing tests */
  int32u sec;
  int32u usec;

  int16u part_num;
  int16u total_parts;
  int32u num_acks_in_this_message;

} pre_prepare_message;

/* Structure of a Prepare Message */
typedef struct dummy_prepare_message {
  int32u seq_num;              /* seq number                            */
  int32u view;                 /* the view number                       */
  byte   digest[DIGEST_SIZE];  /* a digest of whatever is being ordered */
} prepare_message;

/* Structure of a Commit Message */
typedef struct dummy_commit_message {
  int32u seq_num;                      /* seq number */
  int32u view;
  byte digest[DIGEST_SIZE];   /* a digest of the content */
} commit_message;

typedef struct dummy_complete_pre_prepare_message {
  int32u seq_num;
  int32u view;

  po_aru_signed_message cum_acks[NUM_SERVERS];
} complete_pre_prepare_message;

typedef struct dummy_client_response_message {
  int32u machine_id;
  int32u incarnation;
  int32u seq_num;
  int32u ord_num;
  int32u event_idx;
  int32u event_tot;
  double PO_time;
} client_response_message;

typedef struct dummy_tat_measure {
  int32u view;
  double max_tat;
} tat_measure_message;

typedef struct dummy_rtt_ping {
  int32u ping_seq_num;
  int32u view;
} rtt_ping_message;

typedef struct dummy_rtt_pong {
  int32u dest;
  int32u ping_seq_num;
  int32u view;
} rtt_pong_message;

typedef struct dummy_rtt_measure {
  int32u dest;
  int32u view;
  double rtt;
} rtt_measure_message;

typedef struct dummy_tat_ub {
  int32u view;
  double alpha;
} tat_ub_message;

typedef struct dummy_new_leader {
  int32u new_view;
} new_leader_message;

typedef struct dummy_new_leader_proof {
  int32u new_view;
  /* what follows are: 2*F+K+1 signed new_leader_messages for
      the new proposed view */
} new_leader_proof_message;

/* RB_INIT, RB_ECHO, RB_READY are just a TYPE + signed_message pointer */

typedef struct dummy_reliable_broadcast_tag {
  int32u machine_id;
  int32u view;
  int32u seq_num;
} reliable_broadcast_tag;

typedef struct dummy_report {
  reliable_broadcast_tag rb_tag;
  int32u execARU;
  int32u pc_set_size; /* numSeq in Kirsch thesis */
} report_message;

typedef struct dummy_pc_set {
  reliable_broadcast_tag rb_tag;
  /* prepare certificate follows: 1 pre-prepare and 2f+k prepares */
} pc_set_message;

typedef struct dummy_vc_list {
  int32u view;
  int32u list;
} vc_list_message;

typedef struct dummy_vc_partial_sig {
  int32u view;
  int32u list;
  int32u startSeq;
  byte partial_sig[SIGNATURE_SIZE];
} vc_partial_sig_message;

typedef struct dummy_vc_proof {
  int32u view;
  int32u list;
  int32u startSeq;
  byte thresh_sig[SIGNATURE_SIZE];
} vc_proof_message;

typedef struct dummy_replay {
  int32u view;
  int32u list;
  int32u startSeq;
  byte thresh_sig[SIGNATURE_SIZE];
} replay_message;

typedef struct dummy_replay_prepare {
  int32u view;
  byte digest[DIGEST_SIZE];
} replay_prepare_message;

typedef struct dummy_replay_commit {
  int32u view;
  byte digest[DIGEST_SIZE];
} replay_commit_message;

typedef struct dummy_catchup_request {
//  int32u view;
  int32u aru;
  /* possibly include PO.aru vector so that the
   * receiver can know if they should EXCLUDE any of the
   * PO_Requests that became eligible for exection from
   * this ordinal. In the worst case, they send all
   * PO requests associated with this ord_slot. DO_RECON
   * could then be called comparing this vector with the
   * list of PO Requests */
} catchup_request_message;

//typedef struct dummy_catchup_reply {
//  int32u view;
//  int32u seq_num;
//  int32u type;
  /* ord certificate follows: always 1 pre-prepare, If commit_cert, also 2f+k+1 commits */
//} catchup_reply_message;

typedef struct dummy_ord_certificate_message {
  int32u view;
  int32u seq_num;
  int32u type;
  int32u flag;   /* indicates whether this is part of periodic sending or specifically catchup */
  /* ord certificate follows: always 1 pre-prepare, If commit_cert, also 2f+k+1 commits */
} ord_certificate_message;

typedef struct dummy_po_certificate_message {
  int32u server;
  int32u seq_num;
  // TODO
} po_certificate_message;

typedef struct dummy_erasure_part {

  /* Length of the message this part is encoding, in bytes.  The receiver
   * can compute the length of the part based on this value. */
  int32u mess_len; 

  /* The part follows, in the form <index, part> */
} erasure_part;

typedef struct dummy_recon_message {

  /* The number of parts that follow, each one with a recon_part_header to
   * indicate the preorder identifier (i, j) for the message encoded. */
  int32u num_parts;

} recon_message;

/* A Prepare certificate consists of 1 Pre-Prepare and 2f Prepares */
typedef struct dummy_prepare_certificate {
  complete_pre_prepare_message pre_prepare;
  signed_message* prepare[NUM_SERVER_SLOTS]; 
} prepare_certificate_struct;

/* A Commit certificate consists of 2f+1 Commits */
typedef struct dummy_commit_certificate {
    //byte update_digest[DIGEST_SIZE];    /* The update digest */
    signed_message* commit[NUM_SERVER_SLOTS]; /* The set of prepares */
} commit_certificate_struct;

signed_message* PRE_ORDER_Construct_PO_Request  (void);
signed_message* PRE_ORDER_Construct_PO_Ack      (int32u *more_to_ack, int32u send_all_nonexec);
signed_message* PRE_ORDER_Construct_PO_ARU      (void);
void PRE_ORDER_Construct_Proof_Matrix(signed_message **mset, 
				      int32u *num_parts);
signed_message *PRE_ORDER_Construct_Update(int32u type);

void ORDER_Construct_Pre_Prepare(signed_message **mset, int32u *num_parts);
signed_message* ORDER_Construct_Prepare(complete_pre_prepare_message *pp);
signed_message* ORDER_Construct_Commit (complete_pre_prepare_message *pp);
signed_message* ORDER_Construct_Client_Response(int32u client_id, int32u incarnation, 
                    int32u seq_num, int32u ord_num, int32u event_idx, 
                    int32u event_tot, byte content[UPDATE_SIZE]);

signed_message* SUSPECT_Construct_TAT_Measure(double max_tat);
signed_message* SUSPECT_Construct_RTT_Ping(void);
signed_message* SUSPECT_Construct_RTT_Pong(int32u server_id, int32u seq_num);
signed_message* SUSPECT_Construct_RTT_Measure(int32u server_id, double rtt);
signed_message* SUSPECT_Construct_TAT_UB(double alpha);

signed_message* SUSPECT_Construct_New_Leader();
signed_message* SUSPECT_Construct_New_Leader_Proof();

signed_message* RB_Construct_Message(int32u type, signed_message *mess);

signed_message* VIEW_Construct_Report();
signed_message* VIEW_Construct_PC_Set();
signed_message* VIEW_Construct_VC_List();
signed_message* VIEW_Construct_VC_Partial_Sig(int32u list);
signed_message* VIEW_Construct_VC_Proof(int32u list, int32u startSeq, signed_message **m_arr);
signed_message* VIEW_Construct_Replay(vc_proof_message *vc_proof);
signed_message* VIEW_Construct_Replay_Prepare();
signed_message* VIEW_Construct_Replay_Commit();

signed_message* PR_Construct_Catchup_Request(void);
signed_message* PR_Construct_ORD_Certificate(struct dummy_ord_slot *slot);
signed_message* PR_Construct_PO_Certificate(void);

signed_message *RECON_Construct_Recon_Erasure_Message(dll_struct *list,
							int32u *more_to_encode);
#endif
