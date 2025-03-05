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
 *   Amy Babay            babay@pitt.edu
 *   Thomas Tantillo      tantillo@cs.jhu.edu
 *
 * Major Contributors:
 *   Brian Coan           Design of the Prime algorithm
 *   Jeff Seibert         View Change protocol 
 *   Sahiti Bommareddy    Reconfiguration 
 *   Maher Khan           Reconfiguration 
 * 
 * Copyright (c) 2008-2025
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
		   PO_REQUEST, PO_ACK, PO_ARU, PROOF_MATRIX,
		   PRE_PREPARE, PREPARE, COMMIT, RECON,
           TAT_MEASURE, RTT_PING, RTT_PONG, RTT_MEASURE, TAT_UB,
           NEW_LEADER, NEW_LEADER_PROOF,
           RB_INIT, RB_ECHO, RB_READY,
           REPORT, PC_SET, VC_LIST, VC_PARTIAL_SIG, VC_PROOF,
           REPLAY, REPLAY_PREPARE, REPLAY_COMMIT,
           ORD_CERT, PO_CERT, CATCHUP_REQUEST, JUMP,
           NEW_INCARNATION, INCARNATION_ACK, INCARNATION_CERT,
           PENDING_STATE, PENDING_SHARE,
           RESET_VOTE, RESET_SHARE,
           RESET_PROPOSAL, RESET_PREPARE, RESET_COMMIT,
           RESET_NEWLEADER, RESET_NEWLEADERPROOF, 
           RESET_VIEWCHANGE, RESET_NEWVIEW, RESET_CERT,
		   /* 46 --> */ UPDATE, CLIENT_RESPONSE, 
           OOB_CONFIG,IB_CONFIG,MAX_MESS_TYPE};

enum key_types {SM_TC_PUB, SM_TC_PVT, PRIME_TC_PUB, PRIME_TC_PVT, PRIME_RSA_PUB, PRIME_RSA_PVT};
/* Defines to help with SCADA application */
#define CLIENT_NO_OP 101
#define CLIENT_STATE_TRANSFER 102
#define CLIENT_SYSTEM_RESET 103
#define CLIENT_SYSTEM_RECONF 104
#define CLIENT_OOB_CONFIG_MSG 48
#define CONFIG_KEYS_MSG 49

/* Forward declaration */
struct dummy_ord_slot;
struct dummy_po_slot;

typedef byte packet_body[PRIME_MAX_PACKET_SIZE];

typedef struct dummy_signed_message {
  byte sig[SIGNATURE_SIZE];
  int16u mt_num;
  int16u mt_index;

  int32u site_id;
  int32u machine_id; 
  
  int32u len;        /* length of the content */
  int32u type;       /* type of the message */

  int32u incarnation;          /* set for session-key-signed messages */
  int32u monotonic_counter;    /* set for TPM-signed messages */
  int32u global_configuration_number; /*MS2022:  Global incarnation number to differntiate configurations*/ 
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
  //int32u incarnation;
  int32u seq_num;
  /* the update content follows */
} update_message;

typedef struct dummy_nm_message {
     //New N
   int32u N;
 //f
   int32u f;
 //k
   int32u k;
 //num of sites
   int32u num_sites;
   int32u num_cc;
   int32u num_dc;
   int32u num_cc_replicas;
   int32u num_dc_replicas;
 //1-Max IPs - fill only needed Ips and rest NULL
   int32u tpm_based_id[MAX_NUM_SERVER_SLOTS];
   int replica_flag[MAX_NUM_SERVER_SLOTS];
   char sm_addresses[MAX_NUM_SERVER_SLOTS][32];
   char spines_ext_addresses[MAX_NUM_SERVER_SLOTS][32];
   int32 spines_ext_port;
   char spines_int_addresses[MAX_NUM_SERVER_SLOTS][32];
   int32 spines_int_port;
   char prime_addresses[MAX_NUM_SERVER_SLOTS][32];
 //start state
   int initial_state;
//start state hash
   byte initial_state_digest[DIGEST_SIZE];
   int32u frag_num;
 //pubkeys ???

}nm_message;

typedef struct dummy_key_msg_header{
    int32u frag_idx;
    //key-types: sm_tc_pvt, prime_tc_pvt, prime_rsa_pvt, sm_tc_pub,prime_tc_pub, prime_rsa_pub
}key_msg_header;

typedef struct dummy_pvt_key_header{
    int32u key_type;
    int32u id;
    int32u unenc_size;
    int32u pvt_key_parts;
    int32u pvt_key_part_size;
    /*Note key contents [pvt_key_parts][pvt_key_part_size] */
}pvt_key_header;

typedef struct dummy_pub_key_header {
    int32u key_type;
    int32u id;
    int32u size;
    /*key contents of len size*/
} pub_key_header;

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
  int32u originator;              /* originating entity (server) */
  po_seq_pair seq;
  byte digest[DIGEST_SIZE];       /* a digest of the update */
} po_ack_part;

typedef struct dummy_po_ack_message {
  int32u num_ack_parts;             /* Number of Acks */
  
  /* preinstalled incarnation for each server */
  int32u preinstalled_incarnations[MAX_NUM_SERVERS]; 
  
  /* a list of po_ack_parts follows */
} po_ack_message;

/* Messages for Pre-Ordering */
typedef struct dummy_po_aru_message {
  int32u num;
  /* Cumulative ack for each server */
  po_seq_pair ack_for_server[MAX_NUM_SERVERS];
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
  //int32u sec;
  //int32u usec;
  
  /* Digest representing the global incarnation AKA membership of the
   * reset proposal that started this instantiation of the system */
  byte proposal_digest[DIGEST_SIZE];

  /* Last Executed Vector */
  po_seq_pair last_executed[MAX_NUM_SERVERS];

  int16u part_num;
  int16u total_parts;
  int32u num_acks_in_this_message;

} pre_prepare_message;

/* Structure of a Prepare Message */
typedef struct dummy_prepare_message {
  int32u seq_num;              /* seq number                            */
  int32u view;                 /* the view number                       */
  byte   digest[DIGEST_SIZE];  /* a digest of whatever is being ordered */
  int32u preinstalled_incarnations[MAX_NUM_SERVERS]; 
} prepare_message;

/* Structure of a Commit Message */
typedef struct dummy_commit_message {
  int32u seq_num;                      /* seq number */
  int32u view;
  byte digest[DIGEST_SIZE];   /* a digest of the content */
  int32u preinstalled_incarnations[MAX_NUM_SERVERS]; 
} commit_message;

typedef struct dummy_complete_pre_prepare_message {
  int32u seq_num;
  int32u view;
  
  byte proposal_digest[DIGEST_SIZE];
  po_seq_pair last_executed[MAX_NUM_SERVERS];
  po_aru_signed_message cum_acks[MAX_NUM_SERVERS];
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

typedef struct dummy_ord_certificate_message {
  int32u view;
  int32u seq_num;
  int32u type;
  /* ord certificate follows: always 1 pre-prepare, If commit_cert, also 2f+k+1 commits */
} ord_certificate_message;

typedef struct dummy_po_certificate_message {
  int32u server;
  po_seq_pair seq;
  /* What follows is the PO_request and 2f+k+1 PO_Ack_Part messages */
} po_certificate_message;



/* NOTE: All TPM-signed messages must have the TPM monotonically increasing
 *   counter number on them. In the case of the new_incarnation message,
 *   only the incarnation is needed since it is a snapshot of the counter */

typedef struct dummy_catchup_request {
  int32u flag;    // CATCHUP, JUMP, PERIODIC, RECOVERY
  int32u nonce;
  int32u aru;
  po_seq_pair po_aru[MAX_NUM_SERVERS];
  byte   proposal_digest[DIGEST_SIZE];
  /* possibly include PO.aru vector so that the
   * receiver can know if they should EXCLUDE any of the
   * PO_Requests that became eligible for exection from
   * this ordinal. In the worst case, they send all
   * PO requests associated with this ord_slot. DO_RECON
   * could then be called comparing this vector with the
   * list of PO Requests */
} catchup_request_message;

typedef struct dummy_jump_message {
  int32u seq_num;
  int32u acked_nonce;
  byte   proposal_digest[DIGEST_SIZE];
  /* if the global ARU is 0, there is no ord certificate to send, so only the reset_cert that
   * started the system is sent. Otherwise, there is normally:
   *  (1)  N new_incarnation (or incarnation cert) messages that give currently used session key 
   *        for each replica, which is required to make sense of the ORD cert
   *       FOR NOW - using installed_incarnations vector to emulate session keys
   *  (2)  ord certificate: always 1 pre-prepare, If commit_cert, also 2f+k+1 commits
   *  (3)  Reset certificate that originally bootstrapped this global system incarnation */
  int32u installed_incarn[MAX_NUM_SERVERS];
} jump_message;

typedef struct dummy_new_incarnation_message {
  int32u nonce;
  int32u timestamp;
  byte key[DIGEST_SIZE]; //PRTODO: put real public part of session key here
} new_incarnation_message;

typedef struct dummy_incarnation_ack_message {
  int32u acked_id;             /* ID of which replica this ack is supporting */
  int32u acked_incarnation;    /* Incarnation of that replica being supported */
  byte digest[DIGEST_SIZE];    /* digest of new_incarnation message */
} incarnation_ack_message;

typedef struct dummy_incarnation_cert_message {
  /* What follows is the new_incarnation message + 2f+k+1 incarnation_acks */ 
} incarnation_cert_message;

typedef struct dummy_pending_state_message {
  int32u seq_num;
  int32u acked_nonce;
  int32u total_shares;
} pending_state_message;

typedef struct dummy_pending_share_message {
  int32u acked_nonce;
  int32u type;   /* whether this is an ORD or PO share */
  int32u index;  /* the index within the total shares */
  /* what follows is the message content of the ORD or PO message (i.e. pending
   * pre-prepare or po-request) */
} pending_share_message;

typedef struct dummy_reset_vote_message {
  int32u acked_incarnation;  /* Their incarnation */
  int32u acked_nonce;        /* Their nonce challenge to prove freshness */
} reset_vote_message;

typedef struct dummy_reset_share_message {
  int32u view;
  int32u nonce;
  byte key[DIGEST_SIZE];
} reset_share_message;

typedef struct dummy_reset_proposal_message {
  int32u view;
  int32u num_shares;
  /* What follows is the list of reset_shares (in their complete signed_message form) */
} reset_proposal_message;

typedef struct dummy_reset_prepare_message {
  int32u view;
  byte digest[DIGEST_SIZE];
} reset_prepare_message;

typedef struct dummy_reset_commit_message {
  int32u view;
  byte digest[DIGEST_SIZE];
} reset_commit_message;

typedef struct dummy_reset_newleader_message {
  int32u new_view;
} reset_newleader_message;

typedef struct dummy_reset_newleaderproof_message {
  int32u new_view;
  /* what follows are: 2*F+K+1 signed reset_newleader messages for
      the new proposed view */
} reset_newleaderproof_message;

typedef struct dummy_reset_viewchange_message {
  reliable_broadcast_tag rb_tag;    /* contains the view */
  int32u contains_proposal;
  /* if contains_proposal == TRUE, prepare certificate of proposal follows: 
   *    1 reset_proposal and 2f+k reset_prepares */
} reset_viewchange_message;

typedef struct dummy_reset_newview_message {
  reliable_broadcast_tag rb_tag;    /* contains the view */
  int32u list;
} reset_newview_message;

typedef struct dummy_reset_certificate_message {
  int32u view;
  /* reset certificate follows: 1 reset_proposal and 2f+k+1 reset_commits */
} reset_certificate_message;




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
  signed_message* prepare[MAX_NUM_SERVER_SLOTS]; 
} prepare_certificate_struct;

/* A Commit certificate consists of 2f+1 Commits */
typedef struct dummy_commit_certificate {
    //byte update_digest[DIGEST_SIZE];    /* The update digest */
    signed_message* commit[MAX_NUM_SERVER_SLOTS]; /* The set of prepares */
} commit_certificate_struct;

signed_message* PRE_ORDER_Construct_PO_Request  (void);
signed_message* PRE_ORDER_Construct_PO_Ack      (int32u *more_to_ack, int32u send_all_non_preordered);
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

signed_message* CATCH_Construct_Catchup_Request(int32u catchup_flag);
signed_message* CATCH_Construct_ORD_Certificate(struct dummy_ord_slot *slot);
signed_message* CATCH_Construct_PO_Certificate(int32u replica, struct dummy_po_slot *slot);
signed_message* CATCH_Construct_Jump(int32u sender_nonce);

signed_message* PR_Construct_New_Incarnation_Message(void);
signed_message* PR_Construct_Incarnation_Ack(signed_message *ni_mess);
signed_message* PR_Construct_Incarnation_Cert(void);
signed_message* PR_Construct_Pending_State(int32u target, int32u acked_nonce);
signed_message* PR_Construct_Pending_Share(int32u index, signed_message *mess, int32u acked_nonce);
signed_message* PR_Construct_Reset_Vote(signed_message *ni_mess);
signed_message* PR_Construct_Reset_Share(void);
signed_message* PR_Construct_Reset_Proposal(void);
signed_message* PR_Construct_Reset_Prepare(void);
signed_message* PR_Construct_Reset_Commit(void);
signed_message* PR_Construct_Reset_NewLeader(void);
signed_message* PR_Construct_Reset_NewLeaderProof(void);
signed_message* PR_Construct_Reset_ViewChange(void);
signed_message* PR_Construct_Reset_NewView(void);
signed_message* PR_Construct_Reset_Certificate(void);

signed_message *RECON_Construct_Recon_Erasure_Message(dll_struct *list,
							int32u *more_to_encode);

void print_complete_pre_prepare(complete_pre_prepare_message *complete_pp);
void print_PC_Set(signed_message *pc);
void print_prepare(prepare_message *pm);
#endif
