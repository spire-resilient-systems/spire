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

#ifndef PRIME_DATA_STRUCTS_H
#define PRIME_DATA_STRUCTS_H

#include <stdio.h>
#include "def.h"
#include "arch.h"
#include "spu_events.h"
#include "stdutil/stdhash.h"
#include "stdutil/stddll.h"
#include "stdutil/stdskl.h"
#include "openssl_rsa.h"
#include "stopwatch.h"
#include "util_dll.h"
#include "packets.h"

#define MAX_PRE_PREPARE_PARTS 10
#define PING_HIST 10

/* Public Functions */
void DAT_Initialize(void); 

typedef struct server_variables_dummy {
  int32u My_Server_ID;
  int32u F;
  int32u K;
} server_variables;

typedef struct network_variables_dummy {
  int32    My_Address;
  int32u   program_type;

  /* Client socket descriptor handling */
  /* int32    replica_sd;               */ /* To respond to application replica 
                                            (e.g. SCADA master)  */
  int32    from_client_sd;           /* Recv data from client */
  int32    to_client_sd;             /* Send data to client */ /* to = from for TCP */
  int32    listen_sd;                /* To listen for incoming connections */
  /* int32    client_sd[NUM_CLIENTS+1]; */ /* Which sd is for which client */

#if USE_IPC_CLIENT
  struct sockaddr_un client_addr;
#endif

  /* Stores the IP address of each server, read from configuration file  */
  int32 server_address[NUM_SERVER_SLOTS];

#ifdef SET_USE_SPINES
  channel  Spines_Channel;
  int32 server_address_spines[NUM_SERVER_SLOTS];
  int32 num_spines_daemons;
  int32 spines_daemon_address[NUM_SERVER_SLOTS];
  int32 spines_mcast_addr;
  int16 spines_mcast_port;
#endif

  int16u  Client_Port;

  int16u  Bounded_Port;
  int32   Bounded_Channel;
  int32   Bounded_Mcast_Address;
  int16u  Bounded_Mcast_Port;
  channel Bounded_Mcast_Channel;

  int16u  Timely_Port;
  int32   Timely_Channel;
  int32   Timely_Mcast_Address;
  int16u  Timely_Mcast_Port;
  channel Timely_Mcast_Channel;

  int16u  Recon_Port;
  channel Recon_Channel;

  dll_struct pending_messages_dll[NUM_TRAFFIC_CLASSES];
  double tokens[NUM_TRAFFIC_CLASSES];
  util_stopwatch sw[NUM_TRAFFIC_CLASSES];

} network_variables;

typedef struct dummy_net_struct {
  signed_message *mess;
  int32u server_id;
  int32u site_id;

  int32u dest_bits;
  int32u num_remaining_destinations;
  int32u destinations[NUM_SERVER_SLOTS];

  int32u timeliness;

} net_struct;

typedef struct dummy_benchmark_struct {
  int32u updates_executed;

  int32u num_po_requests_sent;
  int32u total_updates_requested;

  int32u num_flooded_pre_prepares;

  int32u num_po_acks_sent;
  int32u num_acks;
  double total_bits_sent[3];
  int32u clock_started;

  double bits[25];

  int32u num_signatures;
  int32u total_signed_messages;
  int32u max_signature_batch_size;
  int32u signature_types[MAX_MESS_TYPE];

  double num_throttle_sends;

  util_stopwatch test_stopwatch;
  util_stopwatch sw;
  util_stopwatch total_test_sw;

  FILE *state_machine_fp;

} benchmark_struct;

/* Pre-Order Data structures*/
typedef struct dummy_po_data_struct {

  /* For each client, this is the highest sequence number update that
   * we've locally introduced. */
  po_seq_pair intro_client_seq[NUM_CLIENT_SLOTS];

  /* For each client, this is the highest sequence number update that
   * we've executed and delivered to the connected application */
  //po_seq_pair exec_client_seq[NUM_CLIENT_SLOTS];

  /* Last po-request I've executed for each server */
  po_seq_pair last_executed_po_reqs[NUM_SERVER_SLOTS];

  /* For each server, what is the last one I've sent a PO-Ack for */
  po_seq_pair max_acked[NUM_SERVER_SLOTS];

  /* For each server, I've collected PO-Requests contiguously up to
   * this sequence number */
  po_seq_pair aru[NUM_SERVER_SLOTS];

  /* For each (i, j), I know that i has acknowledged (cumulatively or
   * regularly) having PO_Requests through [i][j] from j */
  po_seq_pair cum_max_acked[NUM_SERVER_SLOTS][NUM_SERVER_SLOTS];

  /* For each server, I know that at least 2f+k+1 total servers, possibly
   * including myself, have sent a PO_ACK for everything up to and including
   * this sequence number */
  po_seq_pair cum_aru[NUM_SERVER_SLOTS];

  /* Indicates whether new progress has been made in the cum_aru since we
   * last sent a PO_ARU - this flag is set back to 0 when we sent a PO_ARU,
   * and set to 1 when we update the cum aru */
  char cum_aru_updated;

  stdhash History[NUM_SERVER_SLOTS];

  /* This is the highest sequence number (client update) from each replica that
   * what we think the leader should know about. Essentially, its the highest
   * sequence number that 2f+k+1 have acked for that server. This is updated
   * either when we send a challenge (proof_matrix) or we get a pre-prepare
   * that is more up-to-date than we know (indicating the leader already knew
   * something we didn't send him directly) */
  po_seq_pair max_num_sent_in_proof[NUM_SERVER_SLOTS];
  
  /* The last PO-ARU I've received from each server */
  po_aru_signed_message cum_acks[NUM_SERVER_SLOTS];

  /* Preorder sequence information: includes incarnation and personal sequence
   * number that I use to assign to each local originated PO_request. Preorder
   * incarnation - this is used for crash/recovery in order send PO_requests
   * (and other preordering messages) such that the other replicas will know
   * you have recovered and will accept new sequence numbers from you */
  po_seq_pair po_seq;

  /* Keeps track of the cumulatively executed seq num of my locally
   * injected PO_Requests */
  po_seq_pair po_seq_executed; 

  /* PO-ARU number, incremented each time I send a Local PO-ARU */
  int32u po_aru_num;

  /* For each server i, I've executed preordered PO_requests through 
   * (i, white_line[i]) */
  po_seq_pair white_line[NUM_SERVER_SLOTS];

  /* Used for Timing PO Duration - only works for prime client with
   * 1 outstanding update per replica */
  //util_stopwatch po_duration_sw;
  //int32u already_timed;

  /* Timers */
  util_stopwatch po_request_sw;
  util_stopwatch po_ack_sw;
  util_stopwatch po_aru_sw;
  util_stopwatch proof_matrix_sw;

  /* Local Token rate limiter */
  int32 tokens;
  util_stopwatch token_stopwatch;

  /* Queue of PO-Request and PO-Proof messages waiting to be sent */
  dll_struct po_request_dll;
  dll_struct proof_matrix_dll;

  /* If we try to execute a local commit but don't yet have all of
   * the PO-Requests that become eligible, we need to hold off on
   * executing.  When we hold off b/c of PO-Request (i, j), we'll
   * store a pointer to the ord_slot in Pending_Execution[i] --> j */
  stdhash Pending_Execution[NUM_SERVER_SLOTS];

  /* Map[i] stores local_recon slots for preorder ids (i, j) */
  stdhash Recon_History[NUM_SERVER_SLOTS];

  /* (i, j) = k means: I have sent a recon message to server i for a
   * po_request (j, k) */
  //int32u Recon_Max_Sent[NUM_SERVER_SLOTS][NUM_SERVER_SLOTS];
  
  //int32u debug_drop;

} po_data_struct;

typedef struct dummy_po_id {
  int32u server_id;
  po_seq_pair seq;
} po_id;

typedef struct dummy_po_slot {
  /* The preorder sequence number */
  po_seq_pair seq;           
  
  /* A copy of the request message */
  signed_message *po_request;
  byte po_request_digest[DIGEST_SIZE];

  /* Tracks the acks received and digests from each server */
  int32u ack_received[NUM_SERVER_SLOTS]; 
  po_ack_part ack[NUM_SERVER_SLOTS]; 
  
  /* Used to keep track of how many updates are packed into this po_request */
  int32u num_events;

} po_slot;

/* Ordering data structure slot */
typedef struct dummy_ord_slot {
  /* seq number of this slot */
  int32u seq_num;		
  int32u view;

  /* type indicating what kind of slot this is:
   *    SLOT_COMMIT - created normally w/ commit cert
   *    SLOT_PC_SET - created by replay message during view change
   *    SLOT_NO_OP  - created as no_op during view change */
  int32u type;

  /* current pre prepare */
  int32u pre_prepare_parts[MAX_PRE_PREPARE_PARTS+1];
  signed_message *pre_prepare_parts_msg[MAX_PRE_PREPARE_PARTS+1];
  int32u total_parts;
  int32u num_parts_collected;
  int32u collected_all_parts;
  int32u should_handle_complete_pre_prepare;
  complete_pre_prepare_message complete_pre_prepare;
  int32u sent_prepare; /* I accepted this pre-prepare as valid and sent a prepare for it */

  /* Flag: did we forward the Pre-Prepare part? */
  int32u forwarded_pre_prepare_parts[MAX_PRE_PREPARE_PARTS+1];
  int32u num_forwarded_parts;

  /* current prepares */
  signed_message* prepare[NUM_SERVER_SLOTS]; 
  int32u ordered;
  /*int32u bound; */
  int32u executed;

  /* current commits */
  signed_message* commit[NUM_SERVER_SLOTS];        

  /* When a Prepare certificate is ready, we mark the flag here.  The
   * dispatcher sees this and sends a commit, then sets the flag so we 
   * only send the commit once. */
  int32u prepare_certificate_ready;
  /*int32u sent_commit;*/

  /* Flag to signal if a a commit certificate should be executed */
  int32u execute_commit;	

  /* Last prepare certificate */
  prepare_certificate_struct prepare_certificate;	
  
  /* Commit certificate */
  commit_certificate_struct commit_certificate;	

  /* If we commit the slot before we're ready to execute, this tells
   * us how many missing po-requests we need to collect before we can
   * execute. */
  int32u num_remaining_for_execution;

  /* Have we already reconciled on this slot? */
  int32u reconciled;

  /* In case of catchup and this slot is either SLOT_NO_OP or SLOT_PC_SET,
   * we want to collect f+1 matching copies of the pre-prepare, then go
   * with that */
  signed_message *pp_catchup_replies[NUM_SERVER_SLOTS];

  /* Maintains the PO Slots that become eligible for execution
   * so that when we garbage collect this ord_slot, we can easily
   * determine which PO Slots to destroy as well */
  stddll po_slot_list;

  /* The certificate for this ordinal slot, which is computed each time
   * the slot is both ordered and ready to execute. This certificate
   * may be one of several types:
   *   COMMIT = normal case, pre-prepare and 2f+k+1 commits
   *   PC_SET = ordered during view change, only pre-prepare, need f others
   *   NO_OP  = skipped over during view change, only PP, need f others */
  signed_message *ord_certificate;

} ord_slot;

typedef struct dummy_ordering_data_struct {
  /* The local ARU. */
  int32u ARU;

  /* Maximum Global sequence number that this server has received
   *    consecutive valid pre-prepares for */
  int32u ppARU;

  /* Highest Global sequence number ordered/bound so far */
  int32u high_seq;

  /* If I'm the leader, flag indicating whether to send pre_prepare
   *    at the next timeout */
  int32u should_send_pp;
  
  /* Number of events we've ordered */
  int32u events_ordered;

  /* The next sequence number to assign */
  int32u seq;

  /* The Ordering History, which stores ordering_slots */
  stdhash History;

  util_stopwatch pre_prepare_sw;

  /* To store ord slots that are globally ordered but not yet ready to
   * be globally executed. */
  stdhash Pending_Execution;

  int32u forwarding_white_line;
  int32u recon_white_line;

} ordering_data_struct;

/* Data structure for storing Proof Matrix + Stopwatch for Suspect Leader */
typedef struct dummy_tat_challenge {
    po_aru_signed_message proof_matrix[NUM_SERVER_SLOTS];
    util_stopwatch turnaround_time;
} tat_challenge;

/* Data structure for ping struct, storing seq_num and stopwatch */
typedef struct dummy_ping_cell {
    int32u seq_num;
    util_stopwatch rtt;
} ping_cell;

/* Data structures for suspect leader protocol */
typedef struct dummy_suspect_leader_data_struct {

    /* ---- TAT Leader Measurement ---- */
    /* time between when sending summary (proof) matrix and receiving a
        PP that covers it and is next expected PP_Seq_Num */
    stddll turnaround_times;
    /* highest TAT I've measured this view, I send this in TAT_Measure msgs */
    double max_tat;    
    /* indicates if there was a change to the max_tat since the last time I
     *      sent a TAT Measure message */
    int32u tat_max_change;
    /* last time I sent my measured max_tat this view. Used to prevent me from
     *      sending the same value too often */
    util_stopwatch sent_tatm_sw;
    /* Stores the max_tat from each other replica this view */
    double reported_tats[NUM_SERVER_SLOTS];
    /* the f+k+1 lowest value in reported tats */
    double tat_leader;

    /* ---- TAT Acceptable Measurement ---- */
    /* sequence number used on next ping broadcast */
    int32u ping_seq_num;
    /* array of pings - stores seq_num and time between broadcasting each ping 
     *  and getting back pong from other replicas */
    ping_cell ping_history[PING_HIST]; 
    /* Store RTT-Measure msgs in the appropriate slot, if I was leader,
        store RTT after computing: rtt * K_Lat + PP_time */
    double tat_if_leader[NUM_SERVER_SLOTS];
    /* Store the latest TAT_UB that I sent to everyone else */
    double alpha;
    /* Store TAT-UB msgs from each replica this view */
    double tat_leader_ubs[NUM_SERVER_SLOTS];
    /* the f+k+1 highest value in TAT-UB */
    double tat_acceptable;

    /* ---- New Leader Election ---- */
    /* flag indicating if we've suspected the leader this view yet */
    int32u leader_suspected;
    /* array to store new_leader messagse from replicas */
    signed_message *new_leader[NUM_SERVER_SLOTS];
    /* large signed_message containing new_leader_proof */
    signed_message *new_leader_proof;

} suspect_leader_data_struct;

/* Reliable Broadcast data structures */
typedef struct dummy_rb_data_struct {
    /* Sequence number of the next RB instance I initiate */
    int32u rb_seq; 

    /* Hash table (of slots) for storing all RB instances in this view */
    stdhash instances[NUM_SERVER_SLOTS];

} rb_data_struct;

typedef struct dummy_rb_slot {
  /* The rb init sequence number (from this machine's hash table) */
  int32u seq_num;           
  
  /* Step of this rb_slot in the protocol */
  int32u state;
  
  /* Copy of the rb msg = signed_message + rb_tag (id/seq/view) + content) */
  signed_message *rb_msg; 
  byte rb_digest[DIGEST_SIZE+1];

  /* Keeps track of the origial complete rb_init msg */
  signed_message *rb_init;

  /* Tracks the echos received from each server */
  signed_message *rb_echo[NUM_SERVER_SLOTS];
  int32u echo_received[NUM_SERVER_SLOTS]; 
  int32u echo_count;
  
  /* Tracks the readys received from each server */
  signed_message *rb_ready[NUM_SERVER_SLOTS];
  int32u ready_received[NUM_SERVER_SLOTS];
  int32u ready_count;

} rb_slot;

typedef struct dummy_view_change {
    /* Are we finished with the view change for this view */
    int32u view_change_done;

    /* Have we executed at least one ordinal in this view */
    int32u executed_ord;

    /* The number of Prepare certificates I have to share */
    int32u numSeq;

    /* Report message from each replica, NULL if not received */
    signed_message *report[NUM_SERVER_SLOTS];

    /* Storage for PC set messages from each replica */
    stdskl pc_set[NUM_SERVER_SLOTS];

    /* Store the maximum seq_num of a prepare certificate in any pc_set 
     *  message given to us by each replica */
    int32u max_pc_seq[NUM_SERVER_SLOTS];

    /* Bitmask keeping track of who we have complete state from */
    int32u complete_state; /* NOTE: currently only supports 32 replicas */

    /* Store the vc_list message that I send personally for easy access
     * to retransmissions */
    signed_message *my_vc_list;

    /* Currently, we only need to store one copy of each VC_List message,
     *  using the bitmap of which servers are included in the list of
     *  2f+k+1 as the key to lookup */
    stdhash unique_vc_list;

    /* List of pending VC_List messages that still need a partial sig
     *  but we originally didn't have complete state for the whole list
     *  so we needed to delay it */
    stddll pending_vc_list;

    /* Stores the unique partial_sig messages that we receive, indexed
     *  by the ids list of servers in that set, storing the first
     *  message we receive from each replica that match this id list */
    stdhash unique_partial_sig;

    /* Stores the first replay sent by the leader - The leader uses this itself
     *  to determine if it has sent a replay for this view change yet or not. 
     *  Also store the digest for convenience */
    signed_message *replay;
    byte replay_digest[DIGEST_SIZE];

    /* Array and count of replay prepares received this view change */
    signed_message *replay_prepare[NUM_SERVER_SLOTS];
    int32u replay_prepare_count;
    
    /* Array and count of replay commits received this view change */
    signed_message *replay_commit[NUM_SERVER_SLOTS];
    int32u replay_commit_count;

    /* Flags for keeping track of what we've sent / done so far */
    int32u sent_replay_prepare;
    int32u sent_replay_commit;
    int32u executed_replay;

    /* Stopwatch for measuring view change duration */
    util_stopwatch vc_sw;

    /* Measures TAT betwen sending VC_PROOF and receiving valid REPLAY */
    util_stopwatch vc_tat;
    int32u started_vc_measure;
    int32u done_vc_measure;

    /* Used to measure the size and number of different message types
     *  during a view */
    int32u vc_stats_send_size[MAX_MESS_TYPE];
    int32u vc_stats_send_count[MAX_MESS_TYPE];
    int32u vc_stats_sent_bytes;
    int32u vc_stats_recv_bytes;
    util_stopwatch vc_stats_sw;

} view_change_struct;

typedef struct dummy_proactive_recovery {

  /* Am I currently trying to catcup my ARU? */
  int32u recovery_in_progress;

  /* The global sequence that I'm waiting for my ARU to catchup to */
  int32u catchup_target;

  /* Throttling settings for other replicas */
  /* (1) keep track of when I last helped them catchup to prevent being 
   * drained of resources */

  /* (2) keep track of the sequence number (eventually also epoch) that
   * I sent them, to prevent replay attacks */
  int32u caught_up_seq[NUM_SERVER_SLOTS];

/* ===== NEW CATCHUP BELOW ===== */

  /* Store the latest ordinal certificate received from each replica
   *   This can be either (a) commit_cert (normal ordering),
   *   (b) pc_set (ordered prepare cert during view change) - requires f others,
   *   (c) no_op (skip ordinal during view change) - requires f others
   *
   *   Note: my own latest cert is stored in my slot */
  signed_message *last_ord_cert[NUM_SERVER_SLOTS];

  /* Timer used to rate limit how often replicas ask me to recover. This
   *   represents the next time we are willing to help that replica.
   *   Note: my own slot is used as a personal timer to not try to often */
  sp_time next_catchup_time[NUM_SERVER_SLOTS];

  /* Used to keep track of who we're asking to help us catchup each instance */
  int32u next_catchup_id;

} proactive_recovery_struct;

typedef struct dummy_signature_data_struct {
  dll_struct pending_messages_dll;

  int32u seq_num;

  /* How many messages we've read without generating a signature.  If
   * this gets above a certain threshold, call the Sig signing
   * function immediately. */
  int32u num_consecutive_messages_read;

  sp_time sig_time;

} signature_data_struct;

/* This stores all of the server's state, including Preordering
 * and Ordering state. */
typedef struct dummy_server_data_struct {
  /* The view number.  For the tests, should always be 1. */
  int View;
  
  /* The Pre-Order data structure */
  po_data_struct PO;
  
  /* The Ordering data structure */
  ordering_data_struct ORD;

  /* Suspect Leader data structure */
  suspect_leader_data_struct SUSP;

  /* Reliable Broadcast data structure */
  rb_data_struct RB;

  /* View Change data structure */
  view_change_struct VIEW;

  /* Proactive Recovery data structure */
  proactive_recovery_struct PR;

  signature_data_struct SIG;

} server_data_struct;
#endif
