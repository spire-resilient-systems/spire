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

#ifndef PRIME_DEF_H
#define PRIME_DEF_H

/*---------------------System-wide Configuration Settings-------------------*/
/*MS2022: Max Server Variable , used to create structs*/
/*f=2 3 site number from 2018 paper*/
#define MAX_NUM_SERVERS 30
#define MAX_NUM_SERVER_SLOTS           (MAX_NUM_SERVERS+1)

/*Reconf flag: Set to 0 to run Spire and 1 to run reconfigurable spire*/
#define RECONF 1
#define CONFIDENTIAL 0
/* Maximum number of tolerated Byzantine faults */
#define NUM_F 1

/* Maximum number of tolerated benign faults, including rejuvenations,
 * disconnections (network partition/attack), and crashes */
#define NUM_K 0

/*This parameter is used only in confidential spire. Will be replaced bu VAR.Num_Servers
 * in future version*/
/* Total number of replicas in the system. NUM_SERVERS must be equal to 
 * (3*NUM_F + 2*NUM_K + 1) */
#define NUM_SERVERS (3*NUM_F + 2*NUM_K + 1)

/* Maximum number of clients */
#define NUM_CLIENTS 150

/* Number of bytes in a client update */
#define UPDATE_SIZE 300

/* When running a benchmark, this value indicates how many updates
 * should be executed by the servers before stopping and outputting
 * the throughput. */
/* #define BENCHMARK_END_RUN 8000000 */

/* Set this to 1 if an erasure encoding library is available and
 * integrated. By default, no erasure encoding is used and each
 * correct server that would send an erasure-encoded RECON message
 * instead sends the complete PO-Request itself (not encoded). */
#define USE_ERASURE_CODES 0

/* Variability constant K_Lat */
#define VARIABILITY_KLAT 2.5

/* Catchup History - To catch other replicas up, we
 * keep AT LEAST this many ord_slots around so that we can give them
 * ORD/PO certificates to help them catch up their ARU.
 * 
 * NOTE: CATCHUP_HISTORY is also used for garbage collection or ordinals.
 * If you specify CATCHUP_HISTORY of 0, replicas will always try to jump
 * (never catchup), but garbage collection will still proceed as if the
 * history window is size of 1. */
#define CATCHUP_HISTORY 10

/* Number of outstanding PO_requests that have not yet been executed */
#define MAX_PO_IN_FLIGHT 20

/* How often to print that Prime is making progress - based on number of
 * ordinals that have been ordered */
#define PRINT_PROGRESS 1000

/*--------------------Networking Settings-----------------------------------*/

#define PRIME_BOUNDED_MCAST_PORT       7100
#define PRIME_TIMELY_MCAST_PORT        7101
#define PRIME_TCP_BASE_PORT            7102
#define PRIME_BOUNDED_SERVER_BASE_PORT 7200
#define PRIME_TIMELY_SERVER_BASE_PORT  7250
#define PRIME_RECON_SERVER_BASE_PORT   7300
#define PRIME_SPINES_SERVER_BASE_PORT  7350
#define PRIME_CLIENT_BASE_PORT         7400
#define SPINES_PORT                    8100
#define SPINES_EXT_PORT                8120
/* Set this to 1 if IP multicast is available (i.e., when running in a
 * LAN).  Note that this option is not compatible with the
 * SET_USE_SPINES flag (see Makefile) or the
 * THROTTLE_OUTGOING_MESSAGES flag (see below). */
#define USE_IP_MULTICAST 0

/* Set this to 1 if Prime client and replica are co-located on the
 * same physical machine. Using Inter-Process Communication will speed up 
 * (in terms of latency) messaging between the client and replica when
 * sending messages with more than just a few bytes */
#define USE_IPC_CLIENT 1
#define REPLICA_IPC_PATH "/tmp/prime_replica"
#define CLIENT_IPC_PATH "/tmp/prime_client"
#define CA_DRIVER_IPC_PATH "/tmp/ca_driver_ipc"
/* Set this to 1 if Prime daemon and Spines daemon it connects to are
 * co-located on the same physical machine */
#define USE_SPINES_IPC 1

/* For Prime over the WAN, Spines daemons can be used to represent different geographic
 * sites, with several Prime replicas hosted at each site. To consolidate the number
 * of messages sent over the WAN, we can use a multicast address of the form:
 * 254.255.0.X to send to all replicas reliably */
#define SPINES_MCAST_ADDR      "254.255.0.20"
/*IP and Port Used for Multicast on Configuration Network*/
#define CONF_SPINES_MCAST_ADDR "224.1.1.3"
#define CONF_SPINES_MCAST_PORT 9900
/*IP Address of Configuration Manager- Please edit to match testbed*/
#define CONF_MNGR_ADDR "192.168.101.108"
/*Ports of Spines Configuration Network used by Configuration Manager and Agents*/
#define CONFIGUATION_SPINES_PORT       8900
#define CTRL_BASE_PORT      9580

#define SPINES_PRIORITY 1

#define SPINES_CONNECT_SEC  2
#define SPINES_CONNECT_USEC 0

#define SPINES_EXP_TIME_SEC  5
#define SPINES_EXP_TIME_USEC 0

/*--------------------Crypto Settings---------------------------------------*/

/* Set this to 0 to test performance when clients do not sign their
 * updates.  This approximates the performance should message
 * authentication codes be used.  NOTE: This is only for benchmarking!
 * It is not yet supported by the protocol and could be exploited by
 * faulty processors. */
#define CLIENTS_SIGN_UPDATES 1

/* In order to amortize the cost of an RSA signature over many
 * outgoing messages, each server maintains a linked lists of messages
 * that are awaiting a signature.  The server generates a single RSA
 * signature on a batch of messages (i.e., those in the list) when one
 * of two conditions occurs: (1) Enough time passes in which no
 * messages are added to the list; (2) the size of the list reaches a
 * threshold value.  SIG_SEC and SIG_USEC are the seconds and
 * microseconds of the timeout, and SIG_THRESHOLD is the threshold
 * value. */
/*#define SIG_SEC  0
#define SIG_USEC 1000
#define SIG_THRESHOLD  128 */

#define SIG_MIN_SEC  0
#define SIG_MIN_USEC 1000
#define SIG_MAX_SEC  0
#define SIG_MAX_USEC 5000
#define SIG_THRESHOLD 64

/* This is the maximum number of Merkle tree digests that may be
 * appended to a given message.  This value is dependent on
 * SIG_THRESHOLD: for example, setting SIG_THRESHOLD to 128 (2^7)
 * ensures that at most 7 digests will be appended.  Don't raise
 * SIG_THRESHOLD without raising this value! */
#define MAX_MERKLE_DIGESTS 6

/*---------------------------Throttling Settings----------------------------*/

/* The code can be configured so that outgoing messages are throttled,
 * where that the total sending rate for each traffic class does not
 * exceed some maximum bandwidth. Set this flag to 1 to enable
 * throttling. */
#define THROTTLE_OUTGOING_MESSAGES 0

/* These values define the maximum outgoing bandwidth of each traffic
 * class when throttling is used.  The number are in bits per second
 * (e.g., 10000000 means the outgoing bandwidth is not to exceed
 * 10Mbps). Note that in the current release, RECON messages are
 * always throttled, regardless of whether the
 * THROTTLE_OUTGOING_MESSAGES flag is set. */
#define MAX_OUTGOING_BANDWIDTH_TIMELY  100000000
#define MAX_OUTGOING_BANDWIDTH_BOUNDED 100000000
#define MAX_OUTGOING_BANDWIDTH_RECON   10000000

/* This defines the maximum burst size for the token bucket. */
#define MAX_TOKENS 900000

/* These can be used to control how frequently the throttling function
 * is called (i.e., how often we check to see if we can send new
 * messsages). */
#define THROTTLE_SEND_SEC  0
#define THROTTLE_SEND_USEC 1000

/* When throttling, we can choose to send broadcast messages out to servers
 * in order, or we can send them in a random order.  Set this to 1 to 
 * enable the randomization. */
#define RANDOMIZE_SENDING 0

/*-----------------------Periodic Sending Settings--------------------------*/

/* Certain messages can be configured to be sent periodically rather than 
 * right away.*/

/* How often do we send a Pre-Prepare? */
#define PRE_PREPARE_SEC  0
#define PRE_PREPARE_USEC 20000
//#define PRE_PREPARE_SEC  2
//#define PRE_PREPARE_USEC 0

/* When sending PreOrder messages periodically, how often the timeout
 * fires (i.e, how often we check to see if we can send new
 * messages) */
#define PO_PERIODICALLY_SEC  0
#define PO_PERIODICALLY_USEC 2000

/* These flags control which PO messages are sent periodically.  Set
 * an entry to 0 to have it NOT be sent periodically. */ 
#define SEND_PO_REQUESTS_PERIODICALLY  0
#define SEND_PO_ACKS_PERIODICALLY      1 
#define SEND_PO_ARU_PERIODICALLY       1
#define SEND_PROOF_MATRIX_PERIODICALLY 1

/* When the PO messages are sent periodically, this is how many
 * timeouts need to fire before we send each one.  For example, if 
 * PO_REQUEST_PERIOD = 3, then we send a PO_Request no more frequently
 * than once every (PO_PERIODICALLY_USEC * 3) = 9 ms. */
#define PO_REQUEST_PERIOD             3
#define PO_ACK_PERIOD                 3
#define PO_ARU_PERIOD                 3
#define PROOF_MATRIX_PERIOD           3

/* When sending ping messages for measuring TAT acceptable, how often
 * we send a ping message to other replicas. */
#define SUSPECT_PING_SEC  0
#define SUSPECT_PING_USEC 500000

/* How often do we recompute the TAT acceptable and send the latest
 * value to all other replicas. */
#define SUSPECT_TAT_UB_SEC  0
#define SUSPECT_TAT_UB_USEC 500000

/* This determines how often we measure the TAT so far on un-answered 
 * Proof Matrix challenges. If there is a change during the measure, we
 * send it right away. If there are no changes, we will still periodically
 * send the TAT measure based on the SUSPECT_SEND_TATM timeout */
#define SUSPECT_TAT_MEASURE_SEC  0
#define SUSPECT_TAT_MEASURE_USEC 20000
#define SUSPECT_SEND_TATM_SEC 0
#define SUSPECT_SEND_TATM_USEC 500000
#define TAT_PRINT_THRESH (PRE_PREPARE_SEC + ((PRE_PREPARE_USEC+9500)/1000000.0))
#define MIN_RTT 0.008    /* 8 ms */

/* This is how often the suspect leader timeouts should trigger during a
 * view change. These numbers are more aggressive in the case that we need
 * to go through multiple consecutive (nested) view changes */
#define SUSPECT_VC_SEC  0
#define SUSPECT_VC_USEC 500000

/* How often do we send our New Leader Proof message to other replicas
 * to help them preinstall a new view and participate in the view change */
#define SUSPECT_NEW_LEADER_SEC   1
#define SUSPECT_NEW_LEADER_USEC  0

/* How often do we periodically send our lastet ORD certificate to help other
 * replicas determine they are behind (and eventually get caught back up). */
//#define ORD_CERT_PERIODICALLY_SEC   5
//#define ORD_CERT_PERIODICALLY_USEC  0

/* How often do we periodically send catchup_requests to find out if we are 
 * behind in progress. Other replicas will not respond if we aren't behind,
 * and will only respond according to some rate limit */
#define CATCHUP_REQUEST_PERIODICALLY_SEC   10
#define CATCHUP_REQUEST_PERIODICALLY_USEC  0

/* How often do we allow ourselves to catchup or do we allow ourselves to
 * help others in their catching up */
#define CATCHUP_PERIOD_SEC   2
#define CATCHUP_PERIOD_USEC  0

/* If we are mid-catchup round and the replica we are working with does not
 * help us for this much time, we give up on them and ask the next replica
 * to start helping us */
#define CATCHUP_MOVEON_SEC      0
#define CATCHUP_MOVEON_USEC     100000

/* If we are just about to start a catching up instance, delay the instance
 * for this amount of time to potentially allow the missing message to make
 * it to me before asking for them or jumping ahead */
#define CATCHUP_EPSILON_SEC      0
#define CATCHUP_EPSILON_USEC     20000

/* How often so we retransmit messages from each phase of the protocol 
 * (e.g., PRE_ORDER, ORDER, VIEW_CHANGE, ...) */
#define RETRANS_PERIOD_SEC  2
#define RETRANS_PERIOD_USEC 0

/* How often replicas are allowed to recover */
#define RECOVERY_PERIOD_SEC  10
#define RECOVERY_PERIOD_USEC 0

/* How often replicas wait before re-issuing new_incarnation messages 
 * with a more up-to-date timestamp while trying to recover */
#define RECOVERY_UPDATE_TIMESTAMP_SEC  4
#define RECOVERY_UPDATE_TIMESTAMP_USEC 0

/* How much time does the leader in the fresh system reset case have to
 * collect, send out the proposal, and get the message committed before
 * being voted out of power */
#define SYSTEM_RESET_TIMEOUT_SEC  10
#define SYSTEM_RESET_TIMEOUT_USEC 0

/* How much time the leader (and other replicas) should wait after
 * receving the 2f+k+1th share in order to leave "enough time" for
 * all correct replicas' share to be received - see assumptions */
#define SYSTEM_RESET_MIN_WAIT_SEC  2
#define SYSTEM_RESET_MIN_WAIT_USEC 0

/*-----------------------Attack Settings-----------------------------------*/

/* Set this to 1 to mount the leader's delay attack.  The leader
 * ignores PO-ARU messages, only handles Proof-Matrix messages when it
 * needs to (to avoid being suspected), and only sends the Pre-Prepare
 * to server 2. DELAY_TARGET is how long a Proof-Matrix sits at the
 * leader before it is processed.  Note that in this version of the
 * attack, the leader does not explicitly adjust the rate at which it
 * sends Pre-Prepare messages; it simply adjusts what PO-ARU messages
 * (from the Proof Matrix messages it receives) must be included in
 * the next Pre-Prepare. Note also that this is more generous to the
 * malicious leader than would be allowed in a real implementation:
 * since the leader only sends Pre-Prepares periodically, if it
 * decides not to send a Pre-Prepare now, it needs to wait another
 * timeout before trying again, and so the delays can sum. A more
 * precise attack would compute the minimum time in the future that
 * the leader needs to send the next Pre-Prepare as a function of what
 * Proof-Matrix messages it has received. */
#define DELAY_ATTACK 0
#define DELAY_TARGET 0.020

/* Set this to 1 to mount the reconciliation attack described in the paper.
 * Faulty servers only acknowledge each other's messages and don't send
 * their PO-Requests to f correct servers. */
#define RECON_ATTACK 0

/*----------------------- Internally used defines-------------------------- */
#define FALSE                      0
#define TRUE                       1

#define NET_CLIENT_PROGRAM_TYPE    1
#define NET_SERVER_PROGRAM_TYPE    2
//MS2022
#define NM_PROGRAM_TYPE    	   3

#define BROADCAST                  0

/* NOTE: Currently, we are relying on Spines to handle large messages,
 * in this case up to 10K messages. In the future, we should not assume
 * this and create a nice generic way to break up large messages into
 * packets for any protocol message */
#define PRIME_MAX_PACKET_SIZE      32000
//#define PRIME_MAX_PACKET_SIZE      1472
//#define NUM_SERVER_SLOTS           (NUM_SERVERS+1)
#define NUM_CLIENT_SLOTS           (NUM_CLIENTS+1)

/* We store two additional pieces of information, each an integer, in
 * the util_dll structures.  The first is referred to in the code as
 * dest_bits: the integer is a bitmap containing the destinations for
 * the given signed message.  The second is the timeliness of the
 * message (i.e., what traffic class is it in).*/
#define DEST       0
#define TIMELINESS 1

/* Traffic classes.  Note that these can be set to identical values in
 * order to create fewer traffic classes (e.g., making BOUNDED AND
 * RECON the same number will put them both onto the same queue. */
#define NUM_TRAFFIC_CLASSES        3
#define TIMELY_TRAFFIC_CLASS       0
#define BOUNDED_TRAFFIC_CLASS      1
#define RECON_TRAFFIC_CLASS        2

/* The maximum number of PO-Acks that can fit in a single packet, as a 
 * function of the maximum packet size and the number of Merkle tree 
 * digests that may be appended to the message. */
/* #define MAX_ACK_PARTS  (PRIME_MAX_PACKET_SIZE - sizeof(signed_message) - sizeof(po_ack_message) - (MAX_MERKLE_DIGESTS * DIGEST_SIZE)) / sizeof(po_ack_part) */

/* #define MAX_ACK_PARTS  ((PRIME_MAX_PACKET_SIZE - sizeof(signed_message) - sizeof(po_ack_message) - (MAX_MERKLE_DIGESTS * DIGEST_SIZE)) / (sizeof(signed_message) + sizeof(po_ack_part) + (MAX_MERKLE_DIGESTS * DIGEST_SIZE))) */

#define MAX_ACK_PARTS  (PRIME_MAX_PACKET_SIZE - sizeof(signed_message) - sizeof(po_certificate_message) - (MAX_MERKLE_DIGESTS * DIGEST_SIZE) - sizeof(signed_message) - sizeof(po_request_message) - (MAX_MERKLE_DIGESTS * DIGEST_SIZE) - ((2*NUM_F + NUM_K + 1) * (sizeof(signed_message) + sizeof(po_ack_message) + (MAX_MERKLE_DIGESTS * DIGEST_SIZE)))) / ((2*NUM_F + NUM_K + 1) * sizeof(po_ack_part))

/* After reading an event, we poll the socket to see if there are
 * more.  This lets us do as much reading as possible.  The threshold
 * below adjusts the maximum number of messages that will be read
 * during any one poll. If no message is available, we stop polling
 * immediately and return to the main event loop. See libspread-util/events.c */
#define POLL_NON_LOW_PRIORITY_THRESHOLD 3000

#endif
