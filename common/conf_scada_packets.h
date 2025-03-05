/*
 * Spire.
 *
 * The contents of this file are subject to the Spire Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.dsn.jhu.edu/spire/LICENSE.txt 
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis, 
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
 * for the specific language governing rights and limitations under the 
 * License.
 *
 * Spire is developed at the Distributed Systems and Networks Lab,
 * Johns Hopkins University and the Resilient Systems and Societies Lab,
 * University of Pittsburgh.
 *
 * Creators:
 *   Yair Amir            yairamir@cs.jhu.edu
 *   Trevor Aron          taron1@cs.jhu.edu
 *   Amy Babay            babay@pitt.edu
 *   Thomas Tantillo      tantillo@cs.jhu.edu
 *   Sahiti Bommareddy    sahiti@cs.jhu.edu
 *   Maher Khan           maherkhan@pitt.edu
 *
 * Major Contributors:
 *   Marco Platania       Contributions to architecture design 
 *   Daniel Qian          Contributions to Trip Master and IDS
 *
 * Contributors:
 *   Samuel Beckley       Contributions to HMIs
 *
 * Copyright (c) 2017-2025 Johns Hopkins University.
 * All rights reserved.
 *
 * Partial funding for Spire research was provided by the Defense Advanced 
 * Research Projects Agency (DARPA), the Department of Defense (DoD), and the
 * Department of Energy (DoE).
 * Spire is not necessarily endorsed by DARPA, the DoD or the DoE. 
 *
 */

#ifndef SCADA_PACKETS_H
#define SCADA_PACKETS_H

#include <stdint.h>
#include "def.h"
#include "conf_net_wrapper.h"

/* Definitions for compatibility with Prime */
#define UPDATE_SIZE 300
#define SIGNATURE_SIZE 128
#define MAX_PAYLOAD_SIZE 512  /* should be at least update_size */

#define UPDATE 46
#define CLIENT_RESPONSE 47
#define PRIME_NO_OP 101
#define PRIME_STATE_TRANSFER 102
#define PRIME_SYSTEM_RESET 103

/* SCADA-specific definitions */
#define MAX_SWITCHES 10
#define TC_HISTORY 0
#define TC_FALL_BEHIND_THRESHOLD 10
#define MAX_STATE_SIZE (MAX_LEN - sizeof(signed_message) - sizeof(state_xfer_msg))

/* PNNL scenario definitions */
#define NUM_POINT 8
#define NUM_BREAKER 14

/* EMS scenario definitions */
#define EMS_NUM_GENERATORS 6
#define EMS_NUM_POWERPLANTS 2

/*
 * Message types:
 *   DUMMY = dummy
 *   RTU_DATA = message sent from RTU Proxy to SCADA Master
 *   RTU_FEEDBACK = message sent from SCADA Master to RTU Proxy
 *   HMI_UPDATE = message sent SCADA Master to HMI (PVS)
 *   HMI_COMMAND = message sent from HMI to SCADA Master
 *   TC_SHARE = message containing threshold crypto share for collecting
 *   BENCHMARK = message to measure latency
 *   TC_SHARE_SMENCRYPT = message containing threshold crypto share for collecting (MK added)
 *   TC_FINAL_EMENCRYPT = message containing threshold crypto final for collecting (MK added)
 *   CHECKPOINT = message containing a Checkpoint
 *   CREATE_CHECKPOINT = message that is used to request a new checkpoint from SCADA Master  
 */
enum message_type {DUMMY, RTU_DATA, RTU_FEEDBACK, HMI_UPDATE, HMI_COMMAND, 
                    TC_SHARE, TC_FINAL, STATE_REQUEST, STATE_XFER, SYSTEM_RESET, 
                    BENCHMARK, TC_SHARE_SMENCRYPT, TC_FINAL_SMENCRYPT,
                    CREATE_CHECKPOINT, CHECKPOINT, UPDATE_TRANSFER};

/*
 * Protocols:
 *      MODBUS
 *      DNP3
 */
#define NUM_PROTOCOLS 2
enum protocol{MODBUS, DNP3};


/*
 * Type of variables used in Modbus TCP:
 *   INPUT_REGISTERS = 16-bit word, read-only
 *   HOLDING_REGISTERS = 16-bit word, read-write
 *   INPUT_STATUS = 1 bit, read-only
 *   COIL_STATUS = 1 bit, read-write
 */
enum modbus_var_type {INPUT_REGISTERS, HOLDING_REGISTERS, INPUT_STATUS, COIL_STATUS};

/*
 * Type of variables used in DNP3:
 *   CROB = control output relay block
 */
enum dnp3_var_type {CROB, AO16, AO32, AOF32, AOD64};

enum crob_type{LATCH_ON, LATCH_OFF, PULSE_ON, PULSE_OFF};

/* 
 * Scenarios:
 *      JHU (power grid distribution)
 *      PNNL (power breakers)
 *      EMS (energy management system)
 */
#define JHU 1
#define PNNL 2
#define EMS 3

/*
 * Type of equipment inside of substations
 */
enum substation_type {SWITCH, TRANSFORMER, BREAKER, BREAKER_FLIP, BREAKER_ON, BREAKER_OFF};

/* Definition of these structs that are used
 * in both packets and data structures */
typedef struct seq_pair_d {
    int32u incarnation;
    int32u seq_num;
} seq_pair;

typedef struct ordinal_d {
    int32u ord_num;
    int32u event_idx;
    int32u event_tot;
} ordinal;

typedef struct update_history_d {
    char buff[UPDATE_SIZE];
    ordinal ord; 
} update_history;

typedef struct sm_state_d {
    int32u client;
    int32u num_fields;
    // The data contents follow
} sm_state;

/****************************************************************/
/*                  PRIME CLIENT MESSAGE FORMAT                 */
/****************************************************************/

/* signed_message is a header for SCADA and Prime messages */
typedef struct dummy_signed_message {
    unsigned char sig[SIGNATURE_SIZE];
    uint16_t mt_num;
    uint16_t mt_index;

    int32u site_id; //MK: we don't use this anymore probably, we can repurpose this for TC
    int32u machine_id; 

    int32u len;        /* length of the content */
    int32u type;       /* type of the message */

    int32u incarnation;
    int32u monotonic_counter;
    int32u global_configuration_number; /*MS2022:  Global configuration number to differntiate configurations*/

    /* Content of message follows */
} signed_message;

/* Update content. Note that an update message has almost the same
 * structure as a signed message. It has an additional content
 * structure that contains the time stamp. Therefore, an update
 * message is actually a signed_message with content of update_content
 * and the actual update data */
typedef struct dummy_update_message {
    int32u server_id;
    int32_t address;
    uint16_t port;
    //seq_pair seq;
    int32u seq_num;
    /* the update content follows */
} update_message;

typedef struct dummy_signed_update_message {
    signed_message header;
    update_message update;
    char update_contents[UPDATE_SIZE];
} signed_update_message;

// MK TODO: Simple Encryption
// typedef struct dummy_signed_update_message_simple_encryption {
//     signed_message header;
//     update_message update;
//     unsigned char update_contents[UPDATE_SIZE * NUM_CC];
// } signed_update_message_simple_encryption;


typedef struct dummy_client_response_message {
    int32u machine_id;
    seq_pair seq;
    int32u ord_num;
    int32u event_idx;
    int32u event_tot;
    double PO_time;
    
    /* the update content follows */
} client_response_message;

/****************************************************************/
/*              SCADA SYSTEM MESSAGE DEFINITIONS                */
/****************************************************************/
#define RTU_DATA_PAYLOAD_LEN 64
#define PNNL_DATA_PADDING 4
#define PNNL_RTU_ID 10
#define EMS_DATA_PADDING 44
#define EMS_TARGET_SET 0 // Message type for the RTU Feedback Msg
#define EMS_RTU_ID_BASE 11

/* JHU-specific RTU Data struct */
typedef struct jhu_fields_d {
    int32_t tx_status;
    int32_t sw_status[MAX_SWITCHES];
    int32u  padd1;
    int32u  padd2;
    int32u  padd3;
    int32u  padd4;
    int32u  padd5;
} jhu_fields;

/* PNNL-specific RTU Data struct */
typedef struct pnnl_fields_d {
    int32u padd1;
    int32u point[NUM_POINT];
    unsigned char breaker_read[NUM_BREAKER];
    unsigned char breaker_write[NUM_BREAKER];
} pnnl_fields;

/* EMS-specific RTU Data struct */
typedef struct ems_fields_d {
    int32u id;
    int32u status;
    int32u max_generation;
    int32u curr_generation;
    int32u target_generation;
    int32u padd1[EMS_DATA_PADDING / sizeof(int32u)];
} ems_fields;

/* RTU Data Message */
//TODO: change sub_id to rtu_id
typedef struct dummy_rtu_data_msg {
    seq_pair seq;         // incarnation + seq_num
    int32u rtu_id;        // RTU ID
    // Do not re-arrange order above 
    int32u scen_type;     // Scenario Type: JHU or PNNL
    int32u sec;
    int32u usec;
    unsigned char data[RTU_DATA_PAYLOAD_LEN];
    //int32_t tx_status;    // tx status
    //int32_t sw_status[MAX_SWITCHES]; // sw status 
} rtu_data_msg;

/* RTU Feedback Message */
typedef struct dummy_rtu_feedback_msg {
    seq_pair seq;
    // Do not re-arrange order above 
    //int32u hmi_id;
    int32u scen_type;
    int32u type; //switch or transformer (use substation_type enum)
    //int32u last_seq;
    //TODO: get rid of sub
    int32u sub;
    int32u rtu;
    int32u offset;
    int32_t val;
} rtu_feedback_msg;

/* HMI Update Message */
typedef struct dummy_hmi_update_msg {
    seq_pair seq;
    // Do not re-arrange order above 
    //int32u rtu_orig;
    //int32u last_seq;
    int32u scen_type;
    int32u sec;
    int32u usec;
    int32u len;     //length of status array 
} hmi_update_msg;

/* HMI Command Message */
typedef struct dummy_hmi_command_msg {
    seq_pair seq;
    int32u hmi_id;
    // Do not re-arrange order above 
    int32u scen_type;
    int32_t type;     //0 for switch, 1 for tx
    int32_t ttip_pos; //location in ttip arr
} hmi_command_msg;

/* Threshold Crypto Share Message */
typedef struct dummy_tc_share_msg {
    ordinal ord;
    char payload[MAX_PAYLOAD_SIZE];
    unsigned char partial_sig[SIGNATURE_SIZE];
} tc_share_msg;

typedef struct dummy_tc_final_msg {
    ordinal ord;
    char payload[MAX_PAYLOAD_SIZE];
    unsigned char thresh_sig[SIGNATURE_SIZE];
} tc_final_msg;

/* Threshold Crypto Share Message for SM Encryption */
typedef struct dummy_tc_share_msg_smencrypt {
    seq_pair seq;         // incarnation + seq_num
    int32u client_id;        // RTU/HMI/etc ID
    char payload[MAX_PAYLOAD_SIZE]; // MK TODO: Simple Encryption (need to increase size here)
    unsigned char partial_sig[SIGNATURE_SIZE];
} tc_share_msg_smencrypt;

/* Threshold Crypto Final Message for SM Encryption */
typedef struct dummy_tc_final_msg_smencrypt {
    seq_pair seq;         // incarnation + seq_num
    int32u client_id;
    char payload[MAX_PAYLOAD_SIZE];
    unsigned char thresh_sig[SIGNATURE_SIZE];
} tc_final_msg_smencrypt;

typedef struct dummy_state_request_msg {
    int32u target;
    seq_pair latest_update[MAX_EMU_RTU + NUM_HMI + 1];
} state_request_msg;

/* MK: message struct to hold chekpoint metadata */
// MK TODO: separate encrypted stuff from unencrypted stuff

//#define CHECKPOINT_PAYLOAD_SIZE (MAX_LEN - sizeof(signed_message) - 2*sizeof(int32u) - sizeof(ordinal) - (MAX_EMU_RTU + NUM_HMI + 1) * sizeof(seq_pair))
#define CHECKPOINT_PAYLOAD_SIZE 512

typedef struct dummy_checkpoint_msg {
    ordinal ord;
    seq_pair latest_update[MAX_EMU_RTU + NUM_HMI + 1];
    int32u num_clients;
    int32u state_size;
    char payload[CHECKPOINT_PAYLOAD_SIZE];  // total size of checkpoint
} checkpoint_msg;

/* MK: message struct to hold update data */
typedef struct dummy_update_transfer_msg {
    ordinal ord;
    char payload[MAX_PAYLOAD_SIZE];  // total size of an update
} update_transfer_msg;

// checkpoint_transfer_msg

typedef struct dummy_state_xfer_msg {
    ordinal ord;
    int32u target;
    seq_pair latest_update[MAX_EMU_RTU + NUM_HMI + 1];
    int32u num_clients;
    int32u state_size;  // total size of state
    // state contents follows after this
} state_xfer_msg;

/* Benchmark Message for Latency */
typedef struct dummy_benchmark_msg_d {
    seq_pair seq;
    int32_t  sender;
    int32u ping_sec;
    int32u ping_usec;
    int32u pong_sec;
    int32u pong_usec;
} benchmark_msg;

/*******************************************************
 *      DATA STRUCTS - Putting Here For Now            *
*******************************************************/
#define MAX_SHARES (3*NUM_F + 2*NUM_K + 1)
#define REQ_SHARES (NUM_F + 1)

typedef struct itrc_data_d {
    char ipc_local[100];
    char ipc_remote[100];
    char prime_keys_dir[100];
    char sm_keys_dir[100];
    char spines_int_addr[32];
    int spines_int_port;
    char spines_ext_addr[32];
    int spines_ext_port;
} itrc_data;

typedef struct net_sock_d {
    int sp_int_s;
    int sp_ext_s;
    int ipc_s;
    char ipc_remote[100];
    int inject_s;
    char inject_path[100];
} net_sock;

typedef struct itrc_queue_node_d {
    int32u seq_num;
    char buf[MAX_LEN];
    int len;
    struct itrc_queue_node_d *next;
} itrc_queue_node;

typedef struct itrc_queue_d {
    itrc_queue_node head;
    itrc_queue_node *tail;
} itrc_queue;

typedef struct tc_node_d {
    ordinal ord;
    int32u done;
    int32u count;
    char recvd[MAX_SHARES + 1];
    tc_share_msg shares[MAX_SHARES + 1];
    struct tc_node_d *next;
    signed_message *tcf;
    char skip;
} tc_node;

typedef struct tc_queue_d {
    tc_node head;
    tc_node *tail;
    int32u size;
} tc_queue;

// MK: Needed for SM Encrypt
typedef struct tc_node_d_smencrypt {
    seq_pair seq;
    int32u done;
    int32u count;
    char recvd[MAX_SHARES + 1];
    tc_share_msg_smencrypt shares[MAX_SHARES + 1];
    struct tc_node_d_smencrypt *next;
    signed_message *tcf;
} tc_node_smencrypt;

// MK: Needed for SM Encrypt
typedef struct tc_queue_d_smencrypt {
    tc_node_smencrypt head;
    tc_node_smencrypt *tail;
    int32u size;
} tc_queue_smencrypt;

// MK: Needed for Checkpoint
typedef struct checkpoint_node_d {
    ordinal ord;
    int32u correct;
    int32u stable;
    int32u count;
    char recvd[NUM_SM + 1];
    char checkpoint_messages[NUM_SM + 1][sizeof(signed_message)+sizeof(checkpoint_msg)];
    struct checkpoint_node_d *next;
    char results[sizeof(signed_message)+sizeof(checkpoint_msg)];
} checkpoint_node;

// MK: Needed for Checkpointing
typedef struct checkpoint_queue_d {
    checkpoint_node head;
    checkpoint_node *tail;
    int32u size;
} checkpoint_queue;

// MK: Needed for Updates Queing
typedef struct update_node_d {
    ordinal ord;
    char payload[MAX_PAYLOAD_SIZE];
    struct update_node_d *next;
} update_node;

// MK: Needed for Updates Queing
typedef struct updates_queue_d {
    update_node head;
    update_node *tail;
    int32u size;
} updates_queue;

// MK: Needed for Checkpoint
typedef struct update_transfer_node_d {
    ordinal ord;
    int32u correct;
    int32u count;
    char recvd[NUM_SM + 1];
    update_transfer_msg update_transfer_messages[NUM_SM + 1];
    struct update_transfer_node_d *next;
    update_transfer_msg *result;
} update_transfer_node;

// MK: Needed for Checkpointing
typedef struct update_transfer_queue_d {
    update_transfer_node head;
    update_transfer_node *tail;
    int32u size;
} update_transfer_queue;

typedef struct st_node_d {
    ordinal ord;
    int32u collected;
    int32u count;
    int32u signaled;
    char recvd[MAX_SHARES + 1];
    char state[MAX_SHARES + 1][MAX_LEN];
    state_xfer_msg *result;
    struct st_node_d *next;
} st_node;

typedef struct st_queue_d {
    st_node head;
    st_node *tail;
    int32u size;
} st_queue;


signed_message *PKT_Construct_Signed_Message(int size);
signed_message *PKT_Construct_RTU_Data_Msg(rtu_data_msg* r);
/* signed_message *PKT_Construct_RTU_Data_Msg(seq_pair seq, int32u rtu_id, 
                                           int num_switches, int32_t *sw_status, 
                                           int32_t tx_status); */
signed_message *PKT_Construct_RTU_Feedback_Msg(seq_pair seq, int32u scen_type,
                                               int32u type, int32u sub, 
                                               int32u rtu, int32u offset, 
                                               int32_t val);
signed_message *PKT_Construct_HMI_Update_Msg(seq_pair seq, int32u scen_type, int32u size, 
                                             char *status, int32u sec, int32u usec);
signed_message *PKT_Construct_HMI_Command_Msg(seq_pair seq, int32u hmi_id,
                                              int32u scen_type, int32_t type, 
                                              int32_t ttip_pos);
signed_message *PKT_Construct_TC_Share_Msg(ordinal o, char *payload, int32u len);
signed_message *PKT_Construct_TC_Final_Msg(ordinal o, tc_node *tcn);
signed_message *PKT_Construct_TC_Share_Msg_SMEncrypt(seq_pair *ps, int32u* idx, char *payload, int32u len);
signed_message *PKT_Construct_TC_Final_Msg_SMEncrypt(seq_pair seq, int32u client_id, tc_node_smencrypt *tcn, int32u sender);
signed_message *PKT_Construct_Create_Checkpoint_Msg(ordinal o, seq_pair *latest);
signed_message *PKT_Construct_Checkpoint_Msg(ordinal o, int32u num_clients, 
                                                seq_pair *latest_update,
                                                char *state, int32u state_size);
signed_message *PKT_Construct_State_Xfer_Msg(int32u targ, int32u num_clients, 
                                             seq_pair *latest, char *state, 
                                             int32u state_size);
signed_message *PKT_Construct_Benchmark_Msg(seq_pair seq);
int Var_Type_To_Int(char[]);
char* Var_Type_To_String(int);
int Seq_Pair_Compare(seq_pair p1, seq_pair p2);
void Print_State(ordinal o, update_history *uh);

#endif /* SCADA_PACKETS_H */
