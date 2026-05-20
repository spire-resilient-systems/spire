#ifndef PACKETS_H
#define PACKETS_H

#include <stdbool.h>
#include <stdint.h>

#include "def.h"
#include "ss_tc_wrapper.h"
#include "ss_openssl_rsa.h"

#define STATE_CLOSE    0
#define STATE_TRIP     1

#define SHARES_PER_MSG 2

/* All message types */

#define    SV_SIMPLE 301
#define    SV_BYZ 302
#define    LR_CLOSE 303
#define    LR_TRIP 304

#define    TRIP_SHARE 305
#define    CLOSE_SHARE 306
#define    SIGNED_TRIP 307
#define    SIGNED_CLOSE 308
#define    SIGNED_TRIP_ACK 309
#define    SIGNED_CLOSE_ACK 310
#define    RELAY_TRIP 311
#define    RELAY_CLOSE 312

#define    RECOVERY_QUERY 313

#define    PING 316
#define    PONG 317
#define    PP_START 318

#define    CC_CMD 314
#define    SS_CMD 315

/* Sample values message (from emulator (gen_event.c) to relay (goose_publisher) */
typedef struct dummy_sv_msg {
    uint32_t type;
    uint64_t ss_id;
    uint64_t time_ms;
    uint64_t delay_ms[NUM_REPLICAS];
    int trip[NUM_REPLICAS];
} sv_msg;



/* Local relay messages, published by relay proxy */
typedef struct local_relay_msg {
    uint32_t type;
    uint64_t dts;
    // TODO Other payloads for GOOSE?
} local_relay_msg;


/* TM protocol messages */

/* TODO No need to sign this because spines signs it already? */
/* Or do we need to pass these messages around for non-repudation? */
typedef struct dummy_tm_msg {
    uint32_t type;              /* type of the message */
    uint32_t m_id;              /* id of sender */ 
    uint64_t dts;               /* discretized timestamp of message */
    uint32_t len;               /* length of the content */

    /* Content of message follows */
} tm_msg;

// Internal to TMs only, used to generate signatures/shares
typedef struct dummy_tc_payload {
    uint32_t state;
    uint64_t dts;
} tc_payload; 

typedef struct dummy_tc_share_single {
    unsigned char share[SIGNATURE_SIZE];
    unsigned char proof[PROOF_SIZE];
} tc_share_single;


typedef struct dummy_ss_tc_share_msg {
    tc_share_single shares[SHARES_PER_MSG];
} ss_tc_share_msg;

typedef struct dummy_ss_tc_final_msg {
    unsigned char thresh_sig[SIGNATURE_SIZE];
} ss_tc_final_msg;

typedef struct dummy_pp_payload {
    uint32_t seq;
}pp_payload;


typedef struct dummy_sig_payload {
    unsigned char sig[SIGNATURE_SIZE];
}sig_payload;

/* Helper methods to construct packets */
tm_msg *PKT_Construct_TM_Message(uint32_t type, uint32_t id, uint64_t dts, uint32_t size);
tm_msg *PKT_Construct_TC_Share_Msg_Payload(tm_msg* mess, uint64_t cur_dts);
#endif
