#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "packets.h"
#include "ss_openssl_rsa.h"
#include "ss_tc_wrapper.h"

tm_msg *PKT_Construct_TM_Message(uint32_t type, uint32_t id, uint64_t dts, uint32_t size)
{
    tm_msg *mess;
  
    mess = (tm_msg *)malloc(sizeof(tm_msg) + size);
    memset(mess, 0, sizeof(tm_msg) + size);

    mess->type = type;
    mess->m_id = id;
    mess->dts = dts;
    mess->len = size;

    return mess;
}


/* Takes a tm_msg with an empty (or previously filled tc_share payload) and refills it based on the headers */
tm_msg *PKT_Construct_TC_Share_Msg_Payload(tm_msg* mess, uint64_t prev_dts)
{
    ss_tc_share_msg *tc_mess;
    tc_payload payload;

    byte digest[DIGEST_SIZE];
    
    int state;
    int i;
    int start = 0;

    assert(mess->type == CLOSE_SHARE || mess->type == TRIP_SHARE);
    assert(mess->len == sizeof(ss_tc_share_msg));

    if (mess->type == CLOSE_SHARE) {
        state = STATE_CLOSE;
    } else {
        state = STATE_TRIP;
    }

    tc_mess = (ss_tc_share_msg *)(mess + 1);
    
    /* If this we previously sent a message, we can reuse the last n - 1 shares */
    if (prev_dts != 0) {
        assert(mess->dts == prev_dts + DTS_INTERVAL);

        for (i = 1; i < SHARES_PER_MSG; i++) {
            memcpy(&tc_mess->shares[i - 1], &tc_mess->shares[i], sizeof(tc_share_single));
        }

        start = SHARES_PER_MSG - 1;
    }

    /* Create all the new shares */
    memset(&payload, 0, sizeof(payload));
    payload.state = state;
    for (i = start; i < SHARES_PER_MSG; i++) {
        payload.dts = mess->dts + (i * DTS_INTERVAL);

        OPENSSL_RSA_Make_Digest(&payload, sizeof(tc_payload), digest);

        memset(tc_mess->shares[i].share, 0, SIGNATURE_SIZE);
        memset(tc_mess->shares[i].proof, 0, PROOF_SIZE);

        TC_Generate_Sig_Share(tc_mess->shares[i].share, tc_mess->shares[i].proof, digest);
    }

    return mess;
}
