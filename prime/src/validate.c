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

/* Message validation functions. These functions check to make sure messages
 * came from the server or site that should have sent them and check to make
 * sure that the lengths are correct. */

#include "spu_alarm.h"
#include "validate.h"
#include "data_structs.h"
#include "order.h"
#include "error_wrapper.h"
#include "merkle.h"
#include "openssl_rsa.h"
#include "utility.h"
#include "packets.h"
#include "tc_wrapper.h"

extern server_variables   VAR;
extern server_data_struct DATA;

int32u VAL_Validate_Signed_Message(signed_message *mess, int32u num_bytes, 
				   int32u verify_signature); 
int32u VAL_Signature_Type         (int32u message_type, int32u sender_id); 
int32u VAL_Validate_Sender        (int32u sig_type, int32u sender_id); 
int32u VAL_Is_Valid_Signature     (int32u sig_type, int32u sender_id, 
				   int32u site_id, signed_message *mess);

int32u VAL_Validate_Update      (update_message *update, int32u num_bytes); 
int32u VAL_Validate_PO_Request  (po_request_message *po_request, int32u num_bytes);
int32u VAL_Validate_PO_Ack      (po_ack_message *po_ack, int32u num_bytes);
int32u VAL_Validate_PO_ARU      (po_aru_message *po_aru, int32u num_bytes);
int32u VAL_Validate_Proof_Matrix(proof_matrix_message *pm, int32u num_bytes);
int32u VAL_Validate_Pre_Prepare (pre_prepare_message *pp, int32u num_bytes);
int32u VAL_Validate_Prepare     (prepare_message *prepare, int32u num_bytes);
int32u VAL_Validate_Commit      (commit_message *commit, int32u num_bytes);

int32u VAL_Validate_TAT_Measure (tat_measure_message *measure, int32u num_bytes);
int32u VAL_Validate_RTT_Ping    (rtt_ping_message *ping, int32u num_bytes);
int32u VAL_Validate_RTT_Pong    (rtt_pong_message *pong, int32u num_bytes);
int32u VAL_Validate_RTT_Measure (rtt_measure_message *measure, int32u num_bytes);
int32u VAL_Validate_TAT_UB      (tat_ub_message *ub, int32u num_bytes);
int32u VAL_Validate_New_Leader  (new_leader_message *nl, int32u num_bytes);
int32u VAL_Validate_New_Leader_Proof(new_leader_proof_message *nlp, int32u num_bytes);

int32u VAL_Validate_RB_Init     (signed_message *rb_init, int32u num_bytes);
int32u VAL_Validate_RB_Echo     (signed_message *rb_echo, int32u num_bytes);
int32u VAL_Validate_RB_Ready    (signed_message *rb_ready, int32u num_bytes);

int32u VAL_Validate_Report      (report_message *report, int32u num_bytes);
int32u VAL_Validate_PC_Set      (pc_set_message *pc_set, int32u num_bytes);
int32u VAL_Validate_VC_List     (vc_list_message *vc_list, int32u num_bytes);
int32u VAL_Validate_VC_Partial_Sig(vc_partial_sig_message *vc_psig, int32u num_bytes);
int32u VAL_Validate_VC_Proof    (vc_proof_message *vc_proof, int32u num_bytes);
int32u VAL_Validate_Replay      (replay_message *replay, int32u num_bytes);
int32u VAL_Validate_Replay_Prepare(replay_prepare_message *r_prepare, int32u num_bytes);
int32u VAL_Validate_Replay_Commit(replay_commit_message *r_commit, int32u num_bytes);

int32u VAL_Validate_Catchup_Request(catchup_request_message *c_request, int32u num_bytes);
int32u VAL_Validate_ORD_Certificate(ord_certificate_message *ord_cert, int32u num_bytes);
int32u VAL_Validate_PO_Certificate(po_certificate_message *po_cert, int32u num_bytes);
//int32u VAL_Validate_Catchup_Reply  (catchup_reply_message *c_reply, int32u num_bytes);

/* Determine if a message from the network is valid. */
int32u VAL_Validate_Message(signed_message *message, int32u num_bytes) 
{
  byte *content;
  int32u num_content_bytes;

  /* Since we use Merkle trees, all messages except client updates
   * need to be Merkle-tree verified. */

  /* This is a signed message */
  if (!VAL_Validate_Signed_Message(message, num_bytes, 1)) {
    Alarm(PRINT, "Validate signed message failed.\n");
    VALIDATE_FAILURE_LOG(message,num_bytes);
    return 0;
  }
  
  content = (byte*)(message + 1);
  num_content_bytes = num_bytes - sizeof(signed_message) - MT_Digests_(message->mt_num) * DIGEST_SIZE; /* always >= 0, since checked in Validate_Signed_Message */

  switch (message->type) {

  case UPDATE:
    if((!VAL_Validate_Update((update_message *)(content), num_content_bytes))){
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case PO_REQUEST:
    if((!VAL_Validate_PO_Request((po_request_message *)content,
				 num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
    
  case PO_ACK:
    if((!VAL_Validate_PO_Ack((po_ack_message *)content,
			     num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case PO_ARU:
    if((!VAL_Validate_PO_ARU((po_aru_message *)content,
			     num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case PROOF_MATRIX:
    if((!VAL_Validate_Proof_Matrix((proof_matrix_message *)content,
				   num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
    
  case PRE_PREPARE:
    if((!VAL_Validate_Pre_Prepare((pre_prepare_message *)content,
				  num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case PREPARE:
    if((!VAL_Validate_Prepare((prepare_message *)content,
			      num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
    
  case COMMIT:
    if((!VAL_Validate_Commit((commit_message *)content,
			     num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case TAT_MEASURE:
    if((!VAL_Validate_TAT_Measure((tat_measure_message *)content,
                 num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RTT_PING:
    if((!VAL_Validate_RTT_Ping((rtt_ping_message *)content,
                 num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RTT_PONG:
    if((!VAL_Validate_RTT_Pong((rtt_pong_message *)content,
                 num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RTT_MEASURE:
    if((!VAL_Validate_RTT_Measure((rtt_measure_message *)content,
                 num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case TAT_UB:
    if((!VAL_Validate_TAT_UB((tat_ub_message *)content,
                 num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case NEW_LEADER:
    if((!VAL_Validate_New_Leader((new_leader_message *)content,
                 num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case NEW_LEADER_PROOF:
    if((!VAL_Validate_New_Leader_Proof((new_leader_proof_message *)content,
                 num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RB_INIT:
    if((!VAL_Validate_RB_Init((signed_message *)content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RB_ECHO:
    if((!VAL_Validate_RB_Echo((signed_message *)content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RB_READY:
    if((!VAL_Validate_RB_Ready((signed_message *)content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case REPORT:
    if((!VAL_Validate_Report((report_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
  
  case PC_SET:
    if((!VAL_Validate_PC_Set((pc_set_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
  
  case VC_LIST:
    if((!VAL_Validate_VC_List((vc_list_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
  
  case VC_PARTIAL_SIG:
    if((!VAL_Validate_VC_Partial_Sig((vc_partial_sig_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
  
  case VC_PROOF:
    if((!VAL_Validate_VC_Proof((vc_proof_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
  
  case REPLAY:
    if((!VAL_Validate_Replay((replay_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
  
  case REPLAY_PREPARE:
    if((!VAL_Validate_Replay_Prepare((replay_prepare_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
  
  case REPLAY_COMMIT:
    if((!VAL_Validate_Replay_Commit((replay_commit_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
  
  case CATCHUP_REQUEST:
    if((!VAL_Validate_Catchup_Request((catchup_request_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case ORD_CERT:
    if((!VAL_Validate_ORD_Certificate((ord_certificate_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case PO_CERT:
    if((!VAL_Validate_PO_Certificate((po_certificate_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  /* case CATCHUP_REPLY:
    if((!VAL_Validate_Catchup_Reply((catchup_reply_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break; */

  default:
    Alarm(DEBUG, "Not yet checking message type %d!\n", message->type);
  }
  
  return 1;
}

/* Determine if a signed message is valid. */
int32u VAL_Validate_Signed_Message(signed_message *mess, int32u num_bytes, 
				   int32u verify_signature) 
{
  int32u sig_type;
  int32u sender_id;

  /* Validate minimum message size */
  if (num_bytes < (sizeof(signed_message))) {
    VALIDATE_FAILURE("Num bytes < sizeof(signed_message)");
    return 0;
  }

  /* Validate message type */
  if (mess->type == DUMMY || mess->type >= MAX_MESS_TYPE) {
    VALIDATE_FAILURE("Undefined message type");
    return 0;
  }

  /* Validate total message size (including merkle digests */
  if (mess->mt_num > 256 || mess->mt_index > mess->mt_num) {
      VALIDATE_FAILURE("Merkle tree values set incorrectly");
      return 0;
  }
  if (num_bytes != mess->len + sizeof(signed_message) +
      (MT_Digests_(mess->mt_num) * DIGEST_SIZE)) {
    Alarm(PRINT, "num_bytes = %d, signed_message = %d, mess->len = %d, "
                 "digests = %d\n", num_bytes, sizeof(signed_message),
                 mess->len, MT_Digests_(mess->mt_num));
    VALIDATE_FAILURE("num_bytes != mess->len + sizeof(signed_message)");
    return 0;
  }
  if (num_bytes > PRIME_MAX_PACKET_SIZE) {
    VALIDATE_FAILURE("Message length too long");
    return 0;
  }

  /* Should validate site_id too? */
 
  /* Validate sender and signature */
  sig_type = VAL_Signature_Type( mess->type, mess->machine_id );
  if (sig_type == VAL_TYPE_INVALID) {
    VALIDATE_FAILURE("Sig Type invalid");
    return 0;
  } else if(sig_type == VAL_SIG_TYPE_UNSIGNED) {
    return 1;
  } else if (sig_type == VAL_SIG_TYPE_SERVER || 
             sig_type == VAL_SIG_TYPE_MERKLE ||
             sig_type == VAL_SIG_TYPE_CLIENT) {
    sender_id = mess->machine_id;
  } else {
    /* threshold signed */
    /* AB: I don't think this can happen? */
    sender_id = mess->site_id;
  }
  
  if (!VAL_Validate_Sender(sig_type, sender_id)) {
    VALIDATE_FAILURE("Invalid sender");
    return 0;
  }

  if (verify_signature && !VAL_Is_Valid_Signature(sig_type, sender_id, mess->site_id, mess)) {
    VALIDATE_FAILURE("Invalid signature");
    return 0;
  }

  return 1; /* Passed all checks */
}

/* Determine if the message type is valid and if so return which type of
 * signature is on the message, a client signature, a server signature, or a
 * threshold signature. 
 * 
 * returns: VAL_SIG_TYPE_SERVER, VAL_SIG_TYPE_CLIENT, VAL_SIG_TYPE_SITE, or
 * VAL_TYPE_INVALID */
int32u VAL_Signature_Type(int32u message_type, int32u sender_id) 
{
  int sig_type = VAL_TYPE_INVALID;
  
  /* Return the type of the signature based on the type of the message. If
   * the type is not found, then return TYPE_INVALID */

  switch(message_type) {

  case UPDATE:
    if (sender_id >= 1 && sender_id <= NUM_SERVERS)
      sig_type = VAL_SIG_TYPE_SERVER;
    else
      sig_type = VAL_SIG_TYPE_CLIENT;
    break;
  
  case PO_ARU:
  case NEW_LEADER:
  case REPORT:
  case PC_SET:
    sig_type = VAL_SIG_TYPE_SERVER;
    break;

  case PO_REQUEST:
  case PO_ACK:
  case PROOF_MATRIX:
  case RECON:
  case PRE_PREPARE:
  case PREPARE:
  case COMMIT:
  case RTT_PING:
  case RTT_PONG:
  case RTT_MEASURE:
  case TAT_MEASURE:
  case TAT_UB:
  case NEW_LEADER_PROOF:
  case RB_INIT:
  case RB_ECHO:
  case RB_READY:
  case VC_LIST:
  case VC_PARTIAL_SIG:
  case VC_PROOF:
  case REPLAY:
  case REPLAY_PREPARE:
  case REPLAY_COMMIT:
  case CATCHUP_REQUEST:
  case ORD_CERT:
  case PO_CERT:
  //case CATCHUP_REPLY:
    sig_type = VAL_SIG_TYPE_MERKLE;
    break;
  }

  return sig_type;
} 

/* Determine if the sender is valid depending on the specified signature type.
 * 
 * return: 1 if sender is valid, 0 if sender is not valid */
int32u VAL_Validate_Sender(int32u sig_type, int32u sender_id) 
{
  if (sender_id < 1) 
    return 0;

  if ((sig_type == VAL_SIG_TYPE_SERVER || sig_type == VAL_SIG_TYPE_MERKLE)
      && sender_id <= NUM_SERVERS) {
    return 1;
  } 
    
  if (sig_type == VAL_SIG_TYPE_CLIENT &&
      sender_id <= NUM_CLIENTS) {
    return 1;
  }	

  return 0;
}

/* Determine if the signature is valid. Assume that the lengths of the message
 * is okay. */
int32u VAL_Is_Valid_Signature(int32u sig_type, int32u sender_id, 
			      int32u site_id, signed_message *mess) 
{
  int32 ret;
 
  if (sig_type == VAL_SIG_TYPE_MERKLE) {
    ret = MT_Verify(mess);
    if(ret == 0) {
        Alarm(PRINT, "MT_Verify returned 0 on message from machine %d type %d "
                     "len %d, total len %d\n", mess->machine_id, mess->type, 
                     mess->len, UTIL_Message_Size(mess));
      }
    return ret;
  }

  if (sig_type == VAL_SIG_TYPE_SERVER) {
    /* Check an RSA signature using openssl. A server sent the message. */
    ret = 
      OPENSSL_RSA_Verify( 
			 ((byte*)mess) + SIGNATURE_SIZE,
			 mess->len + sizeof(signed_message) - SIGNATURE_SIZE,
			 (byte*)mess, 
			 sender_id,
			 RSA_SERVER
			 );
    if (ret == 0) 
      Alarm(PRINT,"  Sig Server Failed %d %d\n",
	    mess->type, mess->machine_id);
    return ret; 
  }
   
  if (sig_type == VAL_SIG_TYPE_CLIENT) {
    if (CLIENTS_SIGN_UPDATES == 0) {
        return 1;
    }

    /* Check an RSA signature using openssl. A client sent the message. */
    ret = 
      OPENSSL_RSA_Verify( 
			 ((byte*)mess) + SIGNATURE_SIZE,
			 mess->len + sizeof(signed_message) - SIGNATURE_SIZE,
			 (byte*)mess, 
			 sender_id,
			 RSA_CLIENT
			 );
    if (ret == 0) 
      Alarm(PRINT,"  Sig Client Failed %d\n", mess->type);
    return ret; 
  }
  
  return 0;
}

/* Determine if an update is valid */
int32u VAL_Validate_Update(update_message *update, int32u num_bytes) 
{
  
  /* Check to determine if the update is valid. We have already checked to
   * see if the signature verified. We only need to make sure that the packet
   * is large enough for the timestamp. */
  
  if (num_bytes < sizeof(update_message)) {
    VALIDATE_FAILURE("Update too small");
    return 0;
  }

  if (num_bytes > sizeof(update_message) + UPDATE_SIZE) {
    VALIDATE_FAILURE("Update too large");
    return 0;
  }
  
  return 1;
}

int32u VAL_Validate_PO_Request(po_request_message *po_request, int32u num_bytes)
{
  signed_message *mess;
  char *p;
  int32u i;
  int32u offset;

  if (num_bytes < (sizeof(po_request_message))) {
    VALIDATE_FAILURE("Local PO-Request bad size");
    return 0;
  }
  
  /* This is the start of the events contained in the PO-Request */
  p = (char *)(po_request + 1);
  offset = sizeof(po_request_message);

  for(i = 0; i < po_request->num_events; i++) {
    mess = (signed_message *)p;
    /* Check that there is enough space in the po-request for this update */
    if (offset > num_bytes - sizeof(signed_message)) {
      VALIDATE_FAILURE("PO_Request malformed (not enough space for update)");
      return 0;
    }
    if (offset > num_bytes - sizeof(signed_message) - mess->len) {
      VALIDATE_FAILURE("PO_Request malformed (not enough space for update)");
      return 0;
    }

    if(mess->type != UPDATE ||
       !VAL_Validate_Message(mess, mess->len + sizeof(signed_message))) {
      Alarm(PRINT, "Event %d of PO-Request invalid\n", i);
      VALIDATE_FAILURE("Invalid update in PO-Request");
      return 0;
    }
    else {
      p += mess->len + sizeof(signed_message);
      offset += mess->len + sizeof(signed_message);
    }
  }

  if (offset != num_bytes) {
    VALIDATE_FAILURE("PO_Request message length incorrect");
    return 0;
  }
  
  return 1;
} 

int32u VAL_Validate_PO_Ack(po_ack_message *po_ack, int32u num_bytes)
{
  int32u expected_num_bytes;
  po_ack_part *part;
  int32u p;

  if(num_bytes < sizeof(po_ack_message)) {
    VALIDATE_FAILURE("PO-Ack wrong size");
    return 0;
  }

  expected_num_bytes = (sizeof(po_ack_message) +
			(po_ack->num_ack_parts * sizeof (po_ack_part)));

  if(num_bytes != expected_num_bytes) {
    VALIDATE_FAILURE("PO-Ack wrong expected bytes.");
    return 0;
  }

  /* Iterate over each ack part in the aggregate PO-Ack, and sanity check it */
  part = (po_ack_part *)(po_ack+1);
  for (p = 0; p < po_ack->num_ack_parts; p++) {
    if (part[p].seq.seq_num == 0) {
      VALIDATE_FAILURE("Invalid PO-Ack part seq_num");
      return 0;
    }
    if (part[p].originator < 1 || part[p].originator > NUM_SERVERS) {
      VALIDATE_FAILURE("Invalid PO-Ack part originator");
      return 0;
    }
  }

  return 1;
}

int32u VAL_Validate_PO_ARU(po_aru_message *po_aru, int32u num_bytes)
{
  if (num_bytes != (sizeof(po_aru_message))) {
    VALIDATE_FAILURE("PO_ARU bad size");
    return 0;
  }

  return 1;
}

int32u VAL_Validate_Proof_Matrix(proof_matrix_message *pm, int32u num_bytes)
{
  int32u expected_size;
  po_aru_signed_message *po_aru;
  int32u i;

  if(num_bytes < (sizeof(proof_matrix_message))) {
    VALIDATE_FAILURE("proof_matrix too small");
    return 0;
  }

  expected_size = sizeof(proof_matrix_message) + 
                  (pm->num_acks_in_this_message * sizeof(po_aru_signed_message));
  if (num_bytes != expected_size) {
    VALIDATE_FAILURE("proof_matrix wrong size");
    return 0;
  }

  po_aru = (po_aru_signed_message *)(pm+1);
  for (i = 1; i <= pm->num_acks_in_this_message; i++)
  {
    /* If the type is 0 (DUMMY), this may be a NULL vector, i.e., we haven't received a
     * PO_ARU yet from this replica. In either case, we will not process it later */
    if (po_aru->header.type == DUMMY)
      continue;

    if (po_aru->header.type != PO_ARU || !VAL_Validate_Message((signed_message *) po_aru, sizeof(po_aru_signed_message))) {
      VALIDATE_FAILURE("Invalid PO-ARU in Proof Matrix");
      return 0;
    }
  }
  
  return 1;
}

int32u VAL_Validate_Pre_Prepare(pre_prepare_message *pp, int32u num_bytes)
{
  int32u expected_size;
  po_aru_signed_message *po_aru;
  int32u i;

  Alarm(DEBUG, "VAL_Validate_Pre_Prepare\n");

  if(num_bytes < sizeof(pre_prepare_message)) {
    VALIDATE_FAILURE("Pre-Prepare too small");
    return 0;
  }
 
  expected_size = sizeof(pre_prepare_message) + 
                  (pp->num_acks_in_this_message * sizeof(po_aru_signed_message));
  if (num_bytes != expected_size) {
    VALIDATE_FAILURE("Pre-Prepare wrong size");
    return 0;
  }

  if(pp->seq_num == 0) {
    VALIDATE_FAILURE("Pre-Prepare, bad seq");
    return 0;
  }

  /* Because we're using Spines to fragment large messages, everything should
   * be contained in one Prime message for now */
  if (pp->total_parts != 1 || pp->part_num != 1) {
    VALIDATE_FAILURE("Pre-Prepare wrong part count");
    return 0;
  }

  po_aru = (po_aru_signed_message *)(pp+1);
  for (i = 1; i <= pp->num_acks_in_this_message; i++)
  {
    /* If the type is 0 (DUMMY), this may be a NULL vector, i.e., we haven't received a
     * PO_ARU yet from this replica. In either case, we will not process it later */
    if (po_aru->header.type == DUMMY)
      continue;

    if (po_aru->header.type != PO_ARU || !VAL_Validate_Message((signed_message *) po_aru, sizeof(po_aru_signed_message))) {
      VALIDATE_FAILURE("Invalid PO-ARU in Pre-Prepare");
      return 0;
    }
  }

  return 1;
}

int32u VAL_Validate_Prepare(prepare_message *prepare, int32u num_bytes)
{
  if(num_bytes != sizeof(prepare_message)) {
    VALIDATE_FAILURE("Prepare, bad size");
    return 0;
  }
  
  if(prepare->seq_num == 0) {
    VALIDATE_FAILURE("Prepare, bad seq");
    return 0;
  }
  
  return 1;
}

int32u VAL_Validate_Commit(commit_message *commit, int32u num_bytes)
{
  if(num_bytes != sizeof(commit_message)) {
    VALIDATE_FAILURE("Commit: bad size");
    return 0;
  }

  if(commit->seq_num == 0) {
    VALIDATE_FAILURE("Commit: Bad seq");
    return 0;
  }
  
  return 1;
}

int32u VAL_Validate_TAT_Measure(tat_measure_message *measure, int32u num_bytes)
{
  if (num_bytes != sizeof(tat_measure_message)) {
    VALIDATE_FAILURE("TAT_Measure: bad size");
    return 0;
  }

  return 1;
}

int32u VAL_Validate_RTT_Ping(rtt_ping_message *ping, int32u num_bytes)
{
  if (num_bytes != sizeof(rtt_ping_message)) {
    VALIDATE_FAILURE("RTT_Ping: bad size");
    return 0;
  }

  return 1;
}

int32u VAL_Validate_RTT_Pong(rtt_pong_message *pong, int32u num_bytes)
{
  if (num_bytes != sizeof(rtt_pong_message)) {
    VALIDATE_FAILURE("RTT_Pong: bad size");
    return 0;
  }

  return 1;
}

int32u VAL_Validate_RTT_Measure(rtt_measure_message *measure, int32u num_bytes)
{
  if(num_bytes != sizeof(rtt_measure_message)) {
    VALIDATE_FAILURE("RTT_Measure: bad size");
    return 0;
  }

  return 1;
}

int32u VAL_Validate_TAT_UB(tat_ub_message *measure, int32u num_bytes)
{
  if (num_bytes != sizeof(tat_ub_message)) {
    VALIDATE_FAILURE("TAT_UB: bad size");
    return 0;
  }

  return 1;
}

int32u VAL_Validate_New_Leader(new_leader_message *nl, int32u num_bytes)
{
  if (num_bytes != sizeof(new_leader_message)) {
    VALIDATE_FAILURE("New_Leader: bad size");
    return 0;
  }

  return 1;
}

int32u VAL_Validate_New_Leader_Proof(new_leader_proof_message *nlp, 
    int32u num_bytes)
{
  int32u expected_size;
  signed_message *nl;
  new_leader_message *nl_specific;
  int32u i;

  if (num_bytes < sizeof(new_leader_proof_message)) {
    VALIDATE_FAILURE("New_Leader_Proof: bad size");
    return 0;
  }

  expected_size = sizeof(new_leader_proof_message) + 
                  ((2 * VAR.F + VAR.K + 1) *
                  (sizeof(signed_message) + sizeof(new_leader_message)));
  if (num_bytes != expected_size) {
    VALIDATE_FAILURE("New_Leader_Proof: bad size");
    Alarm(PRINT, "NLP fail: expected = %d, num_bytes = %d\n", expected_size, num_bytes);
    return 0;
  }

  /* Could check this here to reduce computation for old/bad new view messages,
   * but not really a validation problem */
  /* if (nlp->new_view <= DATA.View) {
    Alarm(PRINT, "Old New_Leader_Proof for view %d\n", nlp->new_view);
    return 0;
  }*/

  nl = (signed_message *) (nlp+1);
  for (i = 1; i <= (2 * VAR.F + VAR.K + 1); i++)
  {
    if (nl->type != NEW_LEADER) {
      VALIDATE_FAILURE("New_Leader_Proof: bad type for new leader message");
      return 0;
    }

    if (!VAL_Validate_Message(nl, sizeof(signed_message) + sizeof(new_leader_message))) {
      VALIDATE_FAILURE("New_Leader_Proof: new leader message didn't validate");
      return 0;
    }

    nl_specific = (new_leader_message *) (nl+1);
    if (nl_specific->new_view != nlp->new_view) {
      VALIDATE_FAILURE("New_Leader_Proof: view mismatch with new leader message");
      return 0;
    }

    nl = (signed_message *) (((char *) nl) + sizeof(signed_message) + sizeof(new_leader_message));
  }

  return 1;
}

int32u VAL_Validate_RB_Init(signed_message *rb_init, int32u num_bytes)
{
  if (num_bytes < sizeof(signed_message)) {
    VALIDATE_FAILURE("RB_Init: message too small");
    return 0;
  }

  if (num_bytes != sizeof(signed_message) + rb_init->len) {
    VALIDATE_FAILURE("RB_Init: message too small");
    return 0;
  }
  
  if (rb_init->type != REPORT && rb_init->type != PC_SET) {
    VALIDATE_FAILURE("RB_Init: incorrect payload type (not report or pc set)");
    return 0;
  }

  if (!VAL_Validate_Message(rb_init, num_bytes)) {
    VALIDATE_FAILURE("RB_Init: payload did not validate");
    return 0;
  }

  return 1;
}

int32u VAL_Validate_RB_Echo(signed_message *rb_echo, int32u num_bytes)
{
  if (num_bytes < sizeof(signed_message)) {
    VALIDATE_FAILURE("RB_Echo: message too small");
    return 0;
  }

  if (num_bytes != sizeof(signed_message) + rb_echo->len) {
    VALIDATE_FAILURE("RB_Echo: message too small");
    return 0;
  }
  
  if (rb_echo->type != REPORT && rb_echo->type != PC_SET) {
    VALIDATE_FAILURE("RB_Echo: incorrect payload type (not report or pc set)");
    return 0;
  }

  if (!VAL_Validate_Message(rb_echo, num_bytes)) {
    VALIDATE_FAILURE("RB_Echo: payload did not validate");
    return 0;
  }

  return 1;
}

int32u VAL_Validate_RB_Ready(signed_message *rb_ready, int32u num_bytes)
{
  if (num_bytes < sizeof(signed_message)) {
    VALIDATE_FAILURE("RB_Ready: message too small");
    return 0;
  }

  if (num_bytes != sizeof(signed_message) + rb_ready->len) {
    VALIDATE_FAILURE("RB_Ready: message too small");
    return 0;
  }
  
  if (rb_ready->type != REPORT && rb_ready->type != PC_SET) {
    VALIDATE_FAILURE("RB_Ready: incorrect payload type (not report or pc set)");
    return 0;
  }

  if (!VAL_Validate_Message(rb_ready, num_bytes)) {
    VALIDATE_FAILURE("RB_Ready: payload did not validate");
    return 0;
  }

  return 1;
}

int32u VAL_Validate_Report(report_message *report, int32u num_bytes)
{
  if (num_bytes != sizeof(report_message)) {
    VALIDATE_FAILURE("Report: invalid size");
    return 0;
  }

  if (report->rb_tag.machine_id < 1 || report->rb_tag.machine_id > NUM_SERVERS) {
    VALIDATE_FAILURE("Report: invalid machine id in rb_tag");
    return 0;
  }

  return 1;
}

int32u VAL_Validate_PC_Set(pc_set_message *pc, int32u num_bytes)
{
  signed_message *mess;
  pre_prepare_message *pp;
  prepare_message *pm;
  complete_pre_prepare_message complete_pp;
  int32u sum_len, msg_size, count;
  byte pp_digest[DIGEST_SIZE];

  if (num_bytes < sizeof(pc_set_message)) {
    VALIDATE_FAILURE("PC_Set: invalid size");
    return 0;
  }

  if (pc->rb_tag.machine_id < 1 || pc->rb_tag.machine_id > NUM_SERVERS) {
    VALIDATE_FAILURE("PC_Set: invalid machine id in rb_tag");
    return 0;
  }

  sum_len = sizeof(pc_set_message);
  
  /* First, check the pre-prepare, which should appear first */
  mess     = (signed_message *)(pc + 1);
  msg_size = UTIL_Message_Size(mess);

  if (mess->type != PRE_PREPARE) {
    VALIDATE_FAILURE("PC_Set: first pc_set message not a pre-prepare");
    return 0;
  }
  if (msg_size > num_bytes - sum_len) {
    VALIDATE_FAILURE("PC_Set: pre-prepare too large");
    return 0;
  }
  if (!VAL_Validate_Message(mess, msg_size)) {
    VALIDATE_FAILURE("PC_Set: pre-prepare did not pass VAL function");
    return 0;
  }

  pp = (pre_prepare_message *)(mess + 1);

  /* Construct the complete_pp from the pp we received */
  complete_pp.seq_num = pp->seq_num;
  complete_pp.view = pp->view;
  memcpy((byte *)&complete_pp.cum_acks, (byte *)(pp + 1),  
            sizeof(po_aru_signed_message) * pp->num_acks_in_this_message);

  /* Compute the digest of the PP */
  OPENSSL_RSA_Make_Digest((byte*)&complete_pp, sizeof(complete_pre_prepare_message), pp_digest);

  sum_len += msg_size;
  count = 0;

  /* Next, count the number of valid prepares */
  while (sum_len < num_bytes) {
    mess     = (signed_message *)((char*)mess + msg_size);
    msg_size = UTIL_Message_Size(mess);

    if (mess->type != PREPARE) {
      VALIDATE_FAILURE("PC_Set: pc set message not a prepare");
      return 0;
    }
    if (msg_size > num_bytes - sum_len) {
      VALIDATE_FAILURE("PC_Set: prepare too large");
      return 0;
    }
    if (!VAL_Validate_Message(mess, msg_size)) {
      VALIDATE_FAILURE("PC_Set: prepare did not pass VAL function");
      return 0;
    }

    pm = (prepare_message *)(mess + 1);
    if (pm->seq_num != pp->seq_num) {
        VALIDATE_FAILURE("PC_Set: prepare seq_num does not match pp seq_num");
        return 0;
    }

    /* Calculate the digest of the commit, and compare it against the pp */
    if (!OPENSSL_RSA_Digests_Equal(pm->digest, pp_digest)) {
        VALIDATE_FAILURE("PC_Set: prepare digest does not match pp digest");
        return 0;
    }

    sum_len += msg_size;
    count++;
  }

  /* Finally, do last sanity check on overall length and number of prepares */
  if (sum_len != num_bytes) {
    VALIDATE_FAILURE("PC_Set: total bytes in message does not match num_bytes");
    return 0;
  }
  if (count != 2*VAR.F + VAR.K) {
    VALIDATE_FAILURE("PC_Set: not 2f+k prepare messages inside the pc_set");
    Alarm(PRINT, "PC_Set: count = %d, needed %d\n", count, 2*VAR.F + VAR.K);
    return 0;
  }

  Alarm(DEBUG, "VALID PC_SET Message!\n");
  return 1;
}

int32u VAL_Validate_VC_List(vc_list_message *vc_list, int32u num_bytes)
{
  if (num_bytes != sizeof(vc_list_message)) {
    VALIDATE_FAILURE("VC_List: invalid size");
    return 0;
  }

  return 1;
}

int32u VAL_Validate_VC_Partial_Sig(vc_partial_sig_message *vc_psig, int32u num_bytes)
{
  if (num_bytes != sizeof(vc_partial_sig_message)) {
    VALIDATE_FAILURE("VC_Partial_Sig: invalid size");
    return 0;
  }

  return 1;
}

int32u VAL_Validate_VC_Proof(vc_proof_message *vc_proof, int32u num_bytes)
{
  byte digest[DIGEST_SIZE];

  if (num_bytes != sizeof(vc_proof_message)) {
    VALIDATE_FAILURE("VC_Proof: invalid size");
    return 0;
  }

  /* Validate the threshold signature on the vc_proof message */
  OPENSSL_RSA_Make_Digest(vc_proof, 3 * sizeof(int32u), digest);
  if (!TC_Verify_Signature(1, vc_proof->thresh_sig, digest)) {
    VALIDATE_FAILURE("VC_Proof: vc_proof threshold signature failed verification");
    return 0;
  }
    
  return 1;
}

int32u VAL_Validate_Replay(replay_message *replay, int32u num_bytes)
{
  byte digest[DIGEST_SIZE];

  if (num_bytes != sizeof(replay_message)) {
    VALIDATE_FAILURE("Replay: invalid size");
    return 0;
  }

  /* Validate the threshold signature on the vc_proof message */
  OPENSSL_RSA_Make_Digest(replay, 3 * sizeof(int32u), digest);
  if (!TC_Verify_Signature(1, replay->thresh_sig, digest)) {
    VALIDATE_FAILURE("Replay: replay threshold signature failed verification");
    return 0;
  }

  return 1;
}

int32u VAL_Validate_Replay_Prepare(replay_prepare_message *r_prepare, int32u num_bytes)
{
  if (num_bytes != sizeof(replay_prepare_message)) {
    VALIDATE_FAILURE("Replay_Prepare: invalid size");
    return 0;
  }

  return 1;
}

int32u VAL_Validate_Replay_Commit(replay_commit_message *r_commit, int32u num_bytes)
{
  if (num_bytes != sizeof(replay_commit_message)) {
    VALIDATE_FAILURE("Replay_Commit: invalid size");
    return 0;
  }

  return 1;
}

int32u VAL_Validate_Catchup_Request(catchup_request_message *c_request, int32u num_bytes)
{
  if (num_bytes != sizeof(c_request)) {
    VALIDATE_FAILURE("Catchup_Request: invalid size");
    return 0;
  }

  Alarm(PRINT, "Invalid type: Catchup_Request\n");
  return 0;
  //return 1;
}

int32u VAL_Validate_ORD_Certificate(ord_certificate_message *ord_cert, int32u num_bytes)
{
  signed_message *mess;
  pre_prepare_message *pp;
  commit_message *cm;
  int32u sum_len, msg_size, count;
  complete_pre_prepare_message complete_pp;
  byte pp_digest[DIGEST_SIZE];

  if (num_bytes < sizeof(ord_certificate_message)) {
    VALIDATE_FAILURE("ORD_Certificate: invalid size");
    return 0;
  }

  if (ord_cert->type != SLOT_COMMIT) {
    VALIDATE_FAILURE("ORD_Certificate: invalid type. Must be SLOT_COMMIT");
    return 0;
  }

  sum_len = sizeof(ord_certificate_message);
  
  /* First, check the pre-prepare, which should appear first */
  mess     = (signed_message *)(ord_cert + 1);
  msg_size = UTIL_Message_Size(mess);

  if (mess->type != PRE_PREPARE) {
    VALIDATE_FAILURE("ORD_Certificate: first pc_set message not a pre-prepare");
    return 0;
  }
  if (msg_size > num_bytes - sum_len) {
    VALIDATE_FAILURE("ORD_Certificate: pre-prepare too large");
    return 0;
  }
  if (!VAL_Validate_Message(mess, msg_size)) {
    VALIDATE_FAILURE("ORD_Certificate: pre-prepare did not pass VAL function");
    return 0;
  }
  
  pp = (pre_prepare_message *)(mess + 1);
  if (pp->seq_num != ord_cert->seq_num) {
    VALIDATE_FAILURE("ORD_Certificate: pp seq_num does not match ord_cert seq_num");
    return 0;
  }

  /* Construct the complete_pp from the pp we received */
  complete_pp.seq_num = pp->seq_num;
  complete_pp.view = pp->view;
  memcpy((byte *)&complete_pp.cum_acks, (byte *)(pp + 1), 
            sizeof(po_aru_signed_message) * pp->num_acks_in_this_message);

  /* Compute the digest of the PP */
  OPENSSL_RSA_Make_Digest((byte*)&complete_pp, sizeof(complete_pre_prepare_message), pp_digest);

  sum_len += msg_size;
  count = 0;

  /* Next, count the number of valid commits */
  while (sum_len < num_bytes) {
    mess     = (signed_message *)((char*)mess + msg_size);
    msg_size = UTIL_Message_Size(mess);

    if (mess->type != COMMIT) {
      VALIDATE_FAILURE("ORD_Certificate: non-commit message present");
      return 0;
    }
    if (msg_size > num_bytes - sum_len) {
      VALIDATE_FAILURE("ORD_Certificate: commit too large");
      return 0;
    }
    if (!VAL_Validate_Message(mess, msg_size)) {
      VALIDATE_FAILURE("ORD_Certificate: commit did not pass VAL function");
      return 0;
    }

    cm = (commit_message *)(mess + 1);
    if (cm->seq_num != ord_cert->seq_num) {
        VALIDATE_FAILURE("ORD_Certificate: commit seq_num does not match ord_cert seq_num");
        return 0;
    }

    /* Calculate the digest of the commit, and compare it against the pp */
    if (!OPENSSL_RSA_Digests_Equal(cm->digest, pp_digest)) {
        VALIDATE_FAILURE("ORD_Certificate: commit digest does not match ord_cert digest");
        return 0;
    }

    sum_len += msg_size;
    count++;
  }

  /* Finally, do last sanity check on overall length and number of prepares */
  if (sum_len != num_bytes) {
    VALIDATE_FAILURE("ORD_Certificate: total bytes in message does not match num_bytes");
    return 0;
  }
  if (count != 2*VAR.F + VAR.K + 1) {
    VALIDATE_FAILURE("ORD_Certificate: not 2f+k+1 commit messages inside the cert");
    Alarm(PRINT, "VAL_ORD_Certificate: count = %d, needed %d\n", count, 2*VAR.F + VAR.K + 1);
    return 0;
  }

  return 1;
}

int32u VAL_Validate_PO_Certificate(po_certificate_message *po_cert, int32u num_bytes)
{
  Alarm(PRINT, "Invalid type: PO_Certificate\n");
  return 0;
}

#if 0
int32u VAL_Validate_Catchup_Reply(catchup_reply_message *c_reply, int32u num_bytes)
{
  /* TODO: validate message similar to PC_SET message */
  /* if (num_bytes != sizeof(c_reply)) {
    VALIDATE_FAILURE("Replay_Commit: invalid size");
    return 0;
  } */

  return 1;
}
#endif
