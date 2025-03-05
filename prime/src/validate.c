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

/* Message validation functions. These functions check to make sure messages
 * came from the server or site that should have sent them and check to make
 * sure that the lengths are correct. */

#include "validate.h"
#include "data_structs.h"
#include "order.h"
#include "pre_order.h"
#include "error_wrapper.h"
#include "merkle.h"
#include "openssl_rsa.h"
#include "utility.h"
#include "packets.h"
#include "tc_wrapper.h"
#include "proactive_recovery.h"
#include "spu_alarm.h"

extern server_variables   VAR;
extern server_data_struct DATA;

int32u VAL_Validate_Signed_Message(signed_message *mess, int32u num_bytes, 
				   int32u verify_signature); 
int32u VAL_Validate_Sender        (int32u sig_type, int32u sender_id);
int32u VAL_Validate_Incarnation   (int32u sig_type, signed_message *mess);
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
int32u VAL_Validate_PO_Certificate (po_certificate_message *po_cert, int32u num_bytes);
int32u VAL_Validate_Jump           (jump_message *jump, int32u num_bytes);

int32u VAL_Validate_New_Incarnation(new_incarnation_message *new_inc, int32u num_bytes);
int32u VAL_Validate_Incarnation_Ack(incarnation_ack_message *inc_ack, int32u num_bytes);
int32u VAL_Validate_Incarnation_Cert(incarnation_cert_message *inc_cert, int32u num_bytes, int32u machine_id, int32u incarnation);
int32u VAL_Validate_Pending_State(pending_state_message *pend_state, int32u num_bytes);
int32u VAL_Validate_Pending_Share(pending_share_message *pend_share, int32u num_bytes);
int32u VAL_Validate_Reset_Vote(reset_vote_message *reset_vote, int32u num_bytes);
int32u VAL_Validate_Reset_Share(reset_share_message *reset_share, int32u num_bytes);
int32u VAL_Validate_Reset_Proposal(reset_proposal_message *reset_proposal, int32u num_bytes);
int32u VAL_Validate_Reset_Prepare(reset_prepare_message *reset_prepare, int32u num_bytes);
int32u VAL_Validate_Reset_Commit(reset_commit_message *reset_commit, int32u num_bytes);
int32u VAL_Validate_Reset_NewLeader(reset_newleader_message *reset_newleader, int32u num_bytes);
int32u VAL_Validate_Reset_NewLeaderProof(reset_newleaderproof_message *reset_nlp, int32u num_bytes);
int32u VAL_Validate_Reset_ViewChange(reset_viewchange_message *reset_viewchange, int32u num_bytes);
int32u VAL_Validate_Reset_NewView(reset_newview_message *reset_newview, int32u num_bytes);
int32u VAL_Validate_Reset_Certificate(reset_certificate_message *reset_cert, int32u num_bytes);

// MK Reconf: To validate network manager's message
int32u VAL_Validate_NM(nm_message *update, int32u num_bytes); 

/* Determine if a message from the network is permitted to be processed
 * based on my current state (STARTUP, RESET, RECOVERY, NORMAL) */
int32u VAL_State_Permits_Message(signed_message *mess)
{
   /*If reconfigurable Spire is running check if it is valid configuration*/
   /*
   if(RECONF==1){ 
   	if(mess->global_configuration_number==0){
        	return 0;
       	}
   }
   */
    switch (DATA.PR.recovery_status[VAR.My_Server_ID])
    {
        case PR_STARTUP:
            switch (mess->type) {
                case NEW_INCARNATION:
                case INCARNATION_ACK:
                case INCARNATION_CERT:
                case RESET_VOTE:
                case RESET_SHARE:
                case RESET_PROPOSAL:
                case RESET_CERT:
		case CLIENT_OOB_CONFIG_MSG:
                  return 1;
                default:
                  return 0;
            }
            break;

        case PR_RESET:
            switch (mess->type) {
                case RB_INIT:
                case RB_ECHO:
                case RB_READY:
                case NEW_INCARNATION:
                case RESET_SHARE:
                case RESET_PROPOSAL:
                case RESET_PREPARE:
                case RESET_COMMIT:
                case RESET_NEWLEADER:
                case RESET_NEWLEADERPROOF:
                case RESET_VIEWCHANGE:
                case RESET_NEWVIEW:
                case RESET_CERT:
		case CLIENT_OOB_CONFIG_MSG:
                    return 1;
                default:
                    return 0;
            }
            break;

        case PR_RECOVERY:
            switch (mess->type) {
                case PO_REQUEST:
                case PO_ACK:
                case PO_ARU:
                case PRE_PREPARE:
                case PREPARE: 
                case COMMIT:
                case ORD_CERT:
                case PO_CERT:
                case JUMP:
                case NEW_INCARNATION:
                case INCARNATION_CERT:
                case PENDING_STATE:
                case PENDING_SHARE:

                case UPDATE:
		case CLIENT_OOB_CONFIG_MSG:
                    return 1;
                default:
                    return 0;
            }
            break;

        case PR_NORMAL:
            switch (mess->type) {
                case PO_REQUEST: 
                case PO_ACK: 
                case PO_ARU: 
                case PROOF_MATRIX:
                case PRE_PREPARE: 
                case PREPARE: 
                case COMMIT:
                case RECON:
                case TAT_MEASURE: 
                case RTT_PING: 
                case RTT_PONG: 
                case RTT_MEASURE:
                case TAT_UB:
                case NEW_LEADER: 
                case NEW_LEADER_PROOF:
                case RB_INIT:
                case RB_ECHO:
                case RB_READY:
                case REPORT:
                case PC_SET: 
                case VC_LIST:
                case VC_PARTIAL_SIG:
                case VC_PROOF:
                case REPLAY:
                case REPLAY_PREPARE: 
                case REPLAY_COMMIT:
                case ORD_CERT: 
                case PO_CERT:
                case CATCHUP_REQUEST: 
                case JUMP:

                case NEW_INCARNATION:
                case INCARNATION_CERT:

                case UPDATE:
		case CLIENT_OOB_CONFIG_MSG:
                    return 1;
                default:
                    return 0;
            }
            break;

        default:
            return 0;
    }
}

/* Determine if a message from the network is valid. */
int32u VAL_Validate_Message(signed_message *message, int32u num_bytes) 
{
  byte *content;
  int32u num_content_bytes;

  util_stopwatch profile_sw;
  UTIL_Stopwatch_Start(&profile_sw);

  /* This is a signed message */
  if (!VAL_Validate_Signed_Message(message, num_bytes, 1)) {
    Alarm(PRINT, "Validate signed message failed.\n");
    VALIDATE_FAILURE_LOG(message,num_bytes);
    return 0;
  }

  /* Check that the machine that sent us this message has been in our global
   * incarnation at any point yet, or is sending us a new_incarnation message,
   * or is already marked as STARTUP */
  /* if (DATA.PR.preinstalled_incarnations[mess->machine_id] == 0 &&
       (DATA.PR.recovery_status[mess->machine_id] != PR_STARTUP || 
        mess->type = NEW_INCARNATION))
  {
        return;
  } */
  
  Alarm(DEBUG,"VAL_Validate_Signed_Message passed\n");
  content = (byte*)(message + 1);
  num_content_bytes = num_bytes - sizeof(signed_message) - MT_Digests_(message->mt_num) * DIGEST_SIZE; /* always >= 0, since checked in Validate_Signed_Message */

  switch (message->type) {

  case UPDATE:
    Alarm(DEBUG,"MS2022:Update\n");
    if((!VAL_Validate_Update((update_message *)(content), num_content_bytes))){
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case PO_REQUEST:
    Alarm(DEBUG,"MS2022:PO_REQUEST\n");
    if((!VAL_Validate_PO_Request((po_request_message *)content,
				 num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
    
  case PO_ACK:
    Alarm(DEBUG,"MS2022:PO_ACK\n");
    if((!VAL_Validate_PO_Ack((po_ack_message *)content,
			     num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case PO_ARU:
    Alarm(DEBUG,"MS2022:PO_ARU\n");
    if((!VAL_Validate_PO_ARU((po_aru_message *)content,
			     num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case PROOF_MATRIX:
    Alarm(DEBUG,"MS2022:PROOF_MATRIX\n");
    if((!VAL_Validate_Proof_Matrix((proof_matrix_message *)content,
				   num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
    
  case PRE_PREPARE:
    Alarm(DEBUG,"MS2022:PRE_PREPARE\n");
    if((!VAL_Validate_Pre_Prepare((pre_prepare_message *)content,
				  num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case PREPARE:
    Alarm(DEBUG,"MS2022:PREPARE\n");
    if((!VAL_Validate_Prepare((prepare_message *)content,
			      num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
    
  case COMMIT:
    Alarm(DEBUG,"MS2022:COMMIT\n");
    if((!VAL_Validate_Commit((commit_message *)content,
			     num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case TAT_MEASURE:
    Alarm(DEBUG,"MS2022:TAT_MEASURE\n");
    if((!VAL_Validate_TAT_Measure((tat_measure_message *)content,
                 num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RTT_PING:
    Alarm(DEBUG,"MS2022:RTT_PING\n");
    if((!VAL_Validate_RTT_Ping((rtt_ping_message *)content,
                 num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RTT_PONG:
    Alarm(DEBUG,"MS2022:RTT_PONG\n");
    if((!VAL_Validate_RTT_Pong((rtt_pong_message *)content,
                 num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RTT_MEASURE:
    Alarm(DEBUG,"MS2022:RTT_MEASURE\n");
    if((!VAL_Validate_RTT_Measure((rtt_measure_message *)content,
                 num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case TAT_UB:
    Alarm(DEBUG,"MS2022:TAT_UB\n");
    if((!VAL_Validate_TAT_UB((tat_ub_message *)content,
                 num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case NEW_LEADER:
    Alarm(DEBUG,"MS2022:NEW_LEADER\n");
    if((!VAL_Validate_New_Leader((new_leader_message *)content,
                 num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case NEW_LEADER_PROOF:
    Alarm(DEBUG,"MS2022:NEW_LEADER_PROOF\n");
    if((!VAL_Validate_New_Leader_Proof((new_leader_proof_message *)content,
                 num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RB_INIT:
    Alarm(DEBUG,"MS2022:RB_INIT\n");
    if((!VAL_Validate_RB_Init((signed_message *)content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RB_ECHO:
    Alarm(DEBUG,"MS2022:RB_ECHO\n");
    if((!VAL_Validate_RB_Echo((signed_message *)content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RB_READY:
    Alarm(DEBUG,"MS2022:RB_READY\n");
    if((!VAL_Validate_RB_Ready((signed_message *)content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case REPORT:
    Alarm(DEBUG,"MS2022:REPORT\n");
    if((!VAL_Validate_Report((report_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
  
  case PC_SET:
    Alarm(DEBUG,"MS2022:PC_SET\n");
    if((!VAL_Validate_PC_Set((pc_set_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
  
  case VC_LIST:
    Alarm(DEBUG,"MS2022:VC_LIST\n");
    if((!VAL_Validate_VC_List((vc_list_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
  
  case VC_PARTIAL_SIG:
    Alarm(DEBUG,"MS2022:VC_PARTIAL_SIG\n");
    if((!VAL_Validate_VC_Partial_Sig((vc_partial_sig_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
  
  case VC_PROOF:
    Alarm(DEBUG,"MS2022:VC_PROOF\n");
    if((!VAL_Validate_VC_Proof((vc_proof_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
  
  case REPLAY:
    Alarm(DEBUG,"MS2022:REPLAY\n");
    if((!VAL_Validate_Replay((replay_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
  
  case REPLAY_PREPARE:
    Alarm(DEBUG,"MS2022:REPLAY_PREPARE\n");
    if((!VAL_Validate_Replay_Prepare((replay_prepare_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
  
  case REPLAY_COMMIT:
    Alarm(DEBUG,"MS2022:REPLAY_COMMIT\n");
    if((!VAL_Validate_Replay_Commit((replay_commit_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
  
  case CATCHUP_REQUEST:
    Alarm(DEBUG,"MS2022:CATCHUP_REQUEST\n");
    if((!VAL_Validate_Catchup_Request((catchup_request_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case ORD_CERT:
    Alarm(DEBUG,"MS2022:ORD_CERT\n");
    if((!VAL_Validate_ORD_Certificate((ord_certificate_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case PO_CERT:
    Alarm(DEBUG,"MS2022:PO_CERT\n");
    if((!VAL_Validate_PO_Certificate((po_certificate_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case JUMP:
    Alarm(DEBUG,"MS2022:JUMP\n");
    if((!VAL_Validate_Jump((jump_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case NEW_INCARNATION:
    Alarm(DEBUG,"MS2022:NEW_INCARNATION\n");
    if((!VAL_Validate_New_Incarnation((new_incarnation_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case INCARNATION_ACK:
    Alarm(DEBUG,"MS2022:INCARNATION_ACK\n");
    if((!VAL_Validate_Incarnation_Ack((incarnation_ack_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case INCARNATION_CERT:
    Alarm(DEBUG,"MS2022:INCARNATION_CERT\n");
    if((!VAL_Validate_Incarnation_Cert((incarnation_cert_message* )content, num_content_bytes, message->machine_id, message->incarnation))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case PENDING_STATE:
    Alarm(DEBUG,"MS2022:PENDING_STATE\n");
    if((!VAL_Validate_Pending_State((pending_state_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case PENDING_SHARE:
    Alarm(DEBUG,"MS2022:PENDING_SHARE\n");
    if((!VAL_Validate_Pending_Share((pending_share_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RESET_VOTE:
    Alarm(DEBUG,"MS2022:RESET_VOTE\n");
    if((!VAL_Validate_Reset_Vote((reset_vote_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RESET_SHARE:
    Alarm(DEBUG,"MS2022:RESET_SHARE\n");
    if((!VAL_Validate_Reset_Share((reset_share_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RESET_PROPOSAL:
    Alarm(DEBUG,"MS2022:RESET_PROPOSAL\n");
    if((!VAL_Validate_Reset_Proposal((reset_proposal_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RESET_PREPARE:
    Alarm(DEBUG,"MS2022:RESET_PREPARE\n");
    if((!VAL_Validate_Reset_Prepare((reset_prepare_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RESET_COMMIT:
    Alarm(DEBUG,"MS2022:RESET_COMMIT\n");
    if((!VAL_Validate_Reset_Commit((reset_commit_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RESET_NEWLEADER:
    Alarm(DEBUG,"MS2022:RESET_NEWLEADER\n");
    if((!VAL_Validate_Reset_NewLeader((reset_newleader_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RESET_NEWLEADERPROOF:
    Alarm(DEBUG,"MS2022:RESET_NEWLEADERPROOF\n");
    if((!VAL_Validate_Reset_NewLeaderProof((reset_newleaderproof_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RESET_VIEWCHANGE:
    Alarm(DEBUG,"MS2022:RESET_VIEWCHANGE\n");
    if((!VAL_Validate_Reset_ViewChange((reset_viewchange_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RESET_NEWVIEW:
    Alarm(DEBUG,"MS2022:RESET_NEWVIEW\n");
    if((!VAL_Validate_Reset_NewView((reset_newview_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  case RESET_CERT:
    Alarm(DEBUG,"MS2022:RESET_CERT\n");
    if((!VAL_Validate_Reset_Certificate((reset_certificate_message* )content, num_content_bytes))) {
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;
  case CLIENT_OOB_CONFIG_MSG:
    // MK Reconf: Validating Network Manager msg
    Alarm(DEBUG,"MS2022**************:OOB NM MSG\n");
    if((!VAL_Validate_NM((nm_message *)(content), num_content_bytes))){
      VALIDATE_FAILURE_LOG(message, num_bytes);
      return 0;
    }
    break;

  default:
    Alarm(PRINT, "Not yet checking message type %d!\n", message->type);
    //return 0;
  }
 
  UTIL_Stopwatch_Stop(&profile_sw);
  if (UTIL_Stopwatch_Elapsed(&profile_sw) >= 0.002) {
    Alarm(DEBUG, "PROF VAL: %s took %f s\n", 
            UTIL_Type_To_String(message->type), UTIL_Stopwatch_Elapsed(&profile_sw));
  }
 
  return 1;
}

/* Determine if a signed message is valid. */
int32u VAL_Validate_Signed_Message(signed_message *mess, int32u num_bytes, 
				   int32u verify_signature) 
{
  int32u sig_type;
  int32u sender_id;
  int32u msg_global_inc;

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
  sig_type = VAL_Signature_Type( mess );
  if (sig_type == VAL_TYPE_INVALID) {
    VALIDATE_FAILURE("Sig Type invalid");
    return 0;
  } else if(sig_type == VAL_SIG_TYPE_UNSIGNED) {
    return 1;
  } else if (sig_type == VAL_SIG_TYPE_SERVER || 
             sig_type == VAL_SIG_TYPE_MERKLE ||
             sig_type == VAL_SIG_TYPE_CLIENT ||
             sig_type == VAL_SIG_TYPE_TPM_SERVER ||
             sig_type == VAL_SIG_TYPE_TPM_MERKLE ||
             sig_type == VAL_SIG_TYPE_NM) {          // MK Reconf: Network Manager
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

  /* Validates the incarnation on session-key signed messages */
  if (!DATA.PO.Nested_Ignore_Incarnation && !VAL_Validate_Incarnation(sig_type, mess)) {
    VALIDATE_FAILURE("Invalid incarnation");
    return 0;
  }

  /* PRTODO: validate the monotonically increasing counter on TPM signed messages */

  //return 1;
  if (verify_signature && !VAL_Is_Valid_Signature(sig_type, sender_id, mess->site_id, mess)) {
    VALIDATE_FAILURE("Invalid signature");
    return 0;
  }

  //MS2022: Check Global Incarnation Number
  msg_global_inc = mess->global_configuration_number;
  if (sig_type == VAL_SIG_TYPE_SERVER ||
             sig_type == VAL_SIG_TYPE_MERKLE ||
             sig_type == VAL_SIG_TYPE_CLIENT ||
             sig_type == VAL_SIG_TYPE_TPM_SERVER ||
             sig_type == VAL_SIG_TYPE_TPM_MERKLE){
      if(msg_global_inc!=DATA.NM.global_configuration_number){
        Alarm(PRINT,"Invalid global incarnation in signed message got %d mine %d\n",msg_global_inc,DATA.NM.global_configuration_number);
	Alarm(PRINT,"type=%s, sender=%d\n",UTIL_Type_To_String(mess->type),mess->machine_id);
        VALIDATE_FAILURE("Invalid global incarnation in signed message");
	return 0;
	}
  }

  return 1; /* Passed all checks */
}

/* Determine if the message type is valid and if so return which type of
 * signature is on the message, a client signature, a server signature, or a
 * threshold signature. 
 * 
 * returns: VAL_SIG_TYPE_SERVER, VAL_SIG_TYPE_CLIENT, VAL_SIG_TYPE_SITE, 
 * VAL_SIG_TYPE_TPM_SERVER, VAL_SIG_TYPE_TPM_MERKLE, or VAL_TYPE_INVALID */
int32u VAL_Signature_Type(signed_message *mess) 
{
  int32u sender_id;
  int sig_type = VAL_TYPE_INVALID;
  po_request_message *po_request;
  update_message *up;
  
  /* Return the type of the signature based on the type of the message. If
   * the type is not found, then return TYPE_INVALID */
  sender_id = mess->machine_id;
  switch(mess->type) {

  case UPDATE:
    if (sender_id >= 1 && sender_id <= VAR.Num_Servers) {
        up = (update_message *)(mess + 1);
        if (mess->monotonic_counter > 0) {
            if (up->seq_num == 1) {
                Alarm(PRINT, "VAL: Got TPM-Signed first Update from %u\n", mess->machine_id);
                sig_type = VAL_SIG_TYPE_TPM_SERVER;
            }
            else
                sig_type = VAL_TYPE_INVALID;
        }
        else 
          sig_type = VAL_SIG_TYPE_SERVER;
    }
    else
      sig_type = VAL_SIG_TYPE_CLIENT;
    break;

  case CLIENT_OOB_CONFIG_MSG:
    sig_type = VAL_SIG_TYPE_NM;
    break;
 
  case PO_ARU:
  case NEW_LEADER:
  case REPORT:
  case PC_SET:
    sig_type = VAL_SIG_TYPE_SERVER;
    break;

  case PO_REQUEST:
    po_request = (po_request_message *)(mess + 1);
    if (mess->monotonic_counter > 0) {
        if (po_request->seq.seq_num == 1) {
            Alarm(PRINT, "VAL: Got TPM-Signed first PO_Req from %u\n", mess->machine_id);
            sig_type = VAL_SIG_TYPE_TPM_MERKLE;
        }
        else 
            sig_type = VAL_TYPE_INVALID;
    }
    else
        sig_type = VAL_SIG_TYPE_MERKLE;
    break;

  case RB_INIT:
  case RB_ECHO:
  case RB_READY: 
    if (mess->monotonic_counter > 0)
        sig_type = VAL_SIG_TYPE_TPM_MERKLE;
    else
        sig_type = VAL_SIG_TYPE_MERKLE;
    break;

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
  case VC_LIST:
  case VC_PARTIAL_SIG:
  case VC_PROOF:
  case REPLAY:
  case REPLAY_PREPARE:
  case REPLAY_COMMIT:
  case PO_CERT:
  case ORD_CERT:
  case PENDING_SHARE:
    sig_type = VAL_SIG_TYPE_MERKLE;
    break;

  case RESET_NEWLEADER:
  case RESET_VIEWCHANGE:
  case RESET_NEWVIEW:
    sig_type = VAL_SIG_TYPE_TPM_SERVER;
    break;

  case CATCHUP_REQUEST:
  case JUMP:
  case NEW_INCARNATION:
  case INCARNATION_ACK:
  case INCARNATION_CERT:
  case PENDING_STATE:
  case RESET_VOTE:
  case RESET_SHARE:
  case RESET_PROPOSAL:
  case RESET_PREPARE:
  case RESET_COMMIT:
  case RESET_NEWLEADERPROOF:
  case RESET_CERT:
    sig_type = VAL_SIG_TYPE_TPM_MERKLE;
    break;
  }

  return sig_type;
}

/* Determine if the sender is valid depending on the specified signature type.
 * 
 * return: 1 if sender is valid, 0 if sender is not valid */
int32u VAL_Validate_Sender(int32u sig_type, int32u sender_id) 
{
  // Ms2022: Network Manager
  if (sender_id == 0 && sig_type == VAL_SIG_TYPE_NM)
      return 1;
  if (sender_id < 1) 
    return 0;

  if ((sig_type == VAL_SIG_TYPE_SERVER || sig_type == VAL_SIG_TYPE_MERKLE || 
       sig_type == VAL_SIG_TYPE_TPM_SERVER || sig_type == VAL_SIG_TYPE_TPM_MERKLE) 
      && sender_id <= VAR.Num_Servers) {
    return 1;
  } 
    
  if (sig_type == VAL_SIG_TYPE_CLIENT &&
      sender_id <= NUM_CLIENTS) {
    return 1;
  }


  return 0;
}

/* Determine if the incarnation on a session key-signed message is valid, that
 * is if it matches what we have preinstalled for this sender.
 *
 * return: 1 if incarnation is valid, 0 if incarnation is not valid */
int32u VAL_Validate_Incarnation(int32u sig_type, signed_message *mess)
{
  jump_message *jm;
  update_message *up;
  signed_message *payload;

  /* Special case for pending shares, which are session signed but do not
   * get checked against the installed_incarnations - instead they get checked against
   * the vector of incarnations present in the jump message */
  if (mess->type == PENDING_SHARE) {
    if (DATA.PR.jump_message[mess->machine_id] == NULL) {
        Alarm(PRINT, "Jump message from %u is NULL\n", mess->machine_id); 
        return 0;
    }
    jm = (jump_message *)(DATA.PR.jump_message[mess->machine_id] + 1);
    if (mess->incarnation != jm->installed_incarn[mess->machine_id-1]) {
        Alarm(PRINT, "Pending Share incarnation mismatch. mess = %u != jm = %u\n",
            mess->incarnation, jm->installed_incarn[mess->machine_id-1]);
        return 0;
    }
    return 1;
  }

  if (mess->type == UPDATE && mess->machine_id == VAR.My_Server_ID) {
    up = (update_message *)(mess + 1);
    payload = (signed_message *)(up + 1);
    if (payload->type == CLIENT_STATE_TRANSFER)
        return 1;
  }

  /* Normal check: updates coming from other Prime replicas. Note that the first
   * po_request from recovering replicas are TPM signed, so the incarnation is
   * not checked here for those */
  if (sig_type == VAL_SIG_TYPE_MERKLE || sig_type == VAL_SIG_TYPE_SERVER) {
    /* if (mess->incarnation != DATA.PR.preinstalled_incarnations[mess->machine_id]) {
        Alarm(PRINT, "VAL Incarnation FAIL: mess->incarnation %u != preinstalled[%u] %u\n",
            mess->incarnation, mess->machine_id, DATA.PR.preinstalled_incarnations[mess->machine_id]);
        return 0;
    } */
    if (mess->incarnation != DATA.PR.installed_incarnations[mess->machine_id]) {
        Alarm(PRINT, "VAL Incarnation FAIL: mess->incarnation %u != installed[%u] %u\n",
            mess->incarnation, mess->machine_id, DATA.PR.installed_incarnations[mess->machine_id]);
        Alarm(PRINT, "    sig_type = %u\n", sig_type);
        return 0;
    }
  }

  // MK Reconf TODO: We can check the incarnation number here!

  /* All other SIG types do not / cannot require a valid incarnation */
  return 1;
}


/* Determine if the signature is valid. Assume that the lengths of the message
 * is okay. */
int32u VAL_Is_Valid_Signature(int32u sig_type, int32u sender_id, 
			      int32u site_id, signed_message *mess) 
{
  int32 ret;
  byte digest[DIGEST_SIZE];
 
  //if (sig_type == VAL_SIG_TYPE_MERKLE || (sig_type == VAL_SIG_TYPE_TPM && mess->type != UPDATE)) {
  if (sig_type == VAL_SIG_TYPE_MERKLE || sig_type == VAL_SIG_TYPE_TPM_MERKLE) {
    ret = MT_Verify(mess);
    if(ret == 0) {
        Alarm(PRINT, "MT_Verify returned 0 on message from machine %d type %d "
                     "len %d, total len %d\n", mess->machine_id, mess->type, 
                     mess->len, UTIL_Message_Size(mess));
      }
    return ret;
  }

  //if (sig_type == VAL_SIG_TYPE_SERVER || (sig_type == VAL_SIG_TYPE_TPM && mess->type == UPDATE)) {
  if (sig_type == VAL_SIG_TYPE_SERVER || sig_type == VAL_SIG_TYPE_TPM_SERVER) {
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
    if(!CONFIDENTIAL){
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
   if(CONFIDENTIAL){
	/*
          MK: Verify TC Signature to make sure client request is correct.
          Hence, we do not need to check client's request with client's
          public key.
          Note: We do not need to know client's public key anymore.
        */
    	OPENSSL_RSA_Make_Digest(((byte*)mess)+SIGNATURE_SIZE,
        sizeof(signed_update_message) - SIGNATURE_SIZE, digest);
    	if (!TC_Verify_SM_Signature(1, mess->sig, digest)) {
        	Alarm(PRINT,"  TC Sig Client Failed %d\n", mess->type);
        	return 0;
    	}
    	else {
      		return 1;
    	}

	}
  }

  if (sig_type == VAL_SIG_TYPE_NM) {

    /* Check an RSA signature using openssl. A network manager sent the message. */
    ret = 
      OPENSSL_RSA_Verify( 
       ((byte*)mess) + SIGNATURE_SIZE,
       mess->len + sizeof(signed_message) - SIGNATURE_SIZE,
       (byte*)mess, 
       sender_id,
       RSA_NM
       );
    if (ret == 0) 
      Alarm(PRINT,"  Sig Network Manager Failed %d\n", mess->type);
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

/* MK Reconf: Determine if a network manager msg is valid */
int32u VAL_Validate_NM(nm_message *update, int32u num_bytes) 
{
  
  /* Check to determine if the update is valid. We have already checked to
   * see if the signature verified. We only need to make sure that the packet
   * is large enough for the timestamp. */
  Alarm(PRINT,"VAL_Validate_NM num_bytes=%d\n",num_bytes); 
  Alarm(PRINT,"VAL_Validate_NM size of nm_message=%d\n",sizeof(nm_message)); 
  if (num_bytes < sizeof(signed_message)) {
    VALIDATE_FAILURE("Config msg too small");
    return 0;
  }

  if (num_bytes !=  sizeof(nm_message)) {
    VALIDATE_FAILURE("config msg size is not as expected");
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

  expected_num_bytes = sizeof(po_ack_message) + 
                        (po_ack->num_ack_parts * sizeof(po_ack_part));

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
    if (part[p].originator < 1 || part[p].originator > VAR.Num_Servers) {
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
  int32u nested_state = DATA.PO.Nested_Ignore_Incarnation;

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
  
  DATA.PO.Nested_Ignore_Incarnation = 1;
  po_aru = (po_aru_signed_message *)(pm+1);
  for (i = 1; i <= pm->num_acks_in_this_message; i++)
  {
    /* If the type is 0 (DUMMY), this may be a NULL vector, i.e., we haven't received a
     * PO_ARU yet from this replica. In either case, we will not process it later */
    if (po_aru->header.type == DUMMY)
      continue;

    if (po_aru->header.type != PO_ARU || !VAL_Validate_Message((signed_message *) po_aru, sizeof(po_aru_signed_message))) {
      VALIDATE_FAILURE("Invalid PO-ARU in Proof Matrix");
      DATA.PO.Nested_Ignore_Incarnation = nested_state;
      return 0;
    }

    po_aru = (po_aru_signed_message *)(po_aru + 1);
  }
  
  DATA.PO.Nested_Ignore_Incarnation = nested_state;
  return 1;
}

int32u VAL_Validate_Pre_Prepare(pre_prepare_message *pp, int32u num_bytes)
{
  int32u expected_size;
  po_aru_signed_message *po_aru;
  int32u i;
  int32u nested_state = DATA.PO.Nested_Ignore_Incarnation;

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

  DATA.PO.Nested_Ignore_Incarnation = 1;
  po_aru = (po_aru_signed_message *)(pp+1);
  for (i = 1; i <= pp->num_acks_in_this_message; i++)
  {
    /* If the type is 0 (DUMMY), this may be a NULL vector, i.e., we haven't received a
     * PO_ARU yet from this replica. In either case, we will not process it later */
    if (po_aru->header.type == DUMMY)
      continue;

    if (po_aru->header.type != PO_ARU || !VAL_Validate_Message((signed_message *) po_aru, sizeof(po_aru_signed_message))) {
      VALIDATE_FAILURE("Invalid PO-ARU in Pre-Prepare");
      DATA.PO.Nested_Ignore_Incarnation = nested_state;
      return 0;
    }

    po_aru = (po_aru_signed_message *)(po_aru + 1);
  }

  DATA.PO.Nested_Ignore_Incarnation = nested_state;
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
  Alarm(DEBUG,"MS2022:Val_Validate_Commit success\n");
  
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
  
  if (rb_init->type != REPORT && rb_init->type != PC_SET && 
      rb_init->type != RESET_VIEWCHANGE && rb_init->type != RESET_NEWVIEW) 
  {
    VALIDATE_FAILURE("RB_Init: incorrect payload type (not report or pc set)");
    return 0;
  }

  if (!VAL_State_Permits_Message(rb_init)) {
    Alarm(DEBUG, "RB_Init: payload type %u not allowed for this state %u\n",
            rb_init->type, DATA.PR.recovery_status[VAR.My_Server_ID]);
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
  
  if (rb_echo->type != REPORT && rb_echo->type != PC_SET &&
      rb_echo->type != RESET_VIEWCHANGE && rb_echo->type != RESET_NEWVIEW) 
  {
    VALIDATE_FAILURE("RB_Echo: incorrect payload type (not report or pc set)");
    return 0;
  }

  if (!VAL_State_Permits_Message(rb_echo)) {
    Alarm(DEBUG, "RB_Echo: payload type %u not allowed for this state %u\n",
            rb_echo->type, DATA.PR.recovery_status[VAR.My_Server_ID]);
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
  
  if (rb_ready->type != REPORT && rb_ready->type != PC_SET &&
      rb_ready->type != RESET_VIEWCHANGE && rb_ready->type != RESET_NEWVIEW) 
  {
    VALIDATE_FAILURE("RB_Ready: incorrect payload type (not report or pc set)");
    return 0;
  }

  if (!VAL_State_Permits_Message(rb_ready)) {
    Alarm(DEBUG, "RB_Ready: payload type %u not allowed for this state %u\n",
            rb_ready->type, DATA.PR.recovery_status[VAR.My_Server_ID]);
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

  if (report->rb_tag.machine_id < 1 || report->rb_tag.machine_id > VAR.Num_Servers) {
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

  if (pc->rb_tag.machine_id < 1 || pc->rb_tag.machine_id > VAR.Num_Servers) {
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
  Alarm(DEBUG,"PC_Set: pre-prepare validation pass\n");
  pp = (pre_prepare_message *)(mess + 1);
  
  /* Construct the complete_pp from the pp we received */
  memset(&complete_pp,0,sizeof(complete_pre_prepare_message));
  complete_pp.seq_num = pp->seq_num;
  complete_pp.view = pp->view;
  memcpy((byte *)&complete_pp.last_executed, &pp->last_executed, sizeof(pp->last_executed));
  memcpy((byte *)&complete_pp.proposal_digest, &pp->proposal_digest, DIGEST_SIZE);
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
    Alarm(DEBUG, "PC_Set: count = %d, needed %d\n", count, 2*VAR.F + VAR.K);
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
  if (num_bytes != sizeof(catchup_request_message)) {
    VALIDATE_FAILURE("Catchup_Request: invalid size");
    return 0;
  }

  return 1;
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
  Alarm(DEBUG,"MS2022: pp->seq_num=%u, ord_cert->seq_num=%u\n",pp->seq_num,ord_cert->seq_num);

  /* Construct the complete_pp from the pp we received */
  //MS2022
  memset(&complete_pp,0,sizeof(complete_pre_prepare_message));
  complete_pp.seq_num = pp->seq_num;
  complete_pp.view = pp->view;
  memcpy((byte *)&complete_pp.last_executed, &pp->last_executed, sizeof(pp->last_executed));
  memcpy((byte *)&complete_pp.proposal_digest, &pp->proposal_digest, DIGEST_SIZE);
  memcpy((byte *)&complete_pp.cum_acks, (byte *)(pp + 1), 
            sizeof(po_aru_signed_message) * pp->num_acks_in_this_message);

  /* Compute the digest of the PP */
  OPENSSL_RSA_Make_Digest((byte*)&complete_pp, sizeof(complete_pre_prepare_message), pp_digest);

  sum_len += msg_size;
  count = 0;

  /* Next, count the number of valid commits */
  /* PRTODO: added extra check to make sure we have at least sizeof(signed_message) to work with */
  // while (sum_len < num_bytes) {    // OLD check
  while (sum_len < num_bytes && (num_bytes - sum_len >= sizeof(signed_message))) {
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
        Alarm(DEBUG,"MS2022:pp_digest\n");
	OPENSSL_RSA_Print_Digest(pp_digest);
        Alarm(DEBUG,"MS2022:cm->digest\n");
	OPENSSL_RSA_Print_Digest(cm->digest);
	VALIDATE_FAILURE("ORD_Certificate: commit digest does not match ord_cert digest");
        return 0;
    }

        Alarm(DEBUG,"MS2022:pp_digest or cm->digest after equal\n");
	//OPENSSL_RSA_Print_Digest(pp_digest);
    sum_len += msg_size;
    count++;
  }

  /* Finally, do last sanity check on overall length and number of commits */
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
  //DATA.PO.Nested_Ignore_Incarnation = 1;
  //DATA.PO.Nested_Ignore_Incarnation = 0;
  signed_message *pr, *pa;
  int32u sum_len, msg_size, count;
  po_request_message *pr_specific;
  po_ack_message *pa_specific;
  po_ack_part *part;
  byte pr_digest[DIGEST_SIZE];
  int32u *incarnation_vector = NULL;
  int i;
  int32u nested_state = DATA.PO.Nested_Ignore_Incarnation;

  if (num_bytes < sizeof(po_certificate_message)) {
    VALIDATE_FAILURE("PO_Certificate: invalid size");
    return 0;
  }

  sum_len = sizeof(po_certificate_message);
  
  /* First, check the po-request, which should appear first */
  pr       = (signed_message *)(po_cert + 1);
  msg_size = UTIL_Message_Size(pr);

  if (pr->type != PO_REQUEST) {
    VALIDATE_FAILURE("PO_Certificate: first message not a po-request");
    return 0;
  }
  if (msg_size > num_bytes - sum_len) {
    VALIDATE_FAILURE("PO_Certificate: po-request too large");
    return 0;
  }

  DATA.PO.Nested_Ignore_Incarnation = 1;
  if (!VAL_Validate_Message(pr, msg_size)) {
    VALIDATE_FAILURE("PO_Certificate: po-request did not pass VAL function");
    DATA.PO.Nested_Ignore_Incarnation = nested_state;
    return 0;
  }
  DATA.PO.Nested_Ignore_Incarnation = nested_state;
  
  pr_specific = (po_request_message *)(pr + 1);
  if (PRE_ORDER_Seq_Compare(pr_specific->seq, po_cert->seq) != 0) {
    VALIDATE_FAILURE("PO_Certificate: po-request seq_num does not match po_cert seq_num");
    return 0;
  }

  /* Make PO-Request digest for comparisons */
  OPENSSL_RSA_Make_Digest((byte *)pr, msg_size, pr_digest);

  sum_len += msg_size;
  count = 0;
  pa = pr; /* This gets advanced in the while loop below */

  /* Next, count the number of valid po-acks */
  while (sum_len < num_bytes && (num_bytes - sum_len >= sizeof(signed_message))) {
    pa       = (signed_message *)((char*)pa + msg_size);
    msg_size = UTIL_Message_Size(pa);

    if (pa->type != PO_ACK) {
      VALIDATE_FAILURE("PO_Certificate: non-po-ack message present");
      return 0;
    }
    if (msg_size > num_bytes - sum_len) {
      VALIDATE_FAILURE("PO_Certificate: po-ack too large");
      return 0;
    }
    DATA.PO.Nested_Ignore_Incarnation = 1;
    if (!VAL_Validate_Message(pa, msg_size)) {
      VALIDATE_FAILURE("PO_Certificate: po-ack did not pass VAL function");
      DATA.PO.Nested_Ignore_Incarnation = nested_state;
      return 0;
    }
    DATA.PO.Nested_Ignore_Incarnation = nested_state;

    pa_specific = (po_ack_message *)(pa + 1);
    part = (po_ack_part *)(pa_specific + 1);
    /* Need to make sure all preinstall vectors match, so grab the first one
     * and we'll compare all the rest to that one */
    if (count == 0) {
        incarnation_vector = pa_specific->preinstalled_incarnations;
    } else {
        if (memcmp(pa_specific->preinstalled_incarnations, incarnation_vector,
                   sizeof(int32u) * VAR.Num_Servers) != 0) {
            VALIDATE_FAILURE("PO_Certificate: incarnation vector mismatch");
            return 0;
        }
    }

    for (i = 0; i < pa_specific->num_ack_parts; i++)
    {
        if (part[i].originator == pr->machine_id && 
            PRE_ORDER_Seq_Compare(part[i].seq, pr_specific->seq) == 0)
        {
            if (!OPENSSL_RSA_Digests_Equal(part[i].digest, pr_digest)) {
                VALIDATE_FAILURE("PO_Certificate: po-ack digest does not match po-request");
                return 0;
            }
            break; /* We found a part that matches the po-request */
        }
    }
    if (i == pa_specific->num_ack_parts) {
        VALIDATE_FAILURE("PO_Certificate: po-ack does not contain part matching po-request");
        return 0;
    }

    sum_len += msg_size;
    count++;
  }

  /* Finally, do last sanity check on overall length and number of acks */
  if (sum_len != num_bytes) {
    VALIDATE_FAILURE("PO_Certificate: total bytes in message does not match num_bytes");
    return 0;
  }
  if (count != 2*VAR.F + VAR.K + 1) {
    VALIDATE_FAILURE("PO_Certificate: not 2f+k+1 po-ack messages inside the cert");
    Alarm(PRINT, "VAL_PO_Certificate: count = %d, needed %d\n", count, 2*VAR.F + VAR.K + 1);
    return 0;
  }

  return 1;
}

int32u VAL_Validate_Jump(jump_message *jump, int32u num_bytes)
{
  signed_message *oc, *rc;
  int32u sum_len, msg_size;
  int32u nested_state = DATA.PO.Nested_Ignore_Incarnation;

  /* Validate size */
  if (num_bytes < sizeof(jump_message)) {
    VALIDATE_FAILURE("Jump: message too small");
    return 0;
  }
  sum_len = sizeof(jump_message);

  /* Validate ordinal certificate if needed (i.e. if seq > 0) */
  if (jump->seq_num > 0) {
    oc = (signed_message *)(jump + 1);
    msg_size = UTIL_Message_Size(oc);

    if (oc->type != ORD_CERT) {
      VALIDATE_FAILURE("Jump: first message not ord cert");
      return 0;
    }
    if (msg_size > num_bytes - sum_len) {
      VALIDATE_FAILURE("Jump: ord cert too large");
      return 0;
    }
    DATA.PO.Nested_Ignore_Incarnation = 1;
    if (!VAL_Validate_Message(oc, msg_size)) {
      VALIDATE_FAILURE("Jump: ord cert did not validate");
      DATA.PO.Nested_Ignore_Incarnation = nested_state;
      return 0;
    }
    DATA.PO.Nested_Ignore_Incarnation = nested_state;
    sum_len += msg_size;
  }

  /* Validate reset certificate */
  rc = (signed_message *)((char*)jump + sum_len);
  msg_size = UTIL_Message_Size(rc);

  if (rc->type != RESET_CERT) {
    VALIDATE_FAILURE("Jump: type mismatch; expecting reset cert");
    return 0;
  }
  if (msg_size > num_bytes - sum_len) {
    VALIDATE_FAILURE("Jump: reset cert too large");
    return 0;
  }
  if (!VAL_Validate_Message(rc, msg_size)) {
    VALIDATE_FAILURE("Jump: reset cert did not validate");
    return 0;
  }
  sum_len += msg_size;

  /* Sanity check total length */
  if (sum_len != num_bytes) {
    VALIDATE_FAILURE("Jump: total length does not match");
    return 0;
  }

  return 1;
}

int32u VAL_Validate_New_Incarnation(new_incarnation_message *new_inc, int32u num_bytes)
{
  if (num_bytes != sizeof(new_incarnation_message)) {
    VALIDATE_FAILURE("New_Incarnation: incorrect size");
    Alarm(PRINT, "New_Incarnation: (got %u, should be %u)\n",
          num_bytes, sizeof(new_incarnation_message));
    return 0;
  }
  return 1;
}

int32u VAL_Validate_Incarnation_Ack(incarnation_ack_message *inc_ack, int32u num_bytes)
{
  if (num_bytes != sizeof(incarnation_ack_message)) {
    VALIDATE_FAILURE("Incarnation_Ack: incorrect size");
    Alarm(PRINT, "Incarnation_Ack: (got %u, should be %u)\n",
          num_bytes, sizeof(incarnation_ack_message));
    return 0;
  }
  return 1;
}

int32u VAL_Validate_Incarnation_Cert(incarnation_cert_message *inc_cert, int32u num_bytes, int32u machine_id, int32u incarnation)
{
  signed_message *ni, *ia;
  incarnation_ack_message *ia_specific;
  int32u msg_size, sum_len, count;
  byte ni_digest[DIGEST_SIZE];
  int32u nested_state = DATA.PO.Nested_Ignore_Incarnation;

  /* Validate size (note that incarnation_cert_message is currently empty, so
   * this should never fail */
  if (num_bytes < sizeof(incarnation_cert_message)) {
    VALIDATE_FAILURE("Incarnation_Cert: msg too small");
    return 0;
  }
  sum_len = sizeof(incarnation_cert_message);

  /* Check the new incarnation message */
  ni = (signed_message *)(inc_cert + 1);
  msg_size = UTIL_Message_Size(ni);

  if (ni->type != NEW_INCARNATION) {
    VALIDATE_FAILURE("Incarnation_Cert: first message not a new incarnation msg");
    return 0;
  }
  if (msg_size > num_bytes - sum_len) {
    VALIDATE_FAILURE("Incarnation_Cert: new incarnation msg too large");
    return 0;
  }

  DATA.PO.Nested_Ignore_Incarnation = 1;
  if (!VAL_Validate_Message(ni, msg_size)) {
    VALIDATE_FAILURE("Incarnation_Cert: new incarnation msg did not pass VAL function");
    DATA.PO.Nested_Ignore_Incarnation = nested_state;
    return 0;
  }
  DATA.PO.Nested_Ignore_Incarnation = nested_state;

  /* Check against incarnation and machine id on outer signed message of
   * incarnation cert */
  if (ni->incarnation != incarnation) {
    VALIDATE_FAILURE("Incarnation_Cert: new incarnation msg incarnation does not match");
    Alarm(PRINT, "Outer incarnation %u, inner %u. Outer sender %u, inner %u\n", incarnation, ni->incarnation, machine_id, ni->machine_id);
    return 0;
  }
  if (ni->machine_id != machine_id) {
    VALIDATE_FAILURE("Incarnation_Cert: new incarnation msg sender does not match");
    return 0;
  }
  
  /* Make new incarnation digest for comparisons */
  OPENSSL_RSA_Make_Digest((byte *)ni, msg_size, ni_digest);

  sum_len += msg_size;
  count = 0;

  /* Next, count the number of valid incarnation acks */
  while (sum_len < num_bytes && (num_bytes - sum_len >= sizeof(signed_message))) {
    ia       = (signed_message *)((char*)inc_cert + sum_len);
    msg_size = UTIL_Message_Size(ia);

    if (ia->type != INCARNATION_ACK) {
      VALIDATE_FAILURE("Incarnation_Certificate: non-incarnation-ack message present");
      return 0;
    }
    if (msg_size > num_bytes - sum_len) {
      VALIDATE_FAILURE("Incarnation_Certificate: incarnation-ack too large");
      return 0;
    }
    DATA.PO.Nested_Ignore_Incarnation = 1;
    if (!VAL_Validate_Message(ia, msg_size)) {
      VALIDATE_FAILURE("Incarnation_Certificate: incarnation ack did not pass VAL function");
      DATA.PO.Nested_Ignore_Incarnation = nested_state;
      return 0;
    }
    DATA.PO.Nested_Ignore_Incarnation = nested_state;

    ia_specific = (incarnation_ack_message *)(ia + 1);
    if (ia_specific->acked_incarnation != incarnation) {
        VALIDATE_FAILURE("Incarnation_Certificate: acked incarnation does not match");
        return 0;
    }
    if (ia_specific->acked_id != machine_id) {
        VALIDATE_FAILURE("Incarnation_Certificate: acked id does not match");
        return 0;
    }
    if (!OPENSSL_RSA_Digests_Equal(ia_specific->digest, ni_digest)) {
        VALIDATE_FAILURE("Incarnation_Certificate: ack digest does not match new incarnation msg");
        return 0;
    }

    sum_len += msg_size;
    count++;
  }

  /* Finally, do last sanity check on overall length and number of acks */
  if (sum_len != num_bytes) {
    VALIDATE_FAILURE("Incarnation_Certificate: total bytes in message does not match num_bytes");
    return 0;
  }
  if (count != 2*VAR.F + VAR.K + 1) {
    VALIDATE_FAILURE("Incarnation_Certificate: not 2f+k+1 inc-ack messages inside the cert");
    Alarm(PRINT, "VAL_Inc_Certificate: count = %d, needed %d\n", count, 2*VAR.F + VAR.K + 1);
    return 0;
  }
  return 1;
}

int32u VAL_Validate_Pending_State(pending_state_message *pend_state, int32u num_bytes)
{
  if (num_bytes != sizeof(pending_state_message)) {
    VALIDATE_FAILURE("Pending_State: incorrect size");
    Alarm(PRINT, "Pending_State: (got %u, should be %u)\n",
          num_bytes, sizeof(pending_state_message));
    return 0;
  }
  return 1;
}

int32u VAL_Validate_Pending_Share(pending_share_message *pend_share, int32u num_bytes)
{
  signed_message *mess;
  int32u msg_size;
  int32u nested_state = DATA.PO.Nested_Ignore_Incarnation;

  /* Check that size is large enough for pending share header */
  if (num_bytes < sizeof(pending_share_message)) {
    VALIDATE_FAILURE("Pending_Share: invalid size");
    return 0;
  }

  /* Validate inner message type */
  if (pend_share->type != PRE_PREPARE && pend_share->type != PO_REQUEST) {
    VALIDATE_FAILURE("Pending_Share: invalid type");
    return 0;
  }

  /* Validate contained message */
  mess = (signed_message *)(pend_share + 1);
  msg_size = UTIL_Message_Size(mess);

  if (msg_size > num_bytes - sizeof(pending_share_message)) {
    VALIDATE_FAILURE("Pending_Share: inner message too large");
    return 0;
  }

  /* We won't install the other replicas incarnations until we collect enough
   * jump messages and pending state/shares from other replicas. Therefore, we
   * don't know what incarnation everyone else is supposed to have yet, so we
   * can't validate the incarnation at this time. We should validate the
   * incarnation/signature before processing the message */
  DATA.PO.Nested_Ignore_Incarnation = 1;
  if (!VAL_Validate_Message(mess, msg_size)) {
    VALIDATE_FAILURE("Pending_Share: inner message did not pass VAL function");
    DATA.PO.Nested_Ignore_Incarnation = nested_state;
    return 0;
  }
  DATA.PO.Nested_Ignore_Incarnation = nested_state;

  if (mess->type != pend_share->type) {
    VALIDATE_FAILURE("Pending_Share: type mismatch");
    return 0;
  }
    
  return 1;
}

int32u VAL_Validate_Reset_Vote(reset_vote_message *reset_vote, int32u num_bytes)
{
  if (num_bytes != sizeof(reset_vote_message)) {
    VALIDATE_FAILURE("Reset_Vote: incorrect size");
    Alarm(PRINT, "Reset_Vote: (got %u, should be %u)\n",
          num_bytes, sizeof(reset_vote_message));
    return 0;
  }
  return 1;
}

int32u VAL_Validate_Reset_Share(reset_share_message *reset_share, int32u num_bytes)
{
  if (num_bytes != sizeof(reset_share_message)) {
    VALIDATE_FAILURE("Reset_Share: incorrect size");
    Alarm(PRINT, "Reset_Share: (got %u, should be %u)\n",
          num_bytes, sizeof(reset_share_message));
    return 0;
  }
  return 1;
}

int32u VAL_Validate_Reset_Proposal(reset_proposal_message *reset_proposal, int32u num_bytes)
{
  signed_message *share;
  /*reset_share_message *share_specific;*/
  int32u sum_len, msg_size, count;

  if (num_bytes < sizeof(reset_proposal_message)) {
    VALIDATE_FAILURE("Reset Proposal: invalid size");
    return 0;
  }

  if (reset_proposal->num_shares < 2*VAR.F + VAR.K + 1) {
    VALIDATE_FAILURE("Reset Proposal: not enough shares");
    return 0;
  }
  if (reset_proposal->num_shares > VAR.Num_Servers) {
    VALIDATE_FAILURE("Reset Proposal: too many shares");
    return 0;
  }

  sum_len = sizeof(reset_proposal_message);
  count = 0;

  while (sum_len < num_bytes && (num_bytes - sum_len >= sizeof(signed_message))) {
    share = (signed_message *)((char *)reset_proposal + sum_len);
    msg_size = UTIL_Message_Size(share);

    if (share->type != RESET_SHARE) {
      VALIDATE_FAILURE("Reset_Proposal: non-reset-share message present");
      return 0;
    }
    if (msg_size > num_bytes - sum_len) {
      VALIDATE_FAILURE("Reset_Proposal: reset share too large");
      return 0;
    }
    if (!VAL_Validate_Message(share, msg_size)) {
      VALIDATE_FAILURE("Reset_Proposal: reset share did not pass VAL function");
      return 0;
    }

    /* Shares only get created once, so view may not necessarily match */
    /* share_specific = (reset_share_message *)(share + 1);
    if (share_specific->view != reset_proposal->view) {
        VALIDATE_FAILURE("Reset Proposal: share view does not match");
        return 0;
    } */

    sum_len += msg_size;
    count++;
    if (count == reset_proposal->num_shares) break;
  }
  
  /* Finally, do last sanity check on overall length and number of shares */
  if (sum_len != num_bytes) {
    VALIDATE_FAILURE("Reset_Proposal: total bytes in message does not match num_bytes");
    return 0;
  }
  if (count != reset_proposal->num_shares) {
    VALIDATE_FAILURE("Reset_Proposal: incorrect number of shares");
    Alarm(PRINT, "Reset_Proposal: count = %d, expected %d\n", count, reset_proposal->num_shares);
    return 0;
  }

  return 1;
}

int32u VAL_Validate_Reset_Prepare(reset_prepare_message *reset_prepare, int32u num_bytes)
{
  if (num_bytes != sizeof(reset_prepare_message)) {
    VALIDATE_FAILURE("Reset_Prepare: incorrect size");
    Alarm(PRINT, "Reset_Prepare: (got %u, should be %u)\n",
          num_bytes, sizeof(reset_prepare_message));
    return 0;
  }
  return 1;
}

int32u VAL_Validate_Reset_Commit(reset_commit_message *reset_commit, int32u num_bytes)
{
  if (num_bytes != sizeof(reset_commit_message)) {
    VALIDATE_FAILURE("Reset_Commit: incorrect size");
    Alarm(PRINT, "Reset_Commit: (got %u, should be %u)\n",
          num_bytes, sizeof(reset_commit_message));
    return 0;
  }
  return 1;
}

int32u VAL_Validate_Reset_NewLeader(reset_newleader_message *reset_nl, int32u num_bytes)
{
  if (num_bytes != sizeof(reset_newleader_message)) {
    VALIDATE_FAILURE("Reset_NewLeader: incorrect size");
    Alarm(PRINT, "Reset_NewLeader: (got %u, should be %u)\n",
          num_bytes, sizeof(reset_newleader_message));
    return 0;
  }
  return 1;
}

int32u VAL_Validate_Reset_NewLeaderProof(reset_newleaderproof_message *reset_nlp, int32u num_bytes)
{
  signed_message *nl;
  /* reset_newleader message *nl_specific; */
  int32u msg_size, sum_len, count;

  if (num_bytes < sizeof(reset_newleaderproof_message)) {
    VALIDATE_FAILURE("Reset NewLeaderProof: invalid size");
    return 0;
  }

  sum_len = sizeof(reset_newleaderproof_message);
  count = 0;

  while (sum_len < num_bytes && (num_bytes - sum_len >= sizeof(signed_message))) {
    nl = (signed_message *)((char *)reset_nlp + sum_len);
    msg_size = UTIL_Message_Size(nl);

    if (nl->type != RESET_NEWLEADER) {
      VALIDATE_FAILURE("Reset_NewLeaderProof: non-reset-newleader message present");
      return 0;
    }
    if (msg_size > num_bytes - sum_len) {
      VALIDATE_FAILURE("Reset_NewLeaderProof: reset newleader msg too large");
      return 0;
    }
    if (!VAL_Validate_Message(nl, msg_size)) {
      VALIDATE_FAILURE("Reset_NewLeaderProof: reset newleader did not pass VAL function");
      return 0;
    }

    /* This is already checked in Process_Reset_NewLeaderProof. Note that we
     * should also be checking that the newleader messages come from different
     * replicas... */
    /*nl_specific = (reset_newleader_message *)(nl + 1);
    if (nl_specific->new_view != reset_nlp->new_view) {
        VALIDATE_FAILURE("Reset_NewLeaderProof: newleader view does not match");
        return 0;
    }*/

    sum_len += msg_size;
    count++;
    if (count == 2*VAR.F + VAR.K + 1) break;
  }
  
  /* Finally, do last sanity check on overall length and number of shares */
  if (sum_len != num_bytes) {
    VALIDATE_FAILURE("Reset_NewLeaderProof: total bytes in message does not match num_bytes");
    return 0;
  }
  if (count != 2*VAR.F + VAR.K + 1) {
    VALIDATE_FAILURE("Reset_NewLeaderProof: incorrect number of newleader msgs");
    return 0;
  }

  return 1;
}

int32u VAL_Validate_Reset_ViewChange(reset_viewchange_message *reset_viewchange, int32u num_bytes)
{
  signed_message *rprop, *rprep;
  reset_proposal_message *rprop_specific;
  reset_prepare_message *rprep_specific;
  int32u msg_size, sum_len, count;
  byte rprop_digest[DIGEST_SIZE];

  /* Validate size */
  if (num_bytes < sizeof(reset_viewchange_message)) {
    VALIDATE_FAILURE("Reset_ViewChange: msg too small");
    return 0;
  }
  sum_len = sizeof(reset_viewchange_message);

  /* If the reset_viewchange does not contain a proposal, validation is easy */
  if (!reset_viewchange->contains_proposal) {
    if (num_bytes != sum_len) {
      VALIDATE_FAILURE("Reset_ViewChange: incorrect size for message not containing proposal");
      return 0;
    } else {
      return 1;
    }
  }

  /* Otherwise, need to validate the reset proposal cert (reset proposal + 2f+k
   * reset_prepares) */
  rprop = (signed_message *)(reset_viewchange + 1);
  msg_size = UTIL_Message_Size(rprop);

  if (rprop->type != RESET_PROPOSAL) {
    VALIDATE_FAILURE("Reset_ViewChange: first message not a reset proposal");
    return 0;
  }
  if (msg_size > num_bytes - sum_len) {
    VALIDATE_FAILURE("Reset_ViewChange: reset proposal too large");
    return 0;
  }
  if (!VAL_Validate_Message(rprop, msg_size)) {
    VALIDATE_FAILURE("Reset_ViewChange: reset proposal did not pass VAL function");
    return 0;
  }
  rprop_specific = (reset_proposal_message *)(rprop + 1);

  /* Make reset proposal digest for comparisons: Note that prepares and commits
   * only digest over content of reset proposal, NOT the full signed message */
  OPENSSL_RSA_Make_Digest((byte *)rprop_specific, rprop->len, rprop_digest);

  sum_len += msg_size;
  count = 0;

  /* Next, count the number of valid reset prepares */
  while (sum_len < num_bytes && (num_bytes - sum_len >= sizeof(signed_message))) {
    rprep    = (signed_message *)((char*)reset_viewchange + sum_len);
    msg_size = UTIL_Message_Size(rprep);

    if (rprep->type != RESET_PREPARE) {
      VALIDATE_FAILURE("Reset_ViewChange: non-reset_prepare message present");
      return 0;
    }
    if (msg_size > num_bytes - sum_len) {
      VALIDATE_FAILURE("Reset_ViewChange: reset prepare too large");
      return 0;
    }
    if (!VAL_Validate_Message(rprep, msg_size)) {
      VALIDATE_FAILURE("Reset_ViewChange: reset prepare did not pass VAL function");
      return 0;
    }

    rprep_specific = (reset_prepare_message *)(rprep + 1);
    if (rprep_specific->view != rprop_specific->view) {
        VALIDATE_FAILURE("Reset_ViewChange: prepare view does not match");
        return 0;
    }
    if (!OPENSSL_RSA_Digests_Equal(rprep_specific->digest, rprop_digest)) {
        VALIDATE_FAILURE("Reset_ViewChange: prepare digest does not match proposal");
        return 0;
    }

    sum_len += msg_size;
    count++;
    if (count == 2*VAR.F + VAR.K) break;
  }

  /* Finally, do last sanity check on overall length and number of prepares */
  if (sum_len != num_bytes) {
    VALIDATE_FAILURE("Reset_ViewChange: total bytes in message does not match num_bytes");
    return 0;
  }
  if (count != 2*VAR.F + VAR.K) {
    VALIDATE_FAILURE("Reset_ViewChange: not 2f+k reset prepare messages inside the cert");
    Alarm(PRINT, "VAL_Reset_ViewChange: count = %d, needed %d\n", count, 2*VAR.F + VAR.K);
    return 0;
  }

  return 1;
}

int32u VAL_Validate_Reset_NewView(reset_newview_message *reset_newview, int32u num_bytes)
{
  if (num_bytes != sizeof(reset_newview_message)) {
    VALIDATE_FAILURE("Reset_NewView: incorrect size");
    Alarm(PRINT, "Reset_NewView: (got %u, should be %u)\n",
          num_bytes, sizeof(reset_newview_message));
    return 0;
  }
  return 1;
}

int32u VAL_Validate_Reset_Certificate(reset_certificate_message *reset_cert, int32u num_bytes)
{
  signed_message *rprop, *rcom;
  reset_proposal_message *rprop_specific;
  reset_commit_message *rcom_specific;
  int32u msg_size, sum_len, count;
  byte rprop_digest[DIGEST_SIZE];

  /* Validate size */
  if (num_bytes < sizeof(reset_certificate_message)) {
    VALIDATE_FAILURE("Reset_Cert: msg too small");
    return 0;
  }
  sum_len = sizeof(reset_certificate_message);

  /* Need to validate the reset proposal cert (reset proposal + 2f+k+1
   * reset_commits) */
  rprop = (signed_message *)(reset_cert + 1);
  msg_size = UTIL_Message_Size(rprop);

  if (rprop->type != RESET_PROPOSAL) {
    VALIDATE_FAILURE("Reset_Cert: first message not a reset proposal");
    return 0;
  }
  if (msg_size > num_bytes - sum_len) {
    VALIDATE_FAILURE("Reset_Cert: reset proposal too large");
    return 0;
  }
  if (!VAL_Validate_Message(rprop, msg_size)) {
    VALIDATE_FAILURE("Reset_Cert: reset proposal did not pass VAL function");
    return 0;
  }
  rprop_specific = (reset_proposal_message *)(rprop + 1);

  /* Make reset proposal digest for comparisons: Note that prepares and commits
   * only digest over content of reset proposal, NOT the full signed message */
  OPENSSL_RSA_Make_Digest((byte *)rprop_specific, rprop->len, rprop_digest);

  sum_len += msg_size;
  count = 0;

  /* Next, count the number of valid reset commits */
  while (sum_len < num_bytes && (num_bytes - sum_len >= sizeof(signed_message))) {
    rcom    = (signed_message *)((char*)reset_cert + sum_len);
    msg_size = UTIL_Message_Size(rcom);

    if (rcom->type != RESET_COMMIT) {
      VALIDATE_FAILURE("Reset_Cert: non-reset_commit message present");
      return 0;
    }
    if (msg_size > num_bytes - sum_len) {
      VALIDATE_FAILURE("Reset_Cert: reset commit too large");
      return 0;
    }
    if (!VAL_Validate_Message(rcom, msg_size)) {
      VALIDATE_FAILURE("Reset_Cert: reset commit did not pass VAL function");
      return 0;
    }

    rcom_specific = (reset_commit_message *)(rcom + 1);
    if (rcom_specific->view != rprop_specific->view) {
        VALIDATE_FAILURE("Reset_Cert: commit view does not match");
        return 0;
    }
    if (!OPENSSL_RSA_Digests_Equal(rcom_specific->digest, rprop_digest)) {
        VALIDATE_FAILURE("Reset_Cert: commit digest does not match proposal");
        return 0;
    }

    sum_len += msg_size;
    count++;
    if (count == 2*VAR.F + VAR.K + 1) break;
  }

  /* Finally, do last sanity check on overall length and number of commits */
  if (count != 2*VAR.F + VAR.K + 1) {
    VALIDATE_FAILURE("Reset_Cert: not 2f+k+1 reset commit messages inside the cert");
    Alarm(PRINT, "VAL_Reset_Cert: count = %d, needed %d\n", count, 2*VAR.F + VAR.K);
    return 0;
  }
  if (sum_len != num_bytes) {
    VALIDATE_FAILURE("Reset_Cert: total bytes in message does not match num_bytes");
    Alarm(PRINT, "sum_len == %u, num_bytes == %u\n", sum_len, num_bytes);
    return 0;
  }

  return 1;
}
