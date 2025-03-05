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

/* Process messages by both (i) applying them to the data structures and 
 * (potentially) creating and dispatching new messages as a result of applying. 
 * These functions take a message that has first been validated. */
#include <assert.h>
#include <string.h>

#include "data_structs.h"
#include "process.h"
#include "spu_memory.h"
#include "spu_alarm.h"
#include "error_wrapper.h"
#include "utility.h"
#include "order.h"
#include "recon.h"
#include "pre_order.h"
#include "suspect_leader.h"
#include "reliable_broadcast.h"
#include "view_change.h"
#include "catchup.h"
#include "proactive_recovery.h"
#include "nm_process.h"

/* Gobally Accessible Variables */
extern server_variables   VAR;
extern server_data_struct DATA;
extern benchmark_struct   BENCH;

/* Process a signed message */
void PROCESS_Message(signed_message *mess) 
{

  util_stopwatch profile_sw;
  UTIL_Stopwatch_Start(&profile_sw);

  switch (mess->type) {   

  case UPDATE:
    PRE_ORDER_Process_Update(mess);
    break;

  case PO_REQUEST:
    Alarm(DEBUG,"Processing PO_Request\n");
    PRE_ORDER_Process_PO_Request(mess);
    break;
    
  case PO_ACK:
    Alarm(DEBUG,"Processing PO_Ack\n");
    PRE_ORDER_Process_PO_Ack(mess);
    break;

  case PO_ARU:
    
    /* If the delay attack is used, the leader ignores PO-ARU messages 
     * and only handles proof matrix messages when it needs to. */
#if DELAY_ATTACK
    if(!UTIL_I_Am_Leader())
      PRE_ORDER_Process_PO_ARU(mess);
#else
    PRE_ORDER_Process_PO_ARU(mess);
#endif
    break;

  case PROOF_MATRIX:

    /* If the delay attack is used, the leader adds the proof matrix
     * message to a queue and only processes it when it needs to, when
     * it comes time to send the Pre-Prepare. */
#if DELAY_ATTACK
    if (UTIL_I_Am_Leader()) {
        UTIL_DLL_Add_Data(&DATA.PO.proof_matrix_dll, mess);
        Alarm(DEBUG, "ADD\n"  );  
    }
#else
    PRE_ORDER_Process_Proof_Matrix(mess);
#endif
    break;
    
  case PRE_PREPARE:
    ORDER_Process_Pre_Prepare(mess);
    break;

  case PREPARE:
    ORDER_Process_Prepare(mess);
    break;

  case COMMIT:
    ORDER_Process_Commit(mess);
    break;

  case RECON:
    RECON_Process_Recon(mess);
    break;

  case TAT_MEASURE:
    SUSPECT_Process_TAT_Measure(mess);
    break;

  case RTT_PING:
    SUSPECT_Process_RTT_Ping(mess);
    break;

  case RTT_PONG:
    SUSPECT_Process_RTT_Pong(mess);
    break;

  case RTT_MEASURE:
    SUSPECT_Process_RTT_Measure(mess);
    break;
    
  case TAT_UB:
    SUSPECT_Process_TAT_UB(mess);
    break;

  case NEW_LEADER:
    SUSPECT_Process_New_Leader(mess);
    break;

  case NEW_LEADER_PROOF:
    SUSPECT_Process_New_Leader_Proof(mess);
    break;

  case RB_INIT:
    RB_Process_Init(mess);
    break;

  case RB_ECHO:
    RB_Process_Echo(mess);
    break;

  case RB_READY:
    RB_Process_Ready(mess);
    break;

  case REPORT:
    VIEW_Process_Report(mess);
    break;

  case PC_SET:
    VIEW_Process_PC_Set(mess);
    break;

  case VC_LIST:
    VIEW_Process_VC_List(mess);
    break;

  case VC_PARTIAL_SIG:
    VIEW_Process_VC_Partial_Sig(mess);
    break;

  case VC_PROOF:
    VIEW_Process_VC_Proof(mess);
    break;

  case REPLAY:
    VIEW_Process_Replay(mess);
    break;

  case REPLAY_PREPARE:
    VIEW_Process_Replay_Prepare(mess);
    break;

  case REPLAY_COMMIT:
    VIEW_Process_Replay_Commit(mess);
    break;

  case CATCHUP_REQUEST:
    CATCH_Process_Catchup_Request(mess);
    break;

  case ORD_CERT:
    CATCH_Process_ORD_Certificate(mess);
    break;

  case PO_CERT:
    CATCH_Process_PO_Certificate(mess);
    break;

  case JUMP:
    CATCH_Process_Jump(mess);
    break;

  case NEW_INCARNATION:
    PR_Process_New_Incarnation(mess);
    break;

  case INCARNATION_ACK:
    PR_Process_Incarnation_Ack(mess);
    break;

  case INCARNATION_CERT:
    PR_Process_Incarnation_Cert(mess);
    break;

  case PENDING_STATE:
    PR_Process_Pending_State(mess);
    break;

  case PENDING_SHARE:
    PR_Process_Pending_Share(mess);
    break;
  
  case RESET_VOTE:
    PR_Process_Reset_Vote(mess);
    break;

  case RESET_SHARE:
    PR_Process_Reset_Share(mess);
    break;

  case RESET_PROPOSAL:
    PR_Process_Reset_Proposal(mess);
    break;

  case RESET_PREPARE:
    PR_Process_Reset_Prepare(mess);
    break;

  case RESET_COMMIT:
    PR_Process_Reset_Commit(mess);
    break;

  case RESET_NEWLEADER:
    PR_Process_Reset_NewLeader(mess);
    break;

  case RESET_NEWLEADERPROOF:
    PR_Process_Reset_NewLeaderProof(mess);
    break;

  case RESET_VIEWCHANGE:
    PR_Process_Reset_ViewChange(mess);
    break;

  case RESET_NEWVIEW:
    PR_Process_Reset_NewView(mess);
    break;

  case RESET_CERT:
    PR_Process_Reset_Certificate(mess);
    break;
  case CLIENT_OOB_CONFIG_MSG:
    Alarm(PRINT,"MS2022: Received OOB Config Msg\n");
	Process_OOB_NM_MSG(mess);
	break;


  default:
    Alarm(PRINT, "Unexpected message type in PROCESS message: %d\n", mess->type);
    return;
  }

  UTIL_Stopwatch_Stop(&profile_sw);
  if (UTIL_Stopwatch_Elapsed(&profile_sw) >= 0.002) {
    Alarm(DEBUG, "PROF PROC: %s took %f s\n", 
            UTIL_Type_To_String(mess->type), UTIL_Stopwatch_Elapsed(&profile_sw));
    BENCH.profile_count[mess->type]++;
  }
}
