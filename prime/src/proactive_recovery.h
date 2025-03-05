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

/* Proactive Recovery Functions */

#ifndef PRIME_PROACTIVE_RECOVERY_H
#define PRIME_PROACTIVE_RECOVERY_H

#include "data_structs.h"

#define PR_STARTUP  1 
#define PR_RESET    2
#define PR_RECOVERY 3
#define PR_NORMAL   4

#define NO_RESET_APPLICATION  0
#define RESET_APPLICATION     1

void PR_Initialize_Data_Structure(void);

void PR_Reset_Prime(void);
void PR_Upon_Reset(void);

void PR_Send_Application_Reset(void);
void PR_Start_Recovery(void);
void PR_Resume_Normal_Operation(void);
//void PR_Resume_Normal_Operation(int32u reset_app_flag);

void PR_Process_New_Incarnation(signed_message *mess);

void PR_Process_Incarnation_Ack(signed_message *mess);
void PR_Process_Incarnation_Cert(signed_message *mess);
void PR_Process_Jump(signed_message *mess);
void PR_Process_Pending_State(signed_message *mess);
void PR_Process_Pending_Share(signed_message *mess);

void PR_Send_Pending_State(int32u target, int32u acked_nonce);

void PR_Process_Reset_Vote(signed_message *mess);
void PR_Process_Reset_Share(signed_message *mess);
void PR_Process_Reset_Proposal(signed_message *mess);
void PR_Process_Reset_Prepare(signed_message *mess);
void PR_Process_Reset_Commit(signed_message *mess);
void PR_Process_Reset_NewLeader(signed_message *mess);
void PR_Process_Reset_NewLeaderProof(signed_message *mess);
void PR_Process_Reset_ViewChange(signed_message *mess);
void PR_Process_Reset_NewView(signed_message *mess);
void PR_Process_Reset_Certificate(signed_message *mess);

void PR_Clear_Reset_Data_Structures(void);

#endif /* PRIME_PROACTIVE_RECOVERY_H */
