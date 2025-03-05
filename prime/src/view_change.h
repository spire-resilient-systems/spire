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
 *
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

/* View Change Functions */

#ifndef PRIME_VIEW_CHANGE_H
#define PRIME_VIEW_CHANGE_H

#include "data_structs.h"

void VIEW_Initialize_Data_Structure(void);
void VIEW_Initialize_Upon_View_Change(void);
void VIEW_Upon_Reset(void);
void VIEW_Periodic_Retrans(int d1, void *d2);

void VIEW_Start_View_Change(void);

void VIEW_Process_Report(signed_message *mess);
void VIEW_Process_PC_Set(signed_message *mess);
void VIEW_Check_Complete_State(int32u server_id);

void VIEW_Process_VC_List       (signed_message *mess);
void VIEW_Process_VC_Partial_Sig(signed_message *mess);
void VIEW_Process_VC_Proof      (signed_message *mess);
void VIEW_Process_Replay        (signed_message *mess);
void VIEW_Process_Replay_Prepare(signed_message *mess);
void VIEW_Process_Replay_Commit (signed_message *mess);

#endif /* PRIME_VIEW_CHANGE_H */
