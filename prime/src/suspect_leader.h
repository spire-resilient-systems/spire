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

/* Suspect Leader Functions */

#ifndef PRIME_SUSPECT_LEADER_H
#define PRIME_SUSPECT_LEADER_H

#include "data_structs.h"

void SUSPECT_Initialize_Data_Structure(void);
void SUSPECT_Initialize_Upon_View_Change(void);
void SUSPECT_Restart_Timed_Functions(void);
void SUSPECT_Upon_Reset(void);

void SUSPECT_Process_TAT_Measure     (signed_message *mess);
void SUSPECT_Process_RTT_Ping        (signed_message *mess);
void SUSPECT_Process_RTT_Pong        (signed_message *mess);
void SUSPECT_Process_RTT_Measure     (signed_message *mess);
void SUSPECT_Process_TAT_UB          (signed_message *mess);

void SUSPECT_Suspect_Leader(void);

void SUSPECT_Process_New_Leader      (signed_message *mess);
void SUSPECT_Process_New_Leader_Proof(signed_message *mess);

void SUSPECT_New_Leader_Periodically(int dummy, void *dummyp);
void SUSPECT_New_Leader_Proof_Periodically(int dummy, void *dummyp);

#endif /* PRIME_SUSPECT_LEADER_H */
