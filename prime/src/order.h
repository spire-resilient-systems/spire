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

#ifndef PRIME_ORDER_H
#define PRIME_ORDER_H

#include "packets.h"
#include "data_structs.h"

/* What triggers us to call Send_One_Pre_Prepare: either the timer or
 * a PO-ARU message */
#define TIMEOUT_CALLER 1
#define MESSAGE_CALLER 2

#define SLOT_COMMIT     1
#define SLOT_PC_SET     2
#define SLOT_NO_OP      3
#define SLOT_NO_OP_PLUS 4

void ORDER_Periodically(int dummy, void *dummyp);
int32u ORDER_Send_One_Pre_Prepare   (int32u caller);
void   ORDER_Periodic_Retrans            (int d1, void *d2);

void ORDER_Execute_Event(signed_message *event, int32u ord_num, int32u event_idx, int32u event_tot);
void ORDER_Execute_Commit(ord_slot *slot);

void ORDER_Initialize_Data_Structure (void);
void ORDER_Upon_Reset (void);

int32u ORDER_Commit_Matches_Pre_Prepare(signed_message *commit,
                    complete_pre_prepare_message *pp);

void ORDER_Process_Pre_Prepare  (signed_message *mess);
void ORDER_Process_Prepare      (signed_message *mess);
void ORDER_Process_Commit       (signed_message *mess);

void ORDER_Send_Prepares(void);
void ORDER_Adjust_High_Committed(void);
void ORDER_Adjust_High_Prepared(void);
void ORDER_Adjust_ppARU(void);

void ORDER_Update_Forwarding_White_Line (void);
void ORDER_Attempt_To_Garbage_Collect_ORD_Slots();
//void ORDER_Attempt_To_Garbage_Collect_ORD_Slot (int32u seq);
void ORDER_Garbage_Collect_ORD_Slot (ord_slot *slot, int erase);

void ORDER_Attempt_To_Execute_Pending_Commits (int dummy, void *dummyp);

void ORDER_Cleanup(void);

#endif
