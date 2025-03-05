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

/* Pre Order Functions. */

#ifndef PRIME_PRE_ORDER_H
#define PRIME_PRE_ORDER_H

#include "data_structs.h"

void PRE_ORDER_Initialize_Data_Structure (void);
void PRE_ORDER_Upon_Reset (void);
void PRE_ORDER_Garbage_Collect_PO_Slot(int32u server_id, po_seq_pair ps, int erase);
void PRE_ORDER_Periodically(int d1, void *d2);
void PRE_ORDER_Periodic_Retrans(int d1, void *d2);

void PRE_ORDER_Process_Update      (signed_message *mess);
void PRE_ORDER_Process_PO_Request  (signed_message *mess);
void PRE_ORDER_Process_PO_Ack      (signed_message *mess);
void PRE_ORDER_Process_PO_Ack_Part (po_ack_part *part, signed_message *po_ack);
void PRE_ORDER_Process_PO_ARU      (signed_message *mess);
void PRE_ORDER_Process_Proof_Matrix(signed_message *mess);

void PRE_ORDER_Send_PO_Request(void);
void PRE_ORDER_Send_PO_Ack      (void);
void PRE_ORDER_Send_PO_ARU      (void);
void PRE_ORDER_Send_Proof_Matrix(void);

bool PRE_ORDER_Latest_Proof_Updated    (void);
//bool PRE_ORDER_Latest_Proof_Sent       (void);
//void PRE_ORDER_Update_Latest_Proof_Sent(void);

po_seq_pair PRE_ORDER_Proof_ARU (int32u server, po_aru_signed_message *proof);
int32u PRE_ORDER_Update_ARU(void);
void   PRE_ORDER_Update_Cum_ARU(int32u server_id);

int PRE_ORDER_Seq_Compare(po_seq_pair p1, po_seq_pair p2);

#endif
