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

/* Catchup Functions */

#ifndef PRIME_CATCHUP_H
#define PRIME_CATCHUP_H

#include "data_structs.h"

#define FLAG_CATCHUP    1
#define FLAG_JUMP       2
#define FLAG_PERIODIC   3
#define FLAG_RECOVERY   4

void CATCH_Initialize_Data_Structure(void);
void CATCH_Reset_View_Change_Catchup(void);
void CATCH_Upon_Reset(void);

void CATCH_Process_Catchup_Request(signed_message *mess);
void CATCH_Process_ORD_Certificate(signed_message *mess);
void CATCH_Process_PO_Certificate(signed_message *mess);
void CATCH_Process_Jump(signed_message *mess);

void CATCH_Send_Catchup_Request_Periodically(int dummy, void *dummyp);
void CATCH_Send_ORD_Cert_Periodically(int dummy, void *dummyp);
void CATCH_Schedule_Catchup(void);
void CATCH_Jump_Ahead(signed_message *ord_cert);

#endif /* PRIME_CATCHUP_H */
