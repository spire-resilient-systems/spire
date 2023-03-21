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

/* Proactive Recovery Functions */

#ifndef PRIME_PROACTIVE_RECOVERY_H
#define PRIME_PROACTIVE_RECOVERY_H

#include "data_structs.h"

#define CERT_PERIODIC 1
#define CERT_CATCHUP  2

#define NO_CATCHUP   0
#define CATCHUP_SEQ  1
#define CATCHUP_JUMP 2

void PR_Initialize_Data_Structure(void);

void PR_Process_Catchup_Request(signed_message *mess);
void PR_Process_ORD_Certificate(signed_message *mess);
void PR_Process_PO_Certificate(signed_message *mess);

void PR_Send_ORD_Cert_Periodically(int dummy, void *dummyp);
void PR_Catchup_Periodically(int dummy, void *dummyp);

#endif /* PRIME_PROACTIVE_RECOVERY_H */
