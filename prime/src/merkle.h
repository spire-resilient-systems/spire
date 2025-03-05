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

#ifndef PRIME_MERKLE_H
#define PRIME_MERKLE_H

#include "arch.h"
#include "util_dll.h"
#include "data_structs.h"

void MT_Test (void);
void MT_Clear(void);
void MT_Clear_Verify(void);
void MT_Put_Mess_Digest(int32 n, byte *digest); 
byte* MT_Make_Digest_From_Set(int32 mess_num, byte *digests, 
			      byte *mess_digest, int32u mtnum); 
byte* MT_Make_Digest_From_All(void); 
int32 MT_Verify( signed_message *mess ); 
int32 MT_Set_Num(int32 n); 
int32 MT_Digests(void); 
int32 MT_Digests_( int32 n ); 
void MT_Extract_Set( int32 mess_num, signed_message *mess ); 

byte* MT_Make_Digest_From_List(dll_struct *dll);

#endif
