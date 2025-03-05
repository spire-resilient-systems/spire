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

#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "erasure.h"
#include "data_structs.h"
#include "def.h"
#include "stdutil/stdhash.h"
#include "utility.h"
#include "spu_memory.h"
#include "spu_alarm.h"
#include "process.h"
#include "validate.h"
#include "signature.h"

extern server_data_struct DATA;
extern network_variables  NET;
extern benchmark_struct   BENCH;
extern server_variables   VAR;

/* Initialize the erasure encoding library here */
void ERASURE_Initialize()
{
  /* Call initialization function for EC library */
}

void ERASURE_Clear()
{
  /* Call Clear() function of EC library to clear contents of data structure 
   * before a new encoding or decoding. */
}

void ERASURE_Initialize_Decoding(int32u message_len, int32u message_packets,
				 int32u redundant_packets)
{
  /* Call Initialize_Decoding() function of EC library to give it the 
   * parameters needed to decode. */
}

void ERASURE_Set_Encoded_Part(erasure_part *part)
{
  /*int32u *start_of_part;

  start_of_part = (int32u *)(part+1);*/

  /* Call Set_Encoded_Part() function of EC library to copy the encoded
   * part into the library's buffer before a decoding is done. */
}

void ERASURE_Initialize_Encoding(signed_message *mess, 
				 int32u message_packets, 
				 int32u redundant_packets)
{
  /* Call Initialize_Encoding() function of EC library to copy the
   * message to be encoded into the library's buffer before an
   * encoding is done. */
}

void ERASURE_Encode(int32u *buf)
{
  /* Call the EC library's Encode() function. */
}


int ERASURE_Decode(signed_message *mess)
{
  /* Call the EC library's Decode() function here, which should store
   * the decoded message into mess. Check the return value! */

  return 0;
}

int32u ERASURE_Get_Total_Part_Length()
{
  /* Call the EC library's Get_Total_Part_Length() function to get
   * the number of words in the part (including the index), and then
   * multiply this by word size to get the total number of bytes. */
  return 0;
}
