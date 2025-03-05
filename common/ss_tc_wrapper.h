/*
 * Spire.
 *
 * The contents of this file are subject to the Spire Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.dsn.jhu.edu/spire/LICENSE.txt 
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis, 
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
 * for the specific language governing rights and limitations under the 
 * License.
 *
 * Spire is developed at the Distributed Systems and Networks Lab,
 * Johns Hopkins University and the Resilient Systems and Societies Lab,
 * University of Pittsburgh.
 *
 * Creators:
 *   Yair Amir            yairamir@cs.jhu.edu
 *   Trevor Aron          taron1@cs.jhu.edu
 *   Amy Babay            babay@pitt.edu
 *   Thomas Tantillo      tantillo@cs.jhu.edu 
 *   Sahiti Bommareddy    sahiti@cs.jhu.edu 
 *   Maher Khan           maherkhan@pitt.edu
 *
 * Major Contributors:
 *   Marco Platania       Contributions to architecture design 
 *   Daniel Qian          Contributions to Trip Master and IDS 
 *
 * Contributors:
 *   Samuel Beckley       Contributions to HMIs
 *
 * Copyright (c) 2017-2025 Johns Hopkins University.
 * All rights reserved.
 *
 * Partial funding for Spire research was provided by the Defense Advanced 
 * Research Projects Agency (DARPA), the Department of Defense (DoD), and the
 * Department of Energy (DoE).
 * Spire is not necessarily endorsed by DARPA, the DoD or the DoE. 
 *
 */

#include "ss_net_wrapper.h"

/* Public definitions */
#define DIGEST_SIZE        20
#define SIGNATURE_SIZE     128
#define PROOF_SIZE         160

void TC_Generate(char *directory);

void TC_Read_Partial_Key( int32u server_no, const char *keys_dir );
void TC_Read_Public_Key( const char *keys_dir );

int32u TC_Generate_Sig_Share( byte *dst_share, byte *dst_proof, byte* hash  ); 
int TC_Check_Share( byte *digest, byte *share, byte *proof, int32u sender_id );

void TC_Initialize_Combine_Phase( int32u number );
void TC_Add_Share_To_Be_Combined( int server_no, byte *share );
void TC_Destruct_Combine_Phase( int32u number );

int32u TC_Combine_Shares( byte *signature_dest, byte *digest );

int32u TC_Verify_Signature( byte *signature, byte *digest );

