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

//#include "data_structs.h"

void TC_Read_Partial_Key( int32u server_no, int32u site_id,char *dir );
void TC_Read_Public_Key(char *dir);

int32u TC_Generate_Sig_Share( byte* destination, byte* hash  ); 
void TC_Initialize_Combine_Phase( int32u number );
void TC_Add_Share_To_Be_Combined( int server_no, byte *share );
void TC_Destruct_Combine_Phase( int32u number );
void TC_Combine_Shares( byte *signature_dest, byte *digest );
int32u TC_Verify_Signature( int32u site, byte *signature, byte *digest );
int TC_Check_Share( byte *digest, int32u sender_id );
void TC_Generate(int req_shares, char *directory);
int32u TC_Verify_SM_Signature( int32u site, byte *signature, byte *digest );
void TC_with_args_Generate(int req_shares, char *directory, int faults,int rej_servers,int num_sites);

