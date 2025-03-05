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

/* Openssl initiation, sign, and verify functions. These functions can be used
 * to easily use openssl to create RSA signatures and to verify these RSA
 * signatures. The functions listed below use RSA and sha1 digests. */

#ifndef PRIME_OPENSSL_RSA_H
#define PRIME_OPENSSL_RSA_H

#include <stdio.h>
#include "arch.h"

/* Public definitions */
#define DIGEST_SIZE        20
#define SIGNATURE_SIZE     128
#define RSA_CLIENT         1
#define RSA_SERVER         2
#define RSA_NM             3 //MK Reconf: Network Manager
#define RSA_CONFIG_MNGR    4
#define RSA_CONFIG_AGENT   5

/* Public functions */
void OPENSSL_RSA_Init();

void OPENSSL_RSA_Sign( const unsigned char *message, size_t message_length,
		       unsigned char *signature ); 

int OPENSSL_RSA_Verify( const unsigned char *message, size_t message_length,
			unsigned char *signature, int32u server_number, 
			int32u type ); 
 
void OPENSSL_RSA_Read_Keys( int32u my_number, int32u type, const char *dir ); 

void OPENSSL_RSA_Generate_Keys_with_args(int count, const char *keys_dir );

void OPENSSL_RSA_Generate_Keys(void); 

void OPENSSL_RSA_Make_Signature( const unsigned char *digest_value, 
				 unsigned char *signature ); 

int32u OPENSSL_RSA_Verify_Signature( const unsigned char *digest_value, 
				     unsigned char *signature, int32u number, 
				     int32u type ); 

int32u OPENSSL_RSA_Digests_Equal( unsigned char *digest1, 
				  unsigned char *digest2 ); 

void OPENSSL_RSA_Make_Digest( const void *buffer, size_t buffer_size, 
			      unsigned 	char *digest_value ); 

void OPENSSL_RSA_Print_Digest( unsigned char *digest_value ); 


int OPENSSL_RSA_Get_KeySize(const char *pubKeyFile);


void OPENSSL_RSA_Decrypt(const char  *pvtKeyFile,unsigned char *data, int data_len,unsigned char *decrypted_data);


int OPENSSL_RSA_Encrypt(const char *pubKeyFile,unsigned char *data, int data_len, unsigned char * encrypted_data);

int getFileSize(const char * fileName);

#endif

