/*
 * Spines.
 *
 * The contents of this file are subject to the Spines Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.spines.org/LICENSE.txt
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Creators of Spines are:
 *  Yair Amir, Claudiu Danilov, John Schultz, Daniel Obenshain,
 *  Thomas Tantillo, and Amy Babay.
 *
 * Copyright (c) 2003-2020 The Johns Hopkins University.
 * All rights reserved.
 *
 * Major Contributor(s):
 * --------------------
 *    John Lane
 *    Raluca Musaloiu-Elefteri
 *    Nilo Rivera 
 * 
 * Contributor(s): 
 * ----------------
 *    Sahiti Bommareddy 
 *
 */

#ifndef SECURITY_H
#define SECURITY_H

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <spu_scatter.h>

#define SECURITY_MIN_KEY_SIZE   16
#define SECURITY_MAX_KEY_SIZE   16

#define SECURITY_MIN_BLOCK_SIZE 16
#define SECURITY_MAX_BLOCK_SIZE 16

#define SECURITY_MIN_HMAC_SIZE  32
#define SECURITY_MAX_HMAC_SIZE  32 

#define SECURITY_MAX_OVERHEAD_SIZE (SECURITY_MAX_BLOCK_SIZE /* padding */ + SECURITY_MAX_BLOCK_SIZE /* iv */ + SECURITY_MAX_HMAC_SIZE /* hmac */)

int Sec_init(void);

int Sec_lock_msg(const sys_scatter * const msg,
                 unsigned char * const     dst_begin,
                 const size_t              dst_size,
                 EVP_CIPHER_CTX * const    encrypt_ctx,
                 HMAC_CTX       * const    hmac_ctx);

int Sec_unlock_msg(const sys_scatter * const msg,
                   unsigned char * const     dst_begin,
                   const size_t              dst_size,
                   EVP_CIPHER_CTX * const    decrypt_ctx,
                   HMAC_CTX       * const    hmac_ctx);

void Sec_unit_test(void);

#endif
