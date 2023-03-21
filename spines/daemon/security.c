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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include <openssl/rand.h>

#include "arch.h"
#include "spu_alarm.h"
#include "spu_events.h"
#include "intrusion_tol_udp.h"
#include "security.h"

/* ------------------------------------------------------------------------------------------ */

static EVP_CIPHER_CTX *IV_Ctx;
static unsigned char  IV_Counter[SECURITY_MAX_BLOCK_SIZE];

/* Sec_gen_IV -------------------------------------------------------------------------------
   Returns 0 on success, non-zero on error.
   ------------------------------------------------------------------------------------------ */

static int Sec_gen_IV(unsigned char *iv, unsigned iv_len)
{
    int            ret     = -1;
    unsigned char *iv_end  = iv + iv_len;
    unsigned       blk_len = EVP_CIPHER_CTX_block_size(IV_Ctx);
    unsigned char  blk[SECURITY_MAX_BLOCK_SIZE];
    int            tmp;
    int            i;

    assert(blk_len > 0);  /* NOTE: assumes we are doing block encryption */
    
    for (; iv < iv_end; iv += blk_len)
    {
        /* encrypt IV_Counter */
    
        if (EVP_EncryptUpdate(IV_Ctx, blk, (tmp = (int) sizeof(blk), &tmp), IV_Counter, blk_len) != 1)
        { assert(0); goto FAIL; }

        assert(tmp == blk_len);
    
        /* increment IV_Counter */
    
        for (i = 0; i < (int) sizeof(IV_Counter) && ++IV_Counter[i] == 0; ++i);

        /* copy encrypted bytes into iv */

        if (iv + blk_len > iv_end)
            blk_len = (unsigned) (iv_end - iv);

        memcpy(iv, blk, blk_len);
    }

    ret = 0;
  
FAIL:
    return ret;
}

/* Sec_init ---------------------------------------------------------------------------------
   Returns zero on success, non-zero on failure.
   ------------------------------------------------------------------------------------------ */

int Sec_init(void) 
{
    unsigned char iv_key[SECURITY_MAX_KEY_SIZE] = { 0 };

    OpenSSL_add_all_algorithms();
    IV_Ctx = EVP_CIPHER_CTX_new();
    if (IV_Ctx == NULL)
        Alarmp(SPLOG_FATAL, SECURITY | EXIT, "Sec_init: IV_Ctx = EVP_CIPHER_CTX_new() failed\n");
    
    /* NOTE: we use IV_Ctx = aes-128-ecb(iv_key) on IV_Counter to implement a CTR-like mode for generating unpredictable IVs */
  
    if (RAND_bytes(iv_key, sizeof(iv_key)) != 1 || RAND_bytes(IV_Counter, sizeof(IV_Counter)) != 1)
        Alarmp(SPLOG_FATAL, SECURITY | EXIT, "Sec_init: RAND_bytes(iv_key, IV_Counter) failed\n");
  
    if (EVP_EncryptInit_ex(IV_Ctx, EVP_aes_128_ecb(), NULL, iv_key, NULL) != 1 || EVP_CIPHER_CTX_set_padding(IV_Ctx, 0) != 1)
        Alarmp(SPLOG_FATAL, SECURITY | EXIT, "Sec_init: EVP_EncryptInit_ex(IV_Ctx) failed\n");

    return 0;
}

/* Sec_lock_msg -----------------------------------------------------------------------------
   Returns the non-negative number of bytes written to dst_begin on
   success, or a negative return on failure.

   TODO: Find a better approach (possibly external to these fcns) that only makes copies if
   necessary.  e.g. - If we are just HMAC'ing, then it is unnecessary to copy the message.
   ------------------------------------------------------------------------------------------ */

int Sec_lock_msg(const sys_scatter * const msg,
                 unsigned char * const     dst_begin,
                 const size_t              dst_size,
                 EVP_CIPHER_CTX * const    encrypt_ctx,
                 HMAC_CTX       * const    hmac_ctx)
{
    int            ret;
    const int      blk_len = EVP_CIPHER_CTX_block_size(encrypt_ctx);
    
    unsigned char *iv     = NULL;
    const int      iv_len = EVP_CIPHER_CTX_iv_length(encrypt_ctx);
    unsigned char  iv_buf[SECURITY_MAX_BLOCK_SIZE] = { 0 };
    
    unsigned       local_hmac_len = SECURITY_MAX_HMAC_SIZE;
    unsigned char  local_hmac[SECURITY_MAX_HMAC_SIZE] = { 0 };
    
    unsigned char        *dst     = dst_begin;
    unsigned char * const dst_end = dst_begin + dst_size;
    int                   dst_len;
    int                   i;

    if (blk_len < 0 || iv_len < 0)
    { assert(0); goto FAIL; }

    if (Conf_IT_Link.Encrypt)
    {
        /* generate IV if needed */
  
        if (iv_len > 0)
        {
            iv = iv_buf;
            
            if (Sec_gen_IV(iv, iv_len))
            { assert(0); goto FAIL; }
        }
  
        /* encrypt body of msg */

        if (EVP_EncryptInit_ex(encrypt_ctx, NULL, NULL, NULL, iv) != 1)
        { assert(0); goto FAIL; }

        for (dst = dst_begin, ret = 0, i = 0; i < msg->num_elements; dst += dst_len, ret += msg->elements[i].len, ++i)
        {
            if (dst + msg->elements[i].len + blk_len - 1 > dst_end)
                goto FAIL;
            
            if (EVP_EncryptUpdate(encrypt_ctx, dst, (dst_len = 0, &dst_len), (unsigned char*) msg->elements[i].buf, (int) msg->elements[i].len) != 1 || dst_len < 0)
            { assert(0); goto FAIL; }
        }

        if (dst + blk_len > dst_end)
            goto FAIL;
        
        if (EVP_EncryptFinal_ex(encrypt_ctx, dst, (dst_len = 0, &dst_len)) != 1 || dst_len < 0)
        { assert(0); goto FAIL; }

        dst += dst_len;

        if ((int) (dst - dst_begin) < ret || (int) (dst - dst_begin) > ret + blk_len)  /* NOTE: assumes no compression / inflation and at most 1 block of padding */
        { assert(0); goto FAIL; }
        
        /* append IV */

        if (dst + iv_len > dst_end)
            goto FAIL;

        memcpy(dst, iv, iv_len);
        dst += iv_len;

        /* compute HMAC of entire body (including IV) */

        HMAC_Init_ex(hmac_ctx, NULL, 0, NULL, NULL);
        HMAC_Update(hmac_ctx, dst_begin, (int) (dst - dst_begin));
        HMAC_Final(hmac_ctx, local_hmac, &local_hmac_len);  

        /* append HMAC */

        if (local_hmac_len < SECURITY_MIN_HMAC_SIZE || local_hmac_len > SECURITY_MAX_HMAC_SIZE)
        { assert(0); goto FAIL; }
        
        if (dst + local_hmac_len > dst_end)
            goto FAIL;

        memcpy(dst, local_hmac, local_hmac_len);
        dst += local_hmac_len;
    }
    else
    {
        /* compute HMAC of msg */
        
        HMAC_Init_ex(hmac_ctx, NULL, 0, NULL, NULL);

        for (dst = dst_begin, i = 0; i < msg->num_elements; dst += msg->elements[i].len, ++i)
        {
            if (dst + msg->elements[i].len > dst_end)
                goto FAIL;
            
            HMAC_Update(hmac_ctx, (unsigned char*) msg->elements[i].buf, msg->elements[i].len);
            memcpy(dst, msg->elements[i].buf, msg->elements[i].len);
        }
        
        HMAC_Final(hmac_ctx, local_hmac, &local_hmac_len);

        if (local_hmac_len < SECURITY_MIN_HMAC_SIZE || local_hmac_len > SECURITY_MAX_HMAC_SIZE)
        { assert(0); goto FAIL; }
        
        if (dst + local_hmac_len > dst_end)
            goto FAIL;

        /* append HMAC */

        memcpy(dst, local_hmac, local_hmac_len);
        dst += local_hmac_len;
    }

    /* set return value */

    ret = (int) (dst - dst_begin);
    
    assert(ret >= 0);
    goto END;

    /* error handling and return */
    
FAIL:
    ret = -1;

END:
    return ret;
}

/* Sec_unlock_msg ---------------------------------------------------------------------------
   Returns non-negative number of bytes written to dst_begin on
   success, or a negative return on failure.

   TODO: Find a better approach (possibly external to these fcns) that only makes copies if
   necessary.  e.g. - If we are just HMAC'ing, then it is unnecessary to copy the message.
   ------------------------------------------------------------------------------------------ */

int Sec_unlock_msg(const sys_scatter * const msg,
                   unsigned char * const     dst_begin,
                   const size_t              dst_size,
                   EVP_CIPHER_CTX * const    decrypt_ctx,
                   HMAC_CTX       * const    hmac_ctx)
{
    int            ret;
    int            err     = 0;    
    const int      blk_len = EVP_CIPHER_CTX_block_size(decrypt_ctx);
    const int      iv_len  = EVP_CIPHER_CTX_iv_length(decrypt_ctx);
  
    const unsigned char *msg_iv;
    const unsigned char *msg_hmac;

    unsigned char  local_hmac[SECURITY_MAX_HMAC_SIZE] = { 0 };
    const int      local_hmac_len = EVP_MD_size(HMAC_CTX_get_md(hmac_ctx));
    unsigned       local_hmac_len2;
    
    unsigned char        *dst     = dst_begin;
    unsigned char * const dst_end = dst_begin + dst_size;
    int                   dst_len;
    int                   i;

    if (blk_len < 0 || iv_len < 0 || local_hmac_len < SECURITY_MIN_HMAC_SIZE || local_hmac_len > SECURITY_MAX_HMAC_SIZE)
    { assert(0); goto FAIL; }

    /* KISS: first copy msg to dst_begin */

    for (dst = dst_begin, i = 0; i < msg->num_elements; dst += msg->elements[i].len, ++i)
    {
        if (dst + msg->elements[i].len > dst_end)
            goto FAIL;
        
        memcpy(dst, msg->elements[i].buf, msg->elements[i].len);
    }

    ret = (int) (dst - dst_begin);
    
    /* extract HMAC from dst_begin */

    if (ret < local_hmac_len)
        goto FAIL;

    ret     -= local_hmac_len;
    dst     -= local_hmac_len;
    msg_hmac = dst;

    /* compute local HMAC */
    
    HMAC_Init_ex(hmac_ctx, NULL, 0, NULL, NULL);
    HMAC_Update(hmac_ctx, dst_begin, ret);
    HMAC_Final(hmac_ctx, local_hmac, &local_hmac_len2);

    if (local_hmac_len2 != local_hmac_len)
    { assert(0); goto FAIL; }

    if (Conf_IT_Link.Encrypt)
    {
        /* extract iv from dst_begin */

        if (ret < iv_len)
            goto FAIL;

        ret    -= iv_len;
        dst    -= iv_len;        
        msg_iv  = dst;

        /* decrypt */
        /* NOTE: assumes no compression / inflation and at most 1 block of padding */
        
        dst = dst_begin;
        
        err |= (EVP_DecryptInit_ex(decrypt_ctx, NULL, NULL, NULL, msg_iv) != 1);
        err |= (EVP_DecryptUpdate(decrypt_ctx, dst, (dst_len = 0, &dst_len), dst, ret) != 1);

        if (dst_len < 0 || (dst += dst_len) > dst_end)
        { assert(0); goto FAIL; }

        err |= (EVP_DecryptFinal_ex(decrypt_ctx, dst, (dst_len = 0, &dst_len)) != 1);

        if (dst_len < 0 || (dst += dst_len) > dst_end ||
            (int) (dst - dst_begin) < ret - blk_len || (int) (dst - dst_begin) > ret)
        { assert(0); goto FAIL; }

        ret = (int) (dst - dst_begin);
    }

    /* compare HMACs; NOTE: we don't skip decrypting if HMACs don't match to mitigate timing attacks */
    
    for (i = 0; i < local_hmac_len; ++i)
        err |= msg_hmac[i] ^ local_hmac[i]; 

    if (err)
        goto FAIL;

    assert(err == 0 && ret >= 0);
    goto END;

    /* error handling and return */
    
FAIL:
    ret = -1;

END:
    return ret;
}

/* Sec_diff_msg -----------------------------------------------------------------------------
   Returns the number of byte differences between two scatters.
   ------------------------------------------------------------------------------------------ */

static unsigned Sec_diff_msg(const sys_scatter *src, const sys_scatter *dst, int die_on_diff)
{
    unsigned si = 0, soff = 0, di = 0, doff = 0, diff = 0, min;
    
    while (si < src->num_elements && di < dst->num_elements)
    {
        assert(soff <= src->elements[si].len && doff <= dst->elements[di].len);
        
        min = src->elements[si].len - soff;

        if (min > dst->elements[di].len - doff)
            min = dst->elements[di].len - doff;

        while (min-- > 0)
            if (src->elements[si].buf[soff++] != dst->elements[di].buf[doff++])
            {
                ++diff;
                if (die_on_diff) Alarmp(SPLOG_FATAL, SECURITY | EXIT, "Sec_diff_msg:%d: round trip failed!\n", __LINE__);
            }

        if (soff >= src->elements[si].len)
        {
            ++si;
            soff = 0;
        }

        if (doff >= dst->elements[di].len)
        {
            ++di;
            doff = 0;
        }
    }

    for (; si < src->num_elements; ++si, soff = 0)
    {
        assert(soff <= src->elements[si].len);
        if ((min = src->elements[si].len - soff) > 0 && die_on_diff) Alarmp(SPLOG_FATAL, SECURITY | EXIT, "Sec_diff_msg:%d: round trip failed!\n", __LINE__);
        diff += min;
    }

    for (; di < dst->num_elements; ++di, doff = 0)
    {
        assert(doff <= dst->elements[di].len);
        if ((min = dst->elements[di].len - doff) > 0 && die_on_diff) Alarmp(SPLOG_FATAL, SECURITY | EXIT, "Sec_diff_msg:%d: round trip failed!\n", __LINE__);
        diff += min;
    }

    return diff;
}

/* Sec_run_test ----------------------------------------------------------------------------
   ------------------------------------------------------------------------------------------ */

#define SEC_UNIT_MAX_ELEMS     100
#define SEC_UNIT_MAX_ELEM_SIZE sizeof(packet_body)
#define SEC_UNIT_MAX_BUF_SIZE  (SEC_UNIT_MAX_ELEMS * SEC_UNIT_MAX_ELEM_SIZE + 2 * SECURITY_MAX_BLOCK_SIZE + SECURITY_MAX_HMAC_SIZE)

static char Src_Elems[SEC_UNIT_MAX_ELEMS][SEC_UNIT_MAX_ELEM_SIZE];

static unsigned char Enc_Buf[SEC_UNIT_MAX_BUF_SIZE];  /* scratch buffer */
static unsigned char Dst_Buf[SEC_UNIT_MAX_BUF_SIZE];  /* scratch buffer */

static const char Test_Data[] =
    ("Hey, diddle, diddle,\n"
     "The cat and the fiddle,\n"
     "The cow jumped over the moon;\n"
     "The little dog laughed\n"
     "To see the sport,\n"
     "While the dish ran away with the spoon.\n");
    
static void Sec_run_test(int num_iters, const char *data, size_t data_len, EVP_CIPHER_CTX *encrypt_ctx, EVP_CIPHER_CTX *decrypt_ctx, HMAC_CTX *hmac_ctx)
{
    sys_scatter    src, enc, enc2, dst;
    int            i, j, k;
    int            src_len, enc_len, dst_len, diff;
    sp_time        enc_time = { 0, 0 }, dec_time = { 0, 0 }, t1;
    long           enc_bytes = 0, dec_bytes = 0;

    /* initialize scatters to be similar to what spines will use */
    
    for (i = 0; i < SEC_UNIT_MAX_ELEMS; ++i)
        src.elements[i].buf = &Src_Elems[i][0];

    enc.num_elements     = 1;
    enc.elements[0].buf  = (char*) Enc_Buf;
    enc.elements[0].len  = sizeof(Enc_Buf);
    
    enc2.num_elements    = 2;
    enc2.elements[0].buf = (char*) Enc_Buf;
    enc2.elements[0].len = sizeof(packet_header);
    enc2.elements[1].buf = (char*) Enc_Buf + enc2.elements[0].len;
    enc2.elements[1].len = sizeof(Enc_Buf) - enc2.elements[0].len;

    dst.num_elements     = 1;
    dst.elements[0].buf  = (char*) Dst_Buf;
    dst.elements[0].len  = sizeof(Dst_Buf);
    
    for (i = 0; i < num_iters;)
    {
        /* create a random src msg with at least one element */
        
        src.num_elements = (int) (1 + SEC_UNIT_MAX_ELEMS * (rand() / (1.0 + RAND_MAX)));

        for (j = 0, src_len = 0; j < src.num_elements; ++j)
        {
            /* pick a random size for each element and a random position in data from which to begin copying */
            
            int off = (int) (data_len * (rand() / (1.0 + RAND_MAX)));
            
            src.elements[j].len  = (int) ((1 + SEC_UNIT_MAX_ELEM_SIZE) * (rand() / (1.0 + RAND_MAX)));
            src_len             += src.elements[j].len;

            /* fill in the element */
            
            for (k = 0; k < src.elements[j].len;)
            {
                int len = data_len - off;

                if (len > src.elements[j].len - k)
                    len = src.elements[j].len - k;
                
                memcpy(src.elements[j].buf + k, data + off, len);

                k   += len;
                off  = 0;
            }
        }

        /* encrypt src into Enc_Buf / enc / enc2 */

        t1 = E_get_time();
        
        if ((enc_len = Sec_lock_msg(&src, Enc_Buf, (int) sizeof(Enc_Buf), encrypt_ctx, hmac_ctx)) < 0)
            Alarmp(SPLOG_FATAL, SECURITY | EXIT, "Sec_run_test:%d: Sec_lock_msg failed!\n", __LINE__);

        enc_time   = E_add_time(enc_time, E_sub_time(E_get_time(), t1));
        enc_bytes += src_len;

        enc.elements[0].len = enc_len;
        
        /* make sure lock significantly changed enc's contents */

        if (Conf_IT_Link.Encrypt && (diff = Sec_diff_msg(&src, &enc, 0)) < 0.95 * src_len)
            Alarmp(SPLOG_FATAL, SECURITY | EXIT, "Sec_run_test:%d: Sec_lock_msg didn't do much?! diff = %d, src_len = %d\n", __LINE__, diff, src_len);
        
        /* decrypt enc into Dst_Buf / dst */
        
        t1 = E_get_time();
        
        if ((dst_len = Sec_unlock_msg(&enc, Dst_Buf, sizeof(Dst_Buf), decrypt_ctx, hmac_ctx)) < 0)
            Alarmp(SPLOG_FATAL, SECURITY | EXIT, "Sec_run_test:%d: Sec_unlock_msg failed!\n", __LINE__);

        dec_time   = E_add_time(dec_time, E_sub_time(E_get_time(), t1));
        dec_bytes += enc_len;

        dst.elements[0].len = dst_len;
        
        /* make sure unlock restored dst to be exactly src; will exit at first byte difference found */

        Sec_diff_msg(&src, &dst, 1);

        if ((++i & 0x1fff) == 0)
        {
            Alarmp(SPLOG_PRINT, PRINT, "Encrypted %d msgs (%.1f MB) in %ld.%06ld seconds for an avg. of %.1f Mb/s\n", i,
                   enc_bytes / 1.0e6, enc_time.sec, enc_time.usec, enc_bytes / 1.0e6 * 8 / (enc_time.sec + enc_time.usec / 1.0e6));;

            Alarmp(SPLOG_PRINT, PRINT, "Decrypted %d msgs (%.1f MB) in %ld.%06ld seconds for an avg. of %.1f Mb/s\n", i, 
                   dec_bytes / 1.0e6, dec_time.sec, dec_time.usec, dec_bytes / 1.0e6 * 8 / (dec_time.sec + dec_time.usec / 1.0e6));
        }
    }

    Alarmp(SPLOG_PRINT, PRINT, "Encrypted %d msgs (%.1f MB) in %ld.%06ld seconds for an avg. of %.1f Mb/s\n", i,
           enc_bytes / 1.0e6, enc_time.sec, enc_time.usec, enc_bytes / 1.0e6 * 8 / (enc_time.sec + enc_time.usec / 1.0e6));;

    Alarmp(SPLOG_PRINT, PRINT, "Decrypted %d msgs (%.1f MB) in %ld.%06ld seconds for an avg. of %.1f Mb/s\n", i,
           dec_bytes / 1.0e6, dec_time.sec, dec_time.usec, dec_bytes / 1.0e6 * 8 / (dec_time.sec + dec_time.usec / 1.0e6));
}

/* Sec_unit_test ----------------------------------------------------------------------------
   ------------------------------------------------------------------------------------------ */

void Sec_unit_test(void)
{
    EVP_CIPHER_CTX *encrypt_ctx;
    EVP_CIPHER_CTX *decrypt_ctx;
    HMAC_CTX       *hmac_ctx;
    unsigned char  crypt_key[SECURITY_MAX_KEY_SIZE + 1] = "234567891123456";
    unsigned char  iv_key[SECURITY_MAX_KEY_SIZE + 1]    = "234567891123456";
    unsigned char  hmac_key[SECURITY_MAX_HMAC_SIZE + 1] = "2345678911234567892123456789312";

    crypt_key[SECURITY_MAX_KEY_SIZE] = '\0';
    iv_key[SECURITY_MAX_KEY_SIZE]    = '\0';
    hmac_key[SECURITY_MAX_HMAC_SIZE] = '\0';
    
    encrypt_ctx = EVP_CIPHER_CTX_new();
    if (encrypt_ctx == NULL)
        Alarmp(SPLOG_FATAL, SECURITY | EXIT, "Sec_unit_test:%d: allocation of encrypt_ctx failed!\n", __LINE__);
    decrypt_ctx = EVP_CIPHER_CTX_new();
    if (decrypt_ctx == NULL)
        Alarmp(SPLOG_FATAL, SECURITY | EXIT, "Sec_unit_test:%d: allocation of decrypt_ctx failed!\n", __LINE__);
    hmac_ctx = HMAC_CTX_new();
    if (hmac_ctx == NULL)
        Alarmp(SPLOG_FATAL, SECURITY | EXIT, "Sec_unit_test:%d: allocation of hmac_ctx failed!\n", __LINE__);

    if (EVP_EncryptInit_ex(encrypt_ctx, EVP_aes_128_cbc(), NULL, crypt_key, NULL) != 1 ||
        EVP_DecryptInit_ex(decrypt_ctx, EVP_aes_128_cbc(), NULL, crypt_key, NULL) != 1)
        Alarmp(SPLOG_FATAL, SECURITY | EXIT, "Sec_unit_test:%d: initialization of crypto ctx's failed!\n", __LINE__);

    HMAC_Init_ex(hmac_ctx, hmac_key, sizeof(hmac_key), EVP_sha256(), NULL);

    /* manually do what Sec_init does to make first batch of tests deterministic and repeatable */

    srand(0);
    
    OpenSSL_add_all_algorithms();
    EVP_CIPHER_CTX_init(IV_Ctx);

    strncpy((char*) IV_Counter, Test_Data, sizeof(IV_Counter));
    
    if (EVP_EncryptInit_ex(IV_Ctx, EVP_aes_128_ecb(), NULL, iv_key, NULL) != 1 || EVP_CIPHER_CTX_set_padding(IV_Ctx, 0) != 1)
        Alarmp(SPLOG_FATAL, SECURITY | EXIT, "Sec_unit_test:%d: init of IV_Ctx failed!\n", __LINE__);

    Conf_IT_Link.Encrypt = 1;

    Alarmp(SPLOG_PRINT, PRINT, "Running unit test 1!\n");
    Sec_run_test(1000000, Test_Data, strlen(Test_Data), encrypt_ctx, decrypt_ctx, hmac_ctx);
    Alarmp(SPLOG_PRINT, PRINT, "Success!\n");
    
    Conf_IT_Link.Encrypt = 0;

    Alarmp(SPLOG_PRINT, PRINT, "Running unit test 2!\n");
    Sec_run_test(1000000, Test_Data, strlen(Test_Data), encrypt_ctx, decrypt_ctx, hmac_ctx);
    Alarmp(SPLOG_PRINT, PRINT, "Success!\n");

    EVP_CIPHER_CTX_free(encrypt_ctx);
    EVP_CIPHER_CTX_free(decrypt_ctx);
    HMAC_CTX_free(hmac_ctx);
}    
