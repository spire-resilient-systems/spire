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

#include "ss_tc_wrapper.h"
#include "TC.h" 

#include <assert.h>

#define TIME_GENERATE_SIG_SHARE 0

#define SITE 1 // Used by TC_Lib for something?

// TODO: DQ: Check if these are actually right
#define SIG_SIZE 128
#define PROOF_Z_SIZE 144
#define PROOF_C_SIZE 16

TC_IND *tc_partial_key; /* My Partial Key */
TC_PK *tc_public_key;   /* Public Key of Site */
TC_IND_SIG **tc_partial_signatures; /* A list of Partial Signatures */

void TC_Read_Partial_Key( int32u server_no, const char *keys_dir ) 
{
    char buf[100];
    snprintf(buf, 100, "%s/share%d_%d.pem", keys_dir, server_no - 1, SITE );

    tc_partial_key = (TC_IND *)TC_read_share(buf);
}

void TC_Read_Public_Key( const char *keys_dir ) 
{
    
    char buf[100];

    snprintf(buf, 100, "%s/pubkey_%d.pem", keys_dir, SITE);
    tc_public_key = (TC_PK *)TC_read_public_key(buf);
}

int32u TC_Generate_Sig_Share( byte* dst_share, byte* dst_proof, byte* hash  ) 
{ 
    /* Generate a signature share without the proof. */
    
    TC_IND_SIG *signature;
    int32u length_sig, length_z, length_c;
    BIGNUM *hash_bn;
    int32u pad;
    int ret;

 #if TIME_GENERATE_SIG_SHARE
    sp_time start, end, diff;

    start = E_get_time();
#endif

    hash_bn = BN_bin2bn( hash, DIGEST_SIZE, NULL );

    signature = TC_IND_SIG_new();
    ret = genIndSig( tc_partial_key, hash_bn, signature, 1);

    if (ret != TC_NOERROR) {
        printf("Error in TC Sig Share geneartion : %d \n", ret);
    }  

    BN_free( hash_bn );
    
    /* Made the signature share. Now take the bn sig and proof and store them
     * into dst_share and dst_proof in OPENSSL mpi format. */

    length_sig = BN_num_bytes( signature->sig );
    length_z = BN_num_bytes( signature->proof_z );
    length_c = BN_num_bytes( signature->proof_c );
    
    BN_bn2bin(signature->sig, dst_share + (SIG_SIZE - length_sig));
    BN_bn2bin(signature->proof_z, dst_proof + (PROOF_Z_SIZE - length_z));
    BN_bn2bin(signature->proof_c, dst_proof + PROOF_Z_SIZE + (PROOF_C_SIZE - length_c));

    /* The length should be around fill buffers, if not pad with zeroes */
    for ( pad = 0; pad < (SIG_SIZE - length_sig); pad++ ) {
        dst_share[pad] = 0;
    }

    for ( pad = 0; pad < (PROOF_Z_SIZE - length_z); pad++ ) {
        dst_proof[pad] = 0;
    }

    for ( pad = PROOF_Z_SIZE; pad < PROOF_Z_SIZE + (PROOF_C_SIZE - length_c); pad++ ) {
        dst_proof[pad] = 0;
    }
      
#if 0
    printf("Sig Share (size %d): %s\n", length, BN_bn2hex( signature->sig ));
    printf("Proof Z (size %d): %s\n", BN_num_bytes(signature->proof_z), BN_bn2hex( signature->proof_z ));
    printf("Proof C (size %d): %s\n", BN_num_bytes(signature->proof_c), BN_bn2hex( signature->proof_c ));
#endif

    TC_IND_SIG_free( signature );
    
#if TIME_GENERATE_SIG_SHARE
    end = E_get_time();

    diff = E_sub_time(end, start);
    //Alarm(PRINT, "Gen sig share: %d sec; %d microsec\n", diff.sec, diff.usec);
    printf("Gen sig share: %d sec; %d microsec\n", diff.sec, diff.usec);
#endif

    return length_sig;
}

void TC_Initialize_Combine_Phase( int32u number ) 
{
    tc_partial_signatures = TC_SIG_Array_new( number );
}

void TC_Add_Share_To_Be_Combined( int server_no, byte *share ) 
{
    /* Convert share to bignum. */

    TC_IND_SIG *signature;

    signature = TC_IND_SIG_new();

    //BN_bin2bn( share + 4, *((int32u*)share), signature->sig );

    BN_bin2bn( share, 128, signature->sig );

#if 0    
    printf("ADD: %d; %s\n", server_no, BN_bn2hex( signature->sig ));
#endif

    set_TC_SIG(server_no, signature, tc_partial_signatures );
    TC_IND_SIG_free( signature );
}

void TC_Destruct_Combine_Phase( int32u number ) 
{
    TC_SIG_Array_free( tc_partial_signatures, number );
}

int32u TC_Combine_Shares( byte *signature_dest, byte *digest ) 
{
    TC_SIG combined_signature;
    BIGNUM *hash_bn;
    int32u ret;
    int32u length;
    int32u pad;
    //struct timeval now;
    
    hash_bn = BN_bin2bn( digest, DIGEST_SIZE, NULL );

    ret = TC_Combine_Sigs( tc_partial_signatures, tc_partial_key, 
	    hash_bn, &combined_signature, 0);

    if (ret != TC_NOERROR) {
        printf("Error in TC_Combine_Sigs!\n");
        ret = 0;
        goto END;
    }

    /* There is a probable security error here. We need to make sure
     * that we don't exit if there is an arithmetic error in the
     * combining, and then enter the proof phase, during which we
     * identify the malicious server that sent a message which caused
     * the arithmetic error. This is related to the blacklisting code,
     * which is not currently coded.*/

    ret = TC_verify(hash_bn, combined_signature, tc_public_key);    
    if (ret != 1) {
        printf("TC_verify failed!!\n");
        ret = 0;
        goto END;
    }

    length = BN_num_bytes( combined_signature );
	
    BN_bn2bin( combined_signature, signature_dest + (128 - length) );

    /* The length should be approx 128 bytes if it is not 128 then we need to
     * pad with zeroes */
    for ( pad = 0; pad < (128 - length); pad++ ) {
        signature_dest[pad] = 0;
    }
    
    //gettimeofday(&now,NULL);
    //printf("Time=%ld.%06ld\n",now.tv_sec,now.tv_usec);
    //printf("\tCombined Sig: %s\n", BN_bn2hex( combined_signature ));
    ret = 1;
END:
    BN_free( combined_signature );
    BN_free( hash_bn );
    return ret;
}

int32u TC_Verify_Signature( byte *signature, byte *digest ) 
{
    BIGNUM *hash_bn;
    int32u ret;
    BIGNUM *sig_bn;

    hash_bn = BN_bin2bn( digest, DIGEST_SIZE, NULL );
    sig_bn = BN_bin2bn( signature, SIGNATURE_SIZE, NULL );

    ret = TC_verify(hash_bn, sig_bn, tc_public_key);

    BN_free( sig_bn );
    BN_free( hash_bn );

    return ret;
}

int TC_Check_Share( byte* digest, byte* share, byte* proof, int32u sender_id )
{
    int ret;
    BIGNUM *hash_bn;
    TC_IND_SIG *tc_share;

    /* Load share and proof into TC_IND_SIG */
    tc_share = TC_IND_SIG_new();
    BN_bin2bn( share, 128, tc_share->sig );
    BN_bin2bn( proof, PROOF_Z_SIZE, tc_share->proof_z );
    BN_bin2bn( proof + PROOF_Z_SIZE, PROOF_C_SIZE, tc_share->proof_c );
    
    hash_bn = BN_bin2bn( digest, DIGEST_SIZE, NULL );
    
    ret = TC_Check_Proof(tc_partial_key, hash_bn, 
                          tc_share, 
                          sender_id);

    BN_free(hash_bn);
    TC_IND_SIG_free(tc_share);

    return ret;
}

/* The following function generate the threshold shares and store them on disk. */
void TC_Generate(char *directory)
{
    // TODO: Seed?
    TC_DEALER *dealer; 
    int n, k, keysize;

    keysize = 1024;
    n = NUM_REPLICAS;
    k = NUM_F + 1;

    dealer = NULL;
    dealer = TC_generate(keysize/2, n, k, 17);

    TC_write_shares(dealer, directory, SITE);
    TC_DEALER_free(dealer);

}
