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

/* Openssl RSA signing and verifying functionality. The openssl_rsa.h header
 * file lists the public functions that can be used to sign messages and verify
 * that signatures are valid. */

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include "conf_openssl_rsa.h"
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

/* Defined Types */
// "ripemd160"
#define RSA_TYPE_PUBLIC          1
#define RSA_TYPE_PRIVATE         2
#define RSA_TYPE_CLIENT_PUBLIC   3 
#define RSA_TYPE_CLIENT_PRIVATE  4 
#define DIGEST_ALGORITHM         "sha1"
#define DIGEST_ALGORITHM_HMAC    "md5"  
#define NUMBER_OF_SERVERS        NUM_SM
#define NUMBER_OF_CLIENTS        (MAX_EMU_RTU + 50)

/* This flag is used to remove crypto for testing -- this feature eliminates
 * security and Byzantine fault tolerance. */
#define REMOVE_CRYPTO 0 

/* Global variables */
RSA *private_rsa; /* My Private Key */
RSA *public_rsa_by_server[NUMBER_OF_SERVERS + 1];
RSA *public_rsa_by_client[NUMBER_OF_CLIENTS + 1];
const EVP_MD *message_digest;
const EVP_MD *message_digest_hmac;
_Thread_local EVP_MD_CTX *mdctx=NULL;
void *pt;
int32 verify_count;

/*  
    enc_key: A 256 bit key 
    MK: Encryption Key used for encrypting/decrypting.
        In practice, this should only be available to Control Center replicas.
*/
unsigned char enc_key[32]; // = (unsigned char *)"01234567890123456789012345678901";

/*  
    iv_key: A 256 bit initialization vector (IV) 
    MK: Initialization Vector used for encrypting/decrypting
        In practice, this is available to Control Center replicas
*/
unsigned char iv_key[32]; //= (unsigned char *)"10987654321098765432109876543210";


void Gen_Key_Callback(int32 stage, int32 n, void *unused) 
{
    UNUSED(stage);
    UNUSED(n);
    UNUSED(unused);
} 

void Write_BN(FILE *f, const BIGNUM *bn) 
{
  char *bn_buf;
  
  bn_buf = BN_bn2hex( bn );
  
  fprintf( f, "%s\n", bn_buf );

  /* Note: The memory for the BIGNUM should be freed if the bignum will not
   * be used again. TODO */ 
}

void Write_RSA( int32u rsa_type, int32u server_number, RSA *rsa, const char *keys_dir) 
{
  FILE *f;
  char fileName[100];
  const BIGNUM *n, *e, *d;
  const BIGNUM *p, *q;
  const BIGNUM *dmp1, *dmq1, *iqmp;
  
  /* Write an RSA structure to a file */
  if(rsa_type == RSA_TYPE_PUBLIC)
    snprintf(fileName, 100, "%s/public_%02d.key", keys_dir, server_number);
  else if(rsa_type == RSA_TYPE_PRIVATE)
    snprintf(fileName, 100, "%s/private_%02d.key", keys_dir, server_number);
  else if(rsa_type == RSA_TYPE_CLIENT_PUBLIC)
    snprintf(fileName, 100, "%s/public_client_%02d.key", keys_dir, server_number);
  else if(rsa_type == RSA_TYPE_CLIENT_PRIVATE)
    snprintf(fileName, 100, "%s/private_client_%02d.key", keys_dir, server_number);
     
  f = fopen(fileName, "w");

  RSA_get0_key(rsa, &n, &e, &d);
  RSA_get0_factors(rsa, &p, &q);
  RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
  Write_BN(f, n);
  Write_BN(f, e);

  if(rsa_type == RSA_TYPE_PRIVATE || rsa_type == RSA_TYPE_CLIENT_PRIVATE) {
    Write_BN( f, d );
    Write_BN( f, p );
    Write_BN( f, q );
    Write_BN( f, dmp1 );
    Write_BN( f, dmq1 );
    Write_BN( f, iqmp );
  }
  fprintf( f, "\n" );
  fclose(f);
}

void Read_BN( FILE *f, BIGNUM **bn ) 
{
  char bn_buf[1000];
  char *ret;

  (*bn) = BN_new();
  ret = fgets(bn_buf, 1000, f);
  if (ret == NULL) {
    printf("ERROR: Could not read BN\n");
    exit(1);
  }
  BN_hex2bn( bn, bn_buf );
}

void Read_RSA( int32u rsa_type, int32u server_number, RSA *rsa, const char *keys_dir) 
{
  FILE *f;
  char fileName[100];
  BIGNUM *n = NULL, *e = NULL, *d = NULL;
  BIGNUM *p = NULL, *q = NULL;
  BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
  
  /* Read an RSA structure to a file */
  
  if(rsa_type == RSA_TYPE_PUBLIC)
    snprintf(fileName, 100, "%s/public_%02d.key", keys_dir, server_number);
  else if(rsa_type == RSA_TYPE_PRIVATE)
    snprintf(fileName, 100, "%s/private_%02d.key", keys_dir, server_number);
  else if(rsa_type == RSA_TYPE_CLIENT_PUBLIC)
    snprintf(fileName, 100, "%s/public_client_%02d.key", keys_dir, server_number);
  else if(rsa_type == RSA_TYPE_CLIENT_PRIVATE)
    snprintf(fileName, 100, "%s/private_client_%02d.key", keys_dir, server_number);
  
  if((f = fopen( fileName, "r")) == NULL) {
    printf("ERROR: Could not open the key file: %s\n", fileName );
    exit(1);
  }
  
  Read_BN( f, &n );
  Read_BN( f, &e );
  if (!RSA_set0_key(rsa, n, e, d)) {
    printf("Error: Read_RSA: RSA_set0_key() failed (%s:%d)\n", __FILE__, __LINE__);
    exit(1);
  }
  if ( rsa_type == RSA_TYPE_PRIVATE || rsa_type == RSA_TYPE_CLIENT_PRIVATE ) {
    Read_BN( f, &d );
    Read_BN( f, &p );
    Read_BN( f, &q );
    Read_BN( f, &dmp1 );
    Read_BN( f, &dmq1 );
    Read_BN( f, &iqmp );
    if (!RSA_set0_key(rsa, NULL, NULL, d)) {
      printf("Error: Read_RSA: RSA_set0_key() failed (%s:%d)\n", __FILE__, __LINE__);
      exit(1);
    }
    if (!RSA_set0_factors(rsa, p, q)) {
      printf("Error: Read_RSA: RSA_set0_key() failed (%s:%d)\n", __FILE__, __LINE__);
      exit(1);
    }
    if (!RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp)) {
      printf("Error: Read_RSA: RSA_set0_key() failed (%s:%d)\n", __FILE__, __LINE__);
      exit(1);
    }
  }

  fclose(f);
}


/* This function generates keys based on the current configuration as specified
 * in data_structs.h */
void OPENSSL_RSA_Generate_Keys(const char *keys_dir) {

    RSA *rsa;
    int32u s;
    BIGNUM *e;

    /* Prompt user for a secret key value. */

    /* Generate Keys For Servers, note KEY_SIZE is defined in def.h */
    rsa = RSA_new();
    e = BN_new();
    BN_set_word(e, 3);
    for ( s = 1; s <= NUMBER_OF_SERVERS; s++ ) {
      if (!RSA_generate_key_ex( rsa, KEY_SIZE, e, NULL)) {
        printf("OPENSSL_RSA_Generate_Keys: RSA_generate_key failed (%s:%d)", __FILE__, __LINE__);
        exit(1);
      }
      /*RSA_print_fp( stdout, rsa, 4 );*/
      Write_RSA( RSA_TYPE_PUBLIC,  s, rsa, keys_dir ); 
      Write_RSA( RSA_TYPE_PRIVATE, s, rsa, keys_dir ); 
    } 

    /* Generate Keys For Clients, note KEY_SIZE is defined in def.h */
    for ( s = 1; s <= NUMBER_OF_CLIENTS; s++ ) {
      if (!RSA_generate_key_ex( rsa, KEY_SIZE, e, NULL)) {
        printf("OPENSSL_RSA_Generate_Keys: RSA_generate_key failed (%s:%d)", __FILE__, __LINE__);
        exit(1);
      }
      /*RSA_print_fp( stdout, rsa, 4 );*/
      Write_RSA( RSA_TYPE_CLIENT_PUBLIC,  s, rsa, keys_dir ); 
      Write_RSA( RSA_TYPE_CLIENT_PRIVATE, s, rsa, keys_dir ); 
    } 
}

void OPENSSL_RSA_Gen_Encrypt_Keys( const char *keys_dir )
{
  unsigned char key1[32], key2[32];
  int rc;

  FILE *f1, *f2;
  char fileName1[100], fileName2[100];

  rc = RAND_bytes(key1,sizeof(key1));
    
  if(rc != 1)
  {
    printf("OPENSSL_RSA_Gen_Encrypt_Keys: Generating key1 failed.\n");
    exit(0);
  }

  rc = RAND_bytes(key2,sizeof(key2));
    
  if(rc != 1)
  {
    printf("OPENSSL_RSA_Gen_Encrypt_Keys: Generating key2 failed.\n");
    exit(0);
  }

  snprintf(fileName1, 100, "%s/encrypt_key1.key", keys_dir);
  snprintf(fileName2, 100, "%s/encrypt_key2.key", keys_dir);

  f1 = fopen(fileName1, "w");
  fprintf( f1, "%s\n", key1 );
  fprintf( f1, "\n" );
  fclose(f1);

  f2 = fopen(fileName2, "w");
  fprintf( f2, "%s\n", key2 );
  fprintf( f2, "\n" );  
  fclose(f2);

  OPENSSL_cleanse(key1,sizeof(key1));
  OPENSSL_cleanse(key2,sizeof(key2));
}


void OPENSSL_RSA_Read_Encrypt_Keys( const char *keys_dir )
{
  char *ret;
  FILE *f1, *f2;
  char fileName1[100], fileName2[100];

  snprintf(fileName1, 100, "%s/encrypt_key1.key", keys_dir);
  snprintf(fileName2, 100, "%s/encrypt_key2.key", keys_dir);

  if((f1 = fopen( fileName1, "r")) == NULL) {
    printf("ERROR: Could not open the key file: %s\n", fileName1 );
    exit(1);
  }

  if((f2 = fopen( fileName2, "r")) == NULL) {
    printf("ERROR: Could not open the key file: %s\n", fileName2 );
    exit(1);
  }

  ret = fgets(enc_key, 32, f1);
  if (ret == NULL){
    printf("ERROR: Could not read enc key\n");
    exit(1);
  }

  ret = fgets(iv_key, 32, f2);
  if (ret == NULL){
    printf("ERROR: Could not read enc key\n");
    exit(1);
  }

  fclose(f1);
  fclose(f2);

}

/* Read all of the keys for servers or clients. All of the public keys
 * should be read and the private key for this server should be read. */
 void OPENSSL_RSA_Read_Keys(int32u my_number, int32u type, const char *keys_dir)
{

  int32u s; 
  int32u rt;
  
  /* Read all public keys for servers. */
  for(s = 1; s <= NUMBER_OF_SERVERS; s++) {
    public_rsa_by_server[s] = RSA_new();
    Read_RSA(RSA_TYPE_PUBLIC, s, public_rsa_by_server[s], keys_dir);
  } 

  /* Read all public keys for clients. */
  for ( s = 1; s <= NUMBER_OF_CLIENTS; s++ ) {
    public_rsa_by_client[s] = RSA_new();
    Read_RSA( RSA_TYPE_CLIENT_PUBLIC, s, public_rsa_by_client[s], keys_dir);
  } 
    
  if ( type == RSA_SERVER ) {
    rt = RSA_TYPE_PRIVATE;
  } else if ( type == RSA_CLIENT ) {
    rt = RSA_TYPE_CLIENT_PRIVATE;
  } else {
    printf("OPENSSL_RSA_Read_Keys: Called with invalid type.\n");
    exit(0);
  }

  /* Read my private key. */
  private_rsa = RSA_new();
  Read_RSA( rt, my_number, private_rsa, keys_dir);
}

void OPENSSL_RSA_Init() 
{
  /* Load a table containing names and digest algorithms. */
  OpenSSL_add_all_digests();
  
  /* Use sha1 as the digest algorithm. */
  message_digest = EVP_get_digestbyname( DIGEST_ALGORITHM );
  message_digest_hmac = EVP_get_digestbyname( DIGEST_ALGORITHM_HMAC );
  verify_count = 0;

}

int32u OPENSSL_RSA_Digests_Equal( unsigned char *digest1, 
				  unsigned char *digest2 ) {

    int32u i;

#if REMOVE_CRYPTO    
    //return 1;
#endif    
    
    for ( i = 0; i < DIGEST_SIZE; i++ ) {
	if ( digest1[i] != digest2[i] ) return 0;
    }
    return 1;
}

void OPENSSL_RSA_Make_Digest( const void *buffer, size_t buffer_size, 
	unsigned char *digest_value ) {

    /* EVP functions are a higher level abstraction that encapsulate many
     * different digest algorithms. We currently use sha1. The returned digest
     * is for sha1 and therefore we currently assume that functions which use
     * this type of digest. It would be best to extend the encapsulation
     * through our code. TODO Note that there may be an increase in
     * computational cost because these high-level functions are used. We might
     * want to test this and see if we take a performance hit. */
    
    int32u md_len;
    
#if REMOVE_CRYPTO 
    //return;
#endif

    //memset(digest_value, 0, DIGEST_SIZE);
    //return;
    //EVP_MD_CTX *mdctx;
    if (mdctx==NULL)
    	mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, message_digest, NULL);
    EVP_DigestUpdate(mdctx, buffer, buffer_size);
    EVP_DigestFinal_ex(mdctx, digest_value, &md_len);
    //EVP_MD_CTX_free(mdctx);
    /* Check to determine if the digest length is expected for sha1. It should
     * be DIGEST_SIZE bytes, which is 20 */
   
    if ( md_len != DIGEST_SIZE ) {
	printf("An error occurred while generating a message digest.\n"
		"The length of the digest was set to %d. It should be %d.\n"
		, md_len, DIGEST_SIZE);
	exit(0);
    }

#if 0 
    printf("Digest is, size %d: ",md_len);
#endif
    
}

void OPENSSL_RSA_Print_Digest( unsigned char *digest_value ) {

    int32u i;
    
    for(i = 0; i < DIGEST_SIZE; i++) printf("%02x", digest_value[i]);
    printf("\n");

}

void OPENSSL_RSA_Make_Signature( const byte *digest_value, byte *signature ) 
{
  //sp_time start, end, diff;
  int32u signature_size = 0;
  
  /* Make a signature for the specified digest value. The digest value is
   * assumed to be DIGEST_SIZE bytes. */

#if REMOVE_CRYPTO
  UTIL_Busy_Wait(0.000005);
  return;
#endif
  
  /*int32u rsa_size;*/ 
  
  if(private_rsa == NULL) {
    printf("Error: In Make_Signature, private_rsa key is NULL.\n");
    exit(0);
  }

  /*RSA_print_fp( stdout, private_rsa, 4 );*/
  /*rsa_size = RSA_size( private_rsa ); */
    
  /*printf("Signature size: %d\n", rsa_size);*/
  //private_rsa = RSA_generate_key( KEY_SIZE, 3, Gen_Key_Callback, NULL );
 
  //start = E_get_time();

  RSA_sign(NID_sha1, digest_value, DIGEST_SIZE, signature, &signature_size,private_rsa);

  //end = E_get_time();
  
  //diff = E_sub_time(end, start);
  //Alarm(DEBUG, "Signing: %d sec; %d microsec\n", diff.sec, diff.usec);
}


int32u OPENSSL_RSA_Verify_Signature( const byte *digest_value, 
	unsigned char *signature,  int32u number,  int32u type ) {

    /* Verify a signature for the specified digest value. The digest value is
     * assumed to be DIGEST_SIZE bytes. */
   
    int32 ret;
    RSA *rsa; 

#if REMOVE_CRYPTO 
    UTIL_Busy_Wait(0.000005);
    return 1;
#endif
    
    /*unsigned int32u rsa_size = RSA_size( private_rsa );*/
    /*printf("Signature size: %d\n", rsa_size);*/
   
    if ( type == RSA_CLIENT ) {
	if (number < 1 || number > NUMBER_OF_CLIENTS ) {
	    return 0;
	}
	rsa = public_rsa_by_client[number];
    } else {
	if (number < 1 || number > NUMBER_OF_SERVERS ) {
	    return 0;
	}
        rsa = public_rsa_by_server[number];
    }
    
    ret = RSA_verify(NID_sha1, digest_value, DIGEST_SIZE, signature, SIGNATURE_SIZE,
	    rsa );
    
    verify_count++;
   
    if ( verify_count % 1000 == 0 ) {
	//Alarm(PRINT,"Verify Count %d\n",verify_count);
    }
    
#if 1 
    if ( !ret ) {
	printf("RSA_OPENSSL_Verify: Verification Failed. "
		"Machine number = %d. \n",
		number);
    }
#endif

    return ret; 
}

void OPENSSL_RSA_Sign( const unsigned char *message, size_t message_length,
       unsigned char *signature ) {

  unsigned char md_value[EVP_MAX_MD_SIZE];

#if REMOVE_CRYPTO
    UTIL_Busy_Wait(0.000005);
    return;
#endif

    memset(md_value, 0, sizeof(md_value));
    OPENSSL_RSA_Make_Digest( message, message_length, md_value );

    OPENSSL_RSA_Make_Signature( md_value, signature );

#if 0    
    Alarm( PRINT," verify 1 %d\n",
	   OPENSSL_RSA_Verify_Signature( md_value, signature, 1, 
	   RSA_SERVER ));

    Alarm( PRINT," verify 2 %d\n",
	   OPENSSL_RSA_Verify( message, message_length, signature, 1, 
	   RSA_SERVER ));
#endif

}

int OPENSSL_RSA_Verify( const unsigned char *message, size_t message_length,
	unsigned char *signature, int32u number, int32u type ) {
 
    int32 ret;
     
    unsigned char md_value[EVP_MAX_MD_SIZE];

#if REMOVE_CRYPTO
    UTIL_Busy_Wait(0.000005);
    return 1;
#endif    

    OPENSSL_RSA_Make_Digest( message, message_length, md_value );
    ret =  OPENSSL_RSA_Verify_Signature( md_value, signature, number, type );

   
    return ret;
}


/*
  The following code is adapted from OpenSSL documentation.
  (source: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption)
*/
int OPENSSL_RSA_Encrypt(char *plaintext, int plaintext_len,
            unsigned char *iv, char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
      printf("OPENSSL_RSA_Encrypt: failed!");
      return -1;
    }

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, enc_key, iv))
    {
      printf("OPENSSL_RSA_Encrypt: failed!");
      return -1;
    }


    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
      printf("OPENSSL_RSA_Encrypt: failed!");
      return -1;
    }

    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
      printf("OPENSSL_RSA_Encrypt: failed!");
      return -1;
    }

    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

/*
  The following code is adapted from OpenSSL documentation.
  (source: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption)
*/
int OPENSSL_RSA_Decrypt(char *ciphertext, int ciphertext_len,
            unsigned char *iv, char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
      printf("OPENSSL_RSA_Decrypt: failed!");
      return -1;
    }


    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, enc_key, iv))
    {
      printf("OPENSSL_RSA_Decrypt: failed!");
      return -1;
    }


    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
      printf("OPENSSL_RSA_Decrypt: failed!");
      return -1;
    }

    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
      printf("OPENSSL_RSA_Decrypt: failed!");
      return -1;
    }

    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int OPENSSL_RSA_IV(unsigned char* buffer, int buffer_size, unsigned char* iv)
{
    
    HMAC_CTX *hctx;
    int32u md_len2;
    unsigned char md2[EVP_MAX_MD_SIZE];

    memset(&md2, 0, EVP_MAX_MD_SIZE);

    //HMAC_CTX_init(hctx); // deprecated 1.0.2
    hctx = HMAC_CTX_new(); 
    HMAC_Init_ex(hctx, iv_key, 32, message_digest_hmac, NULL);
    HMAC_Update(hctx, buffer, buffer_size);
    HMAC_Final(hctx, md2, &md_len2);
    //HMAC_CTX_cleanup(hctx); // deprecated 1.0.2
    HMAC_CTX_free(hctx);

    /* Check to determine if the digest length is expected for md5. It should
     * be 16 bytes. */
   
    if ( md_len2 != DIGEST_SIZE_IV ) {
        printf("An error occurred while generating a message digest for HMAC.\n"
                "The length of the digest was set to %d. It should be %d.\n"
                , md_len2, DIGEST_SIZE_IV);
        return -1;
    }

    memcpy(iv, &md2, DIGEST_SIZE_IV);

    return 1;

}
