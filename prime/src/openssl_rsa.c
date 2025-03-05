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

/* Openssl RSA signing and verifying functionality. The openssl_rsa.h header
 * file lists the public functions that can be used to sign messages and verify
 * that signatures are valid. */

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include "openssl_rsa.h"
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>
#include "data_structs.h"
#include "arch.h"
#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_data_link.h"
#include "spu_memory.h"

/* Defined Types */
// "ripemd160"
#define RSA_TYPE_PUBLIC          1
#define RSA_TYPE_PRIVATE         2
#define RSA_TYPE_CLIENT_PUBLIC   3 
#define RSA_TYPE_CLIENT_PRIVATE  4
#define RSA_TYPE_NM_PUBLIC       5 
#define RSA_TYPE_NM_PRIVATE      6  
#define DIGEST_ALGORITHM         "sha1" 
#define NUMBER_OF_CLIENTS        NUM_CLIENTS

/* This flag is used to remove crypto for testing -- this feature eliminates
 * security and Byzantine fault tolerance. */
#define REMOVE_CRYPTO 0 

/*SM2022:  VAR.Num_Servers*/
extern server_variables VAR;

/* Global variables */
RSA *private_rsa; /* My Private Key */
RSA *private_client_rsa; /* My Private Client Key (If im also a server) */
RSA *public_rsa_by_server[MAX_NUM_SERVERS + 1];
RSA *public_rsa_by_client[NUMBER_OF_CLIENTS + 1];
RSA *public_rsa_by_nm;
const EVP_MD *message_digest;
EVP_MD_CTX *mdctx;
void *pt;
int32 verify_count;

void Gen_Key_Callback(int32 stage, int32 n, void *unused) 
{
}

void Write_BN(FILE *f, const BIGNUM *bn) 
{
  char *bn_buf;
  
  bn_buf = BN_bn2hex( bn );
  
  fprintf( f, "%s\n", bn_buf );

  OPENSSL_free(bn_buf);
  /* Note: The memory for the BIGNUM should be freed if the bignum will not
   * be used again. TODO */ 
}


void Write_RSA_To_Dir( int32u rsa_type, int32u server_number, RSA *rsa, const char *keys_dir)
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
  else if(rsa_type == RSA_TYPE_NM_PUBLIC)
    snprintf(fileName, 100, "%s/public_config_mngr.key", keys_dir);
  else if(rsa_type == RSA_TYPE_NM_PRIVATE)
    snprintf(fileName, 100, "%s/private_config_mngr.key", keys_dir);

  f = fopen(fileName, "w");

  RSA_get0_key(rsa, &n, &e, &d);
  RSA_get0_factors(rsa, &p, &q);
  RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
  Write_BN(f, n);
  Write_BN(f, e);

  if(rsa_type == RSA_TYPE_PRIVATE || rsa_type == RSA_TYPE_CLIENT_PRIVATE || rsa_type ==RSA_TYPE_NM_PRIVATE) {
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

void Write_RSA( int32u rsa_type, int32u server_number, RSA *rsa) 
{
  FILE *f;
  char fileName[50];
  char dir[100] = "./keys";
  const BIGNUM *n, *e, *d;
  const BIGNUM *p, *q;
  const BIGNUM *dmp1, *dmq1, *iqmp;
  
  /* Write an RSA structure to a file */
  if(rsa_type == RSA_TYPE_PUBLIC)
    sprintf(fileName,"%s/public_%02d.key", dir, server_number);
  else if(rsa_type == RSA_TYPE_PRIVATE)
    sprintf(fileName,"%s/private_%02d.key", dir, server_number);
  else if(rsa_type == RSA_TYPE_CLIENT_PUBLIC)
    sprintf(fileName,"%s/public_client_%02d.key", dir, server_number);
  else if(rsa_type == RSA_TYPE_CLIENT_PRIVATE)
    sprintf(fileName,"%s/private_client_%02d.key", dir, server_number);
  else if(rsa_type == RSA_TYPE_NM_PUBLIC)
    sprintf(fileName,"%s/public_config_mngr.key", dir);
  else if(rsa_type == RSA_TYPE_NM_PRIVATE)
    sprintf(fileName,"%s/private_config_mngr.key", dir);
     
  f = fopen(fileName, "w");

  RSA_get0_key(rsa, &n, &e, &d);
  RSA_get0_factors(rsa, &p, &q);
  RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
  Write_BN(f, n);
  Write_BN(f, e);

  if(rsa_type == RSA_TYPE_PRIVATE || rsa_type == RSA_TYPE_CLIENT_PRIVATE
     || rsa_type == RSA_TYPE_NM_PRIVATE) {
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
  if (ret == NULL)
    Alarm(EXIT, "ERROR: Could not read BN\n");

  BN_hex2bn( bn, bn_buf );
}

void Read_RSA( int32u rsa_type, int32u server_number, RSA *rsa, const char *dir) 
{
  FILE *f;
  char fileName[50];
  //char dir[100] = "./keys";
  char client_keys_dir[100] = "./keys";
  BIGNUM *n = NULL, *e = NULL, *d = NULL;
  BIGNUM *p = NULL, *q = NULL;
  BIGNUM *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
  
  /* Read an RSA structure to a file */
  
  if(rsa_type == RSA_TYPE_PUBLIC)
    sprintf(fileName,"%s/public_%02d.key", dir, server_number);
  else if(rsa_type == RSA_TYPE_PRIVATE)
    sprintf(fileName,"%s/private_%02d.key", dir, server_number);
  else if(rsa_type == RSA_TYPE_CLIENT_PUBLIC)
    sprintf(fileName,"%s/public_client_%02d.key", client_keys_dir, server_number);
  else if(rsa_type == RSA_TYPE_CLIENT_PRIVATE)
    sprintf(fileName,"%s/private_client_%02d.key", client_keys_dir, server_number);
  else if(rsa_type == RSA_TYPE_NM_PUBLIC)
    sprintf(fileName,"%s/public_config_mngr.key", client_keys_dir);
  else if(rsa_type == RSA_TYPE_NM_PRIVATE)
    sprintf(fileName,"%s/private_config_mngr.key", client_keys_dir);
  //printf("Reading %s\n",fileName);  
  if((f = fopen( fileName, "r")) == NULL)
    Alarm(EXIT,"   ERROR: Could not open the key file: %s\n", fileName );
  
  Read_BN( f, &n );
  Read_BN( f, &e );
  if (!RSA_set0_key(rsa, n, e, d))
    Alarm(EXIT, "Error: Read_RSA: RSA_set0_key() failed (%s:%d)\n", __FILE__, __LINE__);
  if ( rsa_type == RSA_TYPE_PRIVATE || rsa_type == RSA_TYPE_CLIENT_PRIVATE 
       || rsa_type == RSA_TYPE_NM_PRIVATE) {
    Read_BN( f, &d );
    Read_BN( f, &p );
    Read_BN( f, &q );
    Read_BN( f, &dmp1 );
    Read_BN( f, &dmq1 );
    Read_BN( f, &iqmp );
    if (!RSA_set0_key(rsa, NULL, NULL, d))
      Alarm(EXIT, "Error: Read_RSA: RSA_set0_key() failed (%s:%d)\n", __FILE__, __LINE__);
    if (!RSA_set0_factors(rsa, p, q))
      Alarm(EXIT, "Error: Read_RSA: RSA_set0_key() failed (%s:%d)\n", __FILE__, __LINE__);
    if (!RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp))
      Alarm(EXIT, "Error: Read_RSA: RSA_set0_key() failed (%s:%d)\n", __FILE__, __LINE__);
  }

  fclose(f);
}


/* This function generates keys based on the current configuration as specified
 * in data_structs.h */
void OPENSSL_RSA_Generate_Keys() {

    RSA *rsa;
    int32u s;
    BIGNUM *e;
    int ret;
    /* Prompt user for a secret key value. */

    /* Generate Keys For Servers */
    rsa = RSA_new();
    e = BN_new();
    BN_set_word(e, 3);
    for ( s = 1; s <= MAX_NUM_SERVERS; s++ ) {
      ret = RSA_generate_key_ex( rsa, 1024, e, NULL );
      if (ret != 1)
        Alarm(EXIT, "OPENSSL_RSA_Generate_Keys: RSA_generate_key failed\n");
      /*RSA_print_fp( stdout, rsa, 4 );*/
      Write_RSA( RSA_TYPE_PUBLIC,  s, rsa ); 
      Write_RSA( RSA_TYPE_PRIVATE, s, rsa ); 
    } 

    /* Generate Keys For Clients */
    for ( s = 1; s <= NUMBER_OF_CLIENTS; s++ ) {
      ret = RSA_generate_key_ex( rsa, 1024, e, NULL );
      if (ret != 1)
        Alarm(EXIT, "OPENSSL_RSA_Generate_Keys: RSA_generate_key failed\n");
      /*RSA_print_fp( stdout, rsa, 4 );*/
      Write_RSA( RSA_TYPE_CLIENT_PUBLIC,  s, rsa ); 
      Write_RSA( RSA_TYPE_CLIENT_PRIVATE, s, rsa ); 
    }

    // MK Reconf: generating key pair for network manager
    ret = RSA_generate_key_ex( rsa, 1024, e, NULL );
      if (ret != 1)
        Alarm(EXIT, "OPENSSL_RSA_Generate_Keys: RSA_generate_key failed\n");
      /*RSA_print_fp( stdout, rsa, 4 );*/
      Write_RSA( RSA_TYPE_NM_PUBLIC,  1, rsa ); 
      Write_RSA( RSA_TYPE_NM_PRIVATE, 1, rsa );  

    RSA_free(rsa);
    BN_free(e);
}

void OPENSSL_RSA_Generate_Keys_with_args(int count,const char *keys_dir) {

    RSA *rsa;
    int32u s;
    BIGNUM *e;
    int ret;
    /* Prompt user for a secret key value. */

    /* Generate Keys For Servers */
    rsa = RSA_new();
    e = BN_new();
    BN_set_word(e, 3);
    for ( s = 1; s <= count; s++ ) {
      ret = RSA_generate_key_ex( rsa, 1024, e, NULL );
      if (ret != 1)
        Alarm(EXIT, "OPENSSL_RSA_Generate_Keys: RSA_generate_key failed\n");
      /*RSA_print_fp( stdout, rsa, 4 );*/
      Write_RSA_To_Dir( RSA_TYPE_PUBLIC,  s, rsa, keys_dir ); 
      Write_RSA_To_Dir( RSA_TYPE_PRIVATE, s, rsa, keys_dir ); 
    } 

    RSA_free(rsa);
    BN_free(e);
}
/* Read all of the keys for servers or clients. All of the public keys
 * should be read and the private key for this server should be read. */
 void OPENSSL_RSA_Read_Keys(int32u my_number, int32u type, const char *dir)
{
  int32u s; 
  int32u rt;
  
  //MS2022
  int32u READ_NUMBER_OF_SERVERS= VAR.Num_Servers;
  Alarm(DEBUG,"**********MS2022: READ_NUMBER_OF_SERVERS=%u\n",READ_NUMBER_OF_SERVERS);

  /* Read all public keys for servers. */
  for(s = 1; s <= READ_NUMBER_OF_SERVERS; s++) {
    public_rsa_by_server[s] = RSA_new();
    Read_RSA(RSA_TYPE_PUBLIC, s, public_rsa_by_server[s], dir);
  } 

  /* Read all public keys for clients. */
  for ( s = 1; s <= NUMBER_OF_CLIENTS; s++ ) {
    public_rsa_by_client[s] = RSA_new();
    Read_RSA( RSA_TYPE_CLIENT_PUBLIC, s, public_rsa_by_client[s], dir);
  }

  /* MK Reconf: Read public key for network manager. */
  public_rsa_by_nm = RSA_new();
  Read_RSA( RSA_TYPE_NM_PUBLIC, 1, public_rsa_by_nm,dir); 
    
  if ( type == RSA_SERVER ) {
    rt = RSA_TYPE_PRIVATE;
  } else if ( type == RSA_CLIENT ) {
    rt = RSA_TYPE_CLIENT_PRIVATE;
  } else if ( type == RSA_NM ) {
    rt = RSA_TYPE_NM_PRIVATE;
  } else if ( type == RSA_CONFIG_MNGR ){
    rt = RSA_TYPE_NM_PRIVATE;
    Alarm(DEBUG, "RSA_TYPE_CONFIG_MNGR_PRIVATE\n");
  } else if ( type == RSA_CONFIG_AGENT ){
    return;
  } else {
    Alarm(EXIT, "OPENSSL_RSA_Read_Keys: Called with invalid type.\n");
    exit(0); // explicit exit avoids warning about rt being possibly uninitialized below
  }

  /* Read my private key. */
  private_rsa = RSA_new();
  Read_RSA( rt, my_number, private_rsa, dir );

  if (type == RSA_SERVER ) {
    rt = RSA_TYPE_CLIENT_PRIVATE;
    private_client_rsa = RSA_new();
    Read_RSA( rt, my_number, private_client_rsa, dir );
  }
}

void OPENSSL_RSA_Init() 
{
  /* Load a table containing names and digest algorithms. */
  OpenSSL_add_all_digests();
  
  /* Use sha1 as the digest algorithm. */
  message_digest = EVP_get_digestbyname( DIGEST_ALGORITHM );
  verify_count = 0;

  mdctx = EVP_MD_CTX_new();
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

    sp_time start, end, diff;
    double elap;
    start = E_get_time();

    EVP_DigestInit_ex(mdctx, message_digest, NULL);
    EVP_DigestUpdate(mdctx, buffer, buffer_size);
    EVP_DigestFinal_ex(mdctx, digest_value, &md_len);

    /* Check to determine if the digest length is expected for sha1. It should
     * be DIGEST_SIZE bytes, which is 20 */
   
    if ( md_len != DIGEST_SIZE ) {
	printf("An error occurred while generating a message digest.\n"
		"The length of the digest was set to %d. It should be %d.\n"
		, md_len, DIGEST_SIZE);
	exit(0);
    }

    end = E_get_time();
    diff = E_sub_time(end, start);
    elap = diff.sec + diff.usec / 1000000.0;
    if (elap >= 0.0015)
        Alarm(DEBUG, "OPENSSL_Digest: %f sec\n", elap);
    
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
  sp_time start, end, diff;
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
  //private_rsa = RSA_generate_key( 1024, 3, Gen_Key_Callback, NULL );
 
  //start = E_get_time();

  RSA_sign(NID_sha1, digest_value, DIGEST_SIZE, signature, &signature_size,private_rsa);

  //end = E_get_time();
  
  //diff = E_sub_time(end, start);
  //Alarm(DEBUG, "Signing: %d sec; %d microsec\n", diff.sec, diff.usec);
  //OPENSSL_RSA_Print_Digest(digest_value);
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
    } else if (type == RSA_NM){
      rsa = public_rsa_by_nm;
    } else {
	if (number < 1 || number > VAR.Num_Servers ) {
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

int OPENSSL_RSA_Get_KeySize(const char *pubKeyFile){

   FILE *f=fopen(pubKeyFile,"r");
   if (!f){
        printf("Error opening file\n");
        exit(1);
   }

   RSA *pubkey=RSA_new();
   pubkey = PEM_read_RSA_PUBKEY(f, &pubkey, NULL, NULL);
    if(!pubkey){
        printf("OPENSSL_RSA: Error reading pub key\n");
        fclose(f);
        exit(1);
    }
   fclose(f);
   return RSA_size(pubkey);
}

int OPENSSL_RSA_Encrypt(const char *pubKeyFile,unsigned char *data, int data_len, unsigned char * encrypted_data){

   int ret;

  FILE *f=fopen(pubKeyFile,"r");
   if (!f){
        printf("Error opening file\n");
        exit(1);
   }

   RSA *pubkey=RSA_new();
   pubkey = PEM_read_RSA_PUBKEY(f, &pubkey, NULL, NULL);
    if(!pubkey){
        printf("OPENSSL_RSA: Error reading pub key\n");
        fclose(f);
        exit(1);
    }
   fclose(f);

   /*printf("Read pub key \n");*/
   /*printf("Read key size=%d\n",RSA_size(pubkey));*/

   ret = RSA_public_encrypt(data_len,data,encrypted_data,pubkey,RSA_NO_PADDING);
   /*ret = RSA_public_encrypt(data_len,data,encrypted_data,pubkey,RSA_PKCS1_PADDING);*/
   if(ret<=0){
        printf("OPENSSL_RSA: Encrypt error ret=%d\n",ret);
        exit(1);
   }
   /*printf("OPENSSL_RSA: encrypted data is %s\n",encrypted_data);*/
   fflush(stdout);
   return ret;
}

void OPENSSL_RSA_Decrypt(const char *pvtKeyFile,unsigned char *data, int data_len, unsigned char *decrypted_data){
    int ret;

   FILE *f=fopen(pvtKeyFile,"r");
   if (!f){
        printf("Error opening file\n");
        exit(1);
   }
   RSA *pvtkey=RSA_new();
   /*pvtkey = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);*/
   pvtkey = PEM_read_RSAPrivateKey(f, &pvtkey, NULL, NULL);
    if(!pvtkey){
        printf("OPENSSL_RSA: Error reading pvt key\n");
        fclose(f);
        exit(1);
    }
   fclose(f);


   /*RSA_PKCS1_PADDING - 11B padding */
   /*RSA_PKCS1_OAEP_PADDING - 42B padding */
    ret= RSA_private_decrypt(data_len,data,decrypted_data,pvtkey,RSA_NO_PADDING);
    /*ret= RSA_private_decrypt(data_len,data,decrypted_data,pvtkey,RSA_PKCS1_PADDING);*/
   if(ret<=0){
        printf("OPENSSL_RSA: Decrypt error ret=%d\n",ret);
        exit(1);
   }
   /*printf("OPENSSL_RSA: Decrypted text=%s\n",decrypted_data);*/

}

int getFileSize(const char * fileName){
    int ret=0;

    FILE *fp = fopen(fileName, "r");
    if(!fp){
        printf("Error opening file %s\n",fileName);
        exit(1);
    }
    fseek(fp, 0L, SEEK_SET);
    fseek(fp, 0, SEEK_END);
    ret=ftell(fp);
    fseek(fp, 0L, SEEK_SET);
    fclose(fp);
    return ret;
}

