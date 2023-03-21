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

#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include "arch.h"
#include "intrusion_tol_udp.h"
#include "priority_flood.h"
#include "reliable_flood.h"
#include "net_types.h"
#include "multipath.h"
#include "spines.h"

#include <stdio.h>
#include <openssl/sha.h>

#define CIPHER_BLK_LEN 16          /* AES-128-CBC */
#define HMAC_KEY_LEN 32            /* SHA-2-256 */
#define DH_PRIME_LEN_BITS 2048
#define SIGNATURE_LEN_BITS  1024   /* RSA 1024 */
#define PATH_STAMP_DEBUG 0
#define REMOTE_CONNECTIONS 1

#if (DH_PRIME_LEN_BITS % 8 != 0)
#  error DH_PRIME_LEN_BITS must be a multiple of 8!
#endif

#if (SIGNATURE_LEN_BITS % 8 != 0)
#  error SIGNATURE_LEN_BITS must be a multiple of 8!
#endif

#undef  ext
#ifndef ext_configuration
#define ext extern
#else
#define ext
#endif

/* Cryptography */
ext int16u Cipher_Blk_Len;
ext int16u HMAC_Key_Len;
ext int16u DH_Key_Len;
ext int16u Signature_Len;
ext int16u Signature_Len_Bits;
ext EVP_PKEY *Pub_Keys[MAX_NODES + 1];
ext EVP_PKEY *Priv_Key;
ext unsigned char Path_Stamp_Debug;
ext unsigned char Remote_Connections;

ext int16u           temp_neighbor_id[MAX_NODES+1][MAX_NODES+1];
ext Network_Address  temp_node_ip[MAX_NODES+1];
ext int16u           temp_num_nodes;
ext stdskl           Sorted_Edges;
ext int16u           Degree[MAX_NODES+1];

void        Pre_Conf_Setup(void);
void        Post_Conf_Setup(void);
void		Conf_init( char *file_name /*, char *my_name*/ );
void	    Conf_load_conf_file( char *file_name /*, char *my_name*/ );

void        Conf_set_all_crypto(bool new_state);
void        Conf_set_signature_len_bits(int new_value);
void        Conf_set_multipath_bitmask_size(int new_value);
void        Conf_set_directed_edges(bool new_state);
void        Conf_set_path_stamp_debug(bool new_state);
void        Conf_set_unix_domain_path(char *new_prefix);
void        Conf_set_remote_connections(bool new_state);

void        Conf_set_IT_crypto(bool new_state);
void        Conf_set_IT_encrypt(bool new_state);
void        Conf_set_IT_ordered_delivery(bool new_state);
void        Conf_set_IT_reintroduce_messages(bool new_state);
void        Conf_set_IT_tcp_fairness(bool new_state);
void        Conf_set_IT_session_blocking(bool new_state);
void        Conf_set_IT_msg_per_saa(int new_value);
void        Conf_set_IT_send_batch_size(int new_value);
void        Conf_set_IT_intrusion_tolerance_mode(bool new_state);
void        Conf_set_IT_reliable_timeout_factor(int new_value);
void        Conf_set_IT_nack_timeout_factor(int new_value);
void        Conf_set_IT_init_nack_timeout_factor(float new_value);
void        Conf_set_IT_ack_timeout(int new_value);
void        Conf_set_IT_ping_timeout(int new_value);
void        Conf_set_IT_dh_timeout(int new_value);
void        Conf_set_IT_incarnation_timeout(int new_value);
void        Conf_set_IT_min_RTT_ms(int new_value);
void        Conf_set_IT_default_RTT(int new_value);

void        Conf_set_RR_crypto(bool new_state);

void        Conf_set_Prio_crypto(bool new_state);
void        Conf_set_Prio_default_prio(int new_value);
void        Conf_set_Prio_max_mess_stored(int new_value);
void        Conf_set_Prio_min_belly_size(int new_value);
void        Conf_set_Prio_default_expire_sec(int new_value);
void        Conf_set_Prio_default_expire_usec(int new_value);
void        Conf_set_Prio_garbage_collection_sec(int new_value);
    
void        Conf_set_Rel_crypto(bool new_state);
void        Conf_set_Rel_saa_threshold(int new_value);
void        Conf_set_Rel_hbh_advance(bool new_state);
void        Conf_set_Rel_hbh_ack_timeout(int new_value);
void        Conf_set_Rel_e2e_ack_timeout(int new_value);
void        Conf_set_Rel_hbh_ack_optimization(bool new_state);
void        Conf_set_Rel_e2e_ack_optimization(bool new_state);

void        Conf_set_Reroute_loss_threshold(float new_value);
void        Conf_set_Reroute_loss_calc_decay(float new_value);
void        Conf_set_Reroute_loss_calc_time_trigger(int new_value); 
void        Conf_set_Reroute_loss_calc_pkt_trigger(int new_value); 
void        Conf_set_Reroute_loss_penalty(int new_value); 
void        Conf_set_Reroute_ping_threshold(int new_value); 
void        Conf_set_Reroute_status_change_timeout(int new_value);

void        Conf_add_host(int id, int ip);
void        Conf_validate_hosts(void);
void        Conf_add_edge(int host1, int host2, int cost);

void        Conf_compute_hash(void);

#endif /* CONFIGURATION_H */
