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

#define ext_configuration
#include "configuration.h"
#undef ext_configuration

#define ext_conf_body
#include "conf_body.h"
#undef  ext_conf_body

#include <string.h>

#include "spu_alarm.h"
#include "spu_memory.h"

/* Configuration File Variables */
extern char        Config_File_Found;
extern char        Unix_Domain_Prefix[];
extern char        Unix_Domain_Use_Default;
extern stdhash     Node_Lookup_Addr_to_ID;
extern stdhash     Node_Lookup_ID_to_Addr;
extern int16u      My_ID;
extern int32u      *Neighbor_Addrs[];
extern int16u      *Neighbor_IDs[];

extern Node_ID           My_Address;
extern int16u            Num_Local_Interfaces;
extern Network_Address   My_Interface_Addresses[];

unsigned char Conf_Hash[SHA256_DIGEST_LENGTH];

int Edge_Cmp(const void *l, const void *r);

/* Hash function for string to 32 bit int */
/* static LOC_INLINE int32u conf_hash_string(const void * key, int32u key_len)
{
    const char * kit  = (const char*) key;
    const char * kend = (const char*) key + key_len;
    int32u    ret  = (int32u) key_len ^ ((int32u) key_len << 8) ^
        ((int32u) key_len << 16) ^ ((int32u) key_len << 24);

    for (; kit != kend; ++kit) {
        ret += *kit;
        ret += (ret << 10);
        ret ^= (ret >> 6);
    }

    ret += (ret << 3);
    ret ^= (ret >> 11);
    ret += (ret << 15);

    return ret;
} */

void    Pre_Conf_Setup()
{
    int i, j;

    My_ID  = 0;

    stdhash_construct(&Node_Lookup_Addr_to_ID, sizeof(int32), sizeof(int32),
              NULL, NULL, 0);

    stdhash_construct(&Node_Lookup_ID_to_Addr, sizeof(int32), sizeof(int32),
              NULL, NULL, 0);
    
    stdskl_construct(&Sorted_Edges, sizeof(Edge_Key), sizeof(Edge_Value), Edge_Cmp);

    for (i = 0; i <= MAX_NODES; i++) {
        Degree[i] = 0;
        temp_node_ip[i] = 0;
        for (j = 0; j <= MAX_NODES; j++) {
            temp_neighbor_id[i][j] = 0;
        }
    }
    temp_num_nodes = 0;

    Cipher_Blk_Len = CIPHER_BLK_LEN;
    HMAC_Key_Len = HMAC_KEY_LEN;
    DH_Key_Len = DH_PRIME_LEN_BITS / 8;
    Signature_Len_Bits = SIGNATURE_LEN_BITS;
    Path_Stamp_Debug = PATH_STAMP_DEBUG;
    Remote_Connections = REMOTE_CONNECTIONS;

    IT_Link_Pre_Conf_Setup();
    RR_Pre_Conf_Setup();
    Prio_Pre_Conf_Setup();
    Rel_Pre_Conf_Setup();
    MultiPath_Pre_Conf_Setup();
}


void    Post_Conf_Setup()
{
    unsigned int     i, j;
    char             keyFile[80];
    FILE            *key_fp;

    for (i=1; i <= MAX_NODES; i++) { 
        Neighbor_IDs[i]   = (int16u *) Mem_alloc( sizeof(int16u) * (Degree[i]+1) );
        Neighbor_Addrs[i] = (int32u *) Mem_alloc( sizeof(int32u) * (Degree[i]+1) );

        for (j=1; j <= Degree[i]; j++) {
            Neighbor_IDs[i][j]    = temp_neighbor_id[i][j];
            Neighbor_Addrs[i][j]  = temp_node_ip[temp_neighbor_id[i][j]];
        }
    }

    printf("Degree = %d\n", Degree[My_ID]);
    for (j=1; j <= Degree[My_ID]; j++)
        printf("Ngbr[%d] = (%d,"IPF")\n", j, Neighbor_IDs[My_ID][j], IP(Neighbor_Addrs[My_ID][j]));

    Num_Nodes = temp_num_nodes;

    if (Conf_IT_Link.Crypto == 1 || Conf_Prio.Crypto == 1 || Conf_Rel.Crypto == 1) {
        snprintf(keyFile, 80, "keys/private%d.pem", My_ID);
        key_fp = fopen(keyFile, "r");
        if (key_fp == NULL)
            Alarm(EXIT, "Post_Conf_Setup: cannot find file "
                        "keys/private%d.pem\r\n", My_ID);
        Priv_Key = PEM_read_PrivateKey(fopen(keyFile,"r"), 
                NULL, NULL, NULL);
        if (Priv_Key == NULL)
            Alarm(EXIT, "Post_Conf_Setup: Unable to read key "
                        "from keys/private%d.pem\r\n", My_ID);
        Signature_Len = EVP_PKEY_size(Priv_Key);
        if (Signature_Len != Signature_Len_Bits / 8)
            Alarm(EXIT, "Post_Conf_Setup: Key_Length mismatch\r\n");
    }
    else {
        Cipher_Blk_Len = 0;
        HMAC_Key_Len = 0;
        DH_Key_Len = 0;
        Signature_Len = 0;
    }

    if (Conf_Prio.Crypto == 1)
        Prio_Signature_Len = Signature_Len;
    else
        Prio_Signature_Len = 0;

    if (Conf_Rel.Crypto == 1)
        Rel_Signature_Len = Signature_Len;
    else
        Rel_Signature_Len = 0;
    
    IT_Link_Post_Conf_Setup();
    RR_Post_Conf_Setup();
    Prio_Post_Conf_Setup();
    Rel_Post_Conf_Setup();

    Conf_compute_hash();
}

void	Conf_init( char *file_name /*, char *my_name*/ )
{
        /* strncpy(Conf_FileName, file_name, 80); */
        /*if (my_name != NULL) {
                strncpy(Conf_MyName_buf, my_name, 80);
                Conf_MyName = &Conf_MyName_buf[0];
        } else {
                Conf_MyName = NULL;
        }*/

        Pre_Conf_Setup();

        Conf_load_conf_file( file_name /*, my_name*/ );

        Post_Conf_Setup();
}

void	Conf_load_conf_file( char *file_name /*, char *my_name*/ )
{
        /* struct hostent  *host_ptr;
	    char	machine_name[256];
	    char	ip[16];
	    int	i,j;
        int     added_len;
        unsigned int name_len; */
        char    configfile_location[MAXPATHLEN];

        /* Initialize hash string */
        ConfStringRep[0] = '\0';
        ConfStringLen = 0;

	/* init Config from file
	   init My from host
	 */
        configfile_location[0] = '\0';
        strcat(configfile_location, SPREAD_ETCDIR);
        strcat(configfile_location, "/spines.conf");

	if (NULL != (yyin = fopen(file_name,"r")) )
                Alarm( PRINT, "Conf_load_conf_file: using file: %s\n", file_name);
	if (yyin == NULL) 
		if (NULL != (yyin = fopen("./spines.conf", "r")) )
                        Alarm( PRINT, "Conf_load_conf_file: using file: ./spines.conf\n");
	if (yyin == NULL)
		if (NULL != (yyin = fopen(configfile_location, "r")) )
                        Alarm( PRINT, "Conf_load_conf_file: using file: %s\n", configfile_location);
	if (yyin == NULL)
		/* Alarm( EXIT, "Conf_load_conf_file: error opening config file %s\n",
			file_name); */
		Alarm( PRINT, "Conf_load_conf_file: no spines.conf configuration file found," 
                        " using default parameters\n");

    if (yyin != NULL) {
        /* reinitialize all the variables in the yacc parser */
        parser_init();
        
	    yyparse();

        fclose(yyin);

        Config_File_Found = 1;
    }

        /* Final Error Checking? */
        
        /* calculate hash value of configuration. 
         * This daemon will only work with other daemons who have an identical hash value.
         */
        /*Config->hash_code = conf_hash_string(ConfStringRep, ConfStringLen);
        Alarmp( SPLOG_DEBUG, CONF_SYS, "Full hash string is %d characters long:\n%s", ConfStringLen, ConfStringRep);
        Alarmp( SPLOG_INFO, CONF_SYS, "Hash value for this configuration is: %u\n", Config->hash_code); */

        /* Match my IP address to entry in configuration file */
	/* if( my_name == NULL ){
		gethostname(machine_name,sizeof(machine_name)); 
		host_ptr = gethostbyname(machine_name);
		if( host_ptr == 0 )
			Alarm( EXIT, "Conf_load_conf_file: could not get my ip address (my name is %s)\n",
				machine_name );
                if (host_ptr->h_addrtype != AF_INET)
                        Alarm(EXIT, "Conf_load_conf_file: Sorry, cannot handle addr types other than IPv4\n");
                if (host_ptr->h_length != 4)
                        Alarm(EXIT, "Conf_load_conf_file: Bad IPv4 address length\n");
	
		i = -1;	*/ /* in case host_ptr->h_length == 0 */
        /*        for (j = 0; host_ptr->h_addr_list[j] != NULL; j++) {
                        memcpy(&My.id, host_ptr->h_addr_list[j], sizeof(struct in_addr));
			My.id = ntohl( My.id );
			i = Conf_proc_by_id( My.id, &My );
			if( i >= 0 ) break;
                }
		if( i < 0 ) Alarm( EXIT,
			"Conf_load_conf_file: My proc id (%d.%d.%d.%d) is not in configuration\n", IP1(My.id),IP2(My.id),IP3(My.id),IP4(My.id) );

	}else if( ! strcmp( my_name, "Monitor" ) ){
		gethostname(machine_name,sizeof(machine_name)); 
		host_ptr = gethostbyname(machine_name);

		if( host_ptr == 0 )
			Alarm( EXIT, "Conf_load_conf_file: no such monitor host %s\n",
				machine_name );

        	memcpy(&My.id, host_ptr->h_addr_list[0], 
			sizeof(int32) );
		My.id = ntohl( My.id );

		name_len = strlen( machine_name );
		if( name_len > sizeof(My.name) ) name_len = sizeof(My.name);
		memcpy(My.name, machine_name, name_len );
		Alarm( CONF_SYS, "Conf_load_conf_file: My name: %s, id: %d\n",
			My.name, My.id );
		return;
	}else{
		name_len = strlen( my_name );
		if( name_len > sizeof(My.name) ) name_len = sizeof(My.name);
		memcpy(My.name, my_name, name_len );
		i = Conf_proc_by_name( My.name, &My );
		if( i < 0  ) Alarm( EXIT,
				"Conf_load_conf_file: My proc %s is not in configuration \n",
				My.name);

	} */

	/* Conf_id_to_str( My.id, ip );
	Alarm( CONF_SYS, "Conf_load_conf_file: My name: %s, id: %s, port: %hd\n",
		My.name, ip, My.port ); */

    Alarm(DEBUG, "Conf_load_conf_file complete!\n");
	return;
}

void Conf_set_all_crypto(bool new_state) 
{
    /* Crypto = new_state; */
    Conf_set_IT_crypto(new_state);
    Conf_set_IT_encrypt(new_state);
    Conf_set_RR_crypto(new_state);
    Conf_set_Prio_crypto(new_state);
    Conf_set_Rel_crypto(new_state);
}

void Conf_set_signature_len_bits(int new_value)
{
    if (new_value != 2048 && new_value != 1024 && new_value != 512)
        Alarm(EXIT, "Conf_signature_len_bits: Configuration File must "
                "specify either 512 or 1024 or 2048 bit signatures\r\n");
    Signature_Len_Bits = new_value;
}

void Conf_set_multipath_bitmask_size(int new_value)
{
    if (new_value % 64 != 0)
        Alarm(EXIT, "Conf_set_multipath_bitmask_size: bitmask size must "
                    "be a multiple of 64\r\n");
    if (new_value <= 0)
        Alarm(EXIT, "Conf_set_multipath_bitmask_size: bitmask size must "
                    "be greater than 0 \r\n");
    MultiPath_Bitmask_Size = new_value / 8;
}

void Conf_set_directed_edges(bool new_state)
{
    Directed_Edges = new_state;
}

void Conf_set_path_stamp_debug(bool new_state)
{
    Path_Stamp_Debug = new_state; 
}

void Conf_set_unix_domain_path(char *new_prefix)
{
#ifndef ARCH_PC_WIN95
    int ret;
    size_t s_len;

    /* Check room for length of "data" suffix and NULL byte */
    s_len = SUN_PATH_LEN - strlen(SPINES_UNIX_DATA_SUFFIX) - 1;
    ret = snprintf(Unix_Domain_Prefix, s_len, "%s", new_prefix);
    if (ret > s_len) {
        Alarm(EXIT, "Conf_set_unix_domain_path: path name too long (%d), "
                        "max allowed = %u\n", ret, s_len);
    }
    Unix_Domain_Use_Default = 0;
#endif
}

void Conf_set_remote_connections(bool new_state)
{
    Remote_Connections = new_state;
}

void Conf_set_IT_crypto(bool new_state)
{
    if (My_ID != 0)
        Alarm(EXIT, "Conf_set_IT_crypto: Crypto settings cannot be altered "
                "once hosts are loaded. Please move Crypto settings before "
                "the host lists in the configuration file.\n");

    if (Conf_IT_Link.Crypto != new_state)
        Alarm(PRINT, "Conf_set_IT_crypto: changed Crypto to %s\n", 
                        (new_state)?"TRUE":"FALSE");

    if (!(Conf_IT_Link.Crypto = new_state))
        Conf_set_IT_encrypt(0);
}

void Conf_set_IT_encrypt(bool new_state)
{
    if (My_ID != 0)
        Alarm(EXIT, "Conf_set_IT_encrypt: Crypto settings cannot be altered "
                "once hosts are loaded. Please move Crypto settings before "
                "the host lists in the configuration file.\n");

    if (Conf_IT_Link.Crypto != new_state)
        Alarm(PRINT, "Conf_set_IT_crypto: changed Crypto to %s\n", ((new_state) ? "TRUE" : "FALSE"));
    
    if ((Conf_IT_Link.Encrypt = new_state))
        Conf_set_IT_crypto(1);
}

void Conf_set_IT_ordered_delivery(bool new_state)
{
    Conf_IT_Link.Ordered_Delivery = new_state;
}

void Conf_set_IT_reintroduce_messages(bool new_state)
{
    Conf_IT_Link.Reintroduce_Messages = new_state;
}

void Conf_set_IT_tcp_fairness(bool new_state)
{
    Conf_IT_Link.TCP_Fairness = new_state;
}

void Conf_set_IT_session_blocking(bool new_state)
{
    Conf_IT_Link.Session_Blocking = new_state;
}

void Conf_set_IT_msg_per_saa(int new_value)
{
    if (new_value <= 0) {
        Alarm(PRINT, "Conf_set_IT_msg_per_saa: Invalid value (%d)\n", 
                new_value);
        return;
    }
    Conf_IT_Link.Msg_Per_SAA = new_value;
}

void Conf_set_IT_send_batch_size(int new_value)
{
    if (new_value <= 0) {
        Alarm(PRINT, "Conf_set_IT_send_batch_size: Invalid value (%d)\n", 
                new_value);
        return;
    }
    Conf_IT_Link.Send_Batch_Size = new_value;
}


void Conf_set_IT_intrusion_tolerance_mode(bool new_state) 
{
    Conf_IT_Link.Intrusion_Tolerance_Mode = new_state;
}

void Conf_set_IT_reliable_timeout_factor(int new_value)
{
    if (new_value <= 0) {
        Alarm(PRINT, "Conf_set_IT_reliable_timeout_factor: Invalid value (%d)\n", 
                new_value);
        return;
    }
    Conf_IT_Link.Reliable_Timeout_Factor = new_value;
}

void Conf_set_IT_nack_timeout_factor(int new_value)
{
    if (new_value <= 0) {
        Alarm(PRINT, "Conf_set_IT_nack_timeout_factor: Invalid value (%d)\n", 
                new_value);
        return;
    }
    Conf_IT_Link.NACK_Timeout_Factor = new_value;
}

void Conf_set_IT_init_nack_timeout_factor(float new_value)
{
    if (new_value <= 0) {
        Alarm(PRINT, "Conf_set_IT_init_nack_timeout_factor: Invalid value (%d)\n", 
                new_value);
        return;
    }
    Conf_IT_Link.Init_NACK_Timeout_Factor = new_value;
}

void Conf_set_IT_ack_timeout(int new_value)
{
    if (new_value <= 0) {
        Alarm(PRINT, "Conf_set_IT_ack_timeout: Invalid value (%d)\n", 
                new_value);
        return;
    }
    Conf_IT_Link.ACK_Timeout = new_value;
}

void Conf_set_IT_ping_timeout(int new_value)
{
    if (new_value <= 0) {
        Alarm(PRINT, "Conf_set_IT_ping_timeout: Invalid value (%d)\n", 
                new_value);
        return;
    }
    Conf_IT_Link.PING_Timeout = new_value;
}

void Conf_set_IT_dh_timeout(int new_value)
{
    if (new_value <= 0) {
        Alarm(PRINT, "Conf_set_IT_dh_timeout: Invalid value (%d)\n", 
                new_value);
        return;
    }
    Conf_IT_Link.DH_Timeout = new_value;
}

void Conf_set_IT_incarnation_timeout(int new_value)
{
    if (new_value <= 0) {
        Alarm(PRINT, "Conf_set_IT_incarnation_timeout: Invalid value (%d)\n", 
                new_value);
        return;
    }
    Conf_IT_Link.Incarnation_Timeout = new_value;
}

void Conf_set_IT_min_RTT_ms(int new_value)
{
    if (new_value <= 0) {
        Alarm(PRINT, "Conf_set_IT_min_RTT_ms: Invalid value (%d)\n", 
                new_value);
        return;
    }
    Conf_IT_Link.Min_RTT_milliseconds = new_value;
}

void Conf_set_IT_default_RTT(int new_value)
{
    if (new_value <= 0) {
        Alarm(PRINT, "Conf_set_IT_default_RTT: Invalid value (%d)\n", 
                new_value);
        return;
    }
    Conf_IT_Link.Default_RTT = new_value;
}

void Conf_set_RR_crypto(bool new_state) 
{
    if (My_ID != 0)
        Alarm(EXIT, "Conf_set_RR_crypto: Crypto settings cannot be altered "
                "once hosts are loaded. Please move Crypto settings before "
                "the host lists in the configuration file.\n");

    if (Conf_RR.Crypto != new_state)
        Alarm(PRINT, "Conf_set_RR_crypto: changed Crypto to %s\n", 
                        (new_state)?"TRUE":"FALSE");
    Conf_RR.Crypto = new_state;
}

void Conf_set_Prio_crypto(bool new_state)
{
    if (My_ID != 0)
        Alarm(EXIT, "Conf_set_Prio_crypto: Crypto settings cannot be altered "
                "once hosts are loaded. Please move Crypto settings before "
                "the host lists in the configuration file.\n");

    if (Conf_Prio.Crypto != new_state)
        Alarm(PRINT, "Conf_set_Prio_crypto: changed Crypto to %s\n", 
                        (new_state)?"TRUE":"FALSE");
    Conf_Prio.Crypto = new_state;
}

void Conf_set_Prio_default_prio(int new_value)
{
    if (new_value <= 0 || new_value > MAX_PRIORITY) {
        Alarm(PRINT, "Conf_set_Prio_Default_prio: Invalid value (%d)\n",
            new_value);
        return;
    }
    Conf_Prio.Default_Priority = new_value;
}

void Conf_set_Prio_max_mess_stored(int new_value)
{
    if (new_value <= 0) {
        Alarm(PRINT, "Conf_set_Prio_max_mess_stored: Invalid value (%d)\n",
            new_value);
        return;
    }
    Conf_Prio.Max_Mess_Stored = new_value;
}

void Conf_set_Prio_min_belly_size(int new_value)
{
    if (new_value <= 0) {
        Alarm(PRINT, "Conf_set_Prio_min_belly_size: Invalid value (%d)\n",
            new_value);
        return;
    }
    Conf_Prio.Min_Belly_Size = new_value;
}

void Conf_set_Prio_default_expire_sec(int new_value)
{
    if (new_value < 0) {
        Alarm(PRINT, "Conf_set_Prio_default_expire_sec: Invalid value (%d)\n",
            new_value);
        return;
    }
    Conf_Prio.Default_Expire_Sec = new_value;
}

void Conf_set_Prio_default_expire_usec(int new_value)
{
    if (new_value < 0 || new_value >= 1000000) {
        Alarm(PRINT, "Conf_set_Prio_default_expire_usec: Invalid value (%d)\n",
            new_value);
        return;
    }
    Conf_Prio.Default_Expire_USec = new_value;
}

void Conf_set_Prio_garbage_collection_sec(int new_value)
{
    if (new_value <= 0) {
        Alarm(PRINT, "Conf_set_Prio_garbage_collection_sec: Invalid value (%d)\n",
            new_value);
        return;
    }
    Conf_Prio.Garbage_Collection_Sec = new_value;
}

void Conf_set_Rel_crypto(bool new_state)
{
    if (My_ID != 0)
        Alarm(EXIT, "Conf_set_Rel_crypto: Crypto settings cannot be altered "
                "once hosts are loaded. Please move Crypto settings before "
                "the host lists in the configuration file.\n");

    if (Conf_Rel.Crypto != new_state)
        Alarm(PRINT, "Conf_set_Rel_crypto: changed Crypto to %s\n", 
                        (new_state)?"TRUE":"FALSE");
    Conf_Rel.Crypto = new_state;
}

void Conf_set_Rel_saa_threshold(int new_value)
{
    if (new_value <= 0) {
        Alarm(PRINT, "Conf_set_Rel_saa_threshold: Invalid value (%d)\n",
            new_value);
        return;
    }
    Conf_Rel.SAA_Threshold = new_value;
}

void Conf_set_Rel_hbh_advance(bool new_state)
{
    Conf_Rel.HBH_Advance = new_state;
}

void Conf_set_Rel_hbh_ack_timeout(int new_value)
{
    if (new_value <= 0) {
        Alarm(PRINT, "Conf_set_Rel_hbh_ack_timeout: Invalid value (%d)\n",
            new_value);
        return;
    }
    Conf_Rel.HBH_Ack_Timeout = new_value;
}

void Conf_set_Rel_e2e_ack_timeout(int new_value)
{
    if (new_value <= 0) {
        Alarm(PRINT, "Conf_set_Rel_e2e_ack_timeout: Invalid value (%d)\n",
            new_value);
        return;
    }
    Conf_Rel.E2E_Ack_Timeout = new_value;
}

void Conf_set_Rel_hbh_ack_optimization(bool new_state)
{
    Conf_Rel.HBH_Opt = new_state;
}

void Conf_set_Rel_e2e_ack_optimization(bool new_state)
{
    Conf_Rel.E2E_Opt = new_state;
}

void Conf_set_Reroute_loss_threshold(float new_value)
{
    if (new_value < 0 || new_value > 1) {
        Alarm(PRINT, "Conf_set_Reroute_loss_threshold: Invalid value (%d)\n",
            new_value);
        return;
    }
    Conf_IT_Link.Loss_Threshold = new_value;
}

void Conf_set_Reroute_loss_calc_decay(float new_value)
{
    if (new_value <= 0) {
        Alarm(PRINT, "Conf_set_Reroute_loss_calc_decay: Invalid value (%d)\n",
            new_value);
        return;
    }
    Conf_IT_Link.Loss_Calc_Decay = new_value;
}

void Conf_set_Reroute_loss_calc_time_trigger(int new_value)
{
    if (new_value <= 0) {
        Alarm(PRINT, "Conf_set_Reroute_loss_calc_time_trigger: Invalid value (%d)\n",
            new_value);
        return;
    }
    Conf_IT_Link.Loss_Calc_Time_Trigger = new_value;
}

void Conf_set_Reroute_loss_calc_pkt_trigger(int new_value)
{
    if (new_value <= 0) {
        Alarm(PRINT, "Conf_set_Reroute_loss_calc_pkt_trigger: Invalid value (%d)\n",
            new_value);
        return;
    }
    Conf_IT_Link.Loss_Calc_Pkt_Trigger = new_value;
}

void Conf_set_Reroute_loss_penalty(int new_value)
{
    if (new_value <= 0) {
        Alarm(PRINT, "Conf_set_Reroute_loss_penalty: Invalid value (%d)\n",
            new_value);
        return;
    }
    Conf_IT_Link.Loss_Penalty = new_value;
}

void Conf_set_Reroute_ping_threshold(int new_value)
{
    if (new_value <= 0) {
        Alarm(PRINT, "Conf_set_Reroute_ping_threshold: Invalid value (%d)\n",
            new_value);
        return;
    }
    Conf_IT_Link.Ping_Threshold = new_value;
}

void Conf_set_Reroute_status_change_timeout(int new_value)
{
    if (new_value <= 0) {
        Alarm(PRINT, "Conf_set_Reroute_status_change_timeout: Invalid value (%d)\n",
            new_value);
        return;
    }
    Conf_Rel.Status_Change_Timeout = new_value;
}

void Conf_add_host(int id, int ip)
{
    stdit   ip_it;
    char    keyFile[80];
    FILE    *key_fp;

    /* Alarm(PRINT, "Conf_add_host invoked (%d)\n", id); */

    if (id <= 0) {
        Alarm(EXIT, "Conf_add_host: Invalid ID (%d) - Too Low\n", id);
    }
    else if (id > MAX_NODES) {
        Alarm(EXIT, "Conf_add_host: Invalid ID (%d) - Higher than Node Limit\n", id);
    }

    if (temp_node_ip[id] != 0) {
        Alarm(PRINT, "Conf_add_host: Ignoring host [%d]: "IPF", entry already"
                " exists for this ID\r\n", id, IP(ip));
        return;
    }

    /* Store the address */
    stdhash_insert(&Node_Lookup_Addr_to_ID, &ip_it, &ip, &id);
    stdhash_insert(&Node_Lookup_ID_to_Addr, &ip_it, &id, &ip);
    if (ip == My_Address)
        My_ID = id;
    temp_node_ip[id] = ip;
    temp_num_nodes++;

    if (Conf_IT_Link.Crypto == 1 || Conf_Prio.Crypto == 1 || Conf_Rel.Crypto == 1) {
        snprintf(keyFile, 80, "keys/public%d.pem", id);
        key_fp = fopen(keyFile, "r");
        if (key_fp == NULL)
            Alarm(EXIT, "Util_Load_Addresses: cannot find file "
                        "keys/public%d.pem\r\n", id);
        Pub_Keys[id] = PEM_read_PUBKEY(fopen(keyFile,"r"), 
                NULL, NULL, NULL);
        if (Pub_Keys[id] == NULL)
            Alarm(EXIT, "Util_Load_Addresses: Unable to read key "
                        "from keys/public%d.pem\r\n", id);
    }

}

void    Conf_validate_hosts()
{
    if (My_ID == 0)
        Alarm(EXIT, "Conf_validate_hosts: This machine is not specified"
                " as a host in the configuration file\n");
}

void    Conf_add_edge(int h1, int h2, int c) 
{
    stdit it;
    Edge_Key key;
    Edge_Value val;


    Alarm(DEBUG, "Conf_add_edge invoked between %d and %d\n", h1, h2);
 
    if (temp_node_ip[h1] == 0 || temp_node_ip[h2] == 0) {
        Alarm(EXIT, "Conf_add_edge: Adding an edge between logical"
                " IDs that are not both defined (%d, %d)\r\n", h1, h2);
        
        return;
    }

    if (h1 == h2) {
        Alarm(PRINT, "Conf_add_edge: Ignoring edge (%d, %d) since both"
                " endpoints are the same node\r\n", h1, h2);
        return;
    }

    /* Am I an endpoint of this edge? */
    if (Directed_Edges == 0) {
        Degree[h1]++;
        Degree[h2]++;
        temp_neighbor_id[h1][Degree[h1]] = h2;
        temp_neighbor_id[h2][Degree[h2]] = h1;

        if (h1 == My_ID) {
            Remote_Interface_Addresses[Num_Legs] = temp_node_ip[h2];
            ++Num_Legs;
        }
        else if (h2 == My_ID) {
            Remote_Interface_Addresses[Num_Legs] = temp_node_ip[h1];
            ++Num_Legs;
        }
    }
    else { /* Directed_Edges == 1 */
        Degree[h1]++;
        temp_neighbor_id[h1][Degree[h1]] = h2;

        if (h1 == My_ID) {
            Remote_Interface_Addresses[Num_Legs] = temp_node_ip[h2];
            ++Num_Legs;
        }
    }

    /* Store the Edge in the global structure */
    if (Directed_Edges == 0) {
        if (h1 < h2) {
            key.src_id = h1;
            key.dst_id = h2;
        }
        else {
            key.src_id = h2;
            key.dst_id = h1;
        }
    }
    else { /* Directed_Edges == 1 */
        key.src_id = h1;
        key.dst_id = h2;
    }
    val.cost = c;
    val.index = 0;

    stdskl_insert(&Sorted_Edges, &it, &key, &val, STDFALSE);
}

void    Conf_compute_hash()
{
    unsigned char buff[2048] = { 0 };
    int16u i, written = 0;
    stdit it;
    Edge_Key key;
    Edge_Value val;

    written += IT_Link_Conf_hton(buff + written);
    written += RR_Conf_hton(buff + written);
    written += Prio_Conf_hton(buff + written);
    written += Rel_Conf_hton(buff + written);

    /* Add Signature_Len_Bits */
    *(int16u*)(buff + written) = Signature_Len_Bits;
        written += sizeof(int16u);

    /* Add MultiPath_Bitmask_Size */
    *(int16u*)(buff + written) = MultiPath_Bitmask_Size;
        written += sizeof(int16u);

    /* Add Directed_Edges */
    *(unsigned char*)(buff + written) = Directed_Edges;
        written += sizeof(unsigned char);

    /* Add Path_Stamp_Debug */
    *(unsigned char*)(buff + written) = Path_Stamp_Debug;
        written += sizeof(unsigned char);

    *(unsigned char*)(buff + written) = Remote_Connections;
        written += sizeof(unsigned char);

    /* Add Host List - Use the whole array (temp_node_ip) including blanks */
    for (i = 1; i <= MAX_NODES; i++) {
        *(Network_Address*)(buff + written) = temp_node_ip[i];
            written += sizeof(Network_Address);
    }

    /* Add Edge List - Use Sorted_Edges (just pair of IDs) */
    stdskl_begin(&Sorted_Edges, &it);
    while (!stdskl_is_end(&Sorted_Edges, &it)) {
        key = *(Edge_Key*)stdskl_it_key(&it);
        val = *(Edge_Value*)stdskl_it_val(&it);
        *(Node_ID*)(buff + written) = key.src_id;
            written += sizeof(Node_ID);
        *(Node_ID*)(buff + written) = key.dst_id;
            written += sizeof(Node_ID);
        *(int16u*)(buff + written) = val.cost;
            written += sizeof(int16u);
        stdskl_it_next(&it);
    }

    /*printf("BUFF =");
    for (i = 0; i < written; i++) 
        printf("%02x", buff[i]);
        printf("\n");*/

    SHA256(buff, written, Conf_Hash);

    /*printf("HASH = ");
    for (i = 0; i < HMAC_Key_Len; i++) 
        printf("%02x", Conf_Hash[i]);
        printf("\n");*/
}

int Edge_Cmp(const void *l, const void *r)
{
    Edge_Key *left  = (Edge_Key*)l;
    Edge_Key *right = (Edge_Key*)r;

    if (left->src_id < right->src_id)
        return -1;
    else if (left->src_id > right->src_id)
        return 1;
    else {
        if (left->dst_id < right->dst_id)
            return -1;
        else if (left->dst_id > right->dst_id)
            return 1;
        else
            return 0;
    }
}


/* static void set_param_if_valid(char **param, char *value, char *description, unsigned int max_value_len)
{
        if (value != NULL && *value != '\0')
        {
                unsigned int len = strlen(value);
                char *old_value = *param;
                char *buf;
                if (len > max_value_len)
                {
                    Alarm(EXIT, "set_param_if_valid: value string too long\n");
                }
                buf = Mem_alloc(len + 1);
                if (buf == NULL)
                {
                        Alarm(EXIT, "set_param_if_valid: Out of memory\n");
                }
                strncpy(buf, value, len);
                buf[len] = '\0';

                *param = buf;
                if (old_value != NULL)
                {
                    dispose(old_value);
                }
                Alarm(PRINT, "Set %s to '%s'\n", description, value);
        }
        else
        {
                Alarm(DEBUG, "Ignored invalid %s\n", description);
        }
} */
