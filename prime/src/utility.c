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

#include <assert.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include "data_structs.h"
#include "utility.h"
#include "network.h"
#include "util_dll.h"
#include "spu_memory.h"
#include "spu_alarm.h"
#include "spu_data_link.h"
#include "objects.h"
#include "merkle.h"
#include "def.h"
#include "net_wrapper.h"
#include "signature.h"
#include "order.h"

#ifdef SET_USE_SPINES
#include "spines_lib.h"
#endif

/* The globally accessible variables */
extern server_variables   VAR;
extern network_variables  NET;
extern server_data_struct DATA;
extern benchmark_struct   BENCH;

/* Local functions */
void UTIL_Send_IP_Multicast(sys_scatter *scat);

#if 0
#define MAX_MESS_TO_COUNT 100 
int32u mess_count[MAX_MESS_TO_COUNT + 1];
int32u RETRANS_null_add_count;
#endif

int intcmp(const void *n1, const void *n2)
{
  int v1;
  int v2;

  v1 = *((int*)n1);
  v2 = *((int*)n2);

  if ( v1 < v2 ) return -1;
  if ( v1 > v2 ) return 1;
  return 0;
}

int doublecmp(const void *n1, const void *n2)
{
  double v1;
  double v2;

  v1 = *((double*)n1);
  v2 = *((double*)n2);

  if ( v1 < v2 ) return -1;
  if ( v1 > v2 ) return 1;
  return 0;
}

int poseqcmp(const void *n1, const void *n2)
{
  po_seq_pair p1;
  po_seq_pair p2;

  p1 = *((po_seq_pair*)n1);
  p2 = *((po_seq_pair*)n2);

  if (p1.incarnation < p2.incarnation)
     return -1;
   else if (p1.incarnation > p2.incarnation)
     return 1;
   else if (p1.seq_num < p2.seq_num)
     return -1;
   else if (p1.seq_num > p2.seq_num)
     return 1;
   return 0;
}


void Load_Addrs_From_File(char *fileName, int32 addrs[MAX_NUM_SERVER_SLOTS]) 
{
  FILE *f;
  int32u num_assigned, num_expected;
  int32u server;
  int32 ip1,ip2,ip3,ip4;
  
  /* Initialize data structure with 0s */
  for (server = 0; server < MAX_NUM_SERVER_SLOTS; server++)
    addrs[server] = 0;
  
  /* Open file */
  if((f = fopen(fileName, "r")) == NULL)
    Alarm(EXIT, "   ERROR Load_Addrs_From_File: Could not open the address file: %s\n", fileName);

  Alarm(DEBUG, "Load_Addrs_From_File: Opened the address file: %s\n", fileName);
 
  /* Read file. Each line has the following format:
   *    server_id ip1.ip2.ip3.ip4
   */
  num_expected = 5;
  num_assigned = fscanf(f,"%d %d.%d.%d.%d", &server, &ip1, &ip2, &ip3, &ip4);
  Alarm(STATUS,"read line args=%d\n",num_assigned);
  while (num_assigned == num_expected) {
    Alarm(DEBUG,"Load_Addrs_From_File: read server %d, IP: %d.%d.%d.%d "
                "(%d/%d fields assigned correctly)\n", server, ip1, ip2, ip3,
                ip4, num_assigned, num_expected);

    /* Sanity check input */
    if (server <= 0 || server > VAR.Num_Servers) {
        Alarm(EXIT, "ERROR: Load_Addrs_From_File: Invalid input. Config includes "
                    "server %d outside valid range (1 - %d).\n", server, VAR.Num_Servers);
    }
    
    if (addrs[server] != 0) {
        Alarm(EXIT, "ERROR: Load_Addrs_From_File: Multiple entries for server "
                    "%d\n", server);
    }

    /* Correctly formatted input. Store the address */
    addrs[server] = ((ip1 << 24 ) | (ip2 << 16) | (ip3 << 8) | ip4);
    //Alarm(PRINT,"set addrs of server=%d and ip=%s\n",server,addrs[server]);  
    /* Read next line */
    num_assigned = fscanf(f,"%d %d.%d.%d.%d", &server, &ip1, &ip2, &ip3, &ip4);
  }
  
  /* Validate that every entry of the data structure was initialized */
  for (server = 1; server <= VAR.Num_Servers; server++) {
    if (addrs[server] == 0){
        Alarm(PRINT,"********MS2022:Check server=%d \n",server);
        fflush(stdout);
        Alarm(EXIT, "ERROR: Load_Addrs_From_File: Invalid input. Config missing server %d.\n", server);
        }
  }

  fclose(f);
}

int32u UTIL_Message_Size(signed_message *m)
{
  return (sizeof(signed_message) + m->len + 
	  MT_Digests_(m->mt_num) * DIGEST_SIZE);
}

int32u UTIL_Get_Timeliness(int32u type)
{
  int32u ret;

  switch(type) {
    
  case PO_REQUEST:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;
    
  case PO_ACK:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case PO_ARU:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;
    
  case RECON:
    ret = RECON_TRAFFIC_CLASS;
    break;

  case PROOF_MATRIX:
    ret = TIMELY_TRAFFIC_CLASS;
    break;
    
  case PRE_PREPARE:
    ret = TIMELY_TRAFFIC_CLASS;
    break;
    
  case PREPARE:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;
    
  case COMMIT:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case TAT_MEASURE:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case RTT_PING:
    ret = TIMELY_TRAFFIC_CLASS;
    break;

  case RTT_PONG:
    ret = TIMELY_TRAFFIC_CLASS;
    break;

  case RTT_MEASURE:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case TAT_UB:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case NEW_LEADER:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case NEW_LEADER_PROOF:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case RB_INIT:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case RB_ECHO:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case RB_READY:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case REPORT:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case PC_SET:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case VC_LIST:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case VC_PARTIAL_SIG:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case VC_PROOF:
    ret = TIMELY_TRAFFIC_CLASS;
    break;

  case REPLAY:
    ret = TIMELY_TRAFFIC_CLASS;
    break;

  case REPLAY_PREPARE:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case REPLAY_COMMIT:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;
   
  case CATCHUP_REQUEST:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;
   
  case ORD_CERT:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;
   
  case PO_CERT:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case JUMP:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;
   
  case NEW_INCARNATION:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case INCARNATION_ACK:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case INCARNATION_CERT:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case PENDING_STATE:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case PENDING_SHARE:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case RESET_VOTE:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case RESET_SHARE:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case RESET_PROPOSAL:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case RESET_PREPARE:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case RESET_COMMIT:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case RESET_NEWLEADER:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case RESET_NEWLEADERPROOF:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case RESET_VIEWCHANGE:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case RESET_NEWVIEW:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;

  case RESET_CERT:
    ret = BOUNDED_TRAFFIC_CLASS;
    break;
 
  default:
    Alarm(PRINT, "Assigning unknown message type %d as BOUNDED\n", type);
    ret = BOUNDED_TRAFFIC_CLASS;
  }

  return ret;
}

int32u UTIL_I_Am_Faulty()
{
  int32u ret;

  /* The first NUM_F servers are the ones considered faulty */
  if(RECON_ATTACK && (VAR.My_Server_ID <= VAR.F))
    ret = 1;
  else
    ret = 0;
  
  return ret;
}

int16u UTIL_Get_Priority(int type)
{
  int16u prio = 0;

  switch(type) {
    
    case PO_REQUEST: 
    case PO_ACK: 
    case PO_ARU:
    case PREPARE:
    case COMMIT:
    case RECON:
    case TAT_MEASURE: 
    case RTT_MEASURE: 
    case TAT_UB:
    case NEW_LEADER:
    case NEW_LEADER_PROOF:
    case RB_INIT:
    case RB_ECHO:
    case RB_READY:
    case REPORT:
    case PC_SET:
    case VC_LIST:
    case VC_PARTIAL_SIG:
    case REPLAY_PREPARE:
    case REPLAY_COMMIT:
    case CATCHUP_REQUEST:
    case ORD_CERT:
    case PO_CERT:
    case JUMP:
    case NEW_INCARNATION:
    case INCARNATION_ACK:
    case INCARNATION_CERT:
    case PENDING_STATE:
    case PENDING_SHARE:
    case RESET_VOTE:
    case RESET_SHARE:
    case RESET_PROPOSAL:
    case RESET_PREPARE:
    case RESET_COMMIT:
    case RESET_NEWLEADER:
    case RESET_NEWLEADERPROOF:
    case RESET_VIEWCHANGE:
    case RESET_NEWVIEW:
    case RESET_CERT:
    case UPDATE:
    case CLIENT_RESPONSE:
        prio = 2;
        break;

    case RTT_PING: 
    case RTT_PONG:
        prio = 4;
        break;

    case PROOF_MATRIX: 
    case PRE_PREPARE:
    case VC_PROOF:
    case REPLAY:
        prio = 6;
        break;

    default:
        Alarm(PRINT, "Unknown type in UTIL_Get_Priority: %d\n", type);
        break;
  }

  return prio;
}

void UTIL_State_Machine_Output(signed_update_message *u)
{
  /* fprintf(BENCH.state_machine_fp, "Client: %d\tTimestamp: %d\n",
	  u->header.machine_id, u->update.time_stamp); */
}

char *UTIL_Type_To_String(int32u type)
{
  char *ret;

  switch(type) {
    
  case PO_REQUEST:
    ret = "PO_REQUEST";
    break;

  case PO_ACK:
    ret = "PO_ACK";
    break;

  case PO_ARU:
    ret = "PO_ARU";
    break;

  case PROOF_MATRIX:
    ret = "PROOF_MATRIX";
    break;

  case PRE_PREPARE:
    ret = "PRE_PREPARE";
    break;

  case PREPARE:
    ret = "PREPARE";
    break;

  case COMMIT:
    ret = "COMMIT";
    break;

  case RECON:
    ret = "RECON";
    break;

  case TAT_MEASURE:
    ret = "TAT_MEASURE";
    break;

  case RTT_PING:
    ret = "RTT_PING";
    break;

  case RTT_PONG:
    ret = "RTT_PONG";
    break;

  case RTT_MEASURE:
    ret = "RTT_MEASURE";
    break;

  case TAT_UB:
    ret = "TAT_UB";
    break;

  case NEW_LEADER:
    ret = "NEW_LEADER";
    break;

  case NEW_LEADER_PROOF:
    ret = "NEW_LEADER_PROOF";
    break;

  case RB_INIT:
    ret = "RB_INIT";
    break;

  case RB_ECHO:
    ret = "RB_ECHO";
    break;

  case RB_READY:
    ret = "RB_READY";
    break;

  case REPORT:
    ret = "REPORT";
    break;

  case PC_SET:
    ret = "PC_SET";
    break;

  case VC_LIST:
    ret = "VC_LIST";
    break;

  case VC_PARTIAL_SIG:
    ret = "VC_PARTIAL_SIG";
    break;

  case VC_PROOF:
    ret = "VC_PROOF";
    break;

  case REPLAY:
    ret = "REPLAY";
    break;

  case REPLAY_PREPARE:
    ret = "REPLAY_PREPARE";
    break;

  case REPLAY_COMMIT:
    ret = "REPLAY_COMMIT";
    break;

  case CATCHUP_REQUEST:
    ret = "CATCHUP_REQUEST";
    break;

  case ORD_CERT:
    ret = "ORD_CERT";
    break;

  case PO_CERT:
    ret = "PO_CERT";
    break;

  case JUMP:
    ret = "JUMP";
    break;

  case NEW_INCARNATION:
    ret = "NEW_INCARNATION";
    break;

  case INCARNATION_ACK:
    ret = "INCARNATION_ACK";
    break;

  case INCARNATION_CERT:
    ret = "INCARNATION_CERT";
    break;

  case PENDING_STATE:
    ret = "PENDING_STATE";
    break;

  case PENDING_SHARE:
    ret = "PENDING_SHARE";
    break;
  
  case RESET_VOTE:
    ret = "RESET_VOTE";
    break;

  case RESET_SHARE:
    ret = "RESET_SHARE";
    break;

  case RESET_PROPOSAL:
    ret = "RESET_PROPOSAL";
    break;

  case RESET_PREPARE:
    ret = "RESET_PREPARE";
    break;

  case RESET_COMMIT:
    ret = "RESET_COMMIT";
    break;

  case RESET_NEWLEADER:
    ret = "RESET_NEWLEADER";
    break;
  
  case RESET_NEWLEADERPROOF:
    ret = "RESET_NEWLEADERPROOF";
    break;

  case RESET_VIEWCHANGE:
    ret = "RESET_VIEWCHANGE";
    break;

  case RESET_NEWVIEW:
    ret = "RESET_NEWVIEW";
    break;
  
  case RESET_CERT:
    ret = "RESET_CERT";
    break;

  case UPDATE:
    ret = "UPDATE";
    break;

  case CLIENT_RESPONSE:
    ret = "CLIENT_RESPONSE";
    break;
  case CLIENT_OOB_CONFIG_MSG:
    ret= "CLIENT_OOB_CONFIG_MSG";
    break;

  default:
    ret = "UKNOWN TYPE!";
    break;
  }

  return ret;
}

/* Allocate memory for a new signed message */
signed_message* UTIL_New_Signed_Message() 
{
  signed_message *mess;
  
  if((mess = (signed_message*) new_ref_cnt(PACK_BODY_OBJ)) == NULL)
    Alarm(EXIT,"DAT_New_Signed_Message: Could not allocate memory.\n");

  memset(mess, 0, sizeof(packet_body));
  //MS2022: Every signed message has global incarnation number
  if(NET.program_type == NET_SERVER_PROGRAM_TYPE) {
    mess->global_configuration_number = DATA.NM.global_configuration_number;
  }
  return mess;
}

void UTIL_RSA_Sign_Message(signed_message *mess) 
{
  util_stopwatch w;

  UTIL_Stopwatch_Start( &w );

  /* Sign this message */
  OPENSSL_RSA_Sign( ((byte*)mess) + SIGNATURE_SIZE, 
		    mess->len + sizeof(signed_message) - SIGNATURE_SIZE, 
		    (byte*)mess ); 
  UTIL_Stopwatch_Stop( &w );
  Alarm(DEBUG,"%d Sign %f %d\n",
	VAR.My_Server_ID, UTIL_Stopwatch_Elapsed( &w ), mess->type );
}


/* Load addresses of all servers from a configuration file */
void UTIL_Load_Addresses() 
{
  char fileName[50];
  char dir[100] = ".";
  
  /* Open an address.config file and read in the addresses of all
   * servers. */
  sprintf(fileName, "%s/address.config", dir);
  Alarm(PRINT, "Reading server addrs from %s\n", fileName);
  Load_Addrs_From_File(fileName, NET.server_address);
  
#ifdef SET_USE_SPINES
  char sp_fileName[50];
  sprintf(sp_fileName,"%s/spines_address.config",dir);
  UTIL_Load_Spines_Addresses(sp_fileName);
#endif
}

void UTIL_Stopwatch_Start( util_stopwatch *stopwatch ) {
    stopwatch->start = E_get_time();
}

void UTIL_Stopwatch_Stop_Print_Start(util_stopwatch *stopwatch) 
{
  double time;

  UTIL_Stopwatch_Stop(stopwatch);
  time = UTIL_Stopwatch_Elapsed(stopwatch);
  Alarm(PRINT, "Elapsed: %f\n", time);
  UTIL_Stopwatch_Start(stopwatch);
}

/* Send a signed_message to a specific server based on the server's id */
void UTIL_Send_To_Server(signed_message *mess, int32u server_id) 
{
  sys_scatter scat;
  int32 address;
  int32 ret;
#ifdef SET_USE_SPINES
  int16u prio;
  int32u length;
  struct sockaddr_in dest_addr;
  sp_time t = {SPINES_CONNECT_SEC, SPINES_CONNECT_USEC};
#endif

  /* Send a signed message to a server */
  scat.num_elements    = 1;
  scat.elements[0].len = mess->len + sizeof(signed_message);
  scat.elements[0].buf = (char*)mess;

  /* All messages are signed using Merkle trees, so factor in the length
   * of digests. */
  scat.elements[0].len += MT_Digests_(mess->mt_num) * DIGEST_SIZE;
  
  assert(scat.elements[0].len <= PRIME_MAX_PACKET_SIZE);

  Alarm(DEBUG, "Message of type %d was of len %d, now %d\n", mess->type,
	mess->len + sizeof(signed_message), scat.elements[0].len);

  /* Get address and send */
#ifndef SET_USE_SPINES
  address = UTIL_Get_Server_Address(server_id);

  if(UTIL_Get_Timeliness(mess->type) == RECON_TRAFFIC_CLASS)
    ret = DL_send(NET.Recon_Channel, address, 
		  PRIME_RECON_SERVER_BASE_PORT + server_id, &scat);
  else if(UTIL_Get_Timeliness(mess->type) == TIMELY_TRAFFIC_CLASS) {
    ret = DL_send(NET.Timely_Channel, address, 
		  PRIME_TIMELY_SERVER_BASE_PORT + server_id, &scat);
  } else {
    assert(UTIL_Get_Timeliness(mess->type) == BOUNDED_TRAFFIC_CLASS);
    ret = DL_send(NET.Bounded_Channel, address,
		  PRIME_BOUNDED_SERVER_BASE_PORT + server_id, &scat);
  }

  if(ret <= 0) {
    Alarm(PRINT, "I thought message len was: %d\n",
	  mess->len + sizeof(signed_message) + 
	  MT_Digests_(mess->mt_num) * DIGEST_SIZE);
    Alarm(EXIT, "UTIL_Send_To_Server: socket error\n");
  }

#else
  if(NET.program_type == NET_SERVER_PROGRAM_TYPE) {
     
    if (NET.Spines_Channel == -1)
        return;

    address = UTIL_Get_Server_Spines_Address(server_id);
    
    Alarm(DEBUG, "%d SENDING with spines: To %d "IPF" port: %d \n",
	  VAR.My_Server_ID, server_id, IP(address), 
	  PRIME_SPINES_SERVER_BASE_PORT + server_id);
    
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port   = htons(PRIME_SPINES_SERVER_BASE_PORT + server_id);
    dest_addr.sin_addr.s_addr = htonl(address);

    length = (mess->len + sizeof(signed_message) + 
	      (MT_Digests_(mess->mt_num) * DIGEST_SIZE));
   
    if (DATA.VIEW.view_change_done == 0 && 
        address != UTIL_Get_Server_Spines_Address(VAR.My_Server_ID)) 
    {
        DATA.VIEW.vc_stats_send_count[mess->type]++;
        if (DATA.VIEW.vc_stats_send_count[mess->type] == 1)
            DATA.VIEW.vc_stats_send_size[mess->type] = length;
        DATA.VIEW.vc_stats_sent_bytes += length;
    }
        
    //printf("  sending type %s to %d\n", UTIL_Type_To_String(mess->type), server_id);
    prio = UTIL_Get_Priority(mess->type); 
    assert(prio != 0);

    if (spines_setsockopt(NET.Spines_Channel, 0, SPINES_SET_PRIORITY, (void *)&prio, sizeof(int16u)) < 0) {
        Alarm(PRINT, "UTIL_Send_To_Server: error setting priority via setsockopt\n");
        E_detach_fd(NET.Spines_Channel, READ_FD);
        spines_close(NET.Spines_Channel);
        NET.Spines_Channel = -1; 
        if (!E_in_queue(Initialize_Spines, 0, NULL))
          E_queue(Initialize_Spines, 0, NULL, t); 
        return; 
    }
    
    ret = spines_sendto(NET.Spines_Channel, mess, length, 0, 
			(struct sockaddr *)&dest_addr, 
			sizeof(struct sockaddr));
    
    if(ret != length) {
        Alarm(PRINT, "spines_sendto returned length %d, expected %d\n", ret, length);
        E_detach_fd(NET.Spines_Channel, READ_FD);
        spines_close(NET.Spines_Channel);
        NET.Spines_Channel = -1; 
        if (!E_in_queue(Initialize_Spines, 0, NULL))
          E_queue(Initialize_Spines, 0, NULL, t); 
        return; 
    }
  } 
#endif
}

/* Broadcast a message to all servers except me.  Use multicast is
 * available and configured. */
void UTIL_Broadcast( signed_message *mess ) 
{
  sys_scatter scat;
  int32u i;
  int ret;
#ifdef SET_USE_SPINES
  int16u prio;
  int32u length;
  struct sockaddr_in dest_addr;
  sp_time t = {SPINES_CONNECT_SEC, SPINES_CONNECT_USEC};
#endif

  /* Broadcast a signed message to all servers in the site. */
  memset(&scat, 0, sizeof(scat));
  scat.num_elements    = 1;
  scat.elements[0].len = mess->len + sizeof(signed_message);
  scat.elements[0].buf = (char*)mess;
  
  /* All messages might have some digest bytes hanging on */
  scat.elements[0].len += (MT_Digests_(mess->mt_num) * DIGEST_SIZE);
  
  assert(scat.elements[0].len <= PRIME_MAX_PACKET_SIZE);

  /* Cases:
   * 1. Using true multicast: send to appropriate multicast group 
   * 2. Not using true mcast: Send to each server individually */

#ifndef SET_USE_SPINES
  if(USE_IP_MULTICAST){
    Alarm(DEBUG,"UTIL : USE_IP_MULTICAST Use True multicast\n");
	UTIL_Send_IP_Multicast(&scat);
   }
  else {
    int32u i;
    Alarm(DEBUG,"UTIL : Send to server Individually\n");
    for(i = 1; i <= VAR.Num_Servers; i++) {
      if(i != VAR.My_Server_ID)
	UTIL_Send_To_Server(mess, i);
    }
  }
#else
  /* NEW - added for priority sending for TIMELY messages */
  /*
  if(UTIL_Get_Timeliness(mess->type) == TIMELY_TRAFFIC_CLASS) {
      dest_addr.sin_family = AF_INET;
      dest_addr.sin_port   = htons(NET.spines_mcast_prio_port);
      dest_addr.sin_addr.s_addr = htonl(NET.spines_mcast_prio_addr);

      length = (mess->len + sizeof(signed_message) + 
            (MT_Digests_(mess->mt_num) * DIGEST_SIZE));
        
      ret = spines_sendto(NET.Spines_Prio_Channel, mess, length, 0, 
                (struct sockaddr *)&dest_addr, 
                sizeof(struct sockaddr));
        
      if(ret != length) {
          Alarm(PRINT, "spines_sendto returned length %d, expected %d\n",
            ret, length);
          exit(0);
      }
  }
  else { */

    if (NET.Spines_Channel == -1)
        return;

    prio = UTIL_Get_Priority(mess->type); 
    assert(prio != 0);

    if (spines_setsockopt(NET.Spines_Channel, 0, SPINES_SET_PRIORITY, (void *)&prio, sizeof(int16u)) < 0) {
        Alarm(PRINT, "UTIL_Send_To_Server: error setting priority via setsockopt\n");
        E_detach_fd(NET.Spines_Channel, READ_FD);
        spines_close(NET.Spines_Channel);
        NET.Spines_Channel = -1; 
        if (!E_in_queue(Initialize_Spines, 0, NULL))
          E_queue(Initialize_Spines, 0, NULL, t); 
        return; 
    }

    for (i = 1; i <= NET.num_spines_daemons; i++) {
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port   = htons(NET.spines_mcast_port);
        dest_addr.sin_addr.s_addr = htonl(NET.spines_daemon_address[i]);
	

        length = (mess->len + sizeof(signed_message) + 
            (MT_Digests_(mess->mt_num) * DIGEST_SIZE));

        if (DATA.VIEW.view_change_done == 0 &&
            NET.spines_daemon_address[i] != 
            UTIL_Get_Server_Spines_Address(VAR.My_Server_ID)) 
        {
            DATA.VIEW.vc_stats_send_count[mess->type]++;
            if (DATA.VIEW.vc_stats_send_count[mess->type] == 1)
                DATA.VIEW.vc_stats_send_size[mess->type] = length;
            DATA.VIEW.vc_stats_sent_bytes += length;
        }

        //printf("  broadcasting type %s port=%d, address=%lu, socket=%d\n", UTIL_Type_To_String(mess->type),NET.spines_mcast_port, NET.spines_daemon_address[i],NET.Spines_Channel);
    
        ret = spines_sendto(NET.Spines_Channel, mess, length, 0, 
                (struct sockaddr *)&dest_addr, 
                sizeof(struct sockaddr));
    
        if(ret != length) {
            Alarm(PRINT, "spines_sendto returned length %d, expected %d\n", ret, length);
            E_detach_fd(NET.Spines_Channel, READ_FD);
            spines_close(NET.Spines_Channel);
            NET.Spines_Channel = -1; 
            if (!E_in_queue(Initialize_Spines, 0, NULL))
              E_queue(Initialize_Spines, 0, NULL, t); 
            return; 
        }
    }
  /* } */
#endif
}

void UTIL_Send_IP_Multicast(sys_scatter *scat)
{
  int32u ret;
  signed_message *mess;

  mess = (signed_message *)scat->elements[0].buf;

  if(UTIL_Get_Timeliness(mess->type) == TIMELY_TRAFFIC_CLASS) {
    if((ret = DL_send(NET.Timely_Mcast_Channel, NET.Timely_Mcast_Address, 
		      NET.Timely_Mcast_Port, scat)) < 0)
      Alarm(EXIT, "Timely True Mcast: socket error\n");
  }
  else {
    assert(UTIL_Get_Timeliness(mess->type) == BOUNDED_TRAFFIC_CLASS);
    if((ret = DL_send(NET.Bounded_Mcast_Channel, NET.Bounded_Mcast_Address, 
		      NET.Bounded_Mcast_Port, scat)) < 0)
      Alarm(EXIT, "Bounded True Mcast: socket error\n");
  } 
}

void UTIL_Print_Time()
{
  sp_time t;

  t = E_get_time();
  Alarm(PRINT, "%u %u\n", t.sec, t.usec);
}

int32 UTIL_Get_Server_Address(int32u server) 
{
  
  if( (server > VAR.Num_Servers) || (server <= 0) )
    return 0;
  
  return NET.server_address[server];
}

void UTIL_Stopwatch_Stop( util_stopwatch *stopwatch ) 
{
  stopwatch->stop = E_get_time();
}

double UTIL_Stopwatch_Elapsed( util_stopwatch *stopwatch ) 
{
  sp_time result;
  double elapsed;
  
  result  = E_sub_time(stopwatch->stop, stopwatch->start);
  elapsed = (double)result.sec + (double)(result.usec) / 1000000.0;
  return elapsed;
}

void UTIL_Test_Server_Address_Functions() 
{
  /* Assume that the addresses have been loaded. */
  int32u server;
  int32 address;
  
  for(server = 1; server <= VAR.Num_Servers; server++ ) {
    address = UTIL_Get_Server_Address(server);
    if(address != 0) {
      Alarm(PRINT,"Server: %d Address: "IPF"\n", server, IP(address));
    }
  }
}

po_slot* UTIL_Get_PO_Slot(int32u server_id, po_seq_pair ps)
{
  po_slot *slot;
  stdit it;
  stdhash *h;

  h = &DATA.PO.History[server_id];

  stdhash_find(h, &it, &ps);

  Alarm(DEBUG,"GET PO SLOT %d,%d\n", ps.incarnation, ps.seq_num);

  /* If there is nothing in the slot, then create a slot. */
  if (stdhash_is_end(h, &it)) {

    /* If we are about to cross the threshold number of allowed
     * outstanding PO requests, suicide - ordering isn't wokring */
    /* if (stdhash_size(h) > 10*GC_LAG) {
        Alarm(EXIT, "UTIL_Get_PO_Slot: PO request history for server %d has "
                    "reached max size of %d\n", server_id, GC_LAG);
    } */

    /* Allocate memory for a slot. */
    if((slot = (po_slot *) new_ref_cnt(PO_SLOT_OBJ)) == NULL) {
      Alarm(EXIT,"DAT_Get_Pending_Slot:"
	    " Could not allocate memory for slot.\n");
    }
    memset((void*)slot, 0, sizeof(po_slot));
    slot->seq = ps;

    /* insert this slot in the hash */
    stdhash_insert(h, NULL, &ps, &slot);
  } 
  else
    slot = *((po_slot**) stdhash_it_val(&it));

  return slot;
}

po_slot* UTIL_Get_PO_Slot_If_Exists(int32u server_id, po_seq_pair ps)
{
  po_slot *slot;
  stdit it;
  stdhash *h;
  
  h = &DATA.PO.History[server_id];
  
  stdhash_find(h, &it, &ps);
  
  /* If there is nothing in the slot, then do not create a slot. */
  if (stdhash_is_end( h, &it))
    /* There is no slot. */
    slot = NULL;
  else
    slot = *((po_slot**) stdhash_it_val(&it));
  
  return slot;
}

ord_slot *UTIL_Get_ORD_Slot(int32u seq_num)
{
  ord_slot *slot;
  stdit it;
  stdhash *h;

  h = &DATA.ORD.History;

  stdhash_find(h, &it, &seq_num);

  /* If there is nothing in the slot, then create a slot. */
  if (stdhash_is_end( h, &it)) {

    /* Allocate memory for a slot. */
    if((slot = (ord_slot *)new_ref_cnt(ORD_SLOT_OBJ)) == NULL)
      Alarm(EXIT,"Could not allocate memory for ord slot.\n");

    /* insert this slot in the hash */
    memset( (void*)slot, 0, sizeof(ord_slot) );

    slot->seq_num = seq_num; 
    slot->type = SLOT_COMMIT;   /* default value */
    stddll_construct(&slot->po_slot_list, sizeof(po_id));

    stdhash_insert(h, NULL, &seq_num, &slot);
  } 
  else
    slot = *((ord_slot**)stdhash_it_val(&it));
  
  return slot;
}

ord_slot *UTIL_Get_ORD_Slot_If_Exists(int32u seq_num)
{
  ord_slot *slot;
  stdit it;
  stdhash *h;
  
  h    = &DATA.ORD.History;
  slot = NULL;
  
  stdhash_find(h, &it, &seq_num);
  
  /* If there is nothing in the slot, then create a slot. */
  if(!stdhash_is_end( h, &it))
    slot = *((ord_slot**)stdhash_it_val(&it));
  
  return slot;
}

ord_slot *UTIL_Get_Pending_ORD_Slot_If_Exists(int32u gseq)
{
  ord_slot *slot;
  stdit it;
  stdhash *h;

  h    = &DATA.ORD.Pending_Execution;
  slot = NULL;

  stdhash_find(h, &it, &gseq);

  if(!stdhash_is_end(h, &it))
    slot = *((ord_slot **)stdhash_it_val(&it));

  return slot;
}

void UTIL_Mark_ORD_Slot_As_Pending(int32u gseq, ord_slot *slot)
{
  ord_slot *ret;
  stdit it;

  /* Only add it as pending if it is not already in there */

  ret = UTIL_Get_Pending_ORD_Slot_If_Exists(gseq);

  if(ret == NULL) {
    inc_ref_cnt(slot);
    stdhash_insert(&DATA.ORD.Pending_Execution, &it, &gseq, &slot);
    Alarm(DEBUG, "Marked slot %d as pending.\n", gseq);
  }
}

recon_slot *UTIL_Get_Recon_Slot(int32u originator, po_seq_pair ps)
{ 
  recon_slot *slot;
  stdit it;
  stdhash *h;

  h = &DATA.PO.Recon_History[originator];

  stdhash_find(h, &it, &ps);

  Alarm(DEBUG,"GET RECON SLOT %d %d %d\n", originator, ps.incarnation, ps.seq_num);

  /* If there is nothing in the slot, then create a slot. */
  if (stdhash_is_end(h, &it)) {
    
    /* Allocate memory for a slot. */
    if((slot = (recon_slot *) new_ref_cnt(RECON_SLOT_OBJ)) == NULL)
      Alarm(EXIT,"Could not allocate memory for RECON_SLOT.\n");

    memset((void*)slot, 0, sizeof(*slot));

    /* insert this slot in the hash */
    stdhash_insert(h, NULL, &ps, &slot);
  } 
  else
    slot = *((recon_slot**) stdhash_it_val(&it));
  
  return slot;
}

recon_slot *UTIL_Get_Recon_Slot_If_Exists(int32u originator, 
					  po_seq_pair ps)
{ 
  recon_slot *slot;
  stdit it;
  stdhash *h;

  h = &DATA.PO.Recon_History[originator];

  stdhash_find(h, &it, &ps);

  /* If there is nothing in the slot, then create a slot. */
  if (stdhash_is_end(h, &it))
    slot = NULL;
  else
    slot = *((recon_slot**) stdhash_it_val(&it));
  
  return slot;
}

rb_slot* UTIL_Get_RB_Slot(int32u server_id, int32u seq_num)
{
  rb_slot *slot;
  stdit it;
  stdhash *h;

  h = &DATA.RB.instances[server_id];

  stdhash_find(h, &it, &seq_num);

  Alarm(DEBUG,"GET RB SLOT %d\n",seq_num);

  /* If there is nothing in the slot, then create a slot. */
  if (stdhash_is_end(h, &it)) {

    /* Allocate memory for a slot. */
    if((slot = (rb_slot *) new_ref_cnt(RB_SLOT_OBJ)) == NULL) {
      Alarm(EXIT,"UTIL_Get_RB_Slot:"
	    " Could not allocate memory for slot.\n");
    }
    memset((void*)slot, 0, sizeof(rb_slot));
    slot->seq_num = seq_num;
    slot->state = INIT;

    /* insert this slot in the hash */
    stdhash_insert(h, NULL, &seq_num, &slot);
  } 
  else
    slot = *((rb_slot**) stdhash_it_val(&it));

  return slot;
}

rb_slot* UTIL_Get_RB_Slot_If_Exists(int32u server_id, int32u seq_num)
{
  rb_slot *slot;
  stdit it;
  stdhash *h;
  
  h = &DATA.RB.instances[server_id];
  
  stdhash_find(h, &it, &seq_num);
  
  /* If there is nothing in the slot, then do not create a slot. */
  if (stdhash_is_end( h, &it))
    /* There is no slot. */
    slot = NULL;
  else
    slot = *((rb_slot**) stdhash_it_val(&it));
  
  return slot;
}


int32u UTIL_Leader() 
{
  return UTIL_Leader_Of_View(DATA.View);
  /* int32u rep;

  rep = DATA.View % NUM_SERVERS;
  if (rep == 0) 
    rep = NUM_SERVERS;

  return rep; */
}


int32u UTIL_I_Am_Leader() 
{
  if(VAR.My_Server_ID == UTIL_Leader())
    return 1;

  return 0;
}

int32u UTIL_Leader_Of_View(int32u view) 
{
  int32u rep;

  rep = view % VAR.Num_Servers;
  if (rep == 0)
    rep = VAR.Num_Servers;

  return rep;
}

void UTIL_Bitmap_Set(int32u *bm, int32u i)
{
  int32u bit = i % (sizeof(int32u) * 8);

  *bm = *bm | (0x1 << bit);
}

void UTIL_Bitmap_Clear(int32u *bm, int32u i)
{
  int32u bit = i % (sizeof(int32u) * 8);

  *bm = *bm & (~ (0x1 << bit));
}

int32u UTIL_Bitmap_Is_Set(int32u *bm, int32u i)
{
  int32u ret;
  int32u bit = i % (sizeof(int32u) * 8);

  if((*bm & (0x1 << bit)) == 0)
    ret = 0;
  else
    ret = 1;
  
  return ret;
}

int32u UTIL_Bitmap_Num_Bits_Set(int32u *bm)
{
  int32u i;
  int32u target;
  int32u ret = 0;

  target = VAR.Num_Servers;

  for(i = 1; i <= target; i++)
    if(UTIL_Bitmap_Is_Set(bm, i))
      ret++;

  assert(ret > 0);
  return ret;
}

int32u UTIL_Bitmap_Is_Superset(int32u *bm_old, int32u *bm_new)
{
    int32u tmp1, tmp2;

    /* first, grab the differences (if any) between old and new */
    tmp1 = *bm_old ^ *bm_new;

    /* then, see if any thing from old is in the difference */
    tmp2 = *bm_old & tmp1;

    /* tmp2 is 0 if there is nothing from old in differences,
     *  meaning that the new is a superset of old */
    if (tmp2 == 0)
        return 1;

    return 0;
}

erasure_node *UTIL_New_Erasure_Node(int32u dest_bits, int32u type, 
				    int32u part_len, int32u mess_len)
{
  erasure_node *n;

  n = (erasure_node *)new_ref_cnt(ERASURE_NODE_OBJ);

  memset(n, 0, sizeof(erasure_node));

  n->dest_bits = dest_bits;
  n->mess_type = type;
  n->part_len  = part_len;
  n->mess_len  = mess_len;

  return n;
}

erasure_part_obj *UTIL_New_Erasure_Part_Obj()
{
  erasure_part_obj *p;

  p = (erasure_part_obj *)new_ref_cnt(ERASURE_PART_OBJ);
  memset(p, 0, sizeof(erasure_part_obj));

  return p;
}

void UTIL_Respond_To_Client(int32u machine_id, int32u incarnation, 
                            int32u seq_num, int32u ord_num,
                            int32u event_idx, int32u event_tot, 
                            byte content[UPDATE_SIZE])
{
  signed_message *mess;
  
  mess = ORDER_Construct_Client_Response(machine_id, incarnation, seq_num, 
                                        ord_num, event_idx, event_tot, content);

  /* Treated specially, no need to set dest_bits or timeliness */
  /* For Benchmarking Prime, we sign client responses. In Prime for SCADA,
   * with the clients on the same machines as the Prime replicas, we don't need
   * to sign the client responses */
  /* SIG_Add_To_Pending_Messages(mess, 0, 0); */
  UTIL_Write_Client_Response(mess);
  dec_ref_cnt(mess);
}

void UTIL_Write_Client_Response(signed_message *mess)
{
  client_response_message *response;
  int32u machine_id, size;
  int32 ret;

  response   = (client_response_message *)(mess+1);
  machine_id = response->machine_id;

  size = UTIL_Message_Size(mess);
  Alarm(DEBUG, "Getting ready to write %d bytes to client %d seq %d\n", 
	size, machine_id, response->seq_num);

  /* if(NET.client_sd[machine_id] == 0) {
    Alarm(PRINT, "Unable to write reply to client %d, no open connection.\n",
	  machine_id);
    return;
  }
  ret = TCP_Write(NET.client_sd[machine_id], mess, 
		  UTIL_Message_Size(mess)); */
  
  if (NET.to_client_sd == 0) {
    Alarm(DEBUG, "Unable to write reply to client, no open connection.\n");
    return;
  }

#if USE_IPC_CLIENT
  util_stopwatch ipc_send_time;
  UTIL_Stopwatch_Start(&ipc_send_time);
  ret = IPC_Send(NET.to_client_sd, mess, size, NET.client_addr.sun_path);
  UTIL_Stopwatch_Stop(&ipc_send_time);
  DATA.SIG.ipc_send_agg += UTIL_Stopwatch_Elapsed(&ipc_send_time);
  //DATA.SIG.ipc_send_msg[DATA.SIG.ipc_count] = UTIL_Stopwatch_Elapsed(&ipc_send_time);
  //DATA.SIG.ipc_count++;
#else
  ret = NET_Write(NET.to_client_sd, mess, size);
#endif

  if(ret <= 0) {
    Alarm(PRINT, "Respond to Client failed, ret = %d\n", ret);
    Alarm(DEBUG, "Closing and cleaning up connection to client %d\n", 
	  machine_id);
#if !USE_IPC_CLIENT
    close(NET.from_client_sd);
    E_detach_fd(NET.from_client_sd, READ_FD);
    NET.from_client_sd = 0;
    NET.to_client_sd = 0;
#endif
    if (ret == -1) {
        if (errno == EWOULDBLOCK)
            Alarm(PRINT, "  EWOULDBLOCK\n");
        else if (errno == EAGAIN)
            Alarm(PRINT, "  EAGAIN\n");
        else
            Alarm(PRINT, "  EOTHER\n");
            
    }
    /* close(NET.client_sd[machine_id]);
    E_detach_fd(NET.client_sd[machine_id], READ_FD);
    NET.client_sd[machine_id] = 0; */
    /*ORDER_Cleanup();*/
    /*exit(0);*/
  }
  else
    Alarm(DEBUG, "&&&&&&&MS2022: Sent %d TCP bytes to client on %s \n", ret,NET.client_addr.sun_path);
}

net_struct *UTIL_New_Net_Struct()
{
  net_struct *n;

  n = new_ref_cnt(NET_STRUCT_OBJ);
  memset(n, 0, sizeof(*n));
  return n;
}

int32u NET_Add_To_Pending_Messages(signed_message *mess, int32u dest_bits,
				   int32u timeliness)
{
  net_struct *n;
  int32u i;

  n = UTIL_New_Net_Struct();

  inc_ref_cnt(mess);
  n->mess       = mess;
  n->dest_bits  = dest_bits;
  n->timeliness = timeliness;

  /* How many destinations are there for this message? */

  /* Broadcast: Send to all servers but me */
  if(dest_bits == BROADCAST) {
    for(i = 1; i <= VAR.Num_Servers; i++) {
      if(i != VAR.My_Server_ID) {
	n->destinations[i] = 1;
	n->num_remaining_destinations++;
      }
    }
    assert(n->num_remaining_destinations == (VAR.Num_Servers - 1));
  }

  /* Non-broadcast: Send only to those marked as desinations */
  else {
    for(i = 1; i <= VAR.Num_Servers; i++) {
      if(i != VAR.My_Server_ID && UTIL_Bitmap_Is_Set(&dest_bits, i)) {
	n->destinations[i] = 1;
	n->num_remaining_destinations++;
      }
    }
    assert(n->num_remaining_destinations == 
	   UTIL_Bitmap_Num_Bits_Set(&dest_bits));
  }

  /* Add to either the timely or bounded queue */
  if(timeliness == BOUNDED_TRAFFIC_CLASS)
    Alarm(DEBUG, "Added BOUNDED message (type %d) to pending queue\n",
	  n->mess->type);

  UTIL_DLL_Add_Data(&NET.pending_messages_dll[timeliness], n);
  assert(get_ref_cnt(n) > 1);
  dec_ref_cnt(n); /* One copy on queue only */

  return 1;
}

#ifdef SET_USE_SPINES
int32 UTIL_Get_Server_Spines_Address(int32u server) 
{
  if(server > VAR.Num_Servers || server <= 0)
    return 0;
	
  return NET.server_address_spines[server];
}

void UTIL_Load_Spines_Addresses(char *fileName) 
{
  int32u unique_spines;
  int32u server, i;
  
  /* Open spines_address.config file and read in spines address to use for each
   * replica */
  Alarm(DEBUG, "Reading Spines addrs from %s\n", fileName);
  Load_Addrs_From_File(fileName, NET.server_address_spines);

  /* Initialize list of unique spines daemons */
  for (server = 1; server <= VAR.Num_Servers; server++) {
    NET.spines_daemon_address[server] = 0;
  }
  NET.num_spines_daemons = 0;
  
  for (server = 1; server <= VAR.Num_Servers; server++) {
    unique_spines = 1;
    for (i = 1; i <= NET.num_spines_daemons; i++) {
      if (NET.server_address_spines[server] == NET.spines_daemon_address[i]) {
        unique_spines = 0;
        break;
      }
    }
    if (unique_spines == 1) {
      NET.num_spines_daemons++;
      NET.spines_daemon_address[NET.num_spines_daemons] = NET.server_address_spines[server];
    }
  }
}
#endif
