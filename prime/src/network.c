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

#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <assert.h>
#include "arch.h"
#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_data_link.h"
#include "spu_memory.h"
#include "objects.h"
#include "net_types.h"
#include "data_structs.h"
#include "network.h"
#include "utility.h"
#include "validate.h"
#include "process.h"
#include "pre_order.h"
#include "net_wrapper.h"

#ifdef SET_USE_SPINES
#include "spines_lib.h"
#endif

/* Global variables defined elsewhere */
extern network_variables   NET;
extern server_variables    VAR;
extern server_data_struct  DATA;
extern benchmark_struct    BENCH;

/* Local buffer for receiving the packet */
static sys_scatter srv_recv_scat;

/* Local Functions */
#if !USE_IPC_CLIENT
void Initialize_Listening_Socket(void);
void NET_Client_Connection_Acceptor(int sd, int dummy, void *dummyp);
#endif
void NET_Throttle_Send             (int dummy, void* dummyp);
void NET_Send_Message(net_struct *n);
void Initialize_IPC_Socket(void);
void Initialize_UDP_Sockets(void);

/* Maximize the send and receive buffers.  Thanks to Nilo Rivera. */
int max_rcv_buff(int sk);
int max_snd_buff(int sk);

void Reconfig_Reset_Network(void) 
{
  int32u i;
#if THROTTLE_OUTGOING_MESSAGES
  sp_time t;
#endif
#if USE_IPC_CLIENT
  struct sockaddr_un conn;
#endif


#if USE_IPC_CLIENT
  if(NET.from_client_sd==0){
  if((NET.from_client_sd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) 
    Alarm(EXIT, "socket error.\n");

  memset(&conn, 0, sizeof(struct sockaddr_un));
  conn.sun_family = AF_UNIX;
  //sprintf(conn.sun_path, "%s%d", (char *)REPLICA_IPC_PATH, VAR.My_Server_ID);
  sprintf(conn.sun_path, "%s%d", (char *)REPLICA_IPC_PATH, VAR.My_Tpm_ID);

  if (remove(conn.sun_path) == -1 && errno != ENOENT) {
      perror("Initialize_IPC_Socket: error removing previous path binding");
      exit(EXIT_FAILURE);
  }
  if ((bind(NET.from_client_sd, (struct sockaddr *)&conn, sizeof(conn))) < 0) {
    perror("bind");
    exit(0);
  }
  chmod(conn.sun_path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  E_attach_fd(NET.from_client_sd, READ_FD, Net_Srv_Recv, IPC_SOURCE, NULL, MEDIUM_PRIORITY);
  max_rcv_buff(NET.from_client_sd);
  max_snd_buff(NET.from_client_sd);
 Alarm(DEBUG,"During reconfig, READ_FD set NET.from_client\n");
  }
  if(NET.to_client_sd==0){
  if((NET.to_client_sd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) 
    Alarm(EXIT, "socket error.\n");

  memset(&NET.client_addr, 0, sizeof(struct sockaddr_un));
  NET.client_addr.sun_family = AF_UNIX;
  //sprintf(NET.client_addr.sun_path, "%s%d", (char *)CLIENT_IPC_PATH, VAR.My_Server_ID);
  sprintf(NET.client_addr.sun_path, "%s%d", (char *)CLIENT_IPC_PATH, VAR.My_Tpm_ID);

  max_rcv_buff(NET.to_client_sd);
  max_snd_buff(NET.to_client_sd);
 Alarm(DEBUG,"During reconf, Initialized IPC to client\n");
  }
/* TESTING IPC BUFFER SIZE + NONBLOCK */
/*  int on, on_len;
  on_len = sizeof(on);
  getsockopt(NET.to_client_sd, SOL_SOCKET, SO_SNDBUF, (void *)&on, &on_len);
  printf("size = %d\n", on);

  on = 1;
  ioctl(NET.to_client_sd, FIONBIO, &on); */

#else
  /* Each server listens for incoming TCP connections from clients on
   * port PRIME_TCP_PORT */
  Initialize_Listening_Socket();
#endif

  Initialize_UDP_Sockets();

  /* Initialize the receiving scatters */
  srv_recv_scat.num_elements    = 1;
  srv_recv_scat.elements[0].len = sizeof(packet);
  srv_recv_scat.elements[0].buf = (char *) new_ref_cnt(PACK_BODY_OBJ);
  if(srv_recv_scat.elements[0].buf == NULL)
    Alarm(EXIT, "Init_Network: Cannot allocate packet object\n");
  
#ifdef SET_USE_SPINES
  Initialize_Spines(0, NULL);
#endif

  /* Initialize the rest of the data structure */
  for(i = 0; i < 2; i++) {
    UTIL_DLL_Initialize(&NET.pending_messages_dll[i]);
    NET.tokens[i] = 0.0;
    UTIL_Stopwatch_Start(&NET.sw[i]);
  }

#if THROTTLE_OUTGOING_MESSAGES
  t.sec  = THROTTLE_SEND_SEC;
  t.usec = THROTTLE_SEND_USEC;
  E_queue(NET_Throttle_Send, 0, NULL, t);
#endif
}


void Init_Network(void) 
{
  int32u i;
#if THROTTLE_OUTGOING_MESSAGES
  sp_time t;
#endif
#if USE_IPC_CLIENT
  struct sockaddr_un conn;
#endif

  /* Set Application Replica socket to 0 */
  NET.from_client_sd = 0;
  NET.to_client_sd = 0;

#if USE_IPC_CLIENT
  if((NET.from_client_sd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) 
    Alarm(EXIT, "socket error.\n");

  memset(&conn, 0, sizeof(struct sockaddr_un));
  conn.sun_family = AF_UNIX;
  //sprintf(conn.sun_path, "%s%d", (char *)REPLICA_IPC_PATH, VAR.My_Server_ID);
  sprintf(conn.sun_path, "%s%d", (char *)REPLICA_IPC_PATH, VAR.My_Tpm_ID);

  if (remove(conn.sun_path) == -1 && errno != ENOENT) {
      perror("Initialize_IPC_Socket: error removing previous path binding");
      exit(EXIT_FAILURE);
  }
  if ((bind(NET.from_client_sd, (struct sockaddr *)&conn, sizeof(conn))) < 0) {
    perror("bind");
    exit(0);
  }
  chmod(conn.sun_path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  E_attach_fd(NET.from_client_sd, READ_FD, Net_Srv_Recv, IPC_SOURCE, NULL, MEDIUM_PRIORITY);

  if((NET.to_client_sd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) 
    Alarm(EXIT, "socket error.\n");

  memset(&NET.client_addr, 0, sizeof(struct sockaddr_un));
  NET.client_addr.sun_family = AF_UNIX;
  //sprintf(NET.client_addr.sun_path, "%s%d", (char *)CLIENT_IPC_PATH, VAR.My_Server_ID);
  sprintf(NET.client_addr.sun_path, "%s%d", (char *)CLIENT_IPC_PATH, VAR.My_Tpm_ID);

  max_rcv_buff(NET.from_client_sd);
  max_snd_buff(NET.from_client_sd);
  max_rcv_buff(NET.to_client_sd);
  max_snd_buff(NET.to_client_sd);
 Alarm(PRINT,"Initialized IPC to and from client\n");
/* TESTING IPC BUFFER SIZE + NONBLOCK */
/*  int on, on_len;
  on_len = sizeof(on);
  getsockopt(NET.to_client_sd, SOL_SOCKET, SO_SNDBUF, (void *)&on, &on_len);
  printf("size = %d\n", on);

  on = 1;
  ioctl(NET.to_client_sd, FIONBIO, &on); */

#else
  /* Each server listens for incoming TCP connections from clients on
   * port PRIME_TCP_PORT */
  Initialize_Listening_Socket();
#endif

  Initialize_UDP_Sockets();

  /* Initialize the receiving scatters */
  srv_recv_scat.num_elements    = 1;
  srv_recv_scat.elements[0].len = sizeof(packet);
  srv_recv_scat.elements[0].buf = (char *) new_ref_cnt(PACK_BODY_OBJ);
  if(srv_recv_scat.elements[0].buf == NULL)
    Alarm(EXIT, "Init_Network: Cannot allocate packet object\n");
  
#ifdef SET_USE_SPINES
  Initialize_Spines(0, NULL);
#endif

  /* Initialize the rest of the data structure */
  for(i = 0; i < 2; i++) {
    UTIL_DLL_Initialize(&NET.pending_messages_dll[i]);
    NET.tokens[i] = 0.0;
    UTIL_Stopwatch_Start(&NET.sw[i]);
  }

#if THROTTLE_OUTGOING_MESSAGES
  t.sec  = THROTTLE_SEND_SEC;
  t.usec = THROTTLE_SEND_USEC;
  E_queue(NET_Throttle_Send, 0, NULL, t);
#endif
}

#if !USE_IPC_CLIENT
void Initialize_Listening_Socket()
{
  struct sockaddr_in server_addr;
  long on = 1;

  if((NET.listen_sd = socket(AF_INET, SOCK_STREAM, 0)) < 0) 
    Alarm(EXIT, "socket error.\n");
  
  if((setsockopt(NET.listen_sd, SOL_SOCKET, SO_REUSEADDR, &on,
		 sizeof(on))) < 0) {
    perror("setsockopt");
    exit(0);
  }

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family      = AF_INET;
  server_addr.sin_port        = htons(PRIME_TCP_BASE_PORT+VAR.My_Server_ID);
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

  if((bind(NET.listen_sd, (struct sockaddr *)&server_addr, 
        sizeof(server_addr))) < 0) {
    perror("bind");
    exit(0);
  }

  if((listen(NET.listen_sd, 50)) < 0) {
    perror("listen");
    exit(0);
  }

  /* Register the listening socket descriptor */
  E_attach_fd(NET.listen_sd, READ_FD, NET_Client_Connection_Acceptor, 
	      0, NULL, MEDIUM_PRIORITY);
}
#endif

void Initialize_UDP_Sockets()
{
  int32 ret;
  long off = 0;

  /* UDP Unicast */
  NET.Bounded_Port = PRIME_BOUNDED_SERVER_BASE_PORT + VAR.My_Server_ID;
  NET.Timely_Port  = PRIME_TIMELY_SERVER_BASE_PORT  + VAR.My_Server_ID;
  NET.Recon_Port   = PRIME_RECON_SERVER_BASE_PORT   + VAR.My_Server_ID;

  /* Bounded: Unicast */
  NET.Bounded_Channel = DL_init_channel(SEND_CHANNEL | RECV_CHANNEL,
					NET.Bounded_Port, 0, 0);
  
  /* Timely: Unicast */
  NET.Timely_Channel = DL_init_channel(SEND_CHANNEL | RECV_CHANNEL,
				       NET.Timely_Port, 0, 0);
  
  /* Reconciliation: Unicast */
  NET.Recon_Channel = DL_init_channel(SEND_CHANNEL | RECV_CHANNEL,
				      NET.Recon_Port, 0, 0);

  /* Maximize the size of the buffers on each socket */
  max_rcv_buff(NET.Bounded_Channel);
  max_rcv_buff(NET.Timely_Channel);
  max_rcv_buff(NET.Recon_Channel);
  max_snd_buff(NET.Bounded_Channel);
  max_snd_buff(NET.Timely_Channel);
  max_snd_buff(NET.Recon_Channel);

  /* Attach each one to the event system */
  E_attach_fd(NET.Bounded_Channel, READ_FD, Net_Srv_Recv, 
	      UDP_SOURCE, NULL, MEDIUM_PRIORITY); 

  E_attach_fd(NET.Timely_Channel, READ_FD, Net_Srv_Recv, 
	      UDP_SOURCE, NULL, MEDIUM_PRIORITY); 

  E_attach_fd(NET.Recon_Channel, READ_FD, Net_Srv_Recv, 
	      UDP_SOURCE, NULL, MEDIUM_PRIORITY); 

  if(USE_IP_MULTICAST) {

#ifdef SET_USE_SPINES
    /* Use of IP Multicast is not consistent with using spines for
     * communication among servers. */
    Alarm(PRINT, "You are trying to use spines but the USE_IP_MULTICAST "
	  "configuration parameter is set.  Please set one or the other.\n");
    exit(0);
#endif

    if(THROTTLE_OUTGOING_MESSAGES) {
      /* IP Multicast also cannot be used with throttling */
      Alarm(PRINT, "You have both USE_IP_MULTICAST and "
	    "THROTTLE_OUTGOING_MESSAGES set.  Please set one or the other.\n");
      exit(0);
    }    

    /* Bounded traffic class: 225.2.1.1 
     * Timely  traffic class: 225.2.1.2 */
    NET.Bounded_Mcast_Address = 225 << 24 | 2 << 16 | 1 << 8 | 1;
    NET.Timely_Mcast_Address  = 225 << 24 | 2 << 16 | 1 << 8 | 2;

    Alarm(PRINT, "Setting my bounded mcast address to "IPF"\n", 
	  IP(NET.Bounded_Mcast_Address) );
    Alarm(PRINT, "Setting my timely  mcast address to "IPF"\n", 
	  IP(NET.Timely_Mcast_Address) );

    NET.Bounded_Mcast_Port = PRIME_BOUNDED_MCAST_PORT;
    NET.Timely_Mcast_Port  = PRIME_TIMELY_MCAST_PORT;

    NET.Bounded_Mcast_Channel = DL_init_channel(SEND_CHANNEL | RECV_CHANNEL,
						NET.Bounded_Mcast_Port,
						NET.Bounded_Mcast_Address, 0);

    NET.Timely_Mcast_Channel = DL_init_channel(SEND_CHANNEL | RECV_CHANNEL,
					       NET.Timely_Mcast_Port,
					       NET.Timely_Mcast_Address, 0);
    max_rcv_buff(NET.Bounded_Mcast_Channel);
    max_rcv_buff(NET.Timely_Mcast_Channel);
    
    /* If we're using multicast, don't receive your own messages */
    if((ret = setsockopt(NET.Bounded_Mcast_Channel, IPPROTO_IP, 
			 IP_MULTICAST_LOOP, (void *)&off, 1)) < 0) {
      perror("setsockopt");
      exit(0);
    }
    
    /* If we're using multicast, don't receive your own messages */
    if((ret = setsockopt(NET.Timely_Mcast_Channel, IPPROTO_IP, 
			 IP_MULTICAST_LOOP, (void *)&off, 1)) < 0) {
      perror("setsockopt");
      exit(0);
    }

    E_attach_fd(NET.Timely_Mcast_Channel, READ_FD, Net_Srv_Recv, UDP_SOURCE, 
		NULL, MEDIUM_PRIORITY);

    E_attach_fd(NET.Bounded_Mcast_Channel, READ_FD, Net_Srv_Recv, UDP_SOURCE, 
		NULL, MEDIUM_PRIORITY);
  }
}

/* Attempts to send timely and bounded messages */
void NET_Throttle_Send(int dummy, void *dummyp)
{
  int32u i, bits, bytes;
  signed_message *mess;
  double time, add;
  net_struct *n;
  sp_time t;

  /* First send timely messages, then bounded ones */
  for(i = 0; i < NUM_TRAFFIC_CLASSES; i++) {

    while(!UTIL_DLL_Is_Empty(&NET.pending_messages_dll[i])) {

      UTIL_DLL_Set_Begin(&NET.pending_messages_dll[i]);
      
      UTIL_Stopwatch_Stop(&NET.sw[i]);
      time = UTIL_Stopwatch_Elapsed(&NET.sw[i]);
      UTIL_Stopwatch_Start(&NET.sw[i]);

      /* Compute number of tokens to add based on whether we are using erasure
       * codes, are emulated, and are dealing with timely or asynchronous
       * messages. */
      if(i == TIMELY_TRAFFIC_CLASS)
	add = (double) MAX_OUTGOING_BANDWIDTH_TIMELY * time;
      else if(i == BOUNDED_TRAFFIC_CLASS)
	add = (double) MAX_OUTGOING_BANDWIDTH_BOUNDED * time;
      else if(i == RECON_TRAFFIC_CLASS)
      	add = (double) MAX_OUTGOING_BANDWIDTH_RECON * time;
      else
	Alarm(EXIT, "Throttling unknown traffic class: %d\n", i);

      NET.tokens[i] += add;

      if(NET.tokens[i] > MAX_TOKENS)
	NET.tokens[i] = MAX_TOKENS;

      n    = UTIL_DLL_Front_Message(&NET.pending_messages_dll[i]);
      mess = n->mess;

      bytes = UTIL_Message_Size(mess);
#ifdef SET_USE_SPINES
      bytes += 16 + 24;
#endif
      bits = bytes * 8;

      if(NET.tokens[i] < bits) {
	Alarm(DEBUG, "Not enough tokens to send: %f %d, timely = %d\n",
	      NET.tokens[i], bits, i);
	break;
      }
      
      NET.tokens[i] -= bits;

      NET_Send_Message(n);
      Alarm(DEBUG, "Num remaining = %d\n", n->num_remaining_destinations);
      
      if(n->num_remaining_destinations == 0) {
	dec_ref_cnt(n->mess);
	UTIL_DLL_Pop_Front(&NET.pending_messages_dll[i]);
      }
    }
  }

  t.sec  = THROTTLE_SEND_SEC;
  t.usec = THROTTLE_SEND_USEC;
  E_queue(NET_Throttle_Send, 0, NULL, t);
}

void NET_Send_Message(net_struct *n)
{
  int32u i;

  assert(n->mess);

  /* We can either send to the destination servers sequentially, or we
   * can pick one that still needs the message at random. */
  if(RANDOMIZE_SENDING) {
    while(1) {
      i = (rand() % VAR.Num_Servers) + 1;
      if(n->destinations[i] == 1)
	break;
    }
  }
  else {
    for(i = 1; i <= VAR.Num_Servers; i++)
      if(n->destinations[i] == 1)
	break;
  }

  assert(i != VAR.My_Server_ID);
  assert(i <= VAR.Num_Servers);

  /* We've decided to send to server i */
  UTIL_Send_To_Server(n->mess, i);

  n->destinations[i] = 0;
  n->num_remaining_destinations--;
}

#ifdef SET_USE_SPINES
void Initialize_Spines(int dummy, void *dummy_p)
{
  channel spines_recv_sk;
  struct sockaddr_in spines_addr, my_addr;
  struct sockaddr_un spines_uaddr;
  struct ip_mreq mreq;
  int ret, priority, i1, i2, i3, i4;
  long my_ip, spines_ip;
  char lb;
  int16u protocol;
  int16u kpaths;
  spines_nettime exp;
  sp_time t = {SPINES_CONNECT_SEC, SPINES_CONNECT_USEC};

  Alarm(DEBUG, "%d Init Spines... %d\n", VAR.My_Server_ID, SPINES_PORT);
  
  my_ip     = htonl(UTIL_Get_Server_Address(VAR.My_Server_ID));
  spines_ip = htonl(UTIL_Get_Server_Spines_Address(VAR.My_Server_ID));
  NET.Spines_Channel = -1;

  Alarm(PRINT, "Spines IP: "IPF", My IP: "IPF" My_Server_ID=%u\n", 
	  IP(spines_ip), IP(my_ip),VAR.My_Server_ID);
#if 0
  /* ========== Connect to spines for Reliable (Bounded) ========= */
  spines_recv_sk = -1;
  memset(&spines_addr, 0, sizeof(spines_addr));  
  memset(&my_addr, 0, sizeof(my_addr));  

  protocol = 8 | (2 << 8) | (1 << 12);

#if 0
  if (my_ip != spines_ip || USE_SPINES_IPC == 0)  /* TCP */
  {
      spines_addr.sin_family = AF_INET;
      spines_addr.sin_port   = htons(SPINES_PORT);
      spines_addr.sin_addr.s_addr = spines_ip;
      spines_recv_sk = spines_socket(PF_SPINES, SOCK_DGRAM, protocol, 
                     (struct sockaddr *)&spines_addr);
  } else { /* IPC */
      spines_uaddr.sun_family = AF_UNIX;
      sprintf(spines_uaddr.sun_path, "%s%d", "/tmp/spines", SPINES_PORT);
      printf("Spines Unix Socket to %s!\n", spines_uaddr.sun_path);
      spines_recv_sk = spines_socket(PF_SPINES, SOCK_DGRAM, protocol, 
                       (struct sockaddr *)&spines_uaddr);
  }
#endif

  spines_uaddr.sun_family = AF_UNIX;
  sprintf(spines_uaddr.sun_path, "%s%d", "/tmp/spines", SPINES_PORT);
  //printf("Spines Unix Socket to %s!\n", spines_uaddr.sun_path);
  spines_recv_sk = spines_socket(PF_SPINES, SOCK_DGRAM, protocol, 
                   (struct sockaddr *)&spines_uaddr);
  if(spines_recv_sk == -1) {
    Alarm(PRINT, "%d Could not connect to Spines daemon.\n", VAR.My_Server_ID );
    goto fail;
  } 

  /* Setting k-paths to k = 1 */
  kpaths = 1;
  if (spines_setsockopt(spines_recv_sk, 0, SPINES_DISJOINT_PATHS, (void *)&kpaths, sizeof(int16u)) < 0) {
    Alarm(PRINT, "spines_setsockopt failed\n");
    goto fail_close;
  }

  /* Set the buffer size of the socket */
  max_rcv_buff(spines_recv_sk);
  max_snd_buff(spines_recv_sk);

  /* Bind to my unique port */  
  my_addr.sin_addr.s_addr = my_ip;
  my_addr.sin_port        = htons(PRIME_SPINES_SERVER_BASE_PORT + VAR.My_Server_ID);
      
  ret = spines_bind(spines_recv_sk, (struct sockaddr *)&my_addr,
		    sizeof(struct sockaddr_in));
  if (ret == -1) {
    Alarm(PRINT, "Could not bind on Spines daemon.\n");
    goto fail_close;
  }

  /* MCAST CLUGE */
  sscanf(SPINES_MCAST_ADDR, "%d.%d.%d.%d", &i1, &i2, &i3, &i4);
  NET.spines_mcast_addr = ( (i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4 );
  NET.spines_mcast_port = 0XFF00 | i4;

  mreq.imr_multiaddr.s_addr = htonl(NET.spines_mcast_addr);
  mreq.imr_interface.s_addr = htonl(INADDR_ANY);
  if (spines_setsockopt(spines_recv_sk, IPPROTO_IP, SPINES_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq)) < 0) {
    Alarm(PRINT, "spines_setsockopt for mcast membership failed\n");
    goto fail_close;
  }

  lb = 0;
  if (spines_setsockopt(spines_recv_sk, IPPROTO_IP, SPINES_MULTICAST_LOOP, (void *)&lb, sizeof(lb)) < 0) {
    Alarm(PRINT, "spines_setsockopt for mcast loopback failed\n");
    goto fail_close;
  }
  /* END MCAST CLUGE */

  /* Register the socket with the event system */
  priority = HIGH_PRIORITY;
  E_attach_fd(spines_recv_sk, READ_FD, Net_Srv_Recv, SPINES_SOURCE,
	      NULL, priority ); //MEDIUM_PRIORITY );
#endif

  /* ========== Connect to spines for Priority (Timely) ========= */
  spines_recv_sk = -1;
  memset(&spines_addr, 0, sizeof(spines_addr));  
  memset(&my_addr, 0, sizeof(my_addr));  

  protocol = 8 | (1 << 8);

#if 0
  if (my_ip != spines_ip || USE_SPINES_IPC == 0)  /* TCP */
  {
      spines_addr.sin_family = AF_INET;
      spines_addr.sin_port   = htons(SPINES_PORT);
      spines_addr.sin_addr.s_addr = spines_ip;
      spines_recv_sk = spines_socket(PF_SPINES, SOCK_DGRAM, protocol, 
                     (struct sockaddr *)&spines_addr);
  } else { /* IPC */
      spines_uaddr.sun_family = AF_UNIX;
      sprintf(spines_uaddr.sun_path, "%s%d", "/tmp/spines", SPINES_PORT);
      //printf("Spines Unix Socket to %s!\n", spines_uaddr.sun_path);
      spines_recv_sk = spines_socket(PF_SPINES, SOCK_DGRAM, protocol, 
                       (struct sockaddr *)&spines_uaddr);
  }
#endif

  if (my_ip != spines_ip)  /* TCP */
  {
      spines_addr.sin_family = AF_INET;
      spines_addr.sin_port   = htons(SPINES_PORT);
      spines_addr.sin_addr.s_addr = spines_ip;
      Alarm(PRINT, "Spines INET Socket!\n");
      spines_recv_sk = spines_socket(PF_SPINES, SOCK_DGRAM, protocol, 
                     (struct sockaddr *)&spines_addr);
  } else { /* IPC */
      spines_uaddr.sun_family = AF_UNIX;
      sprintf(spines_uaddr.sun_path, "%s%d", "/tmp/spines", SPINES_PORT);
      Alarm(PRINT, "Spines UNIX Socket to %s!\n", spines_uaddr.sun_path);
      spines_recv_sk = spines_socket(PF_SPINES, SOCK_DGRAM, protocol, 
                       (struct sockaddr *)&spines_uaddr);
  }

#if 0
  spines_uaddr.sun_family = AF_UNIX;
  sprintf(spines_uaddr.sun_path, "%s%d", "/tmp/spines", SPINES_PORT);
  //printf("Spines Unix Socket to %s!\n", spines_uaddr.sun_path);
  spines_recv_sk = spines_socket(PF_SPINES, SOCK_DGRAM, protocol, 
                   (struct sockaddr *)&spines_uaddr);
#endif

  if(spines_recv_sk == -1) {
    Alarm(DEBUG, "%d Could not connect to Spines daemon.\n", VAR.My_Server_ID );
    goto fail;
  } 

  /* Setting k-paths to k = 0, which is the default */
  kpaths = 1;
  if (spines_setsockopt(spines_recv_sk, 0, SPINES_DISJOINT_PATHS, (void *)&kpaths, 
        sizeof(int16u)) < 0) {
    Alarm(PRINT, "spines_setsockopt failed for disjoint paths\n");
    goto fail_close;
  }

  /* setup priority garbage collection settings */
  exp.sec  = SPINES_EXP_TIME_SEC;
  exp.usec = SPINES_EXP_TIME_USEC;
  if (spines_setsockopt(spines_recv_sk, 0, SPINES_SET_EXPIRATION, (void *)&exp, 
        sizeof(spines_nettime)) < 0) {
    Alarm(PRINT, "Error setting expiration time for SPINES_PRIORITY type!");
    goto fail_close;
  }

  /* Set the buffer size of the socket */
  max_rcv_buff(spines_recv_sk);
  max_snd_buff(spines_recv_sk);

  /* Bind to my unique port */  
  my_addr.sin_addr.s_addr = my_ip;
  my_addr.sin_port        = htons(PRIME_SPINES_SERVER_BASE_PORT + VAR.My_Server_ID);
      
  ret = spines_bind(spines_recv_sk, (struct sockaddr *)&my_addr,
		    sizeof(struct sockaddr_in));
  if (ret == -1) {
    Alarm(PRINT, "Could not bind on Spines daemon.\n");
    goto fail_close;
  }

  /* MCAST CLUGE */
  sscanf(SPINES_MCAST_ADDR, "%d.%d.%d.%d", &i1, &i2, &i3, &i4);
  NET.spines_mcast_addr = ( (i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4 );
  NET.spines_mcast_port = 0XFF00 | i4;

  mreq.imr_multiaddr.s_addr = htonl(NET.spines_mcast_addr);
  mreq.imr_interface.s_addr = htonl(INADDR_ANY);
  if (spines_setsockopt(spines_recv_sk, IPPROTO_IP, SPINES_ADD_MEMBERSHIP, (void *)&mreq, 
        sizeof(mreq)) < 0) {
    Alarm(PRINT, "spines_setsockopt for mcast membership failed\n");
    goto fail_close;
  }

  lb = 0;
  if (spines_setsockopt(spines_recv_sk, IPPROTO_IP, SPINES_MULTICAST_LOOP, (void *)&lb, 
        sizeof(lb)) < 0) {
    Alarm(PRINT, "spines_setsockopt for mcast loopback failed\n");
    goto fail_close;
  }
  /* END MCAST CLUGE */

  /* Register the socket with the event system */
  priority = HIGH_PRIORITY;
  E_attach_fd(spines_recv_sk, READ_FD, Net_Srv_Recv, SPINES_SOURCE,
	      NULL, priority ); //MEDIUM_PRIORITY );
  
  Alarm(PRINT, "Successfully connected to Spines!\n");
  NET.Spines_Channel = spines_recv_sk;
  return;

fail_close:
  spines_close(spines_recv_sk);
fail:
  NET.Spines_Channel = -1;
  E_queue(Initialize_Spines, 0, NULL, t);
}
#endif

void Net_Srv_Recv(channel sk, int source, void *dummy_p) 
{
  int received_bytes, ret;
  signed_message *mess;
  sp_time t = {SPINES_CONNECT_SEC, SPINES_CONNECT_USEC};

  /* Read the packet from the socket */
  if(source == UDP_SOURCE){
    received_bytes = DL_recv(sk, &srv_recv_scat); 
   Alarm(DEBUG,"MS2022: received on UDP_SOURCE\n"); 
  }
#ifdef SET_USE_SPINES
  else if(source == SPINES_SOURCE) {
   Alarm(DEBUG,"MS2022: received on SPINES_SOURCE\n"); 
    received_bytes = spines_recvfrom(sk, srv_recv_scat.elements[0].buf, 
				     PRIME_MAX_PACKET_SIZE, 0, NULL, 0);
    if(received_bytes <= 0) {
      Alarm(PRINT, "Error: Lost connection to spines...\n");
      E_detach_fd(NET.Spines_Channel, READ_FD);
      spines_close(NET.Spines_Channel);
      NET.Spines_Channel = -1;
      if (!E_in_queue(Initialize_Spines, 0, NULL))
        E_queue(Initialize_Spines, 0, NULL, t);
      return;
    }
    mess = (signed_message*)srv_recv_scat.elements[0].buf;
    if (DATA.VIEW.view_change_done == 0 && 
        UTIL_Get_Server_Spines_Address(mess->machine_id) != 
            UTIL_Get_Server_Spines_Address(VAR.My_Server_ID))
    {
        DATA.VIEW.vc_stats_recv_bytes += received_bytes;
    }
  }
#endif
  else if(source == TCP_SOURCE) {
    ret = NET_Read(sk, srv_recv_scat.elements[0].buf, 
            //sizeof(signed_update_message));
            PRIME_MAX_PACKET_SIZE);
   Alarm(DEBUG,"MS2022: received on TCP_SOURCE\n"); 
    if(ret <= 0) {
      perror("read");
      close(sk);
      E_detach_fd(sk, READ_FD);
      if (sk == NET.from_client_sd) {
        NET.from_client_sd = 0;
        NET.to_client_sd = 0;
        Alarm(DEBUG,"&&&&&&&MS2022: network.c 786 closing IPC with client\n");
      }
      return;
    }
    // received_bytes = sizeof(signed_update_message);
    mess = (signed_message*)srv_recv_scat.elements[0].buf;
    received_bytes = sizeof(signed_message)+mess->len;
  }
#if USE_IPC_CLIENT
  else if (source == IPC_SOURCE) { 
    ret = IPC_Recv(sk, srv_recv_scat.elements[0].buf,
                //sizeof(signed_update_message));
                PRIME_MAX_PACKET_SIZE);
    Alarm(DEBUG,"MS2022: received on IPC_SOURCE size=%d\n",ret); 
    if (ret <= 0) {
        perror("Read from IPC Source bad, dropping packet");
        return;
    }
    // received_bytes = sizeof(signed_update_message);
    received_bytes=ret;
  }
#endif
  else {
    Alarm(EXIT, "Unexpected packet source!\n");
    return;
  }

   Alarm(DEBUG,"MS2022: Received bytes= %d\n",received_bytes); 
  /* Process the packet */
  mess = (signed_message*)srv_recv_scat.elements[0].buf;
    Alarm(DEBUG, "MS2022: Network: Got mess type  %s\n", UTIL_Type_To_String(mess->type));

  if(source == TCP_SOURCE || source == IPC_SOURCE) {
    if (mess->type != UPDATE && mess->type != CLIENT_OOB_CONFIG_MSG) {
        Alarm(DEBUG, "Network: Got invalid mess type %d from client %d,size=%d\n", mess->type,mess->machine_id,received_bytes);
        return;
    }
    Alarm(DEBUG, "MS2022: Network: Got valid mess type %d from client: %d\n", mess->type,mess->machine_id);
    Alarm(DEBUG, "MS2022: Network: Got valid mess type from client: %s\n", UTIL_Type_To_String(mess->type));
    
    /* Store the socket so we know how to send a response */
    /* if(NET.client_sd[mess->machine_id] == 0)
      NET.client_sd[mess->machine_id] = sk; */
  }

  /* Function used to first decide whether or not we should even look at this message 
   * based on the state we are in (STARTUP, RESET, RECOVERY, NORMAL) */
  /*MS2022: DoS / Replay attack handling */
  if (!VAL_State_Permits_Message(mess)) {
    Alarm(STATUS, "State %u does not permit processing type %s, from %u\n",
            DATA.PR.recovery_status[VAR.My_Server_ID], UTIL_Type_To_String(mess->type),
            mess->machine_id);
    return;
  }

  /* 1) Validate the Packet.  If the message does not validate, drop it. */
  if (!VAL_Validate_Message(mess, received_bytes)) {
    Alarm(PRINT, "VALIDATE FAILED for type %s from %u\n", 
            UTIL_Type_To_String(mess->type), mess->machine_id);
    return;
  }

  /* NEW - Process message both applies and (potentially) dispatches
   *    new messages as a result */
  PROCESS_Message(mess);
  
  /* The following checks to see if the packet has been stored and, if so, it
   * allocates a new packet for the next incoming message. */
  if(get_ref_cnt(srv_recv_scat.elements[0].buf) > 1) {
    dec_ref_cnt(srv_recv_scat.elements[0].buf);
    
    if((srv_recv_scat.elements[0].buf = 
	(char *) new_ref_cnt(PACK_BODY_OBJ)) == NULL) {
      Alarm(EXIT, "Net_Srv_Recv: Could not allocate packet body obj\n");
    }
  } 
}

#if !USE_IPC_CLIENT
void NET_Client_Connection_Acceptor(int sd, int dummy, void *dummyp)
{
  struct sockaddr_in client_addr;
  socklen_t len;
  int connfd;

  if (NET.from_client_sd != 0) {
    Alarm(PRINT, "NET_Client_Connection_Acceptor: Cannot accept new client, "
                " Application Replica already connected\n");
    return;
  }

  len = sizeof(client_addr);
  connfd = accept(sd, (struct sockaddr *)&client_addr, &len);

  if (connfd < 0) {
    perror("accept");
    exit(0);
  }
  Alarm(PRINT, "Accepted a client connection!\n");
  NET.from_client_sd = NET.to_client_sd = connfd;
  
  E_attach_fd(connfd, READ_FD, Net_Srv_Recv, TCP_SOURCE, NULL, MEDIUM_PRIORITY);
}
#endif

int max_rcv_buff(int sk)
{
  /* Increasing the buffer on the socket */
  int i, val, ret;
  unsigned int lenval;

  for(i=10; i <= 3000; i+=5) {
    val = 1024*i;
    ret = setsockopt(sk, SOL_SOCKET, SO_RCVBUF, (void *)&val, sizeof(val));
    if (ret < 0)
      break;
    lenval = sizeof(val);
    ret= getsockopt(sk, SOL_SOCKET, SO_RCVBUF, (void *)&val, &lenval);
    if(val < i*1024 )
      break;
  }
  return(1024*(i-5));
}

int max_snd_buff(int sk)
{
  /* Increasing the buffer on the socket */
  int i, val, ret;
  unsigned int lenval;

  for(i=10; i <= 3000; i+=5) {
    val = 1024*i;
    ret = setsockopt(sk, SOL_SOCKET, SO_SNDBUF, (void *)&val, sizeof(val));
    if (ret < 0)
      break;
    lenval = sizeof(val);
    ret = getsockopt(sk, SOL_SOCKET, SO_SNDBUF, (void *)&val,  &lenval);
    if(val < i*1024)
      break;
  }
  return(1024*(i-5));
}
