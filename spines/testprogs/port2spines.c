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
 *  Yair Amir, Claudiu Danilov, John Schultz, Daniel Obenshain, and Thomas Tantillo.
 *
 * Copyright (c) 2003 - 2017 The Johns Hopkins University.
 * All rights reserved.
 *
 * Major Contributor(s):
 * --------------------
 *    John Lane
 *    Raluca Musaloiu-Elefteri
 *    Nilo Rivera
 *
 */

/* port2spines
 *
 * opens a socket to listen for packets incoming on a specified port, then
 * forwards these packets to an open spines connection using the specified
 * protocol
 *
 * Tom Tantillo, Daniel Obenshain
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <netdb.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <errno.h>
#include <math.h>
#include <assert.h>
#include "spines_lib.h"
#include "spu_events.h"
#include "spu_alarm.h"

static int recvPort;
static int sendPort;
static int spinesPort;
static int Protocol;
static char IP[80];
static char SP_IP[80];
static char Unix_domain_path[80];
static int verbose_mode;
static int16u KPaths;

#define MAX_PKT_SIZE 1472
/* we only have 1364 bytes to work with */

typedef struct pkt_stats_d {
    int32u   seq_num;
    int32u   origin_sec;
    int32u   origin_usec;
    int32u   prio;
    unsigned char path[8];
} pkt_stats;

static void Usage(int argc, char *argv[]);

int main(int argc, char *argv[])
{
    int recv_sk, spines_sk, recv_count = 0;
    char buf[MAX_PKT_SIZE];
    int ret, num, bytes, i;
    sp_time now;
    spines_nettime expiration;    
    pkt_stats *ps = (pkt_stats*) buf;

    struct sockaddr_in host, serv_addr, name;
#ifndef ARCH_PC_WIN95
    struct sockaddr_un unix_addr;
#endif /* ARCH_PC_WIN95 */
    struct hostent   h_ent;
    struct hostent  *host_ptr;
    char   machine_name[256];
    int gethostname_error = 0;
    struct sockaddr *daemon_ptr = NULL;
    fd_set mask, dummy_mask, temp_mask;   
 
    Usage(argc, argv);

    /***********************************************************/
    /*        SETTING UP OUTBOUND TRAFFIC (TO SPINES)          */
    /***********************************************************/
    /* gethostname: used for WIN daemon connection & sending to non-specified target */
    gethostname(machine_name,sizeof(machine_name)); 
    host_ptr = gethostbyname(machine_name);
    
    if(host_ptr == NULL) {
        printf("WARNING: could not get my ip addr (my name is %s)\n", machine_name );
        gethostname_error = 1;
    }
    if(host_ptr->h_addrtype != AF_INET) {
        printf("WARNING: Sorry, cannot handle addr types other than IPv4\n");
        gethostname_error = 1;
    }
    if(host_ptr->h_length != 4) {
        printf("WARNING: Bad IPv4 address length\n");
        gethostname_error = 1;
    }

    /* Setup sockaddr structs for daemon connection */
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(spinesPort);
#ifndef ARCH_PC_WIN95
    unix_addr.sun_family = AF_UNIX;
#endif /* ARCH_PC_WIN95 */

    /* INET connections take precedence if specified */
    if(strcmp(SP_IP, "") != 0) {
	    host_ptr = gethostbyname(SP_IP);
        memcpy( &serv_addr.sin_addr, host_ptr->h_addr, sizeof(struct in_addr) );
        daemon_ptr = (struct sockaddr *)&serv_addr;
        printf("Using TCP/IP Connection: %s@%d\n", SP_IP, spinesPort);
    }
    else {
#ifndef ARCH_PC_WIN95
        if (strcmp(Unix_domain_path, "") == 0) {
            if (spinesPort == DEFAULT_SPINES_PORT) {
                daemon_ptr = NULL;
                printf("Using Default IPC Connection\n");
            }
            else  {
                daemon_ptr = (struct sockaddr *)&unix_addr;
                sprintf(unix_addr.sun_path, "%s%hu", SPINES_UNIX_SOCKET_PATH, spinesPort);
                printf("Using IPC on Port %s\n", unix_addr.sun_path);
            }
        } else {
            daemon_ptr = (struct sockaddr *)&unix_addr;
            strncpy(unix_addr.sun_path, Unix_domain_path, sizeof(unix_addr.sun_path));
            printf("Using IPC - custom path = %s\n", unix_addr.sun_path);
        }
#else /* ARCH_PC_WIN95 */
        if (gethostname_error == 1) {
            printf("Exiting... gethostbyname required, but error!\n");
            exit(1);
        }
        daemon_ptr = (struct sockaddr *)&serv_addr;
        memcpy(&serv_addr.sin_addr, host_ptr->h_addr, sizeof(struct in_addr));
        printf("Using TCP/IP Connection - WIN Localhost\n");
#endif /* ARCH_PC_WIN95 */
    }
  
    /* Setup the target (destination spines daemon IPv4 address) to send to */
    if(strcmp(IP, "") != 0) {
        memcpy(&h_ent, gethostbyname(IP), sizeof(h_ent));
        memcpy( &host.sin_addr, h_ent.h_addr, sizeof(host.sin_addr) );
    }
    else {
        if (gethostname_error == 1) {
            printf("Exiting... gethostbyname required, but error!\n");
            exit(1);
        }
        memcpy(&host.sin_addr, host_ptr->h_addr, sizeof(struct in_addr));
    }

    if(spines_init(daemon_ptr) < 0) {
        printf("flooder_client: socket error\n");
        exit(1);
    }


    /* if(strcmp(SP_IP, "") != 0) {
        host_ptr = gethostbyname(SP_IP);
        memcpy(&h_ent, host_ptr, sizeof(h_ent));
        memcpy( &serv_addr.sin_addr, h_ent.h_addr, sizeof(struct in_addr) );
    }
    else {
        gethostname(machine_name,sizeof(machine_name));
        host_ptr = gethostbyname(machine_name);

        if(host_ptr == NULL) {
            printf("could not get my ip address (my name is %s)\n",
                machine_name );
            exit(1);
        }
        if(host_ptr->h_addrtype != AF_INET) {
            printf("Sorry, cannot handle addr types other than IPv4\n");
            exit(1);
         }
        if(host_ptr->h_length != 4) {
            printf("Bad IPv4 address length\n");
            exit(1);
        }
        memcpy(&serv_addr.sin_addr, host_ptr->h_addr, sizeof(struct in_addr));
    }
    serv_addr.sin_port = htons(spinesPort);

    if(spines_init((struct sockaddr*)(&serv_addr)) < 0) {
        printf("port2spines: socket error\n");
        exit(1);
    }

    if(strcmp(IP, "") != 0) {
        memcpy(&h_ent, gethostbyname(IP), sizeof(h_ent));
        memcpy( &host.sin_addr, h_ent.h_addr, sizeof(host.sin_addr) );
    }
    else {
        memcpy(&host.sin_addr, &serv_addr.sin_addr, sizeof(struct in_addr));
    } */
    
    host.sin_family = AF_INET;
    host.sin_port   = htons(sendPort);

    spines_sk = spines_socket(PF_SPINES, SOCK_DGRAM, Protocol, daemon_ptr);
    /* spines_sk = spines_socket(PF_SPINES, SOCK_DGRAM, Protocol, NULL); */
    if (spines_sk < 0) {
      printf("port2spines: client  socket error\n");
      exit(1);
    }

    expiration.sec = 40;
    expiration.usec = 0;
    if (spines_setsockopt(spines_sk, 0, SPINES_SET_EXPIRATION, (void *)&expiration, sizeof(spines_nettime)) < 0) {
        printf("port2spines: error setting expiration time via setsockopt\n");
        exit(0);
    }
    
    /***********************************************************/
    /*        SETTING UP INBOUND TRAFFIC (FROM OUTSIDE)        */
    /***********************************************************/
    recv_sk = socket(AF_INET, SOCK_DGRAM, 0);
    if (recv_sk < 0) {
        printf("port2spines: couldn't open recv socket");
        exit(1);
    }
    
    name.sin_family = AF_INET;
    name.sin_addr.s_addr = INADDR_ANY;
    name.sin_port = htons(recvPort);
    
    if ( bind( recv_sk, (struct sockaddr *)&name, sizeof(name) ) < 0 ) {
        perror("port2spines: bind for recv socket failed");
        exit(1);
    }
    
    FD_ZERO( &mask );
    FD_ZERO( &dummy_mask );
    FD_SET( recv_sk, &mask );

    /* Start FORWARDING */
    printf("\r\nForwarding packets recv'd on port %d to spines daemon on %s:%d with protocol %d\n", 
            recvPort, IP, sendPort, Protocol);

    for (i = 0; i < 8; i++) {
        ps->path[i] = 0;
    }
   
    if (spines_setsockopt(spines_sk, 0, SPINES_DISJOINT_PATHS, (void *)&KPaths,
          sizeof(int16u)) < 0)
    {
        printf("error setting k-paths value = %d via setsockopt\n", KPaths);
        exit(0);
    }

    for(;;) {

        temp_mask = mask;
        num = select( FD_SETSIZE, &temp_mask, &dummy_mask, &dummy_mask, NULL);
        
        bytes = recv( recv_sk, buf+sizeof(pkt_stats), sizeof(buf)-sizeof(pkt_stats), 0);

        now = E_get_time();
        ps->seq_num  = htonl(++recv_count);
        ps->origin_sec = htonl(now.sec);
        ps->origin_usec = htonl(now.usec);
        
        if (recv_count % 1000 == 0)
            printf("packet %d w/ size = %d\n", recv_count, bytes);


        ret = spines_sendto(spines_sk, buf, bytes+sizeof(pkt_stats), 0, 
                            (struct sockaddr *)&host, sizeof(struct sockaddr));

        if (ret != bytes+sizeof(pkt_stats)) {
            printf("error in writing: %d...\n", ret);
            exit(0);
        }
    }
    
    spines_close(spines_sk);
    return 0;
}

static void Usage(int argc, char *argv[])
{
  int tmp;

  /* Setting defaults */
  spinesPort            = 8100;
  sendPort              = 8400;
  recvPort              = 8500;
  Protocol              = 0;
  strcpy(IP, "");
  strcpy(SP_IP, "");
  strcpy(Unix_domain_path, "");
  verbose_mode          = 0;
  tmp                   = 0;
  KPaths                = 0;   /* This is Flooding */

  while( --argc > 0 ) {
    argv++;

    if( !strncmp( *argv, "-p", 2 ) ){
      sscanf(argv[1], "%d", (int*)&spinesPort );
      argc--; argv++;
    } else if( !strncmp( *argv, "-ud", 4 ) ){
      sscanf(argv[1], "%s", Unix_domain_path);
      argc--; argv++;
    } else if( !strncmp( *argv, "-d", 2 ) ){
      sscanf(argv[1], "%d", (int*)&sendPort );
      argc--; argv++;
    } else if( !strncmp( *argv, "-r", 2 ) ){
      sscanf(argv[1], "%d", (int*)&recvPort );
      argc--; argv++;
    } else if( !strncmp( *argv, "-a", 2 ) ){
      sscanf(argv[1], "%s", IP );
      argc--; argv++;
    } else if( !strncmp( *argv, "-k", 2 ) ){
      sscanf(argv[1], "%hu", (int16*)&KPaths );
      argc--; argv++;
    } else if( !strncmp( *argv, "-o", 2 ) ){
      sscanf(argv[1], "%s", SP_IP );
      argc--; argv++;
    } else if( !strncmp( *argv, "-v", 2 ) ){
      verbose_mode = 1;
    } else if( !strncmp( *argv, "-P", 2 ) ){
      if(sscanf(argv[1], "%d", (int*)&tmp ) < 1 || (tmp < 0) || (tmp > 2 && tmp != 8)) { /*dtflood*/
        Alarm(EXIT, "Bad Protocol %d specified through -P option!\r\n", tmp);
      }
      Protocol |= tmp;
      argc--; argv++;
    } else if ( !strncmp( *argv, "-D", 2 ) ) {
        if(sscanf(argv[1], "%d", (int*)&tmp ) < 1 || (tmp < 0) || (tmp > 2)) { /*dtflood*/
            Alarm(EXIT, "Bad Dissemination %d specified through -D option!\r\n", tmp);
        }
        Protocol |= (tmp << ROUTING_BITS_SHIFT);
        argc--; argv++;
    } else {
        printf( "Usage: port2spines\n"
          "\t[-o <address>    ] : address where spines runs, default localhost\n"
          "\t[-p <port number>] : port where spines runs, default is 8100\n"
          "\t[-ud <path>      ] : unix domain socket path to connect to, default is /tmp/spines<port>\n"
          "\t[-r <port number>] : to receive packets on, default is 8500\n"
          "\t[-d <port number>] : to send packets on, default is 8400\n"
          "\t[-a <address>    ] : address to send packets to\n"
          "\t[-P <0, 1, 2, 8> ] : overlay links (0: UDP; 1: Reliable; 2: Realtime; 8: Priority Flooding)\n"
	      "\t[-D <0, 1, 2>    ] : dissemination alg (0: Min Weight; 1: Best-Effort Flood; 2: Reliable Flood)\n"
          "\t[-k <num>        ] : number of node-disjoint paths to take\n"
          "\t[-v              ] : print verbose\n");
        exit( 0 );
    }
  }
}
