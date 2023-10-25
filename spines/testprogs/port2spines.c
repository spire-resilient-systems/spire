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

/* port2spines
 *
 * opens a socket to listen for packets incoming on a specified port, then
 * forwards these packets to an open spines connection using the specified
 * protocol
 *
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
static int Reporting_Interval;

#define MAX_PKT_SIZE               1472 /* we only have 1364 bytes to work with */
#define DEFAULT_SPINES_PORT        8100
#define DEFAULT_RECV_PORT          8400
#define DEFAULT_SEND_PORT          8400
#define DEFAULT_REPORTING_INTERVAL 1000

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

    /* Interval Reporting statistics */
    long unsigned int interval_bytes = 0;
    double interval_start_ms = 0;
    double now_ms;

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
 
    setlinebuf(stdout);

    Usage(argc, argv);

    /***********************************************************/
    /*        SETTING UP OUTBOUND TRAFFIC (TO SPINES)          */
    /***********************************************************/
    /* gethostname: used for WIN daemon connection & sending to non-specified target */
    gethostname(machine_name,sizeof(machine_name)); 
    host_ptr = gethostbyname(machine_name);
    
    if(host_ptr == NULL) {
        Alarm(PRINT, "WARNING: could not get my ip addr (my name is %s)\n", machine_name );
        gethostname_error = 1;
    }
    if(host_ptr->h_addrtype != AF_INET) {
        Alarm(PRINT, "WARNING: Sorry, cannot handle addr types other than IPv4\n");
        gethostname_error = 1;
    }
    if(host_ptr->h_length != 4) {
        Alarm(PRINT, "WARNING: Bad IPv4 address length\n");
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
        Alarm(PRINT, "Using TCP/IP Connection: %s@%d\n", SP_IP, spinesPort);
    }
    else {
#ifndef ARCH_PC_WIN95
        if (strcmp(Unix_domain_path, "") == 0) {
            if (spinesPort == DEFAULT_SPINES_PORT) {
                daemon_ptr = NULL;
                Alarm(PRINT, "Using Default IPC Connection\n");
            }
            else  {
                daemon_ptr = (struct sockaddr *)&unix_addr;
                sprintf(unix_addr.sun_path, "%s%hu", SPINES_UNIX_SOCKET_PATH, (unsigned short) spinesPort);
                Alarm(PRINT, "Using IPC on Port %s\n", unix_addr.sun_path);
            }
        } else {
            daemon_ptr = (struct sockaddr *)&unix_addr;
            strncpy(unix_addr.sun_path, Unix_domain_path, sizeof(unix_addr.sun_path));
            Alarm(PRINT, "Using IPC - custom path = %s\n", unix_addr.sun_path);
        }
#else /* ARCH_PC_WIN95 */
        if (gethostname_error == 1) {
            Alarm(EXIT, "Exiting... gethostbyname required, but error!\n");
        }
        daemon_ptr = (struct sockaddr *)&serv_addr;
        memcpy(&serv_addr.sin_addr, host_ptr->h_addr, sizeof(struct in_addr));
        Alarm(PRINT, "Using TCP/IP Connection - WIN Localhost\n");
#endif /* ARCH_PC_WIN95 */
    }
  
    /* Setup the target (destination spines daemon IPv4 address) to send to */
    if(strcmp(IP, "") != 0) {
        memcpy(&h_ent, gethostbyname(IP), sizeof(h_ent));
        memcpy( &host.sin_addr, h_ent.h_addr, sizeof(host.sin_addr) );
    }
    else {
        if (gethostname_error == 1) {
            Alarm(EXIT, "Exiting... gethostbyname required, but error!\n");
        }
        memcpy(&host.sin_addr, host_ptr->h_addr, sizeof(struct in_addr));
    }

    if(spines_init(daemon_ptr) < 0) {
        Alarm(EXIT, "port2spines: socket error\n");
    }

    host.sin_family = AF_INET;
    host.sin_port   = htons(sendPort);

    spines_sk = spines_socket(PF_SPINES, SOCK_DGRAM, Protocol, daemon_ptr);
    if (spines_sk < 0) {
      Alarm(EXIT, "port2spines: client  socket error\n");
    }

    expiration.sec = 40;
    expiration.usec = 0;
    if (spines_setsockopt(spines_sk, 0, SPINES_SET_EXPIRATION, (void *)&expiration, sizeof(spines_nettime)) < 0) {
        Alarm(EXIT, "port2spines: error setting expiration time via setsockopt\n");
    }
    
    /***********************************************************/
    /*        SETTING UP INBOUND TRAFFIC (FROM OUTSIDE)        */
    /***********************************************************/
    recv_sk = socket(AF_INET, SOCK_DGRAM, 0);
    if (recv_sk < 0) {
        Alarm(EXIT, "port2spines: couldn't open recv socket");
    }
    
    name.sin_family = AF_INET;
    name.sin_addr.s_addr = INADDR_ANY;
    name.sin_port = htons(recvPort);
    
    if ( bind( recv_sk, (struct sockaddr *)&name, sizeof(name) ) < 0 ) {
        Alarm(EXIT, "port2spines: bind for recv socket failed");
    }
    
    FD_ZERO( &mask );
    FD_ZERO( &dummy_mask );
    FD_SET( recv_sk, &mask );

    /* Start FORWARDING */
    Alarm(PRINT, "\r\nForwarding packets recv'd on port %d to spines daemon on %s:%d with protocol %d\n", 
            recvPort, IP, sendPort, Protocol);

    for (i = 0; i < 8; i++) {
        ps->path[i] = 0;
    }
   
    if (spines_setsockopt(spines_sk, 0, SPINES_DISJOINT_PATHS, (void *)&KPaths,
          sizeof(int16u)) < 0)
    {
        Alarm(EXIT, "error setting k-paths value = %d via setsockopt\n", KPaths);
    }

    for(;;) {

        temp_mask = mask;
        num = select( FD_SETSIZE, &temp_mask, &dummy_mask, &dummy_mask, NULL);
        
        bytes = recv( recv_sk, buf+sizeof(pkt_stats), sizeof(buf)-sizeof(pkt_stats), 0);

        /* Set timestamp */
        now = E_get_time();
        ps->seq_num  = htonl(++recv_count);
        ps->origin_sec = htonl(now.sec);
        ps->origin_usec = htonl(now.usec);

        /* Send over spines */
        ret = spines_sendto(spines_sk, buf, bytes+sizeof(pkt_stats), 0, 
                            (struct sockaddr *)&host, sizeof(struct sockaddr));

        if (ret != bytes+sizeof(pkt_stats)) {
            Alarm(EXIT, "error in writing: %d...\n", ret);
        }

        /* Reporting */
        interval_bytes += bytes;
        
        if (recv_count == 1) {
            now_ms = now.sec * 1000.0;
            now_ms += now.usec / 1000.0;
            interval_start_ms = now_ms;
        }

        if (recv_count % Reporting_Interval == 0) {
            now_ms = now.sec * 1000.0;
            now_ms += now.usec / 1000.0;
            Alarm(PRINT, "\t%lu\t%7.4lf Mbps\t%7ld msgs\t%ld bytes\n",
                  recv_count,
                  (interval_bytes * 8.0) / (now_ms - interval_start_ms) / 1000.0,
                  Reporting_Interval, interval_bytes);
            interval_start_ms = now_ms;
            interval_bytes = 0;
        }

    }
    
    spines_close(spines_sk);
    return 0;
}

static void Usage(int argc, char *argv[])
{
  int tmp;

  /* Setting defaults */
  spinesPort            = DEFAULT_SPINES_PORT;
  sendPort              = DEFAULT_SEND_PORT;
  recvPort              = DEFAULT_RECV_PORT;
  Protocol              = 0;
  strcpy(IP, "");
  strcpy(SP_IP, "");
  strcpy(Unix_domain_path, "");
  verbose_mode          = 0;
  tmp                   = 0;
  KPaths                = 0;   /* This is Flooding */
  Reporting_Interval    = DEFAULT_REPORTING_INTERVAL;

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
    } else if( !strncmp( *argv, "-i", 2 ) ){
      sscanf(argv[1], "%d", (int*)&Reporting_Interval );
      argc--; argv++;
      if (Reporting_Interval <= 0)
        Alarm(EXIT, "Invalid printing interval specified: %d. Must be > 0!\r\n", Reporting_Interval);
    } else if( !strncmp( *argv, "-v", 2 ) ){
      verbose_mode = 1;
    } else if( !strncmp( *argv, "-P", 2 ) ){
      if(sscanf(argv[1], "%d", (int*)&tmp ) < 1 || (tmp < 0) || (tmp > 2 && tmp != 8)) { /*dtflood*/
        Alarm(EXIT, "Bad Protocol %d specified through -P option!\r\n", tmp);
      }
      Protocol |= tmp;
      argc--; argv++;
    } else if ( !strncmp( *argv, "-D", 2 ) ) {
        if(sscanf(argv[1], "%d", (int*)&tmp ) < 1 || (tmp < 0) || (tmp > 3)) { /*dtflood (1,2), source-based (3)*/
            Alarm(EXIT, "Bad Dissemination %d specified through -D option!\r\n", tmp);
        }
        Protocol |= (tmp << ROUTING_BITS_SHIFT);
        argc--; argv++;
    } else {
        Alarm(PRINT,  "Usage: port2spines\n");
        Alarm(PRINT, "\t[-o <address>    ] : address where spines runs, default localhost\n");
        Alarm(PRINT, "\t[-p <port number>] : port where spines runs, default is %d\n", DEFAULT_SPINES_PORT);
        Alarm(PRINT, "\t[-ud <path>      ] : unix domain socket path to connect to, default is /tmp/spines<port>\n");
        Alarm(PRINT, "\t[-r <port number>] : to receive packets on, default is %d\n", DEFAULT_RECV_PORT);
        Alarm(PRINT, "\t[-d <port number>] : to send packets on, default is %d\n", DEFAULT_SEND_PORT);
        Alarm(PRINT, "\t[-a <address>    ] : address to send packets to\n");
        Alarm(PRINT, "\t[-P <0, 1, 2, 8> ] : overlay links (0: UDP; 1: Reliable; 2: Realtime; 8: Intrusion-Tolerant Links)\n");
	    Alarm(PRINT, "\t[-D <0, 1, 2, 3> ] : dissemination alg (0: Min Weight; 1: IT Priority Flood; 2: IT Reliable Flood, 3: Source-Based Routing)\n");
        Alarm(PRINT, "\t[-k <num>        ] : number of node-disjoint paths to take\n");
        Alarm(PRINT, "\t[-i <interval>   ] : print stats every <interval> msgs, default %d\n", DEFAULT_REPORTING_INTERVAL);
        Alarm(PRINT, "\t[-v              ] : print verbose\n");
        Alarm(EXIT, "\n");
    }
  }

  Alarm_enable_timestamp("%a %d %b %H:%M:%S %Y");
}
