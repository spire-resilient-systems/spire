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

/* spines2port
 *
 * opens a socket to forward packets to a specified address/port, then
 * forwards packets from an open spines connection to that address/port
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

#define WINDOW_SIZE 20000  /* conservative approach */
#define MAX_PKT_SIZE 1472  /* we only have 1364 bytes to work with */
#define MAX_NEIGHBORS 100  /* we can only mirror to 100 neighbors */ 

static int recvPort;
static int spinesPort;
static int Protocol;
static int Group_Address;
static char MCAST_IP[80];
static char SP_IP[80];
static char Unix_domain_path[80];
static int verbose_mode;
static int wait_buffer;
static int Address[MAX_NEIGHBORS];
static int Port[MAX_NEIGHBORS];
static int numNeighbors;
static int16u KPaths;

typedef struct pkt_stats_d {
    int32u   seq_num;
    int32u   origin_sec;
    int32u   origin_usec;
    int32u   prio;
    unsigned char path[8];
} pkt_stats;

typedef struct history_d {
    struct timeval timeout;
    int size;
    char buffer[MAX_PKT_SIZE];
} history;

static struct timeval addTime( struct timeval t1, struct timeval t2 );
static struct timeval diffTime( struct timeval t1, struct timeval t2 );
static int compTime( struct timeval t1, struct timeval t2 );
static void Usage(int argc, char *argv[]);

int main(int argc, char *argv[])
{
    int send_sk, spines_sk, recv_count = 0, i, k;
    char buf[MAX_PKT_SIZE];
    int ret, bytes;
    long long unsigned int tail = 1, head = 1, ref = 1, recv_seq;
    long long int oneway_time;
    struct timeval then, now, wait_time, pkt_expire;
    struct timeval timeout;
    struct timeval *timeout_ptr;
    pkt_stats *ps = (pkt_stats*) buf;

    struct ip_mreq mreq;
    struct sockaddr_in serv_addr, name;
    struct sockaddr_in connections[MAX_NEIGHBORS];
#ifndef ARCH_PC_WIN95
    struct sockaddr_un unix_addr;
#endif /* ARCH_PC_WIN95 */
    struct hostent  *host_ptr;
    int gethostname_error = 0;
    struct sockaddr *daemon_ptr = NULL;
    fd_set  mask, dummy_mask, temp_mask;
    char   machine_name[256];
 
    history *window;

    window = malloc(sizeof(history) * WINDOW_SIZE);

    if (!window)
    {
        printf("Memory error: unable to malloc");
        exit(1);
    }

    Usage(argc, argv);
    wait_time.tv_sec = 0;
    wait_time.tv_usec = (wait_buffer % 1000) * 1000;

    /***********************************************************/
    /*        SETTING UP INBOUND TRAFFIC (FROM SPINES)         */
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

    if(spines_init(daemon_ptr) < 0) {
        printf("flooder_client: socket error\n");
        exit(1);
    }
    
    /* 
    if(strcmp(SP_IP, "") != 0) {
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
    } */
    
    spines_sk = spines_socket(PF_INET, SOCK_DGRAM, Protocol, daemon_ptr);
    /* spines_sk = spines_socket(PF_INET, SOCK_DGRAM, Protocol, NULL); */
    if (spines_sk <= 0) {
        printf("spines_sk error..\n");
        exit(0);
    }
    
    name.sin_family = AF_INET;
    name.sin_addr.s_addr = INADDR_ANY;
    name.sin_port = htons(recvPort);

    if(spines_bind(spines_sk, (struct sockaddr *)&name, sizeof(name) ) < 0) {
        printf("spines_bind error\n");
        exit(0);
    }

    if(Group_Address != -1) {
        mreq.imr_multiaddr.s_addr = htonl(Group_Address);
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);

        if(spines_setsockopt(spines_sk, IPPROTO_IP, SPINES_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq)) < 0) {
            printf("Mcast: problem in setsockopt to join multicast address");
            exit(0);
        }
    }

    /***********************************************************/
    /*        SETTING UP OUTBOUND TRAFFIC (TO OUTSIDE)         */
    /***********************************************************/
    send_sk = socket(AF_INET, SOCK_DGRAM, 0);
    if (send_sk < 0) {
        printf("spines2port: couldn't open send socket");
        exit(1);
    }
    
    for (i = 0; i < numNeighbors; i++) {
        connections[i].sin_family = AF_INET;
        connections[i].sin_addr.s_addr = htonl(Address[i]);
        connections[i].sin_port = htons(Port[i]);
    }
    
    FD_ZERO( &mask );
    FD_ZERO( &dummy_mask );
    FD_SET( spines_sk, &mask );

    for (i = 0; i < WINDOW_SIZE; i++)
        window[i].size = 0;
   
    if (spines_setsockopt(spines_sk, 0, SPINES_DISJOINT_PATHS, (void *)&KPaths,
          sizeof(int16u)) < 0)
    {
        printf("error setting k-paths value = %d via setsockopt\n", KPaths);
        exit(0);
    }

    for(;;) {

        if (head == tail)
            timeout_ptr = NULL;
        else
        {
            timeout_ptr = &timeout;
            gettimeofday(&now, NULL);
            timeout = diffTime(window[ref % WINDOW_SIZE].timeout, now);
        }

        temp_mask = mask;
       
        ret = select( FD_SETSIZE, &temp_mask, &dummy_mask, &dummy_mask, timeout_ptr);
        
        gettimeofday(&now, NULL);
        
        if (ret > 0) {
            bytes = spines_recvfrom(spines_sk, buf, sizeof(buf), 0, NULL, 0);
            if (bytes <= 0) {
                printf("Disconnected by spines...\n");
                exit(0);
            }
           
            recv_count++;
            if (recv_count % 1000 == 0) {
                then.tv_sec  = ntohl(ps->origin_sec); 
                then.tv_usec = ntohl(ps->origin_usec);
                oneway_time = (now.tv_sec - then.tv_sec);
                oneway_time *= 1000000;
                oneway_time += (now.tv_usec - then.tv_usec);

                printf("%ld\t%d\t%4f\tpath: ", bytes-sizeof(pkt_stats),
                    recv_count, oneway_time/1000.0);
                for (k = 0; k < 8; k++) {
                    if (ps->path[k] != 0)
                        printf("%d ", (int)ps->path[k]);
                    else
                        break;
                }
                printf("\r\n");
            }
            
            recv_seq           = ntohl(ps->seq_num);
            /* pkt_expire.tv_sec  = ntohl(ps->origin_sec);
            pkt_expire.tv_usec = ntohl(ps->origin_usec); */
            pkt_expire = now;
            pkt_expire = addTime(pkt_expire, wait_time);

            /* First check if this packet is already expired */
            /* temp_time = diffTime(pkt_expire, now); */

            /* do nothing, ignore old packet */ 
            /* if (temp_time.tv_sec <= 0 && temp_time.tv_usec <= 0) {
                printf("Received packet too late.\n");
            } */
            if (recv_seq < tail) {
                /* do nothing, ignore old packet */
                /*printf("Error case. Received unexpired but undeliverable packet: recv_seq = %llu tail = %llu\n",
                                recv_seq, tail); */
                printf("recv'd pkt earlier than tail: recv_seq = %llu, tail = %llu\n", recv_seq, tail);
            }
            else if (recv_seq >= tail && recv_seq < head) {
                /* filling in a gap */
                window[recv_seq % WINDOW_SIZE].size = bytes;
                window[recv_seq % WINDOW_SIZE].timeout = pkt_expire;
                memcpy(window[recv_seq % WINDOW_SIZE].buffer, buf, bytes);
                if (recv_seq < ref)
                    ref = recv_seq;
            }
            else if (recv_seq == head) {
                /* regular case, next expected pkt */
                window[recv_seq % WINDOW_SIZE].size = bytes;
                window[recv_seq % WINDOW_SIZE].timeout = pkt_expire;
                memcpy(window[recv_seq % WINDOW_SIZE].buffer, buf, bytes);
                head++;
                if (head - tail == WINDOW_SIZE) {
                    printf("ERROR: window size is too small for this buffering time.\n");
                    printf("head = %llu, ref = %llu, tail = %llu\n", head, ref, tail);
                    printf("now = %lu.%lu, ref_TO = %lu.%lu, ref_size = %d\n", 
                                (unsigned long int)now.tv_sec,
                                (unsigned long int)now.tv_usec,
                                (unsigned long int)window[ref % WINDOW_SIZE].timeout.tv_sec,
                                (unsigned long int)window[ref % WINDOW_SIZE].timeout.tv_usec,
                                window[ref % WINDOW_SIZE].size);
                    window[tail % WINDOW_SIZE].size = 0;
                    if (ref == tail)
                        ref++;
                    tail++;
                    exit(1);
                }
            }
            else { /* recv_seq > head --> missed a pkt, generating gap */
                /* If we are really far ahead */
                if (recv_seq - tail >= WINDOW_SIZE) {
                    printf("Large gap detected: recv_seq = %llu, tail = %llu. Resetting window.\n",
                                    recv_seq, tail);
                    for (i = 0; i < WINDOW_SIZE; i++) {
                        window[i].size = 0;
                    }
                    ref  = recv_seq;
                    tail = recv_seq;
                    head = recv_seq; /* will be incremented once more below to become recv_seq + 1 */
                }
                window[recv_seq % WINDOW_SIZE].size = bytes;
                window[recv_seq % WINDOW_SIZE].timeout = pkt_expire;
                memcpy(window[recv_seq % WINDOW_SIZE].buffer, buf, bytes);
                
                /* Only relevant for "small gaps", not the really far ahead case */
                while (head < recv_seq) {
                    window[head % WINDOW_SIZE].size = 0;
                    head++;
                }
                head++;
                while(window[ref % WINDOW_SIZE].size == 0 && ref < head)
                    ref++;
            }
        }

        if (window[ref % WINDOW_SIZE].size > 0 && compTime(window[ref % WINDOW_SIZE].timeout, now) <= 0)
        {
            for (i = 0; i < numNeighbors; i++) {
                ret = sendto(send_sk, window[ref % WINDOW_SIZE].buffer+sizeof(pkt_stats), 
                        window[ref % WINDOW_SIZE].size-sizeof(pkt_stats), 0, 
                        (struct sockaddr *)&connections[i], sizeof(struct sockaddr));
                if (ret != window[ref % WINDOW_SIZE].size-sizeof(pkt_stats)) {
                  printf("spines2port: error in writing when sending to connection %d...\n", i);
                  exit(0);
                }
            }
            window[ref % WINDOW_SIZE].size = 0;
            if (tail != ref)
            {
                printf("Giving up, skipping packet(s).\n");
            }
            tail = ref + 1;
            while(window[ref % WINDOW_SIZE].size == 0 && ref < head)
                ref++;
        }
                
    }
    
    free(window);

    spines_close(spines_sk);
    return 0;
}

static struct timeval addTime( struct timeval t1, struct timeval t2 ) {
    
    struct timeval res;

	res.tv_sec  = t1.tv_sec  + t2.tv_sec;
	res.tv_usec = t1.tv_usec + t2.tv_usec;
	if ( res.tv_usec > 1000000 )
	{
		res.tv_usec -= 1000000;
		res.tv_sec++;
	}

	return res;
}

static struct timeval diffTime( struct timeval t1, struct timeval t2 ) {
    
    struct timeval diff;

    diff.tv_sec =  t1.tv_sec  - t2.tv_sec;
    diff.tv_usec = t1.tv_usec - t2.tv_usec;
    if ( diff.tv_usec < 0 ) {
        diff.tv_usec += 1000000;
        diff.tv_sec--;
    }
    if ( diff.tv_sec < 0 ) {
        diff.tv_sec = 0;
        diff.tv_usec = 0;
    }

    return diff;
}

static int compTime( struct timeval t1, struct timeval t2 ) {
	if	( t1.tv_sec  > t2.tv_sec  ) return (  1 );
	else if ( t1.tv_sec  < t2.tv_sec  ) return ( -1 );
	else if ( t1.tv_usec > t2.tv_usec ) return (  1 );
	else if ( t1.tv_usec < t2.tv_usec ) return ( -1 );
	else			      return (  0 );
}

static void Usage(int argc, char *argv[])
{
  int i1, i2, i3, i4, tmp;
  int ret, tmpPort;
  char ip_str[24];   /* large enough for X.X.X.X:YYYY ip address */
  char machine_name[80];
  char* portptr;
  struct hostent *p_h_ent;
  struct hostent h_ent;
  long host_num;

  /* Setting defaults */
  spinesPort            = 8100;
  recvPort              = 8400;
  Protocol              = 0;
  numNeighbors          = 0;
  strcpy(SP_IP, "");
  strcpy(MCAST_IP, "");
  strcpy(Unix_domain_path, "");
  Group_Address         = -1;
  verbose_mode          = 0;
  wait_buffer           = 30;
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
    } else if( !strncmp( *argv, "-r", 2 ) ){
      sscanf(argv[1], "%d", (int*)&recvPort );
      argc--; argv++;
    } else if((!strncmp( *argv, "-a", 2)) && (argc > 1) && (numNeighbors < MAX_NEIGHBORS)) {
      sscanf(argv[1], "%24s", ip_str );
      ret = sscanf( ip_str, "%d.%d.%d.%d:%d", &i1, &i2, &i3, &i4, &tmpPort);
      if (ret == 5) {
        Address[numNeighbors] = ( (i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4 );
      } else {
        portptr = strchr(ip_str, ':');
        sscanf(portptr+1, "%d", (int*)&tmpPort);
        *portptr = '\0';
        p_h_ent = gethostbyname(ip_str);
        if (p_h_ent == NULL) {
            printf("gethostbyname error: %s\n", ip_str);
            exit(1);
        }
        memcpy(&h_ent, p_h_ent, sizeof(h_ent));
        memcpy(&host_num, h_ent.h_addr_list[0], sizeof(host_num));
        Address[numNeighbors] = ntohl(host_num);
      }
      if (tmpPort < 0 || tmp > 65535) {
        printf("Error: Bad Port Specified: %d\n", tmpPort);
        exit(1);
      }
      Port[numNeighbors] = tmpPort;
      numNeighbors++; argc--; argv++;
      if (numNeighbors >= MAX_NEIGHBORS) {
        printf("Error: Too many connections specified\n");
        exit(1);
      }
    } else if( !strncmp( *argv, "-k", 2 ) ){
      sscanf(argv[1], "%hu", (int16u*)&KPaths );
      argc--; argv++;
    } else if( !strncmp( *argv, "-j", 2 ) ){
      sscanf(argv[1], "%80s", MCAST_IP );
      sscanf(MCAST_IP ,"%d.%d.%d.%d",&i1, &i2, &i3, &i4);
      Group_Address = ( (i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4 );
      argc--; argv++;
    } else if( !strncmp( *argv, "-o", 2 ) ){
      sscanf(argv[1], "%80s", SP_IP );
      argc--; argv++;
    } else if( !strncmp( *argv, "-v", 2 ) ){
      verbose_mode = 1;
    } else if( !strncmp( *argv, "-w", 2 ) ){
      sscanf(argv[1], "%d", (int*)&wait_buffer );
      argc--; argv++;
      if (wait_buffer < 0)
        Alarm(EXIT, "Invalid wait time specified: %d. Must be between 0-999!\r\n", wait_buffer);
    } else if( !strncmp( *argv, "-P", 2 ) ){
      if(sscanf(argv[1], "%d", (int*)&tmp ) < 1 || (tmp < 0) || (tmp > 2 && tmp != 8)) {
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
        printf( "Usage: spines2port\n"
          "\t[-o <address>    ] : address where spines runs, default localhost\n"
          "\t[-p <port number>] : port where spines runs, default is 8100\n"
          "\t[-ud <path>      ] : unix domain socket path to connect to, default is /tmp/spines<port>\n"
          "\t[-r <port number>] : to receive packets on, default is 8400\n"
          "\t[-a <addr>:<port>] : address:port to send packets to, default is local machine and port 5555\n"
          "\t[-j <mcast addr> ] : multicast address to join\n"
          "\t[-w <millisecond>] : length of time to wait for a missing packet before skipping \n"
          "\t[-P <0, 1, 2, 8> ] : overlay links (0: UDP; 1: Reliable; 2: Realtime; 8: Priority Flooding)\n"
	      "\t[-D <0, 1, 2>    ] : dissemination alg (0: Min Weight; 1: Best-Effort Flood; 2: Reliable Flood)\n"
          "\t[-v              ] : print verbose\n");
        exit( 0 );
    }
  }

  if (numNeighbors == 0) {
    printf("No connections (destination addresses) were specified, setting default (local machine and port 5555)...\n");
    gethostname(machine_name,sizeof(machine_name));
    p_h_ent = gethostbyname(machine_name);
    if (p_h_ent == NULL) {
        printf("gethostbyname error: %s\n", machine_name);
        exit(1);
    }
    memcpy(&h_ent, p_h_ent, sizeof(h_ent));
    memcpy(&host_num, h_ent.h_addr_list[0], sizeof(host_num));
    Address[numNeighbors] = ntohl(host_num);
    Port[numNeighbors] = 5555;
    numNeighbors = 1;
  }
}
