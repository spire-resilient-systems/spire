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

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include "spines_lib.h"

static char DEST_IP[80];
static char MCAST_IP[80];
static char SP_IP[80];
static char Unix_domain_path[80];
static char Loopback;
static int  spinesPort;
static int  sendPort;
static int  recvPort;
static int  Sender;
static int  Protocol;
static int  Group_Address;
static int  Dest_Address;

static void Usage(int argc, char *argv[]);

#define MAX_PKT_SIZE  100000
#define MAX_MESS_LEN     8192

#define IP1( address )  ( ( 0xFF000000 & (address) ) >> 24 )
#define IP2( address )  ( ( 0x00FF0000 & (address) ) >> 16 )
#define IP3( address )  ( ( 0x0000FF00 & (address) ) >> 8 )
#define IP4( address )  ( ( 0x000000FF & (address) ) )
#define IP( address ) IP1(address),IP2(address),IP3(address),IP4(address)
#define IPF "%ld.%ld.%ld.%ld"

int main(int argc, char* argv[])
{
    struct sockaddr_in host, group_addr;
    struct hostent     *host_ptr;
#ifndef ARCH_PC_WIN95
    struct sockaddr_un unix_addr;
#endif /* ARCH_PC_WIN95 */

    char           machine_name[256];
    int            gethostname_error = 0;
    struct         sockaddr *daemon_ptr = NULL;
    int            ss, sr, bytes, num, ret, i;
    fd_set         mask;
    //fd_set         dummy_mask,temp_mask;
    fd_set         temp_mask;
    char           mess_buf[MAX_MESS_LEN];
    char           input_buf[80];
    struct ip_mreq mreq;
    spines_trace   spt;

    Usage(argc, argv);


    /*************************************************************/
    /* INITIALIZE SPINES                                         */
    /*************************************************************/
    #if 0
    if(strcmp(SP_IP, "") != 0) {
        memcpy(&h_ent, gethostbyname(SP_IP), sizeof(h_ent));
        memcpy( &host.sin_addr, h_ent.h_addr, sizeof(struct in_addr) );
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
        memcpy(&host.sin_addr, host_ptr->h_addr, sizeof(struct in_addr));
    }
    host.sin_port = htons(spinesPort);

    if(spines_init((struct sockaddr*)(&host)) < 0) {
        printf("socket error\n");
        exit(1);
    }
    #endif

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
    host.sin_family = AF_INET;
    host.sin_port = htons(spinesPort);
#ifndef ARCH_PC_WIN95
    unix_addr.sun_family = AF_UNIX;
#endif /* ARCH_PC_WIN95 */

    /* INET connections take precedence if specified */
    if(strcmp(SP_IP, "") != 0) {
	    host_ptr = gethostbyname(SP_IP);
        memcpy( &host.sin_addr, host_ptr->h_addr, sizeof(struct in_addr) );
        daemon_ptr = (struct sockaddr *)&host;
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
                sprintf(unix_addr.sun_path, "%s%hu", SPINES_UNIX_SOCKET_PATH, (unsigned short) spinesPort);
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
        daemon_ptr = (struct sockaddr *)&host;
        memcpy(&host.sin_addr, host_ptr->h_addr, sizeof(struct in_addr));
        printf("Using TCP/IP Connection - WIN Localhost\n");
#endif /* ARCH_PC_WIN95 */
    }
  
    /* Setup the target (destination spines daemon IPv4 address) to send to */
    /* if(strcmp(IP, "") != 0) {
        memcpy(&h_ent, gethostbyname(IP), sizeof(h_ent));
        memcpy( &host.sin_addr, h_ent.h_addr, sizeof(host.sin_addr) );
    }
    else {
        if (gethostname_error == 1) {
            printf("Exiting... gethostbyname required, but error!\n");
            exit(1);
        }
        memcpy(&host.sin_addr, host_ptr->h_addr, sizeof(struct in_addr));
    } */

    if(spines_init(daemon_ptr) < 0) {
        printf("flooder_client: socket error\n");
        exit(1);
    }

    /*************************************************************/
    /* RECEIVE SOCKET                                            */
    /*************************************************************/
    sr = spines_socket(PF_SPINES, SOCK_DGRAM, Protocol, daemon_ptr);
    if (sr<0) {
        perror("Receive socket");
        exit(1);
    }
    host.sin_family = AF_INET;
    host.sin_port = htons(recvPort);        
    host.sin_addr.s_addr = INADDR_ANY;

    if ( spines_bind( sr, (struct sockaddr *)&host, sizeof(host) ) < 0 ) {
        perror("Receive bind 2\n");
        exit(1);
    }
    mreq.imr_multiaddr.s_addr = htonl(Group_Address);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    group_addr.sin_addr.s_addr = htonl(Group_Address);
            
    if(spines_setsockopt(sr, IPPROTO_IP, SPINES_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq)) < 0) {
        printf("Mcast: problem in setsockopt to join multicast address");
        exit(0);
    }
    if(Loopback == 0) {
        if(spines_setsockopt(sr, IPPROTO_IP, SPINES_MULTICAST_LOOP, (void *)&Loopback, sizeof(char)) < 0) {
            printf("Mcast: problem in setsockopt to join multicast address");
            exit(0);
        }
    }


    /*************************************************************/
    /* SEND SOCKET                                               */
    /*************************************************************/
    ss = spines_socket(PF_SPINES, SOCK_DGRAM, Protocol, daemon_ptr);
    if (ss<0) {
        perror("Send socket");
        exit(1);
    }

    host.sin_family = AF_INET;
    host.sin_addr.s_addr = htonl(Dest_Address);
    host.sin_port   = htons(sendPort);

    /*************************************************************/
    /* MAIN PROGRAM                                              */
    /*************************************************************/
    ret = 1;
    FD_ZERO( &mask );
    //FD_ZERO( &dummy_mask );
    FD_SET( sr, &mask );
    if (Sender == 1) {
        FD_SET( (long)0, &mask );   /* stdin */
    }
    for(;;)
    {
        temp_mask = mask;
        bytes = 0;
        num = select( FD_SETSIZE, &temp_mask, NULL, NULL, NULL);
        if (num > 0) {
            if ( FD_ISSET( sr, &temp_mask) ) {
                bytes = spines_recvfrom(sr, mess_buf, sizeof(mess_buf), 0, NULL, 0);
                mess_buf[bytes] = 0;
                printf( "Received: %s\n", mess_buf );
            } else if( FD_ISSET(0, &temp_mask) ) {
                bytes = read( 0, input_buf, sizeof(input_buf) );
                input_buf[bytes] = 0;
                if (!strncmp(input_buf, "1", 1) || !strncmp(input_buf, "2", 1)) {
                    /* spt sends and receives a value */
                    memset((void*)&spt, '\0', sizeof(spt));
                    ((struct sockaddr_in *)(&spt))->sin_addr.s_addr = htonl(Group_Address);
                    if (!strncmp(input_buf, "1", 1)) {
                        ret = spines_ioctl(sr, 0, SPINES_MEMBERSHIP, (void *)&spt, sizeof(spt));
                    } else if (!strncmp(input_buf, "2", 1)) {
                        ret = spines_ioctl(sr, 0, SPINES_EDISTANCE, (void *)&spt, sizeof(spt));
                    }
                    ret = ret + 1;
                    printf("\n\nTOTAL: %d\n", spt.count);
                    for (i=0; i<spt.count; i++) {
                        printf("   ---"IPF" :%d :%d\n", IP(spt.address[i]), spt.distance[i], spt.cost[i]);
                    }
                } else {
                    printf( "Sending: %s\n", input_buf );
                    ret = spines_sendto(ss, input_buf, strlen(input_buf), 0, (struct sockaddr *)&host, sizeof(struct sockaddr));
                }
            }
            if(ret <= 0 || bytes <=0) {
                printf("Disconnected by spines...\n");
                exit(0);
            }
        }
    }
    return 1;
}


static void Usage(int argc, char *argv[])
{
    int i1, i2, i3, i4;

    /* Setting defaults */
    spinesPort = 8100;
    sendPort = 8400;
    recvPort = 8400;
    Protocol = 0;
    Loopback = 1;
    Sender = 0;
    strcpy(DEST_IP, "");
    strcpy(SP_IP, "");
    strcpy(MCAST_IP, "");
    strcpy(Unix_domain_path, "");
    Group_Address = (240 << 24) + 1; /* 240.0.0.1 */
    Dest_Address = (240 << 24) + 1; /* 240.0.0.1 */

    while( --argc > 0 ) {
        argv++;
        if( !strncmp( *argv, "-p", 2 ) ){
            sscanf(argv[1], "%d", (int*)&spinesPort );
            argc--; argv++;
        } else if( !strncmp( *argv, "-ud", 4 ) ){
            sscanf(argv[1], "%s", Unix_domain_path);
            argc--; argv++;
        }else if( !strncmp( *argv, "-d", 2 ) ){
            sscanf(argv[1], "%d", (int*)&sendPort );
            argc--; argv++;
        }else if( !strncmp( *argv, "-r", 2 ) ){
            sscanf(argv[1], "%d", (int*)&recvPort );
            argc--; argv++;
        }else if( !strncmp( *argv, "-a", 2 ) ){
            sscanf(argv[1], "%s", DEST_IP );
            sscanf(DEST_IP ,"%d.%d.%d.%d",&i1, &i2, &i3, &i4);
            Dest_Address = ( (i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4 ); 
            Sender = 1;
            argc--; argv++;
        }else if( !strncmp( *argv, "-j", 2 ) ){
            sscanf(argv[1], "%s", MCAST_IP );
            sscanf(MCAST_IP ,"%d.%d.%d.%d",&i1, &i2, &i3, &i4);
            Group_Address = ( (i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4 ); 
            argc--; argv++;
        }else if( !strncmp( *argv, "-o", 2 ) ){
            sscanf(argv[1], "%s", SP_IP );
            argc--; argv++;
        }else if( !strncmp( *argv, "-l", 2 ) ){
            sscanf(argv[1], "%d", (int*)&i1 );
            Loopback = i1;
            argc--; argv++;
        }else if( !strncmp( *argv, "-P", 2 ) ){
            sscanf(argv[1], "%d", (int*)&Protocol );
            argc--; argv++;
        }else{
            printf( "Usage: sp_xcast\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
                    "\t[-o <address>    ] : address where spines runs, default localhost",
                    "\t[-p <port number>] : port where spines runs, default is 8100",
                    "\t[-ud <path>      ] : unix domain socket path to connect to, default is /tmp/spines<port>",
                    "\t[-d <port number>] : to send packets on, default is 8400",
                    "\t[-r <port number>] : to receive packets on, default is 8400",
                    "\t[-a <address>    ] : address to send text messages to, from stdin",
                    "\t[-j <xcast addr> ] : multicast or anycast address to join",
                    "\t[-l <0, 1>       ] : turn on or off loopback for this router",
                    "\t[-P <0, 1 or 2>  ] : overlay links (0 : UDP; 1; Reliable; 2: Realtime)");
            exit( 0 );
        }
    }
}
