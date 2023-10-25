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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h> 
#include <netdb.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <errno.h>
#include "../spines_lib.h"
#include "../util/sp_events.h"
#include "../util/arch.h"

#define RECV_PORT  8500
#define	MAX_BYTES  100000

void print_usage(void);

#define IP1( address )  ( ( 0xFF000000 & (address) ) >> 24 )
#define IP2( address )  ( ( 0x00FF0000 & (address) ) >> 16 )
#define IP3( address )  ( ( 0x0000FF00 & (address) ) >> 8 )
#define IP4( address )  ( ( 0x000000FF & (address) ) )
#define IP( address ) IP1(address),IP2(address),IP3(address),IP4(address)
#define IPF "%d.%d.%d.%d"

#define TYPE_A 1
#define TYPE_B 2
#define TYPE_G 3 

int main(int argc, char *argv[])
{
    int ip1, ip2, ip3, ip4;
    int server_address, mcast_address, sender_address, port, recvPort,
          sk, ret, num_to_join;
    int address_a, address_b, address_g;
    int i, j, k;
    char host_name[80];
    struct hostent *h_tmp;
    struct hostent h_ent;
    char mess[1400];
    struct sockaddr_in mcast_addr, serv_addr, name;
    struct hostent  *host_ptr;
    char   machine_name[256] = "localhost";
    char   message[100];
    int type;    
    char *arg;
    sp_time start, finish, diff;
    char buf[MAX_PACKET_SIZE];
    char out_file_name[1000];
    FILE *out_file;
    int message_num;
    int receiver, sender;
    
    port = 8014;
   
    mcast_address = 0xef000000;

    server_address = (128 << 24) + (220 << 16) + (221 << 8) + 101;

    if(argc > 1) {
        /*printf("%s\n",argv[1]);*/
	sscanf(argv[1],"%d.%d.%d.%d",&ip1,&ip2,&ip3,&ip4);
        /*printf("%d %d %d %d\n",ip1,ip2,ip3,ip4);*/
        server_address = (ip1 << 24) + (ip2 << 16) + (ip3 << 8) + ip4;
    }

    if(argc > 2) {
	sscanf(argv[2],"%d",&num_to_join);
        printf("number to join: %d\n");
    }

    if (argc > 3) {
	if (argv[3][0] == 's') {
	    sender = 1;
	    receiver = 0;
	} else if (argv[3][0] == 'r') {
	    sender = 0;
	    receiver = 1;
	}
    }

    if (num_to_join > 0) {
    	recvPort = 8400;
    } else {
	recvPort = 8500;
    }
 
    /*memcpy(&serv_addr.sin_addr, &server_address, sizeof(struct in_addr));*/
    
    serv_addr.sin_addr.s_addr = htonl(server_address);
    serv_addr.sin_port = htons(port);

    /*
    printf("serv_addr = "IPF" serv_port = %d\n", IP(serv_addr.sin_addr.s_addr),
	serv_addr.sin_port );
    */

    if(spines_init((struct sockaddr*)(&serv_addr)) < 0) {
	printf("sp_rmcast: cannot initialize connection to spines.\n");
	exit(1);
    }

    sk = spines_socket(PF_SPINES, SOCK_DGRAM, 0, NULL);

    if (sk < 0) {
	printf("socket error\n");
	exit(1);
    }

    name.sin_family = AF_INET;
    name.sin_addr.s_addr = INADDR_ANY;
    name.sin_port = htons(recvPort);	
	
    if(spines_bind(sk, (struct sockaddr *)&name, sizeof(name) ) < 0) {
        perror("err: bind");
	exit(1);
    }
    
    start = E_get_time();

    printf("mcast_addr = "IPF" \n", IP(mcast_address) );

/*

   DON'T JOIN ANY GROUPS
   for ( i = 1; i < num_to_join; i++ ) {
	mcast_address++;
    	ret = spines_reliable_join(sk, mcast_address, SENDRECV_GROUP);
    	if( ret < 0 ) {
		printf("join error\n");
		exit(1);
    	}
        if ( i % 1000 == 0 ) {
	    printf("%d\n",i);
	    fflush(NULL);	    
    	}
    }

*/
    
    mcast_address = 0xef000000;
    /* join the last group */
    if ( sender ) {
	sleep(5);
	ret = spines_reliable_join(sk, mcast_address, SEND_GROUP);
    } else {
	ret = spines_reliable_join(sk, mcast_address, SENDRECV_GROUP);
    }
    if( ret < 0 ) {
	printf("join error\n");
	exit(1);
    }
    printf("%d\n",i);
 
    mcast_addr.sin_addr.s_addr = htonl(mcast_address);
    mcast_addr.sin_port = htons(1);

    /*
    sender_address = 
       (128 << 24) + (220 << 16) + (221 << 8) + 118;
    */
    
    start.sec = 0;
    start.usec = 0;  

    message_num = 0;
    if ( sender ) {
       /* Send messages to the group */
       sleep(10);
       while (1) {
	   message_num++;
	   sprintf(message,"%d",message_num);
	   spines_sendto(sk, message, 30, 0, (struct sockaddr *) &mcast_addr,
              sizeof (struct sockaddr) );
           usleep( 10000 );
	    //sleep(1);
       }
    } else {
	sprintf(out_file_name,"rmcast_tree_change."IPF".rmdat",IP(server_address));
        out_file = fopen(out_file_name,"w");
        //fclose(out_file);
	while (1) {
	    ret = spines_recvfrom(sk, buf, sizeof(buf), 0, NULL, 0);
	    finish = E_get_time();
	    if ( start.usec == 0 && start.sec == 0 ) {
		start = finish;
	    }
	    diff = E_sub_time( finish, start );
	    fprintf(out_file,"%s %d.%06d\n",buf,diff.sec,diff.usec);
	    fflush(NULL);
	}
    }

}


