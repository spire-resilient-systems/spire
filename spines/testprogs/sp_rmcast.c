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

#define RECV_PORT  8500
#define	MAX_BYTES  100000

void print_usage(void);

#define IP1( address )  ( ( 0xFF000000 & (address) ) >> 24 )
#define IP2( address )  ( ( 0x00FF0000 & (address) ) >> 16 )
#define IP3( address )  ( ( 0x0000FF00 & (address) ) >> 8 )
#define IP4( address )  ( ( 0x000000FF & (address) ) )
#define IP( address ) IP4(address),IP3(address),IP2(address),IP1(address)
#define IPF "%d.%d.%d.%d"

#define TYPE_A 1
#define TYPE_B 2
#define TYPE_G 3 

int main(int argc, char *argv[])
{
    int server_address, mcast_address, port, sk, ret;
    int address_a, address_b, address_g;
    int i, j, k;
    char host_name[80];
    struct hostent *h_tmp;
    struct hostent h_ent;
    char mess[1400];
    struct sockaddr_in mcast_addr, serv_addr;
    struct hostent  *host_ptr;
    char   machine_name[256] = "localhost";
    char   message[100];
    int type;    
    char *arg;
 
    port = 8014;

    address_a = 0xeffffff1;
    address_b = 0xeffffff2;
    address_g = 0xefffffff;

    /* Default functionality. */	
    server_address = (128 << 24) + (220 << 16) + (221 << 8) + 12;
    type = TYPE_G;

    if(argc > 1) {
	arg = argv[1];
        if ( 'a' == arg[0] ) {
	    printf("****A\n");
    	    server_address = (128 << 24) + (220 << 16) + (221 << 8) + 15;
	    type = TYPE_A;
	} else if ( arg[0] == 'b' ) {
	    printf("****B\n");
            server_address = (128 << 24) + (220 << 16) + (221 << 8) + 16;
            type = TYPE_B;
	} else {
    	    printf("****G\n");
	}
    }

    /*memcpy(&serv_addr.sin_addr, &server_address, sizeof(struct in_addr));*/
    
    serv_addr.sin_addr.s_addr = htonl(server_address);
    serv_addr.sin_port = htons(port);

    printf("serv_addr = "IPF" serv_port = %d\n", IP(serv_addr.sin_addr.s_addr),
	serv_addr.sin_port );
 
    if(spines_init((struct sockaddr*)(&serv_addr)) < 0) {
	printf("sp_rmcast: cannot initialize connection to spines.\n");
	exit(1);
    }

    printf("spines_socket\n");

    sk = spines_socket(PF_SPINES, SOCK_DGRAM, 0, NULL);
               /* (struct sockaddr*)(&serv_addr)); */

    if (sk < 0) {
	printf("socket error\n");
	exit(1);
    }

    printf("spines_reliable_join\n");
 
    if ( type == TYPE_A ) {
    	mcast_address = address_a;
    } else if ( type == TYPE_B ) {
    	mcast_address = address_b;
    } else if ( type == TYPE_G ) {
    	mcast_address = address_g;
        /* Join on a and b */
	ret = spines_reliable_join(sk, address_a, SENDRECV_GROUP);
    	if( ret < 0 ) {
	    printf("join error a\n");
	    exit(1);
    	}
	ret = spines_reliable_join(sk, address_b, SENDRECV_GROUP);
    	if( ret < 0 ) {
	    printf("join error b\n");
	    exit(1);
    	}
    }

    printf("mcast_addr = "IPF" \n", IP(mcast_address) );

    if ( mcast_address != address_g ) {
    	ret = spines_reliable_join(sk, mcast_address, RECV_GROUP);
    	if( ret < 0 ) {
		printf("join error\n");
		exit(1);
    	}
    }

    mcast_addr.sin_addr.s_addr = htonl(mcast_address);
    mcast_addr.sin_port = htons(1);

    printf("mcast_addr = "IPF"\n", IP(mcast_addr.sin_addr.s_addr) );

    sleep(3);

    if ( type == TYPE_G ) {
        for ( i = 1; i <= 200; i++ ) {
       	    sprintf(message,"[body; my seq = %10d]",i);
	    printf("--> SEND %d %s\n",i,message);
	    /* Decide to which group the message should be sent */
            if ( 0 ) { /*i % 20 == 0 ) {*/
    	         mcast_addr.sin_addr.s_addr = htonl(address_g); /* to all */
            } else if ( i % 20 <= 10 ) {
    	         mcast_addr.sin_addr.s_addr = htonl(address_a); /* to a */
            } else {
    	         mcast_addr.sin_addr.s_addr = htonl(address_b); /* to b */
            }
	    spines_sendto(sk, message, 30, 0, (struct sockaddr *) &mcast_addr,
               sizeof (struct sockaddr) );
	    usleep( 1000 * 300 );
    	}
    }
    sleep(100);

}


/*	sscanf(argv[1], "%s", host_name);
	h_tmp = gethostbyname(host_name);
	if(h_tmp == NULL) {
	    print_usage();
	    return(1);	    
	}
	memcpy(&h_ent, h_tmp, sizeof(h_ent));
	memcpy(&server_address, h_ent.h_addr, sizeof(server_address) );
	server_address = ntohl(server_address);	
	if(argc == 3) {
	    sscanf(argv[2], "%d", (int*)&port);
	}	
    }
*/

/*
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
*/

    /*sk = spines_socket(port, address, NULL);*/
    /*sk = spines_socket(PF_SPINES, SOCK_STREAM, 0, NULL);*/
    /*memcpy( (void*) &mcast_addr.sin_addr, (void*) &mcast_address, sizeof(mcast_address) );*/



/*
void print_usage(void) {
    printf("Usage:\t%s\n\t%s\n\t%s\n",
	   "sp_rmcast [host_address [port]]",
	   "host_address: address of the Spines daemon [default localhost]",
	   "port        : Spines port [default 8100]"); 
}
*/


/*
    memcpy((void*)&serv_addr.sin_addr, (void*)&server_address, sizeof(struct in_addr));
    serv_addr.sin_port = htons(port);
 
    if(spines_init((struct sockaddr*)(&serv_addr)) < 0) {
	exit(1);
    }
*/ 
 
