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

int main(int argc, char *argv[])
{
    int address, mcast_address, port, sk, ret;
    int i, j, k;
    char host_name[80];
    struct hostent *h_tmp;
    struct hostent h_ent;
    char mess[1400];


 
    address = (127 << 24) + 1; /* 127.0.0.1 */
    mcast_address = (224 << 24) + 1; /* 224.0.0.1 */
    port = 8100;
    

    if(argc > 1) {
	if(argc > 3) {
	    print_usage();
	    return(1);
	}
	sscanf(argv[1], "%s", host_name);
	h_tmp = gethostbyname(host_name);
	if(h_tmp == NULL) {
	    print_usage();
	    return(1);	    
	}
	memcpy(h_ent, h_tmp, sizeof(h_ent));
	memcpy(&address, h_ent.h_addr, sizeof(address) );
	address = ntohl(address);	
	if(argc == 3) {
	    sscanf(argv[2], "%d", (int*)&port);
	}	
    }
    sk = spines_socket(port, address, NULL);
    if (ret < 0) {
	printf("socket error\n");
	exit(1);
    }

    ret = spines_bind(sk, RECV_PORT);
    if (ret < 0) {
     	printf("bind error\n");
     	exit(1);
    }
     

    while(1) {
	mcast_address = (225 << 24) + 1; 
	strcpy(mess, "msg: 1");
	ret = spines_sendto(sk, mcast_address, RECV_PORT, mess, strlen(mess) + 1);
	if( ret < 0 ) {
	    printf("send error\n");
	    exit(1);
	}
	
	mcast_address = (225 << 24) + 2; 
	strcpy(mess, "msg: 2");
	ret = spines_sendto(sk, mcast_address, RECV_PORT, mess, strlen(mess) + 1);
	if( ret < 0 ) {
	    printf("send error\n");
	    exit(1);
	}
	


	usleep(100000);
    }
}

void print_usage(void) {
    printf("Usage:\t%s\n\t%s\n\t%s\n",
	   "sp_groups [host_address [port]]",
	   "host_address: address of the Spines daemon [default localhost]",
	   "port        : Spines port [default 8100]");    
}

