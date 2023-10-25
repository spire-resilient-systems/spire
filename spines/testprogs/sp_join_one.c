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


#define RECV_PORT  8600
#define	MAX_BYTES  100000

void print_usage(void);

int main(int argc, char *argv[])
{
    int address, mcast_address, port, addr, send_port, sk, ret;
    int i, j, k, idx1, idx2, tmp;
    char host_name[80];
    struct hostent *h_tmp;
    struct hostent h_ent;
    struct timeval start, stop;
    struct timezone tz;
    int sec, usec;
    char buf[1400];
    int num_wait;
    int msgs[500];
    int num_msgs;
    int sender_addr;

	
    address = (127 << 24) + 1; /* 127.0.0.1 */
    port = 8100;

    if(argc < 2) {
	print_usage();
	return(1);    
    }
    
    sscanf(argv[1], "%d", &num_wait);
    
    if(argc > 2) {
	if(argc > 4) {
	    print_usage();
	    return(1);
	}
	sscanf(argv[2], "%s", host_name);
	h_tmp = gethostbyname(host_name);
	if(h_tmp == NULL) {
	    print_usage();
	    return(1);	    
	}
	mempy(&h_ent, h_tmp, sizeof(h_ent));
	mempy(&address, h_ent.h_addr, sizeof(address) );
	address = ntohl(address);	
	if(argc == 4) {
	    sscanf(argv[3], "%d", (int*)&port);
	}	
    }


    for(i=0; i<500; i++) {
	msgs[i] = 0;
    }
    num_msgs = 0;

    sk = spines_socket(port, address, NULL);
    ret = spines_bind(sk, RECV_PORT);
    if (ret < 0) {
     	printf("sp_groups: bind error\n");
     	exit(1);
    }
     
    mcast_address = (225 << 24) + 1; 

    gettimeofday(&start, &tz);

    ret = spines_join(sk, mcast_address);
    if (ret < 0) {
	printf("sp_groups: join error\n");
	exit(1);
    }
    
    while(num_msgs < num_wait) {
	ret = spines_recvfrom(sk, &addr, &send_port, buf, sizeof(buf));
	if (ret < 0) {
	    printf("sp_groups: receive error\n");
	    exit(1);
	}
	sscanf(buf, "%d", &sender_addr);

	i = 0;
	while(i < 500) {
	    if(sender_addr == msgs[i] ) {
		break;
	    }
	    if(msgs[i] == 0) {
		msgs[i] = sender_addr;
		num_msgs++;
		break;
	    }
	    i++;
	}
	if(i == 500) {
	    printf("too many messages\n");
	    return(1);
	}
    }

    gettimeofday(&stop, &tz);

    sec = stop.tv_sec - start.tv_sec;
    usec = stop.tv_usec - start.tv_usec;
    if(usec < 0) {
	sec--;
	usec += 1000000;
    }

    printf("total: %d.%06d\n", sec, usec);


    ret = spines_leave(sk, mcast_address);
    if (ret < 0) {
	printf("sp_groups: leave error\n");
	exit(1);
    }

}

void print_usage(void) {
    printf("Usage:\t%s\n\t%s\n\t%s\n\t%s\n",
	   "sp_groups num_wait [host_address [port]]",
	   "num_wait    : number of nodes to wait for", 
	   "host_address: address of the Spines daemon [default localhost]",
	   "port        : Spines port [default 8100]");    
}
















