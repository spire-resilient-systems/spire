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
#include "spines_lib.h"

void print_usage(void);

int main(int argc, char *argv[])
{
    int port, sk, ret;
    float loss_rate, burst_rate;
    int bandwidth, latency;
    int i1, i2, i3, i4;
    struct sockaddr_in daemon, *daemon_ptr = NULL;
    int local_interf_id, remote_interf_id;

    port = DEFAULT_SPINES_PORT;   /* 8100 */
   
    if (argc < 7 || argc > 9) {
	print_usage();
	return(1);    
    }
    
    sscanf(argv[1], "%d", &bandwidth);
    sscanf(argv[2], "%d", &latency);
    sscanf(argv[3], "%f", &loss_rate);
    sscanf(argv[4], "%f", &burst_rate);

    sscanf(argv[5], "%d.%d.%d.%d", &i1, &i2, &i3, &i4);
    remote_interf_id = ((i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4);

    sscanf(argv[6], "%d.%d.%d.%d", &i1, &i2, &i3, &i4);
    local_interf_id = ((i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4);

    if (argc > 7) {
      memset(&daemon, 0, sizeof(daemon));
      daemon_ptr = &daemon;

      sscanf(argv[7], "%d.%d.%d.%d", &i1, &i2, &i3, &i4);
      daemon.sin_family = AF_INET;
      daemon.sin_addr.s_addr = ((i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4);
      daemon.sin_addr.s_addr = htonl(daemon.sin_addr.s_addr);
      daemon.sin_port = htons(DEFAULT_SPINES_PORT);
    }

    if (argc > 8) {
      sscanf(argv[8], "%d", &port);
      daemon.sin_port = htons(port);
    }

    spines_init((struct sockaddr*) daemon_ptr);

    sk = spines_socket(PF_SPINES, SOCK_STREAM, 0, NULL);
    if (sk < 0) {
	printf("socket error\n");
	exit(1);
    }

    ret = spines_setlink(sk, remote_interf_id, local_interf_id, bandwidth*1000, latency, loss_rate, burst_rate);
    if( ret < 0 ) {
	printf("setlink error\n");
	exit(1);
    }
    
    spines_close(sk);
    
    return(1);
}

void print_usage(void) {
  printf("Usage:\tsetlink bandwidth (kbps) latency (ms) loss_rate (%%) burst_rate (%%) remote_interf_id (src) local_interf_id (dst) [daemon_ip [daemon_port]]\n\n");
}

