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
#include <stdlib.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/select.h>
#include "../spines_lib.h"

extern int h_errno;


typedef struct Cell_d {
    int sk;                /* socket */
    struct Cell_d *prev;   /* pointer to the previous element in the list */
    struct Cell_d *next;   /* pointer to the next element in the list */
} Cell;


int main( int argc, char *argv[] )
{
    Cell *head, *p, *tmp;
    int sk_listen;
    int spinesPort = 9100;
    int localhost_ip = (127 << 24) + 1; /* 127.0.0.1 */
    int Address = (127 << 24) + 1; /* 127.0.0.1 */
    int Protocol = 0;
    int recvPort = 8400;
    char IP[20];
    char buf[1472];
    int ret, i, cnt, num;
    int num_connections = 0;
    int connect_flag = 0;
    int chance, rnd_connection;
    struct timeval tv, timeout;
    struct timezone tz;
    struct sockaddr_in host;
    struct hostent     h_ent;
    fd_set mask, dummy_mask,temp_mask;


    sscanf(argv[1], "%s", IP );
    memcpy(&h_ent, gethostbyname(IP), sizeof(h_ent));
    memcpy( &Address, h_ent.h_addr, sizeof(Address) );
    Address = ntohl(Address);

    if(argc > 2) {
	if(strcmp(argv[2], "-c") == 0) {
	    connect_flag = 1;
	}
    }

    gettimeofday(&tv, &tz);
    srand(tv.tv_usec);
    head = NULL;

    sk_listen = spines_socket(spinesPort, localhost_ip, &Protocol);
    if (sk_listen < 0) {
	printf("socket error\n");
	exit(1);
    }
    ret = spines_bind(sk_listen, recvPort);
    if (ret < 0) {
	printf("bind error\n");
	exit(1);
    }
    ret = spines_listen(sk_listen);
    if (ret < 0) {
	printf("bind error\n");
	exit(1);
    }

    FD_ZERO(&mask);
    FD_ZERO(&dummy_mask);
    FD_SET(sk_listen, &mask);
    for(;;) {	
	temp_mask = mask;
	timeout.tv_sec = 0;
	timeout.tv_usec = 50000;
	
	num = select(FD_SETSIZE, &temp_mask, &dummy_mask, &dummy_mask, &timeout);

	if(num > 0) {
	    if (FD_ISSET(sk_listen, &temp_mask)) {
		/* Somebody calls connect... */
		
		/* Create a new cell for the connection */
		tmp = (Cell*)malloc(sizeof(Cell));
		if(tmp == NULL) {
		    printf("malloc error\n");
		    exit(1);
		}

		/* Append tmp to the linked list */
		if(head == NULL) {
		    head = tmp;
		    head->prev = NULL;
		    head->next = NULL;
		}
		else {
		    p = head;
		    while(p->next != NULL) {
			p = p->next;
		    }
		    p->next = tmp;
		    tmp->prev = p;
		    tmp->next = NULL;
		}

		/* Accept the conenction */
		tmp->sk = spines_accept(sk_listen, spinesPort, localhost_ip, &Protocol);
		if(tmp->sk < 0) {
		    printf("accept error\n");
		    exit(1);
		}
		   
		if(tmp->sk == sk_listen) {
		    printf("\n\nnew socket == sk_listen\n");
		    exit(1);
		}

		FD_SET(tmp->sk, &mask);
		num_connections++;
		printf("accepted a connection, now: %d\n", num_connections);
	    }
	    
	    /* Check the sockets for reading */
	    p=head; 
	    while(p != NULL) {
		if (FD_ISSET(p->sk, &temp_mask)) {
		    ret = spines_recv(p->sk, buf, sizeof(buf));
		    if(ret < 0) {
			/* connection closed; remove socket from the list */
			printf("closing a socket...\n");
			FD_CLR(p->sk, &mask);
			spines_close(p->sk);
			tmp = p;
			if(head == p) {
			    head = p->next;
			    p = head;
			}
			else {
			    p->prev->next = p->next;
			    if(p->next != NULL) {
				p->next->prev = p->prev;
			    }
			    p = p->next;
			}
			free(tmp);
			num_connections--;
		    }
		    else {
			/* Connection still alive. Read done. Advance pointer*/
			/*printf("receiving... %d\n", ret);*/
			p = p->next;
		    }
		}
		else {
		    p = p->next;
		}
	    }
	}
	else if(num == 0) {
	    /* Timeout */

	    /* Send something on a random connection */
	    if(head != NULL) {
		rnd_connection=(int)(((float)num_connections)*rand()/(RAND_MAX+1.0));
		printf("sending on connection: %d out of: %d\n", rnd_connection, num_connections);
	    
		p = head;
		for(i=0; i<rnd_connection; i++) {
		    p = p->next;
		    if(p == NULL) {
			printf("Error: num_connections computation error\n");
			exit(1);
		    }
		}		
		ret =  spines_send(p->sk, buf, 1024);
		if(ret < 1024) {
		    /* Error in writing. Close the connection */
		    /* connection closed; remove socket from the list */
		    printf("error sending, closing the socket...\n");
		    FD_CLR(p->sk, &mask);
		    spines_close(p->sk);
		    tmp = p;
		    if(head == p) {
			head = p->next;
			p = head;
		    }
		    else {
			p->prev->next = p->next;
			if(p->next != NULL) {
			    p->next->prev = p->prev;
			}
			p = p->next;
		    }
		    free(tmp);
		    num_connections--;			
		}
	    }


	    /* With independent probability 1/4 close a connection */
	    if(num_connections > 900) {
	        chance = 1+(int)(100.0*rand()/(RAND_MAX+1.0));
	    }
	    else {
	        chance = 100;
	    }
	    if(chance <= 25) {
		if(head != NULL) {
		    rnd_connection=(int)(((float)num_connections)*rand()/(RAND_MAX+1.0));	    
		    printf("closing connection: %d out of: %d\n", rnd_connection, num_connections);
		
		    p = head;
		    for(i=0; i<rnd_connection; i++) {
			p = p->next;
			if(p == NULL) {
			    printf("Error: num_connections computation error\n");
			    exit(1);
			}			
		    }
		    spines_close(p->sk);
		    FD_CLR(p->sk, &mask);
		    tmp = p;
		    if(head == p) {
			head = p->next;
			p = head;
		    }
		    else {
			p->prev->next = p->next;
			if(p->next != NULL) {
			    p->next->prev = p->prev;
			}
			p = p->next;
		    }
		    free(tmp);
		    num_connections--;		    
		}
	    }


	    if(connect_flag == 1) {
		/* With independent probability 1/2 open a new connection */
		if(num_connections < 950) {
		    chance = 1+(int)(100.0*rand()/(RAND_MAX+1.0));
		}
		else {
		    chance = 100;
		}

		if(chance <= 50) {
		    printf("opening a new connection, total now: %d\n", num_connections);
		    
		    /* Create a new cell for the connection */
		    tmp = (Cell*)malloc(sizeof(Cell));
		    if(tmp == NULL) {
			printf("malloc error\n");
			exit(1);
		    }
		    
		    /* Append tmp to the linked list */
		    if(head == NULL) {
			head = tmp;
			head->prev = NULL;
			head->next = NULL;
		    }
		    else {
			p = head;
			while(p->next != NULL) {
			    p = p->next;
			}
			p->next = tmp;
			tmp->prev = p;
			tmp->next = NULL;
		    }
		    
		    /* connect the session */
		    tmp->sk = spines_socket(spinesPort, localhost_ip, &Protocol);
		    if(tmp->sk < 0) {
			printf("socket error\n");
			exit(1);
		    }	
		    
		    if(tmp->sk == sk_listen) {
			printf("\n\nnew socket == sk_listen\n");
			exit(1);
		    }



		    ret = spines_connect(tmp->sk, Address, recvPort);
		    if(ret < 0) {
			printf("connect error\n"); 
			exit(1);
		    }
		    FD_SET(tmp->sk, &mask);
		    num_connections++;
		}	    
	    }
	}
	else {
	    /* Err: num < 0 */
	    printf("select error\n");
	    exit(1);
	}
    }
}


