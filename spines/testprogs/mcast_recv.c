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

/*
 * mcast_recv:
 *
 * This program receives from num_groups consecutive IP multicast groups, 
 * Each of the groups is received on a different socket, bound to a different
 * port, starting from the base port.
 *
 * The program exits when it receives a packet with sequence -1 on any of the
 * sockets / groups/ ports. When calculating rate, the program assumes
 * that the sender program will wait SLEEP_TIME seconds after completing
 * sending the real messages and before sending the -1 sequesnce messages.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h> 
#include <netinet/tcp.h>
#include <netdb.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <errno.h>

#include "spu_events.h"

#define MAX_GROUPS	1000
#define MAX_PKT_SIZE	1536
#define SLEEP_TIME	3

static	int		Recv_sock[MAX_GROUPS];
static	int		Num_groups = 1;
static  char		MCAST_IP[80];
static	int		Group_address;
static	int		Base_port;
static	int		Recv_count;
static	int		First_pkt_flag;
static	int		Num_bytes;
static	int		Num_pkts;

static  struct timeval 	Start_time, End_time;
static  struct timezone tz;

void Usage(int argc, char *argv[]);
void Handle_message( int sock, int index, void *dmy);

int main( int argc, char *argv[] )
{
  	struct ip_mreq 		mreq;
	int			i, j, ret;
	int 			reuse=1;
	char 			results_str[1024];
	long long int 		duration;
  	double 			rate;
	struct sockaddr_in	name;

	Usage(argc, argv);
  
	E_init();

	for( i=0; i <  Num_groups; i++ )
	{
		/* Opening a socket for group[i] */
    		Recv_sock[i] = socket(AF_INET, SOCK_DGRAM, 0);
    		if( Recv_sock[i] < 0 ) 
		{
      			perror("error calling socket...\n");
      			exit(1);
		}

		/* 
                 * Allowing multiple receiving programs to receive on the same port (Linux) 
		 * For MacOS SO_REUSEADDR should be replaced by SO_REUSEPORT.
		 */
		if ( setsockopt( Recv_sock[i], SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0) 
		{
			perror("setting SO_REUSEADDR");
			exit(1);
		}

		/* Increasing the socket buffer */
    		for( j=10; j <= 1000; j+=10 )
    		{
            		int on;
            		socklen_t onlen;

			on = 1024*j;
            		onlen = sizeof(on);

            		ret = setsockopt( Recv_sock[i], SOL_SOCKET, SO_SNDBUF, (void *)&on, onlen);
            		if (ret < 0 ) break;

            		ret = setsockopt( Recv_sock[i], SOL_SOCKET, SO_RCVBUF, (void *)&on, onlen);
            		if (ret < 0 ) break;

            		ret= getsockopt( Recv_sock[i], SOL_SOCKET, SO_SNDBUF, (void *)&on, &onlen );
            		if( on < j*1024 ) break;

            		onlen = sizeof(on);
            		ret= getsockopt( Recv_sock[i], SOL_SOCKET, SO_RCVBUF, (void *)&on, &onlen );
            		if( on < j*1024 ) break;
   		 }

		name.sin_family 	= AF_INET;
		name.sin_addr.s_addr 	= INADDR_ANY;
		name.sin_port 		= htons(Base_port+i);
	  
		/* Binding to the relevant port */
		if( bind( Recv_sock[i], (struct sockaddr *)&name, sizeof(name) ) < 0 ) 
		{
			printf("error binding socket[%d] \n", i);
			exit(1);
    		}

      		mreq.imr_multiaddr.s_addr = htonl(Group_address+i);
      		mreq.imr_interface.s_addr = htonl(INADDR_ANY);
      
		/* Joining the relevant multicast group */
      		if(setsockopt( Recv_sock[i], IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq)) < 0) 
		{
			printf("Mcast: problem in setsockopt to join the %d multicast address \n", i+1);
			exit(1);
      		}	    

		E_attach_fd( Recv_sock[i], READ_FD, Handle_message, i, NULL, HIGH_PRIORITY );
	}
       
	Recv_count     = 0;
	First_pkt_flag = 1;

printf(" Before handle events \n");
	E_handle_events();
printf(" After handle events \n");

	/* if no packet received, report as such */
	if( Recv_count == 0) 
	{
		printf("mcast_recv: No Data Packets Received\n");
		exit(1);
      	} 
    
    	gettimeofday(&End_time, &tz);
    	duration  = End_time.tv_sec - Start_time.tv_sec - SLEEP_TIME;
    	duration *= 1000000; 
    	duration += End_time.tv_usec - Start_time.tv_usec;
    
    	rate = (double)Num_bytes * Recv_count * 8 * 1000;
    	rate = rate/duration;
    
	sprintf(	results_str, 
	      		"mcast_recv:\r\n"
	      		"- Num Pkts Received:\t%d out of %d\r\n"
	      		"- Pkt Size:\t%d\r\n"
	      		"- Throughput:\t%f kbs\r\n\r\n",
	      		Recv_count, Num_pkts, Num_bytes, rate);
    	printf("%s", results_str);

	return 0;
}

void Handle_message( int sock, int index, void *dmy)
{

static	char	buf[MAX_PKT_SIZE];

	int	*pkt_size, *pkts_sending, *pkt_no, *pkt_ts_s, *pkt_ts_us;
	int	ret;


	pkt_size     = (int*)buf;
	pkts_sending = (int*)(buf + sizeof(int));
	pkt_no       = (int*)(buf + 2*sizeof(int));
	pkt_ts_s     = (int*)(buf + 3*sizeof(int));
	pkt_ts_us    = (int*)(buf + 4*sizeof(int));
  
	ret = recv( Recv_sock[index], buf, sizeof(buf), 0);

	if( ret != ntohl(*pkt_size) ) 
	{
		printf("corrupted packet... ret: %d; msg_size: %d\n", ret, ntohl(*pkt_size));
		exit(1);
      	}

	/* starting the timer if first packet */
	if( First_pkt_flag ) 
	{
		gettimeofday(&Start_time, &tz);  /* we calc start time as local clock when first packet arrives */
		Num_bytes = ret;
		First_pkt_flag = 0;
		Num_pkts = ntohl(*pkts_sending); 
		if( Num_pkts <= 0 ) 
		{
			printf("Num packets is not positive %d\n", Num_pkts );
			exit( 1 );
		}
      	}     

      	if(ntohl(*pkt_no) == -1) {
		E_exit_events();
		return;
      	}

	if( ret != ntohl(*pkt_size) ) 
	{
		printf("corrupted packet...%d:%d\n", ret, ntohl(*pkt_size));
		exit(1);
	}

	Recv_count++;
}
    

void    Usage(int argc, char *argv[])
{
	int i1, i2, i3, i4;
  
  	/* Setting defaults */
  	Num_groups	= 1;
	Base_port	= 4444;

      	sscanf("225.1.1.1" ,"%d.%d.%d.%d",&i1, &i2, &i3, &i4);
      	Group_address = ((i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4);
  
	while( --argc > 0 ) 
	{
		argv++;
    
    		if( !strncmp( *argv, "-p", 2 ) ) {
      			sscanf(argv[1], "%d", &Base_port );
      			argc--; argv++;
    		} else if( !strncmp( *argv, "-j", 2 ) ){
      			sscanf(argv[1], "%s", MCAST_IP );
      			sscanf(MCAST_IP ,"%d.%d.%d.%d",&i1, &i2, &i3, &i4);
      			Group_address = ((i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4);
      			argc--; argv++;
    		} else if( !strncmp( *argv, "-g", 2 ) ){
      			sscanf(argv[1], "%d", (int*)&Num_groups );
      			argc--; argv++;
    		} else{
      			printf( "Usage: mcast_recv\n"
	      			"\t[-p <port number>] : base port to recv packets on, default is 4444\n"
	      			"\t[-j <mcast addr> ] : base multicast address to join\n"
	      			"\t[-g <num_groups> ] : number of consecutive groups to join\n");
      			exit( 1 );
    		}	
	}

}
