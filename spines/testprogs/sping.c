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
#include <sys/ipc.h>
#include <sys/shm.h>
#include <netdb.h>
#include <errno.h>


static int  Num_bytes;
static int  Delay;
static int  Num_rounds;
static char IP[80];
static char My_name[80];
static int  sendPort;
static int  recvPort;
static int  Address;
static int  Send_Flag;
static int  Exit_Timeout;

static void Usage(int argc, char *argv[]);

#define MAX_ROUNDS      10000000
#define MAX_PACKET_SIZE     1400
#define AVG_CNT                3



int main( int argc, char *argv[] )
{
    int  sk;
    long long int clockdiffs[AVG_CNT];
    long long int rtt;
    int  min_diff = 100000000;
    int  max_diff = -100000000;
    char buf[MAX_PACKET_SIZE];
    int  i, j, ret, num_losses, read_flag;
    struct timeval *t1, *t2, *t3, *t4;
    struct timeval timeout, temp_timeout, local_recv_time, start, now, prog_life;
    struct timezone tz;
    int  *round_no, *msg_size;
    long *addr;
    int  *port;
    struct timeval oneway_send, oneway_recv;
    fd_set mask, dummy_mask, temp_mask;


    key_t key;
    int shmid, size, opperm_flags, cmd;
    struct shmid_ds shm_buf; 
    char *mem_addr;
    long long int *avg_clockdiff;
    long long int tmp_diff;
    
    struct sockaddr_in name;
    struct sockaddr_in send_addr;
    long	       host_num, local_addr;
    struct hostent     h_ent;


    Usage(argc, argv);

    timeout.tv_sec = 4;
    timeout.tv_usec = 0;

    num_losses = 0;

    for(i=0; i<AVG_CNT; i++)
	clockdiffs[i] = 0;

    sk = socket(AF_INET, SOCK_DGRAM, 0);
    if(sk <= 0) {
	perror("sping: socket");
	exit(0);
    }

    name.sin_family = AF_INET;
    name.sin_addr.s_addr = INADDR_ANY;
    name.sin_port = recvPort;

    if (bind(sk, (struct sockaddr *)&name, sizeof(name)) < 0 ) {
	perror("sping: bind");
	exit(1);
    }
 
    t1 = (struct timeval*)buf;
    t2 = (struct timeval*)(buf+sizeof(struct timeval));
    t3 = (struct timeval*)(buf+2*sizeof(struct timeval));
    t4 = &local_recv_time;
    round_no = (int*)(buf+3*sizeof(struct timeval));
    msg_size = (int*)(buf+3*sizeof(struct timeval)+sizeof(int));
    port = (int*)(buf+3*sizeof(struct timeval)+2*sizeof(int));
    addr = (long*)(buf+3*sizeof(struct timeval)+3*sizeof(int));


    FD_ZERO(&mask);
    FD_ZERO(&dummy_mask);
    FD_SET(sk,&mask);
    
    if(Send_Flag == 1) {
	printf("Checking %s, %d; %d byte pings, every %d milliseconds: %d rounds\n\n",
	       IP, sendPort, Num_bytes, Delay, Num_rounds);

	/* Shared mem init */

	key = 0x01234567;
	size = sizeof(long long int); 
	opperm_flags = SHM_R | SHM_W;
	/* opperm_flags = 0;*/
	opperm_flags = (opperm_flags | IPC_CREAT);
	
	shmid = shmget (key, size, opperm_flags); 
	if(shmid == -1) {
	    shmid = shmget (key, size, 0);
	    if(shmid == -1) {
		perror("shmget:");
		exit(0);
	    }    	
	    cmd = IPC_RMID;
	    ret = shmctl (shmid, cmd, &shm_buf);
	    if(ret == -1) {
		perror("shmctl:");
		exit(0);
	    }	
	}    

	shmid = shmget (key, size, opperm_flags); 
	if(shmid == -1) {
	    perror("shmget:");
	    exit(0);
	}    
	
	mem_addr = (char*)shmat(shmid, 0, SHM_RND);    
	if(mem_addr == (char*)-1) {
	    perror("shmat:");
	    exit(0);
	}
	
	avg_clockdiff = (long long int*)mem_addr;


        memcpy(&h_ent, gethostbyname(IP), sizeof(h_ent));
        memcpy(&host_num, h_ent.h_addr, sizeof(host_num));

	send_addr.sin_family = AF_INET;
	send_addr.sin_addr.s_addr = host_num; 
	send_addr.sin_port = sendPort;

        if(strlen(My_name) == 0){
	   gethostname(My_name, sizeof(My_name));
	}
	memcpy(&h_ent, gethostbyname(My_name), sizeof(h_ent));
        memcpy(&local_addr, h_ent.h_addr, sizeof(local_addr));
	   
	gettimeofday(&start, &tz);

	for(i=0; i<Num_rounds; i++)
	{
	    *round_no = i;
	    *msg_size = Num_bytes;
	    *addr = local_addr;
	    *port = recvPort;

	    gettimeofday(t1, &tz);

	    sendto(sk, buf, Num_bytes, 0, 
		    (struct sockaddr *)&send_addr, sizeof(send_addr));	    
	    
	    read_flag = 1;
	    while(read_flag == 1) {
		temp_mask = mask;
		temp_timeout = timeout;
		select( FD_SETSIZE, &temp_mask, &dummy_mask, &dummy_mask, &temp_timeout);
		
		if(FD_ISSET(sk, &temp_mask)) {
		    ret = recv(sk, buf, sizeof(buf), 0);  
		    gettimeofday(t4, &tz);

		    if(*round_no != i) {
			printf("err: i: %d; round_no: %d\n", i, *round_no);
			continue;
		    }
		    if(ret != Num_bytes) {
			printf("corrupted packet...\n");
			exit(0);
		    }

		    oneway_send.tv_sec = t2->tv_sec - t1->tv_sec;
		    oneway_send.tv_usec = t2->tv_usec - t1->tv_usec;
		    
		    oneway_recv.tv_sec = t4->tv_sec - t3->tv_sec;
		    oneway_recv.tv_usec = t4->tv_usec - t3->tv_usec;


		    rtt = oneway_send.tv_sec + oneway_recv.tv_sec;
		    rtt *= 1000000;
		    rtt += oneway_send.tv_usec + oneway_recv.tv_usec;

		    clockdiffs[i%AVG_CNT] = oneway_send.tv_sec - oneway_recv.tv_sec;
		    clockdiffs[i%AVG_CNT] *= 1000000;
		    clockdiffs[i%AVG_CNT] += oneway_send.tv_usec - oneway_recv.tv_usec;
		    clockdiffs[i%AVG_CNT] /= 2;

		    tmp_diff = 0;
		    for(j=0; j<AVG_CNT; j++) {
			tmp_diff += clockdiffs[j];
		    }
		    tmp_diff /= AVG_CNT;
		    *avg_clockdiff = tmp_diff;

		    gettimeofday(&now, &tz);
		    prog_life.tv_sec = now.tv_sec - start.tv_sec;
		    prog_life.tv_usec = now.tv_usec - start.tv_usec;
		    if(prog_life.tv_usec < 0) {
			prog_life.tv_sec--;
			prog_life.tv_usec += 1000000;
		    }

		    printf("%4lu.%06lu - rtt: %lld usec; clock diff: %lld usec; avg: %lld\n", 
			   (unsigned long int)prog_life.tv_sec,
               (unsigned long int)prog_life.tv_usec, rtt,
			   clockdiffs[i%AVG_CNT], 
			   *avg_clockdiff);

		    if(max_diff < clockdiffs[i%AVG_CNT])
			max_diff = clockdiffs[i%AVG_CNT];
		    if(min_diff > clockdiffs[i%AVG_CNT])
			min_diff = clockdiffs[i%AVG_CNT];
		}
		else {
		    num_losses++;
		    printf("%d: timeout; errors: %d\n", i, num_losses);
		}
		read_flag = 0;
	    }
	    usleep(Delay*1000);
	}
	ret = shmdt(mem_addr);
	if(ret == -1) {
	    perror("shmdt:");
	    exit(0);
	}
	
	cmd = IPC_RMID;
	ret = shmctl (shmid, cmd, &shm_buf);
	if(ret == -1) {
	    perror("shmctl:");
	    exit(0);
	}

	printf("max diff: %d usec; min diff: %d usec\n", max_diff, min_diff);
    }
    else {
	printf("Just answering pings on port %d\n", recvPort);
	while(1) {
	    temp_mask = mask;
	    temp_timeout.tv_sec = Exit_Timeout;
	    temp_timeout.tv_usec = 0;
	    select( FD_SETSIZE, &temp_mask, &dummy_mask, &dummy_mask, &temp_timeout);
		
	    if(FD_ISSET(sk, &temp_mask)) {
		ret = recv(sk, buf, sizeof(buf), 0);  

		if(ret != *msg_size) {
		    perror("corrupted packet...\n");
		    exit(0);
		}
		
		gettimeofday(t2, &tz);
		
		send_addr.sin_family = AF_INET;
		send_addr.sin_addr.s_addr = *addr; 
		send_addr.sin_port = *port;
		
		gettimeofday(t3, &tz);
		ret = sendto(sk, buf, *msg_size,  0, 
			     (struct sockaddr *)&send_addr, sizeof(send_addr));
	    }
	    else {
		return(1);
	    }
	}
    }
    return(1);
}




static  void    Usage(int argc, char *argv[])
{
    /* Setting defaults */
    Num_bytes = 64;
    Delay = 1000;
    Num_rounds = 30;
    sendPort = 8400;
    recvPort = 8400;
    Address = 0;
    Send_Flag = 0;
    strcpy(IP, "127.0.0.1");
    strcpy(My_name, ""); 
    Exit_Timeout = 3600;
    while( --argc > 0 ) {
	argv++;
	
	if( !strncmp( *argv, "-d", 2 ) ){
	    sscanf(argv[1], "%d", (int*)&recvPort );
	    argc--; argv++;
	}else if( !strncmp( *argv, "-r", 2 ) ){
	    sscanf(argv[1], "%d", (int*)&recvPort );
	    argc--; argv++;
	}else if( !strncmp( *argv, "-a", 2 ) ){
	    sscanf(argv[1], "%s", IP );
	    argc--; argv++;
	}else if( !strncmp( *argv, "-l", 2 ) ){
	    sscanf(argv[1], "%s", My_name );
	    argc--; argv++;
	}else if( !strncmp( *argv, "-b", 2 ) ){
	    sscanf(argv[1], "%d", (int*)&Num_bytes );
	    argc--; argv++;
	}else if( !strncmp( *argv, "-t", 2 ) ){
	    sscanf(argv[1], "%d", (int*)&Delay );
	    argc--; argv++;
	}else if( !strncmp( *argv, "-n", 2 ) ){
	    sscanf(argv[1], "%d", (int*)&Num_rounds );
	    argc--; argv++;
	}else if( !strncmp( *argv, "-x", 2 ) ){
	    sscanf(argv[1], "%d", (int*)&Exit_Timeout );
	    argc--; argv++;
	}else if( !strncmp( *argv, "-s", 2 ) ){
	    Send_Flag = 1;
	}else{
	    printf( "Usage: sping\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
		    "\t[-d <port number>] : to send packets on, default is 8400",
		    "\t[-r <port number>] : to receive packets on, default is 8400",
		    "\t[-a <IP address> ] : IP address to send ping packets to",
		    "\t[-l <IP address> ] : local IP address",
		    "\t[-b <size>       ] : size of the ping packets (in bytes)",
		    "\t[-t <delay>      ] : delay between ping packets (in milliseconds)",
		    "\t[-n <rounds>     ] : number of rounds",
		    "\t[-x <exit delay> ] : time until exit (sec), default 3600",
		    "\t[-s              ] : sender ping");
	    exit( 0 );
	}
    }
    
    if(Num_bytes > MAX_PACKET_SIZE)
	Num_bytes = MAX_PACKET_SIZE;
    
    if(Num_bytes < 3*sizeof(struct timeval) + 3*sizeof(int) + sizeof(long)){
	printf("Message too short !!!\n");
	Num_bytes = 3*sizeof(struct timeval) + 3*sizeof(int) + sizeof(long);
    }
    
    if(Num_rounds > MAX_ROUNDS)
	Num_rounds = MAX_ROUNDS;   
}
