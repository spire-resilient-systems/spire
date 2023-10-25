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

#ifndef ARCH_PC_WIN95
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h> 
#include <sys/un.h>
#include <netdb.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#else
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <errno.h>
#include <math.h>
#include <assert.h>
#include "spines_lib.h"
#include "spu_events.h"
#include "spu_alarm.h"

static int Num_bytes;
static int  Rate;
static int  Num_pkts;
static char IP[80];
static char MCAST_IP[80];
static char SP_IP[80];
static char Unix_domain_path[80];
static char filename[80];
static int  fileflag;
static int  spinesPort;
static int  sendPort;
static int  recvPort;
static int  Send_Flag;
static int  Protocol;
static int  Group_Address;
static int  ttl;
static int  report_latency_stats;
static int  verbose_mode;
static int  no_rotate_priority;
static int16u KPaths;

static void Usage(int argc, char *argv[]);

#define SP_MAX_PKT_SIZE  100000
#define MAX_PRIORITY 10

typedef struct flood_pkt_d {
    int32u   seq_num;
    int32u   origin_sec;
    int32u   origin_usec;
    int32u   prio;
    unsigned char path[8];
} flood_pkt;

typedef struct trie_node_d {
    int count;
    struct trie_node_d* child[256];
} trie_node;
 
void isleep(int usec)
{
  int diff;
  sp_time start, now;
  
  start = E_get_time();   
  diff = 0;
  
  while(diff < usec) {
    if(usec - diff > 1) {
#ifdef ARCH_PC_WIN95
	  Sleep(1);
#else
      usleep(1);
#endif
    }

    now = E_get_time();
    diff = now.sec - start.sec;
    diff *= 1000000;
    diff += now.usec - start.usec;
  }
}

void trie_add(trie_node *root, unsigned char *path, int len)
{
    if (root == NULL)
    {
        printf("Error in trie_add: root is NULL\n");
        exit(1);
    }
    if (len == 0)
    {
        root->count++;
        return;
    }
    if (root->child[(int)(path[0])] == NULL)
        root->child[(int)(path[0])] = calloc(1, sizeof(trie_node));
    trie_add(root->child[(int)(path[0])], path+1, len-1);
}

void trie_print(trie_node *root, unsigned char path[], int path_len)
{
    int i;
    if (root == NULL)
    {
        printf("Error in trie_print: root is NULL\n");
        exit(1);
    }
    if (root->count > 0)
    {
        for(i = 0; i<path_len; i++)
            printf("%d ", path[i]);
        printf(": %d\n", root->count);
    }   
    for (i = 0; i<256; i++)
        if (root->child[i] != NULL)
        {
            path[path_len] = i;
            trie_print(root->child[i], path, path_len + 1);
        }
}

int main( int argc, char *argv[] )
{
  int  sk, recv_count, first_pkt_flag;
  char buf[SP_MAX_PKT_SIZE];
  char results_str[1024];
  int  i, j, ret, k;
  int16u prio_change;
  sp_time t1, t2;
  sp_time start, now, report_time, /*expire_time,*/ checkpoint;
  spines_nettime expiration;
  trie_node *root;
  unsigned char temp_path[10];
  int prio_count[MAX_PRIORITY + 1];
  int temp_prio_count[MAX_PRIORITY + 1];

#ifdef ARCH_PC_WIN95
  WSADATA		WSAData;
#endif

  long long int duration_now, int_delay, oneway_time;
  double rate_now;
  int sent_packets = 0;
  long elapsed_time;
  struct ip_mreq mreq;
  FILE *f1 = NULL;
  
  struct sockaddr_in host, serv_addr;
#ifndef ARCH_PC_WIN95
  struct sockaddr_un unix_addr;
#endif /* ARCH_PC_WIN95 */
  struct sockaddr_in name;
  struct hostent     h_ent;
  struct hostent  *host_ptr;
  char   machine_name[256];
  int gethostname_error = 0;
  struct sockaddr *daemon_ptr = NULL;
  
  flood_pkt  *f_pkt;
  long long unsigned int tmp_time;
  /*int        *pkt_size, *pkts_sending, *pkt_no, *pkt_ts_s, *pkt_ts_us;*/
  int        num_out_of_order, duplicates, num_lost;
  double     /*avg_latency, jitter,*/ min_latency, max_latency;
  long long int running_latency;
  int        last_seq, bytes_checkpoint, seq_checkpoint = 0;
  double     running_std_dev; /*now_loss;*/
  
#ifdef	ARCH_PC_WIN95    
  ret = WSAStartup( MAKEWORD(1,1), &WSAData );
  if( ret != 0 ) {
    Alarm( EXIT, "sp_bflooder error: winsock initialization error %d\n", ret );
  }
#endif	/* ARCH_PC_WIN95 */

  for (i = 0; i <= MAX_PRIORITY; i++)
  {
    prio_count[i] = 0;
    temp_prio_count[i] = 0;
  }

  Usage(argc, argv);
  
  seq_checkpoint = Num_pkts/100;

  if(fileflag == 1) {
    f1 = fopen(filename, "wt");
  }

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
    daemon_ptr = (struct sockaddr *)&serv_addr;
    memcpy(&serv_addr.sin_addr, host_ptr->h_addr, sizeof(struct in_addr));
    printf("Using TCP/IP Connection - WIN Localhost\n");
#endif /* ARCH_PC_WIN95 */
  }
  
  /* Setup the target (destination spines daemon IPv4 address) to send to */
  if(strcmp(IP, "") != 0) {
    memcpy(&h_ent, gethostbyname(IP), sizeof(h_ent));
    memcpy( &host.sin_addr, h_ent.h_addr, sizeof(host.sin_addr) );
  }
  else {
    if (gethostname_error == 1) {
        printf("Exiting... gethostbyname required, but error!\n");
        exit(1);
    }
    memcpy(&host.sin_addr, host_ptr->h_addr, sizeof(struct in_addr));
  }

  if(spines_init(daemon_ptr) < 0) {
    printf("flooder_client: socket error\n");
    exit(1);
  }

  f_pkt        = (flood_pkt*)buf;

  start = E_get_time();
  checkpoint = start;
  
  /*  !!!!!!!!!! SENDER CODE !!!!!!!!!!!!!!  */

  if(Send_Flag == 1) {
    host.sin_family = AF_INET;
    host.sin_port   = htons(sendPort);
    
    sk = spines_socket(PF_SPINES, SOCK_DGRAM, Protocol, NULL);

    if (sk < 0) {
      printf("sp_bflooder: client  socket error\n");
      exit(1);
    }
    
    printf("\r\nSending %d packets of size %d bytes to %s:%d with protocol %d ", Num_pkts, Num_bytes, IP, sendPort, Protocol);
    if(fileflag == 1) {
      fprintf(f1, "\r\nSending %d packets of size %d bytes to %s:%d with protocol %d ", Num_pkts, Num_bytes, IP, sendPort, Protocol);
    }	
    
    if(Rate > 0) {	    
      printf("at a rate of %d Kbps\r\n", Rate);
      if(fileflag == 1) {
	fprintf(f1, "at a rate of %d Kbps\r\n", Rate);
      }		    
    }
    else {
      printf("\n\n");
      if(fileflag == 1) {
	fprintf(f1, "\n\n");
      }
    }
    
    /* set the ttl if instructed to */
    if(ttl != 255) {
      if((ttl >= 0) && (ttl <= 255)) {
	if(!Is_mcast_addr(ntohl(host.sin_addr.s_addr)) && !Is_acast_addr(ntohl(host.sin_addr.s_addr))) { 
	  /* This is unicast */
	  if(spines_setsockopt(sk, 0, SPINES_IP_TTL, &ttl, sizeof(ttl)) != 0) {
	    exit(0);
	  }
	} else {
	  /* This is a multicast */
	  if(spines_setsockopt(sk, 0, SPINES_IP_MULTICAST_TTL, &ttl, sizeof(ttl)) != 0) {
	    exit(0);
	  }
	}
      } else {
	printf("error, the ttl value %d is not between 0 and 255\r\n", ttl);
	exit(0);
      }
    }
    
    start = E_get_time();
    report_time.sec = start.sec;
    report_time.usec = start.usec;

    sp_time old = E_get_time();

    expiration.sec = 300;
    expiration.usec = 0;
    if (spines_setsockopt(sk, 0, SPINES_SET_EXPIRATION, (void *)&expiration, sizeof(spines_nettime)) < 0) {
        printf("sp_bflooder: error setting expiration time via setsockopt\n");
        exit(0);
    }
        
    prio_change = 10;
    if (spines_setsockopt(sk, 0, SPINES_SET_PRIORITY, (void *)&prio_change, sizeof(int16u)) < 0) {
        printf("sp_flooder: error setting priority via setsockopt\n");
        exit(0);
    }

    if (spines_setsockopt(sk, 0, SPINES_DISJOINT_PATHS, (void *)&KPaths, sizeof(int16u)) < 0) {
        printf("sp_flooder: error setting k-paths value via setsockopt\n");
        exit(0);
    }
   
    for(i=1; i<=Num_pkts; i++) {
      t1 = E_get_time();
      /*t2 = E_add_time(t1,expire_time);*/
    
      f_pkt->seq_num      = htonl(i);
      f_pkt->origin_sec   = htonl(t1.sec);
      f_pkt->origin_usec  = htonl(t1.usec);
      for (k = 0; k < 8; k++)
        f_pkt->path[k] = 0;

      if ( verbose_mode) {
        if (Num_pkts < 100 || i%(Num_pkts/100) == 0 )
            printf("sent pkt: %d\n", i);
      }

      if (no_rotate_priority == 1) {
        prio_change = 10;
      }
      else {
        /* Set the priority to cycle through 10 values */
        prio_change = ((i-1) % 10) + 1;
        if (spines_setsockopt(sk, 0, SPINES_SET_PRIORITY, (void *)&prio_change, sizeof(int16u)) < 0) {
            printf("sp_flooder: error setting priorty in round-robin fashion via setsockopt\n");
            exit(0);
        } 
      }
      f_pkt->prio = htonl(prio_change);

      ret = spines_sendto(sk, buf, Num_bytes, 0, (struct sockaddr *)&host, sizeof(struct sockaddr));
      if(ret != Num_bytes) {
	    printf("error in writing: %d...\n", ret);
	    exit(0);
      }
      
      now = E_get_time();
      /* if (E_sub_time(now,old).usec > 1000)
        printf("sending pkt = %d, time = %d\n",i, E_sub_time(now,old).usec); *//*dtflood*/
      old = now;

      if(fileflag == 1) {
	    sent_packets++;
	    elapsed_time  = (now.sec - report_time.sec);
	    elapsed_time *= 1000000;
	    elapsed_time += now.usec - report_time.usec;
	
	    if(elapsed_time >= 1000000) {
	        fprintf(f1, "%ld.%ld\t%ld\n", (long)now.sec, (long)now.usec, sent_packets*1000000/elapsed_time);
	  
	    sent_packets = 0;
	    report_time.sec = now.sec;
	    report_time.usec = now.usec;
	    }
      }
      
      if((Rate > 0)&&(i != Num_pkts)) {
        duration_now  = (now.sec - start.sec);
        duration_now *= 1000000;
        duration_now += now.usec - start.usec;
        
        rate_now = Num_bytes;
        rate_now = rate_now * (i+1) * 8 * 1000;
        rate_now = rate_now/duration_now;
        
        if(rate_now > Rate) {
          int_delay = Num_bytes;
          int_delay = int_delay * (i+1) * 8 * 1000;
          int_delay = int_delay/Rate; 
          int_delay = int_delay - duration_now;
          
          if((int_delay < 0)||(int_delay > 10000000)) {
            printf("!!!!!!!!!!!!!! %lld\n", int_delay);
          }
          if(int_delay > 0) {
            isleep(int_delay);
          }
	    }
      }
  }

    t1 = E_get_time();
   
    f_pkt->seq_num      = htonl(-1);
    f_pkt->origin_sec   = htonl(t1.sec);
    f_pkt->origin_usec  = htonl(t1.usec);

    now = E_get_time();
    
    prio_change = 10;
    f_pkt->prio = htonl(prio_change);
    if (spines_setsockopt(sk, 0, SPINES_SET_PRIORITY, (void *)&prio_change, sizeof(int16u)) < 0) {
        printf("sp_flooder: error setting priorty in round-robin fashion via setsockopt\n");
        exit(0);
    }

    for(j = 1; j < 5; j++) {
      ret = spines_sendto(sk, buf, Num_bytes, 0, (struct sockaddr *)&host, sizeof(struct sockaddr));
      //isleep(10000);
    }

    now = E_get_time();
    duration_now  = now.sec - start.sec;
    duration_now *= 1000000; 
    duration_now += now.usec - start.usec;
    
    rate_now = Num_bytes;
    rate_now = rate_now * Num_pkts * 8 * 1000;
    rate_now = rate_now/duration_now;
    
    printf("\r\nSender: Avg transmit rate: %5.3f\r\n\r\n", rate_now);
    if(fileflag == 1) {
      fprintf(f1, "\r\nSender: Avg transmit rate: %5.3f\r\n\r\n", rate_now);
    }

    /* flushs the buffers, or at least gives it time to complete the OS level sends */
#ifdef	ARCH_PC_WIN95 
    Sleep(1);
#else
    sleep(1);
#endif
    spines_close(sk);

  }

  /*  !!!!!!!!!! RECEIVER CODE !!!!!!!!!!!!!!  */

  else {
    printf("\r\nReceiving flooder msgs on port %d\n", recvPort);
   
    /* Set up path data structure */
    /* calloc guarantees that count is 0 and all pointers are null. */
    root = calloc(1, sizeof(trie_node));

    if(verbose_mode == 1) {
      printf("\r\n - VERBOSE REPORTING - \r\nMsg size, Num Msgs being Sent, Msg Sequence Num, Oneway Latency\r\n");
      if(fileflag == 1) {
	fprintf(f1, "(Msg size, Num Msgs being Sent, Msg Sequence Num, Oneway Latency)\r\n");
	fflush(f1);
      }       
    }
    
    sk = spines_socket(PF_SPINES, SOCK_DGRAM, Protocol, NULL);
    if(sk <= 0) {
      printf("error socket...\n");
      exit(0);
    }
    
    name.sin_family = AF_INET;
    name.sin_addr.s_addr = INADDR_ANY;
    name.sin_port = htons(recvPort);	
    
    if(spines_bind(sk, (struct sockaddr *)&name, sizeof(name) ) < 0) {
      perror("err: bind");
      exit(1);
    }
    
    if(Group_Address != -1) {
      mreq.imr_multiaddr.s_addr = htonl(Group_Address);
      mreq.imr_interface.s_addr = htonl(INADDR_ANY);
      
      if(spines_setsockopt(sk, IPPROTO_IP, SPINES_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq)) < 0) {
	printf("Mcast: problem in setsockopt to join multicast address");
	exit(0);
      }	    
    }
    
    last_seq         = 0;
    recv_count       = 0;
    first_pkt_flag   = 1;
    duplicates       = 0;
    oneway_time      = 0;
    min_latency      = 0;
    max_latency      = 0;
    num_out_of_order = 0;
    num_lost         = 0;
    running_latency  = 0;
    running_std_dev  = 0;
    num_lost         = 0;
    bytes_checkpoint = 0;
    start = E_get_time();
    checkpoint = start;

    while(1) {	    
      ret = spines_recvfrom(sk, buf, sizeof(buf), 0, NULL, 0);
      t2 = E_get_time();

      if(ret <= 0) {
	    printf("Disconnected by spines...\n");
	    exit(0);
      }
      if(ret != Num_bytes) {
	printf("corrupted packet... ret: %d; msg_size: %d\n", ret, Num_bytes);
	exit(0);
      }

        bytes_checkpoint += ret;

      if (ntohl(f_pkt->seq_num) == -1)
        break;

      if (first_pkt_flag) {
	start = E_get_time();       /* we calc start time as local clock when first packet arrives */
	                            /* alternatively we could take the time stamp time on the first packet, but if clock skew, this is bad */
	//Num_bytes = ret;
	first_pkt_flag = 0;
	//Num_pkts = ntohl(*pkts_sending); 
	assert(Num_pkts > 0);
	/*if(report_latency_stats == 1) {
	  history = (pkt_stats*) calloc(Num_pkts + 1, sizeof(pkt_stats));
	}*/
	last_seq = -1;
      }     

      /*if(report_latency_stats == 1) {
	if(history[ntohl(*pkt_no)].sent_seq_no != 0) { 
	  duplicates++; 
	  printf("pkt_no %d is a duplicate!\r\n", ntohl(*pkt_no));
	  continue;
	}
      }*/

      t2 = E_get_time();
      if(ret != Num_bytes) {
	printf("corrupted packet...%d:%d\n", ret, Num_bytes);
	exit(0);
      }
     
      /* if (ntohl(f_pkt->seq_num) != last_seq + 1)
        printf("Out of Order: Expected %d, Recv %d\n", last_seq + 1, ntohl(f_pkt->seq_num)); */

      /*if(report_latency_stats == 1) {
	if(ntohl(*pkt_no) != last_seq + 1) {
	  history[ntohl(*pkt_no)].recvd_out_of_order = 1;
	}
      }*/
      
      last_seq = ntohl(f_pkt->seq_num);
      prio_count[ntohl(f_pkt->prio)]++;
      temp_prio_count[ntohl(f_pkt->prio)]++;

       /*if(report_latency_stats == 1) {*/
	oneway_time = (t2.sec - ntohl(f_pkt->origin_sec));
	oneway_time *= 1000000; 
	oneway_time += t2.usec - ntohl(f_pkt->origin_usec);
	/*if(oneway_time < 0) {
	  printf("ERROR: One Way calculated latency is negative (%lld), and probably indicated the clocks are not synchronized\r\n", oneway_time);
	}
      }*/
      recv_count++;
      
      /*if(report_latency_stats == 1) {
	history[ntohl(*pkt_no)].sent_pkt_size          = ntohl(*pkt_size);
	history[ntohl(*pkt_no)].sent_total_count       = ntohl(*pkts_sending);
	history[ntohl(*pkt_no)].sent_seq_no            = ntohl(*pkt_no);
	history[ntohl(*pkt_no)].sent_timestamp.sec  = ntohl(*pkt_ts_s);
	history[ntohl(*pkt_no)].sent_timestamp.usec = ntohl(*pkt_ts_us);
	history[ntohl(*pkt_no)].recvd_timestamp        = t2;
	history[ntohl(*pkt_no)].transmition_latency    = oneway_time;
	history[ntohl(*pkt_no)].recvd_pkt_cnt          = recv_count;
      }*/

    trie_add(root, f_pkt->path, 8);

    if(verbose_mode == 1 && last_seq >= seq_checkpoint) { 
    /* if(verbose_mode == 1 && oneway_time/1000.0 > 1) { */
	    printf("%d\t%d\t%d\t%4f\tpath: ", Num_bytes, Num_pkts, 
            ntohl(f_pkt->seq_num), oneway_time/1000.0);
        for (k = 0; k < 8; k++) {
            /*if (f_pkt->path[k] != 0)*/
                printf("%d ", (int)f_pkt->path[k]);
            /*else
                break;*/
        }
        now = E_get_time();
        duration_now  = now.sec - checkpoint.sec;
        duration_now *= 1000000;
        duration_now += now.usec - checkpoint.usec;
        rate_now = (double)bytes_checkpoint * 8;
        rate_now = rate_now/duration_now;
        printf("    rate(Mbps):\t %f", rate_now);
        tmp_time = (now.sec * 1000000) + now.usec;
        tmp_time = tmp_time - 10000000000 * (tmp_time / 10000000000);
        printf("    \t%llu", tmp_time);
        for (k = 1; k <= MAX_PRIORITY; k++)
        {
          /* printf("\t%d ", temp_prio_count[k]); */
          temp_prio_count[k] = 0;
        }
        printf("\n");
        checkpoint = now;
        bytes_checkpoint = 0;
        seq_checkpoint += (Num_pkts/100);
        if (seq_checkpoint < last_seq)
            seq_checkpoint = last_seq - (last_seq % (Num_pkts/100)) + (Num_pkts/100);

        /*printf("Printing path statistics:\n");
        trie_print(root, temp_path, 0);*/

        /* for (k = sizeof(flood_pkt); k <= 10*sizeof(int) + sizeof(flood_pkt); k += sizeof(int)) {
            printf("%d  ", *(int*)(buf + k));
        }
        printf("\r\n"); */
	if(fileflag == 1) {
	  fprintf(f1, "%d\t%d\t%d\t%lld\r\n", Num_bytes, Num_pkts, 
            ntohl(f_pkt->seq_num), oneway_time);
	  fflush(f1);
	}       
      }
    
  }

    if(verbose_mode == 1) {
      printf("\r\n");
      if(fileflag == 1) {
	fprintf(f1, "\r\n");
	fflush(f1);
      }       
    }
    
    /* if no packet received, report as such */
    if(recv_count == 0) {
      printf("sp_bflooder Receiver: No Data Packets Received\r\n\r\n");
      if(fileflag == 1) {
	fprintf(f1, "sp_bflooder Receiver: No Data Packets Received\r\n\r\n");
	fflush(f1);
      } 
      return(0);
    }  
    
    now = E_get_time();
    duration_now  = now.sec - start.sec;
    duration_now *= 1000000; 
    duration_now += now.usec - start.usec;
    
    rate_now = (double)Num_bytes * recv_count * 8 * 1000;
    rate_now = rate_now/duration_now;
   
#if 0
    if(report_latency_stats == 1) {
      /* lets calc more results */
      running_latency   = 0;
      num_out_of_order  = 0;
      jitter            = 0;
      min_latency       = 2147483647;
      max_latency       = 0;
      avg_latency       = 0;
      running_std_dev   = 0;
      now_loss          = 0;
      
      for(i=0; i<Num_pkts; i++) {
	
	if(history[i].sent_pkt_size == 0) {        /* detect lost packets */
	  num_lost++;
	  
	} else {
	  num_out_of_order += history[i].recvd_out_of_order;   /* detect out of order */
	  
	  /* calc the avg, min, and max latency */
	  running_latency += history[i].transmition_latency;
	  
	  if(history[i].transmition_latency < min_latency) { min_latency = history[i].transmition_latency; }
	  if(history[i].transmition_latency > max_latency) { max_latency = history[i].transmition_latency; }
	}
      }
      
      avg_latency = running_latency / recv_count;
      assert(avg_latency > 0);
      
      /* calculate the jitter (standard deviation) */
      
      if(recv_count > 1) {
	for(i=1; i<=Num_pkts; i++) { 
	  if(history[i].sent_pkt_size != 0) {
	    running_std_dev += ((avg_latency - history[i].transmition_latency) * (avg_latency - history[i].transmition_latency));
	  }
	}
	
	running_std_dev = running_std_dev / (recv_count - 1);
	running_std_dev = sqrt(running_std_dev);
	
      } else {
	running_std_dev = 0;  /* no std dev on sample of 1 */
      }
      
      now_loss = 100 * ((double)num_lost / (double)Num_pkts);
    }
#endif
    
    /*if(report_latency_stats == 1) {
      sprintf(results_str, 
	      "sp_bflooder Receiver:\r\n"
	      "- Num Pkts Received:\t%d out of %d\r\n"
	      "- Pkt Size:\t%d\r\n"
	      "- Pkts Out of Order:\t%d\r\n"
	      "- Duplicate Packets:\t%d\r\n"
	      "- Throughput:\t%f kbs\r\n" 
	      "- Detected Loss (pct): %.2f\r\n"
	      "- Latency (ms) (Avg Min Max):\t%.2f \t %.2f \t %.2f\r\n"
	      "- Jitter (ms): \t%.2f\r\n\r\n",
	      recv_count, Num_pkts, Num_bytes, num_out_of_order, duplicates, rate_now, now_loss, avg_latency/1000, (double)(min_latency/1000), (double)(max_latency/1000), running_std_dev/1000);
      
    } else {*/
      sprintf(results_str, 
	      "sp_bflooder Receiver:\r\n"
	      "- Num Pkts Received:\t%d out of %d\r\n"
	      "- Pkt Size:\t%d\r\n"
	      "- Throughput:\t%f kbs\r\n\r\n",
	      recv_count, Num_pkts, Num_bytes, rate_now);
   // }
    printf("%s", results_str);
    if(fileflag == 1) {
      fprintf(f1, "%s", results_str);
    }

    printf("Printing path statistics:\n");
    trie_print(root, temp_path, 0);

    printf("\nPrinting packet priority breakdown\n");
    for (i = 1; i <= MAX_PRIORITY; i++)
        printf("\t[%2d] : %d\n", i, prio_count[i]);

    spines_close(sk);
  }
  
  if(fileflag == 1) {
    fclose(f1);
  }
  
#ifdef ARCH_PC_WIN95
  Sleep(1000);
#else 
  usleep(1000000);  /* sleep 1 sec */
#endif

  /*if(report_latency_stats == 1) {
    free(history);
  }*/
  
  return(0);
}

static  void    Usage(int argc, char *argv[])
{
  int i1, i2, i3, i4, tmp;
  
  /* Setting defaults */
  Num_bytes             = 1000;
  Rate                  = 500;
  Num_pkts              = 10000;
  spinesPort            = 8100;
  sendPort              = 8400;
  recvPort              = 8400;
  fileflag              = 0;
  Send_Flag             = 0;
  Protocol              = 0;
  strcpy(IP, "");
  strcpy(SP_IP, "");
  strcpy(MCAST_IP, "");
  strcpy(Unix_domain_path, "");
  Group_Address         = -1;
  ttl                   = 255;
  report_latency_stats  = 0;
  verbose_mode          = 0;
  tmp                   = 0;
  no_rotate_priority    = 0;
  KPaths                = 0;  /* This is Flooding */
  
  while( --argc > 0 ) {
    argv++;
    
    if( !strncmp( *argv, "-p", 2 ) ){
      sscanf(argv[1], "%d", (int*)&spinesPort );
      argc--; argv++;
    } else if( !strncmp( *argv, "-d", 2 ) ){
      sscanf(argv[1], "%d", (int*)&sendPort );
      argc--; argv++;
    } else if( !strncmp( *argv, "-r", 2 ) ){
      sscanf(argv[1], "%d", (int*)&recvPort );
      argc--; argv++;
    } else if( !strncmp( *argv, "-a", 2 ) ){
      sscanf(argv[1], "%s", IP );
      argc--; argv++;
    } else if( !strncmp( *argv, "-k", 2 ) ){
      sscanf(argv[1], "%hu", (int16u*)&KPaths );
      argc--; argv++;
    } else if( !strncmp( *argv, "-j", 2 ) ){
      sscanf(argv[1], "%s", MCAST_IP );
      sscanf(MCAST_IP ,"%d.%d.%d.%d",&i1, &i2, &i3, &i4);
      Group_Address = ( (i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4 );	    
      argc--; argv++;
    } else if( !strncmp( *argv, "-o", 2 ) ){
      sscanf(argv[1], "%s", SP_IP );
      argc--; argv++;
    } else if( !strncmp( *argv, "-ud", 4 ) ){
      sscanf(argv[1], "%s", Unix_domain_path);
      argc--; argv++;
    } else if( !strncmp( *argv, "-b", 2 ) ){
      sscanf(argv[1], "%d", (int*)&Num_bytes );
      argc--; argv++;
    } else if( !strncmp( *argv, "-R", 2 ) ){
      sscanf(argv[1], "%d", (int*)&Rate );
      argc--; argv++;
    } else if( !strncmp( *argv, "-t", 2 ) ){
      sscanf(argv[1], "%d", (int*)&ttl );
      argc--; argv++;
    } else if( !strncmp( *argv, "-n", 2 ) ){
      sscanf(argv[1], "%d", (int*)&Num_pkts );
      argc--; argv++;
    } else if( !strncmp( *argv, "-s", 2 ) ){
      Send_Flag = 1;
    } else if( !strncmp( *argv, "-v", 2 ) ){
      verbose_mode = 1;
    } else if( !strncmp( *argv, "-x", 2 ) ){
      no_rotate_priority = 1;
    } else if( !strncmp( *argv, "-q", 2 ) ){
      report_latency_stats = 1;
    } else if( !strncmp( *argv, "-P", 2 ) ){
      if(sscanf(argv[1], "%d", (int*)&tmp ) < 1 || (tmp < 0) || (tmp > 2 && tmp != 8)) {
        Alarm(EXIT, "Bad Protocol %d specified through -P option!\r\n", tmp);
      }
      Protocol |= tmp;
      argc--; argv++;
    } else if ( !strncmp( *argv, "-D", 2 ) ) {
        if(sscanf(argv[1], "%d", (int*)&tmp ) < 1 || (tmp < 0) || (tmp > 3)) {
            Alarm(EXIT, "Bad Dissemination %d specified through -D option!\r\n", tmp);
        }
        Protocol |= (tmp << ROUTING_BITS_SHIFT);
        argc--; argv++;
    } else if ( !strncmp( *argv, "-S", 2 ) ) {
        if(sscanf(argv[1], "%d", (int*)&tmp ) < 1 || (tmp < 0) || (tmp > 1)) {
            Alarm(EXIT, "Bad Session Semantics %d specified through -S option!\r\n", tmp);
        }
        Protocol |= (tmp << SESSION_BITS_SHIFT);
        argc--; argv++;
    } else if( !strncmp( *argv, "-f", 2 ) ){
      sscanf(argv[1], "%s", filename );
      fileflag = 1;
      argc--; argv++;
    } else{
      printf( "Usage: sp_bflooder\n"
	      "\t[-o <address>    ] : address where spines runs, default localhost\n"
	      "\t[-p <port number>] : port where spines runs, default is 8100\n"
          "\t[-ud <path>      ] : unix domain socket path to connect to, default is /tmp/spines<port>\n"
	      "\t[-d <port number>] : to send packets on, default is 8400\n"
	      "\t[-r <port number>] : to receive packets on, default is 8400\n"
	      "\t[-a <address>    ] : address to send packets to\n"
	      "\t[-j <mcast addr> ] : multicast address to join\n"
	      "\t[-t <ttl number> ] : set a ttl on the packets, default is 255\n"
	      "\t[-b <size>       ] : size of the packets (in bytes)\n"
	      "\t[-R <rate>       ] : sending rate (in 1000's of bits per sec)\n"
	      "\t[-n <rounds>     ] : number of packets\n"
	      "\t[-f <filename>   ] : file where to save statistics\n"
	      "\t[-P <0, 1, 2, 8> ] : overlay links (0: UDP; 1: Reliable; 2: Realtime; 8: Intrusion-Tolerant)\n"
	      "\t[-D <0, 1, 2, 3> ] : dissemination alg (0: Min Weight; 1: IT Priority; 2: IT Reliable, 3: Source Based)\n"
          "\t[-S <0, 1>       ] : session semantics (0: Reliable STREAM; 1: Reliable DGRAM no backpressure)\n"
	      "\t[-k              ] : number of node-disjoint paths to route on (only valid for D = 1 and D = 2),\n"
                                    "\t                     \tdefault is MAX_INT (for flooding)\n"
	      "\t[-v              ] : print verbose\n"
	      "\t[-x              ] : turn off rotating priority messages\n"
	      "\t[-q              ] : report latency stats (required tight clock sync)\n"
	      "\t[-s              ] : sender flooder\n");
      exit( 0 );
    }
  }

  if((Num_bytes > SP_MAX_PKT_SIZE) || (Num_bytes < sizeof(flood_pkt))){
    printf("packet size is not within range of %d -> %d\r\n", (int)sizeof(flood_pkt), SP_MAX_PKT_SIZE);
    exit(0);
  } 
}
