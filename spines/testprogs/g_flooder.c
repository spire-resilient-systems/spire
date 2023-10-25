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
#include <sys/ioctl.h>
#include <netinet/in.h> 
#include <netinet/tcp.h>
#include <netdb.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <errno.h>
#include <math.h>
#include <assert.h>

static int  Num_bytes;
static int  Rate;
static int  Num_pkts;
static char IP[80];
static char MCAST_IP[80];
static char filename[80];
static int  fileflag;
static int  sendPort;
static int  recvPort;
static int  Address;
static int  Send_Flag;
static int  Reliable_Flag;
static int  Forwarder_Flag;
static int  Group_Address;
static int  Num_groups;
static int  Num_ports;
static int  Realtime;
static int  report_latency_stats;
static int  verbose_mode;

static void Usage(int argc, char *argv[]);
int max_rcv_buff(int sk);
int max_snd_buff(int sk);

#define SP_MAX_PKT_SIZE        1400

#define SLEEP_TIME	3

typedef struct pkt_stats_imp {
  int             sent_pkt_size;
  int             sent_total_count;
  int             sent_seq_no;
  struct timeval  sent_timestamp;
  struct timeval  recvd_timestamp;
  int             transmition_latency;
  int             recvd_pkt_cnt;
  int             recvd_out_of_order; /* 0 false or 1 true */


} pkt_stats;

void isleep(int usec)
{
  int diff;
  struct timeval start, now;
  struct timezone tz;
  
  gettimeofday(&start, &tz);    
  diff = 0;
  while(diff < usec) {
    /* If enough time to sleep, otherwise, busywait */
    if(usec - diff > 200) {
      usleep(usec-20);
    }
    gettimeofday(&now, &tz);
    diff = now.tv_sec - start.tv_sec;
    diff *= 1000000;
    diff += now.tv_usec - start.tv_usec;
  }
}

int main( int argc, char *argv[] )
{
  int  sk, recv_count, first_pkt_flag;
  char buf[SP_MAX_PKT_SIZE];
  char results_str[1024];
  int  i, j, ret, ioctl_cmd, block_count;
  struct timeval t1, t2;
  struct timeval start, now, report_time;
  struct timezone tz;
  
  long long int duration_now, int_delay, oneway_time;
  double rate_now;
  int sent_packets = 0;
  long elapsed_time;
  struct ip_mreq mreq;
  FILE *f1 = NULL;
  
  struct sockaddr_in host;
  struct sockaddr_in name;
  struct hostent     h_ent;
  
  pkt_stats* history = NULL;  /* array of size Num_pkts */
  int        *pkt_size, *pkts_sending, *pkt_no, *pkt_ts_s, *pkt_ts_us;
  int        num_out_of_order, duplicates, num_lost;
  double     avg_latency, jitter, min_latency, max_latency;
  long long int running_latency;
  int        last_seq;
  int	     original_ip, current_ip;
  double     running_std_dev, now_loss;
  
  
  Usage(argc, argv);
  
  if(fileflag == 1) {
    f1 = fopen(filename, "wt");
  }
  
  memcpy(&h_ent, gethostbyname(IP), sizeof(h_ent));
  memcpy( &host.sin_addr, h_ent.h_addr, sizeof(host.sin_addr) );
  memcpy( &original_ip, h_ent.h_addr, sizeof(original_ip) );
  original_ip = htonl( original_ip );

  pkt_size     = (int*)buf;
  pkts_sending = (int*)(buf + sizeof(int));
  pkt_no       = (int*)(buf + 2*sizeof(int));
  pkt_ts_s     = (int*)(buf + 3*sizeof(int));
  pkt_ts_us    = (int*)(buf + 4*sizeof(int));
  
  if (Forwarder_Flag == 1) {
    sk = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk < 0) {
      perror("g_flooder_client: socket error");
      exit(1);
    }
  
	  
  /*
   * Enable SO_REUSEADDR to allow multiple instances of this
   * application to receive copies of the multicast datagrams.
   */
   {
	int reuse=1;

		if ( setsockopt(sk, SOL_SOCKET, SO_REUSEADDR,
				  (char *)&reuse, sizeof(reuse)) < 0) {
			perror("setting SO_REUSEADDR");
			close(sk);
			exit(1);
		}
    }

    max_rcv_buff(sk);
    max_snd_buff(sk);
    
    host.sin_family = AF_INET;
    host.sin_port   = htons(sendPort);
    
    name.sin_family = AF_INET;
    name.sin_addr.s_addr = INADDR_ANY;
    name.sin_port = htons(recvPort);
    
    if(bind(sk, (struct sockaddr *)&name, sizeof(name) ) < 0) {
      perror("err: bind");
      exit(1);
    }
    
    if(Group_Address != 0) {
      mreq.imr_multiaddr.s_addr = htonl(Group_Address);
      mreq.imr_interface.s_addr = htonl(INADDR_ANY);
      
      if(setsockopt(sk, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq)) < 0) {
	printf("Mcast: problem in setsockopt to join multicast address");
	exit(0);
      }	    
    }
    
    recv_count = 0;
    first_pkt_flag = 1;
    
    while(1) {
      ret = recv(sk, buf, sizeof(buf), 0);
      if (first_pkt_flag) {
	gettimeofday(&start, &tz);
	first_pkt_flag = 0;
      }
      recv_count++;
      Num_bytes = sendto(sk, buf, ret, 0, (struct sockaddr *)&host, sizeof(struct sockaddr));
      if(ret != Num_bytes) {
	printf("error in writing: %d...\n", ret);
	exit(0);
      }
      if (recv_count%1000 == 0) {
	gettimeofday(&now, &tz);
	duration_now  = now.tv_sec - start.tv_sec;
	duration_now *= 1000000; 
	duration_now += now.tv_usec - start.tv_usec;
	
	rate_now = (double)Num_bytes * recv_count * 8 * 1000;
	rate_now = rate_now/duration_now;
	
	printf("Forwarder: Pkt Size: %d   Avg. rate: %8.3lf Kbps\n", Num_bytes, rate_now);
      }
    }
  } else if(Send_Flag == 1) {

    /*  !!!!!!!!!! SENDER CODE !!!!!!!!!!!!!!  */

    sk = socket(AF_INET, SOCK_DGRAM, 0);
    if (sk < 0) {
      perror("g_flooder_client: socket error");
      exit(1);
    }

  /*
   * Enable SO_REUSEADDR to allow multiple instances of this
   * application to receive copies of the multicast datagrams.
   */
   {
	int reuse=1;

	if ( setsockopt(sk, SOL_SOCKET, SO_REUSEADDR,
				  (char *)&reuse, sizeof(reuse)) < 0) {
		perror("setting SO_REUSEADDR");
		close(sk);
		exit(1);
	}
    }

    max_snd_buff(sk);
    
    /* Bind to control the source port of sent packets, 
       so that we can go over to a NATed network */
    name.sin_family = AF_INET;
    name.sin_addr.s_addr = INADDR_ANY;
    name.sin_port = htons(recvPort);
    
    if(bind(sk, (struct sockaddr *)&name, sizeof(name) ) < 0) {
      perror("err: bind");
      exit(1);
    }
    if (Realtime) {
      /* Realtime here means, if I can't send, drop it, and
       * worry only about the next packet.  This will happen 
       * if the sending buffer was full, which is pretty bad 
       * already for time-sensitive data. */
      ioctl_cmd = 1;
      ret = ioctl(sk, FIONBIO, &ioctl_cmd);
      if (ret == -1) {
	perror("err: ioctl");
	exit(1);
      }
    }
    
    host.sin_family = AF_INET;
    host.sin_port   = htons(sendPort);

    printf("\r\nSending %d packets of size %d bytes to %s:%d", Num_pkts, Num_bytes, IP, sendPort);
    if(fileflag == 1) {
      fprintf(f1, "\r\nSending %d packets of size %d bytes to %s:%d", Num_pkts, Num_bytes, IP, sendPort);
    }      
    
    if(Rate > 0) {
      printf("at a rate of %d Kbps\n\n", Rate);
      if(fileflag == 1) {
	fprintf(f1, "at a rate of %d Kbps\n\n", Rate);
      }           
    }
    else {
      printf("\n\n");
      if(fileflag == 1) {
	fprintf(f1, "\n\n");
      }
    }
    
    gettimeofday(&start, &tz);
    report_time.tv_sec = start.tv_sec;
    report_time.tv_usec = start.tv_usec;
    block_count = 0;
    
    for(i=0; i<Num_pkts; i++) {
      gettimeofday(&t1, &tz);

      *pkt_size     = htonl(Num_bytes);
      *pkts_sending = htonl(Num_pkts);
      *pkt_no       = htonl(i/Num_groups);
      *pkt_ts_s     = htonl(t1.tv_sec);
      *pkt_ts_us    = htonl(t1.tv_usec);
      
      current_ip = htonl( original_ip + (i%Num_groups) );   

      memcpy( &host.sin_addr, &current_ip, sizeof(host.sin_addr) );

      host.sin_port   = htons( sendPort +(i%Num_ports) );
   
      ret = sendto(sk, buf, Num_bytes, 0, (struct sockaddr *)&host, sizeof(struct sockaddr));

      if (ret < 0) {
	if((errno == EWOULDBLOCK)||(errno == EAGAIN)) {
	  block_count++;
	  printf("Dropped %d:%d\n", i, block_count);
	} else {
	  printf("error in writing: %d...\n", ret);
	  printf("Num_groups is %d, i is %d\n", Num_groups, i );
	  printf("errno is %d: %s \n", errno, strerror(errno));
	  exit(0);
	}
      }
      else if(ret != Num_bytes) {
	printf("error in writing: %d...\n", ret);
	exit(0);
      }

      gettimeofday(&now, &tz);

      if(fileflag == 1) {
	sent_packets++;
	elapsed_time  = (now.tv_sec - report_time.tv_sec);
	elapsed_time *= 1000000;
	elapsed_time += now.tv_usec - report_time.tv_usec;
        
	if(elapsed_time >= 1000000) {
	  fprintf(f1, "%ld.%ld\t%ld\n", (long)now.tv_sec, (long)now.tv_usec, sent_packets*1000000/elapsed_time);
	  sent_packets = 0;
	  report_time.tv_sec = now.tv_sec;
	  report_time.tv_usec = now.tv_usec;
	}
      }
        
      if((Rate > 0)&&(i != Num_pkts-1)) {
	duration_now  = (now.tv_sec - start.tv_sec);
	duration_now *= 1000000;
	duration_now += now.tv_usec - start.tv_usec;
	rate_now = Num_bytes;
	rate_now = rate_now * (i+1) * 8 * 1000;
	rate_now = rate_now/duration_now;
	
	if(rate_now > Rate) {
	  int_delay = Num_bytes;
	  int_delay = int_delay * (i+1) * 8 * 1000;
	  int_delay = int_delay/Rate; 
	  int_delay = int_delay - duration_now;
	  
	  if((int_delay <= 0)||(int_delay > 10000000))
	    printf("!!! BIG delay !!!  %lld\n", int_delay);
	  if(int_delay > 0)
	    isleep(int_delay);
	} 
      }
    }

    gettimeofday(&t1, &tz);
    
    *pkt_size     = htonl(sizeof(pkt_stats));
    *pkts_sending = htonl(Num_pkts/Num_groups);
    *pkt_no       = htonl(-1);
    *pkt_ts_s     = htonl(t1.tv_sec);
    *pkt_ts_us    = htonl(t1.tv_usec);

    sleep(SLEEP_TIME);
    for( i = 0; i < Num_groups; i++)
    {
	
        current_ip = htonl( original_ip + (i%Num_groups) );   
        memcpy( &host.sin_addr, &current_ip, sizeof(host.sin_addr) );
	for(j = 0; j < 10; j++) {
      		ret = sendto(sk, buf, sizeof(pkt_stats), 0, (struct sockaddr *)&host, sizeof(struct sockaddr));
      		//isleep(10000);
    	}
    
    }
    gettimeofday(&now, &tz);
    duration_now  = now.tv_sec - start.tv_sec - SLEEP_TIME;
    duration_now *= 1000000; 
    duration_now += now.tv_usec - start.tv_usec;
    
    rate_now = Num_bytes;
    rate_now = rate_now * Num_pkts * 8 * 1000;
    rate_now = rate_now/duration_now;

    printf("Sender: Avg transmit rate: %8.3f Kbps\n", rate_now);
    if(fileflag == 1) {
      fprintf(f1, "Sender: Avg. rate: %8.3f Kbps\n", rate_now);
    }
    if(Realtime) {
      printf("   RT: Dropped %d packets \n", block_count);
    }

  } else {
    
    /*  !!!!!!!!!! RECEIVER CODE !!!!!!!!!!!!!!  */
    printf("\r\nReceiving flooder msgs on port %d\n", recvPort);
       
    sk = socket(AF_INET, SOCK_DGRAM, 0);
    if(sk <= 0) {
      printf("error socket...\n");
      exit(0);
    }
    
  /*
   * Enable SO_REUSEADDR to allow multiple instances of this
   * application to receive copies of the multicast datagrams.
   */
   {
	int reuse=1;

	if ( setsockopt(sk, SOL_SOCKET, SO_REUSEADDR,
				  (char *)&reuse, sizeof(reuse)) < 0) {
		perror("setting SO_REUSEADDR");
		close(sk);
		exit(1);
	}
    }

    for( i=10; i <= 8000; i+=10 )
    {
            int on = 1024*i;
            socklen_t onlen = sizeof(on);

            ret = setsockopt( sk, SOL_SOCKET, SO_SNDBUF, (void *)&on, onlen);
            if (ret < 0 ) break;

            ret = setsockopt( sk, SOL_SOCKET, SO_RCVBUF, (void *)&on, onlen);
            if (ret < 0 ) break;

            ret= getsockopt( sk, SOL_SOCKET, SO_SNDBUF, (void *)&on, &onlen );
            if( on < i*1024 ) break;

            onlen = sizeof(on);
            ret= getsockopt( sk, SOL_SOCKET, SO_RCVBUF, (void *)&on, &onlen );
            if( on < i*1024 ) break;
    }

    printf("Socket buffer limit is %d\n", i );

    name.sin_family = AF_INET;
    name.sin_addr.s_addr = INADDR_ANY;
    name.sin_port = htons(recvPort);
	  
    if(bind(sk, (struct sockaddr *)&name, sizeof(name) ) < 0) {
      perror("err: bind");
      exit(1);
    }

    if(Group_Address != 0) {
      	for( i=0; i< Num_groups; i++) {
      		mreq.imr_multiaddr.s_addr = htonl(Group_Address+i);
      		mreq.imr_interface.s_addr = htonl(INADDR_ANY);
      
      		if(setsockopt(sk, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq)) < 0) {
			printf("Mcast: problem in setsockopt to join the %d multicast address", i+1);
			exit(0);
      		}	    
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

    while(1) {
      ret = recv(sk, buf, sizeof(buf), 0);
      gettimeofday(&t2, &tz);

      if(ret != ntohl(*pkt_size)) {
	printf("corrupted packet... ret: %d; msg_size: %d\n", ret, ntohl(*pkt_size));
	exit(0);
      }

      if(ntohl(*pkt_no) == -1) {
	/* todo */
	/*	if(wait_for_stragglers == 1 && stragger_timer_started == 1) {
	  straggler_timer_started = 1;
	  //start timer
	  continue;

	} else {
	  break;
	}
	*/
	break;
      }

      if (first_pkt_flag) {
	gettimeofday(&start, &tz);  /* we calc start time as local clock when first packet arrives */
	                            /* alternatively we could take the time stamp time on the first packet, but if clock skew, this is bad */
	Num_bytes = ret;
	first_pkt_flag = 0;
	Num_pkts = ntohl(*pkts_sending); 
	assert(Num_pkts > 0);
	if(report_latency_stats == 1) {
	  history = (pkt_stats*) calloc(Num_pkts + 1, sizeof(pkt_stats));
	}
	last_seq = -1;//ntohl(*pkt_no);
      }     

      if(report_latency_stats == 1) {
	if(history[ntohl(*pkt_no)].sent_seq_no != 0) { 
	  duplicates++; 
	  printf("pkt_no %d is a duplicate!\r\n", ntohl(*pkt_no));
	  continue;
	}
      }
      
      gettimeofday(&t2, &tz);
      if(ret != ntohl(*pkt_size)) {
	printf("corrupted packet...%d:%d\n", ret, ntohl(*pkt_size));
	exit(0);
      }
      
      if(report_latency_stats == 1) {
	if(ntohl(*pkt_no) != last_seq + 1) {
	  history[ntohl(*pkt_no)].recvd_out_of_order = 1;
	}
      }

      last_seq = ntohl(*pkt_no);
      
      if(report_latency_stats == 1) {
	oneway_time = (t2.tv_sec - ntohl(*pkt_ts_s));
	oneway_time *= 1000000; 
	oneway_time += t2.tv_usec - ntohl(*pkt_ts_us);
	if(oneway_time < 0) {
	  printf("ERROR: One Way calculated catency is negative (%lld), and priobably indicated the clocks are not synchronized\r\n", oneway_time);
	}
      }
      recv_count++;
      
      if(report_latency_stats == 1) {
	history[ntohl(*pkt_no)].sent_pkt_size          = ntohl(*pkt_size);
	history[ntohl(*pkt_no)].sent_total_count       = ntohl(*pkts_sending);
	history[ntohl(*pkt_no)].sent_seq_no            = ntohl(*pkt_no);
	history[ntohl(*pkt_no)].sent_timestamp.tv_sec  = ntohl(*pkt_ts_s);
	history[ntohl(*pkt_no)].sent_timestamp.tv_usec = ntohl(*pkt_ts_us);
	history[ntohl(*pkt_no)].recvd_timestamp        = t2;
	history[ntohl(*pkt_no)].transmition_latency    = oneway_time;
	history[ntohl(*pkt_no)].recvd_pkt_cnt          = recv_count;
      }
      
      if(verbose_mode == 1) {
	printf("%d\t%d\t%d\t%lld\r\n", ntohl(*pkt_size), ntohl(*pkts_sending), ntohl(*pkt_no), oneway_time);
	if(fileflag == 1) {
	  fprintf(f1, "%d\t%d\t%d\t%lld\r\n", ntohl(*pkt_size), ntohl(*pkts_sending), ntohl(*pkt_no), oneway_time);
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
      printf("sp_uflooder Receiver: No Data Packets Received\r\n\r\n");
      if(fileflag == 1) {
	fprintf(f1, "sp_uflooder Receiver: No Data Packets Received\r\n\r\n");
	fflush(f1);
      } 
      return(0);
    }  
    
    gettimeofday(&now, &tz);
    duration_now  = now.tv_sec - start.tv_sec - SLEEP_TIME;
    duration_now *= 1000000; 
    duration_now += now.tv_usec - start.tv_usec;
    
    rate_now = (double)Num_bytes * recv_count * 8 * 1000;
    rate_now = rate_now/duration_now;
    
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
    
    if(report_latency_stats == 1) {
      sprintf(results_str, 
	      "sp_uflooder Receiver:\r\n"
	      "- Num Pkts Received:\t%d out of %d\r\n"
	      "- Pkt Size:\t%d\r\n"
	      "- Pkts Out of Order:\t%d\r\n"
	      "- Duplicate Packets:\t%d\r\n"
	      "- Throughput:\t%f kbs\r\n" 
	      "- Detected Loss (pct): %.2f\r\n"
	      "- Latency (ms) (Avg Min Max):\t%.2f \t %.2f \t %.2f\r\n"
	      "- Jitter (ms): \t%.2f\r\n\r\n",
	      recv_count, Num_pkts, Num_bytes, num_out_of_order, duplicates, rate_now, now_loss, avg_latency/1000, (double)(min_latency/1000), (double)(max_latency/1000), running_std_dev/1000);
      
    } else {
      sprintf(results_str, 
	      "sp_uflooder Receiver:\r\n"
	      "- Num Pkts Received:\t%d out of %d\r\n"
	      "- Pkt Size:\t%d\r\n"
	      "- Throughput:\t%f kbs\r\n\r\n",
	      recv_count, Num_pkts, Num_bytes, rate_now);
    }
    printf("%s", results_str);
    if(fileflag == 1) {
      fprintf(f1, "%s", results_str);
    }
  }

  if(fileflag == 1) {
    fclose(f1);
  }
  usleep(2000000);
  
  if(report_latency_stats == 1) {
    free(history);
  }
  
  return(1);
}

int max_rcv_buff(int sk)
{
  /* Increasing the buffer on the socket */
  int i, val, ret;
  socklen_t lenval;
  
  for(i=10; i <= 100; i+=5) {
    val = 1024*i;
    ret = setsockopt(sk, SOL_SOCKET, SO_RCVBUF, (void *)&val, sizeof(val));
    if (ret < 0) 
      break;
    lenval = sizeof(val);
    ret = getsockopt(sk, SOL_SOCKET, SO_RCVBUF, (void *)&val, &lenval);
    if(val < i*1024 ) 
      break;
  }
  return(1024*(i-5));
}

int max_snd_buff(int sk)
{
    /* Increasing the buffer on the socket */
  int i, val, ret;
  socklen_t lenval;
  
  for(i=10; i <= 100; i+=5){
    val = 1024*i;
    ret = setsockopt(sk, SOL_SOCKET, SO_SNDBUF, (void *)&val, sizeof(val));
    if (ret < 0) 
      break;
    lenval = sizeof(val);
    ret = getsockopt(sk, SOL_SOCKET, SO_SNDBUF, (void *)&val,  &lenval);
    if(val < i*1024) 
      break;
  }
  return(1024*(i-5));
}

static  void    Usage(int argc, char *argv[])
{
  int i1, i2, i3, i4;
  
  /* Setting defaults */
  Num_bytes             = 1000;
  Rate                  = 500;
  Num_pkts              = 10000;
  sendPort              = 4100;
  recvPort              = 4100;
  Address               = 0;
  Send_Flag             = 0;
  fileflag              = 0;
  Reliable_Flag         = 0;
  Forwarder_Flag        = 0;
  strcpy(IP, "127.0.0.1");
  strcpy(MCAST_IP, "");
  Num_groups		= 1;
  Num_ports		= 1;
  Group_Address         = 0;
  Realtime              = 0;
  report_latency_stats  = 0;
  verbose_mode          = 0;
  
  while( --argc > 0 ) {
    argv++;
    
    if( !strncmp( *argv, "-d", 2 ) ){
      sscanf(argv[1], "%d", (int*)&sendPort );
      argc--; argv++;
    } else if( !strncmp( *argv, "-m", 2 ) ){
      Realtime = 1;
    } else if( !strncmp( *argv, "-r", 2 ) ){
      sscanf(argv[1], "%d", (int*)&recvPort );
      argc--; argv++;
    } else if( !strncmp( *argv, "-a", 2 ) ){
      sscanf(argv[1], "%s", IP );
      argc--; argv++;
    } else if( !strncmp( *argv, "-b", 2 ) ){
      sscanf(argv[1], "%d", (int*)&Num_bytes );
      argc--; argv++;
    } else if( !strncmp( *argv, "-R", 2 ) ){
      sscanf(argv[1], "%d", (int*)&Rate );
      argc--; argv++;
    } else if( !strncmp( *argv, "-n", 2 ) ){
      sscanf(argv[1], "%d", (int*)&Num_pkts );
      argc--; argv++;
    } else if( !strncmp( *argv, "-j", 2 ) ){
      sscanf(argv[1], "%s", MCAST_IP );
      sscanf(MCAST_IP ,"%d.%d.%d.%d",&i1, &i2, &i3, &i4);
      Group_Address = ((i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4);
      argc--; argv++;
    } else if( !strncmp( *argv, "-g", 2 ) ){
      sscanf(argv[1], "%d", (int*)&Num_groups );
      argc--; argv++;
    } else if( !strncmp( *argv, "-p", 2 ) ){
      sscanf(argv[1], "%d", (int*)&Num_ports );
      argc--; argv++;
    } else if( !strncmp( *argv, "-s", 2 ) ){
      Send_Flag = 1;
    } else if( !strncmp( *argv, "-v", 2 ) ){
      verbose_mode = 1;
    } else if( !strncmp( *argv, "-q", 2 ) ){
      report_latency_stats = 1;
    } else if( !strncmp( *argv, "-F", 2 ) ){
      Forwarder_Flag = 1;
    } else if( !strncmp( *argv, "-f", 2 ) ){
      sscanf(argv[1], "%s", filename );
      fileflag = 1;
      argc--; argv++;
    } else{
      printf( "Usage: g_flooder\n"
	      "\t[-d <port number>] : to send packets on, default is 4100\n"
	      "\t[-r <port number>] : to receive packets on, default is 4100\n"
	      "\t[-a <address>    ] : address (or IP multicast address) to send packets to\n"
	      "\t[-b <size>       ] : size of the packets (in bytes)\n"
	      "\t[-R <rate>       ] : sending rate (in 1000's of bits per sec)\n"
	      "\t[-n <rounds>     ] : number of packets\n"
	      "\t[-j <mcast addr> ] : multicast address to join for receiving\n"
	      "\t[-g <num_groups> ] : number of consecutive groups (or IPs for sending) to send to or receive from\n"
	      "\t[-p <num_ports>  ] : number of ports to send the messages over (num_groups mod num_ports has to be 0)\n"
	      "\t[-f <filename>   ] : file where to save statistics\n"
	      "\t[-rt             ] : real-time, non-blocking i/o\n"
	      "\t[-s              ] : sender flooder\n"
	      "\t[-F              ] : forwarder only\n");
      exit( 0 );
    }
  }

/*
*/
  if((Num_bytes > SP_MAX_PKT_SIZE) || (Num_bytes < sizeof(pkt_stats))){
    	printf("packet size is not within range of %d -> %d\r\n", (int)sizeof(pkt_stats), SP_MAX_PKT_SIZE);
    	exit(0);
  } 

  if( Num_groups % Num_ports != 0 ) {
	printf("Num_groups (%d) modulo Num_ports (%d) has to be 0\n", Num_groups, Num_ports );
	exit(0);
  }
printf("In Usage: Group_Address is %d\n", Group_Address );
}
