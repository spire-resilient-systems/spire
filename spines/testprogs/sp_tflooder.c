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
#include <errno.h>
#include <assert.h>
#include <math.h>

#ifndef ARCH_PC_WIN95
#  include <unistd.h>
#  include <sys/time.h>
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netinet/in.h> 
#  include <sys/un.h>
#  include <netdb.h>
#  include <sys/ipc.h>
#  include <sys/shm.h>
#else 
#  include <winsock2.h>
#  include <ws2tcpip.h>
#endif

#include "spines_lib.h"

static int  Num_bytes;
static int  Rate;
static int  Num_pkts;
static char IP[80];
static char SP_IP[80];
static char Unix_domain_path[80];
static char filename[80];
static int  fileflag;
static int  spinesPort;
static int  sendPort;
static int  recvPort;
static int  Send_Flag;
static int  Protocol;
static int  report_latency_stats;
static int  verbose_mode;
static int  reliable_connect;

static void Usage(int argc, char *argv[]);

#define SP_MAX_PKT_SIZE  1000000

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
    if(usec - diff > 11000) {
      usleep(1);
    }
    gettimeofday(&now, &tz);
    diff = now.tv_sec - start.tv_sec;
    diff *= 1000000;
    diff += now.tv_usec - start.tv_usec;
  }
}

int main( int argc, char *argv[] )
{
  int  sk, sk_listen, recv_count, first_pkt_flag;
  char buf[SP_MAX_PKT_SIZE];
  char results_str[1024];
  int  i, ret;
  struct timeval t1, t2;
  struct timeval start, now, report_time;
  struct timezone tz;
  
  long long int duration_now, int_delay, oneway_time;
  double rate_now;
  int total_read;
  int sent_packets = 0;
  long elapsed_time;
  FILE *f1 = NULL;
  
#ifndef ARCH_PC_WIN95
  struct sockaddr_un unix_addr;
#endif /* ARCH_PC_WIN95 */
  struct sockaddr_in host, serv_addr, name, remote;
  socklen_t remote_addr_sz;
  struct hostent     h_ent;
  struct hostent  *host_ptr;
  char   machine_name[256];
  int gethostname_error = 0;
  struct sockaddr *daemon_ptr = NULL;
  
  unsigned char * p_ip;
  
  pkt_stats* history = NULL;  /* array of size Num_pkts */
  int        *pkt_size, *pkts_sending, *pkt_no, *pkt_ts_s, *pkt_ts_us;
  int        num_out_of_order, duplicates, num_lost;
  double     avg_latency, jitter, min_latency, max_latency;
  long long int running_latency;
  int        last_seq;
  double     running_std_dev, now_loss;
  
  Usage(argc, argv);
  
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

#if 0
  if(strcmp(SP_IP, "") != 0) {
    memcpy(&h_ent, gethostbyname(SP_IP), sizeof(h_ent));
    memcpy( &serv_addr.sin_addr, h_ent.h_addr, sizeof(struct in_addr) );
  }
  else {
    gethostname(machine_name,sizeof(machine_name)); 
    host_ptr = gethostbyname(machine_name);
    
    if(host_ptr == NULL) {
      printf("Init_My_Node: could not get my ip address (my name is %s)\n",
	     machine_name );
      exit(1);
    }
    if(host_ptr->h_addrtype != AF_INET) {
      printf("Init_My_Node: Sorry, cannot handle addr types other than IPv4\n");
      exit(1);
    }
    
    if(host_ptr->h_length != 4) {
      printf("Conf_init: Bad IPv4 address length\n");
      exit(1);
    }
    memcpy(&serv_addr.sin_addr, host_ptr->h_addr, sizeof(struct in_addr));
  }
  serv_addr.sin_port = htons(spinesPort);
  
  /* IPC FIX */
  /* if(spines_init((struct sockaddr*)(&serv_addr)) < 0) {
    printf("flooder_client: socket error\n");
    exit(1);
  } */
  
  if(strcmp(IP, "") != 0) {
    memcpy(&h_ent, gethostbyname(IP), sizeof(h_ent));
    memcpy( &host.sin_addr, h_ent.h_addr, sizeof(host.sin_addr) );
  }
  else {
    memcpy(&host.sin_addr, &serv_addr.sin_addr, sizeof(struct in_addr));
  }
#endif

  pkt_size     = (int*)buf;
  pkts_sending = (int*)(buf + sizeof(int));
  pkt_no       = (int*)(buf + 2*sizeof(int));
  pkt_ts_s     = (int*)(buf + 3*sizeof(int));
  pkt_ts_us    = (int*)(buf + 4*sizeof(int));

  
  /*  !!!!!!!!!! SENDER CODE !!!!!!!!!!!!!!  */
	
  if(Send_Flag == 1) {
    host.sin_family = AF_INET;
    host.sin_port   = htons(sendPort);
    
    sk = spines_socket(PF_SPINES, SOCK_STREAM, Protocol, daemon_ptr);
    if (sk < 0) {
      printf("sp_tflooder_client: socket error\n");
      exit(1);
    }

    ret = spines_connect(sk, (struct sockaddr *)&host, sizeof(host));
    if( ret < 0) {
      printf( "sp_tflooder: could not connect to server\n"); 
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

    if(reliable_connect == 1) {
      printf("Connecting to Spines using reliable connection\r\n");
    } else {
      printf("Connecting to Spines using un-reliable connection\r\n");
    } 

    gettimeofday(&start, &tz);
    report_time.tv_sec = start.tv_sec;
    report_time.tv_usec = start.tv_usec;
    
    for(i=0; i<Num_pkts; i++) {
      gettimeofday(&t1, &tz);

      *pkt_size     = htonl(Num_bytes);
      *pkts_sending = htonl(Num_pkts);
      *pkt_no       = htonl(i);
      *pkt_ts_s     = htonl(t1.tv_sec);
      *pkt_ts_us    = htonl(t1.tv_usec);	

      ret = spines_send(sk, buf, Num_bytes, 0);
      if(ret != Num_bytes) {
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
	  fprintf(f1, "%ld.%ld\t%ld\n", (long)now.tv_sec, (long)now.tv_usec, 
		  sent_packets*1000000/elapsed_time);
	  
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

	  if((int_delay <= 0)||(int_delay > 10000000)) {
	    printf("!!!!!!!!!!!!!! %lld\n", int_delay);
	  }
	  if(int_delay > 0) {
	    isleep(int_delay);
	  }
	}
      }
    }

    gettimeofday(&t1, &tz);
    
    *pkt_size     = htonl(sizeof(pkt_stats));
    *pkts_sending = htonl(Num_pkts);
    *pkt_no       = htonl(-1);
    *pkt_ts_s     = htonl(t1.tv_sec);
    *pkt_ts_us    = htonl(t1.tv_usec);
    
    gettimeofday(&now, &tz);

    ret = spines_send(sk, buf, sizeof(pkt_stats), 0);
    if(ret != sizeof(pkt_stats)) {
      printf("error in writing: %d...\n", ret);
      exit(0);
    }

    gettimeofday(&now, &tz);
    duration_now  = now.tv_sec - start.tv_sec;
    duration_now *= 1000000; 
    duration_now += now.tv_usec - start.tv_usec;
    
    rate_now = Num_bytes;
    rate_now = rate_now * Num_pkts * 8 * 1000;
    rate_now = rate_now/duration_now;
    
    printf("Sender: Avg transmit rate: %5.3f\r\n\r\n", rate_now);
    if(fileflag == 1) {
      fprintf(f1, "Sender: Avg transmit rate: %5.3f\r\n\r\n", rate_now);
    }
  }

  /*  !!!!!!!!!! RECEIVER CODE !!!!!!!!!!!!!!  */

  else {
    printf("\r\nReceiving flooder msgs on port %d\n", recvPort);

    sk_listen = spines_socket(PF_SPINES, SOCK_STREAM, Protocol, daemon_ptr);
    if(sk_listen <= 0) {
      printf("error socket...\n");
      exit(0);
    }

    if(reliable_connect == 1) {
      printf("Reliable connecting to Spines daemon\r\n");
    } else {
      printf("Un-reliable connecting to Spines daemon\r\n");
    }

    name.sin_family = AF_INET;
    name.sin_addr.s_addr = INADDR_ANY;
    name.sin_port = htons(recvPort);
    
    
    ret = spines_bind(sk_listen, (struct sockaddr *)&name, sizeof(name));
    if(ret < 0) {
      printf("disconnected by spines...\n");
      exit(0);
    }	
    
    if(spines_listen(sk_listen, 0) < 0) {
      perror("err: listen");
      exit(1);
    }
    
    remote_addr_sz = sizeof(remote);
    sk = spines_accept(sk_listen, (struct sockaddr *)&remote, &remote_addr_sz);
    if(sk < 0) {
      perror("err: accept");
      exit(1);	
    }
    p_ip = (unsigned char*) &remote.sin_addr.s_addr;
    printf("accept from %u.%u.%u.%u port %d\r\n", p_ip[0], p_ip[1], p_ip[2], p_ip[3], remote.sin_port);
    
    /* we no longer need this socket */
    spines_close(sk_listen);

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

    gettimeofday(&start, &tz);

    while(1) {

      /* grab a size of the incoming packet */
      total_read = 0;
      while(total_read < sizeof(int)) {
	ret = spines_recv(sk, buf+total_read, sizeof(int) - total_read, 0);
	if(ret <= 0) {
	  printf("err reading... read until now: %d; ret: %d\n", total_read, ret);
	  exit(0);
	}
	total_read += ret;
      }


      /* now that we know the size of the packet, lets read until we have the full packet */

      while(total_read < ntohl(*pkt_size)) {
	ret = spines_recv(sk, buf+total_read, ntohl(*pkt_size) - total_read, 0);
	if(ret <= 0) {
	  printf("err reading... read until now:  %d\n", total_read);
	  exit(0);
	}
	total_read += ret;
      }
      
      if(ntohl(*pkt_no) == -1) {
	break;
      }

      if (first_pkt_flag) {
	gettimeofday(&start, &tz);  /* we calc start time as local clock when first packet arrives */
	                            /* alternatively we could take the time stamp time on the first packet, but if clock skew, this is bad */
	Num_bytes = ntohl(*pkt_size);
	first_pkt_flag = 0;
	Num_pkts = ntohl(*pkts_sending);
	assert(Num_pkts > 0);

        /* if (ntohl(*pkt_no) != last_seq + 1)
             printf("Out of Order: Expected %d, Recv %d\n", last_seq + 1, ntohl(*pkt_no)); */

	if(report_latency_stats == 1) {
	  history = (pkt_stats*) calloc(Num_pkts + 1, sizeof(pkt_stats));
	}
	last_seq = -1;
      }     

      if(report_latency_stats == 1) {
	if(history[ntohl(*pkt_no)].sent_seq_no != 0) { 
	  duplicates++; 
	  printf("pkt_no %d is a duplicate!\r\n", ntohl(*pkt_no));
	  continue;
	}
      }

      gettimeofday(&t2, &tz);
      if(total_read != ntohl(*pkt_size)) {
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
	  printf("ERROR: One Way calculated latency is negative (%lld), and probably indicated the clocks are not synchronized\r\n", oneway_time);
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
        if (ntohl(*pkts_sending) < 100 || ntohl(*pkt_no) % (ntohl(*pkt_no) % (ntohl(*pkts_sending) / 100)) == 0 )
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
      printf("sp_tflooder Receiver: No Data Packets Received\r\n\r\n");
      if(fileflag == 1) {
	fprintf(f1, "sp_tflooder Receiver: No Data Packets Received\r\n\r\n");
	fflush(f1);
      } 
      return(0);
    }  
      
    gettimeofday(&now, &tz);
    duration_now  = now.tv_sec - start.tv_sec;
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
	      "sp_tflooder Receiver:\r\n"
	      "- Num Pkts Received:\t%d out of %d\r\n"
	      "- Pkt Size:\t\t%d\r\n"
	      "- Pkts Out of Order:\t%d\r\n"
	      "- Duplicate Packets:\t%d\r\n"
	      "- Throughput:\t%f kbs\r\n" 
	      "- Detected Loss (pct): \t%.2f\r\n"
	      "- Latency (ms) (Avg Min Max):\t%.2f \t %.2f \t %.2f\r\n"
	      "- Jitter (ms): \t\t%.2f\r\n\r\n",
	      recv_count, Num_pkts, Num_bytes, num_out_of_order, duplicates, rate_now, now_loss, 
	      avg_latency/1000, (double)(min_latency/1000), (double)(max_latency/1000), running_std_dev/1000);
      
    } else {
      sprintf(results_str, 
	      "sp_tflooder Receiver:\r\n"
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
  
  spines_close(sk);
  if(fileflag == 1) {
    fclose(f1);
  }
  
  usleep(1000000);  /* sleep 1 sec */

  if(report_latency_stats == 1) {
    free(history);
  }
  
  return(0);  
}


static  void    Usage(int argc, char *argv[])
{
  int tmp;

  /* Setting defaults */
  Num_bytes             = 1000;
  Rate                  = -1;
  Num_pkts              = 10000;
  spinesPort            = 8100;
  sendPort              = 8400;
  recvPort              = 8400;
  fileflag              = 0;
  Send_Flag             = 0;
  Protocol              = 0;
  strcpy(IP, "");
  strcpy(SP_IP, "");
  strcpy(Unix_domain_path, "");
  report_latency_stats  = 0;
  verbose_mode          = 0;
  reliable_connect      = 1;
  
  
  while( --argc > 0 ) {
    argv++;
    
    if( !strncmp( *argv, "-p", 2 ) ){
      sscanf(argv[1], "%d", (int*)&spinesPort );
      argc--; argv++;
    } else if( !strncmp( *argv, "-uc", 4) ){
      Protocol |= UDP_CONNECT;
      reliable_connect = 0;
    } else if( !strncmp( *argv, "-d", 2 ) ){
      sscanf(argv[1], "%d", (int*)&sendPort );
      argc--; argv++;
    } else if( !strncmp( *argv, "-r", 2 ) ){
      sscanf(argv[1], "%d", (int*)&recvPort );
      argc--; argv++;
    } else if( !strncmp( *argv, "-a", 2 ) ){
      sscanf(argv[1], "%s", IP );
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
    } else if( !strncmp( *argv, "-n", 2 ) ){
      sscanf(argv[1], "%d", (int*)&Num_pkts );
      argc--; argv++;
    } else if( !strncmp( *argv, "-s", 2 ) ){
      Send_Flag = 1;
    } else if( !strncmp( *argv, "-v", 2 ) ){
      verbose_mode = 1;
    } else if( !strncmp( *argv, "-q", 2 ) ){
      report_latency_stats = 1;
    } else if( !strncmp( *argv, "-P", 2 ) ){
      if(sscanf(argv[1], "%d", (int*)&tmp ) < 1 || tmp < 0 || (tmp > 2 && tmp != 8)) {
	printf("Bad Protocol %d specified through -P option!\r\n", tmp);
	exit(0);
      }
      Protocol |= tmp;
      argc--; argv++;
    } else if( !strncmp( *argv, "-D", 2 ) ){
        if(sscanf(argv[1], "%d", (int*)&tmp ) < 1 || (tmp < 0) || (tmp > 2)) {
            printf("Bad Dissemination Method!\n");
            exit(0);
        }
        Protocol |= (tmp << ROUTING_BITS_SHIFT);
        argc--; argv++;
    } else if( !strncmp( *argv, "-f", 2 ) ){
      sscanf(argv[1], "%s", filename );
      fileflag = 1;
      argc--; argv++;
    }else{
      printf( "Usage: sp_tflooder\r\n"
	      "\t[-o <address>    ] : address where spines runs, default localhost\n"
	      "\t[-p <port number>] : port where spines runs, default is 8100\n"
          "\t[-ud <path>      ] : unix domain socket path to connect to, default is /tmp/spines<port>\n"
	      "\t[-uc             ] : udp unreliably connect flooder client to spines\n"
	      "\t[-d <port number>] : to send packets on, default is 8400\n"
	      "\t[-r <port number>] : to receive packets on, default is 8400\n"
	      "\t[-a <address>    ] : address to send packets to\n"
	      "\t[-b <size>       ] : size of the packets (in bytes)\n"
	      "\t[-R <rate>       ] : sending rate (in 1000's of bits per sec)\n"
	      "\t[-n <rounds>     ] : number of packets\n"
	      "\t[-f <filename>   ] : file where to save statistics\n"
	      "\t[-P <0, 1 or 2>  ] : overlay links (0: UDP; 1: Reliable; 2: Soft Realtime)\n"
	      "\t[-v              ] : print verbose\n"
	      "\t[-q              ] : report latency stats (required tight clock sync)\n"
	      "\t[-s              ] : sender flooder\n");
      exit( 0 );
    }
  }
  
  if((Num_bytes > SP_MAX_PKT_SIZE) || (Num_bytes < sizeof(pkt_stats))){
    printf("packet size is not within range of %d -> %d\r\n", (int)sizeof(pkt_stats), SP_MAX_PKT_SIZE);
    exit(0);
  } 

}   
