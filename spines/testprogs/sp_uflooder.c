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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <assert.h>
#include <limits.h>

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
#include "spu_events.h"
#include "spu_alarm.h"

static int  Num_bytes;
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
static int  enforce_ordering;
static int  verbose_mode;
static int  reliable_connect;

static void Usage(int argc, char *argv[]);

#define SP_MAX_PKT_SIZE  100000

typedef struct pkt_stats_imp {
  int             sent_pkt_size;
  int             sent_total_count;
  int             sent_seq_no;
  sp_time         sent_timestamp;
  sp_time         recvd_timestamp;
  sp_time         delvd_timestamp;
  int             latency;
  int             recvd_pkt_ind;

} pkt_stats;

int pkt_stats_lat_cmp(const void *left, const void *right)
{
  const pkt_stats *l = (const pkt_stats*) left;
  const pkt_stats *r = (const pkt_stats*) right;

  return (l->latency < r->latency ? -1 : l->latency != r->latency);
}

void isleep(int usec)
{
  int diff;
  sp_time start, now;
  
  start = E_get_time();   
  diff = 0;
  
  while(diff < usec) {

    if(usec - diff > 11000) {
#ifdef ARCH_PC_WIN95
      Sleep(1);
#else
      usleep(1);
#endif
    }

    now  = E_get_time();
    diff = (now.sec - start.sec) * 1000000 + (now.usec - start.usec);
  }
}


int main( int argc, char *argv[] )
{
  int  sk, recv_count, first_pkt_flag;
  char buf[SP_MAX_PKT_SIZE];
  char results_str[1024];
  int  i, j, ret;
  sp_time t1, t2;
  sp_time start = { 0, 0 } , now, report_time;

#ifdef ARCH_PC_WIN95
  WSADATA		WSAData;
#endif

  long long int duration_now, int_delay;
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
  
  pkt_stats* history = NULL;  /* array of size Num_pkts */
  int        *pkt_size, *pkts_sending, *pkt_no, *pkt_ts_s, *pkt_ts_us;
  int        num_out_of_order, duplicates, num_lost, latency;
  double     loss_pct;
  int        tail, head;

  #ifdef	ARCH_PC_WIN95    
  ret = WSAStartup( MAKEWORD(1,1), &WSAData );
  if( ret != 0 ) {
     Alarm( EXIT, "sp_uflooder error: winsock initialization error %d\n", ret );
  }
#endif	/* ARCH_PC_WIN95 */

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
	host_ptr = gethostbyname(SP_IP);
    memcpy(&h_ent, host_ptr, sizeof(h_ent));
    memcpy( &serv_addr.sin_addr, h_ent.h_addr, sizeof(struct in_addr) );
  }
  else {
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
    memcpy(&serv_addr.sin_addr, host_ptr->h_addr, sizeof(struct in_addr));
  }
  serv_addr.sin_port = htons(spinesPort);
  serv_addr.sin_family = AF_INET;
  
  if(spines_init((struct sockaddr*)(&serv_addr)) < 0) {
    printf("flooder_client: socket error\n");
    exit(1);
  }
  
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

    printf("Sender calling spines_socket w/ Protocol = %d\r\n", Protocol);
    
    /* sk = spines_socket(PF_SPINES, SOCK_DGRAM, Protocol, NULL); */
    sk = spines_socket(PF_SPINES, SOCK_DGRAM, Protocol, daemon_ptr);

    if (sk < 0) {
      printf("sp_uflooder: client  socket error\n");
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
    
    for(i=0; i<Num_pkts; i++) {
      t1 = E_get_time();

      *pkt_size     = htonl(Num_bytes);
      *pkts_sending = htonl(Num_pkts);
      *pkt_no       = htonl(i);
      *pkt_ts_s     = htonl(t1.sec);
      *pkt_ts_us    = htonl(t1.usec);

      ret = spines_sendto(sk, buf, Num_bytes, 0, (struct sockaddr *)&host, sizeof(struct sockaddr));
      if(ret != Num_bytes) {
	printf("error in writing: %d...\n", ret);
	exit(0);
      }
      
      now = E_get_time();
      
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
      
      if((Rate > 0)&&(i != Num_pkts-1)) {
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
    
    *pkt_size     = htonl(sizeof(pkt_stats));
    *pkts_sending = htonl(Num_pkts);
    *pkt_no       = htonl(-1);
    *pkt_ts_s     = htonl(t1.sec);
    *pkt_ts_us    = htonl(t1.usec);
    
    now = E_get_time();
    
    for(j = 1; j < 10; j++) {
      ret = spines_sendto(sk, buf, sizeof(pkt_stats), 0, (struct sockaddr *)&host, sizeof(struct sockaddr));
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

#ifdef  ARCH_PC_WIN95
    Sleep(1);
#else
    sleep(1);
#endif

    spines_close(sk);

  }

  /*  !!!!!!!!!! RECEIVER CODE !!!!!!!!!!!!!!  */

  else {
    printf("\r\nReceiving flooder msgs on port %d\n", recvPort);
    
    if(verbose_mode == 1) {
      printf("\r\n - VERBOSE REPORTING - \r\nMsg size, Num Msgs being Sent, Msg Sequence Num, Oneway Latency\r\n");
      if(fileflag == 1) {
	fprintf(f1, "(Msg size, Num Msgs being Sent, Msg Sequence Num, Oneway Latency)\r\n");
	fflush(f1);
      }       
    }
    
    if(reliable_connect == 1) {
      printf("Reliable connecting to Spines daemon\r\n");
    } else {
      printf("Un-reliable connecting to Spines daemon\r\n");
    }

    printf("Receiver calling spines_socket w/ Protocol = %d\r\n", Protocol);

    /* sk = spines_socket(PF_INET, SOCK_DGRAM, Protocol, NULL); */
    sk = spines_socket(PF_INET, SOCK_DGRAM, Protocol, daemon_ptr);
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
    
    first_pkt_flag = 1;
    duplicates     = 0;
    recv_count     = 0;
    tail           = -1;
    head           = -1;

    while(1) {	    

      ret = spines_recvfrom(sk, buf, sizeof(buf), 0, NULL, 0);
      t2  = E_get_time();

      if (ret < 5 * (int) sizeof(int)) {
	exit((printf("Disconnected by spines... %d\n", ret), -1));
      }

      *pkt_size     = ntohl(*pkt_size);
      *pkts_sending = ntohl(*pkts_sending);
      *pkt_no       = ntohl(*pkt_no);
      *pkt_ts_s     = ntohl(*pkt_ts_s);
      *pkt_ts_us    = ntohl(*pkt_ts_us);
  
      if (ret != *pkt_size) {
	exit((printf("corrupted packet... ret: %d; msg_size: %d\n", ret, *pkt_size), -1));
      }
      
      if (*pkt_no == -1) {
	break;
      }

      if (first_pkt_flag) {
	first_pkt_flag = 0;
	start          = t2;
	Num_bytes      = ret;
	Num_pkts       = *pkts_sending; 
	assert(Num_pkts > 0);
	
	if (report_latency_stats == 1 && (history = (pkt_stats*) calloc(Num_pkts + 1, sizeof(pkt_stats))) == NULL) {
	  exit((printf("history allocation failed!\n"), -1));
	}
      }

      if (*pkt_size != Num_bytes) {
	exit((printf("wrong packet size %d; should be %d!\n", ret, Num_bytes), -1));
      }

      if (*pkt_no >= Num_pkts) {
	exit((printf("pkt_no (%d) too high; should be < %d!\n", *pkt_no, Num_pkts), -1));
      }

      if ((latency = (t2.sec - *pkt_ts_s) * 1000000 + (t2.usec - *pkt_ts_us)) < 0) {
	exit((printf("ERROR: latency is negative (%d us); clocks are not synchronized tightly enough!\r\n", latency), -1));
      }
          
      if (report_latency_stats) {

	if (history[*pkt_no].sent_seq_no != 0) { 
	  ++duplicates;
	  continue;
	}

	history[*pkt_no].sent_pkt_size       = *pkt_size;
	history[*pkt_no].sent_total_count    = *pkts_sending;
	history[*pkt_no].sent_seq_no         = *pkt_no;
	history[*pkt_no].sent_timestamp.sec  = *pkt_ts_s;
	history[*pkt_no].sent_timestamp.usec = *pkt_ts_us;
	history[*pkt_no].recvd_timestamp     = t2;
	history[*pkt_no].latency             = latency;
	history[*pkt_no].recvd_pkt_ind       = recv_count;

	if (enforce_ordering) {

	  if (*pkt_no > head) {
	    head = *pkt_no;
	  }
	
	  if (*pkt_no == tail + 1) {

	    for (i = *pkt_no; i <= head && history[i].sent_pkt_size != 0; ++i) {
	      history[i].delvd_timestamp = t2;
	      history[i].latency         = (t2.sec - history[i].sent_timestamp.sec) * 1000000 + (t2.usec - history[i].sent_timestamp.usec);

	      if (verbose_mode) {
		printf("%ld.%06ld\t%d\t%d\t%d\t%d\r\n", t2.sec, t2.usec, *pkt_no, latency, *pkt_size, *pkts_sending);
	    
		if (fileflag) {
		  fprintf(f1, "%ld.%06ld\t%d\t%d\t%d\t%d\r\n", t2.sec, t2.usec, *pkt_no, latency, *pkt_size, *pkts_sending);
		}       
	      }
	    }

	    tail = i - 1;
	  }

	} else {
	  history[*pkt_no].delvd_timestamp = t2;

	  if (verbose_mode) {
	    printf("%ld.%06ld\t%d\t%d\t%d\t%d\r\n", t2.sec, t2.usec, *pkt_no, latency, *pkt_size, *pkts_sending);
	    
	    if (fileflag) {
	      fprintf(f1, "%ld.%06ld\t%d\t%d\t%d\t%d\r\n", t2.sec, t2.usec, *pkt_no, latency, *pkt_size, *pkts_sending);
	    }       
	  }
	}

      } else if (verbose_mode) {
	printf("%ld.%06ld\t%d\t%d\t%d\t%d\r\n", t2.sec, t2.usec, *pkt_no, latency, *pkt_size, *pkts_sending);

	if (fileflag) {
	  fprintf(f1, "%ld.%06ld\t%d\t%d\t%d\t%d\r\n", t2.sec, t2.usec, *pkt_no, latency, *pkt_size, *pkts_sending);
	}       
      }

      ++recv_count;
    }

    now = E_get_time();

    if (verbose_mode) {
      printf("\r\n");

      if (fileflag) {
	fprintf(f1, "\r\n");
	fflush(f1);
      }       
    }
    
    /* if no packet received, report it */

    if (recv_count == 0) {
      printf("sp_uflooder Receiver: No Data Packets Received\r\n\r\n");

      if (fileflag) {
	fprintf(f1, "sp_uflooder Receiver: No Data Packets Received\r\n\r\n");
	fclose(f1);
      } 

      return 0;
    }  
    
    duration_now = (now.sec - start.sec) * 1000000 + (now.usec - start.usec);
    rate_now     = (double) Num_bytes * recv_count * 8 * 1000 / duration_now;
    
    if (report_latency_stats) {

      double lat_mean      = 0.0;
      double prev_lat_mean = 0.0;
      double lat_kvar      = 0.0;
      double jitter        = 0.0;
      
      double lat_min;
      double lat_01;
      double lat_05;
      double lat_10;
      double lat_25;
      double lat_med;
      double lat_75;
      double lat_90;
      double lat_95;
      double lat_99;
      double lat_max;

      num_lost         = 0;
      num_out_of_order = 0;
      
      for (i = 0; i < Num_pkts; ++i) {
	
	if (history[i].sent_pkt_size == 0) {            /* detect lost packets */
	  ++num_lost;
	  history[i].latency = INT_MAX;
	  continue;
	}

	if (history[i].recvd_pkt_ind > i - num_lost) {  /* detect out of order */
	  ++num_out_of_order;
	}

	/* compute mean and k-variance */

	lat_mean      += (history[i].latency - prev_lat_mean) / (i - num_lost + 1);
	lat_kvar      += (history[i].latency - prev_lat_mean) * (history[i].latency - lat_mean);
	prev_lat_mean  = lat_mean;
      }

      /* compute jitter and loss % */

      assert(i - num_lost == recv_count);
      lat_mean /= 1000.0;
      jitter   = sqrt(lat_kvar / (recv_count - 1)) / 1000.0;
      loss_pct = 100.0 * num_lost / Num_pkts;

      /* compute min, median, max and other percentiles */

      qsort(history, Num_pkts, sizeof(pkt_stats), pkt_stats_lat_cmp);

      lat_min = history[(int) ((recv_count - 1) * 0.00 + 0.5)].latency / 1000.0;
      lat_01  = history[(int) ((recv_count - 1) * 0.01 + 0.5)].latency / 1000.0;
      lat_05  = history[(int) ((recv_count - 1) * 0.05 + 0.5)].latency / 1000.0;
      lat_10  = history[(int) ((recv_count - 1) * 0.10 + 0.5)].latency / 1000.0;
      lat_25  = history[(int) ((recv_count - 1) * 0.25 + 0.5)].latency / 1000.0;
      lat_med = history[(int) ((recv_count - 1) * 0.50 + 0.5)].latency / 1000.0;
      lat_75  = history[(int) ((recv_count - 1) * 0.75 + 0.5)].latency / 1000.0;
      lat_90  = history[(int) ((recv_count - 1) * 0.90 + 0.5)].latency / 1000.0;
      lat_95  = history[(int) ((recv_count - 1) * 0.95 + 0.5)].latency / 1000.0;
      lat_99  = history[(int) ((recv_count - 1) * 0.99 + 0.5)].latency / 1000.0;
      lat_max = history[(int) ((recv_count - 1) * 1.00 + 0.5)].latency / 1000.0;

      sprintf(results_str, 
	      "sp_uflooder Receiver:\r\n"
	      "- Num Pkts Received: \t%d\tout of\t%d\r\n"
	      "- Loss Rate (%%):    \t%.3f\r\n"
	      "- Pkt Size:          \t%d\r\n"
	      "- Throughput (kbps): \t%.3f\r\n"
	      "- Mean Latency (ms): \t%.3f\r\n"
	      "- Jitter (ms):       \t%.3f\r\n"
	      "- Min  Latency (ms): \t%.3f\r\n"
	      "- 1%%  Latency (ms): \t%.3f\r\n"
	      "- 5%%  Latency (ms): \t%.3f\r\n"
	      "- 10%% Latency (ms): \t%.3f\r\n"
	      "- 25%% Latency (ms): \t%.3f\r\n"
	      "- Med. Latency (ms): \t%.3f\r\n"
	      "- 75%% Latency (ms): \t%.3f\r\n"
	      "- 90%% Latency (ms): \t%.3f\r\n"
	      "- 95%% Latency (ms): \t%.3f\r\n"
	      "- 99%% Latency (ms): \t%.3f\r\n"
	      "- Max  Latency (ms): \t%.3f\r\n"
	      "- Pkts Out of Order: \t%d\r\n"
	      "- Duplicate Packets: \t%d\r\n",
	      recv_count, Num_pkts, loss_pct, Num_bytes, rate_now, lat_mean, jitter,
	      lat_min, lat_01, lat_05, lat_10, lat_25, lat_med, lat_75, lat_90, lat_95, lat_99, lat_max,
	      num_out_of_order, duplicates);
      
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

  if(report_latency_stats == 1) {
    free(history);
  }
  
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
    } else if( !strncmp( *argv, "-q", 2 ) ){
      report_latency_stats = 1;

    } else if( !strncmp( *argv, "-O", 3 ) ){
      enforce_ordering = 1;

    } else if( !strncmp( *argv, "-P", 2 ) ){

      if(sscanf(argv[1], "%d", &tmp) < 1 || tmp < 0 || tmp > 2) {
	Alarm(EXIT, "Bad Protocol %d specified through -P option!\r\n", tmp);
      }

      Protocol |= tmp;
      argc--; argv++;

    } else if( !strncmp( *argv, "-f", 2 ) ){
      sscanf(argv[1], "%s", filename );
      fileflag = 1;
      argc--; argv++;
    } else {
      printf( "Usage: sp_uflooder\n"
	      "\t[-o <address>    ] : address where spines runs, default localhost\n"
	      "\t[-p <port number>] : port where spines runs, default is 8100\n"
          "\t[-ud <path>      ] : unix domain socket path to connect to, default is /tmp/spines<port>\n"
	      "\t[-uc             ] : unreliably UDP connect flooder client to spines\n"
	      "\t[-d <port number>] : to send packets on, default is 8400\n"
	      "\t[-r <port number>] : to receive packets on, default is 8400\n"
	      "\t[-a <address>    ] : address to send packets to\n"
	      "\t[-j <mcast addr> ] : multicast address to join\n"
	      "\t[-t <ttl number> ] : set a ttl on the packets, defualt is 255\n"
	      "\t[-b <size>       ] : size of the packets (in bytes)\n"
	      "\t[-R <rate>       ] : sending rate (in 1000's of bits per sec)\n"
	      "\t[-n <rounds>     ] : number of packets\n"
	      "\t[-f <filename>   ] : file where to save statistics\n"
	      "\t[-P <0, 1, 2>    ] : overlay links (0: UDP; 1: Reliable; 2: Realtime)\n"
	      "\t[-v              ] : print verbose\n"
	      "\t[-O              ] : enforce ordering for timing\n"
	      "\t[-q              ] : report latency stats (required tight clock sync)\n"
	      "\t[-s              ] : sender flooder\n");
      exit(0);
    }
  }

  if((Num_bytes > SP_MAX_PKT_SIZE) || (Num_bytes < sizeof(pkt_stats))){
    printf("packet size is not within range of %d -> %d\r\n", (int)sizeof(pkt_stats), SP_MAX_PKT_SIZE);
    exit(0);
  } 
  
}
