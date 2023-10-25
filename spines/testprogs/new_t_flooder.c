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
#include <unistd.h>
#include <math.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>

#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h> 
#include <netinet/tcp.h>
#include <netdb.h>

#define SP_HAVE_PTHREAD 1

#ifdef SP_HAVE_PTHREAD
#  include <pthread.h>
#endif

/*********************************************************************
 ********************************************************************/

#define SP_CREATE(T, F)    do { int _t; if ((_t = pthread_create((T), 0, (F), 0))) { assert(!_t); abort(); } } while (0)
#define SP_JOIN(T)         do { int _t; if ((_t = pthread_join((T), 0)))           { assert(!_t); abort(); } } while (0)
#define SP_MUTEX_LOCK(M)   do { int _t; if ((_t = pthread_mutex_lock(M)))          { assert(!_t); abort(); } } while (0)
#define SP_MUTEX_UNLOCK(M) do { int _t; if ((_t = pthread_mutex_unlock((M))))      { assert(!_t); abort(); } } while (0)
#define SP_COND_WAIT(C, M) do { int _t; if ((_t = pthread_cond_wait((C), (M))))    { assert(!_t); abort(); } } while (0)
#define SP_COND_SIGNAL(C)  do { int _t; if ((_t = pthread_cond_signal((C))))       { assert(!_t); abort(); } } while (0)

#define SP_MILLION           1000000
#define SP_MAX_PKT_SIZE      ((0x1 << 16) - 1)
#define SP_LAT_HISTOGRAM_MS  (30 * 1000)

/* NOTE: SP_HISTORY_SIZE must be a power of 2 */

#define SP_HISTORY_SIZE      (0x1 << 20)
#define SP_HISTORY_MASK      (SP_HISTORY_SIZE - 1)

/* NOTE: SP_VERBOSE_FAST_CNT must be a power of 2 */

#define SP_VERBOSE_FAST_CNT  (0x1 << 10)  
#define SP_VERBOSE_FAST_MASK (SP_VERBOSE_FAST_CNT - 1)

#if (SP_VERBOSE_FAST_CNT >= SP_HISTORY_SIZE)
#  error SP_VERBOSE_FAST_CNT must be less than SP_HISTORY_SIZE!
#endif

#define SP_DEFAULT_NUM_BYTES      1000
#define SP_DEFAULT_NUM_PKTS       INT_MAX
#define SP_DEFAULT_IP             "127.0.0.1"
#define SP_DEFAULT_SEND_PORT      8400
#define SP_DEFAULT_RECV_PORT      8400
#define SP_DEFAULT_SEND_RATE_MBPS 0.1

/*********************************************************************
 ********************************************************************/

typedef struct
{
  int            sec;
  int            usec;

} my_time;

typedef struct 
{
  int            sent_pkt_size;
  int            sent_total_count;
  int            sent_seq_no;
  my_time        sent_ts;
  my_time        recv_ts;
  int            recv_index;
  int            unique_index;
  double         latency;

} pkt_stats;

typedef struct 
{
  int            num_samples;

  double         min;
  double         max;
  double         mean;
  double         kvar;
  double         jitter;

  int            histogram_ms[SP_LAT_HISTOGRAM_MS + 1];  /* X ms of histogram; +1 for > X */  
  int            pctls_ms[101];

} lat_stats;

/*********************************************************************
 ********************************************************************/

static int             TCP_Mode;
static int             Force_Bind;
static int             Num_Bytes = SP_DEFAULT_NUM_BYTES;
static int             Num_Pkts  = SP_DEFAULT_NUM_PKTS;
static char            IP[256]   = SP_DEFAULT_IP;
static int             Send_Port = SP_DEFAULT_SEND_PORT;
static int             Recv_Port = SP_DEFAULT_RECV_PORT;
static double          Rate_Mbps = SP_DEFAULT_SEND_RATE_MBPS;
static int             Send_Flag;
static int             Report_Latency_Stats;
static int             Enforce_Order;
static int             Verbose_Mode;
static char            Verbose_Fname[256];

static my_time         Start;
static my_time         Report_Time;
static my_time         Now;

static int             Num_Sent;
static int             Num_Receipts;
static int             Num_Unique;
static int             Num_Too_Late;
static int             Num_Duplicates;
static int             Num_Out_Of_Order;
static int             Num_Lost;

static pkt_stats       History[SP_HISTORY_SIZE];
static int             Head     = -1;
static int             Tail     = -1;
static int             Trailing = -1;

static lat_stats       Recv_Lats;
static lat_stats       Delv_Lats;

static FILE           *Verbose_Out;

#ifdef SP_HAVE_PTHREAD

static pthread_mutex_t Verbose_Mut  = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  Verbose_Cond = PTHREAD_COND_INITIALIZER;
static pthread_t       Verbose_Thread;
static int             Verbose_Quit;

/* NOTE: these heads + tail are unsigned and start from 0 to allow
   Num_Receipts to properly exceed INT_MAX 
*/

static pkt_stats       Verbose_Q[SP_HISTORY_SIZE];
static unsigned        Verbose_Fast_Head = 0;  /* NOTE: not synchronized by Verbose_Mut */
static unsigned        Verbose_Head      = 0;
static unsigned        Verbose_Tail      = 0;

#endif

static pkt_stats       Buf[SP_MAX_PKT_SIZE / sizeof(pkt_stats) + 1];
/* static pkt_stats       Send_Buf[SP_MAX_PKT_SIZE / sizeof(pkt_stats) + 1]; */

/*********************************************************************
 ********************************************************************/

my_time get_my_time(void)
{
  my_time        ret;
  struct timeval t;

  if (gettimeofday(&t, NULL)) {
    exit((fprintf(stderr, "gettimeofday error %d '%s'\n", errno, strerror(errno)), -1));
  }

  ret.sec  = (int) t.tv_sec;
  ret.usec = (int) t.tv_usec;
  assert(ret.sec > 0 && ret.usec >= 0 && ret.usec < SP_MILLION);

  return ret;
}

/*********************************************************************
 ********************************************************************/

void isleep(double secs)
{
  double  elapsed = 0.0;
  my_time start   = get_my_time();
  my_time now;

  while (elapsed < secs) {

    if (secs - elapsed > 0.011) {
      usleep(1);
    }
    
    now     = get_my_time();
    elapsed = (now.sec - start.sec) + (now.usec - start.usec) / 1.0e6;
  }
}

/*********************************************************************
 ********************************************************************/

int increase_buffers(int sk,
		     int buf,
		     int min, 
		     int max, 
		     int step)
{
  socklen_t len;
  int       ret;
  int       i;

  assert(min <= max && step > 0);

  for (i = min; i <= max && !setsockopt(sk, SOL_SOCKET, buf, (ret = i, &ret), sizeof(ret)); i += step);
    
  if (getsockopt(sk, SOL_SOCKET, buf, (ret = -1, &ret), (len = sizeof(ret), &len))) {
    ret = -1;
  }

  return ret;
}

/*********************************************************************
 ********************************************************************/

static int print_usage(FILE       *out, 
		       const char *exe)
{
  fprintf(out,
	  "Usage: %s\n"
	  "\t[-T              ] : use TCP rather than UDP\n"
	  "\t[-r <port number>] : port on which to receive packets (default is %d)\n"
	  "\t[-q              ] : report receipt latency stats     (NOTE: requires tight clock sync)\n"
	  "\t[-v <file>       ] : verbose receipt reporting\n"
	  "\t[-O              ] : enforce receipt ordering\n"
	  "\t[-s              ] : sender flooder\n"
	  "\t[-a <address>    ] : address to which to send packets (default is %s)\n"
	  "\t[-d <port number>] : port to which to send packets    (default is %d)\n"
	  "\t[-n <packets>    ] : number of packets to send        (default is %d)\n"
	  "\t[-b <size>       ] : size of the packets in bytes     (default is %d)\n"
	  "\t[-R <rate>       ] : sending rate in Mbps             (default is %f; non-positive -> unlimited)\n"
	  "\t[-F              ] : force sender to bind to recv port\n", 
	  exe, SP_DEFAULT_RECV_PORT, SP_DEFAULT_IP, SP_DEFAULT_SEND_PORT, 
	  SP_DEFAULT_NUM_PKTS, SP_DEFAULT_NUM_BYTES, SP_DEFAULT_SEND_RATE_MBPS);

  return 1;
}

/*********************************************************************
 ********************************************************************/

static void usage(int    argc, 
		  char **argv)
{
  const char *exe = argv[0];
  int         ret;

  assert(sizeof(int) == 4);

  for (--argc, ++argv; argc > 0; --argc, ++argv) {

    if (strlen(*argv) == 2 && (*argv)[0] == '-') {

      switch ((*argv)[1]) {

      case 'r':
      case 'v':
      case 'a':
      case 'd':
      case 'n':
      case 'b':
      case 'R':

	if (argc < 2) {
	  exit((fprintf(stderr, "%s requires a parameter!\n\n", *argv), print_usage(stderr, exe)));
	}

	switch ((*argv)[1]) {

	case 'r': ret = sscanf(argv[1], "%d",    &Recv_Port);                      break;
	case 'v': ret = sscanf(argv[1], "%255s", Verbose_Fname); Verbose_Mode = 1; break;
	case 'a': ret = sscanf(argv[1], "%255s", IP);                              break;
	case 'd': ret = sscanf(argv[1], "%d",    &Send_Port);                      break;
	case 'n': ret = sscanf(argv[1], "%d",    &Num_Pkts);                       break;
	case 'b': ret = sscanf(argv[1], "%d",    &Num_Bytes);                      break;
	case 'R': ret = sscanf(argv[1], "%lf",   &Rate_Mbps);                      break;
	default:  abort();
	}

	if (ret != 1) {
	  exit((fprintf(stderr, "%s parameter didn't match!\n\n", *argv), print_usage(stderr, exe)));
	}

	--argc; ++argv;
	break;

      case 'T': TCP_Mode             = 1; break;
      case 'q': Report_Latency_Stats = 1; break;
      case 'O': Enforce_Order        = 1; break;
      case 's': Send_Flag            = 1; break;
      case 'F': Force_Bind           = 1; break;

      default:
	exit((fprintf(stderr, "Unrecognized parameter '%s' (1)\n\n", *argv), print_usage(stderr, exe)));
      }

    } else {
      exit((fprintf(stderr, "Unrecognized parameter '%s' (2)\n\n", *argv), print_usage(stderr, exe)));
    }
  }

  if (Send_Flag) {

    if (Num_Pkts <= 0) {
      exit((fprintf(stderr, "Number of packets must be positive!\n\n"), print_usage(stderr, exe)));
    }

    if (Num_Bytes > SP_MAX_PKT_SIZE || Num_Bytes < sizeof(pkt_stats)) {
      exit((fprintf(stderr, "Packet size is not within range [%d, %d]\n\n", 
		    (int) sizeof(pkt_stats), SP_MAX_PKT_SIZE), print_usage(stderr, exe)));
    }

    if (Recv_Port != SP_DEFAULT_RECV_PORT) {
      fprintf(stderr, "WARNING: sender flooder ignores recv port! (-r option)\n");
    }

    if (Report_Latency_Stats) {
      fprintf(stderr, "WARNING: sender flooder ignores reporting receipt latencies! (-q option)\n");
    }

    if (Verbose_Mode) {
      fprintf(stderr, "WARNING: sender flooder ignores verbose receipt reporting! (-v option)\n");
    }

    if (Enforce_Order) {
      fprintf(stderr, "WARNING: sender flooder ignores enforce receipt ordering! (-O option)\n");
    }

  } else {

    if (strncmp(IP, SP_DEFAULT_IP, sizeof(SP_DEFAULT_IP)) != 0) {
      fprintf(stderr, "WARNING: receiver flooder ignores send address! (-a option)\n");
    }

    if (Send_Port != SP_DEFAULT_SEND_PORT) {
      fprintf(stderr, "WARNING: receiver flooder ignores send port! (-d option)\n");
    }

    if (Num_Pkts != SP_DEFAULT_NUM_PKTS) {
      fprintf(stderr, "WARNING: receiver flooder ignores number of packets to send! (-n option)\n");
    }

    if (Num_Bytes != SP_DEFAULT_NUM_BYTES) {
      fprintf(stderr, "WARNING: receiver flooder ignores size of packets to send! (-b option)\n");
    }

    if (Rate_Mbps != SP_DEFAULT_SEND_RATE_MBPS) {
      fprintf(stderr, "WARNING: receiver flooder ignores sending rate! (-R option)\n");
    }
  }
}

/*********************************************************************
 ********************************************************************/

static void Sender(void)
{
  pkt_stats         *p = Buf;
  int                sk;
  struct sockaddr_in addr;
  struct hostent    *h_ent;
  unsigned char     *p_ip;
  my_time            start;
  my_time            now;
  my_time            report_time;
  int                report_packets = 0;
  double             elapsed_start;
  double             elapsed_rate;
  double             elapsed_report;
  socklen_t          len;
  int                ret;
  int                tmp;

  if ((sk = socket(AF_INET, (TCP_Mode ? SOCK_STREAM : SOCK_DGRAM), 0)) < 0) {
    exit((fprintf(stderr, "socket error %d %d '%s'\n", sk, errno, strerror(errno)), -1));
  }

  if (TCP_Mode && (ret = setsockopt(sk, IPPROTO_TCP, TCP_NODELAY, (tmp = 1, &tmp), sizeof(tmp))) != 0) {
    exit((fprintf(stderr, "setsockopt(TCP_NODELAY) error %d %d '%s'\n", ret, errno, strerror(errno)), -1));
  }

  if (Rate_Mbps > 0) {  /* if sending at a fixed rate -> increase socket buffers to simulate application buffers */
    increase_buffers(sk, SO_SNDBUF, 64 * 1024, 1024 * 1024, 8 * 1024);
  }

  if (getsockopt(sk, SOL_SOCKET, SO_SNDBUF, (ret = -1, &ret), (len = sizeof(ret), &len))) {
    exit((fprintf(stderr, "getsockopt(SO_SNDBUF) error %d %d '%s'\n", ret, errno, strerror(errno)), -1));
  }

  fprintf(stdout, "Sender socket buffer size = %d\n", ret);

  if (Force_Bind) {

    fprintf(stdout, "Binding to port %d\n", Recv_Port);

    if ((ret = setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, (tmp = 1, &tmp), sizeof(tmp)))) {
      exit((fprintf(stderr, "setsockopt error %d %d '%s'\n", ret, errno, strerror(errno)), -1));
    } 

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(Recv_Port);

    if ((ret = bind(sk, (struct sockaddr*) &addr, sizeof(addr)))) {
      exit((fprintf(stderr, "bind error %d %d '%s'\n", ret, errno, strerror(errno)), -1));
    }
  }

  if ((h_ent = gethostbyname(IP)) == NULL) {
    exit((fprintf(stderr, "gethostbyname(%s) error %d '%s'\n", IP, h_errno, hstrerror(h_errno)), -1));
  }

  if (h_ent->h_addrtype != AF_INET) {
    exit((fprintf(stderr, "gethostbyname(%s) didn't resolve to an IPv4 address\n", IP), -1));
  }

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port   = htons(Send_Port);
  memcpy(&addr.sin_addr, h_ent->h_addr, sizeof(addr.sin_addr));

  p_ip = (unsigned char*) &addr.sin_addr.s_addr;
  fprintf(stdout, "Connecting to %u.%u.%u.%u:%d ...\n", p_ip[0], p_ip[1], p_ip[2], p_ip[3], ntohs(addr.sin_port));

  if ((ret = connect(sk, (struct sockaddr*) &addr, sizeof(addr))) < 0) {
    exit((fprintf(stderr, "connect error %d %d '%s'\n", ret, errno, strerror(errno)), -1));
  }

  fprintf(stdout, "Sending %d packets of size %d bytes at a rate of %.6f Mbps ...\n\n", Num_Pkts, Num_Bytes, Rate_Mbps);

  start = now = report_time = get_my_time();
 
  p->sent_pkt_size    = htonl(Num_Bytes);
  p->sent_total_count = htonl(Num_Pkts);
       
  while (1) {

    /* build and send next packet */

    p->sent_seq_no  = htonl(Num_Sent);
    p->sent_ts.sec  = htonl(now.sec);
    p->sent_ts.usec = htonl(now.usec);
      
    if ((ret = send(sk, p, Num_Bytes, 0)) != Num_Bytes) {
      exit((fprintf(stderr, "send error %d %d '%s'\n", ret, errno, strerror(errno)), -1));
    }

    now = get_my_time();

    if (++Num_Sent == Num_Pkts) {
      break;
    }

    /* periodically print progress */

    if (now.sec - report_time.sec >= 10) {

      tmp            = Num_Sent - report_packets;
      elapsed_start  = (now.sec - start.sec)       + (now.usec - start.usec)       / 1.0e6;
      elapsed_report = (now.sec - report_time.sec) + (now.usec - report_time.usec) / 1.0e6;

      fprintf(stdout, 
	      "Overall sent %d packets at %.6f Mbps (%.3f pps) in last %.6fs; "
	      "Sent %d packets at %.6f Mbps (%.3f pps) in last %.6fs\n",
	      Num_Sent, 8.0 * Num_Bytes * Num_Sent / 1.0e6 / elapsed_start, Num_Sent / elapsed_start, elapsed_start,
	      tmp, 8.0 * Num_Bytes * tmp / 1.0e6 / elapsed_report, tmp / elapsed_report, elapsed_report);

      now            = get_my_time();
      report_time    = now;
      report_packets = Num_Sent;
    }

    /* rate control if requested */

    if (Rate_Mbps > 0) {
      elapsed_start = (now.sec - start.sec) + (now.usec - start.usec) / 1.0e6;  /* how much time has passed */
      elapsed_rate  = 8.0 * Num_Bytes * Num_Sent / 1.0e6 / Rate_Mbps;           /* how much time would pass at Rate_Mbps */

      if (elapsed_start < elapsed_rate) {  /* less time has passed than should have -> wait */
	isleep(elapsed_rate - elapsed_start);
	now = get_my_time();
      }
    }
  }

  /* send termination packet */

  p->sent_seq_no  = htonl(-1);
  p->sent_ts.sec  = htonl(now.sec);
  p->sent_ts.usec = htonl(now.usec);
    
  if ((ret = send(sk, p, Num_Bytes, 0)) != Num_Bytes) {
    exit((fprintf(stderr, "send error %d %d '%s'\n", ret, errno, strerror(errno)), -1));
  }

  /* print final report */

  tmp            = Num_Sent - report_packets;
  elapsed_start  = (now.sec - start.sec)       + (now.usec - start.usec)       / 1.0e6;
  elapsed_report = (now.sec - report_time.sec) + (now.usec - report_time.usec) / 1.0e6;

  fprintf(stdout, 
	  "Overall sent %d packets at %.6f Mbps (%.3f pps) in last %.6fs; "
	  "Sent %d packets at %.6f Mbps (%.3f pps) in last %.6fs\n",
	  Num_Sent, 8.0 * Num_Bytes * Num_Sent / 1.0e6 / elapsed_start, Num_Sent / elapsed_start, elapsed_start,
	  tmp, 8.0 * Num_Bytes * tmp / 1.0e6 / elapsed_report, tmp / elapsed_report, elapsed_report);

  close(sk);
}

/*********************************************************************
 ********************************************************************/

static void finish_lat_stats(lat_stats *s)
{
  assert(s->num_samples >= 0);

  if (s->num_samples > 0) {
    int num_target = 1;
    int num_seen   = 0;
    int pctl       = 0;
    int new_target;
    int i;

    for (i = 0; i <= SP_LAT_HISTOGRAM_MS && pctl <= 100; ++i) {
      
      num_seen += s->histogram_ms[i];
      
      while (num_seen >= num_target && pctl <= 100) {
	s->pctls_ms[pctl++] = i;

	if ((new_target = (int) (pctl / 100.0 * s->num_samples + 0.5)) > num_target) {
	  num_target = new_target;
	}
      }
    }

    assert(num_seen == s->num_samples);

  } else {
    memset(s->pctls_ms, 0xff, sizeof(s->pctls_ms));
  }

  s->jitter = (s->num_samples > 1 ? sqrt(s->kvar / (s->num_samples - 1)) : 0.0);
}

/*********************************************************************
 ********************************************************************/

static void fprint_lat_stats(FILE       *out, 
			     lat_stats  *s, 
			     const char *label, 
			     int         all_pctls, 
			     int         histogram)
{
  int i;

  if (label == NULL) {
    label = "Latency ";
  }

  if (histogram) {
    fprintf(out, "\n%sHistogram:\n", label);

    for (i = 0; i < SP_LAT_HISTOGRAM_MS; ++i) {

      if (s->histogram_ms[i] != 0) {
	fprintf(out, "%d\tms\t%d\n", i, s->histogram_ms[i]);
      }
    }

    if (s->histogram_ms[SP_LAT_HISTOGRAM_MS] != 0) {
      fprintf(out, "%d\tms\t%d\t(out of range!)\n", i, s->histogram_ms[i]);
    }
  }

  fprintf(out, "\n%sPercentiles:\n", label);

  if (!all_pctls) {

    fprintf(out,
	    "-   0 pctl (ms):         \t%d%s\n"
	    "-   1 pctl (ms):         \t%d%s\n"
	    "-   5 pctl (ms):         \t%d%s\n"
	    "-  10 pctl (ms):         \t%d%s\n"
	    "-  25 pctl (ms):         \t%d%s\n"
	    "-  50 pctl (ms):         \t%d%s\n"
	    "-  75 pctl (ms):         \t%d%s\n"
	    "-  90 pctl (ms):         \t%d%s\n"
	    "-  95 pctl (ms):         \t%d%s\n"
	    "-  99 pctl (ms):         \t%d%s\n"
	    "- 100 pctl (ms):         \t%d%s\n",
	    s->pctls_ms[0],   (s->pctls_ms[0]   < SP_LAT_HISTOGRAM_MS ? "" : "\t(out of range!)"),
	    s->pctls_ms[1],   (s->pctls_ms[1]   < SP_LAT_HISTOGRAM_MS ? "" : "\t(out of range!)"),
	    s->pctls_ms[5],   (s->pctls_ms[5]   < SP_LAT_HISTOGRAM_MS ? "" : "\t(out of range!)"),
	    s->pctls_ms[10],  (s->pctls_ms[10]  < SP_LAT_HISTOGRAM_MS ? "" : "\t(out of range!)"),
	    s->pctls_ms[25],  (s->pctls_ms[25]  < SP_LAT_HISTOGRAM_MS ? "" : "\t(out of range!)"),
	    s->pctls_ms[50],  (s->pctls_ms[50]  < SP_LAT_HISTOGRAM_MS ? "" : "\t(out of range!)"),
	    s->pctls_ms[75],  (s->pctls_ms[75]  < SP_LAT_HISTOGRAM_MS ? "" : "\t(out of range!)"),
	    s->pctls_ms[90],  (s->pctls_ms[90]  < SP_LAT_HISTOGRAM_MS ? "" : "\t(out of range!)"),
	    s->pctls_ms[95],  (s->pctls_ms[95]  < SP_LAT_HISTOGRAM_MS ? "" : "\t(out of range!)"),
	    s->pctls_ms[99],  (s->pctls_ms[99]  < SP_LAT_HISTOGRAM_MS ? "" : "\t(out of range!)"),
	    s->pctls_ms[100], (s->pctls_ms[100] < SP_LAT_HISTOGRAM_MS ? "" : "\t(out of range!)"));

  } else {

    for (i = 0; i <= 100; ++i) {
      fprintf(out, "- %3d pctl (ms):         \t%d%s\n", 
	      i, s->pctls_ms[i], (s->pctls_ms[i] < SP_LAT_HISTOGRAM_MS ? "" : "\t(out of range!)"));
    }
  }

  fprintf(out,
	  "\n"
	  "%sNormal Statistics:\n"
	  "- Min      (ms):         \t%.3f\n"
	  "- Max      (ms):         \t%.3f\n"
	  "- Mean     (ms):         \t%.3f\n"
	  "- Jitter   (ms):         \t%.3f\n", 
	  label, s->min * 1000, s->max * 1000, s->mean * 1000, s->jitter * 1000);
}

/*********************************************************************
 ********************************************************************/

void fprint_stats(FILE *out,
		  int   num_pkts,
		  int   all_pctls, 
		  int   histogram)
{
  double elapsed = (Now.sec - Start.sec) + (Now.usec - Start.usec) / 1.0e6;

  if (Report_Latency_Stats) {
    finish_lat_stats(&Recv_Lats);
    fprint_lat_stats(out, &Recv_Lats, "Receipt Latency ", all_pctls, histogram);

    if (Enforce_Order) {
      finish_lat_stats(&Delv_Lats);
      fprint_lat_stats(out, &Delv_Lats, "Delivery Latency ", all_pctls, histogram);
    }
  }

  fprintf(out,
	  "\n"
	  "Receiver Statistics:\n"
	  "- Pkt Size:              \t%d\n"
	  "- Num Pkts Sent:         \t%d\n"
	  "- Num Pkts Unique:       \t%d\n"
	  "- Num Pkts Lost:         \t%d\n"
	  "- Num Pkts Receipts:     \t%d\n"
	  "- Num Pkts Duplicate:    \t%d\n"
	  "- Num Pkts Too Late:     \t%d\n"
	  "- Num Pkts Out of Order: \t%d\n"
	  "- Loss rate (%%):        \t%.3f\n"
	  "- Throughput (Mbps):     \t%.6f\n",
	  Num_Bytes, num_pkts, Num_Unique, Num_Lost, Num_Receipts, Num_Duplicates, Num_Too_Late, Num_Out_Of_Order,
	  100.0 - 100.0 * Num_Unique / num_pkts, 8.0 * Num_Bytes * Num_Unique / 1.0e6 / elapsed);
}

/*********************************************************************
 * Log a packet's stats verbosely.
 ********************************************************************/

int verbose_pkt(const pkt_stats *p)
{
#ifdef SP_HAVE_PTHREAD

  /* quickly record it in Verbose_Q */

  Verbose_Q[++Verbose_Fast_Head & SP_HISTORY_MASK] = *p;

  /* periodically (to reduce overhead) signal Verbose_Thread to write out Verbose_Q */

  if ((Verbose_Fast_Head & SP_VERBOSE_FAST_MASK) == 0) {
    my_time t1 = { 0, 0 };
    my_time t2 = { 0, 0 };

    SP_MUTEX_LOCK(&Verbose_Mut);
    {
      assert(Verbose_Fast_Head >  Verbose_Head && 
	     Verbose_Head      >= Verbose_Tail && 
	     Verbose_Fast_Head <= Verbose_Tail + SP_HISTORY_SIZE);

      Verbose_Head = Verbose_Fast_Head;
      SP_COND_SIGNAL(&Verbose_Cond);

      /* ensure we don't overrun Verbose_Thread on Verbose_Q (shouldn't happen) */

      if (Verbose_Head >= Verbose_Tail + (SP_HISTORY_SIZE - SP_VERBOSE_FAST_CNT)) {

	t1 = get_my_time();

	while (Verbose_Head >= Verbose_Tail + (SP_HISTORY_SIZE - SP_VERBOSE_FAST_CNT)) {
	  SP_COND_WAIT(&Verbose_Cond, &Verbose_Mut);
	}

	t2 = get_my_time();
      }
    }
    SP_MUTEX_UNLOCK(&Verbose_Mut);

    if (t1.usec != 0 || t1.sec != 0) {
      fprintf(stderr, "WARNING: verbose_pkt was held up for %.6fs by Verbose_Thread!\n", 
	      (t2.sec - t1.sec) + (t2.usec - t1.usec) / 1.0e6);
    }
  }
#else
  fprintf(Verbose_Out, "%d\t%d\t%d\t%.6f\t%d.%06d\t%d.%06d\t%d\t%d\n", 
	  p->recv_index, p->unique_index, p->sent_seq_no, p->latency,
	  p->sent_ts.sec, p->sent_ts.usec, p->recv_ts.sec, p->recv_ts.usec, 
	  p->sent_pkt_size, p->sent_total_count);
#endif

  return 1;
}

/*********************************************************************
 ********************************************************************/

void verbose_done(void)
{
#ifdef SP_HAVE_PTHREAD
  SP_MUTEX_LOCK(&Verbose_Mut);
  {
    Verbose_Quit = 1;
    Verbose_Head = Verbose_Fast_Head;
    SP_COND_SIGNAL(&Verbose_Cond);
  }
  SP_MUTEX_UNLOCK(&Verbose_Mut);
  
  SP_JOIN(Verbose_Thread);
#endif
}

/*********************************************************************
 * Thread dedicated to packet logging I/O when verbose printing.
 ********************************************************************/

#ifdef SP_HAVE_PTHREAD

void *verbose_printer(void *dmy)
{
  int        new_tail;
  int        need_signal;
  int        loops_left;
  pkt_stats *p;

  SP_MUTEX_LOCK(&Verbose_Mut);
  {
    while (!Verbose_Quit || Verbose_Tail < Verbose_Head) {
      assert(Verbose_Tail <= Verbose_Head);
      
      while (!Verbose_Quit && Verbose_Tail == Verbose_Head) {
	SP_COND_WAIT(&Verbose_Cond, &Verbose_Mut);
      }

      if (Verbose_Quit && Verbose_Tail == Verbose_Head) {
	break;
      }

      /* figure out how many packets to log */

      assert(Verbose_Tail < Verbose_Head);
      new_tail    = Verbose_Tail;
      need_signal = (Verbose_Head >= Verbose_Tail + (SP_HISTORY_SIZE - SP_VERBOSE_FAST_CNT));

      /* if we aren't holding up the main thread */
      
      if (!need_signal) {

	if ((loops_left = Verbose_Head - Verbose_Tail) > SP_VERBOSE_FAST_CNT) {  /* print some max # of lines */
	  loops_left = SP_VERBOSE_FAST_CNT;
	}

      } else {  /* compute min # of packets before main thread can continue */
	loops_left = 1 + Verbose_Head - Verbose_Tail - (SP_HISTORY_SIZE - SP_VERBOSE_FAST_CNT);
      }

      SP_MUTEX_UNLOCK(&Verbose_Mut);
      {
	while (loops_left-- > 0) {

	  p = &Verbose_Q[++new_tail & SP_HISTORY_MASK];
	    
	  fprintf(Verbose_Out, "%d\t%d\t%d\t%.6f\t%d.%06d\t%d.%06d\t%d\t%d\n", 
		  p->recv_index, p->unique_index, p->sent_seq_no, p->latency, 
		  p->sent_ts.sec, p->sent_ts.usec, p->recv_ts.sec, p->recv_ts.usec, 
		  p->sent_pkt_size, p->sent_total_count);
	}
      }
      SP_MUTEX_LOCK(&Verbose_Mut);

      Verbose_Tail = new_tail;

      if (need_signal) {
	SP_COND_SIGNAL(&Verbose_Cond);  /* signal main thread to continue */
      }
    }
  }
  SP_MUTEX_UNLOCK(&Verbose_Mut);

  return NULL;
}

#endif

/*********************************************************************
 * Determines when packets are lost (because they fall out of History
 * as holes), out-of-order and also computes latency stats of in-order
 * delivery if requested.
 *********************************************************************/

void advance_tail(void)
{
  my_time          max_rts = { 0, 0 };
  const pkt_stats *p;

  assert(Head > Tail && Tail >= Trailing);

  /* special case if we are being forced to abandon a hole */

  if (History[(Tail + 1) & SP_HISTORY_MASK].sent_pkt_size == 0) {
    ++Tail;
    ++Num_Lost;

    /* if another hole immediately follows, then stop advancing tail until forced to do so again */

    if (Tail == Head || History[(Tail + 1) & SP_HISTORY_MASK].sent_pkt_size == 0) {
      goto END;
    }
  }

  /* loop delivering packets in order, no-holes */
  /* use the highest thus far seen recv TS for computing latencies */

  do {
    p = &History[++Tail & SP_HISTORY_MASK];
    assert(Head >= Tail && p->sent_pkt_size != 0);

    /* consider packets that arrive later than they "should" as out of order while ignoring "early" packets */

    if (p->unique_index > Tail - Num_Lost) {
      ++Num_Out_Of_Order;
    }

    /* compute in-order delivery latencies if we are reporting them */

    if (Enforce_Order && Report_Latency_Stats) {
      double prev_mean = Delv_Lats.mean;
      double lat;
      int    lat_ms;

      /* track the maximum recv timestamp in the string of deliveries */

      if (p->recv_ts.sec > max_rts.sec || 
	  (p->recv_ts.sec == max_rts.sec && p->recv_ts.usec > max_rts.usec)) {
	max_rts = p->recv_ts;
      }
      
      lat = (max_rts.sec - p->sent_ts.sec) + (max_rts.usec - p->sent_ts.usec) / 1.0e6;
      
      if (lat <= -500e-6) {
	exit((fprintf(stderr, "Error: latency is too negative (%fs) -> clocks are not synchronized to within 500us\n", lat), -1));
      }

      ++Delv_Lats.num_samples;

      if (lat < Delv_Lats.min) {
	Delv_Lats.min = lat;
      }

      if (lat > Delv_Lats.max) {
	Delv_Lats.max = lat;
      }
      
      Delv_Lats.mean += (lat - Delv_Lats.mean) / Delv_Lats.num_samples;
      Delv_Lats.kvar += (lat - prev_mean) * (lat - Delv_Lats.mean);
      
      lat_ms = (int) (lat * 1000 + 0.5);  /* round to nearest ms for histogram */
      
      if (lat_ms < 0) {
	assert(0);
	lat_ms = 0;
      }
      
      if (lat_ms >= SP_LAT_HISTOGRAM_MS) {
	lat_ms = SP_LAT_HISTOGRAM_MS;
      }
      
      ++Delv_Lats.histogram_ms[lat_ms];
    }

  } while (Tail != Head && History[(Tail + 1) & SP_HISTORY_MASK].sent_pkt_size != 0);

 END:
  assert(Head >= Tail && Tail > Trailing);
}

/*********************************************************************
 ********************************************************************/

static void Receiver_atexit(void)
{
  /* inform verbose printing we're done */

  if (Verbose_Mode) {
    verbose_done();
  }

  /* compute and print final statistics */
      
  if (Num_Unique != 0) {

    while (Tail < Head) {  /* force Tail to be at Head if it isn't already */
      advance_tail();
    }
      
    fprint_stats(stdout, Head + 1, 1, 1);

    if (Verbose_Mode) {
      fprint_stats(Verbose_Out, Head + 1, 1, 1);
    }

  } else {
    fprintf(stdout, "Receiver: No Data Packets Received!\n");
  }

  if (Verbose_Mode) {
    fclose(Verbose_Out);
  }

  fprintf(stdout, "\nGoodbye.\n");
  fflush(stdout);
}

/*********************************************************************
 ********************************************************************/

static void Receiver(void)
{
  pkt_stats         *p              = Buf;
  int                first_pkt_flag = 1;
  my_time            report_time2   = { 0, 0 };
  struct sockaddr_in addr;
  unsigned char     *p_ip;
  socklen_t          len;
  int                sk;
  int                ret;
  int                tmp;
  int                total_read;

  if (setvbuf(stdout, NULL, _IOFBF, 0)) {
    fprintf(stderr, "WARNING: couldn't switch stdout to buffered output!\n");
  }

  if (Verbose_Mode) {

    if ((Verbose_Out = fopen(Verbose_Fname, "w")) == NULL) {
      exit((fprintf(stderr, "fopen(%s) error %d '%s'\n", Verbose_Fname, errno, strerror(errno)), -1));
    }

#ifdef SP_HAVE_PTHREAD
    SP_CREATE(&Verbose_Thread, verbose_printer);
#endif
  }

  if ((sk = socket(AF_INET, (TCP_Mode ? SOCK_STREAM : SOCK_DGRAM), 0)) < 0) {
    exit((fprintf(stderr, "socket error %d %d '%s'\n", sk, errno, strerror(errno)), -1));
  }

  if ((ret = setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, (tmp = 1, &tmp), sizeof(tmp)))) {
    exit((fprintf(stderr, "setsockopt error %d %d '%s'\n", ret, errno, strerror(errno)), -1));
  } 

  memset(&addr, 0, sizeof(addr));
  addr.sin_family      = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port        = htons(Recv_Port);

  if ((ret = bind(sk, (struct sockaddr*) &addr, sizeof(addr)))) {
    exit((fprintf(stderr, "bind error %d %d '%s'\n", ret, errno, strerror(errno)), -1));
  }

  fprintf(stdout, "Accepting input on port %d\n", Recv_Port);
  fflush(stdout);
 
  if (TCP_Mode) {

    if ((ret = listen(sk, 4))) {
      exit((fprintf(stderr, "listen error %d %d '%s'\n", ret, errno, strerror(errno)), -1));
    }

    if ((ret = accept(sk, (struct sockaddr*) &addr, (len = sizeof(addr), &len))) < 0) {
      exit((fprintf(stderr, "accept error %d %d '%s'\n", ret, errno, strerror(errno)), -1));
    }

    p_ip = (unsigned char*) &addr.sin_addr.s_addr;
    fprintf(stdout, "Accepted connection from %u.%u.%u.%u:%d\n\n", p_ip[0], p_ip[1], p_ip[2], p_ip[3], ntohs(addr.sin_port));

    close(sk);  /* we no longer need the accept socket */
    sk = ret;

    if ((ret = setsockopt(sk, IPPROTO_TCP, TCP_NODELAY, (tmp = 1, (char*) &tmp), sizeof(tmp))) != 0) {
      exit((fprintf(stderr, "setsockopt(TCP_NODELAY) error %d %d '%s'\n", ret, errno, strerror(errno)), 1));
    }
  }

  ret = increase_buffers(sk, SO_RCVBUF, 64 * 1024, 1024 * 1024, 8 * 1024);
  fprintf(stdout, "Receiver socket buffer size = %d\n", ret);
  fflush(stdout);

  if (atexit(Receiver_atexit)) {
    exit((fprintf(stderr, "atexit error %d '%s'\n", errno, strerror(errno)), -1));
  }

  if (signal(SIGINT, (void (*)(int)) exit) == SIG_ERR) {
    exit((fprintf(stderr, "signal error %d '%s'\n", errno, strerror(errno)), -1));
  }

  /* receive packets */

  for (p->sent_seq_no = 0; p->sent_seq_no >= 0; (tmp = (Verbose_Mode && verbose_pkt(p)))) {

    /* read headers of incoming packet */

    if (TCP_Mode) {

      for (total_read = 0; total_read < sizeof(pkt_stats); total_read += ret) {
	
	if ((ret = recv(sk, (char*) p + total_read, sizeof(pkt_stats) - total_read, 0)) <= 0) {
	  exit((fprintf(stderr, "recv error %d %d '%s'; total_read = %d (1)\n", ret, errno, strerror(errno), total_read), -1));
	}
      }
    } else {

      if ((ret = total_read = recvfrom(sk, (char*) p, sizeof(Buf), 0, (struct sockaddr*) &addr, (len = sizeof(addr), &len))) < (int) sizeof(pkt_stats)) {
	exit((fprintf(stderr, "recv error %d %d '%s'; total_read = %d (1)\n", ret, errno, strerror(errno), total_read), -1));
      }
    }

    /* endian correct and validate headers */

    p->sent_pkt_size    = ntohl(p->sent_pkt_size);
    p->sent_total_count = ntohl(p->sent_total_count);
    p->sent_seq_no      = ntohl(p->sent_seq_no);
    p->sent_ts.sec      = ntohl(p->sent_ts.sec);
    p->sent_ts.usec     = ntohl(p->sent_ts.usec);
      
    if (p->sent_pkt_size < total_read || p->sent_pkt_size > SP_MAX_PKT_SIZE || p->sent_total_count <= 0) {
      exit((fprintf(stderr, "Illegal headers: pkt_size = %d; pkts_sending = %d!\n", p->sent_pkt_size, p->sent_total_count), -1));
    }

    if (first_pkt_flag) {  /* record start time and test parameters */
      first_pkt_flag = 0;
      Num_Bytes      = p->sent_pkt_size;
      Num_Pkts       = p->sent_total_count;

      if (Report_Latency_Stats) {
	Start.sec  = p->sent_ts.sec;
	Start.usec = p->sent_ts.usec;

      } else {
	Start = get_my_time();
      }

      Report_Time   = Start;
      report_time2  = Start;
      Delv_Lats.min = 1e6;
      Recv_Lats.min = 1e6;

      fprintf(stdout, "Got first packet!\n");
      fflush(stdout);
    }

    if (p->sent_pkt_size != Num_Bytes || p->sent_total_count != Num_Pkts || p->sent_seq_no >= Num_Pkts) {
      exit((fprintf(stderr, "Illegal headers: pkt_size (%d) changed (!= %d) or pkts_sending (%d) changed (!= %d) or pkt_no (%d) >= %d\n", 
		    p->sent_pkt_size, Num_Bytes, p->sent_total_count, Num_Pkts, p->sent_seq_no, Num_Pkts), -1));
    }

    if (TCP_Mode) {

      /* read rest of packet */
        
      for (; total_read < p->sent_pkt_size; total_read += ret) {
        
	if ((ret = recv(sk, (char*) p + total_read, p->sent_pkt_size - total_read, 0)) <= 0) {
	  exit((fprintf(stderr, "recv error %d %d '%s'; total_read = %d (2)\n", ret, errno, strerror(errno), total_read), -1));
	}
      }
    }

    if (total_read != p->sent_pkt_size) {
      exit((fprintf(stderr, "corrupted packet total_read (%d) != pkt_size (%d)\n", total_read, p->sent_pkt_size), -1));
    }

    /* TS receipt */

    p->recv_ts      = get_my_time();
    p->recv_index   = Num_Receipts++;
    p->unique_index = -1;
    p->latency      = (p->recv_ts.sec - p->sent_ts.sec) + (p->recv_ts.usec - p->sent_ts.usec) / 1.0e6;

    if (p->sent_seq_no < 0) {  /* check for termination signal */
      continue;                /* NOTE: loop will break */
    }

    Now = p->recv_ts;  /* NOTE: done after check for termination signal to keep Now from last real packet */

    /* check if packet too old */

    if (p->sent_seq_no <= Trailing) {  

      if ((Num_Too_Late++ & 0x3ff) == 0) {
	fprintf(stdout, "Num_Too_Late = %d!\n", Num_Too_Late);
	fflush(stdout);
      }

      continue;
    }

    /* advance Head */

    assert(Head >= Tail && Tail >= Trailing && Head - SP_HISTORY_SIZE <= Trailing);

    for (; Head < p->sent_seq_no; ++Head) {

      assert(Head >= Tail && Tail >= Trailing && Head - SP_HISTORY_SIZE <= Trailing);

      if (Head - SP_HISTORY_SIZE == Trailing) {

	if (Tail == Trailing) {                  /* force Tail to stay ahead of Trailing -> loss */
	  advance_tail();
	}

	memset(&History[++Trailing & SP_HISTORY_MASK], 0, sizeof(pkt_stats));  /* erase old History */
      }
    }

    assert(Head >= Tail && Tail >= Trailing && Head - SP_HISTORY_SIZE <= Trailing);

    /* check for duplicates */

    if (History[p->sent_seq_no & SP_HISTORY_MASK].sent_pkt_size != 0) {  

      if ((Num_Duplicates++ & 0x3ff) == 0) {
	fprintf(stdout, "Num_Duplicates = %d!\n", Num_Duplicates);
	fflush(stdout);
      }

      continue;
    }

    /* record packet in History */
      
    p->unique_index                           = Num_Unique++;
    History[p->sent_seq_no & SP_HISTORY_MASK] = *p;

    /* advance Tail */

    if (p->sent_seq_no == Tail + 1) {
      advance_tail();
    }

    if (Report_Latency_Stats) {

      double prev_mean = Recv_Lats.mean;
      int    lat_ms;

      /* update packet latency stats */

      if (p->latency <= -500e-6) {
	exit((fprintf(stderr, "Error: latency is too negative (%fs) -> clocks not synched within 500us\n", p->latency), -1));
      }

      ++Recv_Lats.num_samples;

      if (p->latency < Recv_Lats.min) {
	Recv_Lats.min = p->latency;
      }
	
      if (p->latency > Recv_Lats.max) {
	Recv_Lats.max = p->latency;
      }

      Recv_Lats.mean += (p->latency - Recv_Lats.mean) / Recv_Lats.num_samples;
      Recv_Lats.kvar += (p->latency - prev_mean) * (p->latency - Recv_Lats.mean);

      lat_ms = (int) (p->latency * 1000 + 0.5);  /* round to nearest ms for histogram */

      if (lat_ms < 0) {
	assert(0);
	lat_ms = 0;
      }

      if (lat_ms >= SP_LAT_HISTOGRAM_MS) {
	lat_ms = SP_LAT_HISTOGRAM_MS;
      }

      ++Recv_Lats.histogram_ms[lat_ms];
    }

    /* periodically print some stats */

    if (Now.sec - Report_Time.sec >= 10) {

      if (Now.sec - report_time2.sec < 60) {
	fprint_stats(stdout, Head + 1, 0, 0);

      } else {
	fprint_stats(stdout, Head + 1, 1, 1);
	report_time2 = Now;
      }

      Report_Time = Now;
      fflush(stdout);
    }
  }

  close(sk);
}

/*********************************************************************
 ********************************************************************/

int main(int argc, char **argv)
{
  usage(argc, argv);

  if (Send_Flag) {
    Sender();

  } else {  
    Receiver();
  }

  return 0;
}
