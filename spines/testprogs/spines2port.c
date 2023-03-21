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

/* spines2port
 *
 * opens a socket to forward packets to a specified address/port, then
 * forwards packets from an open spines connection to that address/port
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
#include <sys/un.h>
#include <netdb.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <errno.h>
#include <math.h>
#include <assert.h>
#include <signal.h>
#include "spines_lib.h"
#include "spu_events.h"
#include "spu_alarm.h"

#define WINDOW_SIZE      20000  /* conservative approach */
#define MAX_PKT_SIZE      1472  /* we only have 1364 bytes to work with */
#define MAX_NEIGHBORS      100  /* we can only mirror to 100 neighbors */ 
#define HIST_NUM_BUCKETS 10000
#define HIST_BUCKET_SIZE     1

#define DEFAULT_SPINES_PORT        8100
#define DEFAULT_RECV_PORT          8400
#define DEFAULT_SEND_PORT          8400
#define DEFAULT_REPORTING_INTERVAL 1000
#define DEFAULT_WAIT_BUFFER          30

typedef struct pkt_stats_d {
    int32u   seq_num;
    int32u   origin_sec;
    int32u   origin_usec;
    int32u   prio;
    unsigned char path[8];
} pkt_stats;

typedef struct trie_node_d {
    int count;
    struct trie_node_d* child[256];
} trie_node;

typedef struct hist_bucket_d {
    int count;
    trie_node *paths_trie;
} hist_bucket;

typedef struct history_d {
    struct timeval timeout;
    int size;
    char buffer[MAX_PKT_SIZE];
} history;

typedef struct interval_stats_d {
    int32u high_seq;
    double oneway_ms;
    long unsigned int msgs;
    long unsigned int bytes;
    trie_node *total_paths;
    hist_bucket histogram[HIST_NUM_BUCKETS+1];
} interval_stats;

static int recvPort;
static int spinesPort;
static int Protocol;
static int Group_Address;
static char MCAST_IP[80];
static char SP_IP[80];
static char Unix_domain_path[80];
static int Cummulative_Print_Mode;
static int Verbose_Print_Mode;
static double wait_buffer;
static double expire_buffer;
static int Address[MAX_NEIGHBORS];
static int Port[MAX_NEIGHBORS];
static int numNeighbors;
static int16u KPaths;
static int Reporting_Interval;
static int Arrival_Base_Time_Flag;

/* Interval Reporting statistics */
static double Interval_start_ms = 0;
static long unsigned int Interval_target = 0;
static interval_stats Arrival_stats;
static interval_stats Delivery_stats;

static void intervalStatsInit(interval_stats *stats);
static void intervalStatsPrint(const char *prefix, interval_stats *stats, double interval_start_ms);
static void histogramPrint(interval_stats *stats);
static void Final_Report(int signum);
static struct timeval addTime( struct timeval t1, struct timeval t2 );
static struct timeval diffTime( struct timeval t1, struct timeval t2 );
static int compTime( struct timeval t1, struct timeval t2 );
static void trie_add(trie_node *root, unsigned char *path, int len);
static void trie_print(trie_node *root);
static void trie_clean(trie_node *root);
static void Usage(int argc, char *argv[]);

int main(int argc, char *argv[])
{
    int send_sk, spines_sk, recv_count = 0, i, k, recvd_first_flag = 0;
    char buf[MAX_PKT_SIZE];
    int ret, bytes;
    long long unsigned int tail = 1, head = 1, ref = 1, recv_seq;
    double then_ms, now_ms, elapsed_ms;
    struct timeval now, wait_time, expire_time, pkt_expire, pkt_deliver;
    struct timeval timeout;
    struct timeval *timeout_ptr;
    pkt_stats *ps = (pkt_stats*) buf;
    pkt_stats *deliver_ps;

    struct ip_mreq mreq;
    struct sockaddr_in serv_addr, name;
    struct sockaddr_in connections[MAX_NEIGHBORS];
#ifndef ARCH_PC_WIN95
    struct sockaddr_un unix_addr;
#endif /* ARCH_PC_WIN95 */
    struct hostent  *host_ptr;
    int gethostname_error = 0;
    struct sockaddr *daemon_ptr = NULL;
    fd_set  mask, dummy_mask, temp_mask;
    char   machine_name[256];

    history *window;

    setlinebuf(stdout);

    window = malloc(sizeof(history) * WINDOW_SIZE);

    if (!window)
    {
        Alarm(EXIT, "Memory error: unable to malloc");
    }

    Usage(argc, argv);
    wait_time.tv_sec = (int) (wait_buffer / 1000);
    wait_time.tv_usec = (wait_buffer - (wait_time.tv_sec * 1000)) * 1000;
    expire_time.tv_sec = (int) (expire_buffer / 1000);
    expire_time.tv_usec = (expire_buffer - (expire_time.tv_sec * 1000)) * 1000;
    /*printf("Wait time: %ld %d\n", wait_time.tv_sec, wait_time.tv_usec);
    printf("Expire time: %ld %d\n", expire_time.tv_sec, expire_time.tv_usec);*/

    /***********************************************************/
    /*        SETTING UP INBOUND TRAFFIC (FROM SPINES)         */
    /***********************************************************/
    /* gethostname: used for WIN daemon connection & sending to non-specified target */
    gethostname(machine_name,sizeof(machine_name)); 
    host_ptr = gethostbyname(machine_name);
    
    if(host_ptr == NULL) {
        Alarm(PRINT, "WARNING: could not get my ip addr (my name is %s)\n", machine_name );
        gethostname_error = 1;
    }
    if(host_ptr != NULL && host_ptr->h_addrtype != AF_INET) {
        Alarm(PRINT, "WARNING: Sorry, cannot handle addr types other than IPv4\n");
        gethostname_error = 1;
    }
    if(host_ptr != NULL && host_ptr->h_length != 4) {
        Alarm(PRINT, "WARNING: Bad IPv4 address length\n");
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
        Alarm(PRINT, "Using TCP/IP Connection: %s@%d\n", SP_IP, spinesPort);
    }
    else {
#ifndef ARCH_PC_WIN95
        if (strcmp(Unix_domain_path, "") == 0) {
            if (spinesPort == DEFAULT_SPINES_PORT) {
                daemon_ptr = NULL;
                Alarm(PRINT, "Using Default IPC Connection\n");
            }
            else  {
                daemon_ptr = (struct sockaddr *)&unix_addr;
                sprintf(unix_addr.sun_path, "%s%hu", SPINES_UNIX_SOCKET_PATH, (unsigned short) spinesPort);
                Alarm(PRINT, "Using IPC on Port %s\n", unix_addr.sun_path);
            }
        } else {
            daemon_ptr = (struct sockaddr *)&unix_addr;
            strncpy(unix_addr.sun_path, Unix_domain_path, sizeof(unix_addr.sun_path));
            Alarm(PRINT, "Using IPC - custom path = %s\n", unix_addr.sun_path);
        }
#else /* ARCH_PC_WIN95 */
        if (gethostname_error == 1) {
            Alarm(EXIT, "Exiting... gethostbyname required, but error!\n");
        }
        daemon_ptr = (struct sockaddr *)&serv_addr;
        memcpy(&serv_addr.sin_addr, host_ptr->h_addr, sizeof(struct in_addr));
        Alarm(PRINT, "Using TCP/IP Connection - WIN Localhost\n");
#endif /* ARCH_PC_WIN95 */
    }

    if(spines_init(daemon_ptr) < 0) {
        Alarm(EXIT, "flooder_client: socket error\n");
    }
    
    spines_sk = spines_socket(PF_INET, SOCK_DGRAM, Protocol, daemon_ptr);
    if (spines_sk <= 0) {
        Alarm(EXIT, "spines_sk error..\n");
    }
    
    name.sin_family = AF_INET;
    name.sin_addr.s_addr = INADDR_ANY;
    name.sin_port = htons(recvPort);

    if(spines_bind(spines_sk, (struct sockaddr *)&name, sizeof(name) ) < 0) {
        Alarm(EXIT, "spines_bind error\n");
    }

    if(Group_Address != -1) {
        mreq.imr_multiaddr.s_addr = htonl(Group_Address);
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);

        if(spines_setsockopt(spines_sk, IPPROTO_IP, SPINES_ADD_MEMBERSHIP, (void *)&mreq, sizeof(mreq)) < 0) {
            Alarm(EXIT, "Mcast: problem in setsockopt to join multicast address");
        }
    }
   
    if (spines_setsockopt(spines_sk, 0, SPINES_DISJOINT_PATHS, (void *)&KPaths,
          sizeof(int16u)) < 0)
    {
        Alarm(EXIT, "error setting k-paths value = %d via setsockopt\n", KPaths);
    }

    Alarm(PRINT, "\r\nConnecting to spines daemon %s on port %d with protocol %d\n", 
            SP_IP, recvPort, Protocol);

    /***********************************************************/
    /*        SETTING UP OUTBOUND TRAFFIC (TO OUTSIDE)         */
    /***********************************************************/
    send_sk = socket(AF_INET, SOCK_DGRAM, 0);
    if (send_sk < 0) {
        Alarm(EXIT, "spines2port: couldn't open send socket");
    }
    
    for (i = 0; i < numNeighbors; i++) {
        connections[i].sin_family = AF_INET;
        connections[i].sin_addr.s_addr = htonl(Address[i]);
        connections[i].sin_port = htons(Port[i]);
    }
    
    FD_ZERO( &mask );
    FD_ZERO( &dummy_mask );
    FD_SET( spines_sk, &mask );

    for (i = 0; i < WINDOW_SIZE; i++)
        window[i].size = 0;

    /* Set up interval stats + signal handler for final report */
    intervalStatsInit(&Arrival_stats);
    intervalStatsInit(&Delivery_stats);
    signal(SIGINT, Final_Report);

    for(;;) {

        if (head == tail)
            timeout_ptr = NULL;
        else
        {
            timeout_ptr = &timeout;
            gettimeofday(&now, NULL);
            timeout = diffTime(window[ref % WINDOW_SIZE].timeout, now);
        }

        temp_mask = mask;
       
        ret = select( FD_SETSIZE, &temp_mask, &dummy_mask, &dummy_mask, timeout_ptr);
        
        gettimeofday(&now, NULL);
        now_ms = now.tv_sec * 1000.0;
        now_ms += now.tv_usec / 1000.0;
        
        if (ret > 0) {
            bytes = spines_recvfrom(spines_sk, buf, sizeof(buf), 0, NULL, 0);
            if (bytes <= 0) {
                Alarm(PRINT, "Disconnected by spines...\n");
                Final_Report(0);
            }
           
            recv_count++;
            recv_seq = ntohl(ps->seq_num);
            if (Arrival_Base_Time_Flag) {
                pkt_deliver = now;
                pkt_expire = now;
            } else {
                pkt_deliver.tv_sec  = ntohl(ps->origin_sec);
                pkt_deliver.tv_usec = ntohl(ps->origin_usec);
                pkt_expire = pkt_deliver;
            }
            pkt_deliver = addTime(pkt_deliver, wait_time);
            pkt_expire = addTime(pkt_expire, expire_time);

            /* Get pkt latency */
            then_ms  = ntohl(ps->origin_sec) * 1000.0; 
            then_ms += ntohl(ps->origin_usec) / 1000.0;
            elapsed_ms = now_ms - then_ms;

            /* Do reporting */
            if (Reporting_Interval > 0) {
                if (recvd_first_flag == 0) {
                    Interval_start_ms = now_ms;
                    Interval_target = Reporting_Interval;
                    Alarm(PRINT, "Set initial interval target %lu\n", Interval_target);
                    recvd_first_flag = 1;
                }
                if (recv_seq > Arrival_stats.high_seq) {
                    Arrival_stats.high_seq = recv_seq;
                }
                Arrival_stats.msgs++;
                Arrival_stats.bytes += bytes - sizeof(pkt_stats);

                Arrival_stats.oneway_ms += elapsed_ms;
                if (elapsed_ms < 0) {
                    /* Using last spot of array to catch anything with a
                     * negative elapsed time (due to clock sync issues) */
                    Arrival_stats.histogram[HIST_NUM_BUCKETS].count++;
                    trie_add(Arrival_stats.histogram[HIST_NUM_BUCKETS].paths_trie, ps->path, 8);
                } else if (elapsed_ms > HIST_BUCKET_SIZE * HIST_NUM_BUCKETS) {
                    Arrival_stats.histogram[HIST_NUM_BUCKETS - 1].count++;
                    trie_add(Arrival_stats.histogram[HIST_NUM_BUCKETS - 1].paths_trie, ps->path, 8);
                } else {
                    Arrival_stats.histogram[(int) (elapsed_ms / HIST_BUCKET_SIZE)].count++;
                    trie_add(Arrival_stats.histogram[(int) (elapsed_ms / HIST_BUCKET_SIZE)].paths_trie, ps->path, 8);
                }

                trie_add(Arrival_stats.total_paths, ps->path, 8);
            }
            else if (!Verbose_Print_Mode && Reporting_Interval == 0 && recv_count % 1000 == 0) {
                Alarm(PRINT, "%ld\t%d\t%4f\tpath: ", bytes-sizeof(pkt_stats),
                    recv_count, elapsed_ms);
                for (k = 0; k < 8; k++) {
                    if (ps->path[k] != 0)
                        Alarm(PRINT, "%d ", (int)ps->path[k]);
                    else
                        break;
                }
                Alarm(PRINT, "\r\n");
            }
            else if (Verbose_Print_Mode) {
                Alarm(PRINT, "%ld\t%lf\t%lf\t%lf\n", recv_seq, then_ms, now_ms, elapsed_ms);
            }
            
            /* First check if this packet is already expired */
            if (compTime(pkt_expire, now) == -1) {
                /* do nothing, ignore old packet */
                //Alarm(PRINT, "Received packet too late.\n");
            }
            else if (recv_seq < tail) {
                /* do nothing, ignore old packet */
                /*Alarm(PRINT, "Error case. Received unexpired but undeliverable packet: recv_seq = %llu tail = %llu\n",
                                recv_seq, tail); */
                //Alarm(PRINT, "recv'd pkt earlier than tail: recv_seq = %llu, tail = %llu\n", recv_seq, tail);
            }
            else if (recv_seq >= tail && recv_seq < head) {
                /* filling in a gap */
                window[recv_seq % WINDOW_SIZE].size = bytes;
                window[recv_seq % WINDOW_SIZE].timeout = pkt_deliver;
                memcpy(window[recv_seq % WINDOW_SIZE].buffer, buf, bytes);
                if (recv_seq < ref)
                    ref = recv_seq;
            }
            else if (recv_seq == head) {
                /* regular case, next expected pkt */
                window[recv_seq % WINDOW_SIZE].size = bytes;
                window[recv_seq % WINDOW_SIZE].timeout = pkt_deliver;
                memcpy(window[recv_seq % WINDOW_SIZE].buffer, buf, bytes);
                head++;
                if (head - tail == WINDOW_SIZE) {
                    Alarm(PRINT, "ERROR: window size is too small for this buffering time.\n");
                    Alarm(PRINT, "head = %llu, ref = %llu, tail = %llu\n", head, ref, tail);
                    Alarm(PRINT, "now = %lu.%lu, ref_TO = %lu.%lu, ref_size = %d\n", 
                                (unsigned long int)now.tv_sec,
                                (unsigned long int)now.tv_usec,
                                (unsigned long int)window[ref % WINDOW_SIZE].timeout.tv_sec,
                                (unsigned long int)window[ref % WINDOW_SIZE].timeout.tv_usec,
                                window[ref % WINDOW_SIZE].size);
                    window[tail % WINDOW_SIZE].size = 0;
                    if (ref == tail)
                        ref++;
                    tail++;
                    Alarm(PRINT, "Exiting\n");
                    Final_Report(0);
                }
            }
            else { /* recv_seq > head --> missed a pkt, generating gap */
                /* If we are really far ahead */
                if (recv_seq - tail >= WINDOW_SIZE) {
                    Alarm(PRINT, "Large gap detected: recv_seq = %llu, tail = %llu. Resetting window.\n",
                                    recv_seq, tail);
                    for (i = 0; i < WINDOW_SIZE; i++) {
                        window[i].size = 0;
                    }
                    ref  = recv_seq;
                    tail = recv_seq;
                    head = recv_seq; /* will be incremented once more below to become recv_seq + 1 */
                }
                window[recv_seq % WINDOW_SIZE].size = bytes;
                window[recv_seq % WINDOW_SIZE].timeout = pkt_deliver;
                memcpy(window[recv_seq % WINDOW_SIZE].buffer, buf, bytes);
                
                /* Only relevant for "small gaps", not the really far ahead case */
                while (head < recv_seq) {
                    window[head % WINDOW_SIZE].size = 0;
                    head++;
                }
                head++;
                while(window[ref % WINDOW_SIZE].size == 0 && ref < head)
                    ref++;
            }

        }

        if (window[ref % WINDOW_SIZE].size > 0 && compTime(window[ref % WINDOW_SIZE].timeout, now) <= 0)
        {
            for (i = 0; i < numNeighbors; i++) {
                ret = sendto(send_sk, window[ref % WINDOW_SIZE].buffer+sizeof(pkt_stats), 
                        window[ref % WINDOW_SIZE].size-sizeof(pkt_stats), 0, 
                        (struct sockaddr *)&connections[i], sizeof(struct sockaddr));
                if (ret != window[ref % WINDOW_SIZE].size-sizeof(pkt_stats)) {
                  Alarm(PRINT, "spines2port: error in writing when sending to connection %d...\n", i);
                  Final_Report(0);
                }
            }
            if (Reporting_Interval > 0) {
                if (ref > Interval_target) {
                    /* Print results */
                    intervalStatsPrint("ARRIVAL STATS:", &Arrival_stats, Interval_start_ms);
                    intervalStatsPrint("DELIVERY STATS:", &Delivery_stats, Interval_start_ms);
                    Alarm(PRINT, "-- Arrival Histogram (%u) --\n", ref);
                    histogramPrint(&Arrival_stats);
                    Alarm(PRINT, "-- Delivery Histogram (%u) --\n", ref);
                    histogramPrint(&Delivery_stats);
                    Alarm(PRINT, "\n");

                    /* Integer division to get highest multiple of the
                     * Reporting_Interval that we've passed so far. Set new
                     * target to be that + another Reporting_Interval */
                    Interval_target = (((ref - 1) / Reporting_Interval) + 1) * Reporting_Interval;

                    /* Reset interval statistics */
                    if (!Cummulative_Print_Mode) {
                        intervalStatsInit(&Arrival_stats);
                        intervalStatsInit(&Delivery_stats);
                        Interval_start_ms = now_ms;
                    }
                }

                /* Update delivery stats */
                if (ref > Delivery_stats.high_seq) {
                    Delivery_stats.high_seq = ref;
                }
                Delivery_stats.msgs++;
                Delivery_stats.bytes += window[ref % WINDOW_SIZE].size - sizeof(pkt_stats);
                deliver_ps = (pkt_stats*)window[ref % WINDOW_SIZE].buffer;
                then_ms  = ntohl(deliver_ps->origin_sec) * 1000.0; 
                then_ms += ntohl(deliver_ps->origin_usec) / 1000.0;
                elapsed_ms = now_ms - then_ms;
                Delivery_stats.oneway_ms += elapsed_ms;
                if (elapsed_ms < 0) {
                    /* Using last spot of array to catch anything with a
                     * negative elapsed time (due to clock sync issues) */
                    Delivery_stats.histogram[HIST_NUM_BUCKETS].count++;
                    trie_add(Delivery_stats.histogram[HIST_NUM_BUCKETS].paths_trie, deliver_ps->path, 8);
                }else if (elapsed_ms > HIST_BUCKET_SIZE * HIST_NUM_BUCKETS) {
                    Delivery_stats.histogram[HIST_NUM_BUCKETS - 1].count++;
                    trie_add(Delivery_stats.histogram[HIST_NUM_BUCKETS - 1].paths_trie, deliver_ps->path, 8);
                } else {
                    Delivery_stats.histogram[(int) (elapsed_ms / HIST_BUCKET_SIZE)].count++;
                    trie_add(Delivery_stats.histogram[(int) (elapsed_ms / HIST_BUCKET_SIZE)].paths_trie, deliver_ps->path, 8);
                }

                trie_add(Delivery_stats.total_paths, deliver_ps->path, 8);
            }
            window[ref % WINDOW_SIZE].size = 0;
            if (tail != ref)
            {
                //Alarm(PRINT, "Giving up, skipping packet(s).\n");
            }
            tail = ref + 1;
            while(window[ref % WINDOW_SIZE].size == 0 && ref < head)
                ref++;
        }
                
    }
    
    free(window);

    spines_close(spines_sk);
    return 0;
}

static void Final_Report(int signum)
{
    if (Reporting_Interval > 0) {
        Alarm(PRINT, "FINAL STATS\n\n");
        intervalStatsPrint("ARRIVAL STATS:", &Arrival_stats, Interval_start_ms);
        intervalStatsPrint("DELIVERY STATS:", &Delivery_stats, Interval_start_ms);
        Alarm(PRINT, "-- Arrival Histogram --\n");
        histogramPrint(&Arrival_stats);
        Alarm(PRINT, "-- Delivery Histogram --\n");
        histogramPrint(&Delivery_stats);
    }
    Alarm(PRINT, "\n");
    Alarm(EXIT, "");
}

static void intervalStatsPrint(const char *prefix, interval_stats *stats,
                               double interval_start_ms)
{
    struct timeval now;
    double now_ms;
    double avg_latency;

    gettimeofday(&now, NULL);
    now_ms = now.tv_sec * 1000.0;
    now_ms += now.tv_usec / 1000.0;

    if (stats->msgs > 0)
        avg_latency = stats->oneway_ms / stats->msgs;
    else
        avg_latency = 0;

    Alarm(PRINT, "%15s\t%lu\t%7.4lf Mbps\t%7.4lf ms\t%7ld msgs\t%lu bytes\n",
           prefix, stats->high_seq,
           (stats->bytes * 8.0) / (now_ms - interval_start_ms) / 1000.0,
           avg_latency, stats->msgs, stats->bytes);
}

static void histogramPrint(interval_stats *stats)
{
    int i;

    /* Print out counts */
    if (stats->histogram[HIST_NUM_BUCKETS].count != 0) {
        Alarm(PRINT, "\t[-1 - 0]\t%d\n", stats->histogram[HIST_NUM_BUCKETS].count);
    }

    for (i = 0; i < HIST_NUM_BUCKETS-1; i++)
    {
        if (stats->histogram[i].count != 0) {
            Alarm(PRINT, "\t[%d - %d]\t%d\n", i * HIST_BUCKET_SIZE,
                   (i + 1) * HIST_BUCKET_SIZE, stats->histogram[i].count);
        }
    }
    if (stats->histogram[HIST_NUM_BUCKETS-1].count != 0) {
        Alarm(PRINT, "\t[%d   + ]\t%d\n",
               (HIST_NUM_BUCKETS-1) * HIST_BUCKET_SIZE,
               stats->histogram[HIST_NUM_BUCKETS-1].count);
    }

    /* Print out paths */
    Alarm(PRINT, "\n");
    Alarm(PRINT, "   ** Paths **\n");
    if (stats->histogram[HIST_NUM_BUCKETS].count != 0) {
        Alarm(PRINT, "\t[-1 - 0]\n");
        trie_print(stats->histogram[i].paths_trie);
    }

    for (i = 0; i < HIST_NUM_BUCKETS-1; i++)
    {
        if (stats->histogram[i].count != 0) {
            Alarm(PRINT, "\t[%d - %d]\n", i * HIST_BUCKET_SIZE,
                   (i + 1) * HIST_BUCKET_SIZE);
            trie_print(stats->histogram[i].paths_trie);
        }
    }
    if (stats->histogram[HIST_NUM_BUCKETS-1].count != 0) {
        Alarm(PRINT, "\t[%d   + ]\n",
               (HIST_NUM_BUCKETS-1) * HIST_BUCKET_SIZE);
        trie_print(stats->histogram[HIST_NUM_BUCKETS-1].paths_trie);
    }

    /* Print out trie showing all paths taken */
    Alarm(PRINT, "\n");
    Alarm(PRINT, "   ** Total Paths Taken ** \n");
    trie_print(stats->total_paths);
    Alarm(PRINT, "\n");
}

static void intervalStatsInit(interval_stats *stats) {
    int i;

    stats->high_seq = 0;
    stats->oneway_ms = 0;
    stats->msgs = 0;
    stats->bytes = 0;

    for (i = 0; i <= HIST_NUM_BUCKETS; i++)
    {
        stats->histogram[i].count = 0;
        trie_clean(stats->histogram[i].paths_trie);
        stats->histogram[i].paths_trie = calloc(1, sizeof(trie_node));
    }

    trie_clean(stats->total_paths);
    stats->total_paths = calloc(1, sizeof(trie_node));
}

static struct timeval addTime( struct timeval t1, struct timeval t2 ) {
    
    struct timeval res;

	res.tv_sec  = t1.tv_sec  + t2.tv_sec;
	res.tv_usec = t1.tv_usec + t2.tv_usec;
	if ( res.tv_usec > 1000000 )
	{
		res.tv_usec -= 1000000;
		res.tv_sec++;
	}

	return res;
}

static struct timeval diffTime( struct timeval t1, struct timeval t2 ) {
    
    struct timeval diff;

    diff.tv_sec =  t1.tv_sec  - t2.tv_sec;
    diff.tv_usec = t1.tv_usec - t2.tv_usec;
    if ( diff.tv_usec < 0 ) {
        diff.tv_usec += 1000000;
        diff.tv_sec--;
    }
    if ( diff.tv_sec < 0 ) {
        diff.tv_sec = 0;
        diff.tv_usec = 0;
    }

    return diff;
}

static int compTime( struct timeval t1, struct timeval t2 ) {
	if	( t1.tv_sec  > t2.tv_sec  ) return (  1 );
	else if ( t1.tv_sec  < t2.tv_sec  ) return ( -1 );
	else if ( t1.tv_usec > t2.tv_usec ) return (  1 );
	else if ( t1.tv_usec < t2.tv_usec ) return ( -1 );
	else			      return (  0 );
}

static void trie_add(trie_node *root, unsigned char *path, int len)
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

static void trie_print_recurse(trie_node *root, unsigned char path[], int path_len)
{
    int i;
    int ret;
    char buf[100];
    int cpos = 0;

    if (root == NULL)
    {
        Alarm(EXIT, "Error in trie_print: root is NULL\n");
    }
    if (root->count > 0)
    {
        snprintf(buf+cpos, sizeof(buf)-cpos, "\t");
        cpos++;
        for(i = 0; i<path_len; i++) {
            ret = snprintf(buf+cpos, sizeof(buf)-cpos, "%d ", path[i]);
            if (ret <= 0) Alarm(EXIT, "trie_print: Error in snprintf");
            cpos += ret;
        }
        snprintf(buf+cpos, sizeof(buf)-cpos, ": %d\n", root->count);
        Alarm(PRINT, buf);
    }   
    for (i = 0; i<256; i++)
        if (root->child[i] != NULL)
        {
            path[path_len] = i;
            trie_print_recurse(root->child[i], path, path_len + 1);
        }
}

static void trie_print(trie_node *root)
{
    unsigned char temp_path[10];

    trie_print_recurse(root, temp_path, 0);
}

static void trie_clean_recurse(trie_node *root)
{
    int i;

    for (i = 0; i < 256; i++) {
        if (root->child[i] != NULL) {
            trie_clean_recurse(root->child[i]);
        }
    }

    for (i = 0; i < 256; i++) {
        if (root->child[i] != NULL) {
            free(root->child[i]);
        }
    }
}

static void trie_clean(trie_node *root)
{
    if (root == NULL) return;

    trie_clean_recurse(root);
    free(root);
}

static void Usage(int argc, char *argv[])
{
  int i1, i2, i3, i4, tmp;
  int ret, tmpPort;
  char ip_str[24];   /* large enough for X.X.X.X:YYYY ip address */
  char machine_name[80];
  char* portptr;
  struct hostent *p_h_ent;
  struct hostent h_ent;
  long host_num;

  /* Setting defaults */
  spinesPort            = DEFAULT_SPINES_PORT;
  recvPort              = DEFAULT_RECV_PORT;
  Protocol              = 0;
  numNeighbors          = 0;
  strcpy(SP_IP, "");
  strcpy(MCAST_IP, "");
  strcpy(Unix_domain_path, "");
  Group_Address          = -1;
  Cummulative_Print_Mode = 0;
  Verbose_Print_Mode = 0;
  wait_buffer            = DEFAULT_WAIT_BUFFER;
  expire_buffer          = -1;
  tmp                    = 0;
  KPaths                 = 0;   /* This is Flooding */
  Reporting_Interval     = DEFAULT_REPORTING_INTERVAL;
  Arrival_Base_Time_Flag = 0;

  while( --argc > 0 ) {
    argv++;

    if( !strncmp( *argv, "-p", 3 ) ){
      sscanf(argv[1], "%d", (int*)&spinesPort );
      argc--; argv++;
    } else if( !strncmp( *argv, "-ud", 4 ) ){
      sscanf(argv[1], "%s", Unix_domain_path);
      argc--; argv++;
    } else if( !strncmp( *argv, "-r", 3 ) ){
      sscanf(argv[1], "%d", (int*)&recvPort );
      argc--; argv++;
    } else if((!strncmp( *argv, "-a", 3)) && (argc > 1) && (numNeighbors < MAX_NEIGHBORS)) {
      sscanf(argv[1], "%24s", ip_str );
      ret = sscanf( ip_str, "%d.%d.%d.%d:%d", &i1, &i2, &i3, &i4, &tmpPort);
      if (ret == 5) {
        Address[numNeighbors] = ( (i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4 );
      } else {
        portptr = strchr(ip_str, ':');
        sscanf(portptr+1, "%d", (int*)&tmpPort);
        *portptr = '\0';
        p_h_ent = gethostbyname(ip_str);
        if (p_h_ent == NULL) {
            Alarm(EXIT, "gethostbyname error: %s\n", ip_str);
        }
        memcpy(&h_ent, p_h_ent, sizeof(h_ent));
        memcpy(&host_num, h_ent.h_addr_list[0], sizeof(host_num));
        Address[numNeighbors] = ntohl(host_num);
      }
      if (tmpPort < 0 || tmp > 65535) {
        Alarm(EXIT, "Error: Bad Port Specified: %d\n", tmpPort);
      }
      Port[numNeighbors] = tmpPort;
      numNeighbors++; argc--; argv++;
    } else if( !strncmp( *argv, "-k", 3 ) ){
      sscanf(argv[1], "%hu", (int16u*)&KPaths );
      argc--; argv++;
    } else if( !strncmp( *argv, "-j", 3 ) ){
      sscanf(argv[1], "%80s", MCAST_IP );
      sscanf(MCAST_IP ,"%d.%d.%d.%d",&i1, &i2, &i3, &i4);
      Group_Address = ( (i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4 );
      argc--; argv++;
    } else if( !strncmp( *argv, "-o", 3 ) ){
      sscanf(argv[1], "%80s", SP_IP );
      argc--; argv++;
    } else if( !strncmp( *argv, "-c", 3 ) ){
      Cummulative_Print_Mode = 1;
    } else if( !strncmp( *argv, "-v", 3 ) ){
      Verbose_Print_Mode = 1;
    } else if( !strncmp( *argv, "-t", 3 ) ){
      Arrival_Base_Time_Flag = 1;
    } else if( !strncmp( *argv, "-i", 3 ) ){
      sscanf(argv[1], "%d", (int*)&Reporting_Interval );
      argc--; argv++;
      if (Reporting_Interval < 0)
        Alarm(EXIT, "Invalid printing interval specified: %d. Must be >= 0!\r\n", Reporting_Interval);
    } else if( !strncmp( *argv, "-w", 3 ) ){
      sscanf(argv[1], "%lf", &wait_buffer );
      argc--; argv++;
      if (wait_buffer < 0)
        Alarm(EXIT, "Invalid wait time specified: %d. Must be between >= 0!\r\n", wait_buffer);
    } else if( !strncmp( *argv, "-x", 3 ) ){
      sscanf(argv[1], "%lf", &expire_buffer );
      argc--; argv++;
      if (expire_buffer < 0)
        Alarm(EXIT, "Invalid expire timeout specified: %d. Must be >= 0!\r\n", expire_buffer);
    } else if( !strncmp( *argv, "-P", 2 ) ){
      if(sscanf(argv[1], "%d", (int*)&tmp ) < 1 || (tmp < 0) || (tmp > 2 && tmp != 8)) {
        Alarm(EXIT, "Bad Protocol %d specified through -P option!\r\n", tmp);
      }
      Protocol |= tmp;
      argc--; argv++;
    } else if ( !strncmp( *argv, "-D", 3 ) ) {
        if(sscanf(argv[1], "%d", (int*)&tmp ) < 1 || (tmp < 0) || (tmp > 3)) { /* dtflood (1,2), source-based (3)*/
            Alarm(EXIT, "Bad Dissemination %d specified through -D option!\r\n", tmp);
        }
        Protocol |= (tmp << ROUTING_BITS_SHIFT);
        argc--; argv++;
    } else {
        Alarm(PRINT,  "Usage: spines2port\n");
        Alarm(PRINT, "\t[-o <address>    ] : address where spines runs, default localhost\n");
        Alarm(PRINT, "\t[-p <port number>] : port where spines runs, default is %d\n", DEFAULT_SPINES_PORT);
        Alarm(PRINT, "\t[-ud <path>      ] : unix domain socket path to connect to, default is /tmp/spines<port>\n");
        Alarm(PRINT, "\t[-r <port number>] : to receive packets on, default is %d\n", DEFAULT_RECV_PORT);
        Alarm(PRINT, "\t[-a <addr>:<port>] : address:port to send packets to, default is local machine and port %d\n", DEFAULT_SEND_PORT);
        Alarm(PRINT, "\t[-j <mcast addr> ] : multicast address to join\n");
        Alarm(PRINT, "\t[-w <millisecond>] : time to wait before delivering a packet (>= 0 ms)\n");
        Alarm(PRINT, "\t[-x <millisecond>] : length of time to wait for a missing packet before skipping (>= 0 ms)\n");
        Alarm(PRINT, "\t[-P <0, 1, 2, 8> ] : overlay links (0: UDP; 1: Reliable; 2: Realtime; 8: Intrusion-Tolerant Link)\n");
	    Alarm(PRINT, "\t[-D <0, 1, 2, 3> ] : dissemination alg (0: Min Weight; 1: IT Priority Flood; 2: IT Reliable Flood, 3: Source-Based Routing)\n");
        Alarm(PRINT, "\t[-i <interval>   ] : print stats every <interval> msgs, default %d\n", DEFAULT_REPORTING_INTERVAL);
        Alarm(PRINT, "\t[-t              ] : calculate wait time based on arrival time (rather than send time)\n");
        Alarm(PRINT, "\t[-c              ] : print in cummulative mode (don't reset stats every interval)\n");
        Alarm(PRINT, "\t[-v              ] : report every received packet\n");
        Alarm(EXIT, "\n");
    }
  }

  /* If expire buffer not specified, set it to match wait buffer */
  if (expire_buffer == -1) {
    expire_buffer = wait_buffer;
  }

  if (expire_buffer < wait_buffer) {
    Alarm(EXIT, "Error: expire_buffer %lf < wait_buffer %lf! Packets should not "
                "expire before they can be delivered...\n", expire_buffer,
                wait_buffer);
  }

  if (numNeighbors == 0) {
    Alarm(PRINT, "No connections (destination addresses) were specified, setting default (local machine and port %d)...\n", DEFAULT_SEND_PORT);
    gethostname(machine_name,sizeof(machine_name));
    p_h_ent = gethostbyname(machine_name);
    if (p_h_ent == NULL) {
        Alarm(EXIT, "gethostbyname error: %s\n", machine_name);
    }
    memcpy(&h_ent, p_h_ent, sizeof(h_ent));
    memcpy(&host_num, h_ent.h_addr_list[0], sizeof(host_num));
    Address[numNeighbors] = ntohl(host_num);
    Port[numNeighbors] = DEFAULT_SEND_PORT;
    numNeighbors = 1;
  }

  Alarm_enable_timestamp("%a %d %b %H:%M:%S %Y");
}
