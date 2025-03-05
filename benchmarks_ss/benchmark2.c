/*
 * Spire.
 *
 * The contents of this file are subject to the Spire Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.dsn.jhu.edu/spire/LICENSE.txt
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * Spire is developed at the Distributed Systems and Networks Lab,
 * Johns Hopkins University and the Resilient Systems and Societies Lab,
 * University of Pittsburgh.
 *
 * Creators:
 *   Yair Amir            yairamir@cs.jhu.edu
 *   Trevor Aron          taron1@cs.jhu.edu
 *   Amy Babay            babay@pitt.edu
 *   Thomas Tantillo      tantillo@cs.jhu.edu 
 *   Sahiti Bommareddy    sahiti@cs.jhu.edu 
 *   Maher Khan           maherkhan@pitt.edu 
 *
 * Major Contributors:
 *   Marco Platania       Contributions to architecture design 
 *   Daniel Qian          Contributions to Trip Master and IDS
 *
 * Contributors:
 *   Samuel Beckley       Contributions to HMIs
 *
 * Copyright (c) 2017-2025 Johns Hopkins University.
 * All rights reserved.
 *
 * Partial funding for Spire research was provided by the Defense Advanced
 * Research Projects Agency (DARPA), the Department of Defense (DoD), and the
 * Department of Energy (DoE).
 * Spire is not necessarily endorsed by DARPA, the DoD or the DoE.
 *
 */


#include "def.h"
#include "ss_net_wrapper.h"
#include "packets.h"
#include "ss_openssl_rsa.h"

#include "spu_alarm.h"
#include "spu_events.h"
#include "spines_lib.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <time.h>



#define NUM_BUCKETS 100
#define BUCKET_SIZE 100
#define TIME_LEN 20
typedef char timestr[TIME_LEN];

static uint64_t trips[NUM_REPLICAS+1];
static uint64_t closes[NUM_REPLICAS+1];
static tm_msg *curr_b;
static int      s,count,m,ack_count,total,gt_count;
static uint64_t dts;
static int      b_state;
static sv_msg payload;
struct timeval tr_start,tr_end;
static uint64_t *latencies;
//static uint64_t *rdtsc_diff;
//static uint64_t rdtsc1,rdtsc2;
static struct sockaddr_in send_addr,name;
sp_time delta;
static timestr *scatter_time;



static void usage(int argc, char *argv[]);
static void print_stats();
static int setup_mcast();
static void send_simple_sv();
static void print_relay_msgs(uint64_t mess_arr[]);
static bool count_relay_msgs(uint64_t mess_arr[]);
static void Handle_Recovery_Query(tm_msg *mess);
static void Handle_Relay_Trip(tm_msg *mess);
static void Handle_Relay_Close(tm_msg *mess);
static void Handle_Ext_Spines_Msg();
static void PROXY_Startup();
static void PROXY_Send_Ack();
static void print_notice();

uint64_t rdtsc(){
        unsigned int lo,hi;
            __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
                return ((uint64_t)hi << 32) | lo;
}
 

int main(int argc, char* argv[])
{
    int     ret;
    char *  sp_addr = SPINES_PROXY_ADDR;


    setlinebuf(stdout);
    Alarm_enable_timestamp_high_res("%m/%d/%y %H:%M:%S");
    Alarm_set_types(PRINT);
    //Alarm_set_types(STATUS);
    //Alarm_set_types(DEBUG);
    
    /* TODO:Initialize crypto stuff */
    OPENSSL_RSA_Init();
    OPENSSL_RSA_Read_Keys(1, RSA_CLIENT, "../trip_master_v2/tm_keys");
    Alarm(DEBUG, "Dest Proxy 2.0 read keys\n");

    usage(argc,argv);
    print_notice();

    count=0;
    b_state=-1;

    /*Initiallize mcast port and set up mcast address*/
    m=setup_mcast();
    //TODO: error handling

    /* Initialize network */
    s = Spines_Sock(sp_addr, SS_SPINES_EXT_PORT, SPINES_PRIORITY, TM_PROXY_PORT);

    if (s < 0) {
        Alarm(EXIT,"dst_proxy: socket\n");
	//TODO: Try reconnect
    }
    
    //On start, gather XCBR status
    while(b_state==-1)
    	PROXY_Startup();

    //TODO: I think we should send breaker state after restart
    PROXY_Send_Ack();

    E_init();
    E_queue(send_simple_sv,NULL,NULL,delta);//Queue first event to happen later
    E_attach_fd(s,READ_FD,Handle_Ext_Spines_Msg,NULL,NULL,MEDIUM_PRIORITY);
    E_handle_events();
}
static int setup_mcast()
{
    /* Setup socket for sending */
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        Alarm(EXIT,"Error setting up Mcast socket\n");
    }
    memset(&name,0,sizeof(name));
    memset(&send_addr,0,sizeof(send_addr));
    name.sin_family = AF_INET;
    name.sin_addr.s_addr = htonl(SPINES_PROXY_ADDR);
    name.sin_port = htons(EMULATOR_MCAST_PORT);

    if(bind(s, (struct sockaddr *)&name, sizeof(name) ) < 0) {
          Alarm(EXIT, "Error binding mcast port\n");
        }
    /*set up sender address*/
    send_addr.sin_family = AF_INET;
    send_addr.sin_addr.s_addr = htonl(EMULATOR_MCAST_ADDR);
    send_addr.sin_port = htons(EMULATOR_MCAST_PORT);
    /*sv_msg setup*/
    memset(&payload,0,sizeof(payload));
    payload.type=SV_SIMPLE;

    return s;

}
static void PROXY_Startup()
{
    // TODO query braker until response is received, for now just initialize to closed
    
    sp_time now;
    uint64_t   now_msec;
    uint32_t    m_id;
    int     mess_type,i;

    memset(trips, 0, sizeof(trips));
    memset(closes, 0, sizeof(closes));

    now=E_get_time(); 
    now_msec = now.sec * 1000 + now.usec / 1000;
    dts = (now_msec / DTS_INTERVAL) * DTS_INTERVAL;
    //TODO: Read from CB
    b_state = STATE_CLOSE;
    mess_type = (b_state == STATE_CLOSE) ? SIGNED_CLOSE_ACK : SIGNED_TRIP_ACK;
    m_id = NUM_REPLICAS+1; // TODO do we want a special proxy id?
    curr_b=PKT_Construct_TM_Message(mess_type,m_id,dts,sizeof(sig_payload));
    OPENSSL_RSA_Sign(((byte*)curr_b),sizeof(tm_msg),(byte*)(curr_b+1));

    Alarm(PRINT, "Initialized with state %s at dts %ld\n",
            b_state == STATE_CLOSE ? "CLOSED" : "TRIPPED", dts);
}

static void send_simple_sv()
{
    sp_time now;
    int i,j,ret,trip;
    time_t    time_now;
    struct tm *tm_now;
    timestr tstr;

    if(count==0)
        Alarm(PRINT,"*******Start SV msgs**********\n");

    if(count==total){
        Alarm(DEBUG,"count=%d, total=%d, acks_count=%d\n",count,total,ack_count);
        print_stats();
    }

    if(b_state==STATE_TRIP){
        trip=0;
    }else{
        trip=1;
    }


    for (i = 0; i < NUM_REPLICAS; i++) {
                    payload.delay_ms[i] = 0;
                    payload.trip[i] = trip;
                }

        now = E_get_time();
        payload.time_ms = now.sec * 1000 + now.usec / 1000;
        ret = sendto(m, &payload, sizeof(payload), 0, (struct sockaddr *)&send_addr, sizeof(send_addr));

        if (ret < 0){
                Alarm(EXIT," SV error sending\n");
        }
        if(ret<sizeof(payload)){
                Alarm(PRINT,"Wrong size of msg sent\n");
        }
        count+=1;
        gettimeofday(&tr_start, NULL);
        time_now=tr_start.tv_sec;
        tm_now = localtime(&time_now);
        memset(tstr,0,TIME_LEN);
        strftime (tstr, TIME_LEN, "%m/%d/%y %H:%M:%S",tm_now);

        strcpy(scatter_time[count],tstr);
        //rdtsc1=rdtsc();

        Alarm(DEBUG,"Sent [%d]=%d\n",count,trip);
        if(count%PRINT_PROGRESS==0){
            Alarm(STATUS,"Sent [%d]\n",count);
    }


}

static void Handle_Ext_Spines_Msg()
{
    struct sockaddr_in  from_addr;
    socklen_t           from_len = sizeof(from_addr);  
    byte                buff[SPINES_MAX_SIZE];
    byte                digest[DIGEST_SIZE];
    tm_msg *            mess;
    sig_payload *       sign;
    int                 ret;
    sp_time             now;
    uint64_t            now_msec,now_dts;
    //receive spines message
    now=E_get_time();
    now_msec=now.sec * 1000 + now.usec / 1000;
    now_dts = (now_msec / DTS_INTERVAL) * DTS_INTERVAL;
    ret = spines_recvfrom(s, buff, MAX_LEN, 0, (struct sockaddr *) &from_addr, &from_len);

    //Check message size
    if(ret<0){
	    Alarm(PRINT, "Spines recvfrom ret <0\n");
	    return;
    }
    if (ret < sizeof(tm_msg)){
    	Alarm(PRINT,"Msg size less than tm_msg size\n");
	return;
    }
    mess = (tm_msg *) buff;
    if (ret < (sizeof(tm_msg)+mess->len)){
    	Alarm(PRINT,"Msg size less than (tm_msg + mess->len) size\n");
	return;
    }
    //Check Identity of sender
    if (mess->m_id < 1 || mess->m_id > NUM_REPLICAS){
    	Alarm(PRINT,"mess->m_id error\n");
	    return;
    }
    if (from_addr.sin_addr.s_addr != inet_addr(Relay_Ext_Addrs[mess->m_id-1])) {
    	Alarm(PRINT, "Machine id %d does not match address %s!\n", mess->m_id, Relay_Ext_Addrs[mess->m_id - 1]);
	    return;
    }
    //assert(mess->type == RELAY_TRIP || mess->type == RELAY_CLOSE);
    if(mess->type != RELAY_TRIP && mess->type != RELAY_CLOSE && mess->type!=RECOVERY_QUERY){
        Alarm(PRINT," Not a Relay Trip or Close  or Recovery message \n");
        return;
    }
    //Check that it is not older than previous b message
     if (mess->dts < dts){
         Alarm(DEBUG, "Old message %d type from %d (dts = %ld, b.dts = %ld) ignoring\n",mess->type ,mess->m_id,mess->dts, dts);
         return;
     }
     //accept messages with dts-1 or dts or dts+1
    if(mess->dts>(now_dts+DTS_INTERVAL)){
    //if(mess->dts<(now_dts-(2*DTS_INTERVAL)) || mess->dts>(now_dts+DTS_INTERVAL)){
         Alarm(DEBUG, "Sync Issues** message from %d (dts = %ld, now_dts = %ld) ignoring\n", mess->m_id,mess->dts, now_dts);
         return;

    }

    //Check Signature
    sign=(sig_payload *)(mess+1);
    ret=OPENSSL_RSA_Verify(mess,sizeof(tm_msg),sign,mess->m_id,RSA_SERVER);
    if(!ret){
        Alarm(DEBUG,"RSA Verify failed for ack\n");
        return;
    }
    Alarm(DEBUG, "Valid %s, from %d with dts=%lu , now_dts=%lu\n",(mess->type == RELAY_TRIP?"RELAY_TRIP":"RELAY_CLOSE"),mess->m_id,mess->dts,now_dts);

    //Handle each type of possible messages
    switch(mess->type){
    	case RECOVERY_QUERY:
		Handle_Recovery_Query(mess);
		break;
	case RELAY_TRIP:
		Handle_Relay_Trip(mess);
		break;

	case RELAY_CLOSE:
		Handle_Relay_Close(mess);
		break;
	default:
		Alarm(PRINT, "Invalid type %d, ignoring\n", mess->type);
		return;
    }
	
}


static void Handle_Recovery_Query(tm_msg *mess)
{
	Alarm(DEBUG,"Receive RECOVERY_QUERY from %d!\n",mess->m_id);
	PROXY_Send_Ack();
}

static void Handle_Relay_Trip(tm_msg *mess)
{
    sp_time now;
    uint64_t   now_msec,lat;
    sig_payload *sign;
    struct timeval tr_time;

    //If already tripped, just resend ack
    if(b_state==STATE_TRIP){
        PROXY_Send_Ack();
        return;
    }
    //store
    trips[mess->m_id]=mess->dts;

    //count
    if (!count_relay_msgs(trips)){
        Alarm(DEBUG,"Not enough trips\n");
        return;
    }
    //we have sufficient trips to issue Breaker trip
    //TODO: CB trip issue and get status change masg
    now=E_get_time();
    now_msec = now.sec * 1000 + now.usec / 1000;
    dts = (now_msec / DTS_INTERVAL) * DTS_INTERVAL;
    b_state = STATE_TRIP;
    //benchmark time
    gettimeofday(&tr_end, NULL);
    //rdtsc2=rdtsc();
    //Alarm(DEBUG,"rdtsc diff = %llu\n",rdtsc2-rdtsc1);
    tr_time=diffTime(tr_end,tr_start);
    Alarm(DEBUG,"Difftime[%lu]= %ld.%06ld\n",count,tr_time.tv_sec,tr_time.tv_usec);
    lat = (1000000*tr_time.tv_sec) + tr_time.tv_usec;
    if(lat>4000){
        gt_count+=1;
        Alarm(PRINT,"******gt 4msec so far=%d\n",gt_count);
    }
    latencies[count]=lat;
    //rdtsc_diff[count]=rdtsc2-rdtsc1;
    ack_count+=1;
    //Update curr_b message and resign it
    curr_b->type = SIGNED_TRIP_ACK;
    curr_b->dts=dts;
    OPENSSL_RSA_Sign(((byte*)curr_b),sizeof(tm_msg),(byte*)(curr_b+1));
    PROXY_Send_Ack();
    memset(trips, 0, sizeof(trips));
    memset(closes, 0, sizeof(closes));
    //send next sv
    E_queue(send_simple_sv,NULL,NULL,delta);
    return;

}


static void Handle_Relay_Close(tm_msg *mess)
{
    sp_time now;
    uint64_t   now_msec;
    sig_payload *sign;
    struct timeval tr_time;
    uint64_t lat;

    //If already closed, just resend ack
    if(b_state==STATE_CLOSE){
        PROXY_Send_Ack();
        return;
    }
    //store
    closes[mess->m_id]=mess->dts;

    //count
    if (!count_relay_msgs(closes)){
        Alarm(DEBUG,"Not enough trips\n");
        return;
    }
    //we have sufficient trips to issue Breaker trip
    //TODO: CB trip issue and get status change masg
    now=E_get_time();
    now_msec = now.sec * 1000 + now.usec / 1000;
    dts = (now_msec / DTS_INTERVAL) * DTS_INTERVAL;
    b_state = STATE_CLOSE;
    //benchmark time
    gettimeofday(&tr_end, NULL);
    //rdtsc2=rdtsc();
    //Alarm(DEBUG,"rdtsc diff = %llu\n",rdtsc2-rdtsc1);
    tr_time=diffTime(tr_end,tr_start);
    Alarm(DEBUG,"Difftime[%lu]= %ld.%06ld\n",count,tr_time.tv_sec,tr_time.tv_usec);
    lat = (1000000*tr_time.tv_sec) + tr_time.tv_usec;
    if(lat>4000){
        gt_count+=1;
        Alarm(PRINT,"******gt 4msec so far=%d\n",gt_count);
    }
    latencies[count]=lat;
    //rdtsc_diff[count]=rdtsc2-rdtsc1;
    ack_count+=1;
    //Update curr_b message and resign it
    curr_b->type = SIGNED_CLOSE_ACK;
    curr_b->dts=dts;
    OPENSSL_RSA_Sign(((byte*)curr_b),sizeof(tm_msg),(byte*)(curr_b+1));
    PROXY_Send_Ack();
    memset(trips, 0, sizeof(trips));
    memset(closes, 0, sizeof(closes));
    //send next sv
    E_queue(send_simple_sv,NULL,NULL,delta);
    return;

}


static void print_relay_msgs(uint64_t mess_arr[]){
    int i;    
    for(i=1;i<=NUM_REPLICAS;i++){
        if(mess_arr[i]==0)
            continue;
        Alarm(DEBUG,"i=%d,dts=%lu\n",i,mess_arr[i]);
    }
}


static bool count_relay_msgs(uint64_t mess_arr[])
{
    int i,j,msg_count1, msg_count2;
    uint64_t curr_dts,curr_dts_nxt;


    for(i=1;i<NUM_REPLICAS;i++){
        if(mess_arr[i]==0)
            continue;
        curr_dts=mess_arr[i];
        curr_dts_nxt=mess_arr[i]+DTS_INTERVAL;
        
        msg_count1,msg_count2=1;

        for(j=i+1;j<=NUM_REPLICAS;j++){
            if(mess_arr[j]==0)
                continue;
            if(mess_arr[j]==curr_dts || (mess_arr[j]+DTS_INTERVAL)==curr_dts){
                msg_count1+=1;
                if(msg_count1==2){
                    print_relay_msgs(mess_arr);
                    return true;
                }
            }
            if(mess_arr[j]==curr_dts_nxt || (mess_arr[j]+DTS_INTERVAL)==curr_dts_nxt){
                msg_count2+=1;
                if(msg_count2==2){
                    print_relay_msgs(mess_arr);
                    return true;
                }
            }
        }
    }
    return false;
}


static void PROXY_Send_Ack()
{
    int i,ret;
    struct sockaddr_in addr;


    addr.sin_family = AF_INET;
    addr.sin_port = htons(TM_PROXY_PORT);

    for (i = 0; i < NUM_REPLICAS; i++) {
        addr.sin_addr.s_addr = inet_addr(Relay_Ext_Addrs[i]);
        
        ret = spines_sendto(s, curr_b, (sizeof(tm_msg)+curr_b->len),
            0, (struct sockaddr *) &addr, sizeof(addr));
        
        if (ret < 0) {
            perror("sendto: \n");
            // TODO attempt to reconnect?
        }
    }

    Alarm(DEBUG,"Sent type=%s, m_id=%u,dts=%lu,len=%u\n",curr_b->type == SIGNED_CLOSE_ACK ? "CLOSE ACK":"TRIP ACK",curr_b->m_id,curr_b->dts,curr_b->len);
}

static void print_stats()
{
    int               Histogram[NUM_BUCKETS];
    int index,i,j;
    double            Sum_Lat, Count_Lat, Min_Lat, Max_Lat,count_4;

    Alarm(PRINT,"*******STATS***********\n");
    Alarm(PRINT,"SV total=%d, count=%d, ack_count=%d\n",total,count,ack_count);
    Alarm(PRINT,"*******STATS***********\n");
    Alarm(PRINT,"count \t latency \t rdtsc diff\n");

    memset(Histogram, 0, sizeof(int) * NUM_BUCKETS);
    Sum_Lat = 0;
    Count_Lat = 0;
    Min_Lat =99999;
    Max_Lat = 0;
    count_4=0;

    for(j=1;j<=count;j++){
        printf("%s :  [%07d]: %lu \n",scatter_time[j],j,latencies[j]);
        Sum_Lat += latencies[j];
        Count_Lat++;
        if(latencies[j]<Min_Lat)
            Min_Lat=latencies[j];
        if(latencies[j]>Max_Lat)
            Max_Lat=latencies[j];
        if(latencies[j]>4000)
            count_4+=1;
        index = latencies[j]  / BUCKET_SIZE;
        Histogram[index]++;
    }
    for (i = 0; i < NUM_BUCKETS; i++)
            printf("\t[%3u - %3u]:\t%u\n", i*BUCKET_SIZE, (i+1)*BUCKET_SIZE, Histogram[i]);
    printf("Min / Average / Max Latency = %f usec / %f usec / %f usec\n",
                Min_Lat,(Sum_Lat / Count_Lat),  Max_Lat);
    printf("Count of transactions > 4msec= %f\n",count_4);
    exit(1);


}

static void print_notice()
{
  Alarm( PRINT, "/==================================================================================\\\n");
  Alarm( PRINT, "| Spire                                                                             |\n");
  Alarm( PRINT, "| Copyright (c) 2017-2025 Johns Hopkins University                                  |\n");
  Alarm( PRINT, "| All rights reserved.                                                              |\n");
  Alarm( PRINT, "|                                                                                   |\n");
  Alarm( PRINT, "| Spire is licensed under the Spire Open-Source License.                            |\n");
  Alarm( PRINT, "| You may only use this software in compliance with the License.                    |\n");
  Alarm( PRINT, "| A copy of the License can be found at http://www.dsn.jhu.edu/spire/LICENSE.txt    |\n");
  Alarm( PRINT, "|                                                                                   |\n");
  Alarm( PRINT, "| Creators:                                                                         |\n");
  Alarm( PRINT, "|    Yair Amir                 yairamir@cs.jhu.edu                                  |\n");
  Alarm( PRINT, "|    Trevor Aron               taron1@cs.jhu.edu                                    |\n");
  Alarm( PRINT, "|    Amy Babay                 babay@pitt.edu                                       |\n");
  Alarm( PRINT, "|    Thomas Tantillo           tantillo@cs.jhu.edu                                  |\n");
  Alarm( PRINT, "|    Sahiti Bommareddy         sahiti@cs.jhu.edu                                    |\n");
  Alarm( PRINT, "|                                                                                   |\n");
  Alarm( PRINT, "| Major Contributors:                                                               |\n");
  Alarm( PRINT, "|    Marco Platania            Contributions to architecture design                 |\n");
  Alarm( PRINT, "|    Daniel Qian               Contributions to Trip Master and IDS                 |\n");
  Alarm( PRINT, "|                                                                                   |\n");
  Alarm( PRINT, "| WWW:     www.dsn.jhu/spire   www.dsn.jhu.edu                                      |\n");
  Alarm( PRINT, "| Contact: spire@dsn.jhu.edu                                                        |\n");
  Alarm( PRINT, "|                                                                                   |\n");
  Alarm( PRINT, "| Version 2.2, Built March 5, 2025         	                                     |\n");
  Alarm( PRINT, "|                                                                                   |\n");
  Alarm( PRINT, "| This product uses software developed by Spread Concepts LLC for use               |\n");
  Alarm( PRINT, "| in the Spread toolkit. For more information about Spread,                         |\n");
  Alarm( PRINT, "| see http://www.spread.org                                                         |\n");
  Alarm( PRINT, "\\=================================================================================/\n\n");
}

static void usage(int argc, char *argv[])
{
    total=10;
    ack_count=0;
    delta.sec=5;
    delta.usec=0;
    gt_count=0;
    
    while( --argc > 0 ) {
        argv++;
        if( !strncmp( *argv, "-n", 2 ) ){
            sscanf(argv[1], "%d", &total);
            Alarm(DEBUG,"Total=%d\n",total);
            latencies=malloc((total+1) * sizeof(*latencies));
            memset(latencies,0,(total+1) * sizeof(*latencies));
            //rdtsc_diff=malloc((total+1) * sizeof(*rdtsc_diff));
            scatter_time=malloc((total+1)*sizeof(timestr));
            argc--; argv++;
            Alarm(PRINT,"Sending total %d SV msgs \n",total);
        }else{
          Alarm(PRINT,"Usage: benchmark \n%s\n%s\n",
                  "\t[-n <int count>]: Number of events to emulate, default 10");
          exit(0);
        }
    }
}
