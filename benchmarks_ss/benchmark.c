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
#include "ss_tc_wrapper.h"
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


static int      s,m,count,total,trip,so_far;
static uint64_t dts; //store last final's dts
static int      b_state; //store breaker state
static struct sockaddr_in send_addr,name; //for multicast
static sv_msg payload;
struct timeval tr_start,tr_end;
sp_time delta;
static uint64_t *latencies;
//static uint64_t *rdtsc_diff;
//static uint64_t rdtsc1,rdtsc2;
static timestr *scatter_time;

static void print_notice();
static void usage(int argc, char **argv);
static int setup_mcast();
static void print_stats();
static void send_simple_sv();
static bool Validate_Final_Msg(tm_msg *mess);
static void Handle_Recovery_Query(tm_msg *mess);
static void Handle_Signed_Trip(tm_msg *mess);
static void Handle_Signed_Close(tm_msg *mess);
static void Handle_Ext_Spines_Msg();
static void PROXY_Startup();
static void PROXY_Send_Ack();

uint64_t rdtsc(){
        unsigned int lo,hi;
            __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
                return ((uint64_t)hi << 32) | lo;
}

int main(int argc, char** argv)
{
    int     ret;
    char *  sp_addr = SPINES_PROXY_ADDR;
    sp_time delay;


    setlinebuf(stdout);
    Alarm_enable_timestamp_high_res("%m/%d/%y %H:%M:%S");
    Alarm_set_types(PRINT);
    //Alarm_set_types(PRINT|STATUS);
    //Alarm_set_types(STATUS);
    //Alarm_set_types(PRINT|DEBUG|STATUS);
    usage(argc, argv);
    print_notice();
    
    /* Initialize crypto stuff */
    TC_Read_Public_Key("../trip_master/tm_keys"); // TODO fix this
    OPENSSL_RSA_Init();

    count=0;
    b_state=-1;

    /*Initiallize mcast port and set up mcast address*/
    m=setup_mcast();
    
    /* Initialize Spines network */
    s = Spines_Sock(sp_addr, SS_SPINES_EXT_PORT, SPINES_PRIORITY, TM_PROXY_PORT);

    if (s < 0) {
        Alarm(EXIT,"Spines socket error\n");
	//TODO: Try reconnect
    }
    
    //On start, gather XCBR status
    while(b_state==-1)
    	PROXY_Startup();
    //I think we should send breaker state after restart
    PROXY_Send_Ack();

    E_init();
    Alarm(PRINT,"Start SV msgs\n");

    E_queue(send_simple_sv,NULL,NULL,delta);//Queue first event to happen later
    E_attach_fd(s,READ_FD,Handle_Ext_Spines_Msg,NULL,NULL,MEDIUM_PRIORITY);
    E_handle_events();
}

static void PROXY_Startup()
{
    // TODO query braker until response is received, for now just initialize to closed
    
    sp_time now;

    now=E_get_time();
    //dts=(curr_time_in_msec / DTS_INTERVAL) * DTS_INTERVAL
    dts = ((now.sec * 1000 + now.usec / 1000) / DTS_INTERVAL) * DTS_INTERVAL;
    //b_state = STATE_TRIP;
    b_state = STATE_CLOSE;

    Alarm(PRINT, "Initialized with state %s at dts %ld\n",
            b_state == STATE_CLOSE ? "CLOSED" : "TRIPPED", dts);
}

static void Handle_Ext_Spines_Msg()
{
    struct sockaddr_in  from_addr;
    socklen_t           from_len = sizeof(from_addr);  
    byte                buff[SPINES_MAX_SIZE];
    byte                digest[DIGEST_SIZE];
    tm_msg *            mess;
    int ret;
    //receive spines message
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

    //Handle each type of possible messages
    switch(mess->type){
    	case RECOVERY_QUERY:
		Handle_Recovery_Query(mess);
		break;
	case SIGNED_TRIP:
		Handle_Signed_Trip(mess);
		break;

	case SIGNED_CLOSE:
		Handle_Signed_Close(mess);
		break;
	default:
		Alarm(PRINT, "Invalid type %d, ignoring\n", mess->type);
		return;
    }

	
}


static void Handle_Recovery_Query(tm_msg *mess)
{
	Alarm(DEBUG,"Receive RECOVERY_QUERY from %d!\n",mess->m_id);
	//TODO: rate limit???
	PROXY_Send_Ack();
}

static void Handle_Signed_Trip(tm_msg *mess)
{

	sp_time now;
        struct timeval tr_time;
	uint64_t lat;
	
	//If already in same state, ignore signed messages with lesser time stamp
	if (b_state == STATE_TRIP) {
                if(mess->dts<=dts){
			Alarm(DEBUG, "At dts=%lu, STATE already tripped, ignoring TRIP. Received from %d with %lu\n",dts,mess->m_id,mess->dts);
                        return;
                }
	 }
	//Validate the message
	 if(!Validate_Final_Msg(mess)){
	 	return;
	 }
	 //First Signed trip after trip sv, queue next close, inform XCBR and get confirm, then ack
	 if(b_state!=STATE_TRIP){
		if(trip!=1){
			Alarm(PRINT, "Mcast sent close but got Signed TRIP \n");
			print_stats();
		}
	 	gettimeofday(&tr_end, NULL);
        //rdtsc2=rdtsc();
        //Alarm(DEBUG,"rdtsc diff = %llu\n",rdtsc2-rdtsc1);
	 	tr_time=diffTime(tr_end,tr_start);
	 	Alarm(DEBUG,"Difftime= %ld.%06ld\n",tr_time.tv_sec,tr_time.tv_usec);
	 	lat = (1000000*tr_time.tv_sec) + tr_time.tv_usec;
	 	latencies[so_far]=lat;
        if(lat>4000){
            Alarm(PRINT,"****gt 4000 [%d]:%lu\n",so_far,lat);
        }
       // rdtsc_diff[so_far]=rdtsc2-rdtsc1;
	 	count+=1;
	 	//TODO: Publish GOOSE to XCBR and wait for ack/status change
	 	
		E_queue(send_simple_sv,NULL,NULL,delta);
	 }
	 //If not first ack for sv, and if dts> curr dts, send ack with higher dts. Need not send to XCBR as already tripped
	 b_state=STATE_TRIP;
	 now=E_get_time();
    	 dts = ((now.sec * 1000 + now.usec / 1000) / DTS_INTERVAL) * DTS_INTERVAL;
	 Alarm(DEBUG, "[%d]:Valid %s, from %d with dts =%lu  \n",count,(mess->type == SIGNED_TRIP?"SIGNED_TRIP":"SIGNED_CLOSE"),mess->m_id,mess->dts);
	 PROXY_Send_Ack();
	 sp_time timeout;
}


static void Handle_Signed_Close(tm_msg *mess)
{

	sp_time now;
	struct timeval tr_time;
	uint64_t lat;

	//If already in same state, ignore signed messages with lesser time stamp
	if (b_state == STATE_CLOSE) {
                if(mess->dts<=dts){
			Alarm(DEBUG, "At dts=%lu,STATE already closed, ignoring CLOSE. Received from %d with %lu\n",dts,mess->m_id,mess->dts);
                        return;
                }
	 }
	 if(!Validate_Final_Msg(mess)){
	 	return;
	 }
	 
	 //First Signed close after close sv, queue next trip sv, inform XCBR and get confirm, then ack
	 if(b_state!=STATE_CLOSE){
		if(trip!=0){
			Alarm(PRINT, "Mcast sent trip but got Signed close \n");
			print_stats();
		}
	 	gettimeofday(&tr_end, NULL);
        //rdtsc2=rdtsc();
        //Alarm(DEBUG,"rdtsc diff = %llu\n",rdtsc2-rdtsc1);
	 	tr_time=diffTime(tr_end,tr_start);
	 	Alarm(DEBUG,"Difftime= %ld.%06ld\n",tr_time.tv_sec,tr_time.tv_usec);
	 	lat = (1000000*tr_time.tv_sec) + tr_time.tv_usec;
	 	latencies[so_far]=lat;
        //rdtsc_diff[so_far]=rdtsc2-rdtsc1;
        if(lat>4000){
            Alarm(PRINT,"****gt 4000 [%d]:%lu\n",so_far,lat);
        }
	 	count+=1;
	 	//TODO: Publish GOOSE to XCBR and wait for ack

	 	E_queue(send_simple_sv,NULL,NULL,delta);
	 }

	 //If not first ack for sv, and if dts> curr dts, send ack with higher dts. Need not send to XCBR as already closed
	 b_state=STATE_CLOSE;
	 now=E_get_time();
    	 dts = ((now.sec * 1000 + now.usec / 1000) / DTS_INTERVAL) * DTS_INTERVAL;

	 Alarm(DEBUG, "[%d]:Valid %s, from %d with dts=%lu \n",count,(mess->type == SIGNED_TRIP?"SIGNED_TRIP":"SIGNED_CLOSE"),mess->m_id,mess->dts);
	 PROXY_Send_Ack();
	 sp_time timeout;
}


static bool Validate_Final_Msg(tm_msg *mess)
{
	tc_final_msg *      tc_final;
	tc_payload          payload;
        byte                digest[DIGEST_SIZE];
	
	if (mess->len != sizeof(tc_final_msg)){
		Alarm(PRINT, "Invalid 1: mess->len is not same as tc_final_message\n");
		return false;
	}
	//Check that it is not old message
	 if (mess->dts <= dts){
		 Alarm(DEBUG, "Invalid 2: Old message from %d (dts = %ld, cur = %ld) ignoring\n", mess->m_id,mess->dts, dts);
		 return false;
	 }

	 //Valid message i.e., Signed Trip/close with dts > what we last know
	 Alarm(DEBUG,"Valid: message from %d (dts = %ld, cur = %ld)\n",mess->m_id,mess->dts, dts);
	 
	 tc_final = (tc_final_msg *)(mess + 1);
	 memset(&payload, 0, sizeof(payload));
	 payload.dts = mess->dts;
	 payload.state = mess->type == SIGNED_TRIP ? STATE_TRIP : STATE_CLOSE;
	 OPENSSL_RSA_Make_Digest(&payload, sizeof(payload), digest);
	 //OPENSSL_RSA_Print_Digest(digest);
	 if (!TC_Verify_Signature(tc_final->thresh_sig, digest)){
	 	 Alarm(PRINT, "Invalid 3: Signature invalid, ignoring\n");
		 return false;
	 }
	 return true;

}


static void PROXY_Send_Ack()
{
    int i; 
    int ret;
    struct sockaddr_in addr;
    tm_msg mess;

    mess.type = (b_state == STATE_CLOSE) ? SIGNED_CLOSE_ACK : SIGNED_TRIP_ACK;
    mess.m_id = NUM_REPLICAS; // TODO do we want a special proxy id?
    mess.len  = 0;
    mess.dts  = dts;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(TM_PROXY_PORT);

    for (i = 0; i < NUM_REPLICAS; i++) {
        addr.sin_addr.s_addr = inet_addr(Relay_Ext_Addrs[i]);
        
        ret = spines_sendto(s, &mess, sizeof(tm_msg),
            0, (struct sockaddr *) &addr, sizeof(addr));
        
        if (ret < 0) {
            Alarm(EXIT,"Spines sento error\n");
            // TODO attempt to reconnect?
        }
    }
    Alarm(DEBUG,"Sent %s ack at dts=%lu\n",b_state == STATE_CLOSE? "CLOSE":"TRIP",dts);
}



static void send_simple_sv()
{
	sp_time now;
    int i,j,ret;
    time_t    time_now;
    struct tm *tm_now;
    timestr tstr;
        
	so_far+=1;
	if(trip==1){
		trip=0;
	}else{
		trip=1;
	}

	if (so_far>total){
		Alarm(PRINT,"DONE SV msgs so_far=%d, total=%d\n",so_far,total);
		print_stats();
		exit(0);
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
	 gettimeofday(&tr_start, NULL);

     time_now=tr_start.tv_sec;
     tm_now = localtime(&time_now);
     memset(tstr,0,TIME_LEN);
     strftime (tstr, TIME_LEN, "%m/%d/%y %H:%M:%S",tm_now);
     strcpy(scatter_time[so_far],tstr);
        //rdtsc1=rdtsc();

        if(so_far%PRINT_PROGRESS==0){
		Alarm(PRINT,"Sent [%d]=%d\n",so_far,trip);
	}


}

static void print_stats()
{
	int               Histogram[NUM_BUCKETS];
	int index,i,j;
	double            Sum_Lat, Count_Lat, Min_Lat, Max_Lat,count_4;

	Alarm(PRINT,"*******STATS***********\n");
    Alarm(PRINT,"count \t latency \t rdtsc diff\n");

	memset(Histogram, 0, sizeof(int) * NUM_BUCKETS);
	Sum_Lat = 0;
    	Count_Lat = 0;
    	Min_Lat = 9999;
    	Max_Lat = 0;
        count_4=0;

	for(j=1;j<so_far;j++){
		printf("%s : [%d]: %lu \n",scatter_time[j],j,latencies[j]);
		//printf("%s : [%07d]: %05lu \t %lu\n",scatter_time[j],j,latencies[j],rdtsc_diff[j]);
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
	printf(" Min / Average / Max Latency = %f usec / %f usec / %f usec\n",
                Min_Lat,(Sum_Lat / Count_Lat), Max_Lat);
    printf("Count of transactions > 4msec= %f\n",count_4);
	exit(1);


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
  Alarm( PRINT, "|    Amy Babay                 babay@pitt.edu                                     |\n");
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
  Alarm( PRINT, "| Version 2.2, Built March 5, 2025                                                  |\n");
  Alarm( PRINT, "|                                                                                   |\n");
  Alarm( PRINT, "| This product uses software developed by Spread Concepts LLC for use               |\n");
  Alarm( PRINT, "| in the Spread toolkit. For more information about Spread,                         |\n");
  Alarm( PRINT, "| see http://www.spread.org                                                         |\n");
  Alarm( PRINT, "\\=================================================================================/\n\n");
}

static void usage(int argc, char **argv)
{
	total=10;
	trip=0;
	so_far=0;
	delta.sec=2;
	delta.usec=0;
    //delta.sec=0;
	//delta.usec=80000;
	while( --argc > 0 ) {
	    argv++;
	    if( !strncmp( *argv, "-n", 2 ) ){
		sscanf(argv[1], "%d", &total);
		latencies=malloc((total+1) * sizeof(*latencies));
        memset(latencies,0,(total+1) * sizeof(*latencies));
        //rdtsc_diff=malloc((total+1) * sizeof(*rdtsc_diff));
        scatter_time=malloc((total+1)*sizeof(timestr));
        for(int i=0;i<=total;i++){
            latencies[i]=0;
        }
             	argc--; argv++;
            }else if(*argv,"-e",2){
		sscanf(argv[1],"%d", &trip);    
             	argc--; argv++;
	    }else{
	      Alarm(PRINT,"Usage: benchmark \n%s\n%s\n",
			      "\t[-n <int count>]: Number of events to emulate, default 10",
			      "\t[-e <int 0/1>]: event to start with, by default trip");
	      exit(0);
	    }
	}
	Alarm(PRINT,"Sending total %d SV msgs starting with %d\n",total,trip);
}

