/*
 * Spire.
 *
 * The contents of this file are subject to the Spire Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * https://jhu-dsn.github.io/spire/LICENSE.txt
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
 * Copyright (c) 2017-2026 Johns Hopkins University.
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
#include "scada_packets.h"
#include "packets.h"
#include "ss_openssl_rsa.h"

#include "goose_subscriber.h"
#include "goose_receiver.h"
#include "mms_value.h"
#include "goose_publisher.h"

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
#include <unistd.h>


#define TESTING 1

#define BRKR_T1 500
#define BRKR_T0 20000


int My_ID,Prime_Client_ID,Type,seq_num;
int32u My_Incarnation;
signed_update_message up_mess;
int Curr_num_SM = NUM_SM;
char* cc_addrs[NUM_CC_CONNECTORS] = CC_CONNECTORS;

static uint64_t dts;
static int      b_state;
static int      s,count,s1;
static uint64_t trips[NUM_REPLICAS+1];
static uint64_t closes[NUM_REPLICAS+1];
static tm_msg *curr_b;

static void send_to_cc();
static GooseReceiver goose_receiver;
static GooseSubscriber goose_subscriber;
static char* interface;
GoosePublisher publisher;
LinkedList dataSetValues;
MmsValue *mms_trip;
int timeout_ms;
CommParameters gooseCommParameters;



static void usage(int argc, char *argv[]);
static void print_relay_msgs(uint64_t mess_arr[]);
static bool count_relay_msgs(uint64_t mess_arr[]);
static void Handle_Recovery_Query(tm_msg *mess);
static void Handle_Relay_Trip(tm_msg *mess);
static void Handle_Relay_Close(tm_msg *mess);
static void Handle_Ext_Spines_Msg();
static void PROXY_Startup();
static void PROXY_Force_Startup();
static void PROXY_Send_Ack();
static void PROXY_Send_Breaker_Ack();
static void print_notice();
static void Init_Subscriber();
static void Init_Spines();
static void goose_listener(GooseSubscriber subscriber, void* parameter);
static void Init_goosepub();
static void publish_goose(int code, int v_trip);
static void repeat_goose(int code, void *dummy);


static void Init_goosepub()
{
    timeout_ms=BRKR_T1;
        /* Setup payload data structure */
    dataSetValues = LinkedList_create();
    mms_trip = MmsValue_newBoolean(0);
    LinkedList_add(dataSetValues, mms_trip);

    gooseCommParameters.appId = 1000;
    gooseCommParameters.dstAddress[0] = 0x01;
    gooseCommParameters.dstAddress[1] = 0x02;
    gooseCommParameters.dstAddress[2] = 0x03;
    gooseCommParameters.dstAddress[3] = 0x04;
    gooseCommParameters.dstAddress[4] = 0x05;
    gooseCommParameters.dstAddress[5] = 0x06;
    gooseCommParameters.vlanId = 0;
    gooseCommParameters.vlanPriority = 4;

    publisher = GoosePublisher_create(&gooseCommParameters, interface);
    if (!publisher) {
        Alarm(EXIT, "Failed to create GOOSE publisher. Reason can be that the Ethernet interface doesn't exist or root permission are required.\n");
        GoosePublisher_destroy(publisher);
    }
    GoosePublisher_setGoCbRef(publisher, "SPCBMaster/LLN0$GO$GoCB01");
    GoosePublisher_setConfRev(publisher, 1);
    GoosePublisher_setDataSetRef(publisher, "SPCBMaster/LLN0$GOOSE1");
    GoosePublisher_setGoID(publisher,"SPCBMaster");
}


/* Publish a new goose event, i.e. increase state number and change state */
void publish_goose(int code, int v_trip)
{
    int trip = v_trip;

    // If called from handle_event, dequeue because we need to reset timeout
    if(E_in_queue(repeat_goose,0,NULL)){
        E_dequeue(repeat_goose, 0, NULL);
    }

    Alarm(STATUS, "\t********Publisher: New Goose %s Event!\n",trip==1?"Trip":"Close");

    Alarm(STATUS,"chk0\n");
    GoosePublisher_increaseStNum(publisher);
    Alarm(STATUS,"chk1\n");
    MmsValue_setBoolean(mms_trip, trip);

    Alarm(STATUS,"chk2\n");
    timeout_ms= BRKR_T1;
    repeat_goose(0, NULL);
}

/* Send the next seqnum of the Goose publisher and double the timeout if needed*/
void repeat_goose(int code, void *dummy)
{
    sp_time e_timeout;
    GoosePublisher_setTimeAllowedToLive(publisher, timeout_ms);
    if (GoosePublisher_publish(publisher, dataSetValues) == -1) {
        Alarm(PRINT, "Publisher: Error sending message!\n");
    }
    Alarm(STATUS, "\t******Publisher: Sending repeat goose message timeout=%lu!\n",timeout_ms);

    e_timeout.sec = timeout_ms / 1000;
    e_timeout.usec = (timeout_ms % 1000) * 1000;

    timeout_ms *= 2;
    if (timeout_ms > BRKR_T0) timeout_ms = BRKR_T0;

    E_queue(repeat_goose, 0, NULL, e_timeout);
}


static void Init_Subscriber()
{
    goose_receiver= GooseReceiver_create();
    GooseReceiver_setInterfaceId(goose_receiver, interface);
    //GooseReceiver_setInterfaceId(goose_receiver, "bayctrl0");
    goose_subscriber = GooseSubscriber_create("ByzSecBreakerLDInst/LLN0$GO$gcb01", NULL);
    GooseSubscriber_setListener(goose_subscriber, goose_listener, NULL);
        GooseReceiver_addSubscriber(goose_receiver, goose_subscriber);
    GooseReceiver_start(goose_receiver);
    if(GooseReceiver_isRunning(goose_receiver))
        Alarm(STATUS,"Subscriber is Running...\n");
    else{
        GooseReceiver_stop(goose_receiver);
        GooseReceiver_destroy(goose_receiver);
        Alarm(EXIT,"Subscriber for CB Status Not Running...\n");
    }
}
 

static void goose_listener(GooseSubscriber subscriber, void* parameter)
{
     MmsValue* values;
     char buffer[1024];
     uint32_t curr_brkr_state=10;

     Alarm(DEBUG,"\t Sub GOOSE event:  stNum: %u sqNum: %u\n", GooseSubscriber_getStNum(subscriber),GooseSubscriber_getSqNum(subscriber));

     values = GooseSubscriber_getDataSetValues(subscriber);
     MmsValue_printToBuffer(values, buffer, 1024);
     Alarm(STATUS,"\t allData: %s\n", buffer);
     if (MmsValue_getBoolean(MmsValue_getElement(values, 0))) {
                Alarm(DEBUG,"BRKR_TRIP\n");
                curr_brkr_state=STATE_TRIP;
     } else {
                Alarm(DEBUG,"BRKR_CLOSE\n");
                curr_brkr_state=STATE_CLOSE;
            }
     
     if(curr_brkr_state!=b_state){
         Alarm(STATUS,"\t CB Status change GOOSE event:  stNum: %u sqNum: %u, state=%s\n", GooseSubscriber_getStNum(subscriber),GooseSubscriber_getSqNum(subscriber),curr_brkr_state==STATE_TRIP?"TRIP":"CLOSE");
         b_state=curr_brkr_state;
         //PROXY_Send_Ack();
	 PROXY_Send_Breaker_Ack();

     }
}


static void Init_Spines(){
    char *  sp_addr = Breaker_Addr;
    int ss_spines_ext_port=SS_SPINES_EXT_BASE_PORT+((My_ID-16)*10);

 /* Initialize Spines network */
    s = Spines_Sock(sp_addr, ss_spines_ext_port, SPINES_PRIORITY, TM_PROXY_PORT);

    if (s < 0) {
        Alarm(EXIT,"Spines socket error\n");
    }
    Alarm(PRINT,"Spines socket connected s=%d\n",s);

    s1 = Spines_Sock(sp_addr, ss_spines_ext_port, SPINES_PRIORITY, BREAKER_PORT);

    if (s1 < 0) {
        Alarm(EXIT,"Spines breaker socket error\n");
    }
    Alarm(PRINT,"Spines breaker socket connected s1=%d\n",s1);

}

int main(int argc, char* argv[])
{
    int     ret;


    sleep(2);
    setlinebuf(stdout);
    Alarm_enable_timestamp_high_res("%m/%d/%y %H:%M:%S");
    Alarm_set_types(PRINT);
    //Alarm_set_types(STATUS);
    //Alarm_set_types(DEBUG);
    
    usage(argc,argv);
    print_notice();
    Alarm(PRINT, "My substation Id is %d\n",My_ID);
    Load_SS_Conf(My_ID);

    /* Initialize crypto stuff */
    OPENSSL_RSA_Init();
    OPENSSL_RSA_Read_Keys(1, RSA_CLIENT, "../trip_master_v2/tm_keys");
    Alarm(DEBUG, "Dest Proxy 2.0 read keys\n");
    Alarm(DEBUG,"Opened Prime RSA keys\n");

    count=0;
    b_state=-1;


    /* Initialize network */
    Init_Spines();
    
    
    //On start, gather XCBR status
    E_init();
    Init_goosepub();
    Init_Subscriber();

        //TODO: DELETE AFTER INTEGRATION TESTING
        if(TESTING)
        {
            PROXY_Force_Startup();
        }
	else{
		//If uncommented, will start breaker in close mode
                publish_goose(0, 0);
                // If uncommented, will start breaker in trip mode
                //publish_goose(0, 1);
	
	}
    while(b_state==-1){
        PROXY_Startup();

    }

    // I think we should send breaker state after restart
    //PROXY_Send_Ack();



    Alarm(PRINT,"Counting CB Proxy Running.....\n");
    E_attach_fd(s,READ_FD,Handle_Ext_Spines_Msg,NULL,NULL,MEDIUM_PRIORITY);
    E_handle_events();
}
static void PROXY_Force_Startup()
{

    // If uncommented, will start breaker in trip mode
    //publish_goose(0, 1);
    // If uncommented, will start breaker in close mode
    //publish_goose(0, 0);
    sp_time now;

    b_state = STATE_CLOSE;
    now=E_get_time();
    dts = ((now.sec * 1000 + now.usec / 1000) / DTS_INTERVAL) * DTS_INTERVAL;
    PROXY_Send_Ack();

}
static void PROXY_Startup()
{
    sleep(0.010);
    
}



static void Handle_Ext_Spines_Msg()
{
    struct sockaddr_in  from_addr;
    socklen_t           from_len = sizeof(from_addr);  
    byte                buff[SPINES_MAX_SIZE];
    //byte                digest[DIGEST_SIZE];
    tm_msg *            mess;
    sig_payload *       sign;
    int                 ret;
    sp_time             now;
    uint64_t            now_msec,now_dts;
    //receive spines message
    ret = spines_recvfrom(s, buff, MAX_LEN, 0, (struct sockaddr *) &from_addr, &from_len);

    now=E_get_time();
    now_msec=now.sec * 1000 + now.usec / 1000;
    now_dts = (now_msec / DTS_INTERVAL) * DTS_INTERVAL;
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
    Alarm(DEBUG, "Valid %d, from %d with dts=%lu , now_dts=%lu\n",mess->type,mess->m_id,mess->dts,now_dts);

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
    //sp_time now;
   // uint64_t   now_msec,lat;
    //sig_payload *sign;
    //struct timeval tr_time;

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

    
    if(TESTING){
    	b_state=STATE_TRIP;
    	PROXY_Send_Ack();
    }else{
    	publish_goose(0, 1);
    
    }
    
    memset(trips, 0, sizeof(trips));
    memset(closes, 0, sizeof(closes));
    
    return;

}


static void Handle_Relay_Close(tm_msg *mess)
{
    //sp_time now;
   // uint64_t   now_msec;
    //sig_payload *sign;
    //struct timeval tr_time;
    //uint64_t lat;

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
    if(TESTING){
    	b_state=STATE_CLOSE;
    	PROXY_Send_Ack();
    }else{
    	publish_goose(0, 0);
    }
    memset(trips, 0, sizeof(trips));
    memset(closes, 0, sizeof(closes));
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
        
        msg_count1=1;
        msg_count2=1;

        for(j=i+1;j<=NUM_REPLICAS;j++){
            if(mess_arr[j]==0)
                continue;
            if(mess_arr[j]==curr_dts || (mess_arr[j]+DTS_INTERVAL)==curr_dts){
                msg_count1+=1;
                if(msg_count1==(SS_NUM_F+1)){
                    print_relay_msgs(mess_arr);
                    return true;
                }
            }
            if(mess_arr[j]==curr_dts_nxt || (mess_arr[j]+DTS_INTERVAL)==curr_dts_nxt){
                msg_count2+=1;
                if(msg_count2==(SS_NUM_F+1)){
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
    int i,ret,mess_type;
    struct sockaddr_in addr;
    uint32_t m_id;
    sp_time now;


    mess_type=(b_state == STATE_CLOSE) ? SIGNED_CLOSE_ACK : SIGNED_TRIP_ACK;
    m_id=NUM_REPLICAS+1;
    now=E_get_time();
    dts = ((now.sec * 1000 + now.usec / 1000) / DTS_INTERVAL) * DTS_INTERVAL;
    curr_b=PKT_Construct_TM_Message(mess_type,m_id,dts,sizeof(sig_payload));
    OPENSSL_RSA_Sign(((byte*)curr_b),sizeof(tm_msg),(byte*)(curr_b+1));
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TM_PROXY_PORT);

    for (i = 0; i < NUM_REPLICAS; i++) {
        addr.sin_addr.s_addr = inet_addr(Relay_Ext_Addrs[i]);
        
        ret = spines_sendto(s, curr_b, (sizeof(tm_msg)+curr_b->len),
            0, (struct sockaddr *) &addr, sizeof(addr));
        
        if (ret < 0) {
		Alarm(EXIT,"Spines sento error\n");
        }
    }
    send_to_cc();

    Alarm(DEBUG,"Sent type=%s, m_id=%u,dts=%lu,len=%u\n",curr_b->type == SIGNED_CLOSE_ACK ? "CLOSE ACK":"TRIP ACK",curr_b->m_id,curr_b->dts,curr_b->len);
}

static void PROXY_Send_Breaker_Ack()
{
    int i;
    int ret;
    struct sockaddr_in addr;
    tm_msg mess;
    //sp_time now;



    mess.type = (b_state == STATE_CLOSE) ? SIGNED_CLOSE_ACK : SIGNED_TRIP_ACK;
    mess.m_id = NUM_REPLICAS;
    mess.len  = 0;
    mess.dts  = dts;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TM_PROXY_PORT);

    for (i = 0; i < NUM_REPLICAS; i++) {
        addr.sin_addr.s_addr = inet_addr(Relay_Ext_Addrs[i]);

        ret = spines_sendto(s1, &mess, sizeof(tm_msg),0, (struct sockaddr *) &addr, sizeof(addr));
        if (ret < 0) {
            Alarm(EXIT,"Spines sento error\n");
        }
    }
    Alarm(STATUS,"Sent %s breaker ack at dts=%lu\n",b_state == STATE_CLOSE? "CLOSE":"TRIP",dts);
}



static void send_to_cc(){
    signed_message *mess;
    update_message *up;
    signed_message *rtu_mess_header;
    rtu_data_msg *rtu_data;
    struct timeval now;
    substation_fields* sf;
    struct sockaddr_in dest;
    int ret;

    //ITRC_Client: Construct signed_update_message and fill main header
    mess = PKT_Construct_Signed_Message(sizeof(signed_update_message) - sizeof(signed_message));
    mess->machine_id = Prime_Client_ID;
    mess->len = sizeof(signed_update_message) - sizeof(signed_message);
    mess->type = UPDATE;
    mess->incarnation = My_Incarnation;
    //ITRC Clinet: Fill update message header
    up = (update_message *)(mess + 1);
    up->server_id = Prime_Client_ID;
    up->seq_num = seq_num;
    //Proxy:RTU_data's signed message header
    rtu_mess_header = (signed_message *)(up+1);
    rtu_mess_header->machine_id = Prime_Client_ID;
    rtu_mess_header->len = sizeof(rtu_data_msg);
    rtu_mess_header->type = RTU_DATA;
    rtu_mess_header->incarnation = My_Incarnation;
    //RTU Data filling
    rtu_data=(rtu_data_msg *) (rtu_mess_header+1);
    rtu_data->seq.seq_num = seq_num;
    rtu_data->seq.incarnation = My_Incarnation;
    rtu_data->rtu_id = My_ID;
    rtu_data->scen_type = INTEGRATED_CC;
    gettimeofday(&now, NULL);
    rtu_data->sec  = now.tv_sec;
    rtu_data->usec = now.tv_usec;
    //Fill data or substaion fields for this scenario
    sf = (substation_fields *) rtu_data->data;
    if (b_state==STATE_CLOSE)
        sf->breaker_state= 0;
    else if (b_state == STATE_TRIP)
       sf->breaker_state=1;
    else
       sf->breaker_state=2;
    sf->dts = dts;
    sf->ss_id=Prime_Client_ID;
    OPENSSL_RSA_Sign(((byte*)mess) + SIGNATURE_SIZE,
           sizeof(signed_message) + mess->len - SIGNATURE_SIZE,
           (byte*)mess);
    signed_message *test;
    test=(signed_message *)mess;
    Alarm(DEBUG,"Post Sign: type=%lu, id=%lu\n",test->type,test->machine_id);
    Alarm(DEBUG,"\n");
    Alarm(DEBUG,"\n");
    //send to cc connector
    dest.sin_family = AF_INET;
    int relay_ss_port=RELAY_SUBSTATION_BASE_PORT+((My_ID-16)*10);
    dest.sin_port = htons(relay_ss_port);
    for(int i=0;i<NUM_CC_CONNECTORS;i++){
        dest.sin_addr.s_addr = inet_addr(cc_addrs[i]);
        ret = spines_sendto(s, mess,sizeof(signed_update_message),
           0, (struct sockaddr *)&dest, sizeof(struct sockaddr));
        if (ret != sizeof(signed_update_message)) {
                Alarm(PRINT,"Error Sending to cc_connector ret=%d mess size=%d\n",ret,sizeof(*mess));
        }else{
        Alarm(PRINT,"Sent to cc_connector (%s:%d) seq_num=%d size=%d\n",cc_addrs[i],relay_ss_port,seq_num,ret);
        }
    }
    //send to ss hmi
    dest.sin_port = htons(relay_ss_port);
    dest.sin_addr.s_addr = inet_addr(HMI_Addr);
    ret = spines_sendto(s, mess,sizeof(signed_update_message),
           0, (struct sockaddr *)&dest, sizeof(struct sockaddr));
    if (ret != sizeof(signed_update_message)) {
        Alarm(PRINT,"Error Sending to ss HMI ret=%d mess size=%d\n",ret,sizeof(*mess));
        return;
    }else{
        Alarm(PRINT,"Sent to ss hmi seq_num=%d size=%d\n",seq_num,ret);
    }
    seq_num+=1;

}


static void print_notice()
{
  Alarm( PRINT, "/==================================================================================\\\n");
  Alarm( PRINT, "| Spire                                                                             |\n");
  Alarm( PRINT, "| Copyright (c) 2017-2026 Johns Hopkins University                                  |\n");
  Alarm( PRINT, "| All rights reserved.                                                              |\n");
  Alarm( PRINT, "|                                                                                   |\n");
  Alarm( PRINT, "| Spire is licensed under the Spire Open-Source License.                            |\n");
  Alarm( PRINT, "| You may only use this software in compliance with the License.                    |\n");
  Alarm( PRINT, "| A copy of the License can be found at https://jhu-dsn.github.io/spire/LICENSE.txt |\n");
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
  Alarm( PRINT, "| WWW:     https://jhu-dsn.github.io/spire   https://jhu-dsn.github.io              |\n");
  Alarm( PRINT, "| Contact: spire@spire-sys.org                                                      |\n");
  Alarm( PRINT, "|                                                                                   |\n");
  Alarm( PRINT, "| Version 3.0, Built May 20, 2026                                                   |\n");
  Alarm( PRINT, "|                                                                                   |\n");
  Alarm( PRINT, "| This product uses software developed by Spread Concepts LLC for use               |\n");
  Alarm( PRINT, "| in the Spread toolkit. For more information about Spread,                         |\n");
  Alarm( PRINT, "| see http://www.spread.org                                                         |\n");
  Alarm( PRINT, "\\=================================================================================/\n\n");
}

static void usage(int argc, char *argv[])
{
    struct timeval now;
    count=0;

    if (argc!=3){
        Alarm(EXIT,"Usage: sudo ./counting_dst_proxy interface SSID\n");
    }
    interface=argv[1];
    sscanf(argv[2],"%d",&My_ID);
    Alarm(PRINT, "My substation Id is %d\n",My_ID);
    Type = RTU_TYPE;
    Prime_Client_ID = MAX_NUM_SERVER_SLOTS + My_ID;
    seq_num = 1;
    gettimeofday(&now, NULL);
    My_Incarnation = now.tv_sec;

    return;
}
