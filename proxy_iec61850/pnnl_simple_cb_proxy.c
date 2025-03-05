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


static uint64_t dts; //store last final's dts
static int      b_state; //store breaker state
static int count,s,s1;
static GooseReceiver goose_receiver;
static GooseSubscriber goose_subscriber;
static char* interface;
GoosePublisher publisher;
LinkedList dataSetValues;
MmsValue *mms_trip;
int timeout_ms;
CommParameters gooseCommParameters;



static void print_notice();
static void usage(int argc, char **argv);
static bool Validate_Final_Msg(tm_msg *mess);
static void Handle_Recovery_Query(tm_msg *mess);
static void Handle_Signed_Trip(tm_msg *mess);
static void Handle_Signed_Close(tm_msg *mess);
static void Handle_Ext_Spines_Msg();
static void PROXY_Startup();
static void PROXY_Force_Startup();//TODO: Integration testing
static void PROXY_Send_Ack();
static void PROXY_Send_Breaker_Ack();
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

    GoosePublisher_increaseStNum(publisher);
    MmsValue_setBoolean(mms_trip, trip);


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
    Alarm(DEBUG, "\t******Publisher: Sending repeat goose message timeout=%lu!\n",timeout_ms);

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
	goose_subscriber = GooseSubscriber_create("ByzSecBreakerLDInst/LLN0$GO$gcb01", NULL);
	GooseSubscriber_setListener(goose_subscriber, goose_listener, NULL);
     	GooseReceiver_addSubscriber(goose_receiver, goose_subscriber);
	GooseReceiver_start(goose_receiver);
    if(GooseReceiver_isRunning(goose_receiver))
        Alarm(STATUS,"Subscriber is Running...\n");
    else{
        GooseReceiver_stop(goose_receiver);
        GooseReceiver_destroy(goose_receiver);
        Alarm(EXIT,"Subscriber Not Running...\n");
    }
}


static void goose_listener(GooseSubscriber subscriber, void* parameter)
{
	 MmsValue* values;
	 char buffer[1024];
	 uint32_t curr_brkr_state=10;
	 sp_time now;

     Alarm(DEBUG,"\t Sub GOOSE event:  stNum: %u sqNum: %u\n", GooseSubscriber_getStNum(subscriber),GooseSubscriber_getSqNum(subscriber));
   	 Alarm(DEBUG,"\t timeToLive: %u\n", GooseSubscriber_getTimeAllowedToLive(subscriber));

	 values = GooseSubscriber_getDataSetValues(subscriber);
	 MmsValue_printToBuffer(values, buffer, 1024);
	 Alarm(DEBUG,"\t allData: %s\n", buffer);
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
		 now=E_get_time();
         	 dts = ((now.sec * 1000 + now.usec / 1000) / DTS_INTERVAL) * DTS_INTERVAL;
		 
		 //PROXY_Send_Ack();
		 PROXY_Send_Breaker_Ack();

	 }
}


static void Init_Spines(){
    char *  sp_addr = SPINES_PROXY_ADDR;
 /* Initialize Spines network */
    s = Spines_Sock(sp_addr, SS_SPINES_EXT_PORT, SPINES_PRIORITY, TM_PROXY_PORT);

    if (s < 0) {
        Alarm(EXIT,"Spines socket error\n");
    }
    Alarm(PRINT,"Spines socket connected s=%d\n",s); 
    
    s1 = Spines_Sock(sp_addr, SS_SPINES_EXT_PORT, SPINES_PRIORITY, BREAKER_PORT);

    if (s1 < 0) {
        Alarm(EXIT,"Spines breaker socket error\n");
    }
    Alarm(PRINT,"Spines breaker socket connected s1=%d\n",s1); 

}


int main(int argc, char** argv)
{
    int     ret;


    sleep(15);
    setlinebuf(stdout);
    Alarm_enable_timestamp_high_res("%m/%d/%y %H:%M:%S");
    Alarm_set_types(PRINT);
    //Alarm_set_types(STATUS);
    //Alarm_set_types(DEBUG);
    usage(argc, argv);
    print_notice();
    
    /* Initialize crypto stuff */
    TC_Read_Public_Key("../trip_master/tm_keys"); 
    OPENSSL_RSA_Init();

    /* Breaker State is Unknown*/
    b_state=-1;

    /*Spines connect*/

    Init_Spines();    
   //On start, gather XCBR Breaker status
    E_init();
    Init_goosepub();
    Init_Subscriber();
   
        //TODO: DELETE AFTER INTEGRATION TESTING
        if(TESTING)
        {
	   PROXY_Force_Startup();
        }

    
    while(b_state==-1){
    	PROXY_Startup();
    }
    //I think we should send breaker state after restart
    //PROXY_Send_Ack();
    
    

    Alarm(PRINT,"Simple CB Proxy Running.....\n");
    E_attach_fd(s,READ_FD,Handle_Ext_Spines_Msg,NULL,NULL,MEDIUM_PRIORITY);
    E_handle_events();
}

static void PROXY_Force_Startup()
{

    //If uncommented, will start breaker in close mode	
    publish_goose(0, 0);
   // If uncommented, will start breaker in trip mode
    //publish_goose(0, 1);
}


static void PROXY_Startup()
{
    sleep(0.010); //sleep 100ms
    
}

static void Handle_Ext_Spines_Msg()
{
    struct sockaddr_in  from_addr;
    socklen_t           from_len = sizeof(from_addr);  
    byte                buff[SPINES_MAX_SIZE];
    //byte                digest[DIGEST_SIZE];
    tm_msg *            mess;
    int ret;
    //receive spines message
    ret = spines_recvfrom(s, buff, MAX_LEN, 0, (struct sockaddr *) &from_addr, &from_len);

    //Check message size
    if(ret<0){
	    Alarm(DEBUG, "Spines recvfrom ret <0\n");
	    return;
    }
    if (ret < sizeof(tm_msg)){
    	Alarm(DEBUG,"Msg size less than tm_msg size\n");
	return;
    }
    mess = (tm_msg *) buff;
    if (ret < (sizeof(tm_msg)+mess->len)){
    	Alarm(DEBUG,"Msg size less than (tm_msg + mess->len) size\n");
	return;
    }
    //Check Identity of sender
    if (mess->m_id < 1 || mess->m_id > NUM_REPLICAS){
    	Alarm(DEBUG,"mess->m_id error\n");
	return;
    }
    if (from_addr.sin_addr.s_addr != inet_addr(Relay_Ext_Addrs[mess->m_id-1])) {
    	Alarm(DEBUG, "Machine id %d does not match address %s!\n", mess->m_id, Relay_Ext_Addrs[mess->m_id - 1]);
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
		Alarm(DEBUG, "Invalid type %d, ignoring\n", mess->type);
		return;
    }

	
}


static void Handle_Recovery_Query(tm_msg *mess)
{
	Alarm(STATUS,"Receive RECOVERY_QUERY from %d!\n",mess->m_id);
	PROXY_Send_Ack();
}

static void Handle_Signed_Trip(tm_msg *mess)
{

	sp_time now;
	
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
		publish_goose(0, 1);
        	count+=1;
	    	Alarm(STATUS, "[%d]:Valid %s, from %d with dts =%lu  \n",count,(mess->type == SIGNED_TRIP?"SIGNED_TRIP":"SIGNED_CLOSE"),mess->m_id,mess->dts);
	 }

 }


static void Handle_Signed_Close(tm_msg *mess)
{

	sp_time now;

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
		publish_goose(0, 0);
        	count+=1;

	    	Alarm(STATUS, "[%d]:Valid %s, from %d with dts=%lu \n",count,(mess->type == SIGNED_TRIP?"SIGNED_TRIP":"SIGNED_CLOSE"),mess->m_id,mess->dts);
	 }

}


static bool Validate_Final_Msg(tm_msg *mess)
{
	tc_final_msg *      tc_final;
	tc_payload          payload;
    byte                digest[DIGEST_SIZE];
	
	if (mess->len != sizeof(tc_final_msg)){
		Alarm(DEBUG, "Invalid 1: mess->len is not same as tc_final_message\n");
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
	 	 Alarm(DEBUG, "Invalid 3: Signature invalid, ignoring\n");
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
    mess.m_id = NUM_REPLICAS; 
    mess.len  = 0;
    mess.dts  = dts; 
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TM_PROXY_PORT);

    for (i = 0; i < NUM_REPLICAS; i++) {
        addr.sin_addr.s_addr = inet_addr(Relay_Ext_Addrs[i]);
        
        ret = spines_sendto(s, &mess, sizeof(tm_msg),0, (struct sockaddr *) &addr, sizeof(addr));
	Alarm(PRINT,"Sahiti ret=%d\n",ret);        
        if (ret < 0) {
            Alarm(EXIT,"Spines sento error\n");
        }
    }
    Alarm(STATUS,"Sent %s recovery ack at dts=%lu\n",b_state == STATE_CLOSE? "CLOSE":"TRIP",dts);
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
  Alarm( PRINT, "| Version 2.2, Built March 5, 2025                                                  |\n");
  Alarm( PRINT, "|                                                                                   |\n");
  Alarm( PRINT, "| This product uses software developed by Spread Concepts LLC for use               |\n");
  Alarm( PRINT, "| in the Spread toolkit. For more information about Spread,                         |\n");
  Alarm( PRINT, "| see http://www.spread.org                                                         |\n");
  Alarm( PRINT, "\\=================================================================================/\n\n");
}


static void usage(int argc, char **argv)
{
    count=0;
    if (argc!=2){
        Alarm(EXIT,"Usage: sudo ./pnnl_simple_cb_proxy interface\n");
    }
    interface=argv[1];
    return;
}

