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


/*
 * Has to be started as root in Linux.
 */
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

#include "hal_ethernet.h"
#include "goose_subscriber.h"
#include "goose_receiver.h"
#include "mms_value.h"
#include "goose_publisher.h"

#include "spines_lib.h"
#include "spu_alarm.h"
#include "spu_events.h"

#include "def.h"
#include "packets.h"
#include "ss_net_wrapper.h"

#define T1 500
#define T0 2000

/*When Fault is set, the relay proxy will invert TRIP and CLOSE signals sent to trip master module, Used in read team experiment. Default 0*/
#define FAULT 0

/* Receiving Goose Messages from ethernet*/
//static EthernetSocket eth_sock;
//static EthernetHandleSet handle_set;

/* iec61850 objects to parse input goose messages */
//static byte goose_buffer[GOOSE_MAX_LENGTH];
static GooseReceiver goose_receiver;
static GooseSubscriber goose_subscriber;
static local_relay_msg mess;
/* Defs for forwarding over Spines/IPC */
static int ipc_sock,ipc_sock_in;
static struct sockaddr_un ipc_addr;
/* iec61850 objects to publish CB status GOOSE messages */
//static char* interface;
GoosePublisher publisher;
LinkedList dataSetValues;
MmsValue *mms_trip;
int timeout_ms,location;
CommParameters gooseCommParameters;

int first_r, first_b;

/*Local Functions*/
static void Init_ipc();
static void Init_goosepub();
static void Usage(int, char **);
static void goose_listener(GooseSubscriber subscriber, void* parameter);
static void TM_IPC_Recv(int source, void *dummy);
static void publish_goose(int code, int v_trip);
static void repeat_goose(int code, void *dummy);
static void print_notice();

int main(int argc, char** argv)
{
    Alarm_enable_timestamp_high_res("%m/%d/%y %H:%M:%S");
    setlinebuf(stdout);
    Alarm_set_types(PRINT);
    //Alarm_set_types(STATUS);
    //Alarm_set_types(DEBUG);
    
    Usage(argc, argv);
    first_r=1;
    first_b=1;
    print_notice();
    Init_ipc();
    
    Init_goosepub();
    
    //Create Publisher with interface and  CB REF from cmd line args
    
    publisher = GoosePublisher_create(&gooseCommParameters, argv[4]);
    if (!publisher) {
        Alarm(EXIT, "Failed to create GOOSE publisher. Reason can be that the Ethernet interface doesn't exist or root permission are required.\n");
        GoosePublisher_destroy(publisher);
    }
    GoosePublisher_setGoCbRef(publisher, argv[2]);
    Alarm(PRINT, "CB ref =%s\n",argv[2]);
    GoosePublisher_setConfRev(publisher, 1);
    //GoosePublisher_setDataSetRef(publisher, "Dataset1");
    GoosePublisher_setDataSetRef(publisher, argv[6]);
    GoosePublisher_setGoID(publisher,argv[5]);
    
    //Goose Subscriber
    goose_receiver= GooseReceiver_create();
    GooseReceiver_setInterfaceId(goose_receiver, argv[3]);
    goose_subscriber = GooseSubscriber_create(argv[1], NULL);
    Alarm(PRINT, "Relay CB ref =%s\n",argv[1]);
    GooseSubscriber_setListener(goose_subscriber, goose_listener, NULL);
    GooseReceiver_addSubscriber(goose_receiver, goose_subscriber);
    location=atoi(argv[7]);
    fflush(stdout);

    //Initialize local Relay mess to avoid repetitions. We will send LR_message to TM only if there is a change in Relay Goose state
    mess.type=10;
   
    sleep(8);
    GooseReceiver_start(goose_receiver);
    if(GooseReceiver_isRunning(goose_receiver))
        Alarm(STATUS,"Subscriber is Running...\n");
    else{
        GooseReceiver_stop(goose_receiver);
        GooseReceiver_destroy(goose_receiver);
        Alarm(EXIT,"Not Running...\n");
    }
    E_init();
    E_attach_fd(ipc_sock_in, READ_FD, TM_IPC_Recv, NULL, NULL, MEDIUM_PRIORITY);
    E_handle_events();

    //GooseReceiver_stop(goose_receiver);
    //GooseReceiver_destroy(goose_receiver);
    //GoosePublisher_destroy(publisher);


}


void TM_IPC_Recv(int source, void *dummy)
{
    local_relay_msg tm_cb_status;
    int ret;
    int  trip=2;

    ret = IPC_Recv(ipc_sock_in, &tm_cb_status, sizeof(local_relay_msg));
    Alarm(STATUS,"\t********CB status from TM=%s\n",tm_cb_status.type ==SIGNED_TRIP_ACK?"CB TRIP":"CB CLOSE");
    if(tm_cb_status.type ==SIGNED_TRIP_ACK){
        trip =1;
    }
    else if(tm_cb_status.type ==SIGNED_CLOSE_ACK){
        trip=0;
    }
    else{
        Alarm(DEBUG,"TM_IPC_Recv Unknown type=%d\n",tm_cb_status.type);
        return;
    }
    publish_goose(0, trip);

}

/* Publish a new goose event, i.e. increase state number and change state */
void publish_goose(int code, int v_trip)
{
    int trip = v_trip;


    if (first_b==1){
    	Alarm(PRINT, "\t********Publisher: First Goose Event!\n");
        first_b=0;
    }
    // If called from handle_event, dequeue because we need to reset timeout
    if(E_in_queue(repeat_goose,0,NULL)){
        E_dequeue(repeat_goose, 0, NULL);
    }

    Alarm(STATUS, "\t********Publisher: New Goose Event!\n");

    GoosePublisher_increaseStNum(publisher);
    MmsValue_setBoolean(mms_trip, trip);


    timeout_ms= T1;
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
    if (timeout_ms > T0) timeout_ms = T0;

    E_queue(repeat_goose, 0, NULL, e_timeout);
}



static void Init_ipc()
{
    ipc_sock = IPC_DGram_SendOnly_Sock();
    memset(&ipc_addr, 0, sizeof(struct sockaddr_un));
    ipc_addr.sun_family = AF_UNIX;
    strncpy(ipc_addr.sun_path, TM_IPC_IN, sizeof(ipc_addr.sun_path));

    if (ipc_sock < 0) {
        perror("relay_proxy: socket\n");
        exit(EXIT_FAILURE);
    }
    ipc_sock_in=IPC_DGram_Sock(TM_IPC_OUT);
    if(ipc_sock_in<0)
        Alarm(EXIT, "Error setting up IPC relay input communication, exiting\n");

    Alarm(DEBUG,"Set up IPC send and receive sockets\n");
}



static void Init_goosepub()
{
    timeout_ms = T1;
    /* Setup payload data structure */
    dataSetValues = LinkedList_create();
    mms_trip = MmsValue_newBoolean(0);
    LinkedList_add(dataSetValues, mms_trip);

    //TODO: Set appId per relay proxy
    gooseCommParameters.appId = 1000;
    gooseCommParameters.dstAddress[0] = 0x01;
    gooseCommParameters.dstAddress[1] = 0x02;
    gooseCommParameters.dstAddress[2] = 0x03;
    gooseCommParameters.dstAddress[3] = 0x04;
    gooseCommParameters.dstAddress[4] = 0x05;
    gooseCommParameters.dstAddress[5] = 0x06;
    gooseCommParameters.vlanId = 0;
    gooseCommParameters.vlanPriority = 4;
}

static void goose_listener(GooseSubscriber subscriber, void* parameter)
{
    // Do nothing, but subscriber data is accessible
    uint32_t curr_relay_type=10;
    sp_time now;
    uint64_t now_msec;
    int ret;
    uint64_t timestamp;
    MmsValue* values;
    //MmsValue *raw_b_status;
    char buffer[1024];
    //uint32_t uint_b_status=0;
	
    Alarm(DEBUG,"Goose Listner Called ....\n");
    if(first_r==1){
    Alarm(PRINT,"Sub GOOSE event:  stNum: %u sqNum: %u\n", GooseSubscriber_getStNum(subscriber),GooseSubscriber_getSqNum(subscriber));
    first_r=0;
    }
    Alarm(DEBUG,"Sub GOOSE event:  stNum: %u sqNum: %u\n", GooseSubscriber_getStNum(subscriber),GooseSubscriber_getSqNum(subscriber));
    Alarm(DEBUG,"  timeToLive: %u\n", GooseSubscriber_getTimeAllowedToLive(subscriber));

    timestamp = GooseSubscriber_getTimestamp(subscriber);

    Alarm(DEBUG,"  timestamp: %u.%u\n", (uint32_t) (timestamp / 1000), (uint32_t) (timestamp % 1000));
    Alarm(DEBUG,"  message is %s\n", GooseSubscriber_isValid(subscriber) ? "valid" : "INVALID");

    values = GooseSubscriber_getDataSetValues(subscriber);


    MmsValue_printToBuffer(values, buffer, 1024);

    Alarm(DEBUG,"  allData: %s\n", buffer);
    //raw_b_status= MmsValue_getElement(values, 1);
    //uint_b_status= MmsValue_getBitStringAsInteger(raw_b_status);
    //Alarm(DEBUG,"Testing CB status(0-noinfo,1-open,2-close,3-indterminate): %ld\n",uint_b_status);
    if (MmsValue_getBoolean(MmsValue_getElement(values, location))) {
                Alarm(DEBUG,"LR_TRIP\n");
                curr_relay_type=LR_TRIP;
		if(FAULT) {
			curr_relay_type=LR_CLOSE;
                        Alarm(DEBUG,"BYZ_CLOSE\n");
                }
            } else {
                Alarm(DEBUG,"LR_CLOSE\n");
                curr_relay_type=LR_CLOSE;
		if(FAULT) {
			curr_relay_type=LR_TRIP;
                        Alarm(DEBUG,"BYZ_TRIP\n");
                }
            }
    //Alarm(DEBUG,"Relay mess=%s\n",curr_relay_type==LR_TRIP?"trip":"close");
    if(curr_relay_type != mess.type || GooseSubscriber_getSqNum(subscriber)==0){
        Alarm(STATUS,"Sub GOOSE event:  stNum: %u sqNum: %u\n", GooseSubscriber_getStNum(subscriber),GooseSubscriber_getSqNum(subscriber));
        now=E_get_time();
        now_msec=now.sec * 1000 + now.usec / 1000;
        mess.dts = (now_msec / DTS_INTERVAL) * DTS_INTERVAL;
        mess.type=curr_relay_type;
        ret = IPC_Send(ipc_sock, &mess, sizeof(mess),(char *)TM_IPC_IN);
        if(ret <0)
             perror("\nrelay_proxy: IPC sendto TM  error\n");
        Alarm(STATUS,"Sent relay message %s at dts=%ld\n",mess.type == LR_TRIP ? "TRIP" : "CLOSE" , mess.dts);

    }
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



static void Usage(int argc, char **argv)
{
    if (argc != 8) {
        Alarm(PRINT, "Usage: %s <relay_CB_Ref> <breaker_CB_Ref> <sub_interface> <pub_interface> <goID> <dataset> <trip_loaction_in_relay_goose>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    

}
