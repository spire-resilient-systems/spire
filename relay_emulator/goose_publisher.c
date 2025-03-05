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



#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <errno.h>

#include "spu_alarm.h"
#include "spu_events.h"

#include "mms_value.h"
#include "goose_publisher.h"

#include "def.h"
#include "packets.h"

#define T1 500
#define T0 2000

// Local Function defs
int init_socket(void);
int64_t get_timestamp(void);
void handle_event(int s, int code, void *dummy);
void publish_goose(int code, void *v_trip);
void repeat_goose(int code, void *dummy);

void Usage(int argc, char **argv);

// Global variables
int My_ID;
char* interface;
static uint64_t count;

GoosePublisher publisher;
LinkedList dataSetValues;
MmsValue *mms_timestamp;
MmsValue *mms_trip;

int timeout_ms = T1;

int main(int argc, char** argv)
{
  
    setlinebuf(stdout);
    Alarm_set_types(PRINT);
    //Alarm_set_types(STATUS);
    //Alarm_set_types(DEBUG);
    Alarm_enable_timestamp_high_res("%m/%d/%y %H:%M:%S");
    Usage(argc, argv);

    Alarm(PRINT, "Using interface %s\n", interface);
    count=0;

    /* Setup payload data structure */
    dataSetValues = LinkedList_create();
    mms_timestamp = MmsValue_newUtcTimeByMsTime(0);
    mms_trip = MmsValue_newBoolean(0);
    LinkedList_add(dataSetValues, mms_timestamp);
    LinkedList_add(dataSetValues, mms_trip);

    // TODO does this stuff matter? Probably
    // If the goose subscriber subscribes to these, then the messages are filtered. Same with CbRef
    CommParameters gooseCommParameters;
    gooseCommParameters.appId = 1000;
    gooseCommParameters.dstAddress[0] = 0x01;
    gooseCommParameters.dstAddress[1] = 0x0c;
    gooseCommParameters.dstAddress[2] = 0xcd;
    gooseCommParameters.dstAddress[3] = 0x01;
    gooseCommParameters.dstAddress[4] = 0x00;
    gooseCommParameters.dstAddress[5] = 0x01;
    gooseCommParameters.vlanId = 0;
    gooseCommParameters.vlanPriority = 4;

    /*
     * Create a new GOOSE publisher instance. As the second parameter the interface
     * name can be provided (e.g. "eth0" on a Linux system). If the second parameter
     * is NULL the interface name as defined with CONFIG_ETHERNET_INTERFACE_ID in
     * stack_config.h is used.
     */
    
    publisher = GoosePublisher_create(&gooseCommParameters, interface);

    if (!publisher) {
        Alarm(EXIT, "Failed to create GOOSE publisher. Reason can be that the Ethernet interface doesn't exist or root permission are required.\n");
    }

    GoosePublisher_setGoCbRef(publisher, GOOSE_CB_REF);
    GoosePublisher_setConfRev(publisher, 1);
    GoosePublisher_setDataSetRef(publisher, "simpleIOGenericIO/LLN0$AnalogValues");
    
    /* Setup Socket and timing code */
    int s = init_socket();
    
    E_init();
    E_attach_fd(s, READ_FD, handle_event, 0, NULL, MEDIUM_PRIORITY);
    E_handle_events();

    GoosePublisher_destroy(publisher);
    LinkedList_destroyDeep(dataSetValues, (LinkedListValueDeleteFunction) MmsValue_delete);
}

/* setup mcast socket */
int init_socket(void)
{
  struct sockaddr_in name;
  struct ip_mreq     mreq;

  int sr;

  sr = socket(AF_INET, SOCK_DGRAM, 0); /* socket for receiving */
  if(sr < 0) {
    perror("Mcast: socket");
    exit(1);
  }

  memset(&name,0,sizeof(name));

  name.sin_family = AF_INET;
  name.sin_addr.s_addr = INADDR_ANY;
  name.sin_port = htons(EMULATOR_MCAST_PORT);

  if(bind( sr, (struct sockaddr *)&name, sizeof(name)) < 0 ) {
    perror("Mcast: bind");
    exit(1);
  }

  mreq.imr_multiaddr.s_addr = htonl( EMULATOR_MCAST_ADDR );
  /* the interface could be changed to a specific interface if needed */
  mreq.imr_interface.s_addr = htonl( INADDR_ANY );

  if (setsockopt(sr, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void *)&mreq,
  sizeof(mreq)) < 0)
  {
    perror("Mcast: problem in setsockopt to join multicast address" );
  }

  Alarm(PRINT, "Setup mcast socket\n" );
  return sr;
}

/* now in ms */
int64_t get_timestamp(void)
{
    sp_time now = E_get_time();
    
    return now.sec * 1000 + now.usec / 1000;
}

/* Receive an msg from gen_event.c and queue the timeout */
void handle_event(int s, int code, void *dummy) 
{
    sp_time timeout;

    sv_msg msg; // Receieved from mcast
    int *trip;
    
    int size;

    size = recv(s, &msg, sizeof(msg), 0);
    if(size<sizeof(sv_msg)){
    	Alarm(PRINT,"Mcast corrupt Packet\n");
	return;
    }

    
    trip = malloc(sizeof(int));
    if (trip == NULL)
    {
        perror("malloc: ");
        exit(EXIT_FAILURE);
    }

    if(msg.trip[My_ID-1] == 0){
	    *trip =0;
    }else if (msg.trip[My_ID-1] == 1){
	    *trip = 1;
    }else{
	    free(trip);
	    return;
    }


    timeout.sec = msg.delay_ms[My_ID - 1] / 1000;
    timeout.usec = (msg.delay_ms[My_ID - 1] % 1000) * 1000;
    count+=1;
    if(count%PRINT_PROGRESS==0){
    	Alarm(PRINT, "Count=[%lu] \n",count);
    }
    
    E_queue(publish_goose, 0, trip, timeout);
    
}

/* Publish a new goose event, i.e. increase state number and change state */
void publish_goose(int code, void *v_trip)
{
    int *trip = (int *) v_trip;

    // If called from handle_event, dequeue because we need to reset timeout
    E_dequeue(repeat_goose, 0, NULL);

    Alarm(STATUS, "Publisher: New Goose Event %s!\n",*trip==1?"TRIP":"CLOSE");

    GoosePublisher_increaseStNum(publisher);
    MmsValue_setBoolean(mms_trip, *trip);
    MmsValue_setUtcTimeMs(mms_timestamp, get_timestamp());
    
    free(trip);    

    timeout_ms = T1;
    repeat_goose(0, NULL);
}

/* Send the next seqnum of the Goose publisher and double the timeout if needed*/
void repeat_goose(int code, void *dummy)
{
    sp_time timeout;

    if (GoosePublisher_publish(publisher, dataSetValues) == -1) {
        Alarm(PRINT, "Publisher: Error sending message!\n");
    }
    Alarm(DEBUG, "Publisher: Sending repeat goose message!\n");

    timeout.sec = timeout_ms / 1000;
    timeout.usec = (timeout_ms % 1000) * 1000;

    timeout_ms *= 2;
    if (timeout_ms > T0) timeout_ms = T0;        

    E_queue(repeat_goose, 0, NULL, timeout);
}


void Usage(int argc, char **argv)
{
    if (argc != 3) {
        Alarm(EXIT, "Usage: %s interface relayID\n", argv[0]);
    }
    
    interface = argv[1];

    sscanf(argv[2], "%d", &My_ID);
    if (My_ID < 1 || My_ID > NUM_REPLICAS) {
        Alarm(EXIT, "Invalid My_ID: %d\n", My_ID);
    }

}
