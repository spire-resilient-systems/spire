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


#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "spu_alarm.h"

#include "def.h"
#include "packets.h"

void usage(int argc, char **argv);

void error_and_exit(const char* msg, int ecode)
{
    perror(msg);
    exit(ecode);
}

int main(int argc, char **argv)
{
    struct sockaddr_in send_addr;
    unsigned char      ttl_val;
    int                s;

    int                i;
    int                ret;

    sv_msg             payload;
    struct timeval     now;

    int                trip;

    int                sleep_ms;
    struct timeval     sleep_timeout;

    char               input[20];

    setlinebuf(stdout);
    Alarm_enable_timestamp_high_res("%m/%d/%y %H:%M:%S");
    Alarm_set_types(PRINT|STATUS|DEBUG);

    usage(argc, argv);

    /* Setup socket for sending */
    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        Alarm(EXIT,"EVENT / SV :Mcast socket\n");
    }

    ttl_val = 1;
    if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, (void *)&ttl_val,
        sizeof(ttl_val)) < 0)
    {
        Alarm(PRINT,"EVENT / SV : problem in setsockopt of multicast ttl %d - ignore in WinNT or Win95\n", ttl_val );
    }

    send_addr.sin_family = AF_INET;
    send_addr.sin_addr.s_addr = htonl(EMULATOR_MCAST_ADDR);
    send_addr.sin_port = htons(EMULATOR_MCAST_PORT);

    for (i = 0; i < NUM_REPLICAS; i++) {
        payload.delay_ms[i] = 0;
        payload.trip[i] = 0;
    }

    /* multicast a timestamp in ms (for debugging) and 0/1 for CLOSE/TRIP*/
    while (1) {
    	for (i = 0; i < NUM_REPLICAS; i++) {
        	payload.delay_ms[i] = 0;
        	payload.trip[i] = 0;
	}

        printf("> ");
        fflush(stdout);
        if (scanf("%19s", input) != 1) break;

        if (input[0] == 'd') {
            if (scanf("%d", &sleep_ms) != 1)
                error_and_exit("Expected an int as argument\n", 1);

            sleep_timeout.tv_sec = sleep_ms / 1000;
            sleep_timeout.tv_usec = (sleep_ms % 1000) * 1000;
            
            select(0, NULL, NULL, NULL, &sleep_timeout);

        } else if (input[0] == 's' || input[0] == 'b') {
            if (input[0] == 's') {
                if (scanf("%d", &trip) != 1)
                    error_and_exit("Expected an int as argument\n", 1);

                for (i = 0; i < NUM_REPLICAS; i++) {
                    payload.delay_ms[i] = 0;
                    payload.trip[i] = trip;
                }

                payload.type = SV_SIMPLE;
            } else {
                for (i = 0; i < NUM_REPLICAS; i++) {
                    if (scanf("%lu", &payload.delay_ms[i]) != 1)
                        error_and_exit("Expected a long as argument\n", 1);
                    if (scanf("%d", &trip) != 1)
                        error_and_exit("Expected an int as argument\n", 1);
                    payload.trip[i] = trip;
                }

                payload.type = SV_BYZ;
            }

    	for (i = 0; i < NUM_REPLICAS; i++) {
		    Alarm(PRINT,"i=%d \tdelay=%lu, \ttrip=%d\n",i,payload.delay_ms[i],payload.trip[i]);
    		}
            gettimeofday(&now, NULL);
            payload.time_ms = now.tv_sec * 1000 + now.tv_usec / 1000;

            ret = sendto(s, &payload, sizeof(payload), 0, (struct sockaddr *)&send_addr, sizeof(send_addr));

            if (ret < 0)
                error_and_exit("Mcast: sendto\n", 1);
            printf("\nSimulator: Sent event\n");

		} else {
            printf("Invalid input \n");
        }
    }
    return 0;
}

void usage(int argc, char **argv) {
    if (argc <= 1)
        return;

    if (strcmp(argv[1], "-h") == 0) {
        printf("Commands:\n");
        printf("d <n> : Delay for <n> miliseconds\n");
        printf("s <t> : Send simple message with trip = <t>\n");
        printf("b (<n> <t>) * NUM_OF_RELAYS : Send a byzantine message. Input NUM_REPLICAS pairs of delay = <n> and trip = <t>\n");
    }
}

