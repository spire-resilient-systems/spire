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

#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>

#include "spu_alarm.h"
#include "spu_events.h"
#include "spines_lib.h"

#include "ss_net_wrapper.h"
#include "def.h"
#include "packets.h"
#include "ss_tc_wrapper.h"
#include "ss_openssl_rsa.h"
#include "data_structs.h"
#include "recovery.h"
#include "decision.h"




int myId = 0;

/* Local functions */
static void Usage(int, char **);
static void print_notice();

int main(int argc, char** argv)
{
    Usage(argc, argv);

    print_notice();

    setlinebuf(stdout);
    Alarm_enable_timestamp_high_res("%m/%d/%y %H:%M:%S");
    //Alarm_set_types(NULL);
    Alarm_set_types(PRINT);
    //Alarm_set_types(STATUS);
    //Alarm_set_types(DEBUG);
    //Alarm_set_types(PRINT|STATUS|DEBUG);
    Alarm_set_priority(SPLOG_INFO);

    /* Initialize everything */
    Init_Server_Data(myId);
    Init_Network(myId);
    Init_Bench_Stats();
    OPENSSL_RSA_Init();
    
    /* Read keys */
    TC_Read_Public_Key(TM_KEYS);
    TC_Read_Partial_Key(DATA.id, TM_KEYS);
    
    E_init();
    RECOVERY_Start();


    

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

void Usage(int argc, char **argv)
{
    if (argc != 2) {
        Alarm(EXIT, "Usage: %s relayID\n", argv[0]);
    }

    sscanf(argv[1], "%d", &myId);
    if (myId < 1 || myId > NUM_REPLICAS) {
        Alarm(EXIT, "Invalid ID: %d\n", myId);
    }

}
