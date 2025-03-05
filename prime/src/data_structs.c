/*
 * Prime.
 *     
 * The contents of this file are subject to the Prime Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.dsn.jhu.edu/prime/LICENSE.txt
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis, 
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
 * for the specific language governing rights and limitations under the 
 * License.
 *
 * Creators:
 *   Yair Amir            yairamir@cs.jhu.edu
 *   Jonathan Kirsch      jak@cs.jhu.edu
 *   John Lane            johnlane@cs.jhu.edu
 *   Marco Platania       platania@cs.jhu.edu
 *   Amy Babay            babay@pitt.edu
 *   Thomas Tantillo      tantillo@cs.jhu.edu 
 *
 *
 * Major Contributors:
 *   Brian Coan           Design of the Prime algorithm
 *   Jeff Seibert         View Change protocol 
 *   Sahiti Bommareddy    Reconfiguration 
 *   Maher Khan           Reconfiguration 
 *      
 * Copyright (c) 2008-2025
 * The Johns Hopkins University.
 * All rights reserved.
 * 
 * Partial funding for Prime research was provided by the Defense Advanced 
 * Research Projects Agency (DARPA) and the National Science Foundation (NSF).
 * Prime is not necessarily endorsed by DARPA or the NSF.  
 *
 */

/* data_structs.c: This file contains all globally defined data structures.
 * This corresponds closely to the datastructure section of the pseudocode. The
 * structures are defined in data_structs.h and the variables are defined here.
 * We also define initialization and utility functions. */

/* Globally Accessible Variables -- These should be the only global variables
 * in the program -- Note that global does not refer to "global ordering" but
 * instead to standard global variables in C */

#include <stdlib.h>
#include "data_structs.h"
#include "spu_memory.h"
#include "spu_alarm.h"
#include "stopwatch.h"
#include "process.h"
#include "pre_order.h"
#include "order.h"
#include "signature.h"
#include "suspect_leader.h"
#include "reliable_broadcast.h"
#include "view_change.h"
#include "catchup.h"
#include "proactive_recovery.h"
#include "utility.h"

/* The globally accessible variables */

server_variables    VAR;
network_variables   NET;
server_data_struct  DATA;
benchmark_struct    BENCH;
int Curr_N, Curr_K,Curr_f;


/* Data structure initialization funtions */

void DAT_Reinitialize() 
{
  /* Initialize data structures */
  PR_Initialize_Data_Structure();
  PRE_ORDER_Initialize_Data_Structure();
  ORDER_Initialize_Data_Structure();
  SIG_Initialize_Data_Structure();
  SUSPECT_Initialize_Data_Structure();
  RB_Initialize_Data_Structure();
  VIEW_Initialize_Data_Structure();
  CATCH_Initialize_Data_Structure();
  Alarm(DEBUG, "During reconf reinitialized PO, ORDER, SIG, SUSP, RB, VIEW, CATCH, and PR data structures.\n");

  /* We need to initialize the erasure codes no matter what because
   * we use erasure-encoded reconciliation in Prime. */
  ERASURE_Initialize();

  /*
  int32u i;
  
  BENCH.updates_executed         = 0;
  BENCH.num_po_requests_sent     = 0;
  BENCH.total_updates_requested  = 0;
  BENCH.num_po_acks_sent         = 0;
  BENCH.num_acks                 = 0;
  BENCH.num_flooded_pre_prepares = 0;
  BENCH.clock_started            = 0;

  BENCH.num_signatures = 0;
  BENCH.total_signed_messages = 0;
  BENCH.max_signature_batch_size = 0;
  for(i = 0; i < MAX_MESS_TYPE; i++) {
    BENCH.signature_types[i] = 0;
    BENCH.profile_count[i] = 0;
  }


  */
}


void DAT_Initialize() 
{
  int32u i;
  /* signed_message *mess; */
  /* char buf[128]; */
  
  /* VAR and NET get initialized elsewhere. */
  
  /* Initialize data structures */
  DATA.View    = 1;
  PR_Initialize_Data_Structure();
  PRE_ORDER_Initialize_Data_Structure();
  ORDER_Initialize_Data_Structure();
  SIG_Initialize_Data_Structure();
  SUSPECT_Initialize_Data_Structure();
  RB_Initialize_Data_Structure();
  VIEW_Initialize_Data_Structure();
  CATCH_Initialize_Data_Structure();
  Alarm(DEBUG, "Initialized PO, ORDER, SIG, SUSP, RB, VIEW, CATCH, and PR data structures.\n");

  /* We need to initialize the erasure codes no matter what because
   * we use erasure-encoded reconciliation in Prime. */
  ERASURE_Initialize();

  BENCH.updates_executed         = 0;
  BENCH.num_po_requests_sent     = 0;
  BENCH.total_updates_requested  = 0;
  BENCH.num_po_acks_sent         = 0;
  BENCH.num_acks                 = 0;
  BENCH.num_flooded_pre_prepares = 0;
  BENCH.clock_started            = 0;

  BENCH.num_signatures = 0;
  BENCH.total_signed_messages = 0;
  BENCH.max_signature_batch_size = 0;
  for(i = 0; i < MAX_MESS_TYPE; i++) {
    BENCH.signature_types[i] = 0;
    BENCH.profile_count[i] = 0;
  }

  /* sprintf(buf, "state_machine_out.%d.log", VAR.My_Server_ID);
  if((BENCH.state_machine_fp = fopen(buf, "w")) == NULL) {
    Alarm(PRINT, "Could not open file %s for writing.\n", buf);
    exit(0);
  } */

  /* Send first PO-Request to tell everyone about my incarnation change */
  /* mess = PRE_ORDER_Construct_Update(NEW_INCARNATION);
  PROCESS_Message(mess);
  dec_ref_cnt(mess); */

  Alarm(PRINT, "Initialized data structures.\n");
}
