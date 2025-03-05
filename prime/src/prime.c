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

#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include "arch.h"
#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_memory.h"
#include "spu_data_link.h"
#include "net_types.h"
#include "objects.h"
#include "network.h"
#include "data_structs.h"
#include "utility.h"
#include "error_wrapper.h"
#include "recon.h"
#include "tc_wrapper.h"
#include "proactive_recovery.h"

/* Externally defined global variables */
extern server_variables   VAR;
extern network_variables  NET;
extern server_data_struct DATA;
extern int Curr_N;
extern int Curr_k;
extern int Curr_f;
/* Local Function Definitions */
void Usage(int argc, char **argv);
void Print_Usage(void);
void Init_Memory_Objects(void);

int main(int argc, char** argv) 
{
  setlinebuf(stdout);
  Usage(argc, argv);
  Alarm_set_types(NONE);
  //Alarm_set_types(STATUS);
  //Alarm_set_types(PRINT);
  //Alarm_set_types(DEBUG);
  Alarm_enable_timestamp_high_res(NULL);

  Alarm( PRINT, "/===========================================================================\\\n");
  Alarm( PRINT, "| Prime                                                                     |\n");
  Alarm( PRINT, "| Copyright (c) 2010 - 2025 Johns Hopkins University                        |\n");
  Alarm( PRINT, "| All rights reserved.                                                      |\n");
  Alarm( PRINT, "|                                                                           |\n");
  Alarm( PRINT, "| Prime is licensed under the Prime Open-Source License.                    |\n");
  Alarm( PRINT, "| You may only use this software in compliance with the License.            |\n");
  Alarm( PRINT, "| A copy of the License can be found at http://www.prime.org/LICENSE.txt    |\n");
  Alarm( PRINT, "|                                                                           |\n");
  Alarm( PRINT, "| Creators:                                                                 |\n");
  Alarm( PRINT, "|    Yair Amir                 yairamir@cs.jhu.edu                          |\n");
  Alarm( PRINT, "|    Jonathan Kirsch           jak@cs.jhu.edu                               |\n");
  Alarm( PRINT, "|    John Lane                 johnlane@cs.jhu.edu                          |\n");
  Alarm( PRINT, "|    Marco Platania            platania@cs.jhu.edu                          |\n");
  Alarm( PRINT, "|    Amy Babay                 babay@pitt.edu                               |\n");
  Alarm( PRINT, "|    Thomas Tantillo           tantillo@cs.jhu.edu                          |\n");
  Alarm( PRINT, "|                                                                           |\n");
  Alarm( PRINT, "| Major Contributors:                                                       |\n");
  Alarm( PRINT, "|    Brian Coan                Design of the Prime algorithm                |\n");
  Alarm( PRINT, "|    Jeff Seibert              View Change protocol                         |\n");
  Alarm( PRINT, "|    Sahiti Bommareddy         Reconfiguration                              |\n");
  Alarm( PRINT, "|    Maher Khan                Reconfiguration                              |\n");
  Alarm( PRINT, "|                                                                           |\n");
  Alarm( PRINT, "| WWW:     www.dsn.jhu/prime   www.dsn.jhu.edu                              |\n");
  Alarm( PRINT, "| Contact: prime@dsn.jhu.edu                                                |\n");
  Alarm( PRINT, "|                                                                           |\n");
  Alarm( PRINT, "| Version 4.1, Built March 5, 2025                                          |\n");
  Alarm( PRINT, "|                                                                           |\n");
  Alarm( PRINT, "| This product uses software developed by Spread Concepts LLC for use       |\n");
  Alarm( PRINT, "| in the Spread toolkit. For more information about Spread,                 |\n");
  Alarm( PRINT, "| see http://www.spread.org                                                 |\n");
  Alarm( PRINT, "\\===========================================================================/\n\n");  

  /* This is the server program */
  NET.program_type = NET_SERVER_PROGRAM_TYPE;  
  
  Alarm(PRINT,"Running Server local id %d  and TPM id %d\n", VAR.My_Server_ID,VAR.My_Tpm_ID);

  // Ignore the SIGPIPE signal, handle manually with socket send error
  signal(SIGPIPE, SIG_IGN);

  /* Load server addresses from configuration file */
  UTIL_Load_Addresses(); 
  
  ERROR_WRAPPER_Initialize(); 

  E_init(); 
  Init_Memory_Objects();
  Init_Network();
  
  /* Initialize RSA Keys */
  /* PRTODO: eventually change this to loading TPM public keys from ROM */
  OPENSSL_RSA_Init();
  OPENSSL_RSA_Read_Keys(VAR.My_Server_ID, RSA_SERVER,"./keys");
  TC_Read_Public_Key("./keys");
  TC_Read_Partial_Key(VAR.My_Server_ID, 1,"./keys"); /* only "1" site */

  Alarm(PRINT, "Finished reading keys.\n");

  /* Initialize this server's data structures */
  DAT_Initialize();  

  /* Start the proactive recovery process for this replica */
  PR_Start_Recovery();

  /* Start the server's main event loop */
  E_handle_events();

  return 0;
}

void Init_Memory_Objects(void)
{
  /* Initilize memory object types  */
  Mem_init_object_abort(PACK_BODY_OBJ,    "packet",         sizeof(packet),           100,  1);
  Mem_init_object_abort(SYS_SCATTER,      "sys_scatter",    sizeof(sys_scatter),      100,  1);
  Mem_init_object_abort(DLL_NODE_OBJ,     "dll_node_obj",   sizeof(dll_node_struct),  200, 20);
  Mem_init_object_abort(PO_SLOT_OBJ,      "po_slot",        sizeof(po_slot),          200, 20);
  Mem_init_object_abort(ORD_SLOT_OBJ,     "ord_slot",       sizeof(ord_slot),         200, 20);
  Mem_init_object_abort(ERASURE_NODE_OBJ, "erasure_node",   sizeof(erasure_node),     200, 20);
  Mem_init_object_abort(ERASURE_PART_OBJ, "erasure_part",   sizeof(erasure_part_obj), 200, 20);
  Mem_init_object_abort(RECON_SLOT_OBJ,   "recon_slot",     sizeof(recon_slot),       200, 20);
  Mem_init_object_abort(NET_STRUCT_OBJ,   "net_struct",     sizeof(net_struct),       200, 20);
  Mem_init_object_abort(RB_SLOT_OBJ,      "rb_slot",        sizeof(rb_slot),          200, 20);
  /*SM2022: TODO*/
  Mem_init_object_abort(MSG_ARRAY_OBJ,    "msg_array",      sizeof(signed_message *) * MAX_NUM_SERVER_SLOTS,          200, 20);
}

void Usage(int argc, char **argv)
{
  int tmp;
  float tmp2;

  if(MAX_NUM_SERVERS < (3*NUM_F + 2*NUM_K + 1)) {
    Alarm(PRINT, "Configuration error: MAX_NUM_SERVERS must be greater than or equal to 3f+2k+1\n");
    exit(0);
  }

  VAR.My_Server_ID         = 1;
  VAR.F                    = NUM_F;
  VAR.K                    = NUM_K;
  VAR.Num_Servers          = (3* VAR.F + 2* VAR.K +1);
   
  if(VAR.Num_Servers < (3*NUM_F + 2*NUM_K + 1)) {
    Alarm(PRINT, "Configuration error: NUM_SERVERS is less than 3f+2k+1\n");
    exit(0);
  }
  //MS2022: set initial global incarnation number to 0
  DATA.NM.global_configuration_number=0;
  DATA.NM.PartOfConfig = 1;

  DATA.ORD.delay_attack           = 0;
  DATA.ORD.microseconds_delayed   = 0;
  DATA.ORD.step_duration          = 30.0;
  DATA.ORD.inconsistent_pp_attack = 0;
  DATA.ORD.inconsistent_pp_type   = 0;
  DATA.ORD.inconsistent_delay     = 30.0;
  while(--argc > 0) {
    Alarm(DEBUG, "MS2022: argc=%d\n",argc);
    argv++;

    /* [-i server_id] */
    if( (argc > 1) && (!strncmp(*argv, "-i", 2)) ) {
      sscanf(argv[1], "%d", &tmp);
      VAR.My_Server_ID = tmp;
      if(VAR.My_Server_ID > VAR.Num_Servers || VAR.My_Server_ID <= 0) {
	Alarm(PRINT,"Invalid server id: %d.  Index must be between 1 and %d.\n",
	      VAR.My_Server_ID, VAR.Num_Servers);
	exit(0);
      }
      argc--; argv++;
    }
    else if( (argc > 2) && (!strncmp(*argv, "-d", 2)) ) {
      DATA.ORD.delay_attack = 1;
      sscanf(argv[1], "%d", &tmp);
      DATA.ORD.microseconds_delayed = tmp;
      argc--; argv++;
      sscanf(argv[1], "%f", &tmp2);
      DATA.ORD.step_duration = tmp2;
      if (tmp2 == 0) {
        Alarm(PRINT, "Invalid step duration %f. Must be > 0\n" , tmp2);
        exit(0);
      }
      argc--; argv++;
    }
    else if ( (argc > 2) && (!strncmp(*argv, "-a", 2)) ) {
      DATA.ORD.inconsistent_pp_attack = 1;
      sscanf(argv[1], "%d", &tmp);
      DATA.ORD.inconsistent_pp_type = tmp;
      if (tmp < 1 || tmp > 3) {
        Alarm(PRINT, "Invalid type %d to attack w/ inconsistent PP. 1, 2, or 3 is valid\n", tmp);
        exit(0);
      }
      argc--; argv++;
      sscanf(argv[1], "%f", &tmp2);
      DATA.ORD.inconsistent_delay = tmp2;
      if (tmp2 == 0) {
        Alarm(PRINT, "Invalid inconsistent PP delay %f. Must be > 0\n" , tmp2);
        exit(0);
      }
      argc--; argv++;
    }
    else if ((argc > 1) && (!strncmp(*argv, "-g", 2))){
        sscanf(argv[1], "%d", &tmp);
        printf("MS2022:TPM id from cmd line%d\n",tmp);
        VAR.My_Tpm_ID = tmp;
        if (tmp < 1 || tmp > MAX_NUM_SERVERS){
            Alarm(PRINT,"Invalid TPM ID it should be 1...MAX_NUM_SERVERS\n");
            exit(0);
        }
        argc--; argv++;
    }
    else
      Print_Usage();
  }
}

void Print_Usage()
{
  Alarm(PRINT, "Usage: ./server\n"
	"\t[-i local_id -g tpm_id, indexed base 1, default 1]\n");
  exit(0);
}
