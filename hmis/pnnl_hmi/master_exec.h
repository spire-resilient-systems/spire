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
 * Copyright (c) 2017-2024 Johns Hopkins University.
 * All rights reserved.
 *
 * Partial funding for Spire research was provided by the Defense Advanced 
 * Research Projects Agency (DARPA), the Department of Defense (DoD), and the
 * Department of Energy (DoE).
 * Spire is not necessarily endorsed by DARPA, the DoD or the DoE. 
 *
 */

#include <vector>
#include <set>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern "C" {
    #include "../common/scada_packets.h"
    #include "stdutil/stdcarr.h"
    #include "spu_events.h"
}

#define MAX_LINES_IN_SEGMENT 2
using namespace std;

#define DIAL 1
#define BR_OPENED 2
#define BR_CLOSED 3
#define BR_TRIP 4
#define BR_CLOSE 5

enum Script_Button_States {NO_BUTTON, RESTART_SCRIPT, PAUSE_SCRIPT, CONTINUE_SCRIPT};

/* typedef struct info{
    int type;
    short ttl_len;
    int tooltip_list[MAX_LINES_IN_SEGMENT];
}info;

typedef struct // (todo: define your data structure here)
{
    int len;
    char *status;
    info *info_arr;
}
DATA; */

typedef struct point_info_d {
    int type;
    int id;
    int32u value;
    char to_str[80];
} point_info;

typedef struct breaker_info_d {
    int type;
    int id;
    char value;
    char to_str[80];
} breaker_info;

typedef struct data_model_d // (todo: define your data structure here)
{
    point_info   point_arr[NUM_POINT];
    breaker_info br_read_arr[NUM_BREAKER];
    breaker_info br_write_arr[NUM_BREAKER];
}
data_model;

extern unsigned int Seq_Num;
extern int ipc_sock;
extern itrc_data itrc_in, itrc_out;
extern struct timeval min_wait;
extern data_model the_model;
extern int Script_Running;
extern int Script_Button_Pushed;
extern int Script_Pipe[2];
extern stdcarr Script_History;
extern int Script_History_Seq;
extern int Script_Breaker_Index, Script_Breaker_Val;
extern sp_time Next_Button, Button_Pressed_Duration;

typedef struct {
    data_model *dm;
    struct timeval button_press_time;
    int print_seq;
}
DATA;

void Init_Master(DATA *);
void Read_From_Master(int s, int dummy1, void *dummy2);
void Execute_Script(int s, int dummy1, void *dummy2);
void Append_History(const char *m, ...);
