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

//###############################################################
//# mask1_slots.h for ProcessViewServer created: Wed Jun 3 11:10:58 2015
//# please fill out these slots
//# here you find all possible events
//# Yours: Lehrig Software Engineering

// todo: uncomment me if you want to use this data aquisiton
// also uncomment this classes in main.cpp and pvapp.h
// also remember to uncomment rllib in the project file
//extern rlModbusClient     modbus;
//extern rlSiemensTCPClient siemensTCP;
//extern rlPPIClient        ppi;

#include "master_exec.h"
#include <sys/time.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

extern "C" {
    #include "../common/scada_packets.h"
    #include "../common/net_wrapper.h"
    #include "../common/itrc.h"
    #include "stdutil/stdcarr.h"
    #include "spu_events.h"
}

extern unsigned int Seq_Num;
extern int ipc_sock;
extern itrc_data itrc_in;
extern struct timeval button_press_time;
extern struct timeval min_wait;
extern int Script_Button_Pushed;
extern int Script_Pipe[2];

void modelInit()
{
  data_model *d;
  int ret, ioctl_cmd;

  d = &the_model;

  /* Initialize min wait timers */
  min_wait.tv_sec  = 0;
  min_wait.tv_usec = 250000;
  
  /* Initialize Script timers/values */
  Next_Button.sec  = 8;
  Next_Button.usec = 0;
  Button_Pressed_Duration.sec  = 2;
  Button_Pressed_Duration.usec = 0;
  Script_Breaker_Index = 0;
  Script_Breaker_Val = BREAKER_ON;

  /* Setup the points (shorts) */
  for(int i = 0; i < NUM_POINT; i++) {
    d->point_arr[i].type = DIAL;
    d->point_arr[i].value = 0;
  }
  d->point_arr[0].id = dial1;
  d->point_arr[1].id = dial2;
  d->point_arr[2].id = dial3;
  d->point_arr[3].id = dial4;
  d->point_arr[4].id = -1; //dial5;
  d->point_arr[5].id = -1; //dial6;
  d->point_arr[6].id = -1; //dial7;
  d->point_arr[7].id = -1; //dial8;

  /* Setup the read-only breakers */
  for(int i=0; i < NUM_BREAKER; i += 2) {
    d->br_read_arr[i].type = BR_OPENED;
    d->br_read_arr[i].value = 0;
    d->br_read_arr[i+1].type = BR_CLOSED;
    d->br_read_arr[i+1].value = 1;
  }
  d->br_read_arr[0].id  = opened_b101;
    strncpy(d->br_read_arr[0].to_str, "B10-1 Opened", sizeof(d->br_read_arr[0].to_str));
  d->br_read_arr[1].id  = closed_b101;
    strncpy(d->br_read_arr[1].to_str, "B10-1 Closed", sizeof(d->br_read_arr[1].to_str));
  d->br_read_arr[2].id  = opened_b102;
    strncpy(d->br_read_arr[2].to_str, "B10-2 Opened", sizeof(d->br_read_arr[2].to_str));
  d->br_read_arr[3].id  = closed_b102;
    strncpy(d->br_read_arr[3].to_str, "B10-2 Closed", sizeof(d->br_read_arr[3].to_str));
  d->br_read_arr[4].id  = opened_b1012;
    strncpy(d->br_read_arr[4].to_str, "B10-12 Opened", sizeof(d->br_read_arr[4].to_str));
  d->br_read_arr[5].id  = closed_b1012;
    strncpy(d->br_read_arr[5].to_str, "B10-12 Closed", sizeof(d->br_read_arr[5].to_str));
  d->br_read_arr[6].id  = opened_b54;
    strncpy(d->br_read_arr[6].to_str, "B54 Opened", sizeof(d->br_read_arr[6].to_str));
  d->br_read_arr[7].id  = closed_b54;
    strncpy(d->br_read_arr[7].to_str, "B54 Closed", sizeof(d->br_read_arr[7].to_str));
  d->br_read_arr[8].id  = opened_b55;
    strncpy(d->br_read_arr[8].to_str, "B55 Opened", sizeof(d->br_read_arr[8].to_str));
  d->br_read_arr[9].id  = closed_b55;
    strncpy(d->br_read_arr[9].to_str, "B55 Closed", sizeof(d->br_read_arr[9].to_str));
  d->br_read_arr[10].id = opened_b56;
    strncpy(d->br_read_arr[10].to_str, "B56 Opened", sizeof(d->br_read_arr[10].to_str));
  d->br_read_arr[11].id = closed_b56;
    strncpy(d->br_read_arr[11].to_str, "B56 Closed", sizeof(d->br_read_arr[11].to_str));
  d->br_read_arr[12].id = opened_b57;
    strncpy(d->br_read_arr[12].to_str, "B57 Opened", sizeof(d->br_read_arr[12].to_str));
  d->br_read_arr[13].id = closed_b57;
    strncpy(d->br_read_arr[13].to_str, "B57 Closed", sizeof(d->br_read_arr[13].to_str));

  /* Setup the read-write breakers */
  for(int i=0; i < NUM_BREAKER; i += 2 ) {
    d->br_write_arr[i].type = BR_TRIP;
    d->br_write_arr[i].value = 0;
    d->br_write_arr[i+1].type = BR_CLOSE;
    d->br_write_arr[i+1].value = 1;
  }
  d->br_write_arr[0].id  = trip_b101;
    strncpy(d->br_write_arr[0].to_str, "Trip B10-1", sizeof(d->br_write_arr[0].to_str));
  d->br_write_arr[1].id  = close_b101;
    strncpy(d->br_write_arr[1].to_str, "Close B10-1", sizeof(d->br_write_arr[1].to_str));
  d->br_write_arr[2].id  = trip_b102;
    strncpy(d->br_write_arr[2].to_str, "Trip B10-2", sizeof(d->br_write_arr[2].to_str));
  d->br_write_arr[3].id  = close_b102;
    strncpy(d->br_write_arr[3].to_str, "Close B10-2", sizeof(d->br_write_arr[3].to_str));
  d->br_write_arr[4].id  = trip_b1012;
    strncpy(d->br_write_arr[4].to_str, "Trip B10-12", sizeof(d->br_write_arr[4].to_str));
  d->br_write_arr[5].id  = close_b1012;
    strncpy(d->br_write_arr[5].to_str, "Close B10-12", sizeof(d->br_write_arr[5].to_str));
  d->br_write_arr[6].id  = trip_b54;
    strncpy(d->br_write_arr[6].to_str, "Trip B54", sizeof(d->br_write_arr[6].to_str));
  d->br_write_arr[7].id  = close_b54;
    strncpy(d->br_write_arr[7].to_str, "Close B54", sizeof(d->br_write_arr[7].to_str));
  d->br_write_arr[8].id  = trip_b55;
    strncpy(d->br_write_arr[8].to_str, "Trip B55", sizeof(d->br_write_arr[8].to_str));
  d->br_write_arr[9].id  = close_b55;
    strncpy(d->br_write_arr[9].to_str, "Close B55", sizeof(d->br_write_arr[9].to_str));
  d->br_write_arr[10].id = trip_b56;
    strncpy(d->br_write_arr[10].to_str, "Trip B56", sizeof(d->br_write_arr[10].to_str));
  d->br_write_arr[11].id = close_b56;
    strncpy(d->br_write_arr[11].to_str, "Close B56", sizeof(d->br_write_arr[11].to_str));
  d->br_write_arr[12].id = trip_b57;
    strncpy(d->br_write_arr[12].to_str, "Trip B57", sizeof(d->br_write_arr[12].to_str));
  d->br_write_arr[13].id = close_b57;
    strncpy(d->br_write_arr[13].to_str, "Close B57", sizeof(d->br_write_arr[13].to_str));

  /* Setup the Script_Pipe */
  if (pipe(Script_Pipe) != 0)
    printf("Pipe failure on Script_Pipe\n"), exit(EXIT_FAILURE);

  ret = ioctl(Script_Pipe[0], FIONBIO, (ioctl_cmd = 1, &ioctl_cmd));
  if (ret == -1)
    printf("Non-blocking failure on Script_Pipe[0]\n"), exit(EXIT_FAILURE);

  ret = ioctl(Script_Pipe[1], FIONBIO, (ioctl_cmd = 1, &ioctl_cmd));
  if (ret == -1)
    printf("Non-blocking failure on Script_Pipe[1]\n"), exit(EXIT_FAILURE);
}

static int slotInit(PARAM *p, DATA *dptr)
{
  data_model *d;

  if(p == NULL || dptr == NULL) return -1;

  //memset(d,0,sizeof(DATA));
  //printf("SLOT_INIT: d = %p\n", d);

  dptr->dm = &the_model;
  d = dptr->dm;

  /* Initialize this broswer's button press timer */
  dptr->button_press_time.tv_sec  = 0;
  dptr->button_press_time.tv_usec = 0;
  dptr->print_seq = 0;

  for (int i = 0; i < NUM_POINT; i++) {
    if (d->point_arr[i].id == -1)
        continue;

    qwtDialSetRange(p,d->point_arr[i].id,0,200.0);
    qwtDialSetNeedle(p,d->point_arr[i].id,QwtDialArrowNeedle,255,0,0,255,0,0,0,0,0);
    qwtDialShowBackground(p,d->point_arr[i].id,0);
    qwtDialSetFrameShadow(p,d->point_arr[i].id,DialPlain);
    qwtDialSetValue(p,d->point_arr[i].id,d->point_arr[i].value);
  }

  pvSetValue(p,script_history,25);
  pvSetEditable(p,script_history,0);

  pvDownloadFile(p, "green_on.png");
  pvDownloadFile(p, "green_off.png");
  pvDownloadFile(p, "red_on.png");
  pvDownloadFile(p, "red_off.png");
  //Init_Master(d);

  return 0;
}

static int slotNullEvent(PARAM *p, DATA *dptr)
{
  data_model *d;
  stdit it;
  
  if(p == NULL || dptr == NULL) return -1;

  d = dptr->dm;

  /* Update the dials */
  for (int i = 0; i < NUM_POINT; i++) {
    if (d->point_arr[i].id == -1)
        continue;
    qwtDialSetValue(p,d->point_arr[i].id,d->point_arr[i].value);
  } 

  /* Update the read-only breakers */
  for (int i = 0; i < NUM_BREAKER; i++) {
    if (d->br_read_arr[i].type == BR_OPENED) {
      if (d->br_read_arr[i].value == 0) {
        pvSetImage(p, d->br_read_arr[i].id, "green_off.png");
      }
      else if (d->br_read_arr[i].value == 1) {
        pvSetImage(p, d->br_read_arr[i].id, "green_on.png");
      }
      else {
        printf("ERROR: invalid value (%d) for opened read breaker %d\n", 
                d->br_read_arr[i].value, i);
      }
    }
    else if (d->br_read_arr[i].type == BR_CLOSED) {
      if (d->br_read_arr[i].value == 0) {
          pvSetImage(p, d->br_read_arr[i].id, "red_off.png");
      }
      else if (d->br_read_arr[i].value == 1) {
          pvSetImage(p, d->br_read_arr[i].id, "red_on.png");
      }
      else {
        printf("ERROR: invalid value (%d) for closed read breaker %d\n", 
                d->br_read_arr[i].value, i);
      }
    }
  }

  /* Update the read-write breakers - Nothing at the moment? */
  for (int i = 0; i < NUM_BREAKER; i++) {
    if (d->br_write_arr[i].value == 0) {
      pvSetFont(p, d->br_write_arr[i].id, "Ubuntu",11,0,0,0,0);
    }
    else if (d->br_write_arr[i].value == 1) {
      pvSetFont(p, d->br_write_arr[i].id, "Ubuntu",11,1,0,0,0);
    }
    else {
        printf("ERROR: invalid value (%d) for write breaker %d\n", 
                d->br_write_arr[i].value, i);
    }
  }

  /* Update the Script Command History */
  if (dptr->print_seq < Script_History_Seq) {
      pvClear(p,script_history); 
      for (stdcarr_begin(&Script_History, &it); !stdcarr_is_end(&Script_History, &it);
            stdcarr_it_next(&it))
      {
        pvPrintf(p,script_history,(char *)stdcarr_it_val(&it));
      }
      dptr->print_seq = Script_History_Seq;
  }

  /* Update the Script Indicator Label */
  if (Script_Running == 0) 
    pvSetText(p,script_indicator,"Script Inactive");
  else
    pvSetText(p,script_indicator,"Script Running");

  return 0;
}

static int slotButtonEvent(PARAM *p, int id, DATA *dptr)
{
  if(p == NULL || id == 0 || dptr == NULL) return -1;

  switch(id) {
    case script_restart:
        Script_Button_Pushed = RESTART_SCRIPT;
        Append_History("Restarting Script (User Locked Out)");
        break;
    case script_pause:
        if (Script_Running == 0)
            return 0;
        Script_Button_Pushed = PAUSE_SCRIPT;
        Append_History("Pausing Script (Ready For User)");
        break;
    case script_continue:
        if (Script_Running == 1)
            return 0;
        Script_Button_Pushed = CONTINUE_SCRIPT;
        Append_History("Continuing Script (User Locked Out)");
        break;
    default:
        return 0;
  }

  if (write(Script_Pipe[1], &id, 1) != 1)
    printf("write failure in slotButtonEvent\n"), exit(EXIT_FAILURE);

  return 0;
}

static int slotButtonPressedEvent(PARAM *p, int id, DATA *dptr)
{
  signed_message *mess; 
  seq_pair ps;
  int nbytes;
  data_model *d;

  if(p == NULL || id == 0 || dptr == NULL) return -1;

  if (Script_Running) {
    printf("Script Running - User Locked Out\n");
    Append_History("Script Running! User Input Locked Out");
    return 0;
  }

  d = dptr->dm;

  for(int i = 0; i < NUM_BREAKER; i++) {
    if(d->br_write_arr[i].id == id) {
      gettimeofday(&dptr->button_press_time, NULL);
      ps.incarnation = My_Incarnation;
      ps.seq_num = Seq_Num;
      mess = PKT_Construct_HMI_Command_Msg(ps, MAX_EMU_RTU + My_ID, PNNL, BREAKER_ON, i);

      mess->global_configuration_number=My_Global_Configuration_Number;
      nbytes = sizeof(signed_message) + mess->len;
      Seq_Num++;
      IPC_Send(ipc_sock, (void *)mess, nbytes, itrc_in.ipc_remote);
      free(mess);
      return 0;
    }
  }

  return 0;
}

static int slotButtonReleasedEvent(PARAM *p, int id, DATA *dptr)
{
  signed_message *mess; 
  seq_pair ps;
  int nbytes;
  struct timeval now, diff;
  data_model *d;

  if(p == NULL || id == 0 || dptr == NULL) return -1;

  if (Script_Running) {
    printf("Script Running - User Locked Out\n");
    return 0;
  }

  d = dptr->dm;

  for(int i = 0; i < NUM_BREAKER; i++) {
    if(d->br_write_arr[i].id == id) {

      /* Hack to make sure PLC has enough time to process each message */
      gettimeofday(&now, NULL);
      diff = diffTime(now, dptr->button_press_time);
      printf("diff = %u sec, %u micro\n", (unsigned int)diff.tv_sec, (unsigned int)diff.tv_usec);
      if (compTime(diff, min_wait) < 0) {
        diff = diffTime(min_wait, diff);
        printf("sleeping for %u microseconds\n", (unsigned int)diff.tv_usec);
        usleep(diff.tv_sec*1000000 + diff.tv_usec);
      }

      ps.incarnation = My_Incarnation;
      ps.seq_num = Seq_Num;
      mess = PKT_Construct_HMI_Command_Msg(ps, MAX_EMU_RTU + My_ID, PNNL, BREAKER_OFF, i);

      mess->global_configuration_number=My_Global_Configuration_Number;
      nbytes = sizeof(signed_message) + mess->len;
      Seq_Num++;
      IPC_Send(ipc_sock, (void *)mess, nbytes, itrc_in.ipc_remote);
      free(mess);
      return 0;
    }
  }

  return 0;
}

static int slotTextEvent(PARAM *p, int id, DATA *d, const char *text)
{
  if(p == NULL || id == 0 || d == NULL || text == NULL) return -1;
  return 0;
}

static int slotSliderEvent(PARAM *p, int id, DATA *d, int val)
{
  if(p == NULL || id == 0 || d == NULL || val < -1000) return -1;
  return 0;
}

static int slotCheckboxEvent(PARAM *p, int id, DATA *d, const char *text)
{
  if(p == NULL || id == 0 || d == NULL || text == NULL) return -1;
  return 0;
}

static int slotRadioButtonEvent(PARAM *p, int id, DATA *d, const char *text)
{
  if(p == NULL || id == 0 || d == NULL || text == NULL) return -1;
  return 0;
}

static int slotGlInitializeEvent(PARAM *p, int id, DATA *d)
{
  if(p == NULL || id == 0 || d == NULL) return -1;
  return 0;
}

static int slotGlPaintEvent(PARAM *p, int id, DATA *d)
{
  if(p == NULL || id == 0 || d == NULL) return -1;
  return 0;
}

static int slotGlResizeEvent(PARAM *p, int id, DATA *d, int width, int height)
{
  if(p == NULL || id == 0 || d == NULL || width < 0 || height < 0) return -1;
  return 0;
}

static int slotGlIdleEvent(PARAM *p, int id, DATA *d)
{
  if(p == NULL || id == 0 || d == NULL) return -1;
  return 0;
}

static int slotTabEvent(PARAM *p, int id, DATA *d, int val)
{
  if(p == NULL || id == 0 || d == NULL || val < -1000) return -1;
  return 0;
}

static int slotTableTextEvent(PARAM *p, int id, DATA *d, int x, int y, const char *text)
{
  if(p == NULL || id == 0 || d == NULL || x < -1000 || y < -1000 || text == NULL) return -1;
  return 0;
}

static int slotTableClickedEvent(PARAM *p, int id, DATA *d, int x, int y, int button)
{
  if(p == NULL || id == 0 || d == NULL || x < -1000 || y < -1000 || button < 0) return -1;
  return 0;
}

static int slotSelectionEvent(PARAM *p, int id, DATA *d, int val, const char *text)
{
  if(p == NULL || id == 0 || d == NULL || val < -1000 || text == NULL) return -1;
  return 0;
}

static int slotClipboardEvent(PARAM *p, int id, DATA *d, int val)
{
  if(p == NULL || id == 0 || d == NULL || val < -1000) return -1;
  return 0;
}

static int slotRightMouseEvent(PARAM *p, int id, DATA *d, const char *text)
{
  if(p == NULL || id == 0 || d == NULL || text == NULL) return -1;
  //pvPopupMenu(p,-1,"Menu1,Menu2,,Menu3");
  return 0;
}

static int slotKeyboardEvent(PARAM *p, int id, DATA *d, int val, int modifier)
{
  if(p == NULL || id == 0 || d == NULL || val < -1000 || modifier < -1000) return -1;
  return 0;
}

static int slotMouseMovedEvent(PARAM *p, int id, DATA *d, float x, float y)
{
  if(p == NULL || id == 0 || d == NULL || x < -1000 || y < -1000) return -1;
  return 0;
}

static int slotMousePressedEvent(PARAM *p, int id, DATA *d, float x, float y)
{
  if(p == NULL || id == 0 || d == NULL || x < -1000 || y < -1000) return -1;
  return 0;
}

static int slotMouseReleasedEvent(PARAM *p, int id, DATA *d, float x, float y)
{
  if(p == NULL || id == 0 || d == NULL || x < -1000 || y < -1000) return -1;
  return 0;
}

static int slotMouseOverEvent(PARAM *p, int id, DATA *d, int enter)
{
  if(p == NULL || id == 0 || d == NULL || enter < -1000) return -1;
  return 0;
}

static int slotUserEvent(PARAM *p, int id, DATA *d, const char *text)
{
  if(p == NULL || id == 0 || d == NULL || text == NULL) return -1;
  return 0;
}
