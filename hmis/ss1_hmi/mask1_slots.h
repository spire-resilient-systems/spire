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
    #include "scada_packets.h"
    #include "net_wrapper.h"
    #include "itrc.h"
    #include "stdutil/stdcarr.h"
    #include "spu_events.h"
}

extern unsigned int Seq_Num;
extern int ss_ext_spines;
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
  if (pipe(Script_Pipe) != 0)
    printf("Pipe failure on Script_Pipe\n"), exit(EXIT_FAILURE);

  for (int i = 0; i < SUBSTATION_NUM_POINT; i++) {
  	d->point_arr[i].id=-1;
  }
    d->point_arr[0].id = box_1;
    d->point_arr[1].id = box_2;
    d->point_arr[2].id = box_3;
    d->point_arr[3].id = box_4;
  for (int i = 0; i < SUBSTATION_NUM_POINT; i++) {
    if (d->point_arr[i].id == -1)
        continue;
    d->point_arr[i].value = -1;
   }
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
  // Messaging variables
  signed_message *mess; 
  seq_pair ps;
  int nbytes;

  if(p == NULL || dptr == NULL) return -1;

  //memset(d,0,sizeof(DATA));
  //printf("SLOT_INIT: d = %p\n", d);

  dptr->dm = &the_model;
  d = dptr->dm;

  /* Initialize this broswer's button press timer */
  dptr->button_press_time.tv_sec  = 0;
  dptr->button_press_time.tv_usec = 0;
  dptr->print_seq = 0;

  for (int i = 0; i < SUBSTATION_NUM_POINT; i++) {
    if (d->point_arr[i].id == -1)
        continue;
    printf("Slot Init i=%d, value=%d\n ",i,d->point_arr[i].value);
    if(d->point_arr[i].value ==-1)//Dont know
    {
	pvSetPaletteBackgroundColor(p,d->point_arr[i].id,255,255,255); //White	
	}else if(d->point_arr[i].value ==1)//tripped
    {
	pvSetPaletteBackgroundColor(p,d->point_arr[i].id,0,255,0); //Green
	} else //closed
    {	
	pvSetPaletteBackgroundColor(p,d->point_arr[i].id,255,0,0); //Red
	}
   }

  pvSetValue(p,alert_window,25);
  pvSetEditable(p,alert_window,0);

  pvDownloadFile(p, "87t.png");
    return 0;
}

static int slotNullEvent(PARAM *p, DATA *dptr)
{
  data_model *d;
  stdit it;
  
  if(p == NULL || dptr == NULL) return -1;

  d = dptr->dm;
  for (int i = 0; i < SUBSTATION_NUM_POINT; i++) {
    if (d->point_arr[i].id == -1)
        continue;
    //printf("Slot Null Event i=%d, value=%d\n ",i,d->point_arr[i].value);
    if(d->point_arr[i].value ==-1)//Dont know
    {
	pvSetPaletteBackgroundColor(p,d->point_arr[i].id,255,255,255); //White	
	}else if(d->point_arr[i].value ==1)//tripped
    {
	pvSetPaletteBackgroundColor(p,d->point_arr[i].id,0,255,0); //Green
	} else //closed
    {	
	pvSetPaletteBackgroundColor(p,d->point_arr[i].id,255,0,0); //Red
	}
   }

      /* Update the Script Command History */
  if (dptr->print_seq < Script_History_Seq) {
      pvClear(p,alert_window);
      for (stdcarr_begin(&Script_History, &it); !stdcarr_is_end(&Script_History, &it);
            stdcarr_it_next(&it))
      {
        pvPrintf(p,alert_window,(char *)stdcarr_it_val(&it));
      }
      dptr->print_seq = Script_History_Seq;
  }

  return 0;
}

static int slotButtonEvent(PARAM *p, int id, DATA *dptr)
{
  if(p == NULL || id == 0 || dptr == NULL) return -1;
  return 0;
}

static int slotButtonPressedEvent(PARAM *p, int id, DATA *dptr)
{

  if(p == NULL || id == 0 || dptr == NULL) return -1;
 
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

  d = dptr->dm;

      ps.incarnation = My_Incarnation;
      ps.seq_num = Seq_Num;
      if(id==3){
        printf("BREAKER ON (TRIP) Constructed id=%d\n",id);
        mess = PKT_Construct_HMI_Command_Msg(ps, MAX_EMU_RTU + My_ID, INTEGRATED_SS, BREAKER_ON, 1);
      }
      else if(id==4){
        printf("BREAKER OFF (CLOSE) Constructed id=%d\n",id);
        mess = PKT_Construct_HMI_Command_Msg(ps, MAX_EMU_RTU + My_ID, INTEGRATED_SS, BREAKER_OFF, 1);
      }
      else{
      return 0;
      }
      nbytes = sizeof(signed_message) + mess->len;
      Seq_Num++;
      gettimeofday(&dptr->button_press_time, NULL);
      send_to_ss(mess, nbytes);
      gettimeofday(&now, NULL);
      printf("********HMI Command issued at %u sec %u usec\n",now.tv_sec,now.tv_usec);
      free(mess);

      if(id==3){
        Append_History("Open SS CMD Issued");
      }else if(id==4){
        Append_History("Close SS CMD Issued");
      }else{return 0;}

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



