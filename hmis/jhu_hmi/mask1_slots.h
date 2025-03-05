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

extern "C" {
    #include "scada_packets.h"
    #include "net_wrapper.h"
    #include "itrc.h"
}

extern unsigned int Seq_Num;
extern int ipc_sock;
extern itrc_data itrc_in;

static int slotInit(PARAM *p, DATA *d)
{
  printf("SLOT_INIT \n");
  FILE * fp;
  int line_size = 100;
  char line[100];
  char *token;
  char *ret;
  if(p == NULL || d == NULL) return -1;
  memset(d,0,sizeof(DATA));

  /*Do init stuff here */
  fp = fopen("../../init/ini", "r");
  if(fp == NULL) {
      fprintf(stderr, "problems opening the file. abort");
      exit(1);
  }
  //Find size of tool tip array
  ret = fgets(line,line_size, fp); //ignore this line
  if(ret == NULL) {
    fprintf(stderr, "read issue");
    exit(1);
  }

  ret = fgets(line,line_size, fp);
  if(ret == NULL) {
    fprintf(stderr, "read issue");
    exit(1);
  }
  d->len = atoi(line);
  d->status = new char[d->len];
  d->info_arr = new info[d->len];
  //Store tool tip array
  ret = fgets(line,line_size, fp); //ignore this line
  if(ret == NULL) {
    fprintf(stderr, "read issue");
    exit(1);
  }

  for(int i = 0; i < d->len; i++) {
    int count = 0;

    ret = fgets(line, line_size, fp);
    if(ret == NULL) {
      fprintf(stderr, "read issue");
      exit(1);
    }

    token = strtok(line, " ");
    d->info_arr[i].type = atoi(token);
    token = strtok(NULL, " ");
    while(token != NULL) {
      d->info_arr[i].tooltip_list[count] = atoi(token);
      token = strtok(NULL, " ");
      count++; 
    }
    d->info_arr[i].ttl_len = (short)count;
  }

  //Set default of status array to 0
  for(int i=0; i < d->len; i++) {
    d->status[i] = 0;
  }

  fclose(fp);

  pvDownloadFile(p, "no_power.png");
  pvDownloadFile(p, "has_power.png");
  pvDownloadFile(p, "open_switch.png");
  pvDownloadFile(p, "closed_switch.png");
  pvDownloadFile(p, "fault_switch.png");
  Init_Master(d);
  return 0;
}

static int slotNullEvent(PARAM *p, DATA *d)
{
  if(p == NULL || d == NULL) return -1;
  for(int i = 0; i < d->len; i++) {
    switch(d->info_arr[i].type) {
      //box
      case 0: {
        //not powered
        if(d->status[i] == 0){
          pvSetPaletteBackgroundColor(p, d->info_arr[i].tooltip_list[0], 0, 0, 0);
        }
        //powered
        else if(d->status[i] == 1){
          pvSetPaletteBackgroundColor(p, d->info_arr[i].tooltip_list[0], 0, 0, 255);
        }
        //mistake throw error
        else{
          fprintf(stderr, "Status array error at position %d, Box\n", i);
          exit(1);
        }
        break;
      }
      //transformer
      case 1: {
        //not working
        if(d->status[i] == 0){
          pvSetImage(p, d->info_arr[i].tooltip_list[0], "no_power.png");
        }
        //working
        else if(d->status[i] == 1){
          pvSetImage(p, d->info_arr[i].tooltip_list[0], "has_power.png");
        }
        //mistake throw error
        else{
          fprintf(stderr, "Status array error at position %d, TX\n", i);
          exit(1);
        }
        break;
      }
      //switch
      case 2: {
        //open
        if(d->status[i] == 0){
          pvSetImage(p, d->info_arr[i].tooltip_list[0], "open_switch.png");
        }
        //closed
        else if(d->status[i] == 1){
          pvSetImage(p, d->info_arr[i].tooltip_list[0], "closed_switch.png");
        }
        //tripped
        else if(d->status[i] == 2){
          pvSetImage(p, d->info_arr[i].tooltip_list[0], "fault_switch.png");
        }
        //mistake throw error
        else{
          fprintf(stderr, "Status array error at position %d, Switch\n", i);
          exit(1);
        }
        break;
      }
      //line
      case 3: {
        //not powered
        if(d->status[i] == 0){
          for(int j = 0; j < d->info_arr[i].ttl_len; j++) {
            pvSetPaletteForegroundColor(p, d->info_arr[i].tooltip_list[j], 0, 0, 0);
          }
        }
        //powered
        else if(d->status[i] == 1){
          for(int j = 0; j < d->info_arr[i].ttl_len; j++) {
            pvSetPaletteForegroundColor(p, d->info_arr[i].tooltip_list[j], 0, 255, 0);
          }
        }
        //broken
        else if(d->status[i] == 2){
          for(int j = 0; j < d->info_arr[i].ttl_len; j++) {
            pvSetPaletteForegroundColor(p, d->info_arr[i].tooltip_list[j], 255, 0, 0);
          }
        }
        //mistake throw error
        else{
          fprintf(stderr, "Status array error at position %d", i);
          exit(1);
        }
        break;
      }
    }
  }
  return 0;
}

static int slotButtonEvent(PARAM *p, int id, DATA *d)
{
  signed_message *mess; 
  seq_pair ps;
  int nbytes;

  if(p == NULL || id == 0 || d == NULL) return -1;

  for(int i = 0; i < d->len; i++) {
    if(d->info_arr[i].tooltip_list[0] == id) {
      ps.incarnation = My_Incarnation;
      ps.seq_num = Seq_Num;
      if(d->info_arr[i].type == 1)
        mess = PKT_Construct_HMI_Command_Msg(ps, MAX_EMU_RTU + My_ID, JHU, TRANSFORMER, i);
      else
        mess = PKT_Construct_HMI_Command_Msg(ps, MAX_EMU_RTU + My_ID, JHU, SWITCH, i);
      mess->global_configuration_number=My_Global_Configuration_Number;
      nbytes = sizeof(signed_message) + mess->len;
      Seq_Num++;
      IPC_Send(ipc_sock, (void *)mess, nbytes, itrc_in.ipc_remote);
      free(mess);
      return 0;
    }
  }
  //if control reaches here then the click was on something I don't care about
  return 0;
}

static int slotButtonPressedEvent(PARAM *p, int id, DATA *d)
{
  if(p == NULL || id == 0 || d == NULL) return -1;
  return 0;
}

static int slotButtonReleasedEvent(PARAM *p, int id, DATA *d)
{
  if(p == NULL || id == 0 || d == NULL) return -1;
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
