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
////////////////////////////////////////////////////////////////////////////
//
// show_mask3 for ProcessViewServer created: Thu Jun 8 16:31:31 2017
//
////////////////////////////////////////////////////////////////////////////
#include "pvapp.h"

// _begin_of_generated_area_ (do not edit -> use ui2pvc) -------------------

// our mask contains the following objects
enum {
  ID_MAIN_WIDGET = 0,
  PP2_Control_Panel_frame,
  PP2_Title_label,
  PP2_T1_Title_label,
  PP2_T1_Indicator_image,
  PP2_T1_Current_LCD,
  PP2_T2_Title_label,
  PP2_T2_Indicator_image,
  PP2_Max_label,
  PP2_T1_Max_LCD,
  PP2_T2_Current_LCD,
  PP2_T2_Max_LCD,
  PP2_T3_Title_label,
  PP2_T3_Indicator_image,
  PP2_T3_Current_LCD,
  PP2_T3_Max_LCD,
  PP2_Home_button,
  PP2_T1_Deactivate_button,
  PP2_T2_Deactivate_button,
  PP2_T3_Deactivate_button,
  PP2_Current_Generation_Column_label,
  obj9,
  Legend_label,
  obj10,
  obj11,
  Legend_Faulty_label,
  Legend_Active_label,
  Legend_Green_image,
  Legend_Black_image,
  Legend_Inactive_label,
  Legend_Unresponsive_label,
  obj12,
  PP2_Power_Plant_Overview_frame,
  PP2_Overview_PP2_Stats_label,
  PP2_Overview_Overall_Current_Generation_LCD,
  PP2_Overview_PP2_Current_Maximum_LCD,
  PP2_Current_Maximum_label,
  PP2_Overview_Overall_Current_Generation_label,
  PP2_Overview_Overall_Current_Demand_LCD,
  PP2_Overview_Overall_Current_Demand_label,
  PP2_Overview_All_Stats_label,
  PP2_Overview__PP2_Current_Generation,
  PP2_Overview_Overall_Current_Target_label,
  PP2_Overview_Overall_Current_Target_LCD,
  PP2_Overview_PP2_Current_Generation_LCD,
  PP2_graph,
  ID_END_OF_WIDGETS
};

// our mask contains the following widget names
  static const char *widgetName[] = {
  "ID_MAIN_WIDGET",
  "PP2_Control_Panel_frame",
  "PP2_Title_label",
  "PP2_T1_Title_label",
  "PP2_T1_Indicator_image",
  "PP2_T1_Current_LCD",
  "PP2_T2_Title_label",
  "PP2_T2_Indicator_image",
  "PP2_Max_label",
  "PP2_T1_Max_LCD",
  "PP2_T2_Current_LCD",
  "PP2_T2_Max_LCD",
  "PP2_T3_Title_label",
  "PP2_T3_Indicator_image",
  "PP2_T3_Current_LCD",
  "PP2_T3_Max_LCD",
  "PP2_Home_button",
  "PP2_T1_Deactivate_button",
  "PP2_T2_Deactivate_button",
  "PP2_T3_Deactivate_button",
  "PP2_Current_Generation_Column_label",
  "obj9",
  "Legend_label",
  "obj10",
  "obj11",
  "Legend_Faulty_label",
  "Legend_Active_label",
  "Legend_Green_image",
  "Legend_Black_image",
  "Legend_Inactive_label",
  "Legend_Unresponsive_label",
  "obj12",
  "PP2_Power_Plant_Overview_frame",
  "PP2_Overview_PP2_Stats_label",
  "PP2_Overview_Overall_Current_Generation_LCD",
  "PP2_Overview_PP2_Current_Maximum_LCD",
  "PP2_Current_Maximum_label",
  "PP2_Overview_Overall_Current_Generation_label",
  "PP2_Overview_Overall_Current_Demand_LCD",
  "PP2_Overview_Overall_Current_Demand_label",
  "PP2_Overview_All_Stats_label",
  "PP2_Overview__PP2_Current_Generation",
  "PP2_Overview_Overall_Current_Target_label",
  "PP2_Overview_Overall_Current_Target_LCD",
  "PP2_Overview_PP2_Current_Generation_LCD",
  "PP2_graph",
  "ID_END_OF_WIDGETS",
  ""};

  static const char *toolTip[] = {
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  ""};

  static const char *whatsThis[] = {
  "",
  "",
  "",
  "",
  "assets/blue.png",
  "",
  "",
  "assets/blue.png",
  "",
  "",
  "",
  "",
  "",
  "assets/blue.png",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "assets/blue.png",
  "assets/red.png",
  "",
  "",
  "assets/green.png",
  "assets/black.png",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  ""};

  static const int widgetType[ID_END_OF_WIDGETS+1] = {
  0,
  TQFrame,
  TQLabel,
  TQLabel,
  TQImage,
  TQLCDNumber,
  TQLabel,
  TQImage,
  TQLabel,
  TQLCDNumber,
  TQLCDNumber,
  TQLCDNumber,
  TQLabel,
  TQImage,
  TQLCDNumber,
  TQLCDNumber,
  TQPushButton,
  TQPushButton,
  TQPushButton,
  TQPushButton,
  TQLabel,
  TQFrame,
  TQLabel,
  TQImage,
  TQImage,
  TQLabel,
  TQLabel,
  TQImage,
  TQImage,
  TQLabel,
  TQLabel,
  TQFrame,
  TQFrame,
  TQLabel,
  TQLCDNumber,
  TQLCDNumber,
  TQLabel,
  TQLabel,
  TQLCDNumber,
  TQLabel,
  TQLabel,
  TQLabel,
  TQLabel,
  TQLCDNumber,
  TQLCDNumber,
  TQwtPlotWidget,
  -1 };

static int generated_defineMask(PARAM *p)
{
  int w,h,depth;

  if(p == NULL) return 1;
  if(widgetName[0] == NULL) return 1; // suppress unused warning
  w = h = depth = strcmp(toolTip[0],whatsThis[0]);
  if(widgetType[0] == -1) return 1;
  if(w==h) depth=0; // fool the compiler
  pvStartDefinition(p,ID_END_OF_WIDGETS);

  pvQFrame(p,PP2_Control_Panel_frame,0,Panel,Raised,3,1);
  pvSetGeometry(p,PP2_Control_Panel_frame,369,42,768,231);
  pvSetFont(p,PP2_Control_Panel_frame,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,PP2_Title_label,PP2_Control_Panel_frame);
  pvSetGeometry(p,PP2_Title_label,228,15,350,30);
  pvSetText(p,PP2_Title_label,pvtr("Renewables Control Panel"));
  pvSetFont(p,PP2_Title_label,"Ubuntu",14,1,0,0,0);

  pvQLabel(p,PP2_T1_Title_label,PP2_Control_Panel_frame);
  pvSetGeometry(p,PP2_T1_Title_label,18,90,75,30);
  pvSetText(p,PP2_T1_Title_label,pvtr("Solar"));
  pvSetFont(p,PP2_T1_Title_label,"Ubuntu",11,0,0,0,0);

  pvDownloadFile(p,"assets/blue.png");
  pvQImage(p,PP2_T1_Indicator_image,PP2_Control_Panel_frame,"assets/blue.png",&w,&h,&depth);
  pvSetGeometry(p,PP2_T1_Indicator_image,96,93,22,22);
  pvSetFont(p,PP2_T1_Indicator_image,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,PP2_T1_Indicator_image,pvtr("assets/blue.png"));

  pvQLCDNumber(p,PP2_T1_Current_LCD,PP2_Control_Panel_frame,4,Flat,Dec);
  pvSetGeometry(p,PP2_T1_Current_LCD,243,90,75,30);
  pvSetFont(p,PP2_T1_Current_LCD,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,PP2_T2_Title_label,PP2_Control_Panel_frame);
  pvSetGeometry(p,PP2_T2_Title_label,18,132,75,30);
  pvSetText(p,PP2_T2_Title_label,pvtr("Hydro"));
  pvSetFont(p,PP2_T2_Title_label,"Ubuntu",11,0,0,0,0);

  pvDownloadFile(p,"assets/blue.png");
  pvQImage(p,PP2_T2_Indicator_image,PP2_Control_Panel_frame,"assets/blue.png",&w,&h,&depth);
  pvSetGeometry(p,PP2_T2_Indicator_image,96,135,23,23);
  pvSetFont(p,PP2_T2_Indicator_image,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,PP2_T2_Indicator_image,pvtr("assets/blue.png"));

  pvQLabel(p,PP2_Max_label,PP2_Control_Panel_frame);
  pvSetGeometry(p,PP2_Max_label,339,54,90,30);
  pvSetText(p,PP2_Max_label,pvtr("Maximum\nGeneration"));
  pvSetFont(p,PP2_Max_label,"Ubuntu",11,0,0,0,0);

  pvQLCDNumber(p,PP2_T1_Max_LCD,PP2_Control_Panel_frame,4,Flat,Dec);
  pvSetGeometry(p,PP2_T1_Max_LCD,339,90,75,30);
  pvSetFont(p,PP2_T1_Max_LCD,"Ubuntu",11,0,0,0,0);

  pvQLCDNumber(p,PP2_T2_Current_LCD,PP2_Control_Panel_frame,4,Flat,Dec);
  pvSetGeometry(p,PP2_T2_Current_LCD,243,132,75,30);
  pvSetFont(p,PP2_T2_Current_LCD,"Ubuntu",11,0,0,0,0);

  pvQLCDNumber(p,PP2_T2_Max_LCD,PP2_Control_Panel_frame,4,Flat,Dec);
  pvSetGeometry(p,PP2_T2_Max_LCD,339,132,75,30);
  pvSetFont(p,PP2_T2_Max_LCD,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,PP2_T3_Title_label,PP2_Control_Panel_frame);
  pvSetGeometry(p,PP2_T3_Title_label,18,174,99,30);
  pvSetText(p,PP2_T3_Title_label,pvtr("Wind"));
  pvSetFont(p,PP2_T3_Title_label,"Ubuntu",11,0,0,0,0);

  pvDownloadFile(p,"assets/blue.png");
  pvQImage(p,PP2_T3_Indicator_image,PP2_Control_Panel_frame,"assets/blue.png",&w,&h,&depth);
  pvSetGeometry(p,PP2_T3_Indicator_image,96,177,23,23);
  pvSetFont(p,PP2_T3_Indicator_image,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,PP2_T3_Indicator_image,pvtr("assets/blue.png"));

  pvQLCDNumber(p,PP2_T3_Current_LCD,PP2_Control_Panel_frame,4,Flat,Dec);
  pvSetGeometry(p,PP2_T3_Current_LCD,243,174,75,30);
  pvSetFont(p,PP2_T3_Current_LCD,"Ubuntu",11,0,0,0,0);

  pvQLCDNumber(p,PP2_T3_Max_LCD,PP2_Control_Panel_frame,4,Flat,Dec);
  pvSetGeometry(p,PP2_T3_Max_LCD,339,174,75,30);
  pvSetFont(p,PP2_T3_Max_LCD,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,PP2_Home_button,PP2_Control_Panel_frame);
  pvSetGeometry(p,PP2_Home_button,21,18,120,30);
  pvSetText(p,PP2_Home_button,pvtr("Home Screen"));
  pvSetFont(p,PP2_Home_button,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,PP2_T1_Deactivate_button,PP2_Control_Panel_frame);
  pvSetGeometry(p,PP2_T1_Deactivate_button,132,90,99,30);
  pvSetText(p,PP2_T1_Deactivate_button,pvtr("Deactivate"));
  pvSetFont(p,PP2_T1_Deactivate_button,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,PP2_T2_Deactivate_button,PP2_Control_Panel_frame);
  pvSetGeometry(p,PP2_T2_Deactivate_button,132,132,99,30);
  pvSetText(p,PP2_T2_Deactivate_button,pvtr("Deactivate"));
  pvSetFont(p,PP2_T2_Deactivate_button,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,PP2_T3_Deactivate_button,PP2_Control_Panel_frame);
  pvSetGeometry(p,PP2_T3_Deactivate_button,132,174,99,30);
  pvSetText(p,PP2_T3_Deactivate_button,pvtr("Deactivate"));
  pvSetFont(p,PP2_T3_Deactivate_button,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,PP2_Current_Generation_Column_label,PP2_Control_Panel_frame);
  pvSetGeometry(p,PP2_Current_Generation_Column_label,243,54,90,30);
  pvSetText(p,PP2_Current_Generation_Column_label,pvtr("Current\nGeneration"));
  pvSetFont(p,PP2_Current_Generation_Column_label,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,obj9,0,Panel,Raised,3,1);
  pvSetGeometry(p,obj9,150,42,195,231);
  pvSetFont(p,obj9,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,Legend_label,obj9);
  pvSetGeometry(p,Legend_label,61,9,110,30);
  pvSetText(p,Legend_label,pvtr("Legend"));
  pvSetFont(p,Legend_label,"Ubuntu",14,1,0,0,0);

  pvDownloadFile(p,"assets/blue.png");
  pvQImage(p,obj10,obj9,"assets/blue.png",&w,&h,&depth);
  pvSetGeometry(p,obj10,36,51,25,25);
  pvSetFont(p,obj10,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,obj10,pvtr("assets/blue.png"));

  pvDownloadFile(p,"assets/red.png");
  pvQImage(p,obj11,obj9,"assets/red.png",&w,&h,&depth);
  pvSetGeometry(p,obj11,36,93,25,25);
  pvSetFont(p,obj11,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,obj11,pvtr("assets/red.png"));

  pvQLabel(p,Legend_Faulty_label,obj9);
  pvSetGeometry(p,Legend_Faulty_label,72,48,99,30);
  pvSetText(p,Legend_Faulty_label,pvtr("Faulty"));
  pvSetFont(p,Legend_Faulty_label,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,Legend_Active_label,obj9);
  pvSetGeometry(p,Legend_Active_label,72,90,75,30);
  pvSetText(p,Legend_Active_label,pvtr("Active"));
  pvSetFont(p,Legend_Active_label,"Ubuntu",11,0,0,0,0);

  pvDownloadFile(p,"assets/green.png");
  pvQImage(p,Legend_Green_image,obj9,"assets/green.png",&w,&h,&depth);
  pvSetGeometry(p,Legend_Green_image,36,135,25,25);
  pvSetFont(p,Legend_Green_image,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,Legend_Green_image,pvtr("assets/green.png"));

  pvDownloadFile(p,"assets/black.png");
  pvQImage(p,Legend_Black_image,obj9,"assets/black.png",&w,&h,&depth);
  pvSetGeometry(p,Legend_Black_image,36,177,25,25);
  pvSetFont(p,Legend_Black_image,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,Legend_Black_image,pvtr("assets/black.png"));

  pvQLabel(p,Legend_Inactive_label,obj9);
  pvSetGeometry(p,Legend_Inactive_label,72,132,99,30);
  pvSetText(p,Legend_Inactive_label,pvtr("Inactive"));
  pvSetFont(p,Legend_Inactive_label,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,Legend_Unresponsive_label,obj9);
  pvSetGeometry(p,Legend_Unresponsive_label,72,174,120,30);
  pvSetText(p,Legend_Unresponsive_label,pvtr("Unresponsive"));
  pvSetFont(p,Legend_Unresponsive_label,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,obj12,0,Panel,Raised,3,1);
  pvSetGeometry(p,obj12,150,300,987,438);
  pvSetFont(p,obj12,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,PP2_Power_Plant_Overview_frame,obj12,Panel,Raised,3,1);
  pvSetGeometry(p,PP2_Power_Plant_Overview_frame,15,12,264,411);
  pvSetFont(p,PP2_Power_Plant_Overview_frame,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,PP2_Overview_PP2_Stats_label,PP2_Power_Plant_Overview_frame);
  pvSetGeometry(p,PP2_Overview_PP2_Stats_label,36,216,150,30);
  pvSetText(p,PP2_Overview_PP2_Stats_label,pvtr("Power Plant 2"));
  pvSetFont(p,PP2_Overview_PP2_Stats_label,"Sans Serif",14,1,0,0,0);

  pvQLCDNumber(p,PP2_Overview_Overall_Current_Generation_LCD,PP2_Power_Plant_Overview_frame,4,Flat,Dec);
  pvSetGeometry(p,PP2_Overview_Overall_Current_Generation_LCD,129,105,75,30);
  pvSetFont(p,PP2_Overview_Overall_Current_Generation_LCD,"Ubuntu",11,0,0,0,0);

  pvQLCDNumber(p,PP2_Overview_PP2_Current_Maximum_LCD,PP2_Power_Plant_Overview_frame,4,Flat,Dec);
  pvSetGeometry(p,PP2_Overview_PP2_Current_Maximum_LCD,129,303,75,30);
  pvSetFont(p,PP2_Overview_PP2_Current_Maximum_LCD,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,PP2_Current_Maximum_label,PP2_Power_Plant_Overview_frame);
  pvSetGeometry(p,PP2_Current_Maximum_label,36,303,75,30);
  pvSetText(p,PP2_Current_Maximum_label,pvtr(" Current\nMaximum"));
  pvSetFont(p,PP2_Current_Maximum_label,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,PP2_Overview_Overall_Current_Generation_label,PP2_Power_Plant_Overview_frame);
  pvSetGeometry(p,PP2_Overview_Overall_Current_Generation_label,36,105,100,30);
  pvSetText(p,PP2_Overview_Overall_Current_Generation_label,pvtr("  Current\nGeneration"));
  pvSetFont(p,PP2_Overview_Overall_Current_Generation_label,"Ubuntu",11,0,0,0,0);

  pvQLCDNumber(p,PP2_Overview_Overall_Current_Demand_LCD,PP2_Power_Plant_Overview_frame,4,Flat,Dec);
  pvSetGeometry(p,PP2_Overview_Overall_Current_Demand_LCD,129,60,75,30);
  pvSetFont(p,PP2_Overview_Overall_Current_Demand_LCD,"Sans Serif",9,0,0,0,0);

  pvQLabel(p,PP2_Overview_Overall_Current_Demand_label,PP2_Power_Plant_Overview_frame);
  pvSetGeometry(p,PP2_Overview_Overall_Current_Demand_label,42,60,75,30);
  pvSetText(p,PP2_Overview_Overall_Current_Demand_label,pvtr("Current\nDemand"));
  pvSetFont(p,PP2_Overview_Overall_Current_Demand_label,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,PP2_Overview_All_Stats_label,PP2_Power_Plant_Overview_frame);
  pvSetGeometry(p,PP2_Overview_All_Stats_label,54,15,160,30);
  pvSetText(p,PP2_Overview_All_Stats_label,pvtr("Overall Stats"));
  pvSetFont(p,PP2_Overview_All_Stats_label,"Ubuntu",15,1,0,0,0);

  pvQLabel(p,PP2_Overview__PP2_Current_Generation,PP2_Power_Plant_Overview_frame);
  pvSetGeometry(p,PP2_Overview__PP2_Current_Generation,27,258,100,30);
  pvSetText(p,PP2_Overview__PP2_Current_Generation,pvtr("  Current\nGeneration"));
  pvSetFont(p,PP2_Overview__PP2_Current_Generation,"Ubuntu",11,0,0,0,0);
  pvSetStyle(p,PP2_Overview__PP2_Current_Generation,-1,Raised,-1,-1);

  pvQLabel(p,PP2_Overview_Overall_Current_Target_label,PP2_Power_Plant_Overview_frame);
  pvSetGeometry(p,PP2_Overview_Overall_Current_Target_label,45,147,70,35);
  pvSetText(p,PP2_Overview_Overall_Current_Target_label,pvtr("Current\n Target"));
  pvSetFont(p,PP2_Overview_Overall_Current_Target_label,"Ubuntu",11,0,0,0,0);

  pvQLCDNumber(p,PP2_Overview_Overall_Current_Target_LCD,PP2_Power_Plant_Overview_frame,4,Flat,Dec);
  pvSetGeometry(p,PP2_Overview_Overall_Current_Target_LCD,129,150,75,30);
  pvSetFont(p,PP2_Overview_Overall_Current_Target_LCD,"Sans Serif",9,0,0,0,0);

  pvQLCDNumber(p,PP2_Overview_PP2_Current_Generation_LCD,PP2_Power_Plant_Overview_frame,4,Flat,Dec);
  pvSetGeometry(p,PP2_Overview_PP2_Current_Generation_LCD,129,258,75,30);
  pvSetFont(p,PP2_Overview_PP2_Current_Generation_LCD,"Ubuntu",11,0,0,0,0);

  pvQwtPlotWidget(p,PP2_graph,obj12,10,1000);
  pvSetGeometry(p,PP2_graph,297,21,650,400);
  qpwSetCanvasBackground(p,PP2_graph,212,208,200);
  qpwEnableAxis(p,PP2_graph,yLeft);
  qpwEnableAxis(p,PP2_graph,xBottom);
  pvSetFont(p,PP2_graph,"Ubuntu",11,0,0,0,0);


  pvEndDefinition(p);
  return 0;
}

// _end_of_generated_area_ (do not edit -> use ui2pvc) ---------------------

#include "mask3_slots.h"

static int defineMask(PARAM *p)
{
  if(p == NULL) return 1;
  generated_defineMask(p);
  // (todo: add your code here)
  return 0;
}


static int showData(PARAM *p, DATA *d)
{
  if(p == NULL) return 1;
  if(d == NULL) return 1;
  return 0;
}

static int readData(DATA *d) // from shared memory, database or something else
{
  if(d == NULL) return 1;
  // (todo: add your code here)
  return 0;
}


int show_mask3(PARAM *p)
{
  DATA d;
  char event[MAX_EVENT_LENGTH];
  char text[MAX_EVENT_LENGTH];
  char str1[MAX_EVENT_LENGTH];
  int  i,w,h,val,x,y,button,ret;
  float xval, yval;

  defineMask(p);
  //rlSetDebugPrintf(1);
  if((ret=slotInit(p,&d)) != 0) return ret;
  readData(&d); // from shared memory, database or something else
  showData(p,&d);
  pvClearMessageQueue(p);
  while(1)
  {
    pvPollEvent(p,event);
    switch(pvParseEvent(event, &i, text))
    {
      case NULL_EVENT:
        readData(&d); // from shared memory, database or something else
        showData(p,&d);
        if((ret=slotNullEvent(p,&d)) != 0) return ret;
        break;
      case BUTTON_EVENT:
        if(trace) printf("BUTTON_EVENT id=%d\n",i);
        if((ret=slotButtonEvent(p,i,&d)) != 0) return ret;
        break;
      case BUTTON_PRESSED_EVENT:
        if(trace) printf("BUTTON_PRESSED_EVENT id=%d\n",i);
        if((ret=slotButtonPressedEvent(p,i,&d)) != 0) return ret;
        break;
      case BUTTON_RELEASED_EVENT:
        if(trace) printf("BUTTON_RELEASED_EVENT id=%d\n",i);
        if((ret=slotButtonReleasedEvent(p,i,&d)) != 0) return ret;
        break;
      case TEXT_EVENT:
        if(trace) printf("TEXT_EVENT id=%d %s\n",i,text);
        if((ret=slotTextEvent(p,i,&d,text)) != 0) return ret;
        break;
      case SLIDER_EVENT:
        sscanf(text,"(%d)",&val);
        if(trace) printf("SLIDER_EVENT val=%d\n",val);
        if((ret=slotSliderEvent(p,i,&d,val)) != 0) return ret;
        break;
      case CHECKBOX_EVENT:
        if(trace) printf("CHECKBOX_EVENT id=%d %s\n",i,text);
        if((ret=slotCheckboxEvent(p,i,&d,text)) != 0) return ret;
        break;
      case RADIOBUTTON_EVENT:
        if(trace) printf("RADIOBUTTON_EVENT id=%d %s\n",i,text);
        if((ret=slotRadioButtonEvent(p,i,&d,text)) != 0) return ret;
        break;
      case GL_INITIALIZE_EVENT:
        if(trace) printf("you have to call initializeGL()\n");
        if((ret=slotGlInitializeEvent(p,i,&d)) != 0) return ret;
        break;
      case GL_PAINT_EVENT:
        if(trace) printf("you have to call paintGL()\n");
        if((ret=slotGlPaintEvent(p,i,&d)) != 0) return ret;
        break;
      case GL_RESIZE_EVENT:
        sscanf(text,"(%d,%d)",&w,&h);
        if(trace) printf("you have to call resizeGL(w,h)\n");
        if((ret=slotGlResizeEvent(p,i,&d,w,h)) != 0) return ret;
        break;
      case GL_IDLE_EVENT:
        if((ret=slotGlIdleEvent(p,i,&d)) != 0) return ret;
        break;
      case TAB_EVENT:
        sscanf(text,"(%d)",&val);
        if(trace) printf("TAB_EVENT(%d,page=%d)\n",i,val);
        if((ret=slotTabEvent(p,i,&d,val)) != 0) return ret;
        break;
      case TABLE_TEXT_EVENT:
        sscanf(text,"(%d,%d,",&x,&y);
        pvGetText(text,str1);
        if(trace) printf("TABLE_TEXT_EVENT(%d,%d,\"%s\")\n",x,y,str1);
        if((ret=slotTableTextEvent(p,i,&d,x,y,str1)) != 0) return ret;
        break;
      case TABLE_CLICKED_EVENT:
        sscanf(text,"(%d,%d,%d)",&x,&y,&button);
        if(trace) printf("TABLE_CLICKED_EVENT(%d,%d,button=%d)\n",x,y,button);
        if((ret=slotTableClickedEvent(p,i,&d,x,y,button)) != 0) return ret;
        break;
      case SELECTION_EVENT:
        sscanf(text,"(%d,",&val);
        pvGetText(text,str1);
        if(trace) printf("SELECTION_EVENT(column=%d,\"%s\")\n",val,str1);
        if((ret=slotSelectionEvent(p,i,&d,val,str1)) != 0) return ret;
        break;
      case CLIPBOARD_EVENT:
        sscanf(text,"(%d",&val);
        if(trace) printf("CLIPBOARD_EVENT(id=%d)\n",val);
        if((ret=slotClipboardEvent(p,i,&d,val)) != 0) return ret;
        break;
      case RIGHT_MOUSE_EVENT:
        if(trace) printf("RIGHT_MOUSE_EVENT id=%d text=%s\n",i,text);
        if((ret=slotRightMouseEvent(p,i,&d,text)) != 0) return ret;
        break;
      case KEYBOARD_EVENT:
        sscanf(text,"(%d",&val);
        if(trace) printf("KEYBOARD_EVENT modifier=%d key=%d\n",i,val);
        if((ret=slotKeyboardEvent(p,i,&d,val,i)) != 0) return ret;
        break;
      case PLOT_MOUSE_MOVED_EVENT:
        sscanf(text,"(%f,%f)",&xval,&yval);
        if(trace) printf("PLOT_MOUSE_MOVE %f %f\n",xval,yval);
        if((ret=slotMouseMovedEvent(p,i,&d,xval,yval)) != 0) return ret;
        break;
      case PLOT_MOUSE_PRESSED_EVENT:
        sscanf(text,"(%f,%f)",&xval,&yval);
        if(trace) printf("PLOT_MOUSE_PRESSED %f %f\n",xval,yval);
        if((ret=slotMousePressedEvent(p,i,&d,xval,yval)) != 0) return ret;
        break;
      case PLOT_MOUSE_RELEASED_EVENT:
        sscanf(text,"(%f,%f)",&xval,&yval);
        if(trace) printf("PLOT_MOUSE_RELEASED %f %f\n",xval,yval);
        if((ret=slotMouseReleasedEvent(p,i,&d,xval,yval)) != 0) return ret;
        break;
      case MOUSE_OVER_EVENT:
        sscanf(text,"%d",&val);
        if(trace) printf("MOUSE_OVER_EVENT %d\n",val);
        if((ret=slotMouseOverEvent(p,i,&d,val)) != 0) return ret;
        break;
      case USER_EVENT:
        if(trace) printf("USER_EVENT id=%d %s\n",i,text);
        if((ret=slotUserEvent(p,i,&d,text)) != 0) return ret;
        break;
      default:
        if(trace) printf("UNKNOWN_EVENT id=%d %s\n",i,text);
        break;
    }
  }
}
