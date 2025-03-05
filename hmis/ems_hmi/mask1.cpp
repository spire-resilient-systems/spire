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
// show_mask1 for ProcessViewServer created: Wed Jun 7 23:44:41 2017
//
////////////////////////////////////////////////////////////////////////////
#include "pvapp.h"

// _begin_of_generated_area_ (do not edit -> use ui2pvc) -------------------

// our mask contains the following objects
enum {
  ID_MAIN_WIDGET = 0,
  PP1_box,
  PP1_Title_label,
  PP1_T1_label,
  PP1_T1_LCD,
  PP1_MW_label,
  PP1_T2_label,
  PP1_T2_LCD,
  PP1_T3_label,
  PP1_T3_LCD,
  PP1_T1_Indicator_image,
  PP1_T2_Indicator_image,
  PP1_T3_Indicator_image,
  PP1_total_output_label,
  PP1_Total_Generation_LCD,
  PP1_Detail_button,
  PP2_frame,
  PP2_Title_label,
  PP2_Detail_button,
  PP2_T1_label,
  PP2_T2_label,
  PP2_T1_Indicator_image,
  PP2_T2_Indicator_image,
  PP2_T3_Indicator_image,
  PP2_T1_LCD,
  PP2_T2_LCD,
  PP2_T3_LCD,
  PP2_Total_Generation_LCD,
  PP2_Total_Generation_label,
  obj14,
  PP2_MW_label,
  PP2_T3_label,
  obj11,
  obj12,
  obj8,
  Quick_Values_frame,
  Current_Values_Title_label,
  Current_Demand_label,
  Current_Generation_label,
  obj22,
  Current_Demand_LCD,
  Current_Generation_LCD,
  Highest_Timeframe_Label,
  Timeframe_1_Week_radio_button,
  Timeframe_1_Month_radio_button,
  Timeframe_24_Hours_radio_button,
  Legend_frame,
  Legend_Title_label,
  Legend_Blue_image,
  obj17,
  Legend_Red_image,
  obj18,
  Legend_Faulty_label,
  Legend_Active_label,
  Legend_Inactive_label,
  obj19,
  Legend_Unresponsive_label,
  obj20,
  Overview_graph,
  ID_END_OF_WIDGETS
};

// our mask contains the following widget names
  static const char *widgetName[] = {
  "ID_MAIN_WIDGET",
  "PP1_box",
  "PP1_Title_label",
  "PP1_T1_label",
  "PP1_T1_LCD",
  "PP1_MW_label",
  "PP1_T2_label",
  "PP1_T2_LCD",
  "PP1_T3_label",
  "PP1_T3_LCD",
  "PP1_T1_Indicator_image",
  "PP1_T2_Indicator_image",
  "PP1_T3_Indicator_image",
  "PP1_total_output_label",
  "PP1_Total_Generation_LCD",
  "PP1_Detail_button",
  "PP2_frame",
  "PP2_Title_label",
  "PP2_Detail_button",
  "PP2_T1_label",
  "PP2_T2_label",
  "PP2_T1_Indicator_image",
  "PP2_T2_Indicator_image",
  "PP2_T3_Indicator_image",
  "PP2_T1_LCD",
  "PP2_T2_LCD",
  "PP2_T3_LCD",
  "PP2_Total_Generation_LCD",
  "PP2_Total_Generation_label",
  "obj14",
  "PP2_MW_label",
  "PP2_T3_label",
  "obj11",
  "obj12",
  "obj8",
  "Quick_Values_frame",
  "Current_Values_Title_label",
  "Current_Demand_label",
  "Current_Generation_label",
  "obj22",
  "Current_Demand_LCD",
  "Current_Generation_LCD",
  "Highest_Timeframe_Label",
  "Timeframe_1_Week_radio_button",
  "Timeframe_1_Month_radio_button",
  "Timeframe_24_Hours_radio_button",
  "Legend_frame",
  "Legend_Title_label",
  "Legend_Blue_image",
  "obj17",
  "Legend_Red_image",
  "obj18",
  "Legend_Faulty_label",
  "Legend_Active_label",
  "Legend_Inactive_label",
  "obj19",
  "Legend_Unresponsive_label",
  "obj20",
  "Overview_graph",
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
  "",
  "",
  "",
  "",
  "",
  "",
  "assets/blue.png",
  "assets/blue.png",
  "assets/blue.png",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "assets/blue.png",
  "assets/blue.png",
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
  "assets/blue.png",
  "assets/blue.png",
  "assets/red.png",
  "assets/green.png",
  "",
  "",
  "",
  "assets/black.png",
  "",
  "",
  "",
  ""};

  static const int widgetType[ID_END_OF_WIDGETS+1] = {
  0,
  TQFrame,
  TQLabel,
  TQLabel,
  TQLCDNumber,
  TQLabel,
  TQLabel,
  TQLCDNumber,
  TQLabel,
  TQLCDNumber,
  TQImage,
  TQImage,
  TQImage,
  TQLabel,
  TQLCDNumber,
  TQPushButton,
  TQFrame,
  TQLabel,
  TQPushButton,
  TQLabel,
  TQLabel,
  TQImage,
  TQImage,
  TQImage,
  TQLCDNumber,
  TQLCDNumber,
  TQLCDNumber,
  TQLCDNumber,
  TQLabel,
  TQPushButton,
  TQLabel,
  TQLabel,
  TQFrame,
  TQLabel,
  TQFrame,
  TQFrame,
  TQLabel,
  TQLabel,
  TQLabel,
  TQFrame,
  TQLCDNumber,
  TQLCDNumber,
  TQLabel,
  TQRadio,
  TQRadio,
  TQRadio,
  TQFrame,
  TQLabel,
  TQImage,
  TQImage,
  TQImage,
  TQImage,
  TQLabel,
  TQLabel,
  TQLabel,
  TQImage,
  TQLabel,
  TQFrame,
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

  pvQFrame(p,PP1_box,0,Panel,Raised,3,1);
  pvSetGeometry(p,PP1_box,280,9,213,237);
  pvSetFont(p,PP1_box,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,PP1_Title_label,PP1_box);
  pvSetGeometry(p,PP1_Title_label,9,6,120,30);
  pvSetText(p,PP1_Title_label,pvtr("Power Plant 1"));
  pvSetFont(p,PP1_Title_label,"Ubuntu",11,1,0,0,0);

  pvQLabel(p,PP1_T1_label,PP1_box);
  pvSetGeometry(p,PP1_T1_label,42,54,120,30);
  pvSetText(p,PP1_T1_label,pvtr("Gen. 1"));
  pvSetFont(p,PP1_T1_label,"Ubuntu",11,0,0,0,0);

  pvQLCDNumber(p,PP1_T1_LCD,PP1_box,4,Flat,Dec);
  pvSetGeometry(p,PP1_T1_LCD,129,54,75,30);
  pvSetFont(p,PP1_T1_LCD,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,PP1_MW_label,PP1_box);
  pvSetGeometry(p,PP1_MW_label,156,24,50,30);
  pvSetText(p,PP1_MW_label,pvtr("MW"));
  pvSetFont(p,PP1_MW_label,"Ubuntu",9,0,0,0,0);

  pvQLabel(p,PP1_T2_label,PP1_box);
  pvSetGeometry(p,PP1_T2_label,42,87,120,30);
  pvSetText(p,PP1_T2_label,pvtr("Gen. 2"));
  pvSetFont(p,PP1_T2_label,"Ubuntu",11,0,0,0,0);

  pvQLCDNumber(p,PP1_T2_LCD,PP1_box,4,Flat,Dec);
  pvSetGeometry(p,PP1_T2_LCD,129,87,75,30);
  pvSetFont(p,PP1_T2_LCD,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,PP1_T3_label,PP1_box);
  pvSetGeometry(p,PP1_T3_label,42,120,99,30);
  pvSetText(p,PP1_T3_label,pvtr("Gen. 3"));
  pvSetFont(p,PP1_T3_label,"Ubuntu",11,0,0,0,0);

  pvQLCDNumber(p,PP1_T3_LCD,PP1_box,4,Flat,Dec);
  pvSetGeometry(p,PP1_T3_LCD,129,120,75,30);
  pvSetFont(p,PP1_T3_LCD,"Ubuntu",11,0,0,0,0);

  pvDownloadFile(p,"assets/blue.png");
  pvQImage(p,PP1_T1_Indicator_image,PP1_box,"assets/blue.png",&w,&h,&depth);
  pvSetGeometry(p,PP1_T1_Indicator_image,12,57,25,25);
  pvSetFont(p,PP1_T1_Indicator_image,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,PP1_T1_Indicator_image,pvtr("assets/blue.png"));

  pvDownloadFile(p,"assets/blue.png");
  pvQImage(p,PP1_T2_Indicator_image,PP1_box,"assets/blue.png",&w,&h,&depth);
  pvSetGeometry(p,PP1_T2_Indicator_image,12,90,25,25);
  pvSetFont(p,PP1_T2_Indicator_image,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,PP1_T2_Indicator_image,pvtr("assets/blue.png"));

  pvDownloadFile(p,"assets/blue.png");
  pvQImage(p,PP1_T3_Indicator_image,PP1_box,"assets/blue.png",&w,&h,&depth);
  pvSetGeometry(p,PP1_T3_Indicator_image,12,123,25,25);
  pvSetFont(p,PP1_T3_Indicator_image,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,PP1_T3_Indicator_image,pvtr("assets/blue.png"));

  pvQLabel(p,PP1_total_output_label,PP1_box);
  pvSetGeometry(p,PP1_total_output_label,42,153,120,30);
  pvSetText(p,PP1_total_output_label,pvtr("Total"));
  pvSetFont(p,PP1_total_output_label,"Ubuntu",11,0,0,0,0);

  pvQLCDNumber(p,PP1_Total_Generation_LCD,PP1_box,5,Flat,Dec);
  pvSetGeometry(p,PP1_Total_Generation_LCD,129,153,75,30);
  pvSetFont(p,PP1_Total_Generation_LCD,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,PP1_Detail_button,PP1_box);
  pvSetGeometry(p,PP1_Detail_button,15,192,150,30);
  pvSetText(p,PP1_Detail_button,pvtr("Open Detail Panel"));
  pvSetFont(p,PP1_Detail_button,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,PP2_frame,0,Panel,Raised,3,1);
  pvSetGeometry(p,PP2_frame,530,9,213,237);
  pvSetFont(p,PP2_frame,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,PP2_Title_label,PP2_frame);
  pvSetGeometry(p,PP2_Title_label,9,6,120,30);
  pvSetText(p,PP2_Title_label,pvtr("Renewables"));
  pvSetFont(p,PP2_Title_label,"Ubuntu",11,1,0,0,0);

  pvQPushButton(p,PP2_Detail_button,PP2_frame);
  pvSetGeometry(p,PP2_Detail_button,15,192,150,30);
  pvSetText(p,PP2_Detail_button,pvtr("Open Detail Panel"));
  pvSetFont(p,PP2_Detail_button,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,PP2_T1_label,PP2_frame);
  pvSetGeometry(p,PP2_T1_label,42,54,75,30);
  pvSetText(p,PP2_T1_label,pvtr("Solar"));
  pvSetFont(p,PP2_T1_label,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,PP2_T2_label,PP2_frame);
  pvSetGeometry(p,PP2_T2_label,42,87,75,30);
  pvSetText(p,PP2_T2_label,pvtr("Hydro"));
  pvSetFont(p,PP2_T2_label,"Ubuntu",11,0,0,0,0);

  pvDownloadFile(p,"assets/blue.png");
  pvQImage(p,PP2_T1_Indicator_image,PP2_frame,"assets/blue.png",&w,&h,&depth);
  pvSetGeometry(p,PP2_T1_Indicator_image,12,57,25,25);
  pvSetFont(p,PP2_T1_Indicator_image,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,PP2_T1_Indicator_image,pvtr("assets/blue.png"));

  pvDownloadFile(p,"assets/blue.png");
  pvQImage(p,PP2_T2_Indicator_image,PP2_frame,"assets/blue.png",&w,&h,&depth);
  pvSetGeometry(p,PP2_T2_Indicator_image,12,90,25,25);
  pvSetFont(p,PP2_T2_Indicator_image,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,PP2_T2_Indicator_image,pvtr("assets/blue.png"));

  pvDownloadFile(p,"assets/blue.png");
  pvQImage(p,PP2_T3_Indicator_image,PP2_frame,"assets/blue.png",&w,&h,&depth);
  pvSetGeometry(p,PP2_T3_Indicator_image,12,123,25,25);
  pvSetFont(p,PP2_T3_Indicator_image,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,PP2_T3_Indicator_image,pvtr("assets/blue.png"));

  pvQLCDNumber(p,PP2_T1_LCD,PP2_frame,4,Flat,Dec);
  pvSetGeometry(p,PP2_T1_LCD,129,54,75,30);
  pvSetFont(p,PP2_T1_LCD,"Ubuntu",11,0,0,0,0);

  pvQLCDNumber(p,PP2_T2_LCD,PP2_frame,4,Flat,Dec);
  pvSetGeometry(p,PP2_T2_LCD,129,87,75,30);
  pvSetFont(p,PP2_T2_LCD,"Ubuntu",11,0,0,0,0);

  pvQLCDNumber(p,PP2_T3_LCD,PP2_frame,4,Flat,Dec);
  pvSetGeometry(p,PP2_T3_LCD,129,120,75,30);
  pvSetFont(p,PP2_T3_LCD,"Ubuntu",11,0,0,0,0);

  pvQLCDNumber(p,PP2_Total_Generation_LCD,PP2_frame,5,Flat,Dec);
  pvSetGeometry(p,PP2_Total_Generation_LCD,129,153,75,30);
  pvSetFont(p,PP2_Total_Generation_LCD,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,PP2_Total_Generation_label,PP2_frame);
  pvSetGeometry(p,PP2_Total_Generation_label,42,153,70,30);
  pvSetText(p,PP2_Total_Generation_label,pvtr("Total"));
  pvSetFont(p,PP2_Total_Generation_label,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,obj14,PP2_Total_Generation_label);
  pvSetGeometry(p,obj14,357,144,99,30);
  pvSetText(p,obj14,pvtr("PushButton"));
  pvSetFont(p,obj14,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,PP2_MW_label,PP2_frame);
  pvSetGeometry(p,PP2_MW_label,156,24,50,30);
  pvSetText(p,PP2_MW_label,pvtr("MW"));
  pvSetFont(p,PP2_MW_label,"Ubuntu",9,0,0,0,0);

  pvQLabel(p,PP2_T3_label,PP2_frame);
  pvSetGeometry(p,PP2_T3_label,42,120,75,30);
  pvSetText(p,PP2_T3_label,pvtr("Wind"));
  pvSetFont(p,PP2_T3_label,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,obj11,PP2_frame,Panel,Raised,3,1);
  pvSetGeometry(p,obj11,501,207,720,432);
  pvSetFont(p,obj11,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,obj12,obj11);
  pvSetGeometry(p,obj12,120,48,300,30);
  pvSetText(p,obj12,pvtr("Graph of demand & supply vs time"));
  pvSetFont(p,obj12,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,obj8,obj11,Panel,Raised,3,1);
  pvSetGeometry(p,obj8,876,225,213,234);
  pvSetFont(p,obj8,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,Quick_Values_frame,0,Panel,Raised,3,1);
  pvSetGeometry(p,Quick_Values_frame,765,9,426,237);
  pvSetFont(p,Quick_Values_frame,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,Current_Values_Title_label,Quick_Values_frame);
  pvSetGeometry(p,Current_Values_Title_label,27,6,140,30);
  pvSetText(p,Current_Values_Title_label,pvtr("Current Values"));
  pvSetFont(p,Current_Values_Title_label,"Ubuntu",11,1,0,0,0);

  pvQLabel(p,Current_Demand_label,Quick_Values_frame);
  pvSetGeometry(p,Current_Demand_label,27,39,170,30);
  pvSetText(p,Current_Demand_label,pvtr("Current Demand"));
  pvSetFont(p,Current_Demand_label,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,Current_Generation_label,Quick_Values_frame);
  pvSetGeometry(p,Current_Generation_label,27,69,170,30);
  pvSetText(p,Current_Generation_label,pvtr("Current Production"));
  pvSetFont(p,Current_Generation_label,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,obj22,Quick_Values_frame,Box,Plain,1,1);
  pvSetGeometry(p,obj22,0,111,500,1);
  pvSetFont(p,obj22,"Ubuntu",11,0,0,0,0);

  pvQLCDNumber(p,Current_Demand_LCD,Quick_Values_frame,5,Flat,Dec);
  pvSetGeometry(p,Current_Demand_LCD,200,36,99,30);
  pvSetFont(p,Current_Demand_LCD,"Ubuntu",11,0,0,0,0);

  pvQLCDNumber(p,Current_Generation_LCD,Quick_Values_frame,5,Flat,Dec);
  pvSetGeometry(p,Current_Generation_LCD,200,69,99,30);
  pvSetFont(p,Current_Generation_LCD,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,Highest_Timeframe_Label,Quick_Values_frame);
  pvSetGeometry(p,Highest_Timeframe_Label,27,117,80,30);
  pvSetText(p,Highest_Timeframe_Label,pvtr("Timeframe"));
  pvSetFont(p,Highest_Timeframe_Label,"Ubuntu",11,0,0,0,0);

  pvQRadioButton(p,Timeframe_1_Week_radio_button,Quick_Values_frame);
  pvSetGeometry(p,Timeframe_1_Week_radio_button,27,168,99,30);
  pvSetText(p,Timeframe_1_Week_radio_button,pvtr("1 Week"));
  pvSetFont(p,Timeframe_1_Week_radio_button,"Ubuntu",11,0,0,0,0);

  pvQRadioButton(p,Timeframe_1_Month_radio_button,Quick_Values_frame);
  pvSetGeometry(p,Timeframe_1_Month_radio_button,27,192,99,30);
  pvSetText(p,Timeframe_1_Month_radio_button,pvtr("1 Month"));
  pvSetFont(p,Timeframe_1_Month_radio_button,"Ubuntu",11,0,0,0,0);

  pvQRadioButton(p,Timeframe_24_Hours_radio_button,Quick_Values_frame);
  pvSetGeometry(p,Timeframe_24_Hours_radio_button,27,144,80,30);
  pvSetText(p,Timeframe_24_Hours_radio_button,pvtr("24 Hours"));
  pvSetFont(p,Timeframe_24_Hours_radio_button,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,Legend_frame,0,Panel,Raised,3,1);
  pvSetGeometry(p,Legend_frame,30,9,213,237);
  pvSetFont(p,Legend_frame,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,Legend_Title_label,Legend_frame);
  pvSetGeometry(p,Legend_Title_label,9,6,99,30);
  pvSetText(p,Legend_Title_label,pvtr("Legend"));
  pvSetFont(p,Legend_Title_label,"Ubuntu",11,1,0,0,0);

  pvDownloadFile(p,"assets/blue.png");
  pvQImage(p,Legend_Blue_image,Legend_frame,"assets/blue.png",&w,&h,&depth);
  pvSetGeometry(p,Legend_Blue_image,12,57,25,25);
  pvSetFont(p,Legend_Blue_image,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,Legend_Blue_image,pvtr("assets/blue.png"));

  pvDownloadFile(p,"assets/blue.png");
  pvQImage(p,obj17,Legend_Blue_image,"assets/blue.png",&w,&h,&depth);
  pvSetGeometry(p,obj17,21,21,99,30);
  pvSetFont(p,obj17,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,obj17,pvtr("assets/blue.png"));

  pvDownloadFile(p,"assets/red.png");
  pvQImage(p,Legend_Red_image,Legend_frame,"assets/red.png",&w,&h,&depth);
  pvSetGeometry(p,Legend_Red_image,12,90,25,25);
  pvSetFont(p,Legend_Red_image,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,Legend_Red_image,pvtr("assets/red.png"));

  pvDownloadFile(p,"assets/green.png");
  pvQImage(p,obj18,Legend_frame,"assets/green.png",&w,&h,&depth);
  pvSetGeometry(p,obj18,12,123,25,25);
  pvSetFont(p,obj18,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,obj18,pvtr("assets/green.png"));

  pvQLabel(p,Legend_Faulty_label,Legend_frame);
  pvSetGeometry(p,Legend_Faulty_label,42,54,165,30);
  pvSetText(p,Legend_Faulty_label,pvtr("Faulty"));
  pvSetFont(p,Legend_Faulty_label,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,Legend_Active_label,Legend_frame);
  pvSetGeometry(p,Legend_Active_label,42,87,99,30);
  pvSetText(p,Legend_Active_label,pvtr("Active"));
  pvSetFont(p,Legend_Active_label,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,Legend_Inactive_label,Legend_frame);
  pvSetGeometry(p,Legend_Inactive_label,42,120,99,30);
  pvSetText(p,Legend_Inactive_label,pvtr("Inactive"));
  pvSetFont(p,Legend_Inactive_label,"Ubuntu",11,0,0,0,0);

  pvDownloadFile(p,"assets/black.png");
  pvQImage(p,obj19,Legend_frame,"assets/black.png",&w,&h,&depth);
  pvSetGeometry(p,obj19,12,156,25,25);
  pvSetFont(p,obj19,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,obj19,pvtr("assets/black.png"));

  pvQLabel(p,Legend_Unresponsive_label,Legend_frame);
  pvSetGeometry(p,Legend_Unresponsive_label,42,153,150,30);
  pvSetText(p,Legend_Unresponsive_label,pvtr("Unresponsive"));
  pvSetFont(p,Legend_Unresponsive_label,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,obj20,0,Panel,Raised,3,1);
  pvSetGeometry(p,obj20,33,270,1164,612);
  pvSetFont(p,obj20,"Ubuntu",11,0,0,0,0);

  pvQwtPlotWidget(p,Overview_graph,obj20,10,1000);
  pvSetGeometry(p,Overview_graph,36,75,1000,500);
  qpwSetCanvasBackground(p,Overview_graph,212,208,200);
  qpwEnableAxis(p,Overview_graph,yLeft);
  qpwEnableAxis(p,Overview_graph,xBottom);
  pvSetFont(p,Overview_graph,"Ubuntu",11,0,0,0,0);


  pvEndDefinition(p);
  return 0;
}

// _end_of_generated_area_ (do not edit -> use ui2pvc) ---------------------

#include "mask1_slots.h"

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


int show_mask1(PARAM *p)
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
