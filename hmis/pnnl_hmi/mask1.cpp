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
////////////////////////////////////////////////////////////////////////////
//
// show_mask1 for ProcessViewServer created: Wed Jun 3 11:10:58 2015
//
////////////////////////////////////////////////////////////////////////////
#include "pvapp.h"

// _begin_of_generated_area_ (do not edit -> use ui2pvc) -------------------

// our mask contains the following objects
enum {
  ID_MAIN_WIDGET = 0,
  dial3,
  dial2,
  close_b57,
  dial1,
  trip_b57,
  dial4,
  close_b56,
  trip_b56,
  close_b55,
  close_b54,
  trip_b55,
  trip_b54,
  label_b56,
  label_b55,
  label_b54,
  label_b53,
  label_spert1,
  label_spert2,
  label_spert3,
  label_spert4,
  trip_b1012,
  close_b1012,
  label_b1012,
  trip_b101,
  close_b101,
  close_b102,
  trip_b102,
  label_b102,
  label_b101,
  line_b57,
  line_leftbus,
  box_b57,
  closed_b57,
  opened_b57,
  box_b56,
  opened_b56,
  closed_b56,
  box_b55,
  closed_b55,
  opened_b55,
  box_b54,
  closed_b54,
  opened_b54,
  box_b1012,
  closed_b1012,
  opened_b1012,
  box_b102,
  closed_b102,
  opened_b102,
  box_b101,
  closed_b101,
  opened_b101,
  line_b56,
  line_rightbus,
  line_b55,
  line_b54,
  line_b102,
  line_b101,
  script_restart,
  script_pause,
  script_continue,
  script_history,
  script_hist_label,
  script_indicator,
  ID_END_OF_WIDGETS
};

// our mask contains the following widget names
  static const char *widgetName[] = {
  "ID_MAIN_WIDGET",
  "dial3",
  "dial2",
  "close_b57",
  "dial1",
  "trip_b57",
  "dial4",
  "close_b56",
  "trip_b56",
  "close_b55",
  "close_b54",
  "trip_b55",
  "trip_b54",
  "label_b56",
  "label_b55",
  "label_b54",
  "label_b53",
  "label_spert1",
  "label_spert2",
  "label_spert3",
  "label_spert4",
  "trip_b1012",
  "close_b1012",
  "label_b1012",
  "trip_b101",
  "close_b101",
  "close_b102",
  "trip_b102",
  "label_b102",
  "label_b101",
  "line_b57",
  "line_leftbus",
  "box_b57",
  "closed_b57",
  "opened_b57",
  "box_b56",
  "opened_b56",
  "closed_b56",
  "box_b55",
  "closed_b55",
  "opened_b55",
  "box_b54",
  "closed_b54",
  "opened_b54",
  "box_b1012",
  "closed_b1012",
  "opened_b1012",
  "box_b102",
  "closed_b102",
  "opened_b102",
  "box_b101",
  "closed_b101",
  "opened_b101",
  "line_b56",
  "line_rightbus",
  "line_b55",
  "line_b54",
  "line_b102",
  "line_b101",
  "script_restart",
  "script_pause",
  "script_continue",
  "script_history",
  "script_hist_label",
  "script_indicator",
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
  "red_on.png",
  "green_on.png",
  "",
  "green_on.png",
  "red_on.png",
  "",
  "red_on.png",
  "green_on.png",
  "",
  "red_on.png",
  "green_on.png",
  "",
  "red_on.png",
  "green_on.png",
  "",
  "red_on.png",
  "green_on.png",
  "",
  "red_on.png",
  "green_on.png",
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
  TQwtDial,
  TQwtDial,
  TQPushButton,
  TQwtDial,
  TQPushButton,
  TQwtDial,
  TQPushButton,
  TQPushButton,
  TQPushButton,
  TQPushButton,
  TQPushButton,
  TQPushButton,
  TQLabel,
  TQLabel,
  TQLabel,
  TQLabel,
  TQLabel,
  TQLabel,
  TQLabel,
  TQLabel,
  TQPushButton,
  TQPushButton,
  TQLabel,
  TQPushButton,
  TQPushButton,
  TQPushButton,
  TQPushButton,
  TQLabel,
  TQLabel,
  TQFrame,
  TQFrame,
  TQFrame,
  TQImage,
  TQImage,
  TQFrame,
  TQImage,
  TQImage,
  TQFrame,
  TQImage,
  TQImage,
  TQFrame,
  TQImage,
  TQImage,
  TQFrame,
  TQImage,
  TQImage,
  TQFrame,
  TQImage,
  TQImage,
  TQFrame,
  TQImage,
  TQImage,
  TQFrame,
  TQFrame,
  TQFrame,
  TQFrame,
  TQFrame,
  TQFrame,
  TQPushButton,
  TQPushButton,
  TQPushButton,
  TQMultiLineEdit,
  TQLabel,
  TQLabel,
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

  pvQwtDial(p,dial3,0);
  pvSetGeometry(p,dial3,220,480,150,150);
  pvSetFont(p,dial3,"Ubuntu",11,0,0,0,0);

  pvQwtDial(p,dial2,0);
  pvSetGeometry(p,dial2,447,480,150,150);
  pvSetFont(p,dial2,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,close_b57,0);
  pvSetGeometry(p,close_b57,54,357,80,30);
  pvSetText(p,close_b57,pvtr("Close"));
  pvSetFont(p,close_b57,"Ubuntu",11,0,0,0,0);

  pvQwtDial(p,dial1,0);
  pvSetGeometry(p,dial1,642,480,150,150);
  pvSetFont(p,dial1,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,trip_b57,0);
  pvSetGeometry(p,trip_b57,54,447,80,30);
  pvSetText(p,trip_b57,pvtr("Trip"));
  pvSetFont(p,trip_b57,"Ubuntu",11,0,0,0,0);

  pvQwtDial(p,dial4,0);
  pvSetGeometry(p,dial4,20,480,150,150);
  pvSetFont(p,dial4,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,close_b56,0);
  pvSetGeometry(p,close_b56,252,357,80,30);
  pvSetText(p,close_b56,pvtr("Close"));
  pvSetFont(p,close_b56,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,trip_b56,0);
  pvSetGeometry(p,trip_b56,254,447,80,30);
  pvSetText(p,trip_b56,pvtr("Trip"));
  pvSetFont(p,trip_b56,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,close_b55,0);
  pvSetGeometry(p,close_b55,480,357,80,30);
  pvSetText(p,close_b55,pvtr("Close"));
  pvSetFont(p,close_b55,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,close_b54,0);
  pvSetGeometry(p,close_b54,675,357,80,30);
  pvSetText(p,close_b54,pvtr("Close"));
  pvSetFont(p,close_b54,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,trip_b55,0);
  pvSetGeometry(p,trip_b55,480,447,80,30);
  pvSetText(p,trip_b55,pvtr("Trip"));
  pvSetFont(p,trip_b55,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,trip_b54,0);
  pvSetGeometry(p,trip_b54,675,447,80,30);
  pvSetText(p,trip_b54,pvtr("Trip"));
  pvSetFont(p,trip_b54,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,label_b56,0);
  pvSetGeometry(p,label_b56,150,405,60,30);
  pvSetText(p,label_b56,pvtr("B57"));
  pvSetFont(p,label_b56,"Ubuntu",14,1,0,0,0);

  pvQLabel(p,label_b55,0);
  pvSetGeometry(p,label_b55,348,405,60,30);
  pvSetText(p,label_b55,pvtr("B56"));
  pvSetFont(p,label_b55,"Ubuntu",14,1,0,0,0);

  pvQLabel(p,label_b54,0);
  pvSetGeometry(p,label_b54,576,402,60,30);
  pvSetText(p,label_b54,pvtr("B55"));
  pvSetFont(p,label_b54,"Ubuntu",14,1,0,0,0);

  pvQLabel(p,label_b53,0);
  pvSetGeometry(p,label_b53,771,399,60,30);
  pvSetText(p,label_b53,pvtr("B54"));
  pvSetFont(p,label_b53,"Ubuntu",14,1,0,0,0);

  pvQLabel(p,label_spert1,0);
  pvSetGeometry(p,label_spert1,678,642,80,30);
  pvSetText(p,label_spert1,pvtr("SPERT1"));
  pvSetFont(p,label_spert1,"Ubuntu",14,1,0,0,0);

  pvQLabel(p,label_spert2,0);
  pvSetGeometry(p,label_spert2,486,642,80,30);
  pvSetText(p,label_spert2,pvtr("SPERT2"));
  pvSetFont(p,label_spert2,"Ubuntu",14,1,0,0,0);

  pvQLabel(p,label_spert3,0);
  pvSetGeometry(p,label_spert3,258,642,80,30);
  pvSetText(p,label_spert3,pvtr("SPERT3"));
  pvSetFont(p,label_spert3,"Ubuntu",14,1,0,0,0);

  pvQLabel(p,label_spert4,0);
  pvSetGeometry(p,label_spert4,54,642,80,30);
  pvSetText(p,label_spert4,pvtr("SPERT4"));
  pvSetFont(p,label_spert4,"Ubuntu",14,1,0,0,0);

  pvQPushButton(p,trip_b1012,0);
  pvSetGeometry(p,trip_b1012,366,252,80,30);
  pvSetText(p,trip_b1012,pvtr("Trip"));
  pvSetFont(p,trip_b1012,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,close_b1012,0);
  pvSetGeometry(p,close_b1012,363,165,80,30);
  pvSetText(p,close_b1012,pvtr("Close"));
  pvSetFont(p,close_b1012,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,label_b1012,0);
  pvSetGeometry(p,label_b1012,372,135,80,30);
  pvSetText(p,label_b1012,pvtr("B10-12"));
  pvSetFont(p,label_b1012,"Ubuntu",14,1,0,0,0);

  pvQPushButton(p,trip_b101,0);
  pvSetGeometry(p,trip_b101,147,123,80,30);
  pvSetText(p,trip_b101,pvtr("Trip"));
  pvSetFont(p,trip_b101,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,close_b101,0);
  pvSetGeometry(p,close_b101,144,36,80,30);
  pvSetText(p,close_b101,pvtr("Close"));
  pvSetFont(p,close_b101,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,close_b102,0);
  pvSetGeometry(p,close_b102,576,36,80,30);
  pvSetText(p,close_b102,pvtr("Close"));
  pvSetFont(p,close_b102,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,trip_b102,0);
  pvSetGeometry(p,trip_b102,576,123,80,30);
  pvSetText(p,trip_b102,pvtr("Trip"));
  pvSetFont(p,trip_b102,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,label_b102,0);
  pvSetGeometry(p,label_b102,675,78,80,30);
  pvSetText(p,label_b102,pvtr("B10-2"));
  pvSetFont(p,label_b102,"Ubuntu",14,1,0,0,0);

  pvQLabel(p,label_b101,0);
  pvSetGeometry(p,label_b101,75,81,60,30);
  pvSetText(p,label_b101,pvtr("B10-1"));
  pvSetFont(p,label_b101,"Ubuntu",14,1,0,0,0);

  pvQFrame(p,line_b57,0,VLine,Plain,4,1);
  pvSetGeometry(p,line_b57,90,225,4,130);
  pvSetPaletteForegroundColor(p,line_b57,76,76,76);
  pvSetFont(p,line_b57,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,line_leftbus,0,HLine,Plain,4,1);
  pvSetGeometry(p,line_leftbus,90,222,260,4);
  pvSetPaletteForegroundColor(p,line_leftbus,76,76,76);
  pvSetFont(p,line_leftbus,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,box_b57,0,Box,Plain,3,1);
  pvSetGeometry(p,box_b57,42,393,100,50);
  pvSetPaletteForegroundColor(p,box_b57,76,76,76);
  pvSetPaletteBackgroundColor(p,box_b57,242,241,240);
  pvSetFont(p,box_b57,"Ubuntu",11,0,0,0,0);

  pvDownloadFile(p,"red_on.png");
  pvQImage(p,closed_b57,box_b57,"red_on.png",&w,&h,&depth);
  pvSetGeometry(p,closed_b57,6,6,40,40);
  pvSetFont(p,closed_b57,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,closed_b57,pvtr("red_on.png"));

  pvDownloadFile(p,"green_on.png");
  pvQImage(p,opened_b57,box_b57,"green_on.png",&w,&h,&depth);
  pvSetGeometry(p,opened_b57,57,6,40,40);
  pvSetFont(p,opened_b57,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,opened_b57,pvtr("green_on.png"));

  pvQFrame(p,box_b56,0,Box,Plain,3,1);
  pvSetGeometry(p,box_b56,243,393,100,50);
  pvSetPaletteForegroundColor(p,box_b56,76,76,76);
  pvSetPaletteBackgroundColor(p,box_b56,242,241,240);
  pvSetFont(p,box_b56,"Ubuntu",11,0,0,0,0);

  pvDownloadFile(p,"green_on.png");
  pvQImage(p,opened_b56,box_b56,"green_on.png",&w,&h,&depth);
  pvSetGeometry(p,opened_b56,57,6,40,40);
  pvSetFont(p,opened_b56,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,opened_b56,pvtr("green_on.png"));

  pvDownloadFile(p,"red_on.png");
  pvQImage(p,closed_b56,box_b56,"red_on.png",&w,&h,&depth);
  pvSetGeometry(p,closed_b56,6,6,40,40);
  pvSetFont(p,closed_b56,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,closed_b56,pvtr("red_on.png"));

  pvQFrame(p,box_b55,0,Box,Plain,3,1);
  pvSetGeometry(p,box_b55,471,393,100,50);
  pvSetFont(p,box_b55,"Ubuntu",11,0,0,0,0);

  pvDownloadFile(p,"red_on.png");
  pvQImage(p,closed_b55,box_b55,"red_on.png",&w,&h,&depth);
  pvSetGeometry(p,closed_b55,6,6,40,40);
  pvSetFont(p,closed_b55,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,closed_b55,pvtr("red_on.png"));

  pvDownloadFile(p,"green_on.png");
  pvQImage(p,opened_b55,box_b55,"green_on.png",&w,&h,&depth);
  pvSetGeometry(p,opened_b55,57,6,40,40);
  pvSetFont(p,opened_b55,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,opened_b55,pvtr("green_on.png"));

  pvQFrame(p,box_b54,0,Box,Plain,3,1);
  pvSetGeometry(p,box_b54,666,393,100,50);
  pvSetFont(p,box_b54,"Ubuntu",11,0,0,0,0);

  pvDownloadFile(p,"red_on.png");
  pvQImage(p,closed_b54,box_b54,"red_on.png",&w,&h,&depth);
  pvSetGeometry(p,closed_b54,6,6,40,40);
  pvSetFont(p,closed_b54,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,closed_b54,pvtr("red_on.png"));

  pvDownloadFile(p,"green_on.png");
  pvQImage(p,opened_b54,box_b54,"green_on.png",&w,&h,&depth);
  pvSetGeometry(p,opened_b54,57,6,40,40);
  pvSetFont(p,opened_b54,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,opened_b54,pvtr("green_on.png"));

  pvQFrame(p,box_b1012,0,Box,Plain,3,1);
  pvSetGeometry(p,box_b1012,354,198,100,50);
  pvSetPaletteForegroundColor(p,box_b1012,76,76,76);
  pvSetPaletteBackgroundColor(p,box_b1012,242,241,240);
  pvSetFont(p,box_b1012,"Ubuntu",11,0,0,0,0);

  pvDownloadFile(p,"red_on.png");
  pvQImage(p,closed_b1012,box_b1012,"red_on.png",&w,&h,&depth);
  pvSetGeometry(p,closed_b1012,6,6,40,40);
  pvSetFont(p,closed_b1012,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,closed_b1012,pvtr("red_on.png"));

  pvDownloadFile(p,"green_on.png");
  pvQImage(p,opened_b1012,box_b1012,"green_on.png",&w,&h,&depth);
  pvSetGeometry(p,opened_b1012,57,6,40,40);
  pvSetFont(p,opened_b1012,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,opened_b1012,pvtr("green_on.png"));

  pvQFrame(p,box_b102,0,Box,Plain,3,1);
  pvSetGeometry(p,box_b102,567,69,100,50);
  pvSetPaletteForegroundColor(p,box_b102,76,76,76);
  pvSetPaletteBackgroundColor(p,box_b102,242,241,240);
  pvSetFont(p,box_b102,"Ubuntu",11,0,0,0,0);

  pvDownloadFile(p,"red_on.png");
  pvQImage(p,closed_b102,box_b102,"red_on.png",&w,&h,&depth);
  pvSetGeometry(p,closed_b102,6,6,40,40);
  pvSetFont(p,closed_b102,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,closed_b102,pvtr("red_on.png"));

  pvDownloadFile(p,"green_on.png");
  pvQImage(p,opened_b102,box_b102,"green_on.png",&w,&h,&depth);
  pvSetGeometry(p,opened_b102,57,6,40,40);
  pvSetFont(p,opened_b102,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,opened_b102,pvtr("green_on.png"));

  pvQFrame(p,box_b101,0,Box,Plain,3,1);
  pvSetGeometry(p,box_b101,135,69,100,50);
  pvSetPaletteForegroundColor(p,box_b101,76,76,76);
  pvSetPaletteBackgroundColor(p,box_b101,242,241,240);
  pvSetFont(p,box_b101,"Ubuntu",11,0,0,0,0);

  pvDownloadFile(p,"red_on.png");
  pvQImage(p,closed_b101,box_b101,"red_on.png",&w,&h,&depth);
  pvSetGeometry(p,closed_b101,6,6,40,40);
  pvSetFont(p,closed_b101,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,closed_b101,pvtr("red_on.png"));

  pvDownloadFile(p,"green_on.png");
  pvQImage(p,opened_b101,box_b101,"green_on.png",&w,&h,&depth);
  pvSetGeometry(p,opened_b101,57,6,40,40);
  pvSetFont(p,opened_b101,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,opened_b101,pvtr("green_on.png"));

  pvQFrame(p,line_b56,0,VLine,Plain,4,1);
  pvSetGeometry(p,line_b56,288,225,4,130);
  pvSetPaletteForegroundColor(p,line_b56,76,76,76);
  pvSetFont(p,line_b56,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,line_rightbus,0,HLine,Plain,4,1);
  pvSetGeometry(p,line_rightbus,456,222,260,4);
  pvSetPaletteForegroundColor(p,line_rightbus,76,76,76);
  pvSetFont(p,line_rightbus,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,line_b55,0,VLine,Plain,4,1);
  pvSetGeometry(p,line_b55,519,225,4,130);
  pvSetPaletteForegroundColor(p,line_b55,76,76,76);
  pvSetFont(p,line_b55,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,line_b54,0,VLine,Plain,4,1);
  pvSetGeometry(p,line_b54,714,222,4,130);
  pvSetPaletteForegroundColor(p,line_b54,76,76,76);
  pvSetFont(p,line_b54,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,line_b102,0,VLine,Plain,4,1);
  pvSetGeometry(p,line_b102,615,156,4,67);
  pvSetPaletteForegroundColor(p,line_b102,76,76,76);
  pvSetFont(p,line_b102,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,line_b101,0,VLine,Plain,4,1);
  pvSetGeometry(p,line_b101,186,156,4,67);
  pvSetPaletteForegroundColor(p,line_b101,76,76,76);
  pvSetFont(p,line_b101,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,script_restart,0);
  pvSetGeometry(p,script_restart,840,54,125,30);
  pvSetText(p,script_restart,pvtr("Restart Script"));
  pvSetFont(p,script_restart,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,script_pause,0);
  pvSetGeometry(p,script_pause,840,96,125,30);
  pvSetText(p,script_pause,pvtr("Pause Script"));
  pvSetFont(p,script_pause,"Ubuntu",11,0,0,0,0);

  pvQPushButton(p,script_continue,0);
  pvSetGeometry(p,script_continue,840,138,125,30);
  pvSetText(p,script_continue,pvtr("Continue Script"));
  pvSetFont(p,script_continue,"Ubuntu",11,0,0,0,0);

  pvQMultiLineEdit(p,script_history,0,0,10);
  pvSetGeometry(p,script_history,843,219,400,450);
  pvSetFont(p,script_history,"Sans",10,0,0,0,0);

  pvQLabel(p,script_hist_label,0);
  pvSetGeometry(p,script_hist_label,945,186,250,30);
  pvSetText(p,script_hist_label,pvtr("Script Command History"));
  pvSetFont(p,script_hist_label,"Ubuntu",11,1,0,0,0);

  pvQLabel(p,script_indicator,0);
  pvSetGeometry(p,script_indicator,1032,96,140,30);
  pvSetText(p,script_indicator,pvtr("Script Inactive"));
  pvSetFont(p,script_indicator,"Ubuntu",11,1,0,0,0);


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
        if(trace) printf("clipboard = \n%s\n",p->clipboard);
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
