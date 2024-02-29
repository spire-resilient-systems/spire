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
  sp_box,
  sp_power,
  switch_sp_s1,
  switch_sp_s2,
  sp_label,
  s1_box,
  s1_power,
  switch_s1_sp,
  switch_s1_s3,
  switch_s1_p,
  switch_s1_m,
  switch_s1_f,
  s1_label,
  p_box,
  p_power,
  switch_p_s3,
  switch_p_s1,
  p_label,
  s3_box,
  s3_power,
  switch_s3_s1,
  switch_s3_p,
  switch_s3_m,
  switch_s3_u,
  switch_s3_s4,
  s3_label,
  m_box,
  m_power,
  switch_m_s3,
  switch_m_s1,
  m_label,
  s4_box,
  s4_power,
  switch_s4_u,
  switch_s4_r,
  switch_s4_s2,
  switch_s4_s3,
  s4_label,
  s2_label,
  s2_box,
  s2_power,
  switch_s2_sp,
  switch_s2_s4,
  switch_s2_r,
  switch_s2_f,
  r_label,
  r_box,
  r_power,
  switch_r_s4,
  switch_r_s2,
  u_label,
  u_box,
  u_power,
  switch_u_s4,
  switch_u_s3,
  line_sp_s1_1,
  line_sp_s1_2,
  line_s1_p,
  line_s1_m,
  line_s1_s3,
  line_s3_p_2,
  line_s3_p_1,
  line_s3_m,
  line_s3_u,
  line_s4_u,
  line_s3_s4,
  line_s4_r,
  line_sp_s2_2,
  line_sp_s2_1,
  line_s2_s4,
  line_s2_r,
  key_box,
  key_has_power,
  key_no_power,
  key_closed_switch,
  key_open_switch,
  key_fault_switch,
  key_label_has_power,
  key_label_no_power,
  key_label_closed_switch,
  key_label_open_switch,
  key_label_fault_switch,
  key_label_key_label,
  key_blue,
  key_blue_label,
  f_box,
  switch_f_s1,
  switch_f_s2,
  f_power,
  f_label,
  line_s1_f,
  line_s2_f,
  ID_END_OF_WIDGETS
};

// our mask contains the following widget names
  static const char *widgetName[] = {
  "ID_MAIN_WIDGET",
  "sp_box",
  "sp_power",
  "switch_sp_s1",
  "switch_sp_s2",
  "sp_label",
  "s1_box",
  "s1_power",
  "switch_s1_sp",
  "switch_s1_s3",
  "switch_s1_p",
  "switch_s1_m",
  "switch_s1_f",
  "s1_label",
  "p_box",
  "p_power",
  "switch_p_s3",
  "switch_p_s1",
  "p_label",
  "s3_box",
  "s3_power",
  "switch_s3_s1",
  "switch_s3_p",
  "switch_s3_m",
  "switch_s3_u",
  "switch_s3_s4",
  "s3_label",
  "m_box",
  "m_power",
  "switch_m_s3",
  "switch_m_s1",
  "m_label",
  "s4_box",
  "s4_power",
  "switch_s4_u",
  "switch_s4_r",
  "switch_s4_s2",
  "switch_s4_s3",
  "s4_label",
  "s2_label",
  "s2_box",
  "s2_power",
  "switch_s2_sp",
  "switch_s2_s4",
  "switch_s2_r",
  "switch_s2_f",
  "r_label",
  "r_box",
  "r_power",
  "switch_r_s4",
  "switch_r_s2",
  "u_label",
  "u_box",
  "u_power",
  "switch_u_s4",
  "switch_u_s3",
  "line_sp_s1_1",
  "line_sp_s1_2",
  "line_s1_p",
  "line_s1_m",
  "line_s1_s3",
  "line_s3_p_2",
  "line_s3_p_1",
  "line_s3_m",
  "line_s3_u",
  "line_s4_u",
  "line_s3_s4",
  "line_s4_r",
  "line_sp_s2_2",
  "line_sp_s2_1",
  "line_s2_s4",
  "line_s2_r",
  "key_box",
  "key_has_power",
  "key_no_power",
  "key_closed_switch",
  "key_open_switch",
  "key_fault_switch",
  "key_label_has_power",
  "key_label_no_power",
  "key_label_closed_switch",
  "key_label_open_switch",
  "key_label_fault_switch",
  "key_label_key_label",
  "key_blue",
  "key_blue_label",
  "f_box",
  "switch_f_s1",
  "switch_f_s2",
  "f_power",
  "f_label",
  "line_s1_f",
  "line_s2_f",
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
  "has_power.png",
  "closed_switch.png",
  "closed_switch.png",
  "",
  "",
  "has_power.png",
  "closed_switch.png",
  "closed_switch.png",
  "open_switch.png",
  "open_switch.png",
  "closed_switch.png",
  "",
  "",
  "has_power.png",
  "closed_switch.png",
  "open_switch.png",
  "",
  "Substation3",
  "has_power.png",
  "closed_switch.png",
  "closed_switch.png",
  "closed_switch.png",
  "open_switch.png",
  "open_switch.png",
  "",
  "",
  "has_power.png",
  "closed_switch.png",
  "open_switch.png",
  "",
  "",
  "has_power.png",
  "closed_switch.png",
  "closed_switch.png",
  "closed_switch.png",
  "open_switch.png",
  "",
  "",
  "",
  "has_power.png",
  "closed_switch.png",
  "closed_switch.png",
  "open_switch.png",
  "open_switch.png",
  "",
  "",
  "has_power.png",
  "closed_switch.png",
  "open_switch.png",
  "",
  "",
  "has_power.png",
  "closed_switch.png",
  "open_switch.png",
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
  "has_power.png",
  "no_power.png",
  "closed_switch.png",
  "open_switch.png",
  "fault_switch.png",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "",
  "closed_switch.png",
  "open_switch.png",
  "has_power.png",
  "",
  "",
  "",
  ""};

  static const int widgetType[ID_END_OF_WIDGETS+1] = {
  0,
  TQFrame,
  TQImage,
  TQImage,
  TQImage,
  TQLabel,
  TQFrame,
  TQImage,
  TQImage,
  TQImage,
  TQImage,
  TQImage,
  TQImage,
  TQLabel,
  TQFrame,
  TQImage,
  TQImage,
  TQImage,
  TQLabel,
  TQFrame,
  TQImage,
  TQImage,
  TQImage,
  TQImage,
  TQImage,
  TQImage,
  TQLabel,
  TQFrame,
  TQImage,
  TQImage,
  TQImage,
  TQLabel,
  TQFrame,
  TQImage,
  TQImage,
  TQImage,
  TQImage,
  TQImage,
  TQLabel,
  TQLabel,
  TQFrame,
  TQImage,
  TQImage,
  TQImage,
  TQImage,
  TQImage,
  TQLabel,
  TQFrame,
  TQImage,
  TQImage,
  TQImage,
  TQLabel,
  TQFrame,
  TQImage,
  TQImage,
  TQImage,
  TQFrame,
  TQFrame,
  TQFrame,
  TQFrame,
  TQFrame,
  TQFrame,
  TQFrame,
  TQFrame,
  TQFrame,
  TQFrame,
  TQFrame,
  TQFrame,
  TQFrame,
  TQFrame,
  TQFrame,
  TQFrame,
  TQFrame,
  TQImage,
  TQImage,
  TQImage,
  TQImage,
  TQImage,
  TQLabel,
  TQLabel,
  TQLabel,
  TQLabel,
  TQLabel,
  TQLabel,
  TQFrame,
  TQLabel,
  TQFrame,
  TQImage,
  TQImage,
  TQImage,
  TQLabel,
  TQFrame,
  TQFrame,
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

  pvQFrame(p,sp_box,0,Box,Plain,8,1);
  pvSetGeometry(p,sp_box,498,66,200,100);
  pvSetPaletteForegroundColor(p,sp_box,0,0,0);
  pvSetPaletteBackgroundColor(p,sp_box,0,0,255);
  pvSetFont(p,sp_box,"Ubuntu",11,0,0,0,0);

  pvDownloadFile(p,"has_power.png");
  pvQImage(p,sp_power,sp_box,"has_power.png",&w,&h,&depth);
  pvSetGeometry(p,sp_power,87,12,20,20);
  pvSetFont(p,sp_power,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,sp_power,pvtr("has_power.png"));

  pvDownloadFile(p,"closed_switch.png");
  pvQImage(p,switch_sp_s1,sp_box,"closed_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_sp_s1,36,72,20,20);
  pvSetFont(p,switch_sp_s1,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_sp_s1,pvtr("closed_switch.png"));

  pvDownloadFile(p,"closed_switch.png");
  pvQImage(p,switch_sp_s2,sp_box,"closed_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_sp_s2,141,72,20,20);
  pvSetFont(p,switch_sp_s2,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_sp_s2,pvtr("closed_switch.png"));

  pvQLabel(p,sp_label,0);
  pvSetGeometry(p,sp_label,522,42,162,24);
  pvSetText(p,sp_label,pvtr("Primary Substation"));
  pvSetFont(p,sp_label,"Ubuntu",13,0,0,0,0);

  pvQFrame(p,s1_box,0,Box,Plain,8,1);
  pvSetGeometry(p,s1_box,270,237,200,100);
  pvSetPaletteForegroundColor(p,s1_box,0,0,0);
  pvSetPaletteBackgroundColor(p,s1_box,0,0,255);
  pvSetFont(p,s1_box,"Ubuntu",11,0,0,0,0);

  pvDownloadFile(p,"has_power.png");
  pvQImage(p,s1_power,s1_box,"has_power.png",&w,&h,&depth);
  pvSetGeometry(p,s1_power,84,15,20,20);
  pvSetFont(p,s1_power,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,s1_power,pvtr("has_power.png"));

  pvDownloadFile(p,"closed_switch.png");
  pvQImage(p,switch_s1_sp,s1_box,"closed_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_s1_sp,165,15,20,20);
  pvSetFont(p,switch_s1_sp,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_s1_sp,pvtr("closed_switch.png"));

  pvDownloadFile(p,"closed_switch.png");
  pvQImage(p,switch_s1_s3,s1_box,"closed_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_s1_s3,93,69,20,20);
  pvSetFont(p,switch_s1_s3,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_s1_s3,pvtr("closed_switch.png"));

  pvDownloadFile(p,"open_switch.png");
  pvQImage(p,switch_s1_p,s1_box,"open_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_s1_p,12,21,20,20);
  pvSetFont(p,switch_s1_p,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_s1_p,pvtr("open_switch.png"));

  pvDownloadFile(p,"open_switch.png");
  pvQImage(p,switch_s1_m,s1_box,"open_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_s1_m,27,69,20,20);
  pvSetFont(p,switch_s1_m,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_s1_m,pvtr("open_switch.png"));

  pvDownloadFile(p,"closed_switch.png");
  pvQImage(p,switch_s1_f,s1_box,"closed_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_s1_f,165,69,20,20);
  pvSetFont(p,switch_s1_f,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_s1_f,pvtr("closed_switch.png"));

  pvQLabel(p,s1_label,0);
  pvSetGeometry(p,s1_label,321,210,111,27);
  pvSetText(p,s1_label,pvtr("Substation 1"));
  pvSetFont(p,s1_label,"Ubuntu",13,0,0,0,0);

  pvQFrame(p,p_box,0,Box,Raised,2,1);
  pvSetGeometry(p,p_box,39,240,150,100);
  pvSetPaletteForegroundColor(p,p_box,0,0,0);
  pvSetPaletteBackgroundColor(p,p_box,255,255,0);
  pvSetFont(p,p_box,"Ubuntu",11,0,0,0,0);

  pvDownloadFile(p,"has_power.png");
  pvQImage(p,p_power,p_box,"has_power.png",&w,&h,&depth);
  pvSetGeometry(p,p_power,63,9,20,20);
  pvSetFont(p,p_power,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,p_power,pvtr("has_power.png"));

  pvDownloadFile(p,"closed_switch.png");
  pvQImage(p,switch_p_s3,p_box,"closed_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_p_s3,120,72,20,20);
  pvSetFont(p,switch_p_s3,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_p_s3,pvtr("closed_switch.png"));

  pvDownloadFile(p,"open_switch.png");
  pvQImage(p,switch_p_s1,p_box,"open_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_p_s1,120,15,20,20);
  pvSetFont(p,switch_p_s1,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_p_s1,pvtr("open_switch.png"));

  pvQLabel(p,p_label,0);
  pvSetGeometry(p,p_label,93,216,39,24);
  pvSetText(p,p_label,pvtr("Port"));
  pvSetFont(p,p_label,"Ubuntu",13,0,0,0,0);

  pvQFrame(p,s3_box,0,Box,Plain,8,1);
  pvSetGeometry(p,s3_box,354,450,200,100);
  pvSetPaletteForegroundColor(p,s3_box,0,0,0);
  pvSetPaletteBackgroundColor(p,s3_box,0,0,255);
  pvSetFont(p,s3_box,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,s3_box,pvtr("Substation3"));

  pvDownloadFile(p,"has_power.png");
  pvQImage(p,s3_power,s3_box,"has_power.png",&w,&h,&depth);
  pvSetGeometry(p,s3_power,90,15,20,20);
  pvSetFont(p,s3_power,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,s3_power,pvtr("has_power.png"));

  pvDownloadFile(p,"closed_switch.png");
  pvQImage(p,switch_s3_s1,s3_box,"closed_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_s3_s1,9,12,20,20);
  pvSetFont(p,switch_s3_s1,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_s3_s1,pvtr("closed_switch.png"));

  pvDownloadFile(p,"closed_switch.png");
  pvQImage(p,switch_s3_p,s3_box,"closed_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_s3_p,9,39,20,20);
  pvSetFont(p,switch_s3_p,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_s3_p,pvtr("closed_switch.png"));

  pvDownloadFile(p,"closed_switch.png");
  pvQImage(p,switch_s3_m,s3_box,"closed_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_s3_m,9,69,20,20);
  pvSetFont(p,switch_s3_m,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_s3_m,pvtr("closed_switch.png"));

  pvDownloadFile(p,"open_switch.png");
  pvQImage(p,switch_s3_u,s3_box,"open_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_s3_u,171,69,20,20);
  pvSetFont(p,switch_s3_u,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_s3_u,pvtr("open_switch.png"));

  pvDownloadFile(p,"open_switch.png");
  pvQImage(p,switch_s3_s4,s3_box,"open_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_s3_s4,171,12,20,20);
  pvSetFont(p,switch_s3_s4,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_s3_s4,pvtr("open_switch.png"));

  pvQLabel(p,s3_label,0);
  pvSetGeometry(p,s3_label,405,426,111,24);
  pvSetText(p,s3_label,pvtr("Substation 3"));
  pvSetFont(p,s3_label,"Ubuntu",13,0,0,0,0);

  pvQFrame(p,m_box,0,Box,Raised,2,1);
  pvSetGeometry(p,m_box,135,615,282,105);
  pvSetPaletteBackgroundColor(p,m_box,255,255,0);
  pvSetFont(p,m_box,"Ubuntu",11,0,0,0,0);

  pvDownloadFile(p,"has_power.png");
  pvQImage(p,m_power,m_box,"has_power.png",&w,&h,&depth);
  pvSetGeometry(p,m_power,126,75,20,20);
  pvSetFont(p,m_power,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,m_power,pvtr("has_power.png"));

  pvDownloadFile(p,"closed_switch.png");
  pvQImage(p,switch_m_s3,m_box,"closed_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_m_s3,228,9,20,20);
  pvSetFont(p,switch_m_s3,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_m_s3,pvtr("closed_switch.png"));

  pvDownloadFile(p,"open_switch.png");
  pvQImage(p,switch_m_s1,m_box,"open_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_m_s1,162,9,20,20);
  pvSetFont(p,switch_m_s1,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_m_s1,pvtr("open_switch.png"));

  pvQLabel(p,m_label,0);
  pvSetGeometry(p,m_label,144,591,159,24);
  pvSetText(p,m_label,pvtr("Metropolitan Area"));
  pvSetFont(p,m_label,"Ubuntu",13,0,0,0,0);

  pvQFrame(p,s4_box,0,Box,Plain,8,1);
  pvSetGeometry(p,s4_box,669,450,200,100);
  pvSetPaletteForegroundColor(p,s4_box,0,0,0);
  pvSetPaletteBackgroundColor(p,s4_box,0,0,255);
  pvSetFont(p,s4_box,"Ubuntu",11,0,0,0,0);

  pvDownloadFile(p,"has_power.png");
  pvQImage(p,s4_power,s4_box,"has_power.png",&w,&h,&depth);
  pvSetGeometry(p,s4_power,93,15,20,20);
  pvSetFont(p,s4_power,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,s4_power,pvtr("has_power.png"));

  pvDownloadFile(p,"closed_switch.png");
  pvQImage(p,switch_s4_u,s4_box,"closed_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_s4_u,18,69,20,20);
  pvSetFont(p,switch_s4_u,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_s4_u,pvtr("closed_switch.png"));

  pvDownloadFile(p,"closed_switch.png");
  pvQImage(p,switch_s4_r,s4_box,"closed_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_s4_r,168,69,20,20);
  pvSetFont(p,switch_s4_r,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_s4_r,pvtr("closed_switch.png"));

  pvDownloadFile(p,"closed_switch.png");
  pvQImage(p,switch_s4_s2,s4_box,"closed_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_s4_s2,168,12,20,20);
  pvSetFont(p,switch_s4_s2,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_s4_s2,pvtr("closed_switch.png"));

  pvDownloadFile(p,"open_switch.png");
  pvQImage(p,switch_s4_s3,s4_box,"open_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_s4_s3,9,12,20,20);
  pvSetFont(p,switch_s4_s3,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_s4_s3,pvtr("open_switch.png"));

  pvQLabel(p,s4_label,0);
  pvSetGeometry(p,s4_label,720,429,114,21);
  pvSetText(p,s4_label,pvtr("Substation 4"));
  pvSetFont(p,s4_label,"Ubuntu",13,0,0,0,0);

  pvQLabel(p,s2_label,0);
  pvSetGeometry(p,s2_label,837,213,111,21);
  pvSetText(p,s2_label,pvtr("Substation 2"));
  pvSetFont(p,s2_label,"Ubuntu",13,0,0,0,0);

  pvQFrame(p,s2_box,0,Box,Plain,8,1);
  pvSetGeometry(p,s2_box,789,234,200,100);
  pvSetPaletteForegroundColor(p,s2_box,0,0,0);
  pvSetPaletteBackgroundColor(p,s2_box,0,0,255);
  pvSetFont(p,s2_box,"Ubuntu",11,0,0,0,0);

  pvDownloadFile(p,"has_power.png");
  pvQImage(p,s2_power,s2_box,"has_power.png",&w,&h,&depth);
  pvSetGeometry(p,s2_power,93,15,20,20);
  pvSetFont(p,s2_power,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,s2_power,pvtr("has_power.png"));

  pvDownloadFile(p,"closed_switch.png");
  pvQImage(p,switch_s2_sp,s2_box,"closed_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_s2_sp,12,15,20,20);
  pvSetFont(p,switch_s2_sp,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_s2_sp,pvtr("closed_switch.png"));

  pvDownloadFile(p,"closed_switch.png");
  pvQImage(p,switch_s2_s4,s2_box,"closed_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_s2_s4,45,72,20,20);
  pvSetFont(p,switch_s2_s4,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_s2_s4,pvtr("closed_switch.png"));

  pvDownloadFile(p,"open_switch.png");
  pvQImage(p,switch_s2_r,s2_box,"open_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_s2_r,168,72,20,20);
  pvSetFont(p,switch_s2_r,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_s2_r,pvtr("open_switch.png"));

  pvDownloadFile(p,"open_switch.png");
  pvQImage(p,switch_s2_f,s2_box,"open_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_s2_f,12,72,20,20);
  pvSetFont(p,switch_s2_f,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_s2_f,pvtr("open_switch.png"));

  pvQLabel(p,r_label,0);
  pvSetGeometry(p,r_label,975,423,150,24);
  pvSetText(p,r_label,pvtr("Rural Community"));
  pvSetFont(p,r_label,"Ubuntu",13,0,0,0,0);

  pvQFrame(p,r_box,0,Box,Raised,2,1);
  pvSetGeometry(p,r_box,951,447,180,105);
  pvSetPaletteBackgroundColor(p,r_box,255,255,0);
  pvSetFont(p,r_box,"Ubuntu",11,0,0,0,0);

  pvDownloadFile(p,"has_power.png");
  pvQImage(p,r_power,r_box,"has_power.png",&w,&h,&depth);
  pvSetGeometry(p,r_power,84,9,20,20);
  pvSetFont(p,r_power,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,r_power,pvtr("has_power.png"));

  pvDownloadFile(p,"closed_switch.png");
  pvQImage(p,switch_r_s4,r_box,"closed_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_r_s4,9,75,20,20);
  pvSetFont(p,switch_r_s4,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_r_s4,pvtr("closed_switch.png"));

  pvDownloadFile(p,"open_switch.png");
  pvQImage(p,switch_r_s2,r_box,"open_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_r_s2,9,9,20,20);
  pvSetFont(p,switch_r_s2,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_r_s2,pvtr("open_switch.png"));

  pvQLabel(p,u_label,0);
  pvSetGeometry(p,u_label,555,576,126,42);
  pvSetText(p,u_label,pvtr("Johns Hopkins\n    University"));
  pvSetFont(p,u_label,"Ubuntu",13,0,0,0,0);

  pvQFrame(p,u_box,0,Box,Raised,2,1);
  pvSetGeometry(p,u_box,519,618,200,100);
  pvSetPaletteBackgroundColor(p,u_box,255,255,0);
  pvSetFont(p,u_box,"Ubuntu",11,0,0,0,0);

  pvDownloadFile(p,"has_power.png");
  pvQImage(p,u_power,u_box,"has_power.png",&w,&h,&depth);
  pvSetGeometry(p,u_power,87,69,20,20);
  pvSetFont(p,u_power,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,u_power,pvtr("has_power.png"));

  pvDownloadFile(p,"closed_switch.png");
  pvQImage(p,switch_u_s4,u_box,"closed_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_u_s4,168,9,20,20);
  pvSetFont(p,switch_u_s4,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_u_s4,pvtr("closed_switch.png"));

  pvDownloadFile(p,"open_switch.png");
  pvQImage(p,switch_u_s3,u_box,"open_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_u_s3,9,9,20,20);
  pvSetFont(p,switch_u_s3,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_u_s3,pvtr("open_switch.png"));

  pvQFrame(p,line_sp_s1_1,0,VLine,Plain,4,1);
  pvSetGeometry(p,line_sp_s1_1,543,162,4,100);
  pvSetPaletteForegroundColor(p,line_sp_s1_1,0,255,0);
  pvSetFont(p,line_sp_s1_1,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,line_sp_s1_2,0,HLine,Plain,4,1);
  pvSetGeometry(p,line_sp_s1_2,456,261,88,4);
  pvSetPaletteForegroundColor(p,line_sp_s1_2,0,255,0);
  pvSetFont(p,line_sp_s1_2,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,line_s1_p,0,HLine,Plain,4,1);
  pvSetGeometry(p,line_s1_p,180,267,99,4);
  pvSetFont(p,line_s1_p,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,line_s1_m,0,VLine,Plain,4,1);
  pvSetGeometry(p,line_s1_m,306,324,4,300);
  pvSetFont(p,line_s1_m,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,line_s1_s3,0,VLine,Plain,4,1);
  pvSetGeometry(p,line_s1_s3,372,327,4,135);
  pvSetPaletteForegroundColor(p,line_s1_s3,0,255,0);
  pvSetFont(p,line_s1_s3,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,line_s3_p_2,0,VLine,Plain,4,1);
  pvSetGeometry(p,line_s3_p_2,168,330,4,170);
  pvSetPaletteForegroundColor(p,line_s3_p_2,0,255,0);
  pvSetFont(p,line_s3_p_2,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,line_s3_p_1,0,HLine,Plain,4,1);
  pvSetGeometry(p,line_s3_p_1,168,498,195,4);
  pvSetPaletteForegroundColor(p,line_s3_p_1,0,255,0);
  pvSetFont(p,line_s3_p_1,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,line_s3_m,0,VLine,Plain,4,1);
  pvSetGeometry(p,line_s3_m,372,540,4,80);
  pvSetPaletteForegroundColor(p,line_s3_m,0,255,0);
  pvSetFont(p,line_s3_m,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,line_s3_u,0,VLine,Plain,4,1);
  pvSetGeometry(p,line_s3_u,537,543,4,85);
  pvSetFont(p,line_s3_u,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,line_s4_u,0,VLine,Plain,4,1);
  pvSetGeometry(p,line_s4_u,696,543,4,80);
  pvSetPaletteForegroundColor(p,line_s4_u,0,255,0);
  pvSetFont(p,line_s4_u,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,line_s3_s4,0,HLine,Plain,4,1);
  pvSetGeometry(p,line_s3_s4,543,468,130,4);
  pvSetFont(p,line_s3_s4,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,line_s4_r,0,HLine,Plain,4,1);
  pvSetGeometry(p,line_s4_r,858,534,100,4);
  pvSetPaletteForegroundColor(p,line_s4_r,0,255,0);
  pvSetFont(p,line_s4_r,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,line_sp_s2_2,0,HLine,Plain,4,1);
  pvSetGeometry(p,line_sp_s2_2,648,258,150,4);
  pvSetPaletteForegroundColor(p,line_sp_s2_2,0,255,0);
  pvSetFont(p,line_sp_s2_2,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,line_sp_s2_1,0,VLine,Plain,4,1);
  pvSetGeometry(p,line_sp_s2_1,648,159,4,100);
  pvSetPaletteForegroundColor(p,line_sp_s2_1,0,255,0);
  pvSetFont(p,line_sp_s2_1,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,line_s2_s4,0,VLine,Plain,4,1);
  pvSetGeometry(p,line_s2_s4,843,330,4,130);
  pvSetPaletteForegroundColor(p,line_s2_s4,0,255,0);
  pvSetFont(p,line_s2_s4,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,line_s2_r,0,VLine,Plain,4,1);
  pvSetGeometry(p,line_s2_r,966,324,4,130);
  pvSetFont(p,line_s2_r,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,key_box,0,Box,Plain,1,1);
  pvSetGeometry(p,key_box,786,633,400,171);
  pvSetFont(p,key_box,"Ubuntu",11,0,0,0,0);

  pvDownloadFile(p,"has_power.png");
  pvQImage(p,key_has_power,key_box,"has_power.png",&w,&h,&depth);
  pvSetGeometry(p,key_has_power,12,39,20,20);
  pvSetFont(p,key_has_power,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,key_has_power,pvtr("has_power.png"));

  pvDownloadFile(p,"no_power.png");
  pvQImage(p,key_no_power,key_box,"no_power.png",&w,&h,&depth);
  pvSetGeometry(p,key_no_power,12,78,20,20);
  pvSetFont(p,key_no_power,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,key_no_power,pvtr("no_power.png"));

  pvDownloadFile(p,"closed_switch.png");
  pvQImage(p,key_closed_switch,key_box,"closed_switch.png",&w,&h,&depth);
  pvSetGeometry(p,key_closed_switch,246,33,20,20);
  pvSetFont(p,key_closed_switch,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,key_closed_switch,pvtr("closed_switch.png"));

  pvDownloadFile(p,"open_switch.png");
  pvQImage(p,key_open_switch,key_box,"open_switch.png",&w,&h,&depth);
  pvSetGeometry(p,key_open_switch,246,78,20,20);
  pvSetFont(p,key_open_switch,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,key_open_switch,pvtr("open_switch.png"));

  pvDownloadFile(p,"fault_switch.png");
  pvQImage(p,key_fault_switch,key_box,"fault_switch.png",&w,&h,&depth);
  pvSetGeometry(p,key_fault_switch,246,120,20,20);
  pvSetFont(p,key_fault_switch,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,key_fault_switch,pvtr("fault_switch.png"));

  pvQLabel(p,key_label_has_power,key_box);
  pvSetGeometry(p,key_label_has_power,45,30,158,35);
  pvSetText(p,key_label_has_power,pvtr("Working Transformer"));
  pvSetFont(p,key_label_has_power,"Ubuntu",10,0,0,0,0);

  pvQLabel(p,key_label_no_power,key_box);
  pvSetGeometry(p,key_label_no_power,45,78,150,21);
  pvSetText(p,key_label_no_power,pvtr("Broken Transformer"));
  pvSetFont(p,key_label_no_power,"Ubuntu",10,0,0,0,0);

  pvQLabel(p,key_label_closed_switch,key_box);
  pvSetGeometry(p,key_label_closed_switch,282,33,96,21);
  pvSetText(p,key_label_closed_switch,pvtr("Closed Switch"));
  pvSetFont(p,key_label_closed_switch,"Ubuntu",10,0,0,0,0);

  pvQLabel(p,key_label_open_switch,key_box);
  pvSetGeometry(p,key_label_open_switch,282,78,90,21);
  pvSetText(p,key_label_open_switch,pvtr("Open Switch"));
  pvSetFont(p,key_label_open_switch,"Ubuntu",10,0,0,0,0);

  pvQLabel(p,key_label_fault_switch,key_box);
  pvSetGeometry(p,key_label_fault_switch,282,117,93,21);
  pvSetText(p,key_label_fault_switch,pvtr("Faulty Switch"));
  pvSetFont(p,key_label_fault_switch,"Ubuntu",10,0,0,0,0);

  pvQLabel(p,key_label_key_label,key_box);
  pvSetGeometry(p,key_label_key_label,135,6,42,24);
  pvSetText(p,key_label_key_label,pvtr("Key"));
  pvSetFont(p,key_label_key_label,"Ubuntu",15,1,0,0,0);

  pvQFrame(p,key_blue,key_box,Box,Plain,1,1);
  pvSetGeometry(p,key_blue,9,117,30,30);
  pvSetPaletteForegroundColor(p,key_blue,0,0,0);
  pvSetPaletteBackgroundColor(p,key_blue,0,0,255);
  pvSetFont(p,key_blue,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,key_blue_label,key_box);
  pvSetGeometry(p,key_blue_label,45,117,150,30);
  pvSetText(p,key_blue_label,pvtr("Powered Station"));
  pvSetFont(p,key_blue_label,"Ubuntu",10,0,0,0,0);

  pvQFrame(p,f_box,0,Box,Raised,2,1);
  pvSetGeometry(p,f_box,528,297,150,100);
  pvSetPaletteBackgroundColor(p,f_box,255,255,0);
  pvSetFont(p,f_box,"Ubuntu",11,0,0,0,0);

  pvDownloadFile(p,"closed_switch.png");
  pvQImage(p,switch_f_s1,f_box,"closed_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_f_s1,9,9,20,20);
  pvSetFont(p,switch_f_s1,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_f_s1,pvtr("closed_switch.png"));

  pvDownloadFile(p,"open_switch.png");
  pvQImage(p,switch_f_s2,f_box,"open_switch.png",&w,&h,&depth);
  pvSetGeometry(p,switch_f_s2,123,9,20,20);
  pvSetFont(p,switch_f_s2,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,switch_f_s2,pvtr("open_switch.png"));

  pvDownloadFile(p,"has_power.png");
  pvQImage(p,f_power,f_box,"has_power.png",&w,&h,&depth);
  pvSetGeometry(p,f_power,63,9,20,20);
  pvSetFont(p,f_power,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,f_power,pvtr("has_power.png"));

  pvQLabel(p,f_label,0);
  pvSetGeometry(p,f_label,570,270,75,27);
  pvSetText(p,f_label,pvtr("Facility"));
  pvSetFont(p,f_label,"Ubuntu",13,0,0,0,0);

  pvQFrame(p,line_s1_f,0,HLine,Plain,4,1);
  pvSetGeometry(p,line_s1_f,456,315,82,4);
  pvSetPaletteForegroundColor(p,line_s1_f,0,255,0);
  pvSetFont(p,line_s1_f,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,line_s2_f,0,HLine,Plain,4,1);
  pvSetGeometry(p,line_s2_f,669,315,133,4);
  pvSetFont(p,line_s2_f,"Ubuntu",11,0,0,0,0);


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
