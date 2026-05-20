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
////////////////////////////////////////////////////////////////////////////
//
// show_mask1 for ProcessViewServer created: Wed Jun 3 11:10:58 2015
//
////////////////////////////////////////////////////////////////////////////
#include "pvapp.h"
extern int My_SS_Id;
// _begin_of_generated_area_ (do not edit -> use ui2pvc) -------------------

// our mask contains the following objects
enum {
  ID_MAIN_WIDGET = 0,
  schema_box,
  schema,
  trip_br,
  close_br,
  opened_br,
  closed_br,
  label_ss,
  box_1,
  box_2,
  box_3,
  box_4,
  to_label,
  alert_window,
  label_alert,
  ID_END_OF_WIDGETS
};

// our mask contains the following widget names
  static const char *widgetName[] = {
  "ID_MAIN_WIDGET",
  "schema_box",
  "schema",
  "trip_br",
  "close_br",
  "opened_br",
  "closed_br",
  "label_ss",
  "box_1",
  "box_2",
  "box_3",
  "box_4",
  "to_label",
  "alert_window",
  "label_alert",
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
  ""};

  static const char *whatsThis[] = {
  "",
  "",
  "SS1_HMI.png",
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
  ""};


  static const int widgetType[ID_END_OF_WIDGETS+1] = {
  0,
  TQFrame,
  TQImage,
  TQPushButton,
  TQPushButton,
  TQImage,
  TQImage,
  TQLabel,
  TQFrame,
  TQFrame,
  TQFrame,
  TQFrame,
  TQLabel,
  TQMultiLineEdit,
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

  int x = 50;
  int y = 50;

  char ss_name[50];
  sprintf(ss_name,"Substation %d",My_SS_Id-16);

  pvQFrame(p,schema_box,0,Box,Plain,1,1);
  pvSetGeometry(p,schema_box,x,y,470,250);
//  pvSetPaletteForegroundColor(p,schema_box,76,76,76);
 // pvSetPaletteBackgroundColor(p,schema_box,242,241,240);
  pvSetPaletteBackgroundColor(p,schema_box,255,255,255);
  pvSetFont(p,schema_box,"Ubuntu",11,0,0,0,0);

  pvQLabel(p,to_label,0);
  pvSetGeometry(p,to_label,x+360,y+125,100,30);
  pvSetText(p,to_label,pvtr("To Substation 2"));
  pvSetFont(p,to_label,"Ubuntu",11,1,0,0,0);

  pvDownloadFile(p,"SS1_HMI.png");
  pvQImage(p,schema,schema_box,"SS1_HMI.png",&w,&h,&depth);
  pvSetGeometry(p,schema,25,60,380,380);
  pvSetFont(p,schema,"Ubuntu",11,0,0,0,0);
  pvSetWhatsThis(p,schema,pvtr("red_on.png"));


  pvQPushButton(p,trip_br,0);
  pvSetGeometry(p,trip_br,x+100,y+190,80,30);
  pvSetText(p,trip_br,pvtr("Open"));
  pvSetPaletteForegroundColor(p,trip_br,0,0,0);
  pvSetFont(p,trip_br,"Ubuntu",12,1,0,0,0);  

  pvQPushButton(p,close_br,0);
  pvSetGeometry(p,close_br,x+200,y+190,80,30);
  pvSetText(p,close_br,pvtr("Close"));
  pvSetFont(p,close_br,"Ubuntu",12,1,0,0,0);  

  pvQLabel(p,label_ss,0);
  pvSetGeometry(p,label_ss,x+190,y-30,100,30);
  pvSetText(p,label_ss,pvtr(ss_name));
  pvSetFont(p,label_ss,"Ubuntu",14,1,0,0,0);

  pvQFrame(p,box_1,0,Box,Plain,2,1);
  pvSetGeometry(p,box_1,x+65,y+130,15,15);
  pvSetPaletteForegroundColor(p,box_1,76,76,76);
  //pvSetPaletteBackgroundColor(p,box_1,242,241,240);
  pvSetPaletteBackgroundColor(p,box_1,255,255,255); //White
  pvSetFont(p,box_1,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,box_2,0,Box,Plain,2,1);
  pvSetGeometry(p,box_2,x+140,y+130,15,15);
  pvSetPaletteForegroundColor(p,box_2,76,76,76);
  //pvSetPaletteBackgroundColor(p,box_2,242,241,240);
  pvSetPaletteBackgroundColor(p,box_2,255,255,255); //White
  pvSetFont(p,box_2,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,box_3,0,Box,Plain,2,1);
  pvSetGeometry(p,box_3,x+233,y+130,15,15);
  pvSetPaletteForegroundColor(p,box_3,76,76,76);
  //pvSetPaletteBackgroundColor(p,box_3,242,241,240); //Gray 
  pvSetPaletteBackgroundColor(p,box_3,255,255,255); //White
  //pvSetPaletteBackgroundColor(p,box_3,255,0,0); //Red
  //pvSetPaletteBackgroundColor(p,box_3,0,255,0); //Green
  pvSetFont(p,box_3,"Ubuntu",11,0,0,0,0);

  pvQFrame(p,box_4,0,Box,Plain,2,1);
  pvSetGeometry(p,box_4,x+312,y+130,15,15);
  pvSetPaletteForegroundColor(p,box_4,76,76,76);
  //pvSetPaletteBackgroundColor(p,box_4,242,241,240);
  pvSetPaletteBackgroundColor(p,box_4,255,255,255); //White
  pvSetFont(p,box_4,"Ubuntu",11,0,0,0,0);


  pvQLabel(p,label_alert,0);
  pvSetGeometry(p,label_alert,x+550,y-30,100,80);
  pvSetText(p,label_alert,"ALERTS");
  pvSetFont(p,label_alert,"Ubuntu",14,1,0,0,0);

  pvQMultiLineEdit(p,alert_window,0,0,10);
  pvSetGeometry(p,alert_window,x+490,y,200,250);
  pvSetFont(p,alert_window,"Sans Serif",10,0,0,0,0);


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
