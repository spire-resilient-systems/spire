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
//# mask2_slots.h for ProcessViewServer created: Thu Jun 8 16:31:31 2017
//# please fill out these slots
//# here you find all possible events
//# Yours: Lehrig Software Engineering
//###############################################################

// todo: uncomment me if you want to use this data aquisiton
// also uncomment this classes in main.cpp and pvapp.h
// also remember to uncomment rllib in the project file
//extern rlModbusClient     modbus;  //Change if applicable
//extern rlSiemensTCPClient siemensTCP;
//extern rlPPIClient        ppi;

#include "common_generator_ui.h"

// This is powerplant #0
#define PP_ID 0

static int send_SM_Message(int new_target, int id);

static int slotInit(PARAM *p, DATA *d)
{
    if(p == NULL || d == NULL) return -1;
    /* Putting this here as I don't know if I can make a modelInit that gets called
     * at startup, concerned that at startup this view doesn't exist and that might
     * cause issues */

    d->dm = &the_model;
    d->hm = &the_history_model;

    /* Generator 1 */
    d->dm->pp_arr[PP_ID].gen_arr[0].ui.current = PP1_T1_Current_LCD;
    d->dm->pp_arr[PP_ID].gen_arr[0].ui.max = PP1_T1_Max_LCD;
    d->dm->pp_arr[PP_ID].gen_arr[0].ui.min = PP1_T1_Current_Target_LCD;
    d->dm->pp_arr[PP_ID].gen_arr[0].ui.target = PP1_T1_Target_input;
    d->dm->pp_arr[PP_ID].gen_arr[0].ui.activate = PP1_T1_Activate_button;
    d->dm->pp_arr[PP_ID].gen_arr[0].ui.deactivate = PP1_T1_Deactivate_button;
    d->dm->pp_arr[PP_ID].gen_arr[0].ui.indicator = PP1_T1_Indicator_image;

    /* Generator 2 */
    d->dm->pp_arr[PP_ID].gen_arr[1].ui.current = PP1_T2_Current_LCD;
    d->dm->pp_arr[PP_ID].gen_arr[1].ui.max = PP1_T2_Max_LCD;
    d->dm->pp_arr[PP_ID].gen_arr[1].ui.min = PP1_T2_Current_Target_LCD;
    d->dm->pp_arr[PP_ID].gen_arr[1].ui.target = PP1_T2_Target_input;
    d->dm->pp_arr[PP_ID].gen_arr[1].ui.activate = PP1_T2_Activate_button;
    d->dm->pp_arr[PP_ID].gen_arr[1].ui.deactivate = PP1_T2_Deactivate_button;
    d->dm->pp_arr[PP_ID].gen_arr[1].ui.indicator = PP1_T2_Indicator_image;

    /* Generator 3 */
    d->dm->pp_arr[PP_ID].gen_arr[2].ui.current = PP1_T3_Current_LCD;
    d->dm->pp_arr[PP_ID].gen_arr[2].ui.max = PP1_T3_Max_LCD;
    d->dm->pp_arr[PP_ID].gen_arr[2].ui.min = PP1_T3_Current_Target_LCD;
    d->dm->pp_arr[PP_ID].gen_arr[2].ui.target = PP1_T3_Target_input;
    d->dm->pp_arr[PP_ID].gen_arr[2].ui.activate = PP1_T3_Activate_button;
    d->dm->pp_arr[PP_ID].gen_arr[2].ui.deactivate = PP1_T3_Deactivate_button;
    d->dm->pp_arr[PP_ID].gen_arr[2].ui.indicator = PP1_T3_Indicator_image;

    /* Overall Stats Display */
    /* This gets stored in the last generator in the powerplant */
    d->dm->pp_arr[PP_ID].overall_demand = PP1_Overview_Overall_Current_Demand_LCD;
    d->dm->pp_arr[PP_ID].overall_generation = PP1_Overview_Overall_Current_Generation_LCD;
    d->dm->pp_arr[PP_ID].overall_target = PP1_Overview_Overall_Current_Target_LCD;
    d->dm->pp_arr[PP_ID].pp_generation = PP1_Overview_PP1_Current_Generation_LCD;
    d->dm->pp_arr[PP_ID].pp_target = PP1_Overview_PP1_Current_Target_LCD;
    d->dm->pp_arr[PP_ID].pp_maximum = PP1_Overview_PP1_Current_Maximum_LCD;

    /* Misc UI Elements */
    d->dm->pp_arr[PP_ID].graph = PP1_graph;
    d->dm->pp_arr[PP_ID].home_button = PP1_Home_button;

    // qwt plot begin ---------------------------------------------
    qpwSetCanvasBackground(p,PP1_graph,239,239,239);
    qpwEnableAxis(p,PP1_graph,yLeft);
    qpwEnableAxis(p,PP1_graph,xBottom);
    qpwSetTitle(p,PP1_graph,"Demand & Generation vs Time");

    qpwEnableOutline(p,PP1_graph,1);
    qpwSetOutlinePen(p,PP1_graph,GREEN);

    // legend
    qpwSetAutoLegend(p,PP1_graph,1);
    qpwEnableLegend(p,PP1_graph,1);
    qpwSetLegendPos(p,PP1_graph,BottomLegend);
    qpwSetLegendFrameStyle(p,PP1_graph,Box|Sunken);

    // axes
    qpwSetAxisTitle(p,PP1_graph,xBottom, "Time");
    // qpwSetAxisScaleDraw(p,PP1_graph,xBottom, "hh:mm:ss");
    qpwSetAxisTitle(p,PP1_graph,yLeft, "Demand & Supply");

    // curves
    qpwInsertCurve(p,PP1_graph, 0, "Demand");
    qpwSetCurvePen(p,PP1_graph, 0, BLUE, 3, DashDotLine);
    qpwSetCurveYAxis(p,PP1_graph, 0, yLeft);

    qpwInsertCurve(p, PP1_graph, 1, "Total Generation");
    qpwSetCurvePen(p, PP1_graph, 1, GREEN, 3, DashDotLine);
    qpwSetCurveYAxis(p, PP1_graph, 1, yLeft);

    qpwInsertCurve(p, PP1_graph, 2, "Power Plant 1 Generation");
    qpwSetCurvePen(p, PP1_graph, 2, RED, 3, DashDotLine);
    qpwSetCurveYAxis(p, PP1_graph, 2, yLeft);
    // qwt plot end --------------------------------------------------

    return 0;
}

static int slotNullEvent(PARAM *p, DATA *data)
{
    return common_slotNullEvent(p, data, PP_ID);
}

static int slotButtonEvent(PARAM *p, int id, DATA *d)
{
    if(p == NULL || id == 0 || d == NULL) return -1;
    return 0;
}

static int slotButtonPressedEvent(PARAM *p, int id, DATA *data)
{
    return common_slotButtonPressedEvent(p, id, data, PP_ID);
}

static int slotButtonReleasedEvent(PARAM *p, int id, DATA *d)
{
    if(p == NULL || id == 0 || d == NULL) return -1;
    return 0;
}

static int slotTextEvent(PARAM *p, int id, DATA *data, const char *text)
{
    return common_slotTextEvent(p, id, data, text, PP_ID);
}


/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
/* Everything below here is autogen and unused */
/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

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
    if(p == NULL || id == -1 || d == NULL || val < -1000) return -1;
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
