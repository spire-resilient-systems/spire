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
//# mask3_slots.h copied from mask2_slots.h
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

// This is powerplant #1
#define PP_ID 1

#include "common_generator_ui.h"

static int send_SM_Message(int new_target, int id);

static int slotInit(PARAM *p, DATA *d)
{
    if(p == NULL || d == NULL) return -1;

    d->dm = &the_model;
    d->hm = &the_history_model;

    /* Generator 1 */
    d->dm->pp_arr[PP_ID].gen_arr[3].ui.current = PP2_T1_Current_LCD;
    d->dm->pp_arr[PP_ID].gen_arr[3].ui.max = PP2_T1_Max_LCD;
    d->dm->pp_arr[PP_ID].gen_arr[3].ui.deactivate = PP2_T1_Deactivate_button;
    d->dm->pp_arr[PP_ID].gen_arr[3].ui.indicator = PP2_T1_Indicator_image;

    /* Generator 2 */
    d->dm->pp_arr[PP_ID].gen_arr[4].ui.current = PP2_T2_Current_LCD;
    d->dm->pp_arr[PP_ID].gen_arr[4].ui.max = PP2_T2_Max_LCD;
    d->dm->pp_arr[PP_ID].gen_arr[4].ui.deactivate = PP2_T2_Deactivate_button;
    d->dm->pp_arr[PP_ID].gen_arr[4].ui.indicator = PP2_T2_Indicator_image;

    /* Generator 3 */
    d->dm->pp_arr[PP_ID].gen_arr[5].ui.current = PP2_T3_Current_LCD;
    d->dm->pp_arr[PP_ID].gen_arr[5].ui.max = PP2_T3_Max_LCD;
    d->dm->pp_arr[PP_ID].gen_arr[5].ui.deactivate = PP2_T3_Deactivate_button;
    d->dm->pp_arr[PP_ID].gen_arr[5].ui.indicator = PP2_T3_Indicator_image;

    /* Overall Stats Display */
    /* This gets stored in the last generator in the powerplant */
    d->dm->pp_arr[PP_ID].overall_demand = PP2_Overview_Overall_Current_Demand_LCD;
    d->dm->pp_arr[PP_ID].overall_generation = PP2_Overview_Overall_Current_Generation_LCD;
    d->dm->pp_arr[PP_ID].pp_generation = PP2_Overview_PP2_Current_Generation_LCD;
    d->dm->pp_arr[PP_ID].pp_maximum = PP2_Overview_PP2_Current_Maximum_LCD;

    /* Misc UI Elements */
    d->dm->pp_arr[PP_ID].graph = PP2_graph;
    d->dm->pp_arr[PP_ID].home_button = PP2_Home_button;

    // qwt plot begin ---------------------------------------------
    // TODO what are the 239s?
    qpwSetCanvasBackground(p,PP2_graph,239,239,239);
    // TODO Where do yLeft and xBottom come from?
    qpwEnableAxis(p,PP2_graph,yLeft);
    qpwEnableAxis(p,PP2_graph,xBottom);
    qpwSetTitle(p,PP2_graph,"Demand & Generation vs Time");

    qpwEnableOutline(p,PP2_graph,1);
    qpwSetOutlinePen(p,PP2_graph,GREEN);

    // legend
    qpwSetAutoLegend(p,PP2_graph,1);
    qpwEnableLegend(p,PP2_graph,1);
    // TODO again where do the final values come from?
    qpwSetLegendPos(p,PP2_graph,BottomLegend);
    qpwSetLegendFrameStyle(p,PP2_graph,Box|Sunken);

    // axes
    qpwSetAxisTitle(p,PP2_graph,xBottom, "Time");
    // qpwSetAxisScaleDraw(p,PP2_graph,xBottom, "hh:mm:ss");
    qpwSetAxisTitle(p,PP2_graph,yLeft, "Demand & Supply");

    // curves
    qpwInsertCurve(p,PP2_graph, 0, "Demand");
    qpwSetCurvePen(p,PP2_graph, 0, BLUE, 3, DashDotLine);
    qpwSetCurveYAxis(p,PP2_graph, 0, yLeft);

    qpwInsertCurve(p, PP2_graph, 1, "Total Generation");
    qpwSetCurvePen(p, PP2_graph, 1, GREEN, 3, DashDotLine);
    qpwSetCurveYAxis(p, PP2_graph, 1, yLeft);

    qpwInsertCurve(p, PP2_graph, 2, "Power Plant 2 Generation");
    qpwSetCurvePen(p, PP2_graph, 2, RED, 3, DashDotLine);
    qpwSetCurveYAxis(p, PP2_graph, 2, yLeft);
    // qwt plot end --------------------------------------------------

    return 0;
}

static int slotNullEvent(PARAM *p, DATA *data)
{
    data_model *model;
    generator_info *gen;
    generator_ui_info *ui;
    powerplant_info *pp_info = &data->dm->pp_arr[PP_ID];

    /* iteration variables */
    int gen_start = data->dm->pp_arr[PP_ID].first_gen_id;
    int gen_stop = gen_start + data->dm->pp_arr[PP_ID].num_generators;
    int pp_id = 0;
    /* Local counts */
    int total_target = 0;
    int total_current = 0;
    int total_maximum = 0;
    int graph_start = 0;
    int graph_length = 0;


    if(p == NULL || data == NULL) return -1;
    if(data->dm->dirty) {
        data->dm->dirty = 0;
        model = data->dm;
        /* Reread the state and update the UI */
        for(int i = gen_start; i < gen_stop; ++i) {
            gen = &pp_info->gen_arr[i];
            ui = &gen->ui;

            pvDisplayNum(p, ui->max, gen->max);
            if (renewable_active[i-3] == 0) {
                if (gen->max == 0) {
                    pvSetImage(p, ui->indicator, "black.png");
                } else {
                    pvSetImage(p, ui->indicator, "green.png");
                }
                pvDisplayNum(p, ui->current, 0);
                pvSetText(p, ui->deactivate, "Activate");
                continue;
            }
            pvSetText(p, ui->deactivate, "Deactivate");
            pvDisplayNum(p, ui->current, gen->current);
            if (gen->current > 0) {
                pvSetImage(p, ui->indicator, "red.png");
            } else if (gen->max == 0) {
                pvSetImage(p, ui->indicator, "black.png");
                pvSetText(p, ui->deactivate, "Activate");
            } else {
                pvSetImage(p, ui->indicator, "green.png");
            }
            total_current += gen->current;
            total_maximum += gen->max;
        }
        /* Set the powerplant total stat displays */
        pvDisplayNum(p, pp_info->pp_generation, total_current);
        pvDisplayNum(p, pp_info->pp_maximum, total_maximum);

        total_target = 0;
        total_current = 0;
        /* Make total counts */
        for (int i = 0; i < EMS_NUM_GENERATORS; ++i) {
            if (i < 3) {
                pp_id = 0;
            } else {
                pp_id = 1;
            }

            gen = &data->dm->pp_arr[pp_id].gen_arr[i];

            if (i > 2 && renewable_active[i-3] == 0) {
                continue;
            }

            total_target += gen->target;
            total_current += gen->current;
        }
        /* Set the overall total stat displays */
        pvDisplayNum(p, pp_info->overall_demand, model->current_demand);
        pvDisplayNum(p, pp_info->overall_generation, total_current);
        pvDisplayNum(p, pp_info->overall_target, total_target);
    }
    Advance_Demand(data);
    Record_History(data);
    /* Update the graph */
    graph_start = max(data->hm->current_head-100, 0);
    graph_length = min(data->hm->current_head, 100);
    qpwSetCurveData(p, pp_info->graph, 0, graph_length,
            &data->hm->timestamps[graph_start],
            &data->hm->demand_history[graph_start]);
    qpwSetCurveData(p, pp_info->graph, 1, graph_length,
            &data->hm->timestamps[graph_start],
            &data->hm->generator_totals[graph_start]);
    qpwSetCurveData(p, pp_info->graph, 2, graph_length,
            &data->hm->timestamps[graph_start],
            &data->hm->generator_histories[EMS_NUM_GENERATORS + PP_ID][graph_start]);
    //&data->hm->generator_histories[EMS_NUM_GENERATORS + 0][graph_start]);
    qpwReplot(p, pp_info->graph);
    return 0;
}

static int slotButtonEvent(PARAM *p, int id, DATA *data)
{
    powerplant_info *pp_info = &data->dm->pp_arr[PP_ID];
    /* Iteration start and stop */
    int gen_start = data->dm->pp_arr[PP_ID].first_gen_id;
    int gen_stop = gen_start + data->dm->pp_arr[PP_ID].num_generators;

    if(p == NULL || data == NULL) return -1;

    if (id == pp_info->home_button) {
        data->dm->dirty = 1;
        return 1;
    }

    for(int i = gen_start; i < gen_stop; ++i) {
        /* Find the generator that corresponds to the pressed button */
        if(id == pp_info->gen_arr[i].ui.deactivate) {
            if (renewable_active[i-3] == 0) {
                renewable_active[i-3] = 1;
            } else {
                renewable_active[i-3] = 0;
            }
        }
    }
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

static int slotTextEvent(PARAM *p, int id, DATA *data, const char *text)
{
    if(p == NULL || id == 0 || data == NULL || text == NULL) return -1;
    return 0;
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
