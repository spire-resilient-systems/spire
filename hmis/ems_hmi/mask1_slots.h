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
//# mask1_slots.h for ProcessViewServer created: Wed Jun 7 23:44:41 2017
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

#include "master_exec.h"

extern "C" {
#include "scada_packets.h"
#include "net_wrapper.h"
#include "itrc.h"
#include "stdutil/stdcarr.h"
#include "spu_events.h"
}

#define DEMAND_CURVE_ID 0
#define GENERATION_CURVE_ID 1
void modelInit()
{
    data_model *d;
    history_model *hm;

    for (int i = 0; i < 3; ++i) {
        renewable_active[i] = 1;
    }


    d = &the_model;

    /* Fill in the powerplants' data */
    d->pp_arr[0].first_gen_id = 0;
    d->pp_arr[0].num_generators = 3;
    d->pp_arr[1].first_gen_id = 3;
    d->pp_arr[1].num_generators = 3;

    /* First PP */
    d->pp_arr[0].gen_arr[0].ui.top_indicator = PP1_T1_Indicator_image;
    d->pp_arr[0].gen_arr[0].ui.top_current = PP1_T1_LCD;
    d->pp_arr[0].gen_arr[1].ui.top_indicator = PP1_T2_Indicator_image;
    d->pp_arr[0].gen_arr[1].ui.top_current = PP1_T2_LCD;
    d->pp_arr[0].gen_arr[2].ui.top_indicator = PP1_T3_Indicator_image;
    d->pp_arr[0].gen_arr[2].ui.top_current = PP1_T3_LCD;
    /* Second PP */
    d->pp_arr[1].gen_arr[3].ui.top_indicator = PP2_T1_Indicator_image;
    d->pp_arr[1].gen_arr[3].ui.top_current = PP2_T1_LCD;
    d->pp_arr[1].gen_arr[4].ui.top_indicator = PP2_T2_Indicator_image;
    d->pp_arr[1].gen_arr[4].ui.top_current = PP2_T2_LCD;
    d->pp_arr[1].gen_arr[5].ui.top_indicator = PP2_T3_Indicator_image;
    d->pp_arr[1].gen_arr[5].ui.top_current = PP2_T3_LCD;

    hm = &the_history_model;
    /* Mallocs because no way to preallocate a 2d array in C */
    hm->generator_histories = new double*[EMS_NUM_GENERATORS + EMS_NUM_POWERPLANTS];
    for (int i = 0; i < (EMS_NUM_GENERATORS + EMS_NUM_POWERPLANTS); ++i) {
        hm->generator_histories[i] = new double[EMS_HISTORY_LENGTH];
    }
    hm->current_head = 0;
    hm->display_length = 100;
}

static int slotInit(PARAM *p, DATA *d)
{
    if(p == NULL || d == NULL) return -1;
    //memset(d,0,sizeof(DATA));
    d->dm = &the_model;
    d->hm = &the_history_model;

    /* Set up assets */
    pvDownloadFile(p, "assets/black.png");
    pvDownloadFile(p, "assets/blue.png");
    pvDownloadFile(p, "assets/red.png");
    pvDownloadFile(p, "assets/green.png");

    // qwt plot begin ---------------------------------------------
    // TODO what are the 239s?
    qpwSetCanvasBackground(p,Overview_graph,239,239,239);
    // TODO Where do yLeft and xBottom come from?
    qpwEnableAxis(p,Overview_graph,yLeft);
    qpwEnableAxis(p,Overview_graph,xBottom);
    qpwSetTitle(p,Overview_graph,"Demand & Generation vs Time");

    qpwEnableOutline(p,Overview_graph,1);
    qpwSetOutlinePen(p,Overview_graph,GREEN);

    // legend
    qpwSetAutoLegend(p,Overview_graph,1);
    qpwEnableLegend(p,Overview_graph,1);
    // TODO again where do the final values come from?
    qpwSetLegendPos(p,Overview_graph,BottomLegend);
    qpwSetLegendFrameStyle(p,Overview_graph,Box|Sunken);

    // axes
    qpwSetAxisTitle(p,Overview_graph,xBottom, "Time");
    // qpwSetAxisScaleDraw(p,Overview_graph,xBottom, "hh:mm:ss");
    qpwSetAxisTitle(p,Overview_graph,yLeft, "Demand & Generation");

    // curves
    qpwInsertCurve(p,Overview_graph, DEMAND_CURVE_ID, "Demand");
    qpwSetCurvePen(p,Overview_graph, DEMAND_CURVE_ID, BLUE, 3, DashDotLine);
    qpwSetCurveYAxis(p,Overview_graph, DEMAND_CURVE_ID, yLeft);

    qpwInsertCurve(p, Overview_graph, GENERATION_CURVE_ID, "Total Generation");
    qpwSetCurvePen(p, Overview_graph, GENERATION_CURVE_ID, GREEN, 3, DashDotLine);
    qpwSetCurveYAxis(p, Overview_graph, GENERATION_CURVE_ID, yLeft);
    // qwt plot end --------------------------------------------------
    return 0;
}

static int slotNullEvent(PARAM *p, DATA *data)
{
    data_model *model;
    generator_info *gen;
    generator_ui_info *ui;
    int total_generation = 0;
    int total_target = 0;
    int powerplant_generation = 0;
    int graph_start = 0;
    int graph_length = 0;
    int pp_id = 0;

    if(p == NULL || data == NULL) return -1;

    if(data->dm->dirty) {
        data->dm->dirty = 0;
        model = data->dm;
        /* Reread the state and update the UI */
        for(int i = 0; i < EMS_NUM_GENERATORS; ++i) {
            gen = &model->pp_arr[pp_id].gen_arr[i];
            ui = &gen->ui;
            if (gen->current > 0) {
                pvSetImage(p, ui->top_indicator, "red.png");
            } else if (gen->max == 0) {
                pvSetImage(p, ui->top_indicator, "black.png");
            } else {
                pvSetImage(p, ui->top_indicator, "green.png");
            }
            if (i > 2 && renewable_active[i-3] == 0) {
                pvDisplayNum(p, ui->top_current, 0);
                pvSetImage(p, ui->top_indicator, "green.png");
                continue;
            }
            pvDisplayNum(p, ui->top_current, gen->current);

            // If we hit the end of the first powerplant set its total and reset the total
            if (i+1 == data->dm->pp_arr[1].first_gen_id) {
                pvDisplayNum(p, PP1_Total_Generation_LCD, powerplant_generation);
                powerplant_generation = 0;
                pp_id = 1;
            }
            powerplant_generation += gen->current;
            total_generation += gen->current;
            total_target += gen->target;
        }
        /* Update the totals */
        pvDisplayNum(p, Current_Demand_LCD, model->current_demand);
        pvDisplayNum(p, Current_Generation_LCD, total_generation);
        pvDisplayNum(p, PP2_Total_Generation_LCD, powerplant_generation);
    }
    Advance_Demand(data);
    Record_History(data);

    /* Update the graph */
    graph_start = max(data->hm->current_head - data->hm->display_length, 0);
    graph_length = min(data->hm->current_head, data->hm->display_length);

    qpwSetCurveData(p, Overview_graph, DEMAND_CURVE_ID, graph_length,
            &data->hm->timestamps[graph_start],
            &data->hm->demand_history[graph_start]);

    qpwSetCurveData(p, Overview_graph, GENERATION_CURVE_ID, graph_length,
            &data->hm->timestamps[graph_start],
            &data->hm->generator_totals[graph_start]);
    qpwReplot(p, Overview_graph);
    return 0;
}

static int slotButtonEvent(PARAM *p, int id, DATA *d)
{
    if(p == NULL || id == 0 || d == NULL) return -1;
    // Set the dirty flag so the next page updates itself when it loads
    d->dm->dirty = 1;
    if(id == PP1_Detail_button) return 2;
    if(id == PP2_Detail_button) return 3;
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
    switch(id) {
        case  Timeframe_1_Month_radio_button:
            /* TODO make this strncmps */
            if (strcmp(text, "(1)") == 0) {
                printf("1 Month!\n\n");
                d->hm->display_length = 2800;
            }
            break;
        case  Timeframe_1_Week_radio_button:
            if (strcmp(text, "(1)") == 0) {
                printf("1 Week!\n\n");
                d->hm->display_length = 700;
            }
            break;
        case  Timeframe_24_Hours_radio_button:
            if (strcmp(text, "(1)") == 0) {
                printf("1 Day!\n\n");
                d->hm->display_length = 100;
            }
            break;
    }
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
