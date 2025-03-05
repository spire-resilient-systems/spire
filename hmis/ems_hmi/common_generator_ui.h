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
#include "master_exec.h"

extern "C" {
#include "scada_packets.h"
#include "net_wrapper.h"
#include "itrc.h"
#include "stdutil/stdcarr.h"
#include "spu_events.h"
}

/* Forward Declaration */
static int send_SM_Message(const int new_target, const int id);

static int common_slotNullEvent(PARAM *p, DATA *data, const int pp_id)
{
    data_model *model;
    generator_info *gen;
    generator_ui_info *ui;
    powerplant_info *pp_info = &data->dm->pp_arr[pp_id];

    /* iteration variables */
    int gen_start = data->dm->pp_arr[pp_id].first_gen_id;
    int gen_stop = gen_start + data->dm->pp_arr[pp_id].num_generators;
    int pp;
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
            pvDisplayNum(p, ui->current, gen->current);
            pvDisplayNum(p, ui->max, gen->max);
            pvDisplayNum(p, ui->min, gen->target);
            if (gen->current > 0) {
                pvSetImage(p, ui->indicator, "red.png");
            } else if (gen->max == 0) {
                pvSetImage(p, ui->indicator, "black.png");
            } else {
                pvSetImage(p, ui->indicator, "green.png");
            }
            total_target += gen->target;
            total_current += gen->current;
            total_maximum += gen->max;
        }
        /* Set the powerplant total stat displays */
        pvDisplayNum(p, pp_info->pp_target, total_target);
        pvDisplayNum(p, pp_info->pp_generation, total_current);
        pvDisplayNum(p, pp_info->pp_maximum, total_maximum);

        total_target = 0;
        total_current = 0;
        /* Make total counts */
        for (int i = 0; i < EMS_NUM_GENERATORS; ++i) {
            if (i < 3) {
                pp = 0;
            } else {
                pp = 1;
            }

            gen = &data->dm->pp_arr[pp].gen_arr[i];

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
                        &data->hm->generator_histories[EMS_NUM_GENERATORS + pp_id][graph_start]);
                        //&data->hm->generator_histories[EMS_NUM_GENERATORS + 0][graph_start]);
    qpwReplot(p, pp_info->graph);
    return 0;
}

static int common_slotButtonPressedEvent(PARAM *p, int id, DATA *data,
        const int pp_id)
{
    powerplant_info *pp_info = &data->dm->pp_arr[pp_id];
    /* Iteration start and stop */
    int gen_start = data->dm->pp_arr[pp_id].first_gen_id;
    int gen_stop = gen_start + data->dm->pp_arr[pp_id].num_generators;

    if(p == NULL || id == 0 || data == NULL) return -1;

    if (id == pp_info->home_button) {
        data->dm->dirty = 1;
        return 1;
    }

    for(int i = gen_start; i < gen_stop; ++i) {
        if(id == pp_info->gen_arr[i].ui.activate) {
            // Fire the text event then set the flag to catch it and send a message
            pvText(p, pp_info->gen_arr[i].ui.target);
            data->dm->send_text_id = pp_info->gen_arr[i].ui.target;
            data->dm->send_gen_id = i;
        }
    }

    /* Set the target to 0 when the deactivate button is hit */
    for(int i = gen_start; i < gen_stop; ++i) {
        /* Find the generator that corresponds to the pressed button */
        if(id == pp_info->gen_arr[i].ui.deactivate) {
            pp_info->gen_arr[i].target = 0;
            send_SM_Message(0, i);
        }
    }

    return 0;
}

static int common_slotTextEvent(PARAM *p,
                                 int id,
                                 DATA *data,
                                 const char *text,
                                 int pp_id)
{
    int new_target = 0;
    generator_info gen_info = data->dm->pp_arr[pp_id].gen_arr[data->dm->send_gen_id];

    if(p == NULL || id == 0 || data == NULL || text == NULL) return -1;
    /* This is a hack as the only thing we can do above when the 'activate'
     * button is pushed is cause the text field to fire a TextEvent with its contents,
     * so we have to come down here and catch that event and that is when we can
     * actually send the message with the new new_target value */
    if (id == data->dm->send_text_id) {
        /* Parse and update the target */
        new_target = atoi(text);
        if (new_target < 0 || new_target > gen_info.max) {
            return 0;
        }
        gen_info.target = new_target;

        send_SM_Message(new_target, data->dm->send_gen_id);

        /* Clear the flags */
        data->dm->send_gen_id = -1;
        data->dm->send_text_id = -1;
    }
    return 0;
}

/**
 * new_target: The new target generation amount
 * id: The ID of the generator
 *
 * Returns 0 on success
 */
static int send_SM_Message(const int new_target, const int id) {
    signed_message *mess = NULL;
    seq_pair ps;
    int nbytes;

    /* Create and send message to the SCADA Master */
    ps.incarnation = My_Incarnation;
    ps.seq_num = Seq_Num;
    mess = PKT_Construct_HMI_Command_Msg(ps, MAX_EMU_RTU + My_ID, EMS, new_target, id);
    mess->global_configuration_number=My_Global_Configuration_Number;
    nbytes = sizeof(signed_message) + mess->len;
    Seq_Num++;
    IPC_Send(ipc_sock, (void *)mess, nbytes, itrc_in.ipc_remote);
    free(mess);

    return 0;
}
