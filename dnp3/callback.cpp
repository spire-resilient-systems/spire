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

#include "callback.h"
#include <iostream>
#include <sstream>
#include <string.h>

// This class handles Callbacks for whenever RTU's push a value to the DNP3
// Master. 

using namespace opendnp3;
using std::cout;
using std::endl;

// Send current data data to the SM
int Callback::Write_To_SM(){
    int ret, nBytes;
    signed_message * mess;
    auto data = this->sub_values;

    mess = PKT_Construct_RTU_Data_Msg(&data);
    /* mess = PKT_Construct_RTU_Data_Msg(data.seq, data.rtu_id,
                                      sizeof(data.sw_status) / sizeof(int32_t),
                                      data.sw_status, data.tx_status); */
    nBytes = sizeof(signed_message) + mess->len;
    this->sub_values.seq.seq_num++;
    ret = IPC_Send(this->ipc_sock, (void*)mess, nBytes, 
                   this->ipc_info.ipc_remote);
    free(mess);
    return ret;
}

/*
 * Binary, Double Bit Binary, Analog In, Counter, and Frozen Counter data ignored
 */
void Callback::Process(const HeaderInfo& info, const ICollection<Indexed<Binary>>& values) {
    cout << "Binary data -- IGNORING" << endl;
}

void Callback::Process(const HeaderInfo& info, const ICollection<Indexed<DoubleBitBinary>>& values) {
    cout << "Double Bit Binary data -- IGNORING" << endl;
}

void Callback::Process(const HeaderInfo& info, const ICollection<Indexed<Analog>>& values) {
    cout << "Analog data -- IGNORING" << endl;
}

void Callback::Process(const HeaderInfo& info, const ICollection<Indexed<Counter>>& values) {
    cout << "Counter Data -- IGNORING" << endl;
}

void Callback::Process(const HeaderInfo& info, const ICollection<Indexed<FrozenCounter>>& values) {
    cout << "Frozen Counter data -- IGNORING" << endl;
}

//Binary Output Data
//Get the values and push to the master
void Callback::Process(const HeaderInfo& info, const ICollection<Indexed<BinaryOutputStatus>>& values) {
    cout << "Binary Output Status data" << endl;
    auto fill = [&](const Indexed<BinaryOutputStatus>& pair) {
        if(pair.index == 0){
            jhu_fields *jhf = (jhu_fields *)(this->sub_values.data);
            jhf->tx_status = pair.value.value;
            //this->sub_values.tx_status = pair.value.value;
        }
    };
    values.ForeachItem(fill);
    cout << "SENDING TO ITRC" << endl;
    this->Write_To_SM();
    cout << "____________________" << endl;
}

//AnalogOutput Data
//Get the values and push to the master
void Callback::Process(const HeaderInfo& info, const ICollection<Indexed<AnalogOutputStatus>>& values) {
    cout << "Analog Output Status data" << endl;
    auto fill = [&](const Indexed<AnalogOutputStatus>& pair) {
        jhu_fields *jhf = (jhu_fields *)(this->sub_values.data);
        jhf->sw_status[pair.index] = pair.value.value;
        //this->sub_values.sw_status[pair.index] = pair.value.value;
    };
    values.ForeachItem(fill);
    cout << "SENDING TO ITRC" << endl;
    this->Write_To_SM();
    cout << "____________________" << endl;

}

/*
 * Other Callback Methods for when RTU pushes events to DNP3 proxy
 * Define if needed in the future
 */
void Callback::Process(const HeaderInfo& info, const ICollection<Indexed<OctetString>>& values) {
}

void Callback::Process(const HeaderInfo& info, const ICollection<Indexed<TimeAndInterval>>& values) {
}

void Callback::Process(const HeaderInfo& info, const ICollection<Indexed<BinaryCommandEvent>>& values) {
}

void Callback::Process(const HeaderInfo& info, const ICollection<Indexed<AnalogCommandEvent>>& values) {
}

void Callback::Process(const HeaderInfo& info, const ICollection<Indexed<SecurityStat>>& values) {
}

void Callback::Process (const HeaderInfo &info, const ICollection< DNPTime > &values) {
}



// Constructor -- set everything up
Callback::Callback(int rtu, int ipc_sock, itrc_data ipc_info) {
    this->sub = sub;
    this->sub_values.rtu_id = rtu;
    this->sub_values.seq.incarnation = 0;    // filled in by proxy
    this->sub_values.seq.seq_num = 1;
    this->sub_values.scen_type = JHU;
    memset(this->sub_values.data, 0, sizeof(this->sub_values.data));
    /* this->sub_values.tx_status = 0;
    for(int i =0; i < sizeof(this->sub_values.sw_status) / sizeof(int32_t); i++)
        this->sub_values.sw_status[i] = 0; */
    this->ipc_sock = ipc_sock;
    this->ipc_info = ipc_info;
}

Callback::~Callback() {
}


