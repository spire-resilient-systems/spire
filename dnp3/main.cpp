/*
 * Licensed to Green Energy Corp (www.greenenergycorp.com) under one or
 * more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Green Energy Corp licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except in
 * compliance with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This project was forked on 01/01/2013 by Automatak, LLC and modifications
 * may have been made to this file. Automatak, LLC licenses these modifications
 * to you under the terms of the License.
 *
 * This file was also modified by the Johns Hopkins University Distributed
 * Systems and Networks lab for use in the Spire Project. These modifications
 * fall under the terms of the original License.
 */

#include <asiodnp3/DNP3Manager.h>
#include <asiodnp3/PrintingSOEHandler.h>
#include <asiodnp3/ConsoleLogger.h>
#include <asiodnp3/DefaultMasterApplication.h>
#include <asiodnp3/PrintingCommandCallback.h>
#include <asiodnp3/PrintingChannelListener.h>
#include <opendnp3/LogLevels.h>

#include <string>
#include <string.h>
#include <iostream>
#include <cstdlib>
#include <map>
#include <vector>
#include <thread>
#include <opendnp3/LogLevels.h>
#include <asiopal/UTCTimeSource.h>
#include "callback.h"
#include "command_container.h"
#include <sys/signal.h>
#include <linux/prctl.h>
#include <sys/prctl.h>

#include "command_sender.h"
#include "channel_listener.h"

extern "C" {
    #include "../common/scada_packets.h"
    #include "../common/net_wrapper.h"
    #include "../common/def.h"
    #include "../config/cJSON.h"
    #include "../config/config_helpers.h"
}

using namespace std;
using namespace openpal;
using namespace asiopal;
using namespace asiodnp3;
using namespace opendnp3;

/* Global Values */
int ipc_sock;
itrc_data itrc_info;
int my_id;
std::map<int, std::shared_ptr<IMaster>> master_map;
//std::vector<Callback> callback_arr;
CommandSender *command_sender = CommandSender::Instance();

void Process_SM_Msg() {
    std::cout << "PROCESS SM MSG\n";
    std::cout << "______________\n";
    char buf[MAX_LEN];
    uint32_t ret, type, rtu, offset;
    int32_t val;
    signed_message *mess;
    rtu_feedback_msg *feed;

    ret = IPC_Recv(ipc_sock, buf, MAX_LEN);
    mess = (signed_message *)buf;
    feed = (rtu_feedback_msg *)(mess + 1);
    type = feed->type;
    val = feed->val;
    rtu = feed->rtu;
    offset = feed->offset;
    auto search = master_map.find(rtu);
    if(search == master_map.end()) {
        std::cerr << "ERROR: rtu in feedback msg does not exist" << std::endl;
    }
    auto master = search->second;
    CommandContainer container(offset); 
    if(type == SWITCH) {
        std::cout << "SENDING ANALOG OUTPUT CMD" << std::endl;
        AnalogOutputInt16 ao(val);
        container.set_analog(ao);
        command_sender->send_command(container, rtu);
        // Without Command Sender
        //master->SelectAndOperate(std::move(*commands), PrintingCommandCallback::Get());
    }
    else if(type == TRANSFORMER) {
        std::cout << "SENDING CROB" << std::endl;
        auto crob_val = (val == 1) ? ControlCode::LATCH_ON : ControlCode::LATCH_OFF;
        ControlRelayOutputBlock crob(crob_val);
        container.set_crob(crob);
        command_sender->send_command(container, rtu);
        // With out Command Sender
        //master->DirectOperate(crob, offset, callback);
        
    }
    else {
        std::cerr << "ERROR: rtu feedback msg type does not exist!" << std::endl;
    }
}

void setup(int sub, DNP3Manager &manager) {
	const uint32_t FILTERS = levels::NORMAL;// | levels::ALL_APP_COMMS;
    int i;
    pthread_t chanel_status;

    /* Set up IPC stuff */
    memset(&itrc_info, 0, sizeof(itrc_data));
    sprintf(itrc_info.prime_keys_dir, "%s", (char *)PROXY_PRIME_KEYS);
    sprintf(itrc_info.sm_keys_dir, "%s", (char *)PROXY_SM_KEYS);
    sprintf(itrc_info.ipc_local, "%s%s%d", (char *)RTU_IPC_MAIN, "dnp3", sub);
    sprintf(itrc_info.ipc_remote, "%s%s%d", (char *)RTU_IPC_ITRC, "dnp3", sub);
    printf("DNP3: ipc: %s\n", itrc_info.ipc_local);
    ipc_sock = IPC_DGram_Sock(itrc_info.ipc_local);

    /* read from json */ 
    char * buffer = config_into_buffer();
    cJSON * root = cJSON_Parse(buffer);
    free(buffer);
    // find my location in the json file
    cJSON * my_loc;
    cJSON * locations = cJSON_GetObjectItem(root, "locations");
    for(i = 0 ; i < cJSON_GetArraySize(locations) ; i++) {
        cJSON * loc = cJSON_GetArrayItem(locations, i);
        if(sub == cJSON_GetObjectItem(loc, "ID")->valueint) {
            my_loc = loc;
            break;
        }

    }

    // make masters for the dnp3 rtu's
    cJSON * rtus = cJSON_GetObjectItem(my_loc, "rtus");
    for(i = 0; i < cJSON_GetArraySize(rtus); i++) {
        cJSON * rtu = cJSON_GetArrayItem(rtus, i);
        char * prot_str = cJSON_GetObjectItem(rtu, "protocol")->valuestring;
        if (strcmp(prot_str, "dnp3") == 0) {
            int the_id = cJSON_GetObjectItem(rtu, "ID")->valueint;
            int the_port = cJSON_GetObjectItem(rtu, "PORT")->valueint;
            char * the_ip = cJSON_GetObjectItem(rtu, "IP")->valuestring;
            /* Check that scenario type is JHU */
            printf("Starting master on ip: %s, port: %d\n", the_ip, the_port);
            // Connect via a TCPClient socket to a outstation
            auto pChannel = manager.AddTCPClient(
                    "tcpclient", FILTERS, ChannelRetry::Default(), 
                    the_ip, "0.0.0.0", the_port, 
                    ChannelListener::Create(command_sender, the_id)
            );
            /* 
            pChannel->AddStateListener([=](ChannelState state)
            {
                ChannelState open = ChannelState::OPEN;
                command_sender->set_channel_status(the_id, state == open);
            });
            */
            
            MasterStackConfig stackConfig;

            stackConfig.master.responseTimeout = TimeDuration::Seconds(2);
            /* Disable unsolicited messages */
            stackConfig.master.disableUnsolOnStartup = true;

            //Local address is what you want your index to be
            //Remote address is the index of the RTU
            stackConfig.link.LocalAddr = 1;
            stackConfig.link.RemoteAddr = the_id;
           
            std::cout << "Making Callback" << std::endl; 
            //auto t_callback = Callback(the_id, ipc_sock, itrc_info);
            //callback_arr.push_back(t_callback);

            std::cout << "Making Master" << std::endl; 
            auto master = pChannel->AddMaster(
                              "master sub:" + std::to_string(the_id),
                              //callback_arr[callback_arr.size() - 1].Instance(),
                              Callback::Create(the_id, ipc_sock, itrc_info),
                              asiodnp3::DefaultMasterApplication::Create(),
                              stackConfig
                          );

            // do an integrity poll (Class 3/2/1/0) once per minute
            auto integrityScan = master->AddClassScan(ClassField::AllClasses(), TimeDuration::Minutes(1));
            // do a Class 1 exception poll every 5 seconds
            auto exceptionScan = master->AddClassScan(ClassField(ClassField::CLASS_1), TimeDuration::Seconds(2));
            // Enable the master. This will start communications.
            master->Enable(); 
            std::cout << "Master enabled" << std::endl;
            master_map.insert(std::make_pair(the_id, master));
           
        }
    }
    cJSON_Delete(root);
    command_sender->setup(master_map);
    std::cout << "INIT COMPLETE" << std::endl;

}

int main(int argc, char* argv[])
{
    int sub, num;
    fd_set mask, tmask;

    // this kills the process if the parent gets a sighup
    prctl(PR_SET_PDEATHSIG, SIGHUP);
    setlinebuf(stdout);

    if(argc < 2) {
        std::cout << "Please provide sub" << std::endl;
        exit(1);
    }
    sub = atoi(argv[1]);

    std::cout << "In dnp3" << std::endl;
    std::cout << "DNP3 started on sub: " <<  sub << std::endl;

	// This is the main point of interaction with the stack
	DNP3Manager manager(std::thread::hardware_concurrency(), ConsoleLogger::Create());

    setup(sub, manager);
    std::cout << "Set up complete" << std::endl;    
    // start thread for command sender
    thread c_s_thread(&CommandSender::run, command_sender);
    // Setup the FD_SET for use in select
    FD_ZERO(&mask);
    FD_SET(ipc_sock, &mask);
    while(1) {
        tmask = mask;
        num = select(FD_SETSIZE, &tmask, NULL, NULL, NULL);

        if(num > 0) {
            if(FD_ISSET(ipc_sock, &tmask)) {
                printf("Message from itrc!!!!\n");
                Process_SM_Msg();
            }
        }
    }
    c_s_thread.join();
}

