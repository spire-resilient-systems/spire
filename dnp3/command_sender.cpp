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

#include "command_sender.h"
#include <iostream>
#include "opendnp3/gen/TaskCompletion.h"
#include <unistd.h>

CommandSender * CommandSender::instance;

CommandSender::CommandSender() {
}

// Call this method to send a command. It will be put into the proper
// master's queue
void CommandSender::send_command(CommandContainer command, int master) {
    this->q_lock.lock();

    auto search = this->q_map.find(master);
    if(search == this->q_map.end()) {
        std::cerr << "ERROR: no queue for: " << master << std::endl;
    }

    printf("Adding stuff to q @ master :%d\n", master);
    search->second.push(command); 
    if(!search->second.empty()) {
        printf("S Added succeeded @ master :%d\n", master);
    }
    this->q_lock.unlock();
}

// setup the command sender -- generate queues, etc
void CommandSender::setup(std::map<int, std::shared_ptr<IMaster>> m) {
    this->master_map = m;
    for (std::map<int,std::shared_ptr<IMaster>>::iterator it=m.begin(); it!=m.end(); ++it) {
        int index = it->first;
        //if channel status already in the map don't change it
        if(!this->channel_status_map.count(index))
            this->channel_status_map[index] = true;
        std::queue<CommandContainer> queue;
        this->q_map[index] = queue;
    }
}

void CommandSender::run() {
    while(true) {
         // iterate over the queues for all the RTU's I own
        std::map<int,bool>::iterator it=this->channel_status_map.begin();
        for (; it!=this->channel_status_map.end(); ++it) {
            int index = it->first;
            this->channel_lock.lock();

            // see if the channel status is alive (can change during operation
            // but we want to ignore if it's definitely closed)
            if(this->channel_status_map[index]) {
                this->channel_lock.unlock();
                this->q_lock.lock();
                auto queue = this->q_map[index];
                if(!queue.empty()) {
                    auto command = this->q_map[index].front();
                    this->q_map[index].pop();
                    auto master = this->master_map[index];
                    // Callback function that is called after the command happens
                    // If it fails, it puts the command back into the sender
                    auto callback = [=](const ICommandTaskResult& result) -> void
                    {
                        TaskCompletion failure = TaskCompletion::FAILURE_NO_COMMS; 
                        if(result.summary == failure) {
                            std::cout << "Command failed b/c no comms. Retrying" << std::endl;
                            usleep(10000);
                            this->send_command(command, index);
                        }
                        else {
                            std::cout << "Success!" << std::endl;
                        }
                    };
                    this->q_lock.unlock();
                    // Actually send either CROB or Analog Out Command
                    if(command.is_crob()) {
                        auto crob = command.get_crob();
                        this->master_map[index]->SelectAndOperate(
                            crob, command.loc(), callback
                        );
                    }
                    else {
                        auto analog = command.get_analog();
                        this->master_map[index]->SelectAndOperate(
                            analog, command.loc(), callback
                        );
                    }
                    printf("Command Sent and Operated\n");
                }
                else {
                    this->q_lock.unlock();
                    usleep(10000);
                }
            }
            else 
                this->channel_lock.unlock();
        }
    }
}

// Update channel status info
void CommandSender::set_channel_status(int channel, bool new_status) {
    this->channel_lock.lock();
    this->channel_status_map[channel] = new_status;
    this->channel_lock.unlock();
}
