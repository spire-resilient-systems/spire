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

#ifndef COMMAND_SENDER
#define COMMAND_SENDER


#include <mutex> 
#include <queue> 
#include <map>
#include <asiodnp3/DNP3Manager.h>
#include <asiodnp3/DefaultMasterApplication.h>
#include <asiodnp3/PrintingCommandCallback.h>
#include "command_container.h"

using namespace opendnp3;
using namespace asiodnp3;

class CommandSender {
public:
    void send_command(CommandContainer command, int master);
    static CommandSender * Instance() {
        if (!instance)
            instance = new CommandSender();
        return instance;
    }
    void setup(std::map<int, std::shared_ptr<IMaster>> m);
    void run();
    void set_channel_status(int channel, bool new_status);
private:
    static CommandSender *instance;
    CommandSender();
    std::mutex q_lock;
    std::mutex channel_lock;
    std::map<int, std::queue<CommandContainer>> q_map;
    std::map<int, std::shared_ptr<IMaster>> master_map;
    std::map<int, bool> channel_status_map;
};

#endif /*COMMAND_SENDER*/
