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

#ifndef CHANNEL_LISTENER
#define CHANNEL_LISTENER

#include "asiodnp3/IChannelListener.h"
#include "openpal/util/Uncopyable.h"
#include "command_sender.h"

#include <iostream>
#include <memory>

namespace asiodnp3
{

/**
* Callback interface for receiving information about a running channel
*/
class ChannelListener final : public IChannelListener, private openpal::Uncopyable
{
public:

    virtual void OnStateChange(opendnp3::ChannelState state) override
    {
        ChannelState open = ChannelState::OPEN;
        this->comm_sender->set_channel_status(this->id, state == open);
    }

    static std::shared_ptr<IChannelListener> Create(CommandSender *c_s, int rtu_id)
    {
        return std::make_shared<ChannelListener>(c_s, rtu_id);
    }

    ChannelListener(CommandSender *c_s, int rtu_id) {
        this->id = rtu_id;
        this->comm_sender = c_s;
    }
private:
    int id;
    CommandSender * comm_sender;

};

}

#endif
