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
 * Johns Hopkins University.
 *
 * Creators:
 *   Yair Amir            yairamir@cs.jhu.edu
 *   Trevor Aron          taron1@cs.jhu.edu
 *   Amy Babay            babay@cs.jhu.edu
 *   Thomas Tantillo      tantillo@cs.jhu.edu
 *
 * Major Contributors:
 *   Marco Platania       Contributions to architecture design 
 *   Sahiti Bommareddy    Addition of IDS, Contributions to OpenSSL upgrade, latency optimization
 *
 * Contributors:
 *   Samuel Beckley       Contributions to HMIs
 *   Daniel Qian          Contributions to IDS
 *
 * Copyright (c) 2017-2020 Johns Hopkins University.
 * All rights reserved.
 *
 * Partial funding for Spire research was provided by the Defense Advanced 
 * Research Projects Agency (DARPA) and the Department of Defense (DoD).
 * Spire is not necessarily endorsed by DARPA or the DoD. 
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
