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

#ifndef COMMAND_CONTAINER
#define COMMAND_CONTAINER


#include <asiodnp3/DNP3Manager.h>
#include <asiodnp3/DefaultMasterApplication.h>
#include <asiodnp3/PrintingCommandCallback.h>

using namespace opendnp3;
using namespace asiodnp3;

// Container for commands in the Command Sender
// Basically union type -- either CROB or Analog Out
class CommandContainer {
public:

    CommandContainer(int loc){
        this->has_crob = false;
        this->has_analog = false;
        this->location = loc;
    }

    bool is_crob() {
        return this->has_crob;
    }
    bool is_analog() {
        return this->has_analog;
    }
    void set_crob(ControlRelayOutputBlock crob) {
        this->crob = crob;
        this->has_crob = true;
        this->has_analog = false;
    }
    void set_analog(AnalogOutputInt16 ao) {
        this->ao = ao;
        this->has_crob = false;
        this->has_analog = true;
    }
    int loc() {
        return this->location;
    }
    ControlRelayOutputBlock get_crob() {
        return this->crob;
    }
    AnalogOutputInt16 get_analog() {
        return this->ao;
    }

private:
    ControlRelayOutputBlock crob; 
    AnalogOutputInt16 ao;
    bool has_crob;
    bool has_analog;
    int location;

};

#endif /*COMMAND_CONTAINER*/
