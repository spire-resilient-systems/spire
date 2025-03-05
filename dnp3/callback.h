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

#ifndef CALLBACKS
#define CALLBACKS

#include "opendnp3/master/ISOEHandler.h"
#include <iostream>
#include <sstream> 
#include <memory>

extern "C" {
    #include "../common/scada_packets.h"
    #include "../common/net_wrapper.h"
    #include "../common/def.h"
}


namespace opendnp3{

class Callback : public ISOEHandler
{
public:
    Callback(int rtu, int ipc_sock, itrc_data ipc_info);
    ~Callback();

/*
    ISOEHandler& Instance()
    {
        return *(this);
    }
*/

    static std::shared_ptr<ISOEHandler> Create(int sub, int ipc_sock, itrc_data ipc_info)
    {
        return std::make_shared<Callback>(sub, ipc_sock, ipc_info);
    }

    int Write_To_SM();

    virtual void Process(const HeaderInfo& info, const ICollection<Indexed<Binary>>& values);
    virtual void Process(const HeaderInfo& info, const ICollection<Indexed<DoubleBitBinary>>& values);
    virtual void Process(const HeaderInfo& info, const ICollection<Indexed<Analog>>& values);
    virtual void Process(const HeaderInfo& info, const ICollection<Indexed<Counter>>& values);
    virtual void Process(const HeaderInfo& info, const ICollection<Indexed<FrozenCounter>>& values);
    virtual void Process(const HeaderInfo& info, const ICollection<Indexed<BinaryOutputStatus>>& values);
    virtual void Process(const HeaderInfo& info, const ICollection<Indexed<AnalogOutputStatus>>& values);
    virtual void Process(const HeaderInfo& info, const ICollection<Indexed<OctetString>>& values);
    virtual void Process(const HeaderInfo& info, const ICollection<Indexed<TimeAndInterval>>& values);
    virtual void Process(const HeaderInfo& info, const ICollection<Indexed<BinaryCommandEvent>>& values);
    virtual void Process(const HeaderInfo& info, const ICollection<Indexed<AnalogCommandEvent>>& values);
    virtual void Process (const HeaderInfo &info, const ICollection< DNPTime > &values);
    virtual void Process(const HeaderInfo& info, const ICollection<Indexed<SecurityStat>>& values);

    int sub;
protected:

    void Start() final {}
    void End() final {}

private:
    rtu_data_msg sub_values; 
    int ipc_sock;
    itrc_data ipc_info;

    template <class T>
    static void PrintAll(const opendnp3::HeaderInfo& info, const opendnp3::ICollection<opendnp3::Indexed<T>>& values)
    {
        auto print = [&](const opendnp3::Indexed<T>& pair)
        {
            Print<T>(info, pair.value, pair.index);
        };
        values.ForeachItem(print);
    }

    template <class T>
    static void Print(const opendnp3::HeaderInfo& info, const T& value, uint16_t index)
    {
        std::cout << "[" << index << "] : " <<
                  ValueToString(value) << std::endl;
    }

    template <class T>
    static std::string ValueToString(const T& meas)
    {
        std::ostringstream oss;
        oss << meas.value;
        return oss.str();
    }    
    static std::string GetTimeString(opendnp3::TimestampMode tsmode)
    {
        std::ostringstream oss;
        switch (tsmode)
        {
        case(opendnp3::TimestampMode::SYNCHRONIZED) :
            return "synchronized";
            break;
        case(opendnp3::TimestampMode::UNSYNCHRONIZED) :
            oss << "unsynchronized";
            break;
        default:
            oss << "no timestamp";
            break;
        }

        return oss.str();
    }

    static std::string ValueToString(const opendnp3::DoubleBitBinary& meas)
    {
        return opendnp3::DoubleBitToString(meas.value);
    }

    static Callback instance;

};

}

#endif /*CALLBACKS*/
