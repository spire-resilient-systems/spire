/*
 * Spire.
 *
 * The contents of this file are subject to the Spire Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * https://jhu-dsn.github.io/spire/LICENSE.txt 
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
 * Copyright (c) 2017-2024 Johns Hopkins University.
 * All rights reserved.
 *
 * Partial funding for Spire research was provided by the Defense Advanced 
 * Research Projects Agency (DARPA), the Department of Defense (DoD), and the
 * Department of Energy (DoE).
 * Spire is not necessarily endorsed by DARPA, the DoD or the DoE. 
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>

#include "spu_events.h"
#include "spines_lib.h"

#include "../common/net_wrapper.h" 
#include "../common/def.h"
#include "../common/openssl_rsa.h"
#include "../common/tc_wrapper.h"
#include "../common/itrc.h"
#include "../common/scada_packets.h"
#include "../common/key_value.h"
#include "../config/cJSON.h"
#include "../config/config_helpers.h"
#include "../common/connector_packets.h"


int ss_ext_spines,relay_in;
int32u curr_seq_num, curr_incarnation;

void Handle_CC_Message();
//void Handle_CC_Message(int s, int source, void * dummy_p);

int main(int argc, char *argv[])
{
    setlinebuf(stdout);
    int My_SS_Id;
    
    /* Parse args */
    if(argc != 5) {
        printf("HELP: ss_proxy My_IP My_ID interface_for_MMS SS_Id\n");
        return 0;
    }
    //Net Setup
    Type = RTU_TYPE;
    My_IP=getIP();
    My_ID=atoi(argv[2]);
    My_SS_Id=atoi(argv[4]);
    //Prime_Client_ID = (NUM_SM + 1) + My_ID;
    Prime_Client_ID = MAX_NUM_SERVER_SLOTS + My_ID;

    OPENSSL_RSA_Init();
    OPENSSL_RSA_Read_Keys(Prime_Client_ID, RSA_CLIENT, PROXY_PRIME_KEYS);
    TC_Read_Public_Key(PROXY_SM_KEYS);

    //int ss_spines_ext_port=SS_SPINES_EXT_BASE_PORT+((My_ID-16)*10);
    //int relay_ss_port=RELAY_SUBSTATION_BASE_PORT+((My_ID-16)*10);
    int ss_spines_ext_port=SS_SPINES_EXT_BASE_PORT+((My_SS_Id-16)*10);
    int relay_ss_port=RELAY_SUBSTATION_BASE_PORT+((My_SS_Id-16)*10);
    ss_ext_spines=Spines_Sock(argv[1], ss_spines_ext_port, SPINES_PRIORITY, relay_ss_port);
    if(ss_ext_spines<0){
        printf("Cannot connect to substation dissemination Spines\n");
    }
    else{
        printf("Connected to ss_ext_spines on %s at port %d\n",argv[1], ss_spines_ext_port);
    }
    relay_in = IPC_DGram_SendOnly_Sock();
    if(relay_in < 0){
        printf("Error setting up IPC_DGram_SendOnly_Sock\n");
    }
    curr_seq_num=0;
    curr_incarnation=0;
    E_init();
    E_attach_fd(ss_ext_spines, READ_FD, Handle_CC_Message,NULL,NULL,MEDIUM_PRIORITY);
    E_handle_events();
}

void Handle_CC_Message(){
    static byte buff[SPINES_MAX_SIZE];
    struct sockaddr_in from_addr;
    int ret,ret2;
    socklen_t from_len;
    signed_message *tcf,*scada_mess,*hmi_header;
    tc_final_msg *tcf_specific;
    byte digest[DIGEST_SIZE];
    rtu_feedback_msg *rtuf;
    hmi_cmd cmsg;
    update_message *up;
    hmi_command_msg *hmi_msg;

    from_len=sizeof(from_addr);
    
    memset(&cmsg,0,sizeof(cmsg));
    
    ret = spines_recvfrom(ss_ext_spines, buff, MAX_LEN, 0, (struct sockaddr *) &from_addr, &from_len);
    // Check Signatures
    tcf          = (signed_message *)buff;
    printf("Received CC message of size=%d from %d\n",ret,tcf->machine_id);
    /* VERIFY RSA Signature over whole message */
    if (tcf->machine_id== (MAX_NUM_SERVER_SLOTS + MAX_EMU_RTU + INTEGRATED_SS)){//SS_HMI verification
        ret = OPENSSL_RSA_Verify((unsigned char*)tcf + SIGNATURE_SIZE,
                            sizeof(signed_message) + tcf->len - SIGNATURE_SIZE,
                            (unsigned char *)tcf, tcf->machine_id, RSA_CLIENT);
    
    }else { //CC_HMI Verification
        ret = OPENSSL_RSA_Verify((unsigned char*)tcf + SIGNATURE_SIZE,
                            sizeof(signed_message) + tcf->len - SIGNATURE_SIZE,
                            (unsigned char *)tcf, tcf->machine_id, RSA_SERVER);
    } 
    
    if (!ret) {
        printf("RSA_Verify Failed for CC message from %d\n", tcf->machine_id);
        return;
    }else{
        printf("RSA_Verify passed for HMI message from %d\n", tcf->machine_id);
        }
    if(tcf->machine_id>0 && tcf->machine_id <  MAX_NUM_SERVER_SLOTS ){ 
        tcf_specific = (tc_final_msg *)(tcf + 1);
        scada_mess=(signed_message *)(tcf_specific->payload);
        rtuf = (rtu_feedback_msg *)(scada_mess + 1);
        //CC_HMI TC Verification
        OPENSSL_RSA_Make_Digest(tcf_specific,
                            sizeof(tcf_specific->ord) + sizeof(tcf_specific->payload), digest);
        if (!TC_Verify_Signature(1, tcf_specific->thresh_sig, digest)) {
            printf("TC verify failed from CC replica %d\n", tcf->machine_id);
            return;
        }
        printf("CC RTU feedback message scen_type=%u type=%u sub=%u rtu=%u offset=%u val=%u\n",rtuf->scen_type,rtuf->type,rtuf->sub,rtuf->rtu,rtuf->offset,rtuf->val);
        //Check CC_HMI cmd freshness
        if (rtuf->seq.incarnation >= curr_incarnation && rtuf->seq.seq_num>curr_seq_num){
            curr_incarnation=rtuf->seq.incarnation;
            curr_seq_num=rtuf->seq.seq_num;
    
        }else{
            return;
        }
        //Fill message for proxy 
        cmsg.asset_id=rtuf->offset;
        cmsg.asset_cmd_value=rtuf->val;
    }else if (tcf->machine_id== ( MAX_NUM_SERVER_SLOTS+ MAX_EMU_RTU + INTEGRATED_SS)){
        up = (update_message *)(tcf+1);
        hmi_header=(signed_message *)(up+1);
        hmi_msg=(hmi_command_msg *)(hmi_header+1);
        cmsg.asset_id=hmi_msg->ttip_pos;
        if (hmi_msg->type==BREAKER_OFF){
            cmsg.asset_cmd_value=0;
        }else{
            cmsg.asset_cmd_value=1;
        }
        printf("SS Cmd to asset=%d cmd=%d\n",cmsg.asset_id=hmi_msg->ttip_pos,cmsg.asset_cmd_value);
    
    }else{
        printf("Message from unexpected source\n");
        return;
    }

   if(from_addr.sin_addr.s_addr != inet_addr(SPINES_HMI_ADDR)){
        cmsg.type=IED_CC_CMD;
        printf("Received fresh CC HMI CMD\n");
    }
    else{
        //TODO: Future ass SS HMI and then else
        cmsg.type=IED_SS_CMD;
        printf("Received fresh SS HMI CMD\n");
        
    } // send rtuf to relay_proxy
    
    ret2=IPC_Send(relay_in,&cmsg,sizeof(cmsg),(char *)CONNECTOR_IPC_OUT);
    if (ret2!=sizeof(cmsg)){
        printf("Error sending CC or SS HMI command to relay proxy\n");
    }
    else{
        printf("Sent CC or SS HMI message to relay proxy\n");
    }
    
}

