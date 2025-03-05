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

#ifndef DEF_H
#define DEF_H

/* Each thing needs to know what spines to create socket with */
    /* CC replicas need 2 spines - CMD LINE OPTIONS */
/* All replicas need to know number and ip/port of each CC replica on internal network */
/* All clients (RTU/HMI) need to know number and ip/port of each CC replica on external network */
/* Everyone should know their ID (offset from the base) - CMD LINE OPTION */
/* CC replicas need to know ip/port of each rtu (and hmi) */
/* Update Prime with the correct Spines ports */
/* SM needs to know what port to connect to Prime on (TCP) */

/***********************
 * System-Wide defines *
 ***********************/
#define MAX_NUM_SERVER_SLOTS 31

/* Total number of SCADA Master replicas. Note that NUM_SM must be equal to
 * 3*NUM_F + 2*NUM_K + 1 */
#define NUM_SM           6

/* Maximum number of compromised SCADA Master replicas that can be tolerated
 * simultaneously */
#define NUM_F            1

/* Maximum number of unavailable SCADA Master replicas that can be tolerated
 * simultaneously (in addition to the NUM_F compromises). A replica may be
 * unavailable because it is currently undergoing proactive recovery, or
 * because it has been disconnected by a network attack, or because it has
 * crashed. Note that to tolerate the disconnection of one site, while
 * supporting proactive recovery, NUM_K should be >= the number of replicas in
 * the largest site, plus 1 */
#define NUM_K            1

/* Number of control-center sites */
#define NUM_CC           6

/* Total number of replicas residing in the control-center sites */
#define NUM_CC_REPLICA   6

/* Total number of sites (control centers + data centers) */
#define NUM_SITES        6

/* Number of PLCs/RTUs in the system */
#define NUM_RTU          17

/* Maximum number of PLCs/RTUs in the system (must have NUM_RTU <= MAX_EMU_RTU)
 * */
#define MAX_EMU_RTU      100

/* Number of HMIs in the system */
#define NUM_HMI          3


/* Reconfiguration enabling flag */
#define Reconfiguration_Enable 1
/*Mcast IP and port for control spines*/
#define CTRL_SPINES_MCAST_IP "224.1.1.3" /* (224.1.1.3) */ 
#define CTRL_SPINES_MCAST_PORT 9900

/* List of IP addresses for Spines daemons on the external Spines network
 * connecting the control center sites with the PLC/RTU proxies and HMIs. We
 * assume there is one Spines daemon per site */
#define SPINES_EXT_SITE_ADDRS {"192.168.101.101", \
                               "192.168.101.102", \
                               "192.168.101.103", \
                               "192.168.101.104", \
                               "192.168.101.105", \
                               "192.168.101.106" }

/* List of IP addresses for Spines daemons on the internal Spines network
 * connecting all the control-center and data-center sites with one another. We
 * assume there is one Spines daemon per site */
#define SPINES_INT_SITE_ADDRS {"192.168.101.101", \
                               "192.168.101.102", \
                               "192.168.101.103", \
                               "192.168.101.104", \
                               "192.168.101.105", \
                               "192.168.101.106" }

/* IP address for the Spines daemon that connects with the PLC/RTU proxy or
 * proxies */
#define SPINES_RTU_ADDR "192.168.101.107"

/* IP address for the Spines daemon that connects with the HMI(s) */
#define SPINES_HMI_ADDR "192.168.101.108"

/************************
 *    Spines defines    *
 * **********************/

/* Port on which the external Spines network is deployed (includes control
 * center sites and PLC/RTU/HMI */
#define SPINES_EXT_PORT     8120

/* Port on which the internal Spines network is deployed (includes control
 * center and data center sites */
#define SPINES_INT_PORT     8100
/* Port on which the configuration Spines network is deployed (includes control
 * center and data center sites */
#define SPINES_CTRL_PORT     8900

/* Base ports for Spines connections. Each Spire component connects to Spines
 * on the base port for its connection type + its ID. Note that control-center
 * SCADA Masters connect twice (once on the external network using
 * SM_EXT_BASE_PORT + ID and once on the internal network using
 * SM_INT_BASE_PORT + ID) */
#define SM_EXT_BASE_PORT    8500
#define RTU_BASE_PORT       8520
#define HMI_BASE_PORT       8540
#define SM_INT_BASE_PORT    8560
#define CTRL_BASE_PORT      9580

#define SPINES_PRIORITY     1
#define SPINES_RELIABLE     2
#define INT_EXPIRATION_SEC  5
#define INT_EXPIRATION_USEC 0
#define EXT_EXPIRATION_SEC  5
#define EXT_EXPIRATION_USEC 0
#define SCADA_PRIORITY      8

/* PRIME defines */
#define PRIME_PORT 7102

/* Network defines */
#define USE_IPC_CLIENT 1
#define PRIME_REPLICA_IPC_PATH "/tmp/prime_replica"
#define PRIME_CLIENT_IPC_PATH "/tmp/prime_client"
#define UNUSED(x) (void)(x)
#define LISTEN_QLEN 4
#define MAX_LEN 10000

/* MK: Checkpoint */
#define CHECKPOINT_PERIOD 100

/* Replica Type defines */
#define CC_TYPE  1
#define DC_TYPE  2
#define RTU_TYPE 3
#define HMI_TYPE 4

/* IPC Communication defines */
#define SM_IPC_MAIN  "/tmp/sm_ipc_main"
#define SM_IPC_ITRC  "/tmp/sm_ipc_itrc"
#define SM_IPC_INJECT "/tmp/sm_ipc_inject"
#define HMI_IPC_MAIN "/tmp/hmi_ipc_main"
#define HMI_IPC_ITRC "/tmp/hmi_ipc_itrc"
#define RTU_IPC_MAIN "/tmp/rtu_ipc_main"
#define RTU_IPC_ITRC "/tmp/rtu_ipc_itrc"
#define BM_IPC_MAIN  "/tmp/bm_ipc_main"
#define BM_IPC_ITRC  "/tmp/bm_ipc_itrc"
#define CONFIG_AGENT "/tmp/config_agent_to_sm"

/* Key directories */
#define SM_PRIME_KEYS "../prime/bin/keys"
#define PROXY_PRIME_KEYS "../prime/bin/keys"
#define HMI_PRIME_KEYS "../../prime/bin/keys"
#define SM_SM_KEYS "../scada_master/sm_keys"
#define PROXY_SM_KEYS "../scada_master/sm_keys"
#define HMI_SM_KEYS "../../scada_master/sm_keys"

/* Debugging defines */
#define PRINT_PROGRESS 1000

/* OpenSSL defines */
#define KEY_SIZE 	   1024
#define DIGEST_SIZE        20
#define SIGNATURE_SIZE     128

/***********************************
 * Substation System wide defines  *
 * *********************************/
/* Total number of relays, should equal (2 * NUM_F + NUM_K + 1) */
#define NUM_REPLICAS 4
/* Maximum number of byzantine faults */
#define SS_NUM_F 1
/* Maximum number of fail-stopped relays (i.e. undergoing proactive recovery) */
#define SS_NUM_K 1

/* IP address of machines running Spines, Subscribers, and Trip Masters */
#define SPINES_RELAY_INT_ADDRS {"192.168.101.101", \
                                "192.168.101.102", \
                                "192.168.101.103", \
                                "192.168.101.104"}

#define SPINES_RELAY_EXT_ADDRS {"192.168.101.101", \
                                "192.168.101.102", \
                                "192.168.101.103", \
                                "192.168.101.104"}

/* IP address of destination proxy machine (external spines) connected to Circuit Breaker */
#define SPINES_PROXY_ADDR "192.168.101.105"


/* Interval that discretised timestamps are rounded too, in ms */
#define DTS_INTERVAL 2

#define RECOVERY_TIMEOUT_SEC  10
#define RECOVERY_TIMEOUT_USEC 0

#define SIGNED_TIMEOUT_SEC  0
#define SIGNED_TIMEOUT_USEC 2000

/**********************************
 *    Substation Spines defines    *
 * *********************************/
/* Port used by Spines Disemmination/External network */
#define SS_SPINES_EXT_PORT     10200
#define SS_SPINES_INT_PORT     10000

/* Spines virtual ports
 *
 * With Threshold Crypto (2.a)
 *  TM_OUT_PORT        Used by Trip Master to send to destination Proxy
 *  TM_TC_PORT         Spines Internal PORT for co-ordination by Trip Masters
 *
 * */
#define TM_PROXY_PORT      7501
#define TM_TC_PORT         7502
#define BREAKER_PORT      7601
#define EXPIRATION_SEC      5
#define EXPIRATION_USEC     0
#define SPINES_MAX_SIZE     2000

/* IPC Communication defines */
#define TM_IPC_IN  "/tmp/tm_ipc_in"
#define TM_IPC_OUT  "/tmp/tm_ipc_out"


/* Threshhold Crypto defines */
#define TM_KEYS "tm_keys"

/* GOOSE parameters */
#define GOOSE_MAX_LENGTH 1522
#define ETH_P_GOOSE 0x88b8

#define GOOSE_CB_REF "simpleIOGenericIO/LLN0$GO$gcbAnalogValues"

/* Relay Emulation defines */
#define EMULATOR_MCAST_PORT 8401
#define EMULATOR_MCAST_ADDR (224 << 24 | 1 << 16 | 1 << 8 | 1) /* (224.1.1.1) */

#define SS_KEY_SIZE 1024
#endif /* DEF_H */
