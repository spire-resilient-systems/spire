/*
 * Spines.
 *
 * The contents of this file are subject to the Spines Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.spines.org/LICENSE.txt
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Creators of Spines are:
 *  Yair Amir, Claudiu Danilov, John Schultz, Daniel Obenshain,
 *  Thomas Tantillo, and Amy Babay.
 *
 * Copyright (c) 2003-2020 The Johns Hopkins University.
 * All rights reserved.
 *
 * Major Contributor(s):
 * --------------------
 *    John Lane
 *    Raluca Musaloiu-Elefteri
 *    Nilo Rivera 
 * 
 * Contributor(s): 
 * ----------------
 *    Sahiti Bommareddy 
 *
 *
 */

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <signal.h>
#include <execinfo.h>

#ifdef ARCH_PC_WIN95
#  include <winsock2.h>
#else
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <signal.h>
#  include <sys/ioctl.h>
#  include <unistd.h>
#  include <sys/time.h>
#  include <sys/resource.h>
#  include <netdb.h>
#  include <openssl/engine.h>
#  include <openssl/evp.h>
#  include <openssl/hmac.h>
#  include <openssl/pem.h>
#endif

#include "arch.h"
#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_memory.h"
#include "spu_data_link.h"
#include "stdutil/stdhash.h"
#include "stdutil/stdcarr.h"
#include "stdutil/stddll.h"
#include "stdutil/stdutil.h"

#include "net_types.h"
#include "node.h"
#include "link.h"
#include "state_flood.h"
#include "network.h"
#include "udp.h"
#include "reliable_udp.h"
#include "session.h"
#include "objects.h"
#include "link_state.h"
#include "route.h"
#include "priority_flood.h"
#include "reliable_flood.h"
#include "multicast.h"
#include "kernel_routing.h"
#include "configuration.h"
#include "security.h"

#ifdef	ARCH_PC_WIN95
WSADATA		WSAData;
#else
#  include <sys/ioctl.h>
#  include <net/if.h>
#endif	/* ARCH_PC_WIN95 */

#include "spines.h"

#define HOST_NAME_LEN 50
#define SERVER_TYPE_LEN 20
#define LOG_FILE_NAME_LEN 2000

/* Global Variables */

/* Startup */
Node_ID         My_Address;
int16u	        Port;
char            My_Host_Name[HOST_NAME_LEN];

int16u          Num_Local_Interfaces;
Interface_ID    My_Interface_IDs[MAX_LOCAL_INTERFACES];
Network_Address My_Interface_Addresses[MAX_LOCAL_INTERFACES];

int16           Num_Legs;
Network_Address Remote_Interface_Addresses[MAX_NETWORK_LEGS];
Interface_ID    Remote_Interface_IDs[MAX_NETWORK_LEGS];
Node_ID         Remote_Node_IDs[MAX_NETWORK_LEGS];
Interface_ID    Local_Interface_IDs[MAX_NETWORK_LEGS];

int16           Num_Discovery_Addresses;
Node_ID         Discovery_Address[MAX_DISCOVERY_ADDR];

stdhash         Ltn_Route_Weights = STDHASH_STATIC_CONSTRUCT(sizeof(Network_Leg_ID), sizeof(int16), NULL, NULL, 0);

/* Status Message Variables */
char server_type[SERVER_TYPE_LEN]; /* Type of the server, added to status messages */

/* Nodes and direct links */
Node    *This_Node = NULL;
Node*    Neighbor_Nodes[MAX_LINKS/MAX_LINKS_4_EDGE];
int16    Num_Neighbors;
int16    Num_Nodes;
stdhash  All_Nodes;
stdskl   All_Nodes_by_ID;
stdhash  Known_Interfaces;  /* <Interface_ID -> Interface*> */
stdhash  Known_Addresses;   /* <Network_Address -> Interface*> */
stdhash  Network_Legs;      /* <Network_Leg_ID -> Network_Leg*> */
Link*    Links[MAX_LINKS];
channel  Ses_UDP_Channel;   /* For udp client connections */
sys_scatter Recv_Pack[MAX_LINKS_4_EDGE];
Route*   All_Routes;
stdskl  Client_Cost_Stats; /* AB: added for cost accounting */

stdhash  Monitor_Params;
int      Accept_Monitor;
int      Wireless;
int      Wireless_ts;
char     Wireless_if[20];
int      Wireless_monitor;

char     Log_Filename[LOG_FILE_NAME_LEN];
int      Use_Log_File;

/* Configuration File Variables */
char        Config_file[MAXPATHLEN];
char        Config_File_Found;
char        Unix_Domain_Prefix[SUN_PATH_LEN]; 
char        Unix_Domain_Use_Default;
stdhash     Node_Lookup_Addr_to_ID;
stdhash     Node_Lookup_ID_to_Addr;
int16u      My_ID;
int32u      *Neighbor_Addrs[MAX_NODES + 1];
int16u      *Neighbor_IDs[MAX_NODES + 1];

/* Sessions */

stdhash  Sessions_ID;
stdhash  Sessions_Port;
stdhash  Rel_Sessions_Port;
stdhash  Sessions_Sock;
int16    Link_Sessions_Blocked_On; 

/* Link State */

stdhash  All_Edges;
stdhash  Changed_Edges;

Prot_Def Edge_Prot_Def = {
    Edge_All_States, 
    Edge_All_States_by_Dest, 
    Edge_Changed_States, 
    Edge_State_type,
    Edge_State_header_size,
    Edge_Cell_packet_size,
    Edge_Is_route_change,
    Edge_Is_state_relevant,
    Edge_Set_state_header,
    Edge_Set_state_cell,
    Edge_Process_state_header,
    Edge_Process_state_cell,   
    Edge_Destroy_State_Data  
};

/* Multicast */

stdhash  All_Groups_by_Node; 
stdhash  All_Groups_by_Name; 
stdhash  Changed_Group_States;

Prot_Def Groups_Prot_Def = {
    Groups_All_States, 
    Groups_All_States_by_Name, 
    Groups_Changed_States, 
    Groups_State_type,
    Groups_State_header_size,
    Groups_Cell_packet_size,
    Groups_Is_route_change,
    Groups_Is_state_relevant,
    Groups_Set_state_header,
    Groups_Set_state_cell,
    Groups_Process_state_header,
    Groups_Process_state_cell,   
    Groups_Destroy_State_Data  
};

/* Params */
int      network_flag;
int      Route_Weight;
sp_time  Up_Down_Interval;
sp_time  Time_until_Exit;
int      Minimum_Window;
int      Fast_Retransmit;
int      Stream_Fairness;
int      TCP_Fairness;
int      Print_Cost;
int      Unicast_Only;
int      Memory_Limit;
int16    KR_Flags;

/* Statistics */
int64_t total_received_bytes;
int64_t total_received_pkts;
int64_t total_udp_pkts;
int64_t total_udp_bytes;
int64_t total_rel_udp_pkts;
int64_t total_rel_udp_bytes;
int64_t total_link_ack_pkts;
int64_t total_link_ack_bytes;
int64_t total_intru_tol_pkts;
int64_t total_intru_tol_bytes;
int64_t total_intru_tol_ack_pkts;
int64_t total_intru_tol_ack_bytes;
int64_t total_intru_tol_ping_pkts;
int64_t total_intru_tol_ping_bytes;
int64_t total_hello_pkts;
int64_t total_hello_bytes;
int64_t total_link_state_pkts;
int64_t total_link_state_bytes;
int64_t total_group_state_pkts;
int64_t total_group_state_bytes;

/* DT variables */
int64u IT_full_dropped;
int64u IT_dead_dropped;
int64u IT_size_dropped;
int64u IT_total_pkts;
int64u Injected_Messages;

/* DT Crypto */
int16u HMAC_Key_Len;
int16u DH_Key_Len;
int16u Signature_Len;
int16u Signature_Len_Bits;
EVP_PKEY *Pub_Keys[MAX_NODES + 1];
EVP_PKEY *Priv_Key;

/* Static Variables */

static void 	Usage(int argc, char *argv[]);
static void     Init_Memory_Objects(int x);

void            Set_resource_limit(int max_mem);
int32           Get_Interface_ip(char *iface);

void E_exit_events_wrapper(int signum)
{
    E_exit_events_async_safe();
}

void Immediate_Cleanup(int signum)
{
    Session_Finish();
    printf("Process Terminated with %d signal\n", signum);
    exit(signum);
}

#if 0
/* 01/2015 - SIGNAL HANDLER FUNCTION FOR DEBUGGING CRASHES */
void signal_handler(int sig) {
    
    int size = 100, j, nptrs;
    void *buffer[100];
    char **strings;

    nptrs = backtrace(buffer, size);
    printf("backtrace() returned %d addresses\n", nptrs);

    /* The call backtrace_symbols_fd(buffer, nptrs, STDOUT_FILENO)
       would produce similar output to the following: */

    strings = backtrace_symbols(buffer, nptrs);
    if (strings == NULL) {
        perror("backtrace_symbols");
        exit(EXIT_FAILURE);
    }

    for (j = 0; j < nptrs; j++)
        printf("%s\n", strings[j]);

    free(strings);

    printf("... Goodbye\n");

    Immediate_Cleanup(sig);
    exit(0);
}
#endif

/***********************************************************/
/* int main(int argc, char* argv[])                        */
/*                                                         */
/* Main function. Here it all begins...                    */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* argc, argv: standard, input parameters                  */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

int main(int argc, char* argv[]) 
{
    sp_time now;
    int ret;
    size_t s_len;

    Alarm( PRINT, "/===========================================================================\\\n");
    Alarm( PRINT, "| Spines                                                                    |\n");
    Alarm( PRINT, "| Copyright (c) 2003 - 2020 Johns Hopkins University                        |\n"); 
    Alarm( PRINT, "| All rights reserved.                                                      |\n");
    Alarm( PRINT, "|                                                                           |\n");
    Alarm( PRINT, "| Spines is licensed under the Spines Open-Source License.                  |\n");
    Alarm( PRINT, "| You may only use this software in compliance with the License.            |\n");
    Alarm( PRINT, "| A copy of the License can be found at http://www.spines.org/LICENSE.txt   |\n");
    Alarm( PRINT, "|                                                                           |\n");
    Alarm( PRINT, "| Creators:                                                                 |\n");
    Alarm( PRINT, "|    Yair Amir                 yairamir@cs.jhu.edu                          |\n");
    Alarm( PRINT, "|    Claudiu Danilov           claudiu@cs.jhu.edu                           |\n");
    Alarm( PRINT, "|    John Lane Schultz         jschultz@spreadconcepts.com                  |\n");
    Alarm( PRINT, "|    Daniel Obenshain          dano@cs.jhu.edu                              |\n");
    Alarm( PRINT, "|    Thomas Tantillo           tantillo@cs.jhu.edu                          |\n");
    Alarm( PRINT, "|    Amy Babay                 babay@cs.jhu.edu                             |\n");
    Alarm( PRINT, "|                                                                           |\n");
    Alarm( PRINT, "| Major Contributors:                                                       |\n");
    Alarm( PRINT, "|    John Lane                 johnlane@cs.jhu.edu                          |\n");
    Alarm( PRINT, "|    Raluca Musaloiu-Elefteri  ralucam@cs.jhu.edu                           |\n");
    Alarm( PRINT, "|    Nilo Rivera                nrivera@cs.jhu.edu                           |\n");
    Alarm( PRINT, "|                                                                           |\n");
    Alarm( PRINT, "| Contributors:                                                             |\n");
    Alarm( PRINT, "|    Sahiti Bommareddy         sahiti@jhu.edu                               |\n");
    Alarm( PRINT, "|                                                                           |\n");
    Alarm( PRINT, "|                                                                           |\n");
    Alarm( PRINT, "| WWW:     www.spines.org      www.dsn.jhu.edu                              |\n");
    Alarm( PRINT, "| Contact: spines@spines.org                                                |\n");
    Alarm( PRINT, "|                                                                           |\n");
    Alarm( PRINT, "| Version 5.5, Built December 23, 2020                                      |\n"); 
    Alarm( PRINT, "|                                                                           |\n");
    Alarm( PRINT, "| This product uses software developed by Spread Concepts LLC for use       |\n");
    Alarm( PRINT, "| in the Spread toolkit. For more information about Spread,                 |\n");
    Alarm( PRINT, "| see http://www.spread.org                                                 |\n");
    Alarm( PRINT, "\\===========================================================================/\n\n");

    setlinebuf(stdout);
    Usage(argc, argv);

    Alarm_set_types(PRINT|NETWORK|STATUS);
    /*Alarm_set_types(PRINT|DEBUG|STATUS);*/
    Alarm_set_priority(SPLOG_INFO);
    Alarm_enable_timestamp_high_res(NULL);

    /* add the sigPIPE handler */
#ifndef ARCH_PC_WIN95
    signal(SIGPIPE, SIG_IGN);
#endif

    /* Catch SIGINT, SIGTERM, SIGHUP (and other recoverable signals) in order to cleanup things 
     * after closing event loop */
    signal(SIGINT,  E_exit_events_wrapper);
    signal(SIGTERM, E_exit_events_wrapper);
    signal(SIGHUP,  E_exit_events_wrapper);
    
    /* Catch SIGABRT, SIGSEGV, (and other unrecoverable signals) to cleanup things now.
     * NOTE: handler calls unlink, which is async safe, so this approach is safe */
    signal(SIGABRT, Immediate_Cleanup);
    signal(SIGSEGV, Immediate_Cleanup);
    signal(SIGFPE,  Immediate_Cleanup);
    signal(SIGILL,  Immediate_Cleanup);
    /*signal(SIGABRT, signal_handler);
    signal(SIGSEGV, signal_handler);
    signal(SIGFPE,  signal_handler);
    signal(SIGILL,  signal_handler);*/

#ifdef	ARCH_PC_WIN95    
    ret = WSAStartup( MAKEWORD(1,1), &WSAData );
    if( ret != 0 )
        Alarm( EXIT, "r: winsock initialization error %d\n", ret );
#endif	/* ARCH_PC_WIN95 */

    Injected_Messages = 0;

    /* Initialize this node */
    Init_My_Node();

    /* Load Spines Configuration File */
    Config_File_Found = 0;
    Conf_init(Config_file);

    /* Non-Default Unix Domain Path specified on cmd line or config file? */
    if (Unix_Domain_Use_Default == 1) {
        /* Check room for length of "data" suffix and NULL byte */
        s_len = SUN_PATH_LEN - strlen(SPINES_UNIX_DATA_SUFFIX) - 1;
        ret = snprintf(Unix_Domain_Prefix, s_len, "%s%hu", SPINES_UNIX_SOCKET_PATH, Port);
        if (ret > s_len) {
            Alarm(EXIT, "Default Unix Domain Pathname too large (%d)! Max allowed is %u\n",
                    ret, s_len);
        }
    }

    Sec_init();
    E_init();

    now = E_get_time();
    srand((unsigned) stdhcode_oaat(&now, sizeof(now)));
   
    /* Is there some specified memory constraint */
    if (Memory_Limit != 0) {
        Set_resource_limit(Memory_Limit*1024*1024);
        if (Memory_Limit < 10) {
            Init_Memory_Objects(1);
        } else {
            Init_Memory_Objects(10);
        }
    } else {
        Init_Memory_Objects(10);
    }

    if (Conf_IT_Link.Crypto == 1 || Conf_Prio.Crypto == 1 || 
            Conf_Rel.Crypto == 1) {
        ENGINE_load_builtin_engines();
        ENGINE_register_all_complete();
    }

    Init_Network();

    if(Up_Down_Interval.sec != 0)
	E_queue(Up_Down_Net, 0, NULL, Up_Down_Interval);

    if(Time_until_Exit.sec != 0)
	E_queue(Graceful_Exit, 0, NULL, Time_until_Exit);

    IT_full_dropped = 0;
    IT_dead_dropped = 0;
    IT_size_dropped = 0;
    IT_total_pkts   = 0;

    E_handle_events();

    Session_Finish();

    return(1);
}

/***********************************************************/
/* void Init_Memory_Objects(void)                          */
/*                                                         */
/* Initializes memory                                      */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* x: Increase by multiplicative factor the                */
/*    bound on memory usage that is never released         */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

static void Init_Memory_Objects(int x)
{
  /* initilize memory object types  */
  /* to get original Spines memory parameters, use x=10 */
  Mem_init_object_abort(PACK_HEAD_OBJ, "packet_header", sizeof(packet_header), (int)(10*x), 1);
  Mem_init_object_abort(PACK_BODY_OBJ, "packet_body", sizeof(packet_body), (int)(20*x), 20);
  Mem_init_object_abort(PACK_OBJ, "packet_obj", MAX_PACKET_SIZE, (int)(20*x), 20);
  Mem_init_object_abort(SYS_SCATTER, "sys_scatter", sizeof(sys_scatter), (int)(10*x), 1);
  Mem_init_object_abort(MESSAGE_OBJ, "message", MAX_PACKET_SIZE * MAX_PKTS_PER_MESSAGE, (int)(20*x), 20);
  Mem_init_object_abort(FRAG_OBJ, "fragment", sizeof(fragment_header), (int)(20*x), 20);
  Mem_init_object_abort(TREE_NODE, "Node", sizeof(Node), (int)(3*x), 10);
  Mem_init_object_abort(DIRECT_LINK, "Link", sizeof(Link), (int)(1*x), 1);
  Mem_init_object_abort(OVERLAY_EDGE, "Edge", sizeof(Edge), (int)(5*x), 10);
  Mem_init_object_abort(OVERLAY_ROUTE, "Route", sizeof(Route), (int)(90*x), 10);
  Mem_init_object_abort(CHANGED_STATE, "Changed_State", sizeof(Changed_State), (int)(5*x), 1);
  Mem_init_object_abort(STATE_CHAIN, "State_Chain", sizeof(State_Chain), (int)(20*x), 1);
  Mem_init_object_abort(MULTICAST_GROUP, "Group_State", sizeof(Group_State), (int)(20*x), 1);
  Mem_init_object_abort(INTERFACE, "Interface", sizeof(Interface), 1*x, 1);
  Mem_init_object_abort(NETWORK_LEG, "Network_Leg", sizeof(Network_Leg), 5*x, 10);
  Mem_init_object_abort(BUFFER_CELL, "Buffer_Cell", sizeof(Buffer_Cell), (int)(30*x), 1);
  Mem_init_object_abort(FRAG_PKT, "Frag_Packet", sizeof(Frag_Packet), (int)(30*x), 1);
  Mem_init_object_abort(UDP_CELL, "UDP_Cell", sizeof(UDP_Cell), (int)(30*x), 1);
  Mem_init_object_abort(PRIO_FLOOD_PQ_NODE, "Priority_Flood_PQ", sizeof(Prio_PQ_Node), (int)(30*x), 20);
  Mem_init_object_abort(PRIO_FLOOD_NS_OBJ, "Priority_Flood_NS", sizeof(Prio_Neighbor_Status) * (Degree[My_ID] + 1), (int)(30*x), 20);
  Mem_init_object_abort(SEND_QUEUE_NODE, "Send_Fairness_Queue", sizeof(Send_Fair_Queue), (int)(3*x), 1); 
  Mem_init_object_abort(FLOW_QUEUE_NODE, "Flow_Fairness_Queue", sizeof(Flow_Queue), (int)(3*x), 1); 
  Mem_init_object_abort(RF_SESSION_OBJ, "Reliable_Flood_Session", sizeof(Session_Obj), (int)(3*x), 1); 
  Mem_init_object_abort(DISSEM_QUEUE_NODE, "Dissemination_Queue", sizeof(Dissem_Fair_Queue), (int)(3*x), 1); 
  Mem_init_object_abort(MP_BITMASK, "MultiPath_Bitmask", MultiPath_Bitmask_Size, (int)(10*x), 1); 
  Mem_init_object_abort(CONTROL_DATA, "Control_Data", sizeof(Control_Data), (int)(1*x), 1);
  Mem_init_object_abort(RELIABLE_DATA, "Reliable_Data", sizeof(Reliable_Data), (int)(3*x), 1);
  Mem_init_object_abort(REALTIME_DATA, "Reatltime_Data", sizeof(Realtime_Data), (int)(1*x), 0);
  Mem_init_object_abort(INTRUSION_TOL_DATA, "Intrusion_Tol_Data", sizeof(Int_Tol_Data), (int)(1*x), 0);
  Mem_init_object_abort(SESSION_OBJ, "Session", sizeof(Session), (int)(3*x), 0);
  Mem_init_object_abort(STDHASH_OBJ, "stdhash", sizeof(stdhash), (int)(10*x), 0);
}

/***********************************************************/
/* int32 Get_Interface_ip(char *iface)                     */
/*                                                         */
/* Get the IP address for device name (i.e. eth0)          */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* *iface: string with the if name                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* ip address for the interface/device name                */
/*                                                         */
/***********************************************************/

int32 Get_Interface_ip(char *iface)
{
#ifdef ARCH_PC_WIN95
	Alarm(PRINT, "Windows does not supporting getting the interface that way\r\n");
	return -1;
        /* A code snippit that might support this on windows 
#ifdef _WINDOWS
> +    enum { MAX_URL_INTERFACES = 100 };
> +    SOCKET s = socket (PF_INET, SOCK_STREAM, 0);
> +    if (s != INVALID_SOCKET) {
> +        INTERFACE_INFO interfaces[MAX_URL_INTERFACES];
> +        DWORD filledBytes = 0;
> +        WSAIoctl (s,
> +                  SIO_GET_INTERFACE_LIST,
> +                  0,
> +                  0,
> +                  interfaces,
> +                  sizeof (interfaces),
> +                  &filledBytes,
> +                  0,
> +                  0);
> +        unsigned int interfaceCount = filledBytes / sizeof
> (INTERFACE_INFO);
> +        for (unsigned int i = 0; i < interfaceCount; ++i) {
> +            if (interfaces[i].iiFlags & IFF_UP) {
> +                string
> addr(inet_ntoa(interfaces[i].iiAddress.AddressIn.sin_add
> r));
> +                if (addr != LOCALHOST)
> +                    url.push_back(TcpAddress(addr, port));
> +            }
> +        }
> +        closesocket (s);
> +    }

        */
#else
    int sk;
    int32 addr;
    struct ifreq ifr;

    memset(&ifr, 0, sizeof(struct ifreq));
    if((sk = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) >= 0) {
        ifr.ifr_addr.sa_family = AF_INET;
        strcpy(ifr.ifr_name, iface);

        if (ioctl(sk, SIOCGIFADDR, &ifr) == 0) {
            addr = ((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr.s_addr;
        } else { 
	    Alarm(PRINT, "Get_Interface_ip() SIOCGIFADDR problem (root?)\n");
	    return -1;
        }
    } else { 
	Alarm(PRINT, "Get_Interface_ip() socket error. (root?)\n");
	return -1;
    }
    close(sk);
    return ntohl(addr);
#endif
}

/***********************************************************/
/* void Set_resource_limit(int max_mem)                    */
/*                                                         */
/* Set resource limit on spines for memory constrained     */
/* and/or embeded machines                                 */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* max_mem: maximum amount of virtual memory that          */
/* Spines should use.                                      */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* None                                                    */
/*                                                         */
/***********************************************************/

void Set_resource_limit(int max_mem)
{
#ifdef ARCH_PC_WIN95
	Alarm(PRINT, "ERROR: Can't set memory limit on Windows\r\n");
	return;

#else
    struct rlimit rl;

    if (max_mem == 0) {
        return;
    }
    if (getrlimit(RLIMIT_AS, &rl) < 0) {
        Alarm(EXIT, "Set_resource_limit(): Failed to set maximum memory\n");
    }
    rl.rlim_cur = max_mem;
    if (setrlimit(RLIMIT_AS, &rl) < 0) {
        Alarm(EXIT, "Set_resource_limit(): Failed to set maximum memory\n");
    }
#endif
}

/***********************************************************/
/* void Usage(int argc, char* argv[])                      */
/*                                                         */
/* Parses command line parameters                          */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* argc, argv: standard command line parameters            */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

static  void    Usage(int argc, char *argv[])
{
    char ip_str[16];
    int i1, i2, i3, i4;
    int tmp, ret;
    size_t s_len;
    struct hostent *hostp;
    struct sockaddr_in sock_addr;

    /* Setting defaults values */
    My_Address = 0;
    Port = 8100;
    Route_Weight = DISTANCE_ROUTE;
    network_flag = 1;
    Minimum_Window = 1;
    Fast_Retransmit = 0;
    Stream_Fairness = 0;
    TCP_Fairness = 0;
    Print_Cost = 0;
    Up_Down_Interval.sec  = 0;
    Up_Down_Interval.usec = 0;
    Time_until_Exit.sec  = 0;
    Time_until_Exit.usec = 0;
    Accept_Monitor = 0;
    Unicast_Only = 0;
    KR_Flags = 0;
    Wireless = 0;
    Wireless_ts = 30;
    Wireless_monitor = 0;
    Memory_Limit = 0;
    memset((void*)Wireless_if, '\0', sizeof(Wireless_if));
    Use_Log_File = 0;
    Unix_Domain_Use_Default = 1;
    Leg_Rate_Limit_kbps = 500000;

    strcpy( Config_file, "spines.conf" );
    Num_Discovery_Addresses = 0;

    while(--argc > 0) {
        argv++;
        if(!strncmp(*argv, "-mw", 4)) {
            sscanf(argv[1], "%d", (int*)&Minimum_Window);
            argc--; argv++;
        }else if(!strncmp(*argv, "-fr", 4)) {
            Fast_Retransmit = 1;
        }else if(!strncmp(*argv, "-sf", 4)) {
            Stream_Fairness = 1;
        }else if(!strncmp(*argv, "-tf", 4)) {
            TCP_Fairness = 1;
        }else if(!strncmp(*argv, "-pc", 4)) {
            Print_Cost = 1;
        }else if(!strncmp(*argv, "-m", 3)) {
            Accept_Monitor = 1;
        }else if(!strncmp(*argv, "-U", 3)) {
            Unicast_Only = 1;
        }else if(!strncmp(*argv, "-rl", 4)) {
            sscanf(argv[1], "%d", &Leg_Rate_Limit_kbps);
            argc--; argv++;
        }else if(!strncmp(*argv, "-M", 3)) {
            sscanf(argv[1], "%d", (int*)&Memory_Limit);
            if (Memory_Limit < 1) Memory_Limit = 1; 
            argc--; argv++;
        }else if(!strncmp(*argv, "-Wts", 5)) {
            sscanf(argv[1], "%d", (int*)&Wireless_ts);
            Wireless = 1;
            argc--; argv++;
        }else if(!strncmp(*argv, "-Wif", 5)) {
            sscanf(argv[1], "%s", Wireless_if);
            Wireless = 1;
            Wireless_monitor = 1;
            argc--; argv++;
        }else if(!strncmp(*argv, "-W", 3)) {
            Wireless = 1;
        }else if(!strncmp(*argv, "-p", 3)) {
            sscanf(argv[1], "%d", (int*)&tmp);
            Port = (int16u)tmp;
            argc--; argv++;
        }else if(!strncmp(*argv, "-u", 3)) {
            sscanf(argv[1], "%ld", &Up_Down_Interval.sec);
            argc--; argv++;
        }else if(!strncmp(*argv, "-x", 3)) {
            sscanf(argv[1], "%ld", &Time_until_Exit.sec);
            argc--; argv++;
        }else if(!strncmp(*argv, "-l", 3)) {

            if (My_Address != 0) {
                Alarm(EXIT, "-l should be specified at most once and should "
                            "be specified before any -I parameters!\r\n");
            }

            sscanf(argv[1], "%s", ip_str);
            ret = sscanf( ip_str ,"%d.%d.%d.%d",&i1, &i2, &i3, &i4);
            if (ret == 4) { 
                My_Address = ( (i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4 );
            } else { 
                My_Address = Get_Interface_ip(ip_str);
                if(My_Address == 0) {
                    break;
                }
            }
            /* Look up the host name of My Address */
            sock_addr.sin_addr.s_addr = htonl(My_Address);            
            /*s_addr = htonl(My_Address);*/
            hostp = gethostbyaddr(&(sock_addr.sin_addr.s_addr),
                      sizeof(sock_addr.sin_addr.s_addr), AF_INET);

            if ( hostp != NULL ) {
                snprintf(My_Host_Name,HOST_NAME_LEN,"%s",hostp->h_name); 
            } else {
                snprintf(My_Host_Name,HOST_NAME_LEN,IPF,IP(My_Address)); 
            }

            argc--; argv++;

        } else if (!strncmp(*argv, "-I", 3)) {

            if (Num_Local_Interfaces == MAX_LOCAL_INTERFACES) {
                Alarm(EXIT, "Too many local interfaces specified!\r\n");
            }

            ++argv;
            --argc;

            if (argc == 0) {
                Alarm(EXIT, "-I requires at least one parameter!\r\n");
            }

            if (sscanf(*argv, "%d.%d.%d.%d", &i1, &i2, &i3, &i4) != 4 ||
                i1 < 0 || i1 > 255 || i2 < 0 || i2 > 255 ||
                i3 < 0 || i3 > 255 || i4 < 0 || i4 > 255) {
                  Alarm(EXIT, "-I expects an IPv4 address first!\r\n");
            }

            My_Interface_Addresses[Num_Local_Interfaces] = ((i1 << 24) | (i2 << 16) | (i3 << 8) | i4);

            if (My_Address == 0 && Num_Local_Interfaces == 0)
                My_Address = ((i1 << 24) | (i2 << 16) | (i3 << 8) | i4);

            if (argc > 1 && argv[1][0] != '-') {

                ++argv;
                --argc;

                if (sscanf(*argv, "%d.%d.%d.%d", &i1, &i2, &i3, &i4) != 4 ||
                    i1 < 0 || i1 > 255 || i2 < 0 || i2 > 255 ||
                    i3 < 0 || i3 > 255 || i4 < 0 || i4 > 255) {
                      Alarm(EXIT, "-I expects a logical IPv4 interface identifier second!\r\n");
                }

                My_Interface_IDs[Num_Local_Interfaces] = ((i1 << 24) | (i2 << 16) | (i3 << 8) | i4);
            }

            ++Num_Local_Interfaces;

        }else if(!strncmp(*argv, "-d", 3)) {
            argc--; argv++;
            if (argc == 0)
                Alarm(EXIT, "-d requires an IP parameter\n");

            sscanf(*(argv), "%s", ip_str);
            sscanf(ip_str ,"%d.%d.%d.%d",&i1, &i2, &i3, &i4);

            Discovery_Address[Num_Discovery_Addresses++] = 
                ( (i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4 );

            if (Num_Discovery_Addresses > MAX_DISCOVERY_ADDR) {
                Alarm(EXIT, "too many discovery addresses...\n");
            }
        }else if (!strncmp(*argv, "-w", 3)) {
            argc--; argv++;
            if (argc == 0)
                Alarm(EXIT, "-w requires a route type parameter\n");

            if (!strncmp(*(argv), "distance", 9))
                Route_Weight = DISTANCE_ROUTE;
            else if (!strncmp(*(argv), "latency", 8))
                Route_Weight = LATENCY_ROUTE;
            else if (!strncmp(*(argv), "loss", 5))
                Route_Weight = LOSSRATE_ROUTE;
            else if (!strncmp(*(argv), "explat", 7))
                Route_Weight = AVERAGE_ROUTE;
            else if (!strncmp(*(argv), "problem", 8))
                Route_Weight = PROBLEM_ROUTE;
        } else if (!strncmp(*argv, "-a", 3)) {

            if (Num_Legs == MAX_NETWORK_LEGS) {
                Alarm(EXIT, "Too many network legs specified!\r\n");
            }

            --argc; ++argv;

            if (argc == 0) {
                Alarm(EXIT, "-a requires at least one parameter!\r\n");
            }

            if (sscanf(*argv, "%d.%d.%d.%d", &i1, &i2, &i3, &i4) != 4 ||
                i1 < 0 || i1 > 255 || i2 < 0 || i2 > 255 ||
                i3 < 0 || i3 > 255 || i4 < 0 || i4 > 255) {
                  Alarm(EXIT, "-a expects an IPv4 remote network address first!\r\n");
            }

            Remote_Interface_Addresses[Num_Legs] = ((i1 << 24) | (i2 << 16) | (i3 << 8) | i4);

            if (argc > 1 && argv[1][0] != '-') {

                --argc; ++argv;

                if (sscanf(*argv, "%d.%d.%d.%d", &i1, &i2, &i3, &i4) != 4 ||
                    i1 < 0 || i1 > 255 || i2 < 0 || i2 > 255 ||
                    i3 < 0 || i3 > 255 || i4 < 0 || i4 > 255) {
                      Alarm(EXIT, "-a expects an IPv4 interface identifier second!\r\n");
                }

                Remote_Interface_IDs[Num_Legs] = ((i1 << 24) | (i2 << 16) | (i3 << 8) | i4);
            }

            if (argc > 1 && argv[1][0] != '-') {

                --argc; ++argv;

                if (sscanf(*argv, "%d.%d.%d.%d", &i1, &i2, &i3, &i4) != 4 ||
                    i1 < 0 || i1 > 255 || i2 < 0 || i2 > 255 ||
                    i3 < 0 || i3 > 255 || i4 < 0 || i4 > 255) {
                      Alarm(EXIT, "-a expects an IPv4 node identifier third!\r\n");
                }

                Remote_Node_IDs[Num_Legs] = ((i1 << 24) | (i2 << 16) | (i3 << 8) | i4);
            }

            if (argc > 1 && argv[1][0] != '-') {

                --argc; ++argv;

                if (sscanf(*argv, "%d.%d.%d.%d", &i1, &i2, &i3, &i4) != 4 ||
                    i1 < 0 || i1 > 255 || i2 < 0 || i2 > 255 ||
                    i3 < 0 || i3 > 255 || i4 < 0 || i4 > 255) {
                      Alarm(EXIT, "-a expects an IPv4 local interface identifier fourth!\r\n");
                }

                Local_Interface_IDs[Num_Legs] = ((i1 << 24) | (i2 << 16) | (i3 << 8) | i4);
            }

            ++Num_Legs;

        } else if(!(strncmp(*argv, "-k", 3))) { 
            sscanf(argv[1], "%d", (int*)&tmp);
            if (tmp == 0) KR_Flags |= KR_OVERLAY_NODES;
            if (tmp == 1) KR_Flags |= KR_CLIENT_ACAST_PATH;
            if (tmp == 2) KR_Flags |= KR_CLIENT_MCAST_PATH;
            if (tmp == 3) KR_Flags |= KR_CLIENT_WITHOUT_EDGE;
            argc--; argv++;
        }else if(!(strncmp(*argv, "-lf", 4))) {
            strncpy(Log_Filename,argv[1],LOG_FILE_NAME_LEN);
            Log_Filename[LOG_FILE_NAME_LEN-1] = 0;
            Use_Log_File = 1;
            argc--; argv++;
        }else if(!(strncmp(*argv, "-c", 3))) {
            ++argv;
            --argc;
            if (argc == 0) {
                Alarm(EXIT, "-c requires a parameter!\r\n");
            }
            /* Check room for length of "data" suffix and NULL byte */
            s_len = MAXPATHLEN - 1;
            ret = snprintf( Config_file, s_len, "%s", *argv );
            if (ret > s_len) {
                Alarm(EXIT, "-c: config file name too long (%d), max allowed is %u\n", ret, s_len);
            }
        }else if(!(strncmp(*argv, "-ud", 4))) {
            ++argv;
            --argc;
            if (argc == 0) {
                Alarm(EXIT, "-ud requres a parameter!\r\n");
            }
#ifndef ARCH_PC_WIN95
            /* Check room for length of "data" suffix and NULL byte */
            s_len = SUN_PATH_LEN - strlen(SPINES_UNIX_DATA_SUFFIX) - 1;
            ret = snprintf( Unix_Domain_Prefix, s_len, "%s", *argv );
            if (ret > s_len) {
                Alarm(EXIT, "-ud: path name too long (%d), max allowed is %u\n", ret, s_len);
            }
            Unix_Domain_Use_Default = 0;
#endif
        }else{
            Alarm(PRINT, "ERR: %d | %s\r\n", argc, *argv);

            Alarm(PRINT,
              "Usage:\r\n"
              "\t[-p <port>]                    : base port on which to send, default is 8100\r\n"
              "\t[-l <IP>]                      : the logical ID of this node\r\n"
              "\t[-I <IP> [<IP>]]               : a local network address mapped to an interface ID to\n"
              "\t                                 use for communication\r\n"
              "\t[-a <IP> [<IP> [<IP> [<IP>]]]] : a remote network address, remote interface ID,\n"
              "\t                                 remote node ID and local interface ID that\n"
              "\t                                 define a connection\r\n"
              "\t[-d <IP address>]              : auto-discovery multicast address\r\n"
              "\t[-w <Route_Type>]              : [distance, latency, loss, explat, problem],\n"
              "\t                                 default: distance\r\n"
              "\t[-tf]                          : turn on TCP fairness (was default prior to 5.3)\r\n"
              "\t[-sf]                          : stream based fairness (for reliable links)\r\n"
              "\t[-m]                           : accept monitor commands for setting loss rates\r\n"
              "\t[-x <seconds>]                 : time until exit\r\n"
              "\t[-U]                           : Unicast only: no multicast capabilities\r\n"
              "\t[-W]                           : Wireless Mode\r\n"
              "\t[-k <level>]                   : kernel routing on data packets\r\n"
              "\t[-lf <file>]                   : log file name\r\n"
              "\t[-ud <path>]                   : unix domain socket path prefix, default is %s<port>\r\n"
              "\t[-pc]                          : print cost statistics\r\n"
              "\t[-rl <rate (kbps)>]            : per-leg rate limit (default 500,000 kbps, -1 for no limit)\r\n"
              "\t[-c <file>]                    : configuration file name, default is spines.conf\r\n",
                                                SPINES_UNIX_SOCKET_PATH);
            Alarm(EXIT, "Bye...\r\n");
        }
    }

    /* Alarm_enable_timestamp("%m/%d/%y %H:%M:%S"); */

    if (Use_Log_File) {
        Alarm_set_output(Log_Filename);
    }
}
