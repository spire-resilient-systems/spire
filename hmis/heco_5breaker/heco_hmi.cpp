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
 * Copyright (c) 2017-2023 Johns Hopkins University.
 * All rights reserved.
 *
 * Partial funding for Spire research was provided by the Defense Advanced 
 * Research Projects Agency (DARPA), the Department of Defense (DoD), and the
 * Department of Energy (DoE).
 * Spire is not necessarily endorsed by DARPA, the DoD or the DoE. 
 *
 */
//***************************************************************************
//                          main.cpp  -  description
//                             -------------------
//  begin            : Wed Jun 3 11:10:58 2015
//  generated by     : pvdevelop (C) Lehrig Software Engineering
//  email            : lehrig@t-online.de
//***************************************************************************
//Include headers for socket management
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <signal.h>

//Include other headers
#include "pvapp.h"
#include "master_exec.h"

extern "C" {
    #include "net_wrapper.h"
    #include "def.h"
    #include "itrc.h"
    #include "spu_events.h"
    #include "stdutil/stdcarr.h"
}

// todo: comment me out. you can insert these objects as extern in your masks.
//rlModbusClient     modbus(modbusdaemon_MAILBOX,modbusdaemon_SHARED_MEMORY,modbusdaemon_SHARED_MEMORY_SIZE);
//rlSiemensTCPClient siemensTCP(siemensdaemon_MAILBOX,siemensdaemon_SHARED_MEMORY,siemensdaemon_SHARED_MEMORY_SIZE);
//rlPPIClient        ppi(ppidaemon_MAILBOX,ppidaemon_SHARED_MEMORY,ppidaemon_SHARED_MEMORY_SIZE);

unsigned int Seq_Num;
int ipc_sock;
itrc_data itrc_in, itrc_out;
struct timeval min_wait;
data_model the_model;
int Script_Running;
int Script_Button_Pushed;
int Script_Pipe[2];
stdcarr Script_History = STDCARR_STATIC_CONSTRUCT(80,0);
int Script_History_Seq;
int Script_Breaker_Index;
int Script_Breaker_Val;
sp_time Next_Button, Button_Pressed_Duration;
extern int32u My_Global_Configuration_Number;

extern void modelInit();

void itrc_init(int ac, char **av) 
{
    char *ip;
    struct timeval now;
    
    // Usage check
    if (ac < 2 || ac > 3) {
        printf("Usage: %s spinesAddr:spinesPort [-port=PORT]\n", av[0]);
        exit(EXIT_FAILURE);
    }

    My_Global_Configuration_Number = 0;
    Init_SM_Replicas();

    // NET Setup
    gettimeofday(&now, NULL);
    My_Incarnation = now.tv_sec;
    Seq_Num = 1;
    Type = HMI_TYPE;
    My_ID = PNNL;
    //Prime_Client_ID = (NUM_SM + 1) + MAX_EMU_RTU + My_ID;
    Prime_Client_ID = MAX_NUM_SERVER_SLOTS + MAX_EMU_RTU + My_ID;
    My_IP = getIP();
    // Setup IPC for HMI main thread
    memset(&itrc_in, 0, sizeof(itrc_data));
    sprintf(itrc_in.prime_keys_dir, "%s", (char *)HMI_PRIME_KEYS);
    sprintf(itrc_in.sm_keys_dir, "%s", (char *)HMI_SM_KEYS);
    sprintf(itrc_in.ipc_local, "%s%d", (char *)HMI_IPC_MAIN, My_ID);
    sprintf(itrc_in.ipc_remote, "%s%d", (char *)HMI_IPC_ITRC, My_ID);
    ipc_sock = IPC_DGram_Sock(itrc_in.ipc_local);

    // Setup IPC for Worker thread (itrc client)
    memset(&itrc_out, 0, sizeof(itrc_data));
    sprintf(itrc_out.prime_keys_dir, "%s", (char *)HMI_PRIME_KEYS);
    sprintf(itrc_out.sm_keys_dir, "%s", (char *)HMI_SM_KEYS);
    sprintf(itrc_out.ipc_local, "%s%d", (char *)HMI_IPC_ITRC, My_ID);
    sprintf(itrc_out.ipc_remote, "%s%d", (char *)HMI_IPC_MAIN, My_ID);
    ip = strtok(av[1], ":");
    sprintf(itrc_out.spines_ext_addr, "%s", ip);
    ip = strtok(NULL, ":");
    sscanf(ip, "%d", &itrc_out.spines_ext_port);
}

void *master_connection(void *arg) 
{
    UNUSED(arg);

    E_init();
    //fd_set active_fd_set, read_fd_set;

    // Init data structures for select()
    //FD_ZERO(&active_fd_set);
    //FD_SET(ipc_sock, &active_fd_set);

    E_attach_fd(ipc_sock, READ_FD, Read_From_Master, 0, NULL, MEDIUM_PRIORITY);
    E_attach_fd(Script_Pipe[0], READ_FD, Execute_Script, 0, NULL, MEDIUM_PRIORITY);

    E_handle_events();

    /* while(1) {

        read_fd_set = active_fd_set;
        select(FD_SETSIZE, &read_fd_set, NULL, NULL, NULL);
        
        if(FD_ISSET(ipc_sock, &read_fd_set)) {
            Read_From_Master(ipc_sock);
        }
    } */

    return NULL;
}

int pvMain(PARAM *p)
{
    int ret;

    pvSendVersion(p);
    pvSetCaption(p,"power_grid");
    pvResize(p,0,1280,1024);
    //pvScreenHint(p,1024,768); // this may be used to automatically set the zoomfactor
    ret = 1;
    pvGetInitialMask(p);
    if(strcmp(p->initial_mask,"mask1") == 0) ret = 1;

    while(1) {
        if(trace) printf("show_mask%d\n", ret);
        switch(ret)
        {
            case 1:
                pvStatusMessage(p,-1,-1,-1,"mask1");
                ret = show_mask1(p);
                break;
            default:
                return 0;
        }
    }
}

#ifdef USE_INETD
int main(int ac, char **av)
{
    PARAM p;
    pthread_t tid, itid;

    signal(SIGPIPE, SIG_IGN);
    modelInit();

    itrc_init(ac, av);
    pthread_create(&itid, NULL, &ITRC_Client, (void *)&itrc_out);
    pthread_create(&tid, NULL, &master_connection, NULL);

    pvInit(ac,av,&p);
    /* here you may interpret ac,av and set p->user to your data */
    pvMain(&p);
    return 0;
}
#else  // multi threaded server
int main(int ac, char **av)
{
    PARAM p;
    int s;
    pthread_t tid, itid;

    signal(SIGPIPE, SIG_IGN);
    modelInit();

    itrc_init(ac, av);
    pthread_create(&itid, NULL, &ITRC_Client, (void *)&itrc_out);
    pthread_create(&tid, NULL, &master_connection, NULL);

    pvInit(ac,av,&p);
    /* here you may interpret ac,av and set p->user to your data */
    while(1) {
        s = pvAccept(&p);
        if(s != -1) pvCreateThread(&p,s);
        else        break;
    }

    return 0;
}
#endif
