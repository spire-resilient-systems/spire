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

#ifndef NET_WRAPPER_H
#define NET_WRAPPER_H

#include "def.h"
#include <stdint.h>
#include <signal.h>

#ifndef byte
#define byte uint8_t
#endif

#ifndef int16
#define int16 int16_t
#endif

#ifndef int16u
#define int16u uint16_t
#endif

#ifndef int32
#define int32 int32_t
#endif

#ifndef int32u
#define int32u uint32_t
#endif

/* externs */
extern int Type;
extern int My_ID;
extern int32u My_Incarnation;
extern int Prime_Client_ID;
extern int My_IP;
extern int All_Sites[NUM_SM];
extern int CC_Replicas[NUM_CC_REPLICA];
extern int CC_Sites[NUM_CC_REPLICA];
extern char* Ext_Site_Addrs[NUM_CC];
extern char* Int_Site_Addrs[NUM_SITES];
extern sigset_t signal_mask;

//extern char *IP_Addr[NUM_SM];

/* Functions */
//void initIPAddr();

/* Macros */
# define MAX(a,b) (((a)>(b))?(a):(b))
# define MIN(a,b) (((a)<(b))?(a):(b))

void Init_SM_Replicas();
int  Is_CC_Replica(int id);

int serverTCPsock(int port, int qlen);
int clientTCPsock(int port, int addr);
int NET_Read(int s, void *d_buf, int nBytes);
int NET_Write(int s, void *d_buf, int nBytes);

int IPC_Client_Sock(const char *path);
int IPC_DGram_Sock(const char *path);
int IPC_DGram_SendOnly_Sock();
int IPC_Recv(int s, void *d_buf, int nBytes);
int IPC_Send(int s, void *d_buf, int nBytes, const char *to);

int Spines_Sock(const char *sp_addr, int sp_port, int proto, int my_port);
int Spines_SendOnly_Sock(const char *sp_addr, int sp_port, int proto);

struct timeval diffTime(struct timeval t1, struct timeval t2);
struct timeval addTime(struct timeval t1, struct timeval t2);
int compTime(struct timeval t1, struct timeval t2);
int getIP();

#endif /* CONF_NET_WRAPPER_H */
