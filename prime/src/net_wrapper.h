/*
 * Prime.
 *     
 * The contents of this file are subject to the Prime Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.dsn.jhu.edu/prime/LICENSE.txt
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis, 
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
 * for the specific language governing rights and limitations under the 
 * License.
 *
 * Creators:
 *   Yair Amir            yairamir@cs.jhu.edu
 *   Jonathan Kirsch      jak@cs.jhu.edu
 *   John Lane            johnlane@cs.jhu.edu
 *   Marco Platania       platania@cs.jhu.edu
 *   Amy Babay            babay@pitt.edu
 *   Thomas Tantillo      tantillo@cs.jhu.edu 
 *
 *
 * Major Contributors:
 *   Brian Coan           Design of the Prime algorithm
 *   Jeff Seibert         View Change protocol 
 *   Sahiti Bommareddy    Reconfiguration 
 *   Maher Khan           Reconfiguration 
 *      
 * Copyright (c) 2008-2025
 * The Johns Hopkins University.
 * All rights reserved.
 * 
 * Partial funding for Prime research was provided by the Defense Advanced 
 * Research Projects Agency (DARPA) and the National Science Foundation (NSF).
 * Prime is not necessarily endorsed by DARPA or the NSF.  
 *
 */

#ifndef PRIME_TCP_WRAPPER_H
#define PRIME_TCP_WRAPPER_H

#include "arch.h"
#include "def.h"

int NET_Read (int sd, void *dummy_buf, int32u nBytes);
int NET_Write(int sd, void *dummy_buf, int32u nBytes);

int IPC_Recv(int s, void *d_buf, int nBytes);
int IPC_Send(int s, void *d_buf, int nBytes, char *dst);

int Spines_Mcast_SendOnly_Sock(const char *sp_addr, int sp_port, int proto);
int IPC_DGram_SendOnly_Sock();
int Spines_Sock(const char *sp_addr, int sp_port, int proto, int my_port);
int Spines_SendOnly_Sock(const char *sp_addr, int sp_port, int proto);
#endif
