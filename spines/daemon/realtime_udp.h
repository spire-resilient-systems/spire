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
 */

#ifndef RT_UDP_H
#define RT_UDP_H

#include "node.h"
#include "session.h"
#include "net_types.h"

#define HISTORY_TIME 100000 /* 100 milliseconds */

void Process_RT_UDP_data_packet(Link *lk, sys_scatter *scat,
				int32u type, int mode);

int  Forward_RT_UDP_Data(Node* next_hop, sys_scatter *scat);
int  Request_Resources_RT_UDP(Node *next_hop, int (*callback)(Node*, int));

void Clean_RT_history(Link *lk);
void Send_RT_Nack(int linkid, void* dummy); 
void Send_RT_Retransm(int linkid, void* dummy); 

void Process_RT_nack_packet(Link *lk, sys_scatter *scat, 
			    int32u type, int mode);

#endif
