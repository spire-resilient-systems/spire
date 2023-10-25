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

#ifndef HELLO_H
#define HELLO_H

#include "net_types.h"
#include "network.h"
#include "link.h"

#define DEAD_LINK_CNT     10                        /* Number of hellos unacked until declaring a dead link */
#define CONNECT_LINK_CNT  (1 + DEAD_LINK_CNT / 2)  /* Number of hellos needed b4 connection established */

struct Node_d;
struct Edge_d;
struct Interface_d;
struct Network_Leg_d;
struct Link_d;

extern sp_time hello_timeout;

void Init_Connections(void);
void Send_Hello(int linkid, void* dummy);
void Send_Hello_Request(int linkid, void* dummy);
void Send_Hello_Request_Cnt(int linkid, void* dummy);
void Send_Hello_Ping(int dummy_int, void* dummy);
void Send_Discovery_Hello_Ping(int dummy_int, void* dummy);
void Net_Send_Hello(int16 linkid, int mode);
void Net_Send_Hello_Ping(channel chan, Network_Address addr);

void Process_hello_packet(struct Link_d *lk, packet_header *pack_hdr, char *buf, int remaining_bytes, int32u type);

void Process_hello_ping(packet_header *pack_hdr, Network_Address from_addr, 
			struct Interface_d *local_interf, struct Interface_d **remote_interf, struct Network_Leg_d **leg, struct Link_d **link);

#endif
