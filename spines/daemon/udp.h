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

#ifndef UDP_H
#define UDP_H

#include "node.h"
#include "session.h"
#include "net_types.h"


/* Packet status */

#define NO_ROUTE    1
#define BUFF_EMPTY  2
#define BUFF_OK     3
#define BUFF_FULL   4
#define BUFF_DROP   5
#define NO_BUFF     6


#define MAX_BUFF   30

void Flip_udp_hdr(udp_header *udp_hdr);
void Copy_udp_header(udp_header *from_udp_hdr, udp_header *to_udp_hdr);

void Process_udp_data_packet(Link *lk, sys_scatter *scat, int32u type, int mode);

int  Forward_UDP_Data(Node* next_hop, sys_scatter *scat);
int  Request_Resources_UDP(Node *next_hop, int (*callback)(Node*, int));

#endif
