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

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "spu_scatter.h"
#include "network.h"

struct Interface_d;

void Prot_process_scat(sys_scatter *scat, int total_bytes, struct Interface_d * interface, int mode, int32 type, Network_Address from_addr, int16u from_port);
int32u Get_Link_Data_Type(int mode);
int16u Dissemination_Header_Size(int dissemination);
int16u Link_Header_Size(int mode);
int16u Calculate_Packets_In_Message(sys_scatter *scat, int mode, int16u *last_pkt_space);
void Cleanup_Scatter(sys_scatter *scat);
void Query_Scatter(sys_scatter *scat);

#endif
