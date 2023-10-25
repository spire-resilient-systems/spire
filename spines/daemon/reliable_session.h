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

#ifndef REL_SESSION_H
#define REL_SESSION_H

#include "session.h"

int Init_Reliable_Session(Session *ses, Node_ID address, int16u port);  
int Init_Reliable_Connect(Session *ses, Node_ID address, int16u port);
void Close_Reliable_Session(Session* ses);
int Process_Reliable_Session_Packet(Session *ses);
int Deliver_Rel_UDP_Data(char *buf, int16u len, int32u type);
int Net_Rel_Sess_Send(Session *ses, char *buf, int16u len);
int Process_Sess_Ack(Session *ses, char* buf, int16u ack_len, int32u ses_type, int32u net_type, int32 orig_type);
int Reliable_Ses_Send(Session *ses); 
void Ses_Send_Much(Session *ses); 
void Ses_Send_Ack(int sesid, void* dummy);
void Ses_Send_Nack_Retransm(int sesid, void *dummy);
void Ses_Reliable_Timeout(int sesid, void *dummy);  
void Ses_Try_to_Send(int sesid, void* dummy);
void Ses_Send_Rel_Hello(int sesid, void* dummy); 
int Accept_Rel_Session(Session *ses, udp_header *cmd, char *buf);
void Process_Rel_Ses_Hello(Session *ses, char *buff, int len, int32 orig_type);
int Check_Double_Connect(char *buff, int16u len, int32u type);
void Disconnect_Reliable_Session(Session* ses);
void Ses_Delay_Close(int sesid, void* dummy);
void Ses_Send_One(int sesid, void* dummy);


#endif
