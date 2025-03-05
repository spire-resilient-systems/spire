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

#ifndef PRIME_UTIL_DLL_H
#define PRIME_UTIL_DLL_H

#include "arch.h"
#include "stopwatch.h"

typedef struct dummy_dll_node_struct {
  void *data;
  int32u extra[2]; /* generic integers */
  void *next;
  util_stopwatch sw;
} dll_node_struct;

typedef struct dummy_dll_struct {
  dll_node_struct *begin;
  dll_node_struct *current_position;
  dll_node_struct *end;
  int32u length;
} dll_struct;

void UTIL_DLL_Initialize(dll_struct *dll);

void UTIL_DLL_Clear( dll_struct *dll ); 

void UTIL_DLL_Next( dll_struct *dll );

int32u UTIL_DLL_At_End( dll_struct *dll ); 

void UTIL_DLL_Set_Begin( dll_struct *dll );

void* UTIL_DLL_Get_Signed_Message( dll_struct *dll ); 

void UTIL_DLL_Add_Data( dll_struct *dll, void *data ); 
void UTIL_DLL_Add_Data_To_Front(dll_struct *dll, void *data); 

int32u UTIL_DLL_Is_Empty( dll_struct *dll ); 

void* UTIL_DLL_Front_Message( dll_struct *dll ); 

void UTIL_DLL_Pop_Front( dll_struct *dll ); 

void UTIL_DLL_Set_Last_Extra( dll_struct *dll, int32u index, int32u val ); 

int32u UTIL_DLL_Front_Extra( dll_struct *dll, int32u index ); 

double UTIL_DLL_Elapsed_Front( dll_struct *dll );

#endif
