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

#ifndef PRIME_OBJECTS_H
#define PRIME_OBJECTS_H

#define MAX_OBJECTS             200
#define MAX_OBJ_USED            (UNKNOWN_OBJ+1)

/* Object types 
 *
 * Object types must start with 1 and go up. 0 is reserved 
 */


/* Util objects */
#define BASE_OBJ                1
#define TIME_EVENT              2
#define QUEUE                   3
#define QUEUE_SET               4
#define QUEUE_ELEMENT           5
#define MQUEUE_ELEMENT          6
#define SCATTER                 7
#define SYS_SCATTER             8

/* Sent objects */
#define PACK_BODY_OBJ           9
#define PACK_HEAD_OBJ           10

#define PO_SLOT_OBJ             11
#define ORD_SLOT_OBJ            12
#define DLL_NODE_OBJ	        13
#define ERASURE_SLOT_OBJ        14
#define ERASURE_NODE_OBJ        15
#define ERASURE_PART_OBJ        16
#define RECON_SLOT_OBJ          17
#define NET_STRUCT_OBJ          18
#define RB_SLOT_OBJ             19
#define MSG_ARRAY_OBJ           20

/* Special objects */
#define UNKNOWN_OBJ             25      /* This should be the last one */ 

/* Global Functions to manipulate objects */
int     Is_Valid_Object(int32u oid);
char    *Objnum_to_String(int32u obj_type);

#endif /* OBJECTS_H */


