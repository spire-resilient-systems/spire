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

#ifndef OBJECTS_H
#define OBJECTS_H

#include "arch.h"

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


/* Transmitted objects */
#define PACK_HEAD_OBJ           10
#define PACK_BODY_OBJ           11
#define PACK_OBJ                12
#define SYS_SCATTER             13
#define STDHASH_OBJ             14
#define MESSAGE_OBJ             15
#define FRAG_OBJ                16

/* Non-Transmitted objects */
#define TREE_NODE               21
#define DIRECT_LINK             22
#define OVERLAY_EDGE            23
#define OVERLAY_ROUTE           24
#define CHANGED_STATE           25
#define STATE_CHAIN             26
#define MULTICAST_GROUP         27
#define INTERFACE               28
#define NETWORK_LEG             29

#define BUFFER_CELL             31
#define UDP_CELL                32
#define FRAG_PKT                33

#define PRIO_FLOOD_PQ_NODE      34
#define PRIO_FLOOD_NS_OBJ       35
#define SEND_QUEUE_NODE         36
#define FLOW_QUEUE_NODE         37
#define RF_SESSION_OBJ          38
#define DISSEM_QUEUE_NODE       39
#define MP_BITMASK              40

#define CONTROL_DATA            41
#define RELIABLE_DATA           42
#define REALTIME_DATA           43
#define RESERVED_DATA1          44 /* MN */
#define RESERVED_DATA2          45 /* SC2 */
#define INTRUSION_TOL_DATA      46

#define SESSION_OBJ             51


#define REL_MCAST_TREE_OBJ      52


/* Special objects */
#define UNKNOWN_OBJ             54      /* This represents an object of undertermined or 
                                         * variable type.  Can only be used when appropriate.
                                         * i.e. when internal structure of object is not accessed.
                                         * This is mainly used with queues
                                         */

/* Global Functions to manipulate objects */
int     Is_Valid_Object(int32u oid);
char    *Objnum_to_String(int32u obj_type);

#endif /* OBJECTS_H */


