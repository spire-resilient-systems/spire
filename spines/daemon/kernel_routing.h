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

#ifndef KERNEL_ROUTING_H
#define KERNEL_ROUTING_H

#define IPINT(a,b,c,d) ((int32) ((a << 24) + (b << 16) + (c << 8) + (d)))

/* Type of kernel routing desired. MCAST needs kernel patch */
#define KR_OVERLAY_NODES        0x0001
#define KR_CLIENT_ACAST_PATH    0x0002
#define KR_CLIENT_MCAST_PATH    0x0004
#define KR_CLIENT_WITHOUT_EDGE  0x0008

/* Three special predefined groups for kernel routing */
#define KR_MCAST_GROUP          227
#define KR_ACAST_GROUP          247
#define KR_ACAST_GW_GROUP       (IPINT(240,220,11,1))

#define KR_TO_CLIENT_UCAST_IP(x)  ((10 << 24) | (x & 0xFFFFFF))

#define IPROUTE_EXECUTE(x)      if (iproute != NULL) { iproute(x); } \
                                else system(x);

#define Is_valid_kr_group(x)    ( ( KR_Flags & KR_OVERLAY_NODES &&       \
                                     (x) == KR_ACAST_GW_GROUP      ) ||  \
                                  ( KR_Flags & KR_CLIENT_ACAST_PATH &&   \
                                    IP1(x) == KR_ACAST_GROUP       ) ||  \
                                  ( KR_Flags & KR_CLIENT_MCAST_PATH &&   \
                                    IP1(x) == KR_MCAST_GROUP       ) )


/* Keep track of routes to optimize number of system calls */
typedef struct dummy_kr_entry {
    Spines_ID next_hop;  
    char *dev;   
} KR_Entry;

void  KR_Init();
void  KR_Set_Group_Route(int group_destination, void *dummy);
void  KR_Set_Table_Route(Spines_ID destination, int table_id);
void  KR_Delete_Table_Route(Spines_ID destination, int table_id);
void  KR_Create_Overlay_Node(Spines_ID address);
void  KR_Delete_Overlay_Node(Spines_ID address);
void  KR_Set_Default_Route();
void  KR_Delete_Default_Route();
void  KR_Update_All_Routes();
char* KR_Get_Command_Output(char *cmd);
int   KR_Register_Route(Spines_ID destination, int table_id, Node *nd, stdhash *neighbors, int member);
void  KR_Print_Routes(FILE *fp);

#endif
