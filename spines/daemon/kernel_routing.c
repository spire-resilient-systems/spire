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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <dlfcn.h>

#include "arch.h"
#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_memory.h"
#include "stdutil/stdhash.h"
#include "stdutil/stddll.h"

#include "objects.h"
#include "link.h"
#include "node.h"
#include "route.h"
#include "state_flood.h"
#include "link_state.h"
#include "multicast.h"
#include "kernel_routing.h"


/* Global Variables */
extern Spines_ID My_Address;
extern int16       Port;
extern stdhash     All_Nodes;
extern stdhash     All_Groups_by_Name;
extern stdhash     All_Groups_by_Node;
extern int16       KR_Flags;
extern Spines_ID Discovery_Address[MAX_DISCOVERY_ADDR];
extern int16      Num_Discovery_Addresses;

/* Local Variables */
char    *KR_Client_Device_Name;
char    *CMD_iptables;
char    *CMD_ip;
char    *CMD_sed;
char    *CMD_grep;
char    cmd[1024];
int32   KR_Original_Default_GW;
int     KR_route_time;
int     KR_group_time;
int     (*iproute) (char*);


/* KR_Table is the main kernel routing table. 
   It is a hash based on a destination ip, with a pointer
   to another hash of table_id. Each table_id has another
   pointer to a link list with the list of next_hop addresses */
stdhash KR_Table;

void KR_Init() 
{
    int32 client_net;
    int ret, i1, i2, i3, i4;
    char *temp;
    void *handle;

    if (KR_Flags == 0) {
        return;
    }

    KR_Client_Device_Name = NULL;
    KR_Original_Default_GW = 0;
    KR_route_time = 0;

    /* Get the full path of ip, iptables, grep, and sed commands */
    sprintf(cmd, "which ip");
    CMD_ip = KR_Get_Command_Output(cmd);
    sprintf(cmd, "which iptables");
    CMD_iptables = KR_Get_Command_Output(cmd);
    sprintf(cmd, "which sed");
    CMD_sed = KR_Get_Command_Output(cmd);
    sprintf(cmd, "which grep");
    CMD_grep = KR_Get_Command_Output(cmd);

    if (CMD_ip == NULL || CMD_iptables == NULL || CMD_grep == NULL || CMD_sed == NULL) {
        Alarm(EXIT, "KR_Init(): cannot resolve path for ip, sed, grep or iptables\n");
    }

    /* Get current default gateway */
    sprintf(cmd, "%s route get 128.220.2.80 | %s via | %s -e 's/.* via \\([^ ]*\\).*/\\1/'", CMD_ip, CMD_grep, CMD_sed);
    temp = KR_Get_Command_Output(cmd);
    if (temp != NULL) {
        ret = sscanf(temp, "%d.%d.%d.%d", &i1, &i2, &i3, &i4);
        if (ret == 4) {
            KR_Original_Default_GW = ( (i1 << 24 ) | (i2 << 16) | (i3 << 8) | i4 );
        } else {
            Alarm(EXIT, "KR_Init(): failed to get default route IP");
        }
    }

    /* KR_Table is used to store all nexthop for a destination, and to be able to 
       compare new routes to old ones, so that we only change routes when necessary */
    stdhash_construct(&KR_Table, sizeof(Spines_ID), sizeof(stdhash*),
                                       NULL, NULL, 0);

    /* Try to load iproute library for fast kernel-route table changes */
    iproute = NULL;
    handle = dlopen("./iproute.so", RTLD_NOW);
    if (!handle) {
        handle = dlopen("/lib/iproute.so", RTLD_NOW);
    }
    if (!handle) {
        Alarm(PRINT, "Unable to load iproute dynamic library. Using system() to change route tables instead\n");
    } else {
        iproute = dlsym(handle, "iproute");
        if (iproute == NULL) {
            Alarm(PRINT, "Unable to get iproute symbol. Using system() to change route tables instead\n\t%s", dlerror());
            dlclose(handle);
        }
    }

    /* Get the default route device name for routing packets to clients */
    client_net = KR_TO_CLIENT_UCAST_IP(0);
    sprintf(cmd, "%s route get "IPF" | %s dev | %s -e 's/.* dev \\([^ ]*\\).*/\\1/'", CMD_ip, IP(client_net), CMD_grep, CMD_sed);
    KR_Client_Device_Name = KR_Get_Command_Output(cmd);
    if (KR_Client_Device_Name == NULL) {
        Alarm(EXIT, "KR: device name for "IPF" is empty!\n", IP(client_net));
    }

    /* If setting routes between overlay nodes, we need two different route tables, 
       one for overlay routing (we decide next hop), one for native routing */
    if (KR_Flags & KR_OVERLAY_NODES) {
        ret = 0;
        sprintf(cmd, "%s -D OUTPUT -t mangle -p udp -m multiport --dports %d,%d,%d,%d -j MARK --set-mark 250",
                     CMD_iptables, Port, Port+1, Port+2, Port+3); 
        system(cmd);
        sprintf(cmd, "%s -A OUTPUT -t mangle -p udp -m multiport --dports %d,%d,%d,%d -j MARK --set-mark 250",
                     CMD_iptables, Port, Port+1, Port+2, Port+3); 
        ret += system(cmd);

        sprintf(cmd, "%s route flush table 250", CMD_ip); 
        ret += system(cmd);

        sprintf(cmd, "%s rule del fwmark 250 table 250", CMD_ip);
        system(cmd);
        sprintf(cmd, "%s rule add fwmark 250 table 250", CMD_ip);
        ret += system(cmd);

        sprintf(cmd, "%s route replace default table 250 dev %s", 
                CMD_ip, KR_Client_Device_Name);
        ret += system(cmd);
        sprintf(cmd, "%s route replace "IPF"/8 table 250 dev %s", 
                CMD_ip, IP(My_Address&0xFF000000), KR_Client_Device_Name);
        ret += system(cmd);
        sprintf(cmd, "%s route replace 192.0.0.0/29 table 250 dev %s", 
                CMD_ip, KR_Client_Device_Name);
        ret += system(cmd);
        if (ret != 0) {
            Alarm(EXIT, "KR_Init(): Error setting system parameters\n");
        }
    }
}


/* 
 * Figure out the routing mcast tree for a anycast/multicast group,  
 * and update routing table if different than previous entry 
 */
void KR_Set_Group_Route(int group_destination, void *dummy)
{
    Node *nd;
    stdhash *neighbors;
    stdit nd_it;
    Group_State *g_state;
    int member, route_changed;
    Spines_ID client_ip;
    sp_time start, stop;

    start = E_get_time();
    member = 0;
    neighbors = NULL;
    nd = NULL;

    /* Verfy that it is a valid group */
    if (!Is_valid_kr_group(group_destination)) {
        Alarm(PRINT, "KR_Set_Route: Trying to set kernel route on non-kernel group"); 
        return;
    } 

    //Alarm(PRINT, "Setting "IPF" kernel route\n", IP(group_destination));
    route_changed = 0;

    /* I am a member, make note to directly route to dest */
    if (!(KR_Flags & KR_CLIENT_WITHOUT_EDGE)) {
        if((g_state = (Group_State*)Find_State(&All_Groups_by_Node, My_Address, group_destination)) != NULL) 
        {
            if((g_state->status & ACTIVE_GROUP)) {
                member = 1;
            }
        }
    }

    /* Get all next hops, and set kernel rules */
    if (Is_acast_addr(group_destination)) {
        /* Check if I am a member. If not, look for anycast neighbor */
        neighbors = Get_Mcast_Neighbors(My_Address, group_destination);
        /* See if setting default gateway or anycast client */
        if (group_destination == KR_ACAST_GW_GROUP) {
            route_changed = KR_Register_Route(0, 0, NULL, neighbors, member);
            if (route_changed) {
                KR_Set_Table_Route(0, 0);
            }
        } else if (IP1(group_destination) == KR_ACAST_GROUP) {
            client_ip = KR_TO_CLIENT_UCAST_IP(group_destination);
            route_changed = KR_Register_Route(client_ip, 0, NULL, neighbors, member);
            if (route_changed) {
                KR_Set_Table_Route(client_ip, 0);
            }
        } 
    } else if (Is_mcast_addr(group_destination)) {
        /* If multicast group, get from every source in Overlay */ 
        stdhash_begin(&All_Nodes, &nd_it);
        if (IP1(group_destination) == KR_MCAST_GROUP) {
            while(!stdhash_is_end(&All_Nodes, &nd_it)) {
                /* TODO: What if node is not up ...use Find_Route? */ 
                nd = *((Node **)stdhash_it_val(&nd_it)); 
                neighbors = Get_Mcast_Neighbors(nd->nid, group_destination);
                client_ip = KR_TO_CLIENT_UCAST_IP(group_destination);
                route_changed = KR_Register_Route(client_ip, IP4(nd->nid), 
                                                  NULL, neighbors, member);
                if (route_changed) {
                    KR_Set_Table_Route(client_ip, IP4(nd->nid));
                }
                stdhash_it_next(&nd_it);
            }
        }
    }

    /* Flush Cache */
    if (route_changed) {
        sprintf(cmd, "%s route flush cache", CMD_ip);
        IPROUTE_EXECUTE(cmd);

        stop = E_get_time();
        KR_group_time = (stop.sec - start.sec)*1000000;
        KR_group_time += stop.usec - start.usec;
    }

}

/* 
 * Add route table changes to KR_Table.  
 * Returns true if the route entries changed for this destination/tableid 
 */
int KR_Register_Route(Spines_ID destination, int table_id, Node *nd, stdhash *neighbors, int member)  
{
    Node *next_hop;
    int32 update;
    stdhash *krtid_hash;
    stddll *old_routes, *new_routes, **old_routes_pp;
    stdit krt_it, krtid_it, ngb_it, new_routes_it, old_routes_it;
    KR_Entry kre, *new_kre, *old_kre;

    /* 
     * Construct route entries
     */

    if ((new_routes = (stddll*) new(STDHASH_OBJ)) == NULL) {
        Alarm(EXIT, "KR_Register_Route(): cannot allocate memory\n");
    }
    stddll_construct(new_routes, sizeof(KR_Entry));

    if (member == 1) {
        if (destination == 0) {
            kre.next_hop = KR_Original_Default_GW;
            kre.dev = NULL;
        } else {
            kre.next_hop = destination;
            kre.dev = KR_Client_Device_Name;
        }
        stddll_push_front(new_routes, &kre);
    }

    /* Register neighbors for multicast groups */
    if (neighbors != NULL) {
        stdhash_begin(neighbors, &ngb_it);
        while(!stdhash_is_end(neighbors, &ngb_it)) {
            next_hop = *((Node **)stdhash_it_val(&ngb_it));
            kre.next_hop = next_hop->nid;
            kre.dev = next_hop->device_name;
            stddll_push_back(new_routes, &kre);
            stdhash_it_next(&ngb_it);
        }
    }

    if (nd != NULL) {
        kre.next_hop = nd->nid;
        kre.dev = nd->device_name;
        stddll_push_back(new_routes, &kre);
    }


    /* 
     * Compare to previous route entries
     * Can optimize later and do this while adding stuff
     */

    update = 0;
    old_routes = NULL;
    old_routes_pp = NULL;
    stdhash_find(&KR_Table, &krt_it, &destination);
    if (stdhash_is_end(&KR_Table, &krt_it)) {
        update = 1;
        /* First we need a hash of table_id to route entries */
        if ((krtid_hash = (stdhash*) new(STDHASH_OBJ)) == NULL) {
            Alarm(EXIT, "KR_Register_Route(): cannot allocate memory\n");
        }
        stdhash_construct(krtid_hash, sizeof(Spines_ID), sizeof(stddll*),
                                       NULL, NULL, 0);
        stdhash_insert(&KR_Table, &krt_it, &destination, &krtid_hash);
    } else {
        krtid_hash = *((stdhash**)stdhash_it_val(&krt_it));
        stdhash_find(krtid_hash, &krtid_it, &table_id);
        if (stdhash_is_end(krtid_hash, &krtid_it)) {
            update = 1;
        } else {
            old_routes_pp = (stddll**)stdhash_it_val(&krtid_it);
            old_routes = *((stddll**)stdhash_it_val(&krtid_it));
            if (stddll_size(new_routes) != stddll_size(old_routes)) {
                update = 1;
            } else {
                stddll_begin(old_routes, &old_routes_it);
                while (!stddll_is_end(old_routes, &old_routes_it)) { 
                    old_kre = (KR_Entry *)stddll_it_val(&old_routes_it);
                    /* Find new route that matches IP and device name */
                    stddll_begin(new_routes, &new_routes_it);
                    while(!stddll_is_end(new_routes, &new_routes_it)) {
                        new_kre = (KR_Entry *)stddll_it_val(&new_routes_it);
                        if(old_kre->next_hop == new_kre->next_hop) {
                            /* If device is different, update */
                            if ( (old_kre->dev != NULL && new_kre->dev == NULL) ||
                                 (old_kre->dev == NULL && new_kre->dev != NULL) ||
                                 (old_kre->dev != NULL && new_kre->dev != NULL &&
                                  strcmp(old_kre->dev, new_kre->dev) != 0) )  
                            {
                                update = 1;
                            }
                            break;
                        }
                        stddll_it_next(&new_routes_it);
                    }
                    /* If no entry matched, update */
                    if (stddll_is_end(new_routes, &new_routes_it)) {
                        update = 1;
                    } 
                    stddll_it_next(&old_routes_it);
                }
            }
        }
    }

    if (update == 1) {
        /* Do I need to create routes dll */
        if (old_routes_pp == NULL) {
            stdhash_insert(krtid_hash, &krtid_it, &table_id, &new_routes);
        } else {
            stddll_destruct(old_routes);
            dispose(old_routes);
            *old_routes_pp = new_routes;
        }
    } else {
        stddll_destruct(new_routes);
        dispose(new_routes);
    }
    return (update);
}


/* 
 * Make changes in the kernel, based on global KR_Table entry
 */
void KR_Set_Table_Route(Spines_ID destination, int table_id) 
{
    stdit krt_it, krtid_it, kr_routes_it;
    stdhash *krtid_hash;
    stddll *kr_routes;
    KR_Entry *kre;
    
    /* Get Record 
     * If no next hop, delete route to this client */
    kr_routes = NULL;
    stdhash_find(&KR_Table, &krt_it, &destination);
    if (stdhash_is_end(&KR_Table, &krt_it)) {
        Alarm(EXIT, "KR_Set_Table_Route: Registration Missing (1)\n");
    } else {
        krtid_hash = *((stdhash**)stdhash_it_val(&krt_it));
        stdhash_find(krtid_hash, &krtid_it, &table_id);
        if (stdhash_is_end(krtid_hash, &krtid_it)) {
            Alarm(EXIT, "KR_Set_Table_Route: Registration Missing (2)\n");
        }
        kr_routes = *((stddll**)stdhash_it_val(&krtid_it));
        if (stddll_empty(kr_routes)) {
            KR_Delete_Table_Route(destination, table_id);
            /* TODO: Cannot dispose destination unless no other table has an entry */
            return;
        }
    }

    /* If changing default route */
    if (destination == 0) {
        sprintf(cmd, "%s route replace default ", CMD_ip);
    } else {
        sprintf(cmd, "%s route replace "IPF"/32 ", CMD_ip, IP(destination));
        if (table_id > 0 && table_id < 255) {
            sprintf(cmd+strlen(cmd), " table %d ", table_id);
        }
    }

    stddll_begin(kr_routes, &kr_routes_it);
    while (!stddll_is_end(kr_routes, &kr_routes_it)) { 
        kre = (KR_Entry *)stddll_it_val(&kr_routes_it);
        sprintf(cmd+strlen(cmd), " nexthop via "IPF" ",
                    IP(kre->next_hop));
        if (kre->dev != NULL && strlen(kre->dev) > 0) {
            sprintf(cmd+strlen(cmd), " dev %s ", kre->dev);
        }
        stddll_it_next(&kr_routes_it);
    }

    IPROUTE_EXECUTE(cmd);
}

/* Delete entry for specified destination */
void KR_Delete_Table_Route(Spines_ID destination, int table_id) 
{
    if (destination == 0) {
        if (KR_Original_Default_GW != 0) {
            sprintf(cmd, "%s route replace default nexthop via "IPF" ", CMD_ip, IP(KR_Original_Default_GW));
        } else {
            sprintf(cmd, "%s route delete default ", CMD_ip);
        }
    } else {
        sprintf(cmd, "%s route delete "IPF" ", CMD_ip, IP(destination));
    }

    if (table_id > 0 && table_id < 255) {
        sprintf(cmd+strlen(cmd), " table %d", table_id);
    }

    IPROUTE_EXECUTE(cmd);
}

void KR_Create_Overlay_Node(Spines_ID address) 
{
    if (KR_Flags & KR_CLIENT_MCAST_PATH) {
        sprintf(cmd, "%s -D PREROUTING -t mangle -m u32 --u32 \"2&0xFFFF=%d\" -j MARK --set-mark %d",
                     CMD_iptables, IP4(address), IP4(address)); 
        system(cmd);
        sprintf(cmd, "%s -A PREROUTING -t mangle -m u32 --u32 \"2&0xFFFF=%d\" -j MARK --set-mark %d",
                     CMD_iptables, IP4(address), IP4(address)); 
        system(cmd);
        sprintf(cmd, "%s -D OUTPUT -t mangle -m u32 --u32 \"2&0xFFFF=%d\" -j MARK --set-mark %d",
                     CMD_iptables, IP4(address), IP4(address)); 
        system(cmd);
        sprintf(cmd, "%s -A OUTPUT -t mangle -m u32 --u32 \"2&0xFFFF=%d\" -j MARK --set-mark %d",
                     CMD_iptables, IP4(address), IP4(address)); 
        system(cmd);

        sprintf(cmd, "%s route flush table %d", CMD_ip, IP4(address)); 
        system(cmd);

        sprintf(cmd, "%s rule del fwmark %d table %d",
                     CMD_ip, IP4(address), IP4(address)); 
        system(cmd);
        sprintf(cmd, "%s rule add fwmark %d table %d",
                     CMD_ip, IP4(address), IP4(address)); 
        system(cmd);
    }
}

void KR_Delete_Overlay_Node(Spines_ID address) 
{
    /* TODO: Delete from KR_Table */
    sprintf(cmd, "%s route delete "IPF" ", CMD_ip, IP(address));
    system(cmd);
    if (KR_Flags & KR_CLIENT_MCAST_PATH) {
        sprintf(cmd, "%s route flush table %d", CMD_ip, IP4(address));
        system(cmd);
        sprintf(cmd, "%s -D PREROUTING -t mangle -m u32 --u32 \"2&0xFFFF=%d\" -j MARK --set-mark %d",
                CMD_iptables, IP4(address), IP4(address)); 
        system(cmd);
        sprintf(cmd, "%s rule del fwmark %d table %d",
                     CMD_ip, IP4(address), IP4(address)); 
        system(cmd);
    }
}

/*
 * After a topology change, need to compute and compare all new routes
 * and make appropiate changes to the routing table 
 */
void KR_Update_All_Routes() 
{
    Node *nd;
    Route *route;
    stdit grp_it, nd_it;
    State_Chain *s_chain_grp;
    char *output;
    int route_changed;
    sp_time start, stop;

    start = E_get_time();

    /* Set main routes to overlay nodes */
    stdhash_begin(&All_Nodes, &nd_it);
    while(!stdhash_is_end(&All_Nodes, &nd_it)) {
        nd = *((Node **)stdhash_it_val(&nd_it));
        if(nd->nid != My_Address) {
            route = Find_Route(My_Address, nd->nid);
            if(route != NULL && route->forwarder != NULL) {
                /* Get device name for next hop if necessary */
                if (route->forwarder->device_name == NULL && (KR_Flags & KR_CLIENT_MCAST_PATH)) {
                    sprintf(cmd, "%s route get "IPF" | %s dev | %s -e 's/.* dev \\([^ ]*\\).*/\\1/'", CMD_ip, IP(nd->nid), CMD_grep, CMD_sed);
                    output = KR_Get_Command_Output(cmd);
                    if (output == NULL) {
                        Alarm(PRINT, "KR: Cannot get device name\n\t%s -- NULL", cmd);
                    }
                    nd->device_name = output;
                }
                /* Now make route changes */
                if (KR_Flags & KR_OVERLAY_NODES) {
                    route_changed = KR_Register_Route(nd->nid, 0, route->forwarder, NULL, 0);
                    if (route_changed) {
                        KR_Set_Table_Route(nd->nid, 0);
                    }
                }
            }
            else {
                if (KR_Flags & KR_OVERLAY_NODES) {
                    route_changed = KR_Register_Route(nd->nid, 0, NULL, NULL, 0);
                    if (route_changed) {
                        KR_Set_Table_Route(nd->nid, 0);
                        if (KR_Flags & KR_CLIENT_MCAST_PATH) {
                            sprintf(cmd, "%s route flush table %d", CMD_ip, IP4(nd->nid));
                            IPROUTE_EXECUTE(cmd);
                        }
                    }
                }
            }
        }
        stdhash_it_next(&nd_it);
    }

    /* Now search through every group and update routes
       for groups that map to a kernel route */
    stdhash_begin(&All_Groups_by_Name, &grp_it);
    while(!stdhash_is_end(&All_Groups_by_Name, &grp_it)) {
        s_chain_grp = *((State_Chain **)stdhash_it_val(&grp_it));
        if (Is_valid_kr_group(s_chain_grp->address)) {
            KR_Set_Group_Route(s_chain_grp->address, NULL);
        }
        stdhash_it_next(&grp_it);
    }

    /* Flush Cache */
    sprintf(cmd, "%s route flush cache", CMD_ip);
    IPROUTE_EXECUTE(cmd);

    stop = E_get_time();
    KR_route_time = (stop.sec - start.sec)*1000000;
    KR_route_time += stop.usec - start.usec;
}

/* unused/untested garbage collector; needs work/testing; */
void KR_Garbage_Collect()
{
    stdit krt_it, krtid_it;
    stdhash *krtid_hash;
    stddll *kr_routes;
    int found_entry;
    
    kr_routes = NULL;
    stdhash_begin(&KR_Table, &krt_it);
    while(!stdhash_is_end(&KR_Table, &krt_it)) {
        krtid_hash = *((stdhash**)stdhash_it_val(&krt_it));
        found_entry = 0;
        stdhash_begin(krtid_hash, &krtid_it);
        while(!stdhash_is_end(krtid_hash, &krtid_it)) {
            kr_routes = *((stddll**)stdhash_it_val(&krtid_it));
            if (!stddll_empty(kr_routes)) {
                found_entry = 1;
                break;
            }
            stdhash_it_next(&krtid_it);
        }
        if (found_entry == 0) {
            stdhash_begin(krtid_hash, &krtid_it);
            while(!stdhash_is_end(krtid_hash, &krtid_it)) {
                stddll_destruct(kr_routes);
                dispose(kr_routes);
                stdhash_it_next(&krtid_it);
            }
            stdhash_destruct(krtid_hash);
            dispose(krtid_hash);
            stdhash_erase(&KR_Table, &krt_it); 
        }
        stdhash_it_next(&krt_it);
    }
}


/* Run a command in the shell, and get output from command back */
char* KR_Get_Command_Output(char *temp_cmd) 
{
    FILE *f;
    int n, ret;
    char buf[40], *cp;

    if (!(f = popen(temp_cmd, "r"))) {
        Alarm(EXIT, "popen error");
    }
    n = fread(buf, 1, 40, f);
    if (n <= 1) {
        return NULL;
    }
    buf[n - 1] = '\0';
    Alarm(PRINT, "KR_Command: %s \n\t--> %s\n", temp_cmd, buf);
    if (n > 38) {
        Alarm(EXIT, "KR_Get_Command_Output: result from [%s] exceeds limit \n", temp_cmd);
    }
    ret = pclose(f);
    if (ret != 0) {
        return NULL;
    }
    cp = malloc(n);
    strcpy(cp, buf);
    return(cp);
}

/* Print all of the routes in the KR_Table */
void KR_Print_Routes(FILE *fp) 
{
    KR_Entry *kre;
    stdhash *krtid_hash;
    stddll *kr_routes;
    stdit krt_it, krtid_it, kr_routes_it;
    Spines_ID ip_addr, table_id;

    sprintf(cmd, "\n\n--- KERNEL ROUTE TABLE --- ROUTE TIME [%d] [%d],\n\n", KR_route_time, KR_group_time);
    Alarm(PRINT, "%s", cmd);
    if (fp != NULL) fprintf(fp, "%s", cmd);

    stdhash_begin(&KR_Table, &krt_it);
    while(!stdhash_is_end(&KR_Table, &krt_it)) {
        ip_addr = *(Spines_ID *)stdhash_it_key(&krt_it);
        krtid_hash = *((stdhash**)stdhash_it_val(&krt_it));
        sprintf(cmd, " "IPF"\n", IP(ip_addr));
        Alarm(PRINT, "%s", cmd);
        if (fp != NULL) fprintf(fp, "%s", cmd);
        stdhash_begin(krtid_hash, &krtid_it);
        while(!stdhash_is_end(krtid_hash, &krtid_it)) {
            table_id = *(Spines_ID *)stdhash_it_key(&krtid_it);
            kr_routes = *((stddll**)stdhash_it_val(&krtid_it));
            stddll_begin(kr_routes, &kr_routes_it);
            if (stddll_is_end(kr_routes, &kr_routes_it)) {
                stdhash_it_next(&krtid_it);
                continue;
            }
            sprintf(cmd, "       Table %d: ", table_id);
            while(!stddll_is_end(kr_routes, &kr_routes_it)) {
                kre = (KR_Entry *)stddll_it_val(&kr_routes_it);
                sprintf(cmd+strlen(cmd), "  "IPF" ", IP(kre->next_hop));
                if (kre->dev != NULL && strlen(kre->dev) > 0) {
                    sprintf(cmd+strlen(cmd), "[%s] ", kre->dev);
                }
                stddll_it_next(&kr_routes_it);
            }
            Alarm(PRINT, "%s\n", cmd);
            if (fp != NULL) fprintf(fp, "%s\n", cmd);
            stdhash_it_next(&krtid_it);
        }
        stdhash_it_next(&krt_it);
    }
    Alarm(PRINT, "\n\n---------------------------\n\n");
}


