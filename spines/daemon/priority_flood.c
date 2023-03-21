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

#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#ifdef ARCH_PC_WIN95
#include <winsock2.h>
#endif

#define ext_prio_flood
#include "priority_flood.h"
#undef  ext_prio_flood

/* For printing 64 bit numbers */
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

extern int32u   My_Address;
extern stdhash  All_Nodes;
extern stdhash  All_Groups_by_Node;
extern Link*    Links[MAX_LINKS];

/* Configuration File Variables */
extern stdhash     Node_Lookup_Addr_to_ID;
extern int16u      My_ID;
extern int32u      *Neighbor_Addrs[];
extern int16u      *Neighbor_IDs[];
extern int64u      Injected_Messages;

static const sp_time prio_print_stat_timeout = {15, 0};

/* For debugging */
/* int num_unique;
int total_sent[10];
int sent[10][MAX_NODES + 1]; */

typedef struct prio_stats_d {
    int32u num_msgs;
    int32u num_highprio;
    int64u latency_msgs;
    int64u latency_highprio;
    int32u worst_latency;
    int32u worst_latency_highprio;
    int64u bytes;
} prio_stats;

prio_stats Prio_Stats[MAX_NODES+1];
sp_time elapsed_for_stats;
int64u total_dropped;

void Priority_Garbage_Collect (int dummy1, void *dummy2);
void Cleanup_prio_flood_ds(int ngbr_index, int src_id, 
                            Prio_Flood_Value *fbv_ptr, int ngbr_flag);
void Priority_Print_Statistics (int dummy1, void* dummy2);


void Flip_prio_flood_hdr( prio_flood_header *f_hdr )
{
    f_hdr->incarnation  = Flip_int64( f_hdr->incarnation );
    f_hdr->seq_num      = Flip_int64( f_hdr->seq_num );
    f_hdr->priority     = Flip_int32( f_hdr->priority );
    f_hdr->origin_sec   = Flip_int32( f_hdr->origin_sec );
    f_hdr->origin_usec  = Flip_int32( f_hdr->origin_usec );
    f_hdr->expire_sec   = Flip_int32( f_hdr->expire_sec );
    f_hdr->expire_usec  = Flip_int32( f_hdr->expire_usec );
}

void Copy_prio_flood_header( prio_flood_header *from_flood_hdr,
                        prio_flood_header *to_flood_hdr )
{
    to_flood_hdr->incarnation   = from_flood_hdr->incarnation;
    to_flood_hdr->seq_num       = from_flood_hdr->seq_num;
    to_flood_hdr->priority      = from_flood_hdr->priority;
    to_flood_hdr->origin_sec    = from_flood_hdr->origin_sec;
    to_flood_hdr->origin_usec   = from_flood_hdr->origin_usec;
    to_flood_hdr->expire_sec    = from_flood_hdr->expire_sec;
    to_flood_hdr->expire_usec   = from_flood_hdr->expire_usec;
}

/***********************************************************/
/* void Prio_Pre_Conf_Setup()                              */
/*                                                         */
/* Setup configuration file defaults for Priorty Flooding  */
/*                                                         */
/* Return: NONE                                            */
/*                                                         */
/***********************************************************/
void Prio_Pre_Conf_Setup() 
{
    Conf_Prio.Crypto                    = PRIO_CRYPTO;
    Conf_Prio.Default_Priority          = PRIO_DEFAULT_PLVL;
    Conf_Prio.dummy1                    = 0;
    Conf_Prio.dummy2                    = 0;
    Conf_Prio.Max_Mess_Stored           = MAX_MESS_STORED;
    Conf_Prio.Min_Belly_Size            = MIN_BELLY_SIZE;
    Conf_Prio.Default_Expire_Sec        = PRIO_DEFAULT_EXPIRE_SEC;
    Conf_Prio.Default_Expire_USec       = PRIO_DEFAULT_EXPIRE_USEC;
    Conf_Prio.Garbage_Collection_Sec    = GARB_COLL_TO;

}

/***********************************************************/
/* void Prio_Post_Conf_Setup()                             */
/*                                                         */
/* Sets up timers and data structures after reading from   */
/* the configuration file for Priority Flooding            */
/*                                                         */
/* Return: NONE                                            */
/*                                                         */
/***********************************************************/
void Prio_Post_Conf_Setup() 
{
    prio_garb_coll_timeout.sec = Conf_Prio.Garbage_Collection_Sec;
    prio_garb_coll_timeout.usec = 0;
}

/***********************************************************/
/* int Prio_Conf_hton(unsigned char *buff)                 */
/*                                                         */
/* Converts host storage of configuration parameters into  */
/* network format and writes to buff.                      */
/*                                                         */
/* Return: # of bytes written                              */
/*                                                         */
/***********************************************************/
int Prio_Conf_hton(unsigned char *buff)
{
    unsigned char *write = (unsigned char*)buff;

    *(unsigned char*)write = Conf_Prio.Crypto;
        write += sizeof(unsigned char);
    *(unsigned char*)write = Conf_Prio.Default_Priority;
        write += sizeof(unsigned char);
    *(unsigned char*)write = Conf_Prio.dummy1;
        write += sizeof(unsigned char);
    *(unsigned char*)write = Conf_Prio.dummy2;
        write += sizeof(unsigned char);
    *(int32u*)write = htonl(Conf_Prio.Max_Mess_Stored);
        write += sizeof(int32u);
    *(int32u*)write = htonl(Conf_Prio.Min_Belly_Size);
        write += sizeof(int32u);
    *(int32u*)write = htonl(Conf_Prio.Default_Expire_Sec);
        write += sizeof(int32u);
    *(int32u*)write = htonl(Conf_Prio.Default_Expire_USec);
        write += sizeof(int32u);
    *(int32u*)write = htonl(Conf_Prio.Garbage_Collection_Sec);
        write += sizeof(int32u);
    
    return sizeof(CONF_PRIO);
}

void Init_Priority_Flooding()
{
    int32u h, i, j;
    sp_time now = E_get_time();
    
    /* load in the configuration file taken from Prime code and 
     * set the default vaules for configurable variables */
    Seq_No = 1;

    Belly = (stdhash *) Mem_alloc(sizeof(stdhash) * (MAX_NODES + 1));
    Node_Incarnation = (int64u *) Mem_alloc(sizeof(int64u) * (MAX_NODES + 1));
    for (i = 1; i <= MAX_NODES; i++) {
        stdhash_construct(&Belly[i], sizeof(Prio_Flood_Key),
            sizeof(Prio_Flood_Value), NULL, NULL, STDHASH_OPTS_NO_AUTO_SHRINK );
        stdhash_reserve(&Belly[i], Conf_Prio.Min_Belly_Size);
        if (i == My_ID)
            Node_Incarnation[i] = now.sec;
        else
            Node_Incarnation[i] = 0;
    }

    Edge_Data = (Prio_Link_Data *)
        Mem_alloc(sizeof(Prio_Link_Data) * (Degree[My_ID] + 1));

    for (h = 0; h <= Degree[My_ID]; h++) {
        
        for (i = 0; i <= MAX_NODES; i++) {
            Edge_Data[h].msg_count[i] = 0;
            Edge_Data[h].in_send_queue[i] = 0;
            Edge_Data[h].max_pq[i] = 0;
            Edge_Data[h].min_pq[i] = MAX_PRIORITY + 1;

            for (j = 0; j <= MAX_PRIORITY; j++) {
                Edge_Data[h].pq[i].head[j].next = NULL;
                Edge_Data[h].pq[i].head[j].entry = NULL;
                Edge_Data[h].pq[i].tail[j] =
                    &Edge_Data[h].pq[i].head[j];
            }
        }

        Edge_Data[h].total_msg = 0;

        Edge_Data[h].norm_head.next = NULL;
        Edge_Data[h].norm_head.src_id = -1;
        Edge_Data[h].norm_tail = &Edge_Data[h].norm_head;

        Edge_Data[h].urgent_head.next = NULL;
        Edge_Data[h].urgent_head.src_id = -1;
        Edge_Data[h].urgent_tail = &Edge_Data[h].urgent_head;
        
        Edge_Data[h].sent_messages = 0;
    }

    Bytes_Since_Checkpoint = 0;
    Time_Since_Checkpoint = now;
    E_queue( Priority_Garbage_Collect, 0, NULL, prio_garb_coll_timeout);
    /* E_queue( Suicide_Control, 0, NULL, prio_suicide_timeout); */
    Alarm(DEBUG, "Created Flood Best Effort Data Structures\n");

    /* num_unique = 0;
    for(i = 0; i <= Degree[My_ID]; i++) {
        total_sent[i] = 0;
        for (j = 0; j <= MAX_NODES; j++)
            sent[i][j] = 0;
    } */
    for (i = 0; i <= MAX_NODES; i++) {
        Prio_Stats[i].num_msgs = 0;
        Prio_Stats[i].num_highprio = 0;
        Prio_Stats[i].latency_msgs = 0;
        Prio_Stats[i].latency_highprio = 0;
        Prio_Stats[i].worst_latency = 0;
        Prio_Stats[i].worst_latency_highprio = 0;
        Prio_Stats[i].bytes = 0;
    }
    elapsed_for_stats = E_get_time();
    total_dropped = 0;
    /* E_queue( Priority_Print_Statistics, 0, NULL, prio_print_stat_timeout); */
}

int Fill_Packet_Header_Best_Effort_Flood( char* hdr )
{
    prio_flood_header *f_hdr = (prio_flood_header*)hdr;
    f_hdr->incarnation = Node_Incarnation[My_ID];
    f_hdr->seq_num = Seq_No++;
    return 1;
}


/***********************************************************/
/* int Priority_Flood_Disseminate (Link *src_link,         */
/*                          sys_scatter *scat, int mode)   */
/*                                                         */
/* Processes Priority Flood data                           */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* src_link:    link that this msg came in on              */
/* scat:        sys_scatter containing the message         */
/* mode:        mode of the link the packet arrived on     */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/
int Priority_Flood_Disseminate(Link *src_link, sys_scatter *scat, int mode)
{
    udp_header          *hdr;
    packet_header       *phdr;
    prio_flood_header   *f_hdr;
    int                 msg_size = 0, expected_size, ret = BUFF_OK, crypto_ret;
    int32u              i, src_id, ngbr_iter = 0, max_usage, hog_index;
    int16u              packets = 0;
    int32u              last_hop_ip, last_hop_index = 0, temp_microsecs;
    stdit               ip_it, msg_it, it;
    sp_time             now, temp_time;
    Prio_Flood_Value    fbv, *fbv_ptr;
    Prio_Link_Data      *pldata;
    Prio_PQ_Node        *temp_pq_node;
    Send_Fair_Queue     *temp_sfq;
    Node                *nd;
    unsigned int        sign_len;
    unsigned char       temp_ttl;
    EVP_MD_CTX          *md_ctx;
    unsigned char       *path = NULL, *routing_mask;
    unsigned char       temp_path[8];
    unsigned char       temp_path_index;
    Group_State         *gstate;

    /* ###################################################################### */
    /*                     (0) SANITY CHECKING / PACKET PROCESSING            */
    /* ###################################################################### */
    /* First, did this message came from a valid neighbor? */
    if (src_link == NULL) {
        last_hop_ip = My_Address;
    }
    else {
        last_hop_ip = src_link->leg->remote_interf->net_addr;
        stdhash_find(&Node_Lookup_Addr_to_ID, &ip_it, &last_hop_ip);
        if (stdhash_is_end(&Node_Lookup_Addr_to_ID, &ip_it)) {
            Alarm(DEBUG, "Priority_Flood_Disseminate: received msg on link \
                            that I don't have in my configuration file\r\n");
            return NO_ROUTE;
        }
        /* store the last_hop's index in the neighbor structure for later */
        for (i = 1; i <= Degree[My_ID]; i++) {
            if (Neighbor_Addrs[My_ID][i] == last_hop_ip) {
                last_hop_index = i;
                break;
            }
        }
        if (last_hop_index == 0) /* quick sanity check for valid neighbor */
            return NO_ROUTE;
    }
 
    /* TODO: Before, we did some endianess checking here, but now that might
     * not be possible without putting a type field in the prio_header as
     * well */
    now   = E_get_time();
    hdr   = (udp_header*)scat->elements[1].buf;

    for (i = 0; i < scat->num_elements; i++) 
        msg_size += scat->elements[i].len;

    expected_size = sizeof(packet_header) + sizeof(udp_header) + hdr->len + 
                sizeof(prio_flood_header) + MultiPath_Bitmask_Size + Prio_Signature_Len;

    /* Next, do some sanity checking on the length of the message */
    if (msg_size != expected_size) {
        if (Conf_Prio.Crypto == 0) 
            Alarm(PRINT, "Priority_Flood_Disseminate: \
                        invalid packet size --> %d + %d \
                        + %d + %d + %d != %d\r\n", sizeof(packet_header), 
                        hdr->len, sizeof(udp_header), sizeof(prio_flood_header),
                        MultiPath_Bitmask_Size, msg_size);
        else
            Alarm(PRINT, "Priority_Flood_Disseminate: \
                        invalid packet size --> %d + %d \
                        + %d + %d + %d + %d != %d\r\n", sizeof(packet_header),
                        hdr->len, sizeof(udp_header), sizeof(prio_flood_header),
                        MultiPath_Bitmask_Size, Prio_Signature_Len, msg_size);
        return NO_ROUTE;
    }

    /* Added to put the path on as the first 8 bytes of data */
    if (Path_Stamp_Debug == 1)
        path = ((unsigned char *) scat->elements[1].buf) + sizeof(udp_header) + 16;
        /* The 16 is to skip over the four 32-bit integers the client put on. */

    f_hdr = (prio_flood_header*)(scat->elements[scat->num_elements-1].buf);
    routing_mask = (unsigned char*)(f_hdr) + sizeof(prio_flood_header);

    /* Look for the source (originator) of the message in the lookup table */
    stdhash_find(&Node_Lookup_Addr_to_ID, &ip_it, &hdr->source);
    if (stdhash_is_end(&Node_Lookup_Addr_to_ID,  &ip_it)) {
        Alarm(DEBUG, "Process_flood_data_packet(): \
                      source not in config file");
        return NO_ROUTE;
    }
    src_id = *(int32u *)stdhash_it_val(&ip_it);
  
    if (Path_Stamp_Debug == 1) {
        for (i = 0; i < 8; i++) {
            temp_path[i] = path[i];
            path[i] = (unsigned char) 0;
        }
    }

    /* Verify the Signature */
    if (Conf_Prio.Crypto == 1) {
        /* The ttl value can change and may cause the signature to
         * not verify. We save the value, zero it out, verify the
         * signature, and then replace the ttl value.
         * Note: the ttl value is not protected!
         */
        temp_ttl = hdr->ttl;
        hdr->ttl = 0;

        sign_len = Prio_Signature_Len;
        if (scat->elements[scat->num_elements-1].len - sizeof(prio_flood_header) - MultiPath_Bitmask_Size < sign_len)
        {
            Alarm(PRINT, "Priority_Flood: sign_len is too small\r\n");
            ret = NO_ROUTE;
            goto cr_return;
        }

        md_ctx = EVP_MD_CTX_new();
        if (md_ctx==NULL){
            Alarm(EXIT, "Priority_Flood: EVP_MD_CTX_new() failed\r\n");
        }
        crypto_ret = EVP_VerifyInit(md_ctx, EVP_sha256()); 
        if (crypto_ret != 1) { 
            Alarm(PRINT, "Priority_Flood: VerifyInit failed\r\n");
            ret = NO_ROUTE;
            goto cleanup;
        }

        phdr = (packet_header*)scat->elements[0].buf;
        crypto_ret = EVP_VerifyUpdate(md_ctx, (unsigned char*)&phdr->type, sizeof(phdr->type));
        if (crypto_ret != 1) {
	    Alarm(PRINT, "Priority_Flood: VerifyUpdate failed\r\n");
            ret = NO_ROUTE;
            goto cleanup;
        }
        for (i = 1; i < scat->num_elements; i++) {
            if (i < scat->num_elements - 1)
                crypto_ret = EVP_VerifyUpdate(md_ctx, (unsigned char*)scat->elements[i].buf, 
                                (unsigned int)scat->elements[i].len);
            else
                crypto_ret = EVP_VerifyUpdate(md_ctx, (unsigned char*)scat->elements[i].buf, 
                                (unsigned int)scat->elements[i].len - sign_len);
                
            if (crypto_ret != 1) {
                Alarm(PRINT, "Priority_Flood: VerifyUpdate failed\r\n");
                ret = NO_ROUTE;
                goto cleanup;
            }
        }

        /* printf("DATA_LEN = %u, SIGN_LEN = %u, DATA - SIGN = %u, \
                src_id = %d\n",
                (unsigned int)data_len, sign_len,
                (unsigned int)(data_len - sign_len),
                src_id); */
        
        crypto_ret = EVP_VerifyFinal(md_ctx, 
                            (unsigned char*)(scat->elements[scat->num_elements-1].buf + 
                                scat->elements[scat->num_elements-1].len - sign_len), 
                            sign_len, Pub_Keys[src_id]);
        if (crypto_ret != 1) {
            Alarm(PRINT, "Priority_Flood: VerifyFinal failed\r\n");
            ret = NO_ROUTE;
            goto cleanup;
        }
        hdr->ttl = temp_ttl;

        cleanup:
            EVP_MD_CTX_free(md_ctx);
        cr_return:
            if (ret != BUFF_OK) return ret;
    }

    if (Path_Stamp_Debug == 1) {
        temp_path_index = 8;
        for (i = 0; i < 8; i++) {
            path[i] = temp_path[i];
            if (temp_path_index == 8 && path[i] == 0)
                temp_path_index = i;
        }
        if (temp_path_index != 8)
            path[temp_path_index] = (unsigned char) My_ID;
    }
 
    /* Check the high level incarnation, discard if invalid */
    if (f_hdr->incarnation < Node_Incarnation[src_id])
        return NO_ROUTE;
    else if (f_hdr->incarnation > Node_Incarnation[src_id])
        Node_Incarnation[src_id] = f_hdr->incarnation;

    /* Check for this message in the corresponding Belly's hash */
    /* Note: find is done by <incarnation, seq_num> as the key, using
     * trick where they are next to each other in the header */
    stdhash_find(&Belly[src_id], &msg_it, &f_hdr->incarnation);

    /* ###################################################################### */
    /*                    (1a) NEW MESSAGE                                    */
    /* ###################################################################### */
    if (stdhash_is_end(&Belly[src_id], &msg_it)) {
        fbv.arrival             = now;
        fbv.expire.sec          = f_hdr->expire_sec;
        fbv.expire.usec         = f_hdr->expire_usec;
        fbv.origin_time.sec     = f_hdr->origin_sec;
        fbv.origin_time.usec    = f_hdr->origin_usec;
        fbv.seq_num             = f_hdr->seq_num;
        fbv.priority            = f_hdr->priority;
        fbv.need_count          = Degree[My_ID];
        fbv.degree              = Degree[My_ID];

        /* check if the packet is already expired before inserting into hash */
        if (E_compare_time(fbv.expire, now) <= 0) {
            Alarm(PRINT, "Priority_Flood_Disseminate: Expired Message... Dropping\r\n");
            return NO_ROUTE;
        }
        if (fbv.priority == 0 || fbv.priority > MAX_PRIORITY) {
            Alarm(PRINT, "Priority_Flood_Disseminate: Invalid Priority: %d... Dropping\r\n", fbv.priority);
            return NO_ROUTE;
        }
        
        fbv.msg_scat = scat;
        inc_ref_cnt(fbv.msg_scat);
        for (i = 0; i < scat->num_elements; i++)
            inc_ref_cnt(fbv.msg_scat->elements[i].buf);
        fbv.msg_len = msg_size;
        fbv.link_mode = mode;
        
        fbv.ns = new(PRIO_FLOOD_NS_OBJ);
        if (fbv.ns == NULL) {
            Alarm(EXIT, "Priority_Flood_Disseminate(): could not allocate mem \
                         for NS\r\n");
        }
        
        /* Insert the message into this source's belly */
        stdhash_insert(&Belly[src_id], &msg_it, &f_hdr->incarnation, &fbv);

        /* stdhash makes a copy of FBV, so we need to get a pointer to that 
         * memory */
        stdhash_find(&Belly[src_id], &msg_it, &f_hdr->incarnation);
        fbv_ptr = ((Prio_Flood_Value *)stdhash_it_val(&msg_it));

        /* num_unique++;
        if (num_unique % 1000 == 0) 
            printf("~~~ Stats after %d unique packets ~~~\n", num_unique); */

        /* PRIORITY PRINT STATISTICS */
        if (hdr->dest == My_Address || 
             ((gstate = (Group_State*)Find_State(&All_Groups_by_Node, My_Address, hdr->dest)) != NULL
                && (gstate->status & ACTIVE_GROUP)))
        {
            Prio_Stats[src_id].num_msgs++;
            Prio_Stats[src_id].bytes += hdr->len;
            
            if (E_compare_time(now, fbv.origin_time) <= 0) {
                temp_microsecs = 0;
            }
            else{ 
                temp_time = E_sub_time(now, fbv.origin_time);
                temp_microsecs = temp_time.sec * 1000000 + temp_time.usec;
            }
            Prio_Stats[src_id].latency_msgs += temp_microsecs; 
            if (Prio_Stats[src_id].worst_latency == 0 || 
                Prio_Stats[src_id].worst_latency < temp_microsecs)
            {
                Prio_Stats[src_id].worst_latency = temp_microsecs;
            }

            if (fbv.priority == MAX_PRIORITY) {
                Prio_Stats[src_id].num_highprio++;
                Prio_Stats[src_id].latency_highprio += temp_microsecs;
                if (Prio_Stats[src_id].worst_latency_highprio == 0 || 
                    Prio_Stats[src_id].worst_latency_highprio < temp_microsecs)
                {
                    Prio_Stats[src_id].worst_latency_highprio = temp_microsecs;
                }
            }
        }
        
        for (ngbr_iter = 1; ngbr_iter <= Degree[My_ID]; ngbr_iter++) {
            
            pldata = (Prio_Link_Data*)&Edge_Data[ngbr_iter];

            /* Is this the neighbor that the message came from or is this
             * neighbor the source itself? */
            if (Neighbor_Addrs[My_ID][ngbr_iter] == last_hop_ip || 
                    Neighbor_Addrs[My_ID][ngbr_iter] == hdr->source) {
                fbv_ptr->ns[ngbr_iter].flag = RECV_MSG;
                fbv_ptr->ns[ngbr_iter].ngbr = NULL;
                fbv_ptr->need_count--;
                if (fbv_ptr->need_count == 0) {
                    dispose(fbv_ptr->ns);
                    fbv_ptr->ns = NULL;
                    Cleanup_Scatter(fbv_ptr->msg_scat);
                    fbv_ptr->msg_scat = NULL;
                    fbv_ptr->msg_len = 0;
                }
            }

            /* If this neighbor is not on the Bitmask, do not queue
             * the packet toward this neighbor */
            else if (!MultiPath_Neighbor_On_Path(routing_mask, ngbr_iter)) {
                fbv_ptr->ns[ngbr_iter].flag = NOT_IN_MASK;
                fbv_ptr->ns[ngbr_iter].ngbr = NULL;
                fbv_ptr->need_count--;
                if (fbv_ptr->need_count == 0) {
                    dispose(fbv_ptr->ns);
                    fbv_ptr->ns = NULL;
                    Cleanup_Scatter(fbv_ptr->msg_scat);
                    fbv_ptr->msg_scat = NULL;
                    fbv_ptr->msg_len = 0;
                }
            }

            /* If I am the destination node and this is a unicast message,
             *      do not forward */
            else if (hdr->dest == My_Address)  {
                fbv_ptr->ns[ngbr_iter].flag = DROPPED_MSG;
                fbv_ptr->ns[ngbr_iter].ngbr = NULL;
                fbv_ptr->need_count--;
                if (fbv_ptr->need_count == 0) {
                    dispose(fbv_ptr->ns);
                    fbv_ptr->ns = NULL;
                    Cleanup_Scatter(fbv_ptr->msg_scat);
                    fbv_ptr->msg_scat = NULL;
                    fbv_ptr->msg_len = 0;
                }
            }

            /* We must queue this packet to send to
             * this neighbor that NEEDS it. */
            else {
                
                if ((temp_pq_node = (Prio_PQ_Node *) new (PRIO_FLOOD_PQ_NODE))
                        == NULL)
                {
                    Alarm(EXIT, "Priority_Flood_Disseminate(): cannot allocate \
                                    Prio_PQ_Node object\r\n");
                }

                /* fill in the pq node */
                temp_pq_node->timestamp = fbv_ptr->expire;
                temp_pq_node->entry = fbv_ptr;
                temp_pq_node->next = NULL;
                temp_pq_node->prev =
                    pldata->pq[src_id].tail[f_hdr->priority];

                /* link to the node in the corresponding src's PQ and correct
                 * prior lvl */
                pldata->pq[src_id].tail[f_hdr->priority]->next =
                    temp_pq_node;
                pldata->pq[src_id].tail[f_hdr->priority] = temp_pq_node;

                /* update the Ngbr status for both pointer to msg and flag */
                fbv_ptr->ns[ngbr_iter].flag = NEED_MSG;
                fbv_ptr->ns[ngbr_iter].ngbr = temp_pq_node;

                /* possibly put this source into the send_queues */
                if (pldata->in_send_queue[src_id] == 0) {
                    if((temp_sfq = (Send_Fair_Queue *) new(SEND_QUEUE_NODE))
                        == NULL)
                    {
                        Alarm(EXIT, "Priority_Flood_Disseminate: Cannot \
                                     allocate send_queue objecti\r\n");
                    }
                    temp_sfq->next = NULL;
                    temp_sfq->src_id = src_id;
                    temp_sfq->penalty = 1;
                    pldata->urgent_tail->next = temp_sfq;
                    pldata->urgent_tail = temp_sfq;
                    pldata->in_send_queue[src_id] = 1;
                }

                /* increase the msg_count for that source
                 * and total messages */
                packets = Calculate_Packets_In_Message(fbv_ptr->msg_scat, mode, NULL);
                pldata->msg_count[src_id] += packets;
                pldata->total_msg += packets;

                /* Check if the max has now increased */
                if (f_hdr->priority > pldata->max_pq[src_id]) {
                    pldata->max_pq[src_id] = f_hdr->priority;
                }
                /* Check if the min has now decreased */
                if (f_hdr->priority < pldata->min_pq[src_id]) {
                    pldata->min_pq[src_id] = f_hdr->priority;
                }
               
                /* Find the node that corresponds to this neighbor */
                stdhash_find(&All_Nodes, &it, &Neighbor_Addrs[My_ID][ngbr_iter]);
                if (!stdhash_is_end(&All_Nodes, &it)) {
                    nd = *((Node **)stdhash_it_val(&it));
                    
                    /* While we still have things to send to this neighbor and
                    * we can successfully send a message to the lower level */
                    while( (pldata->norm_head.next != NULL ||
                        pldata->urgent_head.next != NULL) &&
                           Request_Resources((IT_PRIORITY_ROUTING >> ROUTING_BITS_SHIFT), nd, mode, 
                            &Priority_Flood_Send_One));
                }

                /* Check if this belly is now over capacity */
                if (pldata->total_msg > Conf_Prio.Max_Mess_Stored) {
                    
                    /* search for the sender_id w/ the maximum usage */
                    hog_index = 0; max_usage = 0;
                    for (i = 1; i <= MAX_NODES; i++) {
                        if (pldata->msg_count[i] > 0 &&
                                pldata->msg_count[i] > max_usage)
                        {
                            hog_index = i;
                            max_usage = pldata->msg_count[i];
                        }
                    }

                    /* get the current hog's lowest priority, oldest message */
                    temp_pq_node = pldata->pq[hog_index].
                                        head[pldata->min_pq[hog_index]].next;

                    /* call cleanup function */
                    Cleanup_prio_flood_ds(ngbr_iter, hog_index,
                                            temp_pq_node->entry, DROPPED_MSG);
                    total_dropped++;
                    ret = BUFF_DROP;
                }
            }
            
            /* if (num_unique % 1000 == 0) {
                for (j = 1; j <= Degree[My_ID]; j++) {
                    if (Neighbor_Addrs[My_ID][j] == nd->nid) {
                        idx = j;
                        break;
                    }
                }
                printf("%d-->%d:\n", My_ID, Neighbor_IDs[My_ID][idx]);
                for (j = 9; j <= 16; j++)
                    printf("\t[%d] = %d\n", j, pldata->msg_count[j]);
                printf("\n");
            } */

        }
    }

    /* ###################################################################### */
    /*                       (1b) DUPLICATE MESSAGE                           */
    /* ###################################################################### */
    else { /* This is not the first time we've seen this message */

        /* We should never receive a duplicate message from ourselves
         * (when we are source), but we check here just in case */
        if (src_link == NULL)
            return NO_ROUTE;

        fbv_ptr = ((Prio_Flood_Value*)stdhash_it_val(&msg_it));
        pldata = (Prio_Link_Data*)&Edge_Data[last_hop_index];

        /* if all neighbors already have this msg, don't check it */
        if (fbv_ptr->need_count == 0) {
            return NO_ROUTE;
        }
    
        switch (fbv_ptr->ns[last_hop_index].flag) {
            case RECV_MSG: case DROPPED_MSG: case EXPIRED_MSG:
                /* We already know this neighbor doesn't need this message */
                break;
            case ON_LINK_MSG:
                /* Here, we already tried to send this message */
                break;
            case NEED_MSG:
                /* This message is stored in the PQ */
                /* We can effectively get rid of it in the PQ and cleanup */
                temp_pq_node = fbv_ptr->ns[last_hop_index].ngbr;
                Cleanup_prio_flood_ds(last_hop_index, src_id,
                                        temp_pq_node->entry, RECV_MSG);
                break;
            default:
                printf("\tflag == %d\n", fbv_ptr->ns[last_hop_index].flag);
                Alarm(EXIT, "Priority_Flood_Disseminate: duplicate w/ invalid \
                             ngbr status\r\n");

        }
        ret = NO_ROUTE;
    }

    return ret;
}

/***********************************************************/
/* int Priority_Flood_Send_One  (Node *next_hop, int mode) */
/*                                                         */
/* Sends exactly one (or none) packets to the neighbor     */
/*   indicated by Neighbor_IP. This function is also       */
/*   the one that is called by the lower level as a        */
/*   call-back function.                                   */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* next_hop:    Node pointer to the neighbor to send to    */
/* mode:        mode of the link the packet arrived on     */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* num_bytes_sent - if a packet was sent                   */
/* 0              - otherwise                              */
/*                                                         */
/***********************************************************/
int Priority_Flood_Send_One( Node *next_hop, int mode )
{
    int32u              i, sender_id, ngbr_index = 0;
    int32u              Neighbor_IP;
    int                 ret, sent_one = 0, bytes_sent = 0;
    sp_time             now;
    Prio_Flood_Value    *fbv_ptr;
    Prio_Link_Data      *pldata;
    Prio_PQ_Node        *temp_pq_node;
    Send_Fair_Queue     *temp_sfq;
  
    if (next_hop == NULL) {
        Alarm(PRINT, "Priority_Flood_Send_One(): next_hop was NULL - \
                        this should NEVER happen\r\n");
        return 0;
    }
    Neighbor_IP = next_hop->nid;

    /* find the target neighbor's index in our data structures */
    for (i = 1; i <= Degree[My_ID]; i++) {
        if (Neighbor_Addrs[My_ID][i] == Neighbor_IP) {
            ngbr_index = i;
            break;
        }
    }
    assert(ngbr_index >= 1 && ngbr_index <= Degree[My_ID]);
    pldata = &Edge_Data[ngbr_index];

    while (!sent_one) {
        
        temp_sfq = NULL;

        /* first, check the urgent sender fair queue */
        if (pldata->urgent_head.next != NULL) {
            temp_sfq = pldata->urgent_head.next;
            temp_sfq->penalty--;
            /* make sure that this source still has something to send */
            if (temp_sfq->penalty > 0 || pldata->msg_count[temp_sfq->src_id] == 0) {
                pldata->urgent_head.next = pldata->urgent_head.next->next;
                if(pldata->urgent_tail == temp_sfq)
                    pldata->urgent_tail = &pldata->urgent_head;
                /* move to back of normal queue */
                temp_sfq->next = NULL;
                pldata->norm_tail->next = temp_sfq;
                pldata->norm_tail = temp_sfq;
                continue;
            }
        }
        /* next, check normal_head if the urgent was empty */
        else if (pldata->norm_head.next != NULL) {
            temp_sfq = pldata->norm_head.next;
            temp_sfq->penalty--;
            if (temp_sfq->penalty > 0) {
                pldata->norm_head.next = pldata->norm_head.next->next;
                if (pldata->norm_head.next == NULL)
                    pldata->norm_tail = &pldata->norm_head;
                temp_sfq->next = NULL;
                pldata->norm_tail->next = temp_sfq;
                pldata->norm_tail = temp_sfq;
                continue;
            }
            /* make sure that this source still has something to send */
            else if (pldata->msg_count[temp_sfq->src_id] == 0) {
                pldata->norm_head.next = pldata->norm_head.next->next;
                if (pldata->norm_head.next == NULL)
                    pldata->norm_tail = &pldata->norm_head;
                pldata->in_send_queue[temp_sfq->src_id] = 0;
                dispose(temp_sfq);
                continue;
            }
        }
        /* else no source (toward this link) has anything to send */
        else {
            return 0;
        }
            
        /* now, we must get this sender's highest priority, oldest message */
        sender_id = temp_sfq->src_id;
        temp_pq_node =
                pldata->pq[sender_id].head[pldata->max_pq[sender_id]].next;
        assert(temp_pq_node != NULL);
        
        now = E_get_time();
        fbv_ptr = temp_pq_node->entry;
        
        /* check if this msg is expired */
        if (E_compare_time(temp_pq_node->timestamp, now) <= 0) {
            Cleanup_prio_flood_ds(ngbr_index, sender_id, temp_pq_node->entry,
                                    EXPIRED_MSG);
            /* Correcting the penalty because no message was sent this iteration */
            temp_sfq->penalty = 1;
            continue;
        }

        /* DEBUG */
        /* total_sent[ngbr_index]++;
        sent[ngbr_index][sender_id]++; */

        /* we now have a valid, unexpired packet to try and send */
        pldata->sent_messages++;
        /* printf("SENDING DATA #%d TO "IPF"\n",
                fbv_ptr->seq_num, IP(Neighbor_Addrs[My_ID][ngbr_index])); */
        ret = Forward_Data(next_hop, fbv_ptr->msg_scat, mode);

        switch (ret) {
            case BUFF_EMPTY: case BUFF_OK:
                sent_one = 1;
                bytes_sent = fbv_ptr->msg_len;
                break;
            case NO_ROUTE: case BUFF_FULL: case BUFF_DROP: case NO_BUFF:
                Alarm(PRINT, "Priorty_Flood_Send_One(): Bad return from \
                                Forward_Data\r\n");
                Alarm(PRINT, "... Trying to SEND #%"PRIu64" TO "IPF"\n",
                    fbv_ptr->seq_num, IP(Neighbor_Addrs[My_ID][ngbr_index]));
                /* Correcting the penalty because the message failed to send */
                temp_sfq->penalty++;
                return 0;
                break;
            default:
                Alarm(PRINT, "Priority_Flood_Send_One(): got an invalid  \
                                return from Forward_Data\r\n");
                /* Correcting the penalty because the message failed to send */
                temp_sfq->penalty++;
                return 0;
        } 

        /* cleanup the send_fair_queue */
        if (temp_sfq == pldata->urgent_head.next) {
            pldata->urgent_head.next = pldata->urgent_head.next->next;
            if(pldata->urgent_tail == temp_sfq)
                pldata->urgent_tail = &pldata->urgent_head;
        }
        else if (temp_sfq == pldata->norm_head.next) {
            pldata->norm_head.next = pldata->norm_head.next->next;
            if(pldata->norm_tail == temp_sfq)
                pldata->norm_tail = &pldata->norm_head;
        } 
        else { /* error */
            Alarm(PRINT, "Priority_Flood_Send_One(): send_fair_queue \
                            node not possible\r\n");
        }

        /* move to back of normal queue */
        temp_sfq->penalty = Calculate_Packets_In_Message(fbv_ptr->msg_scat, mode, NULL);
        temp_sfq->next = NULL;
        pldata->norm_tail->next = temp_sfq;
        pldata->norm_tail = temp_sfq;

        Cleanup_prio_flood_ds(ngbr_index, sender_id, temp_pq_node->entry,
                                ON_LINK_MSG);
    }
   
    /* DEBUG */
    /* if (total_sent[ngbr_index] % 100 == 0) {
        printf("%d --> %d    total = %d\n", My_ID, Neighbor_IDs[My_ID][ngbr_index], 
            total_sent[ngbr_index]);
        for (i = 9; i <= 16; i++)
            printf("\t[%d] = %d\n", i, sent[ngbr_index][i]);
        printf("\n");
    } */

    return bytes_sent; 
}

/***********************************************************/
/* void Cleanup_prio_flood_ds(int ngbr_index, int src_id,  */
/*                         Prio_Flood_Value *fbv_ptr,      */
/*                         int ngbr_flag)                  */
/*                                                         */
/* Internal Method called to fix max/min pq, dipose msgs,  */
/*              neighbor_status flags, etc.                */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* ngbr_index:   index of neighbor that is being cleaned   */
/*                  (not used if flag == EXPIRED_MSG)      */ 
/* src_id:       src_id of message that is being cleaned   */
/* fbv_ptr:      pointer to entry for message in hash      */
/* ngbr_flag:    new status of the message toward neighbor */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/
void Cleanup_prio_flood_ds(int ngbr_index, int src_id, 
                            Prio_Flood_Value *fbv_ptr, int ngbr_flag)
{
    int                 j, i, start = 1, end = Degree[My_ID];
    int16u              packets = 0;
    Prio_Link_Data      *pldata;
    Prio_PQ_Node        *pqnode;

    if (fbv_ptr->need_count == 0)
        return;

    if (ngbr_flag != EXPIRED_MSG) {
        start = end = ngbr_index;
    }

    packets = Calculate_Packets_In_Message(fbv_ptr->msg_scat, 
                        fbv_ptr->link_mode, NULL);

    for (i = start; i <= end && fbv_ptr->need_count > 0; i++) {

        /* If this neighbor has already cleaned up this message, skip */
        if ( fbv_ptr->ns[i].ngbr == NULL)
            continue;

        pldata = &Edge_Data[i];
        pldata->msg_count[src_id] -= packets;
        pldata->total_msg -= packets;
        pqnode = fbv_ptr->ns[i].ngbr;

        /* Delete the pqnode and fix pointers around it */
        pqnode->prev->next = pqnode->next;
        if (pqnode->next != NULL)
            pqnode->next->prev = pqnode->prev;
        else {
            pldata->pq[src_id].tail[fbv_ptr->priority] = pqnode->prev;

            /* have to update max/min prioirity where we have msgs */
            if (pldata->msg_count[src_id] > 0) { /* still some msgs in PQ */
                for (j = pldata->max_pq[src_id]; j >= 1 && 
                        pldata->pq[src_id].head[j].next == NULL; j--)
                {
                    pldata->max_pq[src_id]--;
                }
                for (j = pldata->min_pq[src_id]; j <= MAX_PRIORITY &&
                        pldata->pq[src_id].head[j].next == NULL; j++) 
                {
                    pldata->min_pq[src_id]++;
                }
            }
            else if (pldata->msg_count[src_id] == 0) { /* PQ is empty */
                pldata->max_pq[src_id] = 0;
                pldata->min_pq[src_id] = MAX_PRIORITY + 1;
            }
            else
                Alarm(EXIT, "Cleanup_flood_ds(): msg_count can't be < 0");
        }
        dispose(pqnode);

        /* Update the NS array for with that status */
        fbv_ptr->need_count--;
        fbv_ptr->ns[i].flag = ngbr_flag;
        fbv_ptr->ns[i].ngbr = NULL;
    }

    /* Is this message not needed by a single neighbor at this point? */
    if (fbv_ptr->need_count == 0) {
        dispose(fbv_ptr->ns);
        fbv_ptr->ns = NULL;
        Cleanup_Scatter(fbv_ptr->msg_scat);
        fbv_ptr->msg_scat = NULL;
        fbv_ptr->msg_len = 0;
    }
}

/**************************************************************/
/* void Priority_Garbage_Collect (int32 dummy1, void *dummy2) */
/*                                                            */
/* Event for deleting expired meta data of messages           */
/*                                                            */
/*                                                            */
/* Arguments                                                  */
/*                                                            */
/* dummy1:   not used                                         */
/* dummy2:  not used                                          */
/*                                                            */
/* Return Value                                               */
/*                                                            */
/* NONE                                                       */
/*                                                            */
/**************************************************************/
void Priority_Garbage_Collect (int dummy1, void* dummy2) 
{
    int32u i;
    int32u gc_count, tot_count, tot_nnodes;
    stdit it;
    Prio_Flood_Value *fbv_ptr;
    sp_time now;

    UNUSED(dummy1);
    UNUSED(dummy2);

    gc_count = 0;
    tot_count = 0;
    tot_nnodes = 0;
    now = E_get_time();

    for (i = 1; i <= MAX_NODES; i++) {
        stdhash_begin(&Belly[i], &it);
        tot_nnodes += stdhash_load_lvl(&Belly[i]);
        while (!stdhash_is_end(&Belly[i], &it)) {
            fbv_ptr = ((Prio_Flood_Value *)stdhash_it_val(&it));
            tot_count++;
            if (E_compare_time(fbv_ptr->expire, now) <= 0) {
                Cleanup_prio_flood_ds(0, i, fbv_ptr, EXPIRED_MSG);
                stdhash_erase(&Belly[i], &it);
                gc_count++;
                continue;
            }
            stdhash_it_next(&it);
        }
    }

    Alarm(DEBUG, "Priority Garbage Collect: Finished, erased %u of %u items, "
            "%u remain, sum hash load = %u\n", gc_count, tot_count, 
            tot_count - gc_count, tot_nnodes);
    E_queue(Priority_Garbage_Collect, 0, NULL, prio_garb_coll_timeout);
}

void Priority_Print_Statistics (int dummy1, void* dummy2)
{
    int i, empty_print = 1;
    sp_time elapsed_time;
    int64u elapsed_microsecs, sum = 0;
    Prio_Link_Data *pldata;
   
    elapsed_time = E_sub_time(E_get_time(), elapsed_for_stats);
    elapsed_microsecs = elapsed_time.sec*1000000 + elapsed_time.usec;

    Alarm(PRINT, "----------PRIORITY STATS-----------\n");
    for (i=1; i <= MAX_NODES; i++)
    {
        if(Prio_Stats[i].num_msgs > 0)
        {
            Alarm(PRINT, "[%d, %d] Throughput: %f Mbps, Worst/Avg Latency for all: %f ms/%f ms, "
                            "Worst/Avg Latency for high priority: %f ms/%f ms\n",
                            i, My_ID, Prio_Stats[i].bytes*8.0/elapsed_microsecs,
                            Prio_Stats[i].worst_latency/1000.0,
                            Prio_Stats[i].latency_msgs/(1000.0*Prio_Stats[i].num_msgs),
                            Prio_Stats[i].worst_latency_highprio/1000.0,
                            Prio_Stats[i].latency_highprio/(1000.0*Prio_Stats[i].num_highprio)
                            );
            Prio_Stats[i].num_msgs = 0;
            Prio_Stats[i].num_highprio = 0;
            Prio_Stats[i].latency_msgs = 0;
            Prio_Stats[i].latency_highprio = 0;
            Prio_Stats[i].worst_latency = 0;
            Prio_Stats[i].worst_latency_highprio = 0;
            Prio_Stats[i].bytes = 0;
            empty_print = 0;
        }
    }
    for (i=1; i <= Degree[My_ID]; i++) {
        pldata = (Prio_Link_Data*) &Edge_Data[i];
        if (pldata->sent_messages > 0) {
            Alarm(PRINT, "\t[%d]: %"PRIu64" \n", i, pldata->sent_messages);
            empty_print = 0;
            sum += pldata->sent_messages;
        }
    }
    if (sum > 0) {
        Alarm(PRINT, "SUM across all links = %"PRIu64" \n", sum);
    }
    if (Injected_Messages > 0) {
        Alarm(PRINT, "Total Injected Messages = %"PRIu64" \n", Injected_Messages);
        empty_print = 0;
    }
    if (total_dropped > 0) {
        Alarm(PRINT, "Total Dropped = %"PRIu64" \n", total_dropped);
        empty_print = 0;
    }

    if (!empty_print)
        Alarm(PRINT, "-----------------------\n");

    elapsed_for_stats = E_get_time();
    E_queue( Priority_Print_Statistics, 0, NULL, prio_print_stat_timeout);
}
