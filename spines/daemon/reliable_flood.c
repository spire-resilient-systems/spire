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

/* For printing 64 bit numbers */
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#ifdef ARCH_PC_WIN95
#include <winsock2.h>
#endif

#define ext_rel_flood
#include "reliable_flood.h"
#undef  ext_rel_flood

#ifndef ULLONG_MAX
#define ULLONG_MAX 18446744073709551615ULL
#endif

extern int32u   My_Address;
extern stdhash  All_Nodes;
extern Link*    Links[MAX_LINKS];
extern stdhash  Sessions_ID;

/* Configuration File Variables */
extern stdhash     Node_Lookup_Addr_to_ID;
extern int16u      My_ID;
extern int32u      *Neighbor_Addrs[];
extern int16u      *Neighbor_IDs[];

/* Local constants */
static const sp_time zero_timeout = {0, 0};
static const sp_time one_sec_timeout = {1, 0};
static const sp_time thirty_sec_timeout = {10, 0};

/* Global variables local to this file */
unsigned char RF_State_Change;
unsigned char Initial_E2E;
unsigned char E2E_Stop; /* only used if Conf_Rel.E2E_Opt == 0 */
unsigned char Local_Status_Change_Progress; 
int64u Next_Assigned_Seq;
int16u Num_Paths_Snapshot;
int e2e_cleared[MAX_NODES + 1][MAX_NODES + 1];
int hbh_cleared[MAX_NODES + 1][MAX_NODES + 1];

typedef struct rel_stats_d {
    int64u bytes;
    int64u num_received;
} rel_stats;

rel_stats Rel_Stats[MAX_NODES+1];
sp_time rel_elapsed_for_stats;

/* Local Session Functions */
void Reliable_Flood_Resume_Sessions(int dst_id, void *dummy);
/* Local Process Functions */
void Reliable_Flood_Process_E2E(int32u last_hop_index, sys_scatter *scat, int mode);
int Reliable_Flood_Process_Data(int32u last_hop_index, int32u src_id,
                                int32u dst_id, sys_scatter *scat, int mode); 
int Reliable_Flood_Process_Acks(int32u last_hop_index, sys_scatter *scat);
/* Local Events */
void Reliable_Flood_Gen_E2E(int mode, void *dummy);
void Reliable_Flood_Neighbor_Transfer(int mode, Link *lk);
void Reliable_Flood_E2E_Event(int mode, void *ngbr_data);
void Reliable_Flood_SAA_Event(int mode, void *ngbr_data);
void Reliable_Flood_Print_Stats(int dummy1, void *dummy2);
/* Local Send Functions */
int Reliable_Flood_Send_E2E (Node *next_hop, int ngbr_index, int mode);
int Reliable_Flood_Send_Data(Node *next_hop, int ngbr_index, int mode); 
int Reliable_Flood_Send_SAA (Node *next_hop, int ngbr_index, int mode);
int Reliable_Flood_Add_Acks (rel_flood_tail *rt, int ngbr_index, int16u remaining);
/* Local Crypto Functions */
int Reliable_Flood_Verify(sys_scatter *scat, int32u src_id, unsigned char type);
void Reliable_Flood_Restamp(void);
/* Link Status Change Functions */
void Process_Status_Change(int32u last_hop_index, sys_scatter *scat, int mode);
void Gen_Status_Change(int mode, void *dummy);
void Status_Change_Event (int mode, void *ngbr_data);
int Send_Status_Change (Node *next_hop, int ngbr_index, int mode);

void Flip_rel_flood_hdr( rel_flood_header *r_hdr )
{
    r_hdr->src          = Flip_int32( r_hdr->src );
    r_hdr->dest         = Flip_int32( r_hdr->dest );
    r_hdr->seq_num      = Flip_int64( r_hdr->seq_num );
    /* Don't need to flip type b/c its a char (one byte) */
}

void Copy_rel_flood_header( rel_flood_header *from_hdr,
                        rel_flood_header *to_hdr )
{
    to_hdr->src         = from_hdr->src;
    to_hdr->dest        = from_hdr->dest;
    to_hdr->seq_num     = from_hdr->seq_num;
    to_hdr->type        = from_hdr->type;
}

/***********************************************************/
/* void Rel_Pre_Conf_Setup()                               */
/*                                                         */
/* Setup configuration file defaults for Reliable Flooding */
/*                                                         */
/* Return: NONE                                            */
/*                                                         */
/***********************************************************/
void Rel_Pre_Conf_Setup()
{
    Conf_Rel.HBH_Ack_Timeout          = HBH_ACK_TO;
    Conf_Rel.E2E_Ack_Timeout          = E2E_ACK_TO;
    Conf_Rel.Status_Change_Timeout    = STATUS_CHANGE_TO;
    Conf_Rel.Crypto                   = REL_CRYPTO;
    Conf_Rel.SAA_Threshold            = REL_FLOOD_SAA_THRESHOLD;
    Conf_Rel.HBH_Advance              = HBH_ADVANCE;
    Conf_Rel.HBH_Opt                  = HBH_OPT;
    Conf_Rel.E2E_Opt                  = E2E_OPT;
    Conf_Rel.dummy1                   = 0;
    Conf_Rel.dummy2                   = 0;
    Conf_Rel.dummy3                   = 0;
}

/***********************************************************/
/* void Rel_Post_Conf_Setup()                              */
/*                                                         */
/* Sets up timers and data structures after reading from   */
/* the configuration file for Reliable Flooding            */
/*                                                         */
/* Return: NONE                                            */
/*                                                         */
/***********************************************************/
void Rel_Post_Conf_Setup()
{
    rel_fl_hbh_ack_timeout.sec  = Conf_Rel.HBH_Ack_Timeout / 1000000;
    rel_fl_hbh_ack_timeout.usec = Conf_Rel.HBH_Ack_Timeout % 1000000;

    rel_fl_e2e_ack_timeout.sec  = Conf_Rel.E2E_Ack_Timeout / 1000000;
    rel_fl_e2e_ack_timeout.usec = Conf_Rel.E2E_Ack_Timeout % 1000000;

    status_change_timeout.sec   = Conf_Rel.Status_Change_Timeout / 1000000;
    status_change_timeout.usec  = Conf_Rel.Status_Change_Timeout % 1000000;
}   

/***********************************************************/
/* int Rel_Conf_hton(unsigned char *buff)                  */
/*                                                         */
/* Converts host storage of configuration parameters into  */
/* network format and writes to buff.                      */
/*                                                         */
/* Return: # of bytes written                              */
/*                                                         */
/***********************************************************/
int Rel_Conf_hton(unsigned char *buff)
{
    unsigned char *write = (unsigned char*)buff;
    
    *(int32u*)write = htonl(Conf_Rel.HBH_Ack_Timeout);
        write += sizeof(int32u);
    *(int32u*)write = htonl(Conf_Rel.E2E_Ack_Timeout);
        write += sizeof(int32u);
    *(int32u*)write = htonl(Conf_Rel.Status_Change_Timeout);
        write += sizeof(int32u);
    *(unsigned char*)write = Conf_Rel.Crypto; 
        write += sizeof(unsigned char);
    *(unsigned char*)write = Conf_Rel.SAA_Threshold;
        write += sizeof(unsigned char);
    *(unsigned char*)write = Conf_Rel.HBH_Advance;
        write += sizeof(unsigned char);
    *(unsigned char*)write = Conf_Rel.HBH_Opt;
        write += sizeof(unsigned char);
    *(unsigned char*)write = Conf_Rel.E2E_Opt;
        write += sizeof(unsigned char);
    *(unsigned char*)write = Conf_Rel.dummy1;
        write += sizeof(unsigned char);
    *(unsigned char*)write = Conf_Rel.dummy2;
        write += sizeof(unsigned char);
    *(unsigned char*)write = Conf_Rel.dummy3;
        write += sizeof(unsigned char);

    return sizeof(CONF_REL);
}

/***********************************************************/
/* void Init_Reliable_Flood ()                             */
/*                                                         */
/* Initializes the Reliable Flooding Data Structures       */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/
void Init_Reliable_Flooding()
{
    int32u i, j, k, d;
    sp_time now = E_get_time();
    
    RF_Edge_Data = (Rel_Flood_Link_Data *)
        Mem_alloc(sizeof(Rel_Flood_Link_Data) * (Degree[My_ID] + 1));

    FB = (All_Flow_Buffers*) Mem_alloc(sizeof(All_Flow_Buffers));

    for (i = 0; i <= MAX_NODES; i++) {
        
        Flow_Seq_No[i] = 1;
        Flow_Source_Epoch[i] = now.sec;
        Handshake_Complete[i] = 0;
        E2E[i].dest = 0; /* if this is 0, there is no valid e2e there */
        E2E_Sig[i] = (unsigned char*) Mem_alloc(Rel_Signature_Len);
        Status_Change[i].epoch = 0; /* We have received no status changes yet */
        Status_Change[i].creator = i; 
        Status_Change_Sig[i] = (unsigned char*) Mem_alloc(Rel_Signature_Len);
        Sess_List[i].size = 0;
        Sess_List[i].head.sess_id = -1;
        Sess_List[i].head.next = NULL;
        Sess_List[i].tail = &Sess_List[i].head;
        
        for (j = 0; j <= MAX_NODES; j++) {
            FB->flow[i][j].sow      = 1;
            FB->flow[i][j].next_seq = (int64u*)
                Mem_alloc(sizeof(int64u) * (Degree[My_ID] + 1));
            FB->flow[i][j].head_seq = 1;
            FB->flow[i][j].src_epoch = 0;
            for (k = 0; k < MAX_MESS_PER_FLOW; k++) {
                FB->flow[i][j].msg[k] = NULL;
                FB->flow[i][j].num_paths[k] = 0;
                FB->flow[i][j].status[k] = (unsigned char*)
                    Mem_alloc(sizeof(unsigned char) * (Degree[My_ID] + 1));
                for (d = 0; d <= Degree[My_ID]; d++) {
                    FB->flow[i][j].status[k][d] = EMPTY;
                }
            }
            for (k = 0; k <= Degree[My_ID]; k++) {
                FB->flow[i][j].next_seq[k] = 1;
            }
            E2E[i].cell[j].aru = 0;
            E2E[i].cell[j].src_epoch = 0;
            E2E[i].cell[j].dest_epoch = 0;
            Status_Change[i].cell[j].seq = 0;
            Status_Change[i].cell[j].cost = 0;

            e2e_cleared[i][j] = 0;
            hbh_cleared[i][j] = 0;
        }
    }
    
    /* This daemon automatically completes the handshake with itself */
    Handshake_Complete[My_ID] = 1;
    FB->flow[My_ID][My_ID].src_epoch = Flow_Source_Epoch[My_ID];

    E2E[My_ID].dest = My_ID;
    for (j = 0; j <= MAX_NODES; j++) {
        E2E[My_ID].cell[j].dest_epoch = Flow_Source_Epoch[My_ID];
    }

    /* Setup Status Change for myself */
    for (i = 1; i <= Degree[My_ID]; i++) {
        Status_Change[My_ID].cell[Neighbor_IDs[My_ID][i]].cost = -1;
    }

    for (i = 0; i <= Degree[My_ID]; i++) {
        
        RF_Edge_Data[i].norm_head.next = NULL;
        RF_Edge_Data[i].norm_head.src_id = 0;
        RF_Edge_Data[i].norm_head.dest_id = 0;
        RF_Edge_Data[i].norm_tail = &RF_Edge_Data[i].norm_head;

        RF_Edge_Data[i].urgent_head.next = NULL;
        RF_Edge_Data[i].urgent_head.src_id = 0;
        RF_Edge_Data[i].urgent_head.dest_id = 0;
        RF_Edge_Data[i].urgent_tail = &RF_Edge_Data[i].urgent_head;

        RF_Edge_Data[i].hbh_unsent_head.next = NULL;
        RF_Edge_Data[i].hbh_unsent_head.src_id = 0;
        RF_Edge_Data[i].hbh_unsent_head.dest_id = 0;
        RF_Edge_Data[i].hbh_unsent_tail = &RF_Edge_Data[i].hbh_unsent_head;

        RF_Edge_Data[i].saa_trigger = Conf_Rel.SAA_Threshold - 1;
        RF_Edge_Data[i].unsent_state_count = 0;
        RF_Edge_Data[i].e2e_ready = 0;
        RF_Edge_Data[i].status_change_ready = 0;
        stdskl_construct(&RF_Edge_Data[i].e2e_skl, sizeof(sp_time), 
                            sizeof(int32u), E2E_TO_cmp);
        stdskl_construct(&RF_Edge_Data[i].status_change_skl, sizeof(sp_time), 
                            sizeof(int32u), E2E_TO_cmp);

        RF_Edge_Data[i].total_pkts_sent = 0;

        for (j = 0; j <= MAX_NODES; j++) {
            RF_Edge_Data[i].e2e_stats[j].timeout.sec            = 0;
            RF_Edge_Data[i].e2e_stats[j].timeout.usec           = 0;
            RF_Edge_Data[i].e2e_stats[j].unsent                 = 0;
            RF_Edge_Data[i].status_change_stats[j].timeout.sec  = 0;
            RF_Edge_Data[i].status_change_stats[j].timeout.usec = 0;
            RF_Edge_Data[i].status_change_stats[j].unsent       = 0;

            for (k = 0; k <= MAX_NODES; k++) {
                RF_Edge_Data[i].e2e_stats[j].flow_block[k] = 0;
                RF_Edge_Data[i].ns_matrix.flow_aru[j][k]   = 0;
                RF_Edge_Data[i].ns_matrix.flow_sow[j][k]   = 1;
                RF_Edge_Data[i].unsent_state[j][k]         = 0;
                RF_Edge_Data[i].in_flow_queue[j][k]        = 0;
            }
        }
    }

    RF_State_Change = 0;
    Initial_E2E = 1;
    E2E_Stop = 0;
    Local_Status_Change_Progress = 0;
    Next_Assigned_Seq = 0;
    Num_Paths_Snapshot = 0;

    /* Using mode = -1 to specify that we are not actually sending
     *  this E2E, just setting up the data structures for later */
    E_queue(Reliable_Flood_Gen_E2E, -1, NULL, zero_timeout);

    /* PRINT STATS */
    for (i = 0; i <= MAX_NODES; i++) {
        Rel_Stats[i].bytes = 0;
        Rel_Stats[i].num_received = 0;
    }
    rel_elapsed_for_stats = E_get_time();
    //E_queue(Reliable_Flood_Print_Stats, 0, NULL, thirty_sec_timeout);

    Alarm(DEBUG, "Created Reliable Flood Data Structures\n");
}

void Reliable_Flood_Print_Stats(int dummy1, void *dummy2)
{
    int i;
    int64u sum = 0, elapsed_microsecs;
    sp_time elapsed_time;
    Rel_Flood_Link_Data *rfldata;

    elapsed_time = E_sub_time(E_get_time(), rel_elapsed_for_stats);
    elapsed_microsecs = elapsed_time.sec*1000000 + elapsed_time.usec;

    Alarm(PRINT, "------RELIABLE STATS--------\n");
    for (i=1; i <= MAX_NODES; i++)
    {
        if (Rel_Stats[i].bytes > 0)
        {
            Alarm(PRINT, "[%d, %d] Throughput: %f Mbps, Total Delivered: %llu\n",
                                i, My_ID, Rel_Stats[i].bytes*8.0/elapsed_microsecs,
                                Rel_Stats[i].num_received);
            Rel_Stats[i].bytes = 0;
        }
    }

    for (i = 1; i <= Degree[My_ID]; i++) {
        rfldata = (Rel_Flood_Link_Data*) &RF_Edge_Data[i];
        printf("\t[%d]: %"PRIu64"\n", i, rfldata->total_pkts_sent);
        sum += rfldata->total_pkts_sent;
    }
    printf("Total = %"PRIu64"\n\n", sum);
        
    rel_elapsed_for_stats = E_get_time();
    E_queue(Reliable_Flood_Print_Stats, 0, NULL, thirty_sec_timeout);
}

/***********************************************************/
/* void Fill_Packet_Header_Reliable_Flood (char *hdr,      */
/*                                       int16u nu_paths)  */
/*                                                         */
/* Processes Reliable Flood data                           */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* hdr:         pointer to rel_flood_header                */
/* num_paths:   value of K-paths for this message          */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/*                                                         */
/* 0 - There was a problem                                 */
/* 1 - Successful                                          */
/*                                                         */
/***********************************************************/
int Fill_Packet_Header_Reliable_Flood( char* hdr, int16u num_paths )
{
    rel_flood_header *r_hdr = (rel_flood_header*)hdr;

    r_hdr->src_epoch   = Flow_Source_Epoch[r_hdr->dest];
    r_hdr->seq_num     = Flow_Seq_No[r_hdr->dest]++;
    r_hdr->type        = REL_FLOOD_DATA;
    
    Next_Assigned_Seq  = r_hdr->seq_num;
    Num_Paths_Snapshot = num_paths;

    return 1;
}

/***********************************************************/
/* int Reliable_Flood_Can_Flow_Send (Session *ses,         */
/*                                        in32u dst)       */
/*                                                         */
/* Check if the flow between me and dst can send (has room */
/*   and a completed handshake between src-dst). If not,   */
/*   return 0                                              */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* ses:         session trying to send                     */
/* dst:         logical ID of this destination             */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* 0 - Flow was full, session now blocked OR Error         */
/* 1 - Success (Flow has space and complete handshake)     */
/*                                                         */
/***********************************************************/
int Reliable_Flood_Can_Flow_Send (Session *ses, int32u dst) 
{
    Flow_Buffer *fb;

    if (dst < 1 || dst > MAX_NODES) {
        Alarm(PRINT, "Reliable_Flood_Can_Flow_Send: invalid dst = %u\n", dst);
        return 0;
    }

    if (ses->blocked == 1) {
        Alarm(PRINT, "Reliable_Flood_Can_Flow_Send: session already blocked??\n");
        return 0;
    }
   
    fb = &FB->flow[My_ID][dst];
    if (fb->head_seq < fb->sow + MAX_MESS_PER_FLOW && Flow_Source_Epoch[dst] == fb->src_epoch)
        return 1;

    return 0;
}

/***********************************************************/
/* int Reliable_Flood_Block_Session (Session *ses,         */
/*                                        in32u dst)       */
/*                                                         */
/* Verify flow between me and dst is full or no handshake  */
/*   complete. Add this session to the corresponding       */
/*   blocked list so that the session can be resume when   */
/*   the flow can send (adds ses->scat to buffer when      */
/*   there is room and completed handshake).               */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* ses:         session trying to send                     */
/* dst:         logical ID of this destination             */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* 0 - Error (Flow not full, invalid dst, etc.)            */
/* 1 - Success (Flow blocked correctly)                    */
/*                                                         */
/***********************************************************/
int Reliable_Flood_Block_Session (Session *ses, int32u dst) 
{
    Session_Obj *so;
    Flow_Buffer *fb;

    if (dst < 1 || dst > MAX_NODES) {
        Alarm(PRINT, "Reliable_Flood_Block_Session: invalid dst = %u\n", dst);
        return 0;
    }

    if (ses->blocked == 1) {
        Alarm(PRINT, "Reliable_Flood_Block_Session: session already blocked??\n");
        return 0;
    }
   
    fb = &FB->flow[My_ID][dst];
    if (fb->head_seq < fb->sow + MAX_MESS_PER_FLOW && Flow_Source_Epoch[dst] == fb->src_epoch) {
        Alarm(PRINT, "Reliable_Flood_Block_Session: not blocking session, flow [%d,%d] has "
                        " space and completed handshake\r\n", My_ID, dst);
        return 0;
    }

    /* if (fb->head_seq >= fb->sow + MAX_MESS_PER_FLOW)
        printf("BLOCKING Session %d to %d b/c full flow\n", ses->sess_id, dst);
    else if (Flow_Source_Epoch[dst] != fb->src_epoch)
        printf("BLOCKING Session %d to %d b/c epoch mismatch [Flow = %d, fb = %d]\n", 
                    ses->sess_id, dst, Flow_Source_Epoch[dst], fb->src_epoch); */
    
    /* Add session_obj to the queue for this dst */
    so = (Session_Obj *) new (RF_SESSION_OBJ);
    if (so == NULL)
        Alarm(EXIT, "Reliable_Flood_Block_Session: memory failure\r\n");
    so->sess_id = ses->sess_id;
    so->next = NULL;
    Sess_List[dst].tail->next = so;
    Sess_List[dst].tail = so;
    Sess_List[dst].size++;

    /* Block session */
    ses->blocked = 1;
    Block_Session(ses);

    /* so = Sess_List[dst].head.next;
    printf("\tSessions[%d] = ", dst);
    while (so != NULL) {
        printf("%d ", so->sess_id);
        so = so->next;
    }
    printf("\n"); */

    return 1;
}


/***********************************************************/
/* void Reliable_Flood_Resume_Sessions (int dst_id,        */
/*                                         void *dummy)    */
/*                                                         */
/* Unblocks sessions in the Sess_List that have a stored   */
/*   message to logical dst_id. Stops when either:         */
/*   (1) no more sessions are blocked or                   */
/*   (2) flow is full and/or cannot send                   */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* dst_id:         logical ID of this destination          */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/
void Reliable_Flood_Resume_Sessions (int dst_id, void *dummy) 
{
    Session     *ses;
    Session_Obj *so, *del;
    stdit       it;
    Flow_Buffer *fb;

    /* If the dst ID is invalid, return */
    if (dst_id < 1 || dst_id > MAX_NODES)
        return;
    
    fb = &FB->flow[My_ID][dst_id];
    so = &Sess_List[dst_id].head;

    /* Start resuming sessions as long as there is room in flow */
    while (so->next != NULL && (fb->head_seq < fb->sow + MAX_MESS_PER_FLOW) &&
            Handshake_Complete[dst_id] == 1) 
    {
        stdhash_find(&Sessions_ID, &it, &so->next->sess_id);
        if(!stdhash_is_end(&Sessions_ID, &it)) {
            ses = *((Session **)stdhash_it_val(&it));
            ses->blocked = 0;
            Alarm(DEBUG, "RESUMING Session %d\n", ses->sess_id);
            Session_Send_Message(ses);
            Resume_Session(ses);
        }
        del = so->next;
        if (Sess_List[dst_id].tail == del)
            Sess_List[dst_id].tail = so;
        so->next = del->next;
        dispose(del);
        Sess_List[dst_id].size--;
    }

    /* printf("\tRESUMED SESSIONS TO %d\n", dst_id); */
}


/***********************************************************/
/* int E2E_TO_cmp (const void *l, const void *r)           */
/*                                                         */
/* Compares two e2e timeouts (sp_time)                     */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* l:       first (left) e2e timeout                       */
/* r:       second (right) e2e timeout                     */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* -1 if l < r, 0 if l == r, 1 if l > r                    */
/*                                                         */
/***********************************************************/
int E2E_TO_cmp(const void *l, const void *r)
{
    sp_time left  = *(sp_time*) l;
    sp_time right = *(sp_time*) r;

    return E_compare_time(left, right);
}

/***********************************************************/
/* void Reliable_Flood_Disseminate (Link *src_link,        */
/*                          sys_scatter *scat, int mode)   */
/*                                                         */
/* Processes Reliable Flood data                           */
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
int Reliable_Flood_Disseminate(Link *src_link, sys_scatter *scat, int mode)
{
    udp_header          *hdr;
    rel_flood_header    *r_hdr;
    rel_flood_tail      *rt;
    Rel_Flood_Link_Data *rfldata;
    rel_flood_e2e_ack   *e2e;
    status_change       *sc;
    Node                *nd;
    int                 ret = BUFF_OK, temp_ret = BUFF_OK, i;
    int32u              msg_size = 0, expected_size;
    int32u              last_hop_ip;
    int32u              last_hop_index = 0, src_id, dst_id, old_count;
    stdit               ip_it, it;
    unsigned char      *path = NULL;
    unsigned char       temp_path[8];
    unsigned char       temp_path_index;
    
    /* First, did this message came from a valid neighbor? */
    if (src_link == NULL) {
        last_hop_ip = My_Address;
    }
    else {
        last_hop_ip = src_link->leg->remote_interf->net_addr;

        stdhash_find(&Node_Lookup_Addr_to_ID, &ip_it, &last_hop_ip);
        if (stdhash_is_end(&Node_Lookup_Addr_to_ID, &ip_it)) {
            Alarm(DEBUG, "Reliable_Flood_Disseminate: received msg on link that"
                            " I don't have in my configuration file\r\n");
            return NO_ROUTE;
        }
        /* store the last_hop's index in the neighbor structure for later */
        for (i = 1; i <= Degree[My_ID]; i++) {
            if (Neighbor_Addrs[My_ID][i] == last_hop_ip) {
                last_hop_index = i;
                break;
            }
        }
        /* quick sanity check that we have a valid neighbor */
        if (last_hop_index == 0) 
            return NO_ROUTE;
    }
 
    hdr = (udp_header*)scat->elements[1].buf;
    r_hdr = (rel_flood_header*)(scat->elements[scat->num_elements - 2].buf); 
    rt = (rel_flood_tail*)(scat->elements[scat->num_elements - 1].buf);

    /* Sanity check on length of message */
    for (i = 0; i < scat->num_elements; i++)
        msg_size += scat->elements[i].len;

    expected_size = sizeof(packet_header) + sizeof(udp_header) + hdr->len +
                    sizeof(rel_flood_header) + sizeof(rel_flood_tail) + rt->ack_len;

    switch (r_hdr->type) {
        case REL_FLOOD_DATA:
            expected_size += MultiPath_Bitmask_Size + Rel_Signature_Len;
            break;
        case REL_FLOOD_E2E:
            expected_size += Rel_Signature_Len;
            break;
        case REL_FLOOD_SAA:
            break;
        case STATUS_CHANGE:
            expected_size += Rel_Signature_Len;
            break;
        default:
            Alarm(PRINT, "Reliable_Flood_Disseminate: Invalid type in r_hdr\n");
            return NO_ROUTE;
    }

    if (msg_size != expected_size) {
        Alarm(PRINT, "Reliable_Flood_Disseminate: invalid message size "
                        "--> %d != %d\r\n", expected_size, msg_size);
        return NO_ROUTE;
    }

    /* Make sure if there are HBH acks, there is an integer number
     * of them */
    if (rt->ack_len % sizeof(rel_flood_hbh_ack) != 0) {
        Alarm(PRINT, "Reliable_Flood_Disseminate: packet does not have an"
                    " integer number of HBH acks (%d mod %d != 0)\r\n",
                    rt->ack_len, sizeof(rel_flood_hbh_ack));
        return NO_ROUTE;
    }

    src_id = r_hdr->src; 
    dst_id = r_hdr->dest; 
    RF_State_Change = 0;

    switch(r_hdr->type) {
        
        case REL_FLOOD_E2E:
            if (hdr->len != sizeof(rel_flood_e2e_ack)) {
                Alarm(PRINT, "LEN != sizeof(e2e)\n");
                return NO_ROUTE;
            }
            e2e = (rel_flood_e2e_ack*)(scat->elements[1].buf + sizeof(udp_header));

            /* Verify RSA Signature */
            if (Reliable_Flood_Verify(scat, e2e->dest, r_hdr->type) != 1)
                return NO_ROUTE; 

            temp_ret = Reliable_Flood_Process_Acks(last_hop_index, scat);
            if (temp_ret == NO_ROUTE) ret = temp_ret;
            /* printf("RECV'D E2E from "IPF" for...\n", IP(last_hop_ip)); */
            Reliable_Flood_Process_E2E(last_hop_index, scat, mode);
            ret = NO_ROUTE;
            break;

        case REL_FLOOD_DATA:
            /* Verify RSA Signature */
            /* zero out the path, but only for data messages */
            /* Added to put the path on as the first 8 bytes of data */
            /* The 16 is to skip over the four 32 bit integers the client puts
             * on, with client specific information. */
            if (Path_Stamp_Debug == 1)  {
                path = ((unsigned char *) scat->elements[1].buf) + sizeof(udp_header) + 16;
                for (i = 0; i < 8; i++) {
                    temp_path[i] = path[i];
                    path[i] = (unsigned char) 0;
                }
            }
            if (Reliable_Flood_Verify(scat, src_id, r_hdr->type) != 1)
                return NO_ROUTE; 

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

            temp_ret = Reliable_Flood_Process_Acks(last_hop_index, scat);
            if (temp_ret == NO_ROUTE) ret = temp_ret;
            if (src_id < 1 || src_id > MAX_NODES) 
                return NO_ROUTE;
            if (dst_id < 1 || dst_id > MAX_NODES) 
                return NO_ROUTE;
            temp_ret = Reliable_Flood_Process_Data(last_hop_index, src_id,
                    dst_id, scat, mode);
            if (temp_ret == NO_ROUTE) ret = temp_ret;
            break;

        case REL_FLOOD_SAA:
            temp_ret = Reliable_Flood_Process_Acks(last_hop_index, scat);
            if (temp_ret == NO_ROUTE) ret = temp_ret;
            ret = NO_ROUTE;
            break;

        case STATUS_CHANGE:
            if (hdr->len != sizeof(status_change)) {
                Alarm(PRINT, "LEN != sizeof(status_change)\n");
                return NO_ROUTE;
            }
            sc = (status_change*)(scat->elements[1].buf + sizeof(udp_header));

            /* Verify RSA Signature */
            if (Reliable_Flood_Verify(scat, sc->creator, r_hdr->type) != 1)
                return NO_ROUTE; 

            temp_ret = Reliable_Flood_Process_Acks(last_hop_index, scat);
            if (temp_ret == NO_ROUTE) ret = temp_ret;
            /* printf("RECV'D STATUS CHANGE from "IPF" for...\n", IP(last_hop_ip)); */
            Process_Status_Change(last_hop_index, scat, mode);
            ret = NO_ROUTE;
            break;

        default:
            Alarm(PRINT, "Reliable_Flood_Disseminate: Invalid type in r_hdr\n");
            return NO_ROUTE;
    }
    
    /* Sending Loop to All Neighbors */
    for (i = 1; i <= Degree[My_ID]; i++) {
        
        rfldata = &RF_Edge_Data[i];
        old_count = rfldata->unsent_state_count;

        if (RF_State_Change == 1)
            rfldata->saa_trigger++;

        stdhash_find(&All_Nodes, &it, &Neighbor_Addrs[My_ID][i]);
        if (!stdhash_is_end(&All_Nodes, &it)) {
            nd = *((Node **)stdhash_it_val(&it));
            while ((rfldata->norm_head.next != NULL ||
                    rfldata->urgent_head.next != NULL) &&
                   Request_Resources((IT_RELIABLE_ROUTING >>
                                      ROUTING_BITS_SHIFT), nd, mode, 
                        &Reliable_Flood_Send_One));
            if (rfldata->unsent_state_count == old_count && 
                    rfldata->saa_trigger >= Conf_Rel.SAA_Threshold)
                /* perhaps also need to queue if unsent_state_count gets
                 * too big */
                E_queue(Reliable_Flood_SAA_Event, mode, rfldata, zero_timeout);
        }
    }

    /* Set data_len to be correct for Deliver_UDP in the session code by
     *      trimming off the rel_flood_tail information that is not needed */

    /* TESTTESTTEST */
    /* *data_len = sizeof(udp_header) + hdr->len + sizeof(rel_flood_header) +
            MultiPath_Bitmask_Size + Rel_Signature_Len; */

    return ret;
}


/***********************************************************/
/* void Reliable_Flood_Process_E2E (int32u last_hop_index, */
/*                           sys_scatter *scat, int mode)  */
/*                                                         */
/* Processes Reliable Flood E2E Acks                       */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* last_hop_index:  ID of the ngbr the data came from      */
/* scat:            a sys_scatter containing the message   */
/* mode:            lower-level link protocol              */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NO_ROUTE - There was a problem                          */
/* BUFF_OK  - Everything worked out correctly              */
/*                                                         */
/***********************************************************/
void Reliable_Flood_Process_E2E (int32u last_hop_index, sys_scatter *scat, int mode) 
{
    udp_header          *hdr;
    rel_flood_e2e_ack   *e2e_new, *e2e_old;
    unsigned char       *sign_start;
    Rel_Flood_Link_Data *rfldata;
    Flow_Buffer         *fb;
    Flow_Queue          *temp_fq;
    int64u              i, j, k, ngbr;
    int32u              d, index;
    char                store_e2e = 0;
    sp_time             now, min_to;
    stdit               it;

    hdr = (udp_header*)(scat->elements[1].buf);
    e2e_new = (rel_flood_e2e_ack*)(scat->elements[1].buf + sizeof(udp_header));

    if (e2e_new->dest < 1 || e2e_new->dest > MAX_NODES) {
        Alarm(DEBUG, "Reliable_Flood_Process_E2E: invalid dest on \
                        e2e ack %u\r\n", e2e_new->dest);
        return;
    }

    sign_start = (unsigned char*)(scat->elements[scat->num_elements-2].buf + 
                                    sizeof(rel_flood_header));
   
    d = e2e_new->dest;
    e2e_old = (rel_flood_e2e_ack*) &E2E[d];

    Alarm(DEBUG, "E2E_ACK from %d about dest = %d\n",
        Neighbor_IDs[My_ID][last_hop_index], d);
  
    /* First, Validate the E2E Ack. If not valid, throw away (don't store)
     *      and return */
    for (i = 1; i <= MAX_NODES; i++) {
    
        if (e2e_new->cell[i].dest_epoch < e2e_old->cell[i].dest_epoch)
            return;
        else if (e2e_new->cell[i].dest_epoch > e2e_old->cell[i].dest_epoch)
            store_e2e = 1;
        else {
            if (e2e_new->cell[i].src_epoch < e2e_old->cell[i].src_epoch)
                return;
            else if (e2e_new->cell[i].src_epoch > e2e_old->cell[i].src_epoch)
                store_e2e = 1;
            else {
                if (e2e_new->cell[i].aru < e2e_old->cell[i].aru)
                    return;
                else if (e2e_new->cell[i].aru > e2e_old->cell[i].aru)
                    store_e2e = 1;
            }
        }
    }

    if (store_e2e == 0)
        return;

    /* New handshake request from a source (also a destination).
     * Two flows considered: from us to them and from them to us.
     */
    if (e2e_new->cell[My_ID].dest_epoch > e2e_old->cell[My_ID].dest_epoch) {
       
        Handshake_Complete[d] = 0;

        /* Our flow to them */
        if (Flow_Seq_No[d] > 1) { /* If I have generated any packets to d, start over */
            now = E_get_time();
            Flow_Seq_No[d] = 1;
            Flow_Source_Epoch[d] = now.sec;
            E2E[My_ID].cell[d].dest_epoch = Flow_Source_Epoch[d];
        }
 
        /* Their flow to us */
        E2E[My_ID].cell[d].src_epoch = e2e_new->cell[My_ID].dest_epoch;
        E2E[My_ID].cell[d].aru = 0;

        fb = &FB->flow[d][My_ID];
        fb->sow = 1;
        fb->head_seq = 1;
        for (i = 1; i <= Degree[My_ID]; i++)
            fb->next_seq[i] = 1;
        fb->src_epoch = e2e_new->cell[My_ID].dest_epoch; 
        /* We don't need to change the status for messages or clean up
         *  message memory because we are the destinaion of this flow */
     
        /* Generate a new E2E */
        Initial_E2E = 1;
        if(!E_in_queue(Reliable_Flood_Gen_E2E, mode, NULL))
            E_queue(Reliable_Flood_Gen_E2E, mode, NULL, zero_timeout);
    }

    /* Handshake complete */
    if (Handshake_Complete[d] == 0 &&
            e2e_new->cell[My_ID].src_epoch == Flow_Source_Epoch[d])
    {
        if (e2e_new->cell[My_ID].aru != 0) {
            Alarm(PRINT, "Reliable_Flood_Process_E2E(): Invalid aru value for handshake"
                    " ("PRIu64")\r\n", e2e_new->cell[My_ID].aru);
            return;
        }
        printf("Completed handshake with %d\n", d);
        Handshake_Complete[d] = 1;
    }

    for (i = 1; i <= MAX_NODES; i++) {

        fb = &FB->flow[i][d];

        /* The destination has changed epochs (maybe crashed and restarted). It is
         * safe for this node to clear all message memory for this flow because the
         * destination will no longer accept any messages an old epoch.
         *
         * The node clears its currently stored packets
         * updates its sow, head_seq, and next_seq based on the E2E
         * and resets src_epoch (may go down) accordingly. */
        if (e2e_new->cell[i].dest_epoch > e2e_old->cell[i].dest_epoch) {
            
            for (k = fb->sow; k < fb->head_seq; k++) {
                index = k % MAX_MESS_PER_FLOW;
                Cleanup_Scatter(fb->msg[index]);
                fb->msg[index] = NULL;
                for (ngbr = 1; ngbr <= Degree[My_ID]; ngbr++)
                    fb->status[index][ngbr] = EMPTY;
                fb->num_paths[index] = 0;
            }
            /* Update head, tail, and next_to_send for each neighbor */
            fb->sow = e2e_new->cell[i].aru + 1;
            fb->head_seq = e2e_new->cell[i].aru + 1;
            for (k = 1; k <= Degree[My_ID]; k++) {
                fb->next_seq[k] = e2e_new->cell[i].aru + 1;
                while (fb->next_seq[k] < fb->head_seq &&
                       (fb->status[fb->next_seq[k] % MAX_MESS_PER_FLOW][k] == NEW_SENT ||
                        fb->status[fb->next_seq[k] % MAX_MESS_PER_FLOW][k] == RESTAMPED_SENT))
                {
                    fb->next_seq[k]++;
                }
                rfldata = &RF_Edge_Data[k];
                rfldata->ns_matrix.flow_aru[i][d] = e2e_new->cell[i].aru;
                rfldata->ns_matrix.flow_sow[i][d] = e2e_new->cell[i].aru + 1;
            }
            fb->src_epoch = e2e_new->cell[i].src_epoch;
        }
       
        /* The destination now has an updated epoch for the source - the destination has finished
         *      its part of the handshake with this source. 
         * 
         * The node updates its sow, head_seq, and next_seq based on the E2E.
         * It now knows that the destination has talked with the source since
         * restarting. */
        else if (e2e_new->cell[i].src_epoch > e2e_old->cell[i].src_epoch) {
        
            /* Update head, tail, and next_to_send for each neighbor */
            fb->sow = e2e_new->cell[i].aru + 1;
            fb->head_seq = e2e_new->cell[i].aru + 1;
            for (k = 1; k <= Degree[My_ID]; k++) {
                fb->next_seq[k] = e2e_new->cell[i].aru + 1;
                while (fb->next_seq[k] < fb->head_seq &&
                       (fb->status[fb->next_seq[k] % MAX_MESS_PER_FLOW][k] == NEW_SENT ||
                        fb->status[fb->next_seq[k] % MAX_MESS_PER_FLOW][k] == RESTAMPED_SENT))
                {
                    fb->next_seq[k]++;
                }
                rfldata = &RF_Edge_Data[k];
                rfldata->ns_matrix.flow_aru[i][d] = e2e_new->cell[i].aru;
                rfldata->ns_matrix.flow_sow[i][d] = e2e_new->cell[i].aru + 1;
            }
            fb->src_epoch = e2e_new->cell[i].src_epoch;
        }

        /* Normal case where ARU increases - no changes to epochs */
        else if (e2e_new->cell[i].aru > e2e_old->cell[i].aru) {
            
            /* Update head, tail, and next_to_send for each neighbor */
            /* if (i == My_ID) {
                printf("[%lu,%u] moved from %lu --> %lu, remaining = %lu\n", 
                        i, d, fb->sow, e2e_new->cell[i].aru+1, 
                        fb->head_seq - (e2e_new->cell[i].aru+1));
            } */
            while (fb->sow <= e2e_new->cell[i].aru) {
                index = fb->sow % MAX_MESS_PER_FLOW;
                if (fb->msg[index] != NULL) {
                    Cleanup_Scatter(fb->msg[index]);
                    fb->msg[index] = NULL;
                    for (ngbr = 1; ngbr <= Degree[My_ID]; ngbr++)
                        fb->status[index][ngbr] = EMPTY;
                    fb->num_paths[index] = 0;
                }
                e2e_cleared[i][d]++;
                fb->sow++;
            }
            /* printf("new_sow = %lu\n", fb->sow); */
            
            if (fb->head_seq < fb->sow)
                fb->head_seq = fb->sow;

            for (k = 1; k <= Degree[My_ID]; k++) {
                if (fb->next_seq[k] < fb->sow)
                    fb->next_seq[k] = fb->sow;
                while (fb->next_seq[k] < fb->head_seq &&
                       (fb->status[fb->next_seq[k] % MAX_MESS_PER_FLOW][k] == NEW_SENT ||
                        fb->status[fb->next_seq[k] % MAX_MESS_PER_FLOW][k] == RESTAMPED_SENT))
                {
                    fb->next_seq[k]++;
                }
                rfldata = &RF_Edge_Data[k];
                if (rfldata->ns_matrix.flow_aru[i][d] < e2e_new->cell[i].aru)
                    rfldata->ns_matrix.flow_aru[i][d] = e2e_new->cell[i].aru;
                if (rfldata->ns_matrix.flow_sow[i][d] <= e2e_new->cell[i].aru)
                    rfldata->ns_matrix.flow_sow[i][d] = e2e_new->cell[i].aru + 1;
            }
        }

        else  /* this cell has no updates/changes */
            continue;


        /* Block this flow toward each ngbr */
        for (j = 1; j <= Degree[My_ID]; j++) {

            index = fb->next_seq[j] % MAX_MESS_PER_FLOW;

            if (j != last_hop_index)
                RF_Edge_Data[j].e2e_stats[d].flow_block[i] = 1;

            else if (RF_Edge_Data[j].in_flow_queue[i][d] == 0 && 
                        fb->next_seq[j] < fb->head_seq &&
                        MultiPath_Neighbor_On_Path((unsigned char*)(
                            fb->msg[index]->elements[fb->msg[index]->num_elements-2].buf + 
                            sizeof(rel_flood_header)), j)
                    )
            {
                RF_Edge_Data[j].in_flow_queue[i][d] = 1;
                temp_fq = (Flow_Queue *) new (FLOW_QUEUE_NODE);
                if (temp_fq == NULL)
                    Alarm(EXIT, "Reliable_Flood_Process_E2E: Can't allocate"
                                "Flow Queue Node for in_flow_queue.\r\n");
                temp_fq->src_id = i;
                temp_fq->dest_id = d;
                temp_fq->penalty = 1;
                temp_fq->next = NULL;
                RF_Edge_Data[j].norm_tail->next = temp_fq;
                RF_Edge_Data[j].norm_tail = temp_fq;
            }
        }
    }

    now = E_get_time();
    for (i = 1; i <= Degree[My_ID]; i++) {
        
        rfldata = &RF_Edge_Data[i];
        
        /* Update timeout, sent */
        if (rfldata->e2e_stats[d].unsent == 0 && i != last_hop_index) {
            rfldata->e2e_stats[d].unsent = 1;
            rfldata->e2e_stats[d].timeout = 
                E_add_time(rfldata->e2e_stats[d].timeout, 
                            rel_fl_e2e_ack_timeout);
            
            stdskl_insert(&rfldata->e2e_skl, &it,
                    &rfldata->e2e_stats[d].timeout, &d, STDFALSE);
            stdskl_begin(&rfldata->e2e_skl, &it); 
            min_to = *(sp_time*) stdskl_it_key(&it);

            if (E_compare_time(min_to, now) <= 0) 
                E_queue(Reliable_Flood_E2E_Event, mode, (void*)rfldata,
                        zero_timeout); 
            else 
                E_queue(Reliable_Flood_E2E_Event, mode, (void*)rfldata,
                        E_sub_time(min_to, now));
        }
    }

    /* Store E2E and Signature (if necessary) */
    memcpy(&E2E[d], e2e_new, sizeof(rel_flood_e2e_ack));
    memcpy(E2E_Sig[d], sign_start, Rel_Signature_Len);

    /* Potentially Resume Blocked Sessions */
    fb = &FB->flow[My_ID][d];

    if (Sess_List[d].size > 0 && fb->head_seq < fb->sow + MAX_MESS_PER_FLOW && 
            Handshake_Complete[d] == 1) 
        E_queue(Reliable_Flood_Resume_Sessions, d, NULL, zero_timeout);

    return;
}
                    

/***********************************************************/
/* int Reliable_Flood_Process_Data (int32u last_hop_index, */
/*                          int32u src_id, int32u dst_id   */
/*                          sys_scatter *scat, int mode)   */
/*                                                         */
/* Processes Reliable Flood Data                           */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* last_hop_index:  ID of the ngbr the data came from      */
/* src_id:          ID of the src of the flow              */
/* dst_id:          ID of the dest of the flow             */
/* scat:            a sys_scatter containing the message   */
/* mode:            protocol of underlying link to send on */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NO_ROUTE - There was a problem                          */
/* BUFF_OK  - Everything worked out correctly              */
/*                                                         */
/***********************************************************/
int Reliable_Flood_Process_Data(int32u last_hop_index, int32u src_id,
              int32u dst_id, sys_scatter *scat, int mode) 
{
    udp_header          *hdr;
    rel_flood_header    *r_hdr;
    Rel_Flood_Link_Data *rfldata;
    Flow_Queue          *temp_fq;
    int32u              ngbr, index; 
    int64u              i, j;
    int64u              min;
    Flow_Buffer         *fb;
    unsigned char       *routing_mask, *stored_mask; /*, *temp_mask;*/
    unsigned char       restamped_message = 0;
    int64u              pre_loop;

    hdr   = (udp_header*)(scat->elements[1].buf);
    r_hdr = (rel_flood_header*)(scat->elements[scat->num_elements-2].buf);
    routing_mask = (unsigned char*)(scat->elements[scat->num_elements-2].buf + 
                                      sizeof(rel_flood_header));
    index = r_hdr->seq_num % MAX_MESS_PER_FLOW;

    fb = &FB->flow[src_id][dst_id];
    if (Conf_Rel.E2E_Opt == 0 && E2E_Stop == 0)
        E2E_Stop = 1;

    /* If this message has a higher source_epoch than any previous message
     * we've seen, or it is older, or it is 0, throw it away. */
    if (r_hdr->src_epoch > fb->src_epoch) {
        if (last_hop_index == 0) /* Came from client */
            Alarm(PRINT, "Reliable_Flood_Process_Data(): Client sent a message"
                " before handshake was established. This is an error, as this"
                " case should be handled by the new blocking scheme\r\n");
        else 
            Alarm(DEBUG, "Reliable_Flood_Process_Data(): source epoch (%u) is "
                "ahead of what is stored (%u). ATTACK?\r\n", r_hdr->src_epoch,
                fb->src_epoch);
        return NO_ROUTE;
    }
    else if (r_hdr->src_epoch < fb->src_epoch) {
        Alarm(PRINT, "Reliable_Flood_Process_Data(): source epoch (%u) is old"
            " (%u) for this flow <%d, %d>\r\n", r_hdr->src_epoch, fb->src_epoch,
            src_id, dst_id);
        return NO_ROUTE;
    }
    else if (r_hdr->src_epoch == 0) {
        Alarm(PRINT, "Reliable_Flood_Process_Data(): source epoch is 0"
            " on this packet. ATTACK?\r\n");
        return NO_ROUTE;
    }

    /* Verify that the seq_num of this message is valid */
    if (r_hdr->seq_num < fb->sow) {
        Alarm(DEBUG, "Reliable_Flood_Process_Data(): seq num (%"PRIu64") is older"
            " than SOW (%"PRIu64") for this flow <%d, %d> FROM "IPF"\r\n", 
            r_hdr->seq_num, fb->sow, src_id, dst_id, 
            IP(Neighbor_Addrs[My_ID][last_hop_index]));
        return NO_ROUTE;
    }
    else if (r_hdr->seq_num > fb->head_seq) {
        /* This might be enough to blacklist the last_hop_ip neighbor? */
        Alarm(DEBUG, "Reliable_Flood_Process_Data(): seq num %"PRIu64" is"
            " above head for flow <%d, %d>\r\n",
            r_hdr->seq_num, src_id, dst_id);
        Alarm(DEBUG, "\tReceived seq %d from "IPF", head is %"PRIu64"\n",
            r_hdr->seq_num, IP(Neighbor_Addrs[My_ID][last_hop_index]),
            fb->head_seq);
        return NO_ROUTE;
    }

    /* Verify that the message is either NEW or OLD and strict superset */
    if (r_hdr->seq_num != fb->head_seq) {
        restamped_message = 1;
        /* printf("got restamped message w/ seq = %lu\n", r_hdr->seq_num); */
        if (fb->msg[index] == NULL) {
            Alarm(EXIT, "Reliable_Flood_Process_Data(): message (%lu) between" 
                        " SOW (%lu) and Head (%lu) is NULL, which should never" 
                        " happen\r\n", r_hdr->seq_num, fb->sow, fb->head_seq);
        }
        stored_mask = (unsigned char*)
                        (fb->msg[index]->elements[fb->msg[index]->num_elements-2].buf + 
                        sizeof(rel_flood_header));
        if ( !MultiPath_Is_Superset(stored_mask, routing_mask) ) {
            if (MultiPath_Is_Equal(stored_mask, routing_mask)) {

                if (fb->status[index][last_hop_index] == NEW_UNSENT && Conf_Rel.HBH_Opt == 1)
                    fb->status[index][last_hop_index] = NEW_SENT;
                else if (fb->status[index][last_hop_index] == RESTAMPED_UNSENT && Conf_Rel.HBH_Opt == 1) {
                    /* printf("seq %lu received from %d, set to RESTAMPED_SENT - Case 1\n", 
                            r_hdr->seq_num, Neighbor_IDs[My_ID][last_hop_index]); */
                    fb->status[index][last_hop_index] = RESTAMPED_SENT;
                }

                while (fb->next_seq[last_hop_index] < fb->head_seq &&
                       (fb->status[fb->next_seq[last_hop_index] % MAX_MESS_PER_FLOW][last_hop_index] == NEW_SENT ||
                        fb->status[fb->next_seq[last_hop_index] % MAX_MESS_PER_FLOW][last_hop_index] == RESTAMPED_SENT))
                {
                    fb->next_seq[last_hop_index]++;
                }

                if (fb->next_seq[last_hop_index] >= fb->head_seq)
                    return NO_ROUTE;

#if 0
                /* Add to sending queue (urgent) if not already in either queue. */
                rfldata = &RF_Edge_Data[last_hop_index];
                index = fb->next_seq[last_hop_index] % MAX_MESS_PER_FLOW;
                temp_mask = (unsigned char*)(fb->msg[index]->elements[fb->msg[index]->num_elements-2].buf + 
                                      sizeof(rel_flood_header));
                if (rfldata->in_flow_queue[src_id][dst_id] == 0 && 
                            fb->next_seq[last_hop_index] == r_hdr->seq_num &&
                            /* dst_id != My_ID && */
                            MultiPath_Neighbor_On_Path(temp_mask,last_hop_index))
                {
                    /* if (My_ID == 11 && last_hop_index == 1)
                        printf("NOOOO. Case A\n"); */
                    rfldata->in_flow_queue[src_id][dst_id] = 1;
                    temp_fq = (Flow_Queue *) new (FLOW_QUEUE_NODE);
                    if (temp_fq == NULL)
                        Alarm(EXIT, "Reliable_Flood_Process_Data(): Cannot allocate"
                                    "Flow Queue Node for in_flow_queue.\r\n");
                    temp_fq->src_id = src_id;
                    temp_fq->dest_id = dst_id;
                    temp_fq->penalty = 1;
                    temp_fq->next = NULL;
                    rfldata->urgent_tail->next = temp_fq;
                    rfldata->urgent_tail = temp_fq;
                }
#endif
                return NO_ROUTE;
            }
            else {
                /* printf("stored = %016llx, new = %016llx\n", *(long long unsigned int*)stored_mask, *(long long unsigned int*)routing_mask); */
                Alarm(PRINT, "\tReceived msg %lu from "IPF", but the bitmask is"
                        " not a superset of already stored message bitmask\r\n",
                        r_hdr->seq_num, IP(Neighbor_Addrs[My_ID][last_hop_index]));
                return NO_ROUTE;
            }
        }
    }

    /* Verify that we have room for the message for this flow */
    if (r_hdr->seq_num >= (fb->sow + MAX_MESS_PER_FLOW)) {
        Alarm(DEBUG, "Reliable_Flood_Process_Data(): seq num (%"PRIu64") from "IPF" "
                "will not fit for the flow, already full, backpressure in "
                "effect\r\n", r_hdr->seq_num,
                IP(Neighbor_Addrs[My_ID][last_hop_index]));
        return NO_ROUTE;
    }

    /* printf("Received seq %"PRIu64" from "IPF". sow = %lu, head = %lu, "
            " mask = %016llx\n", r_hdr->seq_num, IP(Neighbor_Addrs[My_ID][last_hop_index]),
            fb->sow, fb->head_seq, *(long long unsigned int*)routing_mask);
    printf("\t");
    for (ngbr = 1; ngbr <= Degree[My_ID]; ngbr++)
        printf("  [%d] = %lu", ngbr, fb->next_seq[ngbr]);
    printf("\n"); */

    if (restamped_message == 0) {
        fb->head_seq++;
        RF_State_Change = 1;
    }

    if (dst_id == My_ID) {
        if (restamped_message == 0) {
            fb->sow++;
            for (i = 1; i <= Degree[My_ID]; i++)
                fb->next_seq[i] = fb->head_seq;
            if(!E_in_queue(Reliable_Flood_Gen_E2E, mode, NULL))
                E_queue(Reliable_Flood_Gen_E2E, mode, NULL, rel_fl_e2e_ack_timeout);

            /* RELIABLE PRINT STATS */
            Rel_Stats[src_id].bytes += hdr->len; 
            Rel_Stats[src_id].num_received++;
        } 
    }
    else {
        /* For restamped messages, free old message memory */
        if (restamped_message == 1) {
            Cleanup_Scatter(fb->msg[index]);
            fb->msg[index] = NULL;
        }
        /* We can now store this message - don't inc_ref_cnt for the rel_flood_tail */
        for (i = 0; i < scat->num_elements; i++)
            inc_ref_cnt(scat->elements[i].buf);
        inc_ref_cnt(scat);
        fb->msg[index] = scat;
        for (ngbr = 1; ngbr <= Degree[My_ID]; ngbr++) {

            if (My_ID == 11 && ngbr == 1)
                pre_loop = fb->next_seq[ngbr];

            if      (restamped_message == 0 && Conf_Rel.HBH_Opt == 1 &&
                       (ngbr == last_hop_index || Neighbor_IDs[My_ID][ngbr] == src_id))
                fb->status[index][ngbr] = NEW_SENT;
            else if (restamped_message == 0)
                fb->status[index][ngbr] = NEW_UNSENT;
            else if (restamped_message == 1 && Conf_Rel.HBH_Opt == 1 && 
                        (ngbr == last_hop_index || Neighbor_IDs[My_ID][ngbr] == src_id))
            {
                /* printf("seq %lu received from %d, set to RESTAMPED_SENT toward %d, next_seq = %lu - Case 2\n", 
                            r_hdr->seq_num, Neighbor_IDs[My_ID][last_hop_index], Neighbor_IDs[My_ID][ngbr],
                            fb->next_seq[ngbr]); */
                fb->status[index][ngbr] = RESTAMPED_SENT;
            }
            else if (restamped_message == 1)
                fb->status[index][ngbr] = RESTAMPED_UNSENT;
            while (fb->next_seq[ngbr] < fb->head_seq &&
                   (fb->status[fb->next_seq[ngbr] % MAX_MESS_PER_FLOW][ngbr] == NEW_SENT ||
                    fb->status[fb->next_seq[ngbr] % MAX_MESS_PER_FLOW][ngbr] == RESTAMPED_SENT))
            {
                fb->next_seq[ngbr]++;
            }
        }
        if (last_hop_index == 0 && restamped_message == 0) 
           fb->num_paths[index] = Num_Paths_Snapshot;

        if (Conf_Rel.HBH_Advance == 1 && restamped_message == 0) {
            min = fb->head_seq - 1;
            for( j = 1; j <= Degree[My_ID]; j++) {
                if (RF_Edge_Data[j].ns_matrix.flow_aru[src_id][dst_id] < min)
                    min = RF_Edge_Data[j].ns_matrix.flow_aru[src_id][dst_id];
                if (Conf_Rel.HBH_Opt == 0 && fb->next_seq[j] - 1 < min)
                    min = fb->next_seq[j] - 1;
            }

            /* All of our neighbors already ACK'd all messages up to min and we
            * can now clear them. We can move up our SOW for this flow. */

            while(fb->sow <= min)
            {
                /* printf("Discarding message, location #4\n"); */
                Cleanup_Scatter(fb->msg[fb->sow % MAX_MESS_PER_FLOW]);
                fb->msg[fb->sow % MAX_MESS_PER_FLOW] = NULL;
                for (ngbr = 1; ngbr <= Degree[My_ID]; ngbr++)
                    fb->status[fb->sow % MAX_MESS_PER_FLOW][ngbr] = EMPTY;
                fb->num_paths[fb->sow % MAX_MESS_PER_FLOW] = 0;
                fb->sow++;
                hbh_cleared[src_id][dst_id]++;
            }
            for (i = 1; i <= Degree[My_ID]; i++) {
                if (fb->next_seq[i] < fb->sow)
                    fb->next_seq[i] = fb->sow;
                while (fb->next_seq[i] < fb->head_seq &&
                       (fb->status[fb->next_seq[i] % MAX_MESS_PER_FLOW][i] == NEW_SENT ||
                        fb->status[fb->next_seq[i] % MAX_MESS_PER_FLOW][i] == RESTAMPED_SENT))
                {
                    fb->next_seq[i]++;
                }
            }
        }
        else if (restamped_message == 1) {
            for (ngbr = 1; ngbr <= Degree[My_ID]; ngbr++) {
                fb->next_seq[ngbr] = MIN(fb->next_seq[ngbr], r_hdr->seq_num);
                while (fb->next_seq[ngbr] < fb->head_seq &&
                       (fb->status[fb->next_seq[ngbr] % MAX_MESS_PER_FLOW][ngbr] == NEW_SENT ||
                        fb->status[fb->next_seq[ngbr] % MAX_MESS_PER_FLOW][ngbr] == RESTAMPED_SENT))
                {
                    fb->next_seq[ngbr]++;
                }
            }
        }
    }

    for (i = 1; i <= Degree[My_ID]; i++) {
        rfldata = &RF_Edge_Data[i];

        /* Update our view of their ARU for this flow if this is the hop
         *      we got the msg from or this ngbr is the source of the flow */
        if (!(Conf_Rel.HBH_Advance == 1 && Conf_Rel.HBH_Opt == 0) && 
            (i == last_hop_index || Neighbor_IDs[My_ID][i] == src_id)) {
            if (rfldata->ns_matrix.flow_aru[src_id][dst_id] < r_hdr->seq_num)
                rfldata->ns_matrix.flow_aru[src_id][dst_id] = r_hdr->seq_num;
            
            /* Could also update their SOW for this flow to
             * the max of the current SOW and ARU - MAX_MESS_PER_FLOW,
             * but we decided this is not worth it. Very unlikely
             * to be relevant. */
        }

        /* Add to sending queue (urgent) if not already in either queue. */
        else if (rfldata->in_flow_queue[src_id][dst_id] == 0 && 
                    fb->next_seq[i] == r_hdr->seq_num &&
                    /* dst_id != My_ID && */
                    MultiPath_Neighbor_On_Path(routing_mask,i))
        {
            rfldata->in_flow_queue[src_id][dst_id] = 1;
            temp_fq = (Flow_Queue *) new (FLOW_QUEUE_NODE);
            if (temp_fq == NULL)
                Alarm(EXIT, "Reliable_Flood_Process_Data(): Cannot allocate"
                            "Flow Queue Node for in_flow_queue.\r\n");
            temp_fq->src_id = src_id;
            temp_fq->dest_id = dst_id;
            temp_fq->penalty = 1;
            temp_fq->next = NULL;
            rfldata->urgent_tail->next = temp_fq;
            rfldata->urgent_tail = temp_fq;
        }

        /* Note that the state has changed, queue it to be sent to neighbor. */
        if (RF_State_Change == 1 && rfldata->unsent_state[src_id][dst_id] == 0) {
            rfldata->unsent_state[src_id][dst_id] = 1;
            temp_fq = (Flow_Queue *) new (FLOW_QUEUE_NODE);
            if (temp_fq == NULL)
                Alarm(EXIT, "Reliable_Flood_Process_Data(): Cannot allocate"
                            "Flow Queue Node for unsent_state.\r\n");
            temp_fq->src_id = src_id;
            temp_fq->dest_id = dst_id;
            temp_fq->next = NULL;
            rfldata->hbh_unsent_tail->next = temp_fq;
            rfldata->hbh_unsent_tail = temp_fq;
            rfldata->unsent_state_count++;
        }
    }

    /* if (src_id == My_ID && 
            (fb->head_seq >= fb->sow + MAX_MESS_PER_FLOW)) 
    {
        Reliable_Flood_Block_Sessions(dst_id);
    } */

    return BUFF_OK;
}


/***********************************************************/
/* int Reliable_Flood_Process_Acks (int32u last_hop_index, */
/*                          sys_scatter *scat)             */
/*                                                         */
/* Processes Reliable Flood Acks                           */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* last_hop_index:  ID of the ngbr the acks came from      */
/* scat:            a sys_scatte containing the message    */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NO_ROUTE - There was a problem                          */
/* BUFF_OK  - Everything worked out correctly              */
/*                                                         */
/***********************************************************/
int Reliable_Flood_Process_Acks(int32u last_hop_index, sys_scatter *scat) 
{
    udp_header          *hdr;
    rel_flood_header    *r_hdr;
    rel_flood_tail      *rt;
    Rel_Flood_Link_Data *rfldata = &RF_Edge_Data[last_hop_index], *ngbr_data;
    rel_flood_hbh_ack   *ack;
    int32u               src_id, dst_id, i, j, index, ngbr, idx;
    int64u               min;
    Flow_Queue          *temp_fq;
    Flow_Buffer         *fb;
    char                 progress = 0;

    hdr   = (udp_header*)(scat->elements[1].buf);
    r_hdr = (rel_flood_header*)(scat->elements[scat->num_elements-2].buf);
    rt = (rel_flood_tail*)(scat->elements[scat->num_elements-1].buf);

    /* Loop through each HBH Ack on the message */
    for (i = 0; i < rt->ack_len/sizeof(rel_flood_hbh_ack); i++) {

        ack = (rel_flood_hbh_ack*) ((char*) rt + sizeof(rel_flood_tail) +
               i * sizeof(rel_flood_hbh_ack));

        src_id = ack->src;
        if (src_id < 1 || src_id > MAX_NODES) {
            Alarm(PRINT, "invalid src: %d\n", src_id);
            return NO_ROUTE;
        }
       
        dst_id = ack->dest;
        if (dst_id < 1 || dst_id > MAX_NODES) {
            Alarm(PRINT, "invalid dst: %d\n", dst_id);
            return NO_ROUTE;
        }

        fb = &FB->flow[src_id][dst_id];
        progress = 0;

        /* Make sure this hop-by-hop acknowledgement is for the current
         * epoch we have for this flow */
        if (fb->src_epoch != ack->src_epoch)
            continue;

        /* Update our view of this ngbr's sow for this flow only if it
         * increased */
        if (rfldata->ns_matrix.flow_sow[src_id][dst_id] < ack->sow) 
            rfldata->ns_matrix.flow_sow[src_id][dst_id] = ack->sow;

            /* Can we now send more messages to this neighbor since 
             * their window has space? */

        /* Update our view of this ngbr's aru for this flow only if it
         * increased */
        if (rfldata->ns_matrix.flow_aru[src_id][dst_id] < ack->aru) {
           
            /* Do not allow HBH acks for max unsigned long long because it will
                  cause a wrap-around issue */
            if (ack->aru == ULLONG_MAX) 
                ack->aru = ULLONG_MAX - 1;
            
            rfldata->ns_matrix.flow_aru[src_id][dst_id] = ack->aru;

            /* If the next msg to send to this neighbor is older than what they
             * already have, move it up */
            idx = fb->next_seq[last_hop_index] % MAX_MESS_PER_FLOW;
            if (Conf_Rel.HBH_Opt == 1 && fb->next_seq[last_hop_index] <= ack->aru) {
                while (fb->next_seq[last_hop_index] < fb->head_seq &&
                        (fb->status[idx][last_hop_index] == NEW_SENT ||
                         fb->status[idx][last_hop_index] == RESTAMPED_SENT ||
                          (fb->status[idx][last_hop_index] == NEW_UNSENT &&
                           fb->next_seq[last_hop_index] <= ack->aru) ) )
                {
                    if (fb->status[idx][last_hop_index] == NEW_UNSENT)
                        fb->status[idx][last_hop_index] = NEW_SENT;
                    fb->next_seq[last_hop_index]++;
                    idx = fb->next_seq[last_hop_index] % MAX_MESS_PER_FLOW;
                }
            }

            /* Only advance SOW (and make progress) if HBH_Advance == 1 */
            if (Conf_Rel.HBH_Advance == 1) {
            
                /* We must calculate what we can move our own sow
                 * for this flow up to */
                min = fb->head_seq - 1;
                for( j = 1; j <= Degree[My_ID]; j++) {
                    if (RF_Edge_Data[j].ns_matrix.flow_aru[src_id][dst_id] < min)
                        min = RF_Edge_Data[j].ns_matrix.flow_aru[src_id][dst_id];
                    if (Conf_Rel.HBH_Opt == 0 && fb->next_seq[j] - 1 < min)
                        min = fb->next_seq[j] - 1;
                }

                /* Are we about to move up our own SOW and thus make progress? */
                if (fb->sow <= min) {
                    progress = 1;
                    RF_State_Change = 1;
                }

                /* Move up our own sow and clean up memory */
                while (fb->sow <= min) { 
                    index = fb->sow % MAX_MESS_PER_FLOW;
                    if (fb->msg[index] != NULL) {
                        /* printf("Discarding message, location #5\n"); */
                        Cleanup_Scatter(fb->msg[index]);
                        fb->msg[index] = NULL;
                        for (ngbr = 1; ngbr <= Degree[My_ID]; ngbr++)
                            fb->status[index][ngbr] = EMPTY;
                        fb->num_paths[index] = 0;
                    }
                    fb->sow++;
                    hbh_cleared[src_id][dst_id]++;
                }

                /* Check if we made progress and things have become unblocked */
                if (progress == 1 && Sess_List[dst_id].size > 0 && src_id == My_ID)
                    E_queue(Reliable_Flood_Resume_Sessions, dst_id, NULL, zero_timeout);

                for (j = 1; j <= Degree[My_ID]; j++) {
                    /* If our sow moved up past an out of date next_seq index,
                    * move next_seq up */
                    /* TODO: Does this need to change because of recovering
                     * a neighboring node? */
                    if (fb->next_seq[j] < fb->sow)
                        fb->next_seq[j] = fb->sow;
                    while (fb->next_seq[j] < fb->head_seq &&
                           (fb->status[fb->next_seq[j] % MAX_MESS_PER_FLOW][j] == NEW_SENT ||
                            fb->status[fb->next_seq[j] % MAX_MESS_PER_FLOW][j] == RESTAMPED_SENT))
                    {
                        fb->next_seq[j]++;
                    }

                    /* Note that the state has changed, queue it to be sent
                     * to neighbor. */
                    ngbr_data = &RF_Edge_Data[j];
                    if (progress == 1 &&
                            ngbr_data->unsent_state[src_id][dst_id] == 0)
                    {
                        ngbr_data->unsent_state[src_id][dst_id] = 1;
                        temp_fq = (Flow_Queue *) new (FLOW_QUEUE_NODE);
                        if (temp_fq == NULL)
                            Alarm(EXIT, "Reliable_Flood_Process_Data(): Cannot"
                                "allocate Flow Queue Node for unsent_state.\r\n");
                        temp_fq->src_id = src_id;
                        temp_fq->dest_id = dst_id;
                        temp_fq->next = NULL;
                        ngbr_data->hbh_unsent_tail->next = temp_fq;
                        ngbr_data->hbh_unsent_tail = temp_fq;
                        ngbr_data->unsent_state_count++;
                    }
                }
            }
        }
        
        /* If the flow just became unblocked due to this ack, and
         * it wasn't in either the urgent queue or the normal queue,
         * then add it back to the normal queue. */
        idx = fb->next_seq[last_hop_index] % MAX_MESS_PER_FLOW;
        if (rfldata->in_flow_queue[src_id][dst_id] == 0 && 
            fb->next_seq[last_hop_index] <
            rfldata->ns_matrix.flow_sow[src_id][dst_id] + MAX_MESS_PER_FLOW && 
            fb->next_seq[last_hop_index] < fb->head_seq && 
            MultiPath_Neighbor_On_Path((unsigned char*)(
                        fb->msg[idx]->elements[fb->msg[idx]->num_elements-2].buf +
                                sizeof(rel_flood_header)), last_hop_index)
           )
        {
            /* if (My_ID == 11 && last_hop_index == 1)
                printf("\tNOOOO. Case C. next_seq[1] = %lu, status = %d, head = %lu\n",
                            fb->next_seq[last_hop_index], 
                            fb->status[fb->next_seq[last_hop_index]%MAX_MESS_PER_FLOW][last_hop_index], 
                            fb->head_seq); */
            rfldata->in_flow_queue[src_id][dst_id] = 1;
            temp_fq = (Flow_Queue *) new (FLOW_QUEUE_NODE);
            if (temp_fq == NULL)
                Alarm(EXIT, "Reliable_Flood_Process_Data(): Cannot allocate"
                            "Flow Queue Node for in_flow_queue.\r\n");
            temp_fq->src_id = src_id;
            temp_fq->dest_id = dst_id;
            temp_fq->penalty = 1;
            temp_fq->next = NULL;
            rfldata->norm_tail->next = temp_fq;
            rfldata->norm_tail = temp_fq;
        }
    }

    return BUFF_OK;
}


/***********************************************************/
/* void Reliable_Flood_Gen_E2E  (int mode, void *dummy)    */
/*                                                         */
/* Prepares an E2E ack to be sent from this destination    */
/*   on all outgoing links                                 */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* mode:        mode of the link the packet arrived on     */
/*              -1 imples to make E2E, but not send it     */
/* dummy:       not used                                   */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/
void Reliable_Flood_Gen_E2E(int mode, void *dummy)
{
    int i;
    unsigned char progress = 0;
    Rel_Flood_Link_Data *rfldata;
    sp_time now;
    stdit it;

    UNUSED(dummy);

    if (Conf_Rel.E2E_Opt == 0 && E2E_Stop == 1)  
        return;

    if (Initial_E2E == 0) {
        for (i = 1; i <= MAX_NODES; i++) {
            if (E2E[My_ID].cell[i].src_epoch == FB->flow[i][My_ID].src_epoch &&
                E2E[My_ID].cell[i].aru < FB->flow[i][My_ID].head_seq - 1) 
            {
                E2E[My_ID].cell[i].aru = FB->flow[i][My_ID].head_seq - 1;
                progress = 1;
            }
            else if (E2E[My_ID].cell[i].src_epoch == FB->flow[i][My_ID].src_epoch &&
                     E2E[My_ID].cell[i].aru > FB->flow[i][My_ID].head_seq - 1)
                Alarm(PRINT, "Reliable_Flood_Gen_E2E(): our aru (%"PRIu64") has"
                            "gone down since the last E2E (%"PRIu64")! Uh oh."
                            "\r\n", FB->flow[i][My_ID].head_seq - 1, 
                            E2E[My_ID].cell[i].aru);
        }
        if (progress == 0) {
            return;
        }
    }

    /* Dano - uglyish hack. */
    /* The first time through, we need to not enqueue things because mode is -1. */
    if (Initial_E2E == 1) {
        Initial_E2E = 0;
    }
    if (mode == -1)
        return;
       
    E_queue(Reliable_Flood_Gen_E2E, mode, NULL, rel_fl_e2e_ack_timeout);

    for (i = 1; i <= Degree[My_ID]; i++) {
        
        rfldata = &RF_Edge_Data[i];
        if (rfldata->e2e_stats[My_ID].unsent == 1)
            continue;

        rfldata->e2e_stats[My_ID].unsent = 1;
        now = E_get_time();
        stdskl_insert(&rfldata->e2e_skl, &it, &now, &My_ID, STDFALSE);
        E_queue(Reliable_Flood_E2E_Event, mode, (void*)rfldata, zero_timeout);
    }
}

/***********************************************************/
/* void Reliable_Flood_Neighbor_Transfer( int mode,        */
/*                                           Link *lk )    */
/*                                                         */
/* This function is to be called by the lower level if it  */
/*   detects that the other side of the link has lost all  */
/*   its state, possibly due to a benign failure. This     */
/*   function then sets up all end-to-end acks to be sent  */
/*   (again) to this neighbor, but still no sooner than    */
/*   rel_fl_e2e_ack_timeout.                               */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* Node next_hop : the neighbor who needs the transfer     */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/
void Reliable_Flood_Neighbor_Transfer  (int mode, Link *lk)
{
    int32u                   s, d, creator, idx, ngbr_index = 0;
    int64u                   i;
    unsigned char            progress;
    Flow_Buffer             *fb;
    Flow_Queue              *temp_fq;
    int32u                   Neighbor_IP;
    Rel_Flood_Link_Data     *rfldata;
    sp_time                  now, min_to;
    stdit                    it;
   
    now = E_get_time();

    Neighbor_IP = lk->leg->remote_interf->net_addr;
    
    Alarm(PRINT, "*** INITIATING STATE TRANSFER TO "IPF" ***\n",
            IP(Neighbor_IP)); 
    /* Alarm(PRINT, "\tmy_sow = %"PRIu64",   my_aru = %"PRIu64",   "
            "E2E_aru = %"PRIu64"\n", FB->flow[3][8].sow, 
            FB->flow[3][8].head_seq - 1, E2E[8].aru[3]); */

    for (i = 1; i <= Degree[My_ID]; i++) {
        if (Neighbor_Addrs[My_ID][i] == Neighbor_IP) {
            ngbr_index = i;
            break;
        }
    }
    assert(ngbr_index >= 1 && ngbr_index <= Degree[My_ID]);
    rfldata = &RF_Edge_Data[ngbr_index];

    /* Link Status Change Neighbor Transfer */
    progress = 0;
    for (creator = 1; creator <= MAX_NODES; creator++) {
        if (rfldata->status_change_stats[creator].unsent == 0 && 
                creator != Neighbor_IDs[My_ID][ngbr_index] &&
                Status_Change[creator].epoch > 0)
        {
            progress = 1; 
            Alarm(DEBUG, "Queueing Status_Change for creator %u\n", creator);
            rfldata->status_change_stats[creator].unsent = 1;
            rfldata->status_change_stats[creator].timeout = 
                E_add_time(rfldata->status_change_stats[creator].timeout, 
                            status_change_timeout);
            
            stdskl_insert(&rfldata->status_change_skl, &it,
                    &rfldata->status_change_stats[creator].timeout, 
                    &creator, STDFALSE);
        }
    }

    if (!stdskl_empty(&rfldata->status_change_skl) && progress == 1) {
        stdskl_begin(&rfldata->status_change_skl, &it); 
        min_to = *(sp_time*) stdskl_it_key(&it);

        if (E_compare_time(min_to, now) <= 0) 
            E_queue(Status_Change_Event, mode, (void*)rfldata,
                    zero_timeout); 
        else 
            E_queue(Status_Change_Event, mode, (void*)rfldata,
                    E_sub_time(min_to, now));
    }

    /* E2E Neighbor Transfer */
    progress = 0;
    for (d = 1; d <= MAX_NODES; d++) {

        /* TODO: figure out if we should send that neighbor it's own e2e */
        /* Last condition checks if a valid E2E is present */
        if (rfldata->e2e_stats[d].unsent == 0 && d != Neighbor_IDs[My_ID][ngbr_index] 
                && E2E[d].dest == d ) {
            progress = 1;
            Alarm(DEBUG, "Queueing E2E for destination %d\n", d);
            rfldata->e2e_stats[d].unsent = 1;
            rfldata->e2e_stats[d].timeout = 
                E_add_time(rfldata->e2e_stats[d].timeout, 
                            rel_fl_e2e_ack_timeout);
            
            stdskl_insert(&rfldata->e2e_skl, &it,
                    &rfldata->e2e_stats[d].timeout, &d, STDFALSE);

            /* block flows for E2E to go first */
            for (s = 1; s <= MAX_NODES; s++)
                rfldata->e2e_stats[d].flow_block[s] = 1;
        }
        /* else if (rfldata->e2e_stats[d].unsent == 1) {
            printf("\t\t~~~~~Sanity Check~~~~~ e2e_ready = %d, in queue = %d\n",
                rfldata->e2e_ready, E_in_queue(Reliable_Flood_E2E_Event, mode, (void*)rfldata));
        } */

        for (s = 1; s <= MAX_NODES; s++) {
            
            fb = &FB->flow[s][d];

            for (i = fb->sow; i < fb->head_seq; i++) {
                if (fb->status[i % MAX_MESS_PER_FLOW][ngbr_index] == NEW_SENT)
                    fb->status[i % MAX_MESS_PER_FLOW][ngbr_index] = NEW_UNSENT;
                else if (fb->status[i % MAX_MESS_PER_FLOW][ngbr_index] == RESTAMPED_SENT)
                    fb->status[i % MAX_MESS_PER_FLOW][ngbr_index] = RESTAMPED_UNSENT;
            }

            /* fb->next_seq[ngbr_index] = MAX(fb->sow, E2E[d].cell[s].aru + 1); */
            fb->next_seq[ngbr_index] = fb->sow;
            /* while (fb->next_seq[ngbr_index] < fb->head_seq &&
                   (fb->status[fb->next_seq[ngbr_index] % MAX_MESS_PER_FLOW][ngbr_index] == NEW_SENT ||
                    fb->status[fb->next_seq[ngbr_index] % MAX_MESS_PER_FLOW][ngbr_index] == RESTAMPED_SENT))
            {
                fb->next_seq[ngbr_index]++;
            } */

            idx = fb->next_seq[ngbr_index] % MAX_MESS_PER_FLOW; 
            if (rfldata->in_flow_queue[s][d] == 0 && 
                    fb->next_seq[ngbr_index] < fb->head_seq &&
                    MultiPath_Neighbor_On_Path((unsigned char*)(
                        fb->msg[idx]->elements[fb->msg[idx]->num_elements-2].buf +
                                sizeof(rel_flood_header)), ngbr_index)
               ) 
            {
                rfldata->in_flow_queue[s][d] = 1;
                temp_fq = (Flow_Queue *) new (FLOW_QUEUE_NODE);
                if (temp_fq == NULL)
                    Alarm(EXIT, "Reliable_Flood_Neighbor_Transfer: Can't allocate"
                                "Flow Queue Node for in_flow_queue.\r\n");
                temp_fq->src_id = s;
                temp_fq->dest_id = d;
                temp_fq->penalty = 1;
                temp_fq->next = NULL;
                rfldata->urgent_tail->next = temp_fq;
                rfldata->urgent_tail = temp_fq;
            }
        }
    }

    if (!stdskl_empty(&rfldata->e2e_skl) && progress == 1) {
        stdskl_begin(&rfldata->e2e_skl, &it); 
        min_to = *(sp_time*) stdskl_it_key(&it);

        if (E_compare_time(min_to, now) <= 0) 
            E_queue(Reliable_Flood_E2E_Event, mode, (void*)rfldata,
                    zero_timeout); 
        else 
            E_queue(Reliable_Flood_E2E_Event, mode, (void*)rfldata,
                    E_sub_time(min_to, now));
    }
} 

/************************************************************/
/* void Reliable_Flood_E2E_Event(int mode, void *ngbr_data) */
/*                                                          */
/* Event that sets e2e_ready flag and requests resources    */
/*   on the link of type mode towards the neighbor          */
/*   defined by ngbr_data                                   */
/*                                                          */
/*                                                          */
/* Arguments                                                */
/*                                                          */
/* mode:        mode of the link the packet arrived on      */
/* ngbr_data:   link data toward this neighbor              */
/*                                                          */
/*                                                          */
/* Return Value                                             */
/*                                                          */
/* NONE                                                     */
/*                                                          */
/************************************************************/
void Reliable_Flood_E2E_Event  (int mode, void *ngbr_data)
{
    int i, ngbr_index, ret;
    Node *nd;
    stdit it;
    Rel_Flood_Link_Data *rfldata;

    rfldata = (Rel_Flood_Link_Data*)ngbr_data;
    assert(rfldata != NULL);
    
    stdskl_begin(&rfldata->e2e_skl, &it); 
    if (stdskl_is_end(&rfldata->e2e_skl, &it)) {
        Alarm(DEBUG, "Reliable_Flood_E2E_Event: no E2E to send at this time\r\n");
        return;
    }

    /* Verify that this link data goes to a valid neighbor */
    for (i = 1; i <= Degree[My_ID]; i++) {
        if (rfldata == &RF_Edge_Data[i])
            break;
    }
    assert(i <= Degree[My_ID]);
    ngbr_index = i;

    /* Find the node on the other side of this link */
    stdhash_find(&All_Nodes, &it, &Neighbor_Addrs[My_ID][ngbr_index]);
    if (stdhash_is_end(&All_Nodes, &it))
        return;
    nd = *((Node **)stdhash_it_val(&it));

    rfldata->e2e_ready = 1;
    Alarm(DEBUG, "E2E requesting resources to "IPF"\n", IP(nd->nid));
    ret = Request_Resources((IT_RELIABLE_ROUTING >> ROUTING_BITS_SHIFT),
                        nd, mode, &Reliable_Flood_Send_One);
    if (ret == 0)
        E_queue(Reliable_Flood_E2E_Event, mode, ngbr_data, one_sec_timeout);
}


/************************************************************/
/* void Reliable_Flood_SAA_Event(int mode, void *ngbr_data) */
/*                                                          */
/* Event that (potentially) resets SAA event enqueing and   */
/*   requests resources on the link of type mode towards    */
/*   the neighbor defined by ngbr_data                      */
/*                                                          */
/*                                                          */
/* Arguments                                                */
/*                                                          */
/* mode:        mode of the link the packet arrived on      */
/* ngbr_data:   link data toward this neighbor              */
/*                                                          */
/*                                                          */
/* Return Value                                             */
/*                                                          */
/* NONE                                                     */
/*                                                          */
/************************************************************/
void Reliable_Flood_SAA_Event  (int mode, void *ngbr_data)
{
    int i, ngbr_index;
    Node *nd;
    stdit it;
    Rel_Flood_Link_Data *rfldata;

    rfldata = (Rel_Flood_Link_Data*)ngbr_data;
    assert(rfldata != NULL);

    /* Verify that this link data goes to a valid neighbor */
    for (i = 1; i <= Degree[My_ID]; i++) {
        if (rfldata == &RF_Edge_Data[i])
            break;
    }
    assert(i <= Degree[My_ID]);
    ngbr_index = i;
    
    /* Check if we should reset the SAA to initial state */
    if (rfldata->saa_trigger == 0) {
        rfldata->saa_trigger = Conf_Rel.SAA_Threshold - 1;
        return;
    }
  
    /* Find the node on the other side of this link */
    stdhash_find(&All_Nodes, &it, &Neighbor_Addrs[My_ID][ngbr_index]);
    if (stdhash_is_end(&All_Nodes, &it))
        return;
    nd = *((Node **)stdhash_it_val(&it));

    Request_Resources((IT_RELIABLE_ROUTING >> ROUTING_BITS_SHIFT),
                        nd, mode, &Reliable_Flood_Send_One);
}


/***********************************************************/
/* int Reliable_Flood_Send_One  (Node *next_hop, int mode) */
/*                                                         */
/* Sends exactly one (or none) packets to the neighbor     */
/*   indicated by next_hop. This function is also          */
/*   the one that is called by the lower level as a        */
/*   call-back function.                                   */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* next_hop:    neighbor node to which to send to          */
/* mode:        mode of the link the packet arrived on     */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* 1 - if a packet was sent                                */
/* 0 - otherwise                                           */
/*                                                         */
/***********************************************************/
int Reliable_Flood_Send_One( Node *next_hop, int mode )
{
    int i, ngbr_index = 0, ret = 0;
    int32u Neighbor_IP;
    Rel_Flood_Link_Data *rfldata;

    if (next_hop == NULL) {
        Alarm(PRINT, "Reliable_Flood_Send_One(): next_hop was NULL - \
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
    rfldata = &RF_Edge_Data[ngbr_index];
    
    if (rfldata->status_change_ready) {
        ret = Send_Status_Change(next_hop, ngbr_index, mode);
    }
    else if (rfldata->e2e_ready) {
        /* printf("Trying to send E2E in send_one to "IPF"\n",
                IP(next_hop->nid)); */
        ret = Reliable_Flood_Send_E2E(next_hop, ngbr_index, mode);
    }
    else if ((ret = Reliable_Flood_Send_Data(next_hop, ngbr_index, mode)));
    else if (rfldata->unsent_state_count > 0 && 
            !E_in_queue(Reliable_Flood_SAA_Event, mode, (void*)rfldata))
        ret = Reliable_Flood_Send_SAA(next_hop, ngbr_index, mode);
    return ret;
}


/************************************************************/
/* int Reliable_Flood_Send_E2E (Node *next_hop,             */
/*                              int ngbr_index, int mode)   */
/*                                                          */
/* Sends one expired E2E ack to the neighbor specified      */
/*   by ngbr_data on the link protocol define by mode       */
/*                                                          */
/*                                                          */
/* Arguments                                                */
/*                                                          */
/* next_hop:    neighbor node to which to send to           */
/* ngbr_index:  index of neighbor in data structures        */
/* mode:        mode of the link to send E2E on             */
/*                                                          */
/*                                                          */
/* Return Value                                             */
/*                                                          */
/* 0 - Error Case (no packet was sent)                      */
/* num_bytes_sent - E2E Packet was sent via lower level     */
/*                                                          */
/************************************************************/
int Reliable_Flood_Send_E2E (Node *next_hop, int ngbr_index, int mode)
{
    Rel_Flood_Link_Data *rfldata;
    packet_header       *phdr;
    udp_header          *hdr;
    rel_flood_header    *r_hdr;
    rel_flood_tail      *rt;
    rel_flood_e2e_ack   *e2e;
    Flow_Queue          *temp_fq;
    Flow_Buffer         *fb;
    int16u              ack_inc = 0, msg_len = 0, packets = 0, last_pkt_space = 0;
    int32u              index;
    int                 ret, i, d;
    sp_time             now, min_to;
    stdit               it;
    unsigned char       *sign_start, crypto_fail = 0;
    sys_scatter         *scat;
    unsigned int        sign_len;
    EVP_MD_CTX          *md_ctx;

    assert(ngbr_index >= 1 && ngbr_index <= Degree[My_ID]);
    rfldata = &RF_Edge_Data[ngbr_index];

    stdskl_begin(&rfldata->e2e_skl, &it); 
    if (stdskl_is_end(&rfldata->e2e_skl, &it)) {
        Alarm(PRINT, "Reliable_Flood_Send_E2E: no E2E to send at this time\r\n");
        return 0;
    }

    /* Create the empty scatter */
    if ((scat = (sys_scatter*) new_ref_cnt(SYS_SCATTER)) == NULL)
        Alarm(EXIT, "Reliable_Flood_Send_E2E: Could not allocate sys_scatter\r\n");
    scat->num_elements = 0;

    /* Create element for Packet_Header */
    if ((scat->elements[scat->num_elements].buf = new_ref_cnt(PACK_HEAD_OBJ)) == NULL)
        Alarm(EXIT, "Reliable_Flood_Send_E2E: Could not allocate packet_header\r\n");
    scat->elements[scat->num_elements].len = sizeof(packet_header);
    scat->num_elements++;

    /* Create element for UDP_Header and E2E Ack */
    if ((scat->elements[scat->num_elements].buf = new_ref_cnt(PACK_BODY_OBJ)) == NULL)
        Alarm(EXIT, "Reliable_Flood_Send_E2E: Could not allocate packet_body\r\n");
    scat->elements[scat->num_elements].len = sizeof(udp_header) + sizeof(rel_flood_e2e_ack);
    scat->num_elements++;

    /* Create element for Rel_Flood_Header and Signature */
    if ((scat->elements[scat->num_elements].buf = new_ref_cnt(PACK_BODY_OBJ)) == NULL)
        Alarm(EXIT, "Reliable_Flood_Send_E2E: Could not allocate packet_body\r\n");
    scat->elements[scat->num_elements].len = sizeof(rel_flood_header) + Rel_Signature_Len;
    scat->num_elements++;

    /* Create element for Rel_Flood_Tail and (potential) HBH Acks */
    if ((scat->elements[scat->num_elements].buf = new_ref_cnt(PACK_BODY_OBJ)) == NULL)
        Alarm(EXIT, "Reliable_Flood_Send_E2E: Could not allocate packet_body\r\n");
    scat->elements[scat->num_elements].len = sizeof(rel_flood_tail);
    scat->num_elements++;

    /* Spines header */
    phdr = (packet_header*) scat->elements[0].buf;
    phdr->type = Get_Link_Data_Type(mode);
    phdr->type = Set_endian(phdr->type);

    /* UDP header*/
    hdr = (udp_header*) scat->elements[1].buf;
    hdr->source = My_Address;
    hdr->dest = Neighbor_Addrs[My_ID][ngbr_index];
    hdr->source_port = 0;
    hdr->dest_port = 0;   /* By using port 0, won't be delivered to client */
    hdr->len = sizeof(rel_flood_e2e_ack);
    hdr->seq_no = 0;
    hdr->sess_id = 0;
    hdr->frag_num = 0;
    hdr->frag_idx = 0;
    hdr->ttl = 255;
    hdr->routing = (IT_RELIABLE_ROUTING >> ROUTING_BITS_SHIFT);

    e2e = (rel_flood_e2e_ack*)(scat->elements[1].buf + sizeof(udp_header));

    r_hdr = (rel_flood_header*) (scat->elements[scat->num_elements-2].buf);
    r_hdr->src = 0;
    r_hdr->dest = 0;
    r_hdr->seq_num = 0;
    r_hdr->type = REL_FLOOD_E2E;

    sign_start = (unsigned char*)(r_hdr) + sizeof(rel_flood_header);

    rt = (rel_flood_tail*) (scat->elements[scat->num_elements-1].buf);
    rt->ack_len = 0;

    now = E_get_time();
    d = *(int*) stdskl_it_val(&it);

    packets = Calculate_Packets_In_Message(scat, mode, &last_pkt_space);
    ack_inc = Reliable_Flood_Add_Acks(rt, ngbr_index, last_pkt_space);
    assert(ack_inc == rt->ack_len);
    scat->elements[scat->num_elements-1].len += ack_inc;

    if (My_ID == d) {
        /* RSA Sign */
        if (Conf_Rel.Crypto == 1) {
            md_ctx = EVP_MD_CTX_new();
            if (md_ctx==NULL) {
                Alarm(EXIT, "RF_Send_E2E: EVP_MD_CTX_new()  failed\r\n");
            }
            ret = EVP_SignInit(md_ctx, EVP_sha256()); 
            if (ret != 1) {
                Alarm(PRINT, "RF_Send_E2E: SignInit failed\r\n");
                crypto_fail = 1;
            }
        
            /* add the phdr->type */
            ret = EVP_SignUpdate(md_ctx, (unsigned char*)&phdr->type, sizeof(phdr->type));
            if (ret != 1) {
                Alarm(PRINT, "RF_Send_E2E: SignUpdate failed on phdr->type = %d\r\n", phdr->type);
                crypto_fail = 1;
            }

            /* add the e2e ack */
            ret = EVP_SignUpdate(md_ctx, (unsigned char*)&E2E[My_ID], 
                                sizeof(rel_flood_e2e_ack));
            if (ret != 1) {
                Alarm(PRINT, "RF_Send_E2E: SignUpdate failed on E2E Ack\r\n");
                crypto_fail = 1;
            }
            ret = EVP_SignFinal(md_ctx, (unsigned char*)E2E_Sig[My_ID], 
                                &sign_len, Priv_Key);
            if (ret != 1) {
                Alarm(PRINT, "RF_Send_E2E: SignFinal failed\r\n");
                crypto_fail = 1;
            }
            if (sign_len != Rel_Signature_Len) {
                Alarm(PRINT, "RF_Send_E2E: sign_len (%d) != Key_Len (%d)\r\n",
                                sign_len, Rel_Signature_Len);
                crypto_fail = 1;
            }

            EVP_MD_CTX_free(md_ctx);
        }
    }
    
    memcpy(e2e, &E2E[d], sizeof(rel_flood_e2e_ack));
    memcpy(sign_start, E2E_Sig[d], Rel_Signature_Len);

    for (i = 0; i < scat->num_elements; i++) 
        msg_len += scat->elements[i].len;

    if (crypto_fail == 0) {
        Alarm(DEBUG, "\tSending E2E for %d to "IPF"\r\n", d, IP(next_hop->nid));
        ret = Forward_Data(next_hop, scat, mode);
    }
    else
        ret = NO_ROUTE;

    Cleanup_Scatter(scat);
    
    if (ret == BUFF_EMPTY || ret == BUFF_OK) {
        Alarm(DEBUG, "Reliable_Flood_Send_E2E(): E2E forwarded successfully\r\n");
        rfldata->e2e_stats[d].unsent = 0;
        rfldata->e2e_stats[d].timeout = now;
        stdskl_erase(&rfldata->e2e_skl, &it);
        rfldata->e2e_ready = 0;
     
        for (i = 1; i <= MAX_NODES; i++) {
            rfldata->e2e_stats[d].flow_block[i] = 0;
            fb = &FB->flow[i][d];
            index = fb->next_seq[ngbr_index] % MAX_MESS_PER_FLOW;
            if (rfldata->in_flow_queue[i][d] == 0 && 
                    fb->next_seq[ngbr_index] < fb->head_seq && 
                    MultiPath_Neighbor_On_Path((unsigned char*)(
                        fb->msg[index]->elements[fb->msg[index]->num_elements-2].buf + 
                        sizeof(rel_flood_header)), ngbr_index)
                )
            {
                rfldata->in_flow_queue[i][d] = 1;
                temp_fq = (Flow_Queue *) new (FLOW_QUEUE_NODE);
                if (temp_fq == NULL)
                    Alarm(EXIT, "Reliable_Flood_Send_E2E(): Cannot allocate"
                                "Flow Queue Node for in_flow_queue.\r\n");
                temp_fq->src_id = i;
                temp_fq->dest_id = d;
                temp_fq->penalty = 1;
                temp_fq->next = NULL;
                rfldata->norm_tail->next = temp_fq;
                rfldata->norm_tail = temp_fq;
            }
        }
        if (ack_inc > 0) {
            rfldata->saa_trigger = 0;
            E_queue(Reliable_Flood_SAA_Event, (int)mode, (void*)rfldata, 
                        rel_fl_hbh_ack_timeout);             
        }
    }
    else { /* E2E failed to send, requeue for later */
        Alarm(PRINT, "Reliable_Flood_Send_E2E(): Send E2E Failed!\r\n");
        if (crypto_fail == 1)
            Alarm(PRINT, "\tCrypto failure- error in signing message\r\n");
        else
            Alarm(PRINT, "\tE2E forwarded, but failed at lower level with "
                        "ret = %d\r\n", ret);
        rfldata->e2e_stats[d].unsent = 1;
        rfldata->e2e_stats[d].timeout = E_add_time(now, rel_fl_e2e_ack_timeout);
        stdskl_erase(&rfldata->e2e_skl, &it);
        stdskl_insert(&rfldata->e2e_skl, &it, &rfldata->e2e_stats[d].timeout, &d, STDFALSE);
        rfldata->e2e_ready = 0;
        msg_len = 0;
    }
    
    /* Find when (if at all) to requeue E2E_Event function for */
    if (!stdskl_empty(&rfldata->e2e_skl)) {
        stdskl_begin(&rfldata->e2e_skl, &it); 
        min_to = *(sp_time*) stdskl_it_key(&it);
        if (E_compare_time(min_to, now) <= 0) 
            E_queue(Reliable_Flood_E2E_Event, mode, (void*)rfldata,
                    zero_timeout); 
        else 
            E_queue(Reliable_Flood_E2E_Event, mode, (void*)rfldata,
                    E_sub_time(min_to, now));
    }

    return msg_len;
}


/************************************************************/
/* int Reliable_Flood_Send_Data  (Node *next_hop,           */
/*                              int ngbr_index, int mode)   */
/*                                                          */
/* Sends exactly one (or none) packets to the neighbor      */
/*   indicated by next_hop.                                 */
/*                                                          */
/*                                                          */
/* Arguments                                                */
/*                                                          */
/* next_hop:    neighbor node to which to send to           */
/* ngbr_index:  index of neighbor in data structures        */
/* mode:        mode of the link to send E2E on             */
/*                                                          */
/*                                                          */
/* Return Value                                             */
/*                                                          */
/* num_bytes_sent - if a packet was sent                    */
/* 0 - otherwise                                            */
/*                                                          */
/************************************************************/
int Reliable_Flood_Send_Data( Node *next_hop, int ngbr_index, int mode )
{
    int64u              ngbr_aru, ngbr_sow;
    int16u              msg_len = 0, ack_inc = 0, packets = 0, last_pkt_space = 0;
    int                 i, ret, sent_one = 0, j, min, progress = 0;
    int32u              index, ngbr;
    Rel_Flood_Link_Data *rfldata, *ngbr_data;
    rel_flood_tail      *rt;
    Flow_Queue          *temp_fq, *progress_fq;
    Flow_Buffer         *fb;
    sys_scatter         *scat;
    unsigned char       *mask;

    assert(ngbr_index >= 1 && ngbr_index <= Degree[My_ID]);
    rfldata = &RF_Edge_Data[ngbr_index];
    
    while (!sent_one) {
        
        temp_fq = NULL;

        /* first, check the urgent flow queue */
        if (rfldata->urgent_head.next != NULL) {
            temp_fq = rfldata->urgent_head.next;
            temp_fq->penalty--;

            ngbr_aru = rfldata->ns_matrix.
                        flow_aru[temp_fq->src_id][temp_fq->dest_id];
            ngbr_sow = rfldata->ns_matrix.
                        flow_sow[temp_fq->src_id][temp_fq->dest_id];
            fb = &FB->flow[temp_fq->src_id][temp_fq->dest_id];
            index = fb->next_seq[ngbr_index] % MAX_MESS_PER_FLOW;

            /* if this flow hasn't finished paying its penalty or 
             * this flow towards this neighbor is blocked
             * or we don't have anything to send on this flow
             * towards this neighbor, or an End-to-end ack must
             * go first, or this node is the source and is still
             * waiting for a handshake to complete with this
             * destination, then move this node
             * to the normal queue.  OR... 
             * 
             * the last 5 lines are for K-paths. The first part assigns a 
             *    pointer to the packet to determine the client-given data
             *    length. Then, we check if the next packet for the flow toward
             *    this neighbor is marked on the packet's bitmask for this 
             *    neighbor. If not, move to the back of the queue */
            /* TODO: I think we need to add a condition here
             * to check if next_seq < ngbr_sow */
            if (temp_fq->penalty > 0 ||
                fb->next_seq[ngbr_index] >= ngbr_sow + MAX_MESS_PER_FLOW ||
                fb->head_seq <= fb->next_seq[ngbr_index] || 
                rfldata->e2e_stats[temp_fq->dest_id].
                    flow_block[temp_fq->src_id] == 1 ||
                (My_ID == temp_fq->src_id &&
                    Handshake_Complete[temp_fq->dest_id] == 0) ||
                !MultiPath_Neighbor_On_Path((unsigned char*)(
                    fb->msg[index]->elements[fb->msg[index]->num_elements-2].buf + 
                    sizeof(rel_flood_header)), ngbr_index)
               )
            {
                rfldata->urgent_head.next = rfldata->urgent_head.next->next;
                if(rfldata->urgent_tail == temp_fq)
                    rfldata->urgent_tail = &rfldata->urgent_head;
                /* move to back of normal queue */
                temp_fq->next = NULL;
                rfldata->norm_tail->next = temp_fq;
                rfldata->norm_tail = temp_fq;
                continue;
            }
        }
        /* next, check normal_head if the urgent was empty */
        else if (rfldata->norm_head.next != NULL) {
            temp_fq = rfldata->norm_head.next;
            temp_fq->penalty--;
            
            ngbr_aru = rfldata->ns_matrix.
                        flow_aru[temp_fq->src_id][temp_fq->dest_id];
            ngbr_sow = rfldata->ns_matrix.
                        flow_sow[temp_fq->src_id][temp_fq->dest_id];
            fb = &FB->flow[temp_fq->src_id][temp_fq->dest_id];
            index = fb->next_seq[ngbr_index] % MAX_MESS_PER_FLOW;
            
            /* if this flow hasn't finished paying its penalty or 
             * this flow towards this neighbor is blocked
             * or we don't have anything to send on this flow
             * towards this neighbor, or an End-to-end ack must
             * go first, or this node is the source and is still
             * waiting for a handshake to complete with this
             * destination, then delete this node. OR... 
             * 
             * the last 5 lines are for K-paths. The first part assigns a 
             *    pointer to the packet to determine the client-given data
             *    length. Then, we check if the next packet for the flow toward
             *    this neighbor is marked on the packet's bitmask for this 
             *    neighbor. If not, delete from normal queue */
            /* TODO: I think we need to add a condition here
             * to check if next_seq < ngbr_sow */
            if (temp_fq->penalty > 0) {
                rfldata->norm_head.next = rfldata->norm_head.next->next;
                if (rfldata->norm_head.next == NULL)
                    rfldata->norm_tail = &rfldata->norm_head;
                temp_fq->next = NULL;
                rfldata->norm_tail->next = temp_fq;
                rfldata->norm_tail = temp_fq;
                continue;

            }
            else if (fb->next_seq[ngbr_index] >= ngbr_sow + MAX_MESS_PER_FLOW ||
                fb->head_seq <= fb->next_seq[ngbr_index] || 
                rfldata->e2e_stats[temp_fq->dest_id].
                    flow_block[temp_fq->src_id] == 1 ||
                (My_ID == temp_fq->src_id &&
                    Handshake_Complete[temp_fq->dest_id] == 0) ||
                !MultiPath_Neighbor_On_Path((unsigned char*)(
                    fb->msg[index]->elements[fb->msg[index]->num_elements-2].buf + 
                    sizeof(rel_flood_header)), ngbr_index)
               )
            {
                /* printf("Failed to send a packet towards neighbor %d because: ", Neighbor_IDs[My_ID][ngbr_index]);
                if (fb->next_seq[ngbr_index] >= ngbr_sow + MAX_MESS_PER_FLOW)
                    printf("Case 1");
                else if (fb->head_seq <= fb->next_seq[ngbr_index])
                    printf("Case 2: head = %lu, next_seq = %lu", fb->head_seq, fb->next_seq[ngbr_index]);
                else if (rfldata->e2e_stats[temp_fq->dest_id].flow_block[temp_fq->src_id] == 1)
                    printf("Case 3");
                else if (My_ID == temp_fq->src_id && Handshake_Complete[temp_fq->dest_id] == 0)
                    printf("Case 4");
                else if (!MultiPath_Neighbor_On_Path((unsigned char*)(fb->msg[index]->elements[fb->msg[index]->num_elements-2].buf + sizeof(rel_flood_header)), ngbr_index))
                    printf("Case 5");
                printf("\n"); */
                rfldata->norm_head.next = rfldata->norm_head.next->next;
                if (rfldata->norm_head.next == NULL)
                    rfldata->norm_tail = &rfldata->norm_head;
                rfldata->in_flow_queue[temp_fq->src_id][temp_fq->dest_id] = 0;
                dispose(temp_fq);
                continue;
            }
        }
        /* else no flow has anything to send to this neighbor */
        else {
            return 0;
        }
            
        /* Now, we send the next message for this flow */
        fb = &FB->flow[temp_fq->src_id][temp_fq->dest_id];
        index = fb->next_seq[ngbr_index] % MAX_MESS_PER_FLOW;
        assert(fb->msg[index] != NULL);

        /* create a temporary sys_scatter for this data msg */
        if ((scat = new_ref_cnt(SYS_SCATTER)) == NULL)
            Alarm(EXIT, "Reliable_Flood_Send_Data: Cannot allocate sys_scatter\r\n");
        scat->num_elements = fb->msg[index]->num_elements;

        /* grab the static elements from the msg */
        for (i = 0; i < fb->msg[index]->num_elements - 1; i++) {
            scat->elements[i].buf = fb->msg[index]->elements[i].buf;
            scat->elements[i].len = fb->msg[index]->elements[i].len;
            msg_len += scat->elements[i].len;
        }

        /* replace the dynamic Hop-by-hop elements with a new element */
        if ((scat->elements[scat->num_elements-1].buf = new_ref_cnt(PACK_BODY_OBJ)) == NULL)
            Alarm(EXIT, "Reliable_Flood_Send_Data: Cannot allocate packet body\r\n");
        scat->elements[scat->num_elements-1].len = sizeof(rel_flood_tail);
        rt = (rel_flood_tail*)scat->elements[scat->num_elements-1].buf;
        rt->ack_len = 0;

        /* piggyback anything that needs to go on it and fix new length */
        packets = Calculate_Packets_In_Message(scat, mode, &last_pkt_space);
        ack_inc = Reliable_Flood_Add_Acks(rt, ngbr_index, last_pkt_space);
        assert(ack_inc == rt->ack_len);
        scat->elements[scat->num_elements-1].len += ack_inc;
        msg_len += scat->elements[scat->num_elements-1].len;

        ret = Forward_Data(next_hop, scat, mode);
        dec_ref_cnt(scat->elements[scat->num_elements-1].buf);
        dec_ref_cnt(scat);

        if (ret != BUFF_EMPTY && ret != BUFF_OK) {
            Alarm(PRINT, "Reliable_Flood_Send_Data(): got an invalid "
                         "return from Forward_Data = %d\r\n", ret);
            /* printf("SENDING DATA #%d FOR %d-%d TO "IPF"\n",
                       fb->next_seq[ngbr_index], temp_fq->src_id, 
                       temp_fq->dest_id, IP(Neighbor_Addrs[My_ID][ngbr_index])); */
            temp_fq->penalty++;
            return 0;
        }

        sent_one = 1;
        rfldata->total_pkts_sent++;

        if (ack_inc > 0) {
            rfldata->saa_trigger = 0;
            E_queue(Reliable_Flood_SAA_Event, (int)mode, (void*)rfldata, 
                        rel_fl_hbh_ack_timeout);             
        }

        /* cleanup the send_fair_queue */
        if (temp_fq == rfldata->urgent_head.next) {
            rfldata->urgent_head.next = rfldata->urgent_head.next->next;
            if(rfldata->urgent_tail == temp_fq)
                rfldata->urgent_tail = &rfldata->urgent_head;
        }
        else if (temp_fq == rfldata->norm_head.next) {
            rfldata->norm_head.next = rfldata->norm_head.next->next;
            if(rfldata->norm_tail == temp_fq)
                rfldata->norm_tail = &rfldata->norm_head;
        } 
        else { /* error */
            Alarm(PRINT, "Reliable_Flood_Send_Data(): send_fair_queue \
                            node not possible\r\n");
        }

        /* move to back of normal queue */
        temp_fq->penalty = packets;
        temp_fq->next = NULL;
        rfldata->norm_tail->next = temp_fq;
        rfldata->norm_tail = temp_fq;

        /* Update the status of this message toward the neighbor as sent */
        if (fb->status[index][ngbr_index] == NEW_UNSENT)
            fb->status[index][ngbr_index] = NEW_SENT;
        else if (fb->status[index][ngbr_index] == RESTAMPED_UNSENT) {
            /* printf("SENT seq %lu to %d. head = %lu, this_msg_status = %d, next_msg_status = %d\n", 
                    fb->next_seq[ngbr_index], Neighbor_IDs[My_ID][ngbr_index], fb->head_seq,
                    fb->status[index][ngbr_index], 
                    fb->status[(index+1)%MAX_MESS_PER_FLOW][ngbr_index]); */
            /* printf("seq %lu sent to %d and set to RESTAMPED_SENT - Case 3\n", 
                        fb->next_seq[ngbr_index], Neighbor_IDs[My_ID][ngbr_index]); */
            fb->status[index][ngbr_index] = RESTAMPED_SENT;
        }
        else {
            Alarm(PRINT, "Reliable_Flood_Send_Data(): Error - invalid status"
                            " (%d) of message %lu toward neighbor %d, head = %lu\r\n", 
                            fb->status[index][ngbr_index], fb->next_seq[ngbr_index], 
                            ngbr_index, fb->head_seq);
            mask = (unsigned char*)(fb->msg[index]->elements[fb->msg[index]->num_elements-2].buf + 
                                      sizeof(rel_flood_header));
            printf("mask = %016llx\n", *(long long unsigned int*)mask);
            printf("Next_Seq: ");
            for (ngbr = 1; ngbr <= Degree[My_ID]; ngbr++)
                printf("  [%d] = %lu", ngbr, (long unsigned) fb->next_seq[ngbr]);
            printf("\n");
        }

        while (fb->next_seq[ngbr_index] < fb->head_seq &&
               (fb->status[fb->next_seq[ngbr_index] % MAX_MESS_PER_FLOW][ngbr_index] == NEW_SENT ||
                fb->status[fb->next_seq[ngbr_index] % MAX_MESS_PER_FLOW][ngbr_index] == RESTAMPED_SENT))
        {
            fb->next_seq[ngbr_index]++;
        }

        /* Possibly move up the window for this flow if HBH_Opt is off */
        if (Conf_Rel.HBH_Advance == 1 && Conf_Rel.HBH_Opt == 0) {
        
            /* We must calculate what we can move our own sow
             * for this flow up to */
            min = fb->head_seq - 1;
            for( j = 1; j <= Degree[My_ID]; j++) {
                if (RF_Edge_Data[j].ns_matrix.flow_aru[temp_fq->src_id][temp_fq->dest_id] < min)
                    min = RF_Edge_Data[j].ns_matrix.flow_aru[temp_fq->src_id][temp_fq->dest_id];
                if (fb->next_seq[j] - 1 < min)
                    min = fb->next_seq[j] - 1;
            }

            /* Are we about to move up our own SOW and thus make progress? */
            if (fb->sow <= min) {
                progress = 1;
            }

            /* Move up our own sow and clean up memory */
            while (fb->sow <= min) { 
                index = fb->sow % MAX_MESS_PER_FLOW;
                if (fb->msg[index] != NULL) {
                    Cleanup_Scatter(fb->msg[index]);
                    fb->msg[index] = NULL;
                    for (ngbr = 1; ngbr <= Degree[My_ID]; ngbr++)
                        fb->status[index][ngbr] = EMPTY;
                    fb->num_paths[index] = 0;
                }
                fb->sow++;
                hbh_cleared[temp_fq->src_id][temp_fq->dest_id]++;
            }

            /* Check if we made progress and things have become unblocked */
            if (progress == 1 && Sess_List[temp_fq->dest_id].size > 0 &&
                    temp_fq->src_id == My_ID)
                E_queue(Reliable_Flood_Resume_Sessions, temp_fq->dest_id, NULL, zero_timeout);

            for (j = 1; j <= Degree[My_ID]; j++) {
                /* If our sow moved up past an out of date next_seq index,
                * move next_seq up */
                if (fb->next_seq[j] < fb->sow)
                    fb->next_seq[j] = fb->sow;
                while (fb->next_seq[j] < fb->head_seq &&
                       (fb->status[fb->next_seq[j] % MAX_MESS_PER_FLOW][j] == NEW_SENT ||
                        fb->status[fb->next_seq[j] % MAX_MESS_PER_FLOW][j] == RESTAMPED_SENT))
                {
                    fb->next_seq[j]++;
                }

                /* Note that the state has changed, queue it to be sent
                 * to neighbor. */
                ngbr_data = &RF_Edge_Data[j];

                if (progress == 1)
                    ngbr_data->saa_trigger++;

                if (progress == 1 &&
                        ngbr_data->unsent_state[temp_fq->src_id][temp_fq->dest_id] == 0)
                {
                    ngbr_data->unsent_state[temp_fq->src_id][temp_fq->dest_id] = 1;
                    progress_fq = (Flow_Queue *) new (FLOW_QUEUE_NODE);
                    if (progress_fq == NULL)
                        Alarm(EXIT, "Reliable_Flood_Send_Data(): Cannot"
                            "allocate Flow Queue Node for unsent_state.\r\n");
                    progress_fq->src_id = temp_fq->src_id;
                    progress_fq->dest_id = temp_fq->dest_id;
                    progress_fq->next = NULL;
                    ngbr_data->hbh_unsent_tail->next = progress_fq;
                    ngbr_data->hbh_unsent_tail = progress_fq;
                    ngbr_data->unsent_state_count++;
                }
                if (!E_in_queue(Reliable_Flood_SAA_Event, (int)mode, (void*)ngbr_data))
                        E_queue(Reliable_Flood_SAA_Event, (int)mode, (void*)ngbr_data, 
                            rel_fl_hbh_ack_timeout);             
            }
        }
    }
    
    return msg_len;
}


/************************************************************/
/* int Reliable_Flood_Send_SAA (Node *next_hop,             */
/*                              int ngbr_index, int mode)   */
/*                                                          */
/* Sends a standalone ACK to the neighbor specified in      */
/*   the ngbr_data on the link protocol define by mode      */
/*                                                          */
/*                                                          */
/* Arguments                                                */
/*                                                          */
/* next_hop:    neighbor node to which to send to           */
/* ngbr_index:  index of neighbor in data structures        */
/* mode:        mode of the link to send E2E on             */
/*                                                          */
/*                                                          */
/* Return Value                                             */
/*                                                          */
/* num_bytes_sent - if a packet was sent                    */
/* 0 - otherwise                                            */
/*                                                          */
/************************************************************/
int Reliable_Flood_Send_SAA (Node *next_hop, int ngbr_index, int mode)
{
    Rel_Flood_Link_Data *rfldata;
    udp_header          *hdr;
    rel_flood_header    *r_hdr;
    rel_flood_tail      *rt;
    int16u              ack_inc = 0, msg_len = 0, packets = 0, last_pkt_space = 0;
    int                 i, ret;
    sys_scatter         *scat;
  
    assert(ngbr_index >= 1 && ngbr_index <= Degree[My_ID]);
    rfldata = &RF_Edge_Data[ngbr_index];

    /* Create the empty scatter */
    if ((scat = (sys_scatter*) new_ref_cnt(SYS_SCATTER)) == NULL)
        Alarm(EXIT, "Reliable_Flood_Send_E2E: Could not allocate sys_scatter\r\n");
    scat->num_elements = 0;

    /* Create element for Packet_Header */
    if ((scat->elements[scat->num_elements].buf = new_ref_cnt(PACK_HEAD_OBJ)) == NULL)
        Alarm(EXIT, "Reliable_Flood_Send_E2E: Could not allocate packet_header\r\n");
    scat->elements[scat->num_elements].len = sizeof(packet_header);
    scat->num_elements++;

    /* Create element for UDP_Header */
    if ((scat->elements[scat->num_elements].buf = new_ref_cnt(PACK_BODY_OBJ)) == NULL)
        Alarm(EXIT, "Reliable_Flood_Send_E2E: Could not allocate packet_body\r\n");
    scat->elements[scat->num_elements].len = sizeof(udp_header);
    scat->num_elements++;

    /* Create element for Rel_Flood_Header */
    if ((scat->elements[scat->num_elements].buf = new_ref_cnt(PACK_BODY_OBJ)) == NULL)
        Alarm(EXIT, "Reliable_Flood_Send_E2E: Could not allocate packet_body\r\n");
    scat->elements[scat->num_elements].len = sizeof(rel_flood_header);
    scat->num_elements++;

    /* Create element for Rel_Flood_Tail and (potential) HBH Acks */
    if ((scat->elements[scat->num_elements].buf = new_ref_cnt(PACK_BODY_OBJ)) == NULL)
        Alarm(EXIT, "Reliable_Flood_Send_E2E: Could not allocate packet_body\r\n");
    scat->elements[scat->num_elements].len = sizeof(rel_flood_tail);
    scat->num_elements++;

    hdr = (udp_header*) scat->elements[1].buf;
    hdr->source = My_Address;
    hdr->dest = Neighbor_Addrs[My_ID][ngbr_index];
    hdr->source_port = 0;
    hdr->dest_port = 0;   /* By using port 0, won't be delivered to client */
    hdr->len = 0;
    hdr->seq_no = 0;
    hdr->sess_id = 0;
    hdr->frag_num = 0;
    hdr->frag_idx = 0;
    hdr->ttl = 255;
    hdr->routing = (IT_RELIABLE_ROUTING >> ROUTING_BITS_SHIFT);

    r_hdr = (rel_flood_header*) scat->elements[scat->num_elements-2].buf;
    r_hdr->src = 0;
    r_hdr->dest = 0;
    r_hdr->seq_num = 0;
    r_hdr->type = REL_FLOOD_SAA;

    rt = (rel_flood_tail*) scat->elements[scat->num_elements-1].buf;
    rt->ack_len = 0;

    packets = Calculate_Packets_In_Message(scat, mode, &last_pkt_space);
    ack_inc = Reliable_Flood_Add_Acks(rt, ngbr_index, last_pkt_space);
    assert(ack_inc == rt->ack_len);
    scat->elements[scat->num_elements-1].len += ack_inc;

    for (i = 0; i < scat->num_elements; i++)
        msg_len += scat->elements[i].len;

    ret = Forward_Data(next_hop, scat, mode);
    Cleanup_Scatter(scat);

    if (ret != BUFF_EMPTY && ret != BUFF_OK) {
        Alarm(DEBUG, "Reliable_Flood_Send_SAA(): SAA forwarded, but \
                        failed at the lower level w/ ret = %d\r\n", ret);
        msg_len = 0;
    } 

    rfldata->saa_trigger = 0;
    E_queue(Reliable_Flood_SAA_Event, (int)mode, (void*)rfldata, 
                rel_fl_hbh_ack_timeout);

    return msg_len;
}


/***********************************************************/
/* int Reliable_Flood_Add_Acks (rel_flood_tail *rt,        */
/*                      int ngbr_index, int16u remaning)   */
/*                                                         */
/* Adds piggy-backed acks to the end of the packet in the  */
/*   order specfied by the hbh_unsent queue. Only adds     */
/*   that will fit (and not go beyond MAX_PACKET_SIZE).    */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* rt:          struct where acks will be added            */
/* ngbr_index:  index of ngbr in Rel_Flood_Link_Data array */
/* remaining:   bytes left to put HBH acks on the packet   */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* Length (in Bytes) of Acks added to the end of the pkt   */
/*                                                         */
/***********************************************************/
int Reliable_Flood_Add_Acks (rel_flood_tail *rt, int ngbr_index, int16u remaining)
{
    unsigned int             max_acks, i = 0;
    rel_flood_hbh_ack       *temp_ack;
    Flow_Queue              *temp_fq;
    Rel_Flood_Link_Data     *rfldata = &RF_Edge_Data[ngbr_index];
    Flow_Buffer             *fb;
 
    /* REL DEBUG */
    /* return rt->ack_len; */

    /* Calculate number of acks that could be added */
    max_acks = remaining / sizeof (rel_flood_hbh_ack);
    
    /* While there exist more acks and more acks can fit, add them. */
    while (i < max_acks && rfldata->hbh_unsent_head.next != NULL)
    {
        /* Remove from head of queue */
        temp_fq = rfldata->hbh_unsent_head.next;
        rfldata->hbh_unsent_head.next = temp_fq->next;
        if (temp_fq->next == NULL)
            rfldata->hbh_unsent_tail = &rfldata->hbh_unsent_head;
        
        fb = &FB->flow[temp_fq->src_id][temp_fq->dest_id];

        temp_ack = (rel_flood_hbh_ack *)
                ((char*)(rt) + sizeof(rel_flood_tail) + 
                (i * sizeof(rel_flood_hbh_ack)));
        temp_ack->src       = temp_fq->src_id;
        temp_ack->dest      = temp_fq->dest_id;
        temp_ack->src_epoch = fb->src_epoch; 
        temp_ack->aru       = fb->head_seq - 1;
        temp_ack->sow       = fb->sow;

        rfldata->unsent_state[temp_fq->src_id][temp_fq->dest_id] = 0;
        rfldata->unsent_state_count--;
        dispose(temp_fq);
        i++;
    }
    rt->ack_len = i * sizeof(rel_flood_hbh_ack);
    return rt->ack_len;
}


/***********************************************************/
/* int Reliable_Flood_Verify (sys_scatter *scat,           */
/*                              int32u src_id)             */
/*                                                         */
/* Verifies the signature of a Reliable Flood packet. The  */
/*   data is contained in scat, along with the signature.  */
/*   Src_ID's public key will be used to verify.           */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* scat:          pointer to data/signature                */
/* src_id:        src of the rel_flood packet, use this    */
/*                  node's public key to verify            */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* 1 for success, 0 for failure (other if VerifyFinal has  */
/*                                  some other failure)    */
/*                                                         */
/***********************************************************/
int Reliable_Flood_Verify(sys_scatter *scat, int32u src_id, unsigned char type)
{
    unsigned char temp_ttl;
    int i, ret, last_elem = scat->num_elements - 1;
    udp_header *hdr;
    packet_header *phdr;
    EVP_MD_CTX *md_ctx;

    /* Verify the RSA Signature */
    if (Conf_Rel.Crypto == 0)
        return 1;

    if (src_id < 1 || src_id > MAX_NODES)
        return 0;

    hdr = (udp_header*)(scat->elements[1].buf);
    temp_ttl = hdr->ttl;
    hdr->ttl = 0;

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx==NULL) {
        Alarm(EXIT, "RF_Verify: EVP_MD_CTX_new()  failed\r\n");
    }
    ret = EVP_VerifyInit(md_ctx, EVP_sha256()); 
    if (ret != 1) { 
        Alarm(PRINT, "RF_Verify: VerifyInit failed\r\n");
        goto cr_cleanup;
    }

    phdr = (packet_header*)scat->elements[0].buf;
    ret = EVP_VerifyUpdate(md_ctx, (unsigned char*)&phdr->type, sizeof(phdr->type));
    if (ret != 1) {
        Alarm(PRINT, "RF_Verify: VerifyUpdate failed. p_hdr->type = %d\r\n", phdr->type);
        goto cr_cleanup;
    }

    if (type == REL_FLOOD_DATA) {
        for (i = 1; i < last_elem; i++) {
            if (i < last_elem - 1) 
                ret = EVP_VerifyUpdate(md_ctx, (unsigned char*)scat->elements[i].buf, 
                            (unsigned int)scat->elements[i].len);
            else
                ret = EVP_VerifyUpdate(md_ctx, (unsigned char*)scat->elements[i].buf, 
                            (unsigned int)scat->elements[i].len - Rel_Signature_Len);
                
            if (ret != 1) {
                Alarm(PRINT, "RF_Verify: VerifyUpdate failed on Data message.\r\n");
                goto cr_cleanup;
            }
        }
    }
    else if (type == REL_FLOOD_E2E) {
        ret = EVP_VerifyUpdate(md_ctx, 
                        (unsigned char*)scat->elements[1].buf + sizeof(udp_header), 
                        sizeof(rel_flood_e2e_ack));
        if (ret != 1) {
            Alarm(PRINT, "RF_Verify: VerifyUpdate failed on E2E message.\r\n");
            goto cr_cleanup;
        }
    }
    else if (type == STATUS_CHANGE) {
        ret = EVP_VerifyUpdate(md_ctx, 
                        (unsigned char*)scat->elements[1].buf + sizeof(udp_header), 
                        sizeof(status_change));
        if (ret != 1) {
            Alarm(PRINT, "RF_Verify: VerifyUpdate failed on Status Change.\r\n");
            goto cr_cleanup;
        }
    }
    else
        Alarm(EXIT, "Reliable_Flood_Verify: invalid r_hdr type for verifying "
                        "signatures - %d\r\n", type);

    ret = EVP_VerifyFinal(md_ctx, 
                        (unsigned char*)(scat->elements[last_elem - 1].buf +
                            scat->elements[last_elem - 1].len - Rel_Signature_Len),
                        Rel_Signature_Len, Pub_Keys[src_id]);
    if (ret != 1) {
        Alarm(PRINT, "RF_Verify: VerifyFinal failed. Type = %d\r\n", type);
        goto cr_cleanup;
    }

    cr_cleanup:
        EVP_MD_CTX_free(md_ctx);
        if (ret != 1) return ret;

    hdr->ttl = temp_ttl;

    return 1;
}

void Reliable_Flood_Restamp( void )
{
    udp_header          *hdr;
    packet_header       *phdr;
    int32u              i, k;
    int32u              index, ngbr;
    int64u              j, resend_start;
    int                 ret, error;
    unsigned int        sign_len;
    unsigned char       temp_bitmask[MultiPath_Bitmask_Size];
    unsigned char       *old_bitmask;
    unsigned char       temp_ttl;
    unsigned char       temp_path[8];
    unsigned char       *path = NULL, *sign_ptr;
    unsigned char       restamp_flow_flag;
    Rel_Flood_Link_Data *rfldata;
    Flow_Queue          *temp_fq;
    Flow_Buffer         *fb;
    EVP_MD_CTX          *md_ctx;
    stdit               it;
    Node                *nd;
    
    /* With the potential routing change, Source may need to re-stamp and
     *      re-sign some of its unacknowledged messages that it originated */
    /* (1) Recompute for destinations that we have packets stored to */
    for (i = 1; i <= MAX_NODES; i++) {
        
        fb = &FB->flow[My_ID][i];
        error = 0;
        restamp_flow_flag = 0;
        
        if (i == My_ID)
            continue;

        if (fb->sow == fb->head_seq)
            continue;

        for (j = fb->sow; j < fb->head_seq && error == 0; j++) {
            
            index = j % MAX_MESS_PER_FLOW;
           
            /* Get the bitmask that is currently calculated based on network
             *      conditions (after the status changes were applied) */
            ret = MultiPath_Stamp_Bitmask(i, fb->num_paths[index], temp_bitmask);
            if (ret == 0) {
                error = 1;
                continue;
            }

            /* Grab the bitmask stored on the message the last time it was ready
             *      to be sent */
            old_bitmask = (unsigned char*)
                    (fb->msg[index]->elements[fb->msg[index]->num_elements-2].buf);
            old_bitmask += sizeof(rel_flood_header);

            /* Make temp_bitmask the superset of the old_bitmask and currently
             *      calculated bitmask to compare if the bitmask has changed */
            MultiPath_Create_Superset(temp_bitmask, old_bitmask);

            /* If bitmasks are not equal, we need to restamp with temp bitmask, 
             *      resign the packet, and mark it to be sent again */
            if (!MultiPath_Is_Equal(old_bitmask, temp_bitmask))
            {
                /* Mark that this flow has at least 1 restamped message */
                /* if (restamp_flow_flag == 0)
                    printf("\tRESTAMPING\n"); */
                restamp_flow_flag = 1;

                /* Write the superset (stored @ temp_bitmask) onto the message */ 
                memcpy(old_bitmask, temp_bitmask, MultiPath_Bitmask_Size);

                if (Conf_Rel.Crypto == 1) {
                    phdr = (packet_header*)(fb->msg[index]->elements[0].buf);
                    hdr = (udp_header*)(fb->msg[index]->elements[1].buf);
                    path = (unsigned char*)((unsigned char*)hdr + sizeof(udp_header) + 16);
                    sign_ptr = (unsigned char*)
                                    (fb->msg[index]->elements[fb->msg[index]->num_elements-2].buf + 
                                    sizeof(rel_flood_header) + MultiPath_Bitmask_Size);

                    /* Store non-signed contents on the side */
                    temp_ttl = hdr->ttl;
                    hdr->ttl = 0;
                    if (Path_Stamp_Debug == 1) {
                        for (k = 0; k < 8; k++) {
                            temp_path[k] = path[k];
                            path[k] = (unsigned char) 0;
                        }
                    }
                    
                    /* Sign with Priv_Key */
                    md_ctx = EVP_MD_CTX_new();
                    if (md_ctx == NULL) {
                        Alarm(EXIT, "Reliable_Flood_Restamp: EVP_MD_CTX_new()  failed\r\n");
                    }
                    ret = EVP_SignInit(md_ctx, EVP_sha256()); 
                    if (ret != 1) {
                        Alarm(PRINT, "Reliable_Flood_Restamp: SignInit failed\r\n");
                        error = 1;
                        goto cr_cleanup;
                    }

                    /* Add each part of the message to be signed into the md_ctx */
                    /* First, sign over the type in the packet_header */
                    ret = EVP_SignUpdate(md_ctx, (unsigned char*)&phdr->type, sizeof(phdr->type));

                    /* Strip off old signature */
                    fb->msg[index]->elements[fb->msg[index]->num_elements-2].len -= Rel_Signature_Len;

                    /* Sign over the remaining elements in the message (not including the rt) */
                    for (k = 1; k < fb->msg[index]->num_elements - 1; k++) {
                        ret = EVP_SignUpdate(md_ctx, (unsigned char*)fb->msg[index]->elements[k].buf, 
                                                fb->msg[index]->elements[k].len);
                        if (ret != 1) {
                            Alarm(PRINT, "Reliable_Flood_Restamp: SignUpdate failed\r\n");
                            error = 1;
                            break;
                        }
                    }
                    if (error == 1)
                        goto cr_cleanup;

                    ret = EVP_SignFinal(md_ctx, sign_ptr, &sign_len, Priv_Key);
                    if (ret != 1) {
                        Alarm(PRINT, "Reliable_Flood_Restamp: SignFinal failed\r\n");
                        error = 1;
                        goto cr_cleanup;
                    }
                    if (sign_len != Rel_Signature_Len) {
                        Alarm(PRINT, "Reliable_Flood_Restamp: sign_len (%d) != Key_Len (%d)\r\n",
                                        sign_len, Rel_Signature_Len);
                        error = 1;
                        goto cr_cleanup;
                    }

                    /* Update the length for the new signature */
                    fb->msg[index]->elements[fb->msg[index]->num_elements-2].len += Rel_Signature_Len;

                    /* Return non-signed content back to the message */
                    hdr->ttl = temp_ttl;
                    if (Path_Stamp_Debug == 1) {
                        for (k = 0; k < 8; k++) {
                            path[k] = temp_path[k];
                        }
                    }

                    cr_cleanup:
                        EVP_MD_CTX_free(md_ctx);
                        if (error) continue;
                }

                /* mark to be resent */
                for (ngbr = 1; ngbr <= Degree[My_ID]; ngbr++)
                    fb->status[index][ngbr] = RESTAMPED_UNSENT;
            }
        }
        
        if (error == 1)
            continue;

        if (restamp_flow_flag == 1) {
            for (k = 1; k <= Degree[My_ID]; k++) {

                rfldata = &RF_Edge_Data[k];

                /* move back next to send to the first restamped message thats needs to be sent 
                *      NOTE: only the first neighbor makes a change to resend_start, since
                *            all neighbors are synchronized  */
                resend_start = fb->sow;
                while (resend_start < fb->head_seq && 
                        (fb->status[resend_start % MAX_MESS_PER_FLOW][k] == NEW_SENT ||
                         fb->status[resend_start % MAX_MESS_PER_FLOW][k] == RESTAMPED_SENT))
                {
                    resend_start++;
                }

                index = resend_start % MAX_MESS_PER_FLOW;

                if (resend_start > fb->next_seq[k])
                    Alarm(EXIT, "Reliable_Flood_Restamp: Not possible! resend_start (%lu) >" 
                                    " next_seq (%lu). SOW = %lu, NGBR = %d,"
                                    " First Msg Status = %d\r\n", 
                                    resend_start, fb->next_seq[k], fb->sow, k,
                                    fb->status[fb->sow % MAX_MESS_PER_FLOW][k]);
                fb->next_seq[k] = resend_start;

                /* Add to sending queue (urgent) if not already in either queue. */
                if (rfldata->in_flow_queue[My_ID][i] == 0 && 
                        fb->next_seq[k] < fb->head_seq && 
                        MultiPath_Neighbor_On_Path( (unsigned char*)
                            (fb->msg[index]->elements[fb->msg[index]->num_elements-2].buf) + 
                            sizeof(rel_flood_header), k) )
                {
                    rfldata->in_flow_queue[My_ID][i] = 1;
                    temp_fq = (Flow_Queue *) new (FLOW_QUEUE_NODE);
                    if (temp_fq == NULL)
                        Alarm(EXIT, "Reliable_Flood_Restamp(): Cannot allocate"
                                    "Flow Queue Node for in_flow_queue.\r\n");
                    temp_fq->src_id = My_ID;
                    temp_fq->dest_id = i;
                    temp_fq->penalty = 1;
                    temp_fq->next = NULL;
                    rfldata->urgent_tail->next = temp_fq;
                    rfldata->urgent_tail = temp_fq;

                    /* Request Resources for the re-stamped messages */
                    stdhash_find(&All_Nodes, &it, &Neighbor_Addrs[My_ID][i]);
                    if (!stdhash_is_end(&All_Nodes, &it)) {
                        nd = *((Node **)stdhash_it_val(&it));
                        if (rfldata->norm_head.next != NULL ||
                             rfldata->urgent_head.next != NULL) 
                        {
                            Request_Resources((IT_RELIABLE_ROUTING >>
                                               ROUTING_BITS_SHIFT), nd, INTRUSION_TOL_LINK, 
                                &Reliable_Flood_Send_One);
                        }
                    }
                }
            }
        }
    }
}

/***********************************************************/
/* void Generate_Link_Status_Change (int32 ngbr_addr,      */
/*                                  unsigned char status)  */
/*                                                         */
/* Genereates a new link status change message, and        */
/*      applies the change locally to this node.           */
/*      The status is used to figure out the new cost      */
/*      on the link between this node and the neighbor     */    
/*      the edge defined between ID1 and ID2 to            */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* ngbr_addr:       ip address of neighbor                 */
/* status:          status of the link                     */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */ 
/*                                                         */
/***********************************************************/
void Generate_Link_Status_Change(int32 ngbr_addr, unsigned char status)
{
    Edge_Key    key;
    stdit       it;
    int16u      ngbr_id;
    int16       cost, ref_cost;
    int64u      tmp_cost;

    stdhash_find(&Node_Lookup_Addr_to_ID, &it, &ngbr_addr);
    if (stdhash_is_end(&Node_Lookup_Addr_to_ID,  &it)) {
        Alarm(PRINT, "Generate_Link_Status_Change:"
            " cannot convert Address ("IPF") to ID\n", IP(ngbr_addr));
        return;
    }
    ngbr_id = *(int16u *)stdhash_it_val(&it);

    Alarm(PRINT,"Generate_Link_Status_Change for [%u,%u], Status = %u\n", 
                    My_ID, ngbr_id, status); 

    /* Get the reference cost of the edge from the config file */
    if (Directed_Edges == 0 && My_ID > ngbr_id) {
        key.src_id = ngbr_id;
        key.dst_id = My_ID;
    }
    else {
        key.src_id = My_ID;
        key.dst_id = ngbr_id;
    }
   
    stdskl_find(&Sorted_Edges, &it, &key);
    if (stdskl_is_end(&Sorted_Edges, &it))
        Alarm(PRINT, "Generate_Link_Status_Change: Could not find specified edge"
                        " for [%d,%d] w/ status = %d\n", 
                        key.src_id, key.dst_id, status);
    ref_cost = ((Edge_Value*)stdskl_it_val(&it))->cost;


    /* AT SOME POINT, THIS IS BLACK BOX FUNCTION FOR COMPUTING COSTS */
   if (status == 0) /* Link down */
        cost = -1;
    else if (status == 1) /* Link up */
        cost = ref_cost;
    else if (status == 2) { /* Loss on Link */
        tmp_cost = ref_cost + Conf_IT_Link.Loss_Penalty;
        if (tmp_cost > SHRT_MAX)
            tmp_cost = SHRT_MAX;
        cost = tmp_cost;
    }
    else {
        Alarm(PRINT, "Generate_Link_Status_Change: Unrecognized Link Status: %u\r\n", status);
        return;
    } 
    Apply_Link_Status_Change(My_ID, ngbr_id, cost);

    /* With new status changes applied, we may need to restamp, re-sign,
     *      and resend data messages */
    Reliable_Flood_Restamp();

    /* FUNCTION TO GENERATE MESSAGE TO SEND STATUS CHANGE TO OTHERS */
    if (Status_Change[My_ID].epoch == 0)
        Status_Change[My_ID].epoch = Flow_Source_Epoch[My_ID];       
    Status_Change[My_ID].cell[ngbr_id].seq++;
    Status_Change[My_ID].cell[ngbr_id].cost = cost;
    Local_Status_Change_Progress = 1;

    if(!E_in_queue(Gen_Status_Change, INTRUSION_TOL_LINK, NULL))
        E_queue(Gen_Status_Change, INTRUSION_TOL_LINK, NULL, zero_timeout);
}

/***********************************************************/
/* void Apply_Link_Status_Change (int16u ID1, int16u ID2,  */
/*                                  int16u cost)           */
/*                                                         */
/* Alters the edge defined between ID1 and ID2 to          */
/*   have the new cost.                                    */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* ID1:           id of first link endpoint                */
/* ID2:           id of second link endpoint               */
/* cost:          new cost of the link                     */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */ 
/*                                                         */
/***********************************************************/
void Apply_Link_Status_Change( int16u ID1, int16u ID2, int16 cost)
{
    stdit it;
    int32 addr1, addr2;
    Edge *e;
    Edge_Key key;
    int16 ref_cost;
    
    /* HACK for 16/32 bit mismatch in stdhash.... for now */
    int32u id1, id2;
    id1 = ID1;
    id2 = ID2;

    /* Get the reference cost of the edge from the config file */
    if (Directed_Edges == 0 && id1 > id2) {
        key.src_id = id2;
        key.dst_id = id1;
    }
    else {
        key.src_id = id1;
        key.dst_id = id2;
    }
   
    stdskl_find(&Sorted_Edges, &it, &key);
    if (stdskl_is_end(&Sorted_Edges, &it))
        Alarm(PRINT, "Apply_Link_Status_Change: Could not find specified edge"
                        " for [%d,%d], trying to apply cost = %d\n", 
                        key.src_id, key.dst_id, cost);
    ref_cost = ((Edge_Value*)stdskl_it_val(&it))->cost;

    /* Check ref_cost against the new desired cost */
    if (cost != -1 && cost < ref_cost) {
        Alarm(PRINT, "Apply_Link_Status_Change: Invalid cost!"
                        " cost = %d, ref_cost = %d\n", cost, ref_cost);
        return;
    }

    /* DEBUG - print out all entries */
    /* stdhash_begin(&Node_Lookup_ID_to_Addr, &it);
    while (!stdhash_is_end(&Node_Lookup_ID_to_Addr, &it)) {
        printf("  [%u,", *(int16u*)stdhash_it_key(&it)); 
        printf(""IPF"]", IP(*(int32*)stdhash_it_val(&it))); 
        stdhash_it_next(&it);
    }
    printf("\n"); */

    /* Convert IDs to IP addresses to use the Edge data structure */
    stdhash_find(&Node_Lookup_ID_to_Addr, &it, &id1);
    if (stdhash_is_end(&Node_Lookup_ID_to_Addr,  &it)) {
        Alarm(PRINT, "Apply_Link_Status_Change:"
            " cannot convert ID1 (%u) to Address\n", id1);
        return;
    }
    addr1 = *(int32 *)stdhash_it_val(&it);

    stdhash_find(&Node_Lookup_ID_to_Addr, &it, &id2);
    if (stdhash_is_end(&Node_Lookup_ID_to_Addr,  &it)) {
        Alarm(PRINT, "Apply_Link_Status_Change:"
            " cannot convert ID2 (%u) to Address\n", id2);
        return;
    }
    addr2 = *(int32 *)stdhash_it_val(&it);

    /* Get the current edge between addr1 and addr2 */
    e = Get_Edge(addr1,addr2);
    if (e == NULL) {
        Alarm(PRINT, "Apply_Link_Status_Change: Get_Edge returned null"
                        " between "IPF" and "IPF"\n", IP(addr1), IP(addr2));
        return;
    }

    /* Apply the new cost */
    /* OPTIMIZATION - only update the cost AND clear the cache if cost has changed */
    if (e->cost == cost)
        return;

    e->cost = cost;
    Alarm(PRINT, "Apply_Link_Status_Change: [%u,%u] --> cost = %d\r\n", id1, id2, cost);
   
    /* Clear the multipath cache */
    MultiPath_Clear_Cache();
}

/***********************************************************/
/* void Process_Status_Change (int32u last_hop_index,      */
/*                           sys_scatter *scat, int mode)  */
/*                                                         */
/* Processes Link Status Changes                           */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* last_hop_index:  ID of the ngbr the data came from      */
/* scat:            a sys_scatter containing the message   */
/* mode:            lower-level link protocol              */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/
void Process_Status_Change (int32u last_hop_index, sys_scatter *scat, int mode) 
{
    udp_header          *hdr;
    status_change       *sc_new, *sc_old;
    Rel_Flood_Link_Data *rfldata;
    int16               ref_cost;
    int32u              i;
    int32u              creator;
    sp_time             now, min_to;
    stdit               it;
    Edge_Key            key;
    unsigned char       *sign_start;
    unsigned char       new_epoch = 0, old_content = 0, new_content = 0;
    unsigned char       valid_neighbors[MAX_NODES + 1];

    hdr = (udp_header*)(scat->elements[1].buf);
    sc_new = (status_change*)(scat->elements[1].buf + sizeof(udp_header));

    if (sc_new->creator < 1 || sc_new->creator > MAX_NODES) {
        Alarm(DEBUG, "Process_Status_Change: invalid creator on"
                        " status_change %u\r\n", sc_new->creator);
        return;
    }

    sign_start = (unsigned char*)(scat->elements[scat->num_elements-2].buf + 
                                    sizeof(rel_flood_header));
   
    creator = sc_new->creator;
    sc_old = (status_change*) &Status_Change[creator];

    Alarm(DEBUG, "Process Status Change from %d about link owned by %d\n",
        Neighbor_IDs[My_ID][last_hop_index], creator);

    /* Setup the valid_neighbors array for validating the status change message */
    for (i = 1; i <= MAX_NODES; i++)
        valid_neighbors[i] = 0;
    for (i = 1; i <= Degree[creator]; i++)
        valid_neighbors[Neighbor_IDs[creator][i]] = 1;

    /* First, Validate the Status Change. If not valid, throw away (don't store)
     *      and return */
    if (sc_new->epoch < sc_old->epoch) {
        Alarm(DEBUG, "Process_Status_Change: epoch %u is older than what" 
                        " is stored %u\r\n", sc_new->epoch, sc_old->epoch);
        return;
    }
    else if (sc_new->epoch > sc_old->epoch)  {
        new_epoch = 1;
        new_content = 1;
    }

    for (i = 1; i <= MAX_NODES; i++) {
       
        /* Check if Creator tries to alter non-neighboring link - MALICIOUS */
        if (valid_neighbors[i] == 0 && 
                (sc_new->cell[i].seq > 0 || sc_new->cell[i].cost != 0)) 
        {
            Alarm(PRINT, "Process_Status_Change: status change from %u tries to alter"
                            " non-neighboring link to %u. BLACKLIST\r\n", creator, i);
            return;
        }

       /* Check the cost value of each link against the reference */
        if (valid_neighbors[i] == 1) {
            if (Directed_Edges == 0 && creator > i) {
                key.src_id = i;
                key.dst_id = creator;
            }
            else {
                key.src_id = creator;
                key.dst_id = i;
            }
           
            stdskl_find(&Sorted_Edges, &it, &key);
            if (stdskl_is_end(&Sorted_Edges, &it))
                Alarm(PRINT, "Process_Status_Change: Could not find specified edge"
                                " for [%d,%d]\r\n", key.src_id, key.dst_id);
            ref_cost = ((Edge_Value*)stdskl_it_val(&it))->cost;

            if (sc_new->cell[i].cost != -1 && sc_new->cell[i].cost < ref_cost) {
                Alarm(PRINT, "Process_Status_Change: Invalid cost!"
                            " cost = %d, ref_cost = %d\n", sc_new->cell[i].cost, ref_cost);
                return;
            }
        }

        if (new_epoch == 0) {
            /* Mark if this packet contains old and/or new content */
            if (sc_new->cell[i].seq < sc_old->cell[i].seq)
                old_content = 1;
            else if (sc_new->cell[i].seq > sc_old->cell[i].seq)
                new_content = 1;
        }
    }

    /* If status change contains both old and new content, MALICIOUS */
    if (new_epoch == 0 && old_content == 1 && new_content == 1) {
        Alarm(PRINT, "Process_Status_Change: status change from %u claims both "
                       "new and old content (non monotonically increasing "
                       "sequence numbers). BLACKLIST\r\n", creator);
        return;
    }

    /* If there is no new content, discard the status change */
    if (new_content == 0) {
        Alarm(DEBUG, "Process_Status_Change: no new content from status change\r\n", 
                        creator);
        return;
    }

    /* Otherwise, there is new and valid content, first apply it */
    for (i = 1; i <= MAX_NODES; i++) {
        if (valid_neighbors[i] == 1 && (new_epoch == 1 ||
                sc_new->cell[i].seq > sc_old->cell[i].seq))
            Apply_Link_Status_Change(creator, i, sc_new->cell[i].cost);
    }

    /* Next, store the status change message */
    memcpy(&Status_Change[creator], sc_new, sizeof(status_change));
    memcpy(Status_Change_Sig[creator], sign_start, Rel_Signature_Len);

    /*  For every other neighbor (other than one we got it from), queue status
     *     change message toward them */
    now = E_get_time();
    for (i = 1; i <= Degree[My_ID]; i++) {
        
        rfldata = &RF_Edge_Data[i];
        
        /* Update timeout and flag for appropriate neighbors */
        if (rfldata->status_change_stats[creator].unsent == 0 && i != last_hop_index) {
            rfldata->status_change_stats[creator].unsent = 1;
            rfldata->status_change_stats[creator].timeout = 
                E_add_time(rfldata->status_change_stats[creator].timeout, 
                            status_change_timeout);
            
            stdskl_insert(&rfldata->status_change_skl, &it,
                    &rfldata->status_change_stats[creator].timeout, &creator, STDFALSE);
            stdskl_begin(&rfldata->status_change_skl, &it); 
            min_to = *(sp_time*) stdskl_it_key(&it);

            if (E_compare_time(min_to, now) <= 0) 
                E_queue(Status_Change_Event, mode, (void*)rfldata,
                        zero_timeout); 
            else 
                E_queue(Status_Change_Event, mode, (void*)rfldata,
                        E_sub_time(min_to, now));
        }
    }

    /* With new status changes applied, we may need to restamp, re-sign,
     *      and resend data messages */
    Reliable_Flood_Restamp();

    return;
}

/***********************************************************/
/* void Gen_Status_Change (int mode, void *dummy)          */
/*                                                         */
/* Prepares an Status Change to be sent from this node     */
/*   on all outgoing links                                 */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* mode:        mode of the link the packet arrived on     */
/* dummy:       not used                                   */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/
void Gen_Status_Change(int mode, void *dummy)
{
    int i;
    Rel_Flood_Link_Data *rfldata;
    sp_time now;
    stdit it;

    UNUSED(dummy);

    if (Local_Status_Change_Progress == 0)
        return;

    Local_Status_Change_Progress = 0;
    E_queue(Gen_Status_Change, mode, NULL, status_change_timeout);
    
    for (i = 1; i <= Degree[My_ID]; i++) {
        
        rfldata = &RF_Edge_Data[i];
        if (rfldata->status_change_stats[My_ID].unsent == 1)
            continue;

        rfldata->status_change_stats[My_ID].unsent = 1;
        now = E_get_time();
        stdskl_insert(&rfldata->status_change_skl, &it, &now, &My_ID, STDFALSE);
        E_queue(Status_Change_Event, mode, (void*)rfldata, zero_timeout);
    }
}

/************************************************************/
/* void Status_Change_Event(int mode, void *ngbr_data)      */
/*                                                          */
/* Event that sets status_change_ready flag and requests    */
/*   resources on the link of type mode towards the         */
/*   neighbor defined by ngbr_data                          */
/*                                                          */
/*                                                          */
/* Arguments                                                */
/*                                                          */
/* mode:        mode of the link the packet arrived on      */
/* ngbr_data:   link data toward this neighbor              */
/*                                                          */
/*                                                          */
/* Return Value                                             */
/*                                                          */
/* NONE                                                     */
/*                                                          */
/************************************************************/
void Status_Change_Event (int mode, void *ngbr_data)
{
    int i, ngbr_index, ret;
    Node *nd;
    stdit it;
    Rel_Flood_Link_Data *rfldata;

    rfldata = (Rel_Flood_Link_Data*)ngbr_data;
    assert(rfldata != NULL);
    
    stdskl_begin(&rfldata->status_change_skl, &it); 
    if (stdskl_is_end(&rfldata->status_change_skl, &it)) {
        Alarm(DEBUG, "Status_Change_Event: no Status Change to send at this time\r\n");
        return;
    }

    /* Verify that this link data goes to a valid neighbor */
    for (i = 1; i <= Degree[My_ID]; i++) {
        if (rfldata == &RF_Edge_Data[i])
            break;
    }
    assert(i <= Degree[My_ID]);
    ngbr_index = i;

    /* Find the node on the other side of this link */
    stdhash_find(&All_Nodes, &it, &Neighbor_Addrs[My_ID][ngbr_index]);
    if (stdhash_is_end(&All_Nodes, &it))
        return;
    nd = *((Node **)stdhash_it_val(&it));

    rfldata->status_change_ready = 1;
    Alarm(DEBUG, "Status_Change requesting resources to "IPF"\n", IP(nd->nid));
    ret = Request_Resources((IT_RELIABLE_ROUTING >> ROUTING_BITS_SHIFT),
                        nd, mode, &Reliable_Flood_Send_One);
    if (ret == 0)
        E_queue(Status_Change_Event, mode, ngbr_data, one_sec_timeout);
}

/************************************************************/
/* int Send_Status_Change (Node *next_hop,                  */
/*                              int ngbr_index, int mode)   */
/*                                                          */
/* Sends one status change to the neighbor specified        */
/*   by ngbr_data on the link protocol define by mode       */
/*                                                          */
/*                                                          */
/* Arguments                                                */
/*                                                          */
/* next_hop:    neighbor node to which to send to           */
/* ngbr_index:  index of neighbor in data structures        */
/* mode:        mode of the link to send E2E on             */
/*                                                          */
/*                                                          */
/* Return Value                                             */
/*                                                          */
/* 0 - Error Case (no packet was sent)                      */
/* num_bytes_sent - Status Change was sent via lower level  */
/*                                                          */
/************************************************************/
int Send_Status_Change (Node *next_hop, int ngbr_index, int mode)
{
    Rel_Flood_Link_Data *rfldata;
    packet_header       *phdr;
    udp_header          *hdr;
    rel_flood_header    *r_hdr;
    rel_flood_tail      *rt;
    status_change       *sc;
    int16u              ack_inc = 0, msg_len = 0, packets = 0, last_pkt_space = 0;
    int                 ret, i, creator;
    sp_time             now, min_to;
    stdit               it;
    unsigned char       *sign_start;
    sys_scatter         *scat;
    unsigned char       crypto_fail = 0;
    unsigned int        sign_len;
    EVP_MD_CTX          *md_ctx;

    assert(ngbr_index >= 1 && ngbr_index <= Degree[My_ID]);
    rfldata = &RF_Edge_Data[ngbr_index];

    stdskl_begin(&rfldata->status_change_skl, &it); 
    if (stdskl_is_end(&rfldata->status_change_skl, &it)) {
        Alarm(PRINT, "Reliable_Flood_Send_Status_Change: no Status Change to send at this time\r\n");
        return 0;
    }

    /* Create the empty scatter */
    if ((scat = (sys_scatter*) new_ref_cnt(SYS_SCATTER)) == NULL)
        Alarm(EXIT, "Reliable_Flood_Send_Status_Change: Could not allocate sys_scatter\r\n");
    scat->num_elements = 0;

    /* Create element for Packet_Header */
    if ((scat->elements[scat->num_elements].buf = new_ref_cnt(PACK_HEAD_OBJ)) == NULL)
        Alarm(EXIT, "Reliable_Flood_Send_Status_Change: Could not allocate packet_header\r\n");
    scat->elements[scat->num_elements].len = sizeof(packet_header);
    scat->num_elements++;

    /* Create element for UDP_Header and E2E Ack */
    if ((scat->elements[scat->num_elements].buf = new_ref_cnt(PACK_BODY_OBJ)) == NULL)
        Alarm(EXIT, "Reliable_Flood_Send_Status_Change: Could not allocate packet_body\r\n");
    scat->elements[scat->num_elements].len = sizeof(udp_header) + sizeof(status_change);
    scat->num_elements++;

    /* Create element for Rel_Flood_Header and Signature */
    if ((scat->elements[scat->num_elements].buf = new_ref_cnt(PACK_BODY_OBJ)) == NULL)
        Alarm(EXIT, "Reliable_Flood_Send_Status_Change: Could not allocate packet_body\r\n");
    scat->elements[scat->num_elements].len = sizeof(rel_flood_header) + Rel_Signature_Len;
    scat->num_elements++;

    /* Create element for Rel_Flood_Tail and (potential) HBH Acks */
    if ((scat->elements[scat->num_elements].buf = new_ref_cnt(PACK_BODY_OBJ)) == NULL)
        Alarm(EXIT, "Reliable_Flood_Send_Status_Change: Could not allocate packet_body\r\n");
    scat->elements[scat->num_elements].len = sizeof(rel_flood_tail);
    scat->num_elements++;

    /* Spines header */
    phdr = (packet_header*) scat->elements[0].buf;
    phdr->type = Get_Link_Data_Type(mode);
    phdr->type = Set_endian(phdr->type);

    /* UDP header */
    hdr = (udp_header*) scat->elements[1].buf;
    hdr->source = My_Address;
    hdr->dest = Neighbor_Addrs[My_ID][ngbr_index];
    hdr->source_port = 0;
    hdr->dest_port = 0;   /* By using port 0, won't be delivered to client */
    hdr->len = sizeof(status_change);
    hdr->seq_no = 0;
    hdr->sess_id = 0;
    hdr->frag_num = 0;
    hdr->frag_idx = 0;
    hdr->ttl = 255;
    hdr->routing = (IT_RELIABLE_ROUTING >> ROUTING_BITS_SHIFT);

    sc = (status_change*)(scat->elements[1].buf + sizeof(udp_header));

    r_hdr = (rel_flood_header*) (scat->elements[scat->num_elements-2].buf);
    r_hdr->src = 0;
    r_hdr->dest = 0;
    r_hdr->seq_num = 0;
    r_hdr->type = STATUS_CHANGE;

    sign_start = (unsigned char*)(r_hdr) + sizeof(rel_flood_header);

    rt = (rel_flood_tail*) (scat->elements[scat->num_elements-1].buf);
    rt->ack_len = 0;

    now = E_get_time();
    creator = *(int*) stdskl_it_val(&it);

    packets = Calculate_Packets_In_Message(scat, mode, &last_pkt_space);
    ack_inc = Reliable_Flood_Add_Acks(rt, ngbr_index, last_pkt_space);
    assert(ack_inc == rt->ack_len);
    scat->elements[scat->num_elements-1].len += ack_inc;

    if (creator == My_ID) {
        /* RSA Sign */
        if (Conf_Rel.Crypto == 1) {
            md_ctx = EVP_MD_CTX_new();
            if (md_ctx == NULL) {
                Alarm(EXIT, "Send_Status_Change: EVP_MD_CTX_new() failed\r\n");
            }
            ret = EVP_SignInit(md_ctx, EVP_sha256()); 
            if (ret != 1) {
                Alarm(PRINT, "Send_Status_Change: SignInit failed\r\n");
                crypto_fail = 1;
            }
            
            /* add the phdr->type */
            ret = EVP_SignUpdate(md_ctx, (unsigned char*)&phdr->type, sizeof(phdr->type));
            if (ret != 1) {
                Alarm(PRINT, "Send_Status_Change: SignUpdate failed on phdr->type = %d\r\n", phdr->type);
                crypto_fail = 1;
            }

            /* add the e2e ack */
            ret = EVP_SignUpdate(md_ctx, (unsigned char*)&Status_Change[My_ID], 
                                sizeof(status_change));
            if (ret != 1) {
                Alarm(PRINT, "Send_Status_Change: SignUpdate failed\r\n");
                crypto_fail = 1;
            }
            ret = EVP_SignFinal(md_ctx, (unsigned char*)Status_Change_Sig[My_ID], 
                                &sign_len, Priv_Key);
            if (ret != 1) {
                Alarm(PRINT, "Send_Status_Change: SignFinal failed\r\n");
                crypto_fail = 1;
            }
            if (sign_len != Rel_Signature_Len) {
                Alarm(PRINT, "Send_Status_Change: sign_len (%d) != Key_Len (%d)\r\n",
                                sign_len, Rel_Signature_Len);
                crypto_fail = 1;
            }

            EVP_MD_CTX_free(md_ctx);
        }
    }

    memcpy(sc, &Status_Change[creator], sizeof(status_change));
    memcpy(sign_start, Status_Change_Sig[creator], Rel_Signature_Len);

    for (i = 0; i < scat->num_elements; i++) 
        msg_len += scat->elements[i].len;

    if (crypto_fail == 0) {
        Alarm(DEBUG, "\tSending Status_Change for %d to "IPF"\r\n", creator, IP(next_hop->nid));
        ret = Forward_Data(next_hop, scat, mode);
    }
    else
        ret = NO_ROUTE;

    Cleanup_Scatter(scat);
    
    if (ret == BUFF_EMPTY || ret == BUFF_OK) {
        Alarm(DEBUG, "Reliable_Flood_Send_Status_Change(): Status Change forwarded successfully\r\n");
        rfldata->status_change_stats[creator].unsent = 0;
        rfldata->status_change_stats[creator].timeout = now;
        stdskl_erase(&rfldata->status_change_skl, &it);
        rfldata->status_change_ready = 0;
     
        if (ack_inc > 0) {
            rfldata->saa_trigger = 0;
            E_queue(Reliable_Flood_SAA_Event, (int)mode, (void*)rfldata, 
                        rel_fl_hbh_ack_timeout);             
        }
    }
    else { /* Status_Change failed to send, requeue for later */
        Alarm(PRINT, "Send_Status_Change: Send Failed!\r\n");
        if (crypto_fail == 1)
            Alarm(PRINT, "\tCrypto failure- error in signing message\r\n");
        else
            Alarm(PRINT, "\tStatus Change forwarded, but failed at lower level with "
                        "ret = %d\r\n", ret);
        rfldata->status_change_stats[creator].unsent = 1;
        rfldata->status_change_stats[creator].timeout = E_add_time(now, status_change_timeout);
        stdskl_erase(&rfldata->status_change_skl, &it);
        stdskl_insert(&rfldata->status_change_skl, &it, &rfldata->status_change_stats[creator].timeout, &creator, STDFALSE);
        rfldata->status_change_ready = 0;
        msg_len = 0;
    }
    
    /* Find when (if at all) to requeue Status_Change_Event function for */
    if (!stdskl_empty(&rfldata->status_change_skl)) {
        stdskl_begin(&rfldata->status_change_skl, &it); 
        min_to = *(sp_time*) stdskl_it_key(&it);
        if (E_compare_time(min_to, now) <= 0) 
            E_queue(Status_Change_Event, mode, (void*)rfldata,
                    zero_timeout); 
        else 
            E_queue(Status_Change_Event, mode, (void*)rfldata,
                    E_sub_time(min_to, now));
    }

    return msg_len;
}
