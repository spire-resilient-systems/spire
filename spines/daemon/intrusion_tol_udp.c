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

#define ext_intru_tol_udp
#include "intrusion_tol_udp.h"
#undef  ext_intru_tol_udp

#include <string.h>

#include "security.h"

/* For printing 64 bit numbers */
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

/* Global variables (extern) */
extern Node     *This_Node;
extern Node_ID   My_Address;
extern Link*     Links[MAX_LINKS];
extern stdhash   All_Nodes;
extern int       network_flag;
extern int       Minimum_Window;

extern int64u    IT_full_dropped;
extern int64u    IT_dead_dropped;
extern int64u    IT_size_dropped;
extern int64u    IT_total_pkts;

extern stdhash   Node_Lookup_Addr_to_ID;
extern int16u    My_ID;
extern int32u   *Neighbor_Addrs[];

extern unsigned char Conf_Hash[];

static unsigned char IT_Crypt_Buf[100000];

/* Local constants */
static const sp_time zero_timeout  = {0, 0};
unsigned char processed[(RESERVED_ROUTING_BITS >> ROUTING_BITS_SHIFT)];

/* Internal functions called from this link protocol */
void Assign_Resources_IT(Node *next_hop);
int Pack_Fragments_Into_Packets_IT(Link *lk);
int Build_Message_From_Fragments_IT(sys_scatter *scat, char *buff, int16u data_len, 
                            unsigned char *idx, unsigned char *total, Link_Type mode);
void Blacklist_Neighbor_IT( Link *lk );
int Send_IT_Data_Msg(int link_id, int64u seq);
int Send_IT_Ack(int link_id);
int Send_IT_Ping(int link_id, char *buff);
void Send_IT_DH(int link_id, void *dummy);
int Process_IT_Ack(int link_id, char* buff, int16u data_len, int16u ack_len);
void Incarnation_Change(int link_id, int32u new_ngbr_inc, int mode);

/* Utility functions and event-based functions w/ timeouts */
void Ack_IT_Timeout(int link_id, void *dummy);
void Reliable_IT_Timeout(int link_id, void *dummy);
void Handle_IT_Retransm(int link_id, void *dummy);
int Add_IT_Nacks(Int_Tol_Data *itdata, intru_tol_pkt_tail *itt,
                 int16u buff_len);

/* Functions for flipping headers */

/***********************************************************/
/***********************************************************/

static int IT_Link_Send(Link *lk, sys_scatter *scat)
{
    Int_Tol_Data *itdata = (Int_Tol_Data*) lk->prot_data;
    int           ret    = BUFF_DROP;
    sys_scatter   msg;
    int           len;
    
    if (Conf_IT_Link.Crypto)
    {
        if (itdata->dh_key_computed != 2)
        {
            Alarm(PRINT, "IT_Link_Send: No DH key computed with neighbor yet! status: %d, neighbor "IPF"\r\n", itdata->dh_key_computed, IP(lk->leg->remote_interf->net_addr));
            goto FAIL;
        }

        if ((len = Sec_lock_msg(scat, IT_Crypt_Buf, (int) sizeof(IT_Crypt_Buf), itdata->encrypt_ctx, itdata->hmac_ctx)) < 0)
        {
            Alarm(PRINT, "IT_Link_Send: Sec_lock_msg failed!\n");
            goto FAIL;
        }

        msg.num_elements    = 1;
        msg.elements[0].buf = (char*) IT_Crypt_Buf;
        msg.elements[0].len = len;
        scat = &msg;
    }

    ret = Link_Send(lk, scat);

FAIL:
    return ret;
}

/***********************************************************/
/***********************************************************/

static void DH_established(Link *lk)
{
    Int_Tol_Data *itdata = (Int_Tol_Data*) lk->prot_data;
    
    if (Conf_IT_Link.Crypto == 1 && itdata != NULL && itdata->dh_established == 0)
    {
        itdata->dh_established = 1;
        
        if (itdata->dh_pkt.elements[0].buf != NULL)
        {
            dec_ref_cnt(itdata->dh_pkt.elements[0].buf);
            itdata->dh_pkt.elements[0].buf = NULL;
            itdata->dh_pkt.elements[0].len = 0;
        }
        
        if (itdata->dh_pkt.elements[1].buf != NULL)
        {
            dec_ref_cnt(itdata->dh_pkt.elements[1].buf);
            itdata->dh_pkt.elements[1].buf = NULL;
            itdata->dh_pkt.elements[1].len = 0;
        }
        /* HANDSHAKE HAS FINISHED, RESTARTING NORMAL RELIABLE TIMEOUT EVENT */
        if (!E_in_queue(Reliable_IT_Timeout, (int)(lk->link_id), NULL))
            E_queue(Reliable_IT_Timeout, (int)(lk->link_id), NULL, zero_timeout);
    }
}

/*********************************************************************
 If using crypto on intrusion tolerant links, then try to authenticate
 and decrypt the message first, including stripping crypto fields.  If
 that succeeds, return the decrypted and authenticated message.  If
 that fails or we don't have a DH key yet, but the msg looks like it
 might be a DH msg, then return that msg unchanged for further
 processing.  Otherwise, reject the message.

 Returns (new) msg size if processing should continue, negative if msg
 should be dropped.
**********************************************************************/

int Preprocess_intru_tol_packet(sys_scatter *scat, int received_bytes, Interface *local_interf, Network_Address src_addr, int16u src_port)
{
    int            ret = -1;
    packet_header *pack_hdr  = (packet_header*) scat->elements[0].buf;
    int32          pack_type = (Same_endian(pack_hdr->type) ? pack_hdr->type : Flip_int32(pack_hdr->type));  /* NOTE: might be invalid or encrypted data at this point */
    Interface     *remote_interf;
    Network_Leg   *leg;
    Link          *lk;
    Int_Tol_Data  *itdata;

    assert(received_bytes >= 0);
    
    /* look up link */
    
    if ((remote_interf = Get_Interface_by_Addr(src_addr))                   == NULL ||
        (leg = Get_Network_Leg(local_interf->iid, remote_interf->iid)) == NULL ||
        (lk = leg->links[INTRUSION_TOL_LINK])                        == NULL ||
        (itdata = (Int_Tol_Data*) lk->prot_data)                     == NULL)
    {
        Alarmp(SPLOG_INFO, NETWORK, "Preprocess_intru_tol_packet:%d: dropping msg from unexpected src!\n", __LINE__);
        goto END;
    }

    /* if we have DH key for link, then try authenicating + decrypting msg; should fail for DH msgs */
    
    if (itdata->dh_key_computed == 2 && (ret = Sec_unlock_msg(scat, IT_Crypt_Buf, sizeof(IT_Crypt_Buf), itdata->decrypt_ctx, itdata->hmac_ctx)) >= 0)
    {
        unsigned char *src     = IT_Crypt_Buf;
        unsigned char *src_end = IT_Crypt_Buf + ret;
        int            i;
        
        /* success, DH handshake completed, copy decrypted msg back into scat and trim it down to stripped size */

        DH_established(lk);
        
        for (i = 0; i < scat->num_elements; src += scat->elements[i].len, ++i)
        {
            if (src + scat->elements[i].len > src_end)
                scat->elements[i].len = src_end - src;
            
            memcpy(scat->elements[i].buf, src, scat->elements[i].len);
        }
        
        goto END;
    }

    /* otherwise, if it looks like it might be a DH packet, then let it pass for further processing */

    if (Is_diffie_hellman(pack_type))
    {
        ret = received_bytes;
        goto END;
    }

    /* otherwise reject it */
    
    Alarmp(SPLOG_INFO, NETWORK, "Preprocess_intru_tol_packet:%d: dropping unauthenticated msg from " IPF "!\n", __LINE__, IP(src_addr));

END:
    return ret;
}

/***********************************************************/
/* void IT_Link_Pre_Conf_Setup()                           */
/*                                                         */
/* Sets up the configuration file defaults for the IT Link */
/*                                                         */
/* Return: NONE                                            */
/*                                                         */
/***********************************************************/
void IT_Link_Pre_Conf_Setup() {
    
    Conf_IT_Link.Crypto                     = IT_CRYPTO;
    Conf_IT_Link.Encrypt                    = IT_ENCRYPT;
    Conf_IT_Link.Ordered_Delivery           = ORDERED_DELIVERY;
    Conf_IT_Link.Reintroduce_Messages       = REINTRODUCE_MSGS;
    Conf_IT_Link.TCP_Fairness               = TCP_FAIRNESS;
    Conf_IT_Link.Session_Blocking           = SESSION_BLOCKING;
    Conf_IT_Link.Msg_Per_SAA                = MSG_PER_SAA;
    Conf_IT_Link.Send_Batch_Size            = SEND_BATCH_SIZE;
    Conf_IT_Link.Intrusion_Tolerance_Mode   = INTRUSION_TOLERANCE_MODE;
    Conf_IT_Link.Reliable_Timeout_Factor    = RELIABLE_TIMEOUT_FACTOR;
    Conf_IT_Link.NACK_Timeout_Factor        = NACK_TIMEOUT_FACTOR;
    Conf_IT_Link.ACK_Timeout                = ACK_TO;
    Conf_IT_Link.PING_Timeout               = PING_TO;
    Conf_IT_Link.DH_Timeout                 = DH_TO;
    Conf_IT_Link.Incarnation_Timeout        = INCARNATION_TO;
    Conf_IT_Link.Min_RTT_milliseconds       = MIN_RTT_MS;
    Conf_IT_Link.Default_RTT                = IT_DEFAULT_RTT;
    Conf_IT_Link.Init_NACK_Timeout_Factor   = INIT_NACK_TO_FACTOR;

    Conf_IT_Link.Loss_Threshold             = LOSS_THRESHOLD;
    Conf_IT_Link.Loss_Calc_Decay            = LOSS_CALC_DECAY;
    Conf_IT_Link.Loss_Calc_Time_Trigger     = LOSS_CALC_TIME_TRIGGER;
    Conf_IT_Link.Loss_Calc_Pkt_Trigger      = LOSS_CALC_PKT_TRIGGER;
    Conf_IT_Link.Loss_Penalty               = LOSS_PENALTY;
    Conf_IT_Link.Ping_Threshold             = PING_THRESHOLD;

/*    printf(
            "%s\n"
            "%s\n"
            "%s\n"
            "%s\n"
            "%s\n"
            
            "%d\n"
            "%d\n"
            "%d\n"
            "%d\n"

            "%d\n"
            "%d\n"
            "%d\n"
            "%d\n"
            "%d\n"
            "%d\n"
            
            "%f\n",

(Conf_IT_Link.Crypto)?"TRUE":"FALSE",
(Conf_IT_Link.Ordered_Delivery)?"TRUE":"FALSE",
(Conf_IT_Link.Reintroduce_Messages)?"TRUE":"FALSE",
(Conf_IT_Link.TCP_Fairness)?"TRUE":"FALSE",
(Conf_IT_Link.Session_Blocking)?"TRUE":"FALSE",

Conf_IT_Link.Msg_Per_SAA,
Conf_IT_Link.Send_Batch_Size,
Conf_IT_Link.Reliable_Timeout_Factor,
Conf_IT_Link.NACK_Timeout_Factor,

Conf_IT_Link.ACK_Timeout,
Conf_IT_Link.PING_Timeout,
Conf_IT_Link.DH_Timeout,
Conf_IT_Link.Incarnation_Timeout,
Conf_IT_Link.Min_RTT_milliseconds,
Conf_IT_Link.Default_RTT,

Conf_IT_Link.Init_NACK_Timeout_Factor); */

}


/***********************************************************/
/* void IT_Link_Post_Conf_Setup()                          */
/*                                                         */
/* Sets up timers and data structures after reading from   */
/* the configuration file for the IT Link                  */
/*                                                         */
/* Return: NONE                                            */
/*                                                         */
/***********************************************************/
void IT_Link_Post_Conf_Setup() {
        
    it_ack_timeout.sec  = Conf_IT_Link.ACK_Timeout / 1000000;
    it_ack_timeout.usec = Conf_IT_Link.ACK_Timeout % 1000000;
    
    it_ping_timeout.sec  = Conf_IT_Link.PING_Timeout / 1000000;
    it_ping_timeout.usec = Conf_IT_Link.PING_Timeout % 1000000;
 
    it_dh_timeout.sec  = Conf_IT_Link.DH_Timeout / 1000000;
    it_dh_timeout.usec = Conf_IT_Link.DH_Timeout % 1000000;

    it_incarnation_timeout.sec  = Conf_IT_Link.Incarnation_Timeout / 1000000;
    it_incarnation_timeout.usec = Conf_IT_Link.Incarnation_Timeout % 1000000;

    loss_calc_timeout.sec  = Conf_IT_Link.Loss_Calc_Time_Trigger / 1000000;
    loss_calc_timeout.usec = Conf_IT_Link.Loss_Calc_Time_Trigger % 1000000;

/*    printf(
            "%s\n"
            "%s\n"
            "%s\n"
            "%s\n"
            "%s\n"
            
            "%d\n"
            "%d\n"
            "%d\n"
            "%d\n"

            "%d\n"
            "%d\n"
            "%d\n"
            "%d\n"
            "%d\n"
            "%d\n"
            
            "%f\n",

(Conf_IT_Link.Crypto)?"TRUE":"FALSE",
(Conf_IT_Link.Ordered_Delivery)?"TRUE":"FALSE",
(Conf_IT_Link.Reintroduce_Messages)?"TRUE":"FALSE",
(Conf_IT_Link.TCP_Fairness)?"TRUE":"FALSE",
(Conf_IT_Link.Session_Blocking)?"TRUE":"FALSE",

Conf_IT_Link.Msg_Per_SAA,
Conf_IT_Link.Send_Batch_Size,
Conf_IT_Link.Reliable_Timeout_Factor,
Conf_IT_Link.NACK_Timeout_Factor,

Conf_IT_Link.ACK_Timeout,
Conf_IT_Link.PING_Timeout,
Conf_IT_Link.DH_Timeout,
Conf_IT_Link.Incarnation_Timeout,
Conf_IT_Link.Min_RTT_milliseconds,
Conf_IT_Link.Default_RTT,

Conf_IT_Link.Init_NACK_Timeout_Factor); */

}

/***********************************************************/
/* int IT_Link_Conf_hton(unsigned char *buff)              */
/*                                                         */
/* Converts host storage of configuration parameters into  */
/* network format and writes to buff.                      */
/*                                                         */
/* Return: # of bytes written                              */
/*                                                         */
/***********************************************************/
int IT_Link_Conf_hton(unsigned char *buff)
{
    char scratch[32];
    unsigned char *write = (unsigned char*)buff;
    
    *(unsigned char*)write = Conf_IT_Link.Crypto; 
        write += sizeof(unsigned char);
    *(unsigned char*) write = Conf_IT_Link.Encrypt;
        write += sizeof(unsigned char);
    *(unsigned char*)write = Conf_IT_Link.Ordered_Delivery;
        write += sizeof(unsigned char);
    *(unsigned char*)write = Conf_IT_Link.Reintroduce_Messages;
        write += sizeof(unsigned char);
    *(unsigned char*)write = Conf_IT_Link.TCP_Fairness;
        write += sizeof(unsigned char);
    *(unsigned char*)write = Conf_IT_Link.Session_Blocking;
        write += sizeof(unsigned char);
    *(unsigned char*)write = Conf_IT_Link.Msg_Per_SAA;
        write += sizeof(unsigned char);
    *(unsigned char*)write = Conf_IT_Link.Send_Batch_Size;
        write += sizeof(unsigned char);
    *(unsigned char*)write = Conf_IT_Link.Intrusion_Tolerance_Mode;
        write += sizeof(unsigned char);
    *(int32u*)write = htonl(Conf_IT_Link.Reliable_Timeout_Factor);
        write += sizeof(int32u);
    *(int32u*)write = htonl(Conf_IT_Link.NACK_Timeout_Factor);
        write += sizeof(int32u);
    *(int32u*)write = htonl(Conf_IT_Link.ACK_Timeout);
        write += sizeof(int32u);
    *(int32u*)write = htonl(Conf_IT_Link.PING_Timeout);
        write += sizeof(int32u);
    *(int32u*)write = htonl(Conf_IT_Link.DH_Timeout);
        write += sizeof(int32u);
    *(int32u*)write = htonl(Conf_IT_Link.Incarnation_Timeout);
        write += sizeof(int32u);
    *(int32u*)write = htonl(Conf_IT_Link.Min_RTT_milliseconds);
        write += sizeof(int32u);
    *(int32u*)write = htonl(Conf_IT_Link.Default_RTT);
        write += sizeof(int32u);

    memset(scratch, 0, 32);
    memset(write, 0, sizeof(double));
    sprintf(scratch, "%g", Conf_IT_Link.Init_NACK_Timeout_Factor);
    sprintf((char*)(write), "%.8s", scratch);
    write += 8;
 
    memset(scratch, 0, 32);
    memset(write, 0, sizeof(double));
    sprintf(scratch, "%g", Conf_IT_Link.Loss_Threshold);
    sprintf((char*)(write), "%.8s", scratch); 
    write += 8;

    memset(scratch, 0, 32);
    memset(write, 0, sizeof(double));
    sprintf(scratch, "%g", Conf_IT_Link.Loss_Calc_Decay);
    sprintf((char*)(write), "%.8s", scratch); 
    write += 8;

    *(int32u*)write = htonl(Conf_IT_Link.Loss_Calc_Time_Trigger);
        write += sizeof(int32u);
    *(int32u*)write = htonl(Conf_IT_Link.Loss_Calc_Pkt_Trigger);
        write += sizeof(int32u);
    *(int32u*)write = htonl(Conf_IT_Link.Loss_Penalty);
        write += sizeof(int32u);
    *(int32u*)write = htonl(Conf_IT_Link.Ping_Threshold);
        write += sizeof(int32u);

    return write - buff;
}

/***********************************************************/
/* void Process_intru_tol_data_packet (Link *lk,           */
/*                         sys_scatter *scat,              */              
/*                         int32u type,                    */
/*                         int mode,                       */
/*                                                         */
/* Processes a Intrustion Tolerant Link data packet        */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* lk:          link that gave me the message              */
/* scat:        a sys_scatter containing the message       */
/* type:        type of the packet                         */
/* mode:        mode of the link the packet arrived on     */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/
void Process_intru_tol_data_packet(Link *lk, sys_scatter *scat, 
        int32u type, int mode) 
{
    int ret;
    Int_Tol_Data *itdata;
    intru_tol_pkt_tail *itt;
    int16u data_len, ack_len;
    packet_header *phdr;

    UNUSED(mode);

    if (scat->num_elements < 2) {
        Alarm(PRINT, "Process_intru_tol_data_packet: scat->num_elements"
            " == %d, which is less than required (2)\r\n", scat->num_elements);
        return;
    }

    if (scat->elements[1].len < sizeof(intru_tol_pkt_tail))
    {
        Alarmp(SPLOG_WARNING, PRINT, "Process_intru_tol_data_packet: packet too small!\n");
        return;
    }

    phdr = (packet_header*) scat->elements[0].buf;
    data_len = phdr->data_len;
    ack_len = phdr->ack_len;

    /* TODO: Check Endianness */
    if (!Same_endian(type)) {
        /* Check if Priority_Flooding and flip Prio_Flood_Hdr? */
        /* Flip pkt_tail */
    }

    itdata  = (Int_Tol_Data*) lk->prot_data;
    if (itdata == NULL) {
        Alarm(DEBUG, "Process_intru_tol_data_packet: Int_Tol_Data is NULL on "
                     "this link\r\n");
        return;
    }

    /* Check the incarnations first */
    itt = (intru_tol_pkt_tail*)(scat->elements[1].buf + data_len); 
    
    /* printf("DATA MSG FROM "IPF", data_len = %d, ack_len = %d, seq_num = %d\n, in_tail_seq = %d\n", 
            IP(lk->leg->remote_interf->net_addr), data_len, ack_len, itt->link_seq, itdata->in_tail_seq); */
    
    if (itt->incarnation != itdata->ngbr_incarnation) {
        Alarm(DEBUG, "\tNGBR_INC DON'T MATCH - "IPF"\n", IP(lk->leg->remote_interf->net_addr));
        return;
    }
    if (itt->aru_incarnation != itdata->my_incarnation) {
        Alarm(DEBUG, "my_inc don't match - "IPF"\n", IP(lk->leg->remote_interf->net_addr));
        return;
    }

    ret = Process_IT_Ack(lk->link_id, scat->elements[1].buf, data_len, ack_len);
}


/***********************************************************/
/* void Process_intru_tol_ack_packet (Link *lk,            */
/*                          sys_scatter *scat,             */
/*                          int32u type,                   */
/*                          int mode,                      */
/*                                                         */
/* Processes a Intrustion Tolerant Link ack                */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* lk:          link that gave me the message              */
/* scat:        a sys_scatter containing the message       */
/* type:        type of the packet                         */
/* mode:        mode of the link the packet arrived on     */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/
void Process_intru_tol_ack_packet(Link *lk, sys_scatter *scat, 
            int32u type, int mode)
{
    int ret;
    Int_Tol_Data *itdata;
    intru_tol_pkt_tail *itt;
    int16u ack_len, data_len;
    packet_header *phdr;

    if (scat->num_elements < 2) {
        Alarm(PRINT, "Process_intru_tol_ack_packet: scat->num_elements"
            " == %d, which is less than required (2)\r\n", scat->num_elements);
        return;
    }

   if (scat->elements[1].len < sizeof(intru_tol_pkt_tail))
    {
        Alarmp(SPLOG_WARNING, PRINT, "Process_intru_tol_ack_packet: packet too small!\n");
        return;
    }
   
    phdr = (packet_header*) scat->elements[0].buf;
    data_len = phdr->data_len;
    ack_len = phdr->ack_len;

    UNUSED(mode);

    /* Check Endianness */
    if (!Same_endian(type)) {
        /* Flip pkt_tail */
    }

    itdata  = (Int_Tol_Data*) lk->prot_data;
    if (itdata == NULL) {
        Alarm(DEBUG, "Process_intru_tol_ack_packet: Int_Tol_Data is NULL on "
                     "this link\r\n");
        return;
    }

    /* Check the incarnations first */
    itt = (intru_tol_pkt_tail*)(scat->elements[1].buf); 
    if (itt->incarnation != itdata->ngbr_incarnation)
        return;
    if (itt->aru_incarnation != itdata->my_incarnation) 
        return;

    ret = Process_IT_Ack(lk->link_id, scat->elements[1].buf, data_len, ack_len);
}

/***********************************************************/
/* void Process_intru_tol_ping (Link *lk,                  */
/*                          sys_scatter *scat,             */
/*                          int32u type,                   */
/*                          int mode,                      */
/*                                                         */
/* Processes a Intrustion Tolerant Link ping               */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* lk:          link that gave me the message              */
/* scat:        a sys_scatter containing the message       */
/* type:        type of the packet                         */
/* mode:        mode of the link the packet arrived on     */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/
void Process_intru_tol_ping(Link *lk, sys_scatter *scat, 
        int32u type, int mode)
{
    double new_rtt;
    int32u index;
    Int_Tol_Data *itdata;
    intru_tol_ping *ping; 
    long unsigned temp;
    sp_time diff_rtt, now, delta;
    int16u data_len, ack_len;
    packet_header *phdr;

    if (scat->num_elements != 2) {
        Alarm(PRINT, "Process_intru_tol_ping: scat->num_elements"
            " == %d, which is less than required (2)\r\n", scat->num_elements);
        return;
    }

    phdr = (packet_header*) scat->elements[0].buf;
    data_len = phdr->data_len;
    ack_len = phdr->ack_len;
    
    now = E_get_time();

    if (scat->elements[1].len < sizeof(intru_tol_ping) || data_len != sizeof(intru_tol_ping)) {
        Alarm(DEBUG, "Process_intru_tol_ping: invalid ping size\r\n");
        return;
    }

    /* Check Endianness */
    if (!Same_endian(type)) {
        /* Flip ping */
    }

    itdata = (Int_Tol_Data*) lk->prot_data;
    if (itdata == NULL) {
        Alarm(DEBUG, "Process_intru_tol_ping:" 
              "Int_Tol_Data is NULL on this link\r\n");
        return;
    }
    
    ping = (intru_tol_ping*)(scat->elements[1].buf);

    /* Optimization - If PONG message, check seq validity and uniqueness */
    if (ping->ping_type == PONG) {
        if (ping->ping_seq >= itdata->next_ping_seq ||
            ping->ping_seq + MAX_PING_HIST < itdata->next_ping_seq) {
            return;
        }
        if (itdata->ping_history[ping->ping_seq % MAX_PING_HIST].answered == 1)
            return;
    }

    /* Optimization - If PING message, can't answer back too quickly */
    if (ping->ping_type == PING && 
            E_compare_time(itdata->pong_freq, now) > 0) {
        return;
    }

    /* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
    /*                    Check Incarnations                        */
    /* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
    /* Check the low-level incarnation advertised by this neighbor  */
    if (ping->incarnation < itdata->ngbr_incarnation)
        return;

    /* Check if their low-level incarnation is greater */
    /* than what we have stored */
    else if (ping->incarnation > itdata->ngbr_incarnation) {
        if (E_compare_time(itdata->incarnation_response, now) > 0)
            return;
        Incarnation_Change(lk->link_id, ping->incarnation, mode);        
        if (!E_in_queue(Reliable_IT_Timeout, (int)(lk->link_id), NULL))
            E_queue(Reliable_IT_Timeout, (int)(lk->link_id), NULL, zero_timeout);
    }

    /* Check if what they have as my incarnation is valid */
    if (ping->aru_incarnation > itdata->my_incarnation) {
        Alarm(PRINT, "Process_IT_Ping: possible bad node detected? They claim \
                        my incarnation is too high\r\n");
        return;
    }

    /* else if (ping->aru_incarnation < itdata->my_incarnation) {
        if (E_compare_time(itdata->incarnation_response, now) <= 0) {
            Alarm(PRINT, "Process_IT_Ping: updating ngbr "IPF" about my "
                    " incarnation\r\n", IP(lk->leg->remote_interf->net_addr));
            Send_IT_Ack(link_id);
            itdata->incarnation_response =
                                E_add_time(now, it_incarnation_timeout);
        }
        return;
    } */

    switch (ping->ping_type) {
        case PING: /* send back a PONG to this neighbor */
            ping->ping_type = PONG;
            ping->incarnation = itdata->my_incarnation;
            ping->aru_incarnation = itdata->ngbr_incarnation;
            temp = (it_ping_timeout.sec * 1000000 + it_ping_timeout.usec) / 2;
            delta.sec = temp / 1000000;
            delta.usec = temp % 1000000;
            itdata->pong_freq = E_add_time(now, delta);
            Send_IT_Ping( lk->link_id, scat->elements[1].buf );
            break;
        case PONG: /* use this PONG to update the rtt */
            index = ping->ping_seq % MAX_PING_HIST;
            if (itdata->ping_history[index].ping_seq == ping->ping_seq &&
                itdata->ping_history[index].ping_nonce == ping->ping_nonce)
            {
                itdata->ping_history[index].answered = 1;
                diff_rtt = E_sub_time(E_get_time(), 
                                      itdata->ping_history[index].ping_sent);
                new_rtt = diff_rtt.sec * 1000.0 + diff_rtt.usec / 1000.0;
                itdata->rtt = (0.8)*itdata->rtt + (0.2)*new_rtt;
                if (itdata->rtt < (double)Conf_IT_Link.Min_RTT_milliseconds)
                    itdata->rtt = (double)Conf_IT_Link.Min_RTT_milliseconds;
                /* Update relevant timers */
                itdata->it_nack_timeout.sec      = 
                        (Conf_IT_Link.NACK_Timeout_Factor * itdata->rtt) / 1000; 
                itdata->it_nack_timeout.usec     =
                        ( (int) (Conf_IT_Link.NACK_Timeout_Factor * itdata->rtt * 1000) )
                        % 1000000;
                itdata->it_initial_nack_timeout.sec  = 
                        (Conf_IT_Link.Init_NACK_Timeout_Factor * itdata->rtt) / 1000; 
                itdata->it_initial_nack_timeout.usec     =
                        ( (int) (Conf_IT_Link.Init_NACK_Timeout_Factor * itdata->rtt * 1000) )
                        % 1000000;
                itdata->it_reliable_timeout.sec  = 
                        (Conf_IT_Link.Reliable_Timeout_Factor * itdata->rtt) / 1000;
                itdata->it_reliable_timeout.usec =
                        ( (int) (Conf_IT_Link.Reliable_Timeout_Factor * itdata->rtt * 1000) )
                        % 1000000;
                Alarm(DEBUG, "[%lu] [%lu] RTT = %f\tNack Timeout = %lu\tReliable "
                             "Timeout = %lu\r\n", 
                    ping->ping_seq, itdata->last_pong_seq_recv, itdata->rtt, itdata->it_nack_timeout.usec, 
                    itdata->it_reliable_timeout.usec);
                /* REROUTE: update latest received PONG seq, link may now be alive again */
                if (ping->ping_seq > itdata->last_pong_seq_recv) {
                    itdata->last_pong_seq_recv = ping->ping_seq;
                    if (Conf_IT_Link.Intrusion_Tolerance_Mode == 1 && itdata->link_status == LINK_DEAD) {
                        /* a recovering link is first considered lossy, then will become "live" again
                         *      after some time - We queue the Loss Calculation Event after this time */
                        /* itdata->link_status = LINK_LIVE; */
                        itdata->link_status = LINK_LOSSY;
                        Generate_Link_Status_Change(lk->leg->remote_interf->net_addr, itdata->link_status);  
                    }
                }
            }
            break;
        default:
            Alarm(DEBUG, "Process_intru_tol_ping: neither PING nor PONG\r\n");
    }
}


/***********************************************************/
/* void Process_DH_IT      (Link *lk,                      */
/*                          sys_scatter *scat,             */
/*                          int32u type,                   */
/*                          int mode,                      */
/*                                                         */
/* Processes a Intrustion Tolerant DH msg                  */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* lk:          link that gave me the message              */
/* scat:        a sys_scatter containing the message       */
/* type:        type of the packet                         */
/* mode:        mode of the link the packet arrived on     */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/
void Process_DH_IT(Link *lk, sys_scatter *scat, 
            int32u type, int mode)
{
    Int_Tol_Data *itdata;
    int bn_size, ret;
    unsigned int sign_len;
    BIGNUM *bn;
    char *read_ptr, *end_ptr;
    stdit it;
    int32u src, dst, my_inc, ngbr_inc, src_id;
    sp_time now = E_get_time();
    EVP_MD_CTX *md_ctx;
    int16u data_len;
    packet_header *phdr;

    if (scat->num_elements != 2) {
        Alarm(PRINT, "Process_DH_IT: scat->num_elements"
            " == %d, which is less than required (2)\r\n", scat->num_elements);
        return;
    }

    phdr = (packet_header*) scat->elements[0].buf;
    data_len = phdr->data_len;

    UNUSED(type);

    /* Flip endianess? */

    itdata = (Int_Tol_Data*) lk->prot_data;
    if (itdata == NULL) {
        Alarm(DEBUG, "Process_DH_IT: Int_Tol_Data is NULL on this link\r\n");
        return;
    }

    /* timing check here */
    if (E_compare_time(itdata->incarnation_response, now) > 0) {
        Alarm(DEBUG, "Process_DH_IT: incarnation response has not timed out yet:"
                    "  response = %u.%u, now = %u.%u\r\n", 
                    itdata->incarnation_response.sec, itdata->incarnation_response.usec,
                    now.sec, now.usec);
        return;
    }

    read_ptr = scat->elements[1].buf;
    end_ptr  = scat->elements[1].buf + data_len;

    if (data_len > scat->elements[1].len || read_ptr + sizeof(Interface_ID) > end_ptr)
    {
        Alarm(PRINT, "Process_DH_IT:%d: packet too small!\n", __LINE__);
        return;
    }
    
    src = *(Interface_ID*)read_ptr;
    if (src != lk->leg->remote_interf->iid) {
        Alarm(PRINT, "Process_DH_IT: bogus src = %d\r\n", src);
        return;
    }
    read_ptr += sizeof(Interface_ID);
    
    if (read_ptr + sizeof(Interface_ID) > end_ptr)
    {
        Alarm(PRINT, "Process_DH_IT:%d: packet too small!\n", __LINE__);
        return;
    }
    
    dst = *(Interface_ID*)read_ptr;
    if (dst != lk->leg->local_interf->iid) {
        Alarm(PRINT, "Process_DH_IT: bogus dst = %d\r\n", dst);
        return;
    }
    read_ptr += sizeof(Interface_ID);

    if (read_ptr + sizeof(int32u) > end_ptr)
    {
        Alarm(PRINT, "Process_DH_IT:%d: packet too small!\n", __LINE__);
        return;
    }
    
    ngbr_inc = *(int32u*)read_ptr;
    if (ngbr_inc <= itdata->ngbr_incarnation) {
        Alarm(PRINT, "Process_DH_IT: bad ngbr_incarnation --> packet = %d, stored = %d \r\n", 
                        ngbr_inc, itdata->ngbr_incarnation);
        return;
    }
    read_ptr += sizeof(int32u);

    if (read_ptr + sizeof(int32u) > end_ptr)
    {
        Alarm(PRINT, "Process_DH_IT:%d: packet too small!\n", __LINE__);
        return;
    }
    
    my_inc = *(int32u*)read_ptr;
    if (my_inc > itdata->my_incarnation) {
        Alarm(PRINT, "Process_DH_IT: bad my_incaration = %d\r\n", my_inc);
        return;
    }
    read_ptr += sizeof(int32u);

    if (read_ptr + sizeof(int16u) > end_ptr)
    {
        Alarm(PRINT, "Process_DH_IT:%d: packet too small!\n", __LINE__);       
        return;
    }
    
    bn_size = *(int16u*)read_ptr;
    read_ptr += sizeof(int16u);

    if (read_ptr + bn_size > end_ptr)
    {
        Alarm(PRINT, "Process_DH_IT:%d: packet too small!\n", __LINE__);
        return;
    }
    
    bn = BN_new();
    if(bn==NULL){
        Alarm(EXIT, "BN_new() failed \r\n");
    }
    BN_bin2bn((unsigned char*)read_ptr, bn_size, bn);
    read_ptr += bn_size;

    /* Check this neighbors configuration file hash against ours */
    if (read_ptr + HMAC_Key_Len > end_ptr)
    {
        Alarm(PRINT, "Process_DH_IT:%d: packet too small!\n", __LINE__);
        goto bn_cleanup;
    }
    
    if (memcmp(read_ptr, Conf_Hash, HMAC_Key_Len) != 0) {
        Alarm(PRINT, "Process_DH_IT: hash of config files do not match!\r\n");
        goto bn_cleanup;
    }
    read_ptr += HMAC_Key_Len;

    /* Verify the RSA signature */
    sign_len = data_len - (unsigned int)(read_ptr - scat->elements[1].buf);
    
    if (sign_len != Signature_Len || sign_len > data_len) {
        Alarm(PRINT, "Process_DH_IT: sign_len (%d) != Key_Len (%d), data_len = %d\n",
              sign_len, Signature_Len, data_len);
        goto bn_cleanup;
    }

    if (read_ptr + sign_len > end_ptr)
    {
        Alarm(PRINT, "Process_DH_IT:%d: packet too small!\n", __LINE__);
        goto bn_cleanup;
    }

    md_ctx = EVP_MD_CTX_new();
    if(md_ctx==NULL){
        Alarm(EXIT, "Process_DH_IT:%d: failed to allocate EVP_MD_CTX\n", __LINE__);
    }
    ret = EVP_VerifyInit(md_ctx, EVP_sha256()); 
    if (ret != 1) { 
        Alarm(PRINT, "Process_DH_IT: VerifyInit failed\r\n");
        goto cr_cleanup;
    }

    /* Adjust seq_no on packet_header for checking signature */
    phdr->seq_no = 0;
    ret = EVP_VerifyUpdate(md_ctx, (unsigned char*)phdr, sizeof(packet_header));
    if (ret != 1) {
        Alarm(PRINT, "Process_DH_IT: VerifyUpdate for packet_header failed\r\n");
        goto cr_cleanup;
    }

    ret = EVP_VerifyUpdate(md_ctx, (unsigned char*)scat->elements[1].buf, 
                            (unsigned int)(data_len - sign_len));
    if (ret != 1) {
        Alarm(PRINT, "Process_DH_IT: VerifyUpdate for packet_body failed\r\n");
        goto cr_cleanup;
    }

    stdhash_find(&Node_Lookup_Addr_to_ID, &it, &src);
    if (stdhash_is_end(&Node_Lookup_Addr_to_ID,  &it)) {
        Alarm(PRINT, "Process_DH_IT: \
                      source not in config file");
        goto cr_cleanup;
    }
    src_id = *(int32u *)stdhash_it_val(&it);
    /* printf("SRC_ID = %d, MSG_LEN = %d, DATA_LEN = %d\n", src_id, data_len - sign_len, data_len); */

    ret = EVP_VerifyFinal(md_ctx, (unsigned char*)read_ptr, sign_len, 
                            Pub_Keys[src_id]);
    if (ret != 1) {
        Alarm(PRINT, "Process_DH_IT: VerifyFinal failed\r\n");
        goto cr_cleanup;
    }

    /* Possibly send response, maybe just set state flag */
    
    if (itdata->dh_key_computed == 1) {
        if (!E_in_queue(Send_IT_DH, lk->link_id, NULL))
            Alarm(EXIT, "Process_DH_IT: send event should be queued\r\n");
    }
    else {
        itdata->dh_key_computed = 0;
        Key_Exchange_IT(lk->link_id, NULL);
    }

    /* Now compute the DH key and enable pings and loss calculation */
    ret = DH_compute_key(itdata->dh_key, bn, itdata->dh_local);
    if (ret < 0)
        Alarm(EXIT, "Process_DH_IT: DH_compute_key failed with ret = -%d\r\n", ret);
    
    itdata->dh_key_computed = 2;

    E_queue(Ping_IT_Timeout, (int)lk->link_id, NULL, it_ping_timeout);
    E_queue(Loss_Calculation_Event, (int)lk->link_id, NULL, loss_calc_timeout);
    
    /* Initialize crypto ctx's for this link */
    EVP_EncryptInit_ex(itdata->encrypt_ctx, EVP_aes_128_cbc(), NULL, itdata->dh_key, NULL);
    EVP_DecryptInit_ex(itdata->decrypt_ctx, EVP_aes_128_cbc(), NULL, itdata->dh_key, NULL);
    HMAC_Init_ex(itdata->hmac_ctx, itdata->dh_key, HMAC_Key_Len, EVP_sha256(), NULL);

    Incarnation_Change(lk->link_id, ngbr_inc, mode);

    /* clean up memory allocated for crypto ops */
    /* if we had a meaningful return value, would want to distinguish failure
     * vs. non-failure cases here, but that requires bigger changes */
    cr_cleanup:
        EVP_MD_CTX_free(md_ctx);
    bn_cleanup:
        BN_clear_free(bn);
}

/***********************************************************/
/* int Forward_Intru_Tol_Data (Node *next_hop,             */
/*                          sys_scatter *scat)             */
/*                                                         */
/* Forwards an Intrustion Tolerant Data Packet             */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* next_hop:    node to send this packet to                */
/* scat:        a sys_scatter containing the message       */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int) the status of the packet (see udp.h)              */
/*                                                         */
/***********************************************************/
int Forward_Intru_Tol_Data(Node *next_hop, sys_scatter *scat)
{
    Link *lk;
    sp_time now;
    Int_Tol_Data *itdata;
    int ret = BUFF_OK;
    int16u msg_size = 0;
    int64u i, j;

    /* Sanity checking for space for new messages, valid link and protocol
     * data, and no jumbo packets. This function will only succeed if there
     * is space for at least one packet of the new message in the window */ 
    if (Full_Link_IT(next_hop)) {
        /* IT_full_dropped++; */
        Alarm( PRINT, "Forward_Intru_Tol_Data: full link\r\n");
        ret = BUFF_FULL;
    }

    if ((lk = Get_Best_Link(next_hop->nid, INTRUSION_TOL_LINK)) == NULL || lk->prot_data == NULL || 
            (Conf_IT_Link.Intrusion_Tolerance_Mode == 0 && lk->leg->links[CONTROL_LINK] == NULL)) {
        /* IT_dead_dropped++; */
        Alarm( PRINT, "Forward_Intru_Tol_Data: link dead\r\n");
        ret = BUFF_DROP;
    }

    itdata  = (Int_Tol_Data*) lk->prot_data;
    if (itdata->out_message != NULL) {
        Alarm( PRINT, "Forward_Intru_Tol_Data: out_message is not NULL!\r\n");
        ret = BUFF_DROP;
    }

    for (i = 1; i < scat->num_elements; i++)
        msg_size += scat->elements[i].len;

    if (msg_size + MAX_PKTS_PER_MESSAGE * (Link_Header_Size(INTRUSION_TOL_LINK) + 
                sizeof(fragment_header)) > MAX_MESSAGE_SIZE) 
    {
        Alarm( PRINT, "Forward_Intru_Tol_Data: cannot forward data, message "
                      "too big: %d + %d\r\n", msg_size, 
                      MAX_PKTS_PER_MESSAGE * (Link_Header_Size(INTRUSION_TOL_LINK) + 
                      sizeof(fragment_header)) );
        /* IT_size_dropped++; */
        ret = BUFF_DROP;
    }

    if (scat->elements[0].len != sizeof(packet_header)) {
        Alarm( PRINT, "Forward_Intru_Tol_Data: spines packet_header malformed in"
                       " element 0\r\n");
        ret = BUFF_DROP;
    }

    if (ret == BUFF_DROP)
        return ret;

    itdata->out_message = scat;
    inc_ref_cnt(scat); 
    for (i = 0; i < scat->num_elements; i++)
        inc_ref_cnt(scat->elements[i].buf);
    itdata->out_frag_idx = 1; /* skip the spines packet_header @ index 0 */
    itdata->out_frag_total = scat->num_elements - 1; /* index 0 doesn't count */

    /* Start packing fragments into packets */
    if (Pack_Fragments_Into_Packets_IT( lk ) == BUFF_DROP) {
        Alarm( PRINT, "Packing problem in Forward Data\r\n");
        Cleanup_Scatter(itdata->out_message);
        itdata->out_message = NULL;
        return BUFF_DROP;
    }

    /*new_pkt = itdata->out_head_seq;
    index   = new_pkt % MAX_SEND_ON_LINK;

    IT_total_pkts++; */
    /* if (IT_total_pkts % 10000 == 0) {
        printf("~~Packet Statistics~~\n");
        printf("\tTCP win_size:%3f   ssthresh:%3d\n", itdata->cwnd,
               itdata->ssthresh);
        printf("\ttotal:%6lu   full:%6lu   dead:%6lu   size%6lu\n",
               IT_total_pkts, IT_full_dropped, IT_dead_dropped,
               IT_size_dropped);
    } */

    /* insert this packet into the window */
    /* itdata->outgoing[index].pkt = buff;
    itdata->outgoing[index].data_len = data_len;
    itdata->outgoing[index].resent = 0;
    itdata->outgoing[index].nacked = 0; */

    /* calculate the nonce for this packet */
    /* itdata->out_nonce[index] = rand();
    itdata->out_nonce[index] = (itdata->out_nonce[index] << 32) |
                                rand();
    itdata->out_nonce_digest[index] = itdata->out_nonce[index] ^
             itdata->out_nonce_digest[(itdata->out_head_seq - 1) %
             MAX_SEND_ON_LINK]; */

    /* increment the head to point to the next available slot */ 
    /* itdata->out_head_seq++; */
    
    /* For client session blocking */
    if (Conf_IT_Link.Session_Blocking == 1 &&
        (itdata->out_head_seq - itdata->out_tail_seq) >= MAX_SEND_ON_LINK) {
        Block_All_Sessions();
    }
    
    now = E_get_time();

    j = MIN(itdata->out_head_seq, itdata->out_tail_seq + (int64u)itdata->cwnd);

    /* Check if we can send this message according to TCP fairness */
    for (i = itdata->tcp_head_seq; i < j && ret != BUFF_DROP; i++) {
        itdata->tcp_head_seq++;
        itdata->outgoing[i % MAX_SEND_ON_LINK].timestamp = 
                        E_add_time(now, itdata->it_initial_nack_timeout);
        ret = Send_IT_Data_Msg(lk->link_id, i);
    }

    return BUFF_OK;
}


/***********************************************************/
/* int Full_Link_IT(Node *next_hop)                        */
/*                                                         */
/* Checks if there is room for a new msg in a IT link      */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* next_hop:    node that this link connects to            */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* true (no room) or false (room)                          */
/*                                                         */
/***********************************************************/
int Full_Link_IT (Node *next_hop)
{
    Link *lk;
    Int_Tol_Data *itdata;

    /* if there is no current link or the IT data is not present,
     * consider this as a full window on the link */
    if ((lk = Get_Best_Link(next_hop->nid, INTRUSION_TOL_LINK)) == NULL || lk->prot_data == NULL ||
            (Conf_IT_Link.Intrusion_Tolerance_Mode == 0 && lk->leg->links[CONTROL_LINK] == NULL)) {
        return 1;
    }

    itdata = (Int_Tol_Data*) lk->prot_data;

    if ( (itdata->out_head_seq - itdata->out_tail_seq) < MAX_SEND_ON_LINK)
        return 0;

    Alarm(DEBUG, "Link is full toward "IPF"\n", IP(next_hop->nid));
    return 1;
}

/***********************************************************/
/* void Fill_Bucket_IT(int link_id, void* dummy)           */
/*                                                         */
/* Method that refills the bucket for this link-level      */
/*  protocol at the specified rate and up to the specified */
/*  capacity in the intrusion_tol_udp.h file               */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* link_id:   id of the link                               */
/* dummy:     not used                                     */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/
void Fill_Bucket_IT(int link_id, void* dummy)
{
    sp_time now, delta;
    unsigned int to_add;
    Link *lk;
    Int_Tol_Data *itdata;

    UNUSED(dummy);

    lk = Links[link_id];
    if (lk == NULL) {
        Alarm(DEBUG, "Fill_Bucket_IT: trying to look at NULL link\r\n");
        return;
    }
    itdata = (Int_Tol_Data*) lk->prot_data;
    if (itdata == NULL) {
        Alarm(DEBUG, "Fill_Bucket_IT: Int_Tol_Data is NULL on this link\r\n");
        return;
    }

    if (itdata->bucket > BUCKET_CAP)
        Alarm(EXIT, "Fill_Bucket_IT(): Bucket grew larger than max capacity\r\n");

    if (itdata->bucket == BUCKET_CAP) {
        Alarm(DEBUG, "Fill_Bucket_IT(): bucket was full!!\r\n");
        return;
    }

    now = E_get_time();
    delta = E_sub_time(now, itdata->last_filled);
    
    /* printf("now = %d.%d, last_filled = %d.%d, delta = %d.%d\n", now.sec, now.usec, itdata->last_filled.sec, itdata->last_filled.usec, delta.sec, delta.usec); */
    
    to_add = (RATE_LIMIT_KBPS / 8000.0) * (delta.sec * 1000000 + delta.usec);
    itdata->bucket += to_add;
    itdata->last_filled = now;

    if (itdata->bucket > BUCKET_CAP)
        itdata->bucket = BUCKET_CAP;

    E_queue(Fill_Bucket_IT, link_id, 0, it_bucket_to);

    if (itdata->needed_tokens > 0 && itdata->bucket > 0)
        Assign_Resources_IT(lk->leg->remote_interf->owner);    
}

/***********************************************************/
/* void Assign_Resources_IT(Node *next_hop)                */
/*                                                         */
/* Method for which lower level fills in its window with   */
/*  packets from high-level dissemination algorithm in     */
/*  a round-robin fashion. Only dissemination algorithms   */
/*  in the queue are considered.                           */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* next_hop:  node that this link connects to              */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/
void Assign_Resources_IT(Node *next_hop)
{
    int ret = 0;
    Link *lk;
    Int_Tol_Data *itdata;
    Dissem_Fair_Queue *dfq;

    if ((lk = Get_Best_Link(next_hop->nid, INTRUSION_TOL_LINK)) == NULL || lk->prot_data == NULL || 
            (Conf_IT_Link.Intrusion_Tolerance_Mode == 0 && lk->leg->links[CONTROL_LINK] == NULL))
    {
        Alarm(DEBUG, "Assign_Resources_IT(): link to neighbor is NULL\r\n");
        return;
    }
    itdata = (Int_Tol_Data*) lk->prot_data;

    /* If the bucket is already depleted, we cannot send a packet, must wait */
    if (itdata->needed_tokens > 0 && itdata->bucket < MAX_PACKET_SIZE)
        return;
    itdata->needed_tokens = 0;

    /* printf("\t\t\tABOUT TO CALL ASSIGN WHILE LOOP %d %d %d\n",
            !Full_Link_IT(next_hop), itdata->dissem_head.next != NULL,
            itdata->bucket >= MAX_PACKET_SIZE); */

    while (!Full_Link_IT(next_hop) && itdata->dissem_head.next != NULL && 
            itdata->bucket > 0) 
    {
        dfq = itdata->dissem_head.next;
        ret = (*dfq->callback)(next_hop, INTRUSION_TOL_LINK);
        itdata->bucket -= ret;
        /* Alarm(PRINT, "Just sent %d bytes to %d, sizes are %d %d %d %d %d %d\r\n",
            ret, &(next_hop->nid), sizeof(packet_header), sizeof(udp_header),
            1000, sizeof(rel_flood_header), 128, sizeof(rel_flood_tail)); */
        processed[dfq->dissemination] = 1;
        itdata->dissem_head.next = dfq->next;
        if (itdata->dissem_tail == dfq)
            itdata->dissem_tail = &itdata->dissem_head;
        if (ret == 0) {
            itdata->in_dissem_queue[dfq->dissemination] = 0;
            /* printf("\t\tCB returned 0, removing %d from queue\n", 
                        dfq->dissemination); */

            dispose(dfq);
        }
        else {
            dfq->next = NULL;
            itdata->dissem_tail->next = dfq;
            itdata->dissem_tail = dfq;
            /* printf("\tCB returned 1, still in queue\n"); */
        }
    } 

    if (!Full_Link_IT(next_hop) && itdata->dissem_head.next != NULL) {
        itdata->needed_tokens = 1;
    }

    if (itdata->bucket < BUCKET_CAP && !E_in_queue(Fill_Bucket_IT, lk->link_id, 0)) {
        E_queue(Fill_Bucket_IT, lk->link_id, 0, it_bucket_to);
        itdata->last_filled = E_get_time();
    }
}


/***********************************************************/
/* int Request_Resources_IT(int dissem, Node *next_hop     */
/*                         int (*callback)(Node*, int))    */
/*                                                         */
/* Method for which higher level dissemination algorithm   */
/* can request space in the lower level window when it     */
/* becomes available (it may be available now)             */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* dissem:    ID of the dissemination algorithm            */
/* next_hop:  node that this link connects to              */
/* callback:  function pointer to high level function that */
/*              is called when resources become available  */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* 1 - Resources available                                 */
/* 0 - Resources not available                             */
/*                                                         */
/***********************************************************/
int Request_Resources_IT(int dissem, Node *next_hop, 
                            int (*callback)(Node*, int))
{
    Link *lk = NULL;
    Int_Tol_Data *itdata;
    Dissem_Fair_Queue *dfq;

    if (dissem < 0 || dissem > (RESERVED_ROUTING_BITS >> ROUTING_BITS_SHIFT)) {
        Alarm(PRINT, "Request_Resources_IT(): invalid dissemination - %d\r\n",
                    dissem);
        return 0;
    }
    if ((lk = Get_Best_Link(next_hop->nid, INTRUSION_TOL_LINK)) == NULL || lk->prot_data == NULL || 
            (Conf_IT_Link.Intrusion_Tolerance_Mode == 0 && lk->leg->links[CONTROL_LINK] == NULL))
    {
        Alarm(DEBUG, "Request_Resources_IT(): link to neighbor is NULL\r\n");
        /* edge = Get_Edge(My_Address, next_hop->nid);
        lk = edge->leg->links[INTRUSION_TOL_LINK];
        itdata = (Int_Tol_Data*) lk->prot_data;
        printf("\ttail = %d, tcp_head = %d, head = %d\n", (int)itdata->out_tail_seq,
                    (int)itdata->tcp_head_seq, (int)itdata->out_head_seq); */
        return 0;
    }
    itdata = (Int_Tol_Data*) lk->prot_data;

    if (itdata->in_dissem_queue[dissem] == 0) {
        itdata->in_dissem_queue[dissem] = 1;
        dfq = (Dissem_Fair_Queue*) new (DISSEM_QUEUE_NODE);
        if (dfq == NULL)
            Alarm(EXIT, "Request_Resources_IT(): Cannot allocate \
                Dissem_Fair_Queue node for in_dissem_queue\r\n");
        dfq->dissemination = dissem;
        dfq->callback = callback;
        dfq->next = NULL;
        itdata->dissem_tail->next = dfq;
        itdata->dissem_tail = dfq;
    }

    if (!Full_Link_IT(next_hop)) {
        processed[dissem] = 0;
        Assign_Resources_IT(next_hop);  
        if (processed[dissem] == 1)
            return 1;
        else
            return 0;
    }
    
    return 0; 
}

/***********************************************************/
/* int Pack_Fragments_Into_Packets_IT (Link *lk)          */
/*                                                         */
/* Internal function that takes message fragments from the */
/*      current message and packs them into packets that   */
/*      fit inside the outgoing window, then places them   */
/*      there                                              */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* lk:      pointer to the link to send packets on         */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* BUFF_OK     success                                     */
/* BUFF_DROP   failure                                     */
/*                                                         */
/***********************************************************/
int Pack_Fragments_Into_Packets_IT ( Link *lk )
{
    int32u index;
    Int_Tol_Data *itdata;
    sys_scatter *link_scat;
    packet_header *phdr;
    fragment_header *fhdr;
  
    if (lk == NULL || (Conf_IT_Link.Intrusion_Tolerance_Mode == 0 && lk->leg->links[CONTROL_LINK] == NULL)) {
        Alarm(PRINT, "Pack_Fragments_Into_Packets_IT: trying to send on NULL link "
                "to " IPF "\r\n", IP(lk->leg->remote_interf->net_addr));
        return BUFF_DROP;   
    }
    itdata  = (Int_Tol_Data*) lk->prot_data;
    if (itdata == NULL) {
        Alarm(PRINT, "Pack_Fragments_Into_Packets_IT: Int_Tol_Data is NULL on this link\r\n");
        return BUFF_DROP;
    }

    /* Continue to pack fragments while:
     *      (1) There is space in the window AND
     *      (2) There is still a message to use */
    while (itdata->out_head_seq - itdata->out_tail_seq < MAX_SEND_ON_LINK &&
                itdata->out_message != NULL)
    {
        /* allocate scatter for the window element */
        if ((link_scat = (sys_scatter*) new_ref_cnt(SYS_SCATTER)) == NULL)
            Alarm(EXIT, "Pack_Fragments_Into_Packets_IT: Could not allocate "
                            "sys_scatter!\r\n");
        link_scat->num_elements = 0;

        /* allocate space for copy of spines header (packet_header) */
        if ((link_scat->elements[0].buf = new_ref_cnt(PACK_HEAD_OBJ)) == NULL)
            Alarm(EXIT, "Pack_Fragments_Into_Packets_IT: Could not allocate "
                            "packet_header!\r\n");
        link_scat->elements[0].len = sizeof(packet_header);
        link_scat->num_elements++;

        /* Copy the relevant information into this spines header */
        phdr = (packet_header*) link_scat->elements[0].buf;
        /* TODO: Endianess with signatures - would need each hop to send the message with the signed
         *          source endianess and make a local copy to read in its own endianess */
        phdr->type           = ((packet_header*)itdata->out_message->elements[0].buf)->type; 
        phdr->sender_id      = My_Address;
        phdr->ctrl_link_id   = lk->leg->ctrl_link_id;
        phdr->data_len       = 0;
        phdr->ack_len        = 0;
        phdr->seq_no         = 0;

        while (itdata->out_frag_idx <= itdata->out_frag_total && 
                phdr->data_len + itdata->out_message->elements[itdata->out_frag_idx].len +
                    Link_Header_Size(INTRUSION_TOL_LINK) + sizeof(fragment_header) <= MAX_PACKET_SIZE)
        {
            /* Set up scat to include new fragment, take responsibility, adjust length, and update
             *      packet_header length to include this fragment */
            link_scat->elements[link_scat->num_elements].buf = 
                itdata->out_message->elements[itdata->out_frag_idx].buf;
            inc_ref_cnt(itdata->out_message->elements[itdata->out_frag_idx].buf);
            link_scat->elements[link_scat->num_elements].len = 
                itdata->out_message->elements[itdata->out_frag_idx].len;
            phdr->data_len += link_scat->elements[link_scat->num_elements].len;
            link_scat->num_elements++;

            /* Add new frag tail for this fragment, allocating memory, setting the length, and
             *      updating the header */
            if ((link_scat->elements[link_scat->num_elements].buf = new_ref_cnt(FRAG_OBJ)) == NULL)
                Alarm(EXIT, "Pack_Fragments_Into_Packets_IT: Could not allocate "
                                "fragment_header!\r\n");
            link_scat->elements[link_scat->num_elements].len = sizeof(fragment_header);
            fhdr = (fragment_header*) link_scat->elements[link_scat->num_elements].buf;
            fhdr->frag_length = itdata->out_message->elements[itdata->out_frag_idx].len;
            fhdr->frag_idx = itdata->out_frag_idx;
            fhdr->frag_total = itdata->out_frag_total;
            phdr->data_len += sizeof(fragment_header);
            link_scat->num_elements++;

            /* Finished with this fragment, increment the index */
            itdata->out_frag_idx++;
        }

        /* Finished filling in a spot in the outgoing window */
        index = itdata->out_head_seq % MAX_SEND_ON_LINK;
        itdata->outgoing[index].pkt      = link_scat;
        itdata->outgoing[index].data_len = phdr->data_len;
        itdata->outgoing[index].resent   = 0;
        itdata->outgoing[index].nacked   = 0;

        /* Calculate the nonce for this packet */
        itdata->out_nonce[index] = rand();
        itdata->out_nonce[index] = (itdata->out_nonce[index] << 32) |
                                        rand();
        itdata->out_nonce_digest[index] = itdata->out_nonce[index] ^
                    itdata->out_nonce_digest[(itdata->out_head_seq - 1) %
                    MAX_SEND_ON_LINK];
        itdata->out_head_seq++;

        /* Add this packet to the loss_history calculation */
        itdata->loss_history_unique_packets[0]++;
        if (itdata->loss_history_unique_packets[0] >= Conf_IT_Link.Loss_Calc_Pkt_Trigger) {
            E_queue(Loss_Calculation_Event, (int)lk->link_id, NULL, zero_timeout);
        }

        /* Did we finish with this message? */
        if (itdata->out_frag_idx > itdata->out_frag_total) {
            Cleanup_Scatter(itdata->out_message);
            itdata->out_message = NULL;
        }
    }

    return BUFF_OK;
}

/***********************************************************/
/* int Build_Message_From_Fragments_IT(sys_scatter *scat,  */
/*                            char *buff, int16u data_len, */
/*                            unsigned char *frag_idx,     */
/*                            unsigned char *frag_total,   */
/*                            Link_Type mode)              */
/*                                                         */
/* Internal function that takes a packet and separates it  */
/*      into the fragments of the overarching message they */
/*      are a part of. The fragments are appended to the   */
/*      working message. If the message is completed, it   */
/*      is marked as ready to be delivered. Otherwise, we  */
/*      wait until the remainder of the message is         */
/*      received.                                          */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* scat:     pointer to the working message                */
/* buff:     pointer to the current packet to unpack       */
/* data_len: length of the packet (not including           */
/*                  link-specific tail)                    */
/* frag_idx: ptr to next expected fragment idx to process  */
/* frag_total: ptr to number of total frags in working msg */
/*              (total == 0 if working msg is empty)       */
/* mode:     type of the lower-level link                  */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */            
/* -1 - error when building the message                    */
/*  0 - message not ready                                  */
/*  1 - message ready for delivery                         */
/*                                                         */
/***********************************************************/
int Build_Message_From_Fragments_IT(sys_scatter *scat, char *buff, int16u data_len, 
                            unsigned char *idx, unsigned char *total, Link_Type mode)
{
    int ret = 0;
    int32u processed = 0, i;
    unsigned char array_idx = 0, max_array_idx = 0;
    char *data_ptr;
    fragment_header *frag_addr[MAX_SCATTER_ELEMENTS + 1];
    fragment_header *fh;
    packet_header *phdr;

    /* First, process the packet in reverse to obtain all of the fragments */
    while (processed < data_len) {
        fh = (fragment_header*)(buff + data_len - processed - sizeof(fragment_header));
    
        /* Check if this frag has a valid frag_total > 0 */
        if (fh->frag_total == 0 || fh->frag_total > MAX_SCATTER_ELEMENTS - 1)
            return -1; 

        /* If we have a new message, set the total to the number of fragments */
        if (*total == 0)
            *total = fh->frag_total;
        else if (*total != fh->frag_total)
            return -2;

        /* Check if the frag_index is valid */
        if (fh->frag_idx == 0 || fh->frag_idx > *total)
            return -3;

        /* If this is a new packet, grab the ending fragment's idx to enforce
         *      consecutive fragment indices */
        if (array_idx == 0) {
            array_idx = fh->frag_idx;
            max_array_idx = fh->frag_idx;
        }

        /* Enforcing consecutive fragment indices */
        if (fh->frag_idx != array_idx)
            return -4;

        /* Storing the fragment header location */
        frag_addr[fh->frag_idx] = fh;
        array_idx--;

        processed += sizeof(fragment_header) + fh->frag_length;
        
        /* Make sure we aren't trying to read before the start of the packet */
        if (processed > data_len)
            return -5;
    }

    /* If the message is new, setup the spines header  */
    if (scat->num_elements == 0) {

        if ((scat->elements[0].buf = (char *) new_ref_cnt (PACK_HEAD_OBJ)) == NULL) 
            Alarm(EXIT, "Build_Message_From_Fragments: could not allocate packet_header\r\n");
        scat->elements[0].len = sizeof(packet_header);
        scat->num_elements++;

        phdr = (packet_header*) scat->elements[0].buf;
        phdr->type = Get_Link_Data_Type(mode);
        phdr->type = Set_endian(phdr->type);
        phdr->data_len = 0;
        phdr->ack_len = 0;
        /* Should we set up the other fields of the spines header here? */ 
    }

    /* Now, process the fragments in increasing order */
    for ( array_idx++ ; array_idx <= max_array_idx; array_idx++) {
      
        if (array_idx != *idx || frag_addr[array_idx]->frag_idx != *idx) {
            for (i = 0; i < scat->num_elements; i++) 
                dec_ref_cnt(scat->elements[i].buf);
            return -6;
        }

        data_ptr = (char*)(frag_addr[array_idx]) - frag_addr[array_idx]->frag_length;
       
        /* The first fragment is not copied, the address is just assigned */
        if (data_ptr == buff) {
            scat->elements[scat->num_elements].buf = data_ptr;
            inc_ref_cnt(data_ptr);
        }
        /* Additional fragments are copied into their own packet_body object */
        else {
            if ( (scat->elements[scat->num_elements].buf = (char*) new_ref_cnt (PACK_BODY_OBJ)) == NULL)
                Alarm(EXIT, "Build_Message_From_Fragments: could not allocate packet body object\r\n");
            memcpy(scat->elements[scat->num_elements].buf, data_ptr, frag_addr[array_idx]->frag_length);
        }
        
        scat->elements[scat->num_elements].len = frag_addr[array_idx]->frag_length;
        scat->num_elements++;
        (*idx)++;
    }
    
    assert(scat->num_elements == *idx);

    /* Is this message complete? */
    if ( *idx == *total + 1) {
        ret = 1;
    }

    return ret;
}

/***********************************************************/
/* int Send_IT_Data_Msg(int link_id, int64u seq)           */
/*                                                         */
/* Internal send function that sends packet w/ sequence    */
/*     number = seq on the current link                    */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* link_id:     id of the link to send the packet on       */
/* seq:         seq number of the desired packet to send   */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* Status of the buffer: dropped, empty (sent), etc.       */
/*                                                         */
/***********************************************************/
int Send_IT_Data_Msg(int link_id, int64u seq)
{
    Link *lk;
    Int_Tol_Data *itdata;
    sys_scatter *link_scat;
    packet_header *hdr;
    int32u index;
    int data_len, ack_len, ret;
    intru_tol_pkt_tail *itt;
    sp_time now;

    now = E_get_time();

    if (network_flag != 1) {
        return BUFF_DROP;
    }

    /* Getting Link and intrusion tolerant data from link_id */
    lk = Links[link_id];
    /* if (lk == NULL) { */
    if (lk == NULL || (Conf_IT_Link.Intrusion_Tolerance_Mode == 0 && lk->leg->links[CONTROL_LINK] == NULL)) {
        Alarm(DEBUG, "Send_IT_Data_Msg: trying to send on NULL link "
                "to " IPF "\r\n", IP(lk->leg->remote_interf->net_addr));
        return BUFF_DROP;   
    }
    itdata  = (Int_Tol_Data*) lk->prot_data;
    if (itdata == NULL) {
        Alarm(PRINT, "Send_IT_Data_Msg: Int_Tol_Data is NULL on this link\r\n");
        return BUFF_DROP;
    }

    /* Check that the sequence is valid (between tail and head) */
    if (seq < itdata->out_tail_seq || seq >= itdata->tcp_head_seq) {
        Alarm(PRINT, "Send_IT_Data_Msg: invalid seq number to send\r\n");
        printf("\ttail = %" PRIu64 ", tcp_head = %" PRIu64 ", head = %" PRIu64
                ", seq = %" PRIu64 "\n", itdata->out_tail_seq,
                itdata->tcp_head_seq, itdata->out_head_seq, seq); 
    }

    /* Set up the pointers, indices, etc. */
    index     = seq % MAX_SEND_ON_LINK;
    link_scat = itdata->outgoing[index].pkt;
    data_len  = itdata->outgoing[index].data_len;

    link_scat->elements[link_scat->num_elements].buf = (char*)new_ref_cnt(PACK_BODY_OBJ);
    
    /* set up the packet_tail for the IT protocol */ 
    itt                  = (intru_tol_pkt_tail*)(link_scat->elements[link_scat->num_elements].buf);
    itt->link_seq        = seq;
    itt->seq_nonce       = itdata->out_nonce[index];
    itt->aru             = itdata->in_tail_seq - 1;
    itt->aru_nonce       = itdata->aru_nonce_digest;
    itt->incarnation     = itdata->my_incarnation;
    itt->aru_incarnation = itdata->ngbr_incarnation;

    /* Add NACKs to the end of this message */
    ack_len              = Add_IT_Nacks(itdata, itt, data_len);

    /* Update the length of the tail element */
    link_scat->elements[link_scat->num_elements].len = ack_len;
    link_scat->num_elements++;
     
    /* set up the spines_header for the packet */
    hdr = (packet_header*) link_scat->elements[0].buf;

    /* TESTTESTTEST - the type assignment should be moved into the session and signed */
    hdr->type             = INTRU_TOL_DATA_TYPE;
    hdr->type             = Set_endian(hdr->type);

    /* hdr.sender_id        = My_Address; */
    hdr->ctrl_link_id     = lk->leg->ctrl_link_id; 
    /* hdr.data_len         = data_len; */
    hdr->ack_len         = ack_len;
    /* hdr.seq_no           = Set_Loss_SeqNo(lk->leg); */
    hdr->seq_no          = 0;
   
    /* printf("\tlen = %d\n", data_len); */
    ret = IT_Link_Send(lk, link_scat);

    /* get rid of the intrusion_tolerant link tail that was added */
    dec_ref_cnt(link_scat->elements[ link_scat->num_elements - 1 ].buf);
    link_scat->num_elements--;
    
    if (ret < 0 || ret == BUFF_DROP)
    {
        Alarm(PRINT, "Send_IT_Data_Msg: IT_Link_Send returned an error for seq %d\r\n", seq);
        return BUFF_DROP;
    }
    /* else
        printf("SENT PACKET %d\n", seq); */

    /* since we sent something, we already piggy-backed acks */
    if (ack_len > sizeof(intru_tol_pkt_tail)) { /* || itdata->in_head_seq == itdata->in_tail_seq) { */
        itdata->incoming_msg_count = 0;
        E_queue(Ack_IT_Timeout, (int)lk->link_id, NULL, it_ack_timeout);
    }

    /* only re-enqueue this if we had something to send */
    /* otherwise, we have nothing to send, and Rel_TO will be */
    /*      re-enqueued when we send the next available message */

    E_queue(Reliable_IT_Timeout, (int)lk->link_id, NULL,
            itdata->it_reliable_timeout);
  
    return BUFF_EMPTY;
}

/***********************************************************/
/* int Send_IT_Ack(int link_id)                            */
/*                                                         */
/* Internal send function that sends a standalone ack      */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* link_id:     id of the link to send the packet on       */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* Status of the buffer: dropped, empty (sent), etc.       */
/*                                                         */
/***********************************************************/
int Send_IT_Ack(int link_id)
{
    Link *lk;
    Int_Tol_Data *itdata;
    sys_scatter scat;
    packet_header hdr;
    packet_body body;
    int ret;
    int32u ack_len;
    /* unsigned char *hash_ret; */
    intru_tol_pkt_tail *itt;

    if (network_flag != 1) {
        return BUFF_DROP;
    }

    /* Getting Link and intrusion tolerant data from link_id */
    lk = Links[link_id];
    /* if (lk == NULL) { */
    if (lk == NULL || (Conf_IT_Link.Intrusion_Tolerance_Mode == 0 && lk->leg->links[CONTROL_LINK] == NULL)) {
        Alarm(DEBUG, "Send_IT_Ack: trying to send on NULL link\r\n");
        return BUFF_DROP;   
    }
    itdata  = (Int_Tol_Data*) lk->prot_data;
    if (itdata == NULL) {
        Alarm(DEBUG, "Send_IT_Ack: Int_Tol_Data is NULL on this link\r\n");
        return BUFF_DROP;
    }

    /* Set up the pointers, indices, etc. */
    itt      = (intru_tol_pkt_tail*)(&body);

    /* set up the packet_tail for the IT protocol */ 
    itt->link_seq        = 0;
    itt->seq_nonce       = 0;
    itt->aru             = itdata->in_tail_seq - 1;
    itt->aru_nonce       = itdata->aru_nonce_digest;
    itt->incarnation     = itdata->my_incarnation;
    itt->aru_incarnation = itdata->ngbr_incarnation;
    ack_len              = Add_IT_Nacks(itdata, itt, 0);
      
    /* set up the spines_header for the packet */
    scat.num_elements    = 2;
    scat.elements[0].len = sizeof(packet_header);
    scat.elements[0].buf = (char *) &hdr;
    scat.elements[1].len = ack_len;
    scat.elements[1].buf = (char *) &body;

    hdr.type             = INTRU_TOL_ACK_TYPE;
    hdr.type             = Set_endian(hdr.type);

    hdr.sender_id        = My_Address;
    hdr.ctrl_link_id     = lk->leg->ctrl_link_id; 
    hdr.data_len         = 0;
    hdr.ack_len          = ack_len;
    /* hdr.seq_no           = Set_Loss_SeqNo(lk->leg); */
    hdr.seq_no           = 0;

    ret = IT_Link_Send(lk, &scat);
    
    if (ret < 0 || ret == BUFF_DROP)
        return BUFF_DROP;
  
    return BUFF_EMPTY;
}


/***********************************************************/
/* int Send_IT_Ping(int link_id, char *buff)               */
/*                                                         */
/* Internal send function that sends a ping                */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* link_id:     id of the link to send the ping on         */
/* buff:        contents of the ping to send               */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* Status of the buffer: dropped, empty (sent), etc.       */
/*                                                         */
/***********************************************************/
int Send_IT_Ping(int link_id, char *buff)
{
    Link *lk;
    sys_scatter scat;
    packet_header hdr;
    Int_Tol_Data *itdata;
    int ret;

    if (network_flag != 1) {
        return BUFF_DROP;
    }

    /* Getting Link and intrusion tolerant data from link_id */
    lk = Links[link_id];
    /* if (lk == NULL) { */
    if (lk == NULL || (Conf_IT_Link.Intrusion_Tolerance_Mode == 0 && lk->leg->links[CONTROL_LINK] == NULL)) {
        Alarm(DEBUG, "Send_IT_Ping: trying to send on NULL link\r\n");
        return BUFF_DROP;   
    }
    itdata  = (Int_Tol_Data*) lk->prot_data;
    if (itdata == NULL) {
        Alarm(DEBUG, "Send_IT_Ping: Int_Tol_Data is NULL on this link\r\n");
        return BUFF_DROP;
    }

    /* set up the spines_header for the packet */
    scat.num_elements    = 2;
    scat.elements[0].len = sizeof(packet_header);
    scat.elements[0].buf = (char *) &hdr;
    scat.elements[1].len = sizeof(intru_tol_ping);
    scat.elements[1].buf = buff;

    hdr.type             = INTRU_TOL_PING_TYPE;
    hdr.type             = Set_endian(hdr.type);

    hdr.sender_id        = My_Address;
    hdr.ctrl_link_id     = lk->leg->ctrl_link_id; 
    hdr.data_len         = sizeof(intru_tol_ping);
    hdr.ack_len          = 0;
    /* hdr.seq_no           = Set_Loss_SeqNo(lk->leg); */
    hdr.seq_no           = 0;

    ret = IT_Link_Send(lk, &scat);
    
    if (ret < 0 || ret == BUFF_DROP)
        return BUFF_DROP;
  
    return BUFF_EMPTY;
}


/***********************************************************/
/* void Send_IT_DH(int link_id, void *dummy)               */
/*                                                         */
/* Internal send function that sends a DH key exchange msg */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* link_id:     id of the link to send the DH msg on       */
/* dummy:       not used                                   */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/
void Send_IT_DH(int link_id, void *dummy)
{
    Link *lk;
    Int_Tol_Data *itdata;
    packet_header *hdr;

    UNUSED(dummy);

    if (network_flag != 1) {
        return;
    }

    /* Getting Link and intrusion tolerant data from link_id */
    lk = Links[link_id];
    /* if (lk == NULL) { */
    if (lk == NULL || (Conf_IT_Link.Intrusion_Tolerance_Mode == 0 && lk->leg->links[CONTROL_LINK] == NULL)) {
        Alarm(DEBUG, "Send_IT_DH: trying to send on NULL link\r\n");
        E_queue(Send_IT_DH, link_id, NULL, it_dh_timeout);
        return;   
    }
    itdata = (Int_Tol_Data*) lk->prot_data;
    if (itdata == NULL) {
        Alarm(DEBUG, "Send_IT_DH: Int_Tol_Data is NULL on this link\r\n");
        E_queue(Send_IT_DH, link_id, NULL, it_dh_timeout);
        return;
    }

    if (itdata->dh_established == 1 || itdata->dh_pkt.elements[1].buf == NULL) {
        return;
    }

    /* set up the spines_header for the packet */
    hdr = (packet_header*)itdata->dh_pkt.elements[0].buf;
    /* hdr->seq_no           = Set_Loss_SeqNo(lk->leg); */
    /* hdr->seq_no           = 0; */

    Link_Send(lk, &(itdata->dh_pkt));
    E_queue(Send_IT_DH, link_id, NULL, it_dh_timeout);
}


/***********************************************************/
/* int Process_IT_Ack(int link_id, char* buff,             */
/*                      int16u data_len, int16u ack_len)   */
/*                                                         */
/* Internal function that validates the ack tail on this   */
/*     link level message, including:                      */
/*     (a) checking incarnations                           */
/*     (b) checking NACK requests                          */
/*     (c) checking nonce digest                           */
/*     (d) updating ARU                                    */
/*     (e) enqueueing retransmissions or standalone        */
/*              acks if necessary                          */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* link_id:     id of the link the packet came in on       */
/* buff:        the buffer containing the msg              */
/* data_len:    length of the data                         */
/* ack_len:     length of the ack tail                     */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* 0 - ACK validates                                       */
/* 1 - something in the ACK is invalid                     */
/*                                                         */
/***********************************************************/
int Process_IT_Ack(int link_id, char* buff, int16u data_len, int16u ack_len)
{
    Link *lk;
    Int_Tol_Data *itdata;
    intru_tol_pkt_tail *itt;
    sys_scatter *temp_scat;
    unsigned char temp_idx, temp_total;
    int ret;
    int64u i = 0, j, k;
    int32u index;
    int64u nack_seq, temp; /* , pre, post; */
    sp_time now;

    /* check if we have at least a barebone ack */
    if (ack_len < sizeof(intru_tol_pkt_tail) ||
            ((ack_len - sizeof(intru_tol_pkt_tail)) % (sizeof(int64u)) != 0)) {
        Alarm(DEBUG, "Process_IT_Ack: invalid ack size...\r\n");
        return 1;
    }

    /* Getting Link and intrusion tolerant data from link_id */
    lk = Links[link_id];
    if (lk == NULL) {
        Alarm(DEBUG, "Process_IT_Ack: trying to send on NULL link\r\n");
        return 1;   
    }
    itdata = (Int_Tol_Data*) lk->prot_data;
    if (itdata == NULL) {
        Alarm(DEBUG, "Process_IT_Ack: Int_Tol_Data is NULL on this link\r\n");
        return 1;
    }

    itt = (intru_tol_pkt_tail*)(buff + data_len); 
    now = E_get_time();

    /* printf("ENTERING FUNC\n"); */

    /* ###################################################################### */
    /*                      (1) CHECK ADVERTISED ARU                          */
    /* ###################################################################### */
    /* Process ARU only if between tail and head */
    if (itdata->out_tail_seq <= itt->aru && itdata->tcp_head_seq > itt->aru) {

        /* verify that their hashed aru nonce matches ours */
        if (itt->aru_nonce !=
                itdata->out_nonce_digest[itt->aru%MAX_SEND_ON_LINK])
        {
            printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n");
            printf("\tneighbor = "IPF"\n", IP(lk->leg->remote_interf->net_addr));
            printf("\tseq_num = %"PRIu64"\n", itt->link_seq);
            printf("\ttheir aru = %"PRIu64", my out_tail = %"PRIu64"\n", itt->aru, itdata->out_tail_seq);
            printf("\tdata_len = %d\n ", data_len);
            printf("\tout_window = %"PRIu64", in_window = %"PRIu64"\n", itdata->out_head_seq - itdata->out_tail_seq, 
                                                            itdata->in_head_seq - itdata->in_tail_seq);
            /* printf("\tinteg = %d, r_src = %d, r_dst = %d, r_seq = %"
                    ""PRIu64", r_type = %d, #acks = %d, hbh_src = %d, "
                    "hbh_dst = %d\n", 
                        *(int*)(buff + sizeof(udp_header) + 496),
                        *(int*)(buff + sizeof(udp_header) + 500), 
                        *(int*)(buff + sizeof(udp_header) + 504), 
                        *(int64u*)(buff + sizeof(udp_header) + 508), 
                        *(char*)(buff + sizeof(udp_header) + 516),
                        *(int*)(buff + sizeof(udp_header) + 500 +
                        sizeof(rel_flood_header)), 
                        *(int*)(buff + sizeof(udp_header) + 500 +
                        sizeof(rel_flood_header) + sizeof(rel_flood_tail)), 
                        *(int*)(buff + sizeof(udp_header) + 500 +
                        sizeof(rel_flood_header) + sizeof(rel_flood_tail) +
                        sizeof(int))); */
            /* printf("\ttheir nonce = %016llX\n", itt->aru_nonce); */
            /* for (i = 0; i < MAX_SEND_ON_LINK; i++) */
            /* printf("\tour nonce   = %016llX\n", itdata->out_nonce_digest[itt->aru%MAX_SEND_ON_LINK]); */
            /* printf("\tngbr_aru = %" PRIu64 ", out_tail = %" PRIu64 ",
                tcp_head = %" PRIu64 "\n", itt->aru, itdata->out_tail_seq,
                itdata->tcp_head_seq); */
            /* printf("\titt->aru_nonce = %" PRIu64 ", should be what I have"
                       " = %" PRIu64 ", aru = %" PRIu64 "\n", itt->aru_nonce,
                       itdata->out_nonce_digest[itt->aru%MAX_SEND_ON_LINK],
                       itt->aru); */
            /* printf("\tngbr_aru = %" PRIu64 ", out_tail = %" PRIu64 ",
                       tcp_head = %" PRIu64 "\n", itt->aru,
                       itdata->out_tail_seq, itdata->tcp_head_seq); */
            Alarm(DEBUG, "\t\tinvalid hash aru nonce in Process_flood_ack\r\n");
            return 1;
        }

        /* nonces are good, first check if we have resolved a loss, which will
         *      cause the TCP window size to decrease */
        if (Conf_IT_Link.TCP_Fairness == 1 && itdata->loss_detected == 1 &&
                itt->aru > itdata->loss_detected_aru)
        {
            itdata->loss_detected = 0;
            itdata->ssthresh = itdata->cwnd / 2.0;
            itdata->cwnd = (itdata->cwnd / 2.0) + 3.0;
            if (itdata->ssthresh < 2) {
                itdata->ssthresh = 2;
                itdata->cwnd = itdata->ssthresh + 3.0;
            }
            /* printf("\tlowering window to %f and ssthresh to %d\n",
                            itdata->cwnd, itdata->ssthresh); */
        }
        /* now handle all messages between tail and aru that have been ack'd */
        for (i = itdata->out_tail_seq; i <= itt->aru; i++) {
            Cleanup_Scatter(itdata->outgoing[i % MAX_SEND_ON_LINK].pkt);

            /* We need to increase the TCP usable window */
            if (Conf_IT_Link.TCP_Fairness == 1) {
                if (itdata->cwnd <= itdata->ssthresh) { /* slow start */
                    itdata->cwnd++;
                }
                else { /* congestion avoidance - linear */
                    itdata->cwnd += (float)(1.0/itdata->cwnd);
                }
            }
        }
        if (Conf_IT_Link.TCP_Fairness == 1 && itdata->cwnd > MAX_SEND_ON_LINK)
            itdata->cwnd = MAX_SEND_ON_LINK;
        itdata->out_tail_seq = itt->aru + 1;
        /* printf("\tMOVED UP OUT_TAIL TO %d\n", itdata->out_tail_seq); */
        /* see if we can fill up our window with new packets
         * from higher level now */
        /* send any packets that tcp_head now allows */
        /* pre = itdata->tcp_head_seq; */
        j = MIN(itdata->out_head_seq,
                itdata->out_tail_seq + (int64u)itdata->cwnd);
        for (i = itdata->tcp_head_seq; i < j; i++) {
            itdata->outgoing[i % MAX_SEND_ON_LINK].timestamp = E_add_time(now,
                                           itdata->it_initial_nack_timeout);
            /* printf("\tSENT FROM CWND: %lu\n", i); */
            itdata->tcp_head_seq++;
            Send_IT_Data_Msg(link_id, i);
        }
        if (Pack_Fragments_Into_Packets_IT(lk) == BUFF_DROP) {
            printf("\tPROCESS_IT_ACK\n");
            Cleanup_Scatter(itdata->out_message);
            itdata->out_message = NULL;
            itdata->out_frag_idx = itdata->out_frag_total = 0;
        }
        Assign_Resources_IT(lk->leg->remote_interf->owner);
        /* post = itdata->tcp_head_seq; */
        if (Conf_IT_Link.Session_Blocking == 1 && 
            (itdata->out_head_seq - itdata->out_tail_seq) < MAX_SEND_ON_LINK) {
            Resume_All_Sessions();
        }
        /* if (post - pre > 15) {
            printf("\tBURST OF %d.    pre = %llu  post = %llu\n", 
                    (int)(post - pre), pre, post);
        } */
    }
    
    /* ###################################################################### */
    /*                       (2) CHECK NACK REQUESTS                          */
    /* ###################################################################### */
    /* Process any NACKs that are on the end of this ACK */
    if (ack_len > sizeof(intru_tol_pkt_tail)) {
        /* printf("marking nacks for "IPF" with ARU %" PRIu64 "\n", 
                IP(lk->leg->remote_interf->net_addr), itt->aru); */
        if (ack_len - sizeof(intru_tol_pkt_tail) > sizeof(packet_body)) {
            Alarm(PRINT, "WOW!! lot of nacks here... def bug\r\n");
            return 1;
        }
        /* printf("\tmarking pkts: "); */
        for (k = 0; k < ack_len - sizeof(intru_tol_pkt_tail);
             k += sizeof(int64u))
        {
            nack_seq = *((int64u*)((char*)itt +
                          sizeof(intru_tol_pkt_tail) + k));
            /* printf("%" PRIu64 ", ", nack_seq); */
            if (nack_seq >= itdata->out_tail_seq &&
                    nack_seq < itdata->tcp_head_seq)
                itdata->outgoing[nack_seq % MAX_SEND_ON_LINK].nacked = 1;
        }
        /* printf("\n"); */
        /* Loss detected: update TCP usable window and slow start threshold */
        if (Conf_IT_Link.TCP_Fairness == 1 && itdata->loss_detected == 0) {
            itdata->loss_detected = 1;
            itdata->loss_detected_aru = itt->aru;
        }
        /* printf("##cwnd << %f, ssthresh = %d\n",
                   itdata->cwnd, itdata->ssthresh); */
        if (!E_in_queue(Handle_IT_Retransm, (int)(lk->link_id), NULL))
            Handle_IT_Retransm((int)(lk->link_id), NULL);
    }

    /* ##################################################################### */
    /*                       (3) CHECK LINK SEQ FOR VALID DATA PKT           */
    /* ##################################################################### */
    /* Only check incoming link_seq if its a data packet, not standalone ACK */
    if (itt->link_seq > 0) {
        
        /* increase the count for incoming messages on this link */
        itdata->incoming_msg_count++;

        /* if no retransmissions were made, we have no piggy-backed acks, */ 
        /*  thus we should check if we need to send a standalone ack      */
        if (itdata->incoming_msg_count >= Conf_IT_Link.Msg_Per_SAA)
            E_queue(Ack_IT_Timeout, (int)(lk->link_id), NULL, zero_timeout);

        /* Is this an old (perhaps duplicate) link_seq? */
        if (itt->link_seq < itdata->in_tail_seq)
            return 1;
        /* Is this link_seq beyond the current window? */
        else if (itt->link_seq >= itdata->in_tail_seq + MAX_SEND_ON_LINK) {
            Alarm( PRINT, "Process_IT_Ack: ngbr "IPF" sent link_seq (%d) > "
                          "maximum acceptable (%d)\r\n", 
                          IP(lk->leg->remote_interf->net_addr), itt->link_seq,
                          itdata->in_tail_seq + MAX_SEND_ON_LINK);
            return 1;
        }
        
        index = itt->link_seq % MAX_SEND_ON_LINK;

        /* Has this packet already been received and processed? */
        if (itdata->incoming[index].flags == RECVD_CELL)
            return 1;

        /* Store the packet in the window */
        /* printf("RECEIVED %d\n", itt->link_seq); */
        inc_ref_cnt(buff);
        itdata->incoming[index].pkt = buff;
        itdata->incoming[index].pkt_len = data_len; 
        itdata->in_nonce[index] = itt->seq_nonce;
        itdata->incoming[index].flags = RECVD_CELL;

        /* Update our own array to generate our acks 
         * in this case, we are adding to or beyond the head,
         * we will fill in any gaps with NACK_CELL flags, and
         * leave head as the next empty cell */
        if (itt->link_seq >= itdata->in_head_seq) {

            /* local variable to avoid MOD operations */
            i = itdata->in_head_seq % MAX_SEND_ON_LINK;
            for (temp = itdata->in_head_seq; temp < itt->link_seq; temp++) {
                itdata->incoming[i].flags = NACK_CELL;
                itdata->incoming[i].nack_expire = 
                        E_add_time(now, itdata->it_initial_nack_timeout);
                itdata->in_head_seq++;
                i++;
                if (i >= MAX_SEND_ON_LINK) i = 0;
            }
            itdata->in_head_seq++;
        }

        /* Special Case for Unordered Delivery:
         *      For messages which fit in one packet only, we
         *      can deliver them out of order as soon as they
         *      are received - all other messages will be delivered
         *      in order */
        if ( Conf_IT_Link.Ordered_Delivery == 0 && 
             ((fragment_header*)(buff + data_len - sizeof(fragment_header)))->frag_total == 1 )
        {
            /* Create sys_scatter to store the packet, and move the packet in the receive 
             *      buffer into the appropriate sys_scatter structure */
            if ( (temp_scat = (sys_scatter*) new_ref_cnt(SYS_SCATTER)) == NULL )
                Alarm(EXIT, "Process_IT_Ack: failed to allocate memory for sys_scatter\r\n");
            temp_scat->num_elements = 0;
            temp_idx = 1;
            temp_total = 0;
            ret = Build_Message_From_Fragments_IT( temp_scat, buff, data_len, 
                                                &temp_idx, &temp_total, lk->link_type );
            if (ret < 0) {
                Blacklist_Neighbor_IT( lk );
                dec_ref_cnt( temp_scat );
            }
            else if (ret == 0)
                Alarm(EXIT, "Process_IT_Ack: Single-Packet message did not fit in a packet\r\n");
            else {
                /* printf("\tDELIVERING %d (in out-of-order check)\n", itt->link_seq); */
                Deliver_and_Forward_Data( temp_scat, lk->link_type, lk );
                Cleanup_Scatter(temp_scat);
            }
        }

        /* In all cases, we try to move the ARU forward if possible */
        /* local variable to avoid mod operations */
        i = itdata->in_tail_seq % MAX_SEND_ON_LINK;
        while (itdata->incoming[i].flags == RECVD_CELL) {
            
            /* printf("LOOP ITERATION: i = %d, tail = %d\n", i, itdata->in_tail_seq); */
            itdata->aru_nonce_digest = itdata->aru_nonce_digest ^
                                           itdata->in_nonce[i];
            itdata->in_tail_seq++;
            itdata->in_nonce[i] = 0;

            if (Conf_IT_Link.Ordered_Delivery == 1 || 
                    ((fragment_header*)(itdata->incoming[i].pkt + 
                                        itdata->incoming[i].pkt_len - 
                                        sizeof(fragment_header)))->frag_total > 1 )
            {
                ret = Build_Message_From_Fragments_IT( itdata->in_message, itdata->incoming[i].pkt, 
                        itdata->incoming[i].pkt_len, &(itdata->in_frag_idx), &(itdata->in_frag_total), 
                        lk->link_type );

                if (ret < 0)
                    Blacklist_Neighbor_IT( lk );
                else if (ret == 1) {
                    /* printf("\tDELIVERING %d (ordered delivery case)\n", itdata->in_tail_seq); */
                    Deliver_and_Forward_Data( itdata->in_message, lk->link_type, lk );
                    Cleanup_Scatter(itdata->in_message);

                    if ( (itdata->in_message = (sys_scatter*) new_ref_cnt(SYS_SCATTER)) == NULL )
                        Alarm(EXIT, "Process_IT_Ack: failed to allocate memory for sys_scatter\r\n");
                    itdata->in_message->num_elements = 0;
                    itdata->in_frag_idx = 1;
                    itdata->in_frag_total = 0;
                }
            }

            dec_ref_cnt(itdata->incoming[i].pkt);
            itdata->incoming[i].pkt = NULL;
            itdata->incoming[i].pkt_len = 0;
            itdata->incoming[i].flags = EMPTY_CELL;
            i++;
            if (i >= MAX_SEND_ON_LINK) i = 0;
        }   
    }

    return 0;
}


/***********************************************************/
/* void Incarnation_Change(int link_id,                    */
/*                int32u new_ngbr_inc, int mode )          */
/*                                                         */
/* Internal function that executes an incarnation change   */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* link_id:       id of the link on which change occurs    */
/* new_ngbr_inc:  neighbor's new incarnation               */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/
void Incarnation_Change(int link_id, int32u new_ngbr_inc, int mode)
{
    Link *lk;
    Int_Tol_Data *itdata;
    int32u index, skipped_pkts = 0;
    int64u i = 0, j;
    sys_scatter *temp_window[MAX_SEND_ON_LINK];
    int16u temp_datalen[MAX_SEND_ON_LINK];
    sp_time now = E_get_time();

    /* Getting Link and intrusion tolerant data from link_id */
    lk = Links[link_id];
    /* if (lk == NULL) { */
    if (lk == NULL || (Conf_IT_Link.Intrusion_Tolerance_Mode == 0 && lk->leg->links[CONTROL_LINK] == NULL)) {
        Alarm(DEBUG, "Incarnation_Change: trying to send on NULL link\r\n");
        return;   
    }
    itdata  = (Int_Tol_Data*) lk->prot_data;
    if (itdata == NULL) {
        Alarm(DEBUG, "Incarnation_Change: Int_Tol_Data is NULL on this link\r\n");
        return;
    }

    Alarm(PRINT, "updating incarnation stored for "IPF"\r\n", 
            IP(lk->leg->remote_interf->net_addr));
    itdata->incarnation_response = E_add_time(now, it_incarnation_timeout);
    itdata->ngbr_incarnation = new_ngbr_inc; 

    /* Reset the incoming link data structures */
    for (i = itdata->in_tail_seq; i < itdata->in_head_seq; i++) {
        index = i % MAX_SEND_ON_LINK;
        itdata->out_nonce_digest[index] = 0;
        if (itdata->incoming[index].flags == RECVD_CELL) {
            Alarm(PRINT, "stored buffer @ %d not empty\r\n", i);
            dec_ref_cnt(itdata->incoming[index].pkt);
            itdata->incoming[index].pkt = NULL;
        }
        itdata->incoming[index].pkt_len = 0;
        itdata->incoming[index].flags = EMPTY_CELL;
        itdata->in_nonce[index] = 0;
    }
    if (itdata->in_frag_idx != 1 || itdata->in_frag_total > 0) {
        Alarm(DEBUG, "SAVED MESSAGE NON-EMPTY!\r\n");
        Cleanup_Scatter(itdata->in_message);
        if ( (itdata->in_message = (sys_scatter*) new_ref_cnt(SYS_SCATTER)) == NULL )
            Alarm(EXIT, "Process_IT_Ack: failed to allocate memory for sys_scatter\r\n");
        itdata->in_message->num_elements = 0;
        itdata->in_frag_idx = 1;
        itdata->in_frag_total = 0;
    } 
    itdata->in_tail_seq = itdata->in_head_seq = LINK_START_SEQ;
    itdata->out_nonce_digest[0] = 0;
    itdata->aru_nonce_digest = 0;

    /* Reset the outgoing link data structures */
    if (Conf_IT_Link.Reintroduce_Messages == 0) {

        /* Cleanup the packets no longer being used */
        for (i = itdata->out_tail_seq; i < itdata->out_head_seq; i++)
            Cleanup_Scatter(itdata->outgoing[i % MAX_SEND_ON_LINK].pkt);

        itdata->out_tail_seq = itdata->out_head_seq = 
            itdata->tcp_head_seq = LINK_START_SEQ;
            
        Cleanup_Scatter(itdata->out_message);
        itdata->out_message = NULL;
        itdata->out_frag_idx = itdata->out_frag_total = 0;
    }   
    else { /* Conf_IT_Link.Reintroduce_Messages == 1 */
        for (i = itdata->out_tail_seq; i < itdata->out_head_seq; i++) {
            if ( ((fragment_header*)(itdata->outgoing[i % MAX_SEND_ON_LINK].pkt->elements[2].buf))->frag_idx != 1 ) {
                Cleanup_Scatter(itdata->outgoing[i % MAX_SEND_ON_LINK].pkt);
                skipped_pkts++;
            }
            else
                break;
        }
        for (j = 1, i = itdata->out_tail_seq + skipped_pkts; i < itdata->out_head_seq; i++) {
            temp_window[j % MAX_SEND_ON_LINK] =
                itdata->outgoing[i % MAX_SEND_ON_LINK].pkt;
            temp_datalen[j % MAX_SEND_ON_LINK] = 
                itdata->outgoing[i % MAX_SEND_ON_LINK].data_len;
            j++;
        }
        for (index = 0, i = 1; i <= itdata->out_head_seq - (itdata->out_tail_seq + skipped_pkts); i++) {
            index = i % MAX_SEND_ON_LINK;
            itdata->outgoing[index].pkt = temp_window[index];
            itdata->outgoing[index].data_len = temp_datalen[index];
            itdata->outgoing[index].resent = 0;
            itdata->outgoing[index].nacked = 0;
            itdata->outgoing[index].timestamp = E_add_time(now,
                                       itdata->it_initial_nack_timeout);

            /* calculate the nonce for this packet */
            itdata->out_nonce[index] = rand();
            itdata->out_nonce[index] = (itdata->out_nonce[index] << 32) |
                                       rand();
            itdata->out_nonce_digest[index] = itdata->out_nonce[index] ^
                    itdata->out_nonce_digest[(i - 1) % MAX_SEND_ON_LINK];
        }

        itdata->tcp_head_seq = 
            MIN( LINK_START_SEQ + 1, itdata->out_head_seq - (itdata->out_tail_seq + skipped_pkts) + LINK_START_SEQ );
        itdata->out_head_seq =
            itdata->out_head_seq - (itdata->out_tail_seq + skipped_pkts) + LINK_START_SEQ;
        itdata->out_tail_seq = LINK_START_SEQ;

        /* Don't need to make sure the first part of the message is in the window to be sent 
         *      since we do not all messages bigger than the outgoing window size */
        if (Pack_Fragments_Into_Packets_IT(lk) == BUFF_DROP) {
            printf("\tINCARNATION CHANGE\n");
            Cleanup_Scatter(itdata->out_message);
            itdata->out_message = NULL;
            itdata->out_frag_idx = itdata->out_frag_total = 0;
        }

        /* Since the other side needs to get a PING/PONG msg
                to update their incarnation, all data packets
                will be dropped until then, no reason to queue
                Reliable Timeout now */
        /* E_queue(Reliable_IT_Timeout, (int)(link_id), NULL,
           zero_timeout); */
    }

    if (Conf_IT_Link.TCP_Fairness == 1)
        itdata->cwnd = (float)Minimum_Window;
    else
        itdata->cwnd = MAX_SEND_ON_LINK;
    itdata->ssthresh = MAX_SEND_ON_LINK;

    Reliable_Flood_Neighbor_Transfer(mode, lk);
    Assign_Resources_IT(lk->leg->remote_interf->owner);
}

/***********************************************************/
/* void Ack_IT_Timeout(int link_id, void *dummy)           */
/*                                                         */
/* Internal function that sends a standalone ack if        */
/*     a data packet has not been sent to this neighbor    */
/*     since (a) some timeout or (b) some msg threshold,   */
/*     whichever happens first                             */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* link_id:     id of the link to send the packet on       */
/* dummy:       not used                                   */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/
void Ack_IT_Timeout(int link_id, void *dummy)
{
    Link *lk;
    Int_Tol_Data *itdata;

    UNUSED(dummy);

    /* Getting Link and intrusion tolerant data from link_id */
    lk = Links[link_id];
    if (lk == NULL) {
        Alarm(DEBUG, "Ack_IT_Timeout: trying to send on NULL link\r\n");
        return;   
    }
    itdata = (Int_Tol_Data*) lk->prot_data;
    if (itdata == NULL) {
        Alarm(DEBUG, "Ack_IT_Timeout: Int_Tol_Data is NULL on this link\r\n");
        return;
    }

    /* check if we should reset the Standalone Ack to the initial state */
    if (itdata->incoming_msg_count == 0) {
        itdata->incoming_msg_count = Conf_IT_Link.Msg_Per_SAA - 1;
        return;
    }

    /* make sure we don't have any packets queued up to send back to */
    /* this neighbor (because then acks will be piggy-backed there)  */
    /* if (itdata->tcp_head_seq == itdata->out_tail_seq) { */
    /* if (itdata->in_head_seq != itdata->in_tail_seq) { */
        Send_IT_Ack(link_id);
        itdata->incoming_msg_count = 0;
        E_queue(Ack_IT_Timeout, (int)(link_id), NULL, it_ack_timeout);
    /* } */
}

/***********************************************************/
/* void Reliable_IT_Timeout(int link_id, void *dummy)      */
/*                                                         */
/* Internal function that resends the latest msg a         */
/*     neighbor if the timeout has expired                 */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* link_id:     id of the link to send the packet on       */
/* dummy:       not used                                   */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/
void Reliable_IT_Timeout(int link_id, void *dummy)
{
    Link *lk;
    Int_Tol_Data *itdata;
    int32u index;
    sp_time now;

    UNUSED(dummy);

    /* Getting Link and intrusion tolerant data from link_id */
    lk = Links[link_id];
    if (lk == NULL) {
        Alarm(DEBUG, "Reliable_IT_Timeout: trying to send on NULL link\r\n");
        return;   
    }
    itdata = (Int_Tol_Data*) lk->prot_data;
    if (itdata == NULL) {
        Alarm(DEBUG, "Reliable_IT_Timeout: Int_Tol_Data is NULL"
                        " on this link\r\n");
        return;
    }
    now = E_get_time();

    /* printf("\t\tRELIABLE_TIMEOUT TO "IPF", sending %"PRIu64", tail = %"PRIu64", my_aru to ngbr = %"PRIu64"\n", 
            IP(lk->leg->remote_interf->net_addr), itdata->tcp_head_seq - 1, itdata->out_tail_seq, itdata->in_tail_seq - 1); */

    if (itdata->tcp_head_seq > itdata->out_tail_seq) {

        index = (itdata->tcp_head_seq - 1) % MAX_SEND_ON_LINK;
        itdata->outgoing[index].resent = 1;
        itdata->outgoing[index].timestamp =
                    E_add_time(now, itdata->it_nack_timeout);
        /* printf("\tSENT from RELIABLE: %lu\n", itdata->tcp_head_seq - 1); */
        Send_IT_Data_Msg( lk->link_id, itdata->tcp_head_seq - 1);    
        
        /* since we did send something, we already piggy-backed acks */
        /* itdata->incoming_msg_count = 0;
        E_queue(Ack_IT_Timeout, (int)(link_id), NULL, it_ack_timeout); */
        
        /* only re-enqueue this if we had something to send */
        /* otherwise, we have nothing to send, and Rel_TO will be */
        /* re-enqueued when we send the next available message */
        E_queue(Reliable_IT_Timeout, (int)(link_id), NULL,
                    itdata->it_reliable_timeout);
    }
    /* else {
        Alarm(PRINT, "Reliable_IT_Timeout: tcp_head = %"PRIu64", out_tail = %"PRIu64"\r\n",
                        itdata->tcp_head_seq, itdata->out_tail_seq);
    } */
}

/***********************************************************/
/* void Handle_IT_Retransm(int link_id, void *dummy)       */
/*                                                         */
/* Internal function that retransmits the requested        */
/*     packets to a neighbor. If there are more requested  */
/*     packets than can be sent at once, this function     */
/*     will reenqueue itself                               */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* link_id:     id of the link to retransmit packets to    */
/* dummy:       not used                                   */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/
void Handle_IT_Retransm(int link_id, void *dummy)
{
    Link *lk;
    Int_Tol_Data *itdata;
    int64u i;
    int32u index;
    /* int pkts_sent = 0; */
    sp_time now, requeue;

    UNUSED(dummy);

    /* Getting Link and intrusion tolerant data from link_id */
    lk = Links[link_id];
    if (lk == NULL) {
        Alarm(DEBUG, "Handle_IT_Retransm: trying to send on NULL link\r\n");
        return;   
    }
    itdata = (Int_Tol_Data*) lk->prot_data;
    if (itdata == NULL) {
        Alarm(DEBUG, "Handle_IT_Retransm: Int_Tol_Data is NULL"
                        " on this link\r\n");
        return;
    }
    now = E_get_time();

    /* Can we handle retransmissions now */
    if (E_compare_time( Burst_Timeout, now ) <= 0) {
        Burst_Count = 0;
        Burst_Timeout = E_add_time(now, flow_control_timeout );
    }
    else if (Burst_Count >= Conf_IT_Link.Send_Batch_Size) {
        requeue = E_add_time(E_sub_time( Burst_Timeout, now ), zero_timeout);
        E_queue(Handle_IT_Retransm, (int)link_id, NULL, requeue );
    }

    /* printf("\tSENT from NACK_RETRANSM:  "); */
    for (i = itdata->out_tail_seq; i < itdata->tcp_head_seq && 
            Burst_Count < Conf_IT_Link.Send_Batch_Size; i++)
    {
        index = i % MAX_SEND_ON_LINK;
        
        /* Check the resend timeout on the packet */
        if (itdata->outgoing[index].nacked == 1 &&
                E_compare_time(itdata->outgoing[index].timestamp, now) <= 0) 
        {
            itdata->outgoing[index].resent = 1;
            itdata->outgoing[index].nacked = 0;
            itdata->outgoing[index].timestamp =
                                E_add_time(now, itdata->it_nack_timeout);
            /* itdata->bucket -= Send_IT_Data_Msg(link_id, i); */
            Send_IT_Data_Msg(link_id, i);
            /* pkts_sent++; */
            itdata->loss_history_retransmissions[0]++;
            Burst_Count++;
            /* printf("%" PRIu64 ",  ", i ); */
        }
    }
    /* printf("\n"); */

    if (i < itdata->tcp_head_seq) { /* didn't get through all the nacks */
        requeue = E_add_time(E_sub_time( Burst_Timeout, now ), zero_timeout);
        E_queue(Handle_IT_Retransm, (int)link_id, NULL, requeue );
    }
}


/***********************************************************/
/* int Add_IT_Nacks(Int_Tol_Data *itdata,                  */
/*                      intru_tol_pkt_tail *itt,           */
/*                      int16u buff_len         )          */
/*                                                         */
/* Adds piggy-backed nacks to outgoing packets             */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* itdata:      link data these NACKS are sent to          */
/* itt:         tail of packet to add NACKS to             */
/* buff_len:    length of the regular paket                */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* size (in bytes) of total flood ack tail                 */
/*                                                         */
/***********************************************************/
int Add_IT_Nacks (Int_Tol_Data *itdata, intru_tol_pkt_tail *itt, int16u buff_len)
{

    int64u i;
    int total_size_avail, ack_len, index;
    char *p_nack;
    sp_time now;

    now = E_get_time();

    /* total_size_avail is the size of a packet (not including the spines
     *      header) minus the space used up by the data, fragment headers,
     *      dissemination headers/signatures, the software udp header,
     *      and the HMAC */
    
    total_size_avail = (int)sizeof(packet_body) - (int)buff_len - 2 * (int)Cipher_Blk_Len - (int)HMAC_Key_Len;
    ack_len          = sizeof(intru_tol_pkt_tail);

    /* Add NACKs to the intru_tol_pkt tail */
    
    p_nack = (char*)itt;
    p_nack += ack_len;

    if (total_size_avail - ack_len < (int) sizeof(int64u))
        Alarm(EXIT, "Add_IT_Nacks: No space for any IT Nacks on this "
                        "packet -> Bad packing\r\n");

    /* printf("\taru = %lu, tail = %lu, head = %lu\n",
               itdata->in_tail_seq - 1, itdata->in_tail_seq,
               itdata->in_head_seq);
    printf("\tnacks = "); */

    for( i = itdata->in_tail_seq; i < itdata->in_head_seq; i++)
    {
        index = (int) (i % MAX_SEND_ON_LINK);
        
        if( ack_len + sizeof(int64u) > total_size_avail )
            break;
        
        if(itdata->incoming[index].flags == NACK_CELL &&
              E_compare_time(itdata->incoming[index].nack_expire, now) <= 0)
        {
            *(int64u*) p_nack = i;
            p_nack += sizeof(int64u);
            ack_len += sizeof(int64u);
            itdata->incoming[index].nack_expire = E_add_time(now, itdata->it_nack_timeout);
        }
    }

    /* printf("\n"); */
    
    return ack_len;
}

/***********************************************************/
/* void Ping_IT_timeout ( int linkid, void *dummy )        */
/*                                                         */
/* Sends a ping to the neighbor @ linkid                   */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* link_id:    id of the link to a neighbor                */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/
void Ping_IT_Timeout(int link_id, void *dummy) 
{
    Link *lk;
    Int_Tol_Data *itdata;
    int32u index;
    packet_body body;
    intru_tol_ping *ping = (intru_tol_ping*)(&body);

    UNUSED(dummy);

    /* Getting Link and intrusion tolerant data from link_id */
    lk = Links[link_id];
    if (lk == NULL) {
        Alarm(DEBUG, "Ping_IT: trying to send on NULL link\r\n");
        E_queue(Ping_IT_Timeout, link_id, NULL, it_ping_timeout);
        return;   
    }
    itdata = (Int_Tol_Data*) lk->prot_data;
    if (itdata == NULL) {
        Alarm(DEBUG, "Ping_IT: Int_Tol_Data is NULL on this link\r\n");
        E_queue(Ping_IT_Timeout, link_id, NULL, it_ping_timeout);
        return;
    }

    if (Conf_IT_Link.Crypto == 0 || 
            (Conf_IT_Link.Crypto == 1 && itdata->dh_key_computed == 2)) 
    {
        index = itdata->next_ping_seq % MAX_PING_HIST;

        if (itdata->ping_history[index].answered == 0) {
            itdata->loss_history_retransmissions[0]++;
        }

        itdata->ping_history[index].ping_seq   = itdata->next_ping_seq;
        itdata->ping_history[index].ping_nonce = rand();
        itdata->ping_history[index].ping_nonce = 
                    (itdata->ping_history[index].ping_nonce << 32) | rand();
        itdata->ping_history[index].ping_sent  = E_get_time();
        itdata->ping_history[index].answered   = 0;
        itdata->next_ping_seq++;
        
        ping->ping_seq        = itdata->ping_history[index].ping_seq;
        ping->ping_nonce      = itdata->ping_history[index].ping_nonce;
        ping->incarnation     = itdata->my_incarnation;
        ping->aru_incarnation = itdata->ngbr_incarnation;
        ping->ping_type       = PING;
        
        Send_IT_Ping( link_id, (char*)&body );
        
        /* Add this packet to the loss_history calculation */
        itdata->loss_history_unique_packets[0]++;
        if (itdata->loss_history_unique_packets[0] >= Conf_IT_Link.Loss_Calc_Pkt_Trigger) {
            E_queue(Loss_Calculation_Event, (int)lk->link_id, NULL, zero_timeout);
        }

        /* REROUTE */
        if (Conf_IT_Link.Intrusion_Tolerance_Mode == 1 && itdata->link_status != LINK_DEAD && 
              itdata->next_ping_seq > itdata->last_pong_seq_recv + Conf_IT_Link.Ping_Threshold)
        {
            itdata->link_status = LINK_DEAD;
            Generate_Link_Status_Change(lk->leg->remote_interf->net_addr, itdata->link_status); 
        }
    }
    E_queue(Ping_IT_Timeout, link_id, NULL, it_ping_timeout);
}


/***********************************************************/
/* void Key_Exchange_IT ( int linkid, void *dummy )        */
/*                                                         */
/* Calculate and send DH public key to the                 */
/*     neighbor @ linkid                                   */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* link_id:    id of the link to a neighbor                */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/
void Key_Exchange_IT(int link_id, void *dummy) 
{
    Link *lk;
    Int_Tol_Data *itdata;
    int bn_size, ret;
    unsigned int sign_len;
    char *write_ptr;
    packet_header *hdr;
    EVP_MD_CTX *md_ctx;
    const BIGNUM *pub_key;

    UNUSED(dummy);

    Alarm(PRINT, "Key Exchange!! lk = %x\n", Links[link_id]);

    /* Getting Link and intrusion tolerant data from link_id */
    lk = Links[link_id];
    if (lk == NULL) {
        Alarm(DEBUG, "Key_Exchange_IT: trying to send on NULL link\r\n");
        E_queue(Key_Exchange_IT, link_id, NULL, it_dh_timeout);
        return;   
    }
    itdata = (Int_Tol_Data*) lk->prot_data;
    if (itdata == NULL) {
        Alarm(DEBUG, "Key_Exchange_IT: Int_Tol_Data is NULL on this link\r\n");
        E_queue(Key_Exchange_IT, link_id, NULL, it_dh_timeout);
        return;
    }
  
    if (E_in_queue(Key_Exchange_IT, link_id, NULL)) {
        Alarm(PRINT, "Dequeuing Key Exchange with %x\n", lk);
        E_dequeue(Key_Exchange_IT, link_id, NULL);
    }

    /* Generate the secret/public parts for DH exchange */
    /* NOTE: this only generates a random # and exponentiates it the
     * first time, otherwise it reuses the existing ones, which should
     * be safe */
    
    if (DH_generate_key(itdata->dh_local) == 0)
        Alarm(EXIT, "Key_Exchange_IT: DH_generate_Key failed\r\n");

    /* Reset the DH state and pkt */
    itdata->dh_established = 0;
    itdata->dh_key_computed = 1;
    
    if (itdata->dh_pkt.elements[0].buf != NULL) {
        dec_ref_cnt(itdata->dh_pkt.elements[0].buf);
        itdata->dh_pkt.elements[0].buf = NULL;
        itdata->dh_pkt.elements[0].len = 0;
    }
    if (itdata->dh_pkt.elements[1].buf != NULL) {
        dec_ref_cnt(itdata->dh_pkt.elements[1].buf);
        itdata->dh_pkt.elements[1].buf = NULL;
        itdata->dh_pkt.elements[1].len = 0;
    }

    /* Dequeue the pings if they are enqueued */
    if (E_in_queue(Ping_IT_Timeout, (int)lk->link_id, NULL))
        E_dequeue(Ping_IT_Timeout, (int)lk->link_id, NULL);

    /* Allocate and setup the DH packet body */
    itdata->dh_pkt.elements[1].buf = (char*)new_ref_cnt(PACK_BODY_OBJ);
    itdata->dh_pkt.elements[1].len = 0;
    write_ptr = itdata->dh_pkt.elements[1].buf;
    
    *(Interface_ID*)write_ptr = lk->leg->local_interf->iid;
    write_ptr += sizeof(Interface_ID);
    itdata->dh_pkt.elements[1].len += sizeof(Interface_ID);

    *(Interface_ID*)write_ptr = lk->leg->remote_interf->iid;
    write_ptr += sizeof(Interface_ID);
    itdata->dh_pkt.elements[1].len += sizeof(Interface_ID);

    *(int32u*)write_ptr = itdata->my_incarnation;
    write_ptr += sizeof(int32u);
    itdata->dh_pkt.elements[1].len += sizeof(int32u);

    *(int32u*)write_ptr = itdata->ngbr_incarnation;
    write_ptr += sizeof(int32u);
    itdata->dh_pkt.elements[1].len += sizeof(int32u);

    pub_key = DH_get0_pub_key(itdata->dh_local);
    bn_size = BN_num_bytes(pub_key);
    *(int16u*)write_ptr = (int16u)bn_size;
    write_ptr += sizeof(int16u);
    itdata->dh_pkt.elements[1].len += sizeof(int16u);

    if (itdata->dh_pkt.elements[1].len + bn_size > sizeof(packet_body))
        Alarm(EXIT, "Key_Exchange_IT: DH key too large for packet_body\r\n");

    BN_bn2bin(pub_key, (unsigned char*)write_ptr);
    write_ptr += bn_size;
    itdata->dh_pkt.elements[1].len += bn_size;

    /* TODO: temporarily putting hash of configuration file here */
    memcpy(write_ptr, (char*)Conf_Hash, HMAC_Key_Len);
    write_ptr += HMAC_Key_Len;
    itdata->dh_pkt.elements[1].len += HMAC_Key_Len;
    if (itdata->dh_pkt.elements[1].len > sizeof(packet_body))
        Alarm(EXIT, "Key_Exchange_IT: Hash of config file doesn't fit\r\n");
    
    /* Pre-emptively adjust length for signature */
    itdata->dh_pkt.elements[1].len += Signature_Len;
    if (itdata->dh_pkt.elements[1].len > sizeof(packet_body))
        Alarm(EXIT, "Key_Exchange_IT: Signature caused packet size" 
                    " to be too large\r\n");

    /* Allocate and setup the DH packet header */
    itdata->dh_pkt.elements[0].buf = (char*)new_ref_cnt(PACK_HEAD_OBJ);
    itdata->dh_pkt.elements[0].len = sizeof(packet_header);
    
    hdr = (packet_header*)itdata->dh_pkt.elements[0].buf;
    
    hdr->type             = DIFFIE_HELLMAN_TYPE;
    hdr->type             = Set_endian(hdr->type);

    hdr->sender_id        = My_Address;
    hdr->ctrl_link_id     = lk->leg->ctrl_link_id; 
    hdr->data_len         = itdata->dh_pkt.elements[1].len;
    hdr->ack_len          = 0;
    hdr->seq_no           = 0;

    /* SIGN THIS WITH PRIV KEY */
    md_ctx = EVP_MD_CTX_new();
    if(md_ctx==NULL)
        Alarm(EXIT, "EVP_MD_CTX_new() failed\r\n");
    ret = EVP_SignInit(md_ctx, EVP_sha256()); 
    if (ret != 1) 
        Alarm(PRINT, "Key_Exchange_IT: SignInit failed\r\n");

    ret = EVP_SignUpdate(md_ctx, (unsigned char*)itdata->dh_pkt.elements[0].buf, 
                            itdata->dh_pkt.elements[0].len);
    if (ret != 1) 
        Alarm(PRINT, "Key_Exchange_IT: SignUpdate of scat header failed\r\n");

    ret = EVP_SignUpdate(md_ctx, (unsigned char*)itdata->dh_pkt.elements[1].buf, 
                            itdata->dh_pkt.elements[1].len - Signature_Len);
    if (ret != 1) 
        Alarm(PRINT, "Key_Exchange_IT: SignUpdate of scat body failed\r\n");

    ret = EVP_SignFinal(md_ctx, (unsigned char*)write_ptr, &sign_len, Priv_Key);
    if (ret != 1) 
        Alarm(PRINT, "Key_Exchange_IT: SignFinal failed\r\n");

    if (sign_len != Signature_Len)
        Alarm(PRINT, "Key_Exchange_IT: sign_len (%d) != Key_Len (%d)\r\n",
                        sign_len, Signature_Len);

    EVP_MD_CTX_free(md_ctx);

    /* ret = EVP_VerifyInit(md_ctx, EVP_sha256()); 
    if (ret != 1) { 
        Alarm(PRINT, "Key_Exchange_IT: VerifyInit failed\r\n");
        return;
    }

    ret = EVP_VerifyUpdate(md_ctx, (unsigned char*)itdata->dh_pkt.pkt, 
                            itdata->dh_pkt.data_len - sign_len);
    if (ret != 1) {
        Alarm(PRINT, "Key_Exchange_IT: VerifyUpdate failed\r\n");
        return;
    }

    ret = EVP_VerifyFinal(md_ctx, (unsigned char*)write_ptr, sign_len, 
                            Pub_Keys[My_ID]);
    if (ret != 1) {
        Alarm(PRINT, "Key_Exchange_IT: VerifyFinal failed\r\n");
        return;
    }
    printf("LOCAL SIGNATURE VERIFIES\n"); */

    E_queue(Send_IT_DH, link_id, NULL, zero_timeout);
}


/***********************************************************/
/* void Loss_Calculation_Event ( int linkid, void *dummy ) */
/*                                                         */
/* Calculate Loss Rate after a link comes up to see if it  */
/*      can quickly go from LOSSY to LIVE.                 */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* link_id:    id of the link to a neighbor                */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/
void Loss_Calculation_Event(int link_id, void *dummy)
{
    Link *lk;
    Int_Tol_Data *itdata;
    int16u i;
    double loss_rate = 0, decay_sum = 0;

    UNUSED(dummy);

    /* Getting Link and intrusion tolerant data from link_id */
    lk = Links[link_id];
    if (lk == NULL) {
        Alarm(PRINT, "Loss_Calculation_Event: Cannot calculate loss on NULL link\r\n");
        E_queue(Loss_Calculation_Event, link_id, NULL, loss_calc_timeout);
        return;   
    }
    itdata = (Int_Tol_Data*) lk->prot_data;
    if (itdata == NULL) {
        Alarm(PRINT, "Loss_Calculation_Event: Int_Tol_Data is NULL on this link\r\n");
        E_queue(Loss_Calculation_Event, link_id, NULL, loss_calc_timeout);
        return;
    }

    /* Shift over the buckets and clear the 0th one in the history */
    for (i = HISTORY_SIZE; i > 0; i--) {
        itdata->loss_history_retransmissions[i] = itdata->loss_history_retransmissions[i-1];
        itdata->loss_history_unique_packets[i]  = itdata->loss_history_unique_packets[i-1];
    }
    itdata->loss_history_retransmissions[0] = 0;
    itdata->loss_history_unique_packets[0]  = 0;

    /* Calculate the current loss_rate based on the history */
    for (i = 1; i <= HISTORY_SIZE; i++) {
        if (itdata->loss_history_unique_packets[i] > 0) {
            loss_rate += itdata->loss_history_decay[i] * 
                            itdata->loss_history_retransmissions[i] / 
                            itdata->loss_history_unique_packets[i];
            decay_sum += itdata->loss_history_decay[i];
        }
    }
    if (decay_sum == 0)
        loss_rate = 1.0;
    else
        loss_rate /= decay_sum;
    Alarm(DEBUG, "Loss_Calculation_Event: Loss Rate to "IPF" = %f\r\n", 
                    IP(lk->leg->remote_interf->net_addr), loss_rate);

    /* Generate a Link Status Change when appropriate */
    if (Conf_IT_Link.Intrusion_Tolerance_Mode == 1 && itdata->link_status == LINK_LOSSY 
            && loss_rate < Conf_IT_Link.Loss_Threshold) 
    {
        Generate_Link_Status_Change(lk->leg->remote_interf->net_addr, LINK_LIVE);
        itdata->link_status = LINK_LIVE;
    }
    else if (Conf_IT_Link.Intrusion_Tolerance_Mode == 1 && itdata->link_status == LINK_LIVE 
            && loss_rate >= Conf_IT_Link.Loss_Threshold) 
    {
        Generate_Link_Status_Change(lk->leg->remote_interf->net_addr, LINK_LOSSY);
        itdata->link_status = LINK_LOSSY;
    }

    E_queue(Loss_Calculation_Event, link_id, NULL, loss_calc_timeout);
}

/***********************************************************/
/* void Neighbor_Blacklist_IT ( Link *lk )                 */
/*                                                         */
/* Shutdown this neighbor which acted maliciously in a     */
/*      detectable way                                     */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* lk:   pointer to the link associated with this neighbor */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/
void Blacklist_Neighbor_IT( Link *lk )
{
    Alarm(PRINT, "Blacklist_Neighbor_IT: Bad link behavior with fragment header."
                    " Ignoring this and all future packets on this link.\r\n");
}
