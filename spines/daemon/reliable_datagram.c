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
#include <string.h>

#ifndef	ARCH_PC_WIN95
#  include <netdb.h>
#  include <sys/socket.h>
#else
#  include <winsock2.h>
#endif

#include "arch.h"
#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_data_link.h"
#include "spu_memory.h"
#include "stdutil/stdhash.h"

#include "objects.h"
#include "net_types.h"
#include "node.h"
#include "link.h"
#include "network.h"
#include "hello.h"
#include "reliable_datagram.h"
#include "protocol.h"

#include "spines.h"

/* Local consts */

static const sp_time zero_timeout  = {     0,    0};

/***********************************************************/
/* Reliable_Send_Msg() takes the given packet_body buffer  */
/* and tries to send it reliably, while giving back        */
/* an empty packet_body buffer to the upper function.      */
/* The current packet may be buffered, may stay in the     */
/* window, etc.                                            */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* linkid:    ID of the link to send on                    */
/* buff:      pointer to the message                       */
/* buff_len:  length of the buffer                         */
/* pack_type: type of the packet                           */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* # of bytes sent                                         */
/***********************************************************/

int Reliable_Send_Msg(int16 linkid, char *buff, int16u buff_len, int32u pack_type) 
{
    int32u i;
    int ret = -1;
    sys_scatter *scat;
    packet_header *hdr;
    reliable_tail *r_tail;
    Link *lk;
    Reliable_Data *r_data;
    Buffer_Cell *buf_cell;
    char *p_nack;
    int16u ack_len;
    sp_time timeout_val, sum_time, tmp_time, now;

    now = E_get_time();

    /* Increment the reference count */
    inc_ref_cnt(buff);

    /* Getting Link and reliable data from linkid */
    lk = Links[linkid];
    if(lk == NULL) {
        Alarm(EXIT, "Reliable_Send_Msg(): Non existing link !");
    }    
    r_data = lk->r_data;
    if(r_data == NULL) {
	Alarm(EXIT, "Reliable_Send_Msg(): Link has no reliable data struct !");
    }
    
    /* Setting the reliability tail of the packet */
    r_tail = (reliable_tail*)(buff+buff_len);
    r_tail->seq_no = r_data->seq_no++;
    r_tail->cummulative_ack = r_data->recv_tail;

    /* First try to send whatever is in the buffer in front of us, if possible */    
    if(r_data->flags & CONNECTED_LINK) {
	Send_Much(linkid);
    }
    
    /*
     *    Alarm(DEBUG, "!!! linkid: %d; head: %d; tail: %d; win_size: %5.3f; max_win: %d\n",
     *	  linkid, r_data->head, r_data->tail, r_data->window_size, r_data->max_window);
     *    Alarm(DEBUG, "!!! linkid: %d; recv_head: %d; recv_tail: %d; flags: %d\n",
     *	  linkid, r_data->recv_head, r_data->recv_tail, r_data->flags);
     */

    /* If there is no more room in the window, or the link is not valid yet, 
     * stick the message in the sending buffer */

    if((r_data->head - r_data->tail >= r_data->window_size)||
       (!stdcarr_empty(&r_data->msg_buff))||
       (!(r_data->flags & CONNECTED_LINK))) {
	if((buf_cell = (Buffer_Cell*) new(BUFFER_CELL))==NULL) {
	    Alarm(EXIT, "Reliable_Send_Control_Msg(): Cannot allocate buffer cell\n");
	}
	buf_cell->data_len = buff_len;
	buf_cell->pack_type = pack_type;
	buf_cell->buff = buff;
	buf_cell->seq_no = r_tail->seq_no;

	stdcarr_push_back(&r_data->msg_buff, &buf_cell);
	/*	
	 * Alarm(DEBUG, "IN buff: seq: %d; tail: %d; head: %d; buff: %d; win: %5.3f\n", 
	 *     r_tail->seq_no, r_data->tail, r_data->head, stdcarr_size(&r_data->msg_buff), r_data->window_size);
	 */
	
	if(stdcarr_size(&r_data->msg_buff) > MAX_BUFF_LINK) {
	    if(Link_Sessions_Blocked_On == -1) {
		Link_Sessions_Blocked_On = linkid;
		Block_All_Sessions();
	    }
	}

	/* Alarm(PRINT, "buff: %d\n", stdcarr_size(&r_data->msg_buff)); */
	if (r_data->flags & CONNECTED_LINK) {
	    /* Resend the tail if there is no room in the window and there are packets buffered. 
	     * It is likely that there will be a timeout */	
            Alarm(DEBUG, " \t: would have resent tail: waiting for timeouts\n"); 
            /*
	    if(((stdcarr_size(&r_data->msg_buff) >= (unsigned int)r_data->window_size) && 
		(r_data->tail - r_data->last_tail_resent >= (unsigned int)(r_data->window_size/2)))||
	       ((stdcarr_size(&r_data->msg_buff) >= (unsigned int)(2*r_data->window_size))&&
		(r_data->tail - r_data->last_tail_resent >= 1))) {
		r_data->last_tail_resent = r_data->tail;
		if(r_data->nack_buff == NULL) {
		    if((r_data->nack_buff = (char*) new(PACK_BODY_OBJ))==NULL) {
			Alarm(EXIT, "Process_Ack(): Cannot allocate pack_body object\n");
		    }	
		}
		if(r_data->nack_len + sizeof(int32) < sizeof(packet_body)) {
		    memcpy(r_data->nack_buff+r_data->nack_len, (char*)(&r_data->tail), 
			   sizeof(int32));
		    r_data->nack_len += sizeof(int32);
		    r_data->cong_flag = 0;
		}
		E_queue(Send_Nack_Retransm, (int)linkid, NULL, zero_timeout);
	    }
            */
	}
	
	return(0);
    }

    /* If I got here it means that I have some space in the window, 
     * so I can go ahead and send the packet */
    if(r_data->head > r_tail->seq_no)
	Alarm(EXIT, "Reliable_Send_Msg(): sending a packet with a smaller seq_no (head %d, sending %d, link %d)\n", r_data->head, r_tail->seq_no, linkid);
    
    r_data->window[r_tail->seq_no%MAX_WINDOW].data_len = buff_len;
    r_data->window[r_tail->seq_no%MAX_WINDOW].pack_type = pack_type;
    r_data->window[r_tail->seq_no%MAX_WINDOW].buff = buff;
    r_data->window[r_tail->seq_no%MAX_WINDOW].timestamp = now;
    r_data->window[r_tail->seq_no%MAX_WINDOW].seq_no = r_tail->seq_no;
    r_data->window[r_tail->seq_no%MAX_WINDOW].resent = 0;

    r_data->head = r_tail->seq_no+1;

    /*
     *    Alarm(DEBUG, " IN wind: seq: %d; tail: %d; head: %d\n", 
     *	  r_tail->seq_no, r_data->tail, r_data->head);
     */

    /* If there is already an ack to be sent on this link, cancel it, 
     * as this packet will contain the ack info. */
    if(r_data->scheduled_ack == 1) {
	r_data->scheduled_ack = 0;
	E_dequeue(Send_Ack, (int)linkid, NULL);
    }


    /* Allocating the new scatter and header for the reliable message */
    
    if((scat = (sys_scatter*) new(SYS_SCATTER))==NULL) {
	Alarm(EXIT, "Reliable_Send_Msg(): Cannot allocate sys_scatter object\n");
    }
    if((hdr = (packet_header*) new(PACK_HEAD_OBJ))==NULL) {
	Alarm(EXIT, "Reliable_Send_Msg(): Cannot allocate pack_header object\n");
    }
    
    ack_len = sizeof(reliable_tail); 
    /* Add NACKs to the reliable tail */
    p_nack = (char*)r_tail;
    p_nack += ack_len;
    for(i=r_data->recv_tail; i<r_data->recv_head; i++) {
	if(ack_len+buff_len > sizeof(packet_body) - sizeof(int32))
	    break;
	if(r_data->recv_window[i%MAX_WINDOW].flag == EMPTY_CELL) {
	    if((r_data->recv_head - i > 3)||
	       ((r_data->recv_head - i > 1)&&(Fast_Retransmit == 1))) {
		*((int32*)p_nack) = i;
		p_nack += sizeof(int32);
		ack_len += sizeof(int32);
		r_data->recv_window[i%MAX_WINDOW].flag = NACK_CELL;
		r_data->recv_window[i%MAX_WINDOW].nack_sent = now;
	    }
	}
	else if(r_data->recv_window[i%MAX_WINDOW].flag == NACK_CELL) {
	    if(r_data->rtt == 0) {
		tmp_time.sec  = 1;
		tmp_time.usec = 0;
	    }
	    else {
		tmp_time.sec  = r_data->rtt*2/1000000;
		tmp_time.usec = r_data->rtt*2%1000000;
	    }
	    sum_time = E_add_time(r_data->recv_window[i%MAX_WINDOW].nack_sent,
				  tmp_time);
	    if((sum_time.sec < now.sec)||
	       ((sum_time.sec == now.sec)&&(sum_time.usec < now.usec))) {
		*((int32*)p_nack) = i;
		p_nack += sizeof(int32);
		ack_len += sizeof(int32);
		r_data->recv_window[i%MAX_WINDOW].nack_sent = now;
	    }
	}
    }


    scat->num_elements    = 2; 
    scat->elements[0].len = sizeof(packet_header);
    scat->elements[0].buf = (char*) hdr;
    scat->elements[1].len = buff_len + ack_len;  
    scat->elements[1].buf = buff;

    /* Preparing a packet header */
    hdr->type             = RELIABLE_TYPE | pack_type;
    hdr->type             = Set_endian(hdr->type);

    hdr->sender_id        = My_Address;
    hdr->ctrl_link_id     = lk->leg->ctrl_link_id;
    hdr->data_len         = buff_len; 
    hdr->ack_len          = ack_len;
    hdr->seq_no           = Set_Loss_SeqNo(lk->leg, lk->link_type);

    /* Sending the data */
    if(network_flag == 1) {
      ret = Link_Send(lk, scat);

      Alarm(DEBUG, "Sent: data: %d; ack: %d; hdr: %d; total: %d\n",
	    buff_len, ack_len, sizeof(packet_header), ret);
    }
    else {
        ret = 0;
    }

    dispose(scat->elements[0].buf);
    dispose(scat);

    if(r_data->scheduled_timeout == 1) {
        E_dequeue(Reliable_timeout, (int)linkid, NULL);
    }
    timeout_val.sec = (r_data->rtt*2)/1000000;
    timeout_val.usec = (r_data->rtt*2)%1000000;

    if(timeout_val.sec == 0 && timeout_val.usec == 0) {
        timeout_val.sec = 1;
    }
    if(timeout_val.sec == 0 && timeout_val.usec < 2000) {
	timeout_val.usec = 2000;
    }
    if(Wireless && timeout_val.sec == 0 && timeout_val.usec < 30000) {
	timeout_val.usec = 20000+5000*(rand()%10);
    }

    timeout_val.sec  *= r_data->timeout_multiply;
    timeout_val.usec *= r_data->timeout_multiply;
    timeout_val.sec += timeout_val.usec/1000000;
    timeout_val.usec = timeout_val.usec%1000000;

    if(timeout_val.sec > (DEAD_LINK_CNT-1)) {
	timeout_val.sec = (DEAD_LINK_CNT-1);
    }

    E_queue(Reliable_timeout, (int)linkid, NULL, timeout_val);
    r_data->scheduled_timeout = 1;

    return ret;
}

/***********************************************************/
/* Tries to send anything in the buffer (if there is room  */
/* available in the window)                                */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* linkid:    ID of the link to send on                    */
/***********************************************************/

void Send_Much(int16 linkid) 
{
    sys_scatter scat;
    packet_header hdr;
    Link *lk;
    Reliable_Data *r_data;
    Buffer_Cell *buf_cell;
    reliable_tail *r_tail;
    char *p_nack;
    stdit it;
    char *send_buff;
    int16 data_len;
    int16 ack_len;
    int32u pack_type, seq_no;
    int buff_size;
    int ret;
    int32u i;
    sp_time timeout_val, sum_time, tmp_time, now;

    now = E_get_time();
    /* Getting Link and protocol data from linkid */
    lk = Links[linkid];
    if(lk == NULL)
	Alarm(EXIT, "Send_Much(): link not valid\n");

    if(lk->r_data == NULL)
	Alarm(EXIT, "Send_Much(): This is not a reliable link !\n");

    r_data = lk->r_data;

    /* Return if the link is not valid yet */
    if(!(r_data->flags & CONNECTED_LINK))
	return;

    /* See if we have room in the window to send anything */
    if(r_data->head - r_data->tail >= r_data->window_size) {
	return;
    }
	
    /* Return if the buffer is empty */
    if(stdcarr_empty(&(r_data->msg_buff))) {
	return;
    }

    buff_size = stdcarr_size(&(r_data->msg_buff));

    /* If there is already an ack to be sent on tihs link, cancel it, 
       as this packet will contain the ack info. */
    if(r_data->scheduled_ack == 1) {
	r_data->scheduled_ack = 0;
	E_dequeue(Send_Ack, (int)linkid, NULL);
	Alarm(DEBUG, "Ack optimization successfull !!!\n");
    }


    /* Allocating the new scatter and header for the reliable messages */
    
    scat.num_elements = 2; /* For now there are only two elements in 
			       the scatter */
    scat.elements[0].len = sizeof(packet_header);
    scat.elements[0].buf = (char *) &hdr;
	

    /* If we got up to here, we do have room in the window. Send what we can */
    while(r_data->head - r_data->tail < r_data->window_size) {
	/* Stop if the buffer is empty */
	if(stdcarr_empty(&(r_data->msg_buff))) {
	    break;
	}

	/* Take the first packet from the buffer (queue) and put it into the window */
	stdcarr_begin(&(r_data->msg_buff), &it);
	buf_cell = *((Buffer_Cell **)stdcarr_it_val(&it));
	stdcarr_pop_front(&(r_data->msg_buff));
	    
	data_len = buf_cell->data_len;
	ack_len = sizeof(reliable_tail);
	pack_type = buf_cell->pack_type;
	    
	if((buff_size > MAX_BUFF_LINK/4)&&(buff_size <= MAX_BUFF_LINK/2)) {
	    if((pack_type & ECN_DATA_MASK) == 0) {
		pack_type = pack_type | ECN_DATA_T1;
	    }
	}
	else if((buff_size > MAX_BUFF_LINK/2)&&(buff_size <= MAX_BUFF_LINK)) {
	    if((pack_type & ECN_DATA_MASK) < ECN_DATA_T2) {
		if((pack_type & ECN_DATA_MASK) == ECN_DATA_T1) {
		    pack_type = pack_type ^ ECN_DATA_T1;		
		}
		pack_type = pack_type | ECN_DATA_T2;
	    }
	}
	else if(buff_size > MAX_BUFF_LINK) {
	    pack_type = pack_type | ECN_DATA_T3;
	}

	send_buff = buf_cell->buff;
	seq_no = buf_cell->seq_no;

	r_tail = (reliable_tail*)(send_buff + data_len);
	    
	/* Discard the cell from the buffer */
	dispose(buf_cell);

	/* Set the cummulative ack */
	r_tail->cummulative_ack = r_data->recv_tail;
	r_tail->seq_no = seq_no;

	if(r_data->head > r_tail->seq_no)
	    Alarm(EXIT, "Send_Much(): smaller seq_no: %d than head: %d\n",
		  r_tail->seq_no, r_data->head);
	    
	r_data->window[r_tail->seq_no%MAX_WINDOW].data_len  = data_len;
	r_data->window[r_tail->seq_no%MAX_WINDOW].pack_type = pack_type;
	r_data->window[r_tail->seq_no%MAX_WINDOW].buff      = send_buff;
	r_data->window[r_tail->seq_no%MAX_WINDOW].seq_no    = seq_no;
	r_data->window[r_tail->seq_no%MAX_WINDOW].timestamp = now;
	r_data->window[r_tail->seq_no%MAX_WINDOW].resent = 0;
	r_data->head = r_tail->seq_no+1;

	Alarm(DEBUG, " OUT buf: seq: %d; tail: %d; head: %d\n", 
	      r_tail->seq_no, r_data->tail, r_data->head);

	    
	ack_len = sizeof(reliable_tail); 
	/* Add NACKs to the reliable tail */
	p_nack = (char*)r_tail;
	p_nack += ack_len;
	for(i=r_data->recv_tail; i<r_data->recv_head; i++) {
	    if(ack_len+data_len > sizeof(packet_body) - sizeof(int32))
		break;
	    if(r_data->recv_window[i%MAX_WINDOW].flag == EMPTY_CELL) {
		if((r_data->recv_head - i > 3)||
		   ((r_data->recv_head - i > 1)&&(Fast_Retransmit == 1))) {
		    *((int32*)p_nack) = i;
		    p_nack += sizeof(int32);
		    ack_len += sizeof(int32);
		    r_data->recv_window[i%MAX_WINDOW].flag = NACK_CELL;
		    r_data->recv_window[i%MAX_WINDOW].nack_sent = now;
		    Alarm(DEBUG, "NACK sent: %d !\n", i);
		}
	    }
	    if(r_data->recv_window[i%MAX_WINDOW].flag == NACK_CELL) {
		if(r_data->rtt == 0) {
		    tmp_time.sec  = 1;
		    tmp_time.usec = 0;
		}
		else {
		    tmp_time.sec  = r_data->rtt*2/1000000;
		    tmp_time.usec = r_data->rtt*2%1000000;
		}
		sum_time = E_add_time(r_data->recv_window[i%MAX_WINDOW].nack_sent,
				      tmp_time);
		if((sum_time.sec < now.sec)||
		   ((sum_time.sec == now.sec)&&(sum_time.usec < now.usec))) {
		    *((int32*)p_nack) = i;
		    p_nack += sizeof(int32);
		    ack_len += sizeof(int32);
		    r_data->recv_window[i%MAX_WINDOW].nack_sent = now;
		    Alarm(DEBUG, "%%% NACK sent again: %d !\n", i);
		}
	    }
	}
	
	/* Send the packet */
	
	/* Preparing a packet header */
	hdr.type         = RELIABLE_TYPE | pack_type;
	hdr.type         = Set_endian(hdr.type);
	hdr.sender_id    = My_Address;
	hdr.ctrl_link_id = lk->leg->ctrl_link_id;
	hdr.data_len     = data_len; 
	hdr.ack_len      = ack_len;
	hdr.seq_no       = Set_Loss_SeqNo(lk->leg, lk->link_type);
	    
	scat.elements[1].len = data_len + ack_len;    
	scat.elements[1].buf = send_buff;

        /* Sending the data */
	ret = Link_Send(Links[linkid], &scat);

	Alarm(DEBUG, "Sent: data: %d; ack: %d; hdr: %d; total: %d\n",
	      data_len, ack_len, sizeof(packet_header), ret);
	
    } 

    if(Link_Sessions_Blocked_On == linkid) {
	if(stdcarr_size(&(r_data->msg_buff)) < MAX_BUFF_LINK/4) {
	    Resume_All_Sessions();
	    Link_Sessions_Blocked_On = -1;
	}
    }


    if(r_data->scheduled_timeout == 1) {
	E_dequeue(Reliable_timeout, (int)linkid, NULL);
    }

    timeout_val.sec = (r_data->rtt*2)/1000000;
    timeout_val.usec = (r_data->rtt*2)%1000000;

    if(timeout_val.sec == 0 && timeout_val.usec == 0) {
        timeout_val.sec = 1;
    }
    if(timeout_val.sec == 0 && timeout_val.usec < 2000) {
	timeout_val.usec = 2000;
    }
    if(Wireless && timeout_val.sec == 0 && timeout_val.usec < 30000) {
	timeout_val.usec = 20000+5000*(rand()%10);
    }

    timeout_val.sec  *= r_data->timeout_multiply;
    timeout_val.usec *= r_data->timeout_multiply;
    timeout_val.sec += timeout_val.usec/1000000;
    timeout_val.usec = timeout_val.usec%1000000;

    if(timeout_val.sec > (DEAD_LINK_CNT-1))
	timeout_val.sec = (DEAD_LINK_CNT-1);


    /*    Alarm(DEBUG, "---timeout sec: %d; usec: %d\n",
     *	  timeout_val.sec, timeout_val.usec);
     */

    E_queue(Reliable_timeout, (int)linkid, NULL, timeout_val);

    r_data->scheduled_timeout = 1;
}

/***********************************************************/
/* Sends an ACK                                            */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* linkid:    ID of the link to send on                    */
/* dummy:     Not used                                     */
/***********************************************************/

void Send_Ack(int linkid, void* dummy) 
{
    sys_scatter scat;
    packet_header hdr;
    packet_body send_buff;
    reliable_tail *r_tail;
    Link *lk;
    Reliable_Data *r_data;
    char *p_nack;
    int16 ack_len;
    int16 data_len = 0;
    int32u i;
    int ret;
    sp_time sum_time, tmp_time, now;

    now = E_get_time();
    /* Getting Link and protocol data from linkid */
    lk = Links[linkid];
    if(lk == NULL)
	Alarm(EXIT, "Send_Ack(): link not valid\n");

    if(lk->r_data == NULL) 
	Alarm(EXIT, "Send_Ack: Not a reliable link\n");
    
    r_data = lk->r_data;
    
    if(!(r_data->flags & CONNECTED_LINK))
	Alarm(EXIT, "Send_Ack: Link not valid yet\n");
    
    r_data->scheduled_ack = 0;

    r_tail = (reliable_tail*)send_buff;
    /*r_tail->seq_no = r_data->seq_no;*/
    r_tail->seq_no = 0;
    r_tail->cummulative_ack = r_data->recv_tail;


    ack_len = sizeof(reliable_tail); 
    /* Add NACKs to the reliable tail */
    p_nack = (char*)r_tail;
    p_nack += ack_len;
    for(i=r_data->recv_tail; i<r_data->recv_head; i++) {
	if(ack_len+data_len > sizeof(packet_body) - sizeof(int32))
	    break;
	if(r_data->recv_window[i%MAX_WINDOW].flag == EMPTY_CELL) {
	    if((r_data->recv_head - i > 3)||
	       ((r_data->recv_head - i > 1)&&(Fast_Retransmit == 1))) {
		*((int32*)p_nack) = i;
		p_nack += sizeof(int32);
		ack_len += sizeof(int32);
		r_data->recv_window[i%MAX_WINDOW].flag = NACK_CELL;
		r_data->recv_window[i%MAX_WINDOW].nack_sent = now;
	    }
	}
	else if(r_data->recv_window[i%MAX_WINDOW].flag == NACK_CELL) {
	    if(r_data->rtt == 0) {
		tmp_time.sec  = 1;
		tmp_time.usec = 0;
	    }
	    else {
		tmp_time.sec  = r_data->rtt*2/1000000;
		tmp_time.usec = r_data->rtt*2%1000000;
	    }
	    sum_time = E_add_time(r_data->recv_window[i%MAX_WINDOW].nack_sent,
				  tmp_time);
	    if((sum_time.sec < now.sec)||
	       ((sum_time.sec == now.sec)&&(sum_time.usec < now.usec))) {
		*((int32*)p_nack) = i;
		p_nack += sizeof(int32);
		ack_len += sizeof(int32);
		r_data->recv_window[i%MAX_WINDOW].nack_sent = now;
	    }
	}
    }

    scat.num_elements = 2; /* For now there are only two elements in 
			      the scatter */
    scat.elements[0].len = sizeof(packet_header);
    scat.elements[0].buf = (char *)(&hdr);
    scat.elements[1].len = ack_len;
    scat.elements[1].buf = send_buff;
	
    /* Preparing a packet header */
    hdr.type         = LINK_ACK_TYPE;
    hdr.type         = Set_endian(hdr.type);
    hdr.sender_id    = My_Address;
    hdr.ctrl_link_id = lk->leg->ctrl_link_id;
    hdr.data_len     = 0; 
    hdr.ack_len      = ack_len;
    hdr.seq_no       = Set_Loss_SeqNo(lk->leg, lk->link_type);

    /* Sending the ack*/
    if(network_flag == 1) {
      ret = Link_Send(Links[linkid], &scat);

      Alarm(DEBUG, "Sent: data: %d; ack: %d; hdr: %d; total: %d\n",
	    data_len, ack_len, sizeof(packet_header), ret);
    }
}

/***********************************************************/
/* Handles a timeout                                       */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* linkid:    ID of the link to send on                    */
/* dummy:     Not used                                     */
/***********************************************************/

void Reliable_timeout(int linkid, void *dummy) 
{
    sys_scatter *scat;
    packet_header *hdr;
    udp_header *cur_uhdr;
    Link *lk;
    Reliable_Data *r_data;
    reliable_tail *r_tail;
    char *send_buff;
    char *p_nack;
    int16 data_len;
    int16 ack_len;
    int32u pack_type, seq_no;
    float stream_window;
    int ret;
    int32u i, cur_seq;
    sp_time timeout_val, sum_time, tmp_time, now;

    now = E_get_time();

    /* Getting Link and protocol data from linkid */
    lk = Links[linkid];
    if(lk == NULL)
	Alarm(EXIT, "Reliable_timeout: link not valid\n");
    if(lk->r_data == NULL) 
	Alarm(EXIT, "Reliable_timeout: not a reliable link\n");
    
    r_data = lk->r_data;

    if(!(r_data->flags & CONNECTED_LINK))
	Alarm(EXIT, "Reliable_timeout: Link not valid yet\n");
    

    /* First see if we have anything in the window */
    if(r_data->head == r_data->tail) {
	Alarm(DEBUG, "Reliable_timeout: Nothing to send ! tail=head=%d\n",
	      r_data->head);
	r_data->scheduled_timeout = 0;
	return;
    }
	
    Alarm(DEBUG, "REL_TMOUT: tail: %d; head:%d; rtt: %d\n", 
	  r_data->tail, r_data->head, r_data->rtt);

    if((Stream_Fairness == 1)&&
       ((r_data->window[r_data->tail%MAX_WINDOW].pack_type & UDP_DATA_TYPE)||
	(r_data->window[r_data->tail%MAX_WINDOW].pack_type & REL_UDP_DATA_TYPE))){

	cur_uhdr = (udp_header*)r_data->window[r_data->tail%MAX_WINDOW].buff;

	stream_window = 0.0;
	for(cur_seq = r_data->tail; (cur_seq < r_data->tail+r_data->window_size)&&
		(cur_seq < r_data->head); cur_seq++) {
	    if(memcmp(r_data->window[cur_seq%MAX_WINDOW].buff, 
		      (char*)cur_uhdr, 2*sizeof(int32)+2*sizeof(int16u)) == 0) {
		stream_window += 1.0;
	    }
	}

	Alarm(DEBUG, "%d:%d -> %d:%d :: Timeout; stream_window: %5.3f : %5.3f\n", 
	      cur_uhdr->source, cur_uhdr->source_port,
	      cur_uhdr->dest, cur_uhdr->dest_port, stream_window, r_data->window_size);

	if(stream_window == 0.0) {
	    stream_window = 1.0;
	    Alarm(DEBUG, "Timeout: stream_window = 0\n");
	}

    }
    else {
	stream_window = r_data->window_size;
    }

    /* Congestion control */
    if (TCP_Fairness) {
        r_data->ssthresh = (unsigned int)(r_data->window_size - stream_window/2);
        if(r_data->ssthresh < (unsigned int)Minimum_Window)
            r_data->ssthresh = Minimum_Window;

        r_data->window_size = r_data->window_size - stream_window + 1;
        if(r_data->window_size < Minimum_Window)
            r_data->window_size = (float)Minimum_Window;
       
        Alarm(DEBUG, "window adjusted: %5.3f timeout; tail: %d\n", r_data->window_size, r_data->tail);
    }

    /* If there is already an ack to be sent on this link, cancel it, 
       as this packet will contain the ack info. */
    if(r_data->scheduled_ack == 1) {
	r_data->scheduled_ack = 0;
	E_dequeue(Send_Ack, (int)linkid, NULL);
	Alarm(DEBUG, "Ack optimization successfull !!!\n");
    }

    /* Allocating the new scatter and header for the reliable messages */
    
    if((scat = (sys_scatter*) new(SYS_SCATTER))==NULL) {
	Alarm(EXIT, "Reliable_timeout: Cannot allocate sys_scatter object\n");
    }
    if((hdr = (packet_header*) new(PACK_HEAD_OBJ))==NULL) {
	Alarm(EXIT, "Reliable_timeout: Cannot allocate pack_header object\n");
    }
    scat->num_elements = 2; /* For now there are only two elements in 
			       the scatter */
    scat->elements[0].len = sizeof(packet_header);
    scat->elements[0].buf = (char *) hdr;
	
    /* If we got up to here, we do have smthg in the window. */

    for(cur_seq = r_data->tail; cur_seq < r_data->head; cur_seq++) {

	data_len  = r_data->window[cur_seq%MAX_WINDOW].data_len;
	ack_len   = sizeof(reliable_tail);
	pack_type = r_data->window[cur_seq%MAX_WINDOW].pack_type;
	send_buff = r_data->window[cur_seq%MAX_WINDOW].buff;
	seq_no    = r_data->window[cur_seq%MAX_WINDOW].seq_no;

	r_data->window[cur_seq%MAX_WINDOW].resent = 1;
	
	if(send_buff == NULL)
	    Alarm(DEBUG, "!!!! ");
	
	Alarm(DEBUG, " %d -- timeout: resending %d\n", linkid, cur_seq);
	
	r_tail = (reliable_tail*)(send_buff + data_len);
	Alarm(DEBUG, "((( tail: %d; seq_no: %d; data_len: %d, ack_len: %d\n",
	      r_data->tail, r_tail->seq_no, data_len, ack_len);
		
	/* Set the cummulative ack */
	r_tail->cummulative_ack = r_data->recv_tail;
	r_tail->seq_no = seq_no;
	
	/* Add NACKs to the reliable tail */
	p_nack = (char*)r_tail;
	p_nack += ack_len;
	for(i=r_data->recv_tail; i<r_data->recv_head; i++) {
	    if(ack_len+data_len > sizeof(packet_body) - sizeof(int32))
	    break;
	    if(r_data->recv_window[i%MAX_WINDOW].flag == EMPTY_CELL) {
		if((r_data->recv_head - i > 3)||
		   ((r_data->recv_head - i > 1)&&(Fast_Retransmit == 1))) {
		    *((int32*)p_nack) = i;
		    p_nack += sizeof(int32);
		    ack_len += sizeof(int32);
		    r_data->recv_window[i%MAX_WINDOW].flag = NACK_CELL;
		    r_data->recv_window[i%MAX_WINDOW].nack_sent = now;
		    Alarm(DEBUG, "NACK sent: %d !\n", i);
		}
	    }
	    else if(r_data->recv_window[i%MAX_WINDOW].flag == NACK_CELL) {
		if(r_data->rtt == 0) {
		    tmp_time.sec  = 1;
		    tmp_time.usec = 0;
		}
		else {
		    tmp_time.sec  = r_data->rtt*2/1000000;
		    tmp_time.usec = r_data->rtt*2%1000000;
		}
		sum_time = E_add_time(r_data->recv_window[i%MAX_WINDOW].nack_sent,
				      tmp_time);
		if((sum_time.sec < now.sec)||
		   ((sum_time.sec == now.sec)&&(sum_time.usec < now.usec))) {
		    *((int32*)p_nack) = i;
		    p_nack += sizeof(int32);
		    ack_len += sizeof(int32);
		    r_data->recv_window[i%MAX_WINDOW].nack_sent = now;
		    Alarm(DEBUG, "%%% NACK sent again: %d !\n", i);
		}
	    }
	}
	
	/* Send the packet */
	
	/* Preparing a packet header */
	hdr->type         = RELIABLE_TYPE | pack_type;
	hdr->type         = Set_endian(hdr->type);
	hdr->sender_id    = My_Address;
	hdr->ctrl_link_id = lk->leg->ctrl_link_id;
	hdr->data_len     = data_len; 
	hdr->ack_len      = ack_len;
	hdr->seq_no       = Set_Loss_SeqNo(lk->leg, lk->link_type);
	
	scat->elements[1].len = data_len + ack_len;    
	scat->elements[1].buf = send_buff;
	
	/* Sending the data */
        if(network_flag == 1) {
	  ret = Link_Send(Links[linkid], scat);

	  Alarm(DEBUG, "Sent: data: %d; ack: %d; hdr: %d; total: %d\n",
		data_len, ack_len, sizeof(packet_header), ret);
        }
    }

    dispose(scat->elements[0].buf);
    dispose(scat);
	
    timeout_val.sec = (r_data->rtt*2)/1000000;
    timeout_val.usec = (r_data->rtt*2)%1000000;

    if(timeout_val.sec == 0 && timeout_val.usec == 0) {
        timeout_val.sec = 1;
    }
    if(timeout_val.sec == 0 && timeout_val.usec < 2000) {
	timeout_val.usec = 2000;
    }
    if(Wireless && timeout_val.sec == 0 && timeout_val.usec < 30000) {
	timeout_val.usec = 20000+5000*(rand()%10);
    }

    /* Increase the timeout exponentially */
    r_data->timeout_multiply *= 2;

    if(r_data->timeout_multiply > 100)
	r_data->timeout_multiply = 100;

    Alarm(DEBUG, "\n! ! timeout_multiply: %d\n", r_data->timeout_multiply);
    Alarm(DEBUG, "Reliable_timeout: Current timeout_multiply: %d\n", r_data->timeout_multiply);

    timeout_val.sec  *= r_data->timeout_multiply;
    timeout_val.usec *= r_data->timeout_multiply;
    timeout_val.sec += timeout_val.usec/1000000;
    timeout_val.usec = timeout_val.usec%1000000;

    if(timeout_val.sec > (DEAD_LINK_CNT-1))
	timeout_val.sec = (DEAD_LINK_CNT-1);

    Alarm(DEBUG, "---timeout sec: %d; usec: %d\n",
	  timeout_val.sec, timeout_val.usec);
    
    E_queue(Reliable_timeout, (int)linkid, NULL, timeout_val);
}

/***********************************************************/
/* Answers to a NACK                                       */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* linkid:    ID of the link to send on                    */
/* dummy:     Not used                                     */
/***********************************************************/

void Send_Nack_Retransm(int linkid, void *dummy) 
{
    sys_scatter *scat;
    packet_header *hdr;
    float stream_window;
    udp_header *cur_uhdr;
    int32u cur_seq;
    Link *lk;
    Reliable_Data *r_data;
    reliable_tail *r_tail;
    char *send_buff;
    char *p_nack;
    int16 data_len;
    int16 ack_len;
    int32u pack_type, seq_no;
    int32u nack_seq;
    int j, ret;
    int32u i;
    sp_time sum_time, tmp_time, now;
    
    now = E_get_time();

    /* Getting Link and protocol data from linkid */
    lk = Links[linkid];
    if(lk == NULL)
	Alarm(EXIT, "Send_Nack_Retransm: link not valid\n");
    if(lk->r_data == NULL) 
	Alarm(EXIT, "Send_Nack_Retransm: not a reliable link\n");
    
    r_data = lk->r_data;

    if(!(r_data->flags & CONNECTED_LINK))
	Alarm(EXIT, "Send_Nack_Retransm: Link not valid yet\n");
    
    /* First see if we have anything in the window to send */
    if((r_data->nack_len == 0)||(r_data->nack_buff == NULL)) {
	Alarm(DEBUG, "Send_Nack_Retransm: Oops, nothing to resend here\n");
	return;
    }

    if(r_data->head == r_data->tail) {
	Alarm(DEBUG, "Send_Nack_Retransm: Nothing to send ! tail=head=%d\n",
	      r_data->head);
	r_data->scheduled_timeout = 0;
	return;
    }
	
    nack_seq = *((int*)r_data->nack_buff);	
	
    if((Stream_Fairness == 1)&&
       ((r_data->window[nack_seq%MAX_WINDOW].pack_type & UDP_DATA_TYPE)||
	(r_data->window[nack_seq%MAX_WINDOW].pack_type & REL_UDP_DATA_TYPE))){

	cur_uhdr = (udp_header*)r_data->window[nack_seq%MAX_WINDOW].buff;

	stream_window = 0.0;
	for(cur_seq = r_data->tail; (cur_seq < r_data->tail+r_data->window_size)&&
		(cur_seq < r_data->head); cur_seq++) {
	    if(memcmp(r_data->window[cur_seq%MAX_WINDOW].buff, 
		      (char*)cur_uhdr, 2*sizeof(int32)+2*sizeof(int16u)) == 0) {
		stream_window += 1.0;
	    }
	}

	Alarm(DEBUG, "%d:%d -> %d:%d :: Nack Retransmission; stream_window: %5.3f : %5.3f\n", 
	      cur_uhdr->source, cur_uhdr->source_port,
	      cur_uhdr->dest, cur_uhdr->dest_port, stream_window, r_data->window_size);

	if(stream_window == 0.0) {
	    stream_window = 1.0;
	    Alarm(DEBUG, "Nack Retransmission: stream_window = 0\n");
	}

    }
    else {
	stream_window = r_data->window_size;
    }

    if (TCP_Fairness) {
        if(r_data->cong_flag == 1) {
            /* Congestion control */
            r_data->ssthresh = (unsigned int)(r_data->window_size - stream_window/2);
            if(r_data->ssthresh < (unsigned int)Minimum_Window) {
                r_data->ssthresh = Minimum_Window;
            }
            r_data->window_size = r_data->window_size - stream_window/2;
            if(r_data->window_size < Minimum_Window) {
                r_data->window_size = (float)Minimum_Window;
            }
            Alarm(DEBUG, "window adjusted: %5.3f nack\n", r_data->window_size);
        }
        else {
            r_data->cong_flag = 1;
        }
    }

    /* If there is already an ack to be sent on this link, cancel it, 
       as these packets will contain the ack info. */
    if(r_data->scheduled_ack == 1) {
	r_data->scheduled_ack = 0;
	E_dequeue(Send_Ack, (int)linkid, NULL);
	Alarm(DEBUG, "Ack optimization successfull !!!\n");
    }

    /* Allocating the new scatter and header for the reliable messages */
    
    if((scat = (sys_scatter*) new(SYS_SCATTER))==NULL) {
	Alarm(EXIT, "Reliable_timeout: Cannot allocate sys_scatter object\n");
    }
    if((hdr = (packet_header*) new(PACK_HEAD_OBJ))==NULL) {
	Alarm(EXIT, "Reliable_timeout: Cannot allocate pack_header object\n");
    }
    scat->num_elements = 2; /* For now there are only two elements in 
			       the scatter */
    scat->elements[0].len = sizeof(packet_header);
    scat->elements[0].buf = (char *) hdr;	

    /* Check each nack individually */
	
    for(j=0; j<r_data->nack_len; j += sizeof(int32)) {
	nack_seq = *((int*)(r_data->nack_buff+j));
	if(r_data->window[nack_seq%MAX_WINDOW].buff == NULL)
	    continue;

	data_len  = r_data->window[nack_seq%MAX_WINDOW].data_len;
	ack_len   = sizeof(reliable_tail);
	pack_type = r_data->window[nack_seq%MAX_WINDOW].pack_type;
	send_buff = r_data->window[nack_seq%MAX_WINDOW].buff;
	seq_no    = r_data->window[nack_seq%MAX_WINDOW].seq_no;

	r_data->window[nack_seq%MAX_WINDOW].resent = 1;
	
	/* Set the cummulative ack */
	r_tail = (reliable_tail*)(send_buff + data_len);
	r_tail->cummulative_ack = r_data->recv_tail;
	r_tail->seq_no = seq_no;

	Alarm(DEBUG, "sending retransm for nack: %d\n", nack_seq);

	/* Add NACKs to the reliable tail */
	p_nack = (char*)r_tail;
	p_nack += ack_len;
	for(i=r_data->recv_tail; i<r_data->recv_head; i++) {
	    if(ack_len+data_len > sizeof(packet_body) - sizeof(int32))
		break;
	    if(r_data->recv_window[i%MAX_WINDOW].flag == EMPTY_CELL) {
		if((r_data->recv_head - i > 3)||
		   ((r_data->recv_head - i > 1)&&(Fast_Retransmit == 1))) {
		    *((int32*)p_nack) = i;
		    p_nack += sizeof(int32);
		    ack_len += sizeof(int32);
		    r_data->recv_window[i%MAX_WINDOW].flag = NACK_CELL;
		    r_data->recv_window[i%MAX_WINDOW].nack_sent = now;
		    Alarm(DEBUG, "NACK sent: %d !\n", i);
		}
	    }
	    if(r_data->recv_window[i%MAX_WINDOW].flag == NACK_CELL) {
		if(r_data->rtt == 0) {
		    tmp_time.sec  = 1;
		    tmp_time.usec = 0;
		}
		else {
		    tmp_time.sec  = r_data->rtt*2/1000000;
		    tmp_time.usec = r_data->rtt*2%1000000;
		}
		sum_time = E_add_time(r_data->recv_window[i%MAX_WINDOW].nack_sent,
				      tmp_time);
		if((sum_time.sec < now.sec)||
		   ((sum_time.sec == now.sec)&&(sum_time.usec < now.usec))) {
		    *((int32*)p_nack) = i;
		    p_nack += sizeof(int32);
		    ack_len += sizeof(int32);
		    r_data->recv_window[i%MAX_WINDOW].nack_sent = now;
		    Alarm(DEBUG, "%%% NACK sent again: %d !\n", i);
		}
	    }
	}

	/* Send the packet */
	
	/* Preparing a packet header */
	hdr->type         = RELIABLE_TYPE | pack_type;
	hdr->type         = Set_endian(hdr->type);
	hdr->sender_id    = My_Address;
	hdr->ctrl_link_id = lk->leg->ctrl_link_id;
	hdr->data_len     = data_len; 
	hdr->ack_len      = ack_len;
        hdr->seq_no       = Set_Loss_SeqNo(lk->leg, lk->link_type);
	
	scat->elements[1].len = data_len + ack_len;    
	scat->elements[1].buf = send_buff;

	/* Sending the data */
        if(network_flag == 1) {
	  ret = Link_Send(Links[linkid], scat);

	  Alarm(DEBUG, "^^^NACK answered: %d; len: %d; j: %d\n", 
		nack_seq, r_data->nack_len, j);
          
	  Alarm(DEBUG, "Sent: data: %d; ack: %d; hdr: %d; total: %d\n",
		data_len, ack_len, sizeof(packet_header), ret);
        }
    }

    dispose(scat->elements[0].buf);
    dispose(scat);

    dispose(r_data->nack_buff);
    r_data->nack_buff = NULL;
    r_data->nack_len = 0;
}

/***********************************************************/
/* Processes an ACK                                        */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* linkid:    ID of the link the ack came on               */
/* buff:      buffer cointaining the ACK                   */
/* ack_len:   length of the ACK                            */
/* type:      type of the packet, cointaining endianess    */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int) 1 if the packet that came with the ack contians   */
/*         any useful data                                 */
/*       0 if that packet has data that we already know    */
/*         (retransm)                                      */
/*      -1 if that packet is just an ack packet            */
/*                                                         */
/***********************************************************/

int Process_Ack(int16 linkid, char *buff, int16u ack_len, int32u type)
{
    Link *lk;
    Reliable_Data *r_data;
    reliable_tail *r_tail;
    float stream_window;
    udp_header *cur_uhdr;
    int32u cur_seq;
    int32u i;
    sp_time timeout_val, now, diff;
    int32u rtt_estimate;
    double old_window;
    int16u to_copy;

    lk = Links[linkid];
    if(lk->r_data == NULL)
	    Alarm(EXIT, "Process_Ack(): Reliable Data is not defined\n");

    r_data = lk->r_data;

    if(!Same_endian(type)) {
	/* Flip for this function only */
	type = Flip_int32(type);
    }

    if(ack_len > sizeof(reliable_tail)) {
	/* We also have NACKs here... */
	/* Alarm(DEBUG, "We also have NACKs here...\n"); */
	if(r_data->nack_len + ack_len > sizeof(packet_body))
        {
	    Alarm(PRINT, "Reliable datagram: process ack on link %d: nack_len: %d; ack_len: %d (sizeof packet_body = %u)\n", linkid, r_data->nack_len, ack_len, sizeof(packet_body));
	    Alarm(PRINT, "WOW !!! a lot of nacks here....is it a bug?\n");
        }

        /* AB: Get amount of nacks we can copy...can end up buffering nacks if the
         * link gets disconnected before we get to send some */
	if(r_data->nack_len + ack_len - sizeof(reliable_tail) > sizeof(packet_body)) {
            to_copy = sizeof(packet_body) - r_data->nack_len;
        } else {
            to_copy = ack_len - sizeof(reliable_tail);
        }

        /* Allocate nack buffer if necessary */
	if(r_data->nack_buff == NULL) {
	    if((r_data->nack_buff = (char*) new(PACK_BODY_OBJ))==NULL) {
		Alarm(EXIT, "Process_Ack(): Cannot allocate pack_body object\n");
	    }	
	}

        /* Copy over nacks to nack buffer */
	memcpy(r_data->nack_buff+r_data->nack_len, buff+sizeof(reliable_tail), to_copy);
	r_data->nack_len += to_copy;
	E_queue(Send_Nack_Retransm, (int)linkid, NULL, zero_timeout);
    }

    /* Check the cummulative acknowledgement */
    r_tail = (reliable_tail*)buff;

    /*
     *Alarm(DEBUG, "%d -- msg: cm_ack: %d; seq: %d; tail: %d; head: %d; recv_tail: %d; wind: %5.3f\n", 
     *	  linkid, r_tail->cummulative_ack, r_tail->seq_no, r_data->tail, r_data->head,
     *	  r_data->recv_tail, r_data->window_size);
     */

    if(r_tail->cummulative_ack > r_data->head) {
        /* This is from another movie...  got an ack for a packet
	 * I haven't sent yet... ignore the packet. 
	 * It's possible that I crashed, woke up, and now got a lost
	 * ack from the other site that doesn't even know I crashed.
	 * Hello Protocol will take care of this. */

        return(0);
    }

    if(r_tail->cummulative_ack > r_data->tail) {
	if(r_tail->cummulative_ack%10 == 0) {
	    /* re-compute the RTT only every 10 packets */
	    if((r_data->window[(r_tail->cummulative_ack-1)%MAX_WINDOW].buff != NULL)&&
	       (r_data->window[(r_tail->cummulative_ack-1)%MAX_WINDOW].resent == 0)) {
		now = E_get_time();
		diff = E_sub_time(now, r_data->window[(r_tail->cummulative_ack-1)%MAX_WINDOW].timestamp);
		rtt_estimate = diff.sec * 1000000 + diff.usec;
		if(r_data->rtt == 0) {
		    r_data->rtt = rtt_estimate;
		}
		else {
		    r_data->rtt = (int)(0.2*rtt_estimate + 0.8*r_data->rtt);
		}
	    }
	}

	for(i=r_data->tail; i<r_tail->cummulative_ack; i++) {
	    if(r_data->window[i%MAX_WINDOW].buff != NULL) {
		dec_ref_cnt(r_data->window[i%MAX_WINDOW].buff);

		r_data->window[i%MAX_WINDOW].buff = NULL;
		r_data->window[i%MAX_WINDOW].data_len = 0;
		r_data->window[i%MAX_WINDOW].pack_type = 0;
	    }
	    else
		Alarm(EXIT, "Process_Ack(): Reliability failure\n");

	    if((Stream_Fairness == 1)&&
	       ((r_data->window[r_data->tail%MAX_WINDOW].pack_type & UDP_DATA_TYPE)||
		(r_data->window[r_data->tail%MAX_WINDOW].pack_type & REL_UDP_DATA_TYPE))){
		
		cur_uhdr = (udp_header*)r_data->window[r_data->tail%MAX_WINDOW].buff;

		stream_window = 0.0;
		for(cur_seq = r_data->tail; (cur_seq < r_data->tail+r_data->window_size)&&
			(cur_seq < r_data->head); cur_seq++) {
		    if(memcmp(r_data->window[cur_seq%MAX_WINDOW].buff, 
			      (char*)cur_uhdr, 2*sizeof(int32)+2*sizeof(int16u)) == 0) {
			stream_window += 1.0;
		    }
		}
		
		Alarm(DEBUG, "%d:%d -> %d:%d :: Timeout; stream_window: %5.3f : %5.3f\n", 
		      cur_uhdr->source, cur_uhdr->source_port,
		      cur_uhdr->dest, cur_uhdr->dest_port, stream_window, r_data->window_size);
		
		if(stream_window == 0.0) {
		    stream_window = 1.0;
		    Alarm(DEBUG, "Congestion control: stream_window = 0\n");
		}
		
	    }
	    else {
		stream_window = r_data->window_size;
	    }
	    
	    r_data->tail++;

	    /* Congestion control */
            if (TCP_Fairness) {
                if(!stdcarr_empty(&(r_data->msg_buff))) {
                    /* there are other packets waiting, so it makes sense to increase the window */
                    old_window = r_data->window_size;
                    if(r_data->window_size < r_data->ssthresh) {
                        /* Slow start */
                        r_data->window_size += 1;
                        if(r_data->window_size > r_data->max_window) {
                            r_data->window_size = (float)r_data->max_window;
                        }
                    }
                    else {
                        /* Congestion avoidance */
                        r_data->window_size += 1/stream_window;
                        if(r_data->window_size > r_data->max_window) {
                            r_data->window_size = (float)r_data->max_window;
                        }
                    }
                }
            }
	}		    
	/* This was a fresh brand new ack. See if it freed some window slots
	 * and we can send some more stuff */	
	if(!stdcarr_empty(&(r_data->msg_buff))) {
	    E_queue(Try_to_Send, (int)linkid, NULL, zero_timeout);
	}
    }

    /* Reset the timeout slowly */
    /*r_data->timeout_multiply = 1;*/

    /* NILO : NEW CODE */
    r_data->timeout_multiply *= (float)(7.0/8.0);
    if (r_data->timeout_multiply < 1) {
        r_data->timeout_multiply = 1;
    }
    /* NILO : END NEW CODE */

    /* Cancel the previous timeout */
    if(r_data->scheduled_timeout == 1) {
        E_dequeue(Reliable_timeout, (int)linkid, NULL);
	r_data->scheduled_timeout = 0;
    }
    
    /*See if we need another timeout */
    if(r_data->head > r_data->tail) {
	/* Alarm(DEBUG, "+++ Another timeout ! tail: %d, head: %d\n",
	 *     r_data->tail, r_data->head);
	 */

	timeout_val.sec = (r_data->rtt*2)/1000000;
	timeout_val.usec = (r_data->rtt*2)%1000000;
	
	if(timeout_val.sec == 0 && timeout_val.usec < 2000) {
	    timeout_val.usec = 2000;
	}
	else if(timeout_val.sec == 0 && timeout_val.usec == 0) {
	    timeout_val.sec = 1;
	}
        if(Wireless && timeout_val.sec == 0 && timeout_val.usec < 30000) {
	    timeout_val.usec = 20000+5000*(rand()%10);
        }

	/* Alarm(DEBUG, "---timeout sec: %d; usec: %d\n",
	 *     timeout_val.sec, timeout_val.usec);
	 */

        /* NILO : NEW CODE */
        timeout_val.sec  *= r_data->timeout_multiply;
        timeout_val.usec *= r_data->timeout_multiply;
        timeout_val.sec += timeout_val.usec/1000000;
        timeout_val.usec = timeout_val.usec%1000000;

        if(timeout_val.sec > (DEAD_LINK_CNT-1))
            timeout_val.sec = (DEAD_LINK_CNT-1);
        /* NILO : END NEW CODE */

	E_queue(Reliable_timeout, (int)linkid, NULL, timeout_val);
	r_data->scheduled_timeout = 1;
    }

    if(Is_link_ack(type)) {  /* There is no data in this packet */
	/*
	 *	Alarm(DEBUG, "%d -- ACK: cm_ack: %d; seq: %d; tail: %d; recv_tail: %d; wind: %5.3f\n", 
	 *	      linkid, r_tail->cummulative_ack, r_tail->seq_no, r_data->tail, 
	 *	      r_data->recv_tail, r_data->window_size);
	 */
	return(-1);    
    }
    /* Now look at the receiving window */
    if((r_data->recv_window[r_tail->seq_no%MAX_WINDOW].flag == RECVD_CELL)||
       (r_tail->seq_no < r_data->recv_tail))  {
	/* We already got this message (and probably processed it also)
	 * That's it, we already processed this message, therefore return 0 */
	return(0);
    }
    
    if(r_tail->seq_no >= r_data->recv_head)
        r_data->recv_head = r_tail->seq_no + 1;

    /* Ok, this is fresh stuff. We should consider it. First, 
     * let's see if this packet filled some holes */
    r_data->recv_window[r_tail->seq_no%MAX_WINDOW].flag = RECVD_CELL;
    
    for(; r_data->recv_tail < r_data->recv_head; r_data->recv_tail++) {
	if(r_data->recv_window[r_data->recv_tail%MAX_WINDOW].flag != RECVD_CELL)
	    break;
	r_data->recv_window[r_data->recv_tail%MAX_WINDOW].flag = EMPTY_CELL;
    }
    /*
     *   Alarm(DEBUG, "%d -- PKT: cm_ack: %d; seq: %d; tail: %d; recv_tail: %d; wind: %5.3f\n", 
     *	  linkid, r_tail->cummulative_ack, r_tail->seq_no, r_data->tail, 
     *	  r_data->recv_tail, r_data->window_size);
     */

    return(1);
}

void Try_to_Send(int linkid, void* dummy) 
{
    Send_Much((int16)linkid);
}

/***********************************************************/
/* Processes an ACK packet                                 */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* sender:    IP of the sender                             */
/* scat:      sys_scatter cointaining the ACK              */
/* type:      type of the packet, cointaining endianess    */
/* mode:      mode of the link                             */
/***********************************************************/
                                                         
void Process_ack_packet(Link *lk, sys_scatter *scat, int32u type, int mode)
{
  packet_header *phdr;
  int16u         ack_len;
  char          *buff;
    
  if (scat->num_elements != 2) {
      Alarm(PRINT, "Proces_ack_packet: Dropping packet because "
          "scat->num_elements == %d instead of 2\r\n", scat->num_elements);
      return;
  }

  phdr     = (packet_header*) scat->elements[0].buf;
  ack_len  = phdr->ack_len;
  buff     = (char*) scat->elements[1].buf;

  if (lk->r_data == NULL) { 
    Alarm(EXIT, "Process_ack_packet: ack packet for non-reliable link?!\r\n");
  }

  if (lk->r_data->flags & CONNECTED_LINK) {
    Process_Ack(lk->link_id, buff, ack_len, type);
  }
}   
