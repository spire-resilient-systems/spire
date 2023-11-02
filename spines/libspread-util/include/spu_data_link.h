/*
 * The Spread Toolkit.
 *     
 * The contents of this file are subject to the Spread Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.spread.org/license/
 *
 * or in the file ``license.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis, 
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
 * for the specific language governing rights and limitations under the 
 * License.
 *
 * The Creators of Spread are:
 *  Yair Amir, Michal Miskin-Amir, Jonathan Stanton, John Schultz.
 *
 *  Copyright (C) 1993-2016 Spread Concepts LLC <info@spreadconcepts.com>
 *
 *  All Rights Reserved.
 *
 * Major Contributor(s):
 * ---------------
 *    Amy Babay            babay@cs.jhu.edu - accelerated ring protocol.
 *    Ryan Caudy           rcaudy@gmail.com - contributions to process groups.
 *    Claudiu Danilov      claudiu@acm.org - scalable wide area support.
 *    Cristina Nita-Rotaru crisn@cs.purdue.edu - group communication security.
 *    Theo Schlossnagle    jesus@omniti.com - Perl, autoconf, old skiplist.
 *    Dan Schoenblum       dansch@cnds.jhu.edu - Java interface.
 *
 */


#ifndef INC_DATA_LINK
#define INC_DATA_LINK

#include "spu_system.h"
#include "spu_scatter.h"
#include "spu_addr.h"

#define		MAX_PACKET_SIZE		1472    /* 1472 = 1536 - 64 (of typical udp/ip/eth headers) */

#define		SEND_CHANNEL	0x00000001
#define		RECV_CHANNEL    0x00000002
#define         NO_LOOP         0x00000004
#define         REUSE_ADDR      0x00000008
#define         DL_BIND_ALL     0x00000010

#define         IS_MCAST_ADDR(addr32)     ( ( (addr32) & 0xF0000000 ) == 0xE0000000 )    /* host byte order */
#define         IS_MCAST_ADDR_NET(addr32) ( ( (unsigned char*) &(addr32) )[0] == 0xE0 )  /* network byte order */

#ifndef channel
#  define         channel                 int
#endif

void    DL_close_channel(channel chan);

channel	DL_init_channel( int32 channel_type, int16 port, int32 mcast_address, int32 interface_address );
int	DL_send( channel chan, int32 address, int16 port, const sys_scatter *scat );
int	DL_recv( channel chan, sys_scatter *scat );
int	DL_recvfrom( channel chan, sys_scatter *scat, int *src_address, unsigned short *src_port );

channel DL_init_channel_gen(int32 channel_type, const spu_addr *mcast_address, const spu_addr *interface_address);
int     DL_join_multicast_gen(channel chan, const spu_addr *mcast_addr, const spu_addr *if_addr);
int     DL_send_gen(channel chan, const sys_scatter *scat);
int     DL_recv_gen(channel chan, sys_scatter *scat);
int     DL_sendto_gen(channel chan, const sys_scatter *scat, const spu_addr *dst);
int     DL_recvfrom_gen(channel chan, sys_scatter *scat, spu_addr *src);

#endif
