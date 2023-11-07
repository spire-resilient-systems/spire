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

#ifndef INC_SPU_ADDR_H
#define INC_SPU_ADDR_H

#include "spu_system.h"

#include <stddef.h>

#ifdef SPU_ARCH_PC_WIN95
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <sys/un.h>
#  include <netinet/in.h>
#endif

#define SPU_ADDR_STRSIZE    256
#define SPU_ADDR_IP_STRSIZE 46

/* NOTE: these macros return the same global buffer, so you typically can't call this fcn multiple times in a single statement (e.g. - in a fcn parameter list) */

#define SPU_ADDR_NTOP(a)       (spu_addr_ntop_r((a),       Spu_addr_ntop_buf, SPU_ADDR_STRSIZE) ? "address conversion failed" : Spu_addr_ntop_buf)
#define SPU_ADDR_NTOP_CANON(a) (spu_addr_ntop_canon_r((a), Spu_addr_ntop_buf, SPU_ADDR_STRSIZE) ? "address conversion failed" : Spu_addr_ntop_buf)

extern char Spu_addr_ntop_buf[SPU_ADDR_STRSIZE];

typedef union
{
  int                     dmy_init;  /* NOTE: Only use this for static initialization! It *DOES NOT* map to sa_family, sin_family, etc.! */
  struct sockaddr         addr;
  struct sockaddr_in      ipv4;
  struct sockaddr_in6     ipv6;
  struct sockaddr_storage storage;

#ifndef SPU_ARCH_PC_WIN95
  struct sockaddr_un      un;
#endif

} spu_addr;

int       spu_addr_from_sockaddr(spu_addr *a, const struct sockaddr *sa, socklen_t sa_len);
int       spu_addr_from_str(spu_addr *a, const char *str, int pfamily, int is_numeric);

int       spu_addr_family(const spu_addr *a);

int       spu_addr_ntop_r(const spu_addr *a, char *str, size_t n);
int       spu_addr_ntop_canon_r(const spu_addr *a, char *str, size_t n);

/* NOTE: the following functions are only valid for families: AF_UNSPEC (0), AF_INET, AF_INET6 and AF_UNIX; will exit on other types */

int         spu_addr_from_sockaddr_known(spu_addr *a, const struct sockaddr *sa);
socklen_t   spu_addr_len(const spu_addr *a);
const char *spu_addr_family_str(const spu_addr *a);

const char *spu_af_str(int afamily);

/* NOTE: the following functions are only valid for AF_INET and AF_INET6; will exit on other types */

int       spu_addr_ip_cmp(const spu_addr *l, const spu_addr *r, int include_port);   /* NOTE: only compares address + optionally port */
int       spu_addr_ip_is_unspecified(const spu_addr *a);
int       spu_addr_ip_is_loopback(const spu_addr *a);
int       spu_addr_ip_is_multicast(const spu_addr *a);
int       spu_addr_ip_is_linklocal(const spu_addr *a);
int       spu_addr_ip_is_sitelocal(const spu_addr *a);

void      spu_addr_ip_set_unspecified(spu_addr *a);        /* sets address to be unspecified (e.g. - INADDR_ANY); no other fields (e.g. - port) are affected */

int16u    spu_addr_ip_get_port(const spu_addr *a);         /* NOTE: host byte order */
void      spu_addr_ip_set_port(spu_addr *a, int16u port);  /* NOTE: host byte order */

#endif
