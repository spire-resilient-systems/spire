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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#ifndef SPU_ARCH_PC_WIN95
#  include <netdb.h>
#endif

#include "arch.h"
#include "spu_alarm.h"
#include "spu_addr.h"

#ifndef GAI_STRERROR
#  ifndef SPU_ARCH_PC_WIN95
#    define GAI_STRERROR(e) gai_strerror(e)
#  else
#    define GAI_STRERROR(e) sock_strerror(e)
#  endif
#endif

#ifndef EOVERFLOW
#  ifndef SPU_ARCH_PC_WIN95
#    define EOVERFLOW EINVAL
#  else
#    define EOVERFLOW WSA_INVALID_PARAMETER
#  endif
#endif

/********************************************************************************
 ********************************************************************************/

char Spu_addr_ntop_buf[SPU_ADDR_STRSIZE];

/********************************************************************************
 ********************************************************************************/

#if !defined(AF_UNSPEC) || AF_UNSPEC != 0
#  error AF_UNSPEC is not defined or is non-zero?!
#endif

static socklen_t spu_addr_len_low(const spu_addr *a)
{
  socklen_t ret = 0;  /* return a length of 0 on unrecognized family to indicate error */
  
  switch (a->addr.sa_family)
  {
  case AF_UNSPEC:
    ret = sizeof(*a);
    break;
    
  case AF_INET:
    ret = sizeof(a->ipv4);
    break;

  case AF_INET6:
    ret = sizeof(a->ipv6);
    break;

#ifndef ARCH_PC_WIN95
  case AF_UNIX:
    ret = sizeof(a->un);
    break;
#endif
  }

  return ret;
}

/********************************************************************************
 ********************************************************************************/

int spu_addr_from_sockaddr(spu_addr *a, const struct sockaddr *sa, socklen_t sa_len)
{
  if (sa_len > sizeof(*a))
  {
    errno = EINVAL; 
    return -1;
  }
  
  memmove(a, sa, sa_len);
  memset((char*) a + sa_len, 0, sizeof(*a) - sa_len);

  return 0;
}

/********************************************************************************
 * Simple wrapper around getaddrinfo that uses first returned address.
 ********************************************************************************/

int spu_addr_from_str(spu_addr *a, const char *str, int pfamily, int is_numeric)
{
  struct addrinfo  hint = { 0 };
  struct addrinfo *rslt = NULL;
  int              ret;

  hint.ai_family = pfamily;
  hint.ai_flags  = (is_numeric ? AI_NUMERICHOST : 0);

  if ((ret = getaddrinfo(str, NULL, &hint, &rslt)))
  {
    Alarmp(SPLOG_ERROR, DATA_LINK, "spu_addr_from_str: lookup on ('%s', %d, %d) failed: %d '%s'!\n", str, pfamily, is_numeric, ret, GAI_STRERROR(ret));
    goto FAIL;
  }

  if (rslt == NULL)
  {
    Alarmp(SPLOG_ERROR, DATA_LINK, "spu_addr_from_str: BUG?  Successful lookup on ('%s', %d, %d) returned no address!\n", str, pfamily, is_numeric);
    ret = EAI_FAIL;
    goto FAIL;
  }

  if (rslt->ai_addr == NULL)
  {
    Alarmp(SPLOG_ERROR, DATA_LINK, "spu_addr_from_str: BUG?  Successful lookup on ('%s', %d, %d) returned no address 2!\n", str, pfamily, is_numeric);
    ret = EAI_FAIL;
    goto FAIL_RSLT;
  }

  if (spu_addr_from_sockaddr(a, rslt->ai_addr, rslt->ai_addrlen))
  {
    Alarmp(SPLOG_ERROR, DATA_LINK, "spu_addr_from_str: BUG? spu_addr_from_sockaddr failed?!\n", str);
    ret = EAI_FAIL;
    goto FAIL_RSLT;
  }
  
FAIL_RSLT:
  freeaddrinfo(rslt);

FAIL:
  return ret;
}

/********************************************************************************
 ********************************************************************************/

int spu_addr_family(const spu_addr *a)
{
  return a->addr.sa_family;
}

/********************************************************************************
 ********************************************************************************/

int spu_addr_ntop_r(const spu_addr *a, char *str, size_t n)
{
  socklen_t len = spu_addr_len_low(a);
  int       ret = getnameinfo(&a->addr, (len ? len : sizeof(*a)), str, n, NULL, 0, NI_NUMERICHOST);

  if (ret)
    Alarmp(SPLOG_ERROR, DATA_LINK, "spu_addr_ntop_r: getnameinfo failed %d '%s'\n", ret, GAI_STRERROR(ret));
  
  return ret;
}

/********************************************************************************
 ********************************************************************************/

int spu_addr_ntop_canon_r(const spu_addr *a, char *str, size_t n)
{
  int ret;

  if (a->addr.sa_family == AF_INET)
  {
    ret = snprintf(str, n, "%u.%u.%u.%u",
                   ((unsigned char*) &a->ipv4.sin_addr.s_addr)[0],
                   ((unsigned char*) &a->ipv4.sin_addr.s_addr)[1],
                   ((unsigned char*) &a->ipv4.sin_addr.s_addr)[2],
                   ((unsigned char*) &a->ipv4.sin_addr.s_addr)[3]);

    if (ret >= 0)
      ret = ((size_t) ret < n ? 0 : EOVERFLOW);
  }
  else if (a->addr.sa_family == AF_INET6)
  {
    ret = snprintf(str, n, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                   a->ipv6.sin6_addr.s6_addr[0],  a->ipv6.sin6_addr.s6_addr[1],  a->ipv6.sin6_addr.s6_addr[2],  a->ipv6.sin6_addr.s6_addr[3],
                   a->ipv6.sin6_addr.s6_addr[4],  a->ipv6.sin6_addr.s6_addr[5],  a->ipv6.sin6_addr.s6_addr[6],  a->ipv6.sin6_addr.s6_addr[7],
                   a->ipv6.sin6_addr.s6_addr[8],  a->ipv6.sin6_addr.s6_addr[9],  a->ipv6.sin6_addr.s6_addr[10], a->ipv6.sin6_addr.s6_addr[11],
                   a->ipv6.sin6_addr.s6_addr[12], a->ipv6.sin6_addr.s6_addr[13], a->ipv6.sin6_addr.s6_addr[14], a->ipv6.sin6_addr.s6_addr[15]);

    if (ret >= 0) 
      ret = ((size_t) ret < n ? 0 : EOVERFLOW);
  }
  else
    ret = spu_addr_ntop_r(a, str, n);
  
  return ret;
}

/********************************************************************************
 ********************************************************************************/

int spu_addr_from_sockaddr_known(spu_addr *a, const struct sockaddr *sa)
{
  int    ret  = 0;
  size_t zero = 0;
  
  switch (sa->sa_family)
  {
  case AF_UNSPEC:
    zero = sizeof(*a);
    break;
    
  case AF_INET:
    a->ipv4 = *(struct sockaddr_in*) sa;
    zero    = sizeof(*a) - sizeof(a->ipv4);
    break;

  case AF_INET6:
    a->ipv6 = *(struct sockaddr_in6*) sa;
    zero    = sizeof(*a) - sizeof(a->ipv6);
    break;

#ifndef ARCH_PC_WIN95
  case AF_UNIX:
    a->un = *(struct sockaddr_un*) sa;
    zero  = sizeof(*a) - sizeof(a->un);
    break;
#endif
    
  default:
    Alarmp(SPLOG_FATAL, NONE, "spu_addr_from_sockaddr_known: unexpected address family: %d\n", sa->sa_family);
    break;
  }

  memset((char*) (a + 1) - zero, 0, zero);

  return ret;
}

/********************************************************************************
 ********************************************************************************/

socklen_t spu_addr_len(const spu_addr *a)
{
  socklen_t ret = spu_addr_len_low(a);

  if (!ret)
    Alarmp(SPLOG_FATAL, NONE, "spu_addr_len: unrecognized address family: %d\n", a->addr.sa_family);

  return ret;
}

/********************************************************************************
 ********************************************************************************/

const char *spu_addr_family_str(const spu_addr *a)
{
  return spu_af_str(a->addr.sa_family);
}

/********************************************************************************
 ********************************************************************************/

const char *spu_af_str(int family)
{
  const char *ret = NULL;
  
  switch (family)
  {
  case AF_UNSPEC:
    ret = "AF_UNSPEC";
    break;
    
  case AF_INET:
    ret = "AF_INET";
    break;

  case AF_INET6:
    ret = "AF_INET6";
    break;

#ifndef ARCH_PC_WIN95
  case AF_UNIX:
    ret = "AF_UNIX";
    break;
#endif
    
  default:
    Alarmp(SPLOG_FATAL, NONE, "spu_af_str: unexpected address family: %d\n", family);
    break;
  }

  return ret;
}

/********************************************************************************
 ********************************************************************************/

int spu_addr_ip_cmp(const spu_addr *l, const spu_addr *r, int include_port)
{
  int ret;

  if ((l->addr.sa_family != AF_INET && l->addr.sa_family != AF_INET6) ||
      (r->addr.sa_family != AF_INET && r->addr.sa_family != AF_INET6))
    Alarmp(SPLOG_FATAL, NONE, "spu_addr_ip_cmp: unrecognized address families %d %d; AF_INET = %d, AF_INET6 = %d\n",
           l->addr.sa_family, r->addr.sa_family, AF_INET, AF_INET6);

  if (l->addr.sa_family == r->addr.sa_family)
  {
    switch(l->addr.sa_family)
    {
    case AF_INET:
      if ((ret = memcmp(&l->ipv4.sin_addr.s_addr, &r->ipv4.sin_addr.s_addr, 4)) == 0 && include_port)
      {
        if (ntohs(l->ipv4.sin_port) < ntohs(r->ipv4.sin_port))
          ret = -1;

        else if (l->ipv4.sin_port != r->ipv4.sin_port)
          ret = 1;
      }      
      break;

    case AF_INET6:
      if ((ret = memcmp(l->ipv6.sin6_addr.s6_addr, r->ipv6.sin6_addr.s6_addr, 16)) == 0 && include_port)
      {
        if (ntohs(l->ipv6.sin6_port) < ntohs(r->ipv6.sin6_port))
          ret = -1;

        else if (l->ipv6.sin6_port != r->ipv6.sin6_port)
          ret = 1;
      }
      break;
    }
  }
  else if (l->addr.sa_family == AF_INET)
    ret = -1;

  else
    ret = 1;

  return ret;
}

/********************************************************************************
 ********************************************************************************/

int spu_addr_ip_is_unspecified(const spu_addr *a)
{
  int ret = 0;
  
  switch (a->addr.sa_family)
  {
  case AF_INET:
    ret = (a->ipv4.sin_addr.s_addr == INADDR_ANY);
    break;

  case AF_INET6:
    ret = IN6_IS_ADDR_UNSPECIFIED(&a->ipv6.sin6_addr);
    break;

  default:
    Alarmp(SPLOG_FATAL, NONE, "spu_addr_ip_is_unspecified: unexpected address family: %d\n", a->addr.sa_family);    
    break;
  }

  return ret;
}

/********************************************************************************
 ********************************************************************************/

int spu_addr_ip_is_loopback(const spu_addr *a)
{
  int ret = 0;
  
  switch (a->addr.sa_family)
  {
  case AF_INET:
    ret = (((char*) &a->ipv4.sin_addr.s_addr)[0] == 127);
    break;

  case AF_INET6:
    ret = IN6_IS_ADDR_LOOPBACK(&a->ipv6.sin6_addr);
    break;

  default:
    Alarmp(SPLOG_FATAL, NONE, "spu_addr_ip_is_loopback: unexpected address family: %d\n", a->addr.sa_family);    
    break;
  }

  return ret;
}

/********************************************************************************
 ********************************************************************************/

int spu_addr_ip_is_multicast(const spu_addr *a)
{
  int            ret  = 0;
  unsigned char *ipv4 = (unsigned char*) &a->ipv4.sin_addr.s_addr;
  
  switch (a->addr.sa_family)
  {
  case AF_INET:
    ret = ((ipv4[0] & 0xF0) == 224);  /* 224.0.0.0/4 */
    break;

  case AF_INET6:
    ret = IN6_IS_ADDR_MULTICAST(&a->ipv6.sin6_addr);
    break;

  default:
    Alarmp(SPLOG_FATAL, NONE, "spu_addr_ip_is_multicast: unexpected address family: %d\n", a->addr.sa_family);    
    break;
  }

  return ret;
}

/********************************************************************************
 ********************************************************************************/

int spu_addr_ip_is_linklocal(const spu_addr *a)
{
  int            ret  = 0;
  unsigned char *ipv4 = (unsigned char*) &a->ipv4.sin_addr.s_addr;
  
  switch (a->addr.sa_family)
  {
  case AF_INET:
    ret = (ipv4[0] == 169 && ipv4[1] == 254);  /* 169.254.0.0/16 */
    break;

  case AF_INET6:
    ret = IN6_IS_ADDR_LINKLOCAL(&a->ipv6.sin6_addr);
    break;

  default:
    Alarmp(SPLOG_FATAL, NONE, "spu_addr_ip_is_linklocal: unexpected address family: %d\n", a->addr.sa_family);    
    break;
  }

  return ret;
}

/********************************************************************************
 ********************************************************************************/

int spu_addr_ip_is_sitelocal(const spu_addr *a)
{
  int            ret  = 0;
  unsigned char *ipv4 = (unsigned char*) &a->ipv4.sin_addr.s_addr;
  
  switch (a->addr.sa_family)
  {
  case AF_INET:
    ret = (ipv4[0] == 10 ||                                 /* 10.0.0.0/24 */
           (ipv4[0] == 172 && ((ipv4[1] & 0xF0) == 16)) ||  /* 172.16.0.0/20 */
           (ipv4[0] == 192 && ipv4[1] == 168));             /* 192.168.0.0/16 */
    break;

  case AF_INET6:
    ret = IN6_IS_ADDR_SITELOCAL(&a->ipv6.sin6_addr);
    break;

  default:
    Alarmp(SPLOG_FATAL, NONE, "spu_addr_ip_is_sitelocal: unexpected address family: %d\n", a->addr.sa_family);    
    break;
  }

  return ret;
}

/********************************************************************************
 ********************************************************************************/

void spu_addr_ip_set_unspecified(spu_addr *a)
{
  switch (a->addr.sa_family)
  {
  case AF_INET:
    a->ipv4.sin_addr.s_addr = htonl(INADDR_ANY);
    break;
    
  case AF_INET6:
    a->ipv6.sin6_addr = in6addr_any;
    break;

  default:
    Alarmp(SPLOG_FATAL, NONE, "spu_addr_ip_inaddrany: unexpected address family: %d\n", a->addr.sa_family);
    break;
  }
}

/********************************************************************************
 ********************************************************************************/

int16u spu_addr_ip_get_port(const spu_addr *a)
{
  int16u ret = 0;
  
  switch (a->addr.sa_family)
  {
  case AF_INET:
    ret = ntohs(a->ipv4.sin_port);
    break;

  case AF_INET6:
    ret = ntohs(a->ipv6.sin6_port);
    break;

  default:
    Alarmp(SPLOG_FATAL, NONE, "spu_addr_ip_get_port: unexpected address family: %d\n", a->addr.sa_family);
    break;
  }

  return ret;
}

/********************************************************************************
 ********************************************************************************/

void spu_addr_ip_set_port(spu_addr *a, int16u port)
{
  switch (a->addr.sa_family)
  {
  case AF_INET:
    a->ipv4.sin_port = htons(port);
    break;

  case AF_INET6:
    a->ipv6.sin6_port = htons(port);
    break;

  default:
    Alarmp(SPLOG_FATAL, NONE, "spu_addr_ip_set_port: unexpected address family: %d\n", a->addr.sa_family);
    break;
  }
}

/********************************************************************************
 ********************************************************************************/
