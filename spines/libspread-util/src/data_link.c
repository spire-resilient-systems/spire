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
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "arch.h"  /* NOTE: must come after #include <errno.h> on Windows bc we redef error defines */

#ifndef ARCH_PC_WIN95
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <sys/uio.h>
#  include <sys/time.h>
#  include <unistd.h>
#else
#  include <winsock2.h>
#endif

#include "spu_data_link.h"
#include "spu_alarm.h"
#include "spu_events.h"

/********************************************************************************
 ********************************************************************************/

void DL_close_channel(channel chan)
{
  int ret = close(chan);  /* NOTE: on windows, arch.h defines close to be closesocket (ick!) /*/
  
  if (ret)
    Alarmp(SPLOG_FATAL, DATA_LINK, "DL_close_channel: error closing channel %d: %d %d %s\n", (int) chan, ret, sock_errno, sock_strerror(sock_errno));
}

/********************************************************************************
 ********************************************************************************/

channel DL_init_channel(int32 channel_type, int16 port, int32 mcast_address, int32 interface_address)
{
  spu_addr mcast = { 0 };
  spu_addr inter = { 0 };

  mcast.ipv4.sin_family      = AF_INET;
  mcast.ipv4.sin_port        = htons(port);
  mcast.ipv4.sin_addr.s_addr = htonl(mcast_address);
  
  inter.ipv4.sin_family      = AF_INET;
  inter.ipv4.sin_port        = htons(port);
  inter.ipv4.sin_addr.s_addr = htonl(interface_address);
  
  return DL_init_channel_gen(channel_type, &mcast, &inter);
}

/********************************************************************************
 ********************************************************************************/

int DL_send(channel chan, int32 address, int16 port, const sys_scatter *scat)
{
  spu_addr dst = { 0 };

  dst.ipv4.sin_family      = AF_INET;
  dst.ipv4.sin_port        = htons(port);
  dst.ipv4.sin_addr.s_addr = htonl(address);

  return DL_sendto_gen(chan, scat, &dst);
}

/********************************************************************************
 ********************************************************************************/

int DL_recv(channel chan, sys_scatter *scat)
{
  return DL_recvfrom_gen(chan, scat, NULL);
}

/********************************************************************************
 ********************************************************************************/

int DL_recvfrom(channel chan, sys_scatter *scat, int *src_address, unsigned short *src_port)
{
  spu_addr src = { 0 };
  int      ret = DL_recvfrom_gen(chan, scat, &src);

  if (ret >= 0)
  {
    if (src_address)
    {
      if (src.addr.sa_family == AF_INET)
        *src_address = (int) ntohl(src.ipv4.sin_addr.s_addr);
    
      else
        *src_address = 0;
    }
    
    if (src_port)
    {
      if (src.addr.sa_family == AF_INET || src.addr.sa_family == AF_INET6)
        *src_port = (unsigned short) spu_addr_ip_get_port(&src);
      
      else
        *src_port = 0;
    }    
  }
  
  return ret;
}

/********************************************************************************
 * Creates a broad/multicast IP datagram socket with options.  Exits on failures.
 *
 *     create a SOCK_DGRAM socket in protocol family of if_addr
 *
 *     if SEND_CHANNEL is set:
 *         if if_addr is IPv4: enable SO_BROADCAST
 *         set multicast hops = 1
 *         if NO_LOOP is set: disable multicast loopback
 *
 *     if RECV_CHANNEL is set:
 *         if if_addr is IPv4: enable SO_BROADCAST
 *         if REUSE_ADDR is set: enable SO_REUSEADDR
 *
 *         if mcast_addr is a multicast address and DL_BIND_ALL not set:
 *             bind to mcast_addr
 *         else:
 *             bind to if_addr
 *
 *         if mcast_addr is a multicast address:
 *             call DL_join_multicast(socket, mcast_addr, if_addr)
 *
 *    return socket
 *
 * TODO: check on sizeof setsockopt types across platforms (i.e. - Sun: char vs. int)
 ********************************************************************************/

channel DL_init_channel_gen(int32 channel_type, const spu_addr *mcast_addr, const spu_addr *if_addr)
{
  int     family = spu_addr_family(if_addr);
  channel chan;
  int     tmp_int;
  unsigned char tmp_uchar;

  Alarmp(SPLOG_INFO, DATA_LINK, "DL_init_channel_gen: creating a SOCK_DGRAM socket of family %d\n", family);

  if (family != AF_INET && family != AF_INET6)
    Alarmp(SPLOG_FATAL, DATA_LINK, "DL_init_channel_gen: bad family(%d); only AF_INET (%d) and AF_INET6 (%d) are currently supported!\n", family, AF_INET, AF_INET6);

  if (mcast_addr != NULL)
  {
    if (family != spu_addr_family(mcast_addr))
      Alarmp(SPLOG_FATAL, DATA_LINK, "DL_init_channel_gen: mcast family (%d) didn't match interface family (%d)!\n", spu_addr_family(mcast_addr), family);
          
    if (spu_addr_ip_get_port(if_addr) != spu_addr_ip_get_port(mcast_addr))
      Alarmp(SPLOG_FATAL, DATA_LINK, "DL_init_channel_gen: mcast port (%u) didn't match interface port (%u)!\n",
             (unsigned) spu_addr_ip_get_port(mcast_addr), (unsigned) spu_addr_ip_get_port(if_addr));
  }

  if ((chan = socket((family == AF_INET ? PF_INET : PF_INET6), SOCK_DGRAM, 0)) == INVALID_SOCKET)
    Alarmp(SPLOG_FATAL, DATA_LINK, "DL_init_channel_gen: socket error (%d: %s)!\n", sock_errno, sock_strerror(sock_errno));

  if (channel_type & SEND_CHANNEL)
  {
    if (family == AF_INET)
    {
      Alarmp(SPLOG_INFO, DATA_LINK, "DL_init_channel_gen: turning SO_BROADCAST on for send IPv4 channel\n");
      
      if (setsockopt(chan, SOL_SOCKET, SO_BROADCAST, (tmp_int = 1, &tmp_int), sizeof(tmp_int)))
        Alarmp(SPLOG_FATAL, DATA_LINK, "DL_init_channel_gen: setsockopt(SOL_SOCKET, SO_BROADCAST, 1) error (%d: %s)!\n", sock_errno, sock_strerror(sock_errno));
      
      Alarmp(SPLOG_INFO, DATA_LINK, "DL_init_channel_gen: setting IPv4 multicast TTL to 1 for send channel\n");
                  
      if (setsockopt(chan, IPPROTO_IP, IP_MULTICAST_TTL, (tmp_uchar = 1, &tmp_uchar), sizeof(tmp_uchar))) 
        Alarmp(SPLOG_FATAL, DATA_LINK, "DL_init_channel_gen: problem (%d: %s) in setsockopt of multicast ttl = 1; ignore on Windows\n", 
               sock_errno, sock_strerror(sock_errno));

      if (channel_type & NO_LOOP)
      {
        Alarmp(SPLOG_INFO, DATA_LINK, "DL_init_channel_gen: Disabling IPv4 multicast loopback\n");
                    
        if (setsockopt(chan, IPPROTO_IP, IP_MULTICAST_LOOP, (tmp_uchar = 0, &tmp_uchar), sizeof(tmp_uchar)))
          Alarmp(SPLOG_FATAL, DATA_LINK, "DL_init_channel_gen: error (%d: %s) in disabling ipv4 loopback!\n", sock_errno, sock_strerror(sock_errno));
      }                  
    }
    else
    {
      Alarmp(SPLOG_INFO, DATA_LINK, "DL_init_channel_gen: setting IPv6 mulitcast hops to 1 for send channel\n");
                  
      if (setsockopt(chan, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (tmp_int = 1, &tmp_int), sizeof(tmp_int))) 
        Alarmp(SPLOG_FATAL, DATA_LINK, "DL_init_channel_gen: problem (%d: %s) in setsockopt of multicast hops = 1; ignore on Windows\n", 
               sock_errno, sock_strerror(sock_errno));

      if (channel_type & NO_LOOP)
      {
        Alarmp(SPLOG_INFO, DATA_LINK, "DL_init_channel_gen: Disabling IPv6 multicast loopback\n");

#ifdef __sun        
        if (setsockopt(chan, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (tmp_uchar = 0, &tmp_uchar), sizeof(tmp_uchar)))
#else
        if (setsockopt(chan, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (tmp_int = 0, &tmp_int), sizeof(tmp_int)))
#endif            
          Alarmp(SPLOG_FATAL, DATA_LINK, "DL_init_channel_gen: error (%d: %s) in disabling ipv6 loopback!\n", sock_errno, sock_strerror(sock_errno));
      }
    }
  }

  if (channel_type & RECV_CHANNEL)
  {
    spu_addr bind_addr = *if_addr;

    if (family == AF_INET)
    {
      Alarmp(SPLOG_INFO, DATA_LINK, "DL_init_channel_gen: turning SO_BROADCAST on for recv IPv4 channel\n");
      
      if (setsockopt(chan, SOL_SOCKET, SO_BROADCAST, (tmp_int = 1, &tmp_int), sizeof(tmp_int)))
        Alarmp(SPLOG_FATAL, DATA_LINK, "DL_init_channel_gen: setsockopt(SOL_SOCKET, SO_BROADCAST, 1) error (%d: %s)!\n", sock_errno, sock_strerror(sock_errno));
    }
      
    if (!(channel_type & DL_BIND_ALL) && mcast_addr != NULL && spu_addr_ip_is_multicast(mcast_addr))
      bind_addr = *mcast_addr;

    if (channel_type & REUSE_ADDR)
    {
      Alarmp(SPLOG_INFO, DATA_LINK, "DL_init_channel_gen: turning SO_REUSEADDR on for recv channel\n");
                
      if (setsockopt(chan, SOL_SOCKET, SO_REUSEADDR, (tmp_int = 1, &tmp_int), sizeof(tmp_int)))
        Alarmp(SPLOG_FATAL, DATA_LINK, "DL_init_channel_gen: Failed to set socket option REUSEADDR, errno: (%d: %s)!\n", sock_errno, sock_strerror(sock_errno));
    }

    Alarmp(SPLOG_INFO, DATA_LINK, "DL_init_channel_gen: binding recv channel to [%s]:%u\n", SPU_ADDR_NTOP(&bind_addr), (unsigned) spu_addr_ip_get_port(&bind_addr));

    if (bind(chan, (struct sockaddr *) &bind_addr, spu_addr_len(&bind_addr))) 
      Alarmp(SPLOG_FATAL, DATA_LINK, "DL_init_channel_gen: bind error (%d: %s) for [%s]:%u; probably already running!\n",
             sock_errno, sock_strerror(sock_errno), SPU_ADDR_NTOP(&bind_addr), (unsigned) spu_addr_ip_get_port(&bind_addr));

    if (mcast_addr != NULL && spu_addr_ip_is_multicast(mcast_addr) && (tmp_int = DL_join_multicast_gen(chan, mcast_addr, if_addr)))
      Alarmp(SPLOG_FATAL, DATA_LINK, "DL_init_channel_gen: DL_join_multicast failed! %d %d %s\n", tmp_int, sock_errno, sock_strerror(sock_errno));
  }

  Alarmp(SPLOG_INFO, DATA_LINK, "DL_init_channel_gen: success; chan = %d\n", (int) chan);
        
  return chan;
}

/********************************************************************************
 * Joins the group mcast_addr on a socket.  Returns zero on success, non-zero on failure.
 *
 *     if mcast_addr is IPv4:
 *         if if_addr != NULL: join mcast_addr on interface if_addr 
 *         else: join mcast_addr on interface INADDR_ANY
 *
 *     else:
 *         if mcast_addr's scope_id is non-zero: join mcast_addr on mcast_addr's scope_id
 *         elif if_addr != NULL: join mcast_addr on if_addr's scope_id
 *         else: join mcast_addr on scope_id 0 (most likely fails)
 *   
 ********************************************************************************/

int DL_join_multicast_gen(channel chan, const spu_addr *mcast_addr, const spu_addr *if_addr)
{
  int ret = -1;
  int family;

  if (mcast_addr == NULL)
  {
    Alarmp(SPLOG_ERROR, DATA_LINK, "DL_join_multicast_gen: called with NULL mcast_addr?!\n");
    sock_set_errno(EINVAL);
    goto END;
  }
  
  family = spu_addr_family(mcast_addr);

  if (family != AF_INET && family != AF_INET6)
  {
    Alarmp(SPLOG_ERROR, DATA_LINK, "DL_join_multicast_gen: called with non-IP mcast_addr?!\n");
    sock_set_errno(EINVAL);
    goto END;
  }
  
  if (family == AF_INET)
  {
    struct ip_mreq mreq;

    memset(&mreq, 0, sizeof(mreq));                        
    mreq.imr_multiaddr = mcast_addr->ipv4.sin_addr;

    if (if_addr != NULL && !spu_addr_ip_is_multicast(if_addr))
      mreq.imr_interface = if_addr->ipv4.sin_addr;
                        
    Alarmp(SPLOG_INFO, DATA_LINK, "DL_join_multicast_gen: Joining ipv4 multicast address " IPF " on interface " IPF "\n",
           IP_NET(mreq.imr_multiaddr.s_addr), IP_NET(mreq.imr_interface.s_addr));
                        
    if (setsockopt(chan, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)))
    {
      Alarmp(SPLOG_ERROR, DATA_LINK, "DL_join_multicast_gen: error (%d: %s) on ipv4 join!\n", sock_errno, sock_strerror(sock_errno));
      goto END;
    }
  }
  else
  {
    struct ipv6_mreq mreq;

    memset(&mreq, 0, sizeof(mreq));
    mreq.ipv6mr_multiaddr = mcast_addr->ipv6.sin6_addr;
    mreq.ipv6mr_interface = mcast_addr->ipv6.sin6_scope_id;

    if (mreq.ipv6mr_interface == 0 && if_addr != NULL)
      mreq.ipv6mr_interface = if_addr->ipv6.sin6_scope_id;
                        
    Alarmp(SPLOG_INFO, DATA_LINK, "DL_join_multicast_gen: Joining ipv6 multicast address %s on interface %u\n", SPU_ADDR_NTOP(mcast_addr), (unsigned) mreq.ipv6mr_interface);
                  
    if (setsockopt(chan, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)))
    {
      Alarmp(SPLOG_ERROR, DATA_LINK, "DL_join_multicast_gen: error (%d: %s) on ipv6 join!\n", sock_errno, sock_strerror(sock_errno));
      goto END;
    }
  }

  ret = 0;

END:
  Alarmp(SPLOG_INFO, DATA_LINK, "DL_join_multicast_gen: ret = %d\n", ret);
  
  return ret;
}

/********************************************************************************
 ********************************************************************************/

int DL_send_gen(channel chan, const sys_scatter *scat)
{
  return DL_sendto_gen(chan, scat, NULL);
}

/********************************************************************************
 ********************************************************************************/

int DL_recv_gen(channel chan, sys_scatter *scat)
{
  return DL_recvfrom_gen(chan, scat, NULL);
}

/********************************************************************************
 ********************************************************************************/

int DL_sendto_gen(channel chan, const sys_scatter *scat, const spu_addr *dst)
{
        int                 ret     = -1;
        socklen_t           dst_len = (dst != NULL ? spu_addr_len(dst) : 0);
        size_t              tot_len = 0;
        size_t              new_len;
        size_t              i;
#ifdef ARCH_SCATTER_NONE
        char                sendto_buf[1500];         /* big enough for any fast ethernet packet */
        char               *sendto_ptr = sendto_buf;
#else
        struct  msghdr      msg = { 0 };

        msg.msg_name    = (caddr_t) dst;
        msg.msg_namelen = dst_len;
        msg.msg_iov     = (struct iovec*) scat->elements;
        msg.msg_iovlen  = (int) scat->num_elements;
#endif
        if (scat->num_elements > ARCH_SCATTER_SIZE)
        {          
          Alarmp(SPLOG_ERROR, DATA_LINK, "DL_sendto_gen: illegal scat->num_elements (%lu) > ARCH_SCATTER_SIZE (%lu)\n", 
                 (unsigned long) scat->num_elements, (unsigned long) ARCH_SCATTER_SIZE);
          sock_set_errno(EINVAL);
          goto END;
        }
#ifdef ARCH_SCATTER_NONE        
        else if (scat->num_elements == 1)
        {
          sendto_ptr = scat->elements[0].buf;    /* NOTE: avoid unnecessary memcpy */
          tot_len    = scat->elements[0].len;
        }
#endif
        else
        {
          for (i = 0, tot_len = 0; i < scat->num_elements; ++i, tot_len = new_len)
          {
            new_len = tot_len + scat->elements[i].len;

            if (new_len < tot_len)  /* rollover */
            {
              Alarmp(SPLOG_ERROR, DATA_LINK, "DL_sendto_gen: scat so big it caused rollover (%lu + %lu -> %lu) > max allowed (%lu)\n", 
                     (unsigned long) tot_len, (unsigned long) scat->elements[i].len, (unsigned long) new_len, (unsigned long) (size_t) -1);
              sock_set_errno(EINVAL);
              goto END;
            }
          }
          
#ifdef ARCH_SCATTER_NONE
            
          if (tot_len > sizeof(sendto_buf) && NULL == (sendto_ptr = (char*) malloc(tot_len)))
          {
            Alarmp(SPLOG_ERROR, DATA_LINK, "DL_sendto_gen: malloc(%lu) failed\n", (unsigned long) tot_len);
            sock_set_errno(ENOMEM);
            goto END;
          }

          for (i = 0, new_len = 0; i < scat->num_elements && new_len < tot_len; new_len += scat->elements[i++].len)
            memcpy(&sendto_ptr[new_len], scat->elements[i].buf, scat->elements[i].len);
#endif
        }

#ifdef ARCH_SCATTER_NONE
        ret = sendto(chan, sendto_ptr, tot_len, 0, (struct sockaddr *) dst, dst_len);
#else
        ret = sendmsg(chan, &msg, 0); 
#endif

        if (ret < 0)                       /* rare */
        {
          Alarmp(SPLOG_ERROR, DATA_LINK, "DL_sendto_gen: error: %d %d '%s' sending on channel %d\n", ret, sock_errno, sock_strerror(sock_errno), (int) chan);
          goto END;
        }
        else if ((size_t) ret < tot_len)   /* can commonly occur on TCP channels; shouldn't happen on UDP */
        {
          if (ALARMP_NEEDED(SPLOG_INFO, DATA_LINK))
            Alarmp(SPLOG_INFO, DATA_LINK, "DL_sendto_gen: partial send: %d out of %lu bytes sent on channel %d\n", ret, (unsigned long) tot_len, (int) chan);  
        }
        else if ((size_t) ret != tot_len)  /* shouldn't happen */
        {
          Alarmp(SPLOG_ERROR, DATA_LINK, "DL_sendto_gen: sent more bytes (%d) than requested (%lu) on channel %d?!\n", ret, (unsigned long) tot_len, (int) chan);  
          sock_set_errno(EIO);
          ret = -1;
          goto END;
        }
        /* else: ret == tot_len: success! */

END:
        
#ifdef ARCH_SCATTER_NONE
        if (sendto_ptr != sendto_buf && sendto_ptr != NULL && scat->num_elements != 1)
          free(sendto_ptr);
#endif

        /* NOTE: it is uncommon for (SPLOG_DEBUG, DATA_LINK) to be active; so conditionally skip needless calls to Alarmp */
        
        if (ALARMP_NEEDED(SPLOG_DEBUG, DATA_LINK))
        {
          char alarm_msg[256], *c = alarm_msg, *e = alarm_msg + sizeof(alarm_msg);

          c += snprintf(c, SPCLAMP(c, e), "DL_sendto_gen: ret = %d, tried to send a message of %lu bytes on channel %d", ret, (unsigned long) tot_len, (int) chan);

          if (dst != NULL)
          {
            c += snprintf(c, SPCLAMP(c, e), "; dst family: %d; dst addr: '%s'", dst->addr.sa_family, SPU_ADDR_NTOP(dst));

            if (dst->addr.sa_family == AF_INET || dst->addr.sa_family == AF_INET6)
              c += snprintf(c, SPCLAMP(c, e), "; dst port: %u", (unsigned) spu_addr_ip_get_port(dst));
          }

          if (c < e)
            *(c++) = '\n';

          if (c < e)
            *(c++) = '\0';

          alarm_msg[sizeof(alarm_msg) - 1] = '\0';
          
          Alarmp(SPLOG_DEBUG, DATA_LINK, "%s", alarm_msg);
        }
                 
        return ret;
}

/********************************************************************************
 ********************************************************************************/

int DL_recvfrom_gen(channel chan, sys_scatter *scat, spu_addr *src)
{
        int             ret     = -1;
        socklen_t       src_len = (src != NULL ? sizeof(*src) : 0);
        size_t          tot_len = 0;
        size_t          new_len;
        size_t          i;
#ifdef ARCH_SCATTER_NONE
        char            recvfrom_buf[1500];           /* big enough for any fast ethernet packet */
        char           *recvfrom_ptr = recvfrom_buf;
        size_t          start;
#else
        struct  msghdr  msg = { 0 };

        msg.msg_name    = (caddr_t) src;
        msg.msg_namelen = src_len;
        msg.msg_iov     = (struct iovec *) scat->elements;
        msg.msg_iovlen  = (int) scat->num_elements;
#endif
        if (scat->num_elements > ARCH_SCATTER_SIZE)
        {
          Alarmp(SPLOG_ERROR, DATA_LINK, "DL_recvfrom_gen: illegal scat->num_elements (%lu) > ARCH_SCATTER_SIZE (%lu)\n", 
                 (unsigned long) scat->num_elements, (unsigned long) ARCH_SCATTER_SIZE);
          
          sock_set_errno(EINVAL);
          goto END;
        }
#ifdef ARCH_SCATTER_NONE
        else if (scat->num_elements == 1)
        {
          recvfrom_ptr = scat->elements[0].buf;   /* NOTE: avoid unnecessary memcpy */
          tot_len      = scat->elements[0].len;
        }
#endif        
        else
        {
          for (i = 0, tot_len = 0; i < scat->num_elements; ++i, tot_len = new_len)
          {
            new_len = tot_len + scat->elements[i].len;

            if (new_len < tot_len)  /* rollover */
            {
              Alarmp(SPLOG_ERROR, DATA_LINK, "DL_recvfrom_gen: scat so big it caused rollover (%lu + %lu -> %lu) > max allowed (%lu)\n", 
                     (unsigned long) tot_len, (unsigned long) scat->elements[i].len, (unsigned long) new_len, (unsigned long) -1);
              sock_set_errno(EINVAL);
              goto END;
            }
          }
          
#ifdef ARCH_SCATTER_NONE
            
          if (tot_len > sizeof(recvfrom_buf) && NULL == (recvfrom_ptr = (char*) malloc(tot_len)))
          {
            Alarmp(SPLOG_ERROR, DATA_LINK, "DL_recvfrom_gen: malloc(%lu) failed\n", (unsigned long) tot_len);
            sock_set_errno(ENOMEM);
            goto END;
          }          
#endif            
        }

#ifdef ARCH_SCATTER_NONE        
        ret     = recvfrom(chan, recvfrom_ptr, tot_len, 0, (struct sockaddr *) src, &src_len);
#else
        ret     = recvmsg(chan, &msg, 0); 
        src_len = msg.msg_namelen;
#endif

        if (ret < 0)                      /* rare */
        {
          Alarmp(SPLOG_ERROR, DATA_LINK, "DL_recvfrom_gen: error: %d %d '%s' receiving on channel %d\n", ret, sock_errno, sock_strerror(sock_errno), (int) chan);
          goto END;
        } 
        else if ((size_t) ret > tot_len)  /* shouldn't happen */
        {
          Alarmp(SPLOG_ERROR, DATA_LINK, "DL_recvfrom_gen: received more bytes (%d) than requested (%lu) on channel %d?!\n", ret, (unsigned long) tot_len, (int) chan);
          sock_set_errno(EIO);
          ret = -1;
          goto END;
        }

#ifdef ARCH_SCATTER_NONE

        if (scat->num_elements != 1)
        {
          size_t next_start;

          for (i = 0, start = 0, new_len = (size_t) ret; i < scat->num_elements && (next_start = start + scat->elements[i].len) < new_len; ++i, start = next_start)
            memcpy(scat->elements[i].buf, &recvfrom_ptr[start], scat->elements[i].len);

          if (i < scat->num_elements)
            memcpy(scat->elements[i].buf, &recvfrom_ptr[start], new_len - start);
        }
#endif

END:
        
#ifdef ARCH_SCATTER_NONE
        if (recvfrom_ptr != recvfrom_buf && recvfrom_ptr != NULL && scat->num_elements != 1)
          free(recvfrom_ptr);
#endif
        
        /* NOTE: it is uncommon for (SPLOG_DEBUG, DATA_LINK) to be active; conditionally skip needless calls to Alarmp */
        
        if (ALARMP_NEEDED(SPLOG_DEBUG, DATA_LINK))
        {
          char alarm_msg[256], *c = alarm_msg, *e = alarm_msg + sizeof(alarm_msg);

          c += snprintf(c, SPCLAMP(c, e), "DL_recvfrom_gen: ret = %d; tried to recv up to %lu bytes on channel %d", ret, (unsigned long) tot_len, (int) chan);
          
          if (ret >= 0 && src != NULL && src_len > 0)
          {
            c += snprintf(c, SPCLAMP(c, e), "; src family: %d; src addr: '%s'", src->addr.sa_family, SPU_ADDR_NTOP(src));

            if (src->addr.sa_family == AF_INET || src->addr.sa_family == AF_INET6)
              c += snprintf(c, SPCLAMP(c, e), "; src port: %u", (unsigned) spu_addr_ip_get_port(src));
          }

          if (c < e)
            *(c++) = '\n';

          if (c < e)
            *(c++) = '\0';

          alarm_msg[sizeof(alarm_msg) - 1] = '\0';
          
          Alarmp(SPLOG_DEBUG, DATA_LINK, "%s", alarm_msg);
        }

        return ret;
}

/********************************************************************************
 ********************************************************************************/
