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
 *  Copyright (C) 1993-2024 Spread Concepts LLC <info@spreadconcepts.com>
 *
 *  All Rights Reserved.
 *
 * Major Contributor(s):
 * ---------------
 *    Amy Babay            babay@pitt.edu - accelerated ring protocol.
 *    Ryan Caudy           rcaudy@gmail.com - contributions to process groups.
 *    Claudiu Danilov      claudiu@acm.org - scalable wide area support.
 *    Cristina Nita-Rotaru crisn@cs.purdue.edu - group communication security.
 *    Theo Schlossnagle    jesus@omniti.com - Perl, autoconf, old skiplist.
 *    Dan Schoenblum       dansch@cnds.jhu.edu - Java interface.
 *
 */

#include "arch.h"

#include <stdlib.h>
#include <stdio.h>

#ifdef ARCH_PC_WIN95
#  include <winsock2.h>
#endif

#ifndef HAVE_STRERROR
/* return value only valid until next call to strerror */

char    *strerror(int err)
{
        char *msg;
static  char buf[32];
        
        sprintf(buf, "Error %d", err);
        msg = buf;

        return(msg);
}

#endif

#ifdef ARCH_PC_WIN95

char *sock_strerror(int err)
{
  const char *ret = "Unknown WSA error!";
  
  switch (err)
  {
  case WSANOTINITIALISED:     ret = "WSANOTINITIALISED: A successful WSAStartup() must occur before using this function.";
  case WSAENETDOWN:           ret = "WSAENETDOWN: The network subsystem has failed.";
  case WSAEACCES:             ret = "WSAEACCES: The requested address is a broadcast address. Call setsockopt with the SO_BROADCAST parameter to allow the use of the broadcast address.";
  case WSAEINTR:              ret = "WSAEINTR: A blocking Windows Sockets call was canceled through WSACancelBlockingCall.";
  case WSAEINPROGRESS:        ret = "WSAEINPROGRESS: A blocking Windows Sockets call is in progress, or the service provider is still processing a callback function.";
  case WSAEFAULT:             ret = "WSAEFAULT: The buf parameter is not completely contained in a valid part of the user address space." ;
  case WSAENETRESET:          ret = "WSAENETRESET: The connection has been broken due to the keep-alive activity detecting a failure while the operation was in progress.";
  case WSAENOBUFS:            ret = "WSAENOBUFS: No buffer space is available.";
  case WSAENOTCONN:           ret = "WSAENOTCONN: The socket is not connected.";
  case WSAENOTSOCK:           ret = "WSAENOTSOCK: The descriptor is not a socket.";
  case WSAEOPNOTSUPP:         ret = "WSAEOPNOTSUPP: Operation not supported.";
  case WSAESHUTDOWN:          ret = "WSAESHUTDOWN The socket has been shut down; it is not possible to send on a socket after shutdown has been invoked with how set to SD_SEND or SD_BOTH.";
  case WSAEWOULDBLOCK:        ret = "WSAEWOULDBLOCK: The socket is marked as nonblocking and the requested operation would block.";
  case WSAEMSGSIZE:           ret = "WSAEMSGSIZE: The socket is message oriented, and the message is larger than the maximum supported by the underlying transport.";
  case WSAEHOSTUNREACH:       ret = "WSAEHOSTUNREACH: The remote host cannot be reached from this host at this time.";
  case WSAEINVAL:             ret = "WSAEINVAL: The socket has not been bound with bind, or an unknown flag was specified, or MSG_OOB was specified for a socket with SO_OOBINLINE enabled.";
  case WSAECONNABORTED:       ret = "WSAECONNABORTED: The virtual circuit was terminated due to a time-out or other failure. The application should close the socket as it is no longer usable.";
  case WSAETIMEDOUT:          ret = "WSAETIMEDOUT: The connection has been dropped, because of a network failure or because the system on the other end went down without notice.";	
  case WSASYSCALLFAILURE:     ret = "WSASYSCALLFAILURE: A system call unexpectedly failed.";
  case WSA_NOT_ENOUGH_MEMORY: ret = "WSA_NOT_ENOUGH_MEMORY: Out of memory.";
  case WSAECONNRESET:         ret = ("WSAECONNRESET: The connection was reset by the remote side executing a hard or abortive close. "
                                      "For a UDP socket, the remote host responded with a Port Unreachable ICMP packet.");
  }

  return (char*) ret;
}

#endif
