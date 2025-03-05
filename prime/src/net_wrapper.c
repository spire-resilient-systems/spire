/*
 * Prime.
 *     
 * The contents of this file are subject to the Prime Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.dsn.jhu.edu/prime/LICENSE.txt
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis, 
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
 * for the specific language governing rights and limitations under the 
 * License.
 *
 * Creators:
 *   Yair Amir            yairamir@cs.jhu.edu
 *   Jonathan Kirsch      jak@cs.jhu.edu
 *   John Lane            johnlane@cs.jhu.edu
 *   Marco Platania       platania@cs.jhu.edu
 *   Amy Babay            babay@pitt.edu
 *   Thomas Tantillo      tantillo@cs.jhu.edu 
 *
 *
 * Major Contributors:
 *   Brian Coan           Design of the Prime algorithm
 *   Jeff Seibert         View Change protocol 
 *   Sahiti Bommareddy    Reconfiguration 
 *   Maher Khan           Reconfiguration 
 *      
 * Copyright (c) 2008-2025
 * The Johns Hopkins University.
 * All rights reserved.
 * 
 * Partial funding for Prime research was provided by the Defense Advanced 
 * Research Projects Agency (DARPA) and the National Science Foundation (NSF).
 * Prime is not necessarily endorsed by DARPA or the NSF.  
 *
 */

#include <stdlib.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "net_wrapper.h"
#include "network.h"
#include "spu_alarm.h"
#include "spines_lib.h"

int NET_Read(int sd, void *dummy_buf, int32u nBytes)
{
  int ret, nRead, nRemaining;
  byte *buf;

  nRemaining = nBytes;
  nRead      = 0;

  buf = (byte *)dummy_buf;

  while(1) {

    ret = read(sd, &buf[nRead], nRemaining);

    if(ret < 0) {
      perror("read");
      Alarm(PRINT, "read returned < 0\n");
      fflush(stdout);
      //exit(0);
      break;
    }
      
    if(ret == 0) {
      Alarm(DEBUG, "read returned 0...\n");
      break;
    }

    if(ret != nBytes)
      Alarm(DEBUG, "Short read in loop: %d out of %d\n", ret, nBytes);

    nRead      += ret;
    nRemaining -= ret;

    if(nRead == nBytes)
      break;
  }

  if(nRead != nBytes) {
    Alarm(DEBUG, "Short read: %d %d\n", nRead, nBytes);
  }

  return ret;
}

int NET_Write(int sd, void *dummy_buf, int32u nBytes)
{
  int ret, nWritten, nRemaining;
  byte *buf;
  
  buf        = (byte *)dummy_buf;
  nWritten   = 0;
  nRemaining = nBytes;

  while(1) {
    ret = write(sd, &buf[nWritten], nRemaining);
  
    if(ret < 0) {
      perror("write");
      fflush(stdout);
      //exit(0);
      break;
    }

    if(ret == 0) {
      Alarm(DEBUG, "Write returned 0...\n");
      break;
    }

    if(ret != nBytes)
      Alarm(DEBUG, "Short write in loop: %d out of %d\n", ret, nBytes);

    nWritten   += ret;
    nRemaining -= ret;
    
    if(nWritten == nBytes)
      break;
  }

  if(nWritten != nBytes) {
    Alarm(DEBUG, "Short write: %d %d\n", nWritten, nBytes);
  }
  return ret;
}

/* Receive message on an IPC socket */
int IPC_Recv(int s, void *d_buf, int nBytes)
{
    int ret;
    struct sockaddr_un from;
    socklen_t from_len;

    from_len = sizeof(struct sockaddr_un);
    ret = recvfrom(s, d_buf, nBytes, 0, (struct sockaddr *)&from, &from_len);
    if (ret < 0) {
        perror("IPC_Recv: error in recvfrom on socket");
    }

    return ret;
}

/* Send message on an IPC socket */
int IPC_Send(int s, void *d_buf, int nBytes, char *dst)
{
    int ret;
    struct sockaddr_un conn;

    memset(&conn, 0, sizeof(struct sockaddr_un));
    conn.sun_family = AF_UNIX;
    sprintf(conn.sun_path, "%s", dst);

    ret = sendto(s, d_buf, nBytes, 0,
                    (struct sockaddr *)&conn, sizeof(struct sockaddr_un));
    if (ret < 0) {
        //perror("IPC_Send: error in sendto on socket");
    }

    return ret;
}

/* Connect to Spines at specified IP and port, with proto as semantics */
int Spines_Mcast_SendOnly_Sock(const char *sp_addr, int sp_port, int proto)
{
    int sk, ret, protocol;
    struct sockaddr_in spines_addr;
    struct sockaddr_un spines_uaddr;
    int16u prio, kpaths;
    spines_nettime exp;

    memset(&spines_addr, 0, sizeof(spines_addr));

    printf("Initiating Spines connection: %s:%d\n", sp_addr, sp_port);
    spines_addr.sin_family = AF_INET;
    spines_addr.sin_port   = htons(sp_port);
    spines_addr.sin_addr.s_addr = inet_addr(sp_addr);

    spines_uaddr.sun_family = AF_UNIX;
    sprintf(spines_uaddr.sun_path, "%s%d", "/tmp/spines", sp_port);

    protocol = 8 | (proto << 8);

     printf("Creating IPC spines_socket\n");
     //sk = spines_socket(PF_SPINES, SOCK_DGRAM, protocol, (struct sockaddr *)&spines_uaddr); 
     sk = spines_socket(PF_SPINES, SOCK_DGRAM, protocol, (struct sockaddr *)&spines_addr);
  /*
    if ((int)inet_addr(sp_addr) == My_IP) {
        printf("Creating default spines_socket\n");
        sk = spines_socket(PF_SPINES, SOCK_DGRAM, protocol, (struct sockaddr *)&spines_uaddr);
    }
    else {
        printf("Creating inet spines_socket\n");
        sk = spines_socket(PF_SPINES, SOCK_DGRAM, protocol,
                (struct sockaddr *)&spines_addr);
    }
    */
    if (sk < 0) {
        perror("Spines_Sock: error creating spines socket!");
        return sk;
    }

    /* setup kpaths = 1 */
    kpaths = 0;
    if ((ret = spines_setsockopt(sk, 0, SPINES_DISJOINT_PATHS, (void *)&kpaths, sizeof(int16u))) < 0) {
        printf("Spines_Sock: spines_setsockopt failed for disjoint paths = %u\n", kpaths);
        return ret;
    }
	exp.sec  = SPINES_EXP_TIME_SEC;
        exp.usec = SPINES_EXP_TIME_USEC;
    
        if ((ret = spines_setsockopt(sk, 0, SPINES_SET_EXPIRATION, (void *)&exp, sizeof(spines_nettime))) < 0) {
            printf("Spines_Sock: error setting expiration time to %u sec %u usec\n", exp.sec, exp.usec);
            return ret;
        }

        if ((ret = spines_setsockopt(sk, 0, SPINES_SET_PRIORITY, (void *)&prio, sizeof(int16u))) < 0) {
            printf("Spines_Sock: error setting priority to %u\n", prio);
            return ret;
        }

    return sk;
}

/* Open an IPC Sending Only Socket (Datagram) */
int IPC_DGram_SendOnly_Sock()
{
    int s;

    s = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("IPCsock: Couldn't create a socket");
        exit(EXIT_FAILURE);
    }

    max_snd_buff(s);
    max_rcv_buff(s);

    return s;
}

/* Connect to Spines at specified IP and port, with proto as semantics */
int Spines_Sock(const char *sp_addr, int sp_port, int proto, int my_port)
{
    int sk, ret;
    struct sockaddr_in my_addr;

    Alarm(DEBUG,"Initiating Spines connection: %s:%d\n", sp_addr, sp_port);
    sk = Spines_SendOnly_Sock(sp_addr, sp_port, proto);
    if (sk < 0) {
        perror("Spines_Sock: failure to connect to spines");
        return sk;
    }

    memset(&my_addr, 0, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    //my_addr.sin_addr.s_addr = NET.My_Address;
    my_addr.sin_addr.s_addr = (int)inet_addr(sp_addr) ;
    my_addr.sin_port = htons(my_port);

    ret = spines_bind(sk, (struct sockaddr *)&my_addr, sizeof(struct sockaddr_in));
    if (ret < 0) {
        perror("Spines_Sock: bind error!");
        return ret;
    }

    return sk;
}

/* Connect to Spines at specified IP and port, with proto as semantics */
int Spines_SendOnly_Sock(const char *sp_addr, int sp_port, int proto)
{
    int sk, ret, protocol;
    struct sockaddr_in spines_addr;
    struct sockaddr_un spines_uaddr;
    int16u prio, kpaths;
    spines_nettime exp;

    memset(&spines_addr, 0, sizeof(spines_addr));

    Alarm(DEBUG,"Initiating Spines connection: %s:%d\n", sp_addr, sp_port);
    fflush(stdout);
    spines_addr.sin_family = AF_INET;
    spines_addr.sin_port   = htons(sp_port);
    spines_addr.sin_addr.s_addr = inet_addr(sp_addr);

    spines_uaddr.sun_family = AF_UNIX;
    sprintf(spines_uaddr.sun_path, "%s%d", "/tmp/spines", sp_port);

    protocol = 8 | (proto << 8);

    Alarm(DEBUG,"Creating default spines_socket\n");
    sk = spines_socket(PF_SPINES, SOCK_DGRAM, protocol, (struct sockaddr *)&spines_uaddr);
       if (sk < 0) {
        perror("Spines_Sock: error creating spines socket!");
        return sk;
    }
    /* setup kpaths = 1 */
    kpaths = 1;
    if ((ret = spines_setsockopt(sk, 0, SPINES_DISJOINT_PATHS, (void *)&kpaths, sizeof(int16u))) < 0) {
        printf("Spines_Sock: spines_setsockopt failed for disjoint paths = %u\n", kpaths);
        return ret;
    }

    if (proto == SPINES_PRIORITY) {
        exp.sec  = SPINES_EXP_TIME_SEC;
        exp.usec = SPINES_EXP_TIME_USEC;
        if ((ret = spines_setsockopt(sk, 0, SPINES_SET_EXPIRATION, (void *)&exp, sizeof(spines_nettime))) < 0) {
            printf("Spines_Sock: error setting expiration time to %u sec %u usec\n", exp.sec, exp.usec);
            return ret;
        }

        if ((ret = spines_setsockopt(sk, 0, SPINES_SET_PRIORITY, (void *)&prio, sizeof(int16u))) < 0) {
            printf("Spines_Sock: error setting priority to %u\n", prio);
            return ret;
        }
    }

    return sk;
}
