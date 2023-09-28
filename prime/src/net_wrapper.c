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
 *      
 * Copyright (c) 2008-2023
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
#include "net_wrapper.h"
#include "spu_alarm.h"

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

