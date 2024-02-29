/*
 * Spire.
 *
 * The contents of this file are subject to the Spire Open-Source
 * License, Version 1.0 (the ``License''); you may not use
 * this file except in compliance with the License.  You may obtain a
 * copy of the License at:
 *
 * http://www.dsn.jhu.edu/spire/LICENSE.txt 
 *
 * or in the file ``LICENSE.txt'' found in this distribution.
 *
 * Software distributed under the License is distributed on an AS IS basis, 
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License 
 * for the specific language governing rights and limitations under the 
 * License.
 *
 * Spire is developed at the Distributed Systems and Networks Lab,
 * Johns Hopkins University and the Resilient Systems and Societies Lab,
 * University of Pittsburgh.
 *
 * Creators:
 *   Yair Amir            yairamir@cs.jhu.edu
 *   Trevor Aron          taron1@cs.jhu.edu
 *   Amy Babay            babay@pitt.edu
 *   Thomas Tantillo      tantillo@cs.jhu.edu 
 *   Sahiti Bommareddy    sahiti@cs.jhu.edu 
 *   Maher Khan           maherkhan@pitt.edu
 *
 * Major Contributors:
 *   Marco Platania       Contributions to architecture design 
 *   Daniel Qian          Contributions to Trip Master and IDS 
 *
 * Contributors:
 *   Samuel Beckley       Contributions to HMIs
 *
 * Copyright (c) 2017-2024 Johns Hopkins University.
 * All rights reserved.
 *
 * Partial funding for Spire research was provided by the Defense Advanced 
 * Research Projects Agency (DARPA), the Department of Defense (DoD), and the
 * Department of Energy (DoE).
 * Spire is not necessarily endorsed by DARPA, the DoD or the DoE. 
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <signal.h>

#include "net_wrapper.h"
#include "spines_lib.h"

//Sahiti Notes:
//NUM_SM : 3f+2k+1 or N
//NUM_CC_REPLICA : replicas in cc
//NUM_CC : num of cc sites
//NUM_SITES : cc + dc

int Type;
int My_ID;
int My_Global_ID,PartOfConfig;
int32u My_Incarnation;
int32u My_Global_Configuration_Number;
int Prime_Client_ID;
int My_IP;
int32u My_curr_global_config_num;
int All_Sites[NUM_SM];
int CC_Replicas[NUM_CC_REPLICA];
int CC_Sites[NUM_CC_REPLICA];
char* Ext_Site_Addrs[NUM_CC]    = SPINES_EXT_SITE_ADDRS;
char* Int_Site_Addrs[NUM_SITES] = SPINES_INT_SITE_ADDRS;
sigset_t signal_mask;
int Curr_num_f = NUM_F;
int Curr_num_k = NUM_K;

char Curr_Ext_Site_Addrs[MAX_NUM_SERVER_SLOTS][32];
char Curr_Int_Site_Addrs[MAX_NUM_SERVER_SLOTS][32];
int Curr_All_Sites[MAX_NUM_SERVER_SLOTS];
int Curr_CC_Replicas[MAX_NUM_SERVER_SLOTS];
int Curr_CC_Sites[MAX_NUM_SERVER_SLOTS];
int Curr_num_SM =NUM_SM;
int Curr_num_CC_Replica = NUM_CC_REPLICA;
int Curr_num_CC= NUM_CC;
int Curr_num_sites=NUM_SITES;

/* local functions */
int max_rcv_buff(int sk);
int max_snd_buff(int sk);

/* Fills in CC_Replicas array with ids of control center replicas */
void Init_SM_Replicas()
{
    int id, site, cc_rep;

    cc_rep = 0;
    site = 0;
    for (id = 1; id <= NUM_SM; id++)
    {   
        All_Sites[id-1] = site;

        if (site < NUM_CC) {
            CC_Replicas[cc_rep] = id; 
            CC_Sites[cc_rep] = site;
            cc_rep++;
        } 
        site = (site + 1) % NUM_SITES;
    }  

    for(int i=0; i < MAX_NUM_SERVER_SLOTS;i++){
        memset(Curr_Ext_Site_Addrs[i],0,sizeof(Curr_Ext_Site_Addrs[i]));
        memset(Curr_Int_Site_Addrs[i],0,sizeof(Curr_Int_Site_Addrs[i]));
        Curr_CC_Replicas[i]=0;
        Curr_CC_Sites[i]=0;
        Curr_All_Sites[i]=0;
    }
    
    for (id = 1; id <= Curr_num_CC ;id++){
        sprintf(Curr_Ext_Site_Addrs[id-1],"%s",Ext_Site_Addrs[id-1]);
    }
    
    for(id = 1; id <= Curr_num_sites ; id++){
        sprintf(Curr_Int_Site_Addrs[id-1],"%s",Int_Site_Addrs[id-1]);
    }

    cc_rep = 0;
     site=0;
     for (id = 1; id <= Curr_num_SM; id++){
         Curr_All_Sites[id-1] = site;
        if (site < Curr_num_CC) {
            Curr_CC_Replicas[cc_rep] = id;
            Curr_CC_Sites[cc_rep] = site;
            cc_rep++;
        }
        site = (site + 1) % Curr_num_sites;
     }

}

void Reset_SM_def_vars(int32u N,int32u f, int32u k, int32u cc_replicas, int32u num_cc, int32 num_dc){
    if(N< (3*f+2*k+1))
            perror("OOB config message has N < 3f+2k+1\n");
    Curr_num_SM=N;
    Curr_num_CC_Replica=cc_replicas;
    Curr_num_CC=num_cc;
    Curr_num_sites= num_cc+num_dc;
    Curr_num_f=f;
    Curr_num_k=k;
    //printf("Reset defs successfully\n");

}

void Reset_SM_Replicas(int32u tpm_based_id[MAX_NUM_SERVER_SLOTS],int replica_flag[MAX_NUM_SERVER_SLOTS],char spines_ext_addresses[MAX_NUM_SERVER_SLOTS][32],char spines_int_addresses[MAX_NUM_SERVER_SLOTS][32]){
   int i,id; 
   for(i=0; i < MAX_NUM_SERVER_SLOTS;i++){
        memset(Curr_Ext_Site_Addrs[i],0,sizeof(Curr_Ext_Site_Addrs[i]));
        memset(Curr_Int_Site_Addrs[i],0,sizeof(Curr_Int_Site_Addrs[i]));
        Curr_CC_Replicas[i]=0;
        Curr_CC_Sites[i]=0;
        Curr_All_Sites[i]=0;
    }
    
    for(i=0;i<MAX_NUM_SERVER_SLOTS;i++){
        if(tpm_based_id[i]==0)
            continue;
        int l_id=tpm_based_id[i];
        int r_flag=replica_flag[i];
        if(r_flag==1){
            sprintf(Curr_Ext_Site_Addrs[l_id-1],"%s",spines_ext_addresses[i]);
        }
        sprintf(Curr_Int_Site_Addrs[l_id-1],"%s",spines_int_addresses[i]);
    }
    if(replica_flag[My_Global_ID-1]==1)
	Type=CC_TYPE;
    else
	Type=DC_TYPE;

    int cc_rep = 0;
    int  site=0;
     for (id = 1; id <= Curr_num_SM; id++){
         Curr_All_Sites[id-1] = site;
        if (site < Curr_num_CC) {
            Curr_CC_Replicas[cc_rep] = id;
            Curr_CC_Sites[cc_rep] = site;
            cc_rep++;
        }
        site = (site + 1) % Curr_num_sites;
     }
    /*
     for (i =0; i<MAX_NUM_SERVER_SLOTS;i++){
         printf("Reset SM Replica ext spines addr[%d]: %s\n",i+1, Curr_Ext_Site_Addrs[i]);
         printf("Reset SM Replica int spines addr[%d]: %s\n",i+1, Curr_Int_Site_Addrs[i]);
         printf("Reset SM Curr_CC_Replicas[%d]:%d\n",i,Curr_CC_Replicas[i]);
         printf("Reset SM Curr_CC_Sites[%d]:%d\n",i,Curr_CC_Sites[i]);
    }
    */
}

/* Returns 1 if given id is the id of a control center replica, 0 otherwise */
int Is_CC_Replica(int id) 
{
    int i;
    //TODO: Curr_num_CC_Replica
    //for (i = 0; i < NUM_CC_REPLICA; i++)
    for (i = 0; i < Curr_num_CC_Replica; i++)
    {   
        if (Curr_CC_Replicas[i] == id) 
            return 1;
    }   

    return 0;
}

/* Create the Server-Side socket for TCP connection */
int serverTCPsock(int port, int qlen) 
{
    int s;
    struct sockaddr_in conn;

    if (qlen == 0)
        qlen = LISTEN_QLEN;

    // Create socket
    s = socket(AF_INET, SOCK_STREAM, 0);
    if(s < 0) {
        perror("serverTCPsock: Couldn't create a socket");
        exit(EXIT_FAILURE);
    }

    memset(&conn, 0, sizeof(conn));
    conn.sin_family = AF_INET;
    conn.sin_port = htons(port);
    conn.sin_addr.s_addr = htonl(INADDR_ANY);

    max_snd_buff(s);
    max_rcv_buff(s);
    
    // Bind
    if(bind(s, (struct sockaddr *)&conn, sizeof(conn)) < 0) {
        perror("Bind failure");
        exit(EXIT_FAILURE);
    }

    // Listen
    if(listen(s, qlen) < 0) {
        perror("Listen error");
        exit(EXIT_FAILURE);
    }

    return s;
}

/* Create the Client-side socket for TCP connection */
int clientTCPsock(int port, int addr) 
{
    int s;
    struct sockaddr_in conn;
    struct in_addr print_addr;

    // Create socket
    s = socket(AF_INET, SOCK_STREAM, 0);
    if(s < 0) {
        perror("Couldn't create a socket");
        exit(EXIT_FAILURE);
    }

    memset(&conn, 0, sizeof(conn));
    conn.sin_family = AF_INET;
    conn.sin_port = htons(port);
    conn.sin_addr.s_addr = addr;

    max_snd_buff(s);
    max_rcv_buff(s);
    
    // Connect to the server
    if(connect(s, (struct sockaddr *)&conn, sizeof(conn)) < 0) {
        print_addr.s_addr = addr;
        printf("clientTCPsock: Connection error with %s\n", inet_ntoa(print_addr));
        return -1;
    }

    return s;
}

/* Read from the connection specified by socket s
   into dummy_buff for nBytes */
int NET_Read(int s, void *d_buf, int nBytes) 
{
    int ret = -1, nRead, nRemaining;
    char *buf;

    nRead = 0;
    nRemaining = nBytes;
    buf = (char *)d_buf;

    while(nRead < nBytes) {
        ret = read(s, &buf[nRead], nRemaining);

        if(ret < 0) {
            perror("NET_Read: read failure inside loop");
            return ret;
        }
      
        if(ret == 0)
            break;

        if(ret != nBytes)
            printf("Short read in loop: %d out of %d\n", ret, nBytes);

        nRead += ret;
        nRemaining -= ret;
    }

    if(nRead != nBytes)
        printf("Short read: %d %d\n", nRead, nBytes);

    return ret;
}

/* Write to the TCP connection specified by socket s
   into dummy_buff for nBytes */
int NET_Write(int s, void *d_buf, int nBytes) 
{
    int ret = -1, nWritten, nRemaining;
    char *buf;

    nWritten = 0;
    nRemaining = nBytes;
    buf = (char *)d_buf;

    while(nWritten < nBytes) {
        ret = write(s, &buf[nWritten], nRemaining);

        if(ret < 0) {
            perror("NET_Write: write failure in loop");
            return ret;
        }

        if(ret == 0)
            break;

        if(ret != nBytes)
            printf("Short write in loop: %d out of %d\n", ret, nBytes);

        nWritten += ret;
        nRemaining -= ret;
    }

    if(nWritten != nBytes)
        printf("Short write: %d %d\n", nWritten, nBytes);
    
    return ret;
}

/* Open a client-side IPC Stream Socket */
int IPC_Client_Sock(const char *path) 
{
    int s;
    struct sockaddr_un conn;

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) {
        perror("IPC_Client_Sock: Couldn't create a socket");
        exit(EXIT_FAILURE);
    }

    memset(&conn, 0, sizeof(struct sockaddr_un));
    conn.sun_family = AF_UNIX;
    strncpy(conn.sun_path, path, sizeof(conn.sun_path) - 1);
    
    max_snd_buff(s);
    max_rcv_buff(s);

    if((connect(s, (struct sockaddr *)&conn, sizeof(conn))) < 0) {
        perror("IPC_Client_Sock: connect");
        return -1;
    }

    return s;
}

/* Open an IPC Receiving and Sending Socket (Datagram) */
int IPC_DGram_Sock(const char *path) 
{
    int s;
    struct sockaddr_un conn;

    s = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (s < 0) {
        perror("IPCsock: Couldn't create a socket");
        exit(EXIT_FAILURE);
    }

    memset(&conn, 0, sizeof(struct sockaddr_un));
    conn.sun_family = AF_UNIX;
    strncpy(conn.sun_path, path, sizeof(conn.sun_path) - 1);

    max_snd_buff(s);
    max_rcv_buff(s);

    if (remove(conn.sun_path) == -1 && errno != ENOENT) {
        perror("IPCsock: error removing previous path binding");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr *)&conn, sizeof(struct sockaddr_un)) < 0) {
        perror("IPCsock: error binding to path");
        exit(EXIT_FAILURE);
    }
    chmod(conn.sun_path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

    return s;
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
int IPC_Send(int s, void *d_buf, int nBytes, const char *to) 
{
    int ret;
    struct sockaddr_un conn;

    memset(&conn, 0, sizeof(struct sockaddr_un));
    conn.sun_family = AF_UNIX;
    strncpy(conn.sun_path, to, sizeof(conn.sun_path) - 1);

    ret = sendto(s, d_buf, nBytes, 0,
                    (struct sockaddr *)&conn, sizeof(struct sockaddr_un));
    if (ret < 0) {
        perror("IPC_Send: error in sendto on socket");
    }

    return ret;
}

/* Connect to Spines at specified IP and port, with proto as semantics */
int Spines_Sock(const char *sp_addr, int sp_port, int proto, int my_port) 
{
    int sk, ret;
    struct sockaddr_in my_addr;
    
    sk = Spines_SendOnly_Sock(sp_addr, sp_port, proto);
    if (sk < 0) {
        perror("Spines_Sock: failure to connect to spines");
        return sk;
    }

    memset(&my_addr, 0, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_addr.s_addr = My_IP;
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

    printf("Initiating Spines connection: %s:%d\n", sp_addr, sp_port);
    spines_addr.sin_family = AF_INET;
    spines_addr.sin_port   = htons(sp_port);
    spines_addr.sin_addr.s_addr = inet_addr(sp_addr);

    spines_uaddr.sun_family = AF_UNIX;
    sprintf(spines_uaddr.sun_path, "%s%d", "/tmp/spines", sp_port);

    protocol = 8 | (proto << 8);

    /* printf("Creating IPC spines_socket\n");
    sk = spines_socket(PF_SPINES, SOCK_DGRAM, protocol, (struct sockaddr *)&spines_uaddr); */
   
    if ((int)inet_addr(sp_addr) == My_IP) {
        printf("Creating default spines_socket\n");
        sk = spines_socket(PF_SPINES, SOCK_DGRAM, protocol, (struct sockaddr *)&spines_uaddr);
    }
    else {
        printf("Creating inet spines_socket\n");
        sk = spines_socket(PF_SPINES, SOCK_DGRAM, protocol, 
                (struct sockaddr *)&spines_addr);
    }
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

    /* setup priority level and garbage collection settings for Priority Messaging */
    prio = SCADA_PRIORITY;
    if (sp_port == SPINES_INT_PORT) {
        exp.sec  = INT_EXPIRATION_SEC;
        exp.usec = INT_EXPIRATION_USEC;
    }
    else if (sp_port == SPINES_EXT_PORT || sp_port == SPINES_CTRL_PORT) {
        exp.sec  = EXT_EXPIRATION_SEC;
        exp.usec = EXT_EXPIRATION_USEC;
    }
    else {
        printf("Invalid spines port specified! (%u)\n", sp_port);
        exit(EXIT_FAILURE);
    }
    if (proto == SPINES_PRIORITY) {
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

    /* printf("Creating IPC spines_socket\n");
    sk = spines_socket(PF_SPINES, SOCK_DGRAM, protocol, (struct sockaddr *)&spines_uaddr); */
   
    if ((int)inet_addr(sp_addr) == My_IP) {
        printf("Creating default spines_socket\n");
        sk = spines_socket(PF_SPINES, SOCK_DGRAM, protocol, (struct sockaddr *)&spines_uaddr);
    }
    else {
        printf("Creating inet spines_socket\n");
        sk = spines_socket(PF_SPINES, SOCK_DGRAM, protocol, 
                (struct sockaddr *)&spines_addr);
    }
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

    /* setup priority level and garbage collection settings for Priority Messaging */
    prio = SCADA_PRIORITY;
    if (sp_port == SPINES_INT_PORT) {
        exp.sec  = INT_EXPIRATION_SEC;
        exp.usec = INT_EXPIRATION_USEC;
    }
    else if (sp_port == SPINES_EXT_PORT || sp_port == SPINES_CTRL_PORT) {
        exp.sec  = EXT_EXPIRATION_SEC;
        exp.usec = EXT_EXPIRATION_USEC;
    }
    else {
        printf("Invalid spines port specified! (%u)\n", sp_port);
        exit(EXIT_FAILURE);
    }
    if (proto == SPINES_PRIORITY) {
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



struct timeval diffTime(struct timeval t1, struct timeval t2)
{
    struct timeval diff;

    diff.tv_sec  = t1.tv_sec  - t2.tv_sec;
    diff.tv_usec = t1.tv_usec - t2.tv_usec;

    if (diff.tv_usec < 0) {
        diff.tv_usec += 1000000;
        diff.tv_sec--;
    }

    if (diff.tv_sec < 0)
        printf("diffTime: Negative time result!\n");

    return diff;
}

struct timeval addTime(struct timeval t1, struct timeval t2) 
{
    struct timeval sum;

    sum.tv_sec  = t1.tv_sec  + t2.tv_sec;
    sum.tv_usec = t1.tv_usec + t2.tv_usec;

    if (sum.tv_usec >= 1000000) {
        sum.tv_usec -= 1000000;
        sum.tv_sec++;
    }

    return sum;
}

int compTime(struct timeval t1, struct timeval t2)
{
    if      (t1.tv_sec  > t2.tv_sec) 
        return 1;
    else if (t1.tv_sec  < t2.tv_sec) 
        return -1;
    else if (t1.tv_usec > t2.tv_usec) 
        return 1;
    else if (t1.tv_usec < t2.tv_usec) 
        return -1;
    else 
        return 0;
}

int getIP()
{
    int my_ip;
    struct hostent *p_h_ent;
    char my_name[80];

    gethostname(my_name, 80);
    p_h_ent = gethostbyname(my_name);

    if (p_h_ent == NULL) {
        perror("getIP: gethostbyname error");
        exit(EXIT_FAILURE);
    }

    memcpy( &my_ip, p_h_ent->h_addr_list[0], sizeof(my_ip));
    return my_ip;
}

int max_rcv_buff(int sk) 
{
  /* Increasing the buffer on the socket */
  int i, val, ret;
  unsigned int lenval;

  for(i=10; i <= 3000; i+=5) {
    val = 1024*i;
    ret = setsockopt(sk, SOL_SOCKET, SO_RCVBUF, (void *)&val, sizeof(val));
    if (ret < 0)
      break;
    lenval = sizeof(val);
    ret= getsockopt(sk, SOL_SOCKET, SO_RCVBUF, (void *)&val, &lenval);
    if(val < i*1024 )
      break;
  }
  return(1024*(i-5));
}

int max_snd_buff(int sk) 
{
  /* Increasing the buffer on the socket */
  int i, val, ret;
  unsigned int lenval;

  for(i=10; i <= 3000; i+=5) {
    val = 1024*i;
    ret = setsockopt(sk, SOL_SOCKET, SO_SNDBUF, (void *)&val, sizeof(val));
    if (ret < 0)
      break;
    lenval = sizeof(val);
    ret = getsockopt(sk, SOL_SOCKET, SO_SNDBUF, (void *)&val,  &lenval);
    if(val < i*1024)
      break;
  }
  return(1024*(i-5));
}
