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

#include "arch.h"

#ifndef	ARCH_PC_WIN95
#  include <sys/socket.h>
#  include <sys/ioctl.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <string.h>
#  include <sys/types.h>
#  include <sys/stat.h>
#  include <fcntl.h>
#  include <unistd.h>
#else
#  include <winsock2.h>
#endif

#ifdef ARCH_SPARC_SOLARIS
#  include <unistd.h>
#  include <stropts.h>
#endif

#ifndef _WIN32_WCE
#  include <errno.h>
#endif

#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>

#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_memory.h"
#include "spu_data_link.h"
#include "stdutil/stdhash.h"
#include "stdutil/stdcarr.h"

#include "objects.h"
#include "net_types.h"
#include "node.h"
#include "link.h"
#include "network.h"
#include "reliable_datagram.h"
#include "link_state.h"
#include "hello.h"
#include "udp.h"
#include "reliable_udp.h"
#include "realtime_udp.h"
#include "intrusion_tol_udp.h"
#include "priority_flood.h"
#include "reliable_flood.h"
#include "protocol.h"
#include "route.h"
#include "session.h"
#include "reliable_session.h"
#include "state_flood.h"
#include "multicast.h"
#include "multipath.h"
#include "configuration.h"

/* Global variables */
extern int16u    Port;
extern Node_ID   My_Address;
extern stdhash   Sessions_ID;
extern stdhash   Sessions_Port;
extern stdhash   Rel_Sessions_Port;
extern stdhash   Sessions_Sock;
extern int16     Link_Sessions_Blocked_On;
extern stdhash   All_Groups_by_Node;
extern stdhash   All_Groups_by_Name;
extern stdhash   All_Nodes;
extern stdhash   Monitor_Params;
extern int       Accept_Monitor;
extern int       Unicast_Only;
extern channel   Ses_UDP_Channel; /* For udp client connection sends
                                     and receives */ 
extern char      Config_File_Found;
extern stdhash   Node_Lookup_Addr_to_ID;
extern int16u    My_ID;
extern int64u    Injected_Messages;

/* Local variables */
static int32u   Session_Num;
static const sp_time zero_timeout  = {     0,    0};
static int last_sess_port;
static sys_scatter Ses_UDP_Pack;
static char *frag_buf[55];
static channel ctrl_sk_requests[MAX_CTRL_SK_REQUESTS];
static int overwrite_ip;

#define FRAG_TTL         30

static int Get_Ses_Mode(int32 ses_links_used)
{
  int ret = -1;

  switch (ses_links_used) {

  case UDP_LINKS:
    ret = UDP_LINK;
    break;

  case RELIABLE_LINKS:
    ret = RELIABLE_UDP_LINK;
    break;

  case SOFT_REALTIME_LINKS:
    ret = REALTIME_UDP_LINK;
    break;

  case INTRUSION_TOL_LINKS:
    ret = INTRUSION_TOL_LINK;
    break;

  default:
    break;
  }

  return ret;
}

Frag_Packet* Delete_Frag_Element(Frag_Packet **head, Frag_Packet *frag_pkt)
{
    int i;
    Frag_Packet *frag_tmp;
    
    if(frag_pkt == NULL) {
        return NULL;
    }
    if(head == NULL) {
        return NULL;
    }


    for(i=0; i<frag_pkt->scat.num_elements; i++) {
        if(frag_pkt->scat.elements[i].buf != NULL) {
            dec_ref_cnt(frag_pkt->scat.elements[i].buf);
        }
    }
    if(frag_pkt->prev == NULL) {
        *head = frag_pkt->next;
    }
    else {
        frag_pkt->prev->next = frag_pkt->next;
    }
    if(frag_pkt->next != NULL) {
        frag_pkt->next->prev = frag_pkt->prev;
    }
    
    frag_tmp = frag_pkt->next;
    dispose(frag_pkt);
    return(frag_tmp);
}

/***********************************************************/
/* void Init_Session(void)                                 */
/*                                                         */
/* Initializes the session layer                           */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Init_Session(void)
{
    int sk_local;
    int i, ret, val;
    size_t s_len;
    struct sockaddr_in name;
#ifndef ARCH_PC_WIN95
    struct sockaddr_un unix_name;
#endif

    Session_Num = 0;
    last_sess_port = 40000;
    overwrite_ip = 0;

    for(i=0; i<50; i++) {
        frag_buf[i] = new_ref_cnt(PACK_BODY_OBJ);
        if(frag_buf[i] == NULL) {
            Alarm(EXIT, "Init_Session: Cannot allocate memory\n");
        }
    }

    stdhash_construct(&Sessions_ID, sizeof(int32), sizeof(Session*),
                      NULL, NULL, 0);

    stdhash_construct(&Sessions_Port, sizeof(int32), sizeof(Session*),
                      NULL, NULL, 0);

    stdhash_construct(&Rel_Sessions_Port, sizeof(int32), sizeof(Session*),
                      NULL, NULL, 0);

    stdhash_construct(&Sessions_Sock, sizeof(int32), sizeof(Session*),
                      NULL, NULL, 0);

#ifndef ARCH_PC_WIN95
    /* Open Socket for IPC Stream Control */
    sk_local = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sk_local < 0)
        Alarm(EXIT, "Init_Session(): AF_UNIX socket failed\n");

    memset(&unix_name, 0, sizeof(unix_name));
    unix_name.sun_family = AF_UNIX;
    /* Check room for length of "data" suffix and NULL byte */
    s_len = SUN_PATH_LEN - strlen(SPINES_UNIX_DATA_SUFFIX) - 1;
    ret = snprintf(unix_name.sun_path, s_len, "%s", Unix_Domain_Prefix);
    if (ret > s_len) {
        Alarm(EXIT, "Init_Session: Unix Domain ctrl pathname too long (%u), "
                "max allowed = %u\n", ret, s_len);
    }

    if (bind(sk_local, (struct sockaddr *) &unix_name, sizeof(unix_name)) < 0)
        Alarm(EXIT, "Init_Session(): AF_UNIX unable to bind to path: %s\n", 
                        unix_name.sun_path);
    if (listen(sk_local, 4) < 0)
        Alarm(EXIT, "Session_Init(): AF_UNIX Listen failure\n");
    E_attach_fd(sk_local, READ_FD, Session_Accept, SESS_CTRL, NULL, LOW_PRIORITY);

    /* Open Socket for IPC Stream Data */
    sk_local = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sk_local < 0)
        Alarm(EXIT, "Init_Session(): AF_UNIX socket failed\n");

    memset(&unix_name, 0, sizeof(unix_name));
    unix_name.sun_family = AF_UNIX;
    /* Check room for NULL byte */
    s_len = SUN_PATH_LEN - 1;
    ret = snprintf(unix_name.sun_path, s_len, "%s%s", Unix_Domain_Prefix, 
            SPINES_UNIX_DATA_SUFFIX);
    if (ret > s_len) {
        Alarm(EXIT, "Init_Session: Unix Domain data pathname too long (%u), "
                "max allowed = %u\n", ret, s_len);
    }

    if (bind(sk_local, (struct sockaddr *) &unix_name, sizeof(unix_name)) < 0)
        Alarm(EXIT, "Init_Session(): AF_UNIX unable to bind to path: %s\n", 
                        unix_name.sun_path);
    if (listen(sk_local, 4) < 0)
        Alarm(EXIT, "Session_Init(): AF_UNIX Listen failure\n");
    E_attach_fd(sk_local, READ_FD, Session_Accept, SESS_DATA, NULL, HIGH_PRIORITY);
#endif

    Link_Sessions_Blocked_On = -1;
   
    /* If we are disabling remote connections, stop here and do not create
     *  TCP sockets to listen for incoming client connections */
    if (Remote_Connections == 0)
        return;

    /* Open Socket for TCP Stream Data */
    sk_local = socket(AF_INET, SOCK_STREAM, 0);
    if (sk_local<0) {
      Alarm(EXIT, "Init_Session(): socket failed\n");
    }

    memset(&name, 0, sizeof(name));
    name.sin_family = AF_INET;
    name.sin_addr.s_addr = INADDR_ANY; /*htonl(My_Address);*/
    name.sin_port = htons((int16)(Port+SESS_PORT));

    val = 1;
    if(setsockopt(sk_local, SOL_SOCKET, SO_REUSEADDR, (char*)&val, sizeof(val)))
    {
#ifndef _WIN32_WCE
        Alarm( EXIT, "Init_Session: Failed to set socket option REUSEADDR, errno: %d\n", errno);
#else
        Alarm( EXIT, "Init_Session: Failed to set socket option REUSEADDR, errno: %d\n", WSAGetLastError());
#endif
    }

    ret = bind(sk_local, (struct sockaddr *) &name, sizeof(name));
    if (ret == -1) {
        Alarm(EXIT, "Init_Session: bind error for port %d\n",Port);
    }

    if(listen(sk_local, 4) < 0) {
        Alarm(EXIT, "Session_Init(): Listen failure\n");
    }

    Alarm(DEBUG, "listen successful on socket: %d\n", sk_local);

    E_attach_fd(sk_local, READ_FD, Session_Accept, SESS_DATA, NULL, HIGH_PRIORITY );

    /* For Datagram sockets */

    /* Use a single socket for sending and receiving udp packets to the client
     * */
    Ses_UDP_Channel = DL_init_channel(SEND_CHANNEL | RECV_CHANNEL,
                                      (int16)(Port+SESS_UDP_PORT), 0, INADDR_ANY /*My_Address*/);

    E_attach_fd(Ses_UDP_Channel, READ_FD, Session_UDP_Read, 0, 
                    NULL, LOW_PRIORITY );

    /* For Control socket */

    sk_local = socket(AF_INET, SOCK_STREAM, 0);
    if (sk_local<0) {
      Alarm(EXIT, "Int_Session(): socket failed\n");
    }

    memset(&name, 0, sizeof(name));
    name.sin_family = AF_INET;
    name.sin_addr.s_addr = INADDR_ANY; /*htonl(My_Address);*/
    name.sin_port = htons((int16)(Port+SESS_CTRL_PORT));

    val = 1;
    if(setsockopt(sk_local, SOL_SOCKET, SO_REUSEADDR, (char*)&val, sizeof(val)))
    {
#ifndef _WIN32_WCE
        Alarm( EXIT, "Init_Session: Failed to set socket option REUSEADDR, errno: %d\n", errno);
#else
        Alarm( EXIT, "Init_Session: Failed to set socket option REUSEADDR, errno: %d\n", WSAGetLastError());
#endif
    }

    ret = bind(sk_local, (struct sockaddr *) &name, sizeof(name));
    if (ret == -1) {
        Alarm(EXIT, "Init_Session: bind error for port %d\n",Port+SESS_CTRL_PORT);
    }

    if(listen(sk_local, 4) < 0) {
        Alarm(EXIT, "Session_Init(): Listen failure\n");
    }

    Alarm(DEBUG, "listen successful on socket: %d\n", sk_local);

    E_attach_fd(sk_local, READ_FD, Session_Accept, SESS_CTRL, NULL, LOW_PRIORITY );
}

/***********************************************************/
/* void Session_Finish (void)                              */
/*                                                         */
/* Cleanup IPC path bindings                               */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/
void Session_Finish(void)
{
#ifndef ARCH_PC_WIN95
    char name[SUN_PATH_LEN];
    
    snprintf(name, sizeof(name), "%s", Unix_Domain_Prefix);
    unlink(name);

    snprintf(name, sizeof(name), "%s%s", Unix_Domain_Prefix, SPINES_UNIX_DATA_SUFFIX);
    unlink(name);
#endif
}

/***********************************************************/
/* void Session_Accept(int sk_local, int dummy,            */
/*                     void *dummy_p)                      */
/*                                                         */
/* Accepts a session socket                                */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* sk_local: the listen socket                             */
/* port: port number of incomming request                  */
/* dummy_p: not used                                       */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Session_Accept(int sk_local, int port, void *dummy_p)
{
    u_int val, lenval, ioctl_cmd;
    channel sk;
    Session *ses;
    stdit it;
    int ret, i, tot_bytes;
    int32 endianess_type;
    spines_sockaddr acc_sin;
    socklen_t acc_sin_len = sizeof(acc_sin);

    if (port != SESS_CTRL && port != SESS_DATA)
        return;

    sk = accept(sk_local, (struct sockaddr*)&acc_sin, &acc_sin_len);
    Alarm(DEBUG, "Accepting socket of type %d\n", acc_sin.family);

    /* Increasing the buffer on the socket */
    for(i=10; i <= 200; i+=5) { 
        val = 1024*i;

        ret = setsockopt(sk, SOL_SOCKET, SO_SNDBUF, (void *)&val, sizeof(val));
        if (ret < 0) break;

        ret = setsockopt(sk, SOL_SOCKET, SO_RCVBUF, (void *)&val, sizeof(val));
        if (ret < 0) break;

        lenval = sizeof(val);
        ret = getsockopt(sk, SOL_SOCKET, SO_SNDBUF, (void *)&val,  &lenval);
        if(val < i*1024) break;
        Alarm(DEBUG, "Sess_accept: set sndbuf %d, ret is %d\n", val, ret);

        lenval = sizeof(val);
        ret= getsockopt(sk, SOL_SOCKET, SO_RCVBUF, (void *)&val, &lenval);
        if(val < i*1024 ) break;
        Alarm(DEBUG, "Sess_accept: set rcvbuf %d, ret is %d\n", val, ret);
    }
    Alarm(DEBUG, "Sess_accept: set sndbuf/rcvbuf to %d\n", 1024*(i-5));

    /* Setting no delay option on the socket */
    if (acc_sin.family == AF_INET) {
        val = 1;
        if (setsockopt(sk, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val))) {
            Alarm(PRINT, "Session_Accept: Failed to set TCP_NODELAY\n");
        }
    }

    /* set file descriptor to non blocking */
    ioctl_cmd = 1;

#ifdef ARCH_PC_WIN95
    ret = ioctlsocket(sk, FIONBIO, (void*) &ioctl_cmd);
#else
    ret = ioctl(sk, FIONBIO, &ioctl_cmd);
#endif

    /* If this is a Control channel setup, just store socket in a 
       safe place, and send socket to the client so that it can
       tell me how to link it's session to the appropiate control channel */
    if (port == SESS_CTRL) {
        tot_bytes = 0;
        while(tot_bytes < sizeof(int32)) {
            ret = send(sk, ((char*)(&sk))+tot_bytes, sizeof(int32)-tot_bytes, 0);
            tot_bytes += ret;
        } 
        if(tot_bytes != sizeof(int32)) {
            close(sk);
        }
        for (i=0; i<MAX_CTRL_SK_REQUESTS; i++) {
            if (ctrl_sk_requests[i] == 0) {
                ctrl_sk_requests[i] = sk;
                break;
            }
        }
        if (i == MAX_CTRL_SK_REQUESTS) {
            Alarm(EXIT, "Session_Accept(): Too many in-progress requests in parallel\n");
        }
        return;
    }

    /* Otherwise, this is a Data channel setup, create the session structure */
    if((ses = (Session*) new(SESSION_OBJ))==NULL) {
        Alarm(EXIT, "Session_Accept(): Cannot allocate session object\n");
    }

    ses->sess_id = Session_Num++;
    ses->type = UDP_SES_TYPE;
    ses->endianess_type = 0;
    ses->sk = sk;
    ses->ctrl_sk = 0;
    ses->port = 0;
    ses->read_len = sizeof(int32);
    ses->partial_len = 0;
    ses->sent_bytes = 0;
    ses->state = READY_ENDIAN;
    ses->r_data = NULL;
    ses->rel_blocked = 0;
    ses->client_stat = SES_CLIENT_ON;
    ses->udp_port = -1;
    ses->recv_fd_flag = 0;
    ses->fd = -1;
    ses->multicast_loopback = 1;
    ses->routing_used   = 0;
    ses->session_semantics = 0;
    ses->deliver_flag = 1;
    ses->priority_lvl   = Conf_Prio.Default_Priority;;
    ses->expire.sec     = Conf_Prio.Default_Expire_Sec;
    ses->expire.usec    = Conf_Prio.Default_Expire_USec;
    ses->disjoint_paths = 0;
    ses->blocked = 0;
    ses->scat = NULL;

    if((ses->data = (char*) new_ref_cnt(MESSAGE_OBJ))==NULL) {
            Alarm(EXIT, "Session_Accept(): Cannot allocate message object\n");
    }

    ses->frag_pkts = NULL;

    stdcarr_construct(&ses->rel_deliver_buff, sizeof(UDP_Cell*), 0);
    stdhash_construct(&ses->joined_groups, sizeof(int32), sizeof(Group_State*),
                      NULL, NULL, 0);


    /* Allocating a port for the session */
    for(i=last_sess_port+1; i < 60000; i++) {
        stdhash_find(&Sessions_Port, &it, &i);
        if(stdhash_is_end(&Sessions_Port, &it)) {
            break;
        }
    }
    if(i == 60000) {
        for(i= 40000; i < last_sess_port; i++) {
            stdhash_find(&Sessions_Port, &it, &i);
            if(stdhash_is_end(&Sessions_Port, &it)) {
                break;
            }
        }
        if(i == last_sess_port) {
            Alarm(EXIT, "Session: No more ports for the session\n");
        }
    }

    last_sess_port = i;

    ses->port = (int16u)i;
    stdhash_insert(&Sessions_Port, &it, &i, &ses);
    stdhash_insert(&Sessions_Sock, &it, &sk, &ses);
    stdhash_insert(&Sessions_ID, &it, &(ses->sess_id), &ses);

    Alarm(PRINT, "new session...%d\n", sk);

    /* Client session data messages are set to low priority to avoid 
     *      starving messages from other daemons */
    E_attach_fd(ses->sk, READ_FD, Session_Read, 0, NULL, LOW_PRIORITY );
    E_attach_fd(ses->sk, EXCEPT_FD, Session_Read, 0, NULL, HIGH_PRIORITY );

    ses->fd_flags = READ_DESC | EXCEPT_DESC;

    /* Send the endianess to the session */
    endianess_type = Set_endian(0);

    tot_bytes = 0;
    while(tot_bytes < sizeof(int32)) {
        ret = send(sk, ((char*)(&endianess_type))+tot_bytes, sizeof(int32)-tot_bytes, 0);
        tot_bytes += ret;
    }  
    if(tot_bytes != sizeof(int32)) {
        Session_Close(ses->sess_id, SOCK_ERR);
    }
}




/***********************************************************/
/* void Session_Read(int sk, int dummy, void *dummy_p)     */
/*                                                         */
/* Reads data from a session socket                        */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* sk: the session socket                                  */
/* dummy, dummy_p: not used                                */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Session_Read(int sk, int dummy, void *dummy_p)
{
    sys_scatter scat;
    udp_header *u_hdr;
    rel_udp_pkt_add *r_add;
    Session *ses;
    stdit it;
    int received_bytes;
    int ret, add_size, i;

    stdhash_find(&Sessions_Sock, &it, &sk);
    if(stdhash_is_end(&Sessions_Sock, &it)) {
        Alarm(PRINT, "Session_Read(): socket does not exist\n");
        return;
    }
    ses = *((Session **)stdhash_it_val(&it));

    scat.num_elements = 1;
    scat.elements[0].len = ses->read_len - ses->partial_len;
    scat.elements[0].buf = (char*)(ses->data + ses->partial_len);

    received_bytes = DL_recv(ses->sk, &scat);

    if(received_bytes <= 0) {

        Alarm(DEBUG, "\nsocket err; len: %d; read_len: %d; partial_len: %d; STATE: %d\n",  
              scat.elements[0].len, ses->read_len, ses->partial_len, ses->state);

        /* This is non-blocking socket. Not all the errors are treated as
         * a disconnect. */
        if(received_bytes == -1) {
#ifndef        ARCH_PC_WIN95
            if((errno == EWOULDBLOCK)||(errno == EAGAIN))
#else
#ifndef _WIN32_WCE
            if((errno == WSAEWOULDBLOCK)||(errno == EAGAIN))
#else
            int sk_errno = WSAGetLastError();
            if((sk_errno == WSAEWOULDBLOCK)||(sk_errno == EAGAIN))
#endif /* Windows CE */
#endif
            {
                Alarm(DEBUG, "EAGAIN - Session_Read()\n");
                return;
            }
            else {
                if(ses->r_data == NULL) {
                    Session_Close(ses->sess_id, SOCK_ERR);
                }
                else {
                    Disconnect_Reliable_Session(ses);
                }
            }
        }
        else {
            if(ses->r_data == NULL) {
                Session_Close(ses->sess_id, SOCK_ERR);
            }
            else {
                Disconnect_Reliable_Session(ses);
            }
        }
        return;
    }

    if(received_bytes + ses->partial_len > ses->read_len)
        Alarm(EXIT, "Session_Read(): Too many bytes...\n");

    if(ses->r_data != NULL) {
        add_size = sizeof(rel_udp_pkt_add);
    }
    else {
        add_size = 0;
    }

    /*
     *Alarm(DEBUG, "* received_bytes: %d; partial_len: %d; read_len: %d; STATE: %d\n",
     *          received_bytes, ses->partial_len, ses->read_len, ses->state);
     */

    if(received_bytes + ses->partial_len < ses->read_len) {
        ses->partial_len += received_bytes;
    }
    else {
        if(ses->state == READY_ENDIAN) {
            ses->endianess_type = *((int32*)(ses->data));

            ses->received_len = 0;
            ses->read_len = sizeof(int32);
            ses->partial_len = 0;
            ses->state = READY_CTRL_SK;
        }
        else if(ses->state == READY_CTRL_SK) {
            ses->ctrl_sk = *((int32*)(ses->data));
            for (i=0; i<MAX_CTRL_SK_REQUESTS; i++) {
                if (ctrl_sk_requests[i] == ses->ctrl_sk) {
                    ctrl_sk_requests[i] = 0;
                    break;
                }
            }
            if (i == MAX_CTRL_SK_REQUESTS) {
                Alarm(PRINT, "Session_Read(): No such control channel: %d\n", ses->ctrl_sk);
                ses->ctrl_sk = 0;
                Session_Close(ses->sess_id, SOCK_ERR);
                return;
            }
            Alarm(PRINT, "linked Spines Socket Channel %d with Control Channel %d\n", ses->sk, ses->ctrl_sk);
            ses->received_len = 0;
            ses->read_len = sizeof(int32);
            ses->partial_len = 0;
            ses->state = READY_LEN;
        }
        else if(ses->state == READY_LEN) {
            ses->total_len = *((int32*)(ses->data));
            if(!Same_endian(ses->endianess_type)) {
                ses->total_len = Flip_int32(ses->total_len);
            }

            /* Sanity check received length */
            if (ses->total_len < sizeof(udp_header) || ses-> total_len > MAX_SPINES_CLIENT_MSG + sizeof(udp_header)) {
                Alarm(PRINT, "Session_Read(): Invalid size recvd from "
                      "client: recvd %d, max = %d (client data + "
                      "udp_header)...disconnecting!\n",
                      ses->total_len, MAX_SPINES_CLIENT_MSG + sizeof(udp_header));
                
                /* Disconnect the client */
                if(ses->r_data == NULL) {
                    Session_Close(ses->sess_id, SES_DISCONNECT);
                }
                else {
                    Disconnect_Reliable_Session(ses);
                }
            }
                

            /* Set up to read data based on protocols used */
            if (ses->routing_used == MIN_WEIGHT_ROUTING || 
                    ses->routing_used == SOURCE_BASED_ROUTING) 
            {
                if(ses->total_len > MAX_SPINES_MSG + sizeof(udp_header) + add_size) {
                    ses->read_len = MAX_SPINES_MSG + sizeof(udp_header) + add_size;
                }
                else {
                    ses->read_len = ses->total_len;
                }
                ses->frag_num = (ses->total_len-sizeof(udp_header)-add_size)/MAX_SPINES_MSG;
                if((ses->total_len-sizeof(udp_header)-add_size)%MAX_SPINES_MSG != 0) {
                    ses->frag_num++;
                }
                /* Allow 0-byte pkts, but still need to have 1 fragment (which
                 * will contain the udp header) */
                if(ses->frag_num == 0) {
                    ses->frag_num++;
                }
                ses->frag_idx = 0;
            }
            else if (ses->routing_used == IT_PRIORITY_ROUTING ||
                        ses->routing_used == IT_RELIABLE_ROUTING) 
            {
                /* Check for len < MAX_SPINES_CLIENT_MSG above makes this unnecessary */
                /* if (ses->total_len <= 0 || ses->total_len > MAX_PACKET_SIZE * MAX_PKTS_PER_MESSAGE) { */
                /* if (ses->total_len <= 0 || ses->total_len > (MAX_SPINES_MSG + sizeof(udp_header)) * MAX_PKTS_PER_MESSAGE) {
                    Alarm(PRINT, "Session_Read(): Invalid size recvd from "
                          "client: recvd %d, max = %d...disconnecting!\n",
                          ses->total_len,
                          (MAX_SPINES_MSG + sizeof(udp_header)) * MAX_PKTS_PER_MESSAGE);
                    if(ses->r_data == NULL) {
                        Session_Close(ses->sess_id, SES_DISCONNECT);
                    }
                    else {
                        Disconnect_Reliable_Session(ses);
                    }
                } */
                ses->read_len = ses->total_len;
                ses->frag_num = 1;
                ses->frag_idx = 0;
            }
            else
                Alarm(PRINT, "Session_Read: Unexpected routing_used %d\r\n",
                            ses->routing_used);

            ses->partial_len = 0;
            ses->received_len = 0;
            ses->seq_no++;
            if(ses->seq_no >= 10000) {
                ses->seq_no = 0;
            }

            ses->state = READY_DATA;
            Alarm(DEBUG,"Finished READY_LEN, ses->read_len = %u, ses->partial_len = %u\r\n",
                        ses->read_len, ses->partial_len);
        }
        else if(ses->state == READY_DATA) {
            u_hdr = (udp_header*)ses->data;
            if(!Same_endian(ses->endianess_type)) {
                Flip_udp_hdr(u_hdr);
            }
            
            if (ses->routing_used == MIN_WEIGHT_ROUTING ||
                ses->routing_used == SOURCE_BASED_ROUTING) {
                if(ses->frag_num > 1) {
                    if(ses->frag_idx == 0) {
                        memcpy((void*)(&ses->save_hdr), (void*)u_hdr, sizeof(udp_header));
                    }
                    u_hdr->len = ses->read_len - sizeof(udp_header);
                    
                    if(ses->r_data != NULL) {
                        r_add = (rel_udp_pkt_add*)(ses->data + sizeof(udp_header));
                        r_add->type = Set_endian(0);
                        r_add->data_len = u_hdr->len - sizeof(rel_udp_pkt_add);
                        r_add->ack_len = 0;
                    }
                }
            }
            
            u_hdr->seq_no = ses->seq_no;
            u_hdr->frag_num = (int16u)ses->frag_num; 
            u_hdr->frag_idx = (int16u)ses->frag_idx; 
            u_hdr->sess_id = (int16u)(ses->sess_id & 0x0000ffff);

            ses->received_len += ses->read_len;
            if(ses->frag_idx > 0) {
                ses->received_len -= sizeof(udp_header)+add_size;
            } 
            ses->frag_idx++;

            ret = Process_Session_Packet(ses);
           
            if(get_ref_cnt(ses->data) > 1) {
                dec_ref_cnt(ses->data);
                if((ses->data = (char*) new_ref_cnt(MESSAGE_OBJ))==NULL) {
                    Alarm(EXIT, "Session_Read(): Cannot allocate packet_body\n");
                }
            }

            if(ret == NO_BUFF){
                return;
            }

            if(ses->frag_idx == ses->frag_num) {
                ses->read_len = sizeof(int32);
                ses->partial_len = 0;
                ses->state = READY_LEN;
            }
            else {
                ses->read_len = ses->total_len - ses->received_len;
                if(ses->read_len > MAX_SPINES_MSG) {
                    ses->read_len = MAX_SPINES_MSG;
                }
                /*
                 *Alarm(PRINT, "TOT total: %d; received: %d; read: %d\n",
                 *     ses->total_len, ses->received_len, ses->read_len);
                 */
                memcpy((void*)(ses->data), (void*)(&ses->save_hdr), sizeof(udp_header));
                ses->read_len += sizeof(udp_header);
                ses->partial_len = sizeof(udp_header);
                if(ses->r_data != NULL) {
                    ses->read_len += sizeof(rel_udp_pkt_add);
                    ses->partial_len += sizeof(rel_udp_pkt_add);
                }
                ses->state = READY_DATA;
            }
            Alarm(DEBUG,"Finished READY_DATA, ses->total_len = %u, "
                            "ses->read_len = %u, ses->partial_len = %u\r\n",
                            ses->total_len, ses->read_len, ses->partial_len);
        }
    }
}



/***********************************************************/
/* void Session_Close(int sesid, int reason)               */
/*                                                         */
/* Closes a session                                        */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* sesid:  the session id                                  */
/* reason: see session.h                                   */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Session_Close(int sesid, int reason)
{
    Session *ses;
    stdit it;
    stdit c_it;
    UDP_Cell *u_cell;
    char *buff;
    int32 dummy_port;
    Group_State *g_state;
    int cnt = 0;
    int i;
    Frag_Packet *frag_pkt;


    /* Get the session */
    stdhash_find(&Sessions_ID, &it, &sesid);
    if(stdhash_is_end(&Sessions_ID, &it)) {
        Alarm(PRINT, "Session_Close(): session does not exist: %d\n", sesid);
        return;
    }
    ses = *((Session **)stdhash_it_val(&it));

    ses->close_reason = reason;

    /* Remove any stored scatter message */
    if (ses->scat != NULL) {
        Cleanup_Scatter(ses->scat); ses->scat = NULL;
    }

    /* Detach the socket so it won't bother us */
    if(ses->client_stat == SES_CLIENT_ON) {
        ses->client_stat = SES_CLIENT_OFF;

        if(ses->fd_flags & READ_DESC)
            E_detach_fd(ses->sk, READ_FD);

        if(ses->fd_flags & EXCEPT_DESC)
            E_detach_fd(ses->sk, EXCEPT_FD);

        if(ses->fd_flags & WRITE_DESC)
            E_detach_fd(ses->sk, WRITE_FD);


        while(!stdcarr_empty(&ses->rel_deliver_buff)) {
            stdcarr_begin(&ses->rel_deliver_buff, &c_it);

            u_cell = *((UDP_Cell **)stdcarr_it_val(&c_it));
            buff = u_cell->buff;

            dec_ref_cnt(buff);
            dispose(u_cell);
            stdcarr_pop_front(&ses->rel_deliver_buff);
        }
        stdcarr_destruct(&ses->rel_deliver_buff);

        stdhash_find(&Sessions_Sock, &it, &ses->sk);
        if(!stdhash_is_end(&Sessions_Sock, &it)) {
            stdhash_erase(&Sessions_Sock, &it);
        }
    }

    /* Dispose the receiving buffer */
    if(ses->data != NULL) {
        dec_ref_cnt(ses->data);
        ses->data = NULL;
    }

    /* Dispose all the incomplete fragmented packets */
    while(ses->frag_pkts != NULL) {
        frag_pkt = ses->frag_pkts;
        ses->frag_pkts = ses->frag_pkts->next;
        for(i=0; i<frag_pkt->scat.num_elements; i++) {
            if(frag_pkt->scat.elements[i].buf != NULL) {
                dec_ref_cnt(frag_pkt->scat.elements[i].buf);
            }
        }
        dispose(frag_pkt);
    }

    /* Remove the reliability data structures */
    if(ses->r_data != NULL) {
        Close_Reliable_Session(ses);
        ses->r_data = NULL;
    }

    /* Leave all the groups */
    stdhash_begin(&ses->joined_groups, &it);
    while(!stdhash_is_end(&ses->joined_groups, &it)) {
        g_state = *((Group_State **)stdhash_it_val(&it));
        /*Alarm(DEBUG, "Disconnect; Leaving group: %d.%d.%d.%d == %d\n",
        */
        Alarm(PRINT, "Disconnect; Leaving group: %d.%d.%d.%d == %d\n",
              IP1(g_state->mcast_gid), IP2(g_state->mcast_gid),
              IP3(g_state->mcast_gid), IP4(g_state->mcast_gid), cnt);
        Leave_Group(g_state->mcast_gid, ses);
        cnt++;
        if(cnt > 10) {
            /* Too many groups to leave at once. Queue the function again  */
            E_queue(Try_Close_Session, (int)ses->sess_id, NULL, zero_timeout);
            return;
        }
        stdhash_begin(&ses->joined_groups, &it);
    }

    /* Left all the groups... */
    stdhash_destruct(&ses->joined_groups);


    stdhash_find(&Sessions_ID, &it, &(ses->sess_id));
    if(!stdhash_is_end(&Sessions_ID, &it)) {
        stdhash_erase(&Sessions_ID, &it);
    }
    else {
        Alarm(EXIT, "Session_Close(): invalid ID\n");
    }

    if(reason != PORT_IN_USE){
        dummy_port = (int32)ses->port;
        if(dummy_port != 0) {
            stdhash_find(&Sessions_Port, &it, &dummy_port);
            if(!stdhash_is_end(&Sessions_Port, &it)) {
                stdhash_erase(&Sessions_Port, &it);
            }
        }
    }

    if(ses->client_stat != SES_CLIENT_ORPHAN) {
        /* Close the socket (now we can, since we won't access the session by socket) */
        Alarm(PRINT, "Session_Close: closing channel: %d\n", ses->sk);
        DL_close_channel(ses->sk);
        if (ses->ctrl_sk > 0)
            DL_close_channel(ses->ctrl_sk);
        Alarm(PRINT, "session closed: %d\n", ses->sk);
    }

    if(ses->recv_fd_flag == 1) {
        if(ses->fd != -1) {
            close(ses->fd);
        }
    }

    /* Dispose the session */
    dispose(ses);
}




/***********************************************************/
/* int void Try_Close_Session(int sesid, void *dummy)      */
/*                                                         */
/* Calls Session_Close() again, until it leaves all groups */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* sesid:    the id of the session                         */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Try_Close_Session(int sesid, void *dummy)
{
    Session *ses;
    stdit it;

    stdhash_find(&Sessions_ID, &it, &sesid);
    if(stdhash_is_end(&Sessions_ID, &it)) {
        return;
    }
    ses = *((Session **)stdhash_it_val(&it));

    Session_Close(ses->sess_id, ses->close_reason);
}

/***********************************************************/
/* int Process_Session_Packet(Session *ses)                */
/*                                                         */
/* Processes a packet from a client                        */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* ses:      the session defining the client               */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int) status of the packet (see udp.h)                  */
/*                                                         */
/***********************************************************/

int Process_Session_Packet(Session *ses)
{
    udp_header *hdr;
    udp_header *cmd;
    int32 *cmd_int, *pkt_len;
    int ret, tot_bytes, routing;
    int msg_size_avail = MAX_MESSAGE_SIZE;
    int32 dummy_port, dest_addr;
    stdit it;
    int32 *type;
    Lk_Param lkp;
    spines_trace *spines_tr;
    char *buf, *read_ptr;
    int i, remaining, link_overhead, paths;
    packet_header *phdr;
    Session *ses_seek;

    /* Process the packet */
    hdr = (udp_header*)(ses->data);

    type = (int32*)(ses->data + sizeof(udp_header));
    cmd = (udp_header*)(ses->data + sizeof(udp_header)+sizeof(int32));
    cmd_int = (int32*)(ses->data + sizeof(udp_header)+sizeof(int32));

    if((hdr->len == 0) && (hdr->source == 0) && (hdr->dest == 0)) {
        /* Session command */
        type = (int32*)(ses->data + sizeof(udp_header));
        if(!Same_endian(ses->endianess_type)) {
            *type = Flip_int32(*type);
        }

        if(*type == BIND_TYPE_MSG) {
            /* spines_bind() */

            cmd = (udp_header*)(ses->data + sizeof(udp_header)+sizeof(int32));
            if(!Same_endian(ses->endianess_type)) {
                Flip_udp_hdr(cmd);
            }

            if(cmd->dest_port == 0) {
                Alarm(PRINT, "\n!!! Session: you cannot bind on port 0 (zero)\n");
                Session_Close(ses->sess_id, PORT_IN_USE);
                return(NO_BUFF);
            }
            if(ses->type == LISTEN_SES_TYPE) {
                Alarm(PRINT, "Cannot bind on a listen session\n");
                Session_Close(ses->sess_id, SES_DISCONNECT);
                return(NO_BUFF);
            }
            if(ses->r_data != NULL) {
                Alarm(PRINT, "\n!!! spines_bind(): session already connected\n");
                Session_Close(ses->sess_id, SES_DISCONNECT);
                return(NO_BUFF);
            }


            /* Check whether the port is already used */
            dummy_port = cmd->dest_port;
            stdhash_find(&Sessions_Port, &it, &dummy_port);
            if(!stdhash_is_end(&Sessions_Port, &it)) {
                Alarm(PRINT, "\n!!! Process_Session_Packet(): port already exists\n");
                Session_Close(ses->sess_id, PORT_IN_USE);
                return(NO_BUFF);
            }

            /* release the current port of the session */
            dummy_port = ses->port;
            stdhash_find(&Sessions_Port, &it, &dummy_port);
            if(stdhash_is_end(&Sessions_Port, &it)) {
                Alarm(EXIT, "BIND: session does not have a port\n");
            }
            stdhash_erase(&Sessions_Port, &it);

            ses->port = cmd->dest_port;
            dummy_port = cmd->dest_port;
            stdhash_insert(&Sessions_Port, &it, &dummy_port, &ses);

            if(ses->udp_port != -1) {
                Ses_Send_ID(ses);
            }

            Alarm(PRINT, "Accepted bind for port: %d\n", dummy_port);

            ses->read_len = sizeof(int32);
            ses->partial_len = 0;
            ses->state = READY_LEN;
            return(BUFF_EMPTY);
        }
        else if(*type == CONNECT_TYPE_MSG) {
            /* spines_connect() */

            if(ses->r_data != NULL) {
                Alarm(PRINT, "\n!!! spines_connect(): session already connected\n");
                Session_Close(ses->sess_id, SES_DISCONNECT);
                return(NO_BUFF);
            }
            if(ses->type == LISTEN_SES_TYPE) {
                Alarm(PRINT, "Listen session\n");
                Session_Close(ses->sess_id, SES_DISCONNECT);
                return(NO_BUFF);
            }

            cmd = (udp_header*)(ses->data + sizeof(udp_header)+sizeof(int32));
            if(!Same_endian(ses->endianess_type)) {
                Flip_udp_hdr(cmd);
            }

            if((cmd->dest & 0xF0000000) == 0xE0000000) {
                /* Multicast address */
                Alarm(PRINT, "Error: Connect to a Multicast address\n");
            }
            else {
                /* Reliable Connect */
                ret = Init_Reliable_Connect(ses, cmd->dest, cmd->dest_port);

                if(ret == -1) {
                    Alarm(PRINT, "Session_Read(): No ports available\n");
                    Session_Close(ses->sess_id, SES_DISCONNECT);
                    return(NO_BUFF);
                }
            }
            ses->read_len = sizeof(int32);
            ses->partial_len = 0;
            ses->state = READY_LEN;
            return(BUFF_EMPTY);
        }
        else if(*type == LISTEN_TYPE_MSG) {
            /* spines_listen() */
            if(ses->r_data != NULL) {
                Alarm(PRINT, "\n!!! spines_listen(): session already connected\n");
                Session_Close(ses->sess_id, SES_DISCONNECT);
                return(NO_BUFF);
            }
            if(ses->type == LISTEN_SES_TYPE) {
                Alarm(PRINT, "This session already listens\n");
                Session_Close(ses->sess_id, SES_DISCONNECT);
                return(NO_BUFF);
            }

            ses->type = LISTEN_SES_TYPE;

            ses->read_len = sizeof(int32);
            ses->partial_len = 0;
            ses->state = READY_LEN;
            return(BUFF_EMPTY);
        }
        else if(*type == LINKS_TYPE_MSG) {
            /* spines_socket() */
            ses->links_used = *cmd_int;
            ses->routing_used = *(cmd_int+1);
            ses->session_semantics = *(cmd_int+2);
            ses->rnd_num  = *(cmd_int+3);
            ses->udp_addr = *(cmd_int+4);
            ses->udp_port = *(cmd_int+5);
            if(!Same_endian(ses->endianess_type)) {
                ses->links_used = Flip_int32(ses->links_used);
                ses->routing_used = Flip_int32(ses->routing_used);
                ses->session_semantics = Flip_int32(ses->session_semantics);
                ses->rnd_num  = Flip_int32(ses->rnd_num);
                ses->udp_addr = Flip_int32(ses->udp_addr);
                ses->udp_port = Flip_int32(ses->udp_port);
            }
            ses->seq_no   = ses->rnd_num%MAX_PKT_SEQ;

            Alarm(DEBUG, "ses->routing = %d, 0x%x, ses->semantics = %d, 0x%x\n", 
                  (ses->routing_used >> ROUTING_BITS_SHIFT), ses->routing_used,
                    ses->session_semantics >> SESSION_BITS_SHIFT, ses->session_semantics);

            if ( ses->links_used != INTRUSION_TOL_LINKS &&
                (ses->routing_used == IT_PRIORITY_ROUTING ||
                 ses->routing_used == IT_RELIABLE_ROUTING))
            {
                Alarm(PRINT, "Cannot support this choice of dissemination (%u) and"
                                " link (%u) protocols\n", 
                      (ses->routing_used >> ROUTING_BITS_SHIFT), 
                                ses->links_used);
                Session_Close(ses->sess_id, SES_DISCONNECT);
                return(NO_BUFF);
            }

            if (Config_File_Found == 0 && 
                    (ses->links_used == INTRUSION_TOL_LINKS ||
                    ses->routing_used == IT_PRIORITY_ROUTING ||
                    ses->routing_used == IT_RELIABLE_ROUTING ||
                    ses->routing_used == SOURCE_BASED_ROUTING) )
            {
                Alarm(PRINT, "Cannot support this choice of dissemination (%u) and"
                                " link (%u) protocols without Configuration File\n", 
                      (ses->routing_used >> ROUTING_BITS_SHIFT), 
                                ses->links_used);
                Session_Close(ses->sess_id, SES_DISCONNECT);
                return(NO_BUFF);
            }

            Ses_Send_ID(ses);

            ses->read_len = sizeof(int32);
            ses->partial_len = 0;
            ses->state = READY_LEN;
            return(BUFF_EMPTY);
        }
        else if(*type == SETLINK_TYPE_MSG) {
            /* spines_setloss() */

            if(Accept_Monitor == 1) {
                Network_Leg_ID lid;

                cmd = (udp_header*)(ses->data + sizeof(udp_header)+sizeof(int32));

                memset(&lkp, 0, sizeof(lkp));

                lkp.bandwidth  = *(int32*)(ses->data + 2 * sizeof(udp_header) + 1 * sizeof(int32));
                lkp.delay.usec = *(int32*)(ses->data + 2 * sizeof(udp_header) + 2 * sizeof(int32));
                lkp.loss_rate  = *(int32*)(ses->data + 2 * sizeof(udp_header) + 3 * sizeof(int32));
                lkp.burst_rate = *(int32*)(ses->data + 2 * sizeof(udp_header) + 4 * sizeof(int32));
                
                if(!Same_endian(ses->endianess_type)) {
                    Flip_udp_hdr(cmd);
                    lkp.bandwidth  = Flip_int32(lkp.bandwidth);
                    lkp.delay.usec = Flip_int32(lkp.delay.usec);
                    lkp.loss_rate  = Flip_int32(lkp.loss_rate);
                    lkp.burst_rate = Flip_int32(lkp.burst_rate);
                }

                /* Delay is given in milliseconds */

                lkp.delay.usec   *= 1000;

                lkp.delay.sec     = lkp.delay.usec / 1000000;
                lkp.delay.usec    = lkp.delay.usec % 1000000;

                lkp.was_loss      = 0;

                lkp.bucket        = BWTH_BUCKET;
                lkp.last_time_add = E_get_time();

                Alarm(PRINT, "\nSetting leg params(" IPF " -> " IPF "): bandwidth: %d; latency: %d; loss: %d; burst: %d; was_loss %d\n\n",
                      IP(cmd->source), IP(cmd->dest), lkp.bandwidth, lkp.delay.usec, lkp.loss_rate, lkp.burst_rate, lkp.was_loss);

                memset(&lid, 0, sizeof(lid));
                lid.src_interf_id = cmd->source;
                lid.dst_interf_id = cmd->dest;

                stdhash_erase_key(&Monitor_Params, &lid);

                if (lkp.bandwidth > 0 || lkp.delay.sec > 0 || lkp.delay.usec > 0 || lkp.loss_rate > 0) {

                  if (stdhash_insert(&Monitor_Params, &it, &lid, &lkp) != 0) {
                    Alarm(EXIT, "Couldn't insert into Monitor_Params!\r\n");
                  }
                }
            }

            return(BUFF_EMPTY);
        }
        else if (*type == SETDISSEM_TYPE_MSG) {
            cmd = (udp_header*)(ses->data + sizeof(udp_header)+sizeof(int32));

            if (!Same_endian(ses->endianess_type)) {
                Flip_udp_hdr(cmd);
            }

            paths = *(int32*)(ses->data + 2*sizeof(udp_header) + sizeof(int32));
            if (paths < 0 || paths > 4) {
                Alarm(PRINT, "Cannot change to unsupported dissemination number" 
                                " of paths: %d\r\n", paths);
                return(BUFF_EMPTY); 
            }

            /* For all the data sessions connected to this daemon, switch them
             *      to the new # of paths (or flooding) */
            stdhash_begin(&Sessions_ID, &it);
            while (!stdhash_is_end(&Sessions_ID, &it)) {
                ses_seek = *((Session **)stdhash_it_val(&it));
                ses_seek->disjoint_paths = (int16u)paths; 
                stdhash_it_next(&it);
            }

            overwrite_ip = *(int32*)(ses->data + 2*sizeof(udp_header) + 2*sizeof(int32));

            Alarm(PRINT, "Changed number of paths in dissemination to %d\r\n", paths);
            return(BUFF_EMPTY);

        }
        else if(*type == FLOOD_SEND_TYPE_MSG) {
            /* spines_flood_send() */
            ses->Sendto_address = *(int32*)(ses->data + sizeof(udp_header)+sizeof(int32));
            ses->Sendto_port = *(int32*)(ses->data + sizeof(udp_header)+2*sizeof(int32));
            ses->Rate        = *(int32*)(ses->data + sizeof(udp_header)+3*sizeof(int32));
            ses->Packet_size = *(int32*)(ses->data + sizeof(udp_header)+4*sizeof(int32));
            ses->Num_packets = *(int32*)(ses->data + sizeof(udp_header)+5*sizeof(int32));
            ses->Sent_packets = 0;
            ses->Start_time = E_get_time();
            if(!Same_endian(ses->endianess_type)) {
                ses->Sendto_address = Flip_int32(ses->Sendto_address);
                ses->Sendto_port = Flip_int32(ses->Sendto_port);
                ses->Rate        = Flip_int32(ses->Rate);
                ses->Packet_size = Flip_int32(ses->Packet_size);
                ses->Num_packets = Flip_int32(ses->Num_packets);
            }

            Session_Flooder_Send(ses->sess_id, NULL);

            return(BUFF_EMPTY);
        }
        else if(*type == FLOOD_RECV_TYPE_MSG) {
            /* spines_flood_recv() */
            ses->recv_fd_flag = 1;
#ifdef ARCH_PC_WIN95
                ses->fd   = 0;
                printf("Error on windows:  flooding not supported\r\n");
                //ses->fd = _open(ses->data+sizeof(udp_header)+2*sizeof(int32), _O_WRONLY|_O_CREAT|_O_TRUNC, _S_IREAD | _S_IWRITE);
#else
                ses->fd = open(ses->data+sizeof(udp_header)+2*sizeof(int32), O_WRONLY|O_CREAT|O_TRUNC, 00666);
#endif
            
            if(ses->fd == -1) {
                Session_Close(ses->sess_id, SES_BUFF_FULL);
            }
            return(BUFF_EMPTY);
        }
        else if(*type == ACCEPT_TYPE_MSG) {
            /* spines_accept() */
            if(ses->r_data != NULL) {

                Alarm(PRINT, "\n!!! spines_accept(): session already connected\n");
                Session_Close(ses->sess_id, SES_DISCONNECT);
                return(NO_BUFF);
            }

            cmd = (udp_header*)(ses->data + sizeof(udp_header)+sizeof(int32));
            if(!Same_endian(ses->endianess_type)) {
                Flip_udp_hdr(cmd);
            }


            ret = Accept_Rel_Session(ses, cmd, ses->data+2*sizeof(udp_header)+sizeof(int32));

            ses->read_len = sizeof(int32);
            ses->partial_len = 0;
            ses->state = READY_LEN;
            return(BUFF_EMPTY);
        }
        else if(*type == JOIN_TYPE_MSG) {
            /* spines_join() for spines_setsockopt() */
            if(ses->r_data != NULL) {
                Alarm(PRINT, "\n!!! spines_join(): session already connected\n");
                Session_Close(ses->sess_id, SES_DISCONNECT); 
                return(NO_BUFF);
            }
            if(ses->type == LISTEN_SES_TYPE) {
                Alarm(PRINT, "Cannot join on a listen session\n");
                Session_Close(ses->sess_id, SES_DISCONNECT);
                return(NO_BUFF);
            }

            cmd = (udp_header*)(ses->data + sizeof(udp_header)+sizeof(int32));
            if(!Same_endian(ses->endianess_type)) {
                Flip_udp_hdr(cmd);
            }
            dest_addr = cmd->dest;

            ret = Join_Group(dest_addr, ses);
            if(ret < 0) {
                Session_Close(ses->sess_id, SES_DISCONNECT);
                return(NO_BUFF);
            }

            ses->read_len = sizeof(int32);
            ses->partial_len = 0;
            ses->state = READY_LEN;
            return(BUFF_EMPTY);
        }
        else if(*type == LEAVE_TYPE_MSG) {
            /* spines_leave() for spines_setsockopt() */
            if(ses->r_data != NULL) {
                Alarm(PRINT, "\n!!! spines_leave(): session already connected\n");
                Session_Close(ses->sess_id, SES_DISCONNECT);
                return(NO_BUFF);
            }
            if(ses->type == LISTEN_SES_TYPE) {
                Alarm(PRINT, "Cannot leave on a listen session\n");
                Session_Close(ses->sess_id, SES_DISCONNECT);
                return(NO_BUFF);
            }

            cmd = (udp_header*)(ses->data + sizeof(udp_header)+sizeof(int32));
            if(!Same_endian(ses->endianess_type)) {
                Flip_udp_hdr(cmd);
            }
            dest_addr = cmd->dest;
            Alarm(PRINT,"LEAVE_TYPE_MESSAGE\n");
            ret = Leave_Group(dest_addr, ses);
            if(ret < 0) {
                Session_Close(ses->sess_id, SES_DISCONNECT);
                return(NO_BUFF);
            }

            ses->read_len = sizeof(int32);
            ses->partial_len = 0;
            ses->state = READY_LEN;
            return(BUFF_EMPTY);
        }
        else if(*type == LOOP_TYPE_MSG) {
            cmd = (udp_header*)(ses->data + sizeof(udp_header)+sizeof(int32));
            if(!Same_endian(ses->endianess_type)) {
                Flip_udp_hdr(cmd);
            }
            ses->multicast_loopback = (char)(cmd->dest);
            return(BUFF_EMPTY);
        }
#if 0
        else if(*type == ADD_NEIGHBOR_MSG) {

          TODO FIX ME to include network address, interface id, etc.

            /* spines_add_neighbor() for spines_ioctl() */
            cmd = (udp_header*)(ses->data + sizeof(udp_header)+sizeof(int32));
            if(!Same_endian(ses->endianess_type)) {
                Flip_udp_hdr(cmd);
            }
            dest_addr = cmd->dest; 
            /* Fake a hello ping to initialize connection */ 
            Process_hello_ping_packet(cmd->dest, 0);
            return(BUFF_EMPTY);
        }
#endif
        else if(*type == TRACEROUTE_TYPE_MSG || 
            *type == EDISTANCE_TYPE_MSG  || 
            *type == MEMBERSHIP_TYPE_MSG ) { 

            cmd = (udp_header*)(ses->data + sizeof(udp_header)+sizeof(int32));
            if(!Same_endian(ses->endianess_type)) {
                Flip_udp_hdr(cmd);
            }
            dest_addr = cmd->dest;

            buf = (char *) new_ref_cnt(PACK_BODY_OBJ); 
            if(buf == NULL) { 
                Alarm(EXIT, "Session_UDP_Read: Cannot allocate buffer\n"); 
            } 
            pkt_len = (int32 *)(buf);
            hdr = (udp_header *)(buf + sizeof(int32));
            hdr->source = My_Address;
            hdr->dest = My_Address;
            hdr->source_port = ses->port;
            hdr->dest_port = ses->port;
            hdr->seq_no = 0;
            hdr->len = sizeof(spines_trace);

            spines_tr = (spines_trace *)( (char *)hdr + sizeof(udp_header));
            memset(spines_tr, 0, sizeof(spines_trace));
            if(*type == TRACEROUTE_TYPE_MSG) {
                Trace_Route(My_Address, dest_addr, spines_tr);
            } else if (*type == EDISTANCE_TYPE_MSG) {
                Trace_Group(dest_addr, spines_tr);
            } else if (*type == MEMBERSHIP_TYPE_MSG ) { 
                Get_Group_Members(dest_addr, spines_tr);
            }

            tot_bytes = 0;
            *pkt_len = sizeof(udp_header)+sizeof(spines_trace);
            while(tot_bytes < sizeof(int32)+*pkt_len) {
                ret = send(ses->ctrl_sk,  buf, sizeof(int32)+*pkt_len-tot_bytes, 0);
                if (ret < 0) {
                    if((errno == EWOULDBLOCK)||(errno == EAGAIN)) {
                        Alarm(PRINT, "Blocking\n");
                    } else {
                        Alarm(EXIT, "Problem sending through control socket\n");
                    }
                }
                tot_bytes += ret;
            } 
            dec_ref_cnt(buf);
            return(BUFF_EMPTY);
        } 
        else if (*type == DELIVERY_FLAG_MSG) {
            cmd = (udp_header*)(ses->data + sizeof(udp_header)+sizeof(int32));
            if(!Same_endian(ses->endianess_type)) {
                Flip_udp_hdr(cmd);
            }
            if ( (int16u)(cmd->dest) >= 1 && (int16u)(cmd->dest) <= 3 ) {
                ses->deliver_flag = (int16u)(cmd->dest);
            }
            return(BUFF_EMPTY);
        }
        else if (*type == PRIORITY_TYPE_MSG) {
            cmd = (udp_header*)(ses->data + sizeof(udp_header)+sizeof(int32));
            if(!Same_endian(ses->endianess_type)) {
                Flip_udp_hdr(cmd);
            }
            if ( (int16u)(cmd->dest) >= 1 && (int16u)(cmd->dest) <= MAX_PRIORITY ) {
                ses->priority_lvl = (int16u)(cmd->dest);
            }
            return(BUFF_EMPTY);
        }
        else if (*type == EXPIRATION_TYPE_MSG) {
            cmd = (udp_header*)(ses->data + sizeof(udp_header)+sizeof(int32));
            if(!Same_endian(ses->endianess_type)) {
                Flip_udp_hdr(cmd);
            }
            ses->expire.sec = (int32u)(cmd->source);
            ses->expire.usec = (int32u)(cmd->dest);
            return(BUFF_EMPTY);
        }
        else if (*type == DIS_PATHS_TYPE_MSG) {
            cmd = (udp_header*)(ses->data + sizeof(udp_header)+sizeof(int32));
            if(!Same_endian(ses->endianess_type)) {
                Flip_udp_hdr(cmd);
            }
            if ( (int16u)(cmd->dest) > 0 ) {
                ses->disjoint_paths = (int16u)(cmd->dest);
                printf("\t\tKPATHS = %hu\n", ses->disjoint_paths);
            }
            return(BUFF_EMPTY);
        }
        else {
            Alarm(PRINT, "Session unknown command: %X\n", *type);
            return(BUFF_EMPTY);
        }
    }

    /* Ok, this is data */
    if(ses->r_data != NULL) {
        /* This is Reliable UDP Data */
        /*Alarm(PRINT,"Reliable UDP Data\n");*/
        ret = Process_Reliable_Session_Packet(ses);
        return(ret);
    }
    else {
        /* This is UDP Data*/
        hdr->source      = My_Address;
        hdr->source_port = ses->port;

        if(hdr->len + sizeof(udp_header) == ses->read_len) {
            
            routing = ((int) hdr->routing << ROUTING_BITS_SHIFT);

            msg_size_avail -= (MAX_PKTS_PER_MESSAGE * 
                    Link_Header_Size(Get_Ses_Mode(ses->links_used)));
            msg_size_avail -= Dissemination_Header_Size(routing);

            /* We check to make sure that it can fit in the packet body
             * along with the original client message. If it doesn't fit, we can
             * split the original packet and send fragments, but this requires
             * reassembling the packet on the other side. */
            if (ses->read_len > msg_size_avail) {
                Alarm(PRINT, "Session: packet too big... dropping (len = %d, "
                      "max = %d)\r\n", ses->read_len, msg_size_avail);
                return(NO_ROUTE);
            }
                
            if ((ses->scat = (sys_scatter*) new_ref_cnt(SYS_SCATTER)) == NULL)
                Alarm(EXIT, "Process_Session_Packet: Could not allocate sys_scatter\r\n");

            if ((ses->scat->elements[0].buf = new_ref_cnt(PACK_HEAD_OBJ)) == NULL)
                Alarm(EXIT, "Process_Session_Packet: Could not allocate packet_header\r\n");

            ses->scat->elements[0].len = sizeof(packet_header);
            ses->scat->num_elements = 1;

            i = 1; 
            remaining = ses->read_len;
            read_ptr = ses->data;
            link_overhead = Link_Header_Size(Get_Ses_Mode(ses->links_used));

            while (remaining > 0) {
                if ((ses->scat->elements[i].buf = new_ref_cnt(PACK_BODY_OBJ)) == NULL)
                    Alarm(EXIT, "Process_Session_Packet: Could not allocate packet_body\r\n");
                if (remaining + link_overhead + sizeof(fragment_header) > MAX_PACKET_SIZE) {
                    ses->scat->elements[i].len = MAX_PACKET_SIZE - link_overhead - sizeof(fragment_header);
                    memcpy(ses->scat->elements[i].buf, read_ptr, ses->scat->elements[i].len);
                }
                else {
                    ses->scat->elements[i].len = remaining;
                    memcpy(ses->scat->elements[i].buf, read_ptr, remaining);
                }
                read_ptr += ses->scat->elements[i].len;
                remaining -= ses->scat->elements[i].len;
                ses->scat->num_elements++;
                i++;
            }
            
            /* Setup the type field in the Spines packet_header for the signature */
            phdr = (packet_header*) ses->scat->elements[0].buf;
            phdr->type = Get_Link_Data_Type(Get_Ses_Mode(ses->links_used));
            phdr->type = Set_endian(phdr->type);

            /* Prepare and Send the Message */
            return Session_Send_Message(ses);
        }
        else {
            Alarm(PRINT, "Process_Session_Packet: Packed data... not available yet\n");
            Alarm(PRINT, "hdr->len: %d; sizeof(udp_header): %d; ses->read_len: %d\n",
                hdr->len, sizeof(udp_header), ses->read_len);
        }
    }
    return(NO_ROUTE);
}

/***********************************************************/
/* int Session_Send_Message(session *ses)                  */
/*                                                         */
/* Prepares and Sends Message from Session                 */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* ses:  pointer to the session creating this message      */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int) return value                                      */
/*                                                         */
/***********************************************************/
int Session_Send_Message(Session *ses)
{
    udp_header *hdr;
    int i, ret, routing, prot_sig_len = 0;
    unsigned int sign_len;
    stdit ip_it;
    int32 src_id, dst_id;
    sp_time now;
    unsigned char temp_ttl;
    unsigned char temp_path[8];
    unsigned char *path = NULL, *sign_ptr = NULL;
    packet_header *phdr;
    prio_flood_header *f_hdr;
    rel_flood_header *r_hdr;
    sb_header *s_hdr;
    rel_flood_tail *rt;
    EVP_MD_CTX *md_ctx;
    int cr_ret;

    if (ses->scat == NULL)
        return NO_ROUTE;

    /* Setup appropriate pointers */
    phdr = (packet_header*) ses->scat->elements[0].buf;
    hdr = (udp_header*) ses->scat->elements[1].buf;
    routing = ((int) hdr->routing << ROUTING_BITS_SHIFT);

    if (routing == MIN_WEIGHT_ROUTING) {
        /* When regular routing has crypto, this should move into the protocol.c function */
        /* if (Conf_RR.Crypto)... */
    }
    else if (routing == SOURCE_BASED_ROUTING) {
        i = ses->scat->num_elements;
        if ((ses->scat->elements[i].buf = new_ref_cnt(PACK_BODY_OBJ)) == NULL)
            Alarm(EXIT, "Session_Send_Message: Could not allocate packet body for s_hdr\r\n");
        ses->scat->elements[i].len = sizeof(sb_header);
        ses->scat->num_elements++;

        /* Set up source-based sequence number for duplicate detection */
        s_hdr = (sb_header *) ses->scat->elements[i].buf;
        if (routing == SOURCE_BASED_ROUTING) {
            My_Source_Seq++;
            /* Handle wraparound by increasing the incarnation. Since
             * incarnation is based on the seconds part of the current time to
             * handle crash/recoveries, this means we can't send more than 2^32
             * messages per second, but that's not feasible anyway */
            if (My_Source_Seq == 0) {
                My_Source_Seq++;
                My_Source_Incarnation++;
                Alarm(PRINT, "Session_Send_Message: My_Source_Seq rolled over! "
                      "Incrementing incarnation to %u\n", My_Source_Incarnation);
            }
            Alarm(DEBUG, "Sending with source seq %u, incarnation %u\n", My_Source_Seq, My_Source_Incarnation);
            s_hdr->source_seq = My_Source_Seq;
            s_hdr->source_incarnation = My_Source_Incarnation;
        }

        /* Look for the destination (target) of the message in the lookup table */
        if(Is_mcast_addr(hdr->dest) || Is_acast_addr(hdr->dest)) {
            if (ses->disjoint_paths != 0) {
                Alarm(PRINT, "Session_Send_Message: can only do multicast with Flooding\r\n");
                Cleanup_Scatter(ses->scat); ses->scat = NULL;
                return NO_ROUTE;
            }
            dst_id = 0; /* Special case for multicast and anycast packets */
        }
        else {
            stdhash_find(&Node_Lookup_Addr_to_ID, &ip_it, &hdr->dest);
            if (stdhash_is_end(&Node_Lookup_Addr_to_ID,  &ip_it)) {
                Alarm(PRINT, "Session_Send_Message: \
                            destination not in config file\r\n");
                Cleanup_Scatter(ses->scat); ses->scat = NULL;
                return NO_ROUTE;
            }
            dst_id = *(int32u *)stdhash_it_val(&ip_it);
        }

        if (MultiPath_Stamp_Bitmask(dst_id, ses->disjoint_paths, 
                (unsigned char*)((char*)s_hdr + sizeof(sb_header))) == 0)
        {
            Cleanup_Scatter(ses->scat); ses->scat = NULL;
            return NO_ROUTE;
        }
        
        ses->scat->elements[i].len += MultiPath_Bitmask_Size;
    }
    else if (routing == IT_PRIORITY_ROUTING) {
        now = E_get_time();
        
        i = ses->scat->num_elements;
        if ((ses->scat->elements[i].buf = new_ref_cnt(PACK_BODY_OBJ)) == NULL)
            Alarm(EXIT, "Session_Send_Message: Could not allocate packet body for f_hdr\r\n");
        ses->scat->elements[i].len = 0;
        ses->scat->num_elements++;

        f_hdr = (prio_flood_header*) ses->scat->elements[i].buf;
        ses->scat->elements[i].len += sizeof(prio_flood_header);

        if (Path_Stamp_Debug == 1)
            path = ((unsigned char *)ses->scat->elements[1].buf) + sizeof(udp_header) + 16;

        Fill_Packet_Header( (char*)f_hdr, routing, ses->disjoint_paths );
        f_hdr->priority    = ses->priority_lvl;
        f_hdr->origin_sec  = now.sec;
        f_hdr->origin_usec = now.usec;
        f_hdr->expire_sec  = E_add_time(now,ses->expire).sec;
        f_hdr->expire_usec = E_add_time(now,ses->expire).usec;

        /* Check if "overwriting" currently active, if so, overwrite dest */
        if((Is_mcast_addr(hdr->dest) || Is_acast_addr(hdr->dest)) && overwrite_ip != 0)
            hdr->dest = overwrite_ip;
        
        /* Look for the destination (target) of the message in the lookup table */
        if(Is_mcast_addr(hdr->dest) || Is_acast_addr(hdr->dest)) {
            if (ses->disjoint_paths != 0) {
                Alarm(PRINT, "Session_Send_Message: can only do multicast with Flooding\r\n");
                Cleanup_Scatter(ses->scat); ses->scat = NULL;
                return NO_ROUTE;
            }
            dst_id = 0; /* Special case for multicast and anycast packets */
        }
        else {
            stdhash_find(&Node_Lookup_Addr_to_ID, &ip_it, &hdr->dest);
            if (stdhash_is_end(&Node_Lookup_Addr_to_ID,  &ip_it)) {
                Alarm(PRINT, "Session_Send_Message: destination \
                    "IPF" not in config file\n", IP(hdr->dest));
                Cleanup_Scatter(ses->scat); ses->scat = NULL;
                return NO_ROUTE;
            }
            dst_id = *(int32u *)stdhash_it_val(&ip_it);
        }

        if (MultiPath_Stamp_Bitmask(dst_id, ses->disjoint_paths, 
                (unsigned char*)((char*)f_hdr + sizeof(prio_flood_header))) == 0)
        {
            Cleanup_Scatter(ses->scat); ses->scat = NULL;
            return NO_ROUTE;
        }
        
        ses->scat->elements[i].len += MultiPath_Bitmask_Size;
        sign_ptr = (unsigned char*)f_hdr + sizeof(prio_flood_header) + MultiPath_Bitmask_Size;
    }
    else if (routing == IT_RELIABLE_ROUTING) {

        /* Look for the source (originator) of the message in the lookup table */
        stdhash_find(&Node_Lookup_Addr_to_ID, &ip_it, &My_Address);
        if (stdhash_is_end(&Node_Lookup_Addr_to_ID,  &ip_it)) {
            Alarm(PRINT, "Session_Send_Message: source not in config file\r\n");
            Cleanup_Scatter(ses->scat); ses->scat = NULL;
            return(NO_ROUTE);
        }
        src_id = *(int32u *)stdhash_it_val(&ip_it);

        /* Look for the destination of the message in the lookup table */
        stdhash_find(&Node_Lookup_Addr_to_ID, &ip_it, &hdr->dest);
        if (stdhash_is_end(&Node_Lookup_Addr_to_ID,  &ip_it)) {
            Alarm(PRINT, "Session_Send_Message: dest not in config file\r\n");
            Cleanup_Scatter(ses->scat); ses->scat = NULL;
            return(NO_ROUTE);
        }
        dst_id = *(int32u *)stdhash_it_val(&ip_it);

        /* Check if we can send now, or if the flow buffer is full - in this case, *
         *    depending on the session semantics, we will either:
         *    (0) become blocked wait until flow has room and/or handshakes complete 
         *    (1) silently drop messages  */
        if (Reliable_Flood_Can_Flow_Send(ses, dst_id) == 0) {
            if (ses->session_semantics == RELIABLE_STREAM_SESSION) {
                Alarm(DEBUG, "Session_Send_Message: RELIABLE_STREAM SESSION to %d\r\n", dst_id);
                Reliable_Flood_Block_Session(ses, dst_id);
            } else { /* ses->session_semantics == RELIABLE_DGRAM_SESSION_NO_BACKPRESSURE */
                Alarm(PRINT, "Session_Send_Message: RELIABLE_DGRAM_NO_BACKPRESSURE: dropping msg to %d\r\n", dst_id);
                Cleanup_Scatter(ses->scat); ses->scat = NULL;
            }
            return NO_ROUTE;
        }
       
        /* Getting here means that we can send right now */
        i = ses->scat->num_elements;
        if ((ses->scat->elements[i].buf = new_ref_cnt(PACK_BODY_OBJ)) == NULL)
            Alarm(EXIT, "Session_Send_Message: Could not allocate packet body for r_hdr\r\n");
        ses->scat->elements[i].len = 0;
        ses->scat->num_elements++;
        
        r_hdr = (rel_flood_header*) ses->scat->elements[i].buf;
        ses->scat->elements[i].len += sizeof(rel_flood_header);

        if (Path_Stamp_Debug == 1) {
            now = E_get_time();
            path = ((unsigned char *)ses->scat->elements[1].buf) + sizeof(udp_header) + 16;
            *((int*) (((unsigned char *)ses->scat->elements[1].buf) + sizeof(udp_header) + 4)) = htonl(now.sec);
            *((int*) (((unsigned char *)ses->scat->elements[1].buf) + sizeof(udp_header) + 8)) = htonl(now.usec);
        }

        r_hdr->src  = src_id;
        r_hdr->dest = dst_id;
        if (Fill_Packet_Header( (char*)r_hdr, routing, ses->disjoint_paths ) == 0) {
            Cleanup_Scatter(ses->scat); ses->scat = NULL;
            return(NO_ROUTE);
        }

        if (MultiPath_Stamp_Bitmask(dst_id, ses->disjoint_paths, 
                (unsigned char*)((char*)r_hdr + sizeof(rel_flood_header))) == 0) {
            Cleanup_Scatter(ses->scat); ses->scat = NULL;
            return NO_ROUTE;
        }

        ses->scat->elements[i].len += MultiPath_Bitmask_Size;
        sign_ptr = (unsigned char*)r_hdr + sizeof(rel_flood_header) + MultiPath_Bitmask_Size;
    }

    /* Sign Messages */
    if ( (routing == IT_RELIABLE_ROUTING && Conf_Rel.Crypto  == 1)  ||
         (routing == IT_PRIORITY_ROUTING && Conf_Prio.Crypto == 1) )
    {
        cr_ret = BUFF_OK;

        if (routing == IT_RELIABLE_ROUTING)
            prot_sig_len = Rel_Signature_Len;
        else /* routing == IT_PRIORITY_ROUTING */
            prot_sig_len = Prio_Signature_Len;

        /* Sign with Priv_Key */
        temp_ttl = hdr->ttl;
        hdr->ttl = 0;
        if (Path_Stamp_Debug == 1) {
            for (i = 0; i<8; i++) {
                temp_path[i] = path[i];
                path[i] = (unsigned char) 0;
            }
        }

        md_ctx = EVP_MD_CTX_new();
        if (md_ctx==NULL) {
            Alarm(EXIT, "Session_Send_Message: EVP_MD_CTX_new failed\r\n");
        }
        ret = EVP_SignInit(md_ctx, EVP_sha256()); 
        if (ret != 1) {
            Alarm(PRINT, "Session_Send_Message: SignInit failed\r\n");
            Cleanup_Scatter(ses->scat); ses->scat = NULL;
            cr_ret = NO_ROUTE;
            goto cr_return;
        }
        /* Add each part of the message to be signed into the md_ctx */
        /*      Sign over the type in the packet_header */
        ret = EVP_SignUpdate(md_ctx, (unsigned char*)&phdr->type, sizeof(phdr->type));
        /*      Sign over the remaining elements in the message */
        for (i = 1; i < ses->scat->num_elements; i++) {
            ret = EVP_SignUpdate(md_ctx, (unsigned char*)ses->scat->elements[i].buf, ses->scat->elements[i].len);
            if (ret != 1) {
                Alarm(PRINT, "Session_Send_Message: SignUpdate failed\r\n");
                Cleanup_Scatter(ses->scat); ses->scat = NULL;
                cr_ret = NO_ROUTE;
                goto cr_return;
            }
        }
        ret = EVP_SignFinal(md_ctx, sign_ptr, &sign_len, Priv_Key);
        if (ret != 1) {
            Alarm(PRINT, "Session_Send_Message: SignFinal failed\r\n");
            Cleanup_Scatter(ses->scat); ses->scat = NULL;
            cr_ret = NO_ROUTE;
            goto cr_return;
        }
        if (sign_len != prot_sig_len) {
            Alarm(PRINT, "Session_Send_Message: sign_len (%d) != Key_Len (%d)\r\n",
                            sign_len, prot_sig_len);
            Cleanup_Scatter(ses->scat); ses->scat = NULL;
            cr_ret = NO_ROUTE;
            goto cr_return;
        }
        ses->scat->elements[ses->scat->num_elements-1].len += prot_sig_len;
        hdr->ttl = temp_ttl;
        if (Path_Stamp_Debug == 1) {
            for (i = 0; i<8; i++) {
                path[i] = temp_path[i];
            }
        }

        cr_return:
            EVP_MD_CTX_free(md_ctx);
            if (cr_ret != BUFF_OK) return cr_ret;
    }

    /* For Reliable, Add the Hop-By-Hop Tail */
    if (routing == IT_RELIABLE_ROUTING) {
        /* Create the scat element for the reliable_flood tail */
        if ((ses->scat->elements[ses->scat->num_elements].buf = new_ref_cnt(PACK_BODY_OBJ)) == NULL)
            Alarm(EXIT, "Session_Send_Message: Could not allocate packet body for f_hdr\r\n");
        ses->scat->elements[ses->scat->num_elements].len = sizeof(rel_flood_tail);
        rt = (rel_flood_tail*)(ses->scat->elements[ses->scat->num_elements].buf);
        rt->ack_len = 0;
        ses->scat->num_elements++;
    }

    /* Send The Message */
    Injected_Messages++;
    ret = Deliver_and_Forward_Data(ses->scat, Get_Ses_Mode(ses->links_used), NULL);
    Cleanup_Scatter(ses->scat); ses->scat = NULL;
    return ret;
}

/***********************************************************/
/* int Deliver_UDP_Data(sys_scatter* scat, int32u type)    */
/*                                                         */
/* Delivers UDP data to the application                    */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* scat: pointer to the scatter holding the message        */
/* type: the routing scheme this packet is coming from     */
/*        this is used to strip off extra headers          */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int) status of the packet (see udp.h)                  */
/*                                                         */
/***********************************************************/

int Deliver_UDP_Data(sys_scatter *scat, int32u type) {
    udp_header *hdr = NULL;
    stdit h_it, it;
    Session *ses;
    int ret, i, len = 0, num_elements = 0;
    int32 dummy_port;
    Group_State *g_state;
    char *msg = NULL;
    char *write_ptr;

    if ((msg = (char*) new_ref_cnt(MESSAGE_OBJ)) == NULL) {
        Alarm(EXIT, "Deliver_Data(): Cannot allocate message_object\n");
    }
    write_ptr = msg;
    
    switch(type) {
        case (int32u)IT_PRIORITY_ROUTING:
            num_elements = scat->num_elements - 1;
            break;
        case (int32u)IT_RELIABLE_ROUTING:
            num_elements = scat->num_elements - 2;
            break;
        case (int32u)MIN_WEIGHT_ROUTING:
            num_elements = scat->num_elements;
            break;
        case (int32u)SOURCE_BASED_ROUTING:
            num_elements = scat->num_elements - 1;
            break;
    }

    /* Skip the 0th element since it is a garbage spines hdr (packet_header) */
    for (i = 1; i < num_elements; i++) {
        memcpy(write_ptr, scat->elements[i].buf, scat->elements[i].len);
        write_ptr += scat->elements[i].len;
        len += scat->elements[i].len;
    }

    hdr = (udp_header*)(msg);
    dummy_port = (int32)hdr->dest_port;

    /* Check if this is a multicast message */
    if(Is_mcast_addr(hdr->dest) || Is_acast_addr(hdr->dest)) {
        /* Multicast or Anycast.... */
        g_state = (Group_State*)Find_State(&All_Groups_by_Node, My_Address,
                         hdr->dest);
        if(g_state == NULL) {
            dec_ref_cnt(msg);
            return(NO_ROUTE);
        }
        if((g_state->status & ACTIVE_GROUP) == 0) {
            dec_ref_cnt(msg);
            return(NO_ROUTE);
        }

        /* NOTE: we iterate over joined_sessions delivering data, however,
           on error we may need to remove some of the joined sessions during the iteration
           which can break a normal iteration if the table reallocs.  So, we disallow it
           to realloc during this iteration
        */           

        stdhash_set_opts(&g_state->joined_sessions, STDHASH_OPTS_NO_AUTO_SHRINK | STDHASH_OPTS_NO_AUTO_GROW);

        /* Ok, this is best effort multicast. */
        ret = NO_ROUTE;
        stdhash_begin(&g_state->joined_sessions, &it);
        while(!stdhash_is_end(&g_state->joined_sessions, &it)) {
            ses = *((Session **)stdhash_it_val(&it));
            stdhash_it_next(&it);      /* NOTE: we do this before we call deliver to keep iterator valid in case the item is deleted */
            
            if( hdr->source != My_Address || ses->port != hdr->source_port || ses->multicast_loopback == 1)
                /* IT Site Multicast Trick (above) replaces below */
                /* (hdr->source == My_Address && ses->multicast_loopback == 1)) */
            {
                ret = Session_Deliver_Data(ses, msg, len, type, ses->deliver_flag);
                /* If using anycast (and not experimental IT SCADA mcast), deliver to only one. */
                if (Is_acast_addr(hdr->dest))
                     break;
            }
        }

        stdhash_set_opts(&g_state->joined_sessions, STDHASH_OPTS_DEFAULTS);

        dec_ref_cnt(msg);
        return ret;
    }

    /* If I got here, this is not multicast */

    stdhash_find(&Sessions_Port, &h_it, &dummy_port);

    if(stdhash_is_end(&Sessions_Port, &h_it)) {
        dec_ref_cnt(msg);
        return(NO_ROUTE);
    }


    ses = *((Session **)stdhash_it_val(&h_it));


    if(ses->type == RELIABLE_SES_TYPE) {
        /* This is a reliable session */
        ret = Deliver_Rel_UDP_Data(msg, len, type);

        dec_ref_cnt(msg);
        return(ret);
    }


    /* This is either a regular UDP message or a connect request for Listen/Accept */

    if(ses->type == LISTEN_SES_TYPE) {
        /* This is a connect request as it addresses a listen session */
        /* Check whether is a double request. If not, the message will be delivered to
         * the client for an accept. */

        if(Check_Double_Connect(msg, len, type)) {
            dec_ref_cnt(msg);
            return(BUFF_DROP);
        }
    }

    if(ses->client_stat == SES_CLIENT_OFF) {
        dec_ref_cnt(msg);
        return(BUFF_DROP);
    }

    ret = Session_Deliver_Data(ses, msg, len, type, ses->deliver_flag);

    dec_ref_cnt(msg);
    return(ret);
}






/***********************************************************/
/* int Session_Deliver_Data(Session *ses, char* buff,      */
/*                          int16u len, int32u type,       */
/*                          int flags)                     */
/*                                                         */
/* Sends the data to the application                       */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* ses:  session where to deliver data                     */
/* buff: pointer to the UDP packet                         */
/* len:  length of the packet                              */
/* flags: when buffer is full, drop the packet (1) or      */
/*        close the session (2)                            */
/*        force sending on the tcp socket (3)              */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int) status of the packet (see udp.h)                  */
/*                                                         */
/***********************************************************/

int Session_Deliver_Data(Session *ses, char* buff, int16u len, int32u type, int flags) 
{
    UDP_Cell *u_cell;
    sys_scatter scat;
    int32 total_bytes;
    int ret, found_frag_packet, cnt, i, j, stop_flag;
    int32 sum_len, send_len;
    udp_header *u_hdr;
    udp_header *first_frag_udp_hdr = NULL;
    Frag_Packet *frag_pkt;
    sp_time now;
    int32 *pkt_no;
    sp_time *t1, send_time, diff;
    int32 oneway_time;
    char line[120];
    

    u_hdr = (udp_header *)buff;

#if 0
    Alarm(PRINT, "Session_Deliver_Data: src_port: %d; sess_id: %d; len: %d; len_rep: %d; seq_no: %d; frag_num: %d; frag_idx: %d\n",
          u_hdr->source_port, u_hdr->sess_id, u_hdr->len, len, u_hdr->seq_no, 
          u_hdr->frag_num, u_hdr->frag_idx);
#endif

    if(ses->routing_used == MIN_WEIGHT_ROUTING || ses->routing_used == SOURCE_BASED_ROUTING) {
        if(u_hdr->frag_num > 1) {
            /* This is a fragmented packet */

            now = E_get_time();

            /* Search for other fragments of the same packet */
            found_frag_packet = FALSE;
            cnt = 0;
            frag_pkt = ses->frag_pkts;
            while(frag_pkt != NULL) {
                if(now.sec - frag_pkt->timestamp_sec > FRAG_TTL) {
                    /* This is an old incomplete packet. Discard it */
            
                    Alarm(DEBUG, "Old incomplete packet. Delete it\n");

                    frag_pkt = Delete_Frag_Element(&ses->frag_pkts, frag_pkt);
                    continue;
                }

                /* This is not an expired packet */

                cnt++;
                if((frag_pkt->sess_id == u_hdr->sess_id)&&
                   (frag_pkt->sender == u_hdr->source)&&
                   (frag_pkt->snd_port == u_hdr->source_port)&&
                   (frag_pkt->seq_no == u_hdr->seq_no)) {

                    /* This is a fragmented packet that we were looking for */

                    Alarm(DEBUG, "Found the packet\n");

                    if((frag_pkt->scat.num_elements != u_hdr->frag_num)||
                       (frag_pkt->scat.elements[(int)(u_hdr->frag_idx)].buf != NULL)) {

                        Alarm(DEBUG, "Corrupt packet. Delete it\n");

                        Delete_Frag_Element(&ses->frag_pkts, frag_pkt);
                        return(BUFF_DROP);
                    }

                    /* Insert the fragment into the packet */

                    frag_pkt->scat.elements[(int)(u_hdr->frag_idx)].buf = buff;
                    inc_ref_cnt(buff);
                    frag_pkt->scat.elements[(int)(u_hdr->frag_idx)].len = u_hdr->len + sizeof(udp_header);
                    frag_pkt->recv_elements++;
                    frag_pkt->timestamp_sec = now.sec;
                    found_frag_packet = TRUE;
                    break;
                }
                frag_pkt = frag_pkt->next;
            }

            if(found_frag_packet == FALSE) {
                Alarm(DEBUG, "Couldn't find a fragmented packet. Total: %d; Create a new one\n", cnt);

                cnt++;
                if((frag_pkt = new(FRAG_PKT)) == NULL) {
                    Alarm(EXIT, "Could not allocate memory\n");
                }
            
                frag_pkt->scat.num_elements = u_hdr->frag_num;

                for(i=0; i<u_hdr->frag_num; i++) {
                    frag_pkt->scat.elements[i].buf = NULL;
                }
                frag_pkt->scat.elements[(int)(u_hdr->frag_idx)].buf = buff;
                inc_ref_cnt(buff);
                frag_pkt->scat.elements[(int)(u_hdr->frag_idx)].len = u_hdr->len + sizeof(udp_header);

                frag_pkt->recv_elements = 1;
                frag_pkt->sess_id = u_hdr->sess_id;
                frag_pkt->seq_no = u_hdr->seq_no;
                frag_pkt->snd_port = u_hdr->source_port;
                frag_pkt->sender = u_hdr->source;
                frag_pkt->timestamp_sec = now.sec;
                
                /* Insert the fragmented packet into the linked list */
                if(ses->frag_pkts != NULL) {
                    ses->frag_pkts->prev = frag_pkt;
                }
                frag_pkt->next = ses->frag_pkts;
                frag_pkt->prev = NULL;
                ses->frag_pkts = frag_pkt;
            }
     
            /* Deliver the packet if it is complete */
            if(frag_pkt->recv_elements == frag_pkt->scat.num_elements) {
                Alarmp(SPLOG_DEBUG, SESSION, "Session_Deliver_Data: Fragmented Packet complete\n");

                /* Calculate total non-fragmented message/packet length */
                sum_len = sizeof(udp_header);
                for(i=0; i<frag_pkt->scat.num_elements; i++) {
                    sum_len += (frag_pkt->scat.elements[i].len - sizeof(udp_header));
                }

                Alarmp(SPLOG_DEBUG, SESSION, "Total length of fragmented packet: sum_len: %d\n", sum_len);

                /* Deliver the packet */
                if((ses->udp_port != -1)&&(flags != 3)) {
                    udp_header *udp_head_buf;

                    /* The session communicates via UDP */

                    /* Build UDP scatter to send */
                    /* Scatter layout:
                     * [0] (int32) total length
                     * [1] (udp_header) 
                     * [2] original first data packet payload
                     * [3..n] original 2..n-2 data packet payloads
                     */

                    scat.num_elements = frag_pkt->scat.num_elements+2;

                    scat.elements[0].len = sizeof(int32);
                    scat.elements[0].buf = (char*)(&sum_len);

                    if ((udp_head_buf = (udp_header*) new_ref_cnt(PACK_BODY_OBJ)) == NULL) {
                        Alarm(EXIT, "Session_Deliver_Data: Failed to allocate packet_body to hold copy of udp_header for fragmented delivery of UDP message.\n");
                    }

                    Copy_udp_header((udp_header *)frag_pkt->scat.elements[0].buf, udp_head_buf );
                    udp_head_buf->len = sum_len;

                    scat.elements[1].buf = (char*) udp_head_buf;
                    scat.elements[1].len = sizeof(udp_header);

                    for(i=0, j=2; i<frag_pkt->scat.num_elements; i++, j++) {
                        scat.elements[j].buf = frag_pkt->scat.elements[i].buf + sizeof(udp_header);
                        scat.elements[j].len = frag_pkt->scat.elements[i].len - sizeof(udp_header);
                    }

                    /* Send message and unref message body */

                    ret = DL_send(Ses_UDP_Channel,  ses->udp_addr, ses->udp_port,  &scat);

                    Alarm(DEBUG,
                            "|||||||||||||||||||| Sending packet for dest (%d.%d.%d.%d) to client addr (%d@%d.%d.%d.%d)!\r\n",
                      IP1(u_hdr->dest), IP2(u_hdr->dest), IP3(u_hdr->dest), IP4(u_hdr->dest),
                      ses->udp_port, IP1(ses->udp_addr), IP2(ses->udp_addr), IP3(ses->udp_addr), IP4(ses->udp_addr));

                    Delete_Frag_Element(&ses->frag_pkts, frag_pkt);
                    dec_ref_cnt(udp_head_buf);
                    return(BUFF_EMPTY);
                }
                else {
                    /* The session communicates via TCP */

                    Alarmp(SPLOG_DEBUG, SESSION, "Session_Deliver_Data: TCP-based session\n");

                    for(i=0; i<frag_pkt->scat.num_elements; i++) {
                        /* Try to deliver all the fragments, one by one */

                        /* If there is already something in the buffer, put this one too */
                        if(!stdcarr_empty(&ses->rel_deliver_buff)) {

                            Alarmp(SPLOG_DEBUG, SESSION, "Session_Deliver_Data: (TCP) There are (%d) packets in the session buffer already\n",
                                   stdcarr_size(&ses->rel_deliver_buff));

                            if(i == 0) {
                                if(stdcarr_size(&ses->rel_deliver_buff) >= 3*MAX_BUFF_SESS) {
                                    /* disconnect the session or drop the packet */
                                    if (flags == 1) {
                        
                                        Alarmp(SPLOG_ERROR, SESSION, "Session_Deliver_Data: (TCP) === Drop packet because session buffer full\n");

                                        Delete_Frag_Element(&ses->frag_pkts, frag_pkt);
                                        return(BUFF_DROP);
                                    } 
                                    else if ((flags == 2)||(flags == 3)) {
                                        /* disconnect */
                                        Session_Close(ses->sess_id, SES_BUFF_FULL);
                                        return(NO_BUFF);
                                    }
                                }			
                            }
                
                            if((u_cell = (UDP_Cell*) new(UDP_CELL))==NULL) {
                                Alarmp(SPLOG_FATAL, SESSION, "Session_Deliver_Data(): Cannot allocate udp cell\n");
                            }
                            u_cell->len = frag_pkt->scat.elements[i].len;
                            u_cell->total_len = sum_len;
                            u_cell->buff = frag_pkt->scat.elements[i].buf;
                            stdcarr_push_back(&ses->rel_deliver_buff, &u_cell);
                            inc_ref_cnt(frag_pkt->scat.elements[i].buf);

                            Alarmp(SPLOG_DEBUG, SESSION, "Session_Deliver_Data: (TCP) Inserted fragment into session buffer\n");
                            continue;
                        }

                        /* There is nothing in the buffer. Try to deliver the fragment */
                        total_bytes = frag_pkt->scat.elements[i].len + sizeof(int32);
                        if(i == 0) {
                            ses->sent_bytes = 0;
                            if ((first_frag_udp_hdr = (udp_header*) new_ref_cnt(PACK_BODY_OBJ)) == NULL) {
                                Alarm(EXIT, "Session_Deliver_Data: Failed to allocate packet_body to hold copy of udp_header for fragmentd delivery.\n");
                            }
                            Copy_udp_header((udp_header *)frag_pkt->scat.elements[0].buf, first_frag_udp_hdr );
                            first_frag_udp_hdr->len = sum_len - sizeof(udp_header);
                        }
                        else {
                            ses->sent_bytes = sizeof(udp_header) + sizeof(int32);
                        }
                        stop_flag = 0;
                        while((ses->sent_bytes < total_bytes)&&(stop_flag == 0)) {
                            if(ses->sent_bytes < sizeof(int32)) {
                                scat.num_elements = 3;
                                scat.elements[0].len = sizeof(int32) - ses->sent_bytes;
                                scat.elements[0].buf = ((char*)(&sum_len)) + ses->sent_bytes;
                                scat.elements[1].len = sizeof(udp_header);
                                scat.elements[1].buf = (char *) first_frag_udp_hdr;
                                scat.elements[2].len = frag_pkt->scat.elements[0].len - sizeof(udp_header);
                                scat.elements[2].buf = frag_pkt->scat.elements[0].buf + sizeof(udp_header);
                            }
                            else if (ses->sent_bytes < (sizeof(udp_header) + sizeof(int32)) ) {
                                scat.num_elements = 2;
                                scat.elements[0].len = sizeof(udp_header) - (ses->sent_bytes- sizeof(int32));
                                scat.elements[0].buf = ((char*)(first_frag_udp_hdr)) + (ses->sent_bytes - sizeof(int32));
                                scat.elements[1].len = frag_pkt->scat.elements[0].len - sizeof(udp_header);
                                scat.elements[1].buf = frag_pkt->scat.elements[0].buf + sizeof(udp_header);
                            } else {
                                scat.num_elements = 1;
                                scat.elements[0].len = frag_pkt->scat.elements[i].len - (ses->sent_bytes - sizeof(int32));
                                scat.elements[0].buf = frag_pkt->scat.elements[i].buf + (ses->sent_bytes - sizeof(int32));
                            }

                            /* The session communicates via TCP */
                            ret = DL_send_connected(ses->sk,  &scat);

                            Alarm(DEBUG,"Session_deliver_data(): %d %d %d %d\n",
                                  ret, ses->sk, ses->port, frag_pkt->scat.elements[i].len);

                            if(ret < 0) {
                                Alarm(PRINT, "Session_Deliver_Data(): write err %d %d '%s'\n", 
                                                    ret, errno, strerror(errno));
#ifndef	ARCH_PC_WIN95
                                if((ret == -1)&&((errno == EWOULDBLOCK)||(errno == EAGAIN)))
#else
#ifndef _WIN32_WCE
                                if((ret == -1)&&((errno == WSAEWOULDBLOCK)||(errno == EAGAIN)))
#else
                                int sk_errno = WSAGetLastError();
                                if((ret == -1)&&((sk_errno == WSAEWOULDBLOCK)||(sk_errno == EAGAIN)))
#endif /* Windows CE */
#endif
                                {
                                    if((u_cell = (UDP_Cell*) new(UDP_CELL))==NULL) {
                                        Alarm(EXIT, "Deliver_UDP_Data(): Cannot allocate udp cell\n");
                                    }
                                    u_cell->len = frag_pkt->scat.elements[i].len;
                                    u_cell->buff = frag_pkt->scat.elements[i].buf;
                                    u_cell->total_len = sum_len;
                                    stdcarr_push_back(&ses->rel_deliver_buff, &u_cell);
                                    inc_ref_cnt(frag_pkt->scat.elements[i].buf);

                                    E_attach_fd(ses->sk, WRITE_FD, Session_Write, ses->sess_id, NULL, HIGH_PRIORITY);
                                    ses->fd_flags = ses->fd_flags | WRITE_DESC;
                                    stop_flag = 1;
                                    break;
                                }
                                else {
                                    if (i == 0)
                                        dec_ref_cnt(first_frag_udp_hdr); /* free udp_header */
                                    Session_Close(ses->sess_id, SOCK_ERR);
                                    return(NO_BUFF);
                                }
                            }
                            if(ret == 0) {
                                Alarm(PRINT, "Error: ZERO write 1; sent: %d, total: %d\n", ses->sent_bytes, total_bytes);
                            }
                            ses->sent_bytes += ret;
                        }
                        if(stop_flag == 0) {
                            if(i == frag_pkt->scat.num_elements - 1) {	
                                ses->sent_bytes = 0;
                            }
                            else {
                                ses->sent_bytes = sizeof(udp_header) + sizeof(int32);
                            }
                        }
                        if (i == 0)
                            dec_ref_cnt(first_frag_udp_hdr); /* free udp_header */
                    }
                }
                Delete_Frag_Element(&ses->frag_pkts, frag_pkt);
            }
            if(stdcarr_empty(&ses->rel_deliver_buff)) {
                return(BUFF_EMPTY);
            }
            else {
                return(BUFF_OK);	
            }
        }

    }

    /* If we got here this is not a fragmented packet. We can send it directly */

    if(ses->recv_fd_flag == 1) {
        /* This is a log-only session */
        
        pkt_no = (int32*)(buff+sizeof(udp_header)+sizeof(int32));
        if(*pkt_no == -1) {
            Session_Close(ses->sess_id, SES_BUFF_FULL);
            return(NO_BUFF);
        }

        t1 = (sp_time*)(buff+sizeof(udp_header)+2*sizeof(int32));
        send_time = *t1;
        now = E_get_time();
        diff = E_sub_time(now, send_time);
        oneway_time = diff.usec + diff.sec*1000000;

        sprintf(line, "%d\t%d\n", *pkt_no, oneway_time);
        
        write(ses->fd, line, strlen(line));
        
        return(BUFF_EMPTY);
    }


    if((ses->udp_port == -1)||(flags == 3)) {
        /* The session communicates via TCP */
        if(!stdcarr_empty(&ses->rel_deliver_buff)) {
            if(stdcarr_size(&ses->rel_deliver_buff) >= 3*MAX_BUFF_SESS) {
                /* disconnect the session or drop the packet */
                if (flags == 1) {
                    return(BUFF_DROP);
                } 
                else if ((flags == 2)||(flags == 3)) {
                    /* disconnect */
                    Session_Close(ses->sess_id,SES_BUFF_FULL);
                    return(NO_BUFF);
                }
            }
            
            if((u_cell = (UDP_Cell*) new(UDP_CELL))==NULL) {
                Alarm(EXIT, "Deliver_UDP_Data(): Cannot allocate udp cell\n");
            }
            u_cell->total_len = len;
            u_cell->len = len;
            u_cell->buff = buff;
            stdcarr_push_back(&ses->rel_deliver_buff, &u_cell);
            inc_ref_cnt(buff);
            return(BUFF_OK);
        }
    }


    /* If I got up to here, the buffer is empty or we send via UDP.
     * Let's see if we can send this packet */
    total_bytes = sizeof(int32) + len;
    send_len = len;
    ses->sent_bytes = 0;
    while(ses->sent_bytes < total_bytes) {
        if(ses->sent_bytes < sizeof(int32)) {
            scat.num_elements = 2;
            scat.elements[0].len = sizeof(int32) - ses->sent_bytes;
            scat.elements[0].buf = ((char*)(&send_len)) + ses->sent_bytes;
            scat.elements[1].len = send_len;
            scat.elements[1].buf = buff;
        }
        else {
            scat.num_elements = 1;
            scat.elements[0].len = send_len - (ses->sent_bytes - sizeof(int32));
            scat.elements[0].buf = buff + (ses->sent_bytes - sizeof(int32));
        }
        if((ses->udp_port == -1)||(flags == 3)) {
            /* The session communicates via TCP */
            ret = DL_send_connected(ses->sk, &scat);
        }
        else {

          /* The session communicates via UDP */
          ret = DL_send(Ses_UDP_Channel,  ses->udp_addr, ses->udp_port,  &scat);

          Alarm(DEBUG,
                "|||||||||||||||||||| Sending packet for dest (%d.%d.%d.%d) to client addr (%d@%d.%d.%d.%d)!\r\n",
                IP1(u_hdr->dest), IP2(u_hdr->dest), IP3(u_hdr->dest), IP4(u_hdr->dest),
                ses->udp_port, IP1(ses->udp_addr), IP2(ses->udp_addr), IP3(ses->udp_addr), IP4(ses->udp_addr));
        }

        Alarm(DEBUG,"Session_deliver_data(): %d %d %d %d\n",ret,ses->sk,ses->port, send_len);

        if(ret < 0) {  /* JLS: shouldn't blocking only occur if/when using TCP session? */
             Alarm(DEBUG, "Session_Deliver_Data(): write err\n");
#ifndef        ARCH_PC_WIN95
            if((ret == -1)&&
               ((errno == EWOULDBLOCK)||(errno == EAGAIN)))
#else
#ifndef _WIN32_WCE
            if((ret == -1)&&
               ((errno == WSAEWOULDBLOCK)||(errno == EAGAIN)))
#else
            int sk_errno = WSAGetLastError();
            if((ret == -1)&&
               ((sk_errno == WSAEWOULDBLOCK)||(sk_errno == EAGAIN)))
#endif /* Windows CE */
#endif
            {
                if((u_cell = (UDP_Cell*) new(UDP_CELL))==NULL) {
                    Alarm(EXIT, "Deliver_UDP_Data(): Cannot allocate udp cell\n");
                }
                u_cell->total_len = len;
                u_cell->len = len;
                u_cell->buff = buff;
                stdcarr_push_back(&ses->rel_deliver_buff, &u_cell);
                inc_ref_cnt(buff);

                E_attach_fd(ses->sk, WRITE_FD, Session_Write, ses->sess_id,
                            NULL, HIGH_PRIORITY );
                ses->fd_flags = ses->fd_flags | WRITE_DESC;
                return(BUFF_OK);
            }
            else {
                if(ses->r_data == NULL) {
                    Session_Close(ses->sess_id, SOCK_ERR);
                }
                else {
                    Disconnect_Reliable_Session(ses);
                }
                return(BUFF_DROP);
            }
        }
        if(ret == 0) {
            Alarm(PRINT, "Error: ZERO write 1; sent: %d, total: %d\n",
                  ses->sent_bytes, total_bytes);

        }
        ses->sent_bytes += ret;
    }
    ses->sent_bytes = 0;
    return(BUFF_EMPTY);
}




/***********************************************************/
/* void Session_Write(int sk, int sess_id, void* dummy_p)  */
/*                                                         */
/* Called by the event system when the socket is again     */
/* ready for writing (after it was blocked)                */
/*                                                         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* sk:      socket to the application                      */
/* sess_id: id of the session                              */
/* dummy_p: not used                                       */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Session_Write(int sk, int sess_id, void *dummy_p)
{
    UDP_Cell *u_cell;
    sys_scatter scat;
    stdit it;
    stdit h_it;
    int32 len;
    rel_udp_pkt_add *r_add;
    Session *ses;
    char *buff;
    int32 total_bytes, data_bytes, send_bytes;
    int ret;
    udp_header *u_hdr;
    udp_header *first_frag_udp_hdr = NULL;


    /* Find the session. This is not the session that I read packets from,
     * but rather the one I'm trying to write data to. */

    stdhash_find(&Sessions_ID, &h_it, &sess_id);
    if(stdhash_is_end(&Sessions_ID, &h_it)) {
        /* The session is gone */
        return;
    }

    ses = *((Session **)stdhash_it_val(&h_it));

    if(ses->sess_id != (unsigned int)sess_id) {
        /* There's another session here, and it just uses the same socket */
        return;
    }

    if(ses->fd_flags & WRITE_DESC) {
        E_detach_fd(sk, WRITE_FD);
        ses->fd_flags = ses->fd_flags ^ WRITE_DESC;
    }
    else{
        Alarm(EXIT, "Session_Write():socket was not set for WRITE_FD\n");
    }

    if(ses->client_stat == SES_CLIENT_OFF)
        return;

    while(!stdcarr_empty(&ses->rel_deliver_buff)) {
        stdcarr_begin(&ses->rel_deliver_buff, &it);

        u_cell = *((UDP_Cell **)stdcarr_it_val(&it));
        buff = u_cell->buff;
        u_hdr = (udp_header*)buff;

        /*        get_ref_cnt(buff); */
        len = u_cell->len;

        if(ses->r_data != NULL) {
            if (ses->sent_bytes == 0) {
                ses->sent_bytes = sizeof(udp_header) + sizeof(rel_udp_pkt_add) + sizeof(int32);
            }

            r_add = (rel_udp_pkt_add*)(buff + sizeof(udp_header));
            data_bytes = len - r_add->ack_len;
            total_bytes = sizeof(int32) + data_bytes;
            Alarm(DEBUG, "Reliable session !!!  %d : %d\n", r_add->data_len, r_add->ack_len);
        }
        else {
            data_bytes = len;
            total_bytes = sizeof(int32) + len;
        }
        if (ses->routing_used == MIN_WEIGHT_ROUTING) {
            if((u_hdr->frag_num > 1)&&(u_hdr->frag_idx == 0)) {
                send_bytes = u_cell->total_len;
                if ((first_frag_udp_hdr = (udp_header*) new_ref_cnt(PACK_BODY_OBJ)) == NULL) {
                    Alarm(EXIT, "Session_Write: Failed to allocate packet_body to hold copy of udp_header for fragmented delivery.\n");
                }
                Copy_udp_header((udp_header *) buff, first_frag_udp_hdr );
                first_frag_udp_hdr->len = u_cell->total_len - sizeof(udp_header);
            }
            else {
                send_bytes = data_bytes;
            }
        }
        else
            send_bytes = data_bytes;

        while(ses->sent_bytes < total_bytes) {
            udp_header *send_hdr = (first_frag_udp_hdr == NULL ? u_hdr : first_frag_udp_hdr);

            if(ses->sent_bytes < sizeof(int32)) {
                scat.num_elements = 3;
                scat.elements[0].len = sizeof(int32) - ses->sent_bytes;
                scat.elements[0].buf = ((char*)(&send_bytes)) + ses->sent_bytes;
                scat.elements[1].len = sizeof(udp_header);
                scat.elements[1].buf = (char *) send_hdr;
                scat.elements[2].len = data_bytes - sizeof(udp_header);
                scat.elements[2].buf = buff + sizeof(udp_header);
            }
            else if (ses->sent_bytes < (sizeof(udp_header) + sizeof(int32)) ) {
                scat.num_elements = 2;
                scat.elements[0].len = sizeof(udp_header) - (ses->sent_bytes- sizeof(int32));
                scat.elements[0].buf = (char *) send_hdr + (ses->sent_bytes - sizeof(int32));
                scat.elements[1].len = data_bytes - sizeof(udp_header);
                scat.elements[1].buf = buff + sizeof(udp_header);
            } else {
                scat.num_elements = 1;
                scat.elements[0].len = data_bytes - sizeof(udp_header) - (ses->sent_bytes - sizeof(int32) - sizeof(udp_header));
                scat.elements[0].buf = buff + sizeof(udp_header) + (ses->sent_bytes - sizeof(int32) - sizeof(udp_header));
            }

            ret = DL_send_connected(ses->sk,  &scat);

            Alarm(DEBUG, "Session_Write(): ret = %d; sk = %d; port = %d; len = %d; sent_bytes = %d; total_bytes = %d\n", ret, ses->sk, ses->port, len, ses->sent_bytes, total_bytes);

            if(ret < 0) {
                Alarm(DEBUG, "Session_WRITE(): write err %d %d '%s'\n", ret, errno, strerror(errno));
#ifndef        ARCH_PC_WIN95
                if((ret == -1)&&
                   ((errno == EWOULDBLOCK)||(errno == EAGAIN)))
#else
#ifndef _WIN32_WCE
                if((ret == -1)&&
                   ((errno == WSAEWOULDBLOCK)||(errno == EAGAIN)))
#else
                int sk_errno = WSAGetLastError();
                if((ret == -1)&&
                   ((sk_errno == WSAEWOULDBLOCK)||(sk_errno == EAGAIN)))
#endif /* Windows CE */
#endif
                {
                    E_attach_fd(ses->sk, WRITE_FD, Session_Write, ses->sess_id,
                                NULL, HIGH_PRIORITY );
                    ses->fd_flags = ses->fd_flags | WRITE_DESC;
                    if (first_frag_udp_hdr != NULL) {
                        dec_ref_cnt(first_frag_udp_hdr);
                        first_frag_udp_hdr = NULL;
                    }
                    return;
                }
                else {
                    if(ses->r_data == NULL) {
                        Session_Close(ses->sess_id, SOCK_ERR);
                    }
                    else {
                        Disconnect_Reliable_Session(ses);
                    }
                    if (first_frag_udp_hdr != NULL) {
                        dec_ref_cnt(first_frag_udp_hdr);
                        first_frag_udp_hdr = NULL;
                    }
                    return;
                }
            }
            if(ret == 0) {
                Alarm(PRINT, "Error: ZERO write 2; sent: %d, total: %d\n",
                      ses->sent_bytes, total_bytes);
                if (first_frag_udp_hdr != NULL) {
                    dec_ref_cnt(first_frag_udp_hdr);
                    first_frag_udp_hdr = NULL;
                }
                return;
            }
            ses->sent_bytes += ret;
        }
        if (ses->routing_used == MIN_WEIGHT_ROUTING) {
            if(ses->r_data == NULL && u_hdr->frag_num > 1 && (u_hdr->frag_idx < u_hdr->frag_num -1)) {
                Alarm(DEBUG, "Session_Write: Not the last Fragmented Packet," 
                             " seq = %d, %d of %d, send_bytes = %d, total_bytes = %d\n", 
                             u_hdr->seq_no, u_hdr->frag_idx, u_hdr->frag_num, ses->sent_bytes, total_bytes);
                ses->sent_bytes = sizeof(udp_header) + sizeof(int32);
            }
            else {
                ses->sent_bytes = 0;
            }
        }
        else 
            ses->sent_bytes = 0;

        if (first_frag_udp_hdr != NULL) {
            dec_ref_cnt(first_frag_udp_hdr);
            first_frag_udp_hdr = NULL;
        }
        dec_ref_cnt(buff);
        dispose(u_cell);
        stdcarr_pop_front(&ses->rel_deliver_buff);
    }

    /* Send an ack if the sender was blocked */
    if(ses->r_data != NULL) {
        if(stdcarr_size(&ses->rel_deliver_buff) < MAX_BUFF_SESS/2) {
            Alarm(DEBUG, "Session_Write(): sending ack: %d\n",
                  stdcarr_size(&ses->rel_deliver_buff));
            E_queue(Ses_Send_Ack, ses->sess_id, NULL, zero_timeout);
        }
    }


    /* Check if this is a disconnected reliable session */
    if(ses->r_data != NULL) {
        if(ses->r_data->connect_state == DISCONNECT_LINK) {
            if(ses->r_data->recv_tail == ses->r_data->last_seq_sent) {
                if(stdcarr_empty(&ses->rel_deliver_buff)) {
                    Disconnect_Reliable_Session(ses);
                }
            }
        }
    }
}



/***********************************************************/
/* void Ses_Send_ID(Session* ses)                          */
/*                                                         */
/* Sends to a session its own ID + port + addr it          */
/*      is assigned                                        */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* ses:     session                                        */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Ses_Send_ID(Session *ses) 
{
    char *buf;
    int32 *ses_id;
    int32 *vport;
    int32 *vaddr;
    udp_header *u_hdr;

    buf = (char *) new_ref_cnt(PACK_BODY_OBJ);
    if(buf == NULL) {
        Alarm(EXIT, "Session_UDP_Read: Cannot allocate buffer\n");
    }

    u_hdr = (udp_header*)buf;
    u_hdr->source = 0;
    u_hdr->dest = 0;
    u_hdr->source_port = 0;
    u_hdr->dest_port = 0;
    u_hdr->len = 3 * sizeof(int32); /* sess ID + virtual port + virtual address */
    u_hdr->seq_no = 0;
    u_hdr->frag_num = 1;
    u_hdr->frag_idx = 0;
    u_hdr->sess_id = 0;

    ses_id = (int32*)(buf+sizeof(udp_header));
    *ses_id = ses->sess_id;

    vport   = (int32 *)(buf+sizeof(udp_header)+sizeof(ses->sess_id));
    *vport  = ses->port;

    vaddr   = (int32 *)(buf+sizeof(udp_header)+sizeof(ses->sess_id)+sizeof(int32));
    *vaddr  = My_Address;

    Session_Deliver_Data(ses, buf, sizeof(udp_header)+(3*sizeof(int32)), 0, 3);
    dec_ref_cnt(buf);
}




/***********************************************************/
/* void Ses_Send_ERR(int address, int port)                */
/*                                                         */
/* Sends to a SOCK_DGRAM client that it should be closed   */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* address:   address of the client                        */
/* port:      port of the client                           */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Ses_Send_ERR(int address, int port) 
{
    sys_scatter scat;
    udp_header u_hdr;
    int32 len;

    len = sizeof(udp_header);
    scat.num_elements = 2;
    scat.elements[0].len = sizeof(int32);
    scat.elements[0].buf = (char*)&len;
    scat.elements[1].len = sizeof(udp_header);
    scat.elements[1].buf = (char*)&u_hdr;
   
    u_hdr.dest = -1;

    DL_send(Ses_UDP_Channel, address, port, &scat);
}


/***********************************************************/
/* void Session_UDP_Read(int sk, int dmy, void *dmy_p)     */
/*                                                         */
/* Receive data from a DGRAM socket                        */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* sk:      socket                                         */
/* dmy:     not used                                       */
/* dmy_p:   not used                                       */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Session_UDP_Read(int sk, int dmy, void * dmy_p) 
{
    int received_bytes;
    Session *ses;
    stdit it;
    int32 sess_id, rnd_num;
    udp_header *u_hdr;
    char *tmp_buf;
    int i, processed_bytes, bytes_to_send;

    int32 recvfrom_address;    /* address from which this packet was
                                  received */
    int16u recvfrom_port;      /* port from which this packet was
                                  received */

    Ses_UDP_Pack.num_elements = 52;
    Ses_UDP_Pack.elements[0].len = sizeof(int32);
    Ses_UDP_Pack.elements[0].buf = (char *)&sess_id;
    Ses_UDP_Pack.elements[1].len = sizeof(int32);
    Ses_UDP_Pack.elements[1].buf = (char *)&rnd_num;
    Ses_UDP_Pack.elements[2].len = MAX_SPINES_MSG+sizeof(udp_header);
    Ses_UDP_Pack.elements[2].buf = frag_buf[0]                   ;
    for(i=1; i<50; i++) {
            Ses_UDP_Pack.elements[i+2].len = MAX_SPINES_MSG;
            Ses_UDP_Pack.elements[i+2].buf = frag_buf[i]+sizeof(udp_header);
    }

    received_bytes = DL_recvfrom(sk, &Ses_UDP_Pack, &recvfrom_address,
            &recvfrom_port );
    received_bytes -= (2*sizeof(int32));

    /* TODO: do/can these two Ses_Send_ERR send an error to all Multicast clients, which probably would be a bad thing? */

    u_hdr = (udp_header*)frag_buf[0];
    stdhash_find(&Sessions_ID, &it, &sess_id);
    if(stdhash_is_end(&Sessions_ID, &it)) {
        /* The session is gone */
        Alarm(PRINT, "The session is gone\n");
        Ses_Send_ERR(u_hdr->source, u_hdr->source_port);
        return;
    }

    ses = *((Session **)stdhash_it_val(&it));

    /* Hack -- TODO needs to be done correctly. The client must send
     * udp packets to the server so that the udp protocol can work
     * through firewalls. The server sends udp packets to the client
     * on the address and port from which this packet was sent (from
     * the NAT). The packets are identified based on the port that
     * they use, 0. A new packet type should be created and handled
     * explicity. */
    if ( u_hdr->dest_port == 0 ) {
            Alarm(PRINT,"Session_UDP_Read() Initial UDP packet, source address="IPF","
            " port=%d sess_id=%d rnd_num=%d\n",
            IP(recvfrom_address),recvfrom_port,sess_id,rnd_num);
        ses->udp_addr = recvfrom_address;
        ses->udp_port = recvfrom_port;
        return;
    }

    if(ses->rnd_num != rnd_num) {
        /* The session is gone */
        Alarm(PRINT, "The session is gone\n");
        Ses_Send_ERR(u_hdr->source, u_hdr->source_port);
        return;
    }

    /* This is valid data for this session. It should be processed */
    /* Replace the session data, with the packet received, and process it */
    /* as it would have been received via TCP */

    ses->seq_no++;
    if(ses->seq_no >= 10000) {
        ses->seq_no = 0;
    }
    ses->frag_num = u_hdr->len/MAX_SPINES_MSG;
    if(u_hdr->len%MAX_SPINES_MSG != 0) {
        ses->frag_num++;
    }
    ses->frag_idx = 0;

    dec_ref_cnt(ses->data);
    processed_bytes = sizeof(udp_header);
    i = 0;
    while(processed_bytes < received_bytes) {
        if(received_bytes - processed_bytes <= MAX_SPINES_MSG) {
            bytes_to_send = received_bytes - processed_bytes;
        }
        else {
            bytes_to_send = MAX_SPINES_MSG;
        }

        tmp_buf = frag_buf[i];

        u_hdr = (udp_header*)tmp_buf;

        if(ses->frag_num > 1) {
            if(ses->frag_idx == 0) {
                memcpy((void*)(&ses->save_hdr), (void*)u_hdr, sizeof(udp_header));
            }
            else {
                memcpy((void*)u_hdr, (void*)(&ses->save_hdr), sizeof(udp_header));
            }
            u_hdr->len = bytes_to_send;
        }
        u_hdr->seq_no = ses->seq_no;
        u_hdr->frag_num = ses->frag_num;
        u_hdr->frag_idx = ses->frag_idx;
        
        Alarm(DEBUG, "snd udp seq_no: %d; frag_num: %d; frag_idx: %d; len: %d\n",
              u_hdr->seq_no, u_hdr->frag_num, u_hdr->frag_idx, u_hdr->len);
        
        ses->data = tmp_buf;
        ses->read_len = u_hdr->len + sizeof(udp_header);

        /* Process the packet */
        Process_Session_Packet(ses);

        /*
         * if(get_ref_cnt(ses->data) > 1) {
         *    Alarm(PRINT, "I'm here\n");
         *    dec_ref_cnt(ses->data);
         * }
         */

        ses->frag_idx++;
        i++;
        processed_bytes += bytes_to_send;
    }

    /*    for(i=ses->frag_num; i<50; i++) {*/
    for(i=0; i<ses->frag_num; i++) {
        dec_ref_cnt(frag_buf[i]);
        frag_buf[i] = new_ref_cnt(PACK_BODY_OBJ);
        if(frag_buf[i] == NULL) {
            Alarm(EXIT, "Cannot allocate memory\n");
        }
    }

    if((ses->data = (char*) new_ref_cnt(MESSAGE_OBJ))==NULL) {
        Alarm(EXIT, "Session_Read(): Cannot allocate packet_body\n");
    }
}




void Block_Session(struct Session_d *ses)
{
    int ret, ioctl_cmd;

    /* set file descriptor to blocking */
    ioctl_cmd = 0;
#ifdef ARCH_PC_WIN95
    ret = ioctlsocket(ses->sk, FIONBIO, (void*) &ioctl_cmd);
#else
    ret = ioctl(ses->sk, FIONBIO, &ioctl_cmd);
#endif

    if(ses->fd_flags & READ_DESC) {
        E_detach_fd(ses->sk, READ_FD);
        ses->fd_flags = ses->fd_flags ^ READ_DESC;
    }

    /*
     *if(ses->fd_flags & EXCEPT_DESC) {
     *        E_detach_fd(ses->sk, EXCEPT_FD);
     *        ses->fd_flags = ses->fd_flags ^ EXCEPT_DESC;
     *}
     */

    /* set file descriptor to non blocking */
    ioctl_cmd = 1;
#ifdef ARCH_PC_WIN95
    ret = ioctlsocket(ses->sk, FIONBIO, (void*) &ioctl_cmd);
#else
    ret = ioctl(ses->sk, FIONBIO, &ioctl_cmd);
#endif

}


void Block_All_Sessions(void) {
    stdit it;
    Session *ses;

    Alarm(DEBUG, "Block_All_Sessions\n");

    stdhash_begin(&Sessions_ID, &it);
    while(!stdhash_is_end(&Sessions_ID, &it)) {
        ses = *((Session **)stdhash_it_val(&it));
        if(ses->rel_blocked == 0) {
            Block_Session(ses);
        }
        stdhash_it_next(&it);
    }
}


void Resume_Session(struct Session_d *ses)
{
    int ret, ioctl_cmd;

    /* set file descriptor to blocking */
    ioctl_cmd = 0;
#ifdef ARCH_PC_WIN95
    ret = ioctlsocket(ses->sk, FIONBIO, (void*) &ioctl_cmd);
#else
    ret = ioctl(ses->sk, FIONBIO, &ioctl_cmd);
#endif

    if(!(ses->fd_flags & READ_DESC)) {
        /* Similar to earlier, avoid client messages causing starvation 
         *      of daemon-daemon messages */
        E_attach_fd(ses->sk, READ_FD, Session_Read, 0, NULL, LOW_PRIORITY );
        ses->fd_flags = ses->fd_flags | READ_DESC;
    }

    if(!(ses->fd_flags & EXCEPT_DESC)) {
             E_attach_fd(ses->sk, EXCEPT_FD, Session_Read, 0, NULL, HIGH_PRIORITY );
             ses->fd_flags = ses->fd_flags | EXCEPT_DESC;
    }


    /* set file descriptor to non blocking */
    ioctl_cmd = 1;
#ifdef ARCH_PC_WIN95
    ret = ioctlsocket(ses->sk, FIONBIO, (void*) &ioctl_cmd);
#else
    ret = ioctl(ses->sk, FIONBIO, &ioctl_cmd);
#endif

}


void Resume_All_Sessions(void) {
    stdit it;
    Session *ses;

    Alarm(DEBUG, "Resume_All_Sessions\n");

    stdhash_begin(&Sessions_ID, &it);
    while(!stdhash_is_end(&Sessions_ID, &it)) {
        ses = *((Session **)stdhash_it_val(&it));
        if(ses->rel_blocked == 0) {
            Resume_Session(ses);
        }

        stdhash_it_next(&it);
    }
}



void Session_Flooder_Send(int sesid, void *dummy)
{
    stdit it;
    Session *ses;
    udp_header *hdr;
    int32 *pkt_no, *msg_size;
    char *buf;
    sp_time *t1, now, next_delay;
    long long int duration_now, int_delay; 
    double rate_now;
    int i;

#ifdef ARCH_PC_WIN95
        printf("ERROR: Flooding NOT SUPPORTED ON WINDOWS CURRENTLY\r\n");
        return;
#endif
 
    stdhash_find(&Sessions_ID, &it, &sesid);
    if(stdhash_is_end(&Sessions_ID, &it)) {
        /* The session is gone */
        return;
    }
    ses = *((Session **)stdhash_it_val(&it));
    if(ses->sess_id != (unsigned int)sesid) {
        /* There's another session here, and it just uses the same socket */
        Alarm(PRINT, "different session: %d != %d\n", sesid, ses->sess_id);
        return;
    }

    Alarm(DEBUG,""IPF" port: %d; rate: %d; size: %d; num: %d\n",
          IP(ses->Sendto_address), ses->Sendto_port, ses->Rate, 
          ses->Packet_size, ses->Num_packets);

    /* Prepare the packet */
    ses->seq_no++;
    ses->Sent_packets++;
    now = E_get_time();        

    hdr = (udp_header*)ses->data;
    hdr->source = My_Address;
    hdr->source_port = ses->port;
    hdr->dest = ses->Sendto_address;
    hdr->dest_port = ses->Sendto_port;
    hdr->len = ses->Packet_size;
    hdr->seq_no = ses->seq_no;
    hdr->frag_num = (int16u)ses->frag_num;
    hdr->frag_idx = (int16u)ses->frag_idx;
    hdr->sess_id = (int16u)(ses->sess_id & 0x0000ffff);

    buf = ses->data+sizeof(udp_header);
    msg_size = (int32*)buf;
    pkt_no = (int32*)(buf+sizeof(int32));
    t1 = (sp_time*)(buf+2*sizeof(int32));
    *pkt_no = ses->Sent_packets;
    *msg_size = ses->Packet_size;
    *t1 = now;

    ses->read_len = ses->Packet_size + sizeof(udp_header);

    Process_Session_Packet(ses);    
    
    if(get_ref_cnt(ses->data) > 1) {
        dec_ref_cnt(ses->data);
        if((ses->data = (char*) new_ref_cnt(MESSAGE_OBJ))==NULL) {
            Alarm(EXIT, "Session_Flooder_Send(): Cannot allocate packet_body\n");
        }
    }


    if(ses->Sent_packets == ses->Num_packets) {
        *pkt_no = -1;
        for(i=0; i<10; i++) {
            ses->seq_no++;
            hdr = (udp_header*)ses->data;
            hdr->source = My_Address;
            hdr->source_port = ses->port;
            hdr->dest = ses->Sendto_address;
            hdr->dest_port = ses->Sendto_port;
            hdr->len = ses->Packet_size;
            hdr->seq_no = ses->seq_no;
            hdr->frag_num = (int16u)ses->frag_num;
            hdr->frag_idx = (int16u)ses->frag_idx;
            hdr->sess_id = (int16u)(ses->sess_id & 0x0000ffff);
            
            buf = ses->data+sizeof(udp_header);
            msg_size = (int32*)buf;
            pkt_no = (int32*)(buf+sizeof(int32));
            t1 = (sp_time*)(buf+2*sizeof(int32));
            *pkt_no = -1;
            *msg_size = ses->Packet_size;
            *t1 = now;

            ses->read_len = ses->Packet_size + sizeof(udp_header);

            Process_Session_Packet(ses);

            if(get_ref_cnt(ses->data) > 1) {
                dec_ref_cnt(ses->data);
                if((ses->data = (char*) new_ref_cnt(MESSAGE_OBJ))==NULL) {
                    Alarm(EXIT, "Session_Flooder_Send(): Cannot allocate packet_body\n");
                }
            }
        }
        Session_Close(sesid, SES_BUFF_FULL);
        return;
    }
    duration_now  = (now.sec - ses->Start_time.sec);
    duration_now *= 1000000;
    duration_now += now.usec - ses->Start_time.usec;

    rate_now = ses->Packet_size;
    rate_now = rate_now * ses->Sent_packets * 8 * 1000;
    rate_now = rate_now/duration_now;
    
    next_delay.sec = 0;
    next_delay.usec = 0;            
    if(rate_now > ses->Rate) {
        int_delay = ses->Packet_size;
        int_delay = int_delay * ses->Sent_packets * 8 * 1000;
        int_delay = int_delay/ses->Rate; 
        int_delay = int_delay - duration_now;
        
        if(int_delay > 0) {
            next_delay.sec = int_delay/1000000;
            next_delay.usec = int_delay%1000000;
        }
    }
    E_queue(Session_Flooder_Send, sesid, NULL, next_delay);   
}
