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

#ifndef	ARCH_PC_WIN95

#include <string.h>
#include <stdlib.h>

#ifndef NDEBUG  /* NOTE: turn this off if you want asserts for debugging */
#  define NDEBUG
#endif
#include <assert.h>

#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>

#else

#include <winsock2.h>
#include <ws2tcpip.h>  /* for some reason the Multicast stuff for setsockopt comes from here and not winsock2.h */

#endif

#include "spu_system.h"
#include "spu_alarm.h"
#include "spu_data_link.h"
#include "spu_events.h"
#include "net_types.h"
#include "session.h" 

#ifndef PRIORITY_TYPE_MSG
#  define PRIORITY_TYPE_MSG   24
#  define EXPIRATION_TYPE_MSG 25
#  define DIS_PATHS_TYPE_MSG  26
#endif

#include "stdutil/stderror.h"
#include "stdutil/stdthread.h"

#include "spines_lib.h"

#define START_UDP_PORT  20000
#define MAX_UDP_PORT    30000

/* NOTE: Need to be careful here.  The MTU has some dependence on what
   link and end-to-end protocols are used.  The above line seems to
   assume reliable link w/ a reliable end-to-end session would have
   the highest header overhead.  If we were to
   add additional protocols that could have more header overhead, then
   we'd need to use that one (basically we need the worst case of all
   the possible protocol combinations)  
*/

/*#define MAX_SPINES_MSG 1400 */ /* (packet_body ) 1456 - ( (udp_header) 28 + (rel_ses_pkt_add) 8 + (reliable_ses_tail) 12 + (reliable_tail) 8 ) = 1456 - 56 */

#if 0
#define MAX_SPINES_MSG (MAX_PACKET_SIZE /* ethernet - IP - UDP */ - sizeof(packet_header) - (sizeof(udp_header) + sizeof(rel_udp_pkt_add) + sizeof(reliable_ses_tail) + sizeof(reliable_tail)))
#endif

#define MAX_APP_CLIENTS  1024
#define MAX_CTRL_SOCKETS 51

typedef struct Lib_Client_d {
    int tcp_sk;
    int udp_sk;
    int type;
    int endianess_type;
    int sess_id;
    int rnd_num;
    spines_sockaddr addr_storage;
    struct sockaddr *srv_addr;
    int protocol;
    int my_addr;
    int my_port;
    int connect_addr;
    int connect_port;
    int connect_flag;
    int session_semantics;   /* blocking, silent, or feedback session */
    int virtual_local_port;  /* stored in host byte order */
    int virtual_addr;        /* stored in host byte order */
    int ip_ttl;              /* ttl to stamp all unicast "DATA" UDP packets */ 
    int mcast_ttl;           /* ttl to stamp all multicast "DATA" UDP packets */
    int routing;
} Lib_Client;

/* Local variables */ 
static spines_sockaddr Spines_Addr;
static int             Local_Address = 0;
static int             Max_Client = 0;
static int             Control_sk[MAX_CTRL_SOCKETS];

static Lib_Client      all_clients[MAX_APP_CLIENTS];
static int             init_flag  = 0;

static stdmutex	       data_mutex = { 0 };

static void	Flip_udp_hdr( udp_header *udp_hdr )
{
    udp_hdr->source	  = Flip_int32( udp_hdr->source );
    udp_hdr->dest	  = Flip_int32( udp_hdr->dest );
    udp_hdr->reserved32   = Flip_int32( udp_hdr->reserved32 );
    udp_hdr->source_port  = Flip_int16( udp_hdr->source_port );
    udp_hdr->dest_port	  = Flip_int16( udp_hdr->dest_port );
    udp_hdr->len	  = Flip_int16( udp_hdr->len );
    udp_hdr->seq_no	  = Flip_int16( udp_hdr->seq_no );
    udp_hdr->sess_id	  = Flip_int16( udp_hdr->sess_id );
}

static void Set_large_socket_buffers(int s)
{
    int i, on, ret;
    socklen_t onlen;

    for(i = 64; i <= 256; i += 8) {
	    on = 1024*i;

	    ret = setsockopt(s, SOL_SOCKET, SO_SNDBUF, (void *)&on, sizeof(on));
	    if (ret < 0) break;

	    ret = setsockopt(s, SOL_SOCKET, SO_RCVBUF, (void *)&on, sizeof(on));
	    if (ret < 0) break;

        onlen = sizeof(on);
        ret = getsockopt(s, SOL_SOCKET, SO_SNDBUF, (void *)&on,  &onlen);
        if(on < i*1024) break;
        Alarm(DEBUG, "Set_large_socket_buffers: set sndbuf %d, ret is %d\n", on, ret);

        onlen = sizeof(on);
        ret= getsockopt(s, SOL_SOCKET, SO_RCVBUF, (void *)&on, &onlen);
        if(on < i*1024 ) break;
        Alarm(DEBUG, "Set_large_socket_buffers: set rcvbuf %d, ret is %d\n", on, ret);
    }
    Alarm(DEBUG, "Set_large_socket_buffers: set sndbuf/rcvbuf to %d\n", 1024*(i-5));
}

void spines_set_errno(int err_val) {
    errno = err_val;
}

/***********************************************************/
/* int spines_init(const struct sockaddr *serv_addr)       */
/*                                                         */
/* Initializes data structures for client-side Spines      */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* serv_addr: Address of Spines node, including family of  */
/*              protocol used (e.g. AF_INET)               */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int)  1 if the initialization succeded                 */
/*        0 if the init was already called                 */
/*                                                         */
/***********************************************************/

int spines_init(const struct sockaddr *serv_addr)
{
    int i, ret; 
    size_t s_len;
    char machine_name[256];
    struct hostent *host_ptr;
    sp_time t_now;
  
    if(init_flag != 0) {
      spines_set_errno(SP_ERROR_LIB_ALREADY_INITED);
      return 0;
    }

    init_flag = 1;
   
    /* Seed global random number generator */
    t_now = E_get_time();
    srand(t_now.sec + t_now.usec);

    /* Once we know we will go through with the init, initialize Spines_Addr and Local_Address */
    memset(&Spines_Addr, 0, sizeof(Spines_Addr));
    Local_Address = 0;

    /* Grab my hostname, used for default WIN connection, local_address in UDP_CONNECT for
     * Spines daemon to respond to, etc. */
    gethostname(machine_name,sizeof(machine_name)); 
    host_ptr = gethostbyname(machine_name);
    if (host_ptr == NULL) {
        Alarm(PRINT, "spines_init WARNING: could not get my ip address (my name is %s)\n", machine_name);
    } else if (host_ptr->h_addrtype != AF_INET) {
        Alarm(PRINT, "spines_init WARNING: Sorry, cannot handle addr types other than IPv4\n");
    } else if (host_ptr->h_length != 4) {
        Alarm(PRINT, "spines_init WARNING: Bad IPv4 address length\n");
    } else {
        memcpy(&Local_Address, host_ptr->h_addr, sizeof(struct in_addr));
        Local_Address = ntohl(Local_Address);
    }

    /* Setup the Spines_Addr based on the family of the serv_addr parameter */
    if (serv_addr == NULL) {
#ifndef ARCH_PC_WIN95
        Spines_Addr.unix_addr.sun_family = AF_UNIX;
        /* Check room for length of "data" suffix and NULL byte */
        s_len = sizeof(Spines_Addr.unix_addr.sun_path) - strlen(SPINES_UNIX_DATA_SUFFIX) - 1;
        ret = snprintf(Spines_Addr.unix_addr.sun_path, s_len, "%s%hu", 
                        SPINES_UNIX_SOCKET_PATH, (unsigned short) DEFAULT_SPINES_PORT);
        if (ret > s_len) {
            Alarm(PRINT, "spines_init ERROR: Unix domain path name too long (len = %d), must be"
                            " less than %u bytes\n", ret, s_len);
            spines_set_errno(SP_ERROR_INPUT_ERR);
            init_flag = 0;
            return(-1);
        }
#else
        if (Local_Address == 0) {
            Alarm(PRINT, "spines_init ERROR: gethostbyname failed, exiting!\r\n");
            init_flag = 0;
            return(-1);
        }
        Spines_Addr.inet_addr.sin_family = AF_INET;
        Spines_Addr.inet_addr.sin_port = htons(DEFAULT_SPINES_PORT);
        memcpy(&Spines_Addr.inet_addr.sin_addr, host_ptr->h_addr, sizeof(struct in_addr));
#endif
#ifndef ARCH_PC_WIN95
    } else if (serv_addr->sa_family == AF_UNIX) {
        memcpy(&Spines_Addr.unix_addr, (struct sockaddr_un *)serv_addr, sizeof(struct sockaddr_un));
#endif
    } else if (serv_addr->sa_family == AF_INET) {
        memcpy(&Spines_Addr.inet_addr, (struct sockaddr_in *)serv_addr, sizeof(struct sockaddr_in));
#ifdef IPV6_SUPPORT
    } else if (serv_addr->sa_family == AF_INET6) {
        Alarm(PRINT, "spines_init ERROR: currently do not support AF_INET6\n");
        init_flag = 0;
        spines_set_errno(SP_ERROR_INPUT_ERR);
        return(-1);
#endif
    } else {
        Alarm(PRINT, "spines_init ERROR: unsupported family on this arch: %d\n", serv_addr->sa_family);
        init_flag = 0;
        spines_set_errno(SP_ERROR_INPUT_ERR);
        return(-1);
    }

#ifdef _REENTRANT    
    stdmutex_construct(&data_mutex, STDMUTEX_FAST);
#else
    stdmutex_construct(&data_mutex, STDMUTEX_NULL);
#endif

    stdmutex_grab(&data_mutex); {
        for(i=0; i<MAX_APP_CLIENTS; i++) {
            all_clients[i].udp_sk = -1; 
        }
    } stdmutex_drop(&data_mutex);
    
    return 1;
}

/* 
 * Sends a UDP packet to the daemon. Such a packet must be sent if the udp
 * client protocol is going to be used behind a NAT. This function is
 * temporary. The packet is sent to the server so that the server can determine
 * the address and port that it should use when sending udp packets to the
 * client having the specified information.
 *
 * Arguments: 
 *
 * int s         udp socket
 * int srv_addr  address of spines server
 * int srv_port  port of spines server
 * int my_addr   address of the client
 * int my_port   udp port of client
 * int sess_id   session id 
 * int rnd_num   random nuber
 *
*/
int Send_Initial_UDP_Packet_To_Server(int s, struct sockaddr *saddr, int my_addr,
    int my_port, int sess_id, int rnd_num )
{
    udp_header          u_hdr;
    sys_scatter         scat;
    int                 port, address, daemon_port, daemon_addr;
    int                 ret;
    int32               len;
    int                 num_sends;
    struct sockaddr_in  *inet_addr;

    inet_addr = (struct sockaddr_in *)saddr;
    if (inet_addr->sin_family != AF_INET)
        return(-1);    

    len = 0;

    address = 0;   /* address not used */
    port    = 0;   /* port must be 0, used to identify this message */
    ret     = 0;

    /* Fill in the header */
    u_hdr.source        =	my_addr;
    u_hdr.source_port   =	my_port;    
    u_hdr.dest          =	(int32)address;
    u_hdr.dest_port     =	port;
    u_hdr.len		    =	len;

#if 0
    TODO -- Set ttl?

    /* set the TTL of the packet */
    if(!Is_mcast_addr(u_hdr.dest) && !Is_acast_addr(u_hdr.dest)) { 
	/* This is unicast */
	u_hdr.ttl = l_ip_ttl;
    } else { 
	/* This is a multicast */
	u_hdr.ttl = l_mcast_ttl;
    }
#endif

    scat.num_elements = 3;
    scat.elements[0].len = sizeof(int);
    scat.elements[0].buf = (char*)&sess_id;
    scat.elements[1].len = sizeof(int);
    scat.elements[1].buf = (char*)&rnd_num;
    scat.elements[2].len = sizeof(udp_header);
    scat.elements[2].buf = (char*)&u_hdr;

    daemon_addr = (int32)ntohl(inet_addr->sin_addr.s_addr);
    daemon_port = (int32)ntohs(inet_addr->sin_port);;

    for ( num_sends = 0; num_sends < 3; num_sends++ ) {
        ret = DL_send(s, daemon_addr, daemon_port+SESS_UDP_PORT, &scat);
        if(ret != 2*sizeof(int32)+sizeof(udp_header)+len) {
	        return(-1);
        }
    }

    return(len);
}

/***********************************************************/
/* int spines_socket(int domain, int type,                 */
/*                   int protocol,                         */
/*                   const struct sockaddr *serv_addr)     */
/*                                                         */
/* Creates a Spines socket                                 */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* domain: communication domain (PF_SPINES)                */
/* type: type of socket (SOCK_DGRAM or SOCK_STREAM)        */
/* protocol: protocol used on the overlay links            */
/* srvr: Address of the Spines node                        */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int) the socket the application can use to             */
/*       send/receive data                                 */
/*       -1 in case of an error                            */
/*                                                         */
/***********************************************************/

int  spines_socket(int domain, int type, int protocol, 
		   const struct sockaddr *serv_addr)
{
    udp_header *u_hdr;
    char buf[MAX_PACKET_SIZE];
    int32 *total_len;
    int32 *msg_type;
    size_t s_len;
    int val, ret, sk, u_sk, ctrl_sk, s_ctrl_sk, client;
    int32 *flag_var, *route_var, *sess_var, *rnd_var, *port_var, *addr_var;
    int udp_port, rnd_num, sess_id;
    int link_prot, route_prot, connect_flag, session_prot;
    int tot_bytes, recv_bytes;
    int v_local_port, v_addr;
    int32 endianess_type;

    spines_sockaddr sp_addr;
    struct sockaddr *ctrl_sk_addr     = NULL;
    socklen_t        ctrl_sk_len      = 0;
    struct sockaddr *sk_addr          = NULL;
    socklen_t        sk_len           = 0;

    struct sockaddr_in inet_ctrl_addr, inet_addr;
#ifndef ARCH_PC_WIN95
    struct sockaddr_un	unix_ctrl_addr, unix_addr;
#endif	/* ARCH_PC_WIN95 */

    if (type != SOCK_DGRAM && type != SOCK_STREAM) {
        Alarm(PRINT, "spines_socket(): Unknown socket type: %d\n", type);
        spines_set_errno(SP_ERROR_INPUT_ERR);
        return(-1);
    }

    link_prot    = protocol & RESERVED_LINKS_BITS;
    route_prot   = protocol & RESERVED_ROUTING_BITS;
    connect_flag = protocol & UDP_CONNECT;
    session_prot = protocol & RESERVED_SESSION_BITS;

    /* Check for valid client-specified protocol options */
    if (type != SOCK_DGRAM && connect_flag == UDP_CONNECT) {
        Alarm(PRINT, "spines_socket(): Type (%d) must be SOCK_DGRAM if using UDP_CONNECT\r\n", type);
        spines_set_errno(SP_ERROR_INPUT_ERR);
        return(-1);
    }
    if ((route_prot == IT_PRIORITY_ROUTING || route_prot == IT_RELIABLE_ROUTING) && 
            link_prot != INTRUSION_TOL_LINKS)
    { 
        Alarm(PRINT, "spines_socket(): Invalid Link Protocol: %d.\r\nPlease use Intrusion-Tolerant "
                    "Link protocol with Intrusion-Tolerant Dissemination methods\r\n", link_prot);
        spines_set_errno(SP_ERROR_INPUT_ERR);
        return(-1);
    }
    if ((route_prot == SOURCE_BASED_ROUTING && link_prot != UDP_LINKS 
         && link_prot != SOFT_REALTIME_LINKS))
    {
        Alarm(PRINT, "spines_socket(): Invalid Link Protocol: %d.\r\n Source-based routing currently only supports UDP or Realtime links\r\n", link_prot);
        spines_set_errno(SP_ERROR_INPUT_ERR);
        return(-1);
    }
    if (session_prot == RELIABLE_DGRAM_SESSION_WITH_BACKPRESSURE) {
        Alarm(PRINT, "spines_socket(): Invalid session semantics: "
                    "RELIABLE_DGRAM_SESSION_WITH_BACKPRESSURE.\r\nThis is experimental "
                    "and is not currently available in the open source\r\n");
        spines_set_errno(SP_ERROR_INPUT_ERR);
        return(-1);
    }

    /* Call spines_init only the first time */
    if (!init_flag) spines_init(serv_addr);
    
    rnd_num = rand();
    udp_port = -1;

    total_len = (int32*)(buf);
    u_hdr = (udp_header*)(buf+sizeof(int32));
    msg_type  = (int32*)(buf+sizeof(int32)+sizeof(udp_header));
    flag_var  = (int32*)(buf+sizeof(int32)+sizeof(udp_header)+sizeof(int32));
    route_var = (int32*)(buf+sizeof(int32)+sizeof(udp_header)+2*sizeof(int32));
    sess_var  = (int32*)(buf+sizeof(int32)+sizeof(udp_header)+3*sizeof(int32));
    rnd_var   = (int32*)(buf+sizeof(int32)+sizeof(udp_header)+4*sizeof(int32));
    addr_var  = (int32*)(buf+sizeof(int32)+sizeof(udp_header)+5*sizeof(int32));
    port_var  = (int32*)(buf+sizeof(int32)+sizeof(udp_header)+6*sizeof(int32));

    /* Setup sp_addr based on serv_addr parameter */
    memset(&sp_addr, 0, sizeof(sp_addr));

    if (serv_addr == NULL) {
        memcpy(&sp_addr, &Spines_Addr, sizeof(sp_addr));
#ifndef ARCH_PC_WIN95
    } else if (serv_addr->sa_family == AF_UNIX) {
        memcpy(&sp_addr.unix_addr, (struct sockaddr_un *)serv_addr, sizeof(struct sockaddr_un));
#endif
    } else if (serv_addr->sa_family == AF_INET) {
        memcpy(&sp_addr.inet_addr, (struct sockaddr_in *)serv_addr, sizeof(struct sockaddr_in));
#ifdef IPV6_SUPPORT
    } else if (serv_addr->sa_family == AF_INET6) {
        Alarm(PRINT, "spines_socket ERROR: currently do not support AF_INET6\n");
        spines_set_errno(SP_ERROR_INPUT_ERR);
        return(-1);
#endif
    } else {
        Alarm(PRINT, "spines_socket ERROR: unsupported family on this arch: %d\n", serv_addr->sa_family);
        spines_set_errno(SP_ERROR_INPUT_ERR);
        return(-1);
    }

#ifndef ARCH_PC_WIN95
    if (sp_addr.family == AF_UNIX && connect_flag == UDP_CONNECT) {
        Alarm(PRINT, "spines_socket(): Currently, UDP_CONNECT over AF_UNIX connection unsupported\r\n");
        spines_set_errno(SP_ERROR_INPUT_ERR);
        return(-1);
    }
#endif

    /* Setup sockaddr pointers to appropriate structs for connection */
    switch (sp_addr.family) {
#ifndef ARCH_PC_WIN95
        case AF_UNIX:
            memset(&unix_ctrl_addr, 0, sizeof(unix_ctrl_addr));
            unix_ctrl_addr.sun_family = AF_UNIX;
            /* Check room for length of "data" suffix and NULL byte */
            s_len = sizeof(unix_addr.sun_path) - strlen(SPINES_UNIX_DATA_SUFFIX) - 1;
            ret = snprintf(unix_ctrl_addr.sun_path, s_len, "%s", sp_addr.unix_addr.sun_path);
            if (ret > s_len) {
                Alarm(PRINT, "spines_socket(): Unix Pathname too long: len = %d, max allowed is %u\n",
                                ret, s_len);
                spines_set_errno(SP_ERROR_INPUT_ERR);
                return(-1);
            }
            ctrl_sk_addr = (struct sockaddr *)&unix_ctrl_addr;
            ctrl_sk_len = sizeof(unix_ctrl_addr);
           
            memset(&unix_addr, 0, sizeof(unix_addr));
            memcpy(&unix_addr, &unix_ctrl_addr, sizeof(unix_addr));
            /* Check room for NULL byte */
            s_len = sizeof(unix_addr.sun_path) - 1;
            ret = snprintf(unix_addr.sun_path, s_len, "%s%s", unix_ctrl_addr.sun_path, SPINES_UNIX_DATA_SUFFIX);
            if (ret > s_len) {
                Alarm(PRINT, "spines_socket(): Data suffix did not fit! total len = %d, max allowed is %u\n",
                                ret, s_len);
                spines_set_errno(SP_ERROR_INPUT_ERR);
                return(-1);
            }
            sk_addr = (struct sockaddr *)&unix_addr;
            sk_len = sizeof(unix_addr);
            break;
#endif
        case AF_INET:
            memset(&inet_ctrl_addr, 0, sizeof(inet_ctrl_addr));
            memcpy(&inet_ctrl_addr, &sp_addr.inet_addr, sizeof(inet_ctrl_addr));
            inet_ctrl_addr.sin_port = htons(ntohs(inet_ctrl_addr.sin_port) + SESS_CTRL_PORT);
            ctrl_sk_addr = (struct sockaddr *)&inet_ctrl_addr;
            ctrl_sk_len = sizeof(inet_ctrl_addr);

            memset(&inet_addr, 0, sizeof(inet_addr));
            memcpy(&inet_addr, &sp_addr.inet_addr, sizeof(inet_addr));
            inet_addr.sin_port = htons(ntohs(inet_addr.sin_port) + SESS_PORT);
            sk_addr = (struct sockaddr *)&inet_addr;
            sk_len = sizeof(inet_addr);
            break;
        default:
            Alarm(PRINT, "spines_socket: unsupported family: %d!\r\n", sp_addr.family);
            spines_set_errno(SP_ERROR_INPUT_ERR);
            return(-1);
    }

    ctrl_sk = socket(sp_addr.family, SOCK_STREAM, 0);
    sk = socket(sp_addr.family, SOCK_STREAM, 0);
    if (sk < 0 || ctrl_sk < 0) {
        Alarm(PRINT, "spines_socket: unable to create socket %d %d %d '%s'\n", 
                sk, ctrl_sk, errno, strerror(errno));
        close(ctrl_sk);
        close(sk);
        spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
        return(-1);
    }

    /* Increase buffer on the socket used for sending/receiving Spines data */
    Set_large_socket_buffers(sk);

    /* Set TCP_NODELAY for AF_INET family */
    if (sp_addr.family == AF_INET) {
        val = 1;
        ret = setsockopt(sk, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
        ret += setsockopt(ctrl_sk, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
        
        if (ret < 0) {
            Alarm(PRINT, "spines_socket(): Failed to set socket option TCP_NODELAY\n");
            close(sk);
            close(ctrl_sk);
            /* errno set by OS level call */
            return(-1);
        }
    }

    u_sk = sk;

    /* Connect the control socket for receiving control information.
       Required for receiving control information without interfering 
       with the regular flow of data packets in the regular spines socket 
       Never send any packet with this socket.  Only for receiving.  Upon
       connecting, receive from Spines daemon the control socket that the
       session is using for this connection - needed for later */
    Alarm(PRINT, "spines_socket: Connecting!\r\n");

    ret = connect(ctrl_sk, ctrl_sk_addr, ctrl_sk_len);

    if(ret < 0) {
        Alarm(PRINT, "spines_socket(): Can not initiate ctrl connection to Spines!\r\n");
        close(sk);
        close(ctrl_sk);
        spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
        return(-1);
    }
    recv_bytes = 0;
    while(recv_bytes < sizeof(int32)) {
        ret = recv(ctrl_sk, ((char*)&s_ctrl_sk)+recv_bytes, sizeof(int32)-recv_bytes, 0);
        if(ret <= 0) {
	        Alarm(PRINT, "spines_socket(): Can not recv on control socket\r\n");
            close(sk);
	        close(ctrl_sk);
            spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
            return(-1);	    
	    }
	    recv_bytes += ret;
    }

    /* Create Spines socket, for sending/receiving data and sending control/commands */
    ret = connect(sk, sk_addr, sk_len);

    if(ret < 0) {
        Alarm(PRINT, "spines_socket(): Can not initiate connection to Spines!\r\n");
        spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
        return(-1);
    }

    /* If using UDP_CONNECT, create separate socket stored in u_sk and
     * gethostbyname to use as the return address for UDP_CONNECT */
    if (type == SOCK_DGRAM && connect_flag == UDP_CONNECT) {
        u_sk = socket(AF_INET, SOCK_DGRAM, 0);

        if (u_sk < 0) {
            Alarm(PRINT, "spines_socket(): Can not initiate socket...\n");
            close(sk);
            close(ctrl_sk);
            close(u_sk);
            spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
            return(-1);
        }

        /* Increase the buffer on the socket used for sending and receiving
         * data. This code is similar to the code used to increase the size of
         * the tcp socket. TODO APRIL 23, 2009 Verify that the buffer should be
         * set this high. */
        Set_large_socket_buffers(u_sk);
    }

    /* Connections are now complete, begin exchanging info with daemon */
    *flag_var = link_prot;
    *route_var = route_prot;
    *sess_var = session_prot;
    *rnd_var = rnd_num;
    if (type == SOCK_DGRAM && connect_flag == UDP_CONNECT) {
        *addr_var = Local_Address;
        *port_var = udp_port;
    }
    else {
        *addr_var = -1;
        *port_var = -1;
    }
    *total_len = (int32)(sizeof(udp_header) + 7*sizeof(int32));

    u_hdr->source = 0;
    u_hdr->dest   = 0;
    u_hdr->len    = 0;

    *msg_type = LINKS_TYPE_MSG;

    /* (1) Send the endianess */
    endianess_type = Set_endian(0);
    tot_bytes = 0;
    while (tot_bytes < sizeof(int32)) {
        if ((ret = send(sk, ((char*)(&endianess_type))+tot_bytes, sizeof(int32)-tot_bytes, 0)) <= 0)
            break;
	    tot_bytes += ret;
    }   
    if (tot_bytes != sizeof(int32)) {
        Alarm(PRINT, "spines_socket(1): Can not initiate connection to Spines...\n");
        close(sk);
        close(ctrl_sk);
        if (type == SOCK_DGRAM && connect_flag == UDP_CONNECT)
	        close(u_sk);
        spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
        return(-1);
    }

    /* (2) Send control channel received from spines daemon.  No endianess correction
       here as this is the data I received from Spines, and is of no use to me here */
    tot_bytes = 0;
    while (tot_bytes < sizeof(int32)) {
        if ((ret = send(sk, ((char*)(&s_ctrl_sk))+tot_bytes, sizeof(int32)-tot_bytes, 0)) <= 0)
            break;
        tot_bytes += ret;
    }   
    if (tot_bytes != sizeof(int32)) {
        Alarm(PRINT, "spines_socket(2): Can not initiate connection to Spines...\n");
        close(sk);
        close(ctrl_sk);
        if (type == SOCK_DGRAM && connect_flag == UDP_CONNECT)
            close(u_sk);
	    spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
	    return(-1);
    }

    /* (3) Send the first packet */
    tot_bytes = 0;
    while (tot_bytes < *total_len+sizeof(int32)) {
        if ((ret = send(sk, buf+tot_bytes, *total_len+sizeof(int32)-tot_bytes, 0)) <= 0)
	    break;
	    tot_bytes += ret;
    }   
    if (tot_bytes != sizeof(udp_header)+sizeof(int32)+7*sizeof(int32)) {
        Alarm(PRINT, "spines_socket(3): Can not initiate connection to Spines...\n");
        close(sk);
        close(ctrl_sk);
        if (type == SOCK_DGRAM && connect_flag == UDP_CONNECT)
            close(u_sk);
	    spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
	    return(-1);
    }

    /* (4) Receive the endianess */
    recv_bytes = 0;
    while (recv_bytes < sizeof(int32)) {
	ret = recv(sk, ((char*)&endianess_type)+recv_bytes, sizeof(int32)-recv_bytes, 0);
	if (ret <= 0) {
	    Alarm(PRINT, "spines_socket(4): Can not initiate connection to Spines...\n");
	    close(sk);
	    close(ctrl_sk);
	    if(type == SOCK_DGRAM && connect_flag == UDP_CONNECT)
	        close(u_sk);
	        spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
	        return(-1);	    
	}
	recv_bytes += ret;
    }

    /* Create the client */
    stdmutex_grab(&data_mutex); {
        for (client=0; client<MAX_APP_CLIENTS; client++) {
	        if (all_clients[client].udp_sk == -1)
	            break;
        }

        if(client == MAX_APP_CLIENTS) {
	        Alarm(PRINT, "spines_socket(): Too many open sockets\n");
	        stdmutex_drop(&data_mutex);
	        close(sk);
	        close(ctrl_sk);
	        if (type == SOCK_DGRAM && connect_flag == UDP_CONNECT)
	            close(u_sk);
	        spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
	        return(-1);
        }
      
        if(client == Max_Client)
	        Max_Client++;

        all_clients[client].type = 0;
        all_clients[client].connect_flag = 0;
        all_clients[client].endianess_type = endianess_type;
        all_clients[client].tcp_sk = sk;
        all_clients[client].udp_sk = sk;
    } stdmutex_drop(&data_mutex);

    /* Get the session ID, virtual local port, and virtual addr */
    ret = spines_recvfrom(sk, buf, sizeof(buf), 1, NULL, NULL);
    if(ret <= 0) {
	    close(sk);
	    close(ctrl_sk);
	    if(type == SOCK_DGRAM && connect_flag == UDP_CONNECT)
	        close(u_sk);
	    spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
	    return(-1);
    }
    sess_id = *((int*)buf);
    v_local_port = *(int*)(buf + sizeof(sess_id));
    v_addr = *(int*)(buf + sizeof(sess_id) + sizeof(v_local_port));

    /* Update the client */
    stdmutex_grab(&data_mutex); {
        if(type == SOCK_DGRAM && connect_flag == UDP_CONNECT) {
            all_clients[client].udp_sk         = u_sk;
            all_clients[client].my_addr        = Local_Address;
            all_clients[client].my_port        = udp_port;
            all_clients[client].connect_flag   = connect_flag;
        } else {
	        all_clients[client].udp_sk         = sk;
	        all_clients[client].connect_flag   = 0;	
        }
        all_clients[client].type               = type;
        all_clients[client].rnd_num            = rnd_num;
        all_clients[client].sess_id            = sess_id;

        memcpy(&all_clients[client].addr_storage, &sp_addr, sizeof(sp_addr));
        all_clients[client].srv_addr = (struct sockaddr*)(&all_clients[client].addr_storage);

        all_clients[client].protocol           = protocol;
        all_clients[client].connect_addr       = -1;
        all_clients[client].connect_port       = -1;   
        all_clients[client].virtual_local_port = v_local_port;
        all_clients[client].virtual_addr       = v_addr;
        all_clients[client].ip_ttl             = SPINES_TTL_MAX;
        all_clients[client].mcast_ttl          = SPINES_TTL_MAX;
        all_clients[client].routing            = ((protocol & RESERVED_ROUTING_BITS) >> ROUTING_BITS_SHIFT);
        all_clients[client].session_semantics  = session_prot;
    } stdmutex_drop(&data_mutex);

    if (type == SOCK_DGRAM && connect_flag == UDP_CONNECT && sp_addr.family == AF_INET) {
        if (Control_sk[u_sk%MAX_CTRL_SOCKETS] != 0)
	        Alarm(EXIT, "spines_socket(): not enough control sockets");
        Control_sk[u_sk%MAX_CTRL_SOCKETS] = ctrl_sk;

        /* Send udp packet to initialize the return address */
        Send_Initial_UDP_Packet_To_Server(u_sk, all_clients[client].srv_addr,
                all_clients[client].my_addr, all_clients[client].my_port,
                sess_id, rnd_num );

        return(u_sk);
    } else {
        if (Control_sk[sk%MAX_CTRL_SOCKETS] != 0)
	        Alarm(EXIT, "spines_socket(): not enough control sockets");
        Control_sk[sk%MAX_CTRL_SOCKETS] = ctrl_sk;
        return(sk);
    }
}


/***********************************************************/
/* void spines_close(int sk)                               */
/*                                                         */
/* Closes a Spines socket                                  */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* sk: the socket defining the connection to Spines        */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void spines_close(int s)
{
    int client, type, tcp_sk, connect_flag;

    stdmutex_grab(&data_mutex); {

        client = spines_get_client(s);
        if(client == -1) {
            stdmutex_drop(&data_mutex);
	        return;
        }
        type = all_clients[client].type;
        tcp_sk = all_clients[client].tcp_sk;
        connect_flag = all_clients[client].connect_flag;
        all_clients[client].udp_sk = -1;
        if(client == Max_Client-1) {
	        Max_Client--;
        }

    } stdmutex_drop(&data_mutex);

#ifdef ARCH_PC_WIN95
    shutdown(s, SD_BOTH);
    close(s);
    shutdown(Control_sk[s%MAX_CTRL_SOCKETS], SD_BOTH);
#else
    shutdown(s, SHUT_RDWR);
    close(s);
    shutdown(Control_sk[s%MAX_CTRL_SOCKETS], SHUT_RDWR);
#endif
    close(Control_sk[s%MAX_CTRL_SOCKETS]);
    Control_sk[s%MAX_CTRL_SOCKETS] = 0;
    if((type == SOCK_DGRAM)&&(connect_flag == UDP_CONNECT)) {
      close(tcp_sk);
    }
}

/***********************************************************/
/* void spines_shutdown(int sk)                            */
/*                                                         */
/* Shuts down a Spines socket                              */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* sk: the socket defining the connection to Spines        */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void spines_shutdown(int s)
{
    int client, type, tcp_sk, connect_flag;

    stdmutex_grab(&data_mutex); {

        client = spines_get_client(s);
        if(client == -1) {
	        stdmutex_drop(&data_mutex);
	        return;
        }
        type = all_clients[client].type;
        tcp_sk = all_clients[client].tcp_sk;
        connect_flag = all_clients[client].connect_flag;

    } stdmutex_drop(&data_mutex);

#ifdef ARCH_PC_WIN95
    shutdown(s, SD_BOTH);
    shutdown(Control_sk[s%MAX_CTRL_SOCKETS], SD_BOTH);

    if((type == SOCK_DGRAM)&&(connect_flag == UDP_CONNECT)) {
      shutdown(tcp_sk, SD_BOTH);
    }

#else
    shutdown(s, SHUT_RDWR);
    shutdown(Control_sk[s%MAX_CTRL_SOCKETS], SHUT_RDWR);

    if ((type == SOCK_DGRAM)&&(connect_flag == UDP_CONNECT)) {
      shutdown(tcp_sk, SHUT_RDWR);
    }
#endif
}


/***********************************************************/
/* int spines_sendto(int s, const void *msg, size_t len,   */
/*                   int flags, const struct sockaddr *to, */
/*                   socklen_t tolen);                     */
/*                                                         */
/* Sends best effort data through the Spines network       */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* s:       the Spines socket                              */
/* msg:     a pointer to the message                       */
/* len:     length of the message                          */
/* flags:   not used yet                                   */
/* to:      the target of the message                      */
/* tolen:   length of the target                           */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int) the number of bytes sent (or -1 if an error)      */
/*                                                         */
/***********************************************************/

int spines_sendto(int s, const void *msg, size_t len,  
		  int flags, const struct sockaddr *to, 
		  socklen_t tolen)
{
    int ret;

    ret = spines_sendto_internal(s, msg, len,  flags, to, tolen, 0);
    return(ret);
}


int spines_sendto_internal(int s, const void *msg, size_t len,  
			   int flags, const struct sockaddr *to, 
			   socklen_t tolen, int force_tcp)
{
    udp_header u_hdr;
    sys_scatter scat;
    int port, address, ret;
    int sess_id, rnd_num;
    char pkt[MAX_PACKET_SIZE];
    unsigned char l_ip_ttl, l_mcast_ttl, routing;
    int32 *total_len;
    udp_header *hdr;
    int client, type, tcp_sk, my_addr, my_port, srv_addr, srv_port, connect_flag;
    int tot_bytes;
    struct sockaddr_in *inet_ptr;

    if (len > MAX_SPINES_CLIENT_MSG) {
        Alarm(PRINT, "spines_sendto(): msg size limit exceeded (recvd %d,"
                     " max %d)...dropping\n", len, MAX_SPINES_CLIENT_MSG);
        return(-1);
    }

    address = ntohl(((struct sockaddr_in*)to)->sin_addr.s_addr);
    port = ntohs(((struct sockaddr_in*)to)->sin_port);
    ret = 0;

    if(port == 0) {
	    Alarm(PRINT, "spines_sendto(): cannot send to port 0\n");
	    spines_set_errno(SP_ERROR_INPUT_ERR);
	    return(-1);
    }

    stdmutex_grab(&data_mutex); {

      client = spines_get_client(s);
      if(client == -1) {
        stdmutex_drop(&data_mutex);
	    return(-1);
      }

      type         = all_clients[client].type;
      tcp_sk       = all_clients[client].tcp_sk;
      sess_id      = all_clients[client].sess_id;
      rnd_num      = all_clients[client].rnd_num;
      my_addr      = all_clients[client].my_addr;
      my_port      = all_clients[client].my_port;
      connect_flag = all_clients[client].connect_flag;
      l_ip_ttl     = all_clients[client].ip_ttl;
      l_mcast_ttl  = all_clients[client].mcast_ttl;
      routing      = all_clients[client].routing;
         
      inet_ptr     = (struct sockaddr_in *)all_clients[client].srv_addr;
    }stdmutex_drop(&data_mutex);

    if((type == SOCK_STREAM)&&(force_tcp != 1)) {
        return(spines_send(tcp_sk, msg, len, flags));
    }

    if((force_tcp == 1)||(connect_flag != UDP_CONNECT)) {

	    /*Force TCP*/
	    total_len = (int32*)(pkt);
	    hdr = (udp_header*)(pkt+sizeof(int32));
	
	    hdr->source    = 0;
	    hdr->dest      = (int32)address;
	    hdr->dest_port = port;
	    hdr->len       = len;

        /* set the TTL of the packet */
        if(!Is_mcast_addr(hdr->dest) && !Is_acast_addr(hdr->dest)) { 
            /* This is unicast */
            hdr->ttl = l_ip_ttl;
        } else  { 
            /* This is a multicast */
            hdr->ttl = l_mcast_ttl;
        }

	    hdr->routing = routing;

	    *total_len = len + sizeof(udp_header);
	    ret = send(tcp_sk, pkt, 
		    sizeof(int32)+sizeof(udp_header), 0); 
	    if(ret != sizeof(int32)+sizeof(udp_header)) {
	        Alarm(PRINT, "spines_sendto(): error sending header: %d\n", ret);
	        spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
	        return(-1);
	    }
	    
	    tot_bytes = 0;
	    while(tot_bytes < len) {
	        if ((ret = send(tcp_sk, (char*)msg + tot_bytes, len - tot_bytes, 0)) <= 0) {
		        break;
	        }
	        tot_bytes += ret;
	    }
	    if(tot_bytes != len) {
	        Alarm(PRINT, "spines_sendto(): error sending: %d\n", ret);	
	        spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
	        return(-1);
	    }

        /* SESSION_SEMANTICS - possibly block on recv feedbackfor session_flag here */
	    return(len);
    }
    else {
	    /* Use UDP communication */
	    u_hdr.source      = my_addr;
	    u_hdr.source_port = my_port;    
	    u_hdr.dest        = (int32)address;
	    u_hdr.dest_port   = port;
	    u_hdr.len         = len;

        if (inet_ptr->sin_family != AF_INET) {
            Alarm(PRINT, "spines_sendto(): cannot send UDP DGRAM using non AF_INET sockaddr\n");
            return(-1);
        }
        srv_addr     = ntohl(inet_ptr->sin_addr.s_addr);
        srv_port     = ntohs(inet_ptr->sin_port);

        /* set the TTL of the packet */
        if(!Is_mcast_addr(u_hdr.dest) && !Is_acast_addr(u_hdr.dest)) { 
            /* This is unicast */
            u_hdr.ttl = l_ip_ttl;
        } else { 
            /* This is a multicast */
            u_hdr.ttl = l_mcast_ttl;
        }

	    u_hdr.routing = routing;

	    scat.num_elements = 4;
	    scat.elements[0].len = sizeof(int);
	    scat.elements[0].buf = (char*)&sess_id;
	    scat.elements[1].len = sizeof(int);
	    scat.elements[1].buf = (char*)&rnd_num;
	    scat.elements[2].len = sizeof(udp_header);
	    scat.elements[2].buf = (char*)&u_hdr;
	    scat.elements[3].len = len;
	    scat.elements[3].buf = (char*)msg;
	    ret = DL_send(s, srv_addr, srv_port+SESS_UDP_PORT, &scat);
	    if(ret != 2*sizeof(int32)+sizeof(udp_header)+len) {
	        Alarm(PRINT, "spines_sendto(): error sending: %d != %d\n", 
                    ret, 2*sizeof(int32)+sizeof(udp_header)+len);	
	        spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
	        return(-1);
	    }
        /* SESSION_SEMANTICS - possibly block on recv feedbackfor session_flag here */
	    return(len);
    }
}



/***********************************************************/
/* int spines_recvfrom(int s, void *buf, size_t len,       */
/*                     int flags, struct sockaddr *from,   */
/*                     socklen_t *fromlen);                */
/*                                                         */
/* Receives data from the Spines network                   */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* s:       the Spines socket                              */
/* buff:    a buffer to receive data                       */
/* len:     length of the buffer                           */
/* flags:   not used yet                                   */
/* from:    a buffer to get the sender of the message      */
/* fromlen: length of the sender buffer                    */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int) the number of bytes received                      */
/*       -1 if an error                                    */
/*                                                         */
/***********************************************************/

int  spines_recvfrom(int s, void *buf, size_t len, int flags, 
		     struct sockaddr *from, socklen_t *fromlen) 
{
    int ret;

    ret = spines_recvfrom_internal(s, buf, len, flags, from, fromlen, 0, NULL);
    return(ret);
}


int  spines_recvfrom_dest(int s, void *buf, size_t len, int flags, 
		     struct sockaddr *from, socklen_t *fromlen, int32u *dest ) 
{
    int ret;

    ret = spines_recvfrom_internal(s, buf, len, flags, from, fromlen, 0, dest);
    return(ret);
}


int  spines_recvfrom_internal(int s, void *buf, size_t len, int flags, 
			      struct sockaddr *from, socklen_t *fromlen,
			      int force_tcp, int32u *dest ) 
{
    int received_bytes;
    sys_scatter scat;
    udp_header u_hdr;
    int32 msg_len;
    udp_header *hdr;
    char pkt[MAX_PACKET_SIZE];
    int32 *pkt_len;
    int total_bytes, r_add_size;
    int client, type = 0, connect_flag = 0;
    int32 endianess_type;

    endianess_type = Set_endian(0);

    stdmutex_grab(&data_mutex); {

      client = spines_get_client(s);
      if(client != -1) {
        type = all_clients[client].type;
        connect_flag = all_clients[client].connect_flag;
        endianess_type = all_clients[client].endianess_type;
      }
    
    } stdmutex_drop(&data_mutex);

    if((connect_flag == UDP_CONNECT)&&(force_tcp != 1)) {
      /* Use UDP communication */
     
      Alarm(DEBUG, "Using UDP recvfrom\n");

      scat.num_elements = 3;
      scat.elements[0].len = sizeof(int32);
      scat.elements[0].buf = (char*)&msg_len;
      scat.elements[1].len = sizeof(udp_header);
      scat.elements[1].buf = (char*)&u_hdr;
      scat.elements[2].len = len;
      scat.elements[2].buf = buf;

      received_bytes = DL_recv(s, &scat);

      if(received_bytes <= 0) {
	/* errno set by OS level call */
	return(-1);
      }
      
      if(!Same_endian(endianess_type)) {
	msg_len = Flip_int32(msg_len);
	Flip_udp_hdr(&u_hdr);
      }
      
      if(u_hdr.dest == -1) {
          Alarm(PRINT, "spines_recvfrom(): unspecified recipient destination field\n");
          spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
          return(-1);
      }

      if(from != NULL) {
	if(*fromlen < sizeof(struct sockaddr_in)) {
	  Alarm(PRINT, "spines_recvfrom(): fromlen too small\n");
	  spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
	  return(-1);
	}
	((struct sockaddr_in*)from)->sin_port = htons((short)u_hdr.source_port);
	((struct sockaddr_in*)from)->sin_addr.s_addr = htonl(u_hdr.source);
	*fromlen = sizeof(struct sockaddr_in);
      }
      /* TODO, June 23, 2009 The destination group should be passed back in a
       * struct. Similar code for the TCP logic below. */
      if ( dest != NULL ) {
   	  *dest = htonl(u_hdr.dest);
      }
      return(received_bytes - sizeof(int32) - sizeof(udp_header));
    }
    else {
	/* Force TCP */
	if((type == SOCK_STREAM)&&(force_tcp != 1)) {
	    return(spines_recv(s, buf, len, flags));
	}
	
        Alarm(DEBUG, "Using Force TCP recvfrom\n");

	pkt_len = (int32*)(pkt);
	hdr = (udp_header*)(pkt+sizeof(int32));

	total_bytes = 0;
	while(total_bytes < sizeof(int32)+sizeof(udp_header)) { 
	    received_bytes = recv(s, pkt+total_bytes, 
				  sizeof(int32)+sizeof(udp_header)-total_bytes, 0);
	    if(received_bytes == 0) {
	      /*
               * Since Force TCP is true and the received_bytes == 0
               * This means the conection was closed orderly -- Not an error
               */
	      Alarm(PRINT, "spines_recvfrom(): recvd 0!\n");
              return(-1);

            } else if(received_bytes <= 0) {
	      Alarm(PRINT, "spines_recvfrom(): network recv error\n");
	      spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
	      return(-1);
	    }

	    total_bytes += received_bytes;
	    if(total_bytes > sizeof(int32)+sizeof(udp_header)) {
		Alarm(PRINT, "spines_recvfrom(): socket error\n");
		spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
		return(-1);
	    }
	}

	if(!Same_endian(endianess_type)) {
	    *pkt_len = Flip_int32(*pkt_len);
	    Flip_udp_hdr(hdr);
	}


	if(*pkt_len - (int)sizeof(udp_header) > len) {
	    Alarm(PRINT, "spines_recvfrom(): message too big: %d :: %d\n", *pkt_len, len);
	    spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
	    return(-1);
	}
	
	r_add_size = 0;

	total_bytes = 0;    
	while(total_bytes < *pkt_len - (int)sizeof(udp_header)-r_add_size) { 
	    received_bytes = recv(s, ((char*)buf) + total_bytes, *pkt_len - (int)sizeof(udp_header) - r_add_size - total_bytes, 0);
	    if(received_bytes <= 0) {
	      Alarm(PRINT, "spines_recvfrom(): network recv error\n");
	      spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
	      return(-1);
	    }
	    total_bytes += received_bytes;
	    if(total_bytes > *pkt_len - (int)sizeof(udp_header)) {
	      Alarm(PRINT, "spines_recvfrom(): socket error\n");
	      spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
	      return(-1);
	    }
	}

	if(from != NULL) {
	    if(*fromlen < sizeof(struct sockaddr_in)) {
	      Alarm(PRINT, "spines_recvfrom(): fromlen too small\n");
	      spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
	      return(-1);
	    }
	    ((struct sockaddr_in*)from)->sin_port = htons((short)hdr->source_port);
	    ((struct sockaddr_in*)from)->sin_addr.s_addr = htonl(hdr->source);
	    *fromlen = sizeof(struct sockaddr_in);
	}

	/* TODO April 24, 2009 */
	if ( dest != NULL ) {
	   *dest = htonl(hdr->dest);
        }
 
	return(total_bytes);
    }
}




/***********************************************************/
/* int spines_bind(int sockfd, struct sockaddr *my_addr,   */
/*                 socklen_t addrlen)                      */
/*                                                         */
/* Assigns a Spines virtual address to a Spines socket     */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* sockfd:  the Spines socket                              */
/* my_addr: the Spines virtual address to be assigned      */
/* addrlen: length of the address                          */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int)  0 if success                                     */
/*       -1 if error                                       */
/*                                                         */
/***********************************************************/

int spines_bind(int sockfd, struct sockaddr *my_addr,  
		socklen_t addrlen)
{
    udp_header *u_hdr, *cmd;
    char pkt[MAX_PACKET_SIZE];
    int32 *total_len;
    int32 *type;
    int port, ret;
    int client, my_type, tcp_sk, sk, connect_flag;
    int tot_bytes;


    stdmutex_grab(&data_mutex); {

      client = spines_get_client(sockfd);
      if(client == -1) {
	    stdmutex_drop(&data_mutex);
	    spines_set_errno(SP_ERROR_INPUT_ERR);
	    Alarm(PRINT, "spines_bind(): spines socket not valid \n");
	    return(-1);
      }
      my_type = all_clients[client].type;
      tcp_sk = all_clients[client].tcp_sk;
      connect_flag = all_clients[client].connect_flag;

    } stdmutex_drop(&data_mutex);

    if(addrlen < sizeof(struct sockaddr_in)) {
	    Alarm(PRINT, "spines_bind(): invalid address\n");
	    spines_set_errno(SP_ERROR_INPUT_ERR);
	    return(-1);	
    }
    port = ntohs(((struct sockaddr_in*)my_addr)->sin_port);

    if(port == 0) {
        return (0);  /* POXIS dictates bind(0) to assign a random port, 
                        which is already done in spines_socket */
    }

    if(my_type == SOCK_STREAM) {
	    sk = sockfd;
    }
    else {
	    sk = tcp_sk;
    }

    total_len = (int32*)(pkt);
    u_hdr     = (udp_header*)(pkt+sizeof(int32));
    type      = (int32*)(pkt+sizeof(int32)+sizeof(udp_header));
    cmd       = (udp_header*)(pkt+sizeof(int32)+sizeof(udp_header)+sizeof(int32));

    *total_len = (int32)(2*sizeof(udp_header) + sizeof(int32));

    u_hdr->source = 0;
    u_hdr->dest   = 0;
    u_hdr->len    = 0;

    *type = BIND_TYPE_MSG;

    cmd->source      = 0;
    cmd->dest        = 0;
    cmd->dest_port   = port;
    cmd->len         = 0;
   
    tot_bytes = 0;
    while(tot_bytes < *total_len+sizeof(int32)) {
	if ((ret = send(sk, pkt+tot_bytes, *total_len+sizeof(int32)-tot_bytes, 0)) <= 0) {
		break;
	}
	tot_bytes += ret;
    }
    if(tot_bytes != 2*sizeof(udp_header)+2*sizeof(int32)) {
      Alarm(PRINT, "spines_bind(): bind communication to daemon failure\n");
      spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
      return(-1);
    }


    if((my_type == SOCK_DGRAM)&&(connect_flag == UDP_CONNECT)) {
	ret = spines_recvfrom(sk, pkt, sizeof(pkt), 1, NULL, NULL);
	if(ret <= 0) {
	  Alarm(PRINT, "spines_bind(): bind communication to daemon failure\n");
	  spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
	  return(-1);
	}
    }

    /* on successs update the stored virtual local port */
    stdmutex_grab(&data_mutex); {
      all_clients[client].virtual_local_port = port;
    } stdmutex_drop(&data_mutex);

    return(0);
}



/***********************************************************/
/* int spines_setsockopt(int s, int level, int optname,    */
/*                       const void *optval,               */
/*                       socklen_t optlen)                 */ 
/*                                                         */
/* Sets the options for a Spines socket. Currently only    */
/* used for multicast join and leave (ADD/DROP MEMBERSHIP) */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* s:         the socket defining the connection to Spines */
/* level:     not currently used                           */
/* optname:   SPINES_(OPTION)                              */
/* optval:    a struct ip_mreq containing the multicast    */
/*            group                                        */
/* optlen:    the length of the optval parameter           */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int)  0 if join was ok                                 */
/*       -1 otherwise                                      */
/*                                                         */
/***********************************************************/

int  spines_setsockopt(int s, int  level,  int  optname,  
		               void  *optval, socklen_t optlen)
{
    udp_header *u_hdr, *cmd;
    char pkt[MAX_PACKET_SIZE];
    int32 *total_len;
    int32 *type;
    int sk, ret, response_expected;
    int client, tcp_sk, udp_sk, my_type;
    spines_nettime expiration;

    if( optname != SPINES_ADD_MEMBERSHIP &&
        optname != SPINES_DROP_MEMBERSHIP &&
        optname != SPINES_MULTICAST_LOOP &&
        optname != SPINES_IP_TTL &&
        optname != SPINES_IP_MULTICAST_TTL &&
        optname != SPINES_TRACEROUTE &&
        optname != SPINES_EDISTANCE &&
        optname != SPINES_MEMBERSHIP &&
        optname != SPINES_ADD_NEIGHBOR &&       
        optname != SPINES_SET_DELIVERY &&
        optname != SPINES_SET_PRIORITY &&
        optname != SPINES_SET_EXPIRATION &&
        optname != SPINES_DISJOINT_PATHS ) {
	return(-1);
    }

    stdmutex_grab(&data_mutex); {

      client = spines_get_client(s);
      if(client == -1) {
	stdmutex_drop(&data_mutex);
	spines_set_errno(SP_ERROR_INPUT_ERR);
	Alarm(PRINT, "spines_bind(): spines socket not valid \n");
	return(-1);
      }

      tcp_sk  = all_clients[client].tcp_sk;
      udp_sk  = all_clients[client].udp_sk;
      my_type = all_clients[client].type;

    } stdmutex_drop(&data_mutex);

    /* if the sock opt is to set the ttl, then just record it locally, no comms needed */
    if((optname == SPINES_IP_TTL) || (optname == SPINES_IP_MULTICAST_TTL)) {
      if(my_type == SOCK_STREAM) {
        Alarm(PRINT, "spines_setsockopt(): TTL for STREAM sockers not supported\r\n");
	spines_set_errno(SP_ERROR_INPUT_ERR);
        return (-1);
      }
      
      stdmutex_grab(&data_mutex); {
        if(optname == SPINES_IP_TTL) {
          all_clients[client].ip_ttl = *((unsigned char*) optval);
	  
        } else if(optname == SPINES_IP_MULTICAST_TTL) {
          all_clients[client].mcast_ttl = *((unsigned char*) optval);
        }

      } stdmutex_drop(&data_mutex);
      
      return(0);
    }


    if(my_type == SOCK_STREAM) {
	/* sk = tcp_sk; */
	Alarm(PRINT, "spines_setsockopt(): Multicast for STREAM sockets not supported\n");
	spines_set_errno(SP_ERROR_INPUT_ERR);
	return(-1);	

    }
    else {
	sk = tcp_sk;
    }

    total_len = (int32*)(pkt);
    u_hdr = (udp_header*)(pkt+sizeof(int32));
    type = (int32*)(pkt+sizeof(int32)+sizeof(udp_header));
    cmd = (udp_header*)(pkt+sizeof(int32)+sizeof(udp_header)+sizeof(int32));

    *total_len = (int32)(2*sizeof(udp_header) + sizeof(int32));
        
    u_hdr->source  = 0;
    u_hdr->dest    = 0;
    u_hdr->len     = 0;

    cmd->source    = 0;
    cmd->dest      = 0;
    cmd->dest_port = 0;
    cmd->len       = 0;

    response_expected = 0;
    
    if(optname == SPINES_ADD_MEMBERSHIP) {
	*type = JOIN_TYPE_MSG; 
	if (optlen < sizeof(struct ip_mreq)) {
            Alarm(PRINT, "return buffer space is too small\r\n");
            spines_set_errno(SP_ERROR_INPUT_ERR);
	    return(-1);
	}
	cmd->dest = ntohl(((struct ip_mreq*)optval)->imr_multiaddr.s_addr);

    }
    else if (optname == SPINES_DROP_MEMBERSHIP) {
	*type = LEAVE_TYPE_MSG;
	if (optlen < sizeof(struct ip_mreq)) {
            Alarm(PRINT, "return buffer space is too small\r\n");
            spines_set_errno(SP_ERROR_INPUT_ERR);
	    return(-1);
	}
	cmd->dest = ntohl(((struct ip_mreq*)optval)->imr_multiaddr.s_addr);

    }
    else if (optname == SPINES_MULTICAST_LOOP) {
	*type = LOOP_TYPE_MSG;
	if (optlen < sizeof(unsigned char)) {
            Alarm(PRINT, "return buffer space is too small\r\n");
            spines_set_errno(SP_ERROR_INPUT_ERR);
	    return(-1);
	}
	cmd->dest = *((char*)(optval));
    }
    else if (optname == SPINES_TRACEROUTE) {
        *type = TRACEROUTE_TYPE_MSG;
        if (optlen < sizeof(spines_trace)) {
            Alarm(PRINT, "return buffer space is too small\r\n");
            spines_set_errno(SP_ERROR_INPUT_ERR);
            return(-1);
        }
        cmd->dest = ntohl(((struct sockaddr_in*)optval)->sin_addr.s_addr);
        response_expected = 1;
    }
    else if (optname == SPINES_EDISTANCE) {
        *type = EDISTANCE_TYPE_MSG;
        if (optlen < sizeof(spines_trace)) {
            Alarm(PRINT, "return buffer space is too small\r\n");
            spines_set_errno(SP_ERROR_INPUT_ERR);
            return(-1);
        }
        cmd->dest = ntohl(((struct sockaddr_in*)optval)->sin_addr.s_addr);
        response_expected = 1;
    }
    else if (optname == SPINES_MEMBERSHIP) {
        *type = MEMBERSHIP_TYPE_MSG;
        if (optlen < sizeof(spines_trace)) {
            Alarm(PRINT, "return buffer space is too small\r\n");
            spines_set_errno(SP_ERROR_INPUT_ERR);
            return(-1);
        }
        cmd->dest = ntohl(((struct sockaddr_in*)optval)->sin_addr.s_addr);
        response_expected = 1;
    }
    else if (optname == SPINES_ADD_NEIGHBOR) {
	*type = ADD_NEIGHBOR_MSG; 
	if(optlen < sizeof(struct sockaddr_in)) {
            Alarm(PRINT, "return buffer space is too small\r\n");
            spines_set_errno(SP_ERROR_INPUT_ERR);
	    return(-1); 
        }
	cmd->dest = ntohl(((struct sockaddr_in*)optval)->sin_addr.s_addr);
    } 
    /* controls whether session drops messages (1) or close the connection (2) when
     * session buffer towards a client fills */
    else if (optname == SPINES_SET_DELIVERY) {
        *type = DELIVERY_FLAG_MSG;
         if(optlen < sizeof(int16u))  {
            Alarm(PRINT, "return buffer space is too small\r\n");
            spines_set_errno(SP_ERROR_INPUT_ERR);
            return(-1);
        }
        cmd->dest = *((int16u*)(optval));
    }
    /* added for priority flooding */
    else if (optname == SPINES_SET_PRIORITY) {
        *type = PRIORITY_TYPE_MSG;
        if(optlen < sizeof(int16u))  {
            Alarm(PRINT, "return buffer space is too small\r\n");
            spines_set_errno(SP_ERROR_INPUT_ERR);
            return(-1);
        }
        cmd->dest = *((int16u*)(optval));
    }
    else if (optname == SPINES_SET_EXPIRATION) {
        *type = EXPIRATION_TYPE_MSG;
        if(optlen < 2*sizeof(int32u))  {
            Alarm(PRINT, "return buffer space is too small\r\n");
            spines_set_errno(SP_ERROR_INPUT_ERR);
            return(-1);
        }
        expiration  = *((spines_nettime*)(optval));
        cmd->source = expiration.sec;
        cmd->dest   = expiration.usec;
    }
    /* end added for priority flooding */
    /* added for K-paths */
    else if (optname == SPINES_DISJOINT_PATHS) {
        *type = DIS_PATHS_TYPE_MSG;
        if(optlen < sizeof(int16u))  {
            Alarm(PRINT, "return buffer space is too small\r\n");
            spines_set_errno(SP_ERROR_INPUT_ERR);
            return(-1);
        }
        cmd->dest = *((int16u*)(optval));
    }    
    /* end added for K-paths */
    else { 
	Alarm(PRINT, "spines_setsockopt(): Bad Option\n");
	spines_set_errno(SP_ERROR_INPUT_ERR);
	return(-1);
    }

    ret = send(sk, pkt, *total_len+sizeof(int32), 0);
    if(ret != 2*sizeof(udp_header)+2*sizeof(int32)) {
        Alarm(PRINT, "spines_setsockopt(): error communicating with Spines Daemon\n");
        spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
	return(-1);
    }
    /* If expecting a response, wait for it in control channel */
    if (response_expected) {
        ret = spines_recvfrom(Control_sk[s%MAX_CTRL_SOCKETS], pkt, sizeof(pkt), 1, NULL, NULL);
        if(ret <= 0) {
            Alarm(PRINT, "spines_setsockopt(): error communicating with Spines Daemon\n");
            spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
	    return(-1);
        }
        /* the response is what we need to return in optval */
        if (ret > optlen) {
            Alarm(PRINT, "spines_lib: Returned data does not fit: %d,%d", ret, optlen);
            ret = optlen;
        }
        /* TODO: need to take care of endianess of data since client and 
                 daemon may run in different machines....depends on option */
        memcpy(optval, pkt, ret);
    }
    return(0);
}

int  spines_ioctl(int s, int  level,  int  optname,  
		          void  *optval, socklen_t optlen)
{
    return spines_setsockopt(s, level, optname, optval, optlen);
}




/***********************************************************/
/* int spines_connect(int sockfd,                          */
/*                    const struct sockaddr *serv_addr,    */
/*                    socklen_t addrlen)                   */
/*                                                         */
/* Connects to another Spines socket at an address         */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* sockdef:   the Spines socket                            */
/* serv_addr: the address to connect to                    */
/* addrlen:   The length of the address                    */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int)  0 if connect was ok                              */
/*       -1 otherwise                                      */
/*                                                         */
/***********************************************************/

/*int spines_connect(int sk, int address, int port)*/
int  spines_connect(int sockfd, const struct sockaddr *serv_addr, 
		    socklen_t addrlen)
{
    udp_header *u_hdr, *cmd;
    char pkt[MAX_PACKET_SIZE];
    int32 *total_len;
    int32 *type;
    int ret, recv_bytes;
    char buf[200];
    int address, port;
    int client, my_type;


    if(addrlen < sizeof(struct sockaddr_in)) {
        Alarm(PRINT, "spines_connect(): buffer too small\r\n");
        spines_set_errno(SP_ERROR_INPUT_ERR);
	    return(-1);
    }

    address = ntohl(((struct sockaddr_in*)serv_addr)->sin_addr.s_addr);
    port = ntohs(((struct sockaddr_in*)serv_addr)->sin_port);

    stdmutex_grab(&data_mutex); {
      client = spines_get_client(sockfd);
      if(client == -1) {
	    stdmutex_drop(&data_mutex);
	    Alarm(PRINT, "spines_connect(): unknown spines socket\r\n");
	    spines_set_errno(SP_ERROR_INPUT_ERR);
	    return(-1);
      }

      my_type = all_clients[client].type;
      if(my_type == SOCK_DGRAM) {
	    all_clients[client].connect_addr = address;
	    all_clients[client].connect_port = port;
	    stdmutex_drop(&data_mutex);
	    return(0);
      }
    } stdmutex_drop(&data_mutex);

    total_len = (int32*)(pkt);
    u_hdr = (udp_header*)(pkt+sizeof(int32));
    type = (int32*)(pkt+sizeof(int32)+sizeof(udp_header));
    cmd = (udp_header*)(pkt+sizeof(int32)+sizeof(udp_header)+sizeof(int32));


    *total_len = (int32)(2*sizeof(udp_header) + sizeof(int32));
        
    u_hdr->source = 0;
    u_hdr->dest   = 0;
    u_hdr->len    = 0;

    *type = CONNECT_TYPE_MSG;

    cmd->source = 0;
    cmd->dest   = address;
    cmd->dest_port   = port;
    cmd->len    = 0;
    
    ret = send(sockfd, pkt, *total_len+sizeof(int32), 0);

    if(ret != 2*sizeof(udp_header)+2*sizeof(int32)) {
        Alarm(PRINT, "spines_connect(): send did not send full data amount\n");
        spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
	    return(-1);
    }

    /*    ret = spines_recvfrom_internal(sockfd, buf, sizeof(buf), 0, NULL, NULL, 1);*/

    recv_bytes = 0;
    while(recv_bytes < sizeof(ses_hello_packet)) {
	    ret = spines_recv(sockfd, buf, sizeof(ses_hello_packet) - recv_bytes, 0); 
	    if(ret <= 0) {
            Alarm(PRINT, "spines_connect(): recv did not get full data amount\n");
            spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
            return(-1);
	    }
	    recv_bytes += ret;
    }

    return(0);
}




/***********************************************************/
/* int spines_send(int s, const void *msg, size_t len,     */
/*                 int flags)                              */
/*                                                         */
/* Sends data through the Spines network                   */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* s:       the Spines socket                              */
/* msg:     a pointer to the message                       */
/* len:     length of the message                          */
/* flags:   not used yet                                   */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int) the number of bytes sent (or -1 if an error)      */
/*                                                         */
/***********************************************************/

int  spines_send(int s, const void *msg, size_t len, int flags)
{
    udp_header *u_hdr;
    char pkt[MAX_PACKET_SIZE];
    rel_udp_pkt_add *r_add;
    int32 *total_len;
    struct sockaddr_in host;
    int ret;
    int client, type, connect_addr, connect_port;
    unsigned char l_ip_ttl, l_mcast_ttl, routing;

    if (len > MAX_SPINES_CLIENT_MSG) {
        Alarm(PRINT, "spines_send(): msg size limit exceeded (recvd %d,"
                     " max %d)...dropping\n", len, MAX_SPINES_CLIENT_MSG);
        return(-1);
    }

    stdmutex_grab(&data_mutex); {

        client = spines_get_client(s);
        if(client == -1) {
	        stdmutex_drop(&data_mutex);
	        Alarm(PRINT, "spines_send(): unknown spines socket\r\n");
	        spines_set_errno(SP_ERROR_INPUT_ERR);
	        return(-1);
        }
        type         = all_clients[client].type;
        connect_addr = all_clients[client].connect_addr;
        connect_port = all_clients[client].connect_port;    
        l_ip_ttl     = all_clients[client].ip_ttl;
        l_mcast_ttl  = all_clients[client].mcast_ttl;
        routing      = all_clients[client].routing;

    } stdmutex_drop(&data_mutex);

    if(type == SOCK_DGRAM) {
	    if(connect_port == -1) {
	        Alarm(PRINT, "DGRAM socket not connected\n");
	        spines_set_errno(SP_ERROR_INPUT_ERR);
	        return(-1);
	    }
	    host.sin_family = AF_INET;
	    host.sin_addr.s_addr = htonl(connect_addr);
	    host.sin_port   = htons(connect_port);
	    return(spines_sendto(s, msg, len, flags, 
			     (struct sockaddr*)&host, sizeof(struct sockaddr)));
    }

    /* Check for maximum length */
    /*   */    
    /*   */

    total_len = (int32*)(pkt);
    u_hdr = (udp_header*)(pkt+sizeof(int32));
    r_add = (rel_udp_pkt_add*)(pkt+sizeof(int32)+sizeof(udp_header));

    *total_len = len + sizeof(udp_header) + sizeof(rel_udp_pkt_add);
     
    u_hdr->source = 0;
    u_hdr->dest   = 0;
    u_hdr->dest_port   = 0;
    u_hdr->len    = len + sizeof(rel_udp_pkt_add);

    /* set the TTL of the packet */
    if(!Is_mcast_addr(u_hdr->dest) && !Is_acast_addr(u_hdr->dest)) { /* This is unicast */
        u_hdr->ttl = l_ip_ttl;
    } else { /* This is a multicast */
        u_hdr->ttl = l_mcast_ttl;
    }

    u_hdr->routing = routing;

    r_add->type = Set_endian(0);
    r_add->data_len = len;
    r_add->ack_len = 0;

    ret = send(s, pkt, sizeof(udp_header)+sizeof(rel_udp_pkt_add)+sizeof(int32), 0);
    if(ret != sizeof(udp_header)+sizeof(rel_udp_pkt_add)+sizeof(int32)) {
        Alarm(PRINT, "spines_send(): send did not send full data amount\n");
        spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
	    return(-1);
    }
    
    ret = send(s, msg, len, 0);
    if(ret != len) {
        Alarm(PRINT, "spines_send(): send did not send full data amount\n");
        spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
	    return(-1);
    }
    
    /* SESSION_SEMANTICS - possibly block on recv feedbackfor session_flag here */
    return(ret);
}




/***********************************************************/
/* int spines_recv(int s, void *buf, size_t len, int flags)*/ 
/*                                                         */
/* Receives data from the Spines network                   */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* s:       the Spines socket                              */
/* buff:    a buffer to receive into                       */
/* len:     length of the buffer                           */
/* flags:   not used yet                                   */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int) the number of bytes received                      */
/*       -1 if an error                                    */
/*                                                         */
/***********************************************************/

int  spines_recv(int s, void *buf, size_t len, int flags)
{
    int received_bytes;
    int client, type;

    Alarm(DEBUG, "Using spines_recv\n");

    stdmutex_grab(&data_mutex); {

      client = spines_get_client(s);
      if(client == -1) {
	stdmutex_drop(&data_mutex);
	Alarm(PRINT, "spines_recv(): unknown spines socket\n");
	spines_set_errno(SP_ERROR_INPUT_ERR);
	return(-1);
      }
      type = all_clients[client].type;

    } stdmutex_drop(&data_mutex);

    if(type == SOCK_DGRAM) {
      return(spines_recvfrom(s, buf, len, flags, NULL, NULL));
    }

    received_bytes = recv(s, buf, len, 0);

    return(received_bytes);
}




/***********************************************************/
/* int spines_listen(int s, int backlog)                   */ 
/*                                                         */
/* Listens on a port of the Spines network                 */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* s:       the socket defining the connection to Spines   */
/* backlog: not used yet                                   */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int)  0 if listen was ok                               */
/*       -1 otherwise                                      */
/*                                                         */
/***********************************************************/

int spines_listen(int s, int backlog)
{
    udp_header *u_hdr, *cmd;
    char pkt[MAX_PACKET_SIZE];
    int32 *total_len;
    int32 *type;
    int ret;
    int client, my_type;

    stdmutex_grab(&data_mutex); {
      client = spines_get_client(s);
      if(client == -1) {
	stdmutex_drop(&data_mutex);
	Alarm(PRINT, "spines_listen(): unknown spines socket\n");
	spines_set_errno(SP_ERROR_INPUT_ERR);
	return(-1);
      }
      my_type = all_clients[client].type;
    } stdmutex_drop(&data_mutex);

    if(my_type == SOCK_DGRAM) {
	Alarm(PRINT, "DATAGRAM socket. spines_listen() not supported\n");
        spines_set_errno(SP_ERROR_INPUT_ERR);
	return(-1);
    }


    total_len = (int32*)(pkt);
    u_hdr = (udp_header*)(pkt+sizeof(int32));
    type = (int32*)(pkt+sizeof(int32)+sizeof(udp_header));
    cmd = (udp_header*)(pkt+sizeof(int32)+sizeof(udp_header)+sizeof(int32));


    *total_len = (int32)(2*sizeof(udp_header) + sizeof(int32));
        
    u_hdr->source = 0;
    u_hdr->dest   = 0;
    u_hdr->len    = 0;

    *type = LISTEN_TYPE_MSG;

    cmd->source = 0;
    cmd->dest   = 0;
    cmd->dest_port   = 0;
    cmd->len    = 0;
    
    ret = send(s, pkt, *total_len+sizeof(int32), 0);
    
    if(ret == 2*sizeof(udp_header)+2*sizeof(int32)) {
	return(0);
    } else {
        Alarm(PRINT, "spines_listen(): error communicating with spines daemon\n");
        spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
	return(-1);
    }
}




/***********************************************************/
/* int spines_accept(int s, struct sockaddr *addr,         */
/*                   socklen_t *addrlen)                   */
/*                                                         */
/* Accepts a conection with another Spines socket          */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* s :           the Spines socket                         */
/* addr:         not used yet                              */
/* addrlen       not used yet                              */
/*                                                         */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int) a socket for a new session                        */
/*       -1 error                                          */
/*                                                         */
/***********************************************************/

/*int spines_accept(int sk, int port, int address, int *flags)*/
int  spines_accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
    char pkt[MAX_PACKET_SIZE];
    udp_header *u_hdr, *cmd;
    int32 *total_len;
    int32 *type;
    char *buf;
    int32 addrtmp, porttmp;
    int ret, data_size, recv_bytes;
    int new_sk;
    struct sockaddr* old_addr;
    struct sockaddr_in otherside_addr;
    int client, my_type, protocol;
    socklen_t lenaddr;


    stdmutex_grab(&data_mutex); {

        client = spines_get_client(s);
        if(client == -1) {
	        stdmutex_drop(&data_mutex);
	        Alarm(PRINT, "spines_accept(): unknown spines socket\n");
	        spines_set_errno(SP_ERROR_INPUT_ERR);
	        return(-1);
        }
        my_type = all_clients[client].type;
        protocol = all_clients[client].protocol;
        old_addr = all_clients[client].srv_addr;

    } stdmutex_drop(&data_mutex);

    if(my_type == SOCK_DGRAM) {
        Alarm(PRINT, "DATAGRAM socket. spines_accept() not supported\n");
        spines_set_errno(SP_ERROR_INPUT_ERR);
        return(-1);
    }

    total_len = (int32*)(pkt);
    u_hdr = (udp_header*)(pkt+sizeof(int32));
    type = (int32*)(pkt+sizeof(int32)+sizeof(udp_header));
    cmd = (udp_header*)(pkt+sizeof(int32)+sizeof(udp_header)+sizeof(int32));
    buf = pkt+sizeof(int32)+2*sizeof(udp_header)+sizeof(int32);

    lenaddr = sizeof(struct sockaddr_in);

    ret = spines_recvfrom_internal(s, buf, sizeof(pkt)-(buf-pkt), 0,
				   (struct sockaddr*)(&otherside_addr), 
				   &lenaddr, 1, NULL );

    if(ret <= 0) {
        /* errno and print out should have occured in the internal fcn() */
	    return(-1);
    }    
    data_size = ret;
    
    addrtmp = ntohl(otherside_addr.sin_addr.s_addr);
    porttmp = ntohs(otherside_addr.sin_port);

    new_sk = spines_socket(PF_SPINES, my_type, protocol, old_addr);

    if(new_sk < 0) { 
        /* errno and print out should have occured in the internal fcn() */
        return(-1);
    }
	
    *total_len = (int32)(2*sizeof(udp_header) + sizeof(int32) + data_size);

    u_hdr->source = 0;
    u_hdr->dest   = 0;
    u_hdr->len    = 0;

    *type = ACCEPT_TYPE_MSG;

    cmd->source = 0;
    cmd->dest   = addrtmp;
    cmd->dest_port = porttmp;
    cmd->len    = data_size;
    
    ret = send(new_sk, pkt, *total_len+sizeof(int32), 0);
    
    if(ret != 2*sizeof(udp_header)+2*sizeof(int32)+data_size) {
	    spines_close(new_sk);
	    spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
	    return(-1);
    }
        
    recv_bytes = 0;
    while(recv_bytes < sizeof(ses_hello_packet)) {
	    ret = spines_recv(new_sk, buf, sizeof(ses_hello_packet) - recv_bytes, 0); 
	    if(ret <= 0) {
            Alarm(PRINT, "spines_accept(): communication error with spines daemon\n");
            spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
	        return(-1);
        }
	    recv_bytes += ret;
    }

    if(ret <= 0) {
	    spines_close(new_sk);
	    Alarm(PRINT, "spines_accept(): communication error with spines daemon\n");
	    spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
	    return(-1);
    }

    /* fill in the other side addr to return */
    if (addr != NULL) {
        if(*addrlen < sizeof(struct sockaddr_in)) {
            Alarm(PRINT, "spines_recvfrom(): fromlen too small\n");
	        spines_set_errno(SP_ERROR_INPUT_ERR);
            return(-1);
        }
        ((struct sockaddr_in*)addr)->sin_family      = otherside_addr.sin_family;
        ((struct sockaddr_in*)addr)->sin_port        = (short)otherside_addr.sin_port;
        ((struct sockaddr_in*)addr)->sin_addr.s_addr = otherside_addr.sin_addr.s_addr;
      
        *addrlen = sizeof(struct sockaddr_in);
    }

    return(new_sk);
}





/***********************************************************/
/* int spines_setlink(int sk, const struct sockaddr *addr, */
/*                    int bandwidth, int latency,          */
/*                    float loss, float burst)             */ 
/*                                                         */
/* Sets the loss rate on packets received on a network leg */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* sk:               the Spines socket (SOCK_STREAM type)  */
/* remote_interf_id: the remote src interface for the leg  */
/* local_interf_id:  the local dst interface for the leg   */
/* link:             link latency                          */
/* loss:             loss rate                             */
/* burst:            conditional probability of loss       */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int)  0 if success                                     */
/*       -1 otherwise                                      */
/*                                                         */
/***********************************************************/

int spines_setlink(int sk, int remote_interf_id, int local_interf_id, 
		   int bandwidth, int latency, float loss, float burst)
{
    udp_header *u_hdr, *cmd;
    char pkt[MAX_PACKET_SIZE];
    int32 *total_len;
    int32 *bandwidth_in, *latency_in, *loss_rate, *burst_rate;
    int32 *type;
    int ret;

    total_len = (int32*)(pkt);
    u_hdr = (udp_header*)(pkt+sizeof(int32));
    type = (int32*)(pkt+sizeof(int32)+sizeof(udp_header));
    cmd = (udp_header*)(pkt+sizeof(int32)+sizeof(udp_header)+sizeof(int32));
    bandwidth_in = (int32*)(pkt+sizeof(int32)+2*sizeof(udp_header)+sizeof(int32));
    latency_in = (int32*)(pkt+sizeof(int32)+2*sizeof(udp_header)+2*sizeof(int32));
    loss_rate = (int32*)(pkt+sizeof(int32)+2*sizeof(udp_header)+3*sizeof(int32));
    burst_rate = (int32*)(pkt+sizeof(int32)+2*sizeof(udp_header)+4*sizeof(int32));

    *bandwidth_in = bandwidth; 
    *latency_in = latency; 
    *loss_rate = (int32)(loss*10000);
    *burst_rate = (int32)(burst*10000);
    
    *total_len = (int32)(2*sizeof(udp_header) + 5*sizeof(int32));   
    
    u_hdr->source = 0;
    u_hdr->dest   = 0;
    u_hdr->len    = 0;

    *type = SETLINK_TYPE_MSG;

    cmd->source    = remote_interf_id;
    cmd->dest      = local_interf_id;
    cmd->dest_port = 0;
    cmd->len       = 4*sizeof(int32);

    ret = send(sk, pkt, *total_len+sizeof(int32), 0);
    
    if(ret != 2*sizeof(udp_header)+6*sizeof(int32)) {
        Alarm(PRINT, "spines_setlink(): communications error with spines daemon\n");
        spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
        return(-1);
    }

    return(0);  
}

/***********************************************************/
/* int spines_dissemination(int sk, int paths,             */
/*                             int overwrite_ip)           */
/*                                                         */
/* Sets the dissemination method of all sessions           */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* sk:               the Spines socket (SOCK_STREAM type)  */
/* paths:            number of paths (0 for flooding)      */
/* overwrite_ip:     ip address to use to overwrite mcast  */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int)  0 if success                                     */
/*       -1 otherwise                                      */
/*                                                         */
/***********************************************************/
int spines_setdissemination(int sk, int paths, int overwrite_ip)
{
    udp_header *u_hdr, *cmd;
    char pkt[MAX_PACKET_SIZE];
    int32 *total_len;
    int32 *path;
    int32 *type;
    int32 *overwrite;
    int ret;

    total_len = (int32*)(pkt);
    u_hdr = (udp_header*)(pkt+sizeof(int32));
    type = (int32*)(pkt+sizeof(int32)+sizeof(udp_header));
    cmd = (udp_header*)(pkt+sizeof(int32)+sizeof(udp_header)+sizeof(int32));
    path = (int32*)(pkt+sizeof(int32)+2*sizeof(udp_header)+sizeof(int32));
    overwrite = (int32*)(pkt+sizeof(int32)+2*sizeof(udp_header)+2*sizeof(int32));

    *path = paths; 
    *overwrite = overwrite_ip;
    
    *total_len = (int32)(2*sizeof(udp_header) + 3*sizeof(int32));   
    
    u_hdr->source = 0;
    u_hdr->dest   = 0;
    u_hdr->len    = 0;

    *type = SETDISSEM_TYPE_MSG;

    cmd->source    = 0;
    cmd->dest      = 0;
    cmd->dest_port = 0;
    cmd->len       = 2*sizeof(int32);

    ret = send(sk, pkt, *total_len+sizeof(int32), 0);
    
    if(ret != 2*sizeof(udp_header)+4*sizeof(int32)) {
        Alarm(PRINT, "spines_setdissemination(): communications error with spines daemon\n");
        spines_set_errno(SP_ERROR_DAEMON_COMM_ERR);
        return(-1);
    }

    return(0);  
}


int spines_get_client(int sk) {
  int i;
  for(i=0; i<Max_Client; i++) {
    if(all_clients[i].udp_sk == sk) {
      return(i);
    }
  }
  return(-1);
}




int spines_flood_send(int sockfd, int address, int port, int rate, int size, int num_pkt)
{
    udp_header *u_hdr;
    char pkt[MAX_PACKET_SIZE];
    int32 *total_len;
    int32 *type;
    int ret;
    int client, my_type, tcp_sk, sk, connect_flag;
    
    int32 *dest, *dest_port, *send_rate, *pkt_size, *num;

#ifdef ARCH_PC_WIN95
    Alarm(PRINT, "spines_flood_send ERROR: NOT SUPPORTED ON WINDOWS CURRENTLY\r\n");
    return -1;
#endif

    stdmutex_grab(&data_mutex); {
      client = spines_get_client(sockfd);
      if(client == -1) {
	stdmutex_drop(&data_mutex);
	Alarm(PRINT, "spines_connect(): unknown spines socket\r\n");
	spines_set_errno(SP_ERROR_INPUT_ERR);
	return(-1);
      }
      my_type = all_clients[client].type;
      tcp_sk = all_clients[client].tcp_sk;
      connect_flag = all_clients[client].connect_flag;
    } stdmutex_drop(&data_mutex);

    sk = sockfd;

    total_len = (int32*)(pkt);
    u_hdr = (udp_header*)(pkt+sizeof(int32));
    type = (int32*)(pkt+sizeof(int32)+sizeof(udp_header));
    dest = (int32*)(pkt+sizeof(int32)+sizeof(udp_header)+sizeof(int32));
    dest_port = (int32*)(pkt+sizeof(int32)+sizeof(udp_header)+2*sizeof(int32));
    send_rate = (int32*)(pkt+sizeof(int32)+sizeof(udp_header)+3*sizeof(int32));
    pkt_size = (int32*)(pkt+sizeof(int32)+sizeof(udp_header)+4*sizeof(int32));
    num = (int32*)(pkt+sizeof(int32)+sizeof(udp_header)+5*sizeof(int32));

    *total_len = (int32)(sizeof(udp_header) + 6*sizeof(int32));

    u_hdr->source = 0;
    u_hdr->dest   = 0;
    u_hdr->len    = 0;

    *type = FLOOD_SEND_TYPE_MSG;

    *dest   = address;
    *dest_port   = port;
    *send_rate   = rate;
    *pkt_size    = size;
    *num         = num_pkt;
    
    ret = send(sk, pkt, *total_len+sizeof(int32), 0);
    if(ret != sizeof(udp_header)+7*sizeof(int32))
	return(-1);


    ret = spines_recvfrom(sk, pkt, sizeof(pkt), 1, NULL, NULL);
    if(ret <= 0) {
	return(-1);
    }

    return(0);
}



int spines_flood_recv(int sockfd, char *filename, int namelen)
{
    udp_header *u_hdr;
    char pkt[MAX_PACKET_SIZE];
    int32 *total_len;
    int32 *type;
    int ret;
    int client, my_type, tcp_sk, sk, connect_flag;
    int *len;
    char *name;

#ifdef ARCH_PC_WIN95
    Alarm(PRINT, "ERROR: NOT SUPPORTED ON WINDOWS CURRENTLY\r\n");
    return -1;
#endif

    stdmutex_grab(&data_mutex); {
      client = spines_get_client(sockfd);
      if(client == -1) {
	stdmutex_drop(&data_mutex);
	Alarm(PRINT, "spines_send(): unknown spines socket\r\n");
	spines_set_errno(SP_ERROR_INPUT_ERR);
	return(-1);
      }
      my_type = all_clients[client].type;
      tcp_sk = all_clients[client].tcp_sk;
      connect_flag = all_clients[client].connect_flag;
    } stdmutex_drop(&data_mutex);

    sk = sockfd;

    total_len = (int32*)(pkt);
    u_hdr = (udp_header*)(pkt+sizeof(int32));
    type = (int32*)(pkt+sizeof(int32)+sizeof(udp_header));
    len = (int*)(pkt+sizeof(int32)+sizeof(udp_header)+sizeof(int32));
    name = (char*)(pkt+sizeof(int32)+sizeof(udp_header)+2*sizeof(int32));


    *total_len = (int32)(sizeof(udp_header) + 2*sizeof(int32) + namelen);

    u_hdr->source = 0;
    u_hdr->dest   = 0;
    u_hdr->len    = 0;

    *type = FLOOD_RECV_TYPE_MSG;
    *len   = namelen;
    memcpy(name, filename, namelen);

    
    ret = send(sk, pkt, *total_len+sizeof(int32), 0);
    if(ret != *total_len+sizeof(int32))
	return(-1);


    ret = spines_recvfrom(sk, pkt, sizeof(pkt), 1, NULL, NULL);
    if(ret <= 0) {
	return(-1);
    }

    return(0);
}


/***********************************************************/
/* int spines_getsockname(int sk, struct sockaddr *name    */
/*                        socklen_t *nlen)                 */
/*                                                         */
/* Retrieves the local address others in the Spines        */
/* use to address this node                                */
/*                                                         */
/* Arguments                                               */
/*   sk:    the Spines socket                              */
/*   name:  local virtual address others user to in        */
/*          Spines network to address this node.           */
/*          fields are in network byte order               */
/*   nlen:  size of 'name' being passed in                 */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* (int)  0 on success                                     */
/*       -1 otherwise                                      */
/*                                                         */
/***********************************************************/

int spines_getsockname(int sk, struct sockaddr *name, socklen_t *nlen)
{
  int client;

  if(name != NULL) {
    if(*nlen < sizeof(struct sockaddr_in)) {
      Alarm(PRINT, "spines_getsockname(): nlen too small\n");
      spines_set_errno(SP_ERROR_INPUT_ERR);
      return(-1);
    }

    stdmutex_grab(&data_mutex); {
      client = spines_get_client(sk);
      if(client != -1) {
        ((struct sockaddr_in*)name)->sin_port = htons((short)all_clients[client].virtual_local_port);
        ((struct sockaddr_in*)name)->sin_addr.s_addr = htonl(all_clients[client].virtual_addr);
        *nlen = sizeof(struct sockaddr_in);
      }
      
    } stdmutex_drop(&data_mutex);   

    if(client == -1) {
      Alarm(PRINT, "spines_getsockname(): unknown socket\n");
      spines_set_errno(SP_ERROR_INPUT_ERR);
      return(-1);
    }

  } else {
    Alarm(PRINT, "spines_getsockname(): name is null \n");
    spines_set_errno(SP_ERROR_INPUT_ERR);
    return (-1);
  }

  return (0);
  
}

#define MAX_MSG_LEN ((0x1 << 20) - 1)

int  spines_sendmsg( int s, const spines_msg *msg, int flags )
{
        int  ret;
        int  buf_len;
        int  i;
        char buf[ MAX_MSG_LEN ];

        if ( ( int ) msg->msg_iovlen < 0 )
        {
                Alarm( DEBUG, "spines_sendmsg(): illegal msg_iovlen\n" );
                spines_set_errno( SP_ERROR_INPUT_ERR );
                assert( 0 );
                return -1;
        }

        for ( i = 0, buf_len = 0; i < (int) msg->msg_iovlen; ++i )
        {
                if ( ( int ) msg->msg_iov[ i ].iov_len < 0 )
                {
                        Alarm( DEBUG, "spines_sendmsg(): illegal iov_len\n" );
                        spines_set_errno( SP_ERROR_INPUT_ERR );
                        assert( 0 );
                        return -1;
                }

                if ( buf_len + ( int ) msg->msg_iov[ i ].iov_len > MAX_MSG_LEN )
                {
                        Alarm( DEBUG, "spines_sendmsg(): msg too big!\n" );
                        spines_set_errno( SP_ERROR_INPUT_ERR );
                        assert( 0 );
                        return -1;
                }

                memcpy( buf + buf_len, msg->msg_iov[ i ].iov_base, msg->msg_iov[ i ].iov_len );
                buf_len += ( int ) msg->msg_iov[ i ].iov_len;
        }

        if ( msg->msg_name == NULL )
        {
                ret = spines_send( s, buf, buf_len, flags );
        }
        else
        {
                ret = spines_sendto( s, buf, buf_len, flags, msg->msg_name, msg->msg_namelen );
        }

        /* SESSION_SEMANTICS - possibly block on recv feedbackfor session_flag here */
        return ret;
}

int  spines_recvmsg(int s, spines_msg *msg, int flags)
{
        int  ret;
        int  buf_len;
        int  adv_bytes;
        int  i;
        char buf[ MAX_MSG_LEN ];

        if ( ( int ) msg->msg_iovlen < 0 )
        {
                Alarm( DEBUG, "spines_recvmsg(): illegal msg_iovlen\n" );
                spines_set_errno( SP_ERROR_INPUT_ERR );
                assert( 0 );
                return -1;
        }

        for ( i = 0, buf_len = 0; i < (int) msg->msg_iovlen; ++i )
        {
                if ( ( int ) msg->msg_iov[ i ].iov_len < 0 )
                {
                        Alarm( DEBUG, "spines_recvmsg(): illegal iov_len\n" );
                        spines_set_errno( SP_ERROR_INPUT_ERR );
                        assert( 0 );
                        return -1;
                }

                if ( buf_len + ( int ) msg->msg_iov[ i ].iov_len > MAX_MSG_LEN )
                {
                        Alarm( DEBUG, "spines_recvmsg(): msg too big!\n" );
                        spines_set_errno( SP_ERROR_INPUT_ERR );
                        assert( 0 );
                        return -1;
                }

                buf_len += ( int ) msg->msg_iov[ i ].iov_len;
        }

        if ( msg->msg_name == NULL )
        {
                ret = spines_recv( s, buf, buf_len, flags );
        }
        else
        {
                ret = spines_recvfrom( s, buf, buf_len, flags, msg->msg_name, &msg->msg_namelen );
        }

        if ( ret > 0 )
        {
                assert( ret <= buf_len );

                for ( i = 0, adv_bytes = 0; i < (int) msg->msg_iovlen && adv_bytes < ret; ++i )
                {
                        int cpy_bytes = ( int ) msg->msg_iov[ i ].iov_len;

                        if ( adv_bytes + cpy_bytes >= ret )
                        {
                                cpy_bytes = ret - adv_bytes;
                        }

                        memcpy( msg->msg_iov[ i ].iov_base, buf + adv_bytes, cpy_bytes );
                        adv_bytes += cpy_bytes;
                }

                if ( adv_bytes != ret )
                {
                        Alarm( DEBUG, "spines_recvmsg(): bug!\n" );
                        spines_set_errno( SP_ERROR_INPUT_ERR );
                        assert( 0 );
                        return -1;
                }
        }

        return ret;
}
