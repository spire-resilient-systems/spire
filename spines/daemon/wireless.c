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
#include "spu_alarm.h"
#include "spu_events.h"
#include "spu_data_link.h"

#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#ifdef HAVE_FEATURES_H
#  include <features.h>    /* for the glibc version number */
#  if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 1
#    ifdef HAVE_NETPACKET_PACKET_H
#      include <netpacket/packet.h>
#    endif
#    ifdef HAVE_NET_ETHERNET_H
#      include <net/ethernet.h>    /* the L2 protocols */
#    endif
#  else
#    include <asm/types.h>
#    include <linux/if_packet.h>
#    include <linux/if_ether.h>    /* The L2 protocols */
#  endif
#else
#  ifdef HAVE_NETPACKET_PACKET_H
#    include <netpacket/packet.h>
#  endif
#  ifdef HAVE_NET_ETHERNET_H
#    include <net/ethernet.h>    /* the L2 protocols */
#  endif
#endif

#ifdef HAVE_NET_IF_ARP_H
#  include <net/if_arp.h>
#endif

#ifdef HAVE_DLFCN_H
#  include <dlfcn.h>
#endif

#include "stdutil/stdhash.h"

#include "objects.h"
#include "net_types.h"
#include "node.h"
#include "wireless.h"

#include "spines.h"

/* Local variables */
char*   (*_pcap_lookupdev) (char*);
pcap_t* (*_pcap_open_live) (char*,int,int,int,char*);
int     (*_pcap_compile) (pcap_t*,struct bpf_program*,char*,int,bpf_u_int32);
int     (*_pcap_setfilter) (pcap_t*,struct bpf_program*);
int     (*_pcap_setnonblock) (pcap_t*,int,char*); 
int     (*_pcap_get_selectable_fd) (pcap_t*);
int     (*_pcap_next_ex) (pcap_t*,struct pcap_pkthdr**,u_char **);
char*   (*_pcap_geterr) (pcap_t*);


/***********************************************************/
/* void Wireless_Init(void)                                */
/*                                                         */
/* Initializes raw sniffer socket used to process 802.11   */
/* frames.  Will link to libpcap shared library.           */
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

void Wireless_Init() 
{
    int wireless_sk;     
    char bpf[50];  
    pcap_t* pcap_handler;
    void *handle;

    if (Wireless != 1) {
        return;
    }

    /* Only when interface is specified */
    if (strlen(Wireless_if) == 0) {
        Wireless_monitor = 0;
        return;
    }

    handle = dlopen("./libpcap.so", RTLD_NOW);
    if (!handle) {
        handle = dlopen("/lib/libpcap.so", RTLD_NOW);
        if (!handle) {
            handle = dlopen("/usr/lib/libpcap.so", RTLD_NOW);
        }
    }
    if (!handle) {
        Alarm(EXIT, "Wireless_Init(): Unable to load libpcap.so library\n");
    } else {
        /* Map functions */
        _pcap_lookupdev = dlsym(handle, "pcap_lookupdev");
        _pcap_open_live = dlsym(handle, "pcap_open_live");
        _pcap_compile = dlsym(handle, "pcap_compile");
        _pcap_setfilter = dlsym(handle, "pcap_setfilter");
        _pcap_setnonblock = dlsym(handle, "pcap_setnonblock");
        _pcap_get_selectable_fd = dlsym(handle, "pcap_get_selectable_fd");
        _pcap_next_ex = dlsym(handle, "pcap_next_ex");
        _pcap_geterr = dlsym(handle, "pcap_geterr");

        if (_pcap_lookupdev == NULL || _pcap_open_live == NULL || _pcap_compile == NULL ||
            _pcap_setfilter == NULL || _pcap_setnonblock == NULL || 
            _pcap_get_selectable_fd == NULL || _pcap_next_ex == NULL || _pcap_geterr == NULL) 
        {
            Alarm(EXIT, "Wireless_Init(): dlsym error: \n\t%s", dlerror());
            dlclose(handle);
        }
    }

    memset(bpf, 0, sizeof(bpf));
    /* Unfortunately, there is a bug in Linux 2.4 bpf on 802.11 raw frames, 
       so use packet size for now, although port-based bpf is the right way. 
       When running on Linux 2.6 or above, you can change this line. */
    /* I am only interested in hello packets, which are 248 bytes */
    //sprintf(bpf, "len<300 and udp port %d", Port);
    sprintf(bpf, "len<260 and len>240");
    wireless_sk = init_p80211(Wireless_if, 1, &pcap_handler, bpf);
    E_attach_fd(wireless_sk, READ_FD, Wireless_process_pkt, 0, 
            (void*)pcap_handler, LOW_PRIORITY);
}


/***********************************************************/
/* void Wireless_process_pkt()                             */
/*                                                         */
/* Called by the event system to receive raw 802.11        */
/* where RSSI and ReTransmission info is recorded          */
/*                                                         */
/* Arguments                                               */
/*                                                         */
/* sk:      socket                                         */
/* dummy_i: not used                                       */
/* dummy_p: not used                                       */
/*                                                         */
/* Return Value                                            */
/*                                                         */
/* NONE                                                    */
/*                                                         */
/***********************************************************/

void Wireless_process_pkt(int sk, int dummy_i, void *pcap_handler)
{
    int ret, dst, temp;
    const u_char *packet;
    u_int16_t eth_type;
    Node *nd;
    stdit it;

    struct pcap_pkthdr *pcap_h;
    wlan_header *wlan_h;
    ieee_802_11_header *i802_h;
    llc_header *llc_h;
    my_ip_header *ip_h;
    my_udp_header *udp_h;
    packet_header *spines_h;

    ret = _pcap_next_ex((pcap_t*)pcap_handler, &pcap_h, (u_char **) &packet);
    if (ret < 0) { 
        Alarm(EXIT, "pcap_next_ex: error\n");
    } else if(ret == 0) {
        /* Timeout Elapsed */
        return;
    }
    if (pcap_h->caplen < 200) {
        /* Alarm(PRINT, "Wireless_process_pkt(): check bpf filtering \n"); */
        return;
    }

    wlan_h   = (wlan_header *)packet;
    i802_h   = (ieee_802_11_header *)((char*)wlan_h + wlan_h->msglen);
    llc_h    = (llc_header*)((char*)i802_h + sizeof(ieee_802_11_header));
    eth_type = ntohs(llc_h->unknown1);

    if (eth_type == ETHERTYPE_IP) {
        /* IP Filtering */
        ip_h  = (my_ip_header*)((char *)llc_h + sizeof(llc_header));
        dst = ntohl(ip_h->ip_dst.s_addr);
        if (ip_h->ip_len < (sizeof(my_ip_header)+sizeof(my_udp_header)+sizeof(packet_header)) || 
            ip_h->ip_p != IPPROTO_UDP || (dst != My_Address && dst != Discovery_Address[0])) {
            return;
        }
        udp_h = (my_udp_header*)((char*)ip_h + sizeof(my_ip_header));

        /* Note: Broadcast packets may show higuer RSSI than Unicast Packets due to rate/modulation */
        if (ntohs(udp_h->dest_port) == Port && 
            (dst == My_Address || (Num_Discovery_Addresses > 0 && dst == Discovery_Address[0]))) {
            /* Apparently valid spines packet. Don't know endianess */
            spines_h = (packet_header *)((char*)udp_h + sizeof(my_udp_header));
            if(!Same_endian(spines_h->type)) {
                spines_h->sender_id = Flip_int32(spines_h->sender_id);
            }
            /* Cannot trust src as it may come from tunnel or private network */
            /* src = ntohl(ip_pkt->ip_src.s_addr); */
            stdhash_find(&All_Nodes, &it, &(spines_h->sender_id));

            /* Update if it exists.  Otherwise, wait for Process hello ping to create node */
            if(!stdhash_is_end(&All_Nodes, &it)) {
                nd = *((Node **)stdhash_it_val(&it));

                /* The RSSI depends on the chip monitoring on the monitoring wireless node
                   Here, we try to be compatible with both db (broadcom) and 0-60 (atheros) values, 
                   mapped to percent.  However, some cards (like Cisco) may differ */

                temp = (int)(wlan_h->rssi).data;
                if (temp < 0)  {
                    temp = 95 + (int)(wlan_h->rssi).data;
                }
                temp = (int)((float)temp * 100.0/60.0);
                if (temp > 100) {
                    temp = 100;
                } else if (temp < 0) {
                    temp = 0;
                }

#if 0
		TODO FIX ME


                /* TODO: RSSI may differ between mcast and ucast packets due tx rate */
                if (Is_Connected_Neighbor2(nd)) {
                    /* Connected node.  Consider only Unicast packets */
                    if (dst == My_Address) {
                        nd->w_data.rssi = (nd->w_data.rssi * 0.8) + (temp * 0.2);
                    }
                } else {
                    nd->w_data.rssi = (nd->w_data.rssi * 0.8) + (temp * 0.2);
                }

                /* Ok, no such thing as 0 RSSI */
                if (nd->w_data.rssi <= 0) {
                    nd->w_data.rssi = 1;
                }

                /* Update retransmit rate, only unicast packets, over last 20 packets */
                if (dst == My_Address) {
                    if (i802_h->frame_control & 0x0800) {
                        if (nd->w_data.retry <= 95) nd->w_data.retry+=5;
                    } else {
                        if (nd->w_data.retry >= 5) nd->w_data.retry-=5;
                    }
                }
#endif
            }
        }
    }
}

inline int init_p80211(char *dev, int promisc, pcap_t** descr, char *my_filter)
{
    struct bpf_program fp;
    int pcap_socket;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (dev == NULL) {
        dev = _pcap_lookupdev(errbuf);
        if(dev == NULL) { 
            printf("%s\n",errbuf); 
            exit(1); 
        }
    }

    /* open device for reading. Need only up to 250 bytes */
    *descr = _pcap_open_live(dev,250,promisc,0,errbuf);
    if(*descr == NULL) { 
        printf("pcap_open_live(): %s\n", errbuf); 
        exit(1); 
    }

    /* Put device in non-blocking mode */
    if(_pcap_setnonblock(*descr, 1, errbuf) == -1) { 
        printf("pcap_setnonblock(): %s\n", errbuf); 
        exit(1); 
    }

    /* Compile/Set filter */
    if (my_filter != NULL) {
        if(_pcap_compile(*descr,&fp,my_filter,0,0) == -1) { 
            printf("Error calling pcap_compile\n%s\n", _pcap_geterr(*descr)); 
            exit(1); 
        }

        if(_pcap_setfilter(*descr,&fp) == -1) { 
            printf("Error setting filter\n"); 
            exit(1); 
        }
    }

    pcap_socket = _pcap_get_selectable_fd(*descr);
    if(pcap_socket < 0) { 
        printf("Error getting pcap select socket\n"); 
        exit(1); 
    }

    printf("\nRAW SOCKET CAPTURE : DEVICE=%s \n", dev);

    return(pcap_socket);
}


void Wireless_Print_Status(FILE *fp) 
{
        Node *nd;
        Link *lk;
        Control_Data *c_data;
        stdit it;
        char line[256];
        int connected, loss_rate;

        sprintf(line, "\n\nWireless Neighbors Status: ["IPF"]\n", IP(My_Address)); 
    	Alarm(PRINT, "%s", line); 
    	if (fp != NULL) fprintf(fp, "%s", line); 
        stdhash_begin(&All_Nodes, &it); 
        while(!stdhash_is_end(&All_Nodes, &it)) {
            nd = *((Node **)stdhash_it_val(&it));

#if 0
	    TODO FIX ME

            /* If node has no rssi, then I can't hear it */
            if(nd->nid == My_Address || nd->w_data.rssi == 0) {
 	        stdhash_it_next(&it);
                continue;
            }

            /* Check if this is a connected neighbor */
            if(Is_Connected_Neighbor2(nd)) {
                connected = 1;
            } else {
                connected = 0;
            }

            /* Get loss rate from link information */
            lk = nd->link[CONTROL_LINK];
            if(lk == NULL) {
                loss_rate = -1;
            } else {
                c_data = (Control_Data*)lk->prot_data;
                loss_rate = 100*(c_data->est_loss_rate);
            }

            /* Print wireless status info for this node */
            sprintf(line, IPF "   rssi: %3d;   retx: %3d;   loss: %3d;   connected:%d ", 
                    IP(nd->nid), nd->w_data.rssi, nd->w_data.retry, loss_rate, connected);
            Alarm(PRINT, "%s\n", line);
            if (fp != NULL) fprintf(fp, "%s\n", line);

#endif

	    stdhash_it_next(&it);
        }
    sprintf(line, "\n\n");
    Alarm(PRINT, "%s", line);
    if (fp != NULL) fprintf(fp, "%s", line);
}

