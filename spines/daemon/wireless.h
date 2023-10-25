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

#ifndef Wireless_H
#define Wireless_H


typedef struct Wireless_Data_d {
    int16 rssi; 
    int16 retry;
} Wireless_Data;


// Prism 802.11 headers from wlan-ng tacked on to the beginning of a
// pcap packet... Snagged from the wlan-ng source

typedef struct {
    uint32_t did;
    uint16_t status;
    uint16_t len;
    uint32_t data;
} p80211item_uint32_t;


typedef struct {
    uint32_t msgcode;
    uint32_t msglen;
    uint8_t devname[16];
    p80211item_uint32_t hosttime;
    p80211item_uint32_t mactime;
    p80211item_uint32_t ch; 
    p80211item_uint32_t rssi;
    p80211item_uint32_t sq;
    p80211item_uint32_t signal;
    p80211item_uint32_t noise;
    p80211item_uint32_t rate;
    p80211item_uint32_t istx;
    p80211item_uint32_t frmlen;
} wlan_header;


typedef struct {
        unsigned short frame_control; 
        unsigned short duration;
        unsigned char mac1[6];
        unsigned char mac2[6];
        unsigned char mac3[6];
        unsigned short SeqCtl;
} ieee_802_11_header;

typedef struct {
	unsigned char dsap;   
	unsigned char ssap;  
    unsigned char ctrl;   
	unsigned char oui[3];   
	unsigned short unknown1; 
	//unsigned short unknown2;
} llc_header;


typedef struct {
        u_int8_t        ip_vhl;         /* header length, version */
        u_int8_t        ip_tos;         /* type of service */
        u_int16_t       ip_len;         /* total length */
        u_int16_t       ip_id;          /* identification */
        u_int16_t       ip_off;         /* fragment offset field */
        u_int8_t        ip_ttl;         /* time to live */
        u_int8_t        ip_p;           /* protocol */
        u_int16_t       ip_sum;         /* checksum */
        struct in_addr  ip_src,ip_dst;  /* source and dest address */
} my_ip_header;


typedef struct {
    unsigned short source_port;
    unsigned short dest_port;
    unsigned short len;
    unsigned short sum;
} my_udp_header;


/* Here we define some libpcap stuff.  They are not likely
   to change.  However, you may need to include your libpcap
   directory, erase the following lines, and #include pcap.h */
#define PCAP_ERRBUF_SIZE 256
typedef struct pcap pcap_t;
typedef	int bpf_int32;
typedef	u_int bpf_u_int32;
struct pcap_pkthdr {
	struct timeval ts;	/* time stamp */
	bpf_u_int32 caplen;	/* length of portion present */
	bpf_u_int32 len;	/* length this packet (off wire) */
};
struct bpf_insn {
	u_short	code;
	u_char 	jt;
	u_char 	jf;
	bpf_int32 k;
};
struct bpf_program {
	u_int bf_len;
	struct bpf_insn *bf_insns;
};


void Wireless_Init();
void Wireless_process_pkt(int sk, int dummy_i, void *pcap_handler);
inline int init_p80211(char *dev, int promisc, pcap_t** descr, char *my_filter);
void Wireless_Print_Status(FILE *fp);


#endif



