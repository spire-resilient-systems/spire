%{
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef ARCH_PC_WIN95
#include <sys/types.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/param.h>

#else /* ARCH_PC_WIN95 */
#include <winsock.h>
#endif /* ARCH_PC_WIN95 */

#include "spu_alarm.h"
#include "configuration.h"
#include "spu_memory.h"
#include "spu_objects.h"
#include "conf_body.h"

        int     line_num, semantic_errors;
 extern char    *yytext;
 extern int     yyerror(char *str);
 extern void    yywarn(char *str);
 extern int     yylex();

/* #define MAX_ALARM_FORMAT 40
 static char    alarm_format[MAX_ALARM_FORMAT];
 static int     alarm_precise = 0;
 static int     alarm_custom_format = 0; */

void    parser_init()
{
    /* Defaults Here */
}

/* static char *segment2str(int seg) {
  static char ipstr[40];
  int id = Config->segments[seg].bcast_address;
  sprintf(ipstr, "%d.%d.%d.%d:%d",
  	(id & 0xff000000)>>24,
  	(id & 0xff0000)>>16,
  	(id & 0xff00)>>8,
  	(id & 0xff),
	Config->segments[seg].port);
  return ipstr;
}
static void alarm_print_proc(proc *p, int port) {
  if(port == p->port)
    Alarm(CONF_SYS, "\t%20s: %d.%d.%d.%d\n", p->name,
  	  (p->id & 0xff000000)>>24,
  	  (p->id & 0xff0000)>>16,
  	  (p->id & 0xff00)>>8,
  	  (p->id & 0xff));
  else
    Alarm(CONF_SYS, "\t%20s: %d.%d.%d.%d:%d\n", p->name,
  	  (p->id & 0xff000000)>>24,
  	  (p->id & 0xff0000)>>16,
  	  (p->id & 0xff00)>>8,
  	  (p->id & 0xff),
	  p->port);
}

static int32u name2ip(char *name) {
  int anip, i1, i2, i3, i4;
  struct hostent *host_ptr;

  host_ptr = gethostbyname(name);
  
  if ( host_ptr == 0)
    Alarm( EXIT, "Conf_init: no such host %s\n",
	   name);
  
  memcpy(&anip, host_ptr->h_addr_list[0], 
	 sizeof(int32) );
  anip = htonl( anip );
  i1= ( anip & 0xff000000 ) >> 24;
  i2= ( anip & 0x00ff0000 ) >> 16;
  i3= ( anip & 0x0000ff00 ) >>  8;
  i4=   anip & 0x000000ff;
  return ((i1<<24)|(i2<<16)|(i3<<8)|i4);
}

static  void expand_filename(char *out_string, int str_size, const char *in_string)
{
  const char *in_loc;
  char *out_loc;
  char hostn[MAXHOSTNAMELEN+1];
  
  for ( in_loc = in_string, out_loc = out_string; out_loc - out_string < str_size; in_loc++ )
  {
          if (*in_loc == '%' ) {
                  switch( in_loc[1] ) {
                  case 'h':
                  case 'H':
                          gethostname(hostn, sizeof(hostn) );
                          out_loc += snprintf(out_loc, str_size - (out_loc - out_string), "%s", hostn); 
                          in_loc++;
                          continue;
                  default:
                          break;
                  }

          }
          *out_loc = *in_loc;
          out_loc++;
          if (*in_loc == '\0') break;
  }
  out_string[str_size-1] = '\0';
}

static  int 	get_parsed_proc_info( char *name, proc *p )
{
	int	i;

	for ( i=0; i < num_procs; i++ )
	{
		if ( strcmp( Config->allprocs[i].name, name ) == 0 )
		{
			*p = Config->allprocs[i];
			return( i );
		}
	}
	return( -1 );
}
*/

/* convert_segment_to_string()
 * char * segstr : output string
 * int strsize : length of output string space
 * segment *seg : input segment structure
 * int return : length of string written or -1 if error (like string not have room)
 * 
 *
 * The format of the returned string will be as shown below with each segment appended
 * to the string. Each use of IPB will be replaced with the broadcast IP address, port
 * with the port. The optional section is a list of interfaces tagged with D or C
 * and idnetified by ip address. 
 *
 * "Segment IP:port host1name host1ip (ALL/ANY/C/D/M IP)+ host2name host2ip (ALL/ANY/C/D/M IP )+ ..."
 *
 */
/* static  int    convert_segment_to_string(char *segstr, int strsize, segment *seg)
{
    int         i,j;
    size_t      curlen = 0;
    char        temp_str[200];

    sprintf(temp_str, "Segment %d.%d.%d.%d:%d ", 
            (seg->bcast_address & 0xff000000)>>24, 
            (seg->bcast_address & 0xff0000)>>16, 
            (seg->bcast_address & 0xff00)>>8, 
            (seg->bcast_address & 0xff), 
            seg->port );

    strncat( segstr, temp_str, strsize - curlen);
    curlen += strlen(temp_str);

    for (i = 0; i < seg->num_procs; i++) {
        sprintf(temp_str, "%s %d.%d.%d.%d ", 
                seg->procs[i]->name, 
                (seg->procs[i]->id & 0xff000000)>>24, 
                (seg->procs[i]->id & 0xff0000)>>16, 
                (seg->procs[i]->id & 0xff00)>>8, 
                (seg->procs[i]->id & 0xff) );
        strncat( segstr, temp_str, strsize - curlen);
        curlen += strlen(temp_str); */

        /* Now add all interfaces */
        /* for ( j=0 ; j < seg->procs[i]->num_if; j++) { */
            /* add addional interface specs to string */
            /* if ( seg->procs[i]->ifc[j].type & IFTYPE_ANY )
            {
                strncat( segstr, "ANY ", strsize - curlen);
                curlen += 4;
            }
            if ( seg->procs[i]->ifc[j].type & IFTYPE_DAEMON )
            {
                strncat( segstr, "D ", strsize - curlen);
                curlen += 2;
            }
            if ( seg->procs[i]->ifc[j].type & IFTYPE_CLIENT )
            {
                strncat( segstr, "C ", strsize - curlen);
                curlen += 2;
            }
            if ( seg->procs[i]->ifc[j].type & IFTYPE_MONITOR )
            {
                strncat( segstr, "M ", strsize - curlen);
                curlen += 2;
            }
            sprintf(temp_str, "%d.%d.%d.%d ", 
                (seg->procs[i]->ifc[j].ip & 0xff000000)>>24, 
                (seg->procs[i]->ifc[j].ip & 0xff0000)>>16, 
                (seg->procs[i]->ifc[j].ip & 0xff00)>>8, 
                (seg->procs[i]->ifc[j].ip & 0xff) );
            strncat( segstr, temp_str, strsize - curlen);
            curlen += strlen(temp_str);
        }
    } */

    /* terminate each segment by a newline */
    /* strncat( segstr, "\n", strsize - curlen);
    curlen += 1;

    if (curlen > strsize) { */
        /* ran out of space in string -- should never happen. */
/*        Alarmp( SPLOG_ERROR, CONF_SYS, "config_parse.y:convert_segment_to_string: The segment string is too long! %d characters attemped is more then %d characters allowed", curlen, strsize);
        Alarmp( SPLOG_ERROR, CONF_SYS, "config_parse.y:convert_segment_to_string:The error occured on segment %d.%d.%d.%d. Successful string was: %s\n",
                (seg->bcast_address & 0xff000000)>>24, 
                (seg->bcast_address & 0xff0000)>>16, 
                (seg->bcast_address & 0xff00)>>8, 
                (seg->bcast_address & 0xff), 
                segstr);
        return(-1);
    }

    Alarmp( SPLOG_DEBUG, CONF_SYS, "config_parse.y:convert_segment_to_string:The segment string is %d characters long:\n%s", curlen, segstr);
    return(curlen);
}

#define PROC_NAME_CHECK( stoken ) { \
                                            char strbuf[80]; \
                                            int ret; \
                                            proc p; \
                                            if ( strlen((stoken)) >= MAX_PROC_NAME ) { \
                                                snprintf(strbuf, 80, "Too long name(%d max): %s)\n", MAX_PROC_NAME, (stoken)); \
                                                return (yyerror(strbuf)); \
                                            } \
                                            ret = get_parsed_proc_info( stoken, &p ); \
                                            if (ret >= 0) { \
                                                snprintf(strbuf, 80, "Name not unique. name: %s equals (%s, %d.%d.%d.%d)\n", (stoken), p.name, IP1(p.id), IP2(p.id), IP3(p.id), IP4(p.id) ); \
                                                return (yyerror(strbuf)); \
                                            } \
                                         }
#define PROCS_CHECK( num_procs, stoken ) { \
                                            char strbuf[80]; \
                                            if ( (num_procs) >= MAX_PROCS_RING ) { \
                                                snprintf(strbuf, 80, "%s (Too many daemons configured--%d max)\n", (stoken), MAX_PROCS_RING); \
                                                return (yyerror(strbuf)); \
                                            } \
                                         }
#define SEGMENT_CHECK( num_segments, stoken )  { \
                                            char strbuf[80]; \
                                            if ( (num_segments) >= MAX_SEGMENTS ) { \
                                                snprintf(strbuf, 80, "%s (Too many segments configured--%d max)\n", (stoken), MAX_SEGMENTS); \
                                                return( yyerror(strbuf)); \
                                            } \
                                         }
#define SEGMENT_SIZE_CHECK( num_procs, stoken )  { \
                                            char strbuf[80]; \
                                            if ( (num_procs) >= MAX_PROCS_SEGMENT ) { \
                                                snprintf(strbuf, 80, "%s (Too many daemons configured in segment--%d max)\n", (stoken), MAX_PROCS_SEGMENT); \
                                                return( yyerror(strbuf)); \
                                            } \
                                         }
#define INTERFACE_NUM_CHECK( num_ifs, stoken )  { \
                                            char strbuf[80]; \
                                            if ( (num_ifs) >= MAX_INTERFACES_PROC ) { \
                                                snprintf(strbuf, 80, "%s (Too many interfaces configured in proc--%d max)\n", (stoken), MAX_INTERFACES_PROC); \
                                                return( yyerror(strbuf)); \
                                            } \
                                         }

*/
%}
%start Config
%token OPENBRACE CLOSEBRACE EQUALS COLON BANG
%token DEBUGFLAGS CRYPTO SIGLENBITS MPBITMASKSIZE DIRECTEDEDGES PATHSTAMPDEBUG UNIXDOMAINPATH
%token REMOTECONNECTIONS
%token RRCRYPTO
%token ITCRYPTO ITENCRYPT ORDEREDDELIVERY REINTRODUCEMSGS TCPFAIRNESS SESSIONBLOCKING MSGPERSAA
%token SENDBATCHSIZE ITMODE RELIABLETIMEOUTFACTOR NACKTIMEOUTFACTOR INITNACKTOFACTOR 
%token ACKTO PINGTO DHTO INCARNATIONTO MINRTTMS ITDEFAULTRTT
%token PRIOCRYPTO DEFAULTPRIO MAXMESSSTORED MINBELLYSIZE
%token DEFAULTEXPIRESEC DEFAULTEXPIREUSEC GARBAGECOLLECTIONSEC
%token RELCRYPTO RELSAATHRESHOLD HBHADVANCE HBHACKTIMEOUT HBHOPT E2EACKTIMEOUT E2EOPT
%token LOSSTHRESHOLD LOSSCALCDECAY LOSSCALCTIMETRIGGER LOSSCALCPKTTRIGGER
%token LOSSPENALTY PINGTHRESHOLD STATUSCHANGETIMEOUT
%token HOSTS EDGES
%token SP_BOOL SP_TRIVAL 
%token DDEBUG DEXIT DPRINT DDATA_LINK DNETWORK DPROTOCOL DSESSION DCONF DALL DNONE
%token IPADDR NUMBER DECIMAL STRING 
%%
Config		:	ConfigStructs
        ;

ConfigStructs	:	ParamStruct ConfigStructs
        |           HostStruct ConfigStructs
        |           EdgeStruct ConfigStructs
        |
		;

ParamStruct	: 
        CRYPTO EQUALS SP_BOOL { Conf_set_all_crypto($3.boolean); } 
    |   SIGLENBITS EQUALS NUMBER { Conf_set_signature_len_bits($3.number); }
    |   MPBITMASKSIZE EQUALS NUMBER { Conf_set_multipath_bitmask_size($3.number); }
    |   DIRECTEDEDGES EQUALS SP_BOOL { Conf_set_directed_edges($3.boolean); }
    |   PATHSTAMPDEBUG EQUALS SP_BOOL { Conf_set_path_stamp_debug($3.boolean); }
    |   UNIXDOMAINPATH EQUALS STRING { Conf_set_unix_domain_path($3.string); }
    |   REMOTECONNECTIONS EQUALS SP_BOOL { Conf_set_remote_connections($3.boolean); }

    |   ITCRYPTO EQUALS SP_BOOL { Conf_set_IT_crypto($3.boolean); }
    |   ITENCRYPT EQUALS SP_BOOL { Conf_set_IT_encrypt($3.boolean); }
    |   ORDEREDDELIVERY EQUALS SP_BOOL { Conf_set_IT_ordered_delivery($3.boolean); }
    |   REINTRODUCEMSGS EQUALS SP_BOOL { Conf_set_IT_reintroduce_messages($3.boolean); }
    |   TCPFAIRNESS EQUALS SP_BOOL { Conf_set_IT_tcp_fairness($3.boolean); }
    |   SESSIONBLOCKING EQUALS SP_BOOL { Conf_set_IT_session_blocking($3.boolean); }
    |   MSGPERSAA EQUALS NUMBER { Conf_set_IT_msg_per_saa($3.number); }
    |   SENDBATCHSIZE EQUALS NUMBER { Conf_set_IT_send_batch_size($3.number); }
    |   ITMODE EQUALS SP_BOOL { Conf_set_IT_intrusion_tolerance_mode($3.boolean); }
    |   RELIABLETIMEOUTFACTOR EQUALS NUMBER { Conf_set_IT_reliable_timeout_factor($3.number); }
    |   NACKTIMEOUTFACTOR EQUALS NUMBER { Conf_set_IT_nack_timeout_factor($3.number); }
    |   INITNACKTOFACTOR EQUALS DECIMAL { Conf_set_IT_init_nack_timeout_factor($3.decimal); }
    |   ACKTO EQUALS NUMBER { Conf_set_IT_ack_timeout($3.number); }
    |   PINGTO EQUALS NUMBER { Conf_set_IT_ping_timeout($3.number); }
    |   DHTO EQUALS NUMBER { Conf_set_IT_dh_timeout($3.number); }
    |   INCARNATIONTO EQUALS NUMBER { Conf_set_IT_incarnation_timeout($3.number); }
    |   MINRTTMS EQUALS NUMBER { Conf_set_IT_min_RTT_ms($3.number); }
    |   ITDEFAULTRTT EQUALS NUMBER { Conf_set_IT_default_RTT($3.number); }
    
    |   RRCRYPTO EQUALS SP_BOOL { Conf_set_RR_crypto($3.boolean); }
    
    |   PRIOCRYPTO EQUALS SP_BOOL { Conf_set_Prio_crypto($3.boolean); }
    |   DEFAULTPRIO EQUALS NUMBER { Conf_set_Prio_default_prio($3.number); }
    |   MAXMESSSTORED EQUALS NUMBER { Conf_set_Prio_max_mess_stored($3.number); }
    |   MINBELLYSIZE EQUALS NUMBER { Conf_set_Prio_min_belly_size($3.number); }
    |   DEFAULTEXPIRESEC EQUALS NUMBER { Conf_set_Prio_default_expire_sec($3.number); }
    |   DEFAULTEXPIREUSEC EQUALS NUMBER { Conf_set_Prio_default_expire_usec($3.number); }
    |   GARBAGECOLLECTIONSEC EQUALS NUMBER { Conf_set_Prio_garbage_collection_sec($3.number); }
    
    |   RELCRYPTO EQUALS SP_BOOL { Conf_set_Rel_crypto($3.boolean); }
    |   RELSAATHRESHOLD EQUALS NUMBER { Conf_set_Rel_saa_threshold($3.number); }
    |   HBHADVANCE EQUALS SP_BOOL { Conf_set_Rel_hbh_advance($3.boolean); }
    |   HBHACKTIMEOUT EQUALS NUMBER { Conf_set_Rel_hbh_ack_timeout($3.number); }
    |   HBHOPT EQUALS SP_BOOL { Conf_set_Rel_hbh_ack_optimization($3.boolean); }
    |   E2EACKTIMEOUT EQUALS NUMBER { Conf_set_Rel_e2e_ack_timeout($3.number); }
    |   E2EOPT EQUALS SP_BOOL { Conf_set_Rel_e2e_ack_optimization($3.boolean); }

    |   LOSSTHRESHOLD EQUALS DECIMAL { Conf_set_Reroute_loss_threshold($3.decimal); }
    |   LOSSCALCDECAY EQUALS DECIMAL { Conf_set_Reroute_loss_calc_decay($3.decimal); }
    |   LOSSCALCTIMETRIGGER EQUALS NUMBER { Conf_set_Reroute_loss_calc_time_trigger($3.number); }
    |   LOSSCALCPKTTRIGGER EQUALS NUMBER { Conf_set_Reroute_loss_calc_pkt_trigger($3.number); }
    |   LOSSPENALTY EQUALS NUMBER { Conf_set_Reroute_loss_penalty($3.number); }
    |   PINGTHRESHOLD EQUALS NUMBER { Conf_set_Reroute_ping_threshold($3.number); }
    |   STATUSCHANGETIMEOUT EQUALS NUMBER { Conf_set_Reroute_status_change_timeout($3.number); }
        ;

HostStruct :  HOSTS OPENBRACE HostList CLOSEBRACE { Conf_validate_hosts(); }
        ;

HostList : Host HostList
        | Host             /* Must be at least one host listed */
        ;

Host : NUMBER IPADDR { Conf_add_host($1.number, $2.ip.addr.s_addr); }
        ;

EdgeStruct : EDGES OPENBRACE EdgeList CLOSEBRACE
        ;

EdgeList : Edge EdgeList
        | Edge              /* Must be at least one edge listed */
        ;

Edge : NUMBER NUMBER NUMBER { Conf_add_edge($1.number, $2.number, $3.number); }
        ;

%%
void yywarn(char *str) {
        fprintf(stderr, "-------Parse Warning-----------\n");
        fprintf(stderr, "Parser warning on or before line %d\n", line_num);
        fprintf(stderr, "Error type; %s\n", str);
        fprintf(stderr, "Offending token: %s\n", yytext);
}
int yyerror(char *str) {
  fprintf(stderr, "-------------------------------------------\n");
  fprintf(stderr, "Parser error on or before line %d\n", line_num);
  fprintf(stderr, "Error type; %s\n", str);
  fprintf(stderr, "Offending token: %s\n", yytext);
  exit(1);
}
