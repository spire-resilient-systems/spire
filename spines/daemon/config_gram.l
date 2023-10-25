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
#include <string.h>

#ifndef  ARCH_PC_WIN95
#include <sys/types.h>
#include <netinet/in.h>

#else /* ARCH_PC_WIN95 */

#include <winsock.h>
#define YY_NO_UNISTD_H  /* Do not include unistd.h header in windows compiles */

#endif /* ARCH_PC_WIN95 */

#include "conf_body.h"
#include "y.tab.h"

extern int line_num;
extern int semantic_errors;
extern int yyerror(char *str);
extern void yywarn(char *str);
%}
qstring \"[^\"]*\"|\'[^\']*\'
string  [^ \t\r\n#{}]+
true    [Tt][Rr][Uu][Ee]
yes     [Yy][Ee][Ss]
on      [Oo][Nn]
false   [Ff][Aa][Ll][Ss][Ee]
no      [Nn][Oo]
off     [Oo][Ff][Ff]
auto    [Aa][Uu][Tt][Oo]
ipaddr  [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}
ipport  [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]{1,5}
%option noyywrap
%option nounput
%option noinput
%%
#.*                         {} /* Comments */
[ \t\r]                     {} /* White space */
\n                          { line_num++;}
"{"                         { return OPENBRACE; }
"}"                         { return CLOSEBRACE; }
"="                         { return EQUALS; }
":"                         { return COLON; }
!/.+ 				        { return BANG; }
DebugFlags                  { return DEBUGFLAGS; }
Crypto                      { return CRYPTO; }
Signature_Len_Bits          { return SIGLENBITS; }
MultiPath_Bitmask_Size      { return MPBITMASKSIZE; }
Directed_Edges              { return DIRECTEDEDGES; }
Path_Stamp_Debug            { return PATHSTAMPDEBUG;  }
Unix_Domain_Path            { return UNIXDOMAINPATH; }
Remote_Connections          { return REMOTECONNECTIONS; }
IT_LinkCrypto               { return ITCRYPTO; }
IT_LinkEncrypt              { return ITENCRYPT; }
IT_OrderedDelivery          { return ORDEREDDELIVERY; }
IT_ReintroduceMessages      { return REINTRODUCEMSGS; }
IT_TCPFairness              { return TCPFAIRNESS; }
IT_SessionBlocking          { return SESSIONBLOCKING; }
IT_MsgPerSAA                { return MSGPERSAA; }
IT_SendBatchSize            { return SENDBATCHSIZE; }
IT_IntrusionToleranceMode   { return ITMODE; }
IT_ReliableTimeoutFactor    { return RELIABLETIMEOUTFACTOR; }
IT_NackTimeoutFactor        { return NACKTIMEOUTFACTOR; }
IT_InitNackTimeoutFactor    { return INITNACKTOFACTOR; }
IT_AckTimeout               { return ACKTO; }
IT_PingTimeout              { return PINGTO; }
IT_DHTimeout                { return DHTO; }
IT_IncarnationTimeout       { return INCARNATIONTO; }
IT_MinRTTMilliseconds       { return MINRTTMS; }
IT_DefaultRTT               { return ITDEFAULTRTT; }
RR_Crypto                   { return RRCRYPTO; }
Prio_Crypto                 { return PRIOCRYPTO; }
Prio_DefaultPrioLevel       { return DEFAULTPRIO; }
Prio_MaxMessStored          { return MAXMESSSTORED; }
Prio_MinBellySize           { return MINBELLYSIZE; }
Prio_DefaultExpireSec       { return DEFAULTEXPIRESEC; }
Prio_DefaultExpireUSec      { return DEFAULTEXPIREUSEC; }
Prio_GarbageCollectionSec   { return GARBAGECOLLECTIONSEC; }
Rel_Crypto                  { return RELCRYPTO; }
Rel_SAAThreshold            { return RELSAATHRESHOLD; }
Rel_HBHAdvance              { return HBHADVANCE; }
Rel_HBHAckTimeout           { return HBHACKTIMEOUT; }
Rel_HBHAckOptimization      { return HBHOPT; }
Rel_E2EAckTimeout           { return E2EACKTIMEOUT; }
Rel_E2EAckOptimization      { return E2EOPT; }
Reroute_LossThreshold       { return LOSSTHRESHOLD; }
Reroute_LossCalcDecay       { return LOSSCALCDECAY; }
Reroute_LossCalcTimeTrigger { return LOSSCALCTIMETRIGGER; }
Reroute_LossCalcPktTrigger  { return LOSSCALCPKTTRIGGER; }
Reroute_LossPenalty         { return LOSSPENALTY; }
Reroute_PingThreshold       { return PINGTHRESHOLD; }
Reroute_StatusChangeTimeout { return STATUSCHANGETIMEOUT; }
Hosts                       { return HOSTS; }
Edges                       { return EDGES; }
{true}|{yes}                { yylval.boolean = TRUE; return SP_BOOL; }
{false}|{no}                { yylval.boolean = FALSE; return SP_BOOL; }
{on}                        { yylval.number = 1; return SP_TRIVAL; }
{off}                       { yylval.number = 0; return SP_TRIVAL; }
{auto}                      { yylval.number = 2; return SP_TRIVAL; }
DEBUG	 			        { yylval.mask = 0x00000001; return DDEBUG; }
EXIT				        { yylval.mask = 0x00000002; return DEXIT; }
PRINT				        { yylval.mask = 0x00000004; return DPRINT; }
DATA_LINK			        { yylval.mask = 0x00000010; return DDATA_LINK; }
NETWORK				        { yylval.mask = 0x00000020; return DNETWORK; }
PROTOCOL			        { yylval.mask = 0x00000040; return DPROTOCOL; }
SESSION				        { yylval.mask = 0x00000080; return DSESSION; }
CONFIGURATION			    { yylval.mask = 0x00000100; return DCONF; }
ALL				            { yylval.mask = 0xffffffff; return DALL; }
NONE				        { yylval.mask = 0x00000000; return DNONE; }
{ipport}                    { struct in_addr inaddr;
                                  int a1,a2,a3,a4,a5;
                                  char *c1,*c2,*c3,*c4,*c5;
                                  c1=strdup(yytext);
                                  c2=strchr(c1, '.'); *(c2++)=0;
                                  c3=strchr(c2, '.'); *(c3++)=0;
                                  c4=strchr(c3, '.'); *(c4++)=0;
                                  c5=strchr(c4, ':'); *(c5++)=0;
                                  a1=atoi(c1); a2=atoi(c2);
                                  a3=atoi(c3); a4=atoi(c4);
                                  a5=atoi(c5);
                                  free(c1);
                                  if ((a1 < 0) || (a1 > 255) ||
				      (a2 < 0) || (a2 > 255) ||
				      (a3 < 0) || (a3 > 255) ||
				      (a4 < 0) || (a4 > 255))
                                    yyerror("Invalid IP");
                                  inaddr.s_addr =
                                      ((a1<<24)|(a2<<16)|(a3<<8)|a4);
                                  yylval.ip.addr = inaddr;
                                  yylval.ip.port = a5;
                                  return IPADDR;
                                }
{ipaddr}                    { struct in_addr inaddr;
                                  int a1,a2,a3,a4;
                                  char *c1,*c2,*c3,*c4;
                                  c1=strdup(yytext);
                                  c2=strchr(c1, '.'); *(c2++)=0;
                                  c3=strchr(c2, '.'); *(c3++)=0;
                                  c4=strchr(c3, '.'); *(c4++)=0;
                                  a1=atoi(c1); a2=atoi(c2);
                                  a3=atoi(c3); a4=atoi(c4);
                                  free(c1);
                                  if ((a1 < 0) || (a1 > 255) ||
				      (a2 < 0) || (a2 > 255) ||
				      (a3 < 0) || (a3 > 255) ||
				      (a4 < 0) || (a4 > 255))
                                    yyerror("Invalid IP");
                                  inaddr.s_addr =
                                      ((a1<<24)|(a2<<16)|(a3<<8)|a4);
                                  yylval.ip.addr = inaddr;
                                  yylval.ip.port = 0;
                                  return IPADDR;
                                }
[0-9]{1,10}                   {
                                  yylval.number = atoi(yytext);
                                  return NUMBER;
                             }
[0-9]{1,6}"."[0-9]{1,6}     {
                                  yylval.decimal = atof(yytext);
                                  return DECIMAL;
                            }
{qstring}                       { int l = strlen(yytext);
                                  yytext[l-1] = 0;
                                  yylval.string = strdup(yytext+1);
                                  return STRING; }
{string}                        { yylval.string = strdup(yytext);
                                  return STRING; }
%%
