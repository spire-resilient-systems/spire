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
 *  Copyright (C) 1993-2016 Spread Concepts LLC <info@spreadconcepts.com>
 *
 *  All Rights Reserved.
 *
 * Major Contributor(s):
 * ---------------
 *    Amy Babay            babay@cs.jhu.edu - accelerated ring protocol.
 *    Ryan Caudy           rcaudy@gmail.com - contributions to process groups.
 *    Claudiu Danilov      claudiu@acm.org - scalable wide area support.
 *    Cristina Nita-Rotaru crisn@cs.purdue.edu - group communication security.
 *    Theo Schlossnagle    jesus@omniti.com - Perl, autoconf, old skiplist.
 *    Dan Schoenblum       dansch@cnds.jhu.edu - Java interface.
 *
 */

#ifndef INC_ALARM
#define INC_ALARM

#include <stdio.h>
#include "spu_system.h"

/* SPCLAMP can be useful with snprintfs:
   {
     char msg[10], *c = msg, *e = msg + sizeof(msg);

     c += snprintf(c, SPCLAMP(c, e), "hello world!\n");
     c += snprintf(c, SPCLAMP(c, e), "neato!\n");
     c += snprintf(c, SPCLAMP(c, e), "how many we doing?!\n");
     and so on ...

     when done, if you care, check if you overfilled (but not
     overran!) your nul terminated buffer (termination guaranteed so
     long as c < e initially):

     if (c > e)
       do stuff;

     (c - msg) is how many characters you tried to write
   }

   Note, this isn't 100% standards compliant bc pointer arithmetic and
   comparison beyond the end of an array isn't guaranteed to be
   meaningful and valid, but it will work on most sane architectures.
 */
#define SPCLAMP(x, y) ((x) < (y) ? (y) - (x) : 0)

/* Type for Alarm realtime handler functions */
typedef int (alarm_realtime_handler)( int16, int32, char *, size_t, char *, size_t);

/* These are always defined for any project using this library */
#define		ALL		0xffffffff
#define 	EXIT  		0x00000001   /* Program will print then exit() or abort() */
#define		DATA_LINK	0x00000002
#define         MEMORY          0x00000004
#define		EVENTS		0x00000008
#define		NONE		0x00000000

/* This includes the custom types for each project */
#include "spu_alarm_types.h"

/* Priority levels */
#define         SPLOG_DEBUG     0x0001       /* Program information that is only useful for debugging. 
                                                Will normally be turned off in operation. */
#define         SPLOG_INFO      0x0002       /* Program reports information that may be useful for 
                                                performance tuning, analysis, or operational checks. */
#define         SPLOG_WARNING   0x0003       /* Program encountered a situation that is not erroneous, 
                                                but is uncommon and may indicate an error. */
#define         SPLOG_ERROR     0x0004       /* Program encountered an error that can be recovered from. */
#define         SPLOG_CRITICAL  0x0005       /* Program will not exit, but has only temporarily recovered 
                                                and without help may soon fail. */
#define         SPLOG_PRINT     0x0006       /* Program will always print, regardless of mask */
#define         SPLOG_FATAL     0x0007       /* Program will always print, regardless of mask, then exit() or abort(). */


#define         SPLOG_PRIORITY_FIELDS 0x000f

/* Feature Flags for Priority field */
#define         SPLOG_NODATE    0x0010       /* Program should omit the datestamp at the beginning of the message. */
#define         SPLOG_REALTIME  0x0020       /* This message should be disseminated through the realtime handler if possible.
                                                This is used for alerts you want sent now and not just logged (they are also logged). */
#define         SPLOG_PRIORITY_FLAGS 0x00f0

/* Can be used to conditionally skip calls to Alarmp (e.g. - expensive parameter evaluation, repeatedly called, etc.) */

#define ALARMP_NEEDED(p, m) (                                           \
    ( (m) & EXIT ) ||                                                   \
    ( ( (p) & SPLOG_PRIORITY_FIELDS ) >= SPLOG_PRINT ) ||               \
    ( ( (p) & SPLOG_PRIORITY_FIELDS ) >= Alarm_cur_priority && ( (m) & Alarm_type_mask ) ) )

extern int32u Alarm_type_mask;
extern int16u Alarm_cur_priority;

void  Alarmp(int16 priority, int32 type, char *message, ...);
void  Alarm(int32 type, char *message, ...);

void  Alarm_set_output(char *filename);

void  Alarm_enable_timestamp(const char *format);
void  Alarm_enable_timestamp_high_res(const char *format);
void  Alarm_disable_timestamp(void);

void  Alarm_set_types(int32 mask);
void  Alarm_clear_types(int32 mask);
int32 Alarm_get_types(void);

void  Alarm_set_priority(int16 priority);
int16 Alarm_get_priority(void);

void  Alarm_set_realtime_print_handler( alarm_realtime_handler *output_message_function );

void  Alarm_set_interactive(void);
int   Alarm_get_interactive(void);

#define IPF "%d.%d.%d.%d"

#define IP1(address)  ( (int) ( ( (address) >> 24 ) & 0xFF ) )
#define IP2(address)  ( (int) ( ( (address) >> 16 ) & 0xFF ) )
#define IP3(address)  ( (int) ( ( (address) >>  8 ) & 0xFF ) )
#define IP4(address)  ( (int) ( ( (address) >>  0 ) & 0xFF ) )

#define IP(address) IP1(address), IP2(address), IP3(address), IP4(address)

#define IP1_NET(address)  ( (int) ( (unsigned char*) &(address) )[0] )
#define IP2_NET(address)  ( (int) ( (unsigned char*) &(address) )[1] )
#define IP3_NET(address)  ( (int) ( (unsigned char*) &(address) )[2] )
#define IP4_NET(address)  ( (int) ( (unsigned char*) &(address) )[3] )

#define IP_NET(address) IP1_NET(address), IP2_NET(address), IP3_NET(address), IP4_NET(address)

#endif	/* INC_ALARM */
