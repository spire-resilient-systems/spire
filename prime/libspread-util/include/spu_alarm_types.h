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


#ifndef INC_ALARM_TYPES
#define INC_ALARM_TYPES

/* List of type values that are valid for this project.
 * This list can be customized for each user of Alarm library.
 * The defines must be consistent amoung all code that will be compiled together, 
 * but can be different for different executables 
 */
#define		PRINT		0x00000010
#define         SYSTEM          0x00000010  /* NOTE: same as PRINT */

#define		NETWORK		0x00000020
#define		PROTOCOL	0x00000040
#define		SESSION		0x00000080
#define		CONF_SYS	0x00000100
#define		MEMB		0x00000200
#define		FLOW_CONTROL	0x00000400
#define		STATUS		0x00000800
#define		DEBUG		0x00001000
#define		GROUPS		0x00002000

#define         HOP             0x00004000
#define         OBJ_HANDLER     0x00008000
#define         ROUTE           0x00020000
#define         QOS             0x00040000
#define         RING            0x00080000
#define         TCP_HOP         0x00100000

#define         SKIPLIST        0x00200000
#define         ACM             0x00400000

#define         SECURITY        0x00800000

#endif	/* INC_ALARM_TYPES */
