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

#ifndef SYSTEM_DEFS_WINDOWS_H
#define SYSTEM_DEFS_WINDOWS_H

#ifndef SYSTEM_DEFS_H
#error "system_defs_windows.h should never be directly included. Include system_defs.h."
#endif

#define         LOC_INLINE

#ifndef int16
#define int16 short
#endif

#ifndef int16u
#define int16u unsigned short
#endif

#ifndef int32
#define int32 int
#endif

#ifndef int32u
#define int32u unsigned int
#endif

#ifndef UINT32_MAX
#define         UINT32_MAX      UINT_MAX
#endif
#ifndef INT32_MAX
#define         INT32_MAX       INT_MAX
#endif

#ifndef int64_t
#define int64_t __int64
#endif

#ifdef MSG_MAXIOVLEN
#define         SPU_ARCH_SCATTER_SIZE       MSG_MAXIOVLEN
#else
#define         SPU_ARCH_SCATTER_SIZE       64
#endif


#endif /* SYSTEM_DEFS_WINDOWS_H */
