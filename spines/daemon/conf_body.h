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

#ifndef CONF_BODY_H
#define CONF_BODY_H

#include "arch.h"
#include "configuration.h"

int		yyparse();
void    parser_init();

#undef  ext
#ifndef ext_conf_body
#define ext extern
#else
#define ext
#endif

ext     FILE		*yyin;

#define MAX_CONF_STRING 20000
ext     char            ConfStringRep[MAX_CONF_STRING];
ext     int             ConfStringLen;

#define YYSTYPE YYSTYPE

#ifndef	ARCH_PC_WIN95

#include <netinet/in.h>

#else 	/* ARCH_PC_WIN95 */

#include <winsock.h>

#endif	/* ARCH_PC_WIN95 */

typedef union {
  bool boolean;
  int32 mask;
  int number;
  float decimal;
  struct {
    struct in_addr addr;
    unsigned short port;
  } ip;
  char *string;
} YYSTYPE;

extern YYSTYPE yylval;
extern int yysemanticerr;

#endif /* CONF_BODY_H */
