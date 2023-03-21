/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton interface for Bison's Yacc-like parsers in C

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     OPENBRACE = 258,
     CLOSEBRACE = 259,
     EQUALS = 260,
     COLON = 261,
     BANG = 262,
     DEBUGFLAGS = 263,
     CRYPTO = 264,
     SIGLENBITS = 265,
     MPBITMASKSIZE = 266,
     DIRECTEDEDGES = 267,
     PATHSTAMPDEBUG = 268,
     UNIXDOMAINPATH = 269,
     REMOTECONNECTIONS = 270,
     RRCRYPTO = 271,
     ITCRYPTO = 272,
     ITENCRYPT = 273,
     ORDEREDDELIVERY = 274,
     REINTRODUCEMSGS = 275,
     TCPFAIRNESS = 276,
     SESSIONBLOCKING = 277,
     MSGPERSAA = 278,
     SENDBATCHSIZE = 279,
     ITMODE = 280,
     RELIABLETIMEOUTFACTOR = 281,
     NACKTIMEOUTFACTOR = 282,
     INITNACKTOFACTOR = 283,
     ACKTO = 284,
     PINGTO = 285,
     DHTO = 286,
     INCARNATIONTO = 287,
     MINRTTMS = 288,
     ITDEFAULTRTT = 289,
     PRIOCRYPTO = 290,
     DEFAULTPRIO = 291,
     MAXMESSSTORED = 292,
     MINBELLYSIZE = 293,
     DEFAULTEXPIRESEC = 294,
     DEFAULTEXPIREUSEC = 295,
     GARBAGECOLLECTIONSEC = 296,
     RELCRYPTO = 297,
     RELSAATHRESHOLD = 298,
     HBHADVANCE = 299,
     HBHACKTIMEOUT = 300,
     HBHOPT = 301,
     E2EACKTIMEOUT = 302,
     E2EOPT = 303,
     LOSSTHRESHOLD = 304,
     LOSSCALCDECAY = 305,
     LOSSCALCTIMETRIGGER = 306,
     LOSSCALCPKTTRIGGER = 307,
     LOSSPENALTY = 308,
     PINGTHRESHOLD = 309,
     STATUSCHANGETIMEOUT = 310,
     HOSTS = 311,
     EDGES = 312,
     SP_BOOL = 313,
     SP_TRIVAL = 314,
     DDEBUG = 315,
     DEXIT = 316,
     DPRINT = 317,
     DDATA_LINK = 318,
     DNETWORK = 319,
     DPROTOCOL = 320,
     DSESSION = 321,
     DCONF = 322,
     DALL = 323,
     DNONE = 324,
     IPADDR = 325,
     NUMBER = 326,
     DECIMAL = 327,
     STRING = 328
   };
#endif
/* Tokens.  */
#define OPENBRACE 258
#define CLOSEBRACE 259
#define EQUALS 260
#define COLON 261
#define BANG 262
#define DEBUGFLAGS 263
#define CRYPTO 264
#define SIGLENBITS 265
#define MPBITMASKSIZE 266
#define DIRECTEDEDGES 267
#define PATHSTAMPDEBUG 268
#define UNIXDOMAINPATH 269
#define REMOTECONNECTIONS 270
#define RRCRYPTO 271
#define ITCRYPTO 272
#define ITENCRYPT 273
#define ORDEREDDELIVERY 274
#define REINTRODUCEMSGS 275
#define TCPFAIRNESS 276
#define SESSIONBLOCKING 277
#define MSGPERSAA 278
#define SENDBATCHSIZE 279
#define ITMODE 280
#define RELIABLETIMEOUTFACTOR 281
#define NACKTIMEOUTFACTOR 282
#define INITNACKTOFACTOR 283
#define ACKTO 284
#define PINGTO 285
#define DHTO 286
#define INCARNATIONTO 287
#define MINRTTMS 288
#define ITDEFAULTRTT 289
#define PRIOCRYPTO 290
#define DEFAULTPRIO 291
#define MAXMESSSTORED 292
#define MINBELLYSIZE 293
#define DEFAULTEXPIRESEC 294
#define DEFAULTEXPIREUSEC 295
#define GARBAGECOLLECTIONSEC 296
#define RELCRYPTO 297
#define RELSAATHRESHOLD 298
#define HBHADVANCE 299
#define HBHACKTIMEOUT 300
#define HBHOPT 301
#define E2EACKTIMEOUT 302
#define E2EOPT 303
#define LOSSTHRESHOLD 304
#define LOSSCALCDECAY 305
#define LOSSCALCTIMETRIGGER 306
#define LOSSCALCPKTTRIGGER 307
#define LOSSPENALTY 308
#define PINGTHRESHOLD 309
#define STATUSCHANGETIMEOUT 310
#define HOSTS 311
#define EDGES 312
#define SP_BOOL 313
#define SP_TRIVAL 314
#define DDEBUG 315
#define DEXIT 316
#define DPRINT 317
#define DDATA_LINK 318
#define DNETWORK 319
#define DPROTOCOL 320
#define DSESSION 321
#define DCONF 322
#define DALL 323
#define DNONE 324
#define IPADDR 325
#define NUMBER 326
#define DECIMAL 327
#define STRING 328




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef int YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;

