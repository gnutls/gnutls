/* A Bison parser, made from x509_ASN.y
   by GNU bison 1.32.  */

#define YYBISON 1  /* Identify Bison output.  */

# define	ASSIG	257
# define	NUM	258
# define	IDENTIFIER	259
# define	OPTIONAL	260
# define	INTEGER	261
# define	SIZE	262
# define	OCTET	263
# define	STRING	264
# define	SEQUENCE	265
# define	BIT	266
# define	UNIVERSAL	267
# define	PRIVATE	268
# define	APPLICATION	269
# define	DEFAULT	270
# define	CHOICE	271
# define	OF	272
# define	OBJECT	273
# define	STR_IDENTIFIER	274
# define	BOOLEAN	275
# define	TRUE	276
# define	FALSE	277
# define	TOKEN_NULL	278
# define	ANY	279
# define	DEFINED	280
# define	BY	281
# define	SET	282
# define	EXPLICIT	283
# define	IMPLICIT	284
# define	DEFINITIONS	285
# define	TAGS	286
# define	BEGIN	287
# define	END	288
# define	UTCTime	289
# define	GeneralizedTime	290
# define	FROM	291
# define	IMPORTS	292
# define	ENUMERATED	293

#line 30 "x509_ASN.y"
 
#include <gnutls_int.h>
#include <x509_asn1.h>
#include <gnutls_errors.h>

FILE *file_asn1;         /* Pointer to file to parse */
extern int parse_mode;   /* PARSE_MODE_CHECK  = only syntax check
                            PARSE_MODE_CREATE = structure creation */ 
int result_parse;        /* result of the parser algorithm */
node_asn *p_tree;        /* pointer to the root of the structure 
                            created by the parser*/     

int yyerror (char *);
int yylex(void);


#line 48 "x509_ASN.y"
#ifndef YYSTYPE
typedef union {
  unsigned int constant;
  char str[129];
  node_asn* node;
} yystype;
# define YYSTYPE yystype
#endif
#ifndef YYDEBUG
# define YYDEBUG 0
#endif



#define	YYFINAL		189
#define	YYFLAG		-32768
#define	YYNTBASE	50

/* YYTRANSLATE(YYLEX) -- Bison token number corresponding to YYLEX. */
#define YYTRANSLATE(x) ((unsigned)(x) <= 293 ? yytranslate[x] : 93)

/* YYTRANSLATE[YYLEX] -- Bison token number corresponding to YYLEX. */
static const char yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
      42,    43,     2,    40,    44,    41,    49,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    45,     2,    46,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    47,     2,    48,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     3,     4,     5,
       6,     7,     8,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38,    39
};

#if YYDEBUG
static const short yyprhs[] =
{
       0,     0,     1,     4,     6,     9,    12,    14,    16,    18,
      20,    22,    24,    28,    33,    35,    39,    41,    44,    46,
      51,    53,    56,    58,    60,    62,    66,    71,    73,    76,
      79,    82,    85,    88,    90,    95,   103,   105,   107,   109,
     114,   122,   124,   128,   131,   135,   140,   142,   146,   149,
     155,   160,   163,   165,   168,   170,   172,   174,   176,   178,
     180,   182,   184,   186,   188,   190,   192,   194,   197,   199,
     202,   205,   208,   210,   214,   219,   223,   228,   233,   237,
     242,   247,   249,   254,   258,   266,   273,   278,   280,   282,
     284,   287,   292,   296,   297,   303,   305,   307
};
static const short yyrhs[] =
{
      -1,    50,    92,     0,     4,     0,    40,     4,     0,    41,
       4,     0,    51,     0,    52,     0,     4,     0,     5,     0,
      53,     0,     5,     0,    42,    53,    43,     0,     5,    42,
      53,    43,     0,    56,     0,    57,    44,    56,     0,     5,
       0,    58,     5,     0,    54,     0,     5,    42,     4,    43,
       0,    59,     0,    60,    59,     0,    13,     0,    14,     0,
      15,     0,    45,     4,    46,     0,    45,    61,     4,    46,
       0,    62,     0,    62,    29,     0,    62,    30,     0,    16,
      55,     0,    16,    22,     0,    16,    23,     0,     7,     0,
       7,    47,    57,    48,     0,    65,    42,    54,    49,    49,
      54,    43,     0,    21,     0,    35,     0,    36,     0,     8,
      42,    54,    43,     0,     8,    42,    54,    49,    49,    54,
      43,     0,    68,     0,    42,    68,    43,     0,     9,    10,
       0,     9,    10,    69,     0,     5,    42,     4,    43,     0,
      71,     0,    72,    44,    71,     0,    12,    10,     0,    12,
      10,    47,    72,    48,     0,    39,    47,    72,    48,     0,
      19,    20,     0,     5,     0,     5,    69,     0,    65,     0,
      74,     0,    66,     0,    67,     0,    70,     0,    73,     0,
      81,     0,    75,     0,    83,     0,    84,     0,    82,     0,
      24,     0,    76,     0,    63,    76,     0,    77,     0,    77,
      64,     0,    77,     6,     0,     5,    78,     0,    79,     0,
      80,    44,    79,     0,    11,    47,    80,    48,     0,    11,
      18,    76,     0,    11,    69,    18,    76,     0,    28,    47,
      80,    48,     0,    28,    18,    76,     0,    28,    69,    18,
      76,     0,    17,    47,    80,    48,     0,    25,     0,    25,
      26,    27,     5,     0,     5,     3,    77,     0,     5,    19,
      20,     3,    47,    60,    48,     0,     5,     5,     3,    47,
      60,    48,     0,     5,     7,     3,     4,     0,    85,     0,
      86,     0,    87,     0,    88,    87,     0,     5,    47,    60,
      48,     0,     5,    47,    48,     0,     0,    38,    58,    37,
       5,    60,     0,    29,     0,    30,     0,    89,    31,    91,
      32,     3,    33,    90,    88,    34,     0
};

#endif

#if YYDEBUG
/* YYRLINE[YYN] -- source line where rule number YYN was defined. */
static const short yyrline[] =
{
       0,   107,   108,   111,   112,   115,   119,   120,   123,   124,
     127,   128,   131,   133,   138,   139,   143,   145,   151,   153,
     158,   159,   163,   164,   165,   168,   170,   174,   175,   176,
     179,   181,   182,   185,   186,   188,   195,   198,   199,   202,
     204,   210,   211,   214,   215,   219,   224,   225,   229,   230,
     235,   240,   243,   245,   248,   249,   250,   251,   252,   253,
     254,   255,   256,   257,   258,   259,   262,   263,   268,   269,
     272,   275,   278,   279,   283,   285,   287,   292,   294,   296,
     301,   305,   306,   311,   314,   318,   323,   329,   330,   333,
     334,   338,   341,   345,   346,   354,   355,   358
};
#endif


#if (YYDEBUG) || defined YYERROR_VERBOSE

/* YYTNAME[TOKEN_NUM] -- String name of the token TOKEN_NUM. */
static const char *const yytname[] =
{
  "$", "error", "$undefined.", "\"::=\"", "NUM", "IDENTIFIER", "OPTIONAL", 
  "INTEGER", "SIZE", "OCTET", "STRING", "SEQUENCE", "BIT", "UNIVERSAL", 
  "PRIVATE", "APPLICATION", "DEFAULT", "CHOICE", "OF", "OBJECT", 
  "STR_IDENTIFIER", "BOOLEAN", "TRUE", "FALSE", "TOKEN_NULL", "ANY", 
  "DEFINED", "BY", "SET", "EXPLICIT", "IMPLICIT", "DEFINITIONS", "TAGS", 
  "BEGIN", "END", "UTCTime", "GeneralizedTime", "FROM", "IMPORTS", 
  "ENUMERATED", "'+'", "'-'", "'('", "')'", "','", "'['", "']'", "'{'", 
  "'}'", "'.'", "input", "pos_num", "neg_num", "pos_neg_num", 
  "num_identifier", "pos_neg_identifier", "constant", "constant_list", 
  "identifier_list", "obj_constant", "obj_constant_list", "class", 
  "tag_type", "tag", "default", "integer_def", "boolean_def", "Time", 
  "size_def2", "size_def", "octet_string_def", "bit_element", 
  "bit_element_list", "bit_string_def", "enumerated_def", "object_def", 
  "type_assig_right", "type_assig_right_tag", 
  "type_assig_right_tag_default", "type_assig", "type_assig_list", 
  "sequence_def", "set_def", "choise_def", "any_def", "type_def", 
  "constant_def", "type_constant", "type_constant_list", "definitions_id", 
  "imports_def", "explicit_implicit", "definitions", NULL
};
#endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives. */
static const short yyr1[] =
{
       0,    50,    50,    51,    51,    52,    53,    53,    54,    54,
      55,    55,    56,    56,    57,    57,    58,    58,    59,    59,
      60,    60,    61,    61,    61,    62,    62,    63,    63,    63,
      64,    64,    64,    65,    65,    65,    66,    67,    67,    68,
      68,    69,    69,    70,    70,    71,    72,    72,    73,    73,
      74,    75,    76,    76,    76,    76,    76,    76,    76,    76,
      76,    76,    76,    76,    76,    76,    77,    77,    78,    78,
      78,    79,    80,    80,    81,    81,    81,    82,    82,    82,
      83,    84,    84,    85,    86,    86,    86,    87,    87,    88,
      88,    89,    89,    90,    90,    91,    91,    92
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN. */
static const short yyr2[] =
{
       0,     0,     2,     1,     2,     2,     1,     1,     1,     1,
       1,     1,     3,     4,     1,     3,     1,     2,     1,     4,
       1,     2,     1,     1,     1,     3,     4,     1,     2,     2,
       2,     2,     2,     1,     4,     7,     1,     1,     1,     4,
       7,     1,     3,     2,     3,     4,     1,     3,     2,     5,
       4,     2,     1,     2,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     2,     1,     2,
       2,     2,     1,     3,     4,     3,     4,     4,     3,     4,
       4,     1,     4,     3,     7,     6,     4,     1,     1,     1,
       2,     4,     3,     0,     5,     1,     1,     9
};

/* YYDEFACT[S] -- default rule to reduce with in state S when YYTABLE
   doesn't specify something else to do.  Zero means the default is an
   error. */
static const short yydefact[] =
{
       1,     0,     0,     0,     2,     0,     0,     8,     9,    92,
      18,    20,     0,    95,    96,     0,     0,    91,    21,     0,
       0,     0,    19,    93,     0,     0,    16,     0,     0,    87,
      88,    89,     0,    17,     0,     0,     0,     0,     0,    97,
      90,     0,    52,    33,     0,     0,     0,     0,     0,    36,
      65,    81,     0,    37,    38,     0,     0,    27,     0,    54,
      56,    57,    58,    59,    55,    61,    66,    83,    60,    64,
      62,    63,     0,     0,     0,     0,     0,     0,    41,    53,
       0,    43,     0,     0,     0,    48,     0,    51,     0,     0,
       0,     0,     0,     0,    22,    23,    24,     0,    28,    29,
      67,     0,     0,    86,     0,     0,     0,     0,     0,    14,
       0,    44,    75,     0,    72,     0,     0,     0,     0,     0,
      78,     0,     0,     0,    46,     0,    25,     0,     9,     0,
       0,     0,     0,    42,     0,     3,     0,     0,     6,     7,
       0,     0,    34,    68,    71,     0,    74,    76,     0,    80,
      82,    77,    79,     0,     0,    50,    26,     0,    85,     0,
      39,     0,     0,     4,     5,    12,    15,    70,     0,    69,
      73,    49,     0,    47,     0,    84,     0,    13,    11,    31,
      32,    10,    30,    45,     0,     0,    35,    40,     0,     0
};

static const short yydefgoto[] =
{
       1,   138,   139,   140,    10,   182,   109,   110,    27,    11,
      12,    97,    57,    58,   169,    59,    60,    61,    78,    79,
      62,   124,   125,    63,    64,    65,    66,    67,   144,   114,
     115,    68,    69,    70,    71,    29,    30,    31,    32,     3,
      25,    15,     4
};

static const short yypact[] =
{
  -32768,    33,    -7,    28,-32768,     0,    -5,-32768,    22,-32768,
  -32768,-32768,     3,-32768,-32768,    42,    62,-32768,-32768,    76,
      45,    60,-32768,    85,   109,   127,-32768,     8,   108,-32768,
  -32768,-32768,     9,-32768,   128,    11,   131,   132,   116,-32768,
  -32768,    67,    18,    90,   129,    23,   130,    91,   121,-32768,
  -32768,   117,    34,-32768,-32768,    95,   106,    87,    73,   102,
  -32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
  -32768,-32768,    98,   142,   145,    67,   107,   143,-32768,-32768,
      12,    18,    73,   147,   135,   103,   147,-32768,   133,    73,
     147,   136,   150,   110,-32768,-32768,-32768,   153,-32768,-32768,
  -32768,   126,    67,-32768,   111,   126,   118,   120,    17,-32768,
      51,-32768,-32768,    11,-32768,    52,    73,   150,    58,   154,
  -32768,    59,    73,   122,-32768,    78,-32768,   119,-32768,   114,
       5,    67,    40,-32768,    17,-32768,   162,   163,-32768,-32768,
     125,    12,-32768,    13,-32768,   147,-32768,-32768,    80,-32768,
  -32768,-32768,-32768,   165,   150,-32768,-32768,   123,-32768,     7,
  -32768,   124,   134,-32768,-32768,-32768,-32768,-32768,    64,-32768,
  -32768,-32768,   137,-32768,   126,-32768,   126,-32768,-32768,-32768,
  -32768,-32768,-32768,-32768,   138,   139,-32768,-32768,   170,-32768
};

static const short yypgoto[] =
{
  -32768,-32768,-32768,  -119,   -99,-32768,    30,-32768,-32768,   -12,
     -40,-32768,-32768,-32768,-32768,-32768,-32768,-32768,    97,    -8,
  -32768,    21,    61,-32768,-32768,-32768,   -55,    63,-32768,    38,
      39,-32768,-32768,-32768,-32768,-32768,-32768,   152,-32768,-32768,
  -32768,-32768,-32768
};


#define	YYLAST		184


static const short yytable[] =
{
      18,    75,   129,   100,     7,     8,   132,     7,     8,     7,
       8,     7,     8,    33,    28,   162,    42,   107,    43,   167,
      44,   135,    45,    46,    13,    14,    76,   112,    47,   168,
      48,    76,    49,   188,   120,    50,    51,    84,     2,    52,
       5,    82,    76,    39,    91,    34,    53,    54,     9,   181,
      55,    17,    89,   158,   108,   175,    56,   136,   137,     6,
      77,   147,   130,    18,    16,    77,    20,   152,   135,   178,
      83,     7,     8,   111,    19,   184,    77,   185,    42,    21,
      43,    90,    44,   160,    45,    46,   179,   180,    22,   161,
      47,   159,    48,    23,    49,   141,   145,    50,    51,   142,
     146,    52,   145,   145,   136,   137,   149,   151,    53,    54,
      93,    35,    55,    36,    26,    37,    98,    99,    18,    94,
      95,    96,   154,    24,   154,   118,   155,    38,   171,   121,
       7,   128,    28,    41,    72,    73,    74,    80,    86,    81,
      85,    87,    92,    88,   101,   102,   103,    18,   104,   105,
     117,    76,   113,   116,   122,   123,   126,   127,   131,   150,
     119,   133,   134,   157,   153,   156,   163,   164,   165,   172,
     189,   166,   174,   176,   106,   173,   143,   177,   148,     0,
     183,   186,   187,   170,    40
};

static const short yycheck[] =
{
      12,    41,   101,    58,     4,     5,   105,     4,     5,     4,
       5,     4,     5,     5,     5,   134,     5,     5,     7,     6,
       9,     4,    11,    12,    29,    30,     8,    82,    17,    16,
      19,     8,    21,     0,    89,    24,    25,    45,     5,    28,
      47,    18,     8,    34,    52,    37,    35,    36,    48,   168,
      39,    48,    18,    48,    42,    48,    45,    40,    41,    31,
      42,   116,   102,    75,    42,    42,     4,   122,     4,     5,
      47,     4,     5,    81,    32,   174,    42,   176,     5,     3,
       7,    47,     9,    43,    11,    12,    22,    23,    43,    49,
      17,   131,    19,    33,    21,    44,    44,    24,    25,    48,
      48,    28,    44,    44,    40,    41,    48,    48,    35,    36,
       4,     3,    39,     5,     5,     7,    29,    30,   130,    13,
      14,    15,    44,    38,    44,    86,    48,    19,    48,    90,
       4,     5,     5,     5,     3,     3,    20,    47,    47,    10,
      10,    20,    47,    26,    42,    47,     4,   159,     3,    42,
      47,     8,     5,    18,    18,     5,    46,     4,    47,     5,
      27,    43,    42,    49,    42,    46,     4,     4,    43,     4,
       0,   141,    49,    49,    77,   154,   113,    43,   117,    -1,
      43,    43,    43,   145,    32
};
/* -*-C-*-  Note some compilers choke on comments on `#line' lines.  */
#line 3 "/usr/share/bison/bison.simple"

/* Skeleton output parser for bison,
   Copyright (C) 1984, 1989, 1990, 2000, 2001 Free Software Foundation, Inc.

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
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* This is the parser code that is written into each bison parser when
   the %semantic_parser declaration is not specified in the grammar.
   It was written by Richard Stallman by simplifying the hairy parser
   used when %semantic_parser is specified.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

#ifdef __cplusplus
# define YYSTD(x) std::x
#else
# define YYSTD(x) x
#endif

#if ! defined (yyoverflow) || defined (YYERROR_VERBOSE)

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# if YYSTACK_USE_ALLOCA
#  define YYSTACK_ALLOC alloca
#  define YYSIZE_T YYSTD (size_t)
# else
#  ifndef YYSTACK_USE_ALLOCA
#   if defined (alloca) || defined (_ALLOCA_H)
#    define YYSTACK_ALLOC alloca
#    define YYSIZE_T YYSTD (size_t)
#   else
#    ifdef __GNUC__
#     define YYSTACK_ALLOC __builtin_alloca
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning. */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
# else
#  ifdef __cplusplus
#   include <cstdlib> /* INFRINGES ON USER NAME SPACE */
#   define YYSIZE_T std::size_t
#  else
#   ifdef __STDC__
#    include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#    define YYSIZE_T size_t
#   endif
#  endif
#  define YYSTACK_ALLOC YYSTD (malloc)
#  define YYSTACK_FREE YYSTD (free)
# endif

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  short yyss;
  YYSTYPE yyvs;
# if YYLSP_NEEDED
  YYLTYPE yyls;
# endif
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAX (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# if YYLSP_NEEDED
#  define YYSTACK_BYTES(N) \
     ((N) * (sizeof (short) + sizeof (YYSTYPE) + sizeof (YYLTYPE))	\
      + 2 * YYSTACK_GAP_MAX)
# else
#  define YYSTACK_BYTES(N) \
     ((N) * (sizeof (short) + sizeof (YYSTYPE))				\
      + YYSTACK_GAP_MAX)
# endif

/* Relocate the TYPE STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Type, Stack)					\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	yymemcpy ((char *) yyptr, (char *) (Stack),			\
		  yysize * (YYSIZE_T) sizeof (Type));			\
	Stack = &yyptr->Stack;						\
	yynewbytes = yystacksize * sizeof (Type) + YYSTACK_GAP_MAX;	\
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (0)

#endif /* ! defined (yyoverflow) || defined (YYERROR_VERBOSE) */


#if ! defined (YYSIZE_T) && defined (__SIZE_TYPE__)
# define YYSIZE_T __SIZE_TYPE__
#endif
#if ! defined (YYSIZE_T) && defined (size_t)
# define YYSIZE_T size_t
#endif
#if ! defined (YYSIZE_T)
# ifdef __cplusplus
#  include <cstddef> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T std::size_t
# else
#  ifdef __STDC__
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#   define YYSIZE_T size_t
#  endif
# endif
#endif
#if ! defined (YYSIZE_T)
# define YYSIZE_T unsigned int
#endif

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		-2
#define YYEOF		0
#define YYACCEPT	goto yyacceptlab
#define YYABORT 	goto yyabortlab
#define YYERROR		goto yyerrlab1
/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */
#define YYFAIL		goto yyerrlab
#define YYRECOVERING()  (!!yyerrstatus)
#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yychar1 = YYTRANSLATE (yychar);				\
      YYPOPSTACK;						\
      goto yybackup;						\
    }								\
  else								\
    { 								\
      yyerror ("syntax error: cannot back up");			\
      YYERROR;							\
    }								\
while (0)

#define YYTERROR	1
#define YYERRCODE	256


/* YYLLOC_DEFAULT -- Compute the default location (before the actions
   are run).

   When YYLLOC_DEFAULT is run, CURRENT is set the location of the
   first token.  By default, to implement support for ranges, extend
   its range to the last symbol.  */

#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)       	\
   Current.last_line   = Rhs[N].last_line;	\
   Current.last_column = Rhs[N].last_column;
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */

#if YYPURE
# if YYLSP_NEEDED
#  ifdef YYLEX_PARAM
#   define YYLEX		yylex (&yylval, &yylloc, YYLEX_PARAM)
#  else
#   define YYLEX		yylex (&yylval, &yylloc)
#  endif
# else /* !YYLSP_NEEDED */
#  ifdef YYLEX_PARAM
#   define YYLEX		yylex (&yylval, YYLEX_PARAM)
#  else
#   define YYLEX		yylex (&yylval)
#  endif
# endif /* !YYLSP_NEEDED */
#else /* !YYPURE */
# define YYLEX			yylex ()
#endif /* !YYPURE */


/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  ifdef __cplusplus
#   include <cstdio>  /* INFRINGES ON USER NAME SPACE */
#  else
#   include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYFPRINTF YYSTD (fprintf)
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (0)
/* Nonzero means print parse trace. [The following comment makes no
   sense to me.  Could someone clarify it?  --akim] Since this is
   uninitialized, it does not stop multiple parsers from coexisting.
   */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
#endif /* !YYDEBUG */

/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   SIZE_MAX < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#if YYMAXDEPTH == 0
# undef YYMAXDEPTH
#endif

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif

#if ! defined (yyoverflow) && ! defined (yymemcpy)
# if __GNUC__ > 1		/* GNU C and GNU C++ define this.  */
#  define yymemcpy __builtin_memcpy
# else				/* not GNU C or C++ */

/* This is the most reliable way to avoid incompatibilities
   in available built-in functions on various systems.  */
static void
#  if defined (__STDC__) || defined (__cplusplus)
yymemcpy (char *yyto, const char *yyfrom, YYSIZE_T yycount)
#  else
yymemcpy (yyto, yyfrom, yycount)
     char *yyto;
     const char *yyfrom;
     YYSIZE_T yycount;
#  endif
{
  register const char *yyf = yyfrom;
  register char *yyt = yyto;
  register YYSIZE_T yyi = yycount;

  while (yyi-- != 0)
    *yyt++ = *yyf++;
}
# endif
#endif

#ifdef YYERROR_VERBOSE

# ifndef yystrlen
#  if defined (__GLIBC__) && defined (_STRING_H)
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
#   if defined (__STDC__) || defined (__cplusplus)
yystrlen (const char *yystr)
#   else
yystrlen (yystr)
     const char *yystr;
#   endif
{
  register const char *yys = yystr;

  while (*yys++ != '\0')
    continue;

  return yys - yystr - 1;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined (__GLIBC__) && defined (_STRING_H) && defined (_GNU_SOURCE)
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
#   if defined (__STDC__) || defined (__cplusplus)
yystpcpy (char *yydest, const char *yysrc)
#   else
yystpcpy (yydest, yysrc)
     char *yydest;
     const char *yysrc;
#   endif
{
  register char *yyd = yydest;
  register const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif
#endif

#line 341 "/usr/share/bison/bison.simple"


/* The user can define YYPARSE_PARAM as the name of an argument to be passed
   into yyparse.  The argument should have type void *.
   It should actually point to an object.
   Grammar actions can access the variable by casting it
   to the proper pointer type.  */

#ifdef YYPARSE_PARAM
# ifdef __cplusplus
#  define YYPARSE_PARAM_ARG void *YYPARSE_PARAM
#  define YYPARSE_PARAM_DECL
# else /* !__cplusplus */
#  define YYPARSE_PARAM_ARG YYPARSE_PARAM
#  define YYPARSE_PARAM_DECL void *YYPARSE_PARAM;
# endif /* !__cplusplus */
#else /* !YYPARSE_PARAM */
# define YYPARSE_PARAM_ARG
# define YYPARSE_PARAM_DECL
#endif /* !YYPARSE_PARAM */

/* Prevent warning if -Wstrict-prototypes.  */
#ifdef __GNUC__
# ifdef YYPARSE_PARAM
int yyparse (void *);
# else
int yyparse (void);
# endif
#endif

/* YY_DECL_VARIABLES -- depending whether we use a pure parser,
   variables are global, or local to YYPARSE.  */

#define YY_DECL_NON_LSP_VARIABLES			\
/* The lookahead symbol.  */				\
int yychar;						\
							\
/* The semantic value of the lookahead symbol. */	\
YYSTYPE yylval;						\
							\
/* Number of parse errors so far.  */			\
int yynerrs;

#if YYLSP_NEEDED
# define YY_DECL_VARIABLES			\
YY_DECL_NON_LSP_VARIABLES			\
						\
/* Location data for the lookahead symbol.  */	\
YYLTYPE yylloc;
#else
# define YY_DECL_VARIABLES			\
YY_DECL_NON_LSP_VARIABLES
#endif


/* If nonreentrant, generate the variables here. */

#if !YYPURE
YY_DECL_VARIABLES
#endif  /* !YYPURE */

int
yyparse (YYPARSE_PARAM_ARG)
     YYPARSE_PARAM_DECL
{
  /* If reentrant, generate the variables here. */
#if YYPURE
  YY_DECL_VARIABLES
#endif  /* !YYPURE */

  register int yystate;
  register int yyn;
  int yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus;
  /* Lookahead token as an internal (translated) token number.  */
  int yychar1 = 0;

  /* Three stacks and their tools:
     `yyss': related to states,
     `yyvs': related to semantic values,
     `yyls': related to locations.

     Refer to the stacks thru separate pointers, to allow yyoverflow
     to reallocate them elsewhere.  */

  /* The state stack. */
  short	yyssa[YYINITDEPTH];
  short *yyss = yyssa;
  register short *yyssp;

  /* The semantic value stack.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  register YYSTYPE *yyvsp;

#if YYLSP_NEEDED
  /* The location stack.  */
  YYLTYPE yylsa[YYINITDEPTH];
  YYLTYPE *yyls = yylsa;
  YYLTYPE *yylsp;
#endif

#if YYLSP_NEEDED
# define YYPOPSTACK   (yyvsp--, yyssp--, yylsp--)
#else
# define YYPOPSTACK   (yyvsp--, yyssp--)
#endif

  YYSIZE_T yystacksize = YYINITDEPTH;


  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;
#if YYLSP_NEEDED
  YYLTYPE yyloc;
#endif

  /* When reducing, the number of symbols on the RHS of the reduced
     rule. */
  int yylen;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss;
  yyvsp = yyvs;
#if YYLSP_NEEDED
  yylsp = yyls;
#endif
  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed. so pushing a state here evens the stacks.
     */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyssp >= yyss + yystacksize - 1)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack. Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	short *yyss1 = yyss;

	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  */
# if YYLSP_NEEDED
	YYLTYPE *yyls1 = yyls;
	/* This used to be a conditional around just the two extra args,
	   but that might be undefined if yyoverflow is a macro.  */
	yyoverflow ("parser stack overflow",
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),
		    &yyls1, yysize * sizeof (*yylsp),
		    &yystacksize);
	yyls = yyls1;
# else
	yyoverflow ("parser stack overflow",
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),
		    &yystacksize);
# endif
	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
      /* Extend the stack our own way.  */
      if (yystacksize >= YYMAXDEPTH)
	goto yyoverflowlab;
      yystacksize *= 2;
      if (yystacksize > YYMAXDEPTH)
	yystacksize = YYMAXDEPTH;

      {
	short *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyoverflowlab;
	YYSTACK_RELOCATE (short, yyss);
	YYSTACK_RELOCATE (YYSTYPE, yyvs);
# if YYLSP_NEEDED
	YYSTACK_RELOCATE (YYLTYPE, yyls);
# endif
# undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;
#if YYLSP_NEEDED
      yylsp = yyls + yysize - 1;
#endif

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyssp >= yyss + yystacksize - 1)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:

/* Do appropriate processing given the current state.  */
/* Read a lookahead token if we need one and don't already have one.  */
/* yyresume: */

  /* First try to decide what to do without reference to lookahead token.  */

  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* yychar is either YYEMPTY or YYEOF
     or a valid token in external form.  */

  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  /* Convert token to internal form (in yychar1) for indexing tables with */

  if (yychar <= 0)		/* This means end of input. */
    {
      yychar1 = 0;
      yychar = YYEOF;		/* Don't call YYLEX any more */

      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yychar1 = YYTRANSLATE (yychar);

#if YYDEBUG
     /* We have to keep this `#if YYDEBUG', since we use variables
	which are defined only if `YYDEBUG' is set.  */
      if (yydebug)
	{
	  YYFPRINTF (stderr, "Next token is %d (%s",
		     yychar, yytname[yychar1]);
	  /* Give the individual parser a way to print the precise
	     meaning of a token, for further debugging info.  */
# ifdef YYPRINT
	  YYPRINT (stderr, yychar, yylval);
# endif
	  YYFPRINTF (stderr, ")\n");
	}
#endif
    }

  yyn += yychar1;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != yychar1)
    goto yydefault;

  yyn = yytable[yyn];

  /* yyn is what to do for this token type in this state.
     Negative => reduce, -yyn is rule number.
     Positive => shift, yyn is new state.
       New state is final state => don't bother to shift,
       just return success.
     0, or most negative number => error.  */

  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrlab;

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Shift the lookahead token.  */
  YYDPRINTF ((stderr, "Shifting token %d (%s), ",
	      yychar, yytname[yychar1]));

  /* Discard the token being shifted unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  *++yyvsp = yylval;
#if YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  yystate = yyn;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to the semantic value of
     the lookahead token.  This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];

#if YYLSP_NEEDED
  /* Similarly for the default location.  Let the user run additional
     commands if for instance locations are ranges.  */
  yyloc = yylsp[1-yylen];
  YYLLOC_DEFAULT (yyloc, (yylsp - yylen), yylen);
#endif

#if YYDEBUG
  /* We have to keep this `#if YYDEBUG', since we use variables which
     are defined only if `YYDEBUG' is set.  */
  if (yydebug)
    {
      int yyi;

      YYFPRINTF (stderr, "Reducing via rule %d (line %d), ",
		 yyn, yyrline[yyn]);

      /* Print the symbols being reduced, and their result.  */
      for (yyi = yyprhs[yyn]; yyrhs[yyi] > 0; yyi++)
	YYFPRINTF (stderr, "%s ", yytname[yyrhs[yyi]]);
      YYFPRINTF (stderr, " -> %s\n", yytname[yyr1[yyn]]);
    }
#endif

  switch (yyn) {

case 3:
#line 111 "x509_ASN.y"
{strcpy(yyval.str,yyvsp[0].str);}
    break;
case 4:
#line 112 "x509_ASN.y"
{strcpy(yyval.str,yyvsp[0].str);}
    break;
case 5:
#line 115 "x509_ASN.y"
{strcpy(yyval.str,"-");
                       strcat(yyval.str,yyvsp[0].str);}
    break;
case 6:
#line 119 "x509_ASN.y"
{strcpy(yyval.str,yyvsp[0].str);}
    break;
case 7:
#line 120 "x509_ASN.y"
{strcpy(yyval.str,yyvsp[0].str);}
    break;
case 8:
#line 123 "x509_ASN.y"
{strcpy(yyval.str,yyvsp[0].str);}
    break;
case 9:
#line 124 "x509_ASN.y"
{strcpy(yyval.str,yyvsp[0].str);}
    break;
case 10:
#line 127 "x509_ASN.y"
{strcpy(yyval.str,yyvsp[0].str);}
    break;
case 11:
#line 128 "x509_ASN.y"
{strcpy(yyval.str,yyvsp[0].str);}
    break;
case 12:
#line 131 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_CONSTANT); 
                                       _asn1_set_value(yyval.node,yyvsp[-1].str,strlen(yyvsp[-1].str)+1);}
    break;
case 13:
#line 133 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_CONSTANT);
	                               _asn1_set_name(yyval.node,yyvsp[-3].str); 
                                       _asn1_set_value(yyval.node,yyvsp[-1].str,strlen(yyvsp[-1].str)+1);}
    break;
case 14:
#line 138 "x509_ASN.y"
{yyval.node=yyvsp[0].node;}
    break;
case 15:
#line 139 "x509_ASN.y"
{yyval.node=yyvsp[-2].node;
                                            _asn1_set_right(_asn1_get_last_right(yyvsp[-2].node),yyvsp[0].node);}
    break;
case 16:
#line 143 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_IDENTIFIER);
                                 _asn1_set_name(yyval.node,yyvsp[0].str);}
    break;
case 17:
#line 146 "x509_ASN.y"
{yyval.node=yyvsp[-1].node;
                                 _asn1_set_right(_asn1_get_last_right(yyval.node),_asn1_add_node(TYPE_IDENTIFIER));
                                 _asn1_set_name(_asn1_get_last_right(yyval.node),yyvsp[0].str);}
    break;
case 18:
#line 151 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_CONSTANT); 
                                   _asn1_set_value(yyval.node,yyvsp[0].str,strlen(yyvsp[0].str)+1);}
    break;
case 19:
#line 153 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_CONSTANT);
	                            _asn1_set_name(yyval.node,yyvsp[-3].str); 
                                    _asn1_set_value(yyval.node,yyvsp[-1].str,strlen(yyvsp[-1].str)+1);}
    break;
case 20:
#line 158 "x509_ASN.y"
{yyval.node=yyvsp[0].node;}
    break;
case 21:
#line 159 "x509_ASN.y"
{yyval.node=yyvsp[-1].node;
                                                    _asn1_set_right(_asn1_get_last_right(yyvsp[-1].node),yyvsp[0].node);}
    break;
case 22:
#line 163 "x509_ASN.y"
{yyval.constant=CONST_UNIVERSAL;}
    break;
case 23:
#line 164 "x509_ASN.y"
{yyval.constant=CONST_PRIVATE;}
    break;
case 24:
#line 165 "x509_ASN.y"
{yyval.constant=CONST_APPLICATION;}
    break;
case 25:
#line 168 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_TAG); 
                            _asn1_set_value(yyval.node,yyvsp[-1].str,strlen(yyvsp[-1].str)+1);}
    break;
case 26:
#line 170 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_TAG | yyvsp[-2].constant); 
                                _asn1_set_value(yyval.node,yyvsp[-1].str,strlen(yyvsp[-1].str)+1);}
    break;
case 27:
#line 174 "x509_ASN.y"
{yyval.node=yyvsp[0].node;}
    break;
case 28:
#line 175 "x509_ASN.y"
{yyval.node=_asn1_mod_type(yyvsp[-1].node,CONST_EXPLICIT);}
    break;
case 29:
#line 176 "x509_ASN.y"
{yyval.node=_asn1_mod_type(yyvsp[-1].node,CONST_IMPLICIT);}
    break;
case 30:
#line 179 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_DEFAULT); 
                                       _asn1_set_value(yyval.node,yyvsp[0].str,strlen(yyvsp[0].str)+1);}
    break;
case 31:
#line 181 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_DEFAULT|CONST_TRUE);}
    break;
case 32:
#line 182 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_DEFAULT|CONST_FALSE);}
    break;
case 33:
#line 185 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_INTEGER);}
    break;
case 34:
#line 186 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_INTEGER|CONST_LIST);
	                                 _asn1_set_down(yyval.node,yyvsp[-1].node);}
    break;
case 35:
#line 189 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_INTEGER|CONST_MIN_MAX);
                                         _asn1_set_down(yyval.node,_asn1_add_node(TYPE_SIZE)); 
                                         _asn1_set_value(_asn1_get_down(yyval.node),yyvsp[-1].str,strlen(yyvsp[-1].str)+1); 
                                         _asn1_set_name(_asn1_get_down(yyval.node),yyvsp[-4].str);}
    break;
case 36:
#line 195 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_BOOLEAN);}
    break;
case 37:
#line 198 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_TIME|CONST_UTC);}
    break;
case 38:
#line 199 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_TIME|CONST_GENERALIZED);}
    break;
case 39:
#line 202 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_SIZE|CONST_1_PARAM);
	                              _asn1_set_value(yyval.node,yyvsp[-1].str,strlen(yyvsp[-1].str)+1);}
    break;
case 40:
#line 205 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_SIZE|CONST_MIN_MAX);
	                              _asn1_set_value(yyval.node,yyvsp[-4].str,strlen(yyvsp[-4].str)+1);
                                      _asn1_set_name(yyval.node,yyvsp[-1].str);}
    break;
case 41:
#line 210 "x509_ASN.y"
{yyval.node=yyvsp[0].node;}
    break;
case 42:
#line 211 "x509_ASN.y"
{yyval.node=yyvsp[-1].node;}
    break;
case 43:
#line 214 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_OCTET_STRING);}
    break;
case 44:
#line 215 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_OCTET_STRING|CONST_SIZE);
                                           _asn1_set_down(yyval.node,yyvsp[0].node);}
    break;
case 45:
#line 219 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_CONSTANT);
	                           _asn1_set_name(yyval.node,yyvsp[-3].str); 
                                    _asn1_set_value(yyval.node,yyvsp[-1].str,strlen(yyvsp[-1].str)+1);}
    break;
case 46:
#line 224 "x509_ASN.y"
{yyval.node=yyvsp[0].node;}
    break;
case 47:
#line 225 "x509_ASN.y"
{yyval.node=yyvsp[-2].node;
                                                       _asn1_set_right(_asn1_get_last_right(yyvsp[-2].node),yyvsp[0].node);}
    break;
case 48:
#line 229 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_BIT_STRING);}
    break;
case 49:
#line 231 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_BIT_STRING|CONST_LIST);
                                _asn1_set_down(yyval.node,yyvsp[-1].node);}
    break;
case 50:
#line 236 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_ENUMERATED|CONST_LIST);
                                _asn1_set_down(yyval.node,yyvsp[-1].node);}
    break;
case 51:
#line 240 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_OBJECT_ID);}
    break;
case 52:
#line 243 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_IDENTIFIER);
                                       _asn1_set_value(yyval.node,yyvsp[0].str,strlen(yyvsp[0].str)+1);}
    break;
case 53:
#line 245 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_IDENTIFIER|CONST_SIZE);
                                       _asn1_set_value(yyval.node,yyvsp[-1].str,strlen(yyvsp[-1].str)+1);
                                       _asn1_set_down(yyval.node,yyvsp[0].node);}
    break;
case 54:
#line 248 "x509_ASN.y"
{yyval.node=yyvsp[0].node;}
    break;
case 55:
#line 249 "x509_ASN.y"
{yyval.node=yyvsp[0].node;}
    break;
case 56:
#line 250 "x509_ASN.y"
{yyval.node=yyvsp[0].node;}
    break;
case 58:
#line 252 "x509_ASN.y"
{yyval.node=yyvsp[0].node;}
    break;
case 59:
#line 253 "x509_ASN.y"
{yyval.node=yyvsp[0].node;}
    break;
case 60:
#line 254 "x509_ASN.y"
{yyval.node=yyvsp[0].node;}
    break;
case 61:
#line 255 "x509_ASN.y"
{yyval.node=yyvsp[0].node;}
    break;
case 62:
#line 256 "x509_ASN.y"
{yyval.node=yyvsp[0].node;}
    break;
case 63:
#line 257 "x509_ASN.y"
{yyval.node=yyvsp[0].node;}
    break;
case 64:
#line 258 "x509_ASN.y"
{yyval.node=yyvsp[0].node;}
    break;
case 65:
#line 259 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_NULL);}
    break;
case 66:
#line 262 "x509_ASN.y"
{yyval.node=yyvsp[0].node;}
    break;
case 67:
#line 263 "x509_ASN.y"
{yyval.node=_asn1_mod_type(yyvsp[0].node,CONST_TAG);
                                               _asn1_set_right(yyvsp[-1].node,_asn1_get_down(yyval.node));
                                               _asn1_set_down(yyval.node,yyvsp[-1].node);}
    break;
case 68:
#line 268 "x509_ASN.y"
{yyval.node=yyvsp[0].node;}
    break;
case 69:
#line 269 "x509_ASN.y"
{yyval.node=_asn1_mod_type(yyvsp[-1].node,CONST_DEFAULT);
                                                       _asn1_set_right(yyvsp[0].node,_asn1_get_down(yyval.node));
						       _asn1_set_down(yyval.node,yyvsp[0].node);}
    break;
case 70:
#line 272 "x509_ASN.y"
{yyval.node=_asn1_mod_type(yyvsp[-1].node,CONST_OPTION);}
    break;
case 71:
#line 275 "x509_ASN.y"
{yyval.node=_asn1_set_name(yyvsp[0].node,yyvsp[-1].str);}
    break;
case 72:
#line 278 "x509_ASN.y"
{yyval.node=yyvsp[0].node;}
    break;
case 73:
#line 279 "x509_ASN.y"
{yyval.node=yyvsp[-2].node;
                                                _asn1_set_right(_asn1_get_last_right(yyvsp[-2].node),yyvsp[0].node);}
    break;
case 74:
#line 283 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_SEQUENCE);
                                              _asn1_set_down(yyval.node,yyvsp[-1].node);}
    break;
case 75:
#line 285 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_SEQUENCE_OF);
                                              _asn1_set_down(yyval.node,yyvsp[0].node);}
    break;
case 76:
#line 287 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_SEQUENCE_OF|CONST_SIZE);
                                            _asn1_set_right(yyvsp[-2].node,yyvsp[0].node);
                                            _asn1_set_down(yyval.node,yyvsp[-2].node);}
    break;
case 77:
#line 292 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_SET);
                                     _asn1_set_down(yyval.node,yyvsp[-1].node);}
    break;
case 78:
#line 294 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_SET_OF);
                                     _asn1_set_down(yyval.node,yyvsp[0].node);}
    break;
case 79:
#line 296 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_SET_OF|CONST_SIZE);
                                       _asn1_set_right(yyvsp[-2].node,yyvsp[0].node);
                                       _asn1_set_down(yyval.node,yyvsp[-2].node);}
    break;
case 80:
#line 301 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_CHOICE);
                                             _asn1_set_down(yyval.node,yyvsp[-1].node);}
    break;
case 81:
#line 305 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_ANY);}
    break;
case 82:
#line 306 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_ANY|CONST_DEFINED_BY);
                                        _asn1_set_down(yyval.node,_asn1_add_node(TYPE_CONSTANT));
	                                _asn1_set_name(_asn1_get_down(yyval.node),yyvsp[0].str);}
    break;
case 83:
#line 311 "x509_ASN.y"
{yyval.node=_asn1_set_name(yyvsp[0].node,yyvsp[-2].str);}
    break;
case 84:
#line 315 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_OBJECT_ID|CONST_ASSIGN);
                         _asn1_set_name(yyval.node,yyvsp[-6].str);  
                         _asn1_set_down(yyval.node,yyvsp[-1].node);}
    break;
case 85:
#line 319 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_OBJECT_ID|CONST_ASSIGN|CONST_1_PARAM);
                         _asn1_set_name(yyval.node,yyvsp[-5].str);  
                         _asn1_set_value(yyval.node,yyvsp[-4].str,strlen(yyvsp[-4].str)+1);
                         _asn1_set_down(yyval.node,yyvsp[-1].node);}
    break;
case 86:
#line 324 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_INTEGER|CONST_ASSIGN);
                         _asn1_set_name(yyval.node,yyvsp[-3].str);  
                         _asn1_set_value(yyval.node,yyvsp[0].str,strlen(yyvsp[0].str)+1);}
    break;
case 87:
#line 329 "x509_ASN.y"
{yyval.node=yyvsp[0].node;}
    break;
case 88:
#line 330 "x509_ASN.y"
{yyval.node=yyvsp[0].node;}
    break;
case 89:
#line 333 "x509_ASN.y"
{yyval.node=yyvsp[0].node;}
    break;
case 90:
#line 334 "x509_ASN.y"
{yyval.node=yyvsp[-1].node;
                                                          _asn1_set_right(_asn1_get_last_right(yyvsp[-1].node),yyvsp[0].node);}
    break;
case 91:
#line 338 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_OBJECT_ID);
                                                          _asn1_set_down(yyval.node,yyvsp[-1].node);
                                                          _asn1_set_name(yyval.node,yyvsp[-3].str);}
    break;
case 92:
#line 341 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_OBJECT_ID);
                                                          _asn1_set_name(yyval.node,yyvsp[-2].str);}
    break;
case 93:
#line 345 "x509_ASN.y"
{yyval.node=NULL;}
    break;
case 94:
#line 347 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_IMPORTS);
                         _asn1_set_down(yyval.node,_asn1_add_node(TYPE_OBJECT_ID));
                         _asn1_set_name(_asn1_get_down(yyval.node),yyvsp[-1].str);  
                         _asn1_set_down(_asn1_get_down(yyval.node),yyvsp[0].node);
                         _asn1_set_right(yyval.node,yyvsp[-3].node);}
    break;
case 95:
#line 354 "x509_ASN.y"
{yyval.constant=CONST_EXPLICIT;}
    break;
case 96:
#line 355 "x509_ASN.y"
{yyval.constant=CONST_IMPLICIT;}
    break;
case 97:
#line 361 "x509_ASN.y"
{yyval.node=_asn1_add_node(TYPE_DEFINITIONS|yyvsp[-6].constant|((yyvsp[-2].node==NULL)?0:CONST_IMPORTS));
                    _asn1_set_name(yyval.node,_asn1_get_name(yyvsp[-8].node));
                    _asn1_set_name(yyvsp[-8].node,"");
                    if(yyvsp[-2].node==NULL) _asn1_set_right(yyvsp[-8].node,yyvsp[-1].node);
                    else {_asn1_set_right(yyvsp[-2].node,yyvsp[-1].node);_asn1_set_right(yyvsp[-8].node,yyvsp[-2].node);}
                    _asn1_set_down(yyval.node,yyvsp[-8].node);
      		    if(parse_mode==PARSE_MODE_CREATE){
		      _asn1_set_default_tag(yyval.node);
		      _asn1_type_set_config(yyval.node);
		      result_parse=_asn1_check_identifier(yyval.node);
		      if(result_parse==ASN_IDENTIFIER_NOT_FOUND)
		      	asn1_delete_structure(yyval.node);
		      else p_tree=yyval.node;
		    }}
    break;
}

#line 727 "/usr/share/bison/bison.simple"


  yyvsp -= yylen;
  yyssp -= yylen;
#if YYLSP_NEEDED
  yylsp -= yylen;
#endif

#if YYDEBUG
  if (yydebug)
    {
      short *yyssp1 = yyss - 1;
      YYFPRINTF (stderr, "state stack now");
      while (yyssp1 != yyssp)
	YYFPRINTF (stderr, " %d", *++yyssp1);
      YYFPRINTF (stderr, "\n");
    }
#endif

  *++yyvsp = yyval;
#if YYLSP_NEEDED
  *++yylsp = yyloc;
#endif

  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTBASE] + *yyssp;
  if (yystate >= 0 && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTBASE];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;

#ifdef YYERROR_VERBOSE
      yyn = yypact[yystate];

      if (yyn > YYFLAG && yyn < YYLAST)
	{
	  YYSIZE_T yysize = 0;
	  char *yymsg;
	  int yyx, yycount;

	  yycount = 0;
	  /* Start YYX at -YYN if negative to avoid negative indexes in
	     YYCHECK.  */
	  for (yyx = yyn < 0 ? -yyn : 0;
	       yyx < (int) (sizeof (yytname) / sizeof (char *)); yyx++)
	    if (yycheck[yyx + yyn] == yyx)
	      yysize += yystrlen (yytname[yyx]) + 15, yycount++;
	  yysize += yystrlen ("parse error, unexpected ") + 1;
	  yysize += yystrlen (yytname[YYTRANSLATE (yychar)]);
	  yymsg = (char *) YYSTACK_ALLOC (yysize);
	  if (yymsg != 0)
	    {
	      char *yyp = yystpcpy (yymsg, "parse error, unexpected ");
	      yyp = yystpcpy (yyp, yytname[YYTRANSLATE (yychar)]);

	      if (yycount < 5)
		{
		  yycount = 0;
		  for (yyx = yyn < 0 ? -yyn : 0;
		       yyx < (int) (sizeof (yytname) / sizeof (char *));
		       yyx++)
		    if (yycheck[yyx + yyn] == yyx)
		      {
			const char *yyq = ! yycount ? ", expecting " : " or ";
			yyp = yystpcpy (yyp, yyq);
			yyp = yystpcpy (yyp, yytname[yyx]);
			yycount++;
		      }
		}
	      yyerror (yymsg);
	      YYSTACK_FREE (yymsg);
	    }
	  else
	    yyerror ("parse error; also virtual memory exhausted");
	}
      else
#endif /* defined (YYERROR_VERBOSE) */
	yyerror ("parse error");
    }
  goto yyerrlab1;


/*--------------------------------------------------.
| yyerrlab1 -- error raised explicitly by an action |
`--------------------------------------------------*/
yyerrlab1:
  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
	 error, discard it.  */

      /* return failure if at end of input */
      if (yychar == YYEOF)
	YYABORT;
      YYDPRINTF ((stderr, "Discarding token %d (%s).\n",
		  yychar, yytname[yychar1]));
      yychar = YYEMPTY;
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */

  yyerrstatus = 3;		/* Each real token shifted decrements this */

  goto yyerrhandle;


/*-------------------------------------------------------------------.
| yyerrdefault -- current state does not do anything special for the |
| error token.                                                       |
`-------------------------------------------------------------------*/
yyerrdefault:
#if 0
  /* This is wrong; only states that explicitly want error tokens
     should shift them.  */

  /* If its default is to accept any token, ok.  Otherwise pop it.  */
  yyn = yydefact[yystate];
  if (yyn)
    goto yydefault;
#endif


/*---------------------------------------------------------------.
| yyerrpop -- pop the current state because it cannot handle the |
| error token                                                    |
`---------------------------------------------------------------*/
yyerrpop:
  if (yyssp == yyss)
    YYABORT;
  yyvsp--;
  yystate = *--yyssp;
#if YYLSP_NEEDED
  yylsp--;
#endif

#if YYDEBUG
  if (yydebug)
    {
      short *yyssp1 = yyss - 1;
      YYFPRINTF (stderr, "Error: state stack now");
      while (yyssp1 != yyssp)
	YYFPRINTF (stderr, " %d", *++yyssp1);
      YYFPRINTF (stderr, "\n");
    }
#endif

/*--------------.
| yyerrhandle.  |
`--------------*/
yyerrhandle:
  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yyerrdefault;

  yyn += YYTERROR;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != YYTERROR)
    goto yyerrdefault;

  yyn = yytable[yyn];
  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrpop;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrpop;

  if (yyn == YYFINAL)
    YYACCEPT;

  YYDPRINTF ((stderr, "Shifting error token, "));

  *++yyvsp = yylval;
#if YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

/*---------------------------------------------.
| yyoverflowab -- parser overflow comes here.  |
`---------------------------------------------*/
yyoverflowlab:
  yyerror ("parser stack overflow");
  yyresult = 2;
  /* Fall through.  */

yyreturn:
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
  return yyresult;
}
#line 377 "x509_ASN.y"



#include <ctype.h>
#include <string.h>

const char *key_word[]={"::=","OPTIONAL","INTEGER","SIZE","OCTET","STRING"
                       ,"SEQUENCE","BIT","UNIVERSAL","PRIVATE","OPTIONAL"
                       ,"DEFAULT","CHOICE","OF","OBJECT","IDENTIFIER"
                       ,"BOOLEAN","TRUE","FALSE","APPLICATION","ANY","DEFINED"
                       ,"SET","BY","EXPLICIT","IMPLICIT","DEFINITIONS","TAGS"
                       ,"BEGIN","END","UTCTime","GeneralizedTime","FROM"
                       ,"IMPORTS","NULL","ENUMERATED"};
const int key_word_token[]={ASSIG,OPTIONAL,INTEGER,SIZE,OCTET,STRING
                       ,SEQUENCE,BIT,UNIVERSAL,PRIVATE,OPTIONAL
                       ,DEFAULT,CHOICE,OF,OBJECT,STR_IDENTIFIER
                       ,BOOLEAN,TRUE,FALSE,APPLICATION,ANY,DEFINED
                       ,SET,BY,EXPLICIT,IMPLICIT,DEFINITIONS,TAGS
                       ,BEGIN,END,UTCTime,GeneralizedTime,FROM
                       ,IMPORTS,TOKEN_NULL,ENUMERATED};

/*************************************************************/
/*  Function: yylex                                          */
/*  Description: looks for tokens in file_asn1 pointer file. */
/*  Return: int                                              */
/*    Token identifier or ASCII code or 0(zero: End Of File) */
/*************************************************************/
int 
yylex() 
{
  int c,counter=0,k;
  char string[129]; /* will contain the next token */  
  while(1)
    {
    while((c=fgetc(file_asn1))==' ' || c=='\t' || c=='\n');
    if(c==EOF) return 0;
    if(c=='(' || c==')' || c=='[' || c==']' || 
       c=='{' || c=='}' || c==',' || c=='.' ||
       c=='+') return c;
    if(c=='-'){  /* Maybe the first '-' of a comment */
      if((c=fgetc(file_asn1))!='-'){
	ungetc(c,file_asn1);
	return '-';
      }
      else{ /* Comments */
	counter=0;
	/* A comment finishes at the end of line */
	while((c=fgetc(file_asn1))!=EOF && c!='\n');
	if(c==EOF) return 0;
	else continue; /* next char, please! (repeat the search) */
      }
    }
    string[counter++]=c;
    /* Till the end of the token */
    while(!((c=fgetc(file_asn1))==EOF || c==' '|| c=='\t' || c=='\n' || 
	     c=='(' || c==')' || c=='[' || c==']' || 
	     c=='{' || c=='}' || c==',' || c=='.'))
      { 
      string[counter++]=c;
      }
    ungetc(c,file_asn1);
    string[counter]=0;

    /* Is STRING a number? */
    for(k=0;k<counter;k++) 
      if(!isdigit(string[k])) break;
    if(k>=counter)
      {
      strcpy(yylval.str,string);  
      return NUM; /* return the number */
      }
 
    /* Is STRING a keyword? */
    for(k=0;k<(sizeof(key_word)/sizeof(char*));k++)  
      if(!strcmp(string,key_word[k])) return key_word_token[k]; 
 
    /* STRING is an IDENTIFIER */
    strcpy(yylval.str,string);
    return IDENTIFIER;
    }
}


/**
  * asn1_parser_asn1 - function used to start the parse algorithm.
  * @file_name: specify the path and the name of file that contains ASN.1 declarations.
  * @pointer: return the pointer to the structure created from 
  *   "file_name" ASN.1 declarations.  
  * Description:
  *
  * Creates the structures needed to manage the definitions included in *FILE_NAME file.
  *
  * Returns:
  *
  * ASN_OK\: the file has a correct syntax and every identifier is known. 
  *
  * ASN_FILE_NOT_FOUND\: an error occured while opening FILE_NAME.
  *
  * ASN_SYNTAX_ERROR\: the syntax is not correct.
  *
  * ASN_IDENTIFIER_NOT_FOUND\: in the file there is an identifier that is not defined.
  **/
int asn1_parser_asn1(char *file_name,node_asn **pointer){
  p_tree=NULL;
  *pointer=NULL;
  
  /* open the file to parse */
  file_asn1=fopen(file_name,"r");
  if(file_asn1==NULL) return ASN_FILE_NOT_FOUND;

  result_parse=ASN_OK;

  /* only syntax check */
  parse_mode=PARSE_MODE_CHECK;
  yyparse();

  if(result_parse==ASN_OK){ /* syntax OK */
    fclose(file_asn1);
    file_asn1=fopen(file_name,"r");

    /* structure creation */
    parse_mode=PARSE_MODE_CREATE;
    yyparse();

    _asn1_change_integer_value(p_tree);
    _asn1_expand_object_id(p_tree);
  }

  fclose(file_asn1);

  parse_mode=PARSE_MODE_CREATE;

  *pointer=p_tree;

  return result_parse;
}


/**
  * asn1_parser_asn1_file_c - function that generates a C structure from an ASN1 file
  * @file_name: specify the path and the name of file that contains ASN.1 declarations.
  * Description:
  *
  * Creates a file containing a C vector to use to manage the definitions included in
  * *FILE_NAME file. If *FILE_NAME is "/aa/bb/xx.yy" the file created is "/aa/bb/xx_asn1_tab.c",
  * and the vector is "xx_asn1_tab".
  *
  * Returns:
  *
  *  ASN_OK\: the file has a correct syntax and every identifier is known. 
  *
  *  ASN_FILE_NOT_FOUND\: an error occured while opening FILE_NAME.
  *
  *  ASN_SYNTAX_ERROR\: the syntax is not correct.
  *
  *  ASN_IDENTIFIER_NOT_FOUND\: in the file there is an identifier that is not defined.
  **/
int asn1_parser_asn1_file_c(char *file_name){
  int result;

  p_tree=NULL;
    
  /* open the file to parse */
  file_asn1=fopen(file_name,"r");
  if(file_asn1==NULL) return ASN_FILE_NOT_FOUND;

  result_parse=ASN_OK;

  /* syntax check */
  parse_mode=PARSE_MODE_CHECK;
  yyparse();

  if(result_parse==ASN_OK){ /* syntax OK */
    fclose(file_asn1);
    file_asn1=fopen(file_name,"r");

    /* structure creation */
    parse_mode=PARSE_MODE_CREATE;
    yyparse();

    /* structure saved in a file */
    result=_asn1_create_static_structure(p_tree,file_name,NULL);

    /* delete structure in memory */
    asn1_delete_structure(p_tree);
   }

  fclose(file_asn1);

  parse_mode=PARSE_MODE_CREATE;

  return result_parse;
}


/*************************************************************/
/*  Function: yyerror                                        */
/*  Description: function called when there are syntax errors*/
/*  Parameters:                                              */
/*    char *s : error description                            */
/*  Return: int                                              */
/*                                                           */
/*************************************************************/
int yyerror (char *s)
{
  /* Sends the error description to the std_out */
  /*  printf("%s\n",s); */
  result_parse=ASN_SYNTAX_ERROR;
  return 0;
}















