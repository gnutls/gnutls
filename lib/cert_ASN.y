/*
 *      Copyright (C) 2000,2001 Fabio Fiorina
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */


/*****************************************************/
/* File: cert_ASN.y                                  */
/* Description: input file for 'bison' program.      */
/*   The output file is a parser (in C language) for */
/*   ASN.1 syntax                                    */
/*****************************************************/


%{
#include <gnutls_int.h>
#include "cert_asn1.h"

FILE *file_asn1;  /* Pointer to file to parse */
extern int parse_mode;
int result_parse;
node_asn *p_tree;
%}


%union {
  unsigned int constant;
  char str[129];
  node_asn* node;
}


%token ASSIG "::=" 
%token <str> NUM
%token <str> IDENTIFIER
%token OPTIONAL
%token INTEGER
%token SIZE
%token OCTET
%token STRING
%token SEQUENCE
%token BIT
%token UNIVERSAL
%token PRIVATE
%token APPLICATION
%token OPTIONAL
%token DEFAULT
%token CHOICE
%token OF
%token OBJECT
%token STR_IDENTIFIER
%token BOOLEAN
%token TRUE
%token FALSE
%token TOKEN_NULL
%token ANY
%token DEFINED
%token BY
%token SET
%token EXPLICIT
%token IMPLICIT
%token DEFINITIONS
%token TAGS
%token BEGIN
%token END
%token UTCTime 
%token GeneralizedTime
%token FROM
%token IMPORTS
%token ENUMERATED

%type <node> octet_string_def constant constant_list type_assig_right 
%type <node> integer_def type_assig type_assig_list sequence_def type_def
%type <node> bit_string_def default size_def choise_def object_def 
%type <node> boolean_def any_def size_def2 obj_constant obj_constant_list
%type <node> constant_def type_constant type_constant_list definitions
%type <node> definitions_id Time bit_element bit_element_list set_def
%type <node> identifier_list imports_def tag_type tag type_assig_right_tag
%type <node> type_assig_right_tag_default enumerated_def
%type <str>  pos_num neg_num pos_neg_num pos_neg_identifier num_identifier 
%type <constant> class explicit_implicit

%%

input:  /* empty */  
       | input definitions
;

pos_num :   NUM       {strcpy($$,$1);}
          | '+' NUM   {strcpy($$,$2);}
;

neg_num : '-' NUM     {strcpy($$,"-");
                       strcat($$,$2);}
;

pos_neg_num :  pos_num  {strcpy($$,$1);}
             | neg_num  {strcpy($$,$1);}
;

num_identifier :  NUM            {strcpy($$,$1);}
                | IDENTIFIER     {strcpy($$,$1);}
;

pos_neg_identifier :  pos_neg_num    {strcpy($$,$1);}
                    | IDENTIFIER     {strcpy($$,$1);}
;

constant: '(' pos_neg_num ')'   {$$=_asn1_add_node(TYPE_CONSTANT); 
                         _asn1_set_value($$,$2,strlen($2)+1);}
        | IDENTIFIER'('pos_neg_num')' {$$=_asn1_add_node(TYPE_CONSTANT);
	                         _asn1_set_name($$,$1); 
                               _asn1_set_value($$,$3,strlen($3)+1);}
;

constant_list:  constant   {$$=$1;}
              | constant_list ',' constant {$$=$1;
                                            _asn1_set_right(_asn1_get_last_right($1),$3);}
;

identifier_list  :  IDENTIFIER  {$$=_asn1_add_node(TYPE_IDENTIFIER);
                                 _asn1_set_name($$,$1);}
                  | identifier_list IDENTIFIER  
                                {$$=$1;
                                 _asn1_set_right(_asn1_get_last_right($$),_asn1_add_node(TYPE_IDENTIFIER));
                                 _asn1_set_name(_asn1_get_last_right($$),$2);}
;

obj_constant:  num_identifier     {$$=_asn1_add_node(TYPE_CONSTANT); 
                                   _asn1_set_value($$,$1,strlen($1)+1);}
             | IDENTIFIER'('NUM')' {$$=_asn1_add_node(TYPE_CONSTANT);
	                            _asn1_set_name($$,$1); 
                                    _asn1_set_value($$,$3,strlen($3)+1);}
;

obj_constant_list:  obj_constant        {$$=$1;}
                  | obj_constant_list obj_constant {$$=$1;
                                                    _asn1_set_right(_asn1_get_last_right($1),$2);}
;

class :  UNIVERSAL    {$$=CONST_UNIVERSAL;}
       | PRIVATE      {$$=CONST_PRIVATE;}
       | APPLICATION  {$$=CONST_APPLICATION;}
;

tag_type :  '[' NUM ']'    {$$=_asn1_add_node(TYPE_TAG); 
                            _asn1_set_value($$,$2,strlen($2)+1);}
          | '[' class NUM ']'  {$$=_asn1_add_node(TYPE_TAG | $2); 
                                _asn1_set_value($$,$3,strlen($3)+1);}
;

tag :  tag_type           {$$=$1;}
     | tag_type EXPLICIT  {$$=_asn1_mod_type($1,CONST_EXPLICIT);}
     | tag_type IMPLICIT  {$$=_asn1_mod_type($1,CONST_IMPLICIT);}
;

default :  DEFAULT pos_neg_identifier {$$=_asn1_add_node(TYPE_DEFAULT); 
                                   _asn1_set_value($$,$2,strlen($2)+1);}
         | DEFAULT TRUE           {$$=_asn1_add_node(TYPE_DEFAULT|CONST_TRUE);}
         | DEFAULT FALSE          {$$=_asn1_add_node(TYPE_DEFAULT|CONST_FALSE);}
;

integer_def: INTEGER   {$$=_asn1_add_node(TYPE_INTEGER);}
           | INTEGER'{'constant_list'}' {$$=_asn1_add_node(TYPE_INTEGER|CONST_LIST);
	                                 _asn1_set_down($$,$3);}
           | integer_def'('num_identifier'.''.'num_identifier')'
                                        {$$=_asn1_add_node(TYPE_INTEGER|CONST_MIN_MAX);
                                         _asn1_set_down($$,_asn1_add_node(TYPE_SIZE)); 
                                         _asn1_set_value(_asn1_get_down($$),$6,strlen($6)+1); 
                                         _asn1_set_name(_asn1_get_down($$),$3);}
;

boolean_def: BOOLEAN   {$$=_asn1_add_node(TYPE_BOOLEAN);}
;

Time:   UTCTime          {$$=_asn1_add_node(TYPE_TIME|CONST_UTC);} 
      | GeneralizedTime  {$$=_asn1_add_node(TYPE_TIME|CONST_GENERALIZED);} 
;

size_def2: SIZE'('num_identifier')'  {$$=_asn1_add_node(TYPE_SIZE|CONST_1_PARAM);
	                              _asn1_set_value($$,$3,strlen($3)+1);}
        | SIZE'('num_identifier'.''.'num_identifier')'  
                                    {$$=_asn1_add_node(TYPE_SIZE|CONST_MIN_MAX);
	                               _asn1_set_value($$,$3,strlen($3)+1);
                                     _asn1_set_name($$,$6);}
;

size_def:   size_def2          {$$=$1;}
          | '(' size_def2 ')'  {$$=$2;}
;

octet_string_def : OCTET STRING   {$$=_asn1_add_node(TYPE_OCTET_STRING);}
                 | OCTET STRING size_def  {$$=_asn1_add_node(TYPE_OCTET_STRING|CONST_SIZE);
                                           _asn1_set_down($$,$3);}
;

bit_element :  IDENTIFIER'('NUM')' {$$=_asn1_add_node(TYPE_CONSTANT);
	                              _asn1_set_name($$,$1); 
                                    _asn1_set_value($$,$3,strlen($3)+1);}
;

bit_element_list :  bit_element   {$$=$1;}
                  | bit_element_list ',' bit_element  {$$=$1;
                                                       _asn1_set_right(_asn1_get_last_right($1),$3);}
;

bit_string_def : BIT STRING    {$$=_asn1_add_node(TYPE_BIT_STRING);}
               | BIT STRING'{'bit_element_list'}' 
                               {$$=_asn1_add_node(TYPE_BIT_STRING|CONST_LIST);
                                _asn1_set_down($$,$4);}
;

enumerated_def : ENUMERATED'{'bit_element_list'}' 
                               {$$=_asn1_add_node(TYPE_ENUMERATED|CONST_LIST);
                                _asn1_set_down($$,$3);}
;

object_def :  OBJECT STR_IDENTIFIER {$$=_asn1_add_node(TYPE_OBJECT_ID);}
;

type_assig_right: IDENTIFIER         {$$=_asn1_add_node(TYPE_IDENTIFIER);
                                      _asn1_set_value($$,$1,strlen($1)+1);}
                | IDENTIFIER size_def {$$=_asn1_add_node(TYPE_IDENTIFIER|CONST_SIZE);
                                      _asn1_set_value($$,$1,strlen($1)+1);
                                      _asn1_set_down($$,$2);}
                | integer_def        {$$=$1;}
                | enumerated_def     {$$=$1;}
                | boolean_def        {$$=$1;}
                | Time            
                | octet_string_def   {$$=$1;}
                | bit_string_def     {$$=$1;}
                | sequence_def       {$$=$1;}
                | object_def         {$$=$1;}
                | choise_def         {$$=$1;}
                | any_def            {$$=$1;}
                | set_def            {$$=$1;}
                | TOKEN_NULL         {$$=_asn1_add_node(TYPE_NULL);}
;

type_assig_right_tag :   type_assig_right  {$$=$1;}
                       | tag type_assig_right {$$=_asn1_mod_type($2,CONST_TAG);
                                                   _asn1_set_right($1,_asn1_get_down($$));
                                                   _asn1_set_down($$,$1);}
;

type_assig_right_tag_default : type_assig_right_tag  {$$=$1;}
                      | type_assig_right_tag default  {$$=_asn1_mod_type($1,CONST_DEFAULT);
                                                       _asn1_set_right($2,_asn1_get_down($$));
						       _asn1_set_down($$,$2);}
                      | type_assig_right_tag OPTIONAL   {$$=_asn1_mod_type($1,CONST_OPTION);}
;
 
type_assig : IDENTIFIER type_assig_right_tag_default  {$$=_asn1_set_name($2,$1);}
;

type_assig_list : type_assig                   {$$=$1;}
                | type_assig_list','type_assig {$$=$1;
                                                _asn1_set_right(_asn1_get_last_right($1),$3)}
;

sequence_def : SEQUENCE'{'type_assig_list'}' {$$=_asn1_add_node(TYPE_SEQUENCE);
                                              _asn1_set_down($$,$3);}
   | SEQUENCE OF type_assig_right  {$$=_asn1_add_node(TYPE_SEQUENCE_OF);
                                    _asn1_set_down($$,$3);}
   | SEQUENCE size_def OF type_assig_right {$$=_asn1_add_node(TYPE_SEQUENCE_OF|CONST_SIZE);
                                            _asn1_set_right($2,$4);
                                            _asn1_set_down($$,$2);}
; 

set_def :  SET'{'type_assig_list'}' {$$=_asn1_add_node(TYPE_SET);
                                     _asn1_set_down($$,$3);}
   | SET OF type_assig_right  {$$=_asn1_add_node(TYPE_SET_OF);
                               _asn1_set_down($$,$3);}
   | SET size_def OF type_assig_right {$$=_asn1_add_node(TYPE_SET_OF|CONST_SIZE);
                                       _asn1_set_right($2,$4);
                                       _asn1_set_down($$,$2);}
; 

choise_def :   CHOICE'{'type_assig_list'}'  {$$=_asn1_add_node(TYPE_CHOICE);
                                              _asn1_set_down($$,$3);}
;

any_def :  ANY                         {$$=_asn1_add_node(TYPE_ANY);}
         | ANY DEFINED BY IDENTIFIER   {$$=_asn1_add_node(TYPE_ANY|CONST_DEFINED_BY);
                                        _asn1_set_down($$,_asn1_add_node(TYPE_CONSTANT));
	                                _asn1_set_name(_asn1_get_down($$),$4);}
;

type_def : IDENTIFIER "::=" type_assig_right_tag  {$$=_asn1_set_name($3,$1);}
;

constant_def :  IDENTIFIER OBJECT STR_IDENTIFIER "::=" '{'obj_constant_list'}'
                        {$$=_asn1_add_node(TYPE_OBJECT_ID|CONST_ASSIGN);
                         _asn1_set_name($$,$1);  
                         _asn1_set_down($$,$6);}
              | IDENTIFIER IDENTIFIER "::=" '{' obj_constant_list '}'
                        {$$=_asn1_add_node(TYPE_OBJECT_ID|CONST_ASSIGN|CONST_1_PARAM);
                         _asn1_set_name($$,$1);  
                         _asn1_set_value($$,$2,strlen($2)+1);
                         _asn1_set_down($$,$5);}
              | IDENTIFIER INTEGER "::=" NUM
                        {$$=_asn1_add_node(TYPE_INTEGER|CONST_ASSIGN);
                         _asn1_set_name($$,$1);  
                         _asn1_set_value($$,$4,strlen($4)+1);}
;

type_constant:   type_def     {$$=$1;}
               | constant_def {$$=$1;}
;

type_constant_list :   type_constant    {$$=$1;}
                     | type_constant_list type_constant  {$$=$1;
                                                          _asn1_set_right(_asn1_get_last_right($1),$2);}
;

definitions_id  :  IDENTIFIER  '{' obj_constant_list '}' {$$=_asn1_add_node(TYPE_OBJECT_ID);
                                                          _asn1_set_down($$,$3);
                                                          _asn1_set_name($$,$1)}
;

imports_def :   /* empty */  {$$=NULL;}
              | IMPORTS identifier_list FROM IDENTIFIER obj_constant_list 
                        {$$=_asn1_add_node(TYPE_IMPORTS);
                         _asn1_set_down($$,_asn1_add_node(TYPE_OBJECT_ID));
                         _asn1_set_name(_asn1_get_down($$),$4);  
                         _asn1_set_down(_asn1_get_down($$),$5);
                         _asn1_set_right($$,$2);}
;

explicit_implicit :  EXPLICIT  {$$=CONST_EXPLICIT;}
                   | IMPLICIT  {$$=CONST_IMPLICIT;}
;

definitions:   definitions_id
               DEFINITIONS explicit_implicit TAGS "::=" BEGIN imports_def 
               type_constant_list END
                   {$$=_asn1_add_node(TYPE_DEFINITIONS|$3|(($7==NULL)?0:CONST_IMPORTS));
                    _asn1_set_name($$,_asn1_get_name($1));
                    _asn1_set_name($1,"");
                    if($7==NULL) _asn1_set_right($1,$8);
                    else {_asn1_set_right($7,$8);_asn1_set_right($1,$7);}
                    _asn1_set_down($$,$1);
      		    if(parse_mode==PARSE_MODE_CREATE){
		      _asn1_set_default_tag($$);
		      _asn1_type_set_config($$);
		      result_parse=_asn1_check_identifier($$);
		      if(result_parse==ASN_IDENTIFIER_NOT_FOUND)
		      	asn1_delete_structure($$);
		      else p_tree=$$;
		    }}
;

%%


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
  char string[129];  
  while(1)
    {
    while((c=fgetc(file_asn1))==' ' || c=='\t' || c=='\n');
    if(c==EOF) return 0;
    if(c=='(' || c==')' || c=='[' || c==']' || 
       c=='{' || c=='}' || c==',' || c=='.' ||
       c=='+') return c;
    if(c=='-'){
      if((c=fgetc(file_asn1))!='-'){
	ungetc(c,file_asn1);
	return '-';
      }
      else{
	/* A comment finishes at the end of line */
	counter=0;
	while((c=fgetc(file_asn1))!=EOF && c!='\n');
	if(c==EOF) return 0;
	else continue; /* repeat the search */
      }
    }
    string[counter++]=c;
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
      return NUM;
      }
 
    /* Is STRING a keyword? */
    for(k=0;k<(sizeof(key_word)/sizeof(char*));k++)  
      if(!strcmp(string,key_word[k])) return key_word_token[k]; 
 
    /* STRING is an IDENTIFIER */
    strcpy(yylval.str,string);
    return IDENTIFIER;
    }
}


/*************************************************************/
/*  Function: parser_asn1                                    */
/*  Description: function used to start the parse algorithm. */
/*  Parameters:                                              */
/*    char *file_name : file name to parse                   */
/*  Return: int                                              */
/*                                                           */
/*************************************************************/
int 
asn1_parser_asn1(char *file_name,node_asn **pointer)
{
  /*  yydebug=1;  */

  p_tree=NULL;
  *pointer=NULL;
  
  file_asn1=fopen(file_name,"r");

  if(file_asn1==NULL) return ASN_FILE_NOT_FOUND;

  result_parse=ASN_OK;

  parse_mode=PARSE_MODE_CHECK;
  yyparse();

  if(result_parse==ASN_OK){
    fclose(file_asn1);
    file_asn1=fopen(file_name,"r");

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



/*************************************************************/
/*  Function: parser_asn1_file_c                             */
/*  Description: function that generates a C structure from  */
/*               an ASN1 file                                */
/*  Parameters:                                              */
/*    char *file_name : file name to parse                   */
/*  Return: int                                              */
/*                                                           */
/*************************************************************/
int 
asn1_parser_asn1_file_c(char *file_name)
{
  int result;

  /*  yydebug=1;  */

  p_tree=NULL;
    
  file_asn1=fopen(file_name,"r");

  if(file_asn1==NULL) return ASN_FILE_NOT_FOUND;

  result_parse=ASN_OK;

  parse_mode=PARSE_MODE_CHECK;
  yyparse();

  if(result_parse==ASN_OK){
    fclose(file_asn1);
    file_asn1=fopen(file_name,"r");

    parse_mode=PARSE_MODE_CREATE;
    yyparse();

    result=_asn1_create_static_structure(p_tree,file_name);

    asn1_delete_structure(p_tree);
   }

  fclose(file_asn1);

  parse_mode=PARSE_MODE_CREATE;

  return result_parse;
}


/*************************************************************/
/*  Function: yyerror                                        */
/*  Description: function used with syntax errors            */
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
}














