
/*****************************************************/
/* File: ASN.y                                       */
/* Description: input file for 'bison' program.      */
/*   The output file is a parser (in C language) for */
/*   ASN.1 syntax                                    */
/*****************************************************/


%{
#include <defines.h>
#include <cert_asn1.h>

FILE *file_asn1;  /* Pointer to the to parse */
extern int parse_mode;
int result_parse;
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

%type <node> octet_string_def constant constant_list type_assig_right 
%type <node> integer_def type_assig type_assig_list sequence_def type_def
%type <node> bit_string_def default size_def choise_def object_def 
%type <node> boolean_def any_def size_def2 obj_constant obj_constant_list
%type <node> constant_def type_constant type_constant_list definitions
%type <node> definitions_id Time bit_element bit_element_list set_def
%type <node> identifier_list imports_def tag_type tag type_assig_right_tag
%type <node> type_assig_right_tag_default
%type <str>  num_identifier 
%type <constant> class explicit_implicit

%%

input:  /* empty */  
       | input definitions
;

num_identifier :  NUM            {strcpy($$,$1);}
                | IDENTIFIER     {strcpy($$,$1);}
;

constant: '(' NUM ')'   {$$=add_node(TYPE_CONSTANT); 
                         set_value($$,$2,strlen($2)+1);}
        | IDENTIFIER'('NUM')' {$$=add_node(TYPE_CONSTANT);
	                         set_name($$,$1); 
                               set_value($$,$3,strlen($3)+1);}
;

constant_list:  constant   {$$=$1;}
              | constant_list ',' constant {$$=$1;
                                            set_right(get_last_right($1),$3);}
;

identifier_list  :  IDENTIFIER  {$$=add_node(TYPE_IDENTIFIER);
                                 set_name($$,$1);}
                  | identifier_list IDENTIFIER  
                                {$$=$1;
                                 set_right(get_last_right($$),add_node(TYPE_IDENTIFIER));
                                 set_name(get_last_right($$),$2);}
;

obj_constant:  num_identifier     {$$=add_node(TYPE_CONSTANT); 
                                   set_value($$,$1,strlen($1)+1);}
             | IDENTIFIER'('NUM')' {$$=add_node(TYPE_CONSTANT);
	                            set_name($$,$1); 
                                    set_value($$,$3,strlen($3)+1);}
;

obj_constant_list:  obj_constant        {$$=$1;}
                  | obj_constant_list obj_constant {$$=$1;
                                                    set_right(get_last_right($1),$2);}
;

class :  UNIVERSAL    {$$=CONST_UNIVERSAL;}
       | PRIVATE      {$$=CONST_PRIVATE;}
       | APPLICATION  {$$=CONST_APPLICATION;}
;

tag_type :  '[' NUM ']'    {$$=add_node(TYPE_TAG); 
                            set_value($$,$2,strlen($2)+1);}
          | '[' class NUM ']'  {$$=add_node(TYPE_TAG | $2); 
                                set_value($$,$3,strlen($3)+1);}
;

tag :  tag_type           {$$=$1;}
     | tag_type EXPLICIT  {$$=mod_type($1,CONST_EXPLICIT);}
     | tag_type IMPLICIT  {$$=mod_type($1,CONST_IMPLICIT);}
;

default :  DEFAULT num_identifier {$$=add_node(TYPE_DEFAULT); 
                                   set_value($$,$2,strlen($2)+1);}
         | DEFAULT TRUE           {$$=add_node(TYPE_DEFAULT|CONST_TRUE);}
         | DEFAULT FALSE          {$$=add_node(TYPE_DEFAULT|CONST_FALSE);}
;

integer_def: INTEGER   {$$=add_node(TYPE_INTEGER);}
           | INTEGER'{'constant_list'}' {$$=add_node(TYPE_INTEGER|CONST_LIST);
                                         set_down($$,$3);}
           | integer_def'('num_identifier'.''.'num_identifier')'
                                        {$$=add_node(TYPE_INTEGER|CONST_MIN_MAX);
                                         set_down($$,add_node(TYPE_SIZE)); 
                                         set_value(get_down($$),$6,strlen($6)+1); 
                                         set_name(get_down($$),$3);}
;

boolean_def: BOOLEAN   {$$=add_node(TYPE_BOOLEAN);}
;

Time:   UTCTime          {$$=add_node(TYPE_TIME|CONST_UTC);} 
      | GeneralizedTime  {$$=add_node(TYPE_TIME|CONST_GENERALIZED);} 
;

size_def2: SIZE'('num_identifier')'  {$$=add_node(TYPE_SIZE|CONST_1_PARAM);
	                              set_value($$,$3,strlen($3)+1);}
        | SIZE'('num_identifier'.''.'num_identifier')'  
                                    {$$=add_node(TYPE_SIZE|CONST_MIN_MAX);
	                               set_value($$,$3,strlen($3)+1);
                                     set_name($$,$6);}
;

size_def:   size_def2          {$$=$1;}
          | '(' size_def2 ')'  {$$=$2;}
;

octet_string_def : OCTET STRING   {$$=add_node(TYPE_OCTET_STRING);}
                 | OCTET STRING size_def  {$$=add_node(TYPE_OCTET_STRING|CONST_SIZE);
                                           set_down($$,$3);}
;

bit_element :  IDENTIFIER'('NUM')' {$$=add_node(TYPE_CONSTANT);
	                              set_name($$,$1); 
                                    set_value($$,$3,strlen($3)+1);}
;

bit_element_list :  bit_element   {$$=$1;}
                  | bit_element_list ',' bit_element  {$$=$1;
                                                       set_right(get_last_right($1),$3);}
;

bit_string_def : BIT STRING    {$$=add_node(TYPE_BIT_STRING);}
               | BIT STRING'{'bit_element_list'}' 
                               {$$=add_node(TYPE_BIT_STRING|CONST_LIST);
                                set_down($$,$4);}
;

object_def :  OBJECT STR_IDENTIFIER {$$=add_node(TYPE_OBJECT_ID);}
;

type_assig_right: IDENTIFIER         {$$=add_node(TYPE_IDENTIFIER);
                                      set_value($$,$1,strlen($1)+1);}
                | IDENTIFIER size_def {$$=add_node(TYPE_IDENTIFIER|CONST_SIZE);
                                      set_value($$,$1,strlen($1)+1);
                                      set_down($$,$2);}
                | integer_def        {$$=$1;}
                | boolean_def        {$$=$1;}
                | Time            
                | octet_string_def   {$$=$1;}
                | bit_string_def     {$$=$1;}
                | sequence_def       {$$=$1;}
                | object_def         {$$=$1;}
                | choise_def         {$$=$1;}
                | any_def            {$$=$1;}
                | set_def            {$$=$1;}
                | TOKEN_NULL         {$$=add_node(TYPE_NULL);}
;

type_assig_right_tag :   type_assig_right  {$$=$1;}
                       | tag type_assig_right {$$=mod_type($2,CONST_TAG);
                                                   set_right($1,get_down($$));
                                                   set_down($$,$1);}
;

type_assig_right_tag_default : type_assig_right_tag  {$$=$1;}
                      | type_assig_right_tag default  {$$=mod_type($1,CONST_DEFAULT);
                                                       set_right($2,get_down($$));
						        set_down($$,$2);}
                      | type_assig_right_tag OPTIONAL   {$$=mod_type($1,CONST_OPTION);}
;
 
type_assig : IDENTIFIER type_assig_right_tag_default  {$$=set_name($2,$1);}
;

type_assig_list : type_assig                   {$$=$1;}
                | type_assig_list','type_assig {$$=$1;
                                                set_right(get_last_right($1),$3)}
;

sequence_def : SEQUENCE'{'type_assig_list'}' {$$=add_node(TYPE_SEQUENCE);
                                              set_down($$,$3);}
   | SEQUENCE OF type_assig_right  {$$=add_node(TYPE_SEQUENCE_OF);
                                    set_down($$,$3);}
   | SEQUENCE size_def OF type_assig_right {$$=add_node(TYPE_SEQUENCE_OF|CONST_SIZE);
                                            set_right($2,$4);
                                            set_down($$,$2);}
; 

set_def :  SET'{'type_assig_list'}' {$$=add_node(TYPE_SET);
                                     set_down($$,$3);}
   | SET OF type_assig_right  {$$=add_node(TYPE_SET_OF);
                               set_down($$,$3);}
   | SET size_def OF type_assig_right {$$=add_node(TYPE_SET_OF|CONST_SIZE);
                                       set_right($2,$4);
                                       set_down($$,$2);}
; 

choise_def :   CHOICE'{'type_assig_list'}'  {$$=add_node(TYPE_CHOICE);
                                              set_down($$,$3);}
;

any_def :  ANY                         {$$=add_node(TYPE_ANY);}
         | ANY DEFINED BY IDENTIFIER   {$$=add_node(TYPE_ANY|CONST_DEFINED_BY);
                                        set_down($$,add_node(TYPE_CONSTANT));
	                                set_name(get_down($$),$4);}
;

type_def : IDENTIFIER "::=" type_assig_right_tag  {$$=set_name($3,$1);}
;

constant_def :  IDENTIFIER OBJECT STR_IDENTIFIER "::=" '{' obj_constant_list '}'
                        {$$=add_node(TYPE_OBJECT_ID);
                         set_name($$,$1);  
                         set_down($$,$6);}
              | IDENTIFIER IDENTIFIER "::=" '{' obj_constant_list '}'
                        {$$=add_node(TYPE_OBJECT_ID|CONST_1_PARAM);
                         set_name($$,$1);  
                         set_value($$,$2,strlen($2)+1);
                         set_down($$,$5);}
              | IDENTIFIER INTEGER "::=" NUM
                        {$$=add_node(TYPE_INTEGER);
                         set_name($$,$1);  
                         set_value($$,$4,strlen($4)+1);}
;

type_constant:   type_def     {$$=$1;}
               | constant_def {$$=$1;}
;

type_constant_list :   type_constant    {$$=$1;}
                     | type_constant_list type_constant  {$$=$1;
                                                          set_right(get_last_right($1),$2);}
;

definitions_id  :  IDENTIFIER  '{' obj_constant_list '}' {$$=add_node(TYPE_OBJECT_ID);
                                                          set_down($$,$3);
                                                          set_name($$,$1)}
;

imports_def :   /* empty */  {$$=NULL;}
              | IMPORTS identifier_list FROM IDENTIFIER obj_constant_list 
                        {$$=add_node(TYPE_IMPORTS);
                         set_down($$,add_node(TYPE_OBJECT_ID));
                         set_name(get_down($$),$4);  
                         set_down(get_down($$),$5);
                         set_right($$,$2);}
;

explicit_implicit :  EXPLICIT  {$$=CONST_EXPLICIT;}
                   | IMPLICIT  {$$=CONST_IMPLICIT;}
;

definitions:   definitions_id
               DEFINITIONS explicit_implicit TAGS "::=" BEGIN imports_def 
               type_constant_list END
                   {$$=add_node(TYPE_DEFINITIONS|$3|(($7==NULL)?0:CONST_IMPORTS));
                    set_name($$,get_name($1));
                    set_name($1,"");
                    if($7==NULL) set_right($1,$8);
                    else {set_right($7,$8);set_right($1,$7);}
                    set_down($$,$1);
		    if(parse_mode==PARSE_MODE_CREATE){
		      check_asn(get_name($$), CHECK_DEFAULT_TAG_TYPE);
		      result_parse=check_asn(get_name($$), CHECK_TYPE);}}
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
                       ,"IMPORTS","NULL"};
const int key_word_token[]={ASSIG,OPTIONAL,INTEGER,SIZE,OCTET,STRING
                       ,SEQUENCE,BIT,UNIVERSAL,PRIVATE,OPTIONAL
                       ,DEFAULT,CHOICE,OF,OBJECT,STR_IDENTIFIER
                       ,BOOLEAN,TRUE,FALSE,APPLICATION,ANY,DEFINED
                       ,SET,BY,EXPLICIT,IMPLICIT,DEFINITIONS,TAGS
                       ,BEGIN,END,UTCTime,GeneralizedTime,FROM
                       ,IMPORTS,TOKEN_NULL};

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
       c=='{' || c=='}' || c==',' || c=='.') return c;
    string[counter++]=c;
    while(!((c=fgetc(file_asn1))==EOF || c==' '|| c=='\t' || c=='\n' || 
	     c=='(' || c==')' || c=='[' || c==']' || 
	     c=='{' || c=='}' || c==',' || c=='.'))
      { 
      string[counter++]=c;
      }
    ungetc(c,file_asn1);
    string[counter]=0;

    /* Is STRING the beginning of a comment? */
    if(!strcmp(string,"--"))
      {
	/* A comment finishes at the end of line */
	counter=0;
      while((c=fgetc(file_asn1))!=EOF && c!='\n');
      if(c==EOF) return 0;
      else continue; /* repeat the search */
      }

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
parser_asn1(char *file_name)
{
  /*  yydebug=1;  */
  
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
  printf("%s\n",s);
  result_parse=ASN_SYNTAX_ERROR;
}














