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
/* File: cert_asn1.c                                 */
/* Description: Functions to manage ASN.1 DEFINITIONS*/
/*****************************************************/


#include <gnutls_int.h> 

/*
#include <string.h>  
#include <stdlib.h> 
#include <stdio.h>
*/

#include "cert_asn1.h"
#include "cert_der.h"


#define UP     1
#define RIGHT  2
#define DOWN   3


int parse_mode;


/******************************************************/
/* Function : add_node                                */
/* Description: adds an element to the list of nodes. */
/* Parameters:                                        */
/*   unsigned int type: node description (see TYPE_   */
/*                      and CONST_ constants)         */
/* Return: node_asn                                   */
/*   Pointer to the new element                       */
/******************************************************/
node_asn *
_asn1_add_node(unsigned int type)
{
  node_asn *punt;

  if(parse_mode==PARSE_MODE_CHECK) return NULL;

  punt=(node_asn *) malloc(sizeof(node_asn));

  punt->left=NULL;
  punt->name=NULL;
  punt->type=type; 
  punt->value=NULL;
  punt->down=NULL;
  punt->right=NULL;

  return punt;
}


node_asn *
_asn1_set_value(node_asn *node,unsigned char *value,unsigned int len)
{
  if(parse_mode==PARSE_MODE_CHECK) return NULL;

  if(node==NULL) return node;
  if(node->value){
    free(node->value);
    node->value=NULL;  
  }
  if(!len) return node;
  node->value=(unsigned char *) malloc(len);
  memcpy(node->value,value,len);
  return node;
}

node_asn *
_asn1_set_name(node_asn *node,char *name)
{
  if(parse_mode==PARSE_MODE_CHECK) return NULL;

  if(node==NULL) return node;

  if(node->name){
    free(node->name);
    node->name=NULL;
  }

  if(name==NULL) return node;

  if(strlen(name))
	{
  	node->name=(char *) malloc(strlen(name)+1);
  	strcpy(node->name,name);
      }
  else node->name=NULL;
  return node;
}


node_asn *
_asn1_set_right(node_asn *node,node_asn *right)
{
  if(parse_mode==PARSE_MODE_CHECK) return NULL;

  if(node==NULL) return node;
  node->right=right;
  if(right) right->left=node;
  return node;
}


node_asn *
_asn1_get_right(node_asn *node)
{
  if(parse_mode==PARSE_MODE_CHECK) return NULL;

  if(node==NULL) return NULL;
  return node->right;
}

node_asn *
_asn1_get_last_right(node_asn *node)
{
  node_asn *p;

  if(parse_mode==PARSE_MODE_CHECK) return NULL;
  if(node==NULL) return NULL;
  p=node;
  while(p->right) p=p->right;
  return p;
}

node_asn *
_asn1_set_down(node_asn *node,node_asn *down)
{
  if(parse_mode==PARSE_MODE_CHECK) return NULL;

  if(node==NULL) return node;
  node->down=down;
  if(down) down->left=node;
  return node;
}

node_asn *
_asn1_get_down(node_asn *node)
{
  if(parse_mode==PARSE_MODE_CHECK) return NULL;

  if(node==NULL) return NULL;
  return node->down;
}

char *
_asn1_get_name(node_asn *node)
{
  if(parse_mode==PARSE_MODE_CHECK) return NULL;

  if(node==NULL) return NULL;
  return node->name;
}

node_asn *
_asn1_mod_type(node_asn *node,unsigned int value)
{
  if(parse_mode==PARSE_MODE_CHECK) return NULL;

  if(node==NULL) return node;
  node->type|=value;
  return node;
}

void
_asn1_remove_node(node_asn *node)
{
  node_asn *punt,*punt_prev;

  if(node==NULL) return;

  free(node->name);
  free(node->value);
  free(node);
}



node_asn *
_asn1_find_node(node_asn *pointer,char *name)
{
  node_asn *p;
  char *n_start,*n_end,n[128];

  if((name==NULL) || (name[0]==0)) return NULL;

  n_start=name;
  n_end=strchr(n_start,'.');
  if(n_end){
    memcpy(n,n_start,n_end-n_start);
    n[n_end-n_start]=0;
    n_start=n_end;
    n_start++;
  }
  else{
    strcpy(n,n_start);
    n_start=NULL;
  }

  p=pointer;
  while(p){
    if((p->name) && (!strcmp(p->name,n))) break;
    else p=p->right;
  }

  if(p==NULL) return NULL;

  while(n_start){
    n_end=strchr(n_start,'.');
    if(n_end){
      memcpy(n,n_start,n_end-n_start);
      n[n_end-n_start]=0;
      n_start=n_end;
      n_start++;
    }
    else{
      strcpy(n,n_start);
      n_start=NULL;
    }

    if(p->down==NULL) return NULL;

    p=p->down;

    if(!strcmp(n,"?LAST")){
      if(p==NULL) return NULL;
      while(p->right) p=p->right;
    }
    else{
      while(p){
	if((p->name) && (!strcmp(p->name,n))) break;
	else p=p->right;
      }
      if(p==NULL) return NULL;
    }
  }

  return p;
}


node_asn *
_asn1_find_left(node_asn *node)
{
  if((node==NULL) || (node->left==NULL) || 
     (node->left->down==node)) return NULL;

  return node->left;  
}


node_asn *
_asn1_find_up(node_asn *node)
{
  node_asn *p;

  if(node==NULL) return NULL;

  p=node;

  while((p->left!=NULL) && (p->left->right==p)) p=p->left;

  return p->left;
}

void
_asn1_convert_integer(char *value,unsigned char *value_out,int *len)
{
  char negative;
  unsigned char val[4],temp;
  int k,k2;

  *((long*)val)=strtol(value,NULL,10);
  for(k=0;k<2;k++){
    temp=val[k];
    val[k]=val[3-k];
    val[3-k]=temp;
  }
	
  if(val[0]&0x80) negative=1;
  else negative=0;
  
  for(k=0;k<3;k++){
    if(negative && (val[k]!=0xFF)) break;
    else if(!negative && val[k]) break;
  }
	
  if((negative && !(val[k]&0x80)) ||
     (!negative && (val[k]&0x80))) k--; 

  for(k2=k;k2<4;k2++) value_out[k2-k]=val[k2];
  *len=4-k;
}


int
asn1_create_tree(static_asn *root,node_asn **pointer)
{
  node_asn *p,*p_last;
  unsigned long k;
  int move;

  *pointer=NULL;
  move=UP;

  k=0;
  while(root[k].value || root[k].type || root[k].name){
    p=_asn1_add_node(root[k].type&(~CONST_DOWN));
    if(root[k].name) _asn1_set_name(p,root[k].name);
    if(root[k].value) _asn1_set_value(p,root[k].value,strlen(root[k].value)+1);

    if(*pointer==NULL) *pointer=p;

    if(move==DOWN) _asn1_set_down(p_last,p);
    else if(move==RIGHT) _asn1_set_right(p_last,p);

    p_last=p;

    if(root[k].type&CONST_DOWN) move=DOWN;
    else if(root[k].type&CONST_RIGHT) move=RIGHT;
    else{
      while(1){
	if(p_last==*pointer) break;
   
	p_last= _asn1_find_up(p_last);

	if(p_last==NULL) break;

	if(p_last->type&CONST_RIGHT){
	  p_last->type&=~CONST_RIGHT;
	  move=RIGHT;
	  break;
	}
      }
    }
    k++;
  }

  if(p_last==*pointer){
    _asn1_change_integer_value(*pointer);
    _asn1_expand_object_id(*pointer);
  }
  else asn1_delete_structure(*pointer);

  return (p_last==*pointer)?ASN_OK:ASN_GENERIC_ERROR;
}


int
_asn1_create_static_structure(node_asn *pointer,char *file_name)
{
  FILE *file;  
  node_asn *p;
  unsigned long t;
  char structure_name[128],file_out_name[128],*char_p,*slash_p,*dot_p;

  char_p=file_name;
  slash_p=file_name;
  while(char_p=strchr(char_p,'/')){
    char_p++;
    slash_p=char_p;
  }

  char_p=slash_p;
  dot_p=file_name+strlen(file_name);

  while(char_p=strchr(char_p,'.')){
    dot_p=char_p;
    char_p++;
  }

  memcpy(structure_name,slash_p,dot_p-slash_p);
  structure_name[dot_p-slash_p]=0;
  strcat(structure_name,"_asn1_tab");

  memcpy(file_out_name,file_name,dot_p-file_name);
  file_out_name[dot_p-file_name]=0;
  strcat(file_out_name,"_asn1_tab.c");

  file=fopen(file_out_name,"w");

  if(file==NULL) return ASN_FILE_NOT_FOUND;

 fprintf(file,"\n#include \"cert_asn1.h\"\n\n");
 fprintf(file,"const static_asn %s[]={\n",structure_name);

 p=pointer;

 while(p){
   fprintf(file,"  {");

   if(p->name) fprintf(file,"\"%s\",",p->name);
   else fprintf(file,"0,");

   t=p->type;
   if(p->down) t|=CONST_DOWN;
   if(p->right) t|=CONST_RIGHT;

   fprintf(file,"%lu,",t);

   if(p->value) fprintf(file,"\"%s\"},\n",p->value);
   else fprintf(file,"0},\n");

   if(p->down){
     p=p->down;
   }
   else if(p->right){
     p=p->right;
   }
   else{
     while(1){
       p=_asn1_find_up(p);
       if(p==pointer){
	 p=NULL;
	 break;
       }
       if(p->right){
	 p=p->right;
	 break;
       }
     }
   }
 }

 fprintf(file,"  {0,0,0}\n};\n");

 fclose(file);

 return ASN_OK;
}


void
asn1_visit_tree(node_asn *pointer,char *name)
{
  node_asn *p,*root;
  int k,indent=0,len,len2,len3;
  unsigned char class;
  unsigned long tag;

  root=_asn1_find_node(pointer,name);   

  if(root==NULL) return;

  p=root;
  while(p){
    for(k=0;k<indent;k++)printf(" ");

    printf("name:");
    if(p->name) printf("%s  ",p->name);
    else printf("NULL  ");

    printf("type:");
    switch(type_field(p->type)){
    case TYPE_NULL:
      printf("NULL");
      break;
    case TYPE_CONSTANT:
      printf("CONST");
       if(p->value) printf("  value:%s",p->value);
      break;
    case TYPE_IDENTIFIER:
      printf("IDENTIFIER");
      if(p->value) printf("  value:%s",p->value);
      break;
    case TYPE_INTEGER:
      printf("INTEGER");
      if(p->value){
	len=_asn1_get_length_der(p->value,&len2);
	printf("  value:0x");
	for(k=0;k<len;k++) printf("%02x",(p->value)[k+len2]);
      }
      break;
    case TYPE_ENUMERATED:
      printf("ENUMERATED");
      if(p->value){
	len=_asn1_get_length_der(p->value,&len2);
	printf("  value:0x");
	for(k=0;k<len;k++) printf("%02x",(p->value)[k+len2]);
      }
      break;
    case TYPE_TIME:
      printf("TIME");
      if(p->value) printf("  value:%s",p->value);
      break;
    case TYPE_BOOLEAN:
      printf("BOOLEAN");
      if(p->value){
	if(p->value[0]=='T') printf("  value:TRUE",p->value);
	else if(p->value[0]=='F') printf("  value:FALSE",p->value);
      }
      break;
    case TYPE_SEQUENCE:
      printf("SEQUENCE");
      break;
    case TYPE_BIT_STRING:
      printf("BIT_STR");
      if(p->value){
	len=_asn1_get_length_der(p->value,&len2);
	printf("  value(%i):",(len-1)*8-(p->value[len2]));
	for(k=1;k<len;k++) printf("%02x",(p->value)[k+len2]);
      }
      break;
    case TYPE_OCTET_STRING:
      printf("OCT_STR");
      if(p->value){
	len=_asn1_get_length_der(p->value,&len2);
	printf("  value:");
	for(k=0;k<len;k++) printf("%02x",(p->value)[k+len2]);
      }
      break;
    case TYPE_TAG:
      printf("TAG");
      printf("  value:%s",p->value);
      break;
    case TYPE_DEFAULT:
      printf("DEFAULT");
      if(p->value) printf("  value:%s",p->value);
      break;
    case TYPE_SIZE:
      printf("SIZE");
      if(p->value) printf("  value:%s",p->value);
      break;
    case TYPE_SEQUENCE_OF:
      printf("SEQ_OF");
      break;
    case TYPE_OBJECT_ID:
      printf("OBJ_ID");
      if(p->value) printf("  value:%s",p->value);
      break;
    case TYPE_ANY:
      printf("ANY");
      if(p->value){
	len2=_asn1_get_length_der(p->value,&len3);
	printf("  value:");
	for(k=0;k<len2;k++) printf("%02x",(p->value)[k+len3]);
      }

      break;
    case TYPE_SET:
      printf("SET");
      break;
    case TYPE_SET_OF:
      printf("SET_OF");
      break;
    case TYPE_CHOICE:
      printf("CHOICE");
      break;
    case TYPE_DEFINITIONS:
      printf("DEFINITIONS");
      break;
    default:
      printf("ERROR\n");
      break;
    }

    if(p->type&0xFFFFFF00){
      printf("  attr:");
      if(p->type & CONST_UNIVERSAL) printf("UNIVERSAL,");
      if(p->type & CONST_PRIVATE) printf("PRIVATE,");
      if(p->type & CONST_APPLICATION) printf("APPLICATION,");
      if(p->type & CONST_EXPLICIT) printf("EXPLICIT,");
      if(p->type & CONST_IMPLICIT) printf("IMPLICIT,");
      if(p->type & CONST_TAG) printf("TAG,");
      if(p->type & CONST_DEFAULT) printf("DEFAULT,");
      if(p->type & CONST_TRUE) printf("TRUE,");
      if(p->type & CONST_FALSE) printf("FALSE,");
      if(p->type & CONST_LIST) printf("LIST,");
      if(p->type & CONST_MIN_MAX) printf("MIN_MAX,");
      if(p->type & CONST_OPTION) printf("OPTION,");
      if(p->type & CONST_1_PARAM) printf("1_PARAM,");
      if(p->type & CONST_SIZE) printf("SIZE,");
      if(p->type & CONST_DEFINED_BY) printf("DEF_BY,");
      if(p->type & CONST_GENERALIZED) printf("GENERALIZED,");
      if(p->type & CONST_UTC) printf("UTC,");
      if(p->type & CONST_IMPORTS) printf("IMPORTS,");
      if(p->type & CONST_SET) printf("SET,");
      if(p->type & CONST_NOT_USED) printf("NOT_USED,");
      if(p->type & CONST_ASSIGN) printf("ASSIGNEMENT,");
    }

    printf("\n");

    if(p->down){
      p=p->down;
      indent+=2;
    }
    else if(p==root){
      p=NULL;
      break;
    }
    else if(p->right) p=p->right;
    else{
      while(1){
	p=_asn1_find_up(p);
	if(p==root){
	  p=NULL;
	  break;
	}
	indent-=2;
	if(p->right){
	  p=p->right;
	  break;
	}
      }
    }
  }
}

int
asn1_delete_structure(node_asn *root)
{
  node_asn *p,*p2,*p3;

  if(root==NULL) return ASN_ELEMENT_NOT_FOUND;

  p=root;
  while(p){
    if(p->down){
      p=p->down;
    }
    else{   /* no down */
      p2=p->right;
      if(p!=root){
	p3=_asn1_find_up(p);
	_asn1_set_down(p3,p2);
	_asn1_remove_node(p);
	p=p3;
      }
      else{   /* p==root */
	p3=_asn1_find_left(p);
	if(!p3){
	  p3=_asn1_find_up(p);
	  if(p3) _asn1_set_down(p3,p2);
	  else{
	    if(p->right) p->right->left=NULL;
	  }
	}
	else _asn1_set_right(p3,p2);
	_asn1_remove_node(p);
	p=NULL;
      }
    }
  }
  return ASN_OK;
}


node_asn *
_asn1_copy_structure3(node_asn *source_node)
{
  node_asn *dest_node,*p_s,*p_d,*p_d_prev;
  int len,len2,move;

  if(source_node==NULL) return NULL;

  dest_node=_asn1_add_node(source_node->type);

  p_s=source_node;
  p_d=dest_node;

  move=DOWN;

  do{
    if(move!=UP){
      if(p_s->name) _asn1_set_name(p_d,p_s->name);
      if(p_s->value){
	switch(type_field(p_s->type)){
	case TYPE_OCTET_STRING: case TYPE_BIT_STRING: 
	case TYPE_INTEGER: case TYPE_DEFAULT:
	  len=_asn1_get_length_der(p_s->value,&len2);
	  _asn1_set_value(p_d,p_s->value,len+len2);
	  break;
	default:
	  _asn1_set_value(p_d,p_s->value,strlen(p_s->value)+1);
	}
      }
      move=DOWN;
    }
    else move=RIGHT;

    if(move==DOWN){
      if(p_s->down){
	p_s=p_s->down;
	p_d_prev=p_d;      
	p_d=_asn1_add_node(p_s->type);
	_asn1_set_down(p_d_prev,p_d);
      }
      else move=RIGHT;
    }
  
    if(p_s==source_node) break;

    if(move==RIGHT){
      if(p_s->right){
	p_s=p_s->right;
	p_d_prev=p_d;
	p_d=_asn1_add_node(p_s->type);
	_asn1_set_right(p_d_prev,p_d);
      }
      else move=UP;
    }
    if(move==UP){
      p_s=_asn1_find_up(p_s);
      p_d=_asn1_find_up(p_d);
    }
  }while(p_s!=source_node);

  return dest_node;
}


node_asn *
_asn1_copy_structure2(node_asn *root,char *source_name)
{
  node_asn *source_node;

  source_node=_asn1_find_node(root,source_name);
  
  return _asn1_copy_structure3(source_node);

}


int
asn1_create_structure(node_asn *root,char *source_name,node_asn **pointer,char *dest_name)
{
  node_asn *dest_node;
  int res;
  char *end,n[129];

  *pointer=NULL;

  dest_node=_asn1_copy_structure2(root,source_name);
 
  if(dest_node==NULL) return ASN_ELEMENT_NOT_FOUND;

  _asn1_set_name(dest_node,dest_name);

  end=strchr(source_name,'.');
  if(end){
    memcpy(n,source_name,end-source_name);
    n[end-source_name]=0;
  }
  else{
    strcpy(n,source_name);
  }

  res=_asn1_expand_identifier(&dest_node,root);
  _asn1_type_choice_config(dest_node);

  *pointer=dest_node;

  return res;
}


int 
_asn1_append_sequence_set(node_asn *node)
{
  node_asn *p,*p2;
  char *temp;
  long n;

  if(!node || !(node->down)) return ASN_GENERIC_ERROR;

  p=node->down;
  while((type_field(p->type)==TYPE_TAG) || (type_field(p->type)==TYPE_SIZE)) p=p->right;
  p2=_asn1_copy_structure3(p);
  while(p->right) p=p->right;
  _asn1_set_right(p,p2);
  temp=(char *) malloc(10);
  if(p->name==NULL) strcpy(temp,"?1");
  else{
    n=strtol(p->name+1,NULL,0);
    n++;
    temp[0]='?';
    _asn1_ltostr(n,temp+1);
  } 
  _asn1_set_name(p2,temp);
  free(temp);

  return ASN_OK;
}


int 
asn1_write_value(node_asn *node_root,char *name,unsigned char *value,int len)
{
  node_asn *node,*p,*p2;
  unsigned char *temp,*value_temp,*default_temp,val[4];
  int len2,k,k2,negative;
  unsigned char *root,*n_end;

  node=_asn1_find_node(node_root,name);
  if(node==NULL) return  ASN_ELEMENT_NOT_FOUND;

  if((node->type & CONST_OPTION) && (value==NULL) && (len==0)){
    asn1_delete_structure(node);
    return ASN_OK;
  }

  switch(type_field(node->type)){
  case TYPE_BOOLEAN:
    if(!strcmp(value,"TRUE")){
      if(node->type&CONST_DEFAULT){
	p=node->down;
	while(type_field(p->type)!=TYPE_DEFAULT) p=p->right;
	if(p->type&CONST_TRUE) _asn1_set_value(node,NULL,0);
	else _asn1_set_value(node,"T",1);
      }
      else _asn1_set_value(node,"T",1);
    }
    else if(!strcmp(value,"FALSE")){
      if(node->type&CONST_DEFAULT){
	p=node->down;
	while(type_field(p->type)!=TYPE_DEFAULT) p=p->right;
	if(p->type&CONST_FALSE) _asn1_set_value(node,NULL,0);
	else _asn1_set_value(node,"F",1);
      }
      else _asn1_set_value(node,"F",1);
    }
    else return ASN_VALUE_NOT_VALID;
    break;
  case TYPE_INTEGER: case TYPE_ENUMERATED:
    if(len==0){
      if(isdigit(value[0])){
	value_temp=(unsigned char *)malloc(4);
	_asn1_convert_integer(value,value_temp,&len);
      }
      else{ /* is an identifier like v1 */
	if(!(node->type&CONST_LIST)) return ASN_VALUE_NOT_VALID;
	p=node->down;
	while(p){
	  if(type_field(p->type)==TYPE_CONSTANT){
	    if((p->name) && (!strcmp(p->name,value))){
	      value_temp=(unsigned char *)malloc(4);
	      _asn1_convert_integer(p->value,value_temp,&len);
	      break;
	    }
	  }
	  p=p->right;
	}
	if(p==NULL) return ASN_VALUE_NOT_VALID;
      }
    }
    else{
      value_temp=(unsigned char *)malloc(len);
      memcpy(value_temp,value,len);
    }


    if(value_temp[0]&0x80) negative=1;
    else negative=0;

    if(negative && (type_field(node->type)==TYPE_ENUMERATED)) 
      {free(value_temp);return ASN_VALUE_NOT_VALID;}

    for(k=0;k<len-1;k++)
      if(negative && (value_temp[k]!=0xFF)) break;
      else if(!negative && value_temp[k]) break;

    if((negative && !(value_temp[k]&0x80)) ||
       (!negative && (value_temp[k]&0x80))) k--; 

    _asn1_length_der(len-k,NULL,&len2);
    temp=(unsigned char *)malloc(len-k+len2);
    _asn1_octet_der(value_temp+k,len-k,temp,&len2);
    _asn1_set_value(node,temp,len2);

    free(temp);

    if(node->type&CONST_DEFAULT){
      p=node->down;
      while(type_field(p->type)!=TYPE_DEFAULT) p=p->right;
      if(isdigit(p->value[0])){
	default_temp=(unsigned char *)malloc(4);
	_asn1_convert_integer(p->value,default_temp,&len2);
      }
      else{ /* is an identifier like v1 */
	if(!(node->type&CONST_LIST)) return ASN_VALUE_NOT_VALID;
	p2=node->down;
	while(p2){
	  if(type_field(p2->type)==TYPE_CONSTANT){
	    if((p2->name) && (!strcmp(p2->name,p->value))){
	      default_temp=(unsigned char *)malloc(4);
	      _asn1_convert_integer(p2->value,default_temp,&len2);
	      break;
	    }
	  }
	  p2=p2->right;
	}
	if(p2==NULL) return ASN_VALUE_NOT_VALID;
      }

      if((len-k)==len2){
	for(k2=0;k2<len2;k2++) 
	  if(value_temp[k+k2]!=default_temp[k2]){
	    break;
	  }
	if(k2==len2) _asn1_set_value(node,NULL,0);
      }
      free(default_temp);
    }
    free(value_temp);
    break;
  case TYPE_OBJECT_ID:
    for(k=0;k<strlen(value);k++)
      if((!isdigit(value[k])) && (value[k]!=' ') && (value[k]!='+')) 
	return ASN_VALUE_NOT_VALID; 
    _asn1_set_value(node,value,strlen(value)+1);
    break;
  case TYPE_TIME:
    if(node->type&CONST_UTC){
      if(strlen(value)<11) return ASN_VALUE_NOT_VALID;
      for(k=0;k<10;k++) 
	if(!isdigit(value[k])) return ASN_VALUE_NOT_VALID;
      switch(strlen(value)){
      case 11:
      if(value[10]!='Z') return ASN_VALUE_NOT_VALID;
      break;
      case 13:
	if((!isdigit(value[10])) || (!isdigit(value[11])) ||
	   (value[12]!='Z')) return ASN_VALUE_NOT_VALID;
	break;
      case 15:
	if((value[10]!='+') && (value[10]!='-')) return ASN_VALUE_NOT_VALID;
	for(k=11;k<15;k++) 
	  if(!isdigit(value[k])) return ASN_VALUE_NOT_VALID;
	break;
      case 17:
	if((!isdigit(value[10])) || (!isdigit(value[11]))) 
	   return ASN_VALUE_NOT_VALID;
	if((value[12]!='+') && (value[12]!='-')) return ASN_VALUE_NOT_VALID;
	for(k=13;k<17;k++) 
	  if(!isdigit(value[k])) return ASN_VALUE_NOT_VALID;
	break; 
      default:
	return ASN_VALUE_NOT_FOUND;
      }
      _asn1_set_value(node,value,strlen(value)+1);
    }
    else{  /* GENERALIZED TIME */
      if(value) _asn1_set_value(node,value,strlen(value)+1);
    }
    break;
  case  TYPE_OCTET_STRING:
    _asn1_length_der(len,NULL,&len2);
    temp=(unsigned char *)malloc(len+len2);
    _asn1_octet_der(value,len,temp,&len2);
    _asn1_set_value(node,temp,len2);
    free(temp);
    break;
  case  TYPE_BIT_STRING:
    _asn1_length_der((len>>3)+2,NULL,&len2);
    temp=(unsigned char *)malloc((len>>3)+2+len2);
    _asn1_bit_der(value,len,temp,&len2);
    _asn1_set_value(node,temp,len2);
    free(temp);
    break;
  case  TYPE_CHOICE:
    p=node->down;
    while(p){
      if(!strcmp(p->name,value)){
	p2=node->down;
	while(p2){
	  if(p2!=p){asn1_delete_structure(p2); p2=node->down;}
	  else p2=p2->right;
	}
	break;
      }
      p=p->right;
    }
    if(!p) return ASN_ELEMENT_NOT_FOUND;
    break;
  case TYPE_ANY:
    _asn1_length_der(len,NULL,&len2);
    temp=(unsigned char *)malloc(len+len2);
    _asn1_octet_der(value,len,temp,&len2);
    _asn1_set_value(node,temp,len2);
    free(temp);
    break;
  case TYPE_SEQUENCE_OF: case TYPE_SET_OF:
    if(strcmp(value,"NEW")) return ASN_VALUE_NOT_VALID;    
    _asn1_append_sequence_set(node);
    break;
  default:
    return  ASN_ELEMENT_NOT_FOUND;
    break;
  }

  return ASN_OK;
}


int 
asn1_read_value(node_asn *root,char *name,unsigned char *value,int *len)
{
  node_asn *node,*p;
  int len2,len3;
  unsigned long tag;
  unsigned char class;

  node=_asn1_find_node(root,name);
  if(node==NULL) return  ASN_ELEMENT_NOT_FOUND;

  if((type_field(node->type)!=TYPE_NULL) && 
     (type_field(node->type)!=TYPE_CHOICE) &&  
     !(node->type&CONST_DEFAULT) && !(node->type&CONST_ASSIGN) &&
     (node->value==NULL)) 
    return ASN_VALUE_NOT_FOUND;

  switch(type_field(node->type)){
  case TYPE_NULL:
    strcpy(value,"NULL");
    *len=strlen(value)+1;
    break;
  case TYPE_BOOLEAN:
    if((node->type&CONST_DEFAULT) && (node->value==NULL)){
      p=node->down;
      while(type_field(p->type)!=TYPE_DEFAULT) p=p->right;
      if(p->type&CONST_TRUE) strcpy(value,"TRUE");
      else strcpy(value,"FALSE");
    }
    else if(node->value[0]=='T') strcpy(value,"TRUE");
    else strcpy(value,"FALSE");
    *len=strlen(value)+1;
    break;
  case TYPE_INTEGER: case TYPE_ENUMERATED:
    if((node->type&CONST_DEFAULT) && (node->value==NULL)){
      p=node->down;
      while(type_field(p->type)!=TYPE_DEFAULT) p=p->right;
      _asn1_convert_integer(p->value,value,len);
    }
    else _asn1_get_octet_der(node->value,&len2,value,len);
    break;
  case TYPE_OBJECT_ID:
    if(node->type&CONST_ASSIGN){
      strcpy(value,"");
      p=node->down;
      while(p){
	if(type_field(p->type)==TYPE_CONSTANT){
	  strcat(value,p->value);
	  strcat(value," ");
	}
	p=p->right;
      }
      value[strlen(value)-1]=0;
    }
    else strcpy(value,node->value);

    *len=strlen(value)+1;
    break;
  case TYPE_TIME:
    strcpy(value,node->value);
    *len=strlen(value)+1;
    break;
  case TYPE_OCTET_STRING:
    _asn1_get_octet_der(node->value,&len2,value,len);
    break;
  case TYPE_BIT_STRING:
    _asn1_get_bit_der(node->value,&len2,value,len);
    break;
  case TYPE_CHOICE:
    strcpy(value,node->down->name);
    *len=strlen(value)+1;
    break; 
  case TYPE_ANY:
    len2=_asn1_get_length_der(node->value,&len3);
    memcpy(value,node->value+len3,len2);
    *len=len2;    
    break;
  default:
    return  ASN_ELEMENT_NOT_FOUND;
    break;
  }
  return ASN_OK;
}


int 
_asn1_set_default_tag(node_asn *node)
{
  node_asn *p;

  if((node==NULL) || (type_field(node->type)!=TYPE_DEFINITIONS))
    return ASN_ELEMENT_NOT_FOUND; 

  p=node;
  while(p){
    if((type_field(p->type)==TYPE_TAG) &&
	    !(p->type&CONST_EXPLICIT) &&
	    !(p->type&CONST_IMPLICIT)){
      if(node->type&CONST_EXPLICIT) p->type|=CONST_EXPLICIT;
      else p->type|=CONST_IMPLICIT;
    }

    if(p->down){
      p=p->down;
    }
    else if(p->right) p=p->right;
    else{
      while(1){
	  p=_asn1_find_up(p);
	  if(p==node){
	    p=NULL;
	    break;
	  }
	  if(p->right){
	    p=p->right;
	    break;
	  }
      }
    }
  }

  return ASN_OK;
}
    

int 
_asn1_check_identifier(node_asn *node)
{
  node_asn *p,*p2;
  char name2[129];

  if(node==NULL) return ASN_ELEMENT_NOT_FOUND;

  p=node;
  while(p){
    if(type_field(p->type)==TYPE_IDENTIFIER){
      strcpy(name2,node->name);strcat(name2,".");strcat(name2,p->value);
      p2=_asn1_find_node(node,name2);
      if(p2==NULL){printf("%s\n",name2); return ASN_IDENTIFIER_NOT_FOUND;} 
    }
    else if((type_field(p->type)==TYPE_OBJECT_ID) && 
	    (p->type&CONST_ASSIGN)){
      p2=p->down;
      if(p2 && (type_field(p2->type)==TYPE_CONSTANT)){
	if(p2->value && !isdigit(p2->value[0])){
	  strcpy(name2,node->name);strcat(name2,".");strcat(name2,p2->value);
	  p2=_asn1_find_node(node,name2);
	  if(!p2 || (type_field(p2->type)!=TYPE_OBJECT_ID) ||
	     !(p2->type&CONST_ASSIGN)) 
	    {printf("%s\n",name2); return ASN_IDENTIFIER_NOT_FOUND;}
	}
      }
    }
    
    if(p->down){
      p=p->down;
    }
    else if(p->right) p=p->right;
    else{
      while(1){
	p=_asn1_find_up(p);
	if(p==node){
	  p=NULL;
	  break;
	}
	if(p->right){
	  p=p->right;
	  break;
	}
      }
    }
  }

  return ASN_OK;
}


int 
_asn1_change_integer_value(node_asn *node)
{
  node_asn *p,*p2;
  char negative;
  unsigned char val[4],val2[5],temp;
  int len,k,force_exit;

  if(node==NULL) return ASN_ELEMENT_NOT_FOUND;

  p=node;
  while(p){
    if((type_field(p->type)==TYPE_INTEGER) && (p->type&CONST_ASSIGN)){
      if(p->value){
	_asn1_convert_integer(p->value,val,&len);	
	_asn1_octet_der(val,len,val2,&len);
	_asn1_set_value(p,val2,len);
      }
    }

    if(p->down){
      p=p->down;
    }
    else{
      if(p==node) p=NULL;
      else if(p->right) p=p->right;
      else{
	while(1){
	  p=_asn1_find_up(p);
	  if(p==node){
	    p=NULL;
	    break;
	  }
	  if(p->right){
	    p=p->right;
	    break;
	  }
	}
      }
    }
  }

  return ASN_OK;
}


int 
_asn1_delete_not_used(node_asn *node)
{
  node_asn *p,*p2;

  if(node==NULL) return ASN_ELEMENT_NOT_FOUND;

  p=node;
  while(p){
    if(p->type&CONST_NOT_USED){
      p2=NULL;
      if(p!=node){
	p2=_asn1_find_left(p);
	if(!p2) p2=_asn1_find_up(p);
      }
      asn1_delete_structure(p);
      p=p2;
    } 

    if(!p) break;  /* reach node */

    if(p->down){
      p=p->down;
    }
    else{
      if(p==node) p=NULL;
      else if(p->right) p=p->right;
      else{
	while(1){
	  p=_asn1_find_up(p);
	  if(p==node){
	    p=NULL;
	    break;
	  }
	  if(p->right){
	    p=p->right;
	    break;
	  }
	}
      }
    }
  }
  return ASN_OK;
}



int 
_asn1_expand_identifier(node_asn **node,node_asn *root)
{
  node_asn *p,*p2,*p3;
  char name2[129];
  int move;
 
  if(node==NULL) return ASN_ELEMENT_NOT_FOUND;

  p=*node;
  move=DOWN;

  while(!((p==*node) && (move==UP))){
    if(move!=UP){
      if(type_field(p->type)==TYPE_IDENTIFIER){
	strcpy(name2,root->name);strcat(name2,".");strcat(name2,p->value);
	p2=_asn1_copy_structure2(root,name2);
	if(p2==NULL) return ASN_IDENTIFIER_NOT_FOUND;
	_asn1_set_name(p2,p->name);
	p2->right=p->right;
	p2->left=p->left;
	if(p->right) p->right->left=p2;
	p3=p->down;
	if(p3){
	  while(p3->right) p3=p3->right;
	  _asn1_set_right(p3,p2->down);
	  _asn1_set_down(p2,p->down);
	}
	
	p3=_asn1_find_left(p);
	if(p3) _asn1_set_right(p3,p2);
	else{
	  p3=_asn1_find_up(p);
	  if(p3) _asn1_set_down(p3,p2);
	  else {
	    p2->left=NULL;
	  }
	}

	if(p->type & CONST_SIZE) p2->type|=CONST_SIZE;
	if(p->type & CONST_TAG) p2->type|=CONST_TAG;
	if(p->type & CONST_OPTION) p2->type|=CONST_OPTION;
	if(p->type & CONST_DEFAULT) p2->type|=CONST_DEFAULT;
	if(p->type & CONST_SET) p2->type|=CONST_SET;
	if(p->type & CONST_NOT_USED) p2->type|=CONST_NOT_USED;

	if(p==*node) *node=p2;
	_asn1_remove_node(p);
	p=p2;
	move=DOWN;
	continue;
      }
      move=DOWN;
    }
    else move=RIGHT;
    
    if(move==DOWN){
      if(p->down) p=p->down;
      else move=RIGHT;
    }
    
    if(p==*node) {move=UP; continue;}
    
    if(move==RIGHT){
      if(p->right) p=p->right;
      else move=UP;
    }
    if(move==UP) p=_asn1_find_up(p);
  }

  return ASN_OK;
}



int 
_asn1_type_choice_config(node_asn *node)
{
  node_asn *p,*p2,*p3,*p4;
  int move;
 
  if(node==NULL) return ASN_ELEMENT_NOT_FOUND;

  p=node;
  move=DOWN;

  while(!((p==node) && (move==UP))){
    if(move!=UP){
      if((type_field(p->type)==TYPE_CHOICE) &&
	 (p->type&CONST_TAG)){
	p2=p->down;
	while(p2){
	  if(type_field(p2->type)!=TYPE_TAG){
	    p2->type|=CONST_TAG;
	    p3=_asn1_find_left(p2);
	    while(p3){
	      if(type_field(p3->type)==TYPE_TAG){
		p4=_asn1_add_node(p3->type);
		_asn1_set_value(p4,p3->value,strlen(p3->value)+1);
		_asn1_set_right(p4,p2->down);
		_asn1_set_down(p2,p4);
	      }
	      p3=_asn1_find_left(p3);
	    }
	  }
	  p2=p2->right;
	}
	p->type&=~(CONST_TAG);
	p2=p->down;
	while(p2){
	  p3=p2->right;
	  if(type_field(p2->type)==TYPE_TAG) asn1_delete_structure(p2);
	  p2=p3;
	}
      }
      move=DOWN;
    }
    else move=RIGHT;
    
    if(move==DOWN){
      if(p->down) p=p->down;
      else move=RIGHT;
    }
    
    if(p==node) {move=UP; continue;}
    
    if(move==RIGHT){
      if(p->right) p=p->right;
      else move=UP;
    }
    if(move==UP) p=_asn1_find_up(p);
  }
  
  return ASN_OK;
}


int 
_asn1_type_set_config(node_asn *node)
{
  node_asn *p,*p2;
  int move;
 
  if(node==NULL) return ASN_ELEMENT_NOT_FOUND;

  p=node;
  move=DOWN;

  while(!((p==node) && (move==UP))){
    if(move!=UP){
      if(type_field(p->type)==TYPE_SET){
	p2=p->down;
	while(p2){
	  if(type_field(p2->type)!=TYPE_TAG) 
	    p2->type|=CONST_SET|CONST_NOT_USED;
	  p2=p2->right;
	}
      }
      move=DOWN;
    }
    else move=RIGHT;

    if(move==DOWN){
      if(p->down) p=p->down;
      else move=RIGHT;
    }

    if(p==node) {move=UP; continue;}

    if(move==RIGHT){
      if(p->right) p=p->right;
      else move=UP;
    }
    if(move==UP) p=_asn1_find_up(p);
  }

  return ASN_OK;
}


int 
_asn1_expand_object_id(node_asn *node)
{
  node_asn *p,*p2,*p3,*p4,*p5;
  char name_root[129],name2[129],*c;
  int move;
 
  if(node==NULL) return ASN_ELEMENT_NOT_FOUND;

  strcpy(name_root,node->name);

  p=node;
  move=DOWN;

  while(!((p==node) && (move==UP))){
    if(move!=UP){
      if((type_field(p->type)==TYPE_OBJECT_ID) && (p->type&CONST_ASSIGN)){
	p2=p->down;
        if(p2 && (type_field(p2->type)==TYPE_CONSTANT)){
	  if(p2->value && !isdigit(p2->value[0])){
	    strcpy(name2,name_root);strcat(name2,".");strcat(name2,p2->value);
	    p3=_asn1_find_node(node,name2);
	    if(!p3 || (type_field(p3->type)!=TYPE_OBJECT_ID) ||
	       !(p3->type&CONST_ASSIGN)) return ASN_ELEMENT_NOT_FOUND;
	    _asn1_set_down(p,p2->right);
	    _asn1_remove_node(p2);
	    p2=p;
	    p4=p3->down;
	    while(p4){
	      if(type_field(p4->type)==TYPE_CONSTANT){
		p5=_asn1_add_node(TYPE_CONSTANT);
		_asn1_set_name(p5,p4->name);
		_asn1_set_value(p5,p4->value,strlen(p4->value)+1);
		if(p2==p){
		  _asn1_set_right(p5,p->down);
		  _asn1_set_down(p,p5);
		}
		else{
		  _asn1_set_right(p5,p2->right);
		  _asn1_set_right(p2,p5);
		}
		p2=p5;
	      }
	      p4=p4->right;
	    }
	    move=DOWN;
	    continue;
	  }
	}
      }
      move=DOWN;
    }
    else move=RIGHT;

    if(move==DOWN){
      if(p->down) p=p->down;
      else move=RIGHT;
    }
    
    if(p==node) {move=UP; continue;}

    if(move==RIGHT){
      if(p->right) p=p->right;
      else move=UP;
    }
    if(move==UP) p=_asn1_find_up(p);
  }

  return ASN_OK;
}












