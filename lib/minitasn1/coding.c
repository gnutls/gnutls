/*
 *      Copyright (C) 2002  Fabio Fiorina
 *
 * This file is part of LIBASN1.
 *
 * The LIBTASN1 library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public   
 * License as published by the Free Software Foundation; either 
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */


/*****************************************************/
/* File: coding.c                                    */
/* Description: Functions to create a DER coding of  */
/*   an ASN1 type.                                   */
/*****************************************************/
 
#include <int.h>
#include <errors.h>
#include "der.h"
#include "parser_aux.h"
#include <gstr.h>
#include "element.h"

/******************************************************/
/* Function : _asn1_error_description_value_not_found */
/* Description: creates the ErrorDescription string   */
/* for the ASN1_VALUE_NOT_FOUND error.                */
/* Parameters:                                        */
/*   node: node of the tree where the value is NULL.  */
/*   ErrorDescription: string returned.               */
/* Return:                                            */
/******************************************************/
void
_asn1_error_description_value_not_found(node_asn *node,char *ErrorDescription)
{

  if (ErrorDescription == NULL) return;

  Estrcpy(ErrorDescription,":: value of element '");
  _asn1_hierarchical_name(node,ErrorDescription+strlen(ErrorDescription),
			  MAX_ERROR_DESCRIPTION_SIZE-40);
  Estrcat(ErrorDescription,"' not found");

}

/******************************************************/
/* Function : _asn1_length_der                        */
/* Description: creates the DER coding for the LEN    */
/* parameter (only the length).                       */
/* Parameters:                                        */
/*   len: value to convert.                           */
/*   ans: string returned.                            */
/*   ans_len: number of meanful bytes of ANS          */
/*            (ans[0]..ans[ans_len-1]).               */
/* Return:                                            */
/******************************************************/
void
_asn1_length_der(unsigned long len,unsigned char *ans,int *ans_len)
{
  int k;
  unsigned char temp[SIZEOF_UNSIGNED_LONG_INT];

  if(len<128){
    /* short form */
    if(ans!=NULL) ans[0]=(unsigned char)len;
    *ans_len=1;
  }
  else{
    /* Long form */
    k=0;
    while(len){
      temp[k++]=len&0xFF;
      len=len>>8;
    }
    *ans_len=k+1;
    if(ans!=NULL){
      ans[0]=((unsigned char)k&0x7F)+128;
      while(k--) ans[*ans_len-1-k]=temp[k];  
    }
  }
}

/******************************************************/
/* Function : _asn1_tag_der                           */
/* Description: creates the DER coding for the CLASS  */
/* and TAG parameters.                                */
/* Parameters:                                        */
/*   class: value to convert.                         */
/*   tag_value: value to convert.                     */
/*   ans: string returned.                            */
/*   ans_len: number of meanful bytes of ANS          */
/*            (ans[0]..ans[ans_len-1]).               */
/* Return:                                            */
/******************************************************/
void
_asn1_tag_der(unsigned char class,unsigned int tag_value,unsigned char *ans,int *ans_len)
{
  int k;
  unsigned char temp[SIZEOF_UNSIGNED_INT];

  if(tag_value<30){
    /* short form */
    ans[0]=(class&0xE0) + ((unsigned char)(tag_value&0x1F));
    *ans_len=1;
  }
  else{
    /* Long form */
    ans[0]=(class&0xE0) + 31;
    k=0;
    while(tag_value){
      temp[k++]=tag_value&0x7F;
      tag_value=tag_value>>7;
    }
    *ans_len=k+1;
    while(k--) ans[*ans_len-1-k]=temp[k]+128;
    ans[*ans_len-1]-=128;  
  }
}

/******************************************************/
/* Function : _asn1_octect_der                        */
/* Description: creates the DER coding for an         */
/* OCTET type (length included).                      */
/* Parameters:                                        */
/*   str: OCTET string.                               */
/*   str_len: STR length (str[0]..str[str_len-1]).    */
/*   der: string returned.                            */
/*   der_len: number of meanful bytes of DER          */
/*            (der[0]..der[ans_len-1]).               */
/* Return:                                            */
/******************************************************/
void
_asn1_octet_der(const unsigned char *str,int str_len,unsigned char *der,int *der_len)
{
  int len_len;

  if(der==NULL) return;
  _asn1_length_der(str_len,der,&len_len);
  memcpy(der+len_len,str,str_len);
  *der_len=str_len+len_len;
}

/******************************************************/
/* Function : _asn1_time_der                          */
/* Description: creates the DER coding for a TIME     */
/* type (length included).                            */
/* Parameters:                                        */
/*   str: TIME null-terminated string.                */
/*   der: string returned.                            */
/*   der_len: number of meanful bytes of DER          */
/*            (der[0]..der[ans_len-1]).               */
/* Return:                                            */
/******************************************************/
void
_asn1_time_der(unsigned char *str,unsigned char *der,int *der_len)
{
  int len_len;

  if(der==NULL) return;
  _asn1_length_der(strlen(str),der,&len_len);
  memcpy(der+len_len,str,strlen(str));
  *der_len=len_len+strlen(str);
}


/*
void
_asn1_get_utctime_der(unsigned char *der,int *der_len,unsigned char *str)
{
  int len_len,str_len;
  char temp[20];

  if(str==NULL) return;
  str_len=_asn1_get_length_der(der,&len_len);
  memcpy(temp,der+len_len,str_len);
  *der_len=str_len+len_len;
  switch(str_len){
  case 11:
    temp[10]=0;
    strcat(temp,"00+0000");
    break;
  case 13:
    temp[12]=0;
    strcat(temp,"+0000");
    break;
  case 15:
    temp[15]=0;
    memmove(temp+12,temp+10,6);
    temp[10]=temp[11]='0';
    break;
  case 17:
    temp[17]=0;
    break;
  default:
    return;
  }
  strcpy(str,temp);
}
*/

/******************************************************/
/* Function : _asn1_objectid_der                      */
/* Description: creates the DER coding for an         */
/* OBJECT IDENTIFIER  type (length included).         */
/* Parameters:                                        */
/*   str: OBJECT IDENTIFIER null-terminated string.   */
/*   der: string returned.                            */
/*   der_len: number of meanful bytes of DER          */
/*            (der[0]..der[ans_len-1]).               */
/* Return:                                            */
/******************************************************/
void
_asn1_objectid_der(unsigned char *str,unsigned char *der,int *der_len)
{
  int len_len,counter,k,first;
  char *temp,*n_end,*n_start;
  unsigned char bit7;
  unsigned long val,val1=0;

  if(der==NULL) return;

  temp=(char *) malloc(strlen(str)+2);

  strcpy(temp, str);
  strcat(temp, ".");

  counter=0;
  n_start=temp;
  while((n_end=strchr(n_start,'.'))){
    *n_end=0;
    val=strtoul(n_start,NULL,10);
    counter++;

    if(counter==1) val1=val;
    else if(counter==2){
      der[0]=40*val1+val;
      *der_len=1;
    }
    else{
      first=0;
      for(k=4;k>=0;k--){
	bit7=(val>>(k*7))&0x7F;
	if(bit7 || first || !k){
	  if(k) bit7|=0x80;
	  der[*der_len]=bit7;
	  (*der_len)++;
	  first=1;
	}
      }

    }
    n_start=n_end+1;
  }

  _asn1_length_der(*der_len,NULL,&len_len);
  memmove(der+len_len,der,*der_len);
  _asn1_length_der(*der_len,der,&len_len);
  *der_len+=len_len;

  free(temp);
}


char bit_mask[]={0xFF,0xFE,0xFC,0xF8,0xF0,0xE0,0xC0,0x80};

/******************************************************/
/* Function : _asn1_bit_der                           */
/* Description: creates the DER coding for a BIT      */
/* STRING  type (length and pad included).            */
/* Parameters:                                        */
/*   str: BIT string.                                 */
/*   bit_len: number of meanful bits in STR.          */
/*   der: string returned.                            */
/*   der_len: number of meanful bytes of DER          */
/*            (der[0]..der[ans_len-1]).               */
/* Return:                                            */
/******************************************************/
void
_asn1_bit_der(const unsigned char *str,int bit_len,unsigned char *der,int *der_len)
{
  int len_len,len_byte,len_pad;

  if(der==NULL) return;
  len_byte=bit_len>>3;
  len_pad=8-(bit_len&7);
  if(len_pad==8) len_pad=0;
  else len_byte++;
  _asn1_length_der(len_byte+1,der,&len_len);
  der[len_len]=len_pad;
  memcpy(der+len_len+1,str,len_byte);
  der[len_len+len_byte]&=bit_mask[len_pad];
  *der_len=len_byte+len_len+1;
}


/******************************************************/
/* Function : _asn1_complete_explicit_tag             */
/* Description: add the length coding to the EXPLICIT */
/* tags.                                              */
/* Parameters:                                        */
/*   node: pointer to the tree element.               */
/*   der: string with the DER coding of the whole tree*/
/*   counter: number of meanful bytes of DER          */
/*            (der[0]..der[*counter-1]).              */
/* Return:                                            */
/******************************************************/
void
_asn1_complete_explicit_tag(node_asn *node,unsigned char *der,int *counter)
{
  node_asn *p;
  int is_tag_implicit,len2,len3;
  unsigned char temp[SIZEOF_UNSIGNED_INT];
  
  is_tag_implicit=0;

  if(node->type&CONST_TAG){
    p=node->down;
    /* When there are nested tags we must complete them reverse to
       the order they were created. This is because completing a tag
       modifies alla date within it, including the incomplete tags 
       which store buffer positions -- simon@josefsson.org 2002-09-06
    */
    while(p->right)
      p=p->right;
    while(p && p!=node->down->left){
      if(type_field(p->type)==TYPE_TAG){
	if(p->type&CONST_EXPLICIT){
	  len2=strtol(p->name,NULL,10);
	  _asn1_set_name(p,NULL);
	  _asn1_length_der(*counter-len2,temp,&len3);
	  memmove(der+len2+len3,der+len2,*counter-len2);
	  memcpy(der+len2,temp,len3);
	  *counter+=len3;	  
	  is_tag_implicit=0;
	}
	else{  /* CONST_IMPLICIT */
	  if(!is_tag_implicit){
	    is_tag_implicit=1;
	  }
	}
      }
      p=p->left;
    }
  }
}


/******************************************************/
/* Function : _asn1_insert_tag_der                    */
/* Description: creates the DER coding of tags of one */
/* NODE.                                              */
/* Parameters:                                        */
/*   node: pointer to the tree element.               */
/*   der: string returned                             */
/*   counter: number of meanful bytes of DER          */
/*            (counter[0]..der[*counter-1]).          */
/* Return:                                            */
/*   ASN1_GENERIC_ERROR if the type is unknown,       */
/*   otherwise ASN1_SUCCESS.                          */
/******************************************************/
int
_asn1_insert_tag_der(node_asn *node,unsigned char *der,int *counter)
{
  node_asn *p;
  int tag_len,is_tag_implicit;
  unsigned char class,class_implicit=0,temp[SIZEOF_UNSIGNED_INT*3+1];
  unsigned long tag_implicit=0;
   
  is_tag_implicit=0;

  if(node->type&CONST_TAG){
    p=node->down;
    while(p){
      if(type_field(p->type)==TYPE_TAG){
	if(p->type&CONST_APPLICATION) class=APPLICATION;
	else if(p->type&CONST_UNIVERSAL) class=UNIVERSAL;
	else if(p->type&CONST_PRIVATE) class=PRIVATE;
	else class=CONTEXT_SPECIFIC;
	
	if(p->type&CONST_EXPLICIT){
	  if(is_tag_implicit)
	    _asn1_tag_der(class_implicit,tag_implicit,der+*counter,&tag_len);
	  else
	    _asn1_tag_der(class|STRUCTURED,strtoul(p->value,NULL,10),der+*counter,&tag_len);
	  *counter+=tag_len;
	  _asn1_ltostr(*counter,temp);
	  _asn1_set_name(p,temp);

	  is_tag_implicit=0;
	}
	else{  /* CONST_IMPLICIT */
	  if(!is_tag_implicit){
	    if((type_field(node->type)==TYPE_SEQUENCE) || 
	       (type_field(node->type)==TYPE_SEQUENCE_OF) ||
	       (type_field(node->type)==TYPE_SET) ||
	       (type_field(node->type)==TYPE_SET_OF)) class|=STRUCTURED;
	    class_implicit=class;
	    tag_implicit=strtoul(p->value,NULL,10);
	    is_tag_implicit=1;
	  }
	}
      }
      p=p->right;
    }
  }
  
  if(is_tag_implicit){
    _asn1_tag_der(class_implicit,tag_implicit,der+*counter,&tag_len);
  }
  else{
    switch(type_field(node->type)){
    case TYPE_NULL:
      _asn1_tag_der(UNIVERSAL,TAG_NULL,der+*counter,&tag_len);
      break;
    case TYPE_BOOLEAN:
      _asn1_tag_der(UNIVERSAL,TAG_BOOLEAN,der+*counter,&tag_len);
      break;
    case TYPE_INTEGER:
      _asn1_tag_der(UNIVERSAL,TAG_INTEGER,der+*counter,&tag_len);
      break;
    case TYPE_ENUMERATED:
      _asn1_tag_der(UNIVERSAL,TAG_ENUMERATED,der+*counter,&tag_len);
      break;
    case TYPE_OBJECT_ID:
      _asn1_tag_der(UNIVERSAL,TAG_OBJECT_ID,der+*counter,&tag_len);
      break;
    case TYPE_TIME:
      if(node->type&CONST_UTC){
	_asn1_tag_der(UNIVERSAL,TAG_UTCTime,der+*counter,&tag_len);
      }
      else _asn1_tag_der(UNIVERSAL,TAG_GENERALIZEDTime,der+*counter,&tag_len);
      break;
    case TYPE_OCTET_STRING:
      _asn1_tag_der(UNIVERSAL,TAG_OCTET_STRING,der+*counter,&tag_len);
      break;
    case TYPE_GENERALSTRING:
      _asn1_tag_der(UNIVERSAL,TAG_GENERALSTRING,der+*counter,&tag_len);
      break;
    case TYPE_BIT_STRING:
      _asn1_tag_der(UNIVERSAL,TAG_BIT_STRING,der+*counter,&tag_len);
      break;
    case TYPE_SEQUENCE: case TYPE_SEQUENCE_OF:
      _asn1_tag_der(UNIVERSAL|STRUCTURED,TAG_SEQUENCE,der+*counter,&tag_len);
      break;
    case TYPE_SET: case TYPE_SET_OF:
      _asn1_tag_der(UNIVERSAL|STRUCTURED,TAG_SET,der+*counter,&tag_len);
      break;
    case TYPE_TAG:
      tag_len=0;
      break;
    case TYPE_CHOICE:
      tag_len=0;
      break;
    case TYPE_ANY:
      tag_len=0;
      break;
    default:
      return ASN1_GENERIC_ERROR;
    }
  }
  
  *counter+=tag_len;

  return ASN1_SUCCESS;
}

/******************************************************/
/* Function : _asn1_ordering_set                      */
/* Description: puts the elements of a SET type in    */
/* the correct order according to DER rules.          */
/* Parameters:                                        */
/*   der: string with the DER coding.                 */
/*   node: pointer to the SET element.                */
/* Return:                                            */
/******************************************************/
void
_asn1_ordering_set(unsigned char *der,node_asn *node)
{
  struct vet{
    int end;
    unsigned long value;
    struct vet *next,*prev;
  };

  int counter,len,len2;
  struct vet *first,*last,*p_vet,*p2_vet;
  node_asn *p;
  unsigned char class,*temp;
  unsigned long tag;

  counter=0;

  if(type_field(node->type)!=TYPE_SET) return;

  p=node->down;
  while((type_field(p->type)==TYPE_TAG)  || (type_field(p->type)==TYPE_SIZE)) p=p->right;

  if((p==NULL) || (p->right==NULL)) return;

  first=last=NULL;
  while(p){
    p_vet=(struct vet *)_asn1_alloca( sizeof(struct vet));
    if (p_vet==NULL) return;
    
    p_vet->next=NULL;
    p_vet->prev=last;
    if(first==NULL) first=p_vet;
    else last->next=p_vet;
    last=p_vet;

    /* tag value calculation */
    tag=_asn1_get_tag_der(der+counter,&class,&len2);
    p_vet->value=(class<<24)|tag;
    counter+=len2;

    /* extraction  and length */
    len2=_asn1_get_length_der(der+counter,&len);
    counter+=len+len2;

    p_vet->end=counter;
    p=p->right;
  }

  p_vet=first;

  while(p_vet){
    p2_vet=p_vet->next;
    counter=0;
    while(p2_vet){
      if(p_vet->value>p2_vet->value){
	/* change position */
	temp=(unsigned char *)_asn1_alloca( p_vet->end-counter);
	if (temp==NULL) return;
	
	memcpy(temp,der+counter,p_vet->end-counter);
	memmove(der+counter,der+p_vet->end,p2_vet->end-p_vet->end);
	memcpy(der+p_vet->end,temp,p_vet->end-counter);
	_asn1_afree(temp);
	
	tag=p_vet->value;
	p_vet->value=p2_vet->value;
	p2_vet->value=tag;
	
	p_vet->end=counter+(p2_vet->end-p_vet->end);
      }
      counter=p_vet->end;
      
      p2_vet=p2_vet->next;
      p_vet=p_vet->next;
    }

    if(p_vet!=first) p_vet->prev->next=NULL;
    else first=NULL;
    _asn1_afree(p_vet);
    p_vet=first;
  }
}

/******************************************************/
/* Function : _asn1_ordering_set_of                   */
/* Description: puts the elements of a SET OF type in */
/* the correct order according to DER rules.          */
/* Parameters:                                        */
/*   der: string with the DER coding.                 */
/*   node: pointer to the SET OF element.             */
/* Return:                                            */
/******************************************************/
void
_asn1_ordering_set_of(unsigned char *der,node_asn *node)
{
  struct vet{
    int end;
    struct vet *next,*prev;
  };

  int counter,len,len2,change;
  struct vet *first,*last,*p_vet,*p2_vet;
  node_asn *p;
  unsigned char *temp,class;
  unsigned long k,max;

  counter=0;

  if(type_field(node->type)!=TYPE_SET_OF) return;

  p=node->down;
  while((type_field(p->type)==TYPE_TAG) || (type_field(p->type)==TYPE_SIZE)) p=p->right;
  p=p->right;

  if((p==NULL) || (p->right==NULL)) return;

  first=last=NULL;
  while(p){
    p_vet=(struct vet *)_asn1_alloca(sizeof(struct vet));
    if (p_vet==NULL) return;
    
    p_vet->next=NULL;
    p_vet->prev=last;
    if(first==NULL) first=p_vet;
    else last->next=p_vet;
    last=p_vet;

    /* extraction of tag and length */
    _asn1_get_tag_der(der+counter,&class,&len);
    counter+=len;
    len2=_asn1_get_length_der(der+counter,&len);
    counter+=len+len2;

    p_vet->end=counter;
    p=p->right;
  }

  p_vet=first;

  while(p_vet){
    p2_vet=p_vet->next;
    counter=0;
    while(p2_vet){
      if((p_vet->end-counter)>(p2_vet->end-p_vet->end))
	max=p_vet->end-counter;
      else
	max=p2_vet->end-p_vet->end;

      change=-1;
      for(k=0;k<max;k++) 
	if(der[counter+k]>der[p_vet->end+k]){change=1;break;}
	else if(der[counter+k]<der[p_vet->end+k]){change=0;break;}

      if((change==-1) && ((p_vet->end-counter)>(p2_vet->end-p_vet->end)))
	change=1;

      if(change==1){
	/* change position */
	temp=(unsigned char *)_asn1_alloca(p_vet->end-counter);
	if (temp==NULL) return;
	
	memcpy(temp,der+counter,p_vet->end-counter);
	memmove(der+counter,der+p_vet->end,p2_vet->end-p_vet->end);
	memcpy(der+p_vet->end,temp,p_vet->end-counter);
	_asn1_afree(temp);
	
	p_vet->end=counter+(p2_vet->end-p_vet->end);
      }
      counter=p_vet->end;
      
      p2_vet=p2_vet->next;
      p_vet=p_vet->next;
    }

    if(p_vet!=first) p_vet->prev->next=NULL;
    else first=NULL;
    _asn1_afree(p_vet);
    p_vet=first;
  }
}

/**
  * asn1_der_coding - Creates the DER encoding for the NAME structure
  * @element: pointer to an ASN1 element
  * @name: the name of the structure you want to encode (it must be inside *POINTER).
  * @der: vector that will contain the DER encoding. DER must be a pointer to memory cells already allocated.
  * @len: number of bytes of *der: der[0]..der[len-1]
  * @errorDescription : return the error description or an empty string if success.
  * Description:
  *
  * Creates the DER encoding for the NAME structure (inside *POINTER structure).
  * 
  * Returns:
  *
  *   ASN1_SUCCESS\: DER encoding OK
  *
  *   ASN1_ELEMENT_NOT_FOUND\: NAME is not a valid element.
  *
  *   ASN1_VALUE_NOT_FOUND\: there is an element without a value.
  **/
asn1_retCode 
asn1_der_coding(ASN1_TYPE element,const char *name,unsigned char *der,int *len,
                char *ErrorDescription)
{
  node_asn *node,*p;
  char temp[SIZEOF_UNSIGNED_LONG_INT*3+1];
  int counter,counter_old,len2,len3,move,ris;

  node=_asn1_find_node(element,name);
  if(node==NULL) return ASN1_ELEMENT_NOT_FOUND;

  counter=0;
  move=DOWN;
  p=node;
  while(1){
    
    counter_old=counter;
    if(move!=UP) ris=_asn1_insert_tag_der(p,der,&counter);

    switch(type_field(p->type)){
    case TYPE_NULL:
      der[counter]=0;
      counter++;
      move=RIGHT;
      break;
    case TYPE_BOOLEAN:
      if((p->type&CONST_DEFAULT) && (p->value==NULL)) counter=counter_old;
      else{
	der[counter++]=1;
	if(p->value[0]=='F') der[counter++]=0;
	else der[counter++]=0xFF;
      }
      move=RIGHT;
      break;
    case TYPE_INTEGER: case TYPE_ENUMERATED:
      if((p->type&CONST_DEFAULT) && (p->value==NULL)) counter=counter_old;
      else{
	if(p->value==NULL){
	  _asn1_error_description_value_not_found(p,ErrorDescription);
	  return ASN1_VALUE_NOT_FOUND;
	}
	len2=_asn1_get_length_der(p->value,&len3);
	memcpy(der+counter,p->value,len3+len2);
	counter+=len3+len2;
      }
      move=RIGHT;
      break;
    case TYPE_OBJECT_ID:
      _asn1_objectid_der(p->value,der+counter,&len2);
      counter+=len2;
      move=RIGHT;
      break;
    case TYPE_TIME:
      _asn1_time_der(p->value,der+counter,&len2);
      counter+=len2;
      move=RIGHT;
      break;
    case TYPE_OCTET_STRING:
      len2=_asn1_get_length_der(p->value,&len3);
      memcpy(der+counter,p->value,len3+len2);
      counter+=len3+len2;
      move=RIGHT;
      break;
    case TYPE_GENERALSTRING:
      len2=_asn1_get_length_der(p->value,&len3);
      memcpy(der+counter,p->value,len3+len2);
      counter+=len3+len2;
      move=RIGHT;
      break;
    case TYPE_BIT_STRING:
      len2=_asn1_get_length_der(p->value,&len3);
      memcpy(der+counter,p->value,len3+len2);
      counter+=len3+len2;
      move=RIGHT;
      break;
    case TYPE_SEQUENCE: case TYPE_SET: 
      if(move!=UP){
	_asn1_ltostr(counter,temp);
	_asn1_set_value(p,temp,strlen(temp)+1);
	move=DOWN;
      }
      else{   /* move==UP */
	len2=strtol(p->value,NULL,10);
	_asn1_set_value(p,NULL,0);
	if(type_field(p->type)==TYPE_SET) _asn1_ordering_set(der+len2,p);
	_asn1_length_der(counter-len2,temp,&len3);
	memmove(der+len2+len3,der+len2,counter-len2);
	memcpy(der+len2,temp,len3);
	counter+=len3;
	move=RIGHT;
      }
      break;
    case TYPE_SEQUENCE_OF: case TYPE_SET_OF: 
      if(move!=UP){
	_asn1_ltostr(counter,temp);
	_asn1_set_value(p,temp,strlen(temp)+1);
	p=p->down;
	while((type_field(p->type)==TYPE_TAG) || (type_field(p->type)==TYPE_SIZE)) p=p->right;
	if(p->right){
	  p=p->right;
	  move=RIGHT;
	  continue;
	}
	else p=_asn1_find_up(p);
	move=UP;
      }
      if(move==UP){
	len2=strtol(p->value,NULL,10);
	_asn1_set_value(p,NULL,0);
	if(type_field(p->type)==TYPE_SET_OF) _asn1_ordering_set_of(der+len2,p);
	_asn1_length_der(counter-len2,temp,&len3);
	memmove(der+len2+len3,der+len2,counter-len2);
	memcpy(der+len2,temp,len3);
	counter+=len3;
	move=RIGHT;
      }
      break;
    case TYPE_ANY:
      len2=_asn1_get_length_der(p->value,&len3);
      memcpy(der+counter,p->value+len3,len2);
      counter+=len2;
      move=RIGHT;
      break;
    default:
       move=(move==UP)?RIGHT:DOWN;
      break;
    }

    if((move!=DOWN) && (counter!=counter_old))
      _asn1_complete_explicit_tag(p,der,&counter);

    if(p==node && move!=DOWN) break;

    if(move==DOWN){
      if(p->down) p=p->down;
      else move=RIGHT;
    }
    if(move==RIGHT){
      if(p->right) p=p->right;
      else move=UP;
    }
   if(move==UP) p=_asn1_find_up(p);
  }

  *len=counter;
  return ASN1_SUCCESS;
}















