/*****************************************************/
/* File: gnutls_asn1.c                               */
/* Description: Functions to manage ASN.1 DEFINITIONS*/
/*****************************************************/

#include <gnutls_int.h>
#include <cert_asn1.h>
#include <cert_der.h>

/*****************************************/
/* Function : parser_asn1                */
/* Description: defined in fine "ASN.y"  */
/*   used to parse a file.               */
/*****************************************/
int parser_asn1(char *file_name);

node_asn *node_list=NULL; /* Pointer to the first element ot the list */

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
add_node(unsigned int type)
{
  node_asn *punt;

  if(parse_mode==PARSE_MODE_CHECK) return NULL;

  punt=(node_asn *) malloc(sizeof(node_asn));

  punt->list=node_list;
  node_list=punt;
  punt->name=NULL;
  punt->type=type; 
  punt->value=NULL;
  punt->down=NULL;
  punt->right=NULL;

  return punt;
}


node_asn *
set_value(node_asn *node,unsigned char *value,unsigned int len)
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
set_name(node_asn *node,char *name)
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
set_right(node_asn *node,node_asn *right)
{
  if(parse_mode==PARSE_MODE_CHECK) return NULL;

  if(node==NULL) return node;
  node->right=right;
  return node;
}


node_asn *
get_right(node_asn *node)
{
  if(parse_mode==PARSE_MODE_CHECK) return NULL;

  if(node==NULL) return NULL;
  return node->right;
}

node_asn *
get_last_right(node_asn *node)
{
  node_asn *p;

  if(parse_mode==PARSE_MODE_CHECK) return NULL;
  if(node==NULL) return NULL;
  p=node;
  while(p->right) p=p->right;
  return p;
}

node_asn *
set_down(node_asn *node,node_asn *down)
{
  if(parse_mode==PARSE_MODE_CHECK) return NULL;

  if(node==NULL) return node;
  node->down=down;
  return node;
}

node_asn *
get_down(node_asn *node)
{
  if(parse_mode==PARSE_MODE_CHECK) return NULL;

  if(node==NULL) return NULL;
  return node->down;
}

char *
get_name(node_asn *node)
{
  if(parse_mode==PARSE_MODE_CHECK) return NULL;

  if(node==NULL) return NULL;
  return node->name;
}

node_asn *
mod_type(node_asn *node,unsigned int value)
{
  if(parse_mode==PARSE_MODE_CHECK) return NULL;

  if(node==NULL) return node;
  node->type|=value;
  return node;
}

void
remove_node(node_asn *node)
{
  node_asn *punt,*punt_prev;

  if(node==NULL) return;

  if(node==node_list){
    punt=node_list;
    node_list=punt->list;
  }
  else{
    punt=node_list;
    while(punt && (punt!=node)){
      punt_prev=punt;
      punt=punt->list;
    }
    if(punt==NULL) return;
    punt_prev->list=punt->list;
  }
  free(punt->name);
  free(punt->value);
}

void
visit_list()
{
  node_asn *p;

  p=node_list;
  while(p){
    printf("name:");
    if(p->name) printf("%s  ",p->name);
    else printf("NULL  ");
    switch(p->type){
    case TYPE_CONSTANT:
      printf("type:CONST  value:%s\n",p->value);
      break;
    case TYPE_INTEGER:
      printf("type:INTEGER\n");
      break;
    case TYPE_SEQUENCE:
      printf("type:SEQUENCE\n");
      break;
    default:
      printf("type:ERROR\n");
      break;
    }
    p=p->list;
  }
}



node_asn *
find_node(char *name)
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
 
  p=node_list;
  while(p){
    if((p->name) && (!strcmp(p->name,n))) break;
    else p=p->list;
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
find_left(node_asn *node)
{
  node_asn *p;

  p=node_list;

  while(p){
    if(p->right==node) return p;
    p=p->list;
  }

  return NULL;
}


node_asn *
find_up(node_asn *node)
{
  node_asn *p,*p_left;

  if(node==NULL) return NULL;

  p_left=node;

  /* look for the most left element of node , result P */
  do{
    p=p_left;
    p_left=find_left(p_left);
  }while(p_left);

  /* look for the upper element of p_left */
  p_left=p;
  p=node_list;
  while(p){
    if(p->down==p_left) return p;
    p=p->list;
  }

  return NULL;
}



void
visit_tree(char *name)
{
  node_asn *p,*root;
  int k,indent=0,len,len2,len3;
  unsigned char class;
  unsigned long tag;

  root=find_node(name);   

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
	len=get_length_der(p->value,&len2);
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
	len=get_length_der(p->value,&len2);
	printf("  value(%i):",(len-1)*8-(p->value[len2]));
	for(k=1;k<len;k++) printf("%02x",(p->value)[k+len2]);
      }
      break;
    case TYPE_OCTET_STRING:
      printf("OCT_STR");
      if(p->value){
	len=get_length_der(p->value,&len2);
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
      if(p->value){
	len=get_length_der(p->value,&len2);
	printf("  value:0x");
	for(k=0;k<len;k++) printf("%02x",(p->value)[k+len2]);
      }
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
	tag=get_tag_der(p->value,&class,&len2);
	len2+=get_length_der(p->value+len2,&len3);
	printf("  value:");
	for(k=0;k<len2+len3;k++) printf("%02x",(p->value)[k]);
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
    }

    printf("\n");

    if(p->down){
      p=p->down;
      indent+=2;
    }
    else if(p->right) p=p->right;
    else{
      if(p==root){
	p=NULL;
	break;
      }
      while(1){
	p=find_up(p);
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
delete_tree2(node_asn *root)
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
	p3=find_up(p);
	p3->down=p2;
	remove_node(p);
	p=p3;
      }
      else{   /* p==root */
	p3=find_left(p);
	if(!p3){
	  p3=find_up(p);
	  if(p3) p3->down=p2;
	}
	else p3->right=p2;
	remove_node(p);
	p=NULL;
      }
    }
  }
  return ASN_OK;
}


int
delete_structure(char *root_name)
{
  node_asn *p,*p2,*p3,*root;

  root=find_node(root_name);
  if(root==NULL) return ASN_ELEMENT_NOT_FOUND;

  return delete_tree2(root);
}


#define UP     1
#define RIGHT  2
#define DOWN   3


node_asn *
copy_structure3(node_asn *source_node)
{
  node_asn *dest_node,*p_s,*p_d,*p_d_prev;
  int len,len2,move;

  if(source_node==NULL) return NULL;

  dest_node=add_node(source_node->type);
  
  p_s=source_node;
  p_d=dest_node;

  if(p_s->down==NULL) return dest_node;

  move=DOWN;

  do{
    if(move!=UP){
      if(p_s->name) set_name(p_d,p_s->name);
      if(p_s->value){
	switch(type_field(p_s->type)){
	case TYPE_OCTET_STRING: case TYPE_BIT_STRING:
	  len=get_length_der(p_s->value,&len2);
	  set_value(p_d,p_s->value,len2);
	  break;
	default:
	  set_value(p_d,p_s->value,strlen(p_s->value)+1);
	}
      }
      move=DOWN;
    }
    else move=RIGHT;

    if(move==DOWN){
      if(p_s->down){
	p_s=p_s->down;
	p_d_prev=p_d;      
	p_d=add_node(p_s->type);
	set_down(p_d_prev,p_d);
      }
      else move=RIGHT;
    }
    if(move==RIGHT){
      if(p_s->right){
	p_s=p_s->right;
	p_d_prev=p_d;
	p_d=add_node(p_s->type);
	set_right(p_d_prev,p_d);
      }
      else move=UP;
    }
    if(move==UP){
      p_s=find_up(p_s);
      p_d=find_up(p_d);
    }
  }while(p_s!=source_node);

  return dest_node;
}


node_asn *
copy_structure2(char *source_name)
{
  node_asn *source_node;

  source_node=find_node(source_name);

  return copy_structure3(source_node);
}


int
create_structure(char *dest_name,char *source_name)
{
  node_asn *dest_node;
  int res;
  char *end,n[129];

  dest_node=copy_structure2(source_name);
  if(dest_node==NULL) return ASN_ELEMENT_NOT_FOUND;
  set_name(dest_node,dest_name);

  end=strchr(source_name,'.');
  if(end){
    memcpy(n,source_name,end-source_name);
    n[end-source_name]=0;
  }
  else{
    strcpy(n,source_name);
  }

  res=expand_asn(dest_name,n);

  check_asn(dest_name,CHECK_INTEGER);
 
  return res;
}


int 
append_sequence_set(node_asn *node)
{
  node_asn *p,*p2;
  char *temp;
  long n;

  if(!node || !(node->down)) return ASN_GENERIC_ERROR;

  p=node->down;
  while((type_field(p->type)==TYPE_TAG) || (type_field(p->type)==TYPE_SIZE)) p=p->right;
  p2=copy_structure3(p);
  while(p->right) p=p->right;
  p->right=p2;
  temp=(char *) malloc(10);
  if(p->name==NULL) strcpy(temp,"?1");
  else{
    n=strtol(p->name+1,NULL,0);
    n++;
    temp[0]='?';
    ltostr(n,temp+1);
  } 
  set_name(p2,temp);
  free(temp);

  return ASN_OK;
}


int 
write_value(char *name,unsigned char *value,int len)
{
  node_asn *node,*p,*p2;
  unsigned char *temp,val[4];
  int len2,k,negative;
  unsigned char *root,*n_end;

  node=find_node(name);
  if(node==NULL) return  ASN_ELEMENT_NOT_FOUND;

  if((node->type & CONST_OPTION) && (value==NULL) && (len==0)){
    delete_structure(name);
    return ASN_OK;
  }

  switch(type_field(node->type)){
  case TYPE_BOOLEAN:
    if(!strcmp(value,"TRUE")){
      if(node->type&CONST_DEFAULT){
	p=node->down;
	while(type_field(p->type)!=TYPE_DEFAULT) p=p->right;
	if(p->type&CONST_TRUE) set_value(node,NULL,0);
	else set_value(node,"T",1);
      }
      else set_value(node,"T",1);
    }
    else if(!strcmp(value,"FALSE")){
      if(node->type&CONST_DEFAULT){
	p=node->down;
	while(type_field(p->type)!=TYPE_DEFAULT) p=p->right;
	if(p->type&CONST_FALSE) set_value(node,NULL,0);
	else set_value(node,"F",1);
      }
      else set_value(node,"F",1);
    }
    else return ASN_VALUE_NOT_VALID;
    break;
  case TYPE_INTEGER:
    if(len==0) return ASN_VALUE_NOT_VALID;

    if(value[0]&0x80) negative=1;
    else negative=0;

    for(k=0;k<len-1;k++)
      if(negative && (value[k]!=0xFF)) break;
      else if(!negative && value[k]) break;

    length_der(len-k,NULL,&len2);
    temp=(unsigned char *)malloc(len-k+len2);
    octet_der(value+k,len-k,temp,&len2);
    set_value(node,temp,len2);
    free(temp);

    if(node->type&CONST_DEFAULT){
      p=node->down;
      while(type_field(p->type)!=TYPE_DEFAULT) p=p->right;
      for(k=0;k<len2;k++) 
	if(node->value[k]!=p->value[k]){
	  break;
	}
      if(k==len2) set_value(node,NULL,0);
    }
    break;
  case TYPE_OBJECT_ID:
    for(k=0;k<strlen(value);k++)
      if((!isdigit(value[k])) && (value[k]!=' ') && (value[k]!='+')) 
	return ASN_VALUE_NOT_VALID; 
    set_value(node,value,strlen(value)+1);
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
      set_value(node,value,strlen(value)+1);
    }
    else{  /* GENERALIZED TIME */
      if(value) set_value(node,value,strlen(value)+1);
    }
    break;
  case  TYPE_OCTET_STRING:
    length_der(len,NULL,&len2);
    temp=(unsigned char *)malloc(len+len2);
    octet_der(value,len,temp,&len2);
    set_value(node,temp,len2);
    free(temp);
    break;
  case  TYPE_BIT_STRING:
    length_der((len>>3)+2,NULL,&len2);
    temp=(unsigned char *)malloc((len>>3)+2+len2);
    bit_der(value,len,temp,&len2);
    set_value(node,temp,len2);
    free(temp);
    break;
  case  TYPE_CHOICE:
    p=node->down;
    while(p){
      if(!strcmp(p->name,value)){
	p2=node->down;
	while(p2){
	  if(p2!=p) delete_tree2(p2);
	p2=p2->right;
	}
	break;
      }
      p=p->right;
    }
    if(!p) return ASN_ELEMENT_NOT_FOUND;

    n_end=strchr(value,'.');
    if(n_end){
      root=(char *)malloc(n_end-value+1);
      memcpy(root,value,n_end-value);
      root[n_end-value]=0;
      expand_asn(name,root);
      free(root);
    }
    break;
  case TYPE_ANY:
    p=copy_structure2(value);
    if(p==NULL) return ASN_VALUE_NOT_VALID;
    set_name(p,node->name);
    set_right(p,node->right);
    p2=node->down;
    if(p2){
      while(p2->right) p2=p2->right;
      p2->right=p->down;
      p->down=node->down;
    }
    p2=find_left(node);
    if(p2) p2->right=p;
    else{
      p2=find_up(node);
      p2->down=p;
    }
    if(node->type & CONST_TAG) p->type|=CONST_TAG;
    if(node->type & CONST_OPTION) p->type|=CONST_OPTION;    
    remove_node(node);

    n_end=strchr(value,'.');
    if(n_end){
      root=(char *)malloc(n_end-value+1);
      memcpy(root,value,n_end-value);
      root[n_end-value]=0;
      expand_asn(name,root);
      free(root);
    }
    break;
  case TYPE_SEQUENCE_OF: case TYPE_SET_OF:
    if(strcmp(value,"NEW")) return ASN_VALUE_NOT_VALID;    
    append_sequence_set(node);
    break;
  default:
    return  ASN_ELEMENT_NOT_FOUND;
    break;
  }

  return ASN_OK;
}


int 
read_value(char *name,unsigned char *value,int *len)
{
  node_asn *node,*p;
  int len2,len3;
  unsigned long tag;
  unsigned char class;

  node=find_node(name);
  if(node==NULL) return  ASN_ELEMENT_NOT_FOUND;

  if((type_field(node->type)!=TYPE_NULL) && 
     (type_field(node->type)!=TYPE_CHOICE) &&  
     !(node->type&CONST_DEFAULT) && (node->value==NULL)) 
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
  case TYPE_INTEGER:
    if((node->type&CONST_DEFAULT) && (node->value==NULL)){
      p=node->down;
      while(type_field(p->type)!=TYPE_DEFAULT) p=p->right;
      get_octet_der(p->value,&len2,value,len);
    }
    else get_octet_der(node->value,&len2,value,len);
    break;
  case TYPE_OBJECT_ID:
    strcpy(value,node->value);
    *len=strlen(value)+1;
    break;
  case TYPE_TIME:
    strcpy(value,node->value);
    *len=strlen(value)+1;
    break;
  case TYPE_OCTET_STRING:
    get_octet_der(node->value,&len2,value,len);
    break;
  case TYPE_BIT_STRING:
    get_bit_der(node->value,&len2,value,len);
    break;
  case TYPE_CHOICE:
    strcpy(value,node->down->name);
    *len=strlen(value)+1;
    break;
  case TYPE_ANY:
    tag=get_tag_der(node->value,&class,&len2);
    len2+=get_length_der((node->value)+len2,&len3);
    memcpy(value,node->value,len3+len2);
    *len=len3+len2;    
    break;
  default:
    return  ASN_ELEMENT_NOT_FOUND;
    break;
  }
  return ASN_OK;
}


int 
check_asn(char *name,int check)
{
  node_asn *node,*p,*p2;
  char name2[129],negative;
  unsigned char val[4],val2[5],temp;
  int k,len;

  node=find_node(name);
  if(node==NULL) return ASN_ELEMENT_NOT_FOUND;

  p=node;
  while(p){

    switch(check){
    case CHECK_TYPE:
      if(type_field(p->type)==TYPE_IDENTIFIER){
        strcpy(name2,name);strcat(name2,".");strcat(name2,p->value);
        p2=find_node(name2);
        if(p2==NULL) return ASN_IDENTIFIER_NOT_FOUND; 
      }
      break;
    case CHECK_NOT_USED:
      if(p->type&CONST_NOT_USED){
	p2=NULL;
	if(p!=node){
	  p2=find_left(p);
	  if(!p2) p2=find_up(p);
	}
	delete_tree2(p);
	p=p2;
      } 
      break;
    case CHECK_DEFAULT_TAG_TYPE:
      if(type_field(p->type)==TYPE_DEFINITIONS) p2=p;
      else if((type_field(p->type)==TYPE_TAG) &&
	      !(p->type&CONST_EXPLICIT) &&
	      !(p->type&CONST_IMPLICIT)){
	if(p2->type&CONST_EXPLICIT) p->type|=CONST_EXPLICIT;
	else p->type|=CONST_IMPLICIT;
      }
      break;
    case CHECK_INTEGER:
      if(type_field(p->type)==TYPE_INTEGER){
	if(p->type&CONST_DEFAULT){
	  p=p->down;
	  while(type_field(p->type)!=TYPE_DEFAULT) p=p->right;
	}
	if(p->value){
	  *((long*)val)=strtol(p->value,NULL,10);
	  for(k=0;k<2;k++){
	    temp=val[k];
	    val[k]=val[3-k];
	    val[3-k]=temp;
	  }
  
	  if(val[0]&0x80) negative=1;
	  else negative=0;

	  for(k=0;k<3;k++)
	    if(negative && (val[k]!=0xFF)) break;
	    else if(!negative && val[k]) break;

	  length_der(4-k,NULL,&len);
	  octet_der(val+k,4-k,val2,&len);
	  set_value(p,val2,len);
	}
      }
    default:
      break;
    }

    if(!p) break;  /* reach node */

    if(p->down){
      p=p->down;
    }
    else if(p->right) p=p->right;
    else{
      while(1){
	  p=find_up(p);
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
expand_asn(char *name,char *root)
{
  node_asn *node,*p,*p2,*p3,*p4;
  char name_root[129],name2[129],*c;
  int move;

  node=find_node(name);
  if(node==NULL) return ASN_ELEMENT_NOT_FOUND;

  strcpy(name_root,root);

  p=node;
  move=DOWN;

  while(!((p==node) && (move==UP))){
    if(move!=UP){
      if(type_field(p->type)==TYPE_IDENTIFIER){
	strcpy(name2,name_root);strcat(name2,".");strcat(name2,p->value);
	p2=copy_structure2(name2);
	if(p2==NULL) return ASN_IDENTIFIER_NOT_FOUND; 
	set_name(p2,p->name);
	set_right(p2,p->right);
	p3=p->down;
	
	if(p3){
	  while(p3->right) p3=p3->right;
	  p3->right=p2->down;
	  p2->down=p->down;
	}
	
	p3=find_left(p);
	if(p3) p3->right=p2;
	else{
	  p3=find_up(p);
	  p3->down=p2;
	}

	if(p->type & CONST_SIZE) p2->type|=CONST_SIZE;
	if(p->type & CONST_TAG) p2->type|=CONST_TAG;
	if(p->type & CONST_OPTION) p2->type|=CONST_OPTION;
	if(p->type & CONST_DEFAULT) p2->type|=CONST_DEFAULT;
	if(p->type & CONST_SET) p2->type|=CONST_SET;
	if(p->type & CONST_NOT_USED) p2->type|=CONST_NOT_USED;

	if(p==node) node=p2;
	remove_node(p);
	p=p2;
	move=DOWN;
	continue;
      }
      else if((type_field(p->type)==TYPE_CHOICE) &&
	      (p->type&CONST_TAG)){
	p2=p->down;
	while(p2){
	  if(type_field(p2->type)!=TYPE_TAG){
	    p2->type|=CONST_TAG;
	    p3=find_left(p2);
	    while(p3){
	      if(type_field(p3->type)==TYPE_TAG){
		p4=add_node(p3->type);
		set_value(p4,p3->value,strlen(p3->value)+1);
		p4->right=p2->down;
		p2->down=p4;
	      }
	      p3=find_left(p3);
	    }
	  }
	  p2=p2->right;
	}
	p->type&=~(CONST_TAG);
	p2=p->down;
	while(p2){
	  p3=p2->right;
	  if(type_field(p2->type)==TYPE_TAG) delete_tree2(p2);
	  p2=p3;
	}
	move=DOWN;
      }
      else if(type_field(p->type)==TYPE_SET){
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
    if(move==UP) p=find_up(p);
  }

  return ASN_OK;
}


