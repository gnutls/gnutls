/*****************************************************/
/* File: gnutls_der.c                                */
/* Description: Functions to manage DER encoding     */
/*****************************************************/

#include <defines.h>
#include <gnutls_int.h>
#include <cert_der.h>
#include <cert_asn1.h>

#define TAG_BOOLEAN          0x01
#define TAG_INTEGER          0x02
#define TAG_SEQUENCE         0x10
#define TAG_SET              0x11
#define TAG_OCTET_STRING     0x04
#define TAG_BIT_STRING       0x03
#define TAG_UTCTime          0x17
#define TAG_GENERALIZEDTime  0x18
#define TAG_OBJECT_ID        0x06
#define TAG_NULL             0x05


char *
ltostr(long v,char *str)
{
  long d,r,v2;
  char temp[20];
  int count,k,start;

  if(v<0){
    str[0]='-';
    start=1;
    v=-v;
  }
  else start=0;

  count=0;
  do{
    d=v/10;
    r=v-d*10;
    temp[start+count]='0'+(char)r;
    count++;
    v=d;
  }while(v);

  for(k=0;k<count;k++) str[k+start]=temp[start+count-k-1];
  str[count+start]=0;
  return str;
}


void
length_der(unsigned long len,unsigned char *ans,int *ans_len)
{
  int k;
  unsigned char temp[128];

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

 
unsigned long
get_length_der(unsigned char *der,int  *len)
{
  unsigned long ans;
  int k,punt;

  if(!(der[0]&128)){
    /* short form */
    *len=1;
    return der[0];
  }
  else{
    /* Long form */
    k=der[0]&0x7F;
    punt=1;
    ans=0;
    while(punt<=k) ans=ans*256+der[punt++];
    
    *len=punt;
    return ans;
  }
}


void
tag_der(unsigned char class,unsigned int tag_value,unsigned char *ans,int *ans_len)
{
  int k;
  unsigned char temp[128];

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


unsigned int
get_tag_der(unsigned char *der,unsigned char *class,int  *len)
{
  unsigned long ans;
  int punt,ris;

  *class=der[0]&0xE0;
  if((der[0]&0x1F)!=0x1F){
    /* short form */
    *len=1;
    ris=der[0]&0x1F;
  }
  else{
    /* Long form */
    punt=1;
    ris=0;
    while(der[punt]&128) ris=ris*128+(der[punt++]&0x7F);
    ris=ris*128+(der[punt++]&0x7F);   
    *len=punt;
  }
  return ris;
}


void
integer_der(char *value,unsigned char *der,int *len)
{
  long v,v2;
  int k,count,len_len;

  v2=v=strtol(value,NULL,10);
  if(!v){
    count=0;
  }
  else if(v>0){
    for(k=0;k<32;k++){
      if(v2&1) count=k+1;
      v2=v2>>1;
    }
  }
  else{  /* v<0 */
    for(k=0;k<32;k++){
      if(!(v2&1)) count=k+1;
      v2=v2>>1;
    }
  }
  count=(count>>3)+1;
  length_der(count,der,&len_len);
  for(k=0;k<count;k++) der[len_len+k]=((char*)(&v))[count-k-1];
  *len=count+len_len;
}


long
get_integer_der(unsigned char *der,int *len)
{
  unsigned long len_integer;
  int len_len,k;
  long v;

  len_integer=get_length_der(der,&len_len);
  if(der[len_len]&0x80) v=-1; /* negative value */
  else v=0; /* positive value */
  for(k=0;k<len_integer;k++) ((char*)(&v))[len_integer-k-1]=der[len_len+k];
  *len=len_integer+len_len;
  return v;
}

void
octet_der(unsigned char *str,int str_len,unsigned char *der,int *der_len)
{
  int len_len;

  if(der==NULL) return;
  length_der(str_len,der,&len_len);
  memcpy(der+len_len,str,str_len);
  *der_len=str_len+len_len;
}


void
get_octet_der(unsigned char *der,int *der_len,unsigned char *str,int *str_len)
{
  int len_len;

  if(str==NULL) return;
  *str_len=get_length_der(der,&len_len);
  memcpy(str,der+len_len,*str_len);
  *der_len=*str_len+len_len;
}


void
time_der(unsigned char *str,unsigned char *der,int *der_len)
{
  int len_len;

  if(der==NULL) return;
  length_der(strlen(str),der,&len_len);
  memcpy(der+len_len,str,strlen(str));
  *der_len=len_len+strlen(str);
}


void
get_utctime_der(unsigned char *der,int *der_len,unsigned char *str)
{
  int len_len,str_len;
  char temp[20];

  if(str==NULL) return;
  str_len=get_length_der(der,&len_len);
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


void
get_generalizedtime_der(unsigned char *der,int *der_len,unsigned char *str)
{
  int len_len,str_len;

  if(str==NULL) return;
  str_len=get_length_der(der,&len_len);
  memcpy(str,der+len_len,str_len);
  str[str_len]=0;
  *der_len=str_len+len_len;
}

void
objectid_der(unsigned char *str,unsigned char *der,int *der_len)
{
  int len_len,counter,k,first;
  char temp[128],*n_end,*n_start;
  unsigned char bit7;
  unsigned long val,val1;

  if(der==NULL) return;

  strcpy(temp,str);
  strcat(temp," ");

  counter=0;
  n_start=temp;
  while(n_end=strchr(n_start,' ')){
    *n_end=0;
    val=strtoul(n_start,NULL,10);
    counter++;
    if(counter==1) val1=val;
    if(counter==2){
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

  length_der(*der_len,NULL,&len_len);
  memmove(der+len_len,der,*der_len);
  length_der(*der_len,der,&len_len);
  *der_len+=len_len;
}


void
get_objectid_der(unsigned char *der,int *der_len,unsigned char *str)
{
  int len_len,len,k;
  char temp[20];
  unsigned long val,val1;

  if(str==NULL) return;
  len=get_length_der(der,&len_len);
  
  val1=der[len_len]/40;
  val=der[len_len]-val1*40;

  strcpy(str,ltostr(val1,temp));
  strcat(str," ");
  strcat(str,ltostr(val,temp));

  val=0;
  for(k=1;k<len;k++){
    val=val<<7;
    val|=der[len_len+k]&0x7F;
    if(!(der[len_len+k]&0x80)){
      strcat(str," ");
      strcat(str,ltostr(val,temp));
      val=0;
    }
  }
  *der_len=len+len_len;
}



char bit_mask[]={0xFF,0xFE,0xFC,0xF8,0xF0,0xE0,0xC0,0x80};

void
bit_der(unsigned char *str,int bit_len,unsigned char *der,int *der_len)
{
  int len_len,len_byte,len_pad;

  if(der==NULL) return;
  len_byte=bit_len>>3;
  len_pad=8-(bit_len&7);
  if(len_pad==8) len_pad=0;
  else len_byte++;
  length_der(len_byte+1,der,&len_len);
  der[len_len]=len_pad;
  memcpy(der+len_len+1,str,len_byte);
  der[len_len+len_byte]&=bit_mask[len_pad];
  *der_len=len_byte+len_len+1;
}


void
get_bit_der(unsigned char *der,int *der_len,unsigned char *str,int *bit_len)
{
  int len_len,len_byte;

  if(str==NULL) return;
  len_byte=get_length_der(der,&len_len)-1;
  memcpy(str,der+len_len+1,len_byte);
  *bit_len=len_byte*8-der[len_len];
  *der_len=len_byte+len_len+1;
}




#define UP    1
#define DOWN  2
#define RIGHT 3


void
complete_explicit_tag(node_asn *node,unsigned char *der,int *counter)
{
  node_asn *p;
  int tag_len,is_tag_implicit,len2,len3;
  unsigned char class,class_implicit,temp[10];
  unsigned long tag_implicit;
   
  is_tag_implicit=0;

  if(node->type&CONST_TAG){
    p=node->down;
    while(p){
      if(type_field(p->type)==TYPE_TAG){
	if(p->type&CONST_EXPLICIT){
	  len2=strtol(p->name,NULL,10);
	  set_name(p,NULL);
	  length_der(*counter-len2,temp,&len3);
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
      p=p->right;
    }
  }
}


int
insert_tag_der(node_asn *node,unsigned char *der,int *counter)
{
  node_asn *p;
  int tag_len,is_tag_implicit,len2,len3;
  unsigned char class,class_implicit,temp[10];
  unsigned long tag_implicit;
   
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
	    tag_der(class_implicit,tag_implicit,der+*counter,&tag_len);
	  else
	    tag_der(class|STRUCTURED,strtoul(p->value,NULL,10),der+*counter,&tag_len);
	  *counter+=tag_len;
	  ltostr(*counter,temp);
	  set_name(p,temp);

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
    tag_der(class_implicit,tag_implicit,der+*counter,&tag_len);
  }
  else{
    switch(type_field(node->type)){
    case TYPE_NULL:
      tag_der(UNIVERSAL,TAG_NULL,der+*counter,&tag_len);
      break;
    case TYPE_BOOLEAN:
      tag_der(UNIVERSAL,TAG_BOOLEAN,der+*counter,&tag_len);
      break;
    case TYPE_INTEGER:
      tag_der(UNIVERSAL,TAG_INTEGER,der+*counter,&tag_len);
      break;
    case TYPE_OBJECT_ID:
      tag_der(UNIVERSAL,TAG_OBJECT_ID,der+*counter,&tag_len);
      break;
    case TYPE_TIME:
      if(node->type&CONST_UTC){
	tag_der(UNIVERSAL,TAG_UTCTime,der+*counter,&tag_len);
      }
      else tag_der(UNIVERSAL,TAG_GENERALIZEDTime,der+*counter,&tag_len);
      break;
    case TYPE_OCTET_STRING:
      tag_der(UNIVERSAL,TAG_OCTET_STRING,der+*counter,&tag_len);
      break;
    case TYPE_BIT_STRING:
      tag_der(UNIVERSAL,TAG_BIT_STRING,der+*counter,&tag_len);
      break;
    case TYPE_SEQUENCE: case TYPE_SEQUENCE_OF:
      tag_der(UNIVERSAL|STRUCTURED,TAG_SEQUENCE,der+*counter,&tag_len);
      break;
    case TYPE_SET: case TYPE_SET_OF:
      tag_der(UNIVERSAL|STRUCTURED,TAG_SET,der+*counter,&tag_len);
      break;
    case TYPE_TAG:
      tag_len=0;
      break;
    case TYPE_CHOICE:
      tag_len=0;
      break;
    default:
      return ASN_GENERIC_ERROR;
    }
  }
  
  *counter+=tag_len;

  return ASN_OK;
}


int
extract_tag_der(node_asn *node,unsigned char *der,int *der_len)
{
  node_asn *p;
  int counter,len2,len3,is_tag_implicit;
  unsigned long tag,tag_implicit;
  unsigned char class,class2,class_implicit;

  counter=is_tag_implicit=0;
  if(node->type&CONST_TAG){
    p=node->down;
    while(p){
      if(type_field(p->type)==TYPE_TAG){
	if(p->type&CONST_APPLICATION) class2=APPLICATION;
	else if(p->type&CONST_UNIVERSAL) class2=UNIVERSAL;
	else if(p->type&CONST_PRIVATE) class2=PRIVATE;
	else class2=CONTEXT_SPECIFIC;
	
	if(p->type&CONST_EXPLICIT){
	  tag=get_tag_der(der+counter,&class,&len2);
	  counter+=len2;
	  len3=get_length_der(der+counter,&len2);
	  counter+=len2;
	  if(!is_tag_implicit){
	    if((class!=(class2|STRUCTURED)) || (tag!=strtoul(p->value,NULL,10)))
	      return ASN_TAG_ERROR;
	  }
	  else{    /* TAG_IMPLICIT */
	    if((class!=class_implicit) || (tag!=tag_implicit))
	      return ASN_TAG_ERROR;
	  }

	  is_tag_implicit=0;
	}
	else{    /* TAG_IMPLICIT */
	  if(!is_tag_implicit){
	    if((type_field(node->type)==TYPE_SEQUENCE) ||
	       (type_field(node->type)==TYPE_SEQUENCE_OF) ||
	       (type_field(node->type)==TYPE_SET) ||
	       (type_field(node->type)==TYPE_SET_OF))  class2|=STRUCTURED;
	    class_implicit=class2;
	    tag_implicit=strtoul(p->value,NULL,10);
	    is_tag_implicit=1;
	  }
	}
      }
      p=p->right;
    }
  }

  if(is_tag_implicit){
    //if(type_field(node->type)==TYPE_ANY) return ASN_ERROR_TYPE_ANY;
    tag=get_tag_der(der+counter,&class,&len2);
    if((class!=class_implicit) || (tag!=tag_implicit)) return ASN_TAG_ERROR;
  }
  else{
    if(type_field(node->type)==TYPE_TAG){
      counter=0;
      *der_len=counter;
      return ASN_OK;
    }

    tag=get_tag_der(der+counter,&class,&len2);
    switch(type_field(node->type)){
    case TYPE_NULL:
      if((class!=UNIVERSAL) || (tag!=TAG_NULL)) return ASN_DER_ERROR;
       break;
    case TYPE_BOOLEAN:
      if((class!=UNIVERSAL) || (tag!=TAG_BOOLEAN)) return ASN_DER_ERROR;
       break;
    case TYPE_INTEGER:
      if((class!=UNIVERSAL) || (tag!=TAG_INTEGER)) return ASN_DER_ERROR;
       break;
    case TYPE_OBJECT_ID:
      if((class!=UNIVERSAL) || (tag!=TAG_OBJECT_ID)) return ASN_DER_ERROR;
       break;
    case TYPE_TIME:
      if(node->type&CONST_UTC){
	  if((class!=UNIVERSAL) || (tag!=TAG_UTCTime)) return ASN_DER_ERROR;
      }
      else{
	if((class!=UNIVERSAL) || (tag!=TAG_GENERALIZEDTime)) 
	  return ASN_DER_ERROR;
      }
      break;
    case TYPE_OCTET_STRING:
      if((class!=UNIVERSAL) || (tag!=TAG_OCTET_STRING)) return ASN_DER_ERROR;
      break;
    case TYPE_BIT_STRING:
      if((class!=UNIVERSAL) || (tag!=TAG_BIT_STRING)) return ASN_DER_ERROR;
      break;
    case TYPE_SEQUENCE: case TYPE_SEQUENCE_OF:
      if((class!=(UNIVERSAL|STRUCTURED)) || (tag!=TAG_SEQUENCE)) 
	return ASN_DER_ERROR;
      break;
    case TYPE_SET: case TYPE_SET_OF:
      if((class!=(UNIVERSAL|STRUCTURED)) || (tag!=TAG_SET)) 
	return ASN_DER_ERROR;
      break;
    case TYPE_ANY:
      counter-=len2;
      break;
    default:
      return ASN_DER_ERROR;
      break;
    }
  }

  counter+=len2;
  *der_len=counter;
  return ASN_OK;
}


void
ordering_set(unsigned char *der,node_asn *node)
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
    p_vet=(struct vet *)malloc(sizeof(struct vet));
    p_vet->next=NULL;
    p_vet->prev=last;
    if(first==NULL) first=p_vet;
    else last->next=p_vet;
    last=p_vet;

    /* tag value calculation */
    tag=get_tag_der(der+counter,&class,&len2);
    p_vet->value=(class<<24)|tag;
    counter+=len2;

    /* extraction  and length */
    len2=get_length_der(der+counter,&len);
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
	temp=(unsigned char *)malloc(p_vet->end-counter);
	memcpy(temp,der+counter,p_vet->end-counter);
	memmove(der+counter,der+p_vet->end,p2_vet->end-p_vet->end);
	memcpy(der+p_vet->end,temp,p_vet->end-counter);
	free(temp);
	
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
    free(p_vet);
    p_vet=first;
  }
}


void
ordering_set_of(unsigned char *der,node_asn *node)
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
    p_vet=(struct vet *)malloc(sizeof(struct vet));
    p_vet->next=NULL;
    p_vet->prev=last;
    if(first==NULL) first=p_vet;
    else last->next=p_vet;
    last=p_vet;

    /* extraction of tag and length */
    get_tag_der(der+counter,&class,&len);
    counter+=len;
    len2=get_length_der(der+counter,&len);
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
	temp=(unsigned char *)malloc(p_vet->end-counter);
	memcpy(temp,der+counter,p_vet->end-counter);
	memmove(der+counter,der+p_vet->end,p2_vet->end-p_vet->end);
	memcpy(der+p_vet->end,temp,p_vet->end-counter);
	free(temp);
	
	p_vet->end=counter+(p2_vet->end-p_vet->end);
      }
      counter=p_vet->end;
      
      p2_vet=p2_vet->next;
      p_vet=p_vet->next;
    }

    if(p_vet!=first) p_vet->prev->next=NULL;
    else first=NULL;
    free(p_vet);
    p_vet=first;
  }
}


int 
create_der(char *name,unsigned char *der,int *len)
{
  node_asn *node,*p,*p2,*p3;
  char temp[20];
  int counter,counter_old,len2,len3,len4,move,ris;

  node=find_node(name);
  if(node==NULL) return ASN_ELEMENT_NOT_FOUND;

  counter=0;
  move=DOWN;
  p=node;
  while(1){
    
    counter_old=counter;
    if(move!=UP) ris=insert_tag_der(p,der,&counter);

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
    case TYPE_INTEGER:
      if((p->type&CONST_DEFAULT) && (p->value==NULL)) counter=counter_old;
      else{
	len2=get_length_der(p->value,&len3);
	memcpy(der+counter,p->value,len3+len2);
	counter+=len3+len2;
      }
      move=RIGHT;
      break;
    case TYPE_OBJECT_ID:
      objectid_der(p->value,der+counter,&len2);
      counter+=len2;
      move=RIGHT;
      break;
    case TYPE_TIME:
      time_der(p->value,der+counter,&len2);
      counter+=len2;
      move=RIGHT;
      break;
    case TYPE_OCTET_STRING:
      len2=get_length_der(p->value,&len3);
      memcpy(der+counter,p->value,len3+len2);
      counter+=len3+len2;
      move=RIGHT;
      break;
    case TYPE_BIT_STRING:
      len2=get_length_der(p->value,&len3);
      memcpy(der+counter,p->value,len3+len2);
      counter+=len3+len2;
      move=RIGHT;
      break;
    case TYPE_SEQUENCE: case TYPE_SET: 
      if(move!=UP){
	ltostr(counter,temp);
	set_value(p,temp,strlen(temp)+1);
	move=DOWN;
      }
      else{   /* move==UP */
	len2=strtol(p->value,NULL,10);
	set_value(p,NULL,0);
	if(type_field(p->type)==TYPE_SET) ordering_set(der+len2,p);
	length_der(counter-len2,temp,&len3);
	memmove(der+len2+len3,der+len2,counter-len2);
	memcpy(der+len2,temp,len3);
	counter+=len3;
	move=RIGHT;
      }
      break;
    case TYPE_SEQUENCE_OF: case TYPE_SET_OF: 
      if(move!=UP){
	ltostr(counter,temp);
	set_value(p,temp,strlen(temp)+1);
	p=p->down;
	while((type_field(p->type)==TYPE_TAG) || (type_field(p->type)==TYPE_SIZE)) p=p->right;
	if(p->right){
	  p=p->right;
	  move=RIGHT;
	  continue;
	}
	else p=find_up(p);
	move=UP;
      }
      if(move==UP){
	len2=strtol(p->value,NULL,10);
	set_value(p,NULL,0);
	if(type_field(p->type)==TYPE_SET_OF) ordering_set_of(der+len2,p);
	length_der(counter-len2,temp,&len3);
	memmove(der+len2+len3,der+len2,counter-len2);
	memcpy(der+len2,temp,len3);
	counter+=len3;
	move=RIGHT;
      }
      break;
    case TYPE_ANY:
      return ASN_ERROR_TYPE_ANY;
      break;
    default:
       move=(move==UP)?RIGHT:DOWN;
      break;
    }

    if((move!=DOWN) && (counter!=counter_old))
      complete_explicit_tag(p,der,&counter);

    if(p==node && move!=DOWN) break;

    if(move==DOWN){
      if(p->down) p=p->down;
      else move=RIGHT;
    }
    if(move==RIGHT){
      if(p->right) p=p->right;
      else move=UP;
    }
   if(move==UP) p=find_up(p);
  }

  *len=counter;
  return ASN_OK;
}


int 
get_der(char *name,unsigned char *der,int len)
{
  node_asn *node,*p,*p2,*p3;
  char temp[128];
  int counter,len2,len3,move,ris;
  unsigned char class;
  unsigned int tag;
  long val;

  node=find_node(name);
  if(node==NULL) return ASN_ELEMENT_NOT_FOUND;

  if(node->type&CONST_OPTION) return ASN_GENERIC_ERROR;

  expand_asn(name,"");

  counter=0;
  move=DOWN;
  p=node;
  while(1){
    ris=ASN_OK;

    if(move!=UP){
      if(p->type&CONST_SET){
	p2=find_up(p);
	len2=strtol(p2->value,NULL,10);
	if(counter==len2){
	  p=p2;
	  move=UP;
	  continue;
	}
	else if(counter>len2) return ASN_DER_ERROR;
	p2=p2->down;
	while(p2){
	  if((p2->type&CONST_SET) && (p2->type&CONST_NOT_USED)){  /* CONTROLLARE */
	    if(type_field(p2->type)!=TYPE_CHOICE)
	      ris=extract_tag_der(p2,der+counter,&len2);
	    else{
	      p3=p2->down;
	      while(p3){
		ris=extract_tag_der(p3,der+counter,&len2);
		if(ris==ASN_OK) break;
		//if(ris==ASN_ERROR_TYPE_ANY) return ASN_ERROR_TYPE_ANY;
		p3=p3->right;
	      }
	    }
	    if(ris==ASN_OK){
	      p2->type&=~CONST_NOT_USED;
	      p=p2;
	      break;
	    }
	    //else if(ris==ASN_ERROR_TYPE_ANY) return ASN_ERROR_TYPE_ANY;
	  }
	  p2=p2->right;
	}
	if(p2==NULL) return ASN_DER_ERROR;
      }

      if(type_field(p->type)==TYPE_CHOICE){
	while(p->down){
	  ris=extract_tag_der(p->down,der+counter,&len2);
	  if(ris==ASN_OK){
	    while(p->down->right) delete_tree2(p->down->right);
	    break;
	  }
	  else if(ris==ASN_ERROR_TYPE_ANY) return ASN_ERROR_TYPE_ANY;
	  else delete_tree2(p->down);
	}
	if(p->down==NULL) return ASN_DER_ERROR;
	p=p->down;
      }

      if((p->type&CONST_OPTION) || (p->type&CONST_DEFAULT)){
	p2=find_up(p);
	len2=strtol(p2->value,NULL,10);
	if(counter>=len2) ris=ASN_TAG_ERROR;
      }

      if(ris==ASN_OK) ris=extract_tag_der(p,der+counter,&len2);
      if(ris!=ASN_OK){
	//if(ris==ASN_ERROR_TYPE_ANY) return ASN_ERROR_TYPE_ANY;
	if(p->type&CONST_OPTION){
	  p->type|=CONST_NOT_USED;
	  move=RIGHT;
	}
	else if(p->type&CONST_DEFAULT) {
	  set_value(p,NULL,0);
	  move=RIGHT;
	}
	else {
	  //return (type_field(p->type)!=TYPE_ANY)?ASN_TAG_ERROR:ASN_ERROR_TYPE_ANY;
	  return ASN_TAG_ERROR;
	}
      } 
      else counter+=len2;
    }

    if(ris==ASN_OK){
      switch(type_field(p->type)){
      case TYPE_NULL:
	if(der[counter]) return ASN_DER_ERROR;
	counter++;
	move=RIGHT;
	break;
      case TYPE_BOOLEAN:
	if(der[counter++]!=1) return ASN_DER_ERROR;
	if(der[counter++]==0) set_value(p,"F",1);
	else set_value(p,"T",1);
	move=RIGHT;
	break;
      case TYPE_INTEGER:
	len2=get_length_der(der+counter,&len3);
	set_value(p,der+counter,len3+len2);
	counter+=len3+len2;
	move=RIGHT;
	break;
      case TYPE_OBJECT_ID:
	get_objectid_der(der+counter,&len2,temp);
	set_value(p,temp,strlen(temp)+1);
	counter+=len2;
	move=RIGHT;
      break;
      case TYPE_TIME:
	if(p->type&CONST_UTC){
	  get_utctime_der(der+counter,&len2,temp);
	  set_value(p,temp,strlen(temp)+1);
	  counter+=len2;
	}
	else{
	  get_generalizedtime_der(der+counter,&len2,temp);
	  set_value(p,temp,strlen(temp)+1);
	  counter+=len2;
	}
	move=RIGHT;
	break;
      case TYPE_OCTET_STRING:
	len2=get_length_der(der+counter,&len3);
	set_value(p,der+counter,len3+len2);
	counter+=len3+len2;
	move=RIGHT;
	break;
      case TYPE_BIT_STRING:
	len2=get_length_der(der+counter,&len3);
	set_value(p,der+counter,len3+len2);
	counter+=len3+len2;
	move=RIGHT;
	break;
      case TYPE_SEQUENCE:  case TYPE_SET:;
	if(move==UP){
	  len2=strtol(p->value,NULL,10);
	  set_value(p,NULL,0);
	  if(len2!=counter) return ASN_DER_ERROR;
	  move=RIGHT;
	}
	else{   /* move==DOWN || move==RIGHT */
	  len3=get_length_der(der+counter,&len2);
	  counter+=len2;
	  ltostr(counter+len3,temp);
	  set_value(p,temp,strlen(temp)+1);
	  move=DOWN; 
	}
	break;
      case TYPE_SEQUENCE_OF: case TYPE_SET_OF:
	if(move==UP){
	  len2=strtol(p->value,NULL,10);
	  if(len2>counter){
	    append_sequence_set(p);
	    p=p->down;
	    while(p->right) p=p->right;
	    move=RIGHT;
	    continue;
	  }
	  set_value(p,NULL,0);
	  if(len2!=counter) return ASN_DER_ERROR;
	}
	else{   /* move==DOWN || move==RIGHT */
	  len3=get_length_der(der+counter,&len2);
	  counter+=len2;
	  if(len3){
	    ltostr(counter+len3,temp);
	    set_value(p,temp,strlen(temp)+1);
	    p2=p->down;
	    while((type_field(p2->type)==TYPE_TAG) || (type_field(p2->type)==TYPE_SIZE)) p2=p2->right;
	    if(p2->right==NULL) append_sequence_set(p);
	    p=p2;
	  }
	}
	move=RIGHT;
	break;
      case TYPE_ANY:
	tag=get_tag_der(der+counter,&class,&len2);
	len2+=get_length_der(der+counter+len2,&len3);
	set_value(p,der+counter,len3+len2);
	counter+=len3+len2;
	move=RIGHT;
	//	return ASN_ERROR_TYPE_ANY;
	break;
      default:
	move=(move==UP)?RIGHT:DOWN;
	break;
      }
    }

    if(p==node && move!=DOWN) break;

    if(move==DOWN){
      if(p->down) p=p->down;
      else move=RIGHT;
    }
    if((move==RIGHT) && !(p->type&CONST_SET)){
      if(p->right) p=p->right;
      else move=UP;
    }
    if(move==UP) p=find_up(p);
  }

  check_asn(name,CHECK_NOT_USED);

  return (counter==len)?ASN_OK:ASN_DER_ERROR;
}



int 
get_start_end_der(char *name,unsigned char *der,int len,char *name_element,int *start, int *end)
{
  node_asn *node,*node_to_find,*p,*p2,*p3;
  char temp[128];
  int counter,len2,len3,move,ris;
  unsigned char class;
  unsigned int tag;
  long val;

  node=find_node(name);
  node_to_find=find_node(name_element);

  if(node_to_find==NULL) return ASN_ELEMENT_NOT_FOUND;

  if(node_to_find==node){
    *start=0;
    *end=len;
    return ASN_OK;
  }

  if(node==NULL) return ASN_ELEMENT_NOT_FOUND;

  if(node->type&CONST_OPTION) return ASN_GENERIC_ERROR;

  expand_asn(name,"");

  counter=0;
  move=DOWN;
  p=node;
  while(1){
    ris=ASN_OK;

    if((p==node_to_find) && (move!=UP)) *start=counter;
 
    if(move!=UP){
      if(p->type&CONST_SET){
	p2=find_up(p);
	len2=strtol(p2->value,NULL,10);
	if(counter==len2){
	  p=p2;
	  move=UP;
	  continue;
	}
	else if(counter>len2) return ASN_DER_ERROR;
	p2=p2->down;
	while(p2){
	  if((p2->type&CONST_SET) && (p2->type&CONST_NOT_USED)){  /* CONTROLLARE */
	    if(type_field(p2->type)!=TYPE_CHOICE)
	      ris=extract_tag_der(p2,der+counter,&len2);
	    else{
	      p3=p2->down;
	      ris=extract_tag_der(p3,der+counter,&len2);
	    }
	    if(ris==ASN_OK){
	      p2->type&=~CONST_NOT_USED;
	      p=p2;
	      break;
	    }
	    //else if(ris==ASN_ERROR_TYPE_ANY) return ASN_ERROR_TYPE_ANY;
	  }
	  p2=p2->right;
	}
	if(p2==NULL) return ASN_DER_ERROR;
      }

      if(type_field(p->type)==TYPE_CHOICE){
	p=p->down;
	ris=extract_tag_der(p,der+counter,&len2);
      }

      if(ris==ASN_OK) ris=extract_tag_der(p,der+counter,&len2);
      if(ris!=ASN_OK){
	if(p->type&CONST_OPTION){
	  p->type|=CONST_NOT_USED;
	  move=RIGHT;
	}
	else if(p->type&CONST_DEFAULT) {
	  move=RIGHT;
	}
	else {
	  return ASN_TAG_ERROR;
	}
      } 
      else counter+=len2;
    }

    if(ris==ASN_OK){
      switch(type_field(p->type)){
      case TYPE_NULL:
     	if(der[counter]) return ASN_DER_ERROR;
	counter++;
	move=RIGHT;
	break;
      case TYPE_BOOLEAN:
	if(der[counter++]!=1) return ASN_DER_ERROR;
	counter++;
	move=RIGHT;
	break;
      case TYPE_INTEGER:
	len2=get_length_der(der+counter,&len3);
	counter+=len3+len2;
	move=RIGHT;
	break;
      case TYPE_OBJECT_ID:
	len2=get_length_der(der+counter,&len3);
	counter+=len2+len3;
	move=RIGHT;
      break;
      case TYPE_TIME:
	len2=get_length_der(der+counter,&len3);
	counter+=len2+len3;
	move=RIGHT;
	break;
      case TYPE_OCTET_STRING:
	len2=get_length_der(der+counter,&len3);
	counter+=len3+len2;
	move=RIGHT;
	break;
      case TYPE_BIT_STRING:
	len2=get_length_der(der+counter,&len3);
	counter+=len3+len2;
	move=RIGHT;
	break;
      case TYPE_SEQUENCE:  case TYPE_SET:
	if(move!=UP){
	  len3=get_length_der(der+counter,&len2);
	  counter+=len2;
	  move=DOWN; 
	}
	else move=RIGHT;
	break;
      case TYPE_SEQUENCE_OF: case TYPE_SET_OF:
	if(move!=UP){
	  len3=get_length_der(der+counter,&len2);
	  counter+=len2;
	  if(len3){
	    p2=p->down;
	    while((type_field(p2->type)==TYPE_TAG) || 
		  (type_field(p2->type)==TYPE_SIZE)) p2=p2->right;
	    p=p2;
	  }
	}
	move=RIGHT;
	break;
      case TYPE_ANY:
	tag=get_tag_der(der+counter,&class,&len2);
	len2+=get_length_der(der+counter+len2,&len3);
	counter+=len3+len2;
 	move=RIGHT;
	break;
      default:
	move=(move==UP)?RIGHT:DOWN;
	break;
      }
    }

    if((p==node_to_find) && (move==RIGHT)){
      *end=counter-1;
      return ASN_OK;
    }

    if(p==node && move!=DOWN) break;

    if(move==DOWN){
      if(p->down) p=p->down;
      else move=RIGHT;
    }
    if((move==RIGHT) && !(p->type&CONST_SET)){
      if(p->right) p=p->right;
      else move=UP;
    }
    if(move==UP) p=find_up(p);
  }

  return ASN_ELEMENT_NOT_FOUND;
}










