/* scanner for DER encoded certificates */

/*
 * Copyright (C) 2000 Tarun Upadhyay <tarun@poboxes.com>
 *
 * This file is part of GNUTLS Certificate API.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS Certificate API is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include "defines.h"
#include "gnutls_der.h"

tag_attribs *find_tag_attribs(int tagcode, tag_attribs *tag){
  int i;
  tag->type = 0;
  for( i = 0; ASN_TAGS[i][1] != 0; i++){
	if (ASN_TAGS[i][0] == tagcode){
	  tag->code = ASN_TAGS[i][0];
	  tag->type = ASN_TAGS[i][1];
	  tag->composite = ASN_TAGS[i][2];
	  break;
	}
  }
  if (tag->type == 0)
	tag->type = tagcode; /* FIX ME (tarun): This is to allow parsing even if
							dont know the tag type */
  return tag;
}  

int read_tag(FILE *instr, tag_attribs* tag){
  int ch = fgetc(instr);
  if (ch == EOF)
	return READ_ERROR;

  if(find_tag_attribs(ch, tag) == NULL)
	return READ_ERROR;
  tag->length = 1;
  return 0;
}

int read_length(FILE *instr, tag_attribs *tag){
  int metalength;
  int i;

  metalength = fgetc(instr);
  tag->length += 1;
  
  if (metalength == EOF)
	return READ_ERROR;
  if ( metalength & 0x80 ){
	metalength &= 0x7f;
	tag->length += metalength;
	for (i = 0; i < metalength; i++){
	  tag->value_length <<= 8;
	  tag->value_length |= fgetc(instr);
	}
  }
  else
	tag->value_length = metalength;
  tag->length += tag->value_length;
  return 0;
}

int pretty_print_tag( tag_attribs *tag, FILE *outstr){
  char fmt[80];
  int i;
  
  for (i = 0; i < tag->level; i++)
	printf("   ");
  switch(tag->type) {
  case DER_BOOLEAN: fprintf(outstr, "BOOLEAN"); break;
  case DER_INTEGER: fprintf(outstr,"INTEGER"); break;
  case DER_BIT_STRING: fprintf(outstr,"BIT STRING"); break;
  case DER_NULL: fprintf(outstr,"NULL"); break;
  case DER_OBJECT_ID: fprintf(outstr,"OBJECT ID"); break;
  case DER_OBJECT_DESC: fprintf(outstr,"OBJECT DESCRIPTOR"); break;	
  case DER_STRING: fprintf(outstr,"STRING"); break;
  case DER_UTC_TIME: fprintf(outstr,"UTC TIME"); break;
  case DER_SEQUENCE: fprintf(outstr,"SEQUENCE"); break;
  case DER_SET: fprintf(outstr,"SET"); break;
  case DER_ARRAY: fprintf(outstr, "ARRAY"); break;
  default: fprintf(outstr, "TYPE UNKNOWN"); break;
  }	
  fprintf(outstr, " (length:%d) ", tag->value_length);
  if (tag->composite == ASN_TAG_COMPOSITE)
	fprintf(outstr, "\n");
  return 0;
}

int process_value(FILE *instr, tag_attribs *tag, FILE *outstr){
  int i;
  int ch;
  
  for (i = 0; i < tag->value_length; i++){
	ch = fgetc(instr);
	if (ch == EOF)
	  return READ_ERROR;
	switch (tag->type){
	case DER_BOOLEAN:
	  fprintf(outstr, "0x%02x ", ch);
	  break;
	case DER_INTEGER:
	  fprintf(outstr, "%02x", ch);
	  break;
	case DER_OBJECT_ID:
	  fprintf(outstr, "%d.", ch);
	  break;
	case DER_STRING:
	  fprintf(outstr, "%c", ch);
	  break;
	case DER_UTC_TIME:
	  fprintf(outstr, "%c", ch);
	  break;
	}
  }
  fprintf(outstr, "\n");
  return 0;
}

int read_der_certificate(FILE *instr, FILE *outstr){
  static int indent = 0;
  tag_attribs tag;
  int current_length;
  int temp_length;
  int i;
  
  memset(&tag, 0, sizeof(tag));
  tag.level = indent;
  if (read_tag(instr, &tag) == READ_ERROR)
	return READ_ERROR;

  if (read_length(instr, &tag) == READ_ERROR)
	return READ_ERROR;

  pretty_print_tag(&tag, outstr);
  if (tag.composite == ASN_TAG_COMPOSITE){
	indent += 1;
	for (
		 current_length = 0;
		 current_length != tag.value_length;
		 current_length += temp_length
		 ) {
	  temp_length = read_der_certificate(instr, outstr);
	  if (temp_length == READ_ERROR)
		return READ_ERROR;
	}
	indent -= 1;
  }
  else { /* process the value */
	process_value(instr, &tag, outstr);
  }
  return tag.length;
}

main (int argc, char *argv[]){
  printf("length of certificate: %d\n", read_der_certificate(stdin, stdout));
}
