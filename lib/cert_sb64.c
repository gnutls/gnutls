/*
 * Copyright (C) 2000 Nikos Mavroyanopoulos <nmav@hellug.gr>
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

#include "defines.h"
#include "gnutls_int.h"

/* this a modified base64 for srp !!! 
 * It seems that everybody makes it's own base64 convertion.
 */
const static uint8 b64table[64] =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz./";

const static uint8 asciitable[128] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0x3e, 0x3f,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
	0x06, 0x07, 0x08, 0x09, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0x0a,
	0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
	0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
	0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22,
	0x23, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x24, 0x25, 0x26, 0x27, 0x28,
	0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
	0x2f, 0x30, 0x31, 0x32, 0x33, 0x34,
	0x35, 0x36, 0x37, 0x38, 0x39, 0x3a,
	0x3b, 0x3c, 0x3d, 0xff, 0xff, 0xff,
	0xff, 0xff
};

int _gnutls_sbase64_encode(uint8 * data, int data_size, uint8 ** result)
{
  int c, pos = data_size % 3;
  unsigned char b0 = 0, b1 = 0, b2 = 0, notleading = 0;
  uint8 *dst;
  
  (*result) = gnutls_malloc( (data_size*4)/3+1+(pos>1?1:0));
  dst = (*result);

  switch(pos) {
  case 1:
    b2 = data[0];
    break;
  case 2:
    b1 = data[0];
    b2 = data[1];
    break;
  }

  while(1) {
    c = (b0 & 0xfc) >> 2;
    if(notleading || c != 0) {
      *dst++ = b64table[c];
      notleading = 1;
    }
    c = ((b0 & 3) << 4) | ((b1 & 0xf0) >> 4);
    if(notleading || c != 0) {
      *dst++ = b64table[c];
      notleading = 1;
    }
    c = ((b1 & 0xf) << 2) | ((b2 & 0xc0) >> 6);
    if(notleading || c != 0) {
      *dst++ = b64table[c];
      notleading = 1;
    }
    c = b2 & 0x3f;
    if(notleading || c != 0) {
      *dst++ = b64table[c];
      notleading = 1;
    }
    if(pos >= data_size)
      break;
    else {
      b0 = data[pos++];
      b1 = data[pos++];
      b2 = data[pos++];
    }
  }

  *dst++ = '\0';
  return strlen(*result);
}

int _gnutls_sbase64_decode(uint8 * data, int data_size, uint8 ** result)
{
  uint8 *a;
  uint8 loc;
  int i, j;

  while(*data && (*data == ' ' || *data == '\t' || *data == '\n'))
      ++data;

  a = gnutls_malloc(data_size + 1);
  if(a == (unsigned char *) 0)
    return -1;

  i = 0;
  while(i < data_size) {
    loc = asciitable[data[i]]; 
    if(loc == 0xff)
      break;
    else
      a[i] = loc;
    ++i;
  }
  data_size = i;

  i = data_size - 1;
  j = data_size;
  while(1) {
    a[j] = a[i];
    if(--i < 0)
      break;
    a[j] |= (a[i] & 3) << 6;
    --j;
    a[j] = (uint8) ((a[i] & 0x3c) >> 2);
    if(--i < 0)
      break;
    a[j] |= (a[i] & 0xf) << 4;
    --j;
    a[j] = (uint8) ((a[i] & 0x30) >> 4);
    if(--i < 0)
      break;
    a[j] |= (a[i] << 2);

    a[--j] = 0;
    if(--i < 0)
      break;
  }

  while(a[j] == 0 && j <= data_size)
    ++j;

  (*result) = gnutls_malloc( data_size-j+1);

  memcpy( (*result), a + j, data_size - j + 1);

  gnutls_free(a);
  return data_size - j + 1;
}



#ifdef B64_TEST
int main()
{
	char x[100*1024];
	int siz;
	uint8 *b64;

/*	for (i = 0; i < 128; i++) {
		if (i % 6 == 0)
			fprintf(stdout, "\n");
		if (strchr(b64table, i) == NULL)
			fprintf(stdout, "0x%.2x, ", 0xff);
		else
			fprintf(stdout, "0x%.2x, ",
				(int) ((int) index(b64table, i) -
				       (int) b64table));


	}
	return 0;*/
	siz = fread(x, 1, sizeof(x), stdin);

      siz = _gnutls_sbase64_encode(x, siz, &b64);
//      siz = _gnutls_sbase64_decode(x, siz, &b64);


	if (siz < 0) {
		fprintf(stderr, "ERROR %d\n", siz);
		exit(1);
	}
	fwrite(b64, siz, 1, stdout);
	return 0;


}
#endif
