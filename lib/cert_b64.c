/*
 * Copyright (C) 2000,2001 Nikos Mavroyanopoulos <nmav@hellug.gr>
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

#include "gnutls_int.h"
#include "gnutls_errors.h"

const static uint8 b64table[64] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const static uint8 asciitable[128] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f,
	0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
	0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff,
	0xff, 0xf1, 0xff, 0xff, 0xff, 0x00,	/* 0xf1 for '=' */
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
	0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
	0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
	0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
	0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
	0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
	0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
	0x31, 0x32, 0x33, 0xff, 0xff, 0xff,
	0xff, 0xff
};

inline static int encode(uint8 * result, const uint8 * data, int left)
{

	int data_len;

	if (left > 3)
		data_len = 3;
	else
		data_len = left;

	switch (data_len) {
	case 3:
		result[0] = b64table[(data[0] >> 2)];
		result[1] =
		    b64table[(((((data[0] & 0x03) & 0xff) << 4) & 0xff) |
			      (data[1] >> 4))];
		result[2] =
		    b64table[((((data[1] & 0x0f) << 2) & 0xff) |
			      (data[2] >> 6))];
		result[3] = b64table[(((data[2] << 2) & 0xff) >> 2)];
		break;
	case 2:
		result[0] = b64table[(data[0] >> 2)];
		result[1] =
		    b64table[(((((data[0] & 0x03) & 0xff) << 4) & 0xff) |
			      (data[1] >> 4))];
		result[2] = b64table[(((data[1] << 4) & 0xff) >> 2)];
		result[3] = '=';
		break;
	case 1:
		result[0] = b64table[(data[0] >> 2)];
		result[1] =
		    b64table[(((((data[0] & 0x03) & 0xff) << 4) & 0xff))];
		result[2] = '=';
		result[3] = '=';
		break;
	default:
		return -1;
	}

	return 4;

}

/* data must be 4 bytes
 * result should be 3 bytes
 */
#define TOASCII(c) (c < 127 ? asciitable[c] : 0xff)
inline static int decode(uint8 * result, const uint8 * data)
{
	uint8 a1, a2;
	int ret = 3;

	a1 = TOASCII(data[0]);
	a2 = TOASCII(data[1]);
	if (a1 == 0xff || a2 == 0xff)
		return -1;
	result[0] = ((a1 << 2) & 0xff) | ((a2 >> 4) & 0xff);

	a1 = a2;
	a2 = TOASCII(data[2]);
	if (a2 == 0xff)
		return -1;
	result[1] = ((a1 << 4) & 0xff) | ((a2 >> 2) & 0xff);

	a1 = a2;
	a2 = TOASCII(data[3]);
	if (a2 == 0xff)
		return -1;
	result[2] = ((a1 << 6) & 0xff) | (a2 & 0xff);

	if (data[2] == '=')
		ret--;

	if (data[3] == '=')
		ret--;
	return ret;
}

/* encodes data and puts the result into result (localy alocated)
 * The result_size is the return value
 */
int _gnutls_base64_encode(uint8 * data, int data_size, uint8 ** result)
{
	int i, ret, tmp, j;
	char tmpres[4];

	ret = data_size % 3;
	if (ret != 0)
		ret = 4;
	else
		ret = 0;

	ret += (data_size / 3) * 4;

	(*result) = gnutls_malloc(ret + 1);
	if ((*result) == NULL)
		return -1;

	for (i = j = 0; i < data_size; i += 3, j += 4) {
		tmp = encode(tmpres, &data[i], data_size - i);
		if (tmp == -1) {
			gnutls_free( (*result));
			return -1;
		}
		memcpy(&(*result)[j], tmpres, tmp);
	}
	(*result)[ret] = 0;	/* null terminated */

	return ret;
}

/* encodes data and puts the result into result (localy alocated)
 * The result_size is the return value
 */
int _gnutls_fbase64_encode(char *msg, uint8 * data, int data_size,
			   uint8 ** result)
{
	int i, ret, tmp, j;
	char tmpres[4];
	uint8 *ptr;
	uint8 top[80];
	uint8 bottom[80];
	int pos;

	memset(bottom, 0, sizeof(bottom));
	memset(top, 0, sizeof(top));

	if (strlen(msg) > 50)
		return -1;

	strcat(top, "-----BEGIN ");
	strcat(top, msg);
	strcat(top, "-----");

	strcat(bottom, "\n-----END ");
	strcat(bottom, msg);
	strcat(bottom, "-----\n");

	ret = data_size % 3;
	if (ret != 0)
		ret = 4;
	else
		ret = 0;

	ret += strlen(top) + strlen(bottom);

	tmp = (data_size / 3) * 4;
	ret += (tmp / 64) + (tmp % 64 > 0 ? 1 : 0);	/* add new lines */
	ret += tmp;

	(*result) = gnutls_calloc(1, ret + 1);
	if ((*result) == NULL)
		return -1;

	strcat(*result, top);
	pos = strlen(top);

	for (i = j = 0; i < data_size; i += 3, j += 4) {
		tmp = encode(tmpres, &data[i], data_size - i);
		if (tmp == -1) {
			gnutls_free( (*result));
			return -1;
		}
		ptr = &(*result)[j + pos];

		if ((j) % 64 == 0) {
			pos++;
			*ptr++ = '\n';
		}
		*ptr++ = tmpres[0];

		if ((j + 1) % 64 == 0) {
			*ptr++ = '\n';
			pos++;
		}
		*ptr++ = tmpres[1];

		if ((j + 2) % 64 == 0) {
			pos++;
			*ptr++ = '\n';
		}
		*ptr++ = tmpres[2];

		if ((j + 3) % 64 == 0) {
			*ptr++ = '\n';
			pos++;
		}
		*ptr++ = tmpres[3];
	}

	strcat(*result, bottom);
	return ret;
}


/* decodes data and puts the result into result (localy alocated)
 * The result_size is the return value
 */
int _gnutls_base64_decode(uint8 * data, int data_size, uint8 ** result)
{
	int i, ret, tmp, j;
	uint8 tmpres[3];

	data_size /= 4;
	data_size *= 4;

	ret = data_size / 4 * 3;
	(*result) = gnutls_malloc(ret+1);
	if ((*result) == NULL)
		return -1;

	for (i = j = 0; i < data_size; i += 4) {
		tmp = decode(tmpres, &data[i]);
		if (tmp < 0) {
			gnutls_free( *result);
			return tmp;
		}
		memcpy(&(*result)[j], tmpres, tmp);
		if (tmp < 3)
			ret -= (3 - tmp);
		j += 3;
	}
	return ret;
}

/* copies data to result but removes newlines and <CR>
 * returns the size of the data copied.
 */
inline static int cpydata(uint8 * data, int data_size, uint8 ** result)
{
	int i, j;

	(*result) = gnutls_malloc(data_size);
	if (*result == NULL)
		return -1;

	for (j = i = 0; i < data_size; i++) {
		if (data[i] == '\n' || data[i] == '\r')
			continue;
		(*result)[j] = data[i];
		j++;
	}
	return j;
}

/* decodes data and puts the result into result (localy alocated)
 * The result_size is the return value
 * FIXME: This function is a mess
 */
#define ENDSTR "-----\n"
int _gnutls_fbase64_decode( uint8 * data, int data_size,
			   uint8 ** result)
{
	int i, ret;
	char top[80];
	char bottom[80];
	uint8 *rdata;
	int rdata_size;
	uint8 *kdata;
	int kdata_size;

	strcpy(top, "-----BEGIN ");

	strcpy(bottom, "\n-----END ");

	i = 0;
	do {
		rdata = &data[i];
		data_size --;
		i++;
	} while (data_size > 0 && strncmp(rdata, top, strlen(top)) != 0);

	if (data_size < 4 + strlen(bottom)) {
		gnutls_assert();
		return -1;
	}
	
	do {
		data_size--;
		rdata++;
	} while( ( strncmp( rdata, ENDSTR, strlen(ENDSTR)) != 0) && data_size > 0) ;

	data_size -= strlen(ENDSTR);
	rdata += strlen(ENDSTR);

	rdata_size = 0;
	do {
		rdata_size++;
	} while (rdata_size < data_size
		 && strncmp(&rdata[rdata_size], bottom, strlen(bottom)) != 0);

	if (rdata_size < 4) {
		gnutls_assert();
		return -1;
	}

	kdata_size = cpydata(rdata, rdata_size, &kdata);

	if (kdata_size < 4) {
		gnutls_assert();
		return -1;
	}

	if ((ret = _gnutls_base64_decode( kdata, kdata_size, result)) < 0) {
		gnutls_assert();
		gnutls_free(kdata);
		return GNUTLS_E_PARSING_ERROR;
	} 
	gnutls_free(kdata);
	return ret;
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

//      siz = _gnutls_fbase64_encode("CERTIFICATE", x, siz, &b64);
      siz = _gnutls_base64_encode(x, siz, &b64);
//      siz = _gnutls_base64_decode(x, siz, &b64);
//	siz = _gnutls_fbase64_decode("CERTIFICATE", x, siz, &b64);


	if (siz < 0) {
		fprintf(stderr, "ERROR %d\n", siz);
		exit(1);
	}
	fwrite(b64, siz, 1, stdout);
	return 0;


}
#endif
