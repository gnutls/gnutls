/*
 *      Copyright (C) 2001 Nikos Mavroyanopoulos
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

#include <config.h>

#ifndef ENABLE_SRP

#include <stdio.h>

int main (int argc, char **argv)
{
    printf ("\nSRP not supported. This program is a dummy.\n\n");
    return 1;
};

#else

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "crypt-gaa.h"
#include <gnutls/gnutls.h>
#include <gnutls/extra.h>
#include <gcrypt.h> /* for randomize */
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


#define _MAX(x,y) (x>y?x:y)

/* This may need some rewrite. A lot of stuff which should be here
 * are in the library, which is not good.
 */

int crypt_int(char *username, char *passwd, int salt,
	      char *tpasswd_conf, char *tpasswd, int uindex);
static int read_conf_values(gnutls_datum * g, gnutls_datum * n, char *str);
static int _verify_passwd_int(char* username, char* passwd, char* verifier, char* salt, 
	const gnutls_datum* g, const gnutls_datum* n);

/* Static parameters according to draft-ietf-tls-srp-05
 */
static const unsigned char srp_params_1024[] = {
 0xEE, 0xAF, 0x0A, 0xB9, 0xAD, 0xB3, 0x8D, 0xD6, 
 0x9C, 0x33, 0xF8, 0x0A, 0xFA, 0x8F, 0xC5, 0xE8, 
 0x60, 0x72, 0x61, 0x87, 0x75, 0xFF, 0x3C, 0x0B,
 0x9E, 0xA2, 0x31, 0x4C, 0x9C, 0x25, 0x65, 0x76,
 0xD6, 0x74, 0xDF, 0x74, 0x96, 0xEA, 0x81, 0xD3,
 0x38, 0x3B, 0x48, 0x13, 0xD6, 0x92, 0xC6, 0xE0,
 0xE0, 0xD5, 0xD8, 0xE2, 0x50, 0xB9, 0x8B, 0xE4,
 0x8E, 0x49, 0x5C, 0x1D, 0x60, 0x89, 0xDA, 0xD1,
 0x5D, 0xC7, 0xD7, 0xB4, 0x61, 0x54, 0xD6, 0xB6,
 0xCE, 0x8E, 0xF4, 0xAD, 0x69, 0xB1, 0x5D, 0x49,
 0x82, 0x55, 0x9B, 0x29, 0x7B, 0xCF, 0x18, 0x85,
 0xC5, 0x29, 0xF5, 0x66, 0x66, 0x0E, 0x57, 0xEC,
 0x68, 0xED, 0xBC, 0x3C, 0x05, 0x72, 0x6C, 0xC0,
 0x2F, 0xD4, 0xCB, 0xF4, 0x97, 0x6E, 0xAA, 0x9A,
 0xFD, 0x51, 0x38, 0xFE, 0x83, 0x76, 0x43, 0x5B,
 0x9F, 0xC6, 0x1D, 0x2F, 0xC0, 0xEB, 0x06, 0xE3
};

static const unsigned char srp_generator = 0x02;

static const unsigned char srp_params_1536[] = {
 0x9D, 0xEF, 0x3C, 0xAF, 0xB9, 0x39, 0x27, 0x7A, 0xB1,
 0xF1, 0x2A, 0x86, 0x17, 0xA4, 0x7B, 0xBB, 0xDB, 0xA5,
 0x1D, 0xF4, 0x99, 0xAC, 0x4C, 0x80, 0xBE, 0xEE, 0xA9,
 0x61, 0x4B, 0x19, 0xCC, 0x4D, 0x5F, 0x4F, 0x5F, 0x55,
 0x6E, 0x27, 0xCB, 0xDE, 0x51, 0xC6, 0xA9, 0x4B, 0xE4,
 0x60, 0x7A, 0x29, 0x15, 0x58, 0x90, 0x3B, 0xA0, 0xD0,
 0xF8, 0x43, 0x80, 0xB6, 0x55, 0xBB, 0x9A, 0x22, 0xE8,
 0xDC, 0xDF, 0x02, 0x8A, 0x7C, 0xEC, 0x67, 0xF0, 0xD0,
 0x81, 0x34, 0xB1, 0xC8, 0xB9, 0x79, 0x89, 0x14, 0x9B,
 0x60, 0x9E, 0x0B, 0xE3, 0xBA, 0xB6, 0x3D, 0x47, 0x54,
 0x83, 0x81, 0xDB, 0xC5, 0xB1, 0xFC, 0x76, 0x4E, 0x3F,
 0x4B, 0x53, 0xDD, 0x9D, 0xA1, 0x15, 0x8B, 0xFD, 0x3E,
 0x2B, 0x9C, 0x8C, 0xF5, 0x6E, 0xDF, 0x01, 0x95, 0x39,
 0x34, 0x96, 0x27, 0xDB, 0x2F, 0xD5, 0x3D, 0x24, 0xB7,
 0xC4, 0x86, 0x65, 0x77, 0x2E, 0x43, 0x7D, 0x6C, 0x7F, 
 0x8C, 0xE4, 0x42, 0x73, 0x4A, 0xF7, 0xCC, 0xB7, 0xAE, 
 0x83, 0x7C, 0x26, 0x4A, 0xE3, 0xA9, 0xBE, 0xB8, 0x7F, 
 0x8A, 0x2F, 0xE9, 0xB8, 0xB5, 0x29, 0x2E, 0x5A, 0x02, 
 0x1F, 0xFF, 0x5E, 0x91, 0x47, 0x9E, 0x8C, 0xE7, 0xA2, 
 0x8C, 0x24, 0x42, 0xC6, 0xF3, 0x15, 0x18, 0x0F, 0x93, 
 0x49, 0x9A, 0x23, 0x4D, 0xCF, 0x76, 0xE3, 0xFE, 0xD1, 
 0x35, 0xF9, 0xBB
};

static const unsigned char srp_params_2048[] = {
 0xAC, 0x6B, 0xDB, 0x41, 0x32, 0x4A, 0x9A, 0x9B, 0xF1,
 0x66, 0xDE, 0x5E, 0x13, 0x89, 0x58, 0x2F, 0xAF, 0x72,
 0xB6, 0x65, 0x19, 0x87, 0xEE, 0x07, 0xFC, 0x31, 0x92,
 0x94, 0x3D, 0xB5, 0x60, 0x50, 0xA3, 0x73, 0x29, 0xCB,
 0xB4, 0xA0, 0x99, 0xED, 0x81, 0x93, 0xE0, 0x75, 0x77, 
 0x67, 0xA1, 0x3D, 0xD5, 0x23, 0x12, 0xAB, 0x4B, 0x03,
 0x31, 0x0D, 0xCD, 0x7F, 0x48, 0xA9, 0xDA, 0x04, 0xFD,
 0x50, 0xE8, 0x08, 0x39, 0x69, 0xED, 0xB7, 0x67, 0xB0,
 0xCF, 0x60, 0x95, 0x17, 0x9A, 0x16, 0x3A, 0xB3, 0x66,
 0x1A, 0x05, 0xFB, 0xD5, 0xFA, 0xAA, 0xE8, 0x29, 0x18,
 0xA9, 0x96, 0x2F, 0x0B, 0x93, 0xB8, 0x55, 0xF9, 0x79,
 0x93, 0xEC, 0x97, 0x5E, 0xEA, 0xA8, 0x0D, 0x74, 0x0A,
 0xDB, 0xF4, 0xFF, 0x74, 0x73, 0x59, 0xD0, 0x41, 0xD5,
 0xC3, 0x3E, 0xA7, 0x1D, 0x28, 0x1E, 0x44, 0x6B, 0x14,
 0x77, 0x3B, 0xCA, 0x97, 0xB4, 0x3A, 0x23, 0xFB, 0x80,
 0x16, 0x76, 0xBD, 0x20, 0x7A, 0x43, 0x6C, 0x64, 0x81,
 0xF1, 0xD2, 0xB9, 0x07, 0x87, 0x17, 0x46, 0x1A, 0x5B,
 0x9D, 0x32, 0xE6, 0x88, 0xF8, 0x77, 0x48, 0x54, 0x45,
 0x23, 0xB5, 0x24, 0xB0, 0xD5, 0x7D, 0x5E, 0xA7, 0x7A,
 0x27, 0x75, 0xD2, 0xEC, 0xFA, 0x03, 0x2C, 0xFB, 0xDB,
 0xF5, 0x2F, 0xB3, 0x78, 0x61, 0x60, 0x27, 0x90, 0x04,
 0xE5, 0x7A, 0xE6, 0xAF, 0x87, 0x4E, 0x73, 0x03, 0xCE,
 0x53, 0x29, 0x9C, 0xCC, 0x04, 0x1C, 0x7B, 0xC3, 0x08,
 0xD8, 0x2A, 0x56, 0x98, 0xF3, 0xA8, 0xD0, 0xC3, 0x82,
 0x71, 0xAE, 0x35, 0xF8, 0xE9, 0xDB, 0xFB, 0xB6, 0x94,
 0xB5, 0xC8, 0x03, 0xD8, 0x9F, 0x7A, 0xE4, 0x35, 0xDE,
 0x23, 0x6D, 0x52, 0x5F, 0x54, 0x75, 0x9B, 0x65, 0xE3,
 0x72, 0xFC, 0xD6, 0x8E, 0xF2, 0x0F, 0xA7, 0x11, 0x1F,
 0x9E, 0x4A, 0xFF, 0x73
};

static void print_num( const char* msg, const gnutls_datum * num)
{
unsigned int i;

	printf( "%s:\t", msg);

	for (i=0;i<num->size;i++) {
		if (i!=0 && i%12==0) printf("\n\t");
		else if (i!=0 && i!=num->size) printf( ":");
		printf( "%.2x", num->data[i]);
	}
	printf("\n\n");

}

int generate_create_conf(char *tpasswd_conf)
{
	FILE *fd;
	char line[5 * 1024];
	int index = 1;
	gnutls_datum g, n;
	gnutls_datum str_g, str_n;

	fd = fopen(tpasswd_conf, "w");
	if (fd == NULL) {
		fprintf(stderr, "Cannot open file '%s'\n", tpasswd_conf);
		return -1;
	}

	for (index = 1; index <= 3; index++) {

		g.data = (void*) &srp_generator;
		g.size = 1;
	
		if (index == 1) {
			n.data = (void*) srp_params_1024;
			n.size = sizeof(srp_params_1024);
		} else if (index==2) {
			n.data = (void*) srp_params_1536;
			n.size = sizeof(srp_params_1536);
		} else {
			n.data = (void*) srp_params_2048;
			n.size = sizeof(srp_params_2048);
		}

		print_num("Generator", &g);
		print_num("Prime", &n);

		if (gnutls_srp_base64_encode_alloc( &n, &str_n) < 0) {
			fprintf(stderr, "Could not encode\n");
			return -1;
		}

		if (gnutls_srp_base64_encode_alloc( &g, &str_g) < 0) {
			fprintf(stderr, "Could not encode\n");
			return -1;
		}
	
		sprintf(line, "%d:%s:%s\n", index, str_n.data, str_g.data);
	
		gnutls_free( str_n.data);
		gnutls_free( str_g.data);

		fwrite(line, 1, strlen(line), fd);

	}

	fclose(fd);
	
	return 0;

}

/* The format of a tpasswd file is:
 * username:verifier:salt:index
 *
 * index is the index of the prime-generator pair in tpasswd.conf
 */
static int _verify_passwd_int(char* username, char* passwd, char* verifier, 
	char* salt, const gnutls_datum* g, const gnutls_datum* n) 
{
char _salt[1024];
gnutls_datum tmp, raw_salt, new_verifier;
int salt_size;
char *pos;

	if (salt==NULL || verifier==NULL) return -1;

	/* copy salt, and null terminate after the ':' */
	strcpy( _salt, salt);
	pos = index(_salt, ':');
	if (pos!=NULL) *pos = 0;

	/* convert salt to binary. */
	tmp.data = _salt;
	tmp.size = strlen(_salt);

	if (gnutls_srp_base64_decode_alloc( &tmp, &raw_salt) < 0) {
		fprintf(stderr, "Could not decode salt.\n");
		return -1;
	}

	if (gnutls_srp_verifier( username, passwd, &raw_salt, g, n, &new_verifier) < 0)
	{
		fprintf(stderr, "Could not make the verifier\n");
		return -1;
	}
	
	free( raw_salt.data);
	
	/* encode the verifier into _salt */
	salt_size = sizeof(_salt);
	if (gnutls_srp_base64_encode( &new_verifier, _salt, &salt_size) < 0) {
		fprintf(stderr, "Encoding error\n");
		return -1;
	}
	
	free( new_verifier.data);

	if (strncmp( verifier, _salt, strlen(_salt))==0) {
		fprintf(stderr, "Password verified\n");
		return 0;
	} else {
		fprintf(stderr,
			"Password does NOT match\n");
	}
	return -1;
}

static int filecopy( char* src, char* dst) {
FILE *fd, *fd2;
char line[5*1024];
char *p;

		fd = fopen(dst, "w");
		if (fd == NULL) {
			fprintf(stderr, "Cannot open '%s' for write\n",
				dst);
			return -1;
		}

		fd2 = fopen(src, "r");
		if (fd2 == NULL) {
			/* empty file */
			fclose(fd);
			return 0;
		}

		line[sizeof(line)-1] = 0;
		do {
			p = fgets( line, sizeof(line)-1, fd2);
			if (p==NULL) break;
			
			fputs( line, fd);
		} while(1);

		fclose(fd);
		fclose(fd2);

		return 0;	
}

/* accepts password file */
static int find_index(char* username, char* file) {
FILE * fd;
char *pos;
char line[5*1024];
unsigned int i;

	fd = fopen(file, "r");
	if (fd == NULL) {
		fprintf(stderr, "Cannot open file '%s'\n", file);
		return -1;
	}

	while (fgets(line, sizeof(line), fd) != NULL) {
		/* move to first ':' */
		i = 0;
		while ((line[i] != ':') && (line[i] != '\0')
		       && (i < sizeof(line))) {
			i++;
		}
		if (strncmp(username, line, _MAX(i,strlen(username)) )  == 0) {
			/* find the index */
			pos = rindex(line, ':');
			pos++;
			fclose(fd);
			return atoi(pos);
		}
	}

	fclose(fd);
	return -1;
}

/* Parses the tpasswd files, in order to verify the given
 * username/password pair.
 */
int verify_passwd(char *conffile, char *tpasswd, char *username, char *passwd)
{
	FILE *fd;
	char line[5 * 1024];
	unsigned int i;
	gnutls_datum g, n;
	int iindex;
	char *p, *pos;

	iindex = find_index( username, tpasswd);
	if (iindex==-1) {
		fprintf(stderr, "Cannot find '%s' in %s\n", username, tpasswd);
		return -1;
	}
	
	fd = fopen(conffile, "r");
	if (fd == NULL) {
		fprintf(stderr, "Cannot find %s\n", conffile);
		return -1;
	}

	do {
		p = fgets(line, sizeof(line) - 1, fd);
	} while(p!=NULL && atoi(p)!=iindex);
	
	if (p == NULL) {
		fprintf(stderr, "Cannot find entry in %s\n", conffile);
		return -1;
	}
	line[sizeof(line) - 1] = 0;

	fclose(fd);

	if ((iindex = read_conf_values(&g, &n, line)) < 0) {
		fprintf(stderr, "Cannot parse conf file '%s'\n", conffile);
		return -1;
	}

	fd = fopen(tpasswd, "r");
	if (fd == NULL) {
		fprintf(stderr, "Cannot open file '%s'\n", tpasswd);
		return -1;
	}

	while (fgets(line, sizeof(line), fd) != NULL) {
		/* move to first ':' 
		 * This is the actual verifier.
		 */
		i = 0;
		while ((line[i] != ':') && (line[i] != '\0')
		       && (i < sizeof(line))) {
			i++;
		}
		if (strncmp(username, line, _MAX(i,strlen(username)) )  == 0) {
			char* verifier_pos, *salt_pos;

			pos = index(line, ':');
			fclose(fd);
			if (pos==NULL) {
				fprintf(stderr, "Cannot parse conf file '%s'\n", conffile);
				return -1;
			}
			pos++;
			verifier_pos = pos;

			/* Move to the salt */
			pos = index(pos, ':');
			if (pos==NULL) {
				fprintf(stderr, "Cannot parse conf file '%s'\n", conffile);
				return -1;
			}
			pos++;
			salt_pos = pos;
			
			return _verify_passwd_int( username, passwd, 
				verifier_pos, salt_pos, &g, &n);
		}
	}

	fclose(fd);
	return -1;

}

#define KPASSWD "/etc/tpasswd"
#define KPASSWD_CONF "/etc/tpasswd.conf"

int main(int argc, char **argv)
{
	gaainfo info;
	char *passwd;
	int salt;
	struct passwd *pwd;

	gnutls_global_init();
	gnutls_global_init_extra();
	
	if (gaa(argc, argv, &info) != -1) {
		fprintf(stderr, "Error in the arguments.\n");
		return -1;
	}

	salt = info.salt;

	if (info.create_conf != NULL) {
		return generate_create_conf(info.create_conf);
	}

	if (info.passwd == NULL)
		info.passwd = KPASSWD;
	if (info.passwd_conf == NULL)
		info.passwd_conf = KPASSWD_CONF;

	if (info.username == NULL) {
		pwd = getpwuid(getuid());

		if (pwd == NULL) {
			fprintf(stderr, "No such user\n");
			return -1;
		}

		info.username = pwd->pw_name;
	}

	salt = 16;

	passwd = getpass("Enter password: ");

/* not ready yet */
	if (info.verify != 0) {
		return verify_passwd(info.passwd_conf, info.passwd,
				     info.username, passwd);
	}


	return crypt_int(info.username, passwd, salt,
			 info.passwd_conf, info.passwd, info.index);

}

char* _srp_crypt( char* username, char* passwd, int salt_size, 
	const gnutls_datum* g,  const gnutls_datum* n)
{
char salt[128];
static char result[1024];
gnutls_datum dat_salt, txt_salt;
gnutls_datum verifier, txt_verifier;

	if ((unsigned)salt_size > sizeof(salt))
		return NULL;

	/* generate the salt */
	gcry_randomize( salt, salt_size, GCRY_WEAK_RANDOM);

	dat_salt.data = salt;
	dat_salt.size = salt_size;

	if (gnutls_srp_verifier( username, passwd, &dat_salt, g, n, &verifier) < 0) {
		fprintf(stderr, "Error getting verifier\n");
		return NULL;
	}
	
	/* base64 encode the verifier */
	if (gnutls_srp_base64_encode_alloc( &verifier, &txt_verifier) < 0) {
		fprintf(stderr, "Error encoding\n");
		free( verifier.data);
		return NULL;
	}

	free( verifier.data);

	if (gnutls_srp_base64_encode_alloc( &dat_salt, &txt_salt) < 0) {
		fprintf(stderr, "Error encoding\n");
		return NULL;
	}

	sprintf( result, "%s:%s", txt_verifier.data, txt_salt.data);
	free(txt_salt.data);
	free(txt_verifier.data);
	
	return result;
	
}


int crypt_int(char *username, char *passwd, int salt_size,
	      char *tpasswd_conf, char *tpasswd, int uindex)
{
	FILE *fd;
	char *cr;
	gnutls_datum g, n;
	char line[5 * 1024];
	char *p, *pp;
	int iindex;
	char tmpname[1024];

	fd = fopen(tpasswd_conf, "r");
	if (fd == NULL) {
		fprintf(stderr, "Cannot find %s\n", tpasswd_conf);
		return -1;
	}

	do { /* find the specified uindex in file */
		p = fgets(line, sizeof(line) - 1, fd);
		iindex = atoi(p);
	} while( p!=NULL && iindex!=uindex);

	if (p == NULL) {
		fprintf(stderr, "Cannot find entry in %s\n", tpasswd_conf);
		return -1;
	}
	line[sizeof(line) - 1] = 0;

	fclose(fd);
	if ((iindex = read_conf_values(&g, &n, line)) < 0) {
		fprintf(stderr, "Cannot parse conf file '%s'\n",
			tpasswd_conf);
		return -1;
	}

	cr = _srp_crypt(username, passwd, salt_size, &g, &n);
	if (cr == NULL) {
		fprintf(stderr, "Cannot _srp_crypt()...\n");
		return -1;
	} else {
		/* delete previous entry */
		struct stat st;
		FILE * fd2;
		int put;

		if (strlen(tpasswd) > sizeof(tmpname)+5) {
			fprintf(stderr, "file '%s' is tooooo long\n", tpasswd);
			return -1;
		}
		strcpy( tmpname, tpasswd);
		strcat( tmpname, ".tmp");

		if ( stat( tmpname, &st) != -1) {
			fprintf(stderr, "file '%s' is locked\n", tpasswd);
			return -1;
		}

		if (filecopy( tpasswd, tmpname)!=0) {
			fprintf(stderr, "Cannot copy '%s' to '%s'\n",
				tpasswd, tmpname);
			return -1;
		}
		
		fd = fopen(tpasswd, "w");
		if (fd == NULL) {
			fprintf(stderr, "Cannot open '%s' for write\n",
				tpasswd);
			remove(tmpname);
			return -1;
		}

		fd2 = fopen(tmpname, "r");
		if (fd2 == NULL) {
			fprintf(stderr, "Cannot open '%s' for read\n",
				tmpname);
			remove(tmpname);
			return -1;
		}

		put = 0;
		do {
			p = fgets( line, sizeof(line)-1, fd2);
			if (p==NULL) break;
			
			pp = index( line, ':');
			if (pp==NULL) continue;
			
			if ( strncmp( p, username, _MAX(strlen(username), (unsigned int)(pp-p)) ) == 0 ) {
				put = 1;
				fprintf(fd, "%s:%s:%u\n", username, cr, iindex);
			} else {
				fputs( line, fd);
			}
		} while(1);

		if (put==0) {
			fprintf(fd, "%s:%s:%u\n", username, cr, iindex);
		}
		
		fclose(fd);
		fclose(fd2);

		remove(tmpname);

	}


	return 0;
}



/* this function parses tpasswd.conf file. Format is:
 * int(index):base64(n):base64(g)
 */
static int read_conf_values(gnutls_datum * g, gnutls_datum * n, char *str)
{
	char *p;
	int len;
	int index, ret;
	gnutls_datum dat;

	index = atoi(str);

	p = rindex(str, ':');	/* we have g */
	if (p == NULL) {
		return -1;
	}

	*p = '\0';
	p++;

	/* read the generator */
	len = strlen(p);
	if (p[len-1]=='\n') len--;
	
	dat.data = p;
	dat.size = len;
	ret = gnutls_srp_base64_decode_alloc(&dat, g);

	if (ret < 0) {
		fprintf(stderr, "Decoding error\n");
		return -1;
	}

	/* now go for n - modulo */
	p = rindex(str, ':');	/* we have n */
	if (p == NULL) {
		return -1;
	}

	*p = '\0';
	p++;

	dat.data = p;
	dat.size = strlen(p);

	ret = gnutls_srp_base64_decode_alloc(&dat, n);

	if (ret < 0) {
		fprintf(stderr, "Decoding error\n");
		free(g->data);
		return -1;
	}

	return index;
}

#endif /* ENABLE_SRP */
