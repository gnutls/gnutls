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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "../lib/defines.h"
#include "../lib/gnutls_int.h"
#include "../libextra/gnutls_srp.h"
#include "../libextra/crypt.h"
#include "../lib/gnutls_mem.h"
#include "../libextra/auth_srp_passwd.h"
#include "crypt-gaa.h"
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>

#define _MAX(x,y) x>y?x:y

/* This may need some rewrite. A lot of stuff which should be here
 * are in the library, which is not good.
 */

int crypt_int(char *username, char *passwd, int crypt, int salt,
	      char *tpasswd_conf, char *tpasswd, int uindex);
static int read_conf_values(MPI * g, MPI * n, char *str, int str_size);
static int _verify_passwd_int(char* username, char* passwd, char* salt, MPI g, MPI n);

int _gnutls_srp_generate_prime(unsigned char ** ret_g, unsigned char ** ret_n, int bits);

int generate_create_conf(char *tpasswd_conf, int bits)
{
	FILE *fd;
	char line[5 * 1024];
	int index = 1;
	unsigned char *g, *n;

	fd = fopen(tpasswd_conf, "w");
	if (fd == NULL) {
		fprintf(stderr, "Cannot open file '%s'\n", tpasswd_conf);
		return -1;
	}

	_gnutls_srp_generate_prime(&g, &n, bits);
	sprintf(line, "%d:%s:%s\n", index, n, g);

	fwrite(line, 1, strlen(line), fd);

	fclose(fd);
	return 0;

}

static int _verify_passwd_int(char* username, char* passwd, char* salt, MPI g, MPI n) {
	if (salt==NULL) return -1;

	if (gnutls_crypt_vrfy
	    (username, passwd, salt, g, n) == 0) {
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
int i;

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

int verify_passwd(char *conffile, char *tpasswd, char *username, char *passwd)
{
	FILE *fd;
	char line[5 * 1024];
	int i;
	MPI g, n;
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

	if ((iindex = read_conf_values(&g, &n, line, strlen(line))) < 0) {
		fprintf(stderr, "Cannot parse conf file '%s'\n", conffile);
		return -1;
	}


	fd = fopen(tpasswd, "r");
	if (fd == NULL) {
		fprintf(stderr, "Cannot open file '%s'\n", tpasswd);
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
			pos = index(line, ':');
			fclose(fd);
			if (pos==NULL) {
				fprintf(stderr, "Cannot parse conf file '%s'\n", conffile);
				return -1;
			}
			pos++;
			return _verify_passwd_int( username, passwd, pos, g, n);
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
	int crypt, salt;
	struct passwd *pwd;

	if (gaa(argc, argv, &info) != -1) {
		fprintf(stderr, "Error in the arguments.\n");
		return -1;
	}

	salt = info.salt;

	if (info.create_conf != NULL) {
		return generate_create_conf(info.create_conf, info.bits);
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

	if (info.crypt == NULL) {
		crypt = SRPSHA1_CRYPT;
		salt = 16;
	} else {
		if (strcasecmp(info.crypt, "bcrypt") == 0) {
			crypt = BLOWFISH_CRYPT;
			if (salt == 0)
				salt = 6;	/* cost is 6 */
		} else if (strcasecmp(info.crypt, "srpsha") == 0) {
			crypt = SRPSHA1_CRYPT;
			if (salt == 0)
				salt = 10;	/* 10 bytes salt */
		} else {
			fprintf(stderr, "Unknown algorithm\n");
			return -1;
		}
	}

	passwd = getpass("Enter password: ");

/* not ready yet */
	if (info.verify != 0) {
		return verify_passwd(info.passwd_conf, info.passwd,
				     info.username, passwd);
	}


	return crypt_int(info.username, passwd, crypt, salt,
			 info.passwd_conf, info.passwd, info.index);

}

int crypt_int(char *username, char *passwd, int crypt, int salt,
	      char *tpasswd_conf, char *tpasswd, int uindex)
{
	FILE *fd;
	char *cr;
	MPI g, n;
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
	if ((iindex = read_conf_values(&g, &n, line, strlen(line))) < 0) {
		fprintf(stderr, "Cannot parse conf file '%s'\n",
			tpasswd_conf);
		return -1;
	}

	cr = gnutls_crypt(username, passwd, crypt, salt, g, n);
	if (cr == NULL) {
		fprintf(stderr, "Cannot gnutls_crypt()...\n");
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
			
			if ( strncmp( p, username, _MAX(strlen(username), (int)(pp-p)) ) == 0 ) {
				put = 1;
				fprintf(fd, "%s:%s:%u\n", username, cr, iindex);
			} else {
				fputs( line, fd);
			}
		} while(1);

		if (put==0) {
			fprintf(fd, "%s:%s:%u\n", username, cr, iindex);
		}
		gnutls_free(cr);
		
		fclose(fd);
		fclose(fd2);

		remove(tmpname);

	}


	return 0;
}



/* this function parses tpasswd.conf file. Format is:
 * int(index):base64(n):base64(g)
 */
static int read_conf_values(MPI * g, MPI * n, char *str, int str_size)
{
	char *p;
	int len;
	opaque *tmp;
	int tmp_size;
	int index;

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
	tmp_size = _gnutls_sbase64_decode(p, len, &tmp);

	if (tmp_size < 0) {
		return -1;
	}
	if (gcry_mpi_scan(g, GCRYMPI_FMT_USG, tmp, &tmp_size)) {
		gnutls_free(tmp);
		return -1;
	}

	gnutls_free(tmp);


	/* now go for n - modulo */
	p = rindex(str, ':');	/* we have n */
	if (p == NULL) {
		return -1;
	}

	*p = '\0';
	p++;

	len = strlen(p);
	tmp_size = _gnutls_sbase64_decode(p, len, &tmp);

	if (tmp_size < 0) {
		gnutls_free(tmp);
		return -1;
	}
	if (gcry_mpi_scan(n, GCRYMPI_FMT_USG, tmp, &tmp_size)) {
		gnutls_free(tmp);
		return -1;
	}

	gnutls_free(tmp);

	return index;
}
