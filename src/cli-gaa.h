
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 81 "cli.gaa"
	char **rest_args;
#line 80 "cli.gaa"
	int nrest_args;
#line 70 "cli.gaa"
	char *srp_passwd;
#line 67 "cli.gaa"
	char *srp_username;
#line 64 "cli.gaa"
	char *x509_certfile;
#line 61 "cli.gaa"
	char *x509_keyfile;
#line 58 "cli.gaa"
	char *pgp_certfile;
#line 55 "cli.gaa"
	char *pgp_trustdb;
#line 52 "cli.gaa"
	char *pgp_keyring;
#line 49 "cli.gaa"
	char *pgp_keyfile;
#line 46 "cli.gaa"
	char *x509_cafile;
#line 43 "cli.gaa"
	char **ctype;
#line 42 "cli.gaa"
	int nctype;
#line 39 "cli.gaa"
	char **kx;
#line 38 "cli.gaa"
	int nkx;
#line 35 "cli.gaa"
	char **macs;
#line 34 "cli.gaa"
	int nmacs;
#line 31 "cli.gaa"
	char **comp;
#line 30 "cli.gaa"
	int ncomp;
#line 27 "cli.gaa"
	char **proto;
#line 26 "cli.gaa"
	int nproto;
#line 23 "cli.gaa"
	char **ciphers;
#line 22 "cli.gaa"
	int nciphers;
#line 18 "cli.gaa"
	int record_size;
#line 15 "cli.gaa"
	int port;
#line 12 "cli.gaa"
	int fingerprint;
#line 9 "cli.gaa"
	int fmtder;
#line 6 "cli.gaa"
	int crlf;
#line 3 "cli.gaa"
	int resume;

#line 114 "gaa.skel"
};

#ifdef __cplusplus
extern "C"
{
#endif

    int gaa(int argc, char *argv[], gaainfo *gaaval);

    void gaa_help(void);
    
    int gaa_file(char *name, gaainfo *gaaval);
    
#ifdef __cplusplus
}
#endif


#endif
