
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 92 "cli.gaa"
	char **rest_args;
#line 91 "cli.gaa"
	int nrest_args;
#line 81 "cli.gaa"
	char *srp_passwd;
#line 78 "cli.gaa"
	char *srp_username;
#line 75 "cli.gaa"
	char *x509_certfile;
#line 72 "cli.gaa"
	char *x509_keyfile;
#line 69 "cli.gaa"
	char *pgp_certfile;
#line 66 "cli.gaa"
	char *pgp_trustdb;
#line 63 "cli.gaa"
	char *pgp_keyring;
#line 60 "cli.gaa"
	char *pgp_keyfile;
#line 57 "cli.gaa"
	char *x509_cafile;
#line 54 "cli.gaa"
	char **ctype;
#line 53 "cli.gaa"
	int nctype;
#line 50 "cli.gaa"
	char **kx;
#line 49 "cli.gaa"
	int nkx;
#line 46 "cli.gaa"
	char **macs;
#line 45 "cli.gaa"
	int nmacs;
#line 42 "cli.gaa"
	char **comp;
#line 41 "cli.gaa"
	int ncomp;
#line 38 "cli.gaa"
	char **proto;
#line 37 "cli.gaa"
	int nproto;
#line 34 "cli.gaa"
	char **ciphers;
#line 33 "cli.gaa"
	int nciphers;
#line 29 "cli.gaa"
	int record_size;
#line 26 "cli.gaa"
	int port;
#line 23 "cli.gaa"
	int fingerprint;
#line 20 "cli.gaa"
	int fmtder;
#line 17 "cli.gaa"
	int crlf;
#line 14 "cli.gaa"
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
