
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 75 "cli.gaa"
	char **rest_args;
#line 74 "cli.gaa"
	int nrest_args;
#line 67 "cli.gaa"
	char *srp_passwd;
#line 64 "cli.gaa"
	char *srp_username;
#line 61 "cli.gaa"
	char *x509_certfile;
#line 58 "cli.gaa"
	char *x509_keyfile;
#line 55 "cli.gaa"
	char *pgp_certfile;
#line 52 "cli.gaa"
	char *pgp_trustdb;
#line 49 "cli.gaa"
	char *pgp_keyring;
#line 46 "cli.gaa"
	char *pgp_keyfile;
#line 43 "cli.gaa"
	char *x509_cafile;
#line 40 "cli.gaa"
	char **ctype;
#line 39 "cli.gaa"
	int nctype;
#line 36 "cli.gaa"
	char **kx;
#line 35 "cli.gaa"
	int nkx;
#line 32 "cli.gaa"
	char **macs;
#line 31 "cli.gaa"
	int nmacs;
#line 28 "cli.gaa"
	char **comp;
#line 27 "cli.gaa"
	int ncomp;
#line 24 "cli.gaa"
	char **proto;
#line 23 "cli.gaa"
	int nproto;
#line 20 "cli.gaa"
	char **ciphers;
#line 19 "cli.gaa"
	int nciphers;
#line 15 "cli.gaa"
	int record_size;
#line 12 "cli.gaa"
	int port;
#line 9 "cli.gaa"
	int fingerprint;
#line 6 "cli.gaa"
	int fmtder;
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
