
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 103 "cli.gaa"
	char *rest_args;
#line 93 "cli.gaa"
	char *srp_passwd;
#line 90 "cli.gaa"
	char *srp_username;
#line 87 "cli.gaa"
	char *x509_certfile;
#line 84 "cli.gaa"
	char *x509_keyfile;
#line 81 "cli.gaa"
	char *pgp_certfile;
#line 78 "cli.gaa"
	char *pgp_trustdb;
#line 75 "cli.gaa"
	char *pgp_keyring;
#line 72 "cli.gaa"
	char *pgp_keyfile;
#line 69 "cli.gaa"
	char *x509_crlfile;
#line 66 "cli.gaa"
	char *x509_cafile;
#line 63 "cli.gaa"
	char **ctype;
#line 62 "cli.gaa"
	int nctype;
#line 59 "cli.gaa"
	char **kx;
#line 58 "cli.gaa"
	int nkx;
#line 55 "cli.gaa"
	char **macs;
#line 54 "cli.gaa"
	int nmacs;
#line 51 "cli.gaa"
	char **comp;
#line 50 "cli.gaa"
	int ncomp;
#line 47 "cli.gaa"
	char **proto;
#line 46 "cli.gaa"
	int nproto;
#line 43 "cli.gaa"
	char **ciphers;
#line 42 "cli.gaa"
	int nciphers;
#line 38 "cli.gaa"
	int record_size;
#line 35 "cli.gaa"
	int port;
#line 32 "cli.gaa"
	int xml;
#line 29 "cli.gaa"
	int disable_extensions;
#line 26 "cli.gaa"
	int fingerprint;
#line 23 "cli.gaa"
	int fmtder;
#line 20 "cli.gaa"
	int crlf;
#line 17 "cli.gaa"
	int starttls;
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
