
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 109 "cli.gaa"
	char *rest_args;
#line 99 "cli.gaa"
	char *srp_passwd;
#line 96 "cli.gaa"
	char *srp_username;
#line 93 "cli.gaa"
	char *x509_certfile;
#line 90 "cli.gaa"
	char *x509_keyfile;
#line 87 "cli.gaa"
	char *pgp_certfile;
#line 84 "cli.gaa"
	char *pgp_trustdb;
#line 81 "cli.gaa"
	char *pgp_keyring;
#line 78 "cli.gaa"
	char *pgp_keyfile;
#line 75 "cli.gaa"
	char *x509_crlfile;
#line 72 "cli.gaa"
	char *x509_cafile;
#line 69 "cli.gaa"
	char **ctype;
#line 68 "cli.gaa"
	int nctype;
#line 65 "cli.gaa"
	char **kx;
#line 64 "cli.gaa"
	int nkx;
#line 61 "cli.gaa"
	char **macs;
#line 60 "cli.gaa"
	int nmacs;
#line 57 "cli.gaa"
	char **comp;
#line 56 "cli.gaa"
	int ncomp;
#line 53 "cli.gaa"
	char **proto;
#line 52 "cli.gaa"
	int nproto;
#line 49 "cli.gaa"
	char **ciphers;
#line 48 "cli.gaa"
	int nciphers;
#line 44 "cli.gaa"
	int record_size;
#line 41 "cli.gaa"
	int port;
#line 38 "cli.gaa"
	int print_cert;
#line 35 "cli.gaa"
	int xml;
#line 32 "cli.gaa"
	int disable_extensions;
#line 29 "cli.gaa"
	int fingerprint;
#line 26 "cli.gaa"
	int fmtder;
#line 23 "cli.gaa"
	int crlf;
#line 20 "cli.gaa"
	int starttls;
#line 17 "cli.gaa"
	int resume;
#line 14 "cli.gaa"
	int debug;

#line 114 "gaa.skel"
};

#ifdef __cplusplus
extern "C"
{
#endif

    int gaa(int argc, char *argv[], gaainfo *gaaval);

    void gaa_help(void);
    
    int gaa_file(const char *name, gaainfo *gaaval);
    
#ifdef __cplusplus
}
#endif


#endif
