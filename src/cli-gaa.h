
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 97 "cli.gaa"
	char *rest_args;
#line 87 "cli.gaa"
	char *srp_passwd;
#line 84 "cli.gaa"
	char *srp_username;
#line 81 "cli.gaa"
	char *x509_certfile;
#line 78 "cli.gaa"
	char *x509_keyfile;
#line 75 "cli.gaa"
	char *pgp_certfile;
#line 72 "cli.gaa"
	char *pgp_trustdb;
#line 69 "cli.gaa"
	char *pgp_keyring;
#line 66 "cli.gaa"
	char *pgp_keyfile;
#line 63 "cli.gaa"
	char *x509_cafile;
#line 60 "cli.gaa"
	char **ctype;
#line 59 "cli.gaa"
	int nctype;
#line 56 "cli.gaa"
	char **kx;
#line 55 "cli.gaa"
	int nkx;
#line 52 "cli.gaa"
	char **macs;
#line 51 "cli.gaa"
	int nmacs;
#line 48 "cli.gaa"
	char **comp;
#line 47 "cli.gaa"
	int ncomp;
#line 44 "cli.gaa"
	char **proto;
#line 43 "cli.gaa"
	int nproto;
#line 40 "cli.gaa"
	char **ciphers;
#line 39 "cli.gaa"
	int nciphers;
#line 35 "cli.gaa"
	int record_size;
#line 32 "cli.gaa"
	int port;
#line 29 "cli.gaa"
	int xml;
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
