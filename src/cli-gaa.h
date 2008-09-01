
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 120 "cli.gaa"
	char *rest_args;
#line 112 "cli.gaa"
	int insecure;
#line 109 "cli.gaa"
	char *port;
#line 106 "cli.gaa"
	char *opaque_prf_input;
#line 103 "cli.gaa"
	char *psk_key;
#line 100 "cli.gaa"
	char *psk_username;
#line 97 "cli.gaa"
	char *srp_passwd;
#line 94 "cli.gaa"
	char *srp_username;
#line 91 "cli.gaa"
	char *x509_certfile;
#line 88 "cli.gaa"
	char *x509_keyfile;
#line 85 "cli.gaa"
	char *pgp_subkey;
#line 82 "cli.gaa"
	char *pgp_certfile;
#line 79 "cli.gaa"
	char *pgp_keyring;
#line 76 "cli.gaa"
	char *pgp_keyfile;
#line 73 "cli.gaa"
	char *x509_crlfile;
#line 70 "cli.gaa"
	char *x509_cafile;
#line 67 "cli.gaa"
	char *priorities;
#line 64 "cli.gaa"
	char **ctype;
#line 63 "cli.gaa"
	int nctype;
#line 60 "cli.gaa"
	char **kx;
#line 59 "cli.gaa"
	int nkx;
#line 56 "cli.gaa"
	char **macs;
#line 55 "cli.gaa"
	int nmacs;
#line 52 "cli.gaa"
	char **comp;
#line 51 "cli.gaa"
	int ncomp;
#line 48 "cli.gaa"
	char **proto;
#line 47 "cli.gaa"
	int nproto;
#line 44 "cli.gaa"
	char **ciphers;
#line 43 "cli.gaa"
	int nciphers;
#line 40 "cli.gaa"
	int verbose;
#line 37 "cli.gaa"
	int record_size;
#line 34 "cli.gaa"
	int print_cert;
#line 31 "cli.gaa"
	int disable_extensions;
#line 28 "cli.gaa"
	int fingerprint;
#line 25 "cli.gaa"
	int fmtder;
#line 22 "cli.gaa"
	int crlf;
#line 19 "cli.gaa"
	int starttls;
#line 16 "cli.gaa"
	int resume;
#line 13 "cli.gaa"
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
