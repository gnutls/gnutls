
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 112 "serv.gaa"
	char *priorities;
#line 109 "serv.gaa"
	char **ctype;
#line 108 "serv.gaa"
	int nctype;
#line 105 "serv.gaa"
	char **kx;
#line 104 "serv.gaa"
	int nkx;
#line 101 "serv.gaa"
	char **macs;
#line 100 "serv.gaa"
	int nmacs;
#line 97 "serv.gaa"
	char **comp;
#line 96 "serv.gaa"
	int ncomp;
#line 93 "serv.gaa"
	char **proto;
#line 92 "serv.gaa"
	int nproto;
#line 89 "serv.gaa"
	char **ciphers;
#line 88 "serv.gaa"
	int nciphers;
#line 85 "serv.gaa"
	char *opaque_prf_input;
#line 82 "serv.gaa"
	char *srp_passwd_conf;
#line 79 "serv.gaa"
	char *srp_passwd;
#line 76 "serv.gaa"
	char *psk_hint;
#line 73 "serv.gaa"
	char *psk_passwd;
#line 70 "serv.gaa"
	int disable_client_cert;
#line 67 "serv.gaa"
	int require_cert;
#line 64 "serv.gaa"
	char *x509_dsacertfile;
#line 61 "serv.gaa"
	char *x509_dsakeyfile;
#line 58 "serv.gaa"
	char *x509_certfile;
#line 55 "serv.gaa"
	char *x509_keyfile;
#line 52 "serv.gaa"
	char *pgp_subkey;
#line 49 "serv.gaa"
	char *pgp_certfile;
#line 46 "serv.gaa"
	char *pgp_keyfile;
#line 43 "serv.gaa"
	char *pgp_keyring;
#line 40 "serv.gaa"
	char *x509_crlfile;
#line 37 "serv.gaa"
	char *x509_cafile;
#line 34 "serv.gaa"
	int fmtder;
#line 31 "serv.gaa"
	char *dh_params_file;
#line 27 "serv.gaa"
	int http;
#line 24 "serv.gaa"
	int nodb;
#line 21 "serv.gaa"
	int quiet;
#line 18 "serv.gaa"
	int port;
#line 15 "serv.gaa"
	int generate;
#line 12 "serv.gaa"
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
