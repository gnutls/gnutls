
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 111 "serv.gaa"
	char *priorities;
#line 108 "serv.gaa"
	char **ctype;
#line 107 "serv.gaa"
	int nctype;
#line 104 "serv.gaa"
	char **kx;
#line 103 "serv.gaa"
	int nkx;
#line 100 "serv.gaa"
	char **macs;
#line 99 "serv.gaa"
	int nmacs;
#line 96 "serv.gaa"
	char **comp;
#line 95 "serv.gaa"
	int ncomp;
#line 92 "serv.gaa"
	char **proto;
#line 91 "serv.gaa"
	int nproto;
#line 88 "serv.gaa"
	char **ciphers;
#line 87 "serv.gaa"
	int nciphers;
#line 84 "serv.gaa"
	char *opaque_prf_input;
#line 81 "serv.gaa"
	char *srp_passwd_conf;
#line 78 "serv.gaa"
	char *srp_passwd;
#line 75 "serv.gaa"
	char *psk_hint;
#line 72 "serv.gaa"
	char *psk_passwd;
#line 69 "serv.gaa"
	int disable_client_cert;
#line 66 "serv.gaa"
	int require_cert;
#line 63 "serv.gaa"
	char *x509_dsacertfile;
#line 60 "serv.gaa"
	char *x509_dsakeyfile;
#line 57 "serv.gaa"
	char *x509_certfile;
#line 54 "serv.gaa"
	char *x509_keyfile;
#line 51 "serv.gaa"
	char *pgp_subkey;
#line 48 "serv.gaa"
	char *pgp_certfile;
#line 45 "serv.gaa"
	char *pgp_keyfile;
#line 42 "serv.gaa"
	char *pgp_keyring;
#line 39 "serv.gaa"
	char *x509_crlfile;
#line 36 "serv.gaa"
	char *x509_cafile;
#line 33 "serv.gaa"
	int fmtder;
#line 30 "serv.gaa"
	char *dh_params_file;
#line 26 "serv.gaa"
	int http;
#line 23 "serv.gaa"
	int nodb;
#line 20 "serv.gaa"
	int quiet;
#line 17 "serv.gaa"
	int port;
#line 14 "serv.gaa"
	int generate;
#line 11 "serv.gaa"
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
