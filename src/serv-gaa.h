
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 83 "serv.gaa"
	char **ctype;
#line 82 "serv.gaa"
	int nctype;
#line 79 "serv.gaa"
	char **kx;
#line 78 "serv.gaa"
	int nkx;
#line 75 "serv.gaa"
	char **macs;
#line 74 "serv.gaa"
	int nmacs;
#line 71 "serv.gaa"
	char **comp;
#line 70 "serv.gaa"
	int ncomp;
#line 67 "serv.gaa"
	char **proto;
#line 66 "serv.gaa"
	int nproto;
#line 63 "serv.gaa"
	char **ciphers;
#line 62 "serv.gaa"
	int nciphers;
#line 58 "serv.gaa"
	char *srp_passwd_conf;
#line 55 "serv.gaa"
	char *srp_passwd;
#line 52 "serv.gaa"
	char *x509_certfile;
#line 49 "serv.gaa"
	char *x509_keyfile;
#line 46 "serv.gaa"
	char *pgp_certfile;
#line 43 "serv.gaa"
	char *pgp_keyfile;
#line 40 "serv.gaa"
	char *pgp_trustdb;
#line 37 "serv.gaa"
	char *pgp_keyring;
#line 34 "serv.gaa"
	char *x509_cafile;
#line 31 "serv.gaa"
	int fmtder;
#line 28 "serv.gaa"
	char *dh_params_file;
#line 24 "serv.gaa"
	int http;
#line 21 "serv.gaa"
	int nodb;
#line 18 "serv.gaa"
	int quiet;
#line 15 "serv.gaa"
	int port;
#line 12 "serv.gaa"
	int generate;

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
