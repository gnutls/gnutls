
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 77 "serv.gaa"
	char **ctype;
#line 76 "serv.gaa"
	int nctype;
#line 73 "serv.gaa"
	char **kx;
#line 72 "serv.gaa"
	int nkx;
#line 69 "serv.gaa"
	char **macs;
#line 68 "serv.gaa"
	int nmacs;
#line 65 "serv.gaa"
	char **comp;
#line 64 "serv.gaa"
	int ncomp;
#line 61 "serv.gaa"
	char **proto;
#line 60 "serv.gaa"
	int nproto;
#line 57 "serv.gaa"
	char **ciphers;
#line 56 "serv.gaa"
	int nciphers;
#line 52 "serv.gaa"
	char *srp_passwd_conf;
#line 49 "serv.gaa"
	char *srp_passwd;
#line 46 "serv.gaa"
	char *pgp_keyserver;
#line 43 "serv.gaa"
	char *x509_certfile;
#line 40 "serv.gaa"
	char *x509_keyfile;
#line 37 "serv.gaa"
	char *pgp_certfile;
#line 34 "serv.gaa"
	char *pgp_keyfile;
#line 31 "serv.gaa"
	char *pgp_trustdb;
#line 28 "serv.gaa"
	char *pgp_keyring;
#line 25 "serv.gaa"
	char *x509_cafile;
#line 22 "serv.gaa"
	int fmtder;
#line 18 "serv.gaa"
	int http;
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
