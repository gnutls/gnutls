
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 64 "serv.gaa"
	char **ctype;
#line 63 "serv.gaa"
	int nctype;
#line 60 "serv.gaa"
	char **kx;
#line 59 "serv.gaa"
	int nkx;
#line 56 "serv.gaa"
	char **macs;
#line 55 "serv.gaa"
	int nmacs;
#line 52 "serv.gaa"
	char **comp;
#line 51 "serv.gaa"
	int ncomp;
#line 48 "serv.gaa"
	char **proto;
#line 47 "serv.gaa"
	int nproto;
#line 44 "serv.gaa"
	char **ciphers;
#line 43 "serv.gaa"
	int nciphers;
#line 39 "serv.gaa"
	char *srp_passwd_conf;
#line 36 "serv.gaa"
	char *srp_passwd;
#line 33 "serv.gaa"
	char *pgp_keyserver;
#line 30 "serv.gaa"
	char *x509_certfile;
#line 27 "serv.gaa"
	char *x509_keyfile;
#line 24 "serv.gaa"
	char *pgp_certfile;
#line 21 "serv.gaa"
	char *pgp_keyfile;
#line 18 "serv.gaa"
	char *pgp_trustdb;
#line 15 "serv.gaa"
	char *pgp_keyring;
#line 12 "serv.gaa"
	char *x509_cafile;
#line 9 "serv.gaa"
	int http;
#line 6 "serv.gaa"
	int port;
#line 3 "serv.gaa"
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
