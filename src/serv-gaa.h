
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 33 "serv.gaa"
	char **ctype;
#line 32 "serv.gaa"
	int nctype;
#line 29 "serv.gaa"
	char **kx;
#line 28 "serv.gaa"
	int nkx;
#line 25 "serv.gaa"
	char **macs;
#line 24 "serv.gaa"
	int nmacs;
#line 21 "serv.gaa"
	char **comp;
#line 20 "serv.gaa"
	int ncomp;
#line 17 "serv.gaa"
	char **proto;
#line 16 "serv.gaa"
	int nproto;
#line 13 "serv.gaa"
	char **ciphers;
#line 12 "serv.gaa"
	int nciphers;
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

    void gaa_help();
    
    int gaa_file(char *name, gaainfo *gaaval);
    
#ifdef __cplusplus
}
#endif


#endif
