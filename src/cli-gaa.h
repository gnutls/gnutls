
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 39 "cli.gaa"
	char **rest_args;
#line 38 "cli.gaa"
	int nrest_args;
#line 31 "cli.gaa"
	char **ctype;
#line 30 "cli.gaa"
	int nctype;
#line 27 "cli.gaa"
	char **kx;
#line 26 "cli.gaa"
	int nkx;
#line 23 "cli.gaa"
	char **macs;
#line 22 "cli.gaa"
	int nmacs;
#line 19 "cli.gaa"
	char **comp;
#line 18 "cli.gaa"
	int ncomp;
#line 15 "cli.gaa"
	char **proto;
#line 14 "cli.gaa"
	int nproto;
#line 11 "cli.gaa"
	char **ciphers;
#line 10 "cli.gaa"
	int nciphers;
#line 6 "cli.gaa"
	int port;
#line 3 "cli.gaa"
	int resume;

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
