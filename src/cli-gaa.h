
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 33 "cli.gaa"
	char **ctype;
#line 32 "cli.gaa"
	int nctype;
#line 29 "cli.gaa"
	char **kx;
#line 28 "cli.gaa"
	int nkx;
#line 25 "cli.gaa"
	char **macs;
#line 24 "cli.gaa"
	int nmacs;
#line 21 "cli.gaa"
	char **comp;
#line 20 "cli.gaa"
	int ncomp;
#line 17 "cli.gaa"
	char **proto;
#line 16 "cli.gaa"
	int nproto;
#line 13 "cli.gaa"
	char **ciphers;
#line 12 "cli.gaa"
	int nciphers;
#line 9 "cli.gaa"
	char *hostname;
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
