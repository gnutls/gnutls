
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 42 "cli.gaa"
	char **rest_args;
#line 41 "cli.gaa"
	int nrest_args;
#line 34 "cli.gaa"
	char **ctype;
#line 33 "cli.gaa"
	int nctype;
#line 30 "cli.gaa"
	char **kx;
#line 29 "cli.gaa"
	int nkx;
#line 26 "cli.gaa"
	char **macs;
#line 25 "cli.gaa"
	int nmacs;
#line 22 "cli.gaa"
	char **comp;
#line 21 "cli.gaa"
	int ncomp;
#line 18 "cli.gaa"
	char **proto;
#line 17 "cli.gaa"
	int nproto;
#line 14 "cli.gaa"
	char **ciphers;
#line 13 "cli.gaa"
	int nciphers;
#line 9 "cli.gaa"
	int record_size;
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
