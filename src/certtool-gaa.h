
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 118 "certtool.gaa"
	int debug;
#line 114 "certtool.gaa"
	char *template;
#line 111 "certtool.gaa"
	char *infile;
#line 108 "certtool.gaa"
	char *outfile;
#line 105 "certtool.gaa"
	int quick_random;
#line 102 "certtool.gaa"
	int bits;
#line 99 "certtool.gaa"
	int outcert_format;
#line 96 "certtool.gaa"
	int incert_format;
#line 93 "certtool.gaa"
	int export;
#line 90 "certtool.gaa"
	char *hash;
#line 87 "certtool.gaa"
	int dsa;
#line 84 "certtool.gaa"
	int pkcs8;
#line 77 "certtool.gaa"
	int v1_cert;
#line 74 "certtool.gaa"
	int fix_key;
#line 53 "certtool.gaa"
	char *pass;
#line 50 "certtool.gaa"
	char *ca;
#line 47 "certtool.gaa"
	char *ca_privkey;
#line 44 "certtool.gaa"
	char *cert;
#line 41 "certtool.gaa"
	char *request;
#line 38 "certtool.gaa"
	char *privkey;
#line 16 "certtool.gaa"
	int action;

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
