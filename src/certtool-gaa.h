
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 103 "certtool.gaa"
	int debug;
#line 99 "certtool.gaa"
	char *template;
#line 96 "certtool.gaa"
	char *infile;
#line 93 "certtool.gaa"
	char *outfile;
#line 90 "certtool.gaa"
	int bits;
#line 87 "certtool.gaa"
	int outcert_format;
#line 84 "certtool.gaa"
	int xml;
#line 81 "certtool.gaa"
	int incert_format;
#line 78 "certtool.gaa"
	int export;
#line 75 "certtool.gaa"
	char *hash;
#line 72 "certtool.gaa"
	int dsa;
#line 69 "certtool.gaa"
	int pkcs8;
#line 52 "certtool.gaa"
	char *pass;
#line 49 "certtool.gaa"
	char *ca;
#line 46 "certtool.gaa"
	char *ca_privkey;
#line 43 "certtool.gaa"
	char *cert;
#line 40 "certtool.gaa"
	char *request;
#line 37 "certtool.gaa"
	char *privkey;
#line 17 "certtool.gaa"
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
