
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 102 "certtool.gaa"
	int debug;
#line 98 "certtool.gaa"
	char *template;
#line 95 "certtool.gaa"
	char *infile;
#line 92 "certtool.gaa"
	char *outfile;
#line 89 "certtool.gaa"
	int bits;
#line 86 "certtool.gaa"
	int outcert_format;
#line 83 "certtool.gaa"
	int xml;
#line 80 "certtool.gaa"
	int incert_format;
#line 77 "certtool.gaa"
	int export;
#line 74 "certtool.gaa"
	char *hash;
#line 71 "certtool.gaa"
	int dsa;
#line 68 "certtool.gaa"
	int pkcs8;
#line 51 "certtool.gaa"
	char *pass;
#line 48 "certtool.gaa"
	char *ca;
#line 45 "certtool.gaa"
	char *ca_privkey;
#line 42 "certtool.gaa"
	char *cert;
#line 39 "certtool.gaa"
	char *request;
#line 36 "certtool.gaa"
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
