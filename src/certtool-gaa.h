
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 94 "certtool.gaa"
	int debug;
#line 90 "certtool.gaa"
	char *template;
#line 87 "certtool.gaa"
	char *infile;
#line 84 "certtool.gaa"
	char *outfile;
#line 81 "certtool.gaa"
	int bits;
#line 78 "certtool.gaa"
	int outcert_format;
#line 75 "certtool.gaa"
	int incert_format;
#line 72 "certtool.gaa"
	int export;
#line 69 "certtool.gaa"
	int dsa;
#line 66 "certtool.gaa"
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
