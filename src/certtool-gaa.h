
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 75 "certtool.gaa"
	int debug;
#line 72 "certtool.gaa"
	char *infile;
#line 69 "certtool.gaa"
	char *outfile;
#line 66 "certtool.gaa"
	int bits;
#line 63 "certtool.gaa"
	int outcert_format;
#line 60 "certtool.gaa"
	int incert_format;
#line 57 "certtool.gaa"
	int export;
#line 54 "certtool.gaa"
	int pkcs8;
#line 43 "certtool.gaa"
	char *pass;
#line 40 "certtool.gaa"
	char *ca;
#line 37 "certtool.gaa"
	char *ca_privkey;
#line 34 "certtool.gaa"
	char *cert;
#line 31 "certtool.gaa"
	char *request;
#line 28 "certtool.gaa"
	char *privkey;
#line 13 "certtool.gaa"
	int action;

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
