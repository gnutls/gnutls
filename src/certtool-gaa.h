
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 65 "certtool.gaa"
	int debug;
#line 62 "certtool.gaa"
	char *infile;
#line 59 "certtool.gaa"
	char *outfile;
#line 56 "certtool.gaa"
	int bits;
#line 53 "certtool.gaa"
	int outcert_format;
#line 50 "certtool.gaa"
	int incert_format;
#line 47 "certtool.gaa"
	int export;
#line 44 "certtool.gaa"
	int pkcs8;
#line 33 "certtool.gaa"
	char *pass;
#line 30 "certtool.gaa"
	char *ca;
#line 27 "certtool.gaa"
	char *ca_privkey;
#line 24 "certtool.gaa"
	char *cert;
#line 21 "certtool.gaa"
	char *request;
#line 18 "certtool.gaa"
	char *privkey;
#line 3 "certtool.gaa"
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
