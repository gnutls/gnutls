
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 88 "certtool.gaa"
	int debug;
#line 85 "certtool.gaa"
	char *infile;
#line 82 "certtool.gaa"
	char *outfile;
#line 79 "certtool.gaa"
	int bits;
#line 76 "certtool.gaa"
	int outcert_format;
#line 73 "certtool.gaa"
	int incert_format;
#line 70 "certtool.gaa"
	int export;
#line 67 "certtool.gaa"
	int dsa;
#line 64 "certtool.gaa"
	int pkcs8;
#line 49 "certtool.gaa"
	char *pass;
#line 46 "certtool.gaa"
	char *ca;
#line 43 "certtool.gaa"
	char *ca_privkey;
#line 40 "certtool.gaa"
	char *cert;
#line 37 "certtool.gaa"
	char *request;
#line 34 "certtool.gaa"
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
    
    int gaa_file(char *name, gaainfo *gaaval);
    
#ifdef __cplusplus
}
#endif


#endif
