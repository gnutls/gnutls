
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 81 "certtool.gaa"
	int debug;
#line 78 "certtool.gaa"
	char *infile;
#line 75 "certtool.gaa"
	char *outfile;
#line 72 "certtool.gaa"
	int bits;
#line 69 "certtool.gaa"
	int outcert_format;
#line 66 "certtool.gaa"
	int incert_format;
#line 63 "certtool.gaa"
	int export;
#line 60 "certtool.gaa"
	int pkcs8;
#line 47 "certtool.gaa"
	char *pass;
#line 44 "certtool.gaa"
	char *ca;
#line 41 "certtool.gaa"
	char *ca_privkey;
#line 38 "certtool.gaa"
	char *cert;
#line 35 "certtool.gaa"
	char *request;
#line 32 "certtool.gaa"
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
