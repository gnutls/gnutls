
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 76 "certtool.gaa"
	int debug;
#line 73 "certtool.gaa"
	char *infile;
#line 70 "certtool.gaa"
	char *outfile;
#line 67 "certtool.gaa"
	int bits;
#line 64 "certtool.gaa"
	int outcert_format;
#line 61 "certtool.gaa"
	int incert_format;
#line 58 "certtool.gaa"
	int export;
#line 55 "certtool.gaa"
	int pkcs8;
#line 44 "certtool.gaa"
	char *pass;
#line 41 "certtool.gaa"
	char *ca;
#line 38 "certtool.gaa"
	char *ca_privkey;
#line 35 "certtool.gaa"
	char *cert;
#line 32 "certtool.gaa"
	char *request;
#line 29 "certtool.gaa"
	char *privkey;
#line 14 "certtool.gaa"
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
