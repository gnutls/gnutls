
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 52 "certtool.gaa"
	int debug;
#line 49 "certtool.gaa"
	char *infile;
#line 46 "certtool.gaa"
	char *outfile;
#line 43 "certtool.gaa"
	int bits;
#line 40 "certtool.gaa"
	int incert_format;
#line 37 "certtool.gaa"
	int pkcs8;
#line 28 "certtool.gaa"
	char *ca;
#line 25 "certtool.gaa"
	char *ca_privkey;
#line 22 "certtool.gaa"
	char *cert;
#line 19 "certtool.gaa"
	char *request;
#line 16 "certtool.gaa"
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
