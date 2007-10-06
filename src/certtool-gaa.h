
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 110 "certtool.gaa"
	int debug;
#line 106 "certtool.gaa"
	char *template;
#line 103 "certtool.gaa"
	char *infile;
#line 100 "certtool.gaa"
	char *outfile;
#line 97 "certtool.gaa"
	int bits;
#line 94 "certtool.gaa"
	int outcert_format;
#line 91 "certtool.gaa"
	int xml;
#line 88 "certtool.gaa"
	int incert_format;
#line 85 "certtool.gaa"
	int export;
#line 82 "certtool.gaa"
	char *hash;
#line 79 "certtool.gaa"
	int dsa;
#line 76 "certtool.gaa"
	int pkcs8;
#line 71 "certtool.gaa"
	int fix_key;
#line 58 "certtool.gaa"
	int quick_random;
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
