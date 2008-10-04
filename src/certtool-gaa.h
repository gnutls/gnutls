
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 125 "certtool.gaa"
	int debug;
#line 121 "certtool.gaa"
	char *template;
#line 118 "certtool.gaa"
	char *infile;
#line 115 "certtool.gaa"
	char *outfile;
#line 112 "certtool.gaa"
	int quick_random;
#line 109 "certtool.gaa"
	int bits;
#line 105 "certtool.gaa"
	int outcert_format;
#line 101 "certtool.gaa"
	int incert_format;
#line 98 "certtool.gaa"
	int export;
#line 95 "certtool.gaa"
	char *hash;
#line 92 "certtool.gaa"
	int dsa;
#line 89 "certtool.gaa"
	int pkcs8;
#line 82 "certtool.gaa"
	int v1_cert;
#line 79 "certtool.gaa"
	int fix_key;
#line 54 "certtool.gaa"
	char *pass;
#line 51 "certtool.gaa"
	char *ca;
#line 48 "certtool.gaa"
	char *ca_privkey;
#line 45 "certtool.gaa"
	char *cert;
#line 42 "certtool.gaa"
	char *request;
#line 39 "certtool.gaa"
	char *privkey;
#line 17 "certtool.gaa"
	int action;
#line 16 "certtool.gaa"
	int privkey_op;

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
