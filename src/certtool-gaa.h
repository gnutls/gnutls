
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 127 "certtool.gaa"
	int debug;
#line 123 "certtool.gaa"
	char *template;
#line 120 "certtool.gaa"
	char *infile;
#line 117 "certtool.gaa"
	char *outfile;
#line 114 "certtool.gaa"
	int quick_random;
#line 111 "certtool.gaa"
	int bits;
#line 107 "certtool.gaa"
	int outcert_format;
#line 103 "certtool.gaa"
	int incert_format;
#line 100 "certtool.gaa"
	int export;
#line 97 "certtool.gaa"
	char *hash;
#line 94 "certtool.gaa"
	int dsa;
#line 91 "certtool.gaa"
	int pkcs8;
#line 84 "certtool.gaa"
	int v1_cert;
#line 81 "certtool.gaa"
	int fix_key;
#line 56 "certtool.gaa"
	char *pass;
#line 53 "certtool.gaa"
	char *ca;
#line 50 "certtool.gaa"
	char *ca_privkey;
#line 47 "certtool.gaa"
	char *cert;
#line 44 "certtool.gaa"
	char *request;
#line 41 "certtool.gaa"
	char *privkey;
#line 19 "certtool.gaa"
	int action;
#line 18 "certtool.gaa"
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
