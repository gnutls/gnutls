
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 145 "certtool.gaa"
	int debug;
#line 142 "certtool.gaa"
	char *pkcs_cipher;
#line 139 "certtool.gaa"
	char *template;
#line 136 "certtool.gaa"
	char *infile;
#line 133 "certtool.gaa"
	char *outfile;
#line 130 "certtool.gaa"
	int quick_random;
#line 127 "certtool.gaa"
	char* sec_param;
#line 124 "certtool.gaa"
	int bits;
#line 120 "certtool.gaa"
	int outcert_format;
#line 116 "certtool.gaa"
	int incert_format;
#line 113 "certtool.gaa"
	int export;
#line 110 "certtool.gaa"
	char *hash;
#line 107 "certtool.gaa"
	int ecc;
#line 104 "certtool.gaa"
	int dsa;
#line 101 "certtool.gaa"
	int pkcs8;
#line 94 "certtool.gaa"
	int v1_cert;
#line 91 "certtool.gaa"
	int fix_key;
#line 74 "certtool.gaa"
	int crq_extensions;
#line 59 "certtool.gaa"
	char *pass;
#line 56 "certtool.gaa"
	char *ca;
#line 53 "certtool.gaa"
	char *ca_privkey;
#line 50 "certtool.gaa"
	char *cert;
#line 47 "certtool.gaa"
	char *request;
#line 44 "certtool.gaa"
	char *pubkey;
#line 41 "certtool.gaa"
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
