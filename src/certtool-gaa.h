
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 139 "certtool.gaa"
	int debug;
#line 135 "certtool.gaa"
	char *pkcs_cipher;
#line 132 "certtool.gaa"
	char *template;
#line 129 "certtool.gaa"
	char *infile;
#line 126 "certtool.gaa"
	char *outfile;
#line 123 "certtool.gaa"
	int quick_random;
#line 120 "certtool.gaa"
	int bits;
#line 116 "certtool.gaa"
	int outcert_format;
#line 112 "certtool.gaa"
	int incert_format;
#line 109 "certtool.gaa"
	int export;
#line 106 "certtool.gaa"
	char *hash;
#line 103 "certtool.gaa"
	int dsa;
#line 100 "certtool.gaa"
	int pkcs8;
#line 95 "certtool.gaa"
	char* pkcs11_url;
#line 92 "certtool.gaa"
	char* pkcs11_provider;
#line 85 "certtool.gaa"
	int v1_cert;
#line 82 "certtool.gaa"
	int fix_key;
#line 67 "certtool.gaa"
	int crq_extensions;
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
