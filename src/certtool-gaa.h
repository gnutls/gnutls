
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 149 "certtool.gaa"
	int debug;
#line 142 "certtool.gaa"
	int pkcs11_type;
#line 139 "certtool.gaa"
	char* pkcs11_url;
#line 136 "certtool.gaa"
	char* pkcs11_provider;
#line 133 "certtool.gaa"
	char *pkcs_cipher;
#line 130 "certtool.gaa"
	char *template;
#line 127 "certtool.gaa"
	char *infile;
#line 124 "certtool.gaa"
	char *outfile;
#line 121 "certtool.gaa"
	int quick_random;
#line 118 "certtool.gaa"
	int bits;
#line 114 "certtool.gaa"
	int outcert_format;
#line 110 "certtool.gaa"
	int incert_format;
#line 107 "certtool.gaa"
	int export;
#line 104 "certtool.gaa"
	char *hash;
#line 101 "certtool.gaa"
	int dsa;
#line 98 "certtool.gaa"
	int pkcs8;
#line 90 "certtool.gaa"
	int v1_cert;
#line 87 "certtool.gaa"
	int fix_key;
#line 70 "certtool.gaa"
	int crq_extensions;
#line 57 "certtool.gaa"
	char *pass;
#line 54 "certtool.gaa"
	char *ca;
#line 51 "certtool.gaa"
	char *ca_privkey;
#line 48 "certtool.gaa"
	char *cert;
#line 45 "certtool.gaa"
	char *request;
#line 42 "certtool.gaa"
	char *pubkey;
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
