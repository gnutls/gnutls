
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 168 "certtool.gaa"
	int debug;
#line 163 "certtool.gaa"
	int pkcs11_detailed_url;
#line 160 "certtool.gaa"
	int pkcs11_trusted;
#line 157 "certtool.gaa"
	char* pkcs11_label;
#line 154 "certtool.gaa"
	int pkcs11_login;
#line 146 "certtool.gaa"
	int pkcs11_type;
#line 143 "certtool.gaa"
	char* pkcs11_url;
#line 140 "certtool.gaa"
	char* pkcs11_provider;
#line 137 "certtool.gaa"
	char *pkcs_cipher;
#line 134 "certtool.gaa"
	char *template;
#line 131 "certtool.gaa"
	char *infile;
#line 128 "certtool.gaa"
	char *outfile;
#line 125 "certtool.gaa"
	int quick_random;
#line 122 "certtool.gaa"
	char* sec_param;
#line 119 "certtool.gaa"
	int bits;
#line 115 "certtool.gaa"
	int outcert_format;
#line 111 "certtool.gaa"
	int incert_format;
#line 108 "certtool.gaa"
	int export;
#line 105 "certtool.gaa"
	char *hash;
#line 102 "certtool.gaa"
	int dsa;
#line 99 "certtool.gaa"
	int pkcs8;
#line 92 "certtool.gaa"
	int v1_cert;
#line 89 "certtool.gaa"
	int fix_key;
#line 72 "certtool.gaa"
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
