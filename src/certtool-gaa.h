
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 169 "certtool.gaa"
	int debug;
#line 164 "certtool.gaa"
	int pkcs11_detailed_url;
#line 161 "certtool.gaa"
	int pkcs11_trusted;
#line 158 "certtool.gaa"
	char* pkcs11_label;
#line 155 "certtool.gaa"
	int pkcs11_login;
#line 147 "certtool.gaa"
	int pkcs11_type;
#line 144 "certtool.gaa"
	char* pkcs11_url;
#line 141 "certtool.gaa"
	char* pkcs11_provider;
#line 138 "certtool.gaa"
	char *pkcs_cipher;
#line 135 "certtool.gaa"
	char *template;
#line 132 "certtool.gaa"
	char *infile;
#line 129 "certtool.gaa"
	char *outfile;
#line 126 "certtool.gaa"
	int quick_random;
#line 123 "certtool.gaa"
	char* sec_param;
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
#line 93 "certtool.gaa"
	int v1_cert;
#line 90 "certtool.gaa"
	int fix_key;
#line 73 "certtool.gaa"
	int crq_extensions;
#line 58 "certtool.gaa"
	char *pass;
#line 55 "certtool.gaa"
	char *ca;
#line 52 "certtool.gaa"
	char *ca_privkey;
#line 49 "certtool.gaa"
	char *cert;
#line 46 "certtool.gaa"
	char *request;
#line 43 "certtool.gaa"
	char *pubkey;
#line 40 "certtool.gaa"
	char *privkey;
#line 18 "certtool.gaa"
	int action;
#line 17 "certtool.gaa"
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
