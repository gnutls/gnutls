
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 94 "p11tool.gaa"
	int debug;
#line 89 "p11tool.gaa"
	char *outfile;
#line 86 "p11tool.gaa"
	int action;
#line 85 "p11tool.gaa"
	char* pkcs11_provider;
#line 81 "p11tool.gaa"
	int incert_format;
#line 78 "p11tool.gaa"
	char* sec_param;
#line 75 "p11tool.gaa"
	int bits;
#line 72 "p11tool.gaa"
	int pkcs8;
#line 69 "p11tool.gaa"
	char *cert;
#line 66 "p11tool.gaa"
	char *pubkey;
#line 63 "p11tool.gaa"
	char *privkey;
#line 60 "p11tool.gaa"
	char* secret_key;
#line 56 "p11tool.gaa"
	int pkcs11_detailed_url;
#line 53 "p11tool.gaa"
	int pkcs11_login;
#line 49 "p11tool.gaa"
	int pkcs11_private;
#line 46 "p11tool.gaa"
	int pkcs11_trusted;
#line 40 "p11tool.gaa"
	int key_type;
#line 35 "p11tool.gaa"
	char* pkcs11_label;
#line 24 "p11tool.gaa"
	int pkcs11_type;
#line 21 "p11tool.gaa"
	char* pkcs11_url;

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
