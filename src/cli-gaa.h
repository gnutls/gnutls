
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 111 "cli.gaa"
	char *rest_args;
#line 99 "cli.gaa"
	int insecure;
#line 96 "cli.gaa"
	char *port;
#line 93 "cli.gaa"
	char *psk_key;
#line 90 "cli.gaa"
	char *psk_username;
#line 87 "cli.gaa"
	char *srp_passwd;
#line 84 "cli.gaa"
	char *srp_username;
#line 81 "cli.gaa"
	char *x509_certfile;
#line 78 "cli.gaa"
	char *x509_keyfile;
#line 75 "cli.gaa"
	char *pgp_subkey;
#line 72 "cli.gaa"
	char *pgp_certfile;
#line 69 "cli.gaa"
	char *pgp_keyring;
#line 66 "cli.gaa"
	char *pgp_keyfile;
#line 63 "cli.gaa"
	char *x509_crlfile;
#line 60 "cli.gaa"
	char *x509_cafile;
#line 57 "cli.gaa"
	char *priorities;
#line 54 "cli.gaa"
	int verbose;
#line 51 "cli.gaa"
	int record_size;
#line 48 "cli.gaa"
	int print_cert;
#line 45 "cli.gaa"
	int disable_extensions;
#line 42 "cli.gaa"
	int fingerprint;
#line 39 "cli.gaa"
	int fmtder;
#line 36 "cli.gaa"
	int crlf;
#line 33 "cli.gaa"
	int mtu;
#line 30 "cli.gaa"
	int udp;
#line 27 "cli.gaa"
	int starttls;
#line 24 "cli.gaa"
	int noticket;
#line 21 "cli.gaa"
	int rehandshake;
#line 18 "cli.gaa"
	int resume;
#line 15 "cli.gaa"
	int debug;

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
