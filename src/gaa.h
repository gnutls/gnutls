
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 22 "crypt.gaa"
	char *create_conf;
#line 19 "crypt.gaa"
	char *passwd_conf;
#line 16 "crypt.gaa"
	int verify;
#line 13 "crypt.gaa"
	int salt;
#line 10 "crypt.gaa"
	char *crypt;
#line 6 "crypt.gaa"
	char *passwd;
#line 3 "crypt.gaa"
	char *username;

#line 114 "gaa.skel"
};

#ifdef __cplusplus
extern "C"
{
#endif

    int gaa(int argc, char *argv[], gaainfo *gaaval);

    void gaa_help();
    
    int gaa_file(char *name, gaainfo *gaaval);
    
#ifdef __cplusplus
}
#endif


#endif
