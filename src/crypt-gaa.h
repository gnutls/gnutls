
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 21 "crypt.gaa"
	char *create_conf;
#line 18 "crypt.gaa"
	char *passwd_conf;
#line 15 "crypt.gaa"
	int verify;
#line 12 "crypt.gaa"
	int salt;
#line 9 "crypt.gaa"
	int index;
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

    void gaa_help(void);
    
    int gaa_file(char *name, gaainfo *gaaval);
    
#ifdef __cplusplus
}
#endif


#endif
