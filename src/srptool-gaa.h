
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 37 "srptool.gaa"
	char *create_conf;
#line 34 "srptool.gaa"
	char *passwd_conf;
#line 31 "srptool.gaa"
	int verify;
#line 28 "srptool.gaa"
	int salt;
#line 25 "srptool.gaa"
	int index;
#line 22 "srptool.gaa"
	char *passwd;
#line 19 "srptool.gaa"
	char *username;
#line 16 "srptool.gaa"
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
