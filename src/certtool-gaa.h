
#line 104 "gaa.skel"
/* GAA HEADER */
#ifndef GAA_HEADER_POKY
#define GAA_HEADER_POKY

typedef struct _gaainfo gaainfo;

struct _gaainfo
{
#line 34 "certtool.gaa"
	int debug;
#line 31 "certtool.gaa"
	int bits;
#line 28 "certtool.gaa"
	int pkcs8;
#line 20 "certtool.gaa"
	char *ca;
#line 17 "certtool.gaa"
	char *ca_privkey;
#line 14 "certtool.gaa"
	char *privkey;
#line 3 "certtool.gaa"
	int action;

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
