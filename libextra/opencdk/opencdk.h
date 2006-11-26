/* opencdk.h - Open Crypto Development Kit (OpenCDK)
 *        Copyright (C) 2006 Free Software Foundation, Inc.
 *        Copyright (C) 2001, 2002, 2003, 2005 Timo Schulz
 *
 * This file is part of OpenCDK.
 *
 * OpenCDK is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * OpenCDK is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with OpenCDK; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef OPENCDK_H
#define OPENCDK_H

#include <stdarg.h>

#define OPENCDK_VERSION "0.5.11"

#ifdef __cplusplus
extern "C" {
#if 0
}
#endif
#endif
    
/* General contexts */
struct cdk_ctx_s;
typedef struct cdk_ctx_s *cdk_ctx_t;

struct cdk_strlist_s;
typedef struct cdk_strlist_s *cdk_strlist_t;

struct cdk_sesskey_s;
typedef struct cdk_sesskey_s *cdk_sesskey_t;

struct cdk_listkey_s;
typedef struct cdk_listkey_s *cdk_listkey_t;
    
struct cdk_mpi_s;
typedef struct cdk_mpi_s *cdk_mpi_t;

struct cdk_dek_s;
typedef struct cdk_dek_s *cdk_dek_t;

struct cdk_s2k_s;
typedef struct cdk_s2k_s *cdk_s2k_t;

struct cdk_stream_s;
typedef struct cdk_stream_s *cdk_stream_t;

struct cdk_prefitem_s;
typedef struct cdk_prefitem_s *cdk_prefitem_t;

struct cdk_kbnode_s;
typedef struct cdk_kbnode_s *cdk_kbnode_t;

struct cdk_keydb_hd_s;
typedef struct cdk_keydb_hd_s *cdk_keydb_hd_t;

struct cdk_keylist_s;
typedef struct cdk_keylist_s *cdk_keylist_t;

struct cdk_subpkt_s;
typedef struct cdk_subpkt_s *cdk_subpkt_t;

struct cdk_keygen_ctx_s;
typedef struct cdk_keygen_ctx_s *cdk_keygen_ctx_t;

struct cdk_desig_revoker_s;
typedef struct cdk_desig_revoker_s *cdk_desig_revoker_t;

struct cdk_md_hd_s;
typedef struct cdk_md_hd_s *cdk_md_hd_t;

struct cdk_cipher_hd_s;
typedef struct cdk_cipher_hd_s *cdk_cipher_hd_t;

    
typedef enum {
    CDK_EOF = -1,
    CDK_Success = 0,
    CDK_General_Error = 1,
    CDK_File_Error = 2,
    CDK_Bad_Sig = 3,
    CDK_Inv_Packet = 4,
    CDK_Inv_Algo = 5,
    CDK_Not_Implemented = 6,
    CDK_Gcry_Error = 7,
    CDK_Armor_Error = 8,
    CDK_Armor_CRC_Error = 9,
    CDK_MPI_Error = 10,
    CDK_Inv_Value = 11,
    CDK_Error_No_Key = 12,
    CDK_Chksum_Error = 13,
    CDK_Time_Conflict = 14,
    CDK_Zlib_Error = 15,
    CDK_Weak_Key = 16,
    CDK_Out_Of_Core = 17,
    CDK_Wrong_Seckey = 18,
    CDK_Bad_MDC = 19,
    CDK_Inv_Mode = 20,
    CDK_Error_No_Keyring = 21,
    CDK_Wrong_Format = 22,
    CDK_Inv_Packet_Ver = 23,
    CDK_Too_Short = 24,
    CDK_Unusable_Key = 25
} cdk_error_t;


enum cdk_control_flags {
    CDK_CTLF_SET          =  0,
    CDK_CTLF_GET          =  1,
    CDK_CTL_DIGEST        = 10,
    CDK_CTL_CIPHER        = 11,
    CDK_CTL_ARMOR         = 12,
    CDK_CTL_COMPRESS      = 13,
    CDK_CTL_COMPAT        = 14,
    CDK_CTL_OVERWRITE     = 15,
    CDK_CTL_S2K           = 16,
    CDK_CTL_KEYCACHE_ON   = 17,
    CDK_CTL_KEYCACHE_FREE = 18,
    CDK_CTL_FORCE_DIGEST  = 19,
    CDK_CTL_TRUSTMODEL    = 20
};

enum cdk_log_level_t {
    CDK_LOG_NONE  = 0,
    CDK_LOG_INFO  = 1,
    CDK_LOG_DEBUG = 2
};

enum cdk_compress_algo_t {
    CDK_COMPRESS_NONE = 0,
    CDK_COMPRESS_ZIP  = 1,
    CDK_COMPRESS_ZLIB = 2
};

enum cdk_pk_algo_t {
    CDK_PK_RSA   =  1,
    CDK_PK_RSA_E =  2,
    CDK_PK_RSA_S =  3,
    CDK_PK_ELG_E = 16,
    CDK_PK_DSA   = 17,
    CDK_PK_ELG   = 20
};

enum cdk_md_algo_t {
    CDK_MD_NONE    = 0,
    CDK_MD_MD5     = 1,
    CDK_MD_SHA1    = 2,
    CDK_MD_RMD160  = 3,
    CDK_MD_MD2     = 5,
    CDK_MD_TIGER   = 6, /* will be removed and thus: reserved */
    CDK_MD_SHA256  = 8
};

enum cdk_cipher_algo_t {
    CDK_CIPHER_NONE        = 0,
    CDK_CIPHER_IDEA        = 1,
    CDK_CIPHER_3DES        = 2,
    CDK_CIPHER_CAST5       = 3,
    CDK_CIPHER_BLOWFISH    = 4,
    CDK_CIPHER_SAFER_SK128 = 5, /* will be removed and thus: reserved */
    CDK_CIPHER_DES_SK      = 6, /* will be removed and thus: reserved */
    CDK_CIPHER_AES         = 7,
    CDK_CIPHER_AES192      = 8,
    CDK_CIPHER_AES256      = 9,
    CDK_CIPHER_TWOFISH     = 10
};

enum cdk_s2k_type_t {
    CDK_S2K_SIMPLE     = 0,
    CDK_S2K_SALTED     = 1,
    CDK_S2K_ITERSALTED = 3
};

enum cdk_pref_type_t {
    CDK_PREFTYPE_NONE = 0,
    CDK_PREFTYPE_SYM  = 1,
    CDK_PREFTYPE_HASH = 2,
    CDK_PREFTYPE_ZIP  = 3
};

enum cdk_sig_subpacket_t {
    CDK_SIGSUBPKT_NONE = 0,
    CDK_SIGSUBPKT_SIG_CREATED = 2,
    CDK_SIGSUBPKT_SIG_EXPIRE = 3,
    CDK_SIGSUBPKT_EXPORTABLE = 4,
    CDK_SIGSUBPKT_TRUST = 5,
    CDK_SIGSUBPKT_REGEXP = 6,
    CDK_SIGSUBPKT_REVOCABLE = 7,
    CDK_SIGSUBPKT_KEY_EXPIRE = 9,
    CDK_SIGSUBPKT_PREFS_SYM = 11,
    CDK_SIGSUBPKT_REV_KEY = 12,
    CDK_SIGSUBPKT_ISSUER = 16,
    CDK_SIGSUBPKT_NOTATION = 20,
    CDK_SIGSUBPKT_PREFS_HASH = 21,
    CDK_SIGSUBPKT_PREFS_ZIP = 22,
    CDK_SIGSUBPKT_KS_FLAGS = 23,
    CDK_SIGSUBPKT_PREF_KS = 24,
    CDK_SIGSUBPKT_PRIMARY_UID = 25,
    CDK_SIGSUBPKT_POLICY = 26,
    CDK_SIGSUBPKT_KEY_FLAGS = 27,
    CDK_SIGSUBPKT_SIGNERS_UID = 28,
    CDK_SIGSUBPKT_REVOC_REASON = 29,
    CDK_SIGSUBPKT_FEATURES = 30
};


enum cdk_revoc_code_t {
    CDK_REVCOD_NOREASON   = 0x00,
    CDK_REVCOD_SUPERCEDED = 0x01,
    CDK_REVCOD_COMPROMISED= 0x02,
    CDK_REVCOD_NOLONGUSED = 0x03
};

enum cdk_armor_type_t {
    CDK_ARMOR_MESSAGE   = 0,
    CDK_ARMOR_PUBKEY    = 1,
    CDK_ARMOR_SECKEY    = 2,
    CDK_ARMOR_SIGNATURE = 3,
    CDK_ARMOR_CLEARSIG  = 4
};

enum cdk_stream_control_t {
    CDK_STREAMCTL_DISABLE    = 2,
    CDK_STREAMCTL_COMPRESSED = 3
};

enum cdk_keydb_flag_t {
    /* database search modes */
    CDK_DBSEARCH_EXACT       =   1,
    CDK_DBSEARCH_SUBSTR      =   2, /* sub string search */
    CDK_DBSEARCH_SHORT_KEYID =   3, /* 32-bit keyid search */
    CDK_DBSEARCH_KEYID       =   4, /* 64-bit keyid search */
    CDK_DBSEARCH_FPR         =   5, /* 160-bit fingerprint search */
    CDK_DBSEARCH_NEXT        =   6, /* enumerate all keys */
    CDK_DBSEARCH_AUTO        =   7, /* try automagically class search */
    /* database types */
    CDK_DBTYPE_PK_KEYRING    = 100,
    CDK_DBTYPE_SK_KEYRING    = 101,
    CDK_DBTYPE_DATA          = 102
};


enum cdk_crypto_mode_t {
    CDK_CRYPTYPE_NONE    = 0,
    CDK_CRYPTYPE_ENCRYPT = 1,
    CDK_CRYPTYPE_DECRYPT = 2,
    CDK_CRYPTYPE_SIGN    = 3,
    CDK_CRYPTYPE_VERIFY  = 4,
    CDK_CRYPTYPE_EXPORT  = 5,
    CDK_CRYPTYPE_IMPORT  = 6
};

enum cdk_key_flag_t {
    CDK_KEY_VALID   = 0,
    CDK_KEY_INVALID = 1, /* missing or wrong self signature */
    CDK_KEY_EXPIRED = 2,
    CDK_KEY_REVOKED = 4,
    CDK_KEY_NOSIGNER= 8
};

enum cdk_trust_flag_t {
    CDK_TRUST_UNKNOWN     =   0,
    CDK_TRUST_EXPIRED     =   1,
    CDK_TRUST_UNDEFINED   =   2,
    CDK_TRUST_NEVER       =   3,
    CDK_TRUST_MARGINAL    =   4,
    CDK_TRUST_FULLY       =   5,
    CDK_TRUST_ULTIMATE    =   6,
    /* trust flags */
    CDK_TFLAG_REVOKED     =  32,
    CDK_TFLAG_SUB_REVOKED =  64,
    CDK_TFLAG_DISABLED    = 128
};


enum cdk_signature_id_t {
    /* signature status */
    CDK_SIGSTAT_NONE  = 0,
    CDK_SIGSTAT_GOOD  = 1,
    CDK_SIGSTAT_BAD   = 2,
    CDK_SIGSTAT_NOKEY = 3,
    /* signature modes */
    CDK_SIGMODE_NORMAL   = 100,
    CDK_SIGMODE_DETACHED = 101,
    CDK_SIGMODE_CLEAR    = 102
};

enum cdk_attribute_t {
    /* cdk attributes */
    CDK_ATTR_CREATED  = 1,
    CDK_ATTR_EXPIRE   = 2,
    CDK_ATTR_KEYID    = 3,
    CDK_ATTR_STATUS   = 4,
    CDK_ATTR_NOTATION = 5,
    CDK_ATTR_ALGO_PK  = 6,
    CDK_ATTR_ALGO_MD  = 7,
    CDK_ATTR_VERSION  = 8,
    CDK_ATTR_LEN      = 9,
    CDK_ATTR_FLAGS    = 10,
    CDK_ATTR_MPI      = 11,
    CDK_ATTR_NAME     = 12,
    CDK_ATTR_FPR      = 13,
    CDK_ATTR_URL      = 14, 
    /* cdk key flags */
    CDK_FLAG_KEY_REVOKED = 256,
    CDK_FLAG_KEY_EXPIRED = 512,
    CDK_FLAG_SIG_EXPIRED = 1024
};


enum cdk_callback_id_t {
    CDK_CB_NONE       = 0,
    CDK_CB_PUBKEY_ENC = 1
};


typedef enum {
    CDK_PKT_RESERVED      =  0,
    CDK_PKT_PUBKEY_ENC    =  1,
    CDK_PKT_SIGNATURE     =  2,
    CDK_PKT_SYMKEY_ENC    =  3,
    CDK_PKT_ONEPASS_SIG   =  4,
    CDK_PKT_SECRET_KEY    =  5,
    CDK_PKT_PUBLIC_KEY    =  6,
    CDK_PKT_SECRET_SUBKEY =  7,
    CDK_PKT_COMPRESSED    =  8,
    CDK_PKT_ENCRYPTED     =  9,
    CDK_PKT_MARKER        = 10,
    CDK_PKT_LITERAL       = 11,
    CDK_PKT_RING_TRUST    = 12,
    CDK_PKT_USER_ID       = 13,
    CDK_PKT_PUBLIC_SUBKEY = 14,
    CDK_PKT_OLD_COMMENT   = 16,
    CDK_PKT_ATTRIBUTE     = 17,
    CDK_PKT_ENCRYPTED_MDC = 18,
    CDK_PKT_MDC           = 19
} cdk_packet_type_t;

#define CDK_PKT_IS_ENCRYPTED(pkttype) (\
     ((pkttype)==CDK_PKT_ENCRYPTED_MDC) \
  || ((pkttype)==CDK_PKT_ENCRYPTED) \
  )

struct cdk_pkt_userid_s {
    unsigned int len;
    unsigned is_primary:1;
    unsigned is_revoked:1;
    unsigned mdc_feature:1;
    cdk_prefitem_t prefs;
    unsigned char * attrib_img; /* Tag 17 if not null */
    size_t attrib_len;
    size_t prefs_size;
    unsigned int created;
    char name[1];
};
typedef struct cdk_pkt_userid_s *cdk_pkt_userid_t;

struct cdk_pkt_pubkey_s {
    unsigned char version;
    unsigned char pubkey_algo;
    unsigned char fpr[20];
    unsigned int keyid[2];
    unsigned int main_keyid[2];
    unsigned int timestamp;
    unsigned int expiredate;
    cdk_mpi_t mpi[4];
    unsigned is_revoked:1;
    unsigned is_invalid:1;
    unsigned has_expired:1;
    int pubkey_usage;
    cdk_pkt_userid_t uid;
    cdk_prefitem_t prefs;
    size_t prefs_size;
    cdk_desig_revoker_t revkeys;
};
typedef struct cdk_pkt_pubkey_s *cdk_pkt_pubkey_t;

struct cdk_pkt_seckey_s {
    cdk_pkt_pubkey_t pk;
    unsigned int expiredate;
    int version;
    int pubkey_algo;
    unsigned int keyid[2];
    unsigned int main_keyid[2];
    unsigned char s2k_usage;
    struct {
        unsigned char algo;
        unsigned char sha1chk; /* SHA1 is used instead of a 16 bit checksum */
        cdk_s2k_t s2k;
        unsigned char iv[16];
        unsigned char ivlen;
    } protect;
    unsigned short csum;
    cdk_mpi_t mpi[4];
    unsigned char * encdata;
    size_t enclen;
    unsigned char is_protected;
    unsigned is_primary:1;
    unsigned has_expired:1;
    unsigned is_revoked:1;
};
typedef struct cdk_pkt_seckey_s *cdk_pkt_seckey_t;

struct cdk_pkt_signature_s {
    unsigned char version;
    unsigned char sig_class;
    unsigned int timestamp;
    unsigned int expiredate;
    unsigned int keyid[2];
    unsigned char pubkey_algo;
    unsigned char digest_algo;
    unsigned char digest_start[2];
    unsigned short hashed_size;
    cdk_subpkt_t hashed;
    unsigned short unhashed_size;
    cdk_subpkt_t unhashed;
    cdk_mpi_t mpi[2];
    cdk_desig_revoker_t revkeys;
    struct {
        unsigned exportable:1;
        unsigned revocable:1;
        unsigned policy_url:1;
        unsigned notation:1;
        unsigned expired:1;
        unsigned checked:1;
        unsigned valid:1;
        unsigned missing_key:1;
    } flags;  
    unsigned int key[2]; /* only valid for key signatures */
};
typedef struct cdk_pkt_signature_s *cdk_pkt_signature_t;

struct cdk_pkt_onepass_sig_s {
    unsigned char version;
    unsigned int keyid[2];
    unsigned char sig_class;
    unsigned char digest_algo;
    unsigned char pubkey_algo;
    unsigned char last;
};
typedef struct cdk_pkt_onepass_sig_s * cdk_pkt_onepass_sig_t;


struct cdk_pkt_pubkey_enc_s {
    unsigned char version;
    unsigned int keyid[2];
    int throw_keyid;
    unsigned char pubkey_algo;
    cdk_mpi_t mpi[2];
};
typedef struct cdk_pkt_pubkey_enc_s * cdk_pkt_pubkey_enc_t;


struct cdk_pkt_symkey_enc_s {
    unsigned char version;
    unsigned char cipher_algo;
    cdk_s2k_t s2k;
    unsigned char seskeylen;
    unsigned char seskey[32];
};
typedef struct cdk_pkt_symkey_enc_s *cdk_pkt_symkey_enc_t;


struct cdk_pkt_encrypted_s {
    unsigned int len;
    int extralen;
    unsigned char mdc_method;
    cdk_stream_t buf;
};
typedef struct cdk_pkt_encrypted_s *cdk_pkt_encrypted_t;


struct cdk_pkt_mdc_s {
    unsigned char hash[20];
};
typedef struct cdk_pkt_mdc_s *cdk_pkt_mdc_t;


struct cdk_pkt_literal_s {
    unsigned int len;
    cdk_stream_t buf;
    int mode;
    unsigned int timestamp;
    int namelen;
    char name[1];
};
typedef struct cdk_pkt_literal_s *cdk_pkt_literal_t;


struct cdk_pkt_compressed_s {
    unsigned int len;
    int algorithm;
    cdk_stream_t buf;
};
typedef struct cdk_pkt_compressed_s *cdk_pkt_compressed_t;


struct cdk_packet_s {
    size_t pktlen; /* real packet length */
    size_t pktsize; /* length with all headers */
    int old_ctb;
    cdk_packet_type_t pkttype;
    union {
        cdk_pkt_mdc_t mdc;
        cdk_pkt_userid_t user_id;
        cdk_pkt_pubkey_t public_key;
        cdk_pkt_seckey_t secret_key;
        cdk_pkt_signature_t signature;
        cdk_pkt_pubkey_enc_t pubkey_enc;
        cdk_pkt_symkey_enc_t symkey_enc;
        cdk_pkt_compressed_t compressed;
        cdk_pkt_encrypted_t encrypted;
        cdk_pkt_literal_t literal;
        cdk_pkt_onepass_sig_t onepass_sig;
    } pkt;
};
typedef struct cdk_packet_s CDK_PACKET;
typedef struct cdk_packet_s *cdk_packet_t;

/*-- main.c --*/
/* memory routines */
typedef void (*cdk_log_fnc_t) (void *, int, const char *, va_list);
void cdk_set_log_level (int lvl);
void cdk_set_log_handler (cdk_log_fnc_t logfnc, void * opaque);
const char* cdk_strerror (int ec);
void cdk_set_malloc_hooks (void *(*new_alloc_func) (size_t n),
                           void *(*new_alloc_secure_func) (size_t n),
                           void *(*new_realloc_func) (void * p, size_t n),
                           void *(*new_calloc_func) (size_t m, size_t n),
                           void (*new_free_func) (void *));
int cdk_malloc_hook_initialized (void);
void * cdk_malloc (size_t size);
void * cdk_calloc (size_t n, size_t m);
void * cdk_realloc (void * ptr, size_t size);
void * cdk_salloc (size_t size, int clear);
char * cdk_strdup (const char * ptr);
void cdk_free (void * ptr);
/* session handle routines */
int cdk_handle_new (cdk_ctx_t * r_ctx);
void cdk_handle_free (cdk_ctx_t hd);
void cdk_handle_set_keydb (cdk_ctx_t hd, cdk_keydb_hd_t db);
cdk_keydb_hd_t cdk_handle_get_keydb( cdk_ctx_t hd, int type );
int cdk_handle_control( cdk_ctx_t hd, int action, int cmd, ... );
void cdk_handle_set_callback (cdk_ctx_t hd,
                              void (*cb) (void *opa, int type, const char * s),
                              void * cb_value);
void cdk_handle_set_passphrase_cb( cdk_ctx_t hd,
                                   char *(*cb) (void *opa, const char *prompt),
                                   void * cb_value );

/* shortcuts for some controls */
#define cdk_handle_set_armor( a, val ) \
  cdk_handle_control( (a), CDK_CTLF_SET, CDK_CTL_ARMOR, (val) )

#define cdk_handle_set_compress( a, algo, level ) \
  cdk_handle_control( (a), CDK_CTLF_SET, CDK_CTL_COMPRESS, (algo), (level) )


/*-- cipher.c --*/
void cdk_set_progress_handler (void (*cb)(void * hd, unsigned off,
                                          unsigned size), void * cb_value);

/*-- new-packet.c --*/
cdk_error_t cdk_pkt_new( cdk_packet_t * r_pkt );
void cdk_pkt_init( cdk_packet_t pkt );
cdk_error_t cdk_pkt_alloc( cdk_packet_t * r_pkt, int pkttype );
void cdk_pkt_free( cdk_packet_t pkt );
void cdk_pkt_release( cdk_packet_t pkt );
cdk_error_t cdk_pkt_read( cdk_stream_t inp, cdk_packet_t pkt );
cdk_error_t cdk_pkt_write( cdk_stream_t out, cdk_packet_t pkt );    
/* sub packet routines */
cdk_subpkt_t cdk_subpkt_new( size_t size );
void cdk_subpkt_free( cdk_subpkt_t ctx );
cdk_subpkt_t cdk_subpkt_find( cdk_subpkt_t ctx, int type );
cdk_error_t cdk_subpkt_add( cdk_subpkt_t root, cdk_subpkt_t node );
const unsigned char * cdk_subpkt_get_data( cdk_subpkt_t ctx,
                                          int * r_type, size_t * r_nbytes );
void cdk_subpkt_init( cdk_subpkt_t node, int type,
                      const void *buf, size_t buflen );
unsigned char * cdk_userid_pref_get_array( cdk_pkt_userid_t id, int type,
                                           size_t *ret_len );
const unsigned char* cdk_key_desig_revoker_walk( cdk_desig_revoker_t root,
                                                 cdk_desig_revoker_t * ctx,
                                                 int *r_class, int *r_algid );

/*-- pubkey.c --*/
#define is_RSA(a) ((a) == CDK_PK_RSA \
                   || (a) == CDK_PK_RSA_E \
                   || (a) == CDK_PK_RSA_S)
#define is_ELG(a) ((a) == CDK_PK_ELG || (a) == CDK_PK_ELG_E)
#define is_DSA(a) ((a) == CDK_PK_DSA)

cdk_error_t cdk_pk_encrypt (cdk_pkt_pubkey_t pk, cdk_pkt_pubkey_enc_t pke,
                            cdk_sesskey_t esk);
cdk_error_t cdk_pk_decrypt (cdk_pkt_seckey_t sk, cdk_pkt_pubkey_enc_t pke,
                            cdk_sesskey_t *r_sk);
cdk_error_t cdk_pk_sign (cdk_pkt_seckey_t sk, cdk_pkt_signature_t sig,
                         const unsigned char * md);
cdk_error_t cdk_pk_verify (cdk_pkt_pubkey_t pk, cdk_pkt_signature_t sig,
                   const unsigned char * md);
cdk_error_t cdk_pk_get_mpi (cdk_pkt_pubkey_t pk, int idx,
                    unsigned char * buf, size_t * r_count, size_t * r_nbits);
cdk_error_t cdk_sk_get_mpi (cdk_pkt_seckey_t sk, int idx,
                    unsigned char * buf, size_t * r_count, size_t * r_nbits);
int cdk_pk_get_nbits (cdk_pkt_pubkey_t pk);
int cdk_pk_get_npkey (int algo);
int cdk_pk_get_nskey (int algo);
int cdk_pk_get_nsig (int algo);
int cdk_pk_get_nenc (int algo);
int cdk_pk_get_fingerprint (cdk_pkt_pubkey_t pk, unsigned char * fpr);
unsigned int cdk_pk_fingerprint_get_keyid (const unsigned char * fpr,
                                            size_t fprlen,
                                            unsigned int * keyid);
unsigned int cdk_pk_get_keyid (cdk_pkt_pubkey_t pk, unsigned int * keyid);
unsigned int cdk_sk_get_keyid (cdk_pkt_seckey_t sk, unsigned int * keyid);
unsigned int cdk_sig_get_keyid (cdk_pkt_signature_t sig,
                                 unsigned int * keyid);
cdk_error_t cdk_sk_unprotect( cdk_pkt_seckey_t sk, const char * pw );
cdk_error_t cdk_sk_protect( cdk_pkt_seckey_t sk, const char * pw );
cdk_error_t cdk_pk_from_secret_key( cdk_pkt_seckey_t sk,
                                    cdk_pkt_pubkey_t *ret_pk );

/*-- seskey.c --*/
cdk_error_t cdk_sesskey_new( cdk_sesskey_t * r_sk );
void cdk_sesskey_free( cdk_sesskey_t sk );
cdk_error_t cdk_dek_new( cdk_dek_t * r_dek );
void cdk_dek_free( cdk_dek_t dek );
cdk_error_t cdk_dek_set_cipher( cdk_dek_t dek, int algo );
cdk_error_t cdk_dek_set_key( cdk_dek_t dek, const unsigned char *key,
                             size_t keylen );
cdk_error_t cdk_dek_from_passphrase( cdk_dek_t * ret_dek, int cipher_algo,
                                     cdk_s2k_t s2k, int mode,
                                     const char * pw );
cdk_error_t cdk_dek_encode_pkcs1( cdk_dek_t dek, int nbits,
                                  cdk_sesskey_t * r_esk );
cdk_error_t cdk_dek_decode_pkcs1( cdk_dek_t * ret_dek, cdk_sesskey_t esk );
cdk_error_t cdk_dek_extract( cdk_dek_t * ret_dek, cdk_ctx_t hd,
                             cdk_pkt_pubkey_enc_t enc,
                             cdk_pkt_seckey_t sk );
void cdk_dek_set_mdc_flag( cdk_dek_t dek, int val );
/* string to key */
cdk_error_t cdk_s2k_new (cdk_s2k_t * ret_s2k, int mode, int algo,
                 const unsigned char * salt);
void cdk_s2k_free (cdk_s2k_t s2k);

/*-- armor.c --*/
cdk_error_t cdk_file_armor( cdk_ctx_t hd, const char * file,
                            const char * output );
cdk_error_t cdk_file_dearmor( const char * file, const char * output );
cdk_error_t cdk_armor_filter_use (cdk_stream_t inp);

/*-- stream.c --*/
int cdk_stream_control (cdk_stream_t s, int ctl, int val);
cdk_error_t cdk_stream_open (const char * file, cdk_stream_t * ret_s);
cdk_error_t cdk_stream_new (const char * file, cdk_stream_t * ret_s);
cdk_error_t cdk_stream_create (const char * file, cdk_stream_t * ret_s);
cdk_stream_t cdk_stream_tmp (void);
cdk_stream_t cdk_stream_tmp_from_mem (const void * buf, size_t count);
void cdk_stream_tmp_set_mode (cdk_stream_t s, int val);
cdk_error_t cdk_stream_flush (cdk_stream_t s);
cdk_error_t cdk_stream_set_cache (cdk_stream_t s, int val);
cdk_error_t cdk_stream_filter_disable (cdk_stream_t s, int type);
cdk_error_t cdk_stream_close (cdk_stream_t s);
unsigned cdk_stream_get_length (cdk_stream_t s);
int cdk_stream_read (cdk_stream_t s, void * buf, size_t count);
int cdk_stream_write (cdk_stream_t s, const void * buf, size_t count);
int cdk_stream_putc (cdk_stream_t s, int c);
int cdk_stream_getc (cdk_stream_t s);
int cdk_stream_eof (cdk_stream_t s);
long cdk_stream_tell (cdk_stream_t s);
cdk_error_t cdk_stream_seek (cdk_stream_t s, long offset);
cdk_error_t cdk_stream_set_armor_flag (cdk_stream_t s, int type);
cdk_error_t cdk_stream_set_literal_flag (cdk_stream_t s, int mode, const char * fname);
cdk_error_t cdk_stream_set_cipher_flag (cdk_stream_t s, cdk_dek_t dek,
                                        int use_mdc);
cdk_error_t cdk_stream_set_compress_flag (cdk_stream_t s, int algo, int level);
cdk_error_t cdk_stream_set_hash_flag (cdk_stream_t s, int algo);
cdk_error_t cdk_stream_set_text_flag (cdk_stream_t s, const char * lf);
cdk_error_t cdk_stream_kick_off (cdk_stream_t inp, cdk_stream_t out);
cdk_error_t cdk_stream_mmap( cdk_stream_t s, unsigned char ** ret_buf,
                             size_t * ret_count );
int cdk_stream_peek( cdk_stream_t inp, unsigned char *s, size_t count );

/*-- keydb.c --*/
cdk_error_t cdk_keydb_new( cdk_keydb_hd_t * r_hd, int type, void * data,
                           size_t count);
cdk_error_t cdk_keydb_open( cdk_keydb_hd_t hd, cdk_stream_t * ret_kr );
int cdk_keydb_check_sk( cdk_keydb_hd_t hd, unsigned int * keyid );
cdk_error_t cdk_keydb_search_start( cdk_keydb_hd_t db, int type, void * desc );
cdk_error_t cdk_keydb_search( cdk_keydb_hd_t hd, cdk_kbnode_t * ret_key );
void cdk_keydb_free( cdk_keydb_hd_t hd );
cdk_error_t cdk_keydb_get_bykeyid( cdk_keydb_hd_t hd, unsigned int * keyid,
                                   cdk_kbnode_t * ret_pk );
cdk_error_t cdk_keydb_get_byfpr( cdk_keydb_hd_t hd, const unsigned char * fpr,
                                 cdk_kbnode_t * ret_pk );
cdk_error_t cdk_keydb_get_bypattern( cdk_keydb_hd_t hd, const char * patt,
                                     cdk_kbnode_t * ret_pk );
cdk_error_t cdk_keydb_get_pk( cdk_keydb_hd_t khd, unsigned int * keyid,
                      cdk_pkt_pubkey_t* ret_pk );
cdk_error_t cdk_keydb_get_sk( cdk_keydb_hd_t khd, unsigned int * keyid,
                              cdk_pkt_seckey_t* ret_sk );
cdk_error_t cdk_keydb_get_keyblock( cdk_stream_t inp, cdk_kbnode_t * ret_key );
cdk_error_t cdk_keydb_idx_rebuild( cdk_keydb_hd_t hd );
cdk_error_t cdk_keydb_export( cdk_keydb_hd_t hd, cdk_stream_t out,
                              cdk_strlist_t remusr );
cdk_error_t cdk_keydb_import( cdk_keydb_hd_t hd, cdk_kbnode_t knode,
                              int *result );
cdk_error_t cdk_keydb_pk_cache_sigs( cdk_kbnode_t pk, cdk_keydb_hd_t hd );

/* listing keys */
cdk_error_t cdk_listkey_start( cdk_listkey_t * r_ctx, cdk_keydb_hd_t db,
                               const char * patt, cdk_strlist_t fpatt );
void cdk_listkey_close( cdk_listkey_t ctx );
cdk_error_t cdk_listkey_next( cdk_listkey_t ctx, cdk_kbnode_t * ret_key );

/*-- kbnode.c --*/
cdk_kbnode_t cdk_kbnode_new (cdk_packet_t pkt);
cdk_error_t cdk_kbnode_read_from_mem (cdk_kbnode_t * ret_node,
                                      const unsigned char * buf,
                                      size_t buflen);
cdk_error_t cdk_kbnode_write_to_mem (cdk_kbnode_t node,
                                     unsigned char * buf, size_t * r_nbytes);
void cdk_kbnode_release (cdk_kbnode_t node);
cdk_kbnode_t cdk_kbnode_walk (cdk_kbnode_t root, cdk_kbnode_t * ctx, int all);
cdk_packet_t cdk_kbnode_find_packet (cdk_kbnode_t node, int pkttype);
cdk_packet_t cdk_kbnode_get_packet (cdk_kbnode_t node);
cdk_kbnode_t cdk_kbnode_find (cdk_kbnode_t node, int pkttype);
cdk_kbnode_t cdk_kbnode_find_prev( cdk_kbnode_t root, cdk_kbnode_t node,
                                   int pkttype );
cdk_kbnode_t cdk_kbnode_find_next (cdk_kbnode_t node, int pkttype);
void * cdk_kbnode_get_attr( cdk_kbnode_t node, int pkttype, int attr );
cdk_error_t cdk_kbnode_hash( cdk_kbnode_t node, cdk_md_hd_t md, int is_v4,
                             int pkttype, int flags );

/*-- sig-check.c --*/
cdk_error_t cdk_pk_check_sigs( cdk_kbnode_t knode, cdk_keydb_hd_t hd,
                               int * r_status );

/*-- keylist.c --*/
int cdk_pklist_select_algo( cdk_keylist_t pkl, int preftype );
int cdk_pklist_use_mdc (cdk_keylist_t pkl);
cdk_error_t cdk_pklist_build( cdk_keylist_t *ret_pkl, cdk_keydb_hd_t hd,
                              cdk_strlist_t remusr, int use );
void cdk_pklist_release (cdk_keylist_t pkl);
cdk_error_t cdk_pklist_encrypt (cdk_keylist_t pk_list, cdk_dek_t dek,
                                cdk_stream_t outp);
/* secret key list */
cdk_error_t cdk_sklist_build( cdk_keylist_t * ret_skl,
                              cdk_keydb_hd_t db, cdk_ctx_t hd,
                              cdk_strlist_t locusr,
                              int unlock, unsigned int use );
void cdk_sklist_release (cdk_keylist_t skl);
cdk_error_t cdk_sklist_write (cdk_keylist_t skl, cdk_stream_t outp,
                              cdk_md_hd_t hash,
                              int sigclass, int sigver);
cdk_error_t cdk_sklist_write_onepass( cdk_keylist_t skl, cdk_stream_t outp,
                                      int sigclass, int mdalgo );

/*-- encrypt.c --*/
cdk_error_t cdk_stream_encrypt (cdk_ctx_t hd, cdk_strlist_t remusr,
                                cdk_stream_t inp, cdk_stream_t out);
cdk_error_t cdk_stream_decrypt (cdk_ctx_t hd, cdk_stream_t inp,
				cdk_stream_t out);
cdk_error_t cdk_file_encrypt (cdk_ctx_t hd, cdk_strlist_t remusr,
                      const char * file, const char * output);
cdk_error_t cdk_file_decrypt (cdk_ctx_t hd, const char * file,
                              const char * output);
cdk_error_t cdk_data_transform( cdk_ctx_t hd, enum cdk_crypto_mode_t mode,
                                cdk_strlist_t locusr, cdk_strlist_t remusr,
                                const void * inbuf, size_t insize,
                                unsigned char ** outbuf, size_t * outsize,
                                int modval );

/*-- sign.c --*/
cdk_error_t cdk_stream_sign( cdk_ctx_t hd, cdk_stream_t inp, cdk_stream_t out,
                             cdk_strlist_t locusr, cdk_strlist_t remusr,
                             int encryptflag, int sigmode );
cdk_error_t cdk_file_sign( cdk_ctx_t hd, cdk_strlist_t locusr,
                           cdk_strlist_t remusr,
                           const char * file, const char * output,
                           int sigmode, int encryptflag );

/*-- verify.c --*/
cdk_error_t cdk_stream_verify( cdk_ctx_t hd, cdk_stream_t inp,
                               cdk_stream_t out );
cdk_error_t cdk_file_verify( cdk_ctx_t hd, const char * file,
                             const char * output );
unsigned long cdk_sig_get_ulong_attr( cdk_ctx_t hd, int idx, int what );
const void * cdk_sig_get_data_attr( cdk_ctx_t hd, int idx, int what );

/*-- trustdb.c --*/
int cdk_trustdb_get_validity( cdk_stream_t inp, cdk_pkt_userid_t id,
                              int *r_val );
int cdk_trustdb_get_ownertrust( cdk_stream_t inp, cdk_pkt_pubkey_t pk,
                                int * r_val, int * r_flags );

/*-- misc.c --*/
void cdk_strlist_free (cdk_strlist_t sl);
cdk_strlist_t cdk_strlist_add (cdk_strlist_t * list, const char * string);
const char * cdk_strlist_walk (cdk_strlist_t root, cdk_strlist_t * context);
const char * cdk_check_version (const char * req_version);
/* UTF8 */
char * cdk_utf8_encode( const char * string );
char * cdk_utf8_decode( const char * string, size_t length, int delim );

/*-- keyserver.c --*/
cdk_error_t cdk_keyserver_recv_key( const char * host, int port,
                                    const unsigned char * keyid, int kid_type,
                                    cdk_kbnode_t * ret_key );

/*-- keygen.c --*/
cdk_error_t cdk_keygen_new( cdk_keygen_ctx_t * r_hd );
void cdk_keygen_free( cdk_keygen_ctx_t hd );
cdk_error_t cdk_keygen_set_prefs( cdk_keygen_ctx_t hd,
                                  enum cdk_pref_type_t type,
                                  const unsigned char * array, size_t n );
cdk_error_t cdk_keygen_set_algo_info( cdk_keygen_ctx_t hd, int type,
                                      enum cdk_pk_algo_t algo, int bits );
void cdk_keygen_set_mdc_feature( cdk_keygen_ctx_t hd, int val );
void cdk_keygen_set_keyserver_flags( cdk_keygen_ctx_t hd, int no_modify,
                                     const char *pref_url );
void cdk_keygen_set_expire_date( cdk_keygen_ctx_t hd, int type,
                                 long int timestamp );
void cdk_keygen_set_name( cdk_keygen_ctx_t hd, const char * name );
void cdk_keygen_set_passphrase( cdk_keygen_ctx_t hd, const char * pass );
cdk_error_t cdk_keygen_start( cdk_keygen_ctx_t hd );
cdk_error_t cdk_keygen_save( cdk_keygen_ctx_t hd,
                     const char * pubf, const char * secf );

#ifdef __cplusplus
}
#endif 

#endif /* OPENCDK_H */

