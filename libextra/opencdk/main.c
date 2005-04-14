/* -*- Mode: C; c-file-style: "bsd" -*-
 * main.c
 *       Copyright (C) 2001, 2002, 2003 Timo Schulz 
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
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <stdio.h>
#include <errno.h>
#ifdef HAVE_PWD_H
# include <pwd.h>
#endif
#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#include "opencdk.h"
#include "main.h"
#include "packet.h"
#include "cipher.h"


#define DEFAULT_CIPHER_ALGO CDK_CIPHER_CAST5
#define DEFAULT_DIGEST_ALGO CDK_MD_SHA1

#define SECMEM_SIZE 32768

static void *(*alloc_func) (size_t n) = gcry_xmalloc;
static void *(*alloc_secure_func) (size_t n) = gcry_malloc_secure;
static void *(*realloc_func) (void *p, size_t n) = gcry_realloc;
static void *(*calloc_func) (size_t m, size_t n) = gcry_calloc;
static void (*free_func) (void *) = gcry_free;
static int malloc_hooks = 0;
static int secmem_init = 0;

static cdk_log_fnc_t log_handler = NULL;
static void *log_handler_value = NULL;
static int log_level = CDK_LOG_NONE;


/**
 * cdk_strerror:
 * @ec: the error number
 *
 * Return an error text for the given id.
 **/
const char *
cdk_strerror (int ec)
{
    static char buf[20];

    switch (ec) {
    case CDK_EOF:              return "End Of File";
    case CDK_Success:          return "No error";
    case CDK_General_Error:    return "General error";
    case CDK_File_Error:       return strerror (errno);
    case CDK_Bad_Sig:          return "Bad signature";
    case CDK_Inv_Packet:       return "Invalid packet";
    case CDK_Inv_Algo:         return "Invalid algorithm";
    case CDK_Not_Implemented:  return "This is not implemented yet";
	/* FIXME: print the actual gcrypt error */
    case CDK_Gcry_Error:       return "Gcrypt error";
    case CDK_Armor_Error:      return "ASCII armor error";
    case CDK_Armor_CRC_Error:  return "ASCII armored damaged (CRC error)";
    case CDK_MPI_Error:        return "Invalid or missformed MPI";
    case CDK_Inv_Value:        return "Invalid parameter or value";
    case CDK_Error_No_Key:     return "No key available or not found";
    case CDK_Chksum_Error:     return "Check for key does not match";
    case CDK_Time_Conflict:    return "Time conflict";
    case CDK_Zlib_Error:       return "ZLIB error";
    case CDK_Weak_Key:         return "Weak key was detected";
    case CDK_Out_Of_Core:      return "Out of core!!";
    case CDK_Wrong_Seckey:     return "Wrong secret key";
    case CDK_Bad_MDC:          return "Manipulated MDC detected";
    case CDK_Inv_Mode:         return "Invalid mode";
    case CDK_Error_No_Keyring: return "No keyring available";
    case CDK_Inv_Packet_Ver:   return "Invalid version for packet";
    case CDK_Too_Short:        return "Buffer or object is too short";
    case CDK_Unusable_Key:     return "Unusable public key";
    default:                   sprintf (buf, "ec=%d", ec); return buf;
    }
    return NULL;
}


static void
out_of_core (size_t n)
{
    fprintf (stderr, "\n ** fatal error: out of memory (%d bytes) **\n", n);
}


/**
 * cdk_set_malloc_hooks: 
 * @new_alloc_func: malloc replacement
 * @new_alloc_secure_func: secure malloc replacement
 * @new_realloc_func: realloc replacement
 * @new_calloc_func: calloc replacement
 * @new_free_func: free replacement
 *
 * Set private memory hooks for the lib.
 */
void
cdk_set_malloc_hooks (void *(*new_alloc_func) (size_t n),
		      void *(*new_alloc_secure_func) (size_t n),
		      void *(*new_realloc_func) (void *p, size_t n),
		      void *(*new_calloc_func) (size_t m, size_t n),
		      void (*new_free_func) (void *))
{
    alloc_func = new_alloc_func;
    alloc_secure_func = new_alloc_secure_func;
    realloc_func = new_realloc_func;
    calloc_func = new_calloc_func;
    free_func = new_free_func;
    malloc_hooks = 1;
}


/**
 * cdk_malloc_hook_initialized:
 *
 * Return if the malloc hooks are already initialized.
 **/
int
cdk_malloc_hook_initialized (void)
{
    return malloc_hooks;
}


void *
cdk_malloc (size_t size)
{
    void * p = alloc_func (size);
    if (!p)
        out_of_core (size);
    return p;
}


void *
cdk_calloc (size_t n, size_t m)
{
    void * p = calloc_func (n, m);
    if (!p)
        out_of_core (m);
    return p;
}


static void
_secmem_init (size_t size)
{
    if (!size) {
        gcry_control (GCRYCTL_DROP_PRIVS);
        return;
    }
    if (secmem_init == 1)
        return;
    if (size >= SECMEM_SIZE)
        size = SECMEM_SIZE;
    gcry_control (GCRYCTL_INIT_SECMEM, size, 0);
    gcry_control (GCRYCTL_USE_SECURE_RNDPOOL);
    gcry_control (GCRYCTL_DISABLE_SECMEM_WARN);
    secmem_init = 1;
}


/* Not used?
static void
_secmem_end (void)
{
    gcry_control (GCRYCTL_TERM_SECMEM);
    secmem_init = 0;
}
*/

void *
cdk_salloc (size_t size, int clear)
{
/*  static size_t n = 0; */
    void * p;
  
    if (!secmem_init) {
        _secmem_init (SECMEM_SIZE);
        secmem_init = 1;
    }
    if (secmem_init == 1) {
        _secmem_init (0);
        secmem_init = 2;
    }
    /*
    n += size;
    _cdk_log_debug ("\ncdk_salloc (%d)\n", n);
    */
    p = alloc_secure_func (size);
    if (!p)
        out_of_core (size);
    if (clear)
        memset (p, 0, size);
    return p;
}


void *
cdk_realloc (void *ptr, size_t size)
{
    void * p = realloc_func (ptr, size);
    if (!p)
        out_of_core (size);
    return p;
}


char *
cdk_strdup (const char * ptr)
{
    char * p = cdk_malloc (strlen (ptr) + 1);
    if (p)
        strcpy (p, ptr);
    return p;
}


void
cdk_free (void * ptr)
{
    if (ptr)
        free_func (ptr);
}


void
_cdk_sec_free( void * ptr, size_t size )
{
    if( ptr ) {
        memset( ptr, 0xff, size );
        memset( ptr, 0xaa, size );
        memset( ptr, 0x55, size );
        memset( ptr, 0x00, size );
        free_func( ptr );
    }
}


static void
_cdk_logv (int level, const char *fmt, va_list arg_ptr)
{

    if (log_handler)
        log_handler (log_handler_value, level, fmt, arg_ptr);
    else {
        switch (level) {
        case CDK_LOG_INFO : break;
        case CDK_LOG_DEBUG: fputs ("DBG: ", stderr); break;
        case CDK_LOG_NONE : return; 
        }
        vfprintf (stderr, fmt, arg_ptr); 
    }
}


/**
 * cdk_set_log_handler: 
 * @logfnc: the function pointer
 * @opaque: a private values for the function
 *
 * set a private handler for logging.
 */
void
cdk_set_log_handler( cdk_log_fnc_t logfnc, void * opaque )
{
    log_handler = logfnc;
    log_handler_value = opaque; 
}


/**
 * cdk_set_log_level: 
 * @lvl: the level
 *
 * set the verbosity level.
 **/
void
cdk_set_log_level (int lvl)
{
  log_level = lvl;
}


int
_cdk_get_log_level (void)
{
    return log_level;
}


void
_cdk_log_info (const char *fmt, ...)
{
    va_list arg;

    if (log_level == CDK_LOG_NONE)
        return;
    va_start (arg, fmt);
    _cdk_logv (CDK_LOG_INFO, fmt, arg);
    va_end (arg);
}


void
_cdk_log_debug (const char *fmt, ...)
{
    va_list arg;
  
    if (log_level < CDK_LOG_DEBUG)
        return;
    va_start (arg, fmt);
    _cdk_logv (CDK_LOG_DEBUG, fmt, arg);
    va_end (arg);
}

#include <getpass.h>

char *
_cdk_passphrase_get( cdk_ctx_t hd, const char * prompt )
{
    char * p, * pass = NULL;
    
    if( hd->passphrase )
        return hd->passphrase( hd->passphrase_value, prompt );
    p = getpass( prompt );
    if( p )
        pass = cdk_strdup( p );
    return pass;
}


void
_cdk_passphrase_free( char *pw, size_t size )
{
    _cdk_sec_free( pw, size );
}


int
_cdk_is_idea_available (void)
{
    int rc = 0;
#ifdef LIBGCRYPT_WITH_IDEA
    rc = 1;
#endif
    return rc;
}


static void
handle_set_cipher (cdk_ctx_t hd, int cipher)
{
    if( !hd )
        return;
    if( cdk_cipher_test_algo( cipher ) )
        cipher = DEFAULT_CIPHER_ALGO;
    hd->cipher_algo = cipher;   
}


static void
handle_set_digest (cdk_ctx_t hd, int digest)
{
    if( !hd )
        return;
    if( cdk_md_test_algo( digest ) )
        digest = DEFAULT_DIGEST_ALGO;
    hd->digest_algo = digest;   
}


static void
handle_set_s2k( cdk_ctx_t hd, int mode, int digest, int cipher )
{
    if( !hd )
        return;
    if( cdk_cipher_test_algo( cipher ) )
        cipher = DEFAULT_CIPHER_ALGO;
    if( cdk_md_test_algo( digest ) )
        digest = DEFAULT_DIGEST_ALGO;
    if( mode != CDK_S2K_SIMPLE
        && mode != CDK_S2K_SALTED
        && mode != CDK_S2K_ITERSALTED )
        mode = CDK_S2K_ITERSALTED;
    hd->_s2k.mode = mode;
    hd->_s2k.digest_algo = digest;
    hd->_s2k.cipher_algo = cipher;
}


static void
handle_set_compat( cdk_ctx_t hd, int val )
{
    if( !hd )
        return;
    hd->opt.compat = val;
    if( !val )
        return;
    hd->opt.mdc = 0;
    hd->opt.rfc1991 = val == -1? 1: 0;
    hd->compress.algo = CDK_COMPRESS_ZIP;
    hd->compress.level = -1;
    hd->cipher_algo = val == -1? CDK_CIPHER_IDEA : DEFAULT_CIPHER_ALGO;
    hd->digest_algo = val == -1? CDK_MD_MD5: DEFAULT_DIGEST_ALGO;
    if( val == -1 )
        handle_set_s2k( hd, 0, hd->digest_algo, hd->cipher_algo );   
}


static void
handle_set_compress( cdk_ctx_t hd, int algo, int level )
{
    if( !hd )
        return;
    if( algo < 0 || algo > 2 )
        algo = 0;
    hd->compress.algo = algo;
    if( !algo )
        hd->opt.compress = 0;
    else {
        if( level > 0 && level < 10 )
            hd->compress.level = level;
        else
            hd->compress.level = 6;
    }
}


/**
 * cdk_handle_control:
 * @hd: session handle
 * @action: flag which indicates whether put or get is requested
 * @cmd: command id
 *
 * Perform various control operations for the current session.
 **/
int
cdk_handle_control( cdk_ctx_t hd, int action, int cmd, ... )
{
    va_list arg_ptr;
    int set = action == CDK_CTLF_SET, val = 0;

    if( !hd )
        return -1;
    if( action != CDK_CTLF_SET && action != CDK_CTLF_GET )
        return -1;
    va_start( arg_ptr, cmd );
    switch( cmd ) {
    case CDK_CTL_ARMOR:
        if( set )
            hd->opt.armor = va_arg( arg_ptr, int );
        else
            val = hd->opt.armor;
        break;

    case CDK_CTL_CIPHER:
        if( set )
            handle_set_cipher( hd, va_arg( arg_ptr, int ) );
        else
            val = hd->cipher_algo;
        break;

    case CDK_CTL_DIGEST:
        if( set )
            handle_set_digest( hd, va_arg( arg_ptr, int ) );
        else
            val = hd->digest_algo;
        break;

    case CDK_CTL_COMPAT:
        if( set )
            handle_set_compat( hd, va_arg( arg_ptr, int ) );
        else
            val = hd->opt.compat;
        break;

    case CDK_CTL_OVERWRITE:
        if( set )
            hd->opt.overwrite = va_arg( arg_ptr, int );
        else
            val = hd->opt.overwrite;
        break;

    case CDK_CTL_COMPRESS:
        if( set ) {
            int algo = va_arg( arg_ptr, int );
            int level = va_arg( arg_ptr, int );
            handle_set_compress( hd, algo, level );
        }
        else
            val = hd->compress.algo;
        break;

    case CDK_CTL_S2K:
        if( set ) {
            int mode = va_arg( arg_ptr, int );
            int digest = va_arg( arg_ptr, int );
            int cipher = va_arg( arg_ptr, int );
            handle_set_s2k( hd, mode, digest, cipher );
        }
        else
            val = hd->_s2k.mode;
        break;

    case CDK_CTL_KEYCACHE_ON:
        if( set )
            hd->cache.on = va_arg( arg_ptr, int );
        else
            val = hd->cache.on;
        break;

    case CDK_CTL_KEYCACHE_FREE:
        _cdk_free_seckey( hd->cache.sk );
        hd->cache.sk = NULL;
        break;

    case CDK_CTL_FORCE_DIGEST:
        if( set )
            hd->opt.force_digest = va_arg( arg_ptr, int );
        else
            val = hd->opt.force_digest;
        break;

    case CDK_CTL_TRUSTMODEL:
        if( set )
            hd->trust_model = va_arg( arg_ptr, int );
        else
            val = hd->trust_model;
        break;

    default:
        val = -1;
        break;
    }
    va_end( arg_ptr );
    return val;
}

            

/**
 * cdk_handle_new:
 * @r_ctx: context to store the handle
 *
 * create a new session handle.
 **/
int
cdk_handle_new( cdk_ctx_t * r_ctx )
{
    cdk_ctx_t c;
  
    if( !r_ctx )
        return CDK_Inv_Value;
    
    c = cdk_calloc( 1, sizeof *c );
    if( !c )
        return CDK_Out_Of_Core;
    /* default */
    c->_s2k.mode = 3;
    c->_s2k.digest_algo = DEFAULT_DIGEST_ALGO;
    c->_s2k.cipher_algo = DEFAULT_CIPHER_ALGO;

    c->opt.mdc = 1;
    c->opt.compress = 1;
    c->opt.armor = 0;
    c->opt.textmode = 0;

    c->digest_algo = DEFAULT_DIGEST_ALGO;
    c->cipher_algo = DEFAULT_CIPHER_ALGO;
    c->compress.algo = CDK_COMPRESS_ZIP;
    c->compress.level = 6;

    *r_ctx = c;
    return 0;
}


/**
 * cdk_handle_set_keydb:
 * @hd: session handle
 * @db: the database handle
 *
 * set the key database handle.
 * the function automatically detects whether this is a public or
 * secret keyring and the right handle is set.
 **/
void
cdk_handle_set_keydb( cdk_ctx_t hd, cdk_keydb_hd_t db )
{
    if( !hd )
        return;
    if( db->secret )
        hd->db.sec = db;
    else
        hd->db.pub = db;
}


/**
 * cdk_handle_get_keydb:
 * @hd: session handle
 * @type: type of the keyring
 *
 * Return the keydb handle from the session handle.
 **/
cdk_keydb_hd_t
cdk_handle_get_keydb( cdk_ctx_t hd, int type )
{
    if( !hd )
        return NULL;
    if( type == CDK_DBTYPE_PK_KEYRING )
        return hd->db.pub;
    else if( type == CDK_DBTYPE_SK_KEYRING )
        return hd->db.sec;
    return NULL;
}


/**
 * cdk_handle_set_callback: 
 * @hd: the handle
 * @cb: the callback function
 * @cb_value: the opaque value for the function
 *
 * set the callback for filter operations.
 **/
void
cdk_handle_set_callback (cdk_ctx_t hd,
                         void (*cb) (void * opaque, int type, const char * s),
                         void * cb_value)
{
    if( !hd )
        return;
    hd->callback = cb;
    hd->callback_value = cb_value;
}


/**
 * cdk_handle_set_passphrase_cb:
 * @hd: session handle
 * @cb: callback function
 * @cb_value: the opaque value for the cb function
 *
 * set the passphrase callback.
 **/
void cdk_handle_set_passphrase_cb( cdk_ctx_t hd,
                                   char *(*cb) (void *opa, const char *prompt),
                                   void * cb_value )
{
    if( !hd )
        return;
    hd->passphrase = cb;
    hd->passphrase_value = cb_value;
}


/**
 * cdk_handle_free:
 * @hd: the handle
 *
 * free the main handle.
 **/
void
cdk_handle_free( cdk_ctx_t hd )
{
    if( !hd )
        return;
    _cdk_result_verify_free( hd->result.verify );
    _cdk_free_seckey( hd->cache.sk );
    cdk_free( hd->s2k );
    cdk_free( hd->dek );
    cdk_free( hd );
}

