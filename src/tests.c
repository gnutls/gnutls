/*
 *      Copyright (C) 2000,2001,2002 Nikos Mavroyanopoulos
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <gnutls/gnutls.h>
#include <gnutls/extra.h>
#include <tests.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <common.h>

extern GNUTLS_SRP_CLIENT_CREDENTIALS srp_cred;
extern GNUTLS_ANON_CLIENT_CREDENTIALS anon_cred;
extern GNUTLS_CERTIFICATE_CLIENT_CREDENTIALS xcred;

extern int more_info;

extern int tls1_ok;
extern int ssl3_ok;

/* keep session info */
static char *session_data = NULL;
static char session_id[32];
static int session_data_size=0, session_id_size=0;
static int sfree=0;

int do_handshake( gnutls_session session) {
int ret, alert;

		do {
			ret = gnutls_handshake(session);
		} while (ret == GNUTLS_E_INTERRUPTED
			 || ret == GNUTLS_E_AGAIN);

		if (ret < 0 && more_info != 0) {
			printf("\n");
			if (ret == GNUTLS_E_WARNING_ALERT_RECEIVED
			    || ret == GNUTLS_E_FATAL_ALERT_RECEIVED) {
				alert = gnutls_alert_get( session);
				printf("*** Received alert [%d]: %s\n",
				       alert, gnutls_alert_get_name( alert));
			}
			printf( "*** Handshake has failed\n");
			GERR(ret);
		}

		if (ret < 0) return FAILED;

		gnutls_session_get_data(session, NULL, &session_data_size);
		
		if (sfree!=0) {
			free(session);
			sfree=0;
		}
		session_data = malloc(session_data_size);
		sfree = 1;
		if (session_data==NULL) exit(1);
		gnutls_session_get_data(session, session_data, &session_data_size);

		session_id_size = sizeof( session_id);
		gnutls_session_get_id(session, session_id, &session_id_size);

		return SUCCEED;
}

static int protocol_priority[16] = { GNUTLS_TLS1, GNUTLS_SSL3, 0 };
const static int kx_priority[16] =
    { GNUTLS_KX_RSA, GNUTLS_KX_DHE_DSS, GNUTLS_KX_DHE_RSA, GNUTLS_KX_ANON_DH, 
    GNUTLS_KX_RSA_EXPORT, 0 };
const static int cipher_priority[16] =
    { GNUTLS_CIPHER_3DES_CBC, GNUTLS_CIPHER_ARCFOUR_128, GNUTLS_CIPHER_ARCFOUR_40, 0 };
const static int comp_priority[16] = { GNUTLS_COMP_NULL, 0 };
const static int mac_priority[16] = { GNUTLS_MAC_SHA, GNUTLS_MAC_MD5, 0 };
const static int cert_type_priority[16] = { GNUTLS_CRT_X509, 0 };

#define ADD_ALL_CIPHERS(session) gnutls_cipher_set_priority(session, cipher_priority)
#define ADD_ALL_COMP(session) gnutls_compression_set_priority(session, comp_priority)
#define ADD_ALL_MACS(session) gnutls_mac_set_priority(session, mac_priority)
#define ADD_ALL_KX(session) gnutls_kx_set_priority(session, kx_priority)
#define ADD_ALL_PROTOCOLS(session) gnutls_protocol_set_priority(session, protocol_priority)
#define ADD_ALL_CERTTYPES(session) gnutls_cert_type_set_priority(session, cert_type_priority)

static void ADD_KX(gnutls_session session, int kx) {
	static int _kx_priority[] = { 0, 0 };
	_kx_priority[0] = kx;

	gnutls_kx_set_priority(session, _kx_priority);
}

static void ADD_KX2(gnutls_session session, int kx1, int kx2) {
	static int _kx_priority[] = { 0, 0, 0 };
	_kx_priority[0] = kx1;
	_kx_priority[1] = kx2;

	gnutls_kx_set_priority(session, _kx_priority);
}

static void ADD_CIPHER(gnutls_session session, int cipher) {
	static int _cipher_priority[] = { 0, 0 };
	_cipher_priority[0] = cipher;

	gnutls_cipher_set_priority(session, _cipher_priority);
}

static void ADD_CIPHER3(gnutls_session session, int cipher1, int cipher2, int cipher3) {
	static int _cipher_priority[] = { 0, 0, 0, 0 };
	_cipher_priority[0] = cipher1;
	_cipher_priority[1] = cipher2;
	_cipher_priority[2] = cipher3;

	gnutls_cipher_set_priority(session, _cipher_priority);
}

static void ADD_MAC(gnutls_session session, int mac) {
	static int _mac_priority[] = { 0, 0 };
	_mac_priority[0] = mac;

	gnutls_mac_set_priority(session, _mac_priority);
}

static void ADD_CERTTYPE(gnutls_session session, int ctype) {
	static int _ct_priority[] = { 0, 0 };
	_ct_priority[0] = ctype;

	gnutls_cert_type_set_priority(session, _ct_priority);
}

static void ADD_PROTOCOL(gnutls_session session, int protocol) {
	static int _proto_priority[] = { 0, 0 };
	_proto_priority[0] = protocol;

	gnutls_protocol_set_priority(session, _proto_priority);
}


int test_srp( gnutls_session session) {
		ADD_ALL_CIPHERS(session);
		ADD_ALL_COMP(session);
		ADD_ALL_CERTTYPES(session);
		ADD_ALL_PROTOCOLS(session);
		ADD_ALL_MACS(session);

		ADD_KX(session, GNUTLS_KX_SRP);
		gnutls_cred_set(session, GNUTLS_CRD_SRP, srp_cred);

		return do_handshake( session);
}

int test_export( gnutls_session session) {
		ADD_ALL_CIPHERS(session);
		ADD_ALL_COMP(session);
		ADD_ALL_CERTTYPES(session);
		ADD_ALL_PROTOCOLS(session);
		ADD_ALL_MACS(session);

		ADD_KX(session, GNUTLS_KX_RSA_EXPORT);
		gnutls_cred_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

		return do_handshake( session);
}

int test_dhe( gnutls_session session) {
		ADD_ALL_CIPHERS(session);
		ADD_ALL_COMP(session);
		ADD_ALL_CERTTYPES(session);
		ADD_ALL_PROTOCOLS(session);
		ADD_ALL_MACS(session);

		ADD_KX2(session, GNUTLS_KX_DHE_RSA, GNUTLS_KX_DHE_DSS);
		gnutls_cred_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

		return do_handshake( session);
}

int test_ssl3( gnutls_session session) {
int ret;
	ADD_ALL_CIPHERS(session);
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_PROTOCOL(session, GNUTLS_SSL3);
	ADD_ALL_MACS(session);
	ADD_ALL_KX(session);
	gnutls_cred_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( session);
	if (ret==SUCCEED) ssl3_ok = 1;
	
	return ret;
}
static int alrm=0;
void got_alarm(int k) {
	alrm = 1;
}
	
int test_bye( gnutls_session session) {
int ret;
char data[20];
int old;
	signal( SIGALRM, got_alarm);

	ADD_ALL_CIPHERS(session);
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_ALL_PROTOCOLS(session);
	ADD_ALL_MACS(session);
	ADD_ALL_KX(session);
	gnutls_cred_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( session);
	if (ret==FAILED) return ret;
	
	ret = gnutls_bye( session, GNUTLS_SHUT_WR);
	if (ret<0) return FAILED;
	
	old = siginterrupt( SIGALRM, 1);
	alarm(6);
	
	do {
		ret = gnutls_record_recv( session, data, sizeof(data));
	} while( ret > 0);

	siginterrupt( SIGALRM, old);
	if (ret==0) return SUCCEED;
	
	if (alrm == 0) return UNSURE;
	
	return FAILED;
}



int test_aes( gnutls_session session) {
int ret;
	ADD_CIPHER(session, GNUTLS_CIPHER_RIJNDAEL_128_CBC);
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_ALL_PROTOCOLS(session);
	ADD_ALL_MACS(session);
	ADD_ALL_KX(session);
	gnutls_cred_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( session);
	return ret;
}

int test_openpgp1( gnutls_session session) {
int ret;
	ADD_ALL_CIPHERS(session);
	ADD_ALL_COMP(session);
	ADD_CERTTYPE(session, GNUTLS_CRT_OPENPGP);
	ADD_ALL_PROTOCOLS(session);
	ADD_ALL_MACS(session);
	ADD_ALL_KX(session);
	gnutls_cred_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( session);
	if (ret==FAILED) return ret;

	if ( gnutls_cert_type_get(session) == GNUTLS_CRT_OPENPGP)
		return SUCCEED;

	return FAILED;
}

int test_unknown_ciphersuites( gnutls_session session) {
int ret;
	ADD_CIPHER3(session, GNUTLS_CIPHER_RIJNDAEL_128_CBC,
		GNUTLS_CIPHER_3DES_CBC, GNUTLS_CIPHER_ARCFOUR_128);
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_ALL_PROTOCOLS(session);
	ADD_ALL_MACS(session);
	ADD_ALL_KX(session);
	gnutls_cred_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( session);
	return ret;
}

int test_md5( gnutls_session session) {
int ret;
	ADD_ALL_CIPHERS(session);
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_ALL_PROTOCOLS(session);
	ADD_MAC(session, GNUTLS_MAC_MD5);
	ADD_ALL_KX(session);
	gnutls_cred_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( session);
	return ret;
}

int test_sha( gnutls_session session) {
int ret;
	ADD_ALL_CIPHERS(session);
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_ALL_PROTOCOLS(session);
	ADD_MAC(session, GNUTLS_MAC_SHA);
	ADD_ALL_KX(session);
	gnutls_cred_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( session);
	return ret;
}

int test_3des( gnutls_session session) {
int ret;
	ADD_CIPHER(session, GNUTLS_CIPHER_3DES_CBC);
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_ALL_PROTOCOLS(session);
	ADD_ALL_MACS(session);
	ADD_ALL_KX(session);
	gnutls_cred_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( session);
	return ret;
}

int test_arcfour( gnutls_session session) {
int ret;
	ADD_CIPHER(session, GNUTLS_CIPHER_ARCFOUR_128);
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_ALL_PROTOCOLS(session);
	ADD_ALL_MACS(session);
	ADD_ALL_KX(session);
	gnutls_cred_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( session);
	return ret;
}

int test_tls1( gnutls_session session) {
int ret;
	ADD_ALL_CIPHERS(session);
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_PROTOCOL(session, GNUTLS_TLS1);
	ADD_ALL_MACS(session);
	ADD_ALL_KX(session);
	gnutls_cred_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( session);
	if (ret==SUCCEED) tls1_ok = 1;

	return ret;

}

int test_tls1_2( gnutls_session session) {
int ret;
	ADD_ALL_CIPHERS(session);
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_ALL_PROTOCOLS(session);
	ADD_ALL_MACS(session);
	ADD_ALL_KX(session);
	gnutls_cred_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( session);
	if (ret==FAILED) {
		/* disable TLS 1.0 */
		if (tls1_ok!=0) {
			protocol_priority[0] = GNUTLS_SSL3;
			protocol_priority[1] = 0;
		}
	}
	return ret;

}

int test_rsa_pms( gnutls_session session) {
int ret;

	/* here we enable both SSL 3.0 and TLS 1.0
	 * and try to connect and use rsa authentication.
	 * If the server is old, buggy and only supports
	 * SSL 3.0 then the handshake will fail.
	 */
	ADD_ALL_CIPHERS(session);
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_ALL_PROTOCOLS(session);
	ADD_ALL_MACS(session);
	ADD_KX(session, GNUTLS_KX_RSA);
	gnutls_cred_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( session);
	if (ret < 0) return FAILED;
	
	if (gnutls_protocol_get_version(session)==GNUTLS_TLS1) return SUCCEED;
	return UNSURE;
}

int test_max_record_size( gnutls_session session) {
int ret;
	ADD_ALL_CIPHERS(session);
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_ALL_PROTOCOLS(session);
	ADD_ALL_MACS(session);
	ADD_ALL_KX(session);
	gnutls_cred_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	gnutls_record_set_max_size( session, 512);

	ret = do_handshake( session);
	if (ret<0) return FAILED;

	ret = gnutls_record_get_max_size(session);
	if (ret==512) return SUCCEED;
	
	return FAILED;
}

int test_hello_extension( gnutls_session session) {
int ret;
	ADD_ALL_CIPHERS(session);
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_ALL_PROTOCOLS(session);
	ADD_ALL_MACS(session);
	ADD_ALL_KX(session);
	gnutls_cred_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	gnutls_record_set_max_size( session, 512);

	ret = do_handshake( session);
	return ret;
}

void _gnutls_record_set_default_version(gnutls_session session, GNUTLS_Version version);

int test_version_rollback( gnutls_session session) {
int ret;
	if (tls1_ok==0) return UNSURE;

	/* here we enable both SSL 3.0 and TLS 1.0
	 * and we connect using a 3.1 client hello version,
	 * and a 3.0 record version. Some implementations
	 * are buggy (and vulnerable to man in the middle
	 * attacks) and this connection will fail.
	 */
	ADD_ALL_CIPHERS(session);
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_ALL_PROTOCOLS(session);
	ADD_ALL_MACS(session);
	ADD_ALL_KX(session);
	gnutls_cred_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	_gnutls_record_set_default_version( session, GNUTLS_SSL3);

	ret = do_handshake( session);
	if (ret!=SUCCEED) return ret;
	
	if (tls1_ok!=0 && gnutls_protocol_get_version( session)==GNUTLS_SSL3)
		return FAILED;
	
	return SUCCEED;
}


int test_anonymous( gnutls_session session) {
	ADD_ALL_CIPHERS(session);
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_ALL_PROTOCOLS(session);
	ADD_ALL_MACS(session);
	ADD_KX(session, GNUTLS_KX_ANON_DH);
	gnutls_cred_set(session, GNUTLS_CRD_ANON, anon_cred);

	return do_handshake( session);

}


int test_session_resume2( gnutls_session session) {
int ret;
char tmp_session_id[32];
int tmp_session_id_size;

	if (session == NULL) return UNSURE;
	
	ADD_ALL_CIPHERS(session);
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_ALL_PROTOCOLS(session);
	ADD_ALL_MACS(session);
	ADD_ALL_KX(session);
	gnutls_cred_set(session, GNUTLS_CRD_ANON, anon_cred);

	gnutls_session_set_data(session, session_data, session_data_size);

	memcpy( tmp_session_id, session_id, session_id_size);
	tmp_session_id_size = session_id_size;

	ret = do_handshake( session);
	if (ret < 0) return FAILED;
	
	/* check if we actually resumed the previous session */

	session_id_size = sizeof(session_id);
	gnutls_session_get_id(session, session_id, &session_id_size);

	if (memcmp(tmp_session_id, session_id, tmp_session_id_size) == 0)
		return SUCCEED;
	else
		return FAILED;

}

int test_certificate( gnutls_session session) {
int ret;

	ADD_ALL_CIPHERS(session);
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_ALL_PROTOCOLS(session);
	ADD_ALL_MACS(session);
	ADD_ALL_KX(session);

	gnutls_cred_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( session);
	if (ret < 0) return FAILED;

	printf("\n");
	print_cert_info( session);

	return SUCCEED;
}
