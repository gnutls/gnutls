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

extern GNUTLS_SRP_CLIENT_CREDENTIALS srp_cred;
extern GNUTLS_ANON_CLIENT_CREDENTIALS anon_cred;
extern GNUTLS_CERTIFICATE_CLIENT_CREDENTIALS xcred;

extern int more_info;

extern int tls1_ok;
extern int ssl3_ok;

/* keep session info */
static char *session = NULL;
static char session_id[32];
static int session_size=0, session_id_size=0;
static int sfree=0;

int do_handshake( GNUTLS_STATE state) {
int ret, alert;

		do {
			ret = gnutls_handshake(state);
		} while (ret == GNUTLS_E_INTERRUPTED
			 || ret == GNUTLS_E_AGAIN);

		if (ret < 0 && more_info != 0) {
			printf("\n");
			if (ret == GNUTLS_E_WARNING_ALERT_RECEIVED
			    || ret == GNUTLS_E_FATAL_ALERT_RECEIVED) {
				alert = gnutls_alert_get( state);
				printf("*** Received alert [%d]: %s\n",
				       alert, gnutls_alert_get_name( alert));
			}
			printf( "*** Handshake has failed\n");
			GERR(ret);
		}

		if (ret < 0) return FAILED;

		gnutls_session_get_data(state, NULL, &session_size);
		
		if (sfree!=0) {
			free(session);
			sfree=0;
		}
		session = malloc(session_size);
		sfree = 1;
		if (session==NULL) exit(1);
		gnutls_session_get_data(state, session, &session_size);

		session_id_size = sizeof( session_id);
		gnutls_session_get_id(state, session_id, &session_id_size);

		return SUCCEED;
}

static int protocol_priority[16] = { GNUTLS_TLS1, GNUTLS_SSL3, 0 };
const static int kx_priority[16] =
    { GNUTLS_KX_RSA, GNUTLS_KX_DHE_DSS, GNUTLS_KX_DHE_RSA, GNUTLS_KX_ANON_DH, 
    GNUTLS_KX_RSA_EXPORT, 0 };
const static int cipher_priority[16] =
    { GNUTLS_CIPHER_3DES_CBC, GNUTLS_CIPHER_ARCFOUR, GNUTLS_CIPHER_ARCFOUR_EXPORT, 0 };
const static int comp_priority[16] = { GNUTLS_COMP_NULL, 0 };
const static int mac_priority[16] = { GNUTLS_MAC_SHA, GNUTLS_MAC_MD5, 0 };
const static int cert_type_priority[16] = { GNUTLS_CRT_X509, 0 };

#define ADD_ALL_CIPHERS(state) gnutls_cipher_set_priority(state, cipher_priority)
#define ADD_ALL_COMP(state) gnutls_compression_set_priority(state, comp_priority)
#define ADD_ALL_MACS(state) gnutls_mac_set_priority(state, mac_priority)
#define ADD_ALL_KX(state) gnutls_kx_set_priority(state, kx_priority)
#define ADD_ALL_PROTOCOLS(state) gnutls_protocol_set_priority(state, protocol_priority)
#define ADD_ALL_CERTTYPES(state) gnutls_cert_type_set_priority(state, cert_type_priority)

static void ADD_KX(GNUTLS_STATE state, int kx) {
	static int _kx_priority[] = { 0, 0 };
	_kx_priority[0] = kx;

	gnutls_kx_set_priority(state, _kx_priority);
}

static void ADD_KX2(GNUTLS_STATE state, int kx1, int kx2) {
	static int _kx_priority[] = { 0, 0, 0 };
	_kx_priority[0] = kx1;
	_kx_priority[1] = kx2;

	gnutls_kx_set_priority(state, _kx_priority);
}

static void ADD_CIPHER(GNUTLS_STATE state, int cipher) {
	static int _cipher_priority[] = { 0, 0 };
	_cipher_priority[0] = cipher;

	gnutls_cipher_set_priority(state, _cipher_priority);
}

static void ADD_CIPHER3(GNUTLS_STATE state, int cipher1, int cipher2, int cipher3) {
	static int _cipher_priority[] = { 0, 0, 0, 0 };
	_cipher_priority[0] = cipher1;
	_cipher_priority[1] = cipher2;
	_cipher_priority[2] = cipher3;

	gnutls_cipher_set_priority(state, _cipher_priority);
}

static void ADD_MAC(GNUTLS_STATE state, int mac) {
	static int _mac_priority[] = { 0, 0 };
	_mac_priority[0] = mac;

	gnutls_mac_set_priority(state, _mac_priority);
}

static void ADD_CERTTYPE(GNUTLS_STATE state, int ctype) {
	static int _ct_priority[] = { 0, 0 };
	_ct_priority[0] = ctype;

	gnutls_cert_type_set_priority(state, _ct_priority);
}

static void ADD_PROTOCOL(GNUTLS_STATE state, int protocol) {
	static int _proto_priority[] = { 0, 0 };
	_proto_priority[0] = protocol;

	gnutls_protocol_set_priority(state, _proto_priority);
}


int test_srp( GNUTLS_STATE state) {
		ADD_ALL_CIPHERS(state);
		ADD_ALL_COMP(state);
		ADD_ALL_CERTTYPES(state);
		ADD_ALL_PROTOCOLS(state);
		ADD_ALL_MACS(state);

		ADD_KX(state, GNUTLS_KX_SRP);
		gnutls_cred_set(state, GNUTLS_CRD_SRP, srp_cred);

		return do_handshake( state);
}

int test_export( GNUTLS_STATE state) {
		ADD_ALL_CIPHERS(state);
		ADD_ALL_COMP(state);
		ADD_ALL_CERTTYPES(state);
		ADD_ALL_PROTOCOLS(state);
		ADD_ALL_MACS(state);

		ADD_KX(state, GNUTLS_KX_RSA_EXPORT);
		gnutls_cred_set(state, GNUTLS_CRD_CERTIFICATE, xcred);

		return do_handshake( state);
}

int test_dhe( GNUTLS_STATE state) {
		ADD_ALL_CIPHERS(state);
		ADD_ALL_COMP(state);
		ADD_ALL_CERTTYPES(state);
		ADD_ALL_PROTOCOLS(state);
		ADD_ALL_MACS(state);

		ADD_KX2(state, GNUTLS_KX_DHE_RSA, GNUTLS_KX_DHE_DSS);
		gnutls_cred_set(state, GNUTLS_CRD_CERTIFICATE, xcred);

		return do_handshake( state);
}

int test_ssl3( GNUTLS_STATE state) {
int ret;
	ADD_ALL_CIPHERS(state);
	ADD_ALL_COMP(state);
	ADD_ALL_CERTTYPES(state);
	ADD_PROTOCOL(state, GNUTLS_SSL3);
	ADD_ALL_MACS(state);
	ADD_ALL_KX(state);
	gnutls_cred_set(state, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( state);
	if (ret==SUCCEED) ssl3_ok = 1;
	
	return ret;
}
static int alrm=0;
void got_alarm(int k) {
	alrm = 1;
}
	
int test_bye( GNUTLS_STATE state) {
int ret;
char data[20];
int old;
	signal( SIGALRM, got_alarm);

	ADD_ALL_CIPHERS(state);
	ADD_ALL_COMP(state);
	ADD_ALL_CERTTYPES(state);
	ADD_ALL_PROTOCOLS(state);
	ADD_ALL_MACS(state);
	ADD_ALL_KX(state);
	gnutls_cred_set(state, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( state);
	if (ret==FAILED) return ret;
	
	ret = gnutls_bye( state, GNUTLS_SHUT_WR);
	if (ret<0) return FAILED;
	
	old = siginterrupt( SIGALRM, 1);
	alarm(6);
	
	do {
		ret = gnutls_record_recv( state, data, sizeof(data));
	} while( ret > 0);

	siginterrupt( SIGALRM, old);
	if (ret==0) return SUCCEED;
	
	if (alrm == 0) return UNSURE;
	
	return FAILED;
}



int test_aes( GNUTLS_STATE state) {
int ret;
	ADD_CIPHER(state, GNUTLS_CIPHER_RIJNDAEL_128_CBC);
	ADD_ALL_COMP(state);
	ADD_ALL_CERTTYPES(state);
	ADD_ALL_PROTOCOLS(state);
	ADD_ALL_MACS(state);
	ADD_ALL_KX(state);
	gnutls_cred_set(state, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( state);
	return ret;
}

int test_openpgp1( GNUTLS_STATE state) {
int ret;
	ADD_ALL_CIPHERS(state);
	ADD_ALL_COMP(state);
	ADD_CERTTYPE(state, GNUTLS_CRT_OPENPGP);
	ADD_ALL_PROTOCOLS(state);
	ADD_ALL_MACS(state);
	ADD_ALL_KX(state);
	gnutls_cred_set(state, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( state);
	if (ret==FAILED) return ret;

	if ( gnutls_cert_type_get(state) == GNUTLS_CRT_OPENPGP)
		return SUCCEED;

	return FAILED;
}

int test_unknown_ciphersuites( GNUTLS_STATE state) {
int ret;
	ADD_CIPHER3(state, GNUTLS_CIPHER_RIJNDAEL_128_CBC,
		GNUTLS_CIPHER_3DES_CBC, GNUTLS_CIPHER_ARCFOUR);
	ADD_ALL_COMP(state);
	ADD_ALL_CERTTYPES(state);
	ADD_ALL_PROTOCOLS(state);
	ADD_ALL_MACS(state);
	ADD_ALL_KX(state);
	gnutls_cred_set(state, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( state);
	return ret;
}

int test_md5( GNUTLS_STATE state) {
int ret;
	ADD_ALL_CIPHERS(state);
	ADD_ALL_COMP(state);
	ADD_ALL_CERTTYPES(state);
	ADD_ALL_PROTOCOLS(state);
	ADD_MAC(state, GNUTLS_MAC_MD5);
	ADD_ALL_KX(state);
	gnutls_cred_set(state, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( state);
	return ret;
}

int test_sha( GNUTLS_STATE state) {
int ret;
	ADD_ALL_CIPHERS(state);
	ADD_ALL_COMP(state);
	ADD_ALL_CERTTYPES(state);
	ADD_ALL_PROTOCOLS(state);
	ADD_MAC(state, GNUTLS_MAC_SHA);
	ADD_ALL_KX(state);
	gnutls_cred_set(state, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( state);
	return ret;
}

int test_3des( GNUTLS_STATE state) {
int ret;
	ADD_CIPHER(state, GNUTLS_CIPHER_3DES_CBC);
	ADD_ALL_COMP(state);
	ADD_ALL_CERTTYPES(state);
	ADD_ALL_PROTOCOLS(state);
	ADD_ALL_MACS(state);
	ADD_ALL_KX(state);
	gnutls_cred_set(state, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( state);
	return ret;
}

int test_arcfour( GNUTLS_STATE state) {
int ret;
	ADD_CIPHER(state, GNUTLS_CIPHER_ARCFOUR);
	ADD_ALL_COMP(state);
	ADD_ALL_CERTTYPES(state);
	ADD_ALL_PROTOCOLS(state);
	ADD_ALL_MACS(state);
	ADD_ALL_KX(state);
	gnutls_cred_set(state, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( state);
	return ret;
}

int test_tls1( GNUTLS_STATE state) {
int ret;
	ADD_ALL_CIPHERS(state);
	ADD_ALL_COMP(state);
	ADD_ALL_CERTTYPES(state);
	ADD_PROTOCOL(state, GNUTLS_TLS1);
	ADD_ALL_MACS(state);
	ADD_ALL_KX(state);
	gnutls_cred_set(state, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( state);
	if (ret==SUCCEED) tls1_ok = 1;

	return ret;

}

int test_tls1_2( GNUTLS_STATE state) {
int ret;
	ADD_ALL_CIPHERS(state);
	ADD_ALL_COMP(state);
	ADD_ALL_CERTTYPES(state);
	ADD_ALL_PROTOCOLS(state);
	ADD_ALL_MACS(state);
	ADD_ALL_KX(state);
	gnutls_cred_set(state, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( state);
	if (ret==FAILED) {
		/* disable TLS 1.0 */
		if (tls1_ok!=0) {
			protocol_priority[0] = GNUTLS_SSL3;
			protocol_priority[1] = 0;
		}
	}
	return ret;

}

int test_rsa_pms( GNUTLS_STATE state) {
int ret;

	/* here we enable both SSL 3.0 and TLS 1.0
	 * and try to connect and use rsa authentication.
	 * If the server is old, buggy and only supports
	 * SSL 3.0 then the handshake will fail.
	 */
	ADD_ALL_CIPHERS(state);
	ADD_ALL_COMP(state);
	ADD_ALL_CERTTYPES(state);
	ADD_ALL_PROTOCOLS(state);
	ADD_ALL_MACS(state);
	ADD_KX(state, GNUTLS_KX_RSA);
	gnutls_cred_set(state, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( state);
	if (ret < 0) return FAILED;
	
	if (gnutls_protocol_get_version(state)==GNUTLS_TLS1) return SUCCEED;
	return UNSURE;
}

int test_max_record_size( GNUTLS_STATE state) {
int ret;
	ADD_ALL_CIPHERS(state);
	ADD_ALL_COMP(state);
	ADD_ALL_CERTTYPES(state);
	ADD_ALL_PROTOCOLS(state);
	ADD_ALL_MACS(state);
	ADD_ALL_KX(state);
	gnutls_cred_set(state, GNUTLS_CRD_CERTIFICATE, xcred);
	gnutls_record_set_max_size( state, 512);

	ret = do_handshake( state);
	if (ret<0) return FAILED;

	ret = gnutls_record_get_max_size(state);
	if (ret==512) return SUCCEED;
	
	return FAILED;
}

int test_hello_extension( GNUTLS_STATE state) {
int ret;
	ADD_ALL_CIPHERS(state);
	ADD_ALL_COMP(state);
	ADD_ALL_CERTTYPES(state);
	ADD_ALL_PROTOCOLS(state);
	ADD_ALL_MACS(state);
	ADD_ALL_KX(state);
	gnutls_cred_set(state, GNUTLS_CRD_CERTIFICATE, xcred);
	gnutls_record_set_max_size( state, 512);

	ret = do_handshake( state);
	return ret;
}

void _gnutls_record_set_default_version(GNUTLS_STATE state, GNUTLS_Version version);

int test_version_rollback( GNUTLS_STATE state) {
int ret;
	if (tls1_ok==0) return UNSURE;

	/* here we enable both SSL 3.0 and TLS 1.0
	 * and we connect using a 3.1 client hello version,
	 * and a 3.0 record version. Some implementations
	 * are buggy (and vulnerable to man in the middle
	 * attacks) and this connection will fail.
	 */
	ADD_ALL_CIPHERS(state);
	ADD_ALL_COMP(state);
	ADD_ALL_CERTTYPES(state);
	ADD_ALL_PROTOCOLS(state);
	ADD_ALL_MACS(state);
	ADD_ALL_KX(state);
	gnutls_cred_set(state, GNUTLS_CRD_CERTIFICATE, xcred);
	_gnutls_record_set_default_version( state, GNUTLS_SSL3);

	ret = do_handshake( state);
	if (ret!=SUCCEED) return ret;
	
	if (tls1_ok!=0 && gnutls_protocol_get_version( state)==GNUTLS_SSL3)
		return FAILED;
	
	return SUCCEED;
}


int test_anonymous( GNUTLS_STATE state) {
	ADD_ALL_CIPHERS(state);
	ADD_ALL_COMP(state);
	ADD_ALL_CERTTYPES(state);
	ADD_ALL_PROTOCOLS(state);
	ADD_ALL_MACS(state);
	ADD_KX(state, GNUTLS_KX_ANON_DH);
	gnutls_cred_set(state, GNUTLS_CRD_ANON, anon_cred);

	return do_handshake( state);

}


int test_session_resume2( GNUTLS_STATE state) {
int ret;
char tmp_session_id[32];
int tmp_session_id_size;

	if (session == NULL) return UNSURE;
	
	ADD_ALL_CIPHERS(state);
	ADD_ALL_COMP(state);
	ADD_ALL_CERTTYPES(state);
	ADD_ALL_PROTOCOLS(state);
	ADD_ALL_MACS(state);
	ADD_ALL_KX(state);
	gnutls_cred_set(state, GNUTLS_CRD_ANON, anon_cred);

	gnutls_session_set_data(state, session, session_size);

	memcpy( tmp_session_id, session_id, session_id_size);
	tmp_session_id_size = session_id_size;

	ret = do_handshake( state);
	if (ret < 0) return FAILED;
	
	/* check if we actually resumed the previous session */

	session_id_size = sizeof(session_id);
	gnutls_session_get_id(state, session_id, &session_id_size);

	if (memcmp(tmp_session_id, session_id, tmp_session_id_size) == 0)
		return SUCCEED;
	else
		return FAILED;

}
