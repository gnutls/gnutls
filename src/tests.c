/*
 * Copyright (C) 2000,2001,2002,2003 Nikos Mavroyanopoulos
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

#include <config.h>
#include <gnutls/gnutls.h>
#include <gnutls/extra.h>
#include <gnutls/x509.h>
#include <tests.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <common.h>

extern gnutls_srp_client_credentials srp_cred;
extern gnutls_anon_client_credentials anon_cred;
extern gnutls_certificate_credentials xcred;

extern int more_info;
static int srp = 0;
static int dh_bits;

extern int tls1_ok;
extern int ssl3_ok;

/* keep session info */
static char *session_data = NULL;
static char session_id[32];
static int session_data_size=0, session_id_size=0;
static int sfree=0;
static int handshake_output = 0;

int do_handshake( gnutls_session session) {
int ret, alert;

		do {
			ret = gnutls_handshake(session);
		} while (ret == GNUTLS_E_INTERRUPTED
			 || ret == GNUTLS_E_AGAIN);
	
		handshake_output = ret;

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

		if (srp) {
			if ((ret == GNUTLS_E_WARNING_ALERT_RECEIVED || ret ==
				GNUTLS_E_FATAL_ALERT_RECEIVED) &&
				gnutls_alert_get(session) == GNUTLS_A_BAD_RECORD_MAC)
				return SUCCEED;

			if (ret == GNUTLS_E_DECRYPTION_FAILED)
				return SUCCEED; /* SRP was detected */
		}

		if (ret < 0) return FAILED;

		gnutls_session_get_data(session, NULL, &session_data_size);
		
		if (sfree!=0) {
			free(session_data);
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
static const int kx_priority[16] =
    { GNUTLS_KX_RSA, GNUTLS_KX_DHE_DSS, GNUTLS_KX_DHE_RSA, GNUTLS_KX_ANON_DH, 
    GNUTLS_KX_RSA_EXPORT, 0 };
static const int cipher_priority[16] =
    { GNUTLS_CIPHER_3DES_CBC, GNUTLS_CIPHER_ARCFOUR_128, GNUTLS_CIPHER_ARCFOUR_40, 0 };
static const int comp_priority[16] = { GNUTLS_COMP_NULL, 0 };
static const int mac_priority[16] = { GNUTLS_MAC_SHA, GNUTLS_MAC_MD5, 0 };
static const int cert_type_priority[16] = { GNUTLS_CRT_X509, 0 };

#define ADD_ALL_CIPHERS(session) gnutls_cipher_set_priority(session, cipher_priority)
#define ADD_ALL_COMP(session) gnutls_compression_set_priority(session, comp_priority)
#define ADD_ALL_MACS(session) gnutls_mac_set_priority(session, mac_priority)
#define ADD_ALL_KX(session) gnutls_kx_set_priority(session, kx_priority)
#define ADD_ALL_PROTOCOLS(session) gnutls_protocol_set_priority(session, protocol_priority)
#define ADD_ALL_CERTTYPES(session) gnutls_certificate_type_set_priority(session, cert_type_priority)

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

	gnutls_certificate_type_set_priority(session, _ct_priority);
}

static void ADD_PROTOCOL(gnutls_session session, int protocol) {
	static int _proto_priority[] = { 0, 0 };
	_proto_priority[0] = protocol;

	gnutls_protocol_set_priority(session, _proto_priority);
}

#ifdef ENABLE_SRP
int test_srp( gnutls_session session) {
int ret;

		ADD_ALL_CIPHERS(session);
		ADD_ALL_COMP(session);
		ADD_ALL_CERTTYPES(session);
		ADD_ALL_PROTOCOLS(session);
		ADD_ALL_MACS(session);

		ADD_KX(session, GNUTLS_KX_SRP);
		srp = 1;

		gnutls_credentials_set(session, GNUTLS_CRD_SRP, srp_cred);

		ret = do_handshake( session);
		srp = 0;
		
		return ret;
}
#endif

int test_export( gnutls_session session) {
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_ALL_PROTOCOLS(session);
	ADD_ALL_MACS(session);

	ADD_KX(session, GNUTLS_KX_RSA_EXPORT);
	ADD_CIPHER(session, GNUTLS_CIPHER_ARCFOUR_40);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

	return do_handshake( session);
}

int test_dhe( gnutls_session session) {
int ret;

	ADD_ALL_CIPHERS(session);
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_ALL_PROTOCOLS(session);
	ADD_ALL_MACS(session);

	ADD_KX2(session, GNUTLS_KX_DHE_RSA, GNUTLS_KX_DHE_DSS);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( session);
	dh_bits = gnutls_dh_get_prime_bits( session);
	if (dh_bits < 0) dh_bits = 0;

	return ret;
}

int test_dhe_bits( gnutls_session session) {
int ret;

	if (dh_bits == 0) return FAILED;

	printf( " %d", dh_bits);
	return SUCCEED;
}

int test_ssl3( gnutls_session session) {
int ret;
	ADD_ALL_CIPHERS(session);
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_PROTOCOL(session, GNUTLS_SSL3);
	ADD_ALL_MACS(session);
	ADD_ALL_KX(session);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

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
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

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
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

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
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( session);
	if (ret==FAILED) return ret;

	if ( gnutls_certificate_type_get(session) == GNUTLS_CRT_OPENPGP)
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
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

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
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

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
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

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
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

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
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

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
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( session);
	if (ret==SUCCEED) tls1_ok = 1;

	return ret;

}

/* Advertize both TLS 1.0 and SSL 3.0 if the connection fails,
 * but the previous SSL 3.0 test succeeded then disable TLS 1.0.
 */
int test_tls1_2( gnutls_session session) {
int ret;
	ADD_ALL_CIPHERS(session);
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_ALL_PROTOCOLS(session);
	ADD_ALL_MACS(session);
	ADD_ALL_KX(session);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( session);
	if (ret==FAILED) {
		/* disable TLS 1.0 */
		if (ssl3_ok!=0) {
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
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( session);
	if (ret == FAILED) return FAILED;

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
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	gnutls_record_set_max_size( session, 512);

	ret = do_handshake( session);
	if (ret == FAILED) return ret;

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
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	gnutls_record_set_max_size( session, 512);

	ret = do_handshake( session);
	return ret;
}

void _gnutls_record_set_default_version(gnutls_session session, unsigned char major,
	unsigned char minor);

int test_version_rollback( gnutls_session session) {
int ret;
	if (tls1_ok==0) return UNSURE;

	/* here we enable both SSL 3.0 and TLS 1.0
	 * and we connect using a 3.1 client hello version,
	 * and a 3.0 record version. Some implementations
	 * are buggy (and vulnerable to man in the middle
	 * attacks which allow a version downgrade) and this 
	 * connection will fail.
	 */
	ADD_ALL_CIPHERS(session);
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_ALL_PROTOCOLS(session);
	ADD_ALL_MACS(session);
	ADD_ALL_KX(session);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	_gnutls_record_set_default_version( session, 3, 0);

	ret = do_handshake( session);
	if (ret!=SUCCEED) return ret;

	if (tls1_ok!=0 && gnutls_protocol_get_version( session)==GNUTLS_SSL3)
		return FAILED;
	
	return SUCCEED;
}

/* See if the server tolerates out of bounds
 * record layer versions in the first client hello
 * message.
 */
int test_version_oob( gnutls_session session) {
int ret;
	/* here we enable both SSL 3.0 and TLS 1.0
	 * and we connect using a 5.5 record version.
	 */
	ADD_ALL_CIPHERS(session);
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_ALL_PROTOCOLS(session);
	ADD_ALL_MACS(session);
	ADD_ALL_KX(session);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	_gnutls_record_set_default_version( session, 5, 5);

	ret = do_handshake( session);
	return ret;
}

void _gnutls_rsa_pms_set_version(gnutls_session session, unsigned char major,
        unsigned char minor);

int test_rsa_pms_version_check( gnutls_session session) 
{
int ret;
	/* here we use an arbitary version in the RSA PMS
	 * to see whether to server will check this version.
	 *
	 * A normal server would abort this handshake.
	 */
	ADD_ALL_CIPHERS(session);
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_ALL_PROTOCOLS(session);
	ADD_ALL_MACS(session);
	ADD_ALL_KX(session);
	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	_gnutls_rsa_pms_set_version( session, 5, 5); /* use SSL 5.5 version */

	ret = do_handshake( session);
	return ret;

}

#ifdef ENABLE_ANON
int test_anonymous( gnutls_session session) {
int ret;

	ADD_ALL_CIPHERS(session);
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_ALL_PROTOCOLS(session);
	ADD_ALL_MACS(session);
	ADD_KX(session, GNUTLS_KX_ANON_DH);
	gnutls_credentials_set(session, GNUTLS_CRD_ANON, anon_cred);

	ret = do_handshake( session);
	dh_bits = gnutls_dh_get_prime_bits( session);
	if (dh_bits < 0) dh_bits = 0;

	return ret;
}
#endif

int test_session_resume2( gnutls_session session) 
{
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

	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
	gnutls_credentials_set(session, GNUTLS_CRD_ANON, anon_cred);

	gnutls_session_set_data(session, session_data, session_data_size);

	memcpy( tmp_session_id, session_id, session_id_size);
	tmp_session_id_size = session_id_size;

	ret = do_handshake( session);
	if (ret == FAILED) return ret;

	/* check if we actually resumed the previous session */

	session_id_size = sizeof(session_id);
	gnutls_session_get_id(session, session_id, &session_id_size);

	if (gnutls_session_is_resumed( session)) return SUCCEED;

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

	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

	ret = do_handshake( session);
	if (ret == FAILED) return ret;

	printf("\n");
	print_cert_info( session);

	return SUCCEED;
}

/* A callback function to be used at the certificate selection time.
 */
static int cert_callback( gnutls_session session, const gnutls_datum* client_certs,
	int client_certs_num, const gnutls_datum * req_ca_rdn, int nreqs)
{
char issuer_dn[256];
int len, i, ret;

	/* Print the server's trusted CAs
	 */
	printf("\n");
	if (nreqs > 0)
		printf("- Server's trusted authorities:\n");
	else
		printf("- Server did not send us any trusted authorities names.\n");

	/* print the names (if any) */
	for (i=0;i<nreqs;i++) {
		len = sizeof(issuer_dn);
		ret = gnutls_x509_rdn_get( &req_ca_rdn[i], issuer_dn, &len);
		if ( ret >= 0) {
			printf("   [%d]: ", i);
			printf("%s\n", issuer_dn);
		}
	}

	return -1;

}

/* Prints the trusted server's CAs. This is only
 * if the server sends a certificate request packet.
 */
int test_server_cas( gnutls_session session) 
{
int ret;

	ADD_ALL_CIPHERS(session);
	ADD_ALL_COMP(session);
	ADD_ALL_CERTTYPES(session);
	ADD_ALL_PROTOCOLS(session);
	ADD_ALL_MACS(session);
	ADD_ALL_KX(session);

	gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
        gnutls_certificate_client_set_select_function( session, cert_callback);

	ret = do_handshake( session);
	if (ret ==FAILED) return ret;

	return SUCCEED;
}



