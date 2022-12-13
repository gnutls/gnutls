#ifndef GNUTLS_LIB_DTLS13_H
#define GNUTLS_LIB_DLTS13_H

#include "gnutls_int.h"
#include "record.h"

uint16_t _dtls13_resolve_epoch(gnutls_session_t session, uint8_t epoch_bits);
int _dtls13_resolve_seq_num(gnutls_session_t session, uint64_t *seq_num,
			    uint8_t seq_bits_size, const void *ciphertext,
			    ssize_t ciphertext_size);
int _dtls13_encrypt_seq_num(uint16_t *sn_num, uint8_t sn_bits_size,
			    const void *ciphertext, ssize_t ciphertext_size,
			    record_parameters_st *params, uint8_t read);

int gnutls_dtls13_recv_ack(gnutls_session_t session);

#endif
