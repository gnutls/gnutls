#ifndef GNUTLS_ECC_H
# define GNUTLS_ECC_H

int _gnutls_ecc_ansi_x963_import(const opaque *in, unsigned long inlen, bigint_t* x, bigint_t* y);
int _gnutls_ecc_ansi_x963_export(gnutls_ecc_curve_t curve, bigint_t x, bigint_t y, gnutls_datum_t * out);
int _gnutls_ecc_curve_fill_params(gnutls_ecc_curve_t curve, gnutls_pk_params_st* params);
#endif
