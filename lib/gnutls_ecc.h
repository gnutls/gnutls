int _gnutls_ecc_ansi_x963_import(ecc_curve_t curve, const opaque *in, unsigned long inlen, bigint_t* x, bigint_t* y);
int _gnutls_ecc_ansi_x963_export(ecc_curve_t curve, bigint_t x, bigint_t y, gnutls_datum_t * out);
