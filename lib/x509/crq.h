#ifndef CRQ_H
# define CRQ_H

typedef struct gnutls_x509_crq_int {
    ASN1_TYPE crq;
} gnutls_x509_crq_int;

typedef struct gnutls_x509_crq_int *gnutls_x509_crq_t;

int gnutls_x509_crq_get_dn_by_oid(gnutls_x509_crq_t crq, const char *oid,
				  int indx, unsigned int raw_flag,
				  void *buf, size_t * sizeof_buf);

int gnutls_x509_crq_init(gnutls_x509_crq_t * crq);
void gnutls_x509_crq_deinit(gnutls_x509_crq_t crq);

int gnutls_x509_crq_import(gnutls_x509_crq_t crq,
			   const gnutls_datum_t * data,
			   gnutls_x509_crt_fmt_t format);

int gnutls_x509_crq_get_pk_algorithm(gnutls_x509_crq_t crq,
				     unsigned int *bits);

#endif
