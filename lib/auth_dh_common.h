#ifndef AUTH_DH_COMMON
# define AUTH_DH_COMMON

typedef struct {
    int secret_bits;

    gnutls_datum_t prime;
    gnutls_datum_t generator;
    gnutls_datum_t public_key;
} dh_info_st;

int _gnutls_gen_dh_common_client_kx(gnutls_session_t, opaque **);
int _gnutls_proc_dh_common_client_kx(gnutls_session_t session,
				     opaque * data, size_t _data_size,
				     mpi_t p, mpi_t g);
int _gnutls_dh_common_print_server_kx(gnutls_session_t, mpi_t g, mpi_t p,
				      opaque ** data);
int _gnutls_proc_dh_common_server_kx(gnutls_session_t session,
				     opaque * data, size_t _data_size);

#endif
