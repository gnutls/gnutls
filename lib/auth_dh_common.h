#ifndef AUTH_DH_COMMON
# define AUTH_DH_COMMON

typedef struct dh_info_st {
    int secret_bits;

    opaque prime[1025];
    size_t prime_size;
    opaque generator[16];
    size_t generator_size;
    opaque public_key[1025];
    size_t public_key_size;
} dh_info_t;

int _gnutls_gen_dh_common_client_kx(gnutls_session, opaque **);
int _gnutls_proc_dh_common_client_kx(gnutls_session session, opaque * data,
				     size_t _data_size, mpi_t p, mpi_t g);
int _gnutls_dh_common_print_server_kx(gnutls_session, mpi_t g,
				      mpi_t p, opaque ** data);
int _gnutls_proc_dh_common_server_kx(gnutls_session session, opaque * data,
				     size_t _data_size);

#endif
