#ifdef ENABLE_SRP

int _gnutls_srp_gx(opaque *text, size_t textsize, opaque** result, mpi_t g, mpi_t prime, gnutls_alloc_function);
mpi_t _gnutls_calc_srp_B(mpi_t * ret_b, mpi_t g, mpi_t n, mpi_t v);
mpi_t _gnutls_calc_srp_u( mpi_t A, mpi_t B);
mpi_t _gnutls_calc_srp_S1(mpi_t A, mpi_t b, mpi_t u, mpi_t v, mpi_t n);
mpi_t _gnutls_calc_srp_A(mpi_t *a, mpi_t g, mpi_t n);
mpi_t _gnutls_calc_srp_S2(mpi_t B, mpi_t g, mpi_t x, mpi_t a, mpi_t u, mpi_t n);
int _gnutls_calc_srp_x( char* username, char* password, opaque* salt, size_t salt_size, size_t* size, void* digest);
int _gnutls_srp_gn( opaque** ret_g, opaque** ret_n, int bits);

/* g is defined to be 2 */
#define SRP_MAX_HASH_SIZE 24

#endif
