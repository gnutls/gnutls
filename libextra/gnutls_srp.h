#ifdef ENABLE_SRP

int _gnutls_srp_gx(opaque *text, size_t textsize, opaque** result, GNUTLS_MPI g, GNUTLS_MPI prime, gnutls_alloc_function);
GNUTLS_MPI _gnutls_calc_srp_B(GNUTLS_MPI * ret_b, GNUTLS_MPI g, GNUTLS_MPI n, GNUTLS_MPI v);
GNUTLS_MPI _gnutls_calc_srp_u( GNUTLS_MPI A, GNUTLS_MPI B);
GNUTLS_MPI _gnutls_calc_srp_S1(GNUTLS_MPI A, GNUTLS_MPI b, GNUTLS_MPI u, GNUTLS_MPI v, GNUTLS_MPI n);
GNUTLS_MPI _gnutls_calc_srp_A(GNUTLS_MPI *a, GNUTLS_MPI g, GNUTLS_MPI n);
GNUTLS_MPI _gnutls_calc_srp_S2(GNUTLS_MPI B, GNUTLS_MPI g, GNUTLS_MPI x, GNUTLS_MPI a, GNUTLS_MPI u, GNUTLS_MPI n);
int _gnutls_calc_srp_x( char* username, char* password, opaque* salt, size_t salt_size, size_t* size, void* digest);
int _gnutls_srp_gn( opaque** ret_g, opaque** ret_n, int bits);

/* g is defined to be 2 */
#define SRP_MAX_HASH_SIZE 24

#endif
