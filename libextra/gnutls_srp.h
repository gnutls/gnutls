#ifdef ENABLE_SRP

int _gnutls_srp_gx(opaque *text, size_t textsize, opaque** result, MPI g, MPI prime);
MPI _gnutls_calc_srp_B(MPI * ret_b, MPI g, MPI n, MPI v);
MPI _gnutls_calc_srp_u( MPI B);
MPI _gnutls_calc_srp_S1(MPI A, MPI b, MPI u, MPI v, MPI n);
MPI _gnutls_calc_srp_A(MPI *a, MPI g, MPI n);
MPI _gnutls_calc_srp_S2(MPI B, MPI g, MPI x, MPI a, MPI u, MPI n);
int _gnutls_calc_srp_x( char* username, char* password, opaque* salt, size_t salt_size, size_t* size, void* digest);
int _gnutls_srp_gn( opaque** ret_g, opaque** ret_n, int bits);

/* our prime */
extern const uint8 diffie_hellman_group1_prime[130];

/* g is defined to be 2 */
#define SRP_MAX_HASH_SIZE 24

#endif
