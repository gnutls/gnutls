int _gnutls_srp_gx(opaque *text, int textsize, opaque** result, char** ret_g, char** ret_n);
MPI _gnutls_calc_srp_B(MPI * ret_b, MPI g, MPI n, MPI v);
MPI _gnutls_calc_srp_u( MPI B);
MPI _gnutls_calc_srp_S1(MPI A, MPI b, MPI u, MPI v, MPI n);
MPI _gnutls_calc_srp_A(MPI *a, MPI g, MPI n);
MPI _gnutls_calc_srp_S2(MPI B, MPI g, MPI x, MPI a, MPI u, MPI n);
void* _gnutls_calc_srp_x( char* username, char* password, opaque* salt, int salt_size, uint8 crypt_algo);

/* our prime */
extern const uint8 diffie_hellman_group1_prime[130];

/* g is defined to be 2 */
#define SRP_G 2
