MPI gnutls_calc_dh_secret( MPI *ret_x );
MPI gnutls_get_dh_params(MPI *ret_p);
MPI gnutls_calc_dh_key( MPI f, MPI x );
MPI _gnutls_calc_dh_secret( MPI *ret_x, MPI g, MPI prime );
MPI _gnutls_calc_dh_key( MPI f, MPI x, MPI prime );
