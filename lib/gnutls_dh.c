#include <defines.h>
#include <gnutls_int.h>

/* Taken from gsti */

static const uint8 diffie_hellman_group1_prime[130] = { 0x04, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
    0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
    0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
    0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
    0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
    0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF  };

#if 0 
        --Example--
     you:  X = g^x mod p;
     peer: Y = g^y mod p;
     
     your_key = Y^x mod p;
     his_key  = X^y mod p;
     
     /* generate our secret and the public value for it */
       X = _gnutls_calc_dh_secret( &x );
     /* now we can calculate the shared secret */
       key = _gnutls_calc_dh_key( Y, x);
       mpi_release( x );
       mpi_release( g );
#endif

/****************
 * Choose a random value x and calculate e = g^x mod p.
 * Return: e and if ret_x is not NULL x.
 * It also returns g and p.
 */
MPI _gnutls_calc_dh_secret( MPI *ret_x )
{
    MPI e, g, x, prime;
    size_t n = sizeof diffie_hellman_group1_prime;

     if( gcry_mpi_scan( &prime, GCRYMPI_FMT_STD,
		       diffie_hellman_group1_prime, &n ) )
	abort();
    /*dump_mpi(stderr, "prime=", prime );*/

    g = mpi_set_ui( NULL, 2 );
    x = mpi_new( 200 );  /* FIXME: allocate in secure memory */
    gcry_mpi_randomize( x, 200, GCRY_STRONG_RANDOM );
    /* fixme: set high bit of x and select a larger one */

    e = mpi_new(1024);
    mpi_powm( e, g, x, prime );

    if( ret_x )
	*ret_x = x;
    else
	mpi_release(x);
	mpi_release(g);
	mpi_release(prime);
    return e;
}

MPI __gnutls_calc_dh_secret( MPI *ret_x, MPI g, MPI prime )
{
    MPI e, x;

    x = mpi_new( 200 );  /* FIXME: allocate in secure memory */
    gcry_mpi_randomize( x, 200, GCRY_STRONG_RANDOM );
    /* fixme: set high bit of x and select a larger one */

    e = mpi_new(1024);
    mpi_powm( e, g, x, prime );

    if( ret_x )
	*ret_x = x;
    else
	mpi_release(x);
    return e;
}

/* returns g and p */
MPI _gnutls_get_dh_params( MPI *ret_p )
{
    MPI g, prime;
    size_t n = sizeof diffie_hellman_group1_prime;

     if( gcry_mpi_scan( &prime, GCRYMPI_FMT_STD,
		       diffie_hellman_group1_prime, &n ) )
	abort();

    g = mpi_set_ui( NULL, 2 );

    if( ret_p )
	*ret_p = prime;
    else
	mpi_release(prime);
    return g;
}


MPI _gnutls_calc_dh_key( MPI f, MPI x )
{
    MPI k, prime;
    size_t n = sizeof diffie_hellman_group1_prime;

    k = mpi_new( 1024 );  /* FIXME: allocate in secure memory */
     if( gcry_mpi_scan( &prime, GCRYMPI_FMT_STD,
		       diffie_hellman_group1_prime, &n ) )
	abort();
    /*dump_mpi(stderr, "prime=", prime );*/

    mpi_powm( k, f, x, prime );
    mpi_release(prime);
    return k;
}

MPI __gnutls_calc_dh_key( MPI f, MPI x, MPI prime )
{
    MPI k;

    k = mpi_new( 1024 );  /* FIXME: allocate in secure memory */

    mpi_powm( k, f, x, prime );
    return k;
}

