#ifdef ENABLE_SRP

#define IS_SRP_KX(kx) ((kx == GNUTLS_KX_SRP || (kx == GNUTLS_KX_SRP_RSA) || \
          kx == GNUTLS_KX_SRP_DSS)?1:0)

int _gnutls_srp_recv_params(gnutls_session_t state, const opaque * data,
			    size_t data_size);
int _gnutls_srp_send_params(gnutls_session_t state, opaque * data, size_t);

#endif
