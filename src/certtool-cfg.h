extern char *organization, *unit, *locality, *state;
extern char *cn, *challenge_password, *password, *pkcs9_email, *country;
extern char *dns_name, *email, *crl_dist_points, *pkcs12_key_name;
extern int serial, expiration_days, ca, tls_www_client, tls_www_server, signing_key;
extern int encryption_key, cert_sign_key, crl_sign_key, code_sign_key, ocsp_sign_key;
extern int time_stamping_key, crl_next_update;

int parse_template(const char *template);
