#!/usr/bin/env bash
# a recipe for tests/cert-tests/data/name-constraints-ip-nodn.pem
set -xEeuo pipefail; shopt -s inherit_errexit

srcdir=${srcdir:-.}
certtool=${CERTTOOL:-certtool}
export TZ=UTC

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cat > "$tmp/key.pem" <<'EOF'
-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKCn9CbgYaa9e2nx2aQx7cKCprlnFhQq9+ZQP8uTHxktqJJv42Dk
1D+4LovTlAiykMForNbig4hEQptJgouSjsECAwEAAQJBAJAi32vZuALO0WDV+TvV
B8mRSl/g2vAxNMRPj0znq+j7n9UTQ48BJiWfoo8Pd8JC3jHCGiQ4XmQapgnw5BNJ
YhkCIQDP5LtoD/7NHmnaw2PRPISrN7+FJLkLsdmbDOuwoRIJAwIhAMXU9HR6ryEG
D24hMeE/9sHKIcIcDhjOuR6kIcMqDcPrAiAPbrpeujk+/s/61mBVivmKQEQuXRCD
hrtRoD7qyLovAwIgaXJc6kkKV9vXFahz4dAqQpju7Xvut6JYYdCyfkhIFgkCICTd
O2hMz0XPCQ3h4mha79QTgleX3DT2xO/gusx/cX3F
-----END RSA PRIVATE KEY-----
EOF

cat > "$tmp/root.tmpl" <<'EOF'
country = US
organization = "Foo Bar Inc."
cn = "Foo Bar Root CA"
unit = "Public Key Infrastructure"
serial = 1
expiration_days = 3650
ca
cert_signing_key
crl_signing_key
EOF

cat > "$tmp/sub.tmpl" <<'EOF'
country = US
organization = "Foo Bar Inc."
cn = "Foo Bar Sub CA 1"
unit = "Public Key Infrastructure"
serial = 2
expiration_days = 3650
ca
path_len = 0
cert_signing_key
crl_signing_key
tls_www_client
tls_www_server
crl_dist_points = "http://pki.foobar.com/root-ca.crl"
ca_issuers_uri = "http://pki.foobar.com/root-ca.crt"
nc_permit_dns = foobar.com
nc_permit_dns = foobar.email
nc_exclude_dns = www.foobar.com
nc_exclude_dns = www.foobar.email
nc_exclude_ip = 0.0.0.0/0
nc_exclude_ip = ::/0
EOF

cat > "$tmp/leaf.tmpl" <<'EOF'
country = US
organization = "Foo Bar Inc."
cn = "bazz.foobar.com"
serial = 3
expiration_days = 365
signing_key
encryption_key
tls_www_client
tls_www_server
dns_name = "update.foobar.com"
dns_name = "mx.foobar.email"
crl_dist_points = "http://ca1.pki.foobar.com/ca1.crl"
ca_issuers_uri = "http://ca1.pki.foobar.com/ca1.crt"
EOF

$certtool --attime "2016-04-22" --generate-self-signed \
          --template "$tmp/root.tmpl" --load-privkey "$tmp/key.pem" \
          --outfile "$tmp/root.pem"
$certtool --attime "2016-04-22" --generate-certificate \
          --template "$tmp/sub.tmpl" --load-privkey "$tmp/key.pem" \
          --load-ca-certificate "$tmp/root.pem" \
          --load-ca-privkey "$tmp/key.pem" \
          --outfile "$tmp/sub.pem"
$certtool --attime "2016-04-22" --generate-certificate \
          --template "$tmp/leaf.tmpl" --load-privkey "$tmp/key.pem" \
          --load-ca-certificate "$tmp/sub.pem" \
          --load-ca-privkey "$tmp/key.pem" \
          --outfile "$tmp/leaf.pem"

cat "$tmp/leaf.pem" "$tmp/root.pem" "$tmp/sub.pem" > "$tmp/chain.pem"
diff -u "$tmp/chain.pem" \
        "$srcdir/tests/cert-tests/data/name-constraints-ip-nodn.pem"

$certtool --attime "2016-04-22" --verify-allow-broken -e \
	  --infile "$tmp/chain.pem"
