# Generate and add new protocol traces 

## Step 1: compilation

Compile GnuTLS as:
```
./configure --enable-fuzzer-target --disable-doc
```

## Step 2: Get the traces

Start the server with the necessary parameters (here TLS1.3 is assumed).
```
./gnutls-http-serv --priority NORMAL:-VERS-ALL:+VERS-TLS1.3
```

Get the traces:
```
gnutls-cli localhost:5556 --priority NORMAL:-VERS-ALL:+VERS-TLS1.3 --insecure --save-server-trace /tmp/server-trace-x509 --save-client-trace /tmp/client-trace-x509 
gnutls-cli localhost:5556 --priority NORMAL:-VERS-ALL:+VERS-TLS1.3:-KX-ALL:+PSK --insecure --save-server-trace /tmp/server-trace-psk1 --save-client-trace /tmp/client-trace-psk1 --pskusername test --pskkey 8a7759b3f26983c453e448060bde8981
gnutls-cli localhost:5556 --priority NORMAL:-VERS-ALL:+VERS-TLS1.3:-KX-ALL:+DHE-PSK --insecure --save-server-trace /tmp/server-trace-psk2 --save-client-trace /tmp/client-trace-psk2 --pskusername test --pskkey 8a7759b3f26983c453e448060bde8981
```

## Step 3: Ensure server can read them

If there is a new key type tested, ensure that `gnutls_server_fuzzer` and
`gnutls_client_fuzzer` enable it, and set the appropriate keys.

To verify that connection proceeds past to reading the first packet use:
$ make gnutls_server_fuzzer gnutls_client_fuzzer
$ GNUTLS_DEBUG_LEVEL=6 gnutls_server_fuzzer /tmp/server-trace-x509
$ GNUTLS_DEBUG_LEVEL=6 gnutls_client_fuzzer /tmp/client-trace-x509


## Step 4: Copy the traces

cp /tmp/server-trace-x509 fuzz/gnutls_client_fuzzer.in/$(sha1sum /tmp/server-trace-x509|cut -d ' ' -f 1)
cp /tmp/server-trace-psk1 fuzz/gnutls_psk_client_fuzzer.in/$(sha1sum /tmp/server-trace-psk1|cut -d ' ' -f 1)
cp /tmp/server-trace-psk2 fuzz/gnutls_psk_client_fuzzer.in/$(sha1sum /tmp/server-trace-psk2|cut -d ' ' -f 1)

cp /tmp/client-trace-x509 fuzz/gnutls_server_fuzzer.in/$(sha1sum /tmp/client-trace-x509|cut -d ' ' -f 1)
cp /tmp/client-trace-psk1 fuzz/gnutls_psk_server_fuzzer.in/$(sha1sum /tmp/client-trace-psk1|cut -d ' ' -f 1)
cp /tmp/client-trace-psk2 fuzz/gnutls_psk_server_fuzzer.in/$(sha1sum /tmp/client-trace-psk2|cut -d ' ' -f 1)
