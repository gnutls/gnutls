# Generate and add new protocol traces 

Compile GnuTLS as:
```
./configure --enable-fuzzer-target --disable-doc
```

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

cp /tmp/server-trace-x509 fuzz/gnutls_client_fuzzer.in/$(sha1sum /tmp/server-trace-x509|cut -d ' ' -f 1)
cp /tmp/server-trace-psk1 fuzz/gnutls_psk_client_fuzzer.in/$(sha1sum /tmp/server-trace-psk1|cut -d ' ' -f 1)
cp /tmp/server-trace-psk2 fuzz/gnutls_psk_client_fuzzer.in/$(sha1sum /tmp/server-trace-psk2|cut -d ' ' -f 1)

cp /tmp/client-trace-x509 fuzz/gnutls_server_fuzzer.in/$(sha1sum /tmp/client-trace-x509|cut -d ' ' -f 1)
cp /tmp/client-trace-psk1 fuzz/gnutls_psk_server_fuzzer.in/$(sha1sum /tmp/client-trace-psk1|cut -d ' ' -f 1)
cp /tmp/client-trace-psk2 fuzz/gnutls_psk_server_fuzzer.in/$(sha1sum /tmp/client-trace-psk2|cut -d ' ' -f 1)
