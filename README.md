A test of using Kernel TLS from Rust.


# Run

```sh
# HTTPS using OpenSSL
make openssl && strace -fe network,writev,poll -- ./target/debug/ktls-test

# HTTPS using Rustls
make rustls && strace -fe network,writev,poll -- ./target/debug/ktls-test

# Unencrypted HTTP
make http && strace -fe network,writev,poll -- ./target/debug/ktls-test
```

Each of these does an HTTP 1.0 GET to `www.google.com/`. In the `openssl` and `rustls` cases, the corresponding library is used for the initial TLS handshake, and post-handshake traffic is done using kTLS. The `http` case does the request over unencrypted TCP and acts as a baseline for the HTTP request behavior.

If everything goes well, the HTTP response from the server will be printed and the connection will be closed.

Note: If the `setsockopt(_, SOL_TCP, TCP_ULP, "tls", sizeof("tls"))` call fails with `ENOENT`, ensure that `/proc/sys/net/ipv4/tcp_available_ulp` contains `tls`. Load the `tls` kmod if it doesn't.

```
Usage: ktls-test (client | proxy <CERT_FILE> <KEY_FILE>) [tls12] [tls13] [aes128] [aes256] [chacha20]


  ACTION

  client      Make a request to http://www.google.com:80/ (http) or
              https://www.google.com:443/ (openssl, rustls)

  proxy       Listen for an incoming connection on 127.0.0.1:18080 (http) or
              127.0.0.1:18443 (openssl, rustls), and proxy its traffic
              back and forth to http://www.google.com:80/ (http) or
              https://www.google.com:443/ (openssl, rustls)

  <CERT_FILE> Path of a file containing a certificate chain in PEM format
              that will be used as the server cert of the proxy.

  <KEY_FILE>  Path of a file containing a private key in PEM format
              of the leaf server cert in <CERT_FILE>.


  TLS VERSIONS

  tls12       Enable TLS 1.2 support
  tls13       Enable TLS 1.3 support

              If neither tls12 nor tls13 are specified,
              then both are enabled.


  CIPHERSUITES

  aes128      Enable AES-128-GCM support
  aes256      Enable AES-256-GCM support
  chacha20    Enable CHACHA20-POLY1305 support

              If none of aes128, aes256 and chacha20 are specified,
              then all three are enabled.

  "TLS VERSIONS" and "CIPHERSUITES" options are ignored in the http case.
```


# Test

## Client

```sh
make -s test && \
make http && ./target/debug/ktls-test client && \
make rustls && for t in '' 'tls12' 'tls13'; do for c in 'aes128' 'aes256' 'chacha20'; do ./target/debug/ktls-test client $t $c || break -1; done || break -1; done && \
make openssl && for t in '' 'tls12' 'tls13'; do for c in 'aes128' 'aes256' 'chacha20'; do ./target/debug/ktls-test client $t $c || break -1; done || break -1; done && \
echo $?
```

## Proxy

```sh
make http && ./target/debug/ktls-test proxy server.pem server.key.pem

curl -vvvv --header 'host:www.google.com' http://127.0.0.1:18080; echo
```

```sh
make openssl && ./target/debug/ktls-test proxy server.pem server.key.pem

curl -kvvvv --header 'host:www.google.com' https://127.0.0.1:18443; echo
```

```sh
make rustls && ./target/debug/ktls-test proxy server.pem server.key.pem

curl -kvvvv --header 'host:www.google.com' https://127.0.0.1:18443; echo
```
