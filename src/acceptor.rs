use std::{
    net::{TcpListener, TcpStream},
    path::Path,
};

#[cfg(any(feature = "openssl", feature = "rustls"))]
use nix::sys::socket::{
    setsockopt,
    sockopt::{TcpTlsRx, TcpTlsTx, TcpUlp},
};

#[cfg(any(feature = "openssl", feature = "rustls"))]
use crate::handshake;

pub(crate) fn accept(
    hostname: &str,
    port: u16,
    tls_allowed: (bool, bool),
    cipher_suites_allowed: (bool, bool, bool),
    cert_file: impl AsRef<Path>,
    key_file: impl AsRef<Path>,
) -> TcpStream {
    let listener = TcpListener::bind((hostname, port)).unwrap();
    let (stream, _) = listener.accept().unwrap();
    stream.set_nonblocking(true).unwrap();

    // =======================
    // Perform TLS handshake.
    // =======================

    #[cfg(not(any(feature = "openssl", feature = "rustls")))]
    {
        _ = tls_allowed;
        _ = cipher_suites_allowed;
        _ = cert_file;
        _ = key_file;
    }

    #[cfg(feature = "openssl")]
    let (tx, rx) = {
        use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

        let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
        acceptor
            .set_certificate_file(cert_file, SslFiletype::PEM)
            .unwrap();
        acceptor
            .set_private_key_file(key_file, SslFiletype::PEM)
            .unwrap();

        let traffic_secrets =
            handshake::openssl_prepare(&mut acceptor, tls_allowed, cipher_suites_allowed);

        let acceptor = acceptor.build();

        handshake::openssl(&stream, &traffic_secrets, acceptor.accept(&stream))
    };

    #[cfg(feature = "rustls")]
    let (tx, rx) = {
        use std::fs;

        use rustls::{pki_types::PrivateKeyDer, Connection, ServerConfig, ServerConnection};

        let certs: Result<_, _> =
            rustls_pemfile::certs(&mut &fs::read(cert_file).unwrap()[..]).collect();
        let certs = certs.unwrap();

        let private_key = rustls_pemfile::pkcs8_private_keys(&mut &fs::read(key_file).unwrap()[..])
            .next()
            .unwrap()
            .unwrap();
        let private_key = PrivateKeyDer::Pkcs8(private_key);

        let mut config = handshake::rustls_prepare(
            ServerConfig::builder_with_protocol_versions,
            tls_allowed,
            cipher_suites_allowed,
        )
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .unwrap();
        config.enable_secret_extraction = true;
        let config = std::sync::Arc::new(config);

        let conn = ServerConnection::new(config).unwrap();

        handshake::rustls(&stream, Connection::Server(conn))
    };

    // ================
    // Initialize kTLS.
    // ================

    #[cfg(any(feature = "openssl", feature = "rustls"))]
    {
        () = setsockopt(&stream, TcpUlp::default(), b"tls\0").unwrap();
        () = setsockopt(&stream, TcpTlsTx, &tx).unwrap();
        () = setsockopt(&stream, TcpTlsRx, &rx).unwrap();
    }

    stream
}
