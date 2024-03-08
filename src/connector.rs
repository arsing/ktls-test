use std::net::TcpStream;

#[cfg(any(feature = "openssl", feature = "rustls"))]
use nix::sys::socket::{
    setsockopt,
    sockopt::{TcpTlsRx, TcpTlsTx, TcpUlp},
};

#[cfg(any(feature = "openssl", feature = "rustls"))]
use crate::handshake;

pub(crate) fn connect(
    hostname: &str,
    port: u16,
    tls_allowed: (bool, bool),
    cipher_suites_allowed: (bool, bool, bool),
) -> TcpStream {
    // ====================
    // Make TCP connection.
    // ====================

    let stream = TcpStream::connect((hostname, port)).unwrap();
    stream.set_nonblocking(true).unwrap();

    // =======================
    // Perform TLS handshake.
    // =======================

    #[cfg(not(any(feature = "openssl", feature = "rustls")))]
    {
        _ = tls_allowed;
        _ = cipher_suites_allowed;
    }

    #[cfg(feature = "openssl")]
    let (tx, rx) = {
        use openssl::ssl::{SslConnector, SslMethod};

        let mut connector = SslConnector::builder(SslMethod::tls_client()).unwrap();

        let traffic_secrets =
            handshake::openssl_prepare(&mut connector, tls_allowed, cipher_suites_allowed);

        let connector = connector.build();

        handshake::openssl(
            &stream,
            &traffic_secrets,
            connector.connect(hostname, &stream),
        )
    };

    #[cfg(feature = "rustls")]
    let (tx, rx) = {
        use rustls::{ClientConfig, ClientConnection, Connection, RootCertStore};

        let root_store = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_owned(),
        };

        let mut config = handshake::rustls_prepare(
            ClientConfig::builder_with_protocol_versions,
            tls_allowed,
            cipher_suites_allowed,
        )
        .with_root_certificates(root_store)
        .with_no_client_auth();
        config.enable_secret_extraction = true;
        let config = std::sync::Arc::new(config);

        let name = hostname.to_owned().try_into().unwrap();

        let conn = ClientConnection::new(config, name).unwrap();

        handshake::rustls(&stream, Connection::Client(conn))
    };

    // ================
    // Initialize kTLS.
    // ================

    #[cfg(any(feature = "openssl", feature = "rustls"))]
    {
        () = setsockopt(&stream, TcpUlp::default(), b"tls").unwrap();
        () = setsockopt(&stream, TcpTlsTx, &tx).unwrap();
        () = setsockopt(&stream, TcpTlsRx, &rx).unwrap();
    }

    stream
}
