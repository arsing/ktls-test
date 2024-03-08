use std::net::TcpStream;

use nix::{
    poll::{poll, PollFd, PollFlags},
    sys::socket::sockopt::TlsCryptoInfo,
};

#[cfg(feature = "openssl")]
pub(crate) fn openssl_prepare(
    context_builder: &mut openssl::ssl::SslContextBuilder,
    tls_allowed: (bool, bool),
    cipher_suites_allowed: (bool, bool, bool),
) -> std::sync::Arc<std::sync::Mutex<(Option<Vec<u8>>, Option<Vec<u8>>)>> {
    use std::sync::{Arc, Mutex};

    use openssl::ssl::SslVersion;

    // We don't use session tickets, and setting it to 0 guarantees that
    // the openssl server doesn't send any session tickets during a handshake
    // and thus cause the sequence number to be greater than 0.
    context_builder.set_num_tickets(0).unwrap();

    context_builder
        .set_min_proto_version(Some(if tls_allowed.0 {
            SslVersion::TLS1_2
        } else {
            SslVersion::TLS1_3
        }))
        .unwrap();
    context_builder
        .set_max_proto_version(Some(if tls_allowed.1 {
            SslVersion::TLS1_3
        } else {
            SslVersion::TLS1_2
        }))
        .unwrap();

    // kTLS supports a limited set of ciphersuites, of which only AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305
    // are relevant for a modern implementation. So we only negotiate AES-256-GCM, CHACHA20-POLY1305 and AES-128-GCM, in that order.
    // We also only support ECDHE, not DHE, because again DHE is not relevant for a modern implementation.
    //
    // The ordering of AES-256-GCM -> Chacha20-Poly1305 -> AES-128-GCM is is in line with openssl's default (`openssl ciphers`),
    // though notably not in line with rustls which does AES-256-GCM -> AES-128-GCM -> Chacha20-Poly1305 instead. [1] [2]
    //
    // [1]: https://github.com/rustls/rustls/issues/509
    //
    // [2]: https://github.com/rustls/rustls/commit/7117a805e0104705da50259357d8effa7d599e37
    let mut tls12_cipher_suites = String::new();
    let mut tls13_cipher_suites = String::new();
    if cipher_suites_allowed.1 {
        tls12_cipher_suites.push_str("ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384");
        tls13_cipher_suites.push_str("TLS_AES_256_GCM_SHA384:");
    }
    if cipher_suites_allowed.2 {
        tls12_cipher_suites.push_str("ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:");
        tls13_cipher_suites.push_str("TLS_CHACHA20_POLY1305_SHA256:");
    }
    if cipher_suites_allowed.0 {
        tls12_cipher_suites.push_str("ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:");
        tls13_cipher_suites.push_str("TLS_AES_128_GCM_SHA256:");
    }
    context_builder
        .set_cipher_list(tls12_cipher_suites.trim_end_matches(':'))
        .unwrap();
    context_builder
        .set_ciphersuites(tls13_cipher_suites.trim_end_matches(':'))
        .unwrap();

    // For TLS 1.2, we can derive traffic secrets ourselves using the master key.
    //
    // For TLS 1.3, the derivation uses the handshake hash which openssl does not expose.
    // However openssl does expose the traffic secrets through the keylog callback, so we use that.
    let traffic_secrets = Arc::new(Mutex::new((None, None)));
    context_builder.set_keylog_callback({
        let traffic_secrets = traffic_secrets.clone();
        move |_ssl, line| {
            // Ref: https://web.archive.org/web/20230425034128/https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/index.html
            let (name, rest) = line.split_once(' ').unwrap();
            match name {
                "CLIENT_TRAFFIC_SECRET_0" => {
                    let (_client_random, value_hex) = rest.split_once(' ').unwrap();
                    let value = hex::decode(value_hex);
                    traffic_secrets.lock().unwrap().0 = Some(value);
                }

                "SERVER_TRAFFIC_SECRET_0" => {
                    let (_client_random, value_hex) = rest.split_once(' ').unwrap();
                    let value = hex::decode(value_hex);
                    traffic_secrets.lock().unwrap().1 = Some(value);
                }

                _ => (),
            }
        }
    });

    traffic_secrets
}

#[cfg(feature = "openssl")]
pub(crate) fn openssl<'a>(
    stream: &TcpStream,
    traffic_secrets: &std::sync::Arc<std::sync::Mutex<(Option<Vec<u8>>, Option<Vec<u8>>)>>,
    mut result: Result<
        openssl::ssl::SslStream<&'a TcpStream>,
        openssl::ssl::HandshakeError<&'a TcpStream>,
    >,
) -> (TlsCryptoInfo, TlsCryptoInfo) {
    use std::os::fd::AsFd as _;

    use nix::poll::PollTimeout;
    use openssl::ssl::{ErrorCode, HandshakeError};

    use opensslext::ssl::ExtractedSecrets;

    #[allow(clippy::needless_pass_by_value)] // Clippy wants `extracted_secret` to be a borrow because all its fields are Copy.
    fn make_tls_crypto_info(
        protocol_version: openssl::ssl::SslVersion,
        extracted_secret: (u64, opensslext::ssl::ConnectionTrafficSecrets),
    ) -> TlsCryptoInfo {
        use openssl::ssl::SslVersion;

        use opensslext::ssl::ConnectionTrafficSecrets;

        let tls_crypto_info = libc::tls_crypto_info {
            version: match protocol_version {
                SslVersion::TLS1_2 => libc::TLS_1_2_VERSION,
                SslVersion::TLS1_3 => libc::TLS_1_3_VERSION,
                protocol_version => unreachable!("expected OpenSSL to negotiate TLS 1.2 or 1.3 because of openssl_prepare but it negotiated {protocol_version:?}"),
            },

            cipher_type: match &extracted_secret.1 {
                ConnectionTrafficSecrets::Aes128Gcm { .. } => libc::TLS_CIPHER_AES_GCM_128,
                ConnectionTrafficSecrets::Aes256Gcm { .. } => libc::TLS_CIPHER_AES_GCM_256,
                ConnectionTrafficSecrets::Chacha20Poly1305 { .. } => {
                    libc::TLS_CIPHER_CHACHA20_POLY1305
                }
            },
        };

        match extracted_secret {
            (rec_seq, ConnectionTrafficSecrets::Aes128Gcm { key, salt, iv }) => {
                TlsCryptoInfo::Aes128Gcm(libc::tls12_crypto_info_aes_gcm_128 {
                    info: tls_crypto_info,
                    iv,
                    key,
                    salt,
                    rec_seq: rec_seq.to_be_bytes(),
                })
            }

            (rec_seq, ConnectionTrafficSecrets::Aes256Gcm { key, salt, iv }) => {
                TlsCryptoInfo::Aes256Gcm(libc::tls12_crypto_info_aes_gcm_256 {
                    info: tls_crypto_info,
                    iv,
                    key,
                    salt,
                    rec_seq: rec_seq.to_be_bytes(),
                })
            }

            (rec_seq, ConnectionTrafficSecrets::Chacha20Poly1305 { key, salt, iv }) => {
                TlsCryptoInfo::Chacha20Poly1305(libc::tls12_crypto_info_chacha20_poly1305 {
                    info: tls_crypto_info,
                    iv,
                    key,
                    salt,
                    rec_seq: rec_seq.to_be_bytes(),
                })
            }
        }
    }

    let ssl_stream = loop {
        match result {
            Ok(ssl_stream) => break ssl_stream,

            Err(HandshakeError::WouldBlock(mid_handshake_stream)) => {
                let mut events = PollFlags::empty();
                let err = mid_handshake_stream.error();
                match err.code() {
                    ErrorCode::WANT_READ => events |= PollFlags::POLLIN,
                    ErrorCode::WANT_WRITE => events |= PollFlags::POLLOUT,
                    _ => panic!("{err}"),
                };
                if !events.is_empty() {
                    let mut poll_fds = [PollFd::new(stream.as_fd(), PollFlags::empty())];
                    poll_fds[0].set_events(events);
                    _ = poll(&mut poll_fds, PollTimeout::NONE).unwrap();
                }

                result = mid_handshake_stream.handshake();
            }

            Err(err) => panic!("{err}"),
        }
    };

    // =================================================
    // Extract TLS parameters needed to initialize kTLS.
    // =================================================

    let ssl = ssl_stream.ssl();

    let protocol_version = ssl.version2().unwrap();
    eprintln!(
        "INFO: using {} {:?}",
        ssl.version_str(),
        ssl.current_cipher().unwrap(),
    );

    let traffic_secrets = &*traffic_secrets.lock().unwrap();
    let ExtractedSecrets { client, server } = opensslext::ssl::extract_secrets(
        ssl,
        traffic_secrets.0.as_deref(),
        traffic_secrets.1.as_deref(),
    )
    .unwrap();

    if ssl.is_server() {
        let tx = make_tls_crypto_info(protocol_version, server);
        let rx = make_tls_crypto_info(protocol_version, client);

        (tx, rx)
    } else {
        let tx = make_tls_crypto_info(protocol_version, client);
        let rx = make_tls_crypto_info(protocol_version, server);

        (tx, rx)
    }
}

#[cfg(feature = "rustls")]
pub(crate) fn rustls_prepare<TConfig>(
    config_builder: impl FnOnce(
        &[&'static rustls::SupportedProtocolVersion],
    ) -> rustls::ConfigBuilder<TConfig, rustls::WantsVerifier>,
    tls_allowed: (bool, bool),
    cipher_suites_allowed: (bool, bool, bool),
) -> rustls::ConfigBuilder<TConfig, rustls::WantsVerifier>
where
    TConfig: rustls::ConfigSide,
{
    use rustls::crypto::{ring as rustls_provider, CryptoProvider};

    // =================================
    // Set up TLS connection parameters.
    // =================================

    // Order is TLS 1.3 -> TLS 1.2
    let mut protocol_versions = vec![];
    if tls_allowed.1 {
        protocol_versions.push(&rustls::version::TLS13);
    }
    if tls_allowed.0 {
        protocol_versions.push(&rustls::version::TLS12);
    }

    // Order is AES-256-GCM -> CHACHA20-POLY1305 -> AES-128-GCM for cipher algorithm,
    // and ECDSA -> RSA for certificate key algorithm.
    //
    // The cipher algorithm order is in line with openssl, though not with rustls
    // which prefers AES-128-GCM to CHACHA20-POLY1305. [1] [2]
    //
    // [1]: https://github.com/rustls/rustls/issues/509
    //
    // [2]: https://github.com/rustls/rustls/commit/7117a805e0104705da50259357d8effa7d599e37
    let mut cipher_suites = vec![];
    if cipher_suites_allowed.1 {
        cipher_suites.extend([
            rustls_provider::cipher_suite::TLS13_AES_256_GCM_SHA384,
            rustls_provider::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            rustls_provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ]);
    }
    if cipher_suites_allowed.2 {
        cipher_suites.extend([
            rustls_provider::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
            rustls_provider::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            rustls_provider::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ]);
    }
    if cipher_suites_allowed.0 {
        cipher_suites.extend([
            rustls_provider::cipher_suite::TLS13_AES_128_GCM_SHA256,
            rustls_provider::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            rustls_provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ]);
    }

    let crypto_provider = CryptoProvider {
        cipher_suites,
        ..rustls_provider::default_provider()
    };
    crypto_provider.install_default().unwrap();

    config_builder(&protocol_versions)
}

#[cfg(feature = "rustls")]
pub(crate) fn rustls(
    mut stream: &TcpStream,
    mut conn: rustls::Connection,
) -> (TlsCryptoInfo, TlsCryptoInfo) {
    use std::{io::ErrorKind, os::fd::AsFd as _};

    use nix::poll::PollTimeout;
    use rustls::ExtractedSecrets;

    #[allow(clippy::needless_pass_by_value)] // Clippy wants `extracted_secret` to be a borrow because all its fields are Copy.
    fn make_tls_crypto_info(
        protocol_version: rustls::ProtocolVersion,
        extracted_secret: (u64, rustls::ConnectionTrafficSecrets),
    ) -> TlsCryptoInfo {
        use rustls::{ConnectionTrafficSecrets, ProtocolVersion};

        let tls_crypto_info = libc::tls_crypto_info {
            version: match protocol_version {
                ProtocolVersion::TLSv1_2 => libc::TLS_1_2_VERSION,
                ProtocolVersion::TLSv1_3 => libc::TLS_1_3_VERSION,
                protocol_version => unreachable!("expected rustls to negotiate TLS 1.2 or 1.3 because of rustls_prepare but it negotiated {protocol_version:?}"),
            },

            cipher_type: match &extracted_secret.1 {
                ConnectionTrafficSecrets::Aes128Gcm { .. } => libc::TLS_CIPHER_AES_GCM_128,
                ConnectionTrafficSecrets::Aes256Gcm { .. } => libc::TLS_CIPHER_AES_GCM_256,
                ConnectionTrafficSecrets::Chacha20Poly1305 { .. } => {
                    libc::TLS_CIPHER_CHACHA20_POLY1305
                }
                _ => unimplemented!(),
            },
        };

        match extracted_secret {
            (rec_seq, ConnectionTrafficSecrets::Aes128Gcm { key, iv }) => {
                let (salt, iv) = iv.as_ref().split_at(4);
                TlsCryptoInfo::Aes128Gcm(libc::tls12_crypto_info_aes_gcm_128 {
                    info: tls_crypto_info,
                    iv: iv.try_into().unwrap(),
                    key: key.as_ref().try_into().unwrap(),
                    salt: salt.try_into().unwrap(),
                    rec_seq: rec_seq.to_be_bytes(),
                })
            }

            (rec_seq, ConnectionTrafficSecrets::Aes256Gcm { key, iv }) => {
                let (salt, iv) = iv.as_ref().split_at(4);
                TlsCryptoInfo::Aes256Gcm(libc::tls12_crypto_info_aes_gcm_256 {
                    info: tls_crypto_info,
                    iv: iv.try_into().unwrap(),
                    key: key.as_ref().try_into().unwrap(),
                    salt: salt.try_into().unwrap(),
                    rec_seq: rec_seq.to_be_bytes(),
                })
            }

            (rec_seq, ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv }) => {
                TlsCryptoInfo::Chacha20Poly1305(libc::tls12_crypto_info_chacha20_poly1305 {
                    info: tls_crypto_info,
                    iv: iv.as_ref().try_into().unwrap(),
                    key: key.as_ref().try_into().unwrap(),
                    salt: [],
                    rec_seq: rec_seq.to_be_bytes(),
                })
            }

            _ => unimplemented!(),
        }
    }

    // =======================
    // Perform TLS handshake.
    // =======================

    let mut revents = PollFlags::POLLIN | PollFlags::POLLOUT;
    while conn.is_handshaking() {
        let mut events = PollFlags::empty();
        if conn.wants_read() && !revents.contains(PollFlags::POLLIN) {
            events |= PollFlags::POLLIN;
        }
        if conn.wants_write() && !revents.contains(PollFlags::POLLOUT) {
            events |= PollFlags::POLLOUT;
        }
        if !events.is_empty() {
            let mut poll_fds = [PollFd::new(stream.as_fd(), PollFlags::empty())];
            poll_fds[0].set_events(events);
            let previous_revents = revents;
            _ = poll(&mut poll_fds, PollTimeout::NONE).unwrap();
            revents = previous_revents | poll_fds[0].revents().unwrap_or_else(PollFlags::empty);
        }

        if revents.contains(PollFlags::POLLIN) && conn.wants_read() {
            match conn.read_tls(&mut stream) {
                Ok(0) => panic!("EOF during handshake"),
                Ok(_) => _ = conn.process_new_packets().unwrap(),
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    revents.remove(PollFlags::POLLIN);
                }
                Err(err) => panic!("{err}"),
            }
        }

        if revents.contains(PollFlags::POLLOUT) && conn.wants_write() {
            match conn.write_tls(&mut stream) {
                Ok(0) => panic!("EOF during handshake"),
                Ok(_) => (),
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    revents.remove(PollFlags::POLLOUT);
                }
                Err(err) => panic!("{err}"),
            }
        }
    }

    // =================================================
    // Extract TLS parameters needed to initialize kTLS.
    // =================================================

    let protocol_version = conn.protocol_version().unwrap();
    eprintln!(
        "INFO: using {protocol_version:?} {:?}",
        conn.negotiated_cipher_suite(),
    );

    let ExtractedSecrets { tx, rx } = conn.dangerous_extract_secrets().unwrap();
    let tx = make_tls_crypto_info(protocol_version, tx);
    let rx = make_tls_crypto_info(protocol_version, rx);

    (tx, rx)
}

#[cfg(feature = "openssl")]
mod hex {
    /// Map of ASCII hex char -> corresponding numeric value
    #[rustfmt::skip] // Prevent rustfmt from mangling the grid layout.
    const NIBBLE_TO_HEX_LOOKUP_TABLE: [u8; 256] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 0x30: b'0'.. */ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, /* 0x61: b'a'.. */ 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    /// Decoded the given hex string.
    pub(super) fn decode(s: &str) -> Vec<u8> {
        let len = s.len() / 2;
        let mut result = Vec::with_capacity(len);

        // TODO(rustup): Use slice::array_chunks when that is stabilized.
        for (dst, src) in result.spare_capacity_mut()[..len]
            .iter_mut()
            .zip(s.as_bytes().chunks_exact(2))
        {
            dst.write(
                (NIBBLE_TO_HEX_LOOKUP_TABLE[usize::from(src[0])] << 4)
                    | NIBBLE_TO_HEX_LOOKUP_TABLE[usize::from(src[1])],
            );
        }

        unsafe {
            result.set_len(len);
        }

        result
    }
}
