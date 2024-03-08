#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::similar_names, clippy::too_many_lines, clippy::type_complexity)]

//! Ref: <https://docs.kernel.org/networking/tls.html>

use std::{
    io::{ErrorKind, IoSlice, Write as _},
    mem::MaybeUninit,
    net::Shutdown,
    os::fd::{AsFd as _, AsRawFd as _},
    path::Path,
    ptr,
};

use nix::poll::{poll, PollFd, PollFlags, PollTimeout};

mod acceptor;
mod connector;
#[cfg(any(feature = "openssl", feature = "rustls"))]
mod handshake;
mod tls_io;

fn main() {
    const HOSTNAME: &str = "www.google.com";

    let mut role = None;
    let mut cert_file = None;
    let mut key_file = None;
    #[cfg_attr(
        not(any(feature = "openssl", feature = "rustls")),
        allow(unused_variables)
    )]
    let (tls_allowed, cipher_suites_allowed) = {
        let mut tls_allowed = None;
        let mut cipher_suites_allowed = None;
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match &*arg {
                "client" => role = Some(Role::Client),
                "proxy" => {
                    role = Some(Role::Proxy);
                    cert_file = Some(args.next().unwrap());
                    key_file = Some(args.next().unwrap());
                }
                "tls12" => tls_allowed.get_or_insert((false, false)).0 = true,
                "tls13" => tls_allowed.get_or_insert((false, false)).1 = true,
                "aes128" => cipher_suites_allowed.get_or_insert((false, false, false)).0 = true,
                "aes256" => cipher_suites_allowed.get_or_insert((false, false, false)).1 = true,
                "chacha20" => cipher_suites_allowed.get_or_insert((false, false, false)).2 = true,
                arg => panic!("unexpected arg {arg:?}"),
            }
        }

        if cfg!(any(feature = "openssl", feature = "rustls")) {
            (
                tls_allowed.unwrap_or((true, true)),
                cipher_suites_allowed.unwrap_or((true, true, true)),
            )
        } else {
            ((true, true), (true, true, true))
        }
    };

    match role.unwrap() {
        Role::Client => client(HOSTNAME, tls_allowed, cipher_suites_allowed),
        Role::Proxy => proxy(
            HOSTNAME,
            tls_allowed,
            cipher_suites_allowed,
            cert_file.unwrap(),
            key_file.unwrap(),
        ),
    }
}

#[derive(Clone, Copy, Debug)]
enum Role {
    Client,
    Proxy,
}

fn client(hostname: &str, tls_allowed: (bool, bool), cipher_suites_allowed: (bool, bool, bool)) {
    let mut stream = connector::connect(
        hostname,
        if cfg!(any(feature = "openssl", feature = "rustls")) {
            443
        } else {
            80
        },
        tls_allowed,
        cipher_suites_allowed,
    );

    // ================================================================================
    // Send HTTP request. Notice that this succeeds, demonstrating that `writev` works.
    // ================================================================================

    let to_write = [
        IoSlice::new(b"GET"),
        IoSlice::new(b" "),
        IoSlice::new(b"/"),
        IoSlice::new(b" "),
        IoSlice::new(b"HTTP/1.0"),
        IoSlice::new(b"\r\n"),
        IoSlice::new(b"user-agent:"),
        IoSlice::new(b"https://github.com/arsing/ktls-test"),
        IoSlice::new(b"host:"),
        IoSlice::new(hostname.as_bytes()),
        IoSlice::new(b"\r\n"),
        IoSlice::new(b"\r\n"),
    ];
    let written = stream.write_vectored(&to_write).unwrap();
    assert_eq!(written, to_write.iter().map(|s| s.len()).sum());

    stream.shutdown(Shutdown::Write).unwrap();

    // Read all TLS records until the server closes the socket. Application data records contain the HTTP response and are printed.
    // Since we don't want to implement our own TLS state machine, post-handshake records are not expected and will cause a panic,
    // except for TLS 1.3 new session tickets which are ignored.

    let mut response = [MaybeUninit::uninit(); 8 * 1024];

    // Buffer to hold partial post-handshake records.
    let mut post_handshake_messages = vec![];

    loop {
        match tls_io::read(
            stream.as_raw_fd(),
            &mut response,
            &mut post_handshake_messages,
        ) {
            Ok(0) => break,

            Ok(read) => {
                let response = unsafe { &*(ptr::addr_of!(response[..read]) as *const [u8]) };
                println!(r#"b"{}""#, response[..read].escape_ascii());
            }

            Err(nix::Error::EAGAIN) => {
                let mut poll_fds = [PollFd::new(stream.as_fd(), PollFlags::POLLIN)];
                _ = poll(&mut poll_fds, PollTimeout::NONE).unwrap();
            }

            Err(err) => panic!("{err}"),
        }
    }
}

fn proxy(
    hostname: &str,
    tls_allowed: (bool, bool),
    cipher_suites_allowed: (bool, bool, bool),
    cert_file: impl AsRef<Path>,
    key_file: impl AsRef<Path>,
) {
    let mut downstream = acceptor::accept(
        "127.0.0.1",
        if cfg!(any(feature = "openssl", feature = "rustls")) {
            18443
        } else {
            18080
        },
        tls_allowed,
        cipher_suites_allowed,
        cert_file,
        key_file,
    );

    let mut upstream = connector::connect(
        hostname,
        if cfg!(any(feature = "openssl", feature = "rustls")) {
            443
        } else {
            80
        },
        tls_allowed,
        cipher_suites_allowed,
    );

    let mut downstream_revents = PollFlags::empty();
    let mut upstream_revents = PollFlags::empty();
    let mut wants_downstream = true;
    let mut wants_upstream = true;
    let mut downstream_buf = [MaybeUninit::uninit(); 8192];
    let mut downstream_buf_len = 0_usize;
    let mut upstream_buf = [MaybeUninit::uninit(); 8192];
    let mut upstream_buf_len = 0_usize;
    let mut downstream_posthandshake_messages = vec![];
    let mut upstream_posthandshake_messages = vec![];
    while wants_downstream && wants_upstream {
        let mut downstream_events = PollFlags::empty();
        let mut upstream_events = PollFlags::empty();
        if wants_downstream {
            if !downstream_events.contains(PollFlags::POLLOUT) {
                downstream_events |= PollFlags::POLLOUT;
            }
            if !upstream_events.contains(PollFlags::POLLIN) {
                upstream_events |= PollFlags::POLLIN;
            }
        }
        if wants_upstream {
            if !downstream_events.contains(PollFlags::POLLIN) {
                downstream_events |= PollFlags::POLLIN;
            }
            if !upstream_events.contains(PollFlags::POLLOUT) {
                upstream_events |= PollFlags::POLLOUT;
            }
        }
        if !downstream_events.is_empty() {
            let mut poll_fds = [PollFd::new(downstream.as_fd(), PollFlags::empty())];
            poll_fds[0].set_events(downstream_events);
            let previous_revents = downstream_revents;
            _ = poll(&mut poll_fds, PollTimeout::NONE).unwrap();
            downstream_revents =
                previous_revents | poll_fds[0].revents().unwrap_or_else(PollFlags::empty);
        }
        if !upstream_events.is_empty() {
            let mut poll_fds = [PollFd::new(upstream.as_fd(), PollFlags::empty())];
            poll_fds[0].set_events(upstream_events);
            let previous_revents = upstream_revents;
            _ = poll(&mut poll_fds, PollTimeout::NONE).unwrap();
            upstream_revents =
                previous_revents | poll_fds[0].revents().unwrap_or_else(PollFlags::empty);
        }

        if wants_upstream {
            if downstream_buf_len == 0 {
                match tls_io::read(
                    downstream.as_raw_fd(),
                    &mut downstream_buf,
                    &mut downstream_posthandshake_messages,
                ) {
                    Ok(0) => {
                        upstream.shutdown(Shutdown::Write).unwrap();
                        wants_upstream = false;
                    }

                    Ok(n) => downstream_buf_len = n,

                    Err(nix::Error::EWOULDBLOCK) => {
                        downstream_revents.remove(PollFlags::POLLIN);
                        upstream_revents.remove(PollFlags::POLLOUT);
                    }

                    Err(err) => panic!("{err}"),
                }
            }
            if downstream_buf_len > 0 {
                match upstream.write(unsafe {
                    &*(ptr::addr_of!(downstream_buf[..downstream_buf_len]) as *const [u8])
                }) {
                    Ok(0) => {
                        downstream.shutdown(Shutdown::Read).unwrap();
                        wants_upstream = false;
                    }

                    Ok(n) => {
                        downstream_buf.rotate_left(n);
                        downstream_buf_len -= n;
                    }

                    Err(err) if err.kind() == ErrorKind::WouldBlock => {
                        downstream_revents.remove(PollFlags::POLLIN);
                        upstream_revents.remove(PollFlags::POLLOUT);
                    }

                    Err(err) => panic!("{err}"),
                }
            }
        }

        if wants_downstream {
            if upstream_buf_len == 0 {
                match tls_io::read(
                    upstream.as_raw_fd(),
                    &mut upstream_buf,
                    &mut upstream_posthandshake_messages,
                ) {
                    Ok(0) => {
                        downstream.shutdown(Shutdown::Write).unwrap();
                        wants_downstream = false;
                    }

                    Ok(n) => upstream_buf_len = n,

                    Err(nix::Error::EWOULDBLOCK) => {
                        upstream_revents.remove(PollFlags::POLLIN);
                        downstream_revents.remove(PollFlags::POLLOUT);
                    }

                    Err(err) => panic!("{err}"),
                }
            }
            if upstream_buf_len > 0 {
                match downstream.write(unsafe {
                    &*(ptr::addr_of!(upstream_buf[..upstream_buf_len]) as *const [u8])
                }) {
                    Ok(0) => {
                        upstream.shutdown(Shutdown::Read).unwrap();
                        wants_downstream = false;
                    }

                    Ok(n) => {
                        upstream_buf.rotate_left(n);
                        upstream_buf_len -= n;
                    }

                    Err(err) if err.kind() == ErrorKind::WouldBlock => {
                        upstream_revents.remove(PollFlags::POLLIN);
                        downstream_revents.remove(PollFlags::POLLOUT);
                    }

                    Err(err) => panic!("{err}"),
                }
            }
        }
    }
}
