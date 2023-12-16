//! Ref:
//!
//! - [TLS 1.2](https://datatracker.ietf.org/doc/html/rfc5246)
//! - [TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446)

use std::{
    fmt,
    mem::{size_of, size_of_val, MaybeUninit},
    os::fd::RawFd,
};

use nix::libc::{
    self, cmsghdr, iovec, msghdr, CMSG_DATA, CMSG_FIRSTHDR, CMSG_NXTHDR, CMSG_SPACE, SOL_TLS,
    TLS_GET_RECORD_TYPE,
};

macro_rules! define_u8_code {
    (
        $(#[$meta:meta])*
        $vis:vis enum $ty:ident {
            $($variant:ident = $value:expr ,)*
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        $vis enum $ty {
            $($variant),*
        }

        impl TryFrom<u8> for $ty {
            type Error = u8;

            fn try_from(raw: u8) -> Result<Self, Self::Error> {
                Ok(match raw {
                    $($value => $ty::$variant ,)*
                    raw => return Err(raw),
                })
            }
        }

        impl From<$ty> for u8 {
            fn from(raw: $ty) -> Self {
                match raw {
                    $($ty::$variant => $value ,)*
                }
            }
        }
    };
}

define_u8_code! {
    /// Ref:
    ///
    /// - [TLS 1.2](https://datatracker.ietf.org/doc/html/rfc5246#section-6.2)
    /// - [TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446#section-5.1)
    enum ContentType {
        Alert = 21,
        ApplicationData = 23,
        ChangeCipherSpec = 20,
        Handshake = 22,
        Invalid = 0,
    }
}

define_u8_code! {
    /// Ref:
    ///
    /// - [TLS 1.2](https://datatracker.ietf.org/doc/html/rfc5246#section-7.4)
    /// - [TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446#section-4)
    enum HandshakeType {
        Certificate = 11,
        CertificateRequest = 13,
        CertificateVerify = 15,
        ClientHello = 1,
        ClientKeyExchange = 16,
        EncryptedExtensions = 8,
        EndOfEarlyData = 5,
        Finished = 20,
        HelloRequest = 0,
        KeyUpdate = 24,
        MessageHash = 254,
        NewSessionTicket = 4,
        ServerHello = 2,
        ServerHelloDone = 14,
        ServerKeyExchange = 12,
    }
}

/// Ref:
///
/// - [TLS 1.2](https://datatracker.ietf.org/doc/html/rfc5246#section-7.4)
/// - [TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446#section-4)
enum Handshake {
    Certificate,
    CertificateRequest,
    CertificateVerify,
    ClientHello,
    ClientKeyExchange,
    EncryptedExtensions,
    EndOfEarlyData,
    Finished,
    HelloRequest,
    KeyUpdate,
    MessageHash,
    NewSessionTicket,
    ServerHello,
    ServerHelloDone,
    ServerKeyExchange,
}

impl Handshake {
    /// Returns:
    ///
    /// - `Some(Ok(handshake))` if there is a complete handshake message in the given buffer of a recognized type.
    ///
    /// - `Some(Err(handshake_type))` if there is a complete handshake message in the given buffer but its type could not be recognized.
    ///
    /// - `None` if there is not a complete handshake message in the given buffer.
    fn decode(src: &mut &[u8]) -> Option<Result<Self, u8>> {
        let Some((&handshake_type, rest)) = src.split_first() else {
            return None;
        };
        let handshake_type = HandshakeType::try_from(handshake_type);

        let (len, rest) = if rest.len() >= 3 {
            rest.split_at(3)
        } else {
            return None;
        };
        let len = usize::try_from(u32::from_be_bytes([0x00, len[0], len[1], len[2]]))
            .expect("u32 -> usize");
        if rest.len() < len {
            return None;
        }

        let (_body, rest) = rest.split_at(len);
        let handshake = handshake_type.map(|handshake_type| match handshake_type {
            HandshakeType::Certificate => Handshake::Certificate,
            HandshakeType::CertificateRequest => Handshake::CertificateRequest,
            HandshakeType::CertificateVerify => Handshake::CertificateVerify,
            HandshakeType::ClientHello => Handshake::ClientHello,
            HandshakeType::ClientKeyExchange => Handshake::ClientKeyExchange,
            HandshakeType::EncryptedExtensions => Handshake::EncryptedExtensions,
            HandshakeType::EndOfEarlyData => Handshake::EndOfEarlyData,
            HandshakeType::Finished => Handshake::Finished,
            HandshakeType::HelloRequest => Handshake::HelloRequest,
            HandshakeType::KeyUpdate => Handshake::KeyUpdate,
            HandshakeType::MessageHash => Handshake::MessageHash,
            HandshakeType::NewSessionTicket => Handshake::NewSessionTicket,
            HandshakeType::ServerHello => Handshake::ServerHello,
            HandshakeType::ServerHelloDone => Handshake::ServerHelloDone,
            HandshakeType::ServerKeyExchange => Handshake::ServerKeyExchange,
        });

        *src = rest;
        Some(handshake)
    }
}

impl fmt::Debug for Handshake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Certificate => f.debug_struct("Certificate").finish_non_exhaustive(),
            Self::CertificateRequest => {
                f.debug_struct("CertificateRequest").finish_non_exhaustive()
            }
            Self::CertificateVerify => f.debug_struct("CertificateVerify").finish_non_exhaustive(),
            Self::ClientHello => f.debug_struct("ClientHello").finish_non_exhaustive(),
            Self::ClientKeyExchange => f.debug_struct("ClientKeyExchange").finish_non_exhaustive(),
            Self::EncryptedExtensions => f
                .debug_struct("EncryptedExtensions")
                .finish_non_exhaustive(),
            Self::EndOfEarlyData => f.debug_struct("EndOfEarlyData").finish_non_exhaustive(),
            Self::Finished => f.debug_struct("Finished").finish_non_exhaustive(),
            Self::HelloRequest => f.debug_struct("HelloRequest").finish_non_exhaustive(),
            Self::KeyUpdate => f.debug_struct("KeyUpdate").finish_non_exhaustive(),
            Self::MessageHash => f.debug_struct("MessageHash").finish_non_exhaustive(),
            Self::NewSessionTicket => f.debug_struct("NewSessionTicket").finish_non_exhaustive(),
            Self::ServerHello => f.debug_struct("ServerHello").finish_non_exhaustive(),
            Self::ServerHelloDone => f.debug_struct("ServerHelloDone").finish_non_exhaustive(),
            Self::ServerKeyExchange => f.debug_struct("ServerKeyExchange").finish_non_exhaustive(),
        }
    }
}

/// Reads from `stream` into `buf`, and returns how many bytes were read. It has the same semantics as [`std::io::Read::read`].
///
/// If any TLS post-handshake messages are received, they are handled internally.
/// `buf` only contains the content of application data records.
///
/// `post_handshake_messages` is used as scratch space to retain any partial post-handshake messages that are split across multiple reads.
/// The same `Vec` should be provided for multiple calls to this function with the same `stream`.
pub(crate) fn read(
    stream: RawFd,
    buf: &mut [MaybeUninit<u8>],
    post_handshake_messages: &mut Vec<u8>,
) -> nix::Result<usize> {
    // For TCP sockets with the TLS ULP enabled, the kernel makes `read` fail if there is a post-handshake message that needs to be consumed,
    // so userspace is expected to use `recvmsg` instead. Then every read contains a cmsg with level `SOL_TLS` and type `TLS_GET_RECORD_TYPE`,
    // and the value is the content type of the iovec.
    //
    // We don't actually care about post-handshake messages since we can't do anything with them. Ideally we'd feed them back to OpenSSL / rustls,
    // but that is not possible because the record sequence number would be out of sync anyway. But we also can't just use `read`
    // instead of `recvmsg` because every client connection to a TLS 1.3 server is likely to produce one or more `NewSessionTicket` records
    // at the very beginning, so we have to at least receive and ignore them.

    loop {
        // NOTE: This uses `nix::libc::recvmsg` instead of `nix::sys::socket::recvmsg` because nix's version has a few problems:
        //
        // 1. It requires using a Vec for the cmsghdr backing buffer. The Vec can be reused across calls so it's not as bad as
        //    allocating for every message, but it's still worse than using a local array.
        //
        // 2. nix does nothing to ensure the Vec is aligned for the `libc::cmsghdr` that it'll eventually contain.
        //    It assumes Vecs will always be suitably aligned because that's what GlobalAlloc does, but it's not ideal to rely on this.
        //    Ref: https://github.com/nix-rust/nix/issues/1040
        //
        // 3. `nix::sys::socket::RecvMsg::cmsgs` is a nice way to get the cmsgs via an `Iterator`, but it is limited to the types of cmsgs
        //    hard-coded as the variants of `enum nix::sys::socket::ControlMessageOwned`. Actually there is a `doc(hidden)` `Unknown` variant
        //    that it falls back to when the cmsg is none of those hard-coded types, but this variant creates its own additional `Vec` copy of the data
        //    which is extremely wasteful in our case.
        //
        // So we eschew `nix`'s wrapper and use `libc` directly, with our own cmsg `Iterator` built from `libc::CMSG_FIRSTHDR` and `libc::CMSG_NXTHDR`.

        /// `cmsg` contains `ContentType` encoded as one byte.
        #[repr(C)]
        struct Cmsg {
            content_type_raw: u8,
        }

        #[allow(clippy::cast_possible_truncation)] // Can't use try_into() in a const context.
        const CMSGHDR_SIZE: usize = unsafe { CMSG_SPACE(size_of::<Cmsg>() as _) } as usize;

        #[repr(C)]
        union CmsghdrAligned {
            cmsghdr: cmsghdr,
            raw: [u8; CMSGHDR_SIZE],
        }

        let mut msg_iov = iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };

        let mut cmsg = CmsghdrAligned {
            raw: [0_u8; CMSGHDR_SIZE],
        };

        // libc::msghdr has private padding fields in musl target, so initialize it C-style.
        let mut msghdr = unsafe { MaybeUninit::<msghdr>::zeroed().assume_init() };
        msghdr.msg_iov = &mut msg_iov;
        msghdr.msg_iovlen = 1;
        msghdr.msg_control = unsafe { <*mut _>::cast(&mut cmsg.raw) };
        #[cfg(target_env = "musl")]
        {
            msghdr.msg_controllen = size_of_val(&cmsg).try_into().expect("usize -> socklen_t");
        }
        #[cfg(not(target_env = "musl"))]
        {
            msghdr.msg_controllen = size_of_val(&cmsg);
        }

        let read = nix::Error::result(unsafe { libc::recvmsg(stream, &mut msghdr, 0) })?;
        if read == 0 {
            return Ok(0);
        }
        let response = &buf[..(usize::try_from(read).expect("-1 would've been mapped to `Err` and recvmsg does not return any other negative values"))];
        // SAFETY: &[T] and &[MaybeUninit<T>] have the same layout
        let response: &[u8] = unsafe { &*(response as *const [MaybeUninit<u8>] as *const [u8]) };

        let mut content_type = None;

        let mut previous_cmsghdr = None::<&_>;
        let cmsghdrs = std::iter::from_fn(|| {
            previous_cmsghdr = if let Some(cmsghdr) = previous_cmsghdr {
                unsafe { CMSG_NXTHDR(&msghdr, cmsghdr).as_ref() }
            } else {
                unsafe { CMSG_FIRSTHDR(&msghdr).as_ref() }
            };
            previous_cmsghdr
        });

        for cmsghdr in cmsghdrs {
            if cmsghdr.cmsg_level != SOL_TLS {
                eprintln!(
                    "WARN: expected cmsg_level == SOL_TLS but got {}",
                    cmsghdr.cmsg_level,
                );
                continue;
            }

            if cmsghdr.cmsg_type != TLS_GET_RECORD_TYPE {
                eprintln!(
                    "WARN: expected cmsg_type == TLS_GET_RECORD_TYPE but got {}",
                    cmsghdr.cmsg_type,
                );
                continue;
            }

            let data = unsafe { CMSG_DATA(cmsghdr).cast::<Cmsg>() };
            let content_type_raw = unsafe { (*data).content_type_raw };
            match content_type_raw.try_into() {
                Ok(content_type_) => content_type = Some(content_type_),
                Err(content_type_raw) => panic!("unhandled content type {content_type_raw}"),
            }
        }

        match content_type {
            // All alerts are precursors to EOF.
            Some(ContentType::Alert) => break Ok(0),

            Some(ContentType::ApplicationData) => break Ok(response.len()),

            None if !cfg!(any(feature = "openssl", feature = "rustls")) => break Ok(response.len()),

            Some(ContentType::Handshake) => {
                post_handshake_messages.extend_from_slice(response);
                loop {
                    let mut src = &post_handshake_messages[..];
                    let Some(post_handshake_message) = Handshake::decode(&mut src) else {
                        break;
                    };
                    let consumed = post_handshake_messages.len() - src.len();
                    _ = post_handshake_messages.drain(..consumed);

                    match post_handshake_message {
                        // We could implement key update properly, but it's okay to treat it as EOF.
                        // It's only done for the sake of PFS or when the record sequence number is going to overflow 2^64,
                        // so it will not happen frequently enough to be a problem.
                        Ok(Handshake::KeyUpdate) => return Ok(0),

                        Ok(Handshake::NewSessionTicket) => {
                            // We may receive one or more NewSessionTicket's for connections to TLS 1.3 servers,
                            // but we don't have a use for it, so ignore it.
                            eprintln!(
                                "INFO: ignoring post-handshake message {post_handshake_message:?}"
                            );
                        }

                        _ => panic!("unhandled post-handshake message {post_handshake_message:?}"),
                    }
                }
            }

            _ => panic!("unhandled content type {content_type:?}"),
        }
    }
}
