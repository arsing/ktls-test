#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::cast_possible_truncation, clippy::default_trait_access)]

//! Extensions to `nix` for kernel TLS.

pub mod sys {
    pub mod socket {
        pub mod sockopt {
            use std::{
                mem,
                os::fd::{AsFd, AsRawFd as _},
            };

            use nix::{libc, sys::socket::SetSockOpt};

            #[derive(Clone, Debug)]
            pub struct TcpUlp<T>(::std::marker::PhantomData<T>);

            impl<T> Default for TcpUlp<T> {
                fn default() -> Self {
                    TcpUlp(Default::default())
                }
            }

            impl<T> SetSockOpt for TcpUlp<T>
            where
                T: AsRef<[u8]> + Clone,
            {
                type Val = T;

                fn set<F>(&self, fd: &F, val: &Self::Val) -> nix::Result<()>
                where
                    F: AsFd,
                {
                    unsafe {
                        let res = libc::setsockopt(
                            fd.as_fd().as_raw_fd(),
                            libc::SOL_TCP,
                            libc::TCP_ULP,
                            val.as_ref().as_ptr().cast(),
                            val.as_ref().len() as libc::socklen_t,
                        );
                        nix::Error::result(res).map(drop)
                    }
                }
            }

            #[derive(Copy, Clone, Debug)]
            pub enum TlsCryptoInfo {
                Aes128Gcm(libc::tls12_crypto_info_aes_gcm_128),
                Aes256Gcm(libc::tls12_crypto_info_aes_gcm_256),
                Chacha20Poly1305(libc::tls12_crypto_info_chacha20_poly1305),
            }

            #[derive(Copy, Clone, Debug)]
            pub struct TcpTlsTx;

            impl SetSockOpt for TcpTlsTx {
                type Val = TlsCryptoInfo;

                fn set<F>(&self, fd: &F, val: &Self::Val) -> nix::Result<()>
                where
                    F: AsFd,
                {
                    let (ffi_ptr, ffi_len) = match val {
                        TlsCryptoInfo::Aes128Gcm(crypto_info) => {
                            (<*const _>::cast(crypto_info), mem::size_of_val(crypto_info))
                        }
                        TlsCryptoInfo::Aes256Gcm(crypto_info) => {
                            (<*const _>::cast(crypto_info), mem::size_of_val(crypto_info))
                        }
                        TlsCryptoInfo::Chacha20Poly1305(crypto_info) => {
                            (<*const _>::cast(crypto_info), mem::size_of_val(crypto_info))
                        }
                    };
                    unsafe {
                        let res = libc::setsockopt(
                            fd.as_fd().as_raw_fd(),
                            libc::SOL_TLS,
                            libc::TLS_TX,
                            ffi_ptr,
                            ffi_len as libc::socklen_t,
                        );
                        nix::Error::result(res).map(drop)
                    }
                }
            }

            #[derive(Copy, Clone, Debug)]
            pub struct TcpTlsRx;

            impl SetSockOpt for TcpTlsRx {
                type Val = TlsCryptoInfo;

                fn set<F>(&self, fd: &F, val: &Self::Val) -> nix::Result<()>
                where
                    F: AsFd,
                {
                    let (ffi_ptr, ffi_len) = match val {
                        TlsCryptoInfo::Aes128Gcm(crypto_info) => {
                            (<*const _>::cast(crypto_info), mem::size_of_val(crypto_info))
                        }
                        TlsCryptoInfo::Aes256Gcm(crypto_info) => {
                            (<*const _>::cast(crypto_info), mem::size_of_val(crypto_info))
                        }
                        TlsCryptoInfo::Chacha20Poly1305(crypto_info) => {
                            (<*const _>::cast(crypto_info), mem::size_of_val(crypto_info))
                        }
                    };
                    unsafe {
                        let res = libc::setsockopt(
                            fd.as_fd().as_raw_fd(),
                            libc::SOL_TLS,
                            libc::TLS_RX,
                            ffi_ptr,
                            ffi_len as libc::socklen_t,
                        );
                        nix::Error::result(res).map(drop)
                    }
                }
            }
        }
    }
}
