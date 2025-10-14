// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

use nginx_sys::ngx_str_t;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl_foreign_types::ForeignType;
use thiserror::Error;

#[derive(Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum PrivateKey {
    Ecdsa(u32),
    MlDsa(u32),
    Rsa(u32),
    File(ngx_str_t),
    Unset,
}

impl Default for PrivateKey {
    fn default() -> Self {
        Self::Ecdsa(256)
    }
}

#[derive(Debug, Error)]
pub enum PKeyParseError {
    #[error("unsupported key size")]
    Bits,
    #[error("unsupported curve")]
    Curve,
    #[error("unsupported key type")]
    Type,
    #[error("invalid UTF-8 in key name")]
    Utf8(#[from] core::str::Utf8Error),
}

#[derive(Debug, Error)]
pub enum PKeyGenError {
    #[error("key generation error: {0}")]
    Ssl(#[from] openssl::error::ErrorStack),
    #[error("cannot generate this key")]
    Invalid,
}

impl TryFrom<ngx_str_t> for PrivateKey {
    type Error = PKeyParseError;

    fn try_from(value: ngx_str_t) -> Result<Self, Self::Error> {
        let bytes = value.as_bytes();
        let split = if let Some(idx) = bytes.iter().position(|x| *x == b':') {
            (&bytes[..idx], Some(&bytes[idx + 1..]))
        } else {
            (bytes, None)
        };

        if !cfg!(openssl = "openssl300")
            && matches!(bytes, b"ml-dsa-44" | b"ml-dsa-65" | b"ml-dsa-87")
        {
            return Err(PKeyParseError::Type);
        }

        let p = match split.0 {
            b"ecdsa" => match split.1 {
                None | Some(b"256") => PrivateKey::Ecdsa(256),
                Some(b"384") => PrivateKey::Ecdsa(384),
                Some(b"521") => PrivateKey::Ecdsa(521),
                _ => return Err(PKeyParseError::Curve),
            },
            b"ml-dsa-44" => PrivateKey::MlDsa(44),
            b"ml-dsa-65" => PrivateKey::MlDsa(65),
            b"ml-dsa-87" => PrivateKey::MlDsa(87),
            b"rsa" => match split.1 {
                None | Some(b"2048") => PrivateKey::Rsa(2048),
                Some(b"3072") => PrivateKey::Rsa(3072),
                Some(b"4096") => PrivateKey::Rsa(4096),
                _ => return Err(PKeyParseError::Bits),
            },
            _ => PrivateKey::File(value),
        };

        Ok(p)
    }
}

impl PrivateKey {
    pub fn generate(&self) -> Result<PKey<Private>, PKeyGenError> {
        match self {
            PrivateKey::Ecdsa(bits) => {
                let nid = match bits {
                    256 => Nid::X9_62_PRIME256V1,
                    384 => Nid::SECP384R1,
                    521 => Nid::SECP521R1,
                    _ => unreachable!(),
                };
                let group = openssl::ec::EcGroup::from_curve_name(nid)?;
                let ec_key = openssl::ec::EcKey::generate(&group)?;
                Ok(PKey::from_ec_key(ec_key)?)
            }
            #[cfg(openssl = "openssl300")]
            PrivateKey::MlDsa(x) => match x {
                44 => Ok(genpkey_by_name(c"ml-dsa-44")?),
                65 => Ok(genpkey_by_name(c"ml-dsa-65")?),
                87 => Ok(genpkey_by_name(c"ml-dsa-87")?),
                _ => unreachable!(),
            },
            PrivateKey::Rsa(bits) => {
                let rsa = openssl::rsa::Rsa::generate(*bits)?;
                Ok(PKey::from_rsa(rsa)?)
            }
            _ => Err(PKeyGenError::Invalid),
        }
    }
}

#[cfg(openssl = "openssl300")]
fn genpkey_by_name(name: &core::ffi::CStr) -> Result<PKey<Private>, openssl::error::ErrorStack> {
    let ctx = unsafe {
        openssl_sys::EVP_PKEY_CTX_new_from_name(
            core::ptr::null_mut(),
            name.as_ptr(),
            core::ptr::null_mut(),
        )
    };
    if ctx.is_null() {
        return Err(openssl::error::ErrorStack::get());
    }
    let mut ctx = unsafe { openssl::pkey_ctx::PkeyCtx::<()>::from_ptr(ctx) };
    ctx.keygen_init()?;
    ctx.keygen()
}
