// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Extensions for [openssl] types.

use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{Id, PKeyRef, Private};
use openssl::x509::X509Ref;
use openssl_foreign_types::ForeignTypeRef;

/// Additional methods for the [X509Ref] type.
pub trait X509RefExt {
    /// Checks the consistency of private key `pkey` with the public key in the certificate.
    fn check_private_key(&self, pkey: &PKeyRef<Private>) -> Result<(), ErrorStack>;
}

impl X509RefExt for X509Ref {
    fn check_private_key(&self, pkey: &PKeyRef<Private>) -> Result<(), ErrorStack> {
        // SAFETY: both arguments are valid pointers, enforced by the rust type system.
        // Constness of the arguments varies with libssl implementation, but the underlying code
        // never mutates the objects.
        //
        // We should treat X509_R_KEY_VALUES_MISMATCH and X509_R_KEY_TYPE_MISMATCH as false and
        // forward the error on anything else.  However, openssl-sys does not translate _any_
        // OpenSSL constants, making the correct check impossible.
        ossl_check(unsafe { openssl_sys::X509_check_private_key(self.as_ptr(), pkey.as_ptr()) })?;

        Ok(())
    }
}

/// Additional methods for the [PKeyRef] type.
pub trait PKeyRefExt {
    /// Returns the default message digest for the public key signature operations associated with
    /// the key.
    fn default_digest(&self) -> MessageDigest;
}

impl PKeyRefExt for PKeyRef<Private> {
    fn default_digest(&self) -> MessageDigest {
        match self.id() {
            Id::RSA | Id::EC => MessageDigest::sha256(),

            // OpenSSL 3.0 or later can tell us the preferred digest name.
            // We'll fallback to SHA256 and let X509_sign() report any errors if unavailable.
            #[cfg(openssl = "openssl300")]
            _ => default_digest_ossl300(self).unwrap_or_else(MessageDigest::sha256),

            // Anything that we want to support that is available in OpenSSL before 3.0 should be
            // compatible with SHA256.
            // BoringSSL supports ML-DSA, but it lacks means to query the preferred digest.
            #[cfg(not(openssl = "openssl300"))]
            _ => MessageDigest::sha256(),
        }
    }
}

#[cfg(openssl = "openssl300")]
fn default_digest_ossl300(pkey: &PKeyRef<Private>) -> Option<MessageDigest> {
    use openssl_sys::{ERR_clear_error, EVP_PKEY_get_default_digest_name, EVP_get_digestbyname};

    // 80 is a magic buffer size from the OpenSSL examples.
    // We expect either "SHA256" or "UNDEF", with both names being slightly shorter than 80.
    let mut buf = [0u8; 80];
    match unsafe {
        EVP_PKEY_get_default_digest_name(pkey.as_ptr(), buf.as_mut_ptr().cast(), buf.len())
    } {
        1 | 2 => {
            let mdname = core::ffi::CStr::from_bytes_until_nul(&buf).unwrap_or_default();

            if mdname == c"UNDEF" {
                // A digest must (2) or may (1) be left unspecified.
                Some(MessageDigest::null())
            } else {
                // Call ffi directly to avoid reallocation in MessageDigest::from_name().
                let md = unsafe { EVP_get_digestbyname(mdname.as_ptr()) };
                if md.is_null() {
                    None
                } else {
                    Some(unsafe { MessageDigest::from_ptr(md) })
                }
            }
        }
        // The operation is not supported by the public key algorithm.
        -2 => {
            unsafe { ERR_clear_error() };
            Some(MessageDigest::null())
        }
        _ => {
            unsafe { ERR_clear_error() };
            None
        }
    }
}

/// Checks for a positive OpenSSL return code.
#[inline]
pub fn ossl_check<T>(rc: T) -> Result<T, ErrorStack>
where
    T: PartialOrd + From<u8>,
{
    if rc <= T::from(0) {
        return Err(ErrorStack::get());
    }

    Ok(rc)
}
