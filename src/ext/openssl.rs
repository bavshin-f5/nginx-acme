// Copyright (c) F5, Inc.
//
// This source code is licensed under the Apache License, Version 2.0 license found in the
// LICENSE file in the root directory of this source tree.

//! Extensions for [openssl] types.

use openssl::error::ErrorStack;
use openssl::pkey::{PKeyRef, Private};
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
