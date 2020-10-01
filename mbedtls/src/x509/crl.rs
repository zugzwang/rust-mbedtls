/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use core::fmt;
use crate::error::{IntoResult, Result};
use mbedtls_sys::*;

pub struct Crl {
    inner: Box<x509_crl>
}

impl Drop for Crl {
    fn drop(&mut self) {
        unsafe { x509_crl_free(self.inner_ptr()); }
    }
}

impl Crl {
    pub fn new() -> Self {
        let mut inner = Box::new(x509_crl::default());
        unsafe { x509_crl_init(&mut *inner); }
        Crl { inner }
    }

    pub fn inner_ptr(&mut self) -> *mut x509_crl {
        &mut *self.inner
    }

    pub fn inner_ptr_const(&self) -> *const x509_crl {
        &*self.inner
    }

    pub fn push_from_der(&mut self, der: &[u8]) -> Result<()> {
        unsafe {
            x509_crl_parse_der(self.inner_ptr(), der.as_ptr(), der.len()).into_result().map(|_| ())
        }
    }

    pub fn push_from_pem(&mut self, pem: &[u8]) -> Result<()> {
        unsafe {
            x509_crl_parse(self.inner_ptr(), pem.as_ptr(), pem.len()).into_result().map(|_| ())
        }
    }
}

impl fmt::Debug for Crl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match crate::private::alloc_string_repeat(|buf, size| unsafe {
            x509_crl_info(buf, size, b"\0".as_ptr() as *const _, self.inner_ptr_const())
        }) {
            Err(_) => Err(fmt::Error),
            Ok(s) => f.write_str(&s),
        }
    }
}

// TODO
// x509_crl_parse_file
//
