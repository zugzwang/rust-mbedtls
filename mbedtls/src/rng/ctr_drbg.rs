/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use mbedtls_sys::*;
use std::sync::Arc;
use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;
use crate::error::{IntoResult, Result};
use crate::rng::{EntropyCallback, RngCallback, RngCallbackMut};

#[allow(dead_code)]
pub struct CtrDrbg {
    // Moving data causes dangling pointers: https://github.com/ARMmbed/mbedtls/issues/2147
    // Storing data in heap and forcing rust move to only move the pointer (box) referencing it.
    // The move will be faster. Access to data will be slower due to additional indirection.
    inner: Box<ctr_drbg_context>,
    entropy: Arc<dyn EntropyCallback + 'static>,
}

#[cfg(feature = "threading")]
unsafe impl Send for CtrDrbg {}

///
/// Class has interior mutability via function called 'call'.
/// That function has an internal mutex to guarantee thread safety.
///
/// The other potential conflict is a mutable reference changing class.
/// That is avoided by having any users of the callback hold an 'Arc' to this class.
/// Rust will then ensure that a mutable reference cannot be aquired if more then 1 Arc exists to the same class.
///
#[cfg(feature = "threading")]
unsafe impl Sync for CtrDrbg {}

#[allow(dead_code)]
impl CtrDrbg {
    pub fn new<T: EntropyCallback + Send + Sync + 'static>(entropy: Arc<T>, additional_entropy: Option<&[u8]>) -> Result<Self> {
        let mut inner = Box::new(ctr_drbg_context::default());

        unsafe {
            ctr_drbg_init(&mut *inner);
            ctr_drbg_seed(
                &mut *inner,
                Some(T::call),
                entropy.data_ptr(),
                additional_entropy.map(<[_]>::as_ptr).unwrap_or(::core::ptr::null()),
                additional_entropy.map(<[_]>::len).unwrap_or(0)
            ).into_result()?;
        }

        Ok(CtrDrbg { inner, entropy })
    }

    pub fn inner_ptr(&mut self) -> *mut ctr_drbg_context {
        &mut *self.inner
    }

    pub fn inner_ptr_const(&self) -> *const ctr_drbg_context {
        &*self.inner
    }
    
    pub fn prediction_resistance(&self) -> bool {
        if self.inner.prediction_resistance == CTR_DRBG_PR_OFF {
            false
        } else {
            true
        }
    }

    pub fn set_prediction_resistance(&mut self, pr: bool) {
        unsafe {
            ctr_drbg_set_prediction_resistance(
                &mut *self.inner,
                if pr { CTR_DRBG_PR_ON } else { CTR_DRBG_PR_OFF },
            )
        }
    }

    pub fn entropy_len(&self) -> size_t {
        self.inner.entropy_len
    }

    pub fn set_entropy_len(&mut self, len: size_t) {
        unsafe { ctr_drbg_set_entropy_len(&mut *self.inner, len); }
    }

    pub fn reseed_interval(&self) -> c_int {
        self.inner.reseed_interval
    }

    pub fn set_reseed_interval(&mut self, i: c_int) {
        unsafe { ctr_drbg_set_reseed_interval(&mut *self.inner, i); }
    }

    pub fn reseed(&mut self, additional_entropy: Option<&[u8]>) -> Result<()> {
        unsafe {
            ctr_drbg_reseed(
                &mut *self.inner,
                additional_entropy
                    .map(<[_]>::as_ptr)
                    .unwrap_or(::core::ptr::null()),
                additional_entropy.map(<[_]>::len).unwrap_or(0)
            )
            .into_result()?
        };
        Ok(())
    }

    pub fn update(&mut self, entropy: &[u8]) {
        unsafe { ctr_drbg_update(&mut *self.inner, entropy.as_ptr(), entropy.len()) };
    }
}

#[allow(dead_code)]
impl Drop for CtrDrbg {
    fn drop(&mut self) {
        unsafe { ctr_drbg_free(&mut *self.inner) };
    }
}

unsafe impl RngCallbackMut for CtrDrbg {
    #[inline(always)]
    unsafe extern "C" fn call(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int where Self: std::marker::Sized {
        // Mutex used in ctr_drbg_random at: ../../../mbedtls-sys/vendor/crypto/library/ctr_drbg.c:546
        ctr_drbg_random(user_data, data, len)
    }

    fn data_ptr_mut(&mut self) -> *mut c_void {
        self.inner_ptr_const() as *const _ as *mut _
    }
}

impl RngCallback for CtrDrbg {
    fn data_ptr(&self) -> *mut c_void {
        self.inner_ptr_const() as *const _ as *mut _
    }
}
