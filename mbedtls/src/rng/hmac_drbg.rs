/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;
pub use mbedtls_sys::HMAC_DRBG_RESEED_INTERVAL as RESEED_INTERVAL;
use mbedtls_sys::*;

use crate::rng::{EntropyCallback, RngCallback, RngCallbackMut};
use crate::error::{IntoResult, Result};
use crate::hash::MdInfo;
use std::sync::Arc;

#[allow(dead_code)]
pub struct HmacDrbg {
    // Moving data causes dangling pointers: https://github.com/ARMmbed/mbedtls/issues/2147
    // Storing data in heap and forcing rust move to only move the pointer (box) referencing it.
    // The move will be faster. Access to data will be slower due to additional indirection.
    inner: Box<hmac_drbg_context>,
    entropy: Option<Arc<dyn EntropyCallback + 'static>>,
}

unsafe impl Send for HmacDrbg {}

#[cfg(feature = "threading")]
unsafe impl Sync for HmacDrbg {}

#[allow(dead_code)]
impl Drop for HmacDrbg {
    fn drop(&mut self) {
        unsafe { hmac_drbg_free(&mut *self.inner) };
    }
}

impl HmacDrbg {
    pub fn new<T: EntropyCallback + Send + Sync + 'static>(
        md_info: MdInfo,
        entropy: Arc<T>,
        additional_entropy: Option<&[u8]>,
    ) -> Result<HmacDrbg> {

        let mut inner = Box::new(hmac_drbg_context::default());
        unsafe {
            hmac_drbg_init(&mut *inner);
            hmac_drbg_seed(
                &mut *inner,
                md_info.into(),
                Some(T::call),
                entropy.data_ptr(),
                additional_entropy.map(<[_]>::as_ptr).unwrap_or(::core::ptr::null()),
                additional_entropy.map(<[_]>::len).unwrap_or(0)
            )
            .into_result()?
        };
        Ok(HmacDrbg { inner, entropy: Some(entropy) })
    }

    pub fn inner_ptr(&mut self) -> *mut hmac_drbg_context {
        &mut *self.inner
    }

    pub fn inner_ptr_const(&self) -> *const hmac_drbg_context {
        &*self.inner
    }

    
    pub fn from_buf(md_info: MdInfo, entropy: &[u8]) -> Result<HmacDrbg> {
        let mut inner = Box::new(hmac_drbg_context::default());
        unsafe {
            hmac_drbg_init(&mut *inner);
            hmac_drbg_seed_buf(
                &mut *inner,
                md_info.into(),
                entropy.as_ptr(),
                entropy.len()
            )
            .into_result()?
        };
        Ok(HmacDrbg { inner, entropy: None })
    }

    pub fn prediction_resistance(&self) -> bool {
        if self.inner.prediction_resistance == HMAC_DRBG_PR_OFF {
            false
        } else {
            true
        }
    }

    pub fn set_prediction_resistance(&mut self, pr: bool) {
        unsafe {
            hmac_drbg_set_prediction_resistance(
                self.inner_ptr(),
                if pr {
                    HMAC_DRBG_PR_ON
                } else {
                    HMAC_DRBG_PR_OFF
                },
            )
        }
    }

    pub fn entropy_len(&self) -> size_t {
        self.inner.entropy_len
    }

    pub fn set_entropy_len(&mut self, len: size_t) {
        unsafe { hmac_drbg_set_entropy_len(self.inner_ptr(), len); }
    }

    pub fn reseed_interval(&self) -> c_int {
        self.inner.reseed_interval
    }

    pub fn set_reseed_interval(&mut self, i: c_int) {
        unsafe { hmac_drbg_set_reseed_interval(self.inner_ptr(), i); }
    }

    pub fn reseed(&mut self, additional_entropy: Option<&[u8]>) -> Result<()> {
        unsafe {
            hmac_drbg_reseed(
                self.inner_ptr(),
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
        unsafe { hmac_drbg_update(self.inner_ptr(), entropy.as_ptr(), entropy.len()) };
    }

    // TODO:
    //
    // hmac_drbg_random_with_add
    // hmac_drbg_write_seed_file
    // hmac_drbg_update_seed_file
    //
}

unsafe impl RngCallbackMut for HmacDrbg {
    #[inline(always)]
    unsafe extern "C" fn call(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        // Mutex used in hmac_drbg_random: ../../../mbedtls-sys/vendor/crypto/library/hmac_drbg.c:363
        hmac_drbg_random(user_data, data, len)
    }

    fn data_ptr_mut(&mut self) -> *mut c_void {
        self.inner_ptr_const() as *const _ as *mut _
    }
}

impl RngCallback for HmacDrbg {
    fn data_ptr(&self) -> *mut c_void {
        self.inner_ptr_const() as *const _ as *mut _
    }
}
