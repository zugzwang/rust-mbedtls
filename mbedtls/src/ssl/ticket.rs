/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use crate::cipher::raw::CipherType;
use crate::error::{IntoResult, Result};
use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;
use mbedtls_sys::*;
use std::sync::Arc;
use crate::rng::RngCallback;

pub trait TicketCallback {
    unsafe extern "C" fn call_write(
        p_ticket: *mut c_void,
        session: *const ssl_session,
        start: *mut c_uchar,
        end: *const c_uchar,
        tlen: *mut size_t,
        lifetime: *mut u32,
    ) -> c_int where Self: Sized;
    unsafe extern "C" fn call_parse(
        p_ticket: *mut c_void,
        session: *mut ssl_session,
        buf: *mut c_uchar,
        len: size_t,
    ) -> c_int where Self: Sized;

    fn data_ptr(&self) -> *mut c_void;
}

pub struct TicketContext {
    inner: Box<ssl_ticket_context>,
    rng: Arc<dyn RngCallback + Send + Sync + 'static>,
}

#[cfg(feature = "threading")]
unsafe impl Sync for TicketContext {}

#[cfg(feature = "threading")]
unsafe impl Send for TicketContext {}


impl Drop for TicketContext {
    fn drop(&mut self) {
        unsafe { ssl_ticket_free(self.into()); }
    }
}

impl Into<*mut mbedtls_sys::ssl_ticket_context> for &mut TicketContext {
    fn into(self) -> *mut mbedtls_sys::ssl_ticket_context {
        &mut *self.inner
    }
}

impl TicketContext {
    pub fn new<T: RngCallback + Send + Sync + 'static>(
        rng: Arc<T>,
        cipher: CipherType,
        lifetime: u32,
    ) -> Result<TicketContext> {

        let mut inner = Box::new(ssl_ticket_context::default());
        
        unsafe {
            ssl_ticket_init(&mut *inner);
            ssl_ticket_setup(
                &mut *inner,
                Some(T::call),
                rng.data_ptr(),
                cipher.into(),
                lifetime,
            ).into_result()?;
        }

        Ok(TicketContext { inner, rng })
    }

    pub fn inner_ptr_const(&self) -> *const ssl_ticket_context {
        &*self.inner
    }

}

impl TicketCallback for TicketContext {
    unsafe extern "C" fn call_write(
        p_ticket: *mut c_void,
        session: *const ssl_session,
        start: *mut c_uchar,
        end: *const c_uchar,
        tlen: *mut size_t,
        lifetime: *mut u32,
    ) -> c_int {
        ssl_ticket_write(p_ticket, session, start, end, tlen, lifetime)
    }

    unsafe extern "C" fn call_parse(
        p_ticket: *mut c_void,
        session: *mut ssl_session,
        buf: *mut c_uchar,
        len: size_t,
    ) -> c_int {
        ssl_ticket_parse(p_ticket, session, buf, len)
    }

    fn data_ptr(&self) -> *mut c_void {
        self.inner_ptr_const() as *const _ as *mut _
    }
}
