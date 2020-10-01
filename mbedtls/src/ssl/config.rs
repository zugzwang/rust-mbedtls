/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use crate::x509::certificate::Certificate;
use crate::error::{Error, Result, IntoResult};
use crate::pk::Pk;
use crate::rng::RngCallback;
use mbedtls_sys::*;
use mbedtls_sys::types::raw_types::{c_int, c_void, c_char, c_uchar, c_uint};
use std::sync::Arc;
use crate::x509::crl::Crl;
use crate::x509::LinkedCertificate;
use crate::x509::VerifyError;
use crate::ssl::context::HandshakeContext;
use mbedtls_sys::types::size_t;
use std::slice::from_raw_parts;
use crate::ssl::ticket::TicketCallback;
use crate::pk::dhparam::Dhm;
use crate::x509::Profile;
use crate::ssl::Context;

extern "C" {
    fn calloc(n: usize, size: usize) -> *mut c_void;
    fn free(ptr: *mut c_void);
}

#[allow(non_camel_case_types)]
#[derive(Eq, PartialEq, PartialOrd, Ord, Debug, Copy, Clone)]
pub enum Version {
    Ssl3,
    Tls1_0,
    Tls1_1,
    Tls1_2,
    #[doc(hidden)]
    __NonExhaustive,
}

define!(
    #[c_ty(c_int)]
    enum Endpoint {
        Client = SSL_IS_CLIENT,
        Server = SSL_IS_SERVER,
    }
);

define!(
    #[c_ty(c_int)]
    enum Transport {
        /// TLS
        Stream = SSL_TRANSPORT_STREAM,
        /// DTLS
        Datagram = SSL_TRANSPORT_DATAGRAM,
    }
);

define!(
    #[c_ty(c_int)]
    enum Preset {
        Default = SSL_PRESET_DEFAULT,
        SuiteB = SSL_PRESET_SUITEB,
    }
);

define!(
    #[c_ty(c_int)]
    enum AuthMode {
        /// **INSECURE** on client, default on server
        None = SSL_VERIFY_NONE,
        /// **INSECURE**
        Optional = SSL_VERIFY_OPTIONAL,
        /// default on client
        Required = SSL_VERIFY_REQUIRED,
    }
);

define!(
    #[c_ty(c_int)]
    enum UseSessionTickets {
        Enabled = SSL_SESSION_TICKETS_ENABLED,
        Disabled = SSL_SESSION_TICKETS_DISABLED,
    }
);

define!(
    #[c_ty(c_int)]
    enum Renegotiation {
        Enabled = SSL_RENEGOTIATION_ENABLED,
        Disabled = SSL_RENEGOTIATION_DISABLED,
    }
);



pub struct Config {
    // Moving data may cause dangling pointers: https://github.com/ARMmbed/mbedtls/issues/2147
    // Storing data in heap and forcing rust move to only move the pointer (box) referencing it.
    inner: Box<ssl_config>,

    // Holding reference counters against any structures that ssl_config might hold pointer to.
    // This allows caller to share structure on multiple configs if needed.
    own_cert: Vec<Arc<Certificate>>,
    own_pk: Vec<Arc<Pk>>,
    
    ca_cert: Option<Arc<Certificate>>,
    crl: Option<Arc<Crl>>,
    
    rng: Option<Arc<dyn RngCallback + Send + Sync + 'static>>,
    ciphersuites: Vec<Arc<Vec<c_int>>>,
    curves: Option<Arc<Vec<ecp_group_id>>>,
    dhm: Option<Arc<Dhm>>,

    verify_callback: Option<Arc<dyn (Fn(LinkedCertificate, i32, &mut VerifyError) -> Result<()>) + Send + Sync + 'static>>,
    dbg_callback: Option<Arc<dyn (Fn(i32, &str, i32, &str) -> ()) + Send + Sync + 'static>>,
    sni_callback: Option<Arc<dyn (Fn(&mut HandshakeContext, &[u8]) -> Result<()>) + Send + Sync + 'static>>,
    ticket_callback: Option<Arc<dyn TicketCallback + Send + Sync + 'static>>,
    ca_callback: Option<Arc<dyn (Fn(&LinkedCertificate, &mut ForeignOwnedCertListBuilder) -> Result<()>) + Send + Sync + 'static>>,

}

#[cfg(feature = "threading")]
unsafe impl Sync for Config {}

#[cfg(feature = "threading")]
unsafe impl Send for Config {}

impl Into<*mut mbedtls_sys::ssl_config> for &mut Config {
    fn into(self) -> *mut mbedtls_sys::ssl_config {
        &mut *self.inner
    }
}


impl Config {
    pub fn new(e: Endpoint, t: Transport, p: Preset) -> Self {
        let mut inner = Box::new(ssl_config::default());

        unsafe {
            // This is just a memset to 0.
            ssl_config_init(&mut *inner);

            // Set default values - after this point we will need ssl_config_free to be called.
            ssl_config_defaults(&mut *inner, e as c_int, t as c_int, p as c_int);
        };

        Config {
            inner,
            own_cert: vec![],
            own_pk: vec![],
            ca_cert: None,
            crl: None,
            rng: None,
            ciphersuites: vec![],
            curves: None,
            dhm: None,
            verify_callback: None,
            dbg_callback: None,
            sni_callback: None,
            ticket_callback: None,
            ca_callback: None,
        }
    }

    // Used to get internal pointer from an Arc
    pub fn inner_ptr_const(&self) -> *const ssl_config {
        &*self.inner
    }

    pub fn set_authmode(&mut self, authmode: AuthMode) {
        unsafe { ssl_conf_authmode(self.into(), authmode as c_int); }
    }

    pub fn read_timeout(&self) -> u32 {
        self.inner.read_timeout
    }

    pub fn set_read_timeout(&mut self, t: u32) {
        unsafe { ssl_conf_read_timeout(self.into(), t); }
    }

    fn check_c_list<T: Default + Eq>(list: &[T]) {
        assert!(list.last() == Some(&T::default()));
    }

    pub fn set_ciphersuites(&mut self, list: Arc<Vec<c_int>>) {
        Self::check_c_list(&list);

        unsafe { ssl_conf_ciphersuites(self.into(), (*Arc::as_ptr(&list)).as_ptr()) }
        self.ciphersuites.push(list);
    }

    pub fn set_ciphersuites_for_version(&mut self, list: Arc<Vec<c_int>>, major: c_int, minor: c_int) {
        Self::check_c_list(&list);
        unsafe { ssl_conf_ciphersuites_for_version(self.into(), (*Arc::as_ptr(&list)).as_ptr(), major, minor) }
        self.ciphersuites.push(list);
    }

    pub fn set_curves(&mut self, list: Arc<Vec<ecp_group_id>>) {
        Self::check_c_list(&list);
        unsafe { ssl_conf_curves(self.into(), (*Arc::as_ptr(&list)).as_ptr()) }
        self.curves = Some(list);
    }

    pub fn set_rng<T: RngCallback + Send + Sync + 'static>(&mut self, rng: Arc<T>) {
        unsafe { ssl_conf_rng(self.into(), Some(T::call), rng.data_ptr()) };
        self.rng = Some(rng);
    }
    
    pub fn set_min_version(&mut self, version: Version) -> Result<()> {
        let minor = match version {
            Version::Ssl3 => 0,
            Version::Tls1_0 => 1,
            Version::Tls1_1 => 2,
            Version::Tls1_2 => 3,
            _ => { return Err(Error::SslBadHsProtocolVersion); }
        };

        unsafe { ssl_conf_min_version(self.into(), 3, minor) };
        Ok(())
    }

    pub fn set_max_version(&mut self, version: Version) -> Result<()> {
        let minor = match version {
            Version::Ssl3 => 0,
            Version::Tls1_0 => 1,
            Version::Tls1_1 => 2,
            Version::Tls1_2 => 3,
            _ => { return Err(Error::SslBadHsProtocolVersion); }
        };
        unsafe { ssl_conf_max_version(self.into(), 3, minor) };
        Ok(())
    }

    // Profile as implemented in profile.rs can only point to global variables from mbedtls which would have 'static lifetime
    pub fn set_cert_profile(&mut self, p: &'static Profile) {
        unsafe { ssl_conf_cert_profile(self.into(), p.into()) };
    }

    /// Takes both DER and PEM forms of FFDH parameters in `DHParams` format.
    ///
    /// When calling on PEM-encoded data, `params` must be NULL-terminated
    pub fn set_dh_params(&mut self, params: &[u8]) -> Result<()> {
        let ctx = Arc::new(Dhm::from_params(params)?);
        unsafe {
            ssl_conf_dh_param_ctx(self.into(), ctx.inner_ptr_const())
                .into_result()
                .map(|_| ())
        }
    }

    pub fn set_ca_list(&mut self, ca_cert: Arc<Certificate>, crl: Option<Arc<Crl>>) {
        // This will override internal pointers to what we provide.
        unsafe { ssl_conf_ca_chain(self.into(), ca_cert.inner_ptr_const(), crl.as_ref().map(|crl| crl.inner_ptr_const()).unwrap_or(::core::ptr::null_mut())); }

        self.ca_cert = Some(ca_cert);
        self.crl = crl;        
    }

    pub fn push_cert(&mut self, own_cert: Arc<Certificate>, own_pk: Arc<Pk>) -> Result<()> {
        // Need to ensure own_cert/pk_key outlive the config.
        self.own_cert.push(own_cert.clone());
        self.own_pk.push(own_pk.clone());

        // This will append pointers to our certificates inside mbedtls
        unsafe { ssl_conf_own_cert(self.into(), own_cert.inner_ptr_const(), own_pk.inner_ptr_const())
                 .into_result()
                 .map(|_| ())
        }
    }

    /// Server only: configure callback to use for generating/interpreting session tickets.
    pub fn set_session_tickets_callback<T: TicketCallback + Send + Sync + 'static>(&mut self, cb: Arc<T>) {
        unsafe {
            ssl_conf_session_tickets_cb(
                self.into(),
                Some(T::call_write),
                Some(T::call_parse),
                cb.data_ptr(),
            )
        };

        self.ticket_callback = Some(cb);
    }

    pub fn set_session_tickets(&mut self, u: UseSessionTickets) {
        unsafe { ssl_conf_session_tickets(self.into(), u.into()); }
    }

    pub fn set_renegotiation(&mut self, u: Renegotiation) {
        unsafe { ssl_conf_renegotiation(self.into(), u.into()); }
    }

    /// Client only: minimal FFDH group size
    pub fn set_ffdh_min_bitlen(&mut self, bitlen: c_uint) {
        unsafe { ssl_conf_dhm_min_bitlen(self.into(), bitlen); }
    }
    
    pub fn set_sni_callback<F>(&mut self, cb: F)
    where
        F: Fn(&mut HandshakeContext, &[u8]) -> Result<()> + Send + Sync + 'static,
    {
        unsafe extern "C" fn sni_callback<F>(
            closure: *mut c_void,
            ctx: *mut ssl_context,
            name: *const c_uchar,
            name_len: size_t,
        ) -> c_int
        where
            F: Fn(&mut HandshakeContext, &[u8]) -> Result<()> + Send + Sync + 'static,
        {
            // This is called from:
            //
            // mbedtls/src/ssl/context.rs           - establish
            // mbedtls-sys/vendor/library/ssl_tls.c - mbedtls_ssl_handshake
            // mbedtls-sys/vendor/library/ssl_tls.c - mbedtls_ssl_handshake_step
            // mbedtls-sys/vendor/library/ssl_srv.c - mbedtls_ssl_handshake_server_step
            // mbedtls-sys/vendor/library/ssl_srv.c - ssl_parse_client_hello
            // mbedtls-sys/vendor/library/ssl_srv.c - ssl_parse_servername_ext
            //
            // As such:
            // - The ssl_context is a rust 'Context' structure that we have a mutable reference to via 'establish'
            // - We can pointer cast to it to allow storing additional objects.
            //
            if closure == ::core::ptr::null_mut() || ctx == ::core::ptr::null_mut() || name == ::core::ptr::null_mut() {
                return ::mbedtls_sys::ERR_X509_BAD_INPUT_DATA;
            }

            let cb = &mut *(closure as *mut F);
            let context = &mut *(ctx as *mut Context);
            
            let mut ctx = HandshakeContext::init(context);
            
            let name = from_raw_parts(name, name_len);
            match cb(&mut ctx, name) {
                Ok(()) => 0,
                Err(_) => -1,
            }
        }

        self.sni_callback = Some(Arc::new(cb));

        unsafe { ssl_conf_sni(self.into(), Some(sni_callback::<F>), Arc::as_ptr(&mut self.sni_callback.as_ref().unwrap()) as *mut F as _) }
    }
    
    // The docs for mbedtls_x509_crt_verify say "The [callback] should return 0 for anything but a
    // fatal error.", so verify callbacks should return Ok(()) for anything but a fatal error.
    // Report verification errors by updating the flags in VerifyError.
    pub fn set_verify_callback<F>(&mut self, cb: F)
    where
        F: Fn(LinkedCertificate, i32, &mut VerifyError) -> Result<()> + Send + Sync + 'static,
    {
        unsafe extern "C" fn verify_callback<F>(
            closure: *mut c_void,
            crt: *mut x509_crt,
            depth: c_int,
            flags: *mut u32,
        ) -> c_int
        where
            F: Fn(LinkedCertificate, i32, &mut VerifyError) -> Result<()> + Send + Sync + 'static,
        {
            if crt == ::core::ptr::null_mut() || closure == ::core::ptr::null_mut() || flags == ::core::ptr::null_mut() {
                return ::mbedtls_sys::ERR_X509_BAD_INPUT_DATA;
            }

            let cb = &mut *(closure as *mut F);
            let crt = LinkedCertificate { inner: &*crt };
            
            let mut verify_error = match VerifyError::from_bits(*flags) {
                Some(ve) => ve,
                // This can only happen if mbedtls is setting flags in VerifyError that are
                // missing from our definition.
                None => return ::mbedtls_sys::ERR_X509_BAD_INPUT_DATA,
            };
            
            let res = cb(crt, depth, &mut verify_error);
            *flags = verify_error.bits();
            match res {
                Ok(()) => 0,
                Err(e) => e.to_int(),
            }
        }

        self.verify_callback = Some(Arc::new(cb));
        
        unsafe {
            ssl_conf_verify(
                self.into(),
                Some(verify_callback::<F>),
                Arc::as_ptr(&mut self.verify_callback.as_ref().unwrap()) as *mut F as _,
            )
        }
    }

    pub fn set_ca_callback<F>(&mut self, cb: F)
        where
            F: Fn(&LinkedCertificate, &mut ForeignOwnedCertListBuilder) -> Result<()> + Send + Sync + 'static,
    {
        unsafe extern "C" fn ca_callback<F>(
            closure: *mut c_void,
            child: *const x509_crt,
            candidate_cas: *mut *mut x509_crt
        ) -> c_int
            where
                F: Fn(&LinkedCertificate, &mut ForeignOwnedCertListBuilder) -> Result<()> + Send + Sync + 'static,
        {
            if child == ::core::ptr::null_mut() || closure == ::core::ptr::null_mut() || candidate_cas == ::core::ptr::null_mut() {
                return ::mbedtls_sys::ERR_X509_BAD_INPUT_DATA;
            }

            let cb = &mut *(closure as *mut F);
            let crt = LinkedCertificate { inner: &*child };
            let mut cert_builder = ForeignOwnedCertListBuilder::new();
            match cb(&crt, &mut cert_builder) {
                Ok(()) => {
                    *candidate_cas = cert_builder.to_x509_crt_ptr();
                    0
                },
                Err(e) => e.to_int(),
            }
        }

        self.ca_callback = Some(Arc::new(cb));

        unsafe {
            ssl_conf_ca_cb(
                self.into(),
                Some(ca_callback::<F>),
                Arc::as_ptr(&mut self.ca_callback.as_ref().unwrap()) as *mut F as _,
            )
        }
    }

    pub fn set_dbg_callback<F>(&mut self, cb: F)
    where
        F: (Fn(i32, &str, i32, &str) -> ()) + Send + Sync + 'static,
    {
        unsafe extern "C" fn dbg_callback<F>(
            closure: *mut c_void,
            level: c_int,
            file: *const c_char,
            line: c_int,
            message: *const c_char
        ) -> ()
        where
            F: (Fn(i32, &str, i32, &str) -> ()) + Send + Sync + 'static,
        {
            if file == ::core::ptr::null_mut() || message == ::core::ptr::null_mut() {
                return ();
            }

            let cb = &mut *(closure as *mut F);

            let file = match std::ffi::CStr::from_ptr(file).to_str() {
                Ok(text) => text,
                Err(_) => return (),
            };
            
            let message = match std::ffi::CStr::from_ptr(message).to_str() {
                Ok(text) => text,
                Err(_) => return (),
            };
            
            
            cb(level, file, line, message);
        }

        self.dbg_callback = Some(Arc::new(cb));
        
        unsafe {
            ssl_conf_dbg(
                self.into(),
                Some(dbg_callback::<F>),
                Arc::as_ptr(&mut self.dbg_callback.as_ref().unwrap()) as *mut F as _,
            )
        }
    }


}


impl Drop for Config {
    fn drop(&mut self) {
        unsafe { ssl_config_free(self.into()); }
    }
}

/// Builds a linked list of x509_crt instances, all of which are owned by mbedtls. That is, the
/// memory for these certificates has been allocated by mbedtls, on the C heap. This is needed for
/// situations in which an mbedtls function takes ownership of a list of certs. The problem with
/// handing such functions a "normal" cert list such as certificate::LinkedCertificate or
/// certificate::List, is that those lists (at least partly) consist of memory allocated on the
/// rust-side and hence cannot be freed on the c-side.
pub struct ForeignOwnedCertListBuilder {
    cert_list: *mut x509_crt,
}

impl ForeignOwnedCertListBuilder {
    pub(crate) fn new() -> Self {
        let cert_list = unsafe { calloc(1, core::mem::size_of::<x509_crt>()) } as *mut x509_crt;
        if cert_list == ::core::ptr::null_mut() {
            panic!("Out of memory");
        }
        unsafe { ::mbedtls_sys::x509_crt_init(cert_list); }

        Self {
            cert_list
        }
    }

    pub fn push_back(&mut self, cert: &LinkedCertificate) {
        self.try_push_back(cert.as_der()).expect("cert is a valid DER-encoded certificate");
    }

    pub fn try_push_back_pem(&mut self, cert: &[u8]) -> Result<()> {
        // x509_crt_parse will allocate memory for the cert on the C heap
        unsafe { x509_crt_parse(self.cert_list, cert.as_ptr(), cert.len()) }.into_result()?;
        Ok(())
    }

    pub fn try_push_back(&mut self, cert: &[u8]) -> Result<()> {
        // x509_crt_parse_der will allocate memory for the cert on the C heap
        unsafe { x509_crt_parse_der(self.cert_list, cert.as_ptr(), cert.len()) }.into_result()?;
        Ok(())
    }

    // The memory pointed to by the return value is managed by mbedtls. If the return value is
    // dropped without handing it to an mbedtls-function that takes ownership of it, that memory
    // will be leaked.
    pub(crate) fn to_x509_crt_ptr(mut self) -> *mut x509_crt {
        let res = self.cert_list;
        self.cert_list = ::core::ptr::null_mut();
        res
    }
}

impl Drop for ForeignOwnedCertListBuilder {
    fn drop(&mut self) {
        unsafe {
            ::mbedtls_sys::x509_crt_free(self.cert_list);
            free(self.cert_list as *mut c_void);
        }
    }
}
