/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
use mbedtls_sys::types::size_t;
use mbedtls_sys::*;
use crate::x509::Certificate;
use crate::pk::Pk;
use std::io::{Read, Write};
use crate::error::{Error, Result, IntoResult};
use std::net::TcpStream;
use std::net::SocketAddr;
use std::time::Duration;
use std::sync::Arc;

pub enum Endpoint {
    Client = SSL_IS_CLIENT as isize,
    Server = SSL_IS_SERVER as isize,
}

pub enum Transport {
    Stream = SSL_TRANSPORT_STREAM as isize,     // TLS
    Datagram = SSL_TRANSPORT_DATAGRAM as isize, // DTLS
}

pub enum Preset {
    Default = SSL_PRESET_DEFAULT as isize,
    SuiteB = SSL_PRESET_SUITEB as isize,
}

pub enum AuthMode {
    None = SSL_VERIFY_NONE as isize,         // **INSECURE** on client, default on server
    Optional = SSL_VERIFY_OPTIONAL as isize, // **INSECURE**
    Required = SSL_VERIFY_REQUIRED as isize, // default on client
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

pub struct MbedSSLConfig {
    inner: ssl_config,

    // Look at const casting + Option<Arc<...>...
    own_cert: Option<Arc<Certificate>>,
    own_pk: Option<Arc<Pk>>,
    ca_cert: Option<Arc<Certificate>>,
}

impl MbedSSLConfig {
    pub fn new(e: Endpoint, t: Transport, p: Preset) -> Self {
        let config = unsafe {
            let mut data = std::mem::MaybeUninit::<ssl_config>::uninit();
            ssl_config_init(data.as_mut_ptr());
            ssl_config_defaults(data.as_mut_ptr(), e as c_int, t as c_int, p as c_int);
            data.assume_init()
        };

        MbedSSLConfig {
            inner: config,
            own_cert: None,
            own_pk: None,
            ca_cert: None,
        }
    }

    pub fn inner_ptr(&mut self) -> *mut ssl_config {
        &mut self.inner
    }

    pub fn inner_ptr_const(&self) -> *const ssl_config {
        &self.inner
    }

    pub fn set_authmode(&mut self, authmode: AuthMode) {
        unsafe { ssl_conf_authmode(&mut self.inner, authmode as c_int); }
    }

    pub fn set_rng<F: crate::rng::Random>(&mut self, rng: Option<&mut F>) {
        unsafe { ssl_conf_rng(&mut self.inner, rng.as_ref().map(|_|F::call as _), rng.map(|f|f.data_ptr()).unwrap_or(::core::ptr::null_mut())) }
    }
    
    pub fn set_min_version(&mut self, version: Version) -> Result<()> {
        let minor = match version {
            Version::Ssl3 => 0,
            Version::Tls1_0 => 1,
            Version::Tls1_1 => 2,
            Version::Tls1_2 => 3,
            _ => { return Err(Error::SslBadHsProtocolVersion); }
        };

        unsafe { ssl_conf_min_version(&mut self.inner, 3, minor) };
        Ok(())
    }

    pub fn push_cert(&mut self, own_cert: Arc<Certificate>, own_pk: Arc<Pk>) -> Result<()> {
        // Need to ensure own_cert/pk_key outlive the config.
        self.own_cert = Some(own_cert.clone());
        self.own_pk = Some(own_pk.clone());

        unsafe { ssl_conf_own_cert(&mut self.inner, own_cert.inner_ptr_const(), own_pk.inner_ptr_const())
                 .into_result()
                 .map(|_| ())
        }
    }

    pub fn set_single_ca(&mut self, ca_cert: Arc<Certificate>) {
        // Lifetime of CA Cert must exceed config.
        self.ca_cert = Some(ca_cert.clone());
        
        unsafe { ssl_conf_ca_chain(&mut self.inner, ca_cert.inner_ptr_const(), ::core::ptr::null_mut()); }
    }
}

impl Drop for MbedSSLConfig {
    fn drop(&mut self) {
        unsafe { ssl_config_free(&mut self.inner); }
    }
}

pub struct MbedSSLContext {
    inner: ssl_context,

    // config is used read-only for mutliple contexts and is immutable once configured.
    #[allow(dead_code)]
    config: Option<Arc<MbedSSLConfig>>, 

    // Must be held in heap and pointer to it as pointer is sent to MbedSSL and can't be re-allocated.
    #[allow(dead_code)]
    io: Option<Box<TcpStream>>,
}


#[allow(dead_code)]
unsafe extern "C" fn call_recv(user_data: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
    let len = if len > (c_int::max_value() as size_t) {
        c_int::max_value() as size_t
    } else {
        len
    };
    match (&mut *(user_data as *mut TcpStream)).read(::core::slice::from_raw_parts_mut(data, len)) {
        Ok(i) => i as c_int,
        Err(_) => ::mbedtls_sys::ERR_NET_RECV_FAILED,
    }
}

#[allow(dead_code)]
unsafe extern "C" fn call_send(user_data: *mut c_void, data: *const c_uchar, len: size_t) -> c_int {
    let len = if len > (c_int::max_value() as size_t) {
        c_int::max_value() as size_t
    } else {
        len
    };
    match (&mut *(user_data as *mut TcpStream)).write(::core::slice::from_raw_parts(data, len)) {
        Ok(i) => i as c_int,
        Err(_) => ::mbedtls_sys::ERR_NET_SEND_FAILED,
    }
}


impl MbedSSLContext {
    pub fn new(config: Arc<MbedSSLConfig>) -> Self {
        let context = unsafe {
            let mut data = std::mem::MaybeUninit::<ssl_context>::uninit();
            ssl_init(data.as_mut_ptr());
            ssl_setup(data.as_mut_ptr(), Arc::as_ptr(&config).as_ref().unwrap().inner_ptr_const());
            data.assume_init()
        };

        MbedSSLContext {
            inner: context,
            config: Some(config.clone()),
            io: None,
        }
    }

    #[allow(dead_code)]
    fn set_hostname(&mut self, hostname: Option<&str>) -> Result<()> {
        if let Some(s) = hostname {
            let cstr = ::std::ffi::CString::new(s).map_err(|_| Error::SslBadInputData)?;
            unsafe {
                ssl_set_hostname(&mut self.inner, cstr.as_ptr())
                    .into_result()
                    .map(|_| ())
            }
        } else {
            Ok(())
        }
    }

    
    #[allow(dead_code)]
    pub fn establish(&mut self, io: TcpStream, hostname: Option<&str>) -> Result<()> {
        unsafe {
            let mut io = Box::new(io);
            
            ssl_session_reset(&mut self.inner).into_result()?;
            self.set_hostname(hostname)?;

            let ptr = &mut *io as *mut TcpStream as *mut c_void;
            ssl_set_bio(
                &mut self.inner,
                ptr,
                Some(call_send),
                Some(call_recv),
                None,
            );

            self.io = Some(io);

            match ssl_handshake(&mut self.inner).into_result() {
                Err(e) => {
                    // safely end borrow of io
                    ssl_set_bio(&mut self.inner, ::core::ptr::null_mut(), None, None, None);
                    self.io = None;
                    Err(e)
                },
                Ok(_) => {
                    Ok(())
                }
            }
        }
    }

    #[allow(dead_code)]
    pub fn close(&mut self) {
        unsafe {
            ssl_close_notify(&mut self.inner);
            ssl_set_bio(&mut self.inner, ::core::ptr::null_mut(), None, None, None);
            self.io = None;
        }
    }

    #[allow(dead_code)]
    pub fn peer_addr(&mut self) -> std::io::Result<SocketAddr> {
        match &self.io {
            Some(stream) => stream.peer_addr(),
            None => Err(std::io::Error::new(std::io::ErrorKind::NotFound, "No peer available")),
        }
    }

    #[allow(dead_code)]
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        match &self.io {
            Some(stream) => stream.set_read_timeout(dur),
            None => Err(std::io::Error::new(std::io::ErrorKind::NotFound, "No peer available")),
        }
    }

    #[allow(dead_code)]
    pub fn set_write_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        match &self.io {
            Some(stream) => stream.set_write_timeout(dur),
            None => Err(std::io::Error::new(std::io::ErrorKind::NotFound, "No peer available")),
        }
    }
    
}

impl Drop for MbedSSLContext {
    fn drop(&mut self) {
        unsafe {
            ssl_close_notify(&mut self.inner);
            ssl_set_bio(&mut self.inner, ::core::ptr::null_mut(), None, None, None);
            ssl_free(&mut self.inner);
        }
    }
}

impl Read for MbedSSLContext {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match unsafe { ssl_read(&mut self.inner, buf.as_mut_ptr(), buf.len()).into_result() } {
            Err(Error::SslPeerCloseNotify) => Ok(0),
            Err(e) => Err(crate::private::error_to_io_error(e)),
            Ok(i) => Ok(i as usize),
        }
    }
}

impl Write for MbedSSLContext {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match unsafe { ssl_write(&mut self.inner, buf.as_ptr(), buf.len()).into_result() } {
            Err(Error::SslPeerCloseNotify) => Ok(0),
            Err(e) => Err(crate::private::error_to_io_error(e)),
            Ok(i) => Ok(i as usize),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

