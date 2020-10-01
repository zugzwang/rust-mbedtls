/* Copyright (c) Fortanix, Inc.
 *
 * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
 * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
 * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
 * option. This file may not be copied, modified, or distributed except
 * according to those terms. */

#![allow(dead_code)]
extern crate mbedtls;

use std::net::TcpStream;

use mbedtls::pk::Pk;
use mbedtls::rng::CtrDrbg;
use mbedtls::ssl::config::{Endpoint, Preset, Transport, ForeignOwnedCertListBuilder};
use mbedtls::ssl::{Config, Context};
use mbedtls::x509::{Certificate, LinkedCertificate};
use mbedtls::Result as TlsResult;
use std::sync::Arc;

mod support;
use support::entropy::entropy_new;


fn client<F>(conn: TcpStream, ca_callback: F) -> TlsResult<()>
    where
        F: Fn(&LinkedCertificate, &mut ForeignOwnedCertListBuilder) -> TlsResult<()> + Send + Sync + 'static,
{
    let entropy = entropy_new();
    let rng = Arc::new(CtrDrbg::new(Arc::new(entropy), None)?);
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    config.set_rng(rng);
    config.set_ca_callback(ca_callback);
    let mut ctx = Context::new(Arc::new(config));
    ctx.establish(conn, None).map(|_| ())
}

fn server(conn: TcpStream, cert: &[u8], key: &[u8]) -> TlsResult<()> {
    let entropy = entropy_new();
    let rng = Arc::new(CtrDrbg::new(Arc::new(entropy), None)?);
    let cert = Arc::new(Certificate::from_pem(cert)?);
    let key = Arc::new(Pk::from_private_key(key, None)?);
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
    config.set_rng(rng);
    config.push_cert(cert, key)?;
    let mut ctx = Context::new(Arc::new(config));

    let _ = ctx.establish(conn, None);
    Ok(())
}

#[cfg(unix)]
mod test {
    use super::*;
    use std::thread;
    use crate::support::net::create_tcp_pair;
    use crate::support::keys;
    use mbedtls::x509::{LinkedCertificate};
    use mbedtls::Error;

    // This callback should accept any valid self-signed certificate
    fn self_signed_ca_callback(child: &LinkedCertificate, cert_builder: &mut ForeignOwnedCertListBuilder) -> TlsResult<()> {
        cert_builder.push_back(child);
        Ok(())
    }

    #[test]
    fn callback_standard_ca() {
        let (c, s) = create_tcp_pair().unwrap();

        let ca_callback =
            |_: &LinkedCertificate, cert_builder: &mut ForeignOwnedCertListBuilder| -> TlsResult<()> {
                cert_builder.try_push_back_pem(keys::ROOT_CA_CERT).unwrap();
                Ok(())
            };
        let c = thread::spawn(move || super::client(c, ca_callback).unwrap());
        let s = thread::spawn(move || super::server(s, keys::PEM_CERT, keys::PEM_KEY).unwrap());
        c.join().unwrap();
        s.join().unwrap();
    }

    #[test]
    fn callback_no_ca() {
        let (c, s) = create_tcp_pair().unwrap();
        let ca_callback =
            |_: &LinkedCertificate, _: &mut ForeignOwnedCertListBuilder| -> TlsResult<()> {
                Ok(())
            };
        let c = thread::spawn(move || assert!(matches!(super::client(c, ca_callback), Err(Error::X509CertVerifyFailed))));
        let s = thread::spawn(move || super::server(s, keys::PEM_CERT, keys::PEM_KEY).unwrap());
        c.join().unwrap();
        s.join().unwrap();
    }

    #[test]
    fn callback_self_signed() {
        let (c, s) = create_tcp_pair().unwrap();
        let c = thread::spawn(move || super::client(c, self_signed_ca_callback).unwrap());
        let s = thread::spawn(move || super::server(s, keys::PEM_SELF_SIGNED_CERT, keys::PEM_SELF_SIGNED_KEY).unwrap());
        c.join().unwrap();
        s.join().unwrap();
    }

    #[test]
    fn callback_self_signed_leaf_cert() {
        // We set up the server to supply a non-self-signed leaf certificate. It should be rejected
        // by the client, because the ca_callback should only accept self-signed certificates.
        let (c, s) = create_tcp_pair().unwrap();
        let c = thread::spawn(move || assert!(matches!(super::client(c, self_signed_ca_callback), Err(Error::X509CertVerifyFailed))));
        let s = thread::spawn(move || super::server(s, keys::PEM_CERT, keys::PEM_KEY).unwrap());
        c.join().unwrap();
        s.join().unwrap();
    }

    #[test]
    fn callback_self_signed_invalid_sig() {
        // We set up the server to supply a self-signed certificate with an invalid signature. It
        // should be rejected by the client.
        let (c, s) = create_tcp_pair().unwrap();
        let c =
            thread::spawn(move || assert!(matches!(super::client(c, self_signed_ca_callback), Err(Error::X509CertVerifyFailed))));
        let s = thread::spawn(move || super::server(s, keys::PEM_SELF_SIGNED_CERT_INVALID_SIG, keys::PEM_SELF_SIGNED_KEY).unwrap());
        c.join().unwrap();
        s.join().unwrap();
    }
}