/* Copyright (c) Fortanix, Inc.                                                                                                                                                                                                          
 *                                                                                                                                                                                                                                       
 * This Source Code Form is subject to the terms of the Mozilla Public                                                                                                                                                                   
 * License, v. 2.0. If a copy of the MPL was not distributed with this                                                                                                                                                                   
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
/* Copyright (c) Fortanix, Inc. */

use hyper::net::{HttpListener, HttpsListener, NetworkListener};
use hyper::status::StatusCode;
use mbedtls::pk::Pk;
use mbedtls::ssl::Config;
use mbedtls::ssl::config::{Endpoint, Preset, Transport, AuthMode, Version};
use mbedtls::ssl::context::HandshakeContext;
use mbedtls::x509::Certificate;
use std::sync::Arc;
use mbedtls::ssl::TicketContext;
use mbedtls_hyper::MbedSSLServer;
use std::net::SocketAddr;
use hyper::{Get, Post};
use hyper::server::{Request, Response};
use hyper::uri::RequestUri::AbsolutePath;
use std::io::Read;

use serde::{Deserialize, Serialize};

#[cfg(not(target_env = "sgx"))]
use mbedtls::rng::{OsEntropy, CtrDrbg};

#[cfg(target_env = "sgx")]
use mbedtls::rng::{Rdrand};


#[cfg(not(target_env = "sgx"))]
pub fn rng_new() -> Arc<CtrDrbg> {
    let entropy = Arc::new(OsEntropy::new());
    let rng = Arc::new(CtrDrbg::new(entropy, None).unwrap());
    rng
}

#[cfg(target_env = "sgx")]
pub fn rng_new() -> Arc<Rdrand> {
    Arc::new(Rdrand)
}

pub const PEM_CERT: &'static str  = concat!(include_str!("./certificates/cert.pem"), '\0');
pub const PEM_KEY: &'static str  = concat!(include_str!("./certificates/key.pem"), '\0');

fn create_server(local_addr: &str) -> Result<(SocketAddr, hyper::Server<HttpsListener<MbedSSLServer>>), hyper::Error> {
    std::env::set_var("RUST_BACKTRACE", "full");
    
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
    let rng = rng_new();
    
    config.set_rng(rng.clone());
    config.set_min_version(Version::Tls1_2).unwrap();

    /* If mbedtls debug is needed.
    #[cfg(not(target_env = "sgx"))]
    {
        mbedtls::set_global_debug_threshold(1);
        let dbg_callback = |level: i32, file: &str, line: i32, message: &str| {
            println!("{} {}:{} {}", level, file, line, message);
        };
        config.set_dbg_callback(dbg_callback.clone());
    }*/
    
    let cert = Arc::new(Certificate::from_pem(PEM_CERT.as_bytes()).unwrap());
    let key = Arc::new(Pk::from_private_key(PEM_KEY.as_bytes(), None).unwrap());
    
    // Using SNI Callback to show we can host multiple domains on one server.
    let sni_callback = move |ctx: &mut HandshakeContext, name: &[u8]| -> Result<(), mbedtls::Error> {
        let name = std::str::from_utf8(name).unwrap();
        println!("Handling request for SNI: {}", name);
        
        if name == "mbedtls.example" {
            ctx.set_authmode(AuthMode::None).unwrap();
            ctx.push_cert(cert.clone(), key.clone()).unwrap();
            Ok(())
        } else {
            println!("We do not have a certificate for hostname: {}", name);
            return Err(mbedtls::Error::SslNoClientCertificate);
        }
    };
    config.set_sni_callback(sni_callback);                                    
    
    let tctx = TicketContext::new(rng.clone(), mbedtls::cipher::raw::CipherType::Aes128Gcm, 300).unwrap();
    config.set_session_tickets_callback(Arc::new(tctx));
    
    let ssl = MbedSSLServer::new(Arc::new(config));
    
    // Random port is intentional
    let mut listener = HttpListener::new(local_addr).unwrap();
    Ok((listener.local_addr().unwrap(), hyper::Server::new(HttpsListener::with_listener(listener, ssl))))
}

fn echo(mut req: Request, mut res: Response) {
    
    match req.uri {
        AbsolutePath(ref path) => match (&req.method, &path[..]) {
            (&Get, "/") | (&Get, "/test") => {
                match res.send(b"Try POST /test") {
                    Ok(_) => (),
                    Err(e) => println!("Error: {}", e),
                }
                return;
            },
            (&Post, "/test") => (), // fall through, fighting mutable borrows
            _ => {
                return;
            }
        },
        _ => {
            return;
        }
    };

    let mut body = String::new();
    req.read_to_string(&mut body).unwrap();

    #[derive(Serialize, Deserialize)]
    struct Person {
        name: String,
    };
    
    #[derive(Serialize, Deserialize)]
    struct Reply {
        status: String,
    };

    match serde_json::from_str::<Person>(&body) {
        Ok(person) => {
            *res.status_mut() = StatusCode::Ok;
            let reply = Reply { status: format!("Found person: {}", person.name) };
            let reply_text = serde_json::to_string(&reply).unwrap();
            res.send(reply_text.as_bytes()).unwrap();
        },
        Err(e) => {
            *res.status_mut() = StatusCode::BadRequest;
            res.send(format!("{}", e).as_bytes()).unwrap();
        }
    }
}


fn main() -> Result<(), String> {
    let (local_addr, server) = create_server("0.0.0.0:9001").unwrap();

    let mut handler = server.handle_threads(echo, 3).unwrap();
    
    println!("\nListening on address: {} for host mbedtls.example", local_addr);
    println!("To test with curl: \n");

    // --cacert uses provided root ca to verify remote certificate
    // --resolve allows us to do a DNS overrride for specified domain.
    println!("# curl --cacert ./src/certificates/ca.pem --resolve mbedtls.example:{}:127.0.0.1 -X POST -d '{{ \"name\": \"john doe\" }} ' https://mbedtls.example:{}/test\n", local_addr.port(), local_addr.port());
    
    
    while true {
        std::thread::sleep(core::time::Duration::from_millis(10));
    }

    handler.close().unwrap();
    Ok(())
}
