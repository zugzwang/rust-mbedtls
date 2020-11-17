/* Copyright (c) Fortanix, Inc.                                                                                                                                                                                                          
 *                                                                                                                                                                                                                                       
 * This Source Code Form is subject to the terms of the Mozilla Public                                                                                                                                                                   
 * License, v. 2.0. If a copy of the MPL was not distributed with this                                                                                                                                                                   
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
/* Copyright (c) Fortanix, Inc. */

#[cfg(target_env = "sgx")]
use em_app::*;

use hyper::net::{HttpListener, HttpsListener, NetworkListener};
use hyper::server::{Request, Response};
use hyper::status::StatusCode;
use hyper::uri::RequestUri::AbsolutePath;
use hyper::{Get, Post};
use mbedtls::pk::Pk;
use mbedtls::ssl::Config;
use mbedtls::ssl::TicketContext;
use mbedtls::ssl::config::{Endpoint, Preset, Transport, AuthMode, Version};
use mbedtls::x509::Certificate;
use mbedtls_hyper::{MbedSSLServer, MbedSSLClient};
use pkix::pem::{pem_to_der, PEM_CERTIFICATE};
use sdkms::{SdkmsClient};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::net::SocketAddr;
use std::sync::Arc;
use hyper::client::Pool;
use hyper::net::HttpsConnector;
use uuid::Uuid;
use sdkms::api_model::{KeyOperations, ObjectType, GroupRequest, SobjectRequest, AppPermissions, AppRequest, AppCredential, TrustAnchor};
use sdkms::api_model::Blob;

#[cfg(not(target_env = "sgx"))]
use mbedtls::rng::{OsEntropy, CtrDrbg};

#[cfg(target_env = "sgx")]
use mbedtls::rng::{Rdrand};

#[cfg(target_env = "sgx")]
fn generate_and_sign_key(domain: &str) -> (Arc<Certificate>, Arc<Pk>) {
    #[cfg(not(target_env = "sgx"))]
    let mut rng = CtrDrbg::new(Arc::new(OsEntropy::new()), None).unwrap();

    #[cfg(target_env = "sgx")]
    let mut rng = Rdrand;

    let mut key = Pk::generate_rsa(&mut rng, 3072, 0x10001).unwrap();

    // This must be on localhost otherwise local attestation will not work
    let node_agent_url = "http://localhost:9092";
    
    // Call to library to fetch certificates
    let result = get_fortanix_em_certificate(node_agent_url, domain, &mut key).map_err(|e| format!("Error: {}", e)).unwrap();
    //println!("certificate: {:?}, key: {:?}", &result.certificate_response.certificate, key.write_private_pem_string().unwrap());
    
    let app_cert = Certificate::from_der(&pem_to_der(&result.certificate_response.certificate.unwrap(), Some(PEM_CERTIFICATE)).unwrap())
        .map_err(|e| format!("Parsing certificate failed: {:?}", e)).unwrap();

    
    (Arc::new(app_cert), Arc::new(key))
}

#[cfg(not(target_env = "sgx"))]
fn generate_and_sign_key(domain: &str) -> (Arc<Certificate>, Arc<Pk>) {
    // For Non-SGX we cannot get a signed certificate since we are not in an enclave.
    // So we are going to use some hardcoded certificates for testing.
    pub const PEM_CERT: &'static str  = concat!(include_str!("../nonsgx_artifacts/cert.pem"), '\0');
    pub const PEM_KEY: &'static str  = concat!(include_str!("../nonsgx_artifacts/key.pem"), '\0');

    let cert = Arc::new(Certificate::from_pem(PEM_CERT.as_bytes()).unwrap());
    let key = Arc::new(Pk::from_private_key(PEM_KEY.as_bytes(), None).unwrap());

    (cert, key)
}

fn create_server(local_addr: &str, client_ca: Option<&str>, cert: Arc<Certificate>, key: Arc<Pk>) -> Result<(SocketAddr, hyper::Server<HttpsListener<MbedSSLServer>>), hyper::Error> {
    let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);

    #[cfg(not(target_env = "sgx"))]
    let rng = Arc::new(CtrDrbg::new(Arc::new(OsEntropy::new()), None).unwrap());

    #[cfg(target_env = "sgx")]
    let rng = Arc::new(Rdrand);
    
    config.set_rng(rng.clone());
    config.set_min_version(Version::Tls1_2).unwrap();
    config.push_cert(cert, key).unwrap();

    if let Some(client_ca) = client_ca {
        config.set_ca_list(Arc::new(Certificate::from_pem(client_ca.as_bytes()).unwrap()), None);
    }

    let tctx = TicketContext::new(rng.clone(), mbedtls::cipher::raw::CipherType::Aes128Gcm, 300).unwrap();
    config.set_session_tickets_callback(Arc::new(tctx));
    
    let ssl = MbedSSLServer::new(Arc::new(config));
    
    let mut listener = HttpListener::new(local_addr).unwrap();
    Ok((listener.local_addr().unwrap(), hyper::Server::new(HttpsListener::with_listener(listener, ssl))))
}

fn get_sdkms_client(cert: Arc<Certificate>, key: Arc<Pk>, api_key: Uuid) -> SdkmsClient {
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    config.set_authmode(AuthMode::Optional);

    #[cfg(not(target_env = "sgx"))]
    let rng = Arc::new(CtrDrbg::new(Arc::new(OsEntropy::new()), None).unwrap());

    #[cfg(target_env = "sgx")]
    let rng = Arc::new(Rdrand);
    
    config.set_rng(rng.clone());
    config.set_min_version(Version::Tls1_2).unwrap();

    // Client certificate use to authenticate on the server
    config.push_cert(cert, key).unwrap();
    let ssl = MbedSSLClient::new(Arc::new(config), true);
    
    let hyper_client = Arc::new(hyper::Client::with_connector(Pool::with_connector(Default::default(), HttpsConnector::new(ssl))));

    SdkmsClient::builder()
        .with_api_endpoint("https://apps.sdkms.test.fortanix.com")
        .with_hyper_client(hyper_client)
        .build().unwrap()
        .authenticate_with_cert(Some(&api_key)).unwrap()
}


struct ServerHandler {
    cert: Arc<Certificate>,
    key: Arc<Pk>,
    api_key: Uuid,
}

impl hyper::server::Handler for ServerHandler {
    fn handle(&self, mut req: Request, mut res: Response) {
        match req.uri {
            AbsolutePath(ref path) => match (&req.method, &path[..]) {
                (&Get, "/") | (&Get, "/sdkms") => {
                    match res.send(b"Try POST /sdkms") {
                        Ok(_) => (),
                        Err(e) => println!("Error: {}", e),
                    }
                    return;
                },
                (&Post, "/sdkms") => (), // fall through, fighting mutable borrows
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
        struct Object {
            id: String,
            value: String,
        };
                
        match serde_json::from_str::<Object>(&body) {
            Ok(object) => {
                *res.status_mut() = StatusCode::Ok;

                // This can be optimized further for production.
                let client = get_sdkms_client(self.cert.clone(), self.key.clone(), self.api_key.clone());
                let request = GroupRequest {
                    approval_policy: None,
                    description: None,
                    name: Some(object.id.to_string()),
                };
                match client.create_group(&request) {
                    Ok(group) => {
                        let request = SobjectRequest {                                                                                                                                                                                                       
                            activation_date: None,                                                                                                                                                                                                           
                            custom_metadata: None,                                                                                                                                                                                                           
                            deactivation_date: None,                                                                                                                                                                                                         
                            description: None,                                                                                                                                                                                                               
                            deterministic_signatures: None,                                                                                                                                                                                                  
                            elliptic_curve: None,                                                                                                                                                                                                            
                            enabled: Some(true),                                                                                                                                                                                                             
                            fpe: None,                                                                                                                                                                                                                       
                            key_ops: Some(KeyOperations::EXPORT | KeyOperations::APPMANAGEABLE),                                                                                                                                                             
                            key_size: None,                                                                                                                                                                                                                  
                            name: Some(object.id),                                                                                                                                                                                 
                            obj_type: Some(ObjectType::Secret),                                                                                                                                                                                              
                            pub_exponent: None,                                                                                                                                                                                                              
                            publish_public_key: None,                                                                                                                                                                                                        
                            rsa: None,                                                                                                                                                                                                                       
                            state: None,                                                                                                                                                                                                                     
                            transient: None,                                                                                                                                                                                                                 
                            value: Some(Blob::from(object.value)),
                            group_id: Some(group.group_id),                                                                                                                                                                                                  
                        };
                        match client.import_sobject(&request) {
                            Ok(secret) => {
                                let reply_text = serde_json::to_string(&secret).unwrap();
                                res.send(reply_text.as_bytes()).unwrap();
                            },
                            Err(e) => {
                                let reply_text = format!("{}", e);
                                *res.status_mut() = StatusCode::BadRequest;
                                res.send(reply_text.as_bytes()).unwrap();
                            }
                        };
                    },
                    Err(e) => {
                        let reply_text = format!("{}", e);
                        *res.status_mut() = StatusCode::BadRequest;
                        res.send(reply_text.as_bytes()).unwrap();
                    }
                }
            },
            Err(e) => {
                *res.status_mut() = StatusCode::BadRequest;
                res.send(format!("{}", e).as_bytes()).unwrap();
            }
        }
    }
}


fn main() -> Result<(), String> {
    std::env::set_var("RUST_BACKTRACE", "full");

    let zone_ca = None;

    // This should be the domain whitelisted in enclave manager / part of register_and_run.sh's config.
    let domain = "localhost";
    let api_key = "4bea4ed2-4025-4392-a54c-a5f98ee55a07";

    let api_key = Uuid::parse_str(api_key).unwrap();
    //
    // Following line generates a certificate within the enclave and sends a certificate signing request to Fortanix Node Agent.
    // This will result in a signed certificate if the Administrator has granted access to specified domain for the application and if environment is set up correctly.
    //
    let (signed_certificate, key) = generate_and_sign_key(domain);

    println!("Generated key and obtained signed certificate");
    // Uncomment if clients should present a certificate signed by provided 'zone_ca'.
    //pub const ZONE_CA: &'static str  = concat!(include_str!("../artifacts/zone_ca.crt"), '\0');
    //let zone_ca = Some(ZONE_CA);

    let (local_addr, server) = create_server("127.0.0.1:8080", zone_ca, signed_certificate.clone(), key.clone()).unwrap();
    let mut handler = server.handle_threads(ServerHandler { cert: signed_certificate, key, api_key }, 3).unwrap();

    println!("\nListening on address: {} for host {}", local_addr, domain);

    println!("To test with curl: \n");

    // --cacert uses provided root ca to verify remote certificate
    // --resolve allows us to do a DNS overrride for specified domain.
    println!("# curl --cacert ./artifacts/zone_ca.crt --resolve {}:{}:127.0.0.1 -X POST -d '{{ \"id\": \"key-id\", \"value\": \"secret\" }} ' https://{}:{}/sdkms\n", domain, local_addr.port(), domain, local_addr.port());

    while true {
        std::thread::sleep(core::time::Duration::from_millis(10));
    }

    handler.close().unwrap();
    Ok(())
}
