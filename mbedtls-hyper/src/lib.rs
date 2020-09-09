use mbedtls::ssl::mbed::MbedSSLConfig;
use mbedtls::ssl::mbed::MbedSSLContext;

use hyper::net::NetworkStream;
use std::net::SocketAddr;
use std::time::Duration;
use std::net::Shutdown;

use hyper::net::NetworkConnector;
use std::sync::Arc;

use std::io::{Read, Write};
use std::net::TcpStream;


#[derive(Clone)]
pub struct MbedSSLNetworkConnector {
    rc_config: Arc<MbedSSLConfig>,
}

unsafe impl Send for MbedSSLNetworkConnector {}
unsafe impl Sync for MbedSSLNetworkConnector {}

impl MbedSSLNetworkConnector {
    pub fn new(config: Arc<MbedSSLConfig>) -> Self {
        MbedSSLNetworkConnector { rc_config : config }
    }
}

impl NetworkConnector for MbedSSLNetworkConnector {
    type Stream = MbedSSLNetworkStream;
        
    fn connect(&self, host: &str, port: u16, _scheme: &str) -> Result<Self::Stream, hyper::Error> {
        let conn = TcpStream::connect((host, port)).unwrap(); //.map_err(|e| format!("TCP connect error: {:?}", e))?;

        let mut ctx = MbedSSLContext::new(self.rc_config.clone()); //.map_err(|e| format!("TLS context creation failed: {:?}", e))?;
        ctx.establish(conn, Some("nodes.localhost")).unwrap(); //.map_err(|e| format!("TLS Session error: {:?}", e))?;

        Ok(MbedSSLNetworkStream {
            context: ctx,
        })
    }
}

pub struct MbedSSLNetworkStream {
    context: MbedSSLContext,
}

// Arc is 'Send' safe - we can pass the structure to from one thread to another.
// Access to contents is done via mutex, so it is sync safe too.
unsafe impl Send for MbedSSLNetworkStream {}
unsafe impl Sync for MbedSSLNetworkStream {}

impl NetworkStream for MbedSSLNetworkStream {
    fn peer_addr(&mut self) -> std::io::Result<SocketAddr> {
        self.context.peer_addr()
    }

    /// Set the maximum time to wait for a read to complete.
    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        self.context.set_read_timeout(dur)
    }
    
    /// Set the maximum time to wait for a write to complete.
    fn set_write_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        self.context.set_write_timeout(dur)
    }

    /// This will be called when Stream should no longer be kept alive.
    #[inline]
    fn close(&mut self, _how: Shutdown) -> std::io::Result<()> {
        Ok(self.context.close())
    }
}

impl Read for MbedSSLNetworkStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.context.read(buf)
    }
}

impl Write for MbedSSLNetworkStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.context.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.context.flush()
    }
}


#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    use hyper::client::Pool;
    use mbedtls::ssl::mbed::MbedSSLConfig;
    use mbedtls::ssl::mbed::{Endpoint, Preset, Transport, AuthMode, Version};
    use std::sync::Arc;
    use mbedtls::rng::OsEntropy;
    
    
    #[test]
    fn test_simple_request() {
        use hyper::client::Pool;
        use mbedtls::ssl::mbed::MbedSSLConfig;
        use mbedtls::ssl::mbed::{Endpoint, Preset, Transport, AuthMode, Version};
        use std::sync::Arc;
        use mbedtls::rng::OsEntropy;
        
        let mut entropy = OsEntropy::new();
        let mut rng = mbedtls::rng::CtrDrbg::new(&mut entropy, None).unwrap();

        let mut config = MbedSSLConfig::new(Endpoint::Client, Transport::Stream, Preset::Default);

        config.set_authmode(AuthMode::None);
        config.set_rng(Some(&mut rng));
        config.set_min_version(Version::Tls1_2).unwrap();
        
        // Immutable from this point on
        let rc_config = Arc::new(config);
        let connector = MbedSSLNetworkConnector::new(rc_config);
        let client = hyper::Client::with_connector(Pool::with_connector(Default::default(), connector));

        let response = client.get("https://www.google.com/").send().unwrap();

        assert_eq!(response.status, hyper::status::StatusCode::Ok);
    }


    #[test]
    fn test_multiple_request() {
        
        let mut entropy = OsEntropy::new();
        let mut rng = mbedtls::rng::CtrDrbg::new(&mut entropy, None).unwrap();

        let mut config = MbedSSLConfig::new(Endpoint::Client, Transport::Stream, Preset::Default);

        config.set_authmode(AuthMode::None);
        config.set_rng(Some(&mut rng));
        config.set_min_version(Version::Tls1_2).unwrap();
        
        // Immutable from this point on
        let rc_config = Arc::new(config);
        let connector = MbedSSLNetworkConnector::new(rc_config);
        
        let client1 = hyper::Client::with_connector(Pool::with_connector(Default::default(), connector.clone()));
        let response = client1.get("https://www.google.com/").send().unwrap();
        assert_eq!(response.status, hyper::status::StatusCode::Ok);

        let client2 = hyper::Client::with_connector(Pool::with_connector(Default::default(), connector.clone()));
        let response = client2.get("https://www.google.com/").send().unwrap();
        assert_eq!(response.status, hyper::status::StatusCode::Ok);

        let client3 = hyper::Client::with_connector(Pool::with_connector(Default::default(), connector));
        let response = client3.get("https://www.google.com/").send().unwrap();
        assert_eq!(response.status, hyper::status::StatusCode::Ok);
    }

}        
