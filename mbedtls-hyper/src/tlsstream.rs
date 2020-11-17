use std::io;
use std::sync::{Arc, Mutex};
use mbedtls::ssl::{Context};
use hyper::net::NetworkStream;
use std::net::SocketAddr;
use std::time::Duration;
use std::marker::PhantomData;

// Native TLS compatibility - to move to native tls client in the future
#[derive(Clone)]
pub struct TlsStream<T> {
    context: Arc<Mutex<Context>>,
    phantom: PhantomData<T>,
}

impl<T> TlsStream<T> {
    pub fn new(context: Arc<Mutex<Context>>) -> Self {
        TlsStream {
            context: context,
            phantom: PhantomData,
        }
    }
}

unsafe impl<T> Send for TlsStream<T> {}
unsafe impl<T> Sync for TlsStream<T> {}

impl<T> io::Read for TlsStream<T>
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.context.lock().unwrap().read(buf)
    }
}

impl<T> io::Write for TlsStream<T>
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.context.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.context.lock().unwrap().flush()
    }
}

impl<T> NetworkStream for TlsStream<T>
    where T: NetworkStream
{
    fn peer_addr(&mut self) -> io::Result<SocketAddr> {
        self.context.lock().unwrap().get_mut_io::<T>()?.peer_addr()
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.context.lock().unwrap().get_mut_io::<T>()?.set_read_timeout(dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.context.lock().unwrap().get_mut_io::<T>()?.set_write_timeout(dur)
    }
}
