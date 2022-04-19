use crate::net::data::Command;
#[cfg(feature = "enable-serde")]
use std::io::{Read, Result as IoResult, Write};
use std::net::{SocketAddr, TcpStream};

pub struct Client {
    stream: TcpStream,
}

impl Client {
    /// Creates a new client that connects to a specified server.
    /// # Panics
    /// If the server address is invalid.
    #[must_use]
    pub fn open(host: &str, port: u16) -> Client {
        let server_addr: SocketAddr = format!("{}:{}", host, port)
            .parse()
            .expect("Invalid socket address.");

        let stream = TcpStream::connect(server_addr).unwrap();

        Client { stream }
    }

    /// Attempts to send a command to the server.
    /// # Errors
    /// IO error if the operation fails.
    pub fn send(&mut self, cmd: &Command) -> IoResult<()> {
        let serialized = serde_json::to_string(cmd)?;

        self.stream.write_all(serialized.as_bytes())?;

        Ok(())
    }

    /// Attempts to receive a result from the server.
    /// # Errors
    /// IO error if the operation fails.
    pub fn receive(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        let n = self.stream.read(buf)?;

        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::Client;
    use crate::net::{Command, IPAService, Pool};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const SERVER_HOST: &str = "127.0.0.1";
    const SERVER_PORT: u16 = 7182;

    const ECHO_TEST: &str = "test";
    const LOOP_COUNT: usize = 100;
    const CLIENT_THREAD_COUNT: usize = 10;

    fn start_server() {
        IPAService::new(SERVER_HOST, SERVER_PORT, 3).start();
    }

    #[test]
    #[ignore]
    fn echo() {
        stderrlog::new().verbosity(5).init().unwrap();

        start_server();

        let mut pool = Pool::new(CLIENT_THREAD_COUNT);
        let counter = Arc::new(AtomicUsize::new(0));

        for _ in 0..LOOP_COUNT {
            let c_counter = Arc::clone(&counter);

            pool.execute(move || {
                let mut client = Client::open(SERVER_HOST, SERVER_PORT);

                client
                    .send(&Command::Echo(String::from(ECHO_TEST)))
                    .unwrap();

                let mut buf = [0; ECHO_TEST.len()];
                client.receive(&mut buf).unwrap();

                if buf == ECHO_TEST.as_bytes() {
                    c_counter.fetch_add(1, Ordering::Relaxed);
                }
            })
            .unwrap();
        }

        pool.shutdown().unwrap();

        assert_eq!(counter.load(Ordering::Relaxed), LOOP_COUNT);
    }
}
