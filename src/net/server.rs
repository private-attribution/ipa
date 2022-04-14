#[cfg(feature = "enable-serde")]
use super::handler::TcpConnection;
use crate::net::Pool;
use log::warn;

/// IPA Server prototype.
/// Currently, we have one connection handler defined here which mocks RC communication.
/// We can add more connection handlers
pub struct IPAService {
    rc_connection_handler_thread: Pool,
    rc_connection_handler: TcpConnection,
}

impl IPAService {
    #[must_use]
    pub fn new(host: &str, port: u16, max_connection_count: usize) -> Self {
        let addr = format!("{}:{}", host, port)
            .parse()
            .expect("Invalid socket address.");

        Self {
            rc_connection_handler_thread: Pool::new(1),
            rc_connection_handler: TcpConnection::new(addr, max_connection_count),
        }
    }

    pub fn start(&self) {
        self.start_connection_handler();
    }

    pub fn stop(&mut self) {
        if let Err(e) = self.rc_connection_handler_thread.shutdown() {
            warn!("Graceful shutdown failed: {}", e);
        }
    }

    /// Spawns a new thread to handle incoming connections.
    /// # Panics
    /// If the thread could not be spawned.
    fn start_connection_handler(&self) {
        if self
            .rc_connection_handler_thread
            .execute(self.rc_connection_handler.handle())
            .is_err()
        {
            panic!("Could not start the connection handler thread.");
        };
    }
}

#[cfg(test)]
mod tests {
    use super::IPAService;
    use crate::net::handler::Command;
    use std::io::prelude::*;
    use std::net::{SocketAddr, TcpStream};

    const CONNECTION_HANDLER_HOST: &str = "127.0.0.1";
    const CONNECTION_HANDLER_PORT: u16 = 7182;
    const MAX_CONNECTION_COUNT: usize = 3;

    const ECHO_TEST: &str = "test";

    fn start_server() {
        IPAService::new(
            CONNECTION_HANDLER_HOST,
            CONNECTION_HANDLER_PORT,
            MAX_CONNECTION_COUNT,
        )
        .start();
    }

    #[test]
    #[ignore]
    fn echo() {
        stderrlog::new().verbosity(5).init().unwrap();

        start_server();

        let addr: SocketAddr = format!("{}:{}", CONNECTION_HANDLER_HOST, CONNECTION_HANDLER_PORT)
            .parse()
            .unwrap();

        for _ in 0..3 {
            let mut stream = TcpStream::connect(addr).unwrap();

            let command = serde_json::to_string(&Command::Echo(String::from("test"))).unwrap();
            stream.write_all(command.as_bytes()).unwrap();

            let mut buffer = [0; ECHO_TEST.len()];
            stream.read_exact(&mut buffer).unwrap();

            assert_eq!(buffer, ECHO_TEST.as_bytes());
        }
    }

    #[test]
    #[ignore]
    fn ignore_invalid_command() {
        stderrlog::new().verbosity(5).init().unwrap();

        start_server();

        let addr: SocketAddr = format!("{}:{}", CONNECTION_HANDLER_HOST, CONNECTION_HANDLER_PORT)
            .parse()
            .unwrap();

        let mut stream = TcpStream::connect(addr).unwrap();

        let command = String::from("invalid_command");
        stream.write_all(command.as_bytes()).unwrap();
    }
}
