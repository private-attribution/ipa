use crate::net::{Job, Pool};
use log::{error, info, trace, warn};
#[cfg(feature = "enable-serde")]
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use std::io::prelude::*;
use std::net::{SocketAddr, TcpListener, TcpStream};

#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
enum Command {
    Echo(String),
}

#[cfg(feature = "debug")]
impl Debug for Command {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        f.write_str("Command::")?;
        match self {
            Self::Echo(_) => f.write_str("Echo"),
        }
    }
}

pub struct Server {
    connection_handler_thread: Pool,
    connection_handler_addr: SocketAddr,
    max_connection_count: usize,
}

impl Server {
    #[must_use]
    pub fn new(host: &str, port: u16, max_connection_count: usize) -> Server {
        let addr = format!("{}:{}", host, port)
            .parse()
            .expect("Invalid socket address.");

        Server {
            connection_handler_thread: Pool::new(1),
            connection_handler_addr: addr,
            max_connection_count,
        }
    }

    pub fn start(&self) {
        self.start_connection_handler();
    }

    pub fn stop(&mut self) {
        if let Err(e) = self.connection_handler_thread.shutdown() {
            warn!("Graceful shutdown failed: {}", e);
        }
    }

    /// Spawns a new thread to handle incoming connections.
    /// # Panics
    /// If the thread could not be spawned.
    fn start_connection_handler(&self) {
        let handler =
            ConnectionHandler::new(self.connection_handler_addr, self.max_connection_count);

        if self
            .connection_handler_thread
            .execute(handler.start())
            .is_err()
        {
            panic!("Could not start the connection handler thread.");
        };
    }
}

struct ConnectionHandler {
    addr: SocketAddr,
    pool_size: usize,
}

impl ConnectionHandler {
    pub fn new(addr: SocketAddr, pool_size: usize) -> ConnectionHandler {
        ConnectionHandler { addr, pool_size }
    }

    fn start(&self) -> Job {
        let addr = self.addr;
        let pool_size = self.pool_size;

        Box::new(move || {
            let listener = TcpListener::bind(addr).expect("Could not bind to the given address.");
            let pool = Pool::new(pool_size);

            info!("Listening for incoming connections...");

            // Since incoming() is blocking, this thread will keep running even after drop() on the thread is called.
            // There are platform-specific signals I can use to shutdown reads on the socket which will cause the
            // incoming() iterator to return an error. For now, use Ctrl-C to terminate.
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        info!("Accepted a new connection.");

                        if pool
                            .execute(|| ConnectionHandler::handle_connection(stream))
                            .is_err()
                        {
                            error!("Failed to create a worker thread to handle the connection.");
                            // Continue processing incoming connections with other workers.
                        }
                    }
                    Err(e) => {
                        error!("Failed to accept: {}", e);
                        // The error could be recoverable, but we'll just shutdown the connection handler for now.
                        return;
                    }
                }
            }
        })
    }

    fn handle_connection(mut stream: TcpStream) {
        let mut buffer = [0; 1024];
        let mut read_bytes = 0;

        // TODO: Accept >1024 bytes
        match stream.read(&mut buffer) {
            Ok(0) => return,
            Ok(n) => {
                read_bytes = n;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                error!("Stream read failed: {}", e);
                return;
            }
        }

        let serialized = String::from_utf8_lossy(&buffer[..read_bytes]);

        trace!("Request: {:?}", serialized);

        let deserialized: Result<Command, _> = serde_json::from_str(&serialized);
        match deserialized {
            Ok(command) => {
                ConnectionHandler::handle_command(command, stream);
            }
            Err(_) => {
                error!("Invalid command received: {}", serialized);
            }
        }
    }

    fn handle_command(command: Command, mut stream: TcpStream) {
        let mut buffer = [0; 1024];

        match command {
            Command::Echo(s) => {
                let bytes = s.as_bytes();
                buffer[..bytes.len()].copy_from_slice(bytes);
            }
        }

        match stream.write_all(&buffer) {
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                error!("Stream write failed: {}", e);
            }
        }
    }
}

// These tests shouldn't be included as a part of check-in tests yet. A spawned
// thread will keep running because we haven't implemented a function to
// terminate the listening socket. Instead, use Ctrl-C to terminate the test.
#[cfg(test)]
mod tests {
    use super::{Command, Server};
    use std::io::prelude::*;
    use std::net::{SocketAddr, TcpStream};

    const CONNECTION_HANDLER_HOST: &str = "127.0.0.1";
    const CONNECTION_HANDLER_PORT: u16 = 7182;
    const MAX_CONNECTION_COUNT: usize = 3;

    const ECHO_TEST: &str = "test";

    fn start_server() -> Server {
        Server::new(
            CONNECTION_HANDLER_HOST,
            CONNECTION_HANDLER_PORT,
            MAX_CONNECTION_COUNT,
        )
    }

    #[test]
    #[ignore]
    fn echo() {
        stderrlog::new().verbosity(5).init().unwrap();

        let _server = start_server();

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

        let _server = start_server();

        let addr: SocketAddr = format!("{}:{}", CONNECTION_HANDLER_HOST, CONNECTION_HANDLER_PORT)
            .parse()
            .unwrap();

        let mut stream = TcpStream::connect(addr).unwrap();

        let command = String::from("invalid_command");
        stream.write_all(command.as_bytes()).unwrap();
    }
}
