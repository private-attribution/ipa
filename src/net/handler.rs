use crate::net::Pool;
use log::{error, info, trace};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
#[cfg(feature = "enable-serde")]
use std::io::prelude::*;
use std::net::{SocketAddr, TcpListener, TcpStream};

/// List of commands which can be handled by structs that implement ``CommandHandler`` trait.
/// We'll probably need to create separate sets of commands for different protocols (server roles)
/// such as MPC operations, health check, internal IPC, etc. For now, just name this enum "Command".
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub(crate) enum Command {
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

trait CommandHandler {
    fn handle_command(command: Command, buf: &mut [u8]);
}

/// A TCP connection handler.
///
/// Waits for incoming connections on a given internet address. Once a connection is accepted, its
/// stream will be sent to one of child threads, and immediately starts listening for new connections.
pub(crate) struct TcpConnection {
    addr: SocketAddr,
    pool_size: usize,
}

impl TcpConnection {
    pub fn new(addr: SocketAddr, connection_count: usize) -> Self {
        Self {
            addr,
            pool_size: connection_count,
        }
    }

    /// Waits and handles incoming connections concurrently using a thread pool.
    pub fn handle(&self) -> impl FnOnce() {
        let addr = self.addr;
        let pool_size = self.pool_size;

        // TODO: This function returns a closure to be passed to ``Pool::execute`` rather than called from a closure.
        // This is because this function owns a ``Pool`` which doesn't implement ``Send`` trait, thus not thread safe
        // from rust compiler's POV. This needs to be rewritten but I'll leave it for now.
        move || {
            let listener = TcpListener::bind(addr).expect("Could not bind to the given address.");
            let pool = Pool::new(pool_size);

            info!("Listening for incoming connections...");

            // TODO: Since incoming() is blocking, this thread will keep running unless a caller is dropped.
            // We can implement a platform-specific signal to shutdown reads on the socket which will cause the
            // incoming() iterator to return an error.
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        info!("Accepted a new connection.");

                        if pool.execute(|| Self::handle_connection(stream)).is_err() {
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
        }
    }

    /// Handles stream IO on an accepted connection. Data being sent are serialized ``Command`` enum.
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
        let mut buffer = [0; 1024];

        match deserialized {
            Ok(command) => {
                Self::handle_command(command, &mut buffer);
            }
            Err(_) => {
                error!("Invalid command received: {}", serialized);
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

impl CommandHandler for TcpConnection {
    fn handle_command(command: Command, buf: &mut [u8]) {
        match command {
            Command::Echo(s) => {
                let bytes = s.as_bytes();
                buf[..bytes.len()].copy_from_slice(bytes);
            }
        }
    }
}
