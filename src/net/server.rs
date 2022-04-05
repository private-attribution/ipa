use crate::net::Pool;
use log::warn;

pub struct Server {
    connection_handler_thread: Pool,
}

impl Server {
    #[must_use]
    pub fn new() -> Server {
        Server {
            connection_handler_thread: Pool::new(1),
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
        if let Err(e) = self.connection_handler_thread.execute(|| {
            // listen
            // read
            // write
        }) {
            panic!("Could not start the connection handler: {}", e);
        }
    }
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::Server;

    #[test]
    fn no_panic() {
        let mut server = Server::new();

        server.start();

        server.stop();
    }
}
