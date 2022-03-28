#[cfg(feature = "debug")]
use crate::net::thread::Thread;

pub struct Server {
    connection_handler_thread: Thread,
}

impl Server {
    pub fn new() -> Server {
        Server {
            connection_handler_thread: Thread::new(),
        }
    }

    pub fn start(&self) {
        self.start_connection_handler();
    }

    fn start_connection_handler(&self) {
        self.connection_handler_thread.execute(|| {
            // listen
            // read
            // write
        });
    }
}

#[cfg(test)]
mod tests {
    use super::Server;
    use std::thread;
    use std::time;

    #[test]
    fn test_no_panic() {
        let server = Server::new();
        server.start();
        thread::sleep(time::Duration::from_millis(500));
    }
}
