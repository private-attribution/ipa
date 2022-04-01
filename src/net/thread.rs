use log::{error, info};
use std::fmt::{Debug, Formatter};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use crate::error::Res;

pub struct Thread {
    worker: Worker,
    sender: mpsc::Sender<Message>,
}

struct Worker {
    thread: Option<thread::JoinHandle<()>>,
}

type Job = Box<dyn FnOnce() + Send + 'static>;

pub enum Message {
    NewJob(Job),
    Terminate,
}

impl Thread {
    #[must_use]
    pub fn new() -> Thread {
        let (sender, receiver) = mpsc::channel();
        let receiver = Arc::new(Mutex::new(receiver));

        Thread {
            worker: Worker::spawn(receiver),
            sender,
        }
    }

    /// Sends a function to the running thread for it to be executed.
    /// # Errors
    ///  If the thread has been terminated.
    pub fn execute<F>(&self, f: F) -> Res<()>
    where
        F: FnOnce() + Send + 'static,
    {
        let job = Box::new(f);

        self.sender.send(Message::NewJob(job))?;

        Ok(())
    }
}

impl Default for Thread {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Thread {
    fn drop(&mut self) {
        info!("Terminating thread {:?}", self.worker);
        if let Ok(()) = self.sender.send(Message::Terminate) {
            if let Some(thread) = self.worker.thread.take() {
                thread.join().unwrap();
            }
        }
    }
}

impl Worker {
    fn spawn(receiver: Arc<Mutex<mpsc::Receiver<Message>>>) -> Worker {
        let thread = thread::spawn(move || loop {
            let message: Message;

            // Receive a message and release the lock before executing anything else.
            if let Ok(receiver) = receiver.lock() {
                if let Ok(msg) = receiver.recv() {
                    message = msg;
                } else {
                    error!("Sender channel is closed.");
                    break;
                }
            } else {
                error!("Failed to lock the mutex.");
                break;
            }

            match message {
                Message::NewJob(job) => {
                    info!(
                        "Worker {:?} received a job; executing.",
                        thread::current().id()
                    );
                    job();
                }
                Message::Terminate => {
                    info!("Worker {:?} is shutting down.", thread::current().id());
                    break;
                }
            }
        });

        info!("Spawned worker {:?}.", thread.thread().id());

        Worker {
            thread: Some(thread),
        }
    }
}

impl Debug for Worker {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        if let Some(thread) = &self.thread {
            write!(f, "{:?}", thread.thread().id())
        } else {
            write!(f, "(dead thread)")
        }
    }
}
