use log::{error, info};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

use crate::error::Res;

pub struct Thread {
    worker: Worker,
    sender: mpsc::Sender<Message>,
}

struct Worker {
    id: usize,
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
            worker: Worker::spawn(0, receiver),
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
        info!("Terminating thread {}", self.worker.id);
        if let Ok(()) = self.sender.send(Message::Terminate) {
            if let Some(thread) = self.worker.thread.take() {
                thread.join().unwrap();
            }
        }
    }
}

impl Worker {
    fn spawn(id: usize, receiver: Arc<Mutex<mpsc::Receiver<Message>>>) -> Worker {
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
                    info!("Worker {} received a job; executing.", id);
                    job();
                }
                Message::Terminate => {
                    info!("Worker {} is shutting down.", id);
                    break;
                }
            }
        });

        Worker {
            id,
            thread: Some(thread),
        }
    }
}
