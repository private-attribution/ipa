use crate::error::Result;
use log::{error, info, warn};
use std::fmt::{Debug, Formatter};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;

pub struct Pool {
    workers: Vec<Worker>,
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

impl Pool {
    #[must_use]
    pub fn new(size: usize) -> Pool {
        let (sender, receiver) = mpsc::channel();
        let receiver = Arc::new(Mutex::new(receiver));
        let mut workers = Vec::with_capacity(size);

        for _ in 0..size {
            workers.push(Worker::spawn(Arc::clone(&receiver)));
        }

        Pool { workers, sender }
    }

    /// Sends a function to a running thread for it to be executed.
    /// # Errors
    ///  If the thread has been terminated.
    pub fn execute<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce() + Send + 'static,
    {
        let job = Box::new(f);

        self.sender.send(Message::NewJob(job))?;

        Ok(())
    }

    /// Sends Terminate instructions to all active threads. This function will
    /// not wait for threads to finish.
    fn terminate(&self) {
        info!("Terminating threads.");

        for _ in &self.workers {
            if self.sender.send(Message::Terminate).is_err() {
                warn!("Receiver channel is closed.");
                // If SendError occurs, that means the receiver is deallocated and all following send() calls will fail.
                break;
            }
        }
    }

    /// Waits for all threads to finish.
    /// # Errors
    /// If any of threads has panicked.
    pub fn shutdown(&mut self) -> Result<()> {
        self.terminate();

        for worker in &mut self.workers {
            if let Some(thread) = worker.thread.take() {
                if let Err(err) = thread.join() {
                    let message = match err.downcast_ref::<&'static str>() {
                        Some(s) => *s,
                        None => match err.downcast_ref::<String>() {
                            Some(s) => &s[..],
                            None => "Unknown error.",
                        },
                    };
                    warn!("Dead thread detected: {}", message);
                };
            }
        }

        Ok(())
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        self.terminate();
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
