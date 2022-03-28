use std::sync::{mpsc, Arc, Mutex};
use std::thread;

pub struct Thread {
    worker: Worker,
    sender: mpsc::Sender<Message>,
}

pub struct Worker {
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
            worker: Worker::new(0, receiver),
            sender,
        }
    }

    /// Sends a function to the running thread for it to be executed.
    /// # Panics
    /// If the thread has been terminated.
    pub fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let job = Box::new(f);

        self.sender.send(Message::NewJob(job)).unwrap();
    }
}

impl Default for Thread {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Thread {
    fn drop(&mut self) {
        println!("Terminating thread {}", self.worker.id);
        self.sender.send(Message::Terminate).unwrap();

        if let Some(thread) = self.worker.thread.take() {
            thread.join().unwrap();
        }
    }
}

impl Worker {
    fn new(id: usize, receiver: Arc<Mutex<mpsc::Receiver<Message>>>) -> Worker {
        let thread = thread::spawn(move || loop {
            let message = receiver.lock().unwrap().recv().unwrap();

            match message {
                Message::NewJob(job) => {
                    println!("Worker {} received a job; executing.", id);
                    job();
                }
                Message::Terminate => {
                    println!("Worker {} is shutting down.", id);
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
