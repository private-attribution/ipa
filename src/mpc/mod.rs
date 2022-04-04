use rug::Integer;
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, SendError, Sender};
use std::thread;
use std::time::Duration;

trait H {
    fn send_to_prev(&self, data: serde_json::Value) -> Result<(), SendError<serde_json::Value>>;
    fn receive(&self, data: serde_json::Value) -> Result<(), SendError<serde_json::Value>>;
    fn retrieve(&self) -> Result<serde_json::Value, RecvTimeoutError>;
}
struct H1 {
    h2: &'static H2,
    sender: Sender<serde_json::Value>,
    receiver: Receiver<serde_json::Value>,
}

impl H for H1 {
    fn send_to_prev(&self, data: serde_json::Value) -> Result<(), SendError<serde_json::Value>> {
        self.h2.receive(data)
    }

    fn receive(&self, data: serde_json::Value) -> Result<(), SendError<serde_json::Value>> {
        self.sender.send(data)
    }
    fn retrieve(&self) -> Result<serde_json::Value, RecvTimeoutError> {
        self.receiver.recv_timeout(Duration::from_secs(5))
    }
}

struct H2 {
    h1: &'static H1,
    sender: Sender<serde_json::Value>,
    receiver: Receiver<serde_json::Value>,
}

impl H for H2 {
    fn send_to_prev(&self, data: serde_json::Value) -> Result<(), SendError<serde_json::Value>> {
        self.h1.receive(data)
    }

    fn receive(&self, data: serde_json::Value) -> Result<(), SendError<serde_json::Value>> {
        self.sender.send(data)
    }
    fn retrieve(&self) -> Result<serde_json::Value, RecvTimeoutError> {
        self.receiver.recv_timeout(Duration::from_secs(5))
    }
}

struct H3 {
    h2: &'static H2,
    sender: Sender<serde_json::Value>,
    receiver: Receiver<serde_json::Value>,
}

impl H for H3 {
    fn send_to_prev(&self, data: serde_json::Value) -> Result<(), SendError<serde_json::Value>> {
        self.h2.receive(data)
    }

    fn receive(&self, data: serde_json::Value) -> Result<(), SendError<serde_json::Value>> {
        self.sender.send(data)
    }
    fn retrieve(&self) -> Result<serde_json::Value, RecvTimeoutError> {
        self.receiver.recv_timeout(Duration::from_secs(5))
    }
}

trait PipelineStep<Hi: H, In, Out> {
    fn run(&self, inp: In, hi: &Hi) -> Out;
}

struct Start {
    input: Integer,
}

impl<Hi: H> PipelineStep<Hi, (), Integer> for Start {
    fn run(&self, _: (), _: &Hi) -> Integer {
        self.input.clone()
    }
}

struct End {
    sender: Sender<Integer>,
}
impl<Hi: H> PipelineStep<Hi, Integer, ()> for End {
    fn run(&self, inp: Integer, hi: &Hi) -> () {
        self.sender.send(inp.clone()).expect("send should complete")
    }
}

struct Pipeline<Hi: H> {
    h1: Hi,
    h2: Hi,
    h3: Hi,
}
impl<Hi: H> Pipeline<Hi> {
    fn new(h1: Hi, h2: Hi, h3: Hi) -> Pipeline<Hi> {
        Pipeline { h1, h2, h3 }
    }
    fn run_h1(&self, output_sender: Sender<Integer>) {
        let h1_start = Start {
            input: Integer::from(1_u32),
        };
        let h1_end = End {
            sender: output_sender,
        };

        let start_out = h1_start.run((), &self.h1);
        h1_end.run(start_out, &self.h1);
    }

    fn run_h2(&self, output_sender: Sender<Integer>) {
        let h2_start = Start {
            input: Integer::from(2_u32),
        };
        let h2_end = End {
            sender: output_sender,
        };

        let start_out = h2_start.run((), &self.h2);
        h2_end.run(start_out, &self.h2);
    }

    fn run_h3(&self, output_sender: Sender<Integer>) {
        let h3_start = Start {
            input: Integer::from(3_u32),
        };
        let h3_end = End {
            sender: output_sender,
        };

        let start_out = h3_start.run((), &self.h3);
        h3_end.run(start_out, &self.h3)
    }
    fn run_pipeline(&self) -> Integer {
        let (output_sender, output_receiver) = channel::<Integer>();
        let h1_thread = thread::spawn(move || self.run_h1(output_sender.clone()));

        let h2_thread = thread::spawn(move || self.run_h2(output_sender.clone()));

        let h3_thread = thread::spawn(move || self.run_h3(output_sender.clone()));

        h1_thread.join().expect("h1 should complete");
        h2_thread.join().expect("h2 should complete");
        h3_thread.join().expect("h3 should complete");

        output_receiver
            .into_iter()
            .take(3)
            .fold(Integer::new(), |mut acc, n| -> Integer {
                acc += n;
                acc
            })
    }
}
