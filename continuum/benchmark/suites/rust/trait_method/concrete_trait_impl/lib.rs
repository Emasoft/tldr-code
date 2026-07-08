pub trait Worker {
    fn work(&self) -> i32;
}

pub struct Job;

impl Worker for Job {
    fn work(&self) -> i32 {
        1
    }
}

pub fn run() -> i32 {
    let job = Job;
    job.work()
}
