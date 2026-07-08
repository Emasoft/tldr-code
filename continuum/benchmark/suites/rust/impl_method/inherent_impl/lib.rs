pub struct Service;

impl Service {
    pub fn helper(&self) -> i32 {
        1
    }

    pub fn run(&self) -> i32 {
        self.helper()
    }
}
