mod model;
use model::Widget;

impl Widget {
    pub fn run(&self) -> i32 {
        self.helper()
    }
}
