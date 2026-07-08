pub struct Widget;

impl Widget {
    pub fn new() -> Self {
        Widget
    }

    pub fn init(&mut self) {}
}

pub fn build() -> Widget {
    let mut widget = Widget::new();
    widget.init();
    widget
}
