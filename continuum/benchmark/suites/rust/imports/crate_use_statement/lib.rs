mod counter;
use crate::counter::increment;

pub fn run() -> i32 {
    increment()
}
