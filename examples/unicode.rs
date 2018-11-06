use std::char;

fn main() {
    for i in 0..65536u32 {
        if let Some(c) = char::from_u32(i) {
            if c.is_alphanumeric() {
                print!("{} ", c);
            }
        }
    }
}
