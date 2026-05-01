// Tier 1 — stack-overflow (Rust / unsafe variant).
//
// Rust safe code cannot stack-OF — bounds-checked. The vulnerability
// surface is `unsafe` blocks where the developer asserts safety the
// borrow checker can't verify.
//
// This cell uses `unsafe { ptr::write_bytes }` past the end of a
// stack-allocated array.
//
// Knowledge: [[Memory/Knowledge/hw_stack_overflow_mechanics]]
// CWE-121.

use std::env;
use std::ptr;

fn greet(name: &[u8]) {
    let mut buf = [0u8; 64];
    unsafe {
        // sink: write past end of buf, no bound check
        ptr::copy_nonoverlapping(name.as_ptr(), buf.as_mut_ptr(), name.len());
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 { return; }
    greet(args[1].as_bytes());
}
