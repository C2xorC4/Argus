// Tier 1 — type confusion (Rust / unsafe variant).
//
// std::mem::transmute reinterprets bytes between types of equal
// size. When the target type has different validity invariants
// than the source, transmute is UB.

use std::mem;

#[repr(C)]
struct A { x: u64, y: u64 }

#[repr(C)]
struct B { ptr: *const u8, len: usize }

fn main() {
    let a = A { x: 0xdead_beef_dead_beef, y: 0x4141_4141_4141_4141 };
    unsafe {
        // sink: transmute reinterprets A as B; A.x ends up as B.ptr
        let b: B = mem::transmute(a);
        println!("ptr={:p} len={}", b.ptr, b.len);
        // dereference would be wild-ptr UB — disabled here
    }
}
