// Tier 1 — use-after-free (Rust / unsafe variant).
//
// Rust safe code cannot UAF — borrow checker enforces lifetime.
// Unsafe Box::from_raw + early Box::drop creates a dangling raw
// pointer; subsequent dereference is UAF.

use std::ptr;

struct Resource { value: i32 }

fn main() {
    let b = Box::new(Resource { value: 0xdead_beefu32 as i32 });
    let raw: *mut Resource = Box::into_raw(b);

    unsafe {
        // free
        let _ = Box::from_raw(raw);
        // sink: read after free
        println!("{}", (*raw).value);
    }
}
