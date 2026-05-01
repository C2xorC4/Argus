// Tier 1 — insecure deserialisation (Rust / serde+bincode).
//
// bincode::deserialize() with attacker-controlled bytes can crash
// the program (panic) and, depending on the target type, can
// trigger logic flaws — e.g., negative size in a length-prefixed
// type. Pure-Rust deserialisation cannot RCE in the way Java/.NET
// gadget chains do (no reflection-based constructor invocation),
// but it can produce DoS / logic compromise.

use serde::Deserialize;
use std::env;
use std::fs;

#[derive(Deserialize, Debug)]
struct Message {
    id: u32,
    payload: Vec<u8>,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 { return; }
    let bytes = fs::read(&args[1]).expect("read");
    // sink: deserialize attacker-controlled bytes with no max-length cap
    let msg: Message = bincode::deserialize(&bytes).expect("deserialize");
    println!("id={} payload_len={}", msg.id, msg.payload.len());
}
