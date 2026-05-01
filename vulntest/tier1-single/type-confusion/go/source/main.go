// Tier 1 — type confusion (Go / unsafe.Pointer variant).
//
// unsafe.Pointer between unrelated struct types reinterprets memory.
// Go provides no validation — the cast is a no-op at the machine
// level.

package main

import (
	"fmt"
	"unsafe"
)

type A struct {
	x uint64
	y uint64
}

type B struct {
	ptr unsafe.Pointer
	len int
}

func main() {
	a := A{x: 0xdeadbeef, y: 0x41414141}
	// sink: reinterpret *A as *B
	b := *(*B)(unsafe.Pointer(&a))
	fmt.Printf("ptr=%p len=%d\n", b.ptr, b.len)
}
