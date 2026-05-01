// Tier 1 — use-after-free (Go / unsafe.Pointer variant).
//
// Pure Go GC prevents UAF. The unsafe.Pointer escape valve lets
// developers obtain raw pointers; if the underlying slice is
// resized (which may relocate the backing array), the raw pointer
// becomes dangling.
//
// Knowledge: [[Memory/Knowledge/bhg_unsafe_pointer_patterns]]
// CWE-416 (analog).
package main

import (
	"fmt"
	"unsafe"
)

func main() {
	s := []byte("hello, world")
	// take raw pointer to backing array
	p := unsafe.Pointer(&s[0])

	// grow slice — may reallocate the backing array
	for i := 0; i < 1024; i++ {
		s = append(s, byte(i))
	}

	// sink: read through stale pointer if backing array moved
	stale := *(*byte)(p)
	fmt.Printf("read=%c\n", stale)
}
