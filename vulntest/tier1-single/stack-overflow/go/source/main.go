// Tier 1 — stack-overflow (Go / cgo variant).
//
// Pure Go cannot stack-overflow — runtime checks every slice access.
// Stack-OF surfaces at the cgo boundary: Go calls into C code that
// performs unbounded copy.
//
// Knowledge: [[Memory/Knowledge/bhg_unsafe_pointer_patterns]]
// CWE-121 (cgo-bounded).
package main

/*
#include <string.h>
void greet(char *out, const char *name) {
    char buf[64];
    strcpy(buf, name);              // sink: same C bug, just reached via cgo
    strcpy(out, buf);
}
*/
import "C"

import (
	"fmt"
	"os"
	"unsafe"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage")
		os.Exit(1)
	}
	cname := C.CString(os.Args[1])
	defer C.free(unsafe.Pointer(cname))

	out := make([]byte, 256)
	C.greet((*C.char)(unsafe.Pointer(&out[0])), cname)
}
