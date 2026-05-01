// Tier 1 — insecure deserialisation (Go / encoding/gob).
//
// encoding/gob.Decoder on attacker-controlled stream. gob is Go's
// native binary serialisation; like other binary formats, no
// length cap by default — large allocations driven by attacker
// content.

package main

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io/ioutil"
	"os"
)

type Message struct {
	ID      uint32
	Payload []byte
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage")
		os.Exit(1)
	}
	data, err := ioutil.ReadFile(os.Args[1])
	if err != nil { panic(err) }

	dec := gob.NewDecoder(bytes.NewReader(data))
	var m Message
	// sink: decode attacker-controlled bytes
	if err := dec.Decode(&m); err != nil { panic(err) }
	fmt.Printf("id=%d payload_len=%d\n", m.ID, len(m.Payload))
}
