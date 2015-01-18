// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"
	"testing"
)

func TestKDFHKDF(t *testing.T) {
	key := []byte("ntor-curve25519-sha256-1:key_extract")
	expand := []byte("ntor-curve25519-sha256-1:key_expand")

	// Test cases shamelessly stolen from the Tor source

	result := fmt.Sprintf("%x", KDFHKDF(100, []byte(""), key, expand))
	expect := "d3490ed48b12a48f9547861583573fe3f19aafe3f81dc7fc75eeed96d741b3290f941576c1f9f0b2d463d1ec7ab2c6bf71cdd7f826c6298c00dbfe6711635d7005f0269493edf6046cc7e7dcf6abe0d20c77cf363e8ffe358927817a3d3e73712cee28d8"
	if result != expect {
		log.Println(result)
		log.Println(expect)
		t.FailNow()
	}

	result = fmt.Sprintf("%x", KDFHKDF(100, []byte("Tor"), key, expand))
	expect = "5521492a85139a8d9107a2d5c0d9c91610d0f95989975ebee6c02a4f8d622a6cfdf9b7c7edd3832e2760ded1eac309b76f8d66c4a3c4d6225429b3a016e3c3d45911152fc87bc2de9630c3961be9fdb9f93197ea8e5977180801926d3321fa21513e59ac"

	if result != expect {
		log.Println(result)
		log.Println(expect)
		t.FailNow()
	}

}
