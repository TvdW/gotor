// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package aes

import (
	"github.com/tvdw/cgolock"
	"runtime"
	"testing"
)

func init() {
	cgolock.Init(runtime.GOMAXPROCS(0))
}

func benchmarkWithSize(size int, b *testing.B) {
	buffer := make(chan []byte, 50000)
	for i := 0; i < cap(buffer); i++ {
		buffer <- make([]byte, size)
	}

	b.SetBytes(int64(size))
	b.RunParallel(func(pb *testing.PB) {
		var key, iv [16]byte

		aes := New(key[:], iv[:])
		for pb.Next() {
			data := <-buffer
			target := <-buffer
			aes.Crypt(target, data)
			buffer <- data
			buffer <- target
		}
	})
}

func Benchmark1(b *testing.B) {
	benchmarkWithSize(1, b)
}

func Benchmark64(b *testing.B) {
	benchmarkWithSize(64, b)
}

func Benchmark128(b *testing.B) {
	benchmarkWithSize(128, b)
}

func Benchmark256(b *testing.B) {
	benchmarkWithSize(256, b)
}

func Benchmark512(b *testing.B) {
	benchmarkWithSize(512, b)
}

func Benchmark1024(b *testing.B) {
	benchmarkWithSize(1024, b)
}

func Benchmark2048(b *testing.B) {
	benchmarkWithSize(2048, b)
}
