// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

const MAX_CELL_SIZE = 514

// Optimizations to avoid constantly allocating and deallocating...
var cellBufChan = make(chan []byte, 100000)

func SeedCellBuf() {
	// Doing this at the start makes our memory usage far more predictable
	for i := 0; i < 1000; i++ {
		ReturnCellBuf(make([]byte, MAX_CELL_SIZE))
	}
}

func GetCellBuf(wiped bool) []byte {
	var buf []byte
	select {
	case buf = <-cellBufChan:
		// Done
	default:
		buf = make([]byte, MAX_CELL_SIZE)
	}

	buf = buf[:MAX_CELL_SIZE]

	if wiped {
		for i := 0; i < cap(buf); i++ {
			buf[i] = 0
		}
	}

	return buf
}

func ReturnCellBuf(buf []byte) {
	if cap(buf) == MAX_CELL_SIZE {
		select {
		case cellBufChan <- buf:
			// Done
		default:
			// Pool full... Release it
		}
	}
}
