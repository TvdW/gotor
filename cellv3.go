// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

type Cell3 []byte

func (c Cell3) Command() Command {
	return Command(c[2])
}

func (c Cell3) Data() []byte {
	return c[3:len(c)]
}

func (c Cell3) CircID() CircuitID {
	return CircuitID(BigEndian.Uint16(c[0:2]))
}

func (c Cell3) ReleaseBuffers() {
	ReturnCellBuf([]byte(c))
}

func (c Cell3) Bytes() []byte {
	return []byte(c)
}

func NewCell3(id CircuitID, cmd Command, d []byte) Cell {
	c := Cell3(GetCellBuf(false))

	BigEndian.PutUint16(c[0:2], uint16(id))
	c[2] = byte(cmd)
	if len(d) > 509 {
		panic("Code error: creating massive cell")
	}
	if d != nil {
		copy(c[3:], d)
	}
	// Now wipe all other data
	for i := 3 + len(d); i < 512; i++ {
		c[i] = 0
	}
	c = c[0:512]
	return &c
}

func NewVarCell3(id CircuitID, cmd Command, d []byte, l int) Cell {
	if d != nil && l > 0 {
		panic("Don't specify both data and length")
	}

	if l == 0 {
		l = len(d)
	}

	var buf []byte
	if l+5 > MAX_CELL_SIZE {
		buf = make([]byte, l+5)
	} else {
		buf = GetCellBuf(false)
	}
	c := Cell3(buf)
	BigEndian.PutUint16(c[0:2], uint16(id))
	c[2] = byte(cmd)
	BigEndian.PutUint16(c[3:5], uint16(l))

	if d != nil {
		copy(c[5:], d)
	} else if l <= MAX_CELL_SIZE { // Go will do this for us when using make()
		for i := 5; i < 5+l; i++ {
			c[i] = 0
		}
	}
	c = c[0 : 5+l]
	return &c
}
