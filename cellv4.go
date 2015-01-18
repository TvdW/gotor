// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

type Cell4 []byte

func (c Cell4) Command() Command {
	return Command(c[4])
}

func (c Cell4) Data() []byte {
	return c[5:len(c)]
}

func (c Cell4) CircID() CircuitID {
	return CircuitID(BigEndian.Uint32(c[0:4]))
}

func (c Cell4) ReleaseBuffers() {
	ReturnCellBuf([]byte(c))
}

func (c Cell4) Bytes() []byte {
	return []byte(c)
}

func NewCell4(id CircuitID, cmd Command, d []byte) Cell {
	c := Cell4(GetCellBuf(false))
	BigEndian.PutUint32(c[0:4], uint32(id))
	c[4] = byte(cmd)
	if len(d) > 509 {
		panic("Code error: creating massive cell")
	}
	if d != nil {
		copy(c[5:], d)
	}
	// Now wipe all other data
	for i := 5 + len(d); i < 514; i++ {
		c[i] = 0
	}
	c = c[0:514]
	return &c
}

func NewVarCell4(id CircuitID, cmd Command, d []byte, l int) Cell {
	if d != nil && l > 0 {
		panic("Don't specify both data and length")
	}

	if l == 0 {
		l = len(d)
	}

	var buf []byte
	if l+7 > MAX_CELL_SIZE {
		buf = make([]byte, l+7)
	} else {
		buf = GetCellBuf(false)
	}
	c := Cell4(buf)
	BigEndian.PutUint32(c[0:4], uint32(id))
	c[4] = byte(cmd)
	BigEndian.PutUint16(c[5:7], uint16(l))
	if d != nil {
		copy(c[7:], d)
	} else if l <= MAX_CELL_SIZE { // Go will do this for us when using make()
		for i := 7; i < 7+l; i++ {
			c[i] = 0
		}
	}
	c = c[0 : 7+l]
	return &c
}
