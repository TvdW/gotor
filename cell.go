// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/binary"
)

var BigEndian = binary.BigEndian

type Cell interface {
	CircID() CircuitID
	Command() Command
	Data() []byte
	ReleaseBuffers()
	Bytes() []byte
}

func NewCell(vers LinkVersion, id CircuitID, cmd Command, data []byte) Cell {
	if vers < 4 {
		return NewCell3(id, cmd, data)
	} else {
		return NewCell4(id, cmd, data)
	}
}

func NewVarCell(vers LinkVersion, id CircuitID, cmd Command, data []byte, length int) Cell {
	if vers < 4 {
		return NewVarCell3(id, cmd, data, length)
	} else {
		return NewVarCell4(id, cmd, data, length)
	}
}
