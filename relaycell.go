// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

type StreamID uint16

type RelayCell struct {
	bytes []byte
}

func (c *RelayCell) Command() RelayCommand {
	return RelayCommand(c.bytes[0])
}

func (c *RelayCell) Recognized() bool {
	if c.bytes[1] != 0 || c.bytes[2] != 0 {
		return false
	} else {
		return true
	}
}

func (c *RelayCell) StreamID() StreamID {
	return StreamID(BigEndian.Uint16(c.bytes[3:5]))
}

func (c *RelayCell) Digest() []byte {
	return c.bytes[5:9]
}

func (c *RelayCell) Length() int {
	return int(BigEndian.Uint16(c.bytes[9:11]))
}

func (c *RelayCell) Data() []byte {
	return c.bytes[11 : 11+c.Length()]
}
