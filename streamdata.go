// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

type StreamData struct {
	NeverForRelay
	circuitID CircuitID
	streamID  StreamID
	data      []byte
}

func (sd *StreamData) CircID() CircuitID {
	return sd.circuitID
}

func (sd *StreamData) Handle(c *OnionConnection, circ *Circuit) ActionableError {
	data := sd.data

	for pos := 0; pos < len(data); pos += MAX_RELAY_LEN {
		thisLen := len(data) - pos
		if thisLen > MAX_RELAY_LEN {
			thisLen = MAX_RELAY_LEN
		}

		data := data[pos : pos+thisLen]
		if err := c.sendRelayCell(circ, sd.streamID, BackwardDirection, RELAY_DATA, data); err != nil {
			return err
		}
	}

	return nil
}

func (sd *StreamData) ReleaseBuffers() {
	ReturnCellBuf(sd.data)
}
