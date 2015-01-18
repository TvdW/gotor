// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

type RelayData struct {
	id       CircuitID
	data     []byte
	forRelay bool
	rType    Command
}

func (c *RelayData) CircID() CircuitID {
	return c.id
}

func (c *RelayData) ForRelay() bool {
	return c.forRelay
}

func (rdata *RelayData) Handle(c *OnionConnection, circ *Circuit) ActionableError {
	data := rdata.data

	cell := NewCell(c.negotiatedVersion, circ.id, CMD_RELAY, nil)

	cstate := circ.backward.cipher
	_, err := cstate.Crypt(data, cell.Data())
	if err != nil {
		cell.ReleaseBuffers()
		return CloseCircuit(err, DESTROY_REASON_INTERNAL)
	}

	c.writeQueue <- cell.Bytes()
	return nil
}

func (data *RelayData) HandleRelay(c *OnionConnection, circ *RelayCircuit) ActionableError {
	c.writeQueue <- NewCell(c.negotiatedVersion, circ.id, data.rType, data.data).Bytes()

	return nil
}

func (data *RelayData) ReleaseBuffers() {
	ReturnCellBuf(data.data)
}
