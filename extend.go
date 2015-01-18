// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
)

func (c *OnionConnection) handleRelayExtend(circ *Circuit, cell *RelayCell) ActionableError {
	data := cell.Data()

	Log(LOG_CIRC, "Got extend!")

	if circ.nextHop != nil {
		return CloseCircuit(errors.New("We already have a next hop."), DESTROY_REASON_PROTOCOL)
	}

	if circ.extendState != nil {
		return CloseCircuit(errors.New("Refusing attempt to extend a circuit twice"), DESTROY_REASON_PROTOCOL)
	}

	if len(data) != 212 {
		return CloseCircuit(errors.New("malformed EXTEND cell"), DESTROY_REASON_PROTOCOL)
	}

	// Check that we're not connecting back to the source
	if c.theyAuthenticated {
		sameFP := true
		for i := 0; i < 20; i++ {
			if c.theirFingerprint[i] != data[192+i] {
				sameFP = false
				break
			}
		}
		if sameFP {
			return CloseCircuit(errors.New("not extending to the source"), DESTROY_REASON_PROTOCOL)
		}
	}

	circReq := &CircuitRequest{}
	circReq.connHint.AddAddress(data[0:6])
	circReq.connHint.AddFingerprint(data[192:212])

	circReq.handshakeData = make([]byte, 186)
	copy(circReq.handshakeData, data[6:192])

	circReq.handshakeType = uint16(HANDSHAKE_TAP)
	circReq.successQueue = c.circuitReadQueue
	circReq.newHandshake = false
	circReq.localID = circ.id
	circReq.handshakeState = &CircuitHandshakeState{}

	circ.extendState = circReq.handshakeState

	if err := c.parentOR.RequestCircuit(circReq); err != nil {
		return CloseCircuit(err, DESTROY_REASON_INTERNAL)
	}

	return nil
}

func (c *OnionConnection) handleRelayExtend2(circ *Circuit, cell *RelayCell) ActionableError {
	Log(LOG_CIRC, "got extend")

	data := cell.Data()
	nspec := int(data[0])
	if 1+(nspec*2)+4 > len(data) {
		return CloseCircuit(errors.New("malformed EXTEND cell"), DESTROY_REASON_PROTOCOL)
	}

	if circ.nextHop != nil {
		return CloseCircuit(errors.New("We already have a next hop."), DESTROY_REASON_PROTOCOL)
	}

	if circ.extendState != nil {
		return CloseCircuit(errors.New("Refusing attempt to extend a circuit twice"), DESTROY_REASON_PROTOCOL)
	}

	circReq := &CircuitRequest{}
	circReq.newHandshake = true

	readPos := 1
	for i := 0; i < nspec; i++ {
		lstype := data[readPos]
		lslen := int(data[readPos+1])
		readPos += 2
		if readPos+lslen > len(data)-4 {
			return CloseCircuit(errors.New("malformed EXTEND cell"), DESTROY_REASON_PROTOCOL)
		}

		lsdata := data[readPos : readPos+lslen]
		readPos += lslen

		if lstype == 0 || lstype == 1 {
			if err := circReq.connHint.AddAddress(lsdata); err != nil {
				return CloseCircuit(err, DESTROY_REASON_PROTOCOL)
			}

		} else if lstype == 2 {
			if err := circReq.connHint.AddFingerprint(lsdata); err != nil {
				return CloseCircuit(err, DESTROY_REASON_PROTOCOL)
			}

			// Check that we're not connecting back to the source
			if c.theyAuthenticated {
				sameFP := true
				for i := 0; i < 20; i++ {
					if c.theirFingerprint[i] != lsdata[i] {
						sameFP = false
						break
					}
				}
				if sameFP {
					return CloseCircuit(errors.New("not extending to the source"), DESTROY_REASON_PROTOCOL)
				}
			}

		} else {
			Log(LOG_INFO, "ignoring unknown link specifier type %d", lstype)
		}
	}

	htype := BigEndian.Uint16(data[readPos : readPos+2])
	hlen := int(BigEndian.Uint16(data[readPos+2 : readPos+4]))
	readPos += 4
	if len(data) < readPos+hlen {
		return CloseCircuit(errors.New("malformed EXTEND cell"), DESTROY_REASON_PROTOCOL)
	}

	if nspec < 2 {
		return CloseCircuit(errors.New("EXTEND cell is super small.."), DESTROY_REASON_PROTOCOL)
	}

	circReq.handshakeData = make([]byte, hlen) // XXX use a cellbuf
	copy(circReq.handshakeData, data[readPos:readPos+hlen])

	circReq.handshakeType = htype
	circReq.successQueue = c.circuitReadQueue
	circReq.localID = circ.id
	circReq.handshakeState = &CircuitHandshakeState{}

	circ.extendState = circReq.handshakeState

	if err := c.parentOR.RequestCircuit(circReq); err != nil {
		return CloseCircuit(err, DESTROY_REASON_INTERNAL)
	}

	return nil
}

func (c *OnionConnection) handleCreated(cell Cell, newHandshake bool) ActionableError {
	circ, ok := c.relayCircuits[cell.CircID()]
	if !ok {
		return RefuseCircuit(errors.New(cell.Command().String()+": no such circuit?"), DESTROY_REASON_PROTOCOL)
	}

	Log(LOG_CIRC, "got a created: %d", cell.CircID())

	data := cell.Data()
	hlen := 148
	pos := 0
	if newHandshake {
		hlen = int(BigEndian.Uint16(data[0:2]))
		pos = 2
	}
	if hlen+pos > len(data) {
		return CloseCircuit(errors.New(cell.Command().String()+" cell badly formed"), DESTROY_REASON_PROTOCOL)
	}

	hdata := make([]byte, hlen) // XXX use a cellbuf
	copy(hdata, data[pos:pos+hlen])

	// Relay the good news
	circ.previousHop <- &CircuitCreated{
		id:            circ.theirID,
		handshakeData: hdata,
		newHandshake:  newHandshake,
	}

	return nil
}

func (data *CircuitCreated) Handle(c *OnionConnection, circ *Circuit) ActionableError {
	if circ.nextHop != nil {
		panic("We managed to create two circuits?")
	}
	if circ.extendState == nil {
		panic("we didn't expect to extend") // XXX this could maybe be triggered by a client?
	}

	extendState := circ.extendState
	circ.nextHop = extendState.nextHop
	circ.nextHopID = extendState.nextHopID
	circ.extendState = nil

	if data.newHandshake {
		cell := GetCellBuf(false)
		defer ReturnCellBuf(cell) // XXX such a waste
		BigEndian.PutUint16(cell[0:2], uint16(len(data.handshakeData)))
		copy(cell[2:], data.handshakeData)

		// circuit streamid direction command data
		return c.sendRelayCell(circ, 0, BackwardDirection, RELAY_EXTENDED2, cell[0:2+len(data.handshakeData)])
	} else {
		// circuit streamid direction command data
		return c.sendRelayCell(circ, 0, BackwardDirection, RELAY_EXTENDED, data.handshakeData)
	}
}

func (req *CircuitRequest) Handle(c *OnionConnection, notreallyanthingatall *Circuit) ActionableError {
	newID := c.NewCircID()

	req.handshakeState.lock.Lock()
	aborted := req.handshakeState.aborted
	if !aborted {
		req.handshakeState.nextHop = c.circuitReadQueue
		req.handshakeState.nextHopID = newID
	}
	req.handshakeState.lock.Unlock()

	if aborted {
		Log(LOG_INFO, "Aborting CREATE - origin is gone")
		return nil
	}

	cmd := CMD_CREATE2
	if !req.newHandshake {
		cmd = CMD_CREATE
	}
	writeCell := NewCell(c.negotiatedVersion, newID, cmd, nil)
	data := writeCell.Data()
	if req.newHandshake {
		BigEndian.PutUint16(data[0:2], uint16(req.handshakeType))
		BigEndian.PutUint16(data[2:4], uint16(len(req.handshakeData)))
		copy(data[4:], req.handshakeData)
	} else {
		copy(data, req.handshakeData)
	}

	// XXX if they send data before the created2, it'll nicely work
	c.relayCircuits[writeCell.CircID()] = &RelayCircuit{
		id:          writeCell.CircID(),
		theirID:     req.localID,
		previousHop: req.successQueue,
	}

	c.writeQueue <- writeCell.Bytes()

	return nil
}
