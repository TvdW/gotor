// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

type CircuitDestroyed struct {
	NoBuffers
	id       CircuitID
	reason   DestroyReason
	forRelay bool
	truncate bool
}

func (c *CircuitDestroyed) CircID() CircuitID {
	return c.id
}

func (data *CircuitDestroyed) ForRelay() bool {
	return data.forRelay
}

func (data *CircuitDestroyed) Handle(c *OnionConnection, circ *Circuit) ActionableError {
	Log(LOG_CIRC, "CircuitDestroy (front)")

	if data.truncate {
		panic("not implemented properly") // XXX needs cleanup of fields like nextHop/nextHopID
		return c.sendRelayCell(circ, 0, BackwardDirection, RELAY_TRUNCATED, []byte{byte(data.reason)})
	} else {
		c.destroyCircuit(circ, false, true, data.reason)
		c.writeQueue <- NewCell(c.negotiatedVersion, circ.id, CMD_DESTROY, []byte{byte(data.reason)}).Bytes()
		return nil
	}
}

func (data *CircuitDestroyed) HandleRelay(c *OnionConnection, circ *RelayCircuit) ActionableError {
	Log(LOG_CIRC, "CircuitDestroy (relay)")
	c.destroyRelayCircuit(circ, false, true, data.reason)

	c.writeQueue <- NewCell(c.negotiatedVersion, circ.id, CMD_DESTROY, []byte{byte(data.reason)}).Bytes()
	return nil
}

func (c *OnionConnection) handleDestroy(cell Cell) ActionableError {
	Log(LOG_CIRC, "Got a destroy for circ %d with reason %s", cell.CircID(), DestroyReason(cell.Data()[0]))

	circID := cell.CircID()
	if circID.MSB(c.negotiatedVersion) != c.isOutbound {
		circ, ok := c.circuits[circID]
		if !ok {
			Log(LOG_INFO, "Got a DESTROY but we don't know the circuit they're talking about. Ignoring")
		} else {
			c.destroyCircuit(circ, true, true, DestroyReason(cell.Data()[0]))
		}
		return nil
	}

	rcirc, ok := c.relayCircuits[circID]
	if ok {
		c.destroyRelayCircuit(rcirc, true, true, DestroyReason(cell.Data()[0]))
		return nil
	}

	Log(LOG_INFO, "Got a DESTROY but we don't know the circuit they're talking about. Ignoring")
	return nil
}
