// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
)

type CircuitCommand interface {
	CircID() CircuitID
	ForRelay() bool
	Handle(*OnionConnection, *Circuit) ActionableError
	HandleRelay(*OnionConnection, *RelayCircuit) ActionableError
	ReleaseBuffers()
}

type NeverForRelay struct {
}

type NoBuffers struct {
}

func (c *NeverForRelay) ForRelay() bool {
	return false
}

func (c *NoBuffers) ReleaseBuffers() {
}

func (c *NeverForRelay) HandleRelay(*OnionConnection, *RelayCircuit) ActionableError {
	panic("reached unreachable code")
}

func (c *OnionConnection) routeCellToFunction(cell Cell) ActionableError {
	switch cell.Command() {
	case CMD_CREATE_FAST:
		return c.handleCreateFast(cell)

	case CMD_RELAY, CMD_RELAY_EARLY:
		// XXX CircType()
		circID := cell.CircID()
		circ, ok := c.circuits[circID]
		if ok {
			return c.handleRelayForward(circ, cell)
		}

		rcirc, ok := c.relayCircuits[circID]
		if ok {
			if cell.Command() == CMD_RELAY_EARLY {
				return CloseConnection(errors.New("Dropping the connection - no way we're routing a RELAY_EARLY cell back"))
			}
			return c.handleRelayBackward(rcirc, cell)
		}

		// Not an error
		Log(LOG_INFO, "Received a %s cell for an unknown circuit - dropping", cell.Command())

	case CMD_CREATE, CMD_CREATE2:
		newHandshake := cell.Command() == CMD_CREATE2
		return c.handleCreate(cell, newHandshake)

	case CMD_DESTROY:
		return c.handleDestroy(cell)

	case CMD_CREATED, CMD_CREATED2:
		return c.handleCreated(cell, cell.Command() == CMD_CREATED2)

	case CMD_PADDING, CMD_VPADDING:
		// Can be ignored

	case CMD_CERTS, CMD_NETINFO, CMD_AUTH_CHALLENGE, CMD_AUTHORIZE, CMD_AUTHENTICATE:
		return CloseConnection(errors.New(fmt.Sprintf("Command %s not allowed at this point. Disconnecting", cell.Command())))

	default:
		Log(LOG_NOTICE, "Got a cell with command %s - dropping", cell.Command())
		Log(LOG_DEBUG, "%v", cell)
	}

	return nil
}

func (c *OnionConnection) routeCircuitCommandToFunction(cmd CircuitCommand) ActionableError {
	circID := cmd.CircID()
	forRelay := cmd.ForRelay()

	if !forRelay {
		if circID == 0 { // Control command
			return cmd.Handle(c, nil)
		}

		// Look in c.circuits
		circ, ok := c.circuits[circID]
		if !ok {
			Log(LOG_INFO, "got internal command for nonexisting circuit %v", cmd)
			return nil // It happens, nothing to worry about
		}

		return cmd.Handle(c, circ)
	} else {
		if circID == 0 { // Control command
			return cmd.HandleRelay(c, nil)
		}

		// Look in c.relayCircuits
		circ, ok := c.relayCircuits[circID]
		if !ok {
			Log(LOG_INFO, "got internal command for nonexisting relayCircuit %v", cmd)
			return nil // It happens, nothing to worry about
		}

		return cmd.HandleRelay(c, circ)
	}
}
