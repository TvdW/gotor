// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"github.com/tvdw/gotor/aes"
	"github.com/tvdw/gotor/sha1"
	"sync"
)

type CircuitID uint32

func (id CircuitID) MSB(vers LinkVersion) bool {
	if vers < 4 {
		if id&0x8000 == 0x8000 {
			return true // outgoing
		} else {
			return false // incoming
		}
	} else {
		if id&0x80000000 == 0x80000000 {
			return true // outgoing
		} else {
			return false // incoming
		}
	}
}

type DirectionalCircuitState struct {
	cipher aes.Cipher
	digest *sha1.Digest
}

type DataDirection bool

const (
	ForwardDirection  = true
	BackwardDirection = false
)

type Circuit struct {
	id                CircuitID
	forward, backward DirectionalCircuitState
	forwardWindow     int
	backwardWindow    *Window
	nextHop           CircReadQueue
	nextHopID         CircuitID

	streams     map[StreamID]*Stream
	extendState *CircuitHandshakeState
}

type RelayCircuit struct {
	id, theirID CircuitID
	previousHop CircReadQueue
}

type CircuitHandshakeState struct {
	lock      sync.Mutex
	aborted   bool
	nextHop   CircReadQueue
	nextHopID CircuitID
}

type CircuitRequest struct {
	NeverForRelay
	localID        CircuitID
	connHint       ConnectionHint
	successQueue   CircReadQueue
	handshakeType  uint16
	handshakeData  []byte
	newHandshake   bool
	handshakeState *CircuitHandshakeState
}

type CircuitCreated struct {
	NeverForRelay
	id            CircuitID
	handshakeData []byte
	newHandshake  bool
}

func (c *CircuitRequest) CircID() CircuitID {
	return 0
}

func (c *CircuitRequest) ReleaseBuffers() {
	ReturnCellBuf(c.handshakeData)
	c.handshakeState = nil
	c.handshakeData = nil
	c.successQueue = nil
}

func (c *CircuitCreated) CircID() CircuitID {
	return c.id
}

func (c *CircuitCreated) ReleaseBuffers() {
	ReturnCellBuf(c.handshakeData)
}

var zeroIv [16]byte

func NewCircuit(id CircuitID, fSeed, bSeed, fKey, bKey []byte) *Circuit {
	if id == 0 {
		panic("wtf?")
	}

	StatsNewCircuit()

	aes_fwd := aes.New(fKey, zeroIv[:])
	aes_rev := aes.New(bKey, zeroIv[:])

	dig_fwd := sha1.New()
	dig_fwd.Write(fSeed)
	dig_rev := sha1.New()
	dig_rev.Write(bSeed)

	circ := &Circuit{
		id: id,
		forward: DirectionalCircuitState{
			cipher: aes_fwd,
			digest: dig_fwd,
		},
		backward: DirectionalCircuitState{
			cipher: aes_rev,
			digest: dig_rev,
		},
		backwardWindow: NewWindow(1000),
		forwardWindow:  1000,
		streams:        make(map[StreamID]*Stream),
	}

	return circ
}

func (c *OnionConnection) destroyCircuit(circ *Circuit, announce, shouldRemove bool, reason DestroyReason) {
	if shouldRemove {
		delete(c.circuits, circ.id)
	}

	circ.backwardWindow.Abort()
	for _, stream := range circ.streams {
		stream.Destroy()
	}

	StatsDestroyCircuit()

	if circ.extendState != nil {
		circ.extendState.lock.Lock()
		circ.extendState.aborted = true
		if circ.extendState.nextHop != nil {
			if circ.nextHop != nil {
				panic("wtf-case")
			}
			circ.nextHop = circ.extendState.nextHop
			circ.nextHopID = circ.extendState.nextHopID
		}
		circ.extendState.lock.Unlock()
		circ.extendState = nil
	}

	if announce && circ.nextHop != nil {
		circ.nextHop <- &CircuitDestroyed{
			id:       circ.nextHopID,
			reason:   reason,
			forRelay: true,
		}
	}

	// Set things to nil to mitigate possible memory leaks caused by other objects retaining this circuit (which is obviously a bug)
	circ.nextHop = nil
	circ.forward = DirectionalCircuitState{}
	circ.backward = DirectionalCircuitState{}
	circ.streams = nil
	circ.backwardWindow = nil
}

func (c *OnionConnection) destroyRelayCircuit(circ *RelayCircuit, announce, shouldRemove bool, reason DestroyReason) {
	if shouldRemove {
		delete(c.relayCircuits, circ.id)
	}

	if announce && circ.previousHop != nil {
		circ.previousHop <- &CircuitDestroyed{
			id:       circ.theirID,
			reason:   reason,
			forRelay: false,
			//truncate: true, // XXX?
		}
	}
}

func (c *OnionConnection) NewCircID() CircuitID {
	for {
		var b [4]byte
		CRandBytes(b[:])
		if c.isOutbound {
			b[0] |= 0x80
		} else {
			b[0] &= 0x7f
		}
		cID := CircuitID(BigEndian.Uint32(b[:]))
		if c.negotiatedVersion < 4 {
			cID = (cID & 0xffff0000) >> 16 // Cut off the last 16 bits as we can't transmit them
		}

		_, exists := c.circuits[cID]
		if !exists { // XXX check infinite loop
			return cID
		}
	}
}
