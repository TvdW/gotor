// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/sha256"
	"io"
	"net"
)

const READ_QUEUE_LENGTH = 100
const WRITE_QUEUE_LENGTH = 2000
const CIRC_QUEUE_LENGTH = 2000

type CircReadQueue chan CircuitCommand

type OnionConnection struct {
	parentOR         *ORCtx
	readQueue        chan Cell
	circuitReadQueue CircReadQueue
	writeQueue       chan []byte
	circuits         map[CircuitID]*Circuit
	relayCircuits    map[CircuitID]*RelayCircuit

	usedTLSCtx        *TorTLS
	negotiatedVersion LinkVersion

	isOutbound          bool
	weAuthenticated     bool
	theyAuthenticated   bool
	theirFingerprint    Fingerprint
	theirFingerprint256 []byte
}

func newOnionConnection(tlsctx *TorTLS, or *ORCtx) *OnionConnection {
	StatsAddConnection()

	return &OnionConnection{
		usedTLSCtx:       tlsctx,
		circuits:         make(map[CircuitID]*Circuit),
		relayCircuits:    make(map[CircuitID]*RelayCircuit),
		readQueue:        make(chan Cell, READ_QUEUE_LENGTH),
		writeQueue:       make(chan []byte, WRITE_QUEUE_LENGTH),
		circuitReadQueue: make(CircReadQueue, CIRC_QUEUE_LENGTH),
		parentOR:         or,
	}
}

func (c *OnionConnection) cleanup() {
	StatsRemoveConnection()

	if c.theyAuthenticated {
		if err := c.parentOR.EndConnection(c.theirFingerprint, c); err != nil {
			Log(LOG_NOTICE, "Warning during deregistration: %s", err)
		}
	}

	close(c.writeQueue)

	for _, circ := range c.relayCircuits {
		c.destroyRelayCircuit(circ, true, false, DESTROY_REASON_OR_CONN_CLOSED)
	}
	c.relayCircuits = nil

	for _, circ := range c.circuits {
		c.destroyCircuit(circ, true, false, DESTROY_REASON_OR_CONN_CLOSED)
	}
	c.circuits = nil

	// It is guaranteed that after calling EndConnection we will no longer receive any CircuitRequest
	// So just process whatever was left.
readTheQueue:
	for {
		select {
		case cmd := <-c.circuitReadQueue:
			creationRequest, ok := cmd.(*CircuitRequest)
			if ok {
				creationRequest.successQueue <- &CircuitDestroyed{
					reason: 8, // OR_CONN_CLOSED
					id:     creationRequest.localID,
					//truncate: true,
				}
			}

			cmd.ReleaseBuffers()
		default:
			break readTheQueue
		}
	}
}

func HandleORConnClient(or *ORCtx, conn net.Conn, req *CircuitRequest) {
	// XXX WTF BUG: The Tor spec requires us to allow AUTHORIZE/VPADDING before VERSIONS

	tlsConn, usedTLSCtx, err := or.WrapTLS(conn, true)
	if err != nil {
		Log(LOG_WARN, "%s", err)
		if req != nil {
			req.successQueue <- &CircuitDestroyed{
				reason: 2, //INTERNAL
				id:     req.localID,
				//truncate: true,
			}
		}
		return
	}
	defer tlsConn.Close()

	me := newOnionConnection(usedTLSCtx, or)
	me.isOutbound = true

	if req != nil {
		me.circuitReadQueue <- req
		req = nil
	}

	defer me.cleanup()

	hash_inbound := sha256.New()
	hash_outbound := sha256.New()

	// Spawn the reader later - we still need to negotiate the version
	go me.writer(tlsConn)

	if err := me.negotiateVersionClient(tlsConn, hash_inbound, hash_outbound); err != nil {
		Log(LOG_INFO, "%s", err)
		return
	}

	go me.reader(tlsConn)

	Log(LOG_CIRC, "Negotiated version %d", me.negotiatedVersion)

handshake:
	for {
		cell, ok := <-me.readQueue
		if !ok {
			Log(LOG_CIRC, "Connection closed")
			return
		}

		hash_inbound.Write(cell.Bytes())

		Log(LOG_CIRC, "pre-runloop got a %s", cell.Command())

		switch cell.Command() {
		case CMD_NETINFO:
			me.sendNetinfo(hash_outbound)
			break handshake

		case CMD_PADDING, CMD_VPADDING:
			// Ignore

		case CMD_AUTH_CHALLENGE:
			err := me.handleAuthChallenge(cell, hash_inbound, hash_outbound, tlsConn)
			if err != nil {
				Log(LOG_INFO, "%s", err)
				return
			}

		case CMD_CERTS:
			peerCert, err := tlsConn.PeerCertificate()
			if err = me.handleCerts(cell, peerCert); err != nil {
				Log(LOG_INFO, "%s", err)
				return
			}

		default:
			Log(LOG_NOTICE, "Cell %s not allowed. Disconnecting", cell.Command())
			return
		}

		cell.ReleaseBuffers()
	}

	if me.theyAuthenticated {
		if err := or.RegisterConnection(me.theirFingerprint, me); err != nil {
			// No worries
			Log(LOG_INFO, "register warning: %s", err)
		}
	}

	hash_inbound = nil
	hash_outbound = nil
	me.Runloop()
}

func HandleORConnServer(or *ORCtx, conn net.Conn) {
	tlsConn, usedTLSCtx, err := or.WrapTLS(conn, false)
	if err != nil {
		Log(LOG_WARN, "%s", err)
		return
	}
	defer tlsConn.Close() // As soon as we leave this function, we make sure the connection is closed

	me := newOnionConnection(usedTLSCtx, or)
	me.isOutbound = false
	defer me.cleanup()

	// Spawn the reader later - we still need to negotiate the version
	go me.writer(tlsConn)

	if err := me.negotiateVersionServer(tlsConn); err != nil {
		Log(LOG_INFO, "%s", err)
		return
	}

	go me.reader(tlsConn)

	Log(LOG_CIRC, "Negotiated version %d", me.negotiatedVersion)

	if err := me.sendCerts(nil); err != nil {
		Log(LOG_INFO, "%s", err)
		return
	}
	me.weAuthenticated = true

	if err := me.sendAuthChallenge(); err != nil {
		Log(LOG_INFO, "%s", err)
		return
	}

	if err := me.sendNetinfo(nil); err != nil {
		Log(LOG_INFO, "%s", err)
		return
	}

handshake:
	for {
		cell, ok := <-me.readQueue
		if !ok {
			Log(LOG_INFO, "readqueue stopped working")
			return
		}

		switch cell.Command() {
		case CMD_AUTHORIZE, CMD_PADDING, CMD_VPADDING:
			// Ignore
		case CMD_CERTS:
			if err := me.handleCerts(cell, nil); err != nil {
				Log(LOG_INFO, "%s", err)
				return
			}
		case CMD_AUTHENTICATE:
			// XXX
		case CMD_NETINFO:
			// Good
			break handshake
		default:
			// Not good
			Log(LOG_NOTICE, "Unexpected %s - dropping connection", cell.Command())
			return
		}

		cell.ReleaseBuffers()
	}

	me.Runloop()
}

func (me *OnionConnection) Runloop() {
	Log(LOG_CIRC, "handshake done, runloop starting")

	for {
		var err ActionableError
		var circID CircuitID // XXX This is messed up.

		select {
		case cell, ok := <-me.readQueue:
			if !ok {
				return
			}

			circID = cell.CircID()

			if cell.Command() != CMD_PADDING {
				Log(LOG_DEBUG, "%s got a %s: %v", me.theirFingerprint, cell.Command(), cell)
			}

			err = me.routeCellToFunction(cell)
			cell.ReleaseBuffers()

		case circData := <-me.circuitReadQueue:
			circID = circData.CircID()

			err = me.routeCircuitCommandToFunction(circData)
			circData.ReleaseBuffers()
		}

		if err != nil {
			switch err.Handle() {
			case ERROR_CLOSE_CONNECTION:
				Log(LOG_NOTICE, "Closing connection: %s", err)
				return

			case ERROR_CLOSE_CIRCUIT:
				if circID == 0 {
					Log(LOG_WARN, "Got a ERROR_CLOSE_CIRCUIT for CircID=0. Disconnecting")
					return
				}

				me.writeQueue <- NewCell(me.negotiatedVersion, circID, CMD_DESTROY, []byte{byte(err.CircDestroyReason())}).Bytes()

				if circID.MSB(me.negotiatedVersion) != me.isOutbound { // Front
					circ, ok := me.circuits[circID]
					if !ok {
						Log(LOG_WARN, "Got a ERROR_CLOSE_CIRCUIT but don't know the circuit. Disconnecting. Original: %s", err)
						return
					}

					me.destroyCircuit(circ, true, true, err.CircDestroyReason())
					Log(LOG_NOTICE, "Closing circuit: %s", err)

				} else {
					circ, ok := me.relayCircuits[circID]
					if !ok {
						Log(LOG_WARN, "Got a ERROR_CLOSE_CIRCUIT but don't know the circuit. Disconnecting. Original: %s", err)
						return
					}

					me.destroyRelayCircuit(circ, true, true, err.CircDestroyReason())
					Log(LOG_NOTICE, "Closing relayCircuit: %s", err)
				}

			case ERROR_REFUSE_CIRCUIT:
				if circID == 0 {
					Log(LOG_WARN, "Got a ERROR_CLOSE_CIRCUIT for CircID=0. Disconnecting")
					return
				}

				me.writeQueue <- NewCell(me.negotiatedVersion, circID, CMD_DESTROY, []byte{byte(err.CircDestroyReason())}).Bytes()

			default:
				Log(LOG_WARN, "Disconnecting: not sure what to do with error %v", err)
				return
			}
		}
	}
}

func (c *OnionConnection) reader(conn io.Reader) {
	defer close(c.readQueue)

	var buffer [SSLRecordSize]byte
	readPos, decodePos := 0, 0
	for {
		bytes, err := conn.Read(buffer[readPos:])
		if err != nil && bytes <= 0 {
			Log(LOG_INFO, "%s", err)
			return
		}
		readPos += bytes
		circLen := 4
		if c.negotiatedVersion < 4 {
			circLen = 2
		}

		for decodePos+3+circLen < readPos { // while we have enough data to figure out command && length
			if buffer[decodePos+circLen] == 7 || buffer[decodePos+circLen]&0x80 != 0 { // Variable length
				varLen := (int(buffer[decodePos+circLen+1]) << 8) + int(buffer[decodePos+circLen+2])
				varLen += circLen + 3 // Don't forget about the cell overhead

				if varLen >= SSLRecordSize {
					Log(LOG_INFO, "Dropping connection with variable-length cell that is WAY too large")
					return
				}

				if readPos-decodePos >= varLen {
					var varCell []byte
					if varLen <= MAX_CELL_SIZE {
						varCell = GetCellBuf(false)[0:varLen]
					} else {
						varCell = make([]byte, varLen)
					}
					copy(varCell, buffer[decodePos:decodePos+varLen])
					decodePos += varLen
					if c.negotiatedVersion < 4 {
						c.readQueue <- (*Cell3)(&varCell)
					} else {
						c.readQueue <- (*Cell4)(&varCell)
					}
				} else {
					break
				}

			} else { // Constant (514) length cell
				if readPos-decodePos >= 510+circLen {
					cell := GetCellBuf(false)
					copy(cell, buffer[decodePos:decodePos+510+circLen])
					cell = cell[0 : 510+circLen]
					decodePos += 510 + circLen
					if c.negotiatedVersion < 4 {
						c.readQueue <- (*Cell3)(&cell)
					} else {
						c.readQueue <- (*Cell4)(&cell)
					}
				} else {
					break
				}
			}
		}

		if decodePos == readPos {
			decodePos = 0
			readPos = 0
		} else if decodePos > readPos {
			panic("BUG: we decoded more than we read")
		} else if decodePos != 0 {
			copy(buffer[:], buffer[decodePos:readPos])
			readPos -= decodePos
			decodePos = 0
		}
	}
}

func (c *OnionConnection) writer(conn net.Conn) {
	defer func() {
		Log(LOG_INFO, "writer ended")
		conn.Close()
	}()

	var buffer [SSLRecordSize]byte
	var nextItem []byte

	for {
		if nextItem != nil {
			_, err := conn.Write(nextItem)
			if err != nil {
				Log(LOG_INFO, "%s", err)
				return
			}
			ReturnCellBuf(nextItem)
			nextItem = nil
		}

		select {
		case data, ok := <-c.writeQueue:
			if !ok {
				return
			}

			Log(LOG_DEBUG, "writing %d: %v", len(data), data)

			datalen := len(data)
			copy(buffer[:], data)
			ReturnCellBuf(data)

		extradata:
			for { // See if we got any extra data
				select {
				case data2, ok := <-c.writeQueue:
					if !ok {
						break extradata
					}

					if datalen+len(data2) > cap(buffer) {
						nextItem = data2
						break extradata
					}

					copy(buffer[datalen:], data2)
					datalen += len(data2)
					ReturnCellBuf(data2)

					if datalen+MAX_CELL_SIZE > cap(buffer) {
						break extradata
					}
				default:
					break extradata
				}
			}

			_, err := conn.Write(buffer[:datalen])
			if err != nil {
				Log(LOG_INFO, "%s", err)
				return
			}
		}
	}
}
