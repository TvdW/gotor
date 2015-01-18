// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

type StreamControl struct {
	NeverForRelay
	NoBuffers
	circuitID  CircuitID
	streamID   StreamID
	data       StreamMessageType
	reason     StreamEndReason
	remoteAddr []byte
}

func (sd *StreamControl) CircID() CircuitID {
	return sd.circuitID
}

func (sc *StreamControl) Handle(c *OnionConnection, circ *Circuit) ActionableError {
	switch sc.data {
	case STREAM_CONNECTED:
		var data []byte
		if sc.remoteAddr != nil {
			if len(sc.remoteAddr) == 4 {
				data = make([]byte, 8) //XXX
				copy(data, sc.remoteAddr)
				data[6] = 1
				data[7] = 44
			} else if len(sc.remoteAddr) == 16 {
				data = make([]byte, 25) //XXX
				data[4] = 6
				copy(data[5:], sc.remoteAddr)
				data[23] = 1
				data[24] = 44
			}
		}

		return c.sendRelayCell(circ, sc.streamID, BackwardDirection, RELAY_CONNECTED, data)

	case STREAM_DISCONNECTED:
		stream, ok := circ.streams[sc.streamID]
		if !ok {
			return nil
		}
		delete(circ.streams, sc.streamID)
		stream.Destroy()

		// We need to inform the OP that the connection died
		var data []byte
		if sc.remoteAddr != nil {
			if len(sc.remoteAddr) == 4 {
				data = make([]byte, 9) //XXX
				data[0] = byte(sc.reason)
				copy(data[1:], sc.remoteAddr)
				data[7] = 1
				data[8] = 44
			} else if len(sc.remoteAddr) == 16 {
				data = make([]byte, 26) //XXX
				data[0] = byte(sc.reason)
				data[5] = 6
				copy(data[6:], sc.remoteAddr)
				data[24] = 1
				data[25] = 44
			} else {
				data = []byte{byte(sc.reason)}
			}
		}
		return c.sendRelayCell(circ, sc.streamID, BackwardDirection, RELAY_END, data)

	case STREAM_SENDME:
		_, ok := circ.streams[sc.streamID]
		if !ok {
			return nil
		}

		return c.sendRelayCell(circ, sc.streamID, BackwardDirection, RELAY_SENDME, nil)

	default:
		panic("Did not understand our StreamControl message!")
	}
}
