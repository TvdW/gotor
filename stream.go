// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

type StreamMessageType byte

const (
	STREAM_CONNECTED StreamMessageType = iota
	STREAM_DISCONNECTED
	STREAM_SENDME
)

type Stream struct {
	id                            StreamID
	writeChan                     chan []byte
	forwardWindow, backwardWindow *Window
	finished                      int32
}

/* Stream cleanups
 *
 * When the writer fails to write we close the socket, triggering the reader to fail.
 * When the reader fails to read we close the channel. Closing the channel will cause the goroutine to finish.
 * When the circuit tells us to close by closing our channel, we just finish the goroutine, causing the other cleanup to happen.
 *
 * Finishing the goroutine means closing the socket and informing the channel that we're done (which should then dealloc us)
 */

func NewStream(id StreamID) (*Stream, error) {
	s := &Stream{
		id:             id,
		writeChan:      make(chan []byte, 505),
		forwardWindow:  NewWindow(500),
		backwardWindow: NewWindow(500),
	}
	return s, nil
}

func (s *Stream) Destroy() {
	close(s.writeChan)
}

var dialer = net.Dialer{
	KeepAlive: 0,
	DualStack: true,
	Timeout:   5 * time.Second,
}

func (s *Stream) Run(circID CircuitID, circWindow *Window, queue CircReadQueue, address string, port uint16, isDir bool, ep ExitPolicy) {
	addr := ResolveDNS(address)[0]

	if !(addr.Type == 4 || addr.Type == 6) {
		queue <- &StreamControl{
			circuitID: circID,
			streamID: s.id,
			data: STREAM_DISCONNECTED,
			reason: STREAM_REASON_RESOLVEFAILED,
		}
	}

	if !isDir && !ep.AllowsConnect(addr.Value, port) {
		queue <- &StreamControl{
			circuitID: circID,
			streamID: s.id,
			data: STREAM_DISCONNECTED,
			reason: STREAM_REASON_EXITPOLICY,
			remoteAddr: addr.Value,
		}
		return
	}

	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", addr.String(), port))
	if err != nil {
		queue <- &StreamControl{
			circuitID: circID,
			streamID:  s.id,
			data:      STREAM_DISCONNECTED,
			reason:    STREAM_REASON_CONNECTREFUSED,
		}
		return
	}

	queue <- &StreamControl{
		circuitID:  circID,
		streamID:   s.id,
		data:       STREAM_CONNECTED,
		remoteAddr: addr.Value,
	}

	defer func() {
		conn.Close()

		atomic.StoreInt32(&s.finished, 1)
		s.backwardWindow.Abort()
		s.forwardWindow.Abort()
		circWindow.Abort()

		queue <- &StreamControl{
			circuitID: circID,
			streamID:  s.id,
			data:      STREAM_DISCONNECTED,
			reason:    STREAM_REASON_DONE,
		} // XXX this could deadlock
		Log(LOG_CIRC, "Disconnected stream %d to %s", s.id, address)
	}()

	readQueue := make(chan []byte, 5)

	go s.reader(conn, circWindow, readQueue)

	for {
		select {
		case data, ok := <-s.writeChan:
			if !ok {
				return
			}
			_, err := conn.Write(data)
			if err != nil {
				return
			}
			ReturnCellBuf(data)

			for len(s.writeChan) < 10 && s.forwardWindow.GetLevel() <= 450 {
				s.forwardWindow.Refill(50)
				queue <- &StreamControl{
					data:      STREAM_SENDME,
					circuitID: circID,
					streamID:  s.id,
				}
			}
		case data, ok := <-readQueue:
			if !ok {
				return
			}
			queue <- &StreamData{
				circuitID: circID,
				streamID:  s.id,
				data:      data,
			} // XXX this could deadlock
		}
	}
}

func (s *Stream) reader(conn net.Conn, circWindow *Window, queue chan []byte) {
	var readBuf [4096]byte

	for {
		hasWnd1 := false
		hasWnd2 := false

		// Try to obtain permission to send the data.
		for !(hasWnd1 && hasWnd2) {
			done := atomic.LoadInt32(&s.finished)
			if done != 0 {
				close(queue)
				return
			}

			if !hasWnd1 {
				hasWnd1 = s.backwardWindow.Take()
				continue
			}
			if !hasWnd2 {
				hasWnd2 = circWindow.Take()
				continue
			}
		}

		bytes, err := conn.Read(readBuf[:])
		if err != nil && bytes <= 0 {
			close(queue)
			return
		}
		for i := 0; i < bytes;  {
			s := MAX_RELAY_LEN
			if s > bytes-i {
				s = bytes-i
			}
			cell := GetCellBuf(false)
			copy(cell, readBuf[i:])
			queue <- cell[0:s] // XXX would it make sense to add a timeout here? This has proven to deadlock
			i += s
		}
	}
}
