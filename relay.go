// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
)

const MAX_RELAY_LEN = 514 - 11 - 5

var regex_ip = `(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])`
var regex_v6 = `\[[0-9a-fA-F:]{3,45}\]`
var regex_host = `(?:(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*(?:[A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])`
var regex_streamtargetstr = `^(` + regex_ip + `|` + regex_v6 + `|` + regex_host + `):([1-9][0-9]{0,4})$`
var regex_streamtarget = regexp.MustCompile(regex_streamtargetstr)

func (c *OnionConnection) handleRelayBackward(circ *RelayCircuit, cell Cell) ActionableError {
	origData := cell.Data()
	data := GetCellBuf(false)
	copy(data, origData)
	data = data[0:len(origData)]

	circ.previousHop <- &RelayData{
		id:       circ.theirID,
		data:     data,
		forRelay: false,
	}

	return nil
}

func (c *OnionConnection) handleRelayForward(circ *Circuit, cell Cell) ActionableError {
	cstate := circ.forward

	dec, err := cstate.cipher.Crypt(cell.Data(), GetCellBuf(false))
	if err != nil {
		return CloseCircuit(err, DESTROY_REASON_INTERNAL)
	}

	rcell := RelayCell{dec}

	should_be_forwarded := false

	if !rcell.Recognized() {
		should_be_forwarded = true
	}

	if !should_be_forwarded {
		tmpCell := GetCellBuf(false)
		defer ReturnCellBuf(tmpCell)
		copy(tmpCell, rcell.bytes)
		tmpCell = tmpCell[:len(rcell.bytes)]
		tmpCell[5] = 0
		tmpCell[6] = 0
		tmpCell[7] = 0
		tmpCell[8] = 0

		old_dig := cstate.digest.Clone() // XXX rofl

		cstate.digest.Write(tmpCell)
		their_digest := rcell.Digest()
		our_digest := cstate.digest.Sum(nil)
		if their_digest[0] != our_digest[0] || their_digest[1] != our_digest[1] || their_digest[2] != our_digest[2] || their_digest[3] != our_digest[3] {
			cstate.digest = old_dig // XXX Find a better way to do this :-)
			should_be_forwarded = true
		}
	}

	if should_be_forwarded {
		if circ.nextHop == nil {
			ReturnCellBuf(dec)
			return CloseCircuit(errors.New("cannot forward that!"), DESTROY_REASON_PROTOCOL)
		}

		circ.nextHop <- &RelayData{
			id:       circ.nextHopID,
			data:     dec,
			forRelay: true,
			rType:    cell.Command(),
		}
		return nil
	}

	defer ReturnCellBuf(dec)

	if rcell.Length()+11 > len(dec) {
		return CloseCircuit(errors.New("Malformed relay cell"), DESTROY_REASON_PROTOCOL)
	}

	return c.handleRelayDecrypted(circ, cell, &rcell)
}

func (c *OnionConnection) handleRelayDecrypted(circ *Circuit, cell Cell, rcell *RelayCell) ActionableError {
	var err ActionableError

	// At this point we established that the rcell is intended for us
	switch rcell.Command() {
	case RELAY_DATA:
		err = c.handleRelayData(circ, rcell)
	case RELAY_END:
		err = c.handleRelayEnd(circ, rcell)
	case RELAY_SENDME:
		err = c.handleRelaySendme(circ, rcell)
	case RELAY_BEGIN_DIR, RELAY_BEGIN:
		err = c.handleRelayBegin(circ, rcell)
	case RELAY_EXTEND:
		if cell.Command() == CMD_RELAY {
			err = CloseCircuit(errors.New("RELAY may not have an EXTEND command"), DESTROY_REASON_PROTOCOL)
			break
		}
		err = c.handleRelayExtend(circ, rcell)
	case RELAY_EXTEND2:
		if cell.Command() == CMD_RELAY {
			err = CloseCircuit(errors.New("RELAY may not have an EXTEND command"), DESTROY_REASON_PROTOCOL)
			break
		}
		err = c.handleRelayExtend2(circ, rcell)
	case RELAY_RESOLVE:
		err = c.handleRelayResolve(circ, rcell)
	case RELAY_DROP:
		// Ignore
	default:
		err = CloseCircuit(fmt.Errorf("Don't know a command %s: %v", rcell.Command(), rcell), DESTROY_REASON_PROTOCOL)
	}

	if err != nil {
		switch err.Handle() {
		case ERROR_CLOSE_STREAM, ERROR_REFUSE_STREAM:
			streamID := rcell.StreamID()
			if streamID == 0 {
				err = CloseConnection(fmt.Errorf("Got a ERROR_REFUSE_STREAM for StreamID=0. Original error: %s", err))
				break
			}

			if err.Handle() == ERROR_REFUSE_STREAM {
				Log(LOG_CIRC, "Refusing stream: %s", err)
			} else {
				Log(LOG_CIRC, "Closing stream: %s", err)

				stream, ok := circ.streams[streamID]
				if !ok {
					err = CloseCircuit(fmt.Errorf("Got ERROR_CLOSE_STREAM for unknown Stream. Original: %s", err), DESTROY_REASON_PROTOCOL)
					break
				}

				delete(circ.streams, streamID)
				stream.Destroy()
			}
			err = c.sendRelayCell(circ, streamID, BackwardDirection, RELAY_END, []byte{byte(err.StreamEndReason())})
		}
	}

	return err
}

func (c *OnionConnection) handleRelayBegin(circ *Circuit, cell *RelayCell) ActionableError {
	streamID := cell.StreamID()
	isDir := cell.Command() == RELAY_BEGIN_DIR

	_, alreadyExists := circ.streams[streamID]
	if alreadyExists {
		return CloseCircuit(errors.New("We already have a stream with that ID"), DESTROY_REASON_PROTOCOL)
	}

	if isDir && c.parentOR.config.DirPort == 0 {
		return RefuseStream(errors.New("We're no directory."), STREAM_REASON_NOTDIRECTORY)
	}

	var addr string
	if isDir {
		addr = fmt.Sprintf("127.0.0.1:%d", c.parentOR.config.DirPort)
	} else {
		for i := 0; i < cell.Length(); i++ {
			if cell.Data()[i] == 0 {
				addr = string(cell.Data()[0:i])
				break
			}
		}
		// XXX handle flags
	}

	if addr == "" {
		return RefuseStream(errors.New("No address found"), STREAM_REASON_TORPROTOCOL)
	}

	matches := regex_streamtarget.FindStringSubmatch(addr)
	if matches == nil {
		return RefuseStream(fmt.Errorf("Refusing to connect to %q as it does not look valid", addr), STREAM_REASON_TORPROTOCOL)
	}

	port, _ := strconv.ParseUint(matches[2], 10, 64)
	if port > 65535 {
		return CloseStream(errors.New("invalid port in RELAY_BEGIN"), STREAM_REASON_TORPROTOCOL)
	}

	Log(LOG_CIRC, "Opening stream to %s", addr)

	stream, err := NewStream(streamID)
	if err != nil {
		return RefuseStream(err, STREAM_REASON_INTERNAL)
	}

	circ.streams[streamID] = stream
	go stream.Run(circ.id, circ.backwardWindow, c.circuitReadQueue, matches[1], uint16(port), isDir, c.parentOR.config.ExitPolicy)

	return nil
}

func (c *OnionConnection) sendRelayCell(circ *Circuit, stream StreamID, direction DataDirection, command RelayCommand, data []byte) ActionableError {
	if len(data) > MAX_RELAY_LEN {
		panic("Somehow we're trying to send a massive cell")
	}

	var crypto DirectionalCircuitState // XXX When would forward be relevant here?
	if direction == ForwardDirection {
		crypto = circ.forward
	} else {
		crypto = circ.backward
	}

	cell := NewCell(c.negotiatedVersion, circ.id, CMD_RELAY, nil)
	buf := cell.Data()

	// The rest will be crypto'd
	buf[0] = byte(command)
	buf[1] = 0 // recognized
	buf[2] = 0
	BigEndian.PutUint16(buf[3:5], uint16(stream))

	// placeholder for digest

	if data != nil && len(data) != 0 {
		BigEndian.PutUint16(buf[9:11], uint16(len(data)))
		copy(buf[11:], data)
	}

	crypto.digest.Write(buf)
	digest := crypto.digest.Sum(nil)
	buf[5] = digest[0]
	buf[6] = digest[1]
	buf[7] = digest[2]
	buf[8] = digest[3]

	// Now AES it
	crypto.cipher.Crypt(buf, buf)

	c.writeQueue <- cell.Bytes() // XXX this could deadlock

	return nil
}

func (c *OnionConnection) handleRelayEnd(circ *Circuit, cell *RelayCell) ActionableError {
	streamID := cell.StreamID()
	stream, ok := circ.streams[streamID]
	if !ok {
		Log(LOG_INFO, "Ignoring RELAY_END for non-existent stream")
		return nil
	}

	delete(circ.streams, streamID)
	stream.Destroy()

	return nil
}

func (c *OnionConnection) handleRelaySendme(circ *Circuit, cell *RelayCell) ActionableError {
	if cell.StreamID() == 0 {
		circ.backwardWindow.Refill(100)
	} else {
		stream, ok := circ.streams[cell.StreamID()]
		if !ok {
			Log(LOG_CIRC, "Ignoring SENDME for unknown stream")
			return nil // Sure, that's ok
		}

		stream.backwardWindow.Refill(50)
	}
	return nil
}

func (c *OnionConnection) handleRelayData(circ *Circuit, cell *RelayCell) ActionableError {
	circ.forwardWindow--
	if circ.forwardWindow <= 900 {
		if err := c.sendRelayCell(circ, 0, BackwardDirection, RELAY_SENDME, nil); err != nil {
			return err
		}
		circ.forwardWindow += 100
	}

	streamID := cell.StreamID()
	stream, ok := circ.streams[streamID]
	if !ok {
		Log(LOG_INFO, "ignoring data for stream we don't know")
		return nil
	}

	ok = stream.forwardWindow.TryTake()
	if !ok {
		return CloseStream(errors.New("Refusing to overflow window"), STREAM_REASON_TORPROTOCOL)
	}

	data := cell.Data()
	// gotta copy that
	dataCopy := GetCellBuf(false)
	copy(dataCopy, data)

	stream.writeChan <- dataCopy[0:len(data)]

	return nil
}

func (c *OnionConnection) handleRelayResolve(circ *Circuit, cell *RelayCell) ActionableError {
	stream := cell.StreamID()
	if stream == 0 {
		return CloseCircuit(errors.New("No Circuit ID for RELAY_RESOLVE"), DESTROY_REASON_PROTOCOL)
	}

	data := cell.Data()
	var firstZero int
	for i, ch := range data {
		if ch == 0 {
			firstZero = i
			break
		}
	}
	if firstZero == 0 {
		return CloseCircuit(errors.New("No DNS name given in RELAY_RESOLVE"), DESTROY_REASON_PROTOCOL)
	}

	dnsName := string(data[:firstZero])
	ResolveDNSAsync(dnsName, circ.id, stream, c.circuitReadQueue)

	return nil
}
