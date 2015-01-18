// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/tvdw/openssl"
	"golang.org/x/crypto/curve25519"
)

type HandshakeType uint16

const (
	HANDSHAKE_TAP  HandshakeType = 0x00
	HANDSHAKE_NTOR HandshakeType = 0x02
)

var dhKeyStr = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"
var dhKey []byte
var funnyNtorHandshake = []byte("ntorNTORntorNTOR")

func (c *OnionConnection) handleCreateFast(cell Cell) ActionableError {
	// XXX check for weAuthenticated (why?)

	circID := cell.CircID()
	Log(LOG_CIRC, "Got a CREATE_FAST for CircID %d", circID)

	if circID == 0 {
		return CloseConnection(errors.New("refusing to create CircID=0"))
	}

	if circID.MSB(c.negotiatedVersion) == c.isOutbound {
		return CloseConnection(fmt.Errorf("refusing an invalid CircID %d %t", circID, c.isOutbound))
	}

	_, alreadyExists := c.circuits[cell.CircID()]
	if alreadyExists {
		return CloseConnection(errors.New("Circuit already exists"))
	}

	writeCell := NewCell(c.negotiatedVersion, circID, CMD_CREATED_FAST, nil)
	writeCellData := writeCell.Data()

	CRandBytes(writeCellData[0:20])

	// Generate a key
	var tmp [40]byte
	copy(tmp[0:20], cell.Data()[0:20])
	copy(tmp[20:40], writeCellData[0:20])
	keyData := KDFTOR(92, tmp[:])

	copy(writeCellData[20:40], keyData[0:20])

	circ := NewCircuit(circID, keyData[20:40], keyData[40:60], keyData[60:76], keyData[76:92])
	c.circuits[circID] = circ

	c.writeQueue <- writeCell.Bytes()

	return nil
}

func (c *OnionConnection) handleCreate(cell Cell, newHandshake bool) ActionableError {
	data := cell.Data()
	handshake := HANDSHAKE_TAP

	Log(LOG_CIRC, "Got a CREATE")

	circID := cell.CircID()
	if circID.MSB(c.negotiatedVersion) == c.isOutbound {
		return CloseConnection(fmt.Errorf("refusing an invalid CircID %d %t", circID, c.isOutbound))
	}

	if circID == 0 {
		return CloseConnection(errors.New("Not creating a circuit with id=0"))
	}

	var handshakeData []byte

	if newHandshake {
		handshake = HandshakeType(BigEndian.Uint16(data[0:2]))
		length := int(BigEndian.Uint16(data[2:4]))
		if length > len(data)-4 {
			return RefuseCircuit(errors.New("malformed CREATE cell"), DESTROY_REASON_PROTOCOL)
		}
		handshakeData = data[4 : length+4]
	} else {
		isNtor := true
		for i, v := range funnyNtorHandshake {
			if data[i] != v {
				isNtor = false
				break
			}
		}
		if isNtor {
			handshake = HANDSHAKE_NTOR
			handshakeData = data[16 : len(data)-16]
		} else {
			handshake = HANDSHAKE_TAP
			handshakeData = data
		}
	}

	if handshake == HANDSHAKE_TAP {
		return c.handleCreateTAP(cell.CircID(), handshakeData, newHandshake)
	} else if handshake == HANDSHAKE_NTOR {
		return c.handleCreateNTOR(cell.CircID(), handshakeData, newHandshake)
	}

	return RefuseCircuit(errors.New("unknown handshake"), DESTROY_REASON_PROTOCOL)
}

func (c *OnionConnection) handleCreateTAP(id CircuitID, data []byte, newHandshake bool) ActionableError {
	theirData, err := HybridDecrypt(c.parentOR.onionKey, data[0:186])
	if err != nil {
		return RefuseCircuit(err, DESTROY_REASON_INTERNAL)
	}

	if len(theirData) != 128 {
		return RefuseCircuit(errors.New("invalid TAP handshake found"), DESTROY_REASON_INTERNAL)
	}

	if dhKey == nil {
		key, err := hex.DecodeString(dhKeyStr)
		if err != nil || key[0] != 255 || key[8] != 0xc9 {
			panic(err)
		}
		dhKey = key
	}

	dh, err := openssl.LoadDHFromBignumWithGenerator(dhKey, 2)
	if err != nil {
		return RefuseCircuit(err, DESTROY_REASON_INTERNAL)
	}

	pub, err := dh.GetPublicKey()
	if err != nil {
		return RefuseCircuit(err, DESTROY_REASON_INTERNAL)
	}

	secr, err := dh.GetSharedKey(theirData)
	if err != nil {
		return RefuseCircuit(err, DESTROY_REASON_INTERNAL)
	}

	keyData := KDFTOR(92, secr)

	cmd := CMD_CREATED2
	if !newHandshake {
		cmd = CMD_CREATED
	}
	writeCell := NewCell(c.negotiatedVersion, id, cmd, nil)
	buf := writeCell.Data()

	if !newHandshake {
		copy(buf[0:128], pub)
		copy(buf[128:148], keyData[0:20])
	} else {
		buf[0] = 0
		buf[1] = 148
		copy(buf[2:130], pub)
		copy(buf[130:150], keyData[0:20])
	}

	circ := NewCircuit(id, keyData[20:40], keyData[40:60], keyData[60:76], keyData[76:92])
	c.circuits[id] = circ

	c.writeQueue <- writeCell.Bytes()
	return nil
}

func (c *OnionConnection) handleCreateNTOR(circID CircuitID, data []byte, newHandshake bool) ActionableError {
	if len(data) < 84 {
		return RefuseCircuit(errors.New("didn't get enough data"), DESTROY_REASON_PROTOCOL)
	}

	_, alreadyThere := c.circuits[circID]
	if alreadyThere {
		return CloseConnection(errors.New("nope"))
	}

	fingerprint := data[0:20]
	myFingerprint := c.usedTLSCtx.Fingerprint
	for i, v := range fingerprint {
		if v != myFingerprint[i] {
			Log(LOG_INFO, "FP mismatch %s != %s", myFingerprint, fingerprint)
			return RefuseCircuit(errors.New("that's not me"), DESTROY_REASON_PROTOCOL)
		}
	}

	var key_X [32]byte
	copy(key_X[:], data[52:84])

	mExpand := []byte("ntor-curve25519-sha256-1:key_expand")
	tKey := []byte("ntor-curve25519-sha256-1:key_extract")
	tMac := []byte("ntor-curve25519-sha256-1:mac")
	tVerify := []byte("ntor-curve25519-sha256-1:verify")

	var key_y [32]byte
	CRandBytes(key_y[:])
	key_y[0] &= 248
	key_y[31] &= 127
	key_y[31] |= 64
	var key_Y [32]byte
	curve25519.ScalarBaseMult(&key_Y, &key_y)

	var buffer bytes.Buffer

	var tmpHolder [32]byte
	curve25519.ScalarMult(&tmpHolder, &key_y, &key_X)
	buffer.Write(tmpHolder[:])

	curve25519.ScalarMult(&tmpHolder, &c.parentOR.ntorPrivate, &key_X)
	buffer.Write(tmpHolder[:])

	buffer.Write(fingerprint)
	buffer.Write(c.parentOR.ntorPublic[:])
	buffer.Write(key_X[:])
	buffer.Write(key_Y[:])
	buffer.Write([]byte("ntor-curve25519-sha256-1"))

	secretInput := buffer.Bytes()
	kdf := KDFHKDF(72, secretInput, tKey, mExpand)

	hhmac := hmac.New(sha256.New, tVerify)
	hhmac.Write(secretInput)
	verify := hhmac.Sum(nil)

	buffer.Reset()
	buffer.Write(verify)
	buffer.Write(fingerprint)
	buffer.Write(c.parentOR.ntorPublic[:])
	buffer.Write(key_Y[:])
	buffer.Write(key_X[:])
	buffer.Write([]byte("ntor-curve25519-sha256-1Server"))
	authInput := buffer.Bytes()

	hhmac = hmac.New(sha256.New, tMac)
	hhmac.Write(authInput)
	auth := hhmac.Sum(nil)

	// XXX check for infinity

	cmd := CMD_CREATED2
	if !newHandshake {
		cmd = CMD_CREATED
	}
	writeCell := NewCell(c.negotiatedVersion, circID, cmd, nil)
	writeCellBuf := writeCell.Data()
	if newHandshake {
		writeCellBuf[0] = 0
		writeCellBuf[1] = 64
		copy(writeCellBuf[2:34], key_Y[:])
		copy(writeCellBuf[34:], auth)
	} else {
		copy(writeCellBuf[0:32], key_Y[:])
		copy(writeCellBuf[32:], auth)
	}

	circ := NewCircuit(circID, kdf[0:20], kdf[20:40], kdf[40:56], kdf[56:72])
	c.circuits[circID] = circ

	c.writeQueue <- writeCell.Bytes()

	return nil
}
