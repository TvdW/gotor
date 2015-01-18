// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"github.com/tvdw/openssl"
	"hash"
	"io"
	"net"
	"time"
)

const OUR_MIN_VERSION = 4
const OUR_MAX_VERSION = 4

type LinkVersion uint16

func (c *OnionConnection) negotiateVersionServer(conn io.Reader) error {
	readCell := GetCellBuf(false)
	defer ReturnCellBuf(readCell)

	// We expect a VERSIONS cell first...
	totalRead := 0
	for totalRead < 5 {
		bytes, err := conn.Read(readCell[totalRead:5])
		totalRead += bytes
		if err != nil {
			return err
		}
	}

	// We now have the head of the variable length cell. Check whether it makes any sense
	circID := CircuitID(BigEndian.Uint16(readCell[0:2]))
	command := Command(readCell[2])
	length := int(BigEndian.Uint16(readCell[3:5]))
	if (command != CMD_VERSIONS) || length == 0 || (length > 1024) || (length%2 != 0) || (circID != 0) {
		return errors.New("Dropping connection - VERSIONS cell seems weird")
	}

	// Read the rest of the VERSIONS cell
	buf := make([]byte, length)

	totalRead = 0
	for totalRead < length {
		bytes, err := conn.Read(buf[totalRead:])
		totalRead += bytes
		if err != nil {
			return err
		}
	}

	bestVersion := LinkVersion(0)
	for i := 0; i < (length / 2); i++ {
		version := LinkVersion(BigEndian.Uint16(buf[(i * 2):(i*2 + 2)]))
		if version < OUR_MIN_VERSION {
			continue
		}
		if version > OUR_MAX_VERSION {
			continue
		}
		if version > bestVersion {
			bestVersion = version
		}
	}

	if bestVersion == 0 {
		ssl := conn.(*openssl.Conn)
		Log(LOG_INFO, "unknown versions data: %v %v", buf, ssl.RemoteAddr())
		return errors.New("Failed to negotiate a version")
	}

	c.negotiatedVersion = bestVersion

	writeCell := GetCellBuf(false)
	writeCell = writeCell[0:7]
	writeCell[0] = 0
	writeCell[1] = 0
	writeCell[2] = byte(CMD_VERSIONS)
	writeCell[3] = 0
	writeCell[4] = 2
	BigEndian.PutUint16(writeCell[5:7], uint16(c.negotiatedVersion))

	c.writeQueue <- writeCell

	return nil
}

func (c *OnionConnection) negotiateVersionClient(conn io.Reader, readHash, writeHash hash.Hash) error {
	// Send a VERSIONS cell with the versions we support, then wait for their reply
	writeCell := GetCellBuf(false)
	writeCell = writeCell[0 : 5+(2*(OUR_MAX_VERSION-OUR_MIN_VERSION+1))]
	writeCell[0] = 0
	writeCell[1] = 0
	writeCell[2] = byte(CMD_VERSIONS)
	writeCell[3] = 0
	writeCell[4] = 2 * (OUR_MAX_VERSION - OUR_MIN_VERSION + 1)
	for i, v := 0, OUR_MIN_VERSION; v <= OUR_MAX_VERSION; v++ {
		writeCell[5+i] = 0
		writeCell[6+i] = byte(v)

		i += 2
	}
	writeHash.Write(writeCell)
	c.writeQueue <- writeCell

	var head [5]byte
	gotBytes := 0
	for gotBytes < 5 {
		bytes, err := conn.Read(head[gotBytes:])
		gotBytes += bytes
		if err != nil {
			return err
		}
	}
	readHash.Write(head[:])

	if head[0] != 0 || head[1] != 0 || head[2] != 7 {
		return errors.New("Doesn't look like a VERSIONS cell")
	}
	length := int(BigEndian.Uint16(head[3:5]))
	if length <= 0 {
		return errors.New("that's no VERSIONS cell")
	}
	if length > 1024 {
		return errors.New("incredibly long VERSIONS cell found")
	}

	readBuf := make([]byte, length)
	gotBytes = 0
	for gotBytes < length {
		bytes, err := conn.Read(readBuf[gotBytes:])
		gotBytes += bytes
		if err != nil {
			return err
		}
	}
	readHash.Write(readBuf)

	best := 0
	for i := 0; i < gotBytes; i += 2 {
		vers := int(BigEndian.Uint16(readBuf[i : i+2]))
		if vers >= OUR_MIN_VERSION && vers <= OUR_MAX_VERSION && vers > best {
			best = vers
		}
	}

	if best == 0 {
		return errors.New("No versions in common")
	}

	c.negotiatedVersion = LinkVersion(best)

	return nil
}

func (c *OnionConnection) sendCerts(writeHash hash.Hash) error { // Now that we've established a version, we need to send our CERTS
	var der1, der2 []byte
	var type1, type2 byte
	if c.isOutbound {
		type1 = 3
		der1 = c.usedTLSCtx.AuthCertDER
	} else {
		type1 = 1
		der1 = c.usedTLSCtx.LinkCertDER
	}
	type2 = 2
	der2 = c.usedTLSCtx.IdCertDER

	certsLen := 1 + (1 + 2 + len(der1)) + (1 + 2 + len(der2))
	cell := NewVarCell(c.negotiatedVersion, 0, CMD_CERTS, nil, certsLen)
	buf := cell.Data() // XXX we still have the 2 length bytes there, lol

	buf[2] = 2 // 2 certs
	buf[3] = type1
	BigEndian.PutUint16(buf[4:6], uint16(len(der1)))
	copy(buf[6:], der1)
	ptr := 6 + len(der1)
	buf[ptr] = type2
	BigEndian.PutUint16(buf[ptr+1:ptr+3], uint16(len(der2)))
	copy(buf[ptr+3:], der2)

	if writeHash != nil {
		writeHash.Write(cell.Bytes())
	}
	c.writeQueue <- cell.Bytes()

	return nil
}

func (c *OnionConnection) sendNetinfo(writeHash hash.Hash) error {
	cell := NewCell(c.negotiatedVersion, 0, CMD_NETINFO, nil)
	buf := cell.Data()

	// XXX TODO
	t := time.Now().Unix()
	BigEndian.PutUint32(buf[0:4], uint32(t))
	buf[4] = 4
	buf[5] = 4
	buf[6] = 10
	buf[7] = 0
	buf[8] = 0
	buf[9] = 1

	myIP := net.ParseIP(c.parentOR.config.Address)
	buf[10] = 1
	buf[11] = 4
	buf[12] = 4

	ip := myIP.To4()
	copy(buf[13:], ip) //XXX v6

	if writeHash != nil { // XXX
		writeHash.Write(cell.Bytes())
	}
	c.writeQueue <- cell.Bytes()

	return nil
}

func (c *OnionConnection) sendAuthChallenge() error {
	var buf bytes.Buffer
	if c.negotiatedVersion >= 4 {
		buf.Write([]byte{0, 0}) // XXX This is a pretty dirty hack. use NewVarCell() instead
	}
	buf.Write([]byte{0, 0, byte(CMD_AUTH_CHALLENGE), 0, (4 + 32)})

	var challenge [32]byte
	CRandBytes(challenge[:])
	buf.Write(challenge[:])
	buf.Write([]byte{0, 1, 0, 1})

	c.writeQueue <- buf.Bytes()

	return nil
}

func (c *OnionConnection) handleAuthChallenge(cell Cell, hashInbound, hashOutbound hash.Hash, conn *openssl.Conn) error {
	if c.weAuthenticated {
		return errors.New("But we already authenticated...")
	}
	if !c.theyAuthenticated {
		return errors.New("But we have no idea who they are...")
	}
	c.weAuthenticated = true

	// Start inspecting the actual data
	data := cell.Data()
	if len(data) < 38 { // This includes the 2 length bytes of the varlen cell
		return errors.New("cell too impossibly short")
	}
	//challengeData := data[2:34]
	methodCount := int(BigEndian.Uint16(data[34:36]))
	if len(data) != 36+(2*methodCount) {
		return errors.New("cell size is wrong")
	}

	canAuth := false
	for i := 0; i < methodCount; i++ {
		if data[36+2*i] == 0 && data[37+2*i] == 1 {
			canAuth = true
		}
	}

	if !canAuth {
		Log(LOG_INFO, "looks like they invented a new AUTHENTICATE thing")
		return nil // It's fine
	}

	if err := c.sendCerts(hashOutbound); err != nil {
		return err
	}

	// Send AUTHENTICATE
	var buf bytes.Buffer
	sha := sha256.New()

	buf.Write([]byte{0, 1, 0, 0})
	buf.Write([]byte("AUTH0001"))
	buf.Write(c.usedTLSCtx.Fingerprint256)
	buf.Write(c.theirFingerprint256)
	buf.Write(hashInbound.Sum(nil))
	buf.Write(hashOutbound.Sum(nil))

	theirCert, err := conn.PeerCertificate()
	if err != nil {
		return err
	}
	DER, err := theirCert.MarshalDER()
	if err != nil {
		return err
	}
	sha.Write(DER)
	buf.Write(sha.Sum(nil))

	mac := hmac.New(sha256.New, conn.GetTLSSecret())
	mac.Write(conn.GetClientServerHelloRandom())
	mac.Write([]byte("Tor V3 handshake TLS cross-certification\x00"))
	buf.Write(mac.Sum(nil))

	// Add 24 random bytes
	var rand [24]byte
	CRandBytes(rand[:])
	buf.Write(rand[:])

	// Sign the rest and add the signature
	sha.Reset()
	sha.Write(buf.Bytes()[4:])
	digest := sha.Sum(nil)
	sig, err := c.usedTLSCtx.AuthKey.PrivateEncrypt(digest[:])
	if err != nil {
		return err
	}
	buf.Write(sig)

	tmpdata := buf.Bytes()
	BigEndian.PutUint16(tmpdata[2:4], uint16(len(tmpdata)-4))

	c.writeQueue <- NewVarCell(c.negotiatedVersion, 0, CMD_AUTHENTICATE, tmpdata, 0).Bytes()

	return nil
}

func (c *OnionConnection) handleCerts(cell Cell, cert *openssl.Certificate) error {
	data := cell.Data()
	if len(data) < 3 {
		return errors.New("way too short")
	}

	var typeHad [4]bool
	var fp Fingerprint
	var fp256 []byte

	numCerts := int(data[2])
	readPos := 3
	for i := 0; i < numCerts; i++ {
		if len(data) < readPos+3 {
			return errors.New("malformed CERTS")
		}

		cType := data[readPos]
		if cType < 1 || cType > 3 {
			return errors.New("no idea what to do with that certificate")
		}

		if typeHad[cType] {
			return errors.New("duplicate certificate in CERTS")
		}
		typeHad[cType] = true

		length := int(BigEndian.Uint16(data[readPos+1 : readPos+3]))
		readPos += 3
		if len(data) < readPos+length {
			return errors.New("malformed CERTS")
		}

		theCert, err := openssl.LoadCertificateFromDER(data[readPos : readPos+length])
		if err != nil {
			return err
		}

		// XXX todo: lots of checks

		if cType == 2 { // ID
			// Find the fingerprint
			pubkey, err := theCert.PublicKey()
			if err != nil {
				return err
			}

			keyDer, err := pubkey.MarshalPKCS1PublicKeyDER()
			if err != nil {
				return err
			}

			fingerprint := sha1.Sum(keyDer)
			copy(fp[:], fingerprint[:])

			sha := sha256.New()
			sha.Write(keyDer)
			fp256 = sha.Sum(nil)
		}

		readPos += length
	}

	Log(LOG_CIRC, "CERTS are looking good")

	if typeHad[2] { // ID
		c.theyAuthenticated = true
		copy(c.theirFingerprint[:], fp[:])
		c.theirFingerprint256 = fp256
	}

	return nil
}
