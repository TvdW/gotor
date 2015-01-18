// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
)

type ConnectionHint struct {
	fp      *Fingerprint
	address [][]byte
}

func (c *ConnectionHint) AddFingerprint(fp []byte) error {
	if c.fp != nil {
		return errors.New("already have a fingerprint")
	}

	if len(fp) != 20 {
		return errors.New("that's no fingerprint")
	}

	c.fp = new(Fingerprint)
	copy(c.fp[:], fp)

	return nil
}

func (c *ConnectionHint) GetFingerprint() *Fingerprint {
	return c.fp
}

func (c *ConnectionHint) AddAddress(addr []byte) error {
	if len(addr) != 6 && len(addr) != 18 {
		return errors.New("not an address we recognize")
	}

	dup := make([]byte, len(addr))
	copy(dup, addr)
	if c.address == nil {
		c.address = make([][]byte, 0, 2)
	}

	c.address = append(c.address, dup)

	return nil
}

func (c *ConnectionHint) GetAddresses() []string {
	if c.address == nil {
		return nil
	}

	addrs := make([]string, 0, len(c.address))
	for _, addr := range c.address {
		if len(addr) == 6 {
			v4 := fmt.Sprintf("%d.%d.%d.%d:%d", addr[0], addr[1], addr[2], addr[3], ((int(addr[4]) << 8) + int(addr[5])))
			addrs = append(addrs, v4)
		} else if len(addr) == 18 {
			v6 := fmt.Sprintf("[%X:%X:%X:%X:%X:%X:%X:%X]:%d",
				addr[0:2], addr[2:4], addr[4:6], addr[6:8],
				addr[8:10], addr[10:12], addr[12:14], addr[14:16],
				(int(addr[16])<<8)+int(addr[17]))
			addrs = append(addrs, v6)
		}
	}

	return addrs
}
