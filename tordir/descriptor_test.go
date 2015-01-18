// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tordir

import (
	"crypto/rand"
	"github.com/tvdw/openssl"
	"golang.org/x/crypto/curve25519"
	"log"
	"net"
	"testing"
	"time"
)

func TestBasic(t *testing.T) {
	var priv, pub [32]byte
	rand.Read(priv[:])
	curve25519.ScalarBaseMult(&pub, &priv)

	var d Descriptor
	d.Nickname = "mylittletorry18"
	d.Contact = "TvdW"
	d.Platform = "Tor 0.2.6.2-alpha on MS-DOS"
	d.Address = net.ParseIP("80.57.124.58")
	d.ORPort = 1234
	d.UptimeStart = time.Now()
	d.NTORKey = pub[:]
	d.BandwidthAvg = 1000000
	d.BandwidthBurst = 1200000
	d.BandwidthObserved = 30107
	k, err := openssl.GenerateRSAKeyWithExponent(1024, 65537)
	if err != nil {
		t.Error(err)
	}
	d.OnionKey, err = openssl.GenerateRSAKeyWithExponent(1024, 65537)
	d.SigningKey = k
	desc, err := d.SignedDescriptor()
	if err != nil {
		t.Error(err)
	}

	log.Println(desc)
}
