// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tordir

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/tvdw/openssl"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

type Descriptor struct {
	// Router definition
	Nickname string
	Address  net.IP
	ORPort   uint16
	DirPort  uint16

	BandwidthAvg, BandwidthBurst, BandwidthObserved int
	Platform                                        string
	LastPublished                                   time.Time
	Fingerprint                                     string
	Hibernating                                     bool
	UptimeStart                                     time.Time
	NTORKey                                         []byte
	SigningKey, OnionKey                            openssl.PrivateKey
	Accept, Reject, IPv6Policy                      string
	Contact                                         string
	Family                                          []string
	ReadHistory, WriteHistory                       []string
	EventDNS                                        bool
	CachesExtraInfo                                 bool
	ExtraInfoDigest                                 string
	HiddenServiceDir                                int
	AllowSingleHopExits                             bool
	ORAddress                                       []string
	GeoIPDBDigest                                   string
	GeoIP6DBDigest                                  string
	ExitPolicy                                      string
}

func (d *Descriptor) Validate() error {
	if d.Nickname == "" {
		return errors.New("Nickname is required")
	}
	if d.Address == nil {
		return errors.New("Address is required")
	}
	if d.ORPort == 0 && d.DirPort == 0 {
		return errors.New("A descriptor without ORPort or DirPort cannot be published")
	}
	if d.Platform == "" {
		return errors.New("platform is required")
	}
	if d.SigningKey == nil {
		return errors.New("A signing key is required")
	}
	if d.UptimeStart.IsZero() {
		return errors.New("no UptimeStart given")
	}
	if d.OnionKey == nil {
		return errors.New("No OnionKey given")
	}
	if d.NTORKey == nil {
		return errors.New("no NTORKey given")
	}
	return nil
}

func (d *Descriptor) SignedDescriptor() (string, error) {
	var buf, extra bytes.Buffer
	if err := d.Validate(); err != nil {
		return "", err
	}

	published := time.Now()

	keyDer, _ := d.SigningKey.MarshalPKCS1PublicKeyDER()
	fingerprint := sha1.Sum(keyDer)
	fp := fmt.Sprintf("%X %X %X %X %X %X %X %X %X %X",
		fingerprint[0:2], fingerprint[2:4], fingerprint[4:6], fingerprint[6:8], fingerprint[8:10],
		fingerprint[10:12], fingerprint[12:14], fingerprint[14:16], fingerprint[16:18], fingerprint[18:20],
	)

	buf.WriteString(fmt.Sprintf("router %s %s %d 0 %d\n", d.Nickname, d.Address, d.ORPort, d.DirPort))
	extra.WriteString(fmt.Sprintf("extra-info %s %X\n", d.Nickname, fingerprint))
	extra.WriteString(fmt.Sprintf("published %s\n", published.Format("2006-01-02 15:04:05")))

	for _, addr := range d.ORAddress {
		buf.WriteString(addr)
	}
	buf.WriteString(fmt.Sprintf("platform %s\n", d.Platform))
	buf.WriteString(fmt.Sprintf("protocols Link 1 2 Circuit 1\n")) // Is this really needed?
	buf.WriteString(fmt.Sprintf("published %s\n", published.Format("2006-01-02 15:04:05")))
	buf.WriteString(fmt.Sprintf("fingerprint %s\n", fp))
	buf.WriteString(fmt.Sprintf("uptime %d\n", published.Unix()-d.UptimeStart.Unix()+1))
	buf.WriteString(fmt.Sprintf("bandwidth %d %d %d\n", d.BandwidthAvg, d.BandwidthBurst, d.BandwidthObserved))
	extraDigest := sha1.Sum(extra.Bytes())
	buf.WriteString(fmt.Sprintf("extra-info-digest %X\n", extraDigest[:]))
	buf.WriteString(fmt.Sprintf("onion-key\n"))
	onion, err := d.OnionKey.MarshalPKCS1PublicKeyPEM()
	if err != nil {
		return "", err
	}
	buf.Write(onion)

	buf.WriteString(fmt.Sprintf("signing-key\n"))

	pub, err := d.SigningKey.MarshalPKCS1PublicKeyPEM()
	if err != nil {
		return "", err
	}
	buf.Write(pub)

	if len(d.Family) != 0 {
		buf.WriteString(fmt.Sprintf("family %s\n", strings.Join(d.Family, " ")))
	}
	if d.Hibernating {
		buf.WriteString(fmt.Sprintf("hibernating 1\n"))
	}
	if d.HiddenServiceDir != 0 {
		buf.WriteString(fmt.Sprintf("hidden-service-dir\n"))
	}
	if d.AllowSingleHopExits {
		buf.WriteString(fmt.Sprintf("allow-single-hop-exits\n"))
	}
	if d.Contact != "" {
		buf.WriteString(fmt.Sprintf("contact %s\n", d.Contact))
	}
	buf.WriteString(fmt.Sprintf("ntor-onion-key %s\n", base64.StdEncoding.EncodeToString(d.NTORKey)))
	buf.WriteString(d.ExitPolicy)
	buf.WriteString(fmt.Sprintf("router-signature\n"))

	digest := sha1.Sum(buf.Bytes())

	// Sign descriptor
	signature, err := d.SigningKey.PrivateEncrypt(digest[:])
	if err != nil {
		return "", err
	}
	pem.Encode(&buf, &pem.Block{
		Type:  "SIGNATURE",
		Bytes: signature,
	})

	// Sign extrainfo
	signature, err = d.SigningKey.PrivateEncrypt(extraDigest[:])
	if err != nil {
		return "", err
	}
	pem.Encode(&extra, &pem.Block{
		Type:  "SIGNATURE",
		Bytes: signature,
	})

	return buf.String() + extra.String(), nil
}

func (d *Descriptor) Publish(address string) error {
	where := fmt.Sprintf("http://%s/tor/", address)

	desc, err := d.SignedDescriptor()
	if err != nil {
		return err
	}
	resp, err := http.Post(where, "tor/descriptor", strings.NewReader(desc))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	//body, err := ioutil.ReadAll(resp.Body)
	//if err != nil {
	//	return err
	//}
	log.Println(resp)

	return nil
}
