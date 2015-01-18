// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"net"
	"github.com/miekg/dns"
)

type DNSAddress struct {
	Type  byte
	TTL   int
	Value []byte
}

type DNSResult struct {
	NeverForRelay
	NoBuffers
	circuitID CircuitID
	streamID  StreamID

	Results []DNSAddress
}

func (dr *DNSResult) CircID() CircuitID {
	return dr.circuitID
}

func (da DNSAddress) String() string {
	if da.Type == 4 {
		return net.IPv4(da.Value[0], da.Value[1], da.Value[2], da.Value[3]).String()
	} else if da.Type == 6 {
		return "[" + net.IP(da.Value).String() + "]"
	} else {
		return "error"
	}
}

var dnsClient = new(dns.Client)
var config, _ = dns.ClientConfigFromFile("/etc/resolv.conf")

func ResolveDNS(host string) []DNSAddress {
	parsedIP := net.ParseIP(host)
	if parsedIP != nil {
		v := parsedIP.To16()
		t := byte(6)
		if parsedIP.To4() != nil {
			v = parsedIP.To4()
			t = 4
		}
		return []DNSAddress{
			DNSAddress{
				Value: []byte(v),
				Type:  t,
				TTL:   86400, // XXX
			},
		}
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA) //XXX will this stop us from getting AAAA?
	in, _, err := dnsClient.Exchange(m, config.Servers[0]+":"+config.Port)
	if err != nil {
		return []DNSAddress{DNSAddress{0xF0, 0, nil}}
	}

	var r []DNSAddress
	for _, answer := range in.Answer {
		if a, ok := answer.(*dns.A); ok {
			r = append(r, DNSAddress{
				Value: []byte(a.A.To4()),
				Type: 4,
				TTL: int(a.Hdr.Ttl),
			})
		}
		if aaaa, ok := answer.(*dns.AAAA); ok {
			r = append(r, DNSAddress{
				Value: []byte(aaaa.AAAA.To16()),
				Type: 6,
				TTL: int(aaaa.Hdr.Ttl),
			})
		}
	}
	if len(r) == 0 {
		return []DNSAddress{DNSAddress{0xF1, 0, nil}}
	}
	return r
}

func ResolveDNSAsync(host string, circ CircuitID, stream StreamID, resultChan CircReadQueue) {
	go func() { // XXX this can be a lot faster and we really don't need a goroutine for each.
		result := ResolveDNS(host)
		resultChan <- &DNSResult{
			circuitID: circ,
			streamID:  stream,
			Results:   result,
		}
	}()
}

func (dr *DNSResult) Handle(c *OnionConnection, circ *Circuit) ActionableError {
	var buf [MAX_RELAY_LEN]byte
	pos := 0
	for _, item := range dr.Results {
		if len(item.Value) > 255 {
			panic("Huh? I thought we're talking IP addresses")
		}
		if len(buf)-pos-6-len(item.Value) < 0 {
			break
		}
		buf[pos] = item.Type
		buf[pos+1] = byte(len(item.Value))
		copy(buf[pos+2:], []byte(item.Value))
		pos += 2 + len(item.Value)
		BigEndian.PutUint32(buf[pos:pos+4], uint32(item.TTL))
		pos += 4
	}

	return c.sendRelayCell(circ, dr.streamID, BackwardDirection, RELAY_RESOLVED, buf[:pos])
}
