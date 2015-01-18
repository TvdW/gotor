// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
)

type Config struct {
	IsPublicServer bool
	ORPort         uint16
	DirPort        uint16
	DataDirectory  string

	// Descriptor related only
	Contact, Nickname, Platform, Address            string
	BandwidthAvg, BandwidthBurst, BandwidthObserved int
	Family                                          []string

	ExitPolicy ExitPolicy
}

func (c *Config) ReadFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}

	re := regexp.MustCompile(`^\s*(?:([a-zA-Z0-9]+)\s+([^#]+?))?\s*(?:#.*)?$`)
	policyRe := regexp.MustCompile(`^((?:accept|reject)(?:6?))\s+(\*|(?:[0-9]{1,3}\.){3}[0-9]{1,3}):(\*|[1-9][0-9]{0,4})$`)
	familyRe := regexp.MustCompile(`^(?:(?:\$[a-fA-F0-9]{40})[ ,]?)+$`)
	familySplit := regexp.MustCompile(`[, ]+`)
	bandwidthRe := regexp.MustCompile(`^(?i)([0-9]+)\s*(bytes?|kbytes?|mbytes?|gbytes?|kbits?|mbits?|gbits?)$`)

	sc := bufio.NewScanner(file)
	for sc.Scan() {
		matches := re.FindStringSubmatch(sc.Text())
		if matches == nil {
			return errors.New(fmt.Sprintf("Could not parse line: %q", sc.Text()))
		}
		if len(matches[1]) == 0 && len(matches[2]) != 0 {
			panic("Parser bug?")
		}
		if len(matches[1]) == 0 {
			continue
		}

		lower := strings.ToLower(matches[1])
		switch lower {
		case "orport":
			port, err := strconv.ParseUint(matches[2], 0, 16)
			if err != nil {
				return err //XXX
			}
			c.ORPort = uint16(port)

		case "bandwidthrate", "bandwidthburst", "maxadvertisedbandwidth":
			bw := bandwidthRe.FindStringSubmatch(matches[2])
			if bw == nil {
				return fmt.Errorf("Could not parse %s %q", matches[1], matches[2])
			}

			val_, err := strconv.ParseInt(bw[1], 0, 16)
			if err != nil {
				return err
			}

			val := int(val_)

			switch strings.ToLower(bw[2]) {
			case "byte", "bytes":
				val *= 1
			case "kbyte", "kbytes":
				val *= 1000
			case "mbyte", "mbytes":
				val *= 1000000
			case "gbyte", "gbytes":
				val *= 1000000000
			case "kbit", "kbits":
				val *= 125
			case "mbit", "mbits":
				val *= 125000
			case "gbit", "gbits":
				val *= 125000000
			}

			if lower == "bandwidthrate" {
				c.BandwidthAvg = val
			} else if lower == "bandwidthburst" {
				c.BandwidthBurst = val
			} else if lower == "maxadvertisedbandwidth" {
				c.BandwidthObserved = val
			}

		case "datadirectory":
			c.DataDirectory = matches[2]

		case "nickname":
			c.Nickname = matches[2]

		case "contactinfo":
			c.Contact = matches[2]

		case "myfamily":
			m := familyRe.FindStringSubmatch(matches[2])
			if len(m) == 0 {
				return errors.New(fmt.Sprintf("could not parse MyFamily %q\n", matches[2]))
			}
			c.Family = familySplit.Split(m[0], -1)

		case "exitpolicy":
			m := policyRe.FindStringSubmatch(matches[2])
			if m == nil {
				return errors.New(fmt.Sprintf("Could not parse ExitPolicy %q\n", matches[2]))
			}
			rule := ExitRule{}
			if m[1] == "accept" || m[1] == "accept6" {
				rule.Action = true
			} else {
				rule.Action = false
			}
			if m[len(m)-1] == "6" {
				rule.V6 = true
			}
			if m[3] != "*" {
				port, err := strconv.ParseUint(m[3], 0, 16)
				if err != nil {
					return err //XXX
				}
				rule.Port = uint16(port)
			}
			if m[2] != "*" {
				log.Panicln("not implemented: address parsing") //XXX
			}
			c.ExitPolicy.Rules = append(c.ExitPolicy.Rules, rule)

		case "address":
			c.Address = matches[2]

		default:
			log.Printf("Configuration option %q not recognized. Ignoring its value\n", matches[1])
		}
	}

	return nil
}
