// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
)

type ExitRule struct {
	Address []byte
	Port    uint16
	Action  bool
	V6      bool
}

type ExitPolicy struct {
	// The "zero value" of this struct is a "reject *:*"
	Rules         []ExitRule
	DefaultAction bool
}

func (ep *ExitPolicy) AllowsConnect(addr []byte, port uint16) bool {
	for _, rule := range ep.Rules {
		if rule.Port == port || rule.Port == 0 { // "<something>:port" or "<something>:*"
			if rule.Address == nil { // "*:port" or "*:*"
				return rule.Action
			}

			if len(rule.Address) == len(addr) {
				matches := true
				for i := 0; i < len(addr); i++ {
					if rule.Address[i] != addr[i] {
						matches = false
						break
					}
				}
				if matches {
					return rule.Action
				}
			}
		}
	}

	return ep.DefaultAction
}

func (ep *ExitPolicy) Describe() (string, error) {
	var buf bytes.Buffer
	var v6buf bytes.Buffer

	for _, rule := range ep.Rules {
		if rule.V6 {

		} else {
			if rule.Action {
				buf.WriteString("accept ")
			} else {
				buf.WriteString("reject ")
			}

			if rule.Address != nil {
				panic("todo") // XXX BUG
			} else {
				buf.WriteString("*:")
			}

			if rule.Port != 0 {
				buf.WriteString(fmt.Sprintf("%d\n", rule.Port))
			} else {
				buf.WriteString("*\n")
			}
		}
	}

	return buf.String() + v6buf.String(), nil
}
