// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"
)

const debugLevel = LOG_NOTICE

const (
	LOG_DEBUG  = 6
	LOG_PROTO  = 5
	LOG_CIRC   = 4
	LOG_INFO   = 3
	LOG_NOTICE = 2
	LOG_WARN   = 1
)

var levels = []string{
	"warn",
	"notice",
	"info",
	"circ",
	"proto",
	"debug",
}

func Log(level byte, format string, args ...interface{}) {
	if level <= debugLevel {
		text := fmt.Sprintf(format, args...)
		log.Print(levels[level-1], " ", text)
	}
}
