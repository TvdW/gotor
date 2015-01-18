// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"sync/atomic"
)

const (
	_ = iota
	STATCTR_CONNECTIONS
	STATCTR_CIRC_CREATE
	STATCTR_CIRC_DESTROY
	STATCTR_CIRC_CURRENT

	STATCTR_COUNT // must be last
)

var counts [STATCTR_COUNT]int32

func StatsUpd(t, val int32) int32 {
	n := atomic.AddInt32(&(counts[t]), val)
	return n
}

func StatsNewCircuit() {
	a := StatsUpd(STATCTR_CIRC_CREATE, 1)
	b := StatsUpd(STATCTR_CIRC_CURRENT, 1)
	Log(LOG_INFO, "Now have %d circuits (a total of %d were created)", b, a)
}

func StatsDestroyCircuit() {
	a := StatsUpd(STATCTR_CIRC_DESTROY, 1)
	b := StatsUpd(STATCTR_CIRC_CURRENT, -1)
	Log(LOG_INFO, "Now have %d circuits (a total of %d were destroyed)", b, a)
}

func StatsAddConnection() {
	a := StatsUpd(STATCTR_CONNECTIONS, 1)
	Log(LOG_INFO, "Now have %d connections", a)
}

func StatsRemoveConnection() {
	a := StatsUpd(STATCTR_CONNECTIONS, -1)
	Log(LOG_INFO, "Now have %d connections", a)
}

func StatsAddInput(bytes uint32) {
	//atomic.AddUint32(&counterInput, bytes)
}

func StatsAddOutput(bytes uint32) {
	//atomic.AddUint32(&counterOutput, bytes)
}

func RecordStats() (input, output uint32) {
	//input = atomic.SwapUint32(&counterInput, 0)
	//output = atomic.SwapUint32(&counterOutput, 0)
	return
}
