// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"github.com/tvdw/cgolock"
	"log"
	"net/http"
	"os"
	"runtime"
	"time"
)

import _ "net/http/pprof"
import _ "expvar"

func main() {
	cgolock.Init(runtime.NumCPU())
	runtime.GOMAXPROCS(runtime.NumCPU())
	SetupRand()
	SeedCellBuf()

	torConfig := Config{
		IsPublicServer:    true,
		Platform:          "Tor 0.2.6.2-alpha on Go",
		BandwidthAvg:      1073741824,
		BandwidthBurst:    1073741824,
		BandwidthObserved: 1 << 16,
	}
	if err := torConfig.ReadFile(os.Args[1]); err != nil {
		log.Panicln(err)
	}

	or, err := NewOR(&torConfig)
	if err != nil {
		log.Panicln(err)
	}

	/*
		go func() {
			or.RequestCircuit(&CircuitRequest{
				localID: 5,
				connHint: ConnectionHint{
					address: [][]byte{[]byte{127,0,0,1,35,41}},
				},
			})
		}()
	*/

	anythingFinished := make(chan int)
	go func() {
		or.Run()
		anythingFinished <- 1
	}()
	go func() {
		Log(LOG_WARN, "%v", http.ListenAndServe("localhost:6060", nil))
	}()

	or.PublishDescriptor()

	nextRotate := time.After(time.Hour * 1)
	nextPublish := time.After(time.Hour * 18)
	for {
		select {
		case <-nextRotate: //XXX randomer intervals
			if err := or.RotateKeys(); err != nil {
				Log(LOG_WARN, "%v", err)
			}
			nextRotate = time.After(time.Hour * 1)

		case <-nextPublish:
			or.PublishDescriptor()
			nextPublish = time.After(time.Hour * 18)

		case <-anythingFinished:
			log.Panicln("Somehow a main.go goroutine we spawned managed to finish, which is not good")
		}
	}
}
