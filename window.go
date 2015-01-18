// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"sync"
)

type Window struct {
	cond   *sync.Cond
	window int
}

func NewWindow(window int) *Window {
	return &Window{
		cond:   sync.NewCond(&sync.Mutex{}),
		window: window,
	}
}

func (w *Window) Abort() {
	w.cond.Broadcast()
}

func (w *Window) Refill(count int) {
	w.cond.L.Lock()
	w.window += count
	w.cond.Broadcast()
	w.cond.L.Unlock()
}

func (w *Window) Take() bool {
	w.cond.L.Lock()
	if w.window <= 0 {
		w.cond.Wait()
	}
	st := false
	if w.window > 0 {
		st = true
		w.window--
	}
	w.cond.L.Unlock()
	return st
}

func (w *Window) TryTake() bool {
	w.cond.L.Lock()
	if w.window > 0 {
		w.window--
		w.cond.L.Unlock()
		return true
	}
	w.cond.L.Unlock()
	return false
}

func (w *Window) GetLevel() int {
	w.cond.L.Lock()
	l := w.window
	w.cond.L.Unlock()
	return l
}
