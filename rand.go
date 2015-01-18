// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	crand "crypto/rand"
	brand "math/rand"
)

func SetupRand() error {
	// Seed our pseudo-random RNG with crpyto-random data
	seed := make([]byte, 8)
	_, err := crand.Read(seed)
	if err != nil {
		return err
	}

	s := int64(0)
	for i := 0; i < 8; i++ {
		s = s << 8
		s += int64(seed[i])
	}
	brand.Seed(s)

	return nil
}

func CRandBytes(target []byte) error {
	_, err := crand.Read(target)
	return err
}
