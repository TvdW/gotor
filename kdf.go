// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
)

func KDFTOR(bytes int, random []byte) []byte {
	tmp := make([]byte, len(random)+1)
	copy(tmp, random)

	result := make([]byte, bytes+(20-(bytes%20)))
	for i, left := 0, bytes; left > 0; left -= 20 {
		tmp[len(random)] = byte(i)
		sha := sha1.Sum(tmp)
		copy(result[20*i:20*(i+1)], sha[:])

		i++
	}

	return result[:bytes]
}

func KDFHKDF(bytes int, secretInput, key, mExpand []byte) []byte {
	if bytes == 0 {
		return nil
	}

	result := make([]byte, bytes+(32-(bytes%32)))

	// Calculate "KEY_SEED"
	kSeed := hmac.New(sha256.New, key)
	kSeed.Write(secretInput)
	keySeed := kSeed.Sum(nil)
	mac := hmac.New(sha256.New, keySeed)

	var singleByte [1]byte
	singleByte[0] = 1

	mac.Write(mExpand)
	mac.Write(singleByte[:])
	copy(result[0:32], mac.Sum(nil))

	gotBytes := 32
	i := 0
	for bytes > gotBytes {
		mac.Reset()
		i++

		mac.Write(result[gotBytes-32 : gotBytes])
		mac.Write(mExpand)
		singleByte[0] = byte(i + 1)
		mac.Write(singleByte[:])

		copy(result[gotBytes:gotBytes+32], mac.Sum(nil))

		gotBytes += 32
	}

	return result[0:bytes]
}
