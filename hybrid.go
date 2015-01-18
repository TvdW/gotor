// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"github.com/tvdw/gotor/aes"
	"github.com/tvdw/openssl"
)

func HybridDecrypt(priv openssl.PrivateKey, d []byte) ([]byte, error) {
	// XXX this could probably be optimized a little

	res, err := priv.Decrypt(d[0:128])
	if err != nil {
		return nil, err
	}

	if len(res) < 86 {
		return res, nil
	}

	data1 := res[16:86]
	aes := aes.New(res[0:16], make([]byte, 16))

	res2 := make([]byte, len(d)-128)
	res2, err = aes.Crypt(d[128:len(d)], res2)
	if err != nil {
		return nil, err
	}

	finalRes := make([]byte, len(data1)+len(res2))
	copy(finalRes, data1)
	copy(finalRes[len(data1):], res2)

	return finalRes, nil
}
