// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package aes

// #cgo pkg-config: libssl
// #include <openssl/evp.h>
import "C"

import (
	"errors"
	"github.com/tvdw/cgolock"
	"runtime"
)

type Cipher interface {
	Crypt(source, target []byte) ([]byte, error)
}

type cipher struct {
	evp C.EVP_CIPHER_CTX
}

func New(key, iv []byte) Cipher {
	c := &cipher{}
	cgolock.Lock()
	defer cgolock.Unlock()

	C.EVP_CIPHER_CTX_init(&c.evp)
	runtime.SetFinalizer(c, func(c *cipher) {
		C.EVP_CIPHER_CTX_cleanup(&c.evp)
	})

	C.EVP_EncryptInit_ex(&c.evp, C.EVP_aes_128_ctr(), nil, (*C.uchar)(&key[0]), (*C.uchar)(&iv[0]))

	return c
}

func (c *cipher) Crypt(source, target []byte) ([]byte, error) {
	if len(source) > cap(target) {
		return nil, errors.New("aes: target must be at least as long as the source")
	}

	var outl C.int
	cgolock.Lock()
	C.EVP_EncryptUpdate(&c.evp, (*C.uchar)(&target[0]), &outl, (*C.uchar)(&source[0]), C.int(len(source)))
	cgolock.Unlock()

	return target[:int(outl)], nil
}
