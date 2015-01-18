// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"github.com/tvdw/openssl"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"
)

const SSLRecordSize = openssl.SSLRecordSize

type TorTLS struct {
	ctx *openssl.Ctx

	LinkKey, IdKey, AuthKey             openssl.PrivateKey
	LinkCert, IdCert, AuthCert          *openssl.Certificate
	LinkCertDER, IdCertDER, AuthCertDER []byte
	Fingerprint                         Fingerprint
	Fingerprint256                      []byte
}

func NewTLSCtx(isClient bool, or *ORCtx) (*TorTLS, error) {
	log.Printf("Creating TLS context with isClient=%v\n", isClient)

	sslCtx, err := openssl.NewCtxWithVersion(openssl.AnyVersion)
	if err != nil {
		return nil, err
	}

	tls := &TorTLS{
		ctx: sslCtx,
	}

	// Considering how important this piece of code is for resisting fingerprints, we just follow whatever Tor itself does

	if !isClient { // XXX simplify
		nickname1 := RandomHostname(8, 20, "www.", ".net")
		nickname2 := RandomHostname(8, 20, "www.", ".com")

		issued, _ := time.ParseDuration("-24h") // XXX check what tor does (some time ago, then a long-time cert)
		expires, _ := time.ParseDuration("24h") // XXX also, don't re-use for all certs

		tmpPk, err := openssl.GenerateRSAKeyWithExponent(1024, 65537)
		if err != nil {
			return nil, err
		}

		authPk, err := openssl.GenerateRSAKeyWithExponent(1024, 65537)
		if err != nil {
			return nil, err
		}

		cert, err := openssl.NewCertificate(&openssl.CertificateInfo{
			CommonName: nickname1,
			Serial:     rand.Int63(),
			Issued:     issued,
			Expires:    expires,
		}, tmpPk)
		if err != nil {
			return nil, err
		}

		identityPk := or.identityKey

		idcert, err := openssl.NewCertificate(&openssl.CertificateInfo{
			CommonName: nickname2,
			Serial:     rand.Int63(),
			Issued:     issued,
			Expires:    expires,
		}, identityPk)
		if err != nil {
			return nil, err
		}

		authcert, err := openssl.NewCertificate(&openssl.CertificateInfo{
			CommonName: nickname1,
			Serial:     rand.Int63(),
			Issued:     issued,
			Expires:    expires,
		}, authPk)
		if err != nil {
			return nil, err
		}

		if err := cert.SetIssuer(idcert); err != nil {
			return nil, err
		}
		if err := cert.Sign(identityPk, openssl.EVP_SHA1); err != nil {
			return nil, err
		}

		if err := idcert.SetIssuer(idcert); err != nil {
			return nil, err
		}
		if err := idcert.Sign(identityPk, openssl.EVP_SHA1); err != nil {
			return nil, err
		}

		if err := authcert.SetIssuer(idcert); err != nil {
			return nil, err
		}
		if err := authcert.Sign(identityPk, openssl.EVP_SHA1); err != nil {
			return nil, err
		}

		sslCtx.UseCertificate(cert)
		sslCtx.UsePrivateKey(tmpPk)

		sslCtx.SetEllipticCurve(openssl.Prime256v1)

		tls.LinkCert = cert
		tls.LinkKey = tmpPk
		tls.LinkCertDER, err = cert.MarshalDER()
		if err != nil {
			return nil, err
		}

		tls.IdCert = idcert
		tls.IdKey = identityPk
		tls.IdCertDER, err = idcert.MarshalDER()
		if err != nil {
			return nil, err
		}

		keyDer, _ := identityPk.MarshalPKCS1PublicKeyDER()
		fingerprint := sha1.Sum(keyDer)
		log.Printf("Our fingerprint is %X\n", fingerprint)
		copy(tls.Fingerprint[:], fingerprint[:])

		{
			sha := sha256.New()
			sha.Write(keyDer)
			tls.Fingerprint256 = sha.Sum(nil)
		}

		tls.AuthCert = authcert
		tls.AuthKey = authPk
		tls.AuthCertDER, err = authcert.MarshalDER()
		if err != nil {
			return nil, err
		}
	}

	// We don't want SSLv2 or SSLv3
	sslCtx.SetOptions(openssl.NoSSLv2 | openssl.NoSSLv3)

	// Prefer the server's ordering of ciphers: the client's ordering has
	// historically been chosen for fingerprinting resistance.
	sslCtx.SetOptions(openssl.CipherServerPreference)

	//XXX: panic() if we don't have openssl of 1.0.1e or later
	//XXX: please remember me why...

	// Tickets hurt perfect forward secrecy, but we still have non-server clients announce them, to reduce fingerprinting impact
	if !isClient {
		sslCtx.SetOptions(openssl.NoTicket)
	}

	// This saves us quite some memory
	//sslCtx.SetMode(openssl.ReleaseBuffers)

	// Avoid reusing DH keys if we don't have to
	sslCtx.SetOptions(openssl.SingleDHUse | openssl.SingleECDHUse)

	// Never renegotiate.
	sslCtx.SetOptions(openssl.NoSessionResumptionOrRenegotiation)

	// All compression does with encrypted data is waste CPU cycles. Disable it
	sslCtx.SetOptions(openssl.NoCompression)

	// Disable session caching
	sslCtx.SetSessionCacheMode(openssl.SessionCacheOff)

	// Allow all peer certificates
	sslCtx.SetVerify(openssl.VerifyNone, nil)

	return tls, nil
}

func (or *ORCtx) GetTLSCtx(isClient bool) *TorTLS {
	or.tlsLock.Lock()
	defer or.tlsLock.Unlock()

	//assert(xxxxxxTlsCtx)
	if isClient {
		return or.clientTlsCtx
	} else {
		return or.serverTlsCtx
	}
}

func SetupTLS(or *ORCtx) error {
	var serverCtx, clientCtx *TorTLS

	serverCtx, err := NewTLSCtx(false, or)
	if err != nil {
		return err
	}

	if or.config.IsPublicServer {
		clientCtx = serverCtx
	} else {
		cCtx, err := NewTLSCtx(true, or)
		if err != nil {
			return err
		}
		clientCtx = cCtx
	}

	or.tlsLock.Lock()
	defer or.tlsLock.Unlock()

	or.clientTlsCtx = clientCtx
	or.serverTlsCtx = serverCtx

	return nil
}

func (or *ORCtx) WrapTLS(conn net.Conn, isClient bool) (*openssl.Conn, *TorTLS, error) {
	tls := or.GetTLSCtx(isClient)

	var tlsConn *openssl.Conn
	var err error
	if isClient {
		tlsConn, err = openssl.Client(conn, tls.ctx)
	} else {
		tlsConn, err = openssl.Server(conn, tls.ctx)
	}

	if err != nil {
		return nil, nil, err
	}

	return tlsConn, tls, nil
}

func RandomHostname(minLen, maxLen int, prefix, suffix string) string {
	chars := (rand.Int() % (maxLen - minLen)) + minLen

	enc := base32.StdEncoding
	rndChars := chars
	host := make([]byte, rndChars)
	CRandBytes(host)

	return prefix + strings.ToLower(enc.EncodeToString(host)[:chars]) + suffix
}
