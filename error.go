// Copyright 2015 The GoTor Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

type ErrorHandleMethod byte

const (
	_                                        = iota
	ERROR_CLOSE_CONNECTION ErrorHandleMethod = iota
	ERROR_CLOSE_CIRCUIT
	ERROR_CLOSE_STREAM
	ERROR_REFUSE_CIRCUIT
	ERROR_REFUSE_STREAM
)

type ActionableError interface {
	error
	Handle() ErrorHandleMethod
	CircDestroyReason() DestroyReason
	StreamEndReason() StreamEndReason
}

type wrappedError struct {
	wrappedError      error
	handleType        ErrorHandleMethod
	circDestroyReason DestroyReason
	streamEndReason   StreamEndReason
}

func (e *wrappedError) Handle() ErrorHandleMethod {
	return e.handleType
}

func (e *wrappedError) Error() string {
	return e.wrappedError.Error()
}

func (e *wrappedError) CircDestroyReason() DestroyReason {
	return e.circDestroyReason
}

func (e *wrappedError) StreamEndReason() StreamEndReason {
	return e.streamEndReason
}

func CloseCircuit(e error, reason DestroyReason) ActionableError {
	return &wrappedError{e, ERROR_CLOSE_CIRCUIT, reason, 0}
}

func RefuseCircuit(e error, reason DestroyReason) ActionableError {
	return &wrappedError{e, ERROR_REFUSE_CIRCUIT, reason, 0}
}

func CloseConnection(e error) ActionableError {
	return &wrappedError{e, ERROR_CLOSE_CONNECTION, 0, 0}
}

func CloseStream(e error, reason StreamEndReason) ActionableError {
	return &wrappedError{e, ERROR_CLOSE_STREAM, 0, reason}
}

func RefuseStream(e error, reason StreamEndReason) ActionableError {
	return &wrappedError{e, ERROR_REFUSE_STREAM, 0, reason}
}
