/*
 * Copyright (c) 2018, Sam Kumar <samkumar@cs.berkeley.edu>
 * Copyright (c) 2018, University of California, Berkeley
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

// Package internal implements common functionality shared by the other
// packages in this library.
package internal

/*
#cgo CFLAGS: -I ../../../include
#cgo LDFLAGS: ${SRCDIR}/pairing.a
#include <string.h>
#include "go_utils.h"
*/
import "C"
import (
	"crypto/rand"
	"math"
	"math/big"
	"unsafe"

	"golang.org/x/crypto/sha3"
)

//export randomBytes
func randomBytes(buffer unsafe.Pointer, length int) {
	slice := PointerToByteSlice(buffer, length)
	if _, err := rand.Read(slice); err != nil {
		panic(err)
	}
}

//export hashFill
func hashFill(buffer unsafe.Pointer, bufferLength int, toHash unsafe.Pointer, toHashLength int) {
	bufferSlice := PointerToByteSlice(buffer, bufferLength)
	toHashSlice := PointerToByteSlice(toHash, toHashLength)

	shake := sha3.NewShake256()
	shake.Write(toHashSlice)
	shake.Read(bufferSlice)
}

// RandomBytesFunction is a C function pointer that takes an array pointer as
// input and fills the array with random bytes.
var RandomBytesFunction = (*[0]byte)(C.go_random_bytes)

// HashFillFunction is a C function pointer that takes two array pointers and
// fills the first with the hash of the second.
var HashFillFunction = (*[0]byte)(C.go_hash_fill)

// PointerToByteSlice builds a byte slice around a pointer to data.
func PointerToByteSlice(pointer unsafe.Pointer, capacity int) []byte {
	return (*[math.MaxInt32]byte)(pointer)[:capacity:capacity]
}

// BigIntToC converts from a Golang big.Int to a BigInt of the appropriate
// length.
func BigIntToC(result unsafe.Pointer, resultSize int, scalar *big.Int) unsafe.Pointer {
	if scalar.Sign() == 0 {
		C.memset(result, 0x00, C.size_t(resultSize))
	} else if scalar.Sign() != 1 {
		panic("Invalid BigInt: negative")
	}
	resultSlice := PointerToByteSlice(result, resultSize)
	scalarBytes := scalar.Bytes()
	if len(scalarBytes) > len(resultSlice) {
		panic("Invalid BigInt: too large")
	}
	j := 0
	for j != len(scalarBytes) {
		resultSlice[j] = scalarBytes[len(scalarBytes)-j-1]
		j++
	}
	for j != len(resultSlice) {
		resultSlice[j] = 0
		j++
	}
	return result
}

// BigIntFromC converts a BigInt of the given length to a Golang big.Int.
func BigIntFromC(result *big.Int, bigInt unsafe.Pointer, bigIntSize int) *big.Int {
	bigIntSlice := PointerToByteSlice(bigInt, bigIntSize)
	bigEndianSlice := make([]byte, bigIntSize)
	for i := range bigEndianSlice {
		bigEndianSlice[i] = bigIntSlice[bigIntSize-i-1]
	}
	result.SetBytes(bigEndianSlice)
	return result
}
