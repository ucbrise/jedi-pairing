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

package cryptutils

/*
#cgo CFLAGS: -I ../../../include
#cgo LDFLAGS: ${SRCDIR}/pairing.a
#include <string.h>
#include "wkdibe/wkdibe.h"
#include "go_utils.h"
*/
import "C"
import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"unsafe"

	"golang.org/x/crypto/sha3"
)

// GroupOrder is the order of the bilinear group on which this implementation
// is based. Signables and elements of attribute lists must have a value
// strictly less than this and strictly greater than 0.
var GroupOrder, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

//export randomBytes
func randomBytes(buffer unsafe.Pointer, length int) {
	slice := (*[1 << 32]byte)(buffer)[:length:length]
	if _, err := rand.Read(slice); err != nil {
		panic(err)
	}
}

//export hashFill
func hashFill(buffer unsafe.Pointer, bufferLength int, toHash unsafe.Pointer, toHashLength int) {
	bufferSlice := (*[1 << 32]byte)(buffer)[:bufferLength:bufferLength]
	toHashSlice := (*[1 << 32]byte)(toHash)[:toHashLength:toHashLength]

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

// Encryptable represents a message that can be encrypted with WKD-IBE. The
// intended usage is to choose a random message, encrypt that message, and
// then hash the message to obtain a symmetric key.
type Encryptable struct {
	Data C.embedded_pairing_wkdibe_gt_t
}

// Random sets the message to a random valid message and returns a pointer to
// the message on which it was invoked.
func (m *Encryptable) Random() *Encryptable {
	C.embedded_pairing_wkdibe_random_gt(&m.Data, RandomBytesFunction)
	return m
}

// Bytes returns a slice of bytes representing the value of the message. It is
// a copy of the underlying C memory, so it can be safely mutated. It can be
// passed to a hash function to hash the message to a symmetric key.
func (m *Encryptable) Bytes() []byte {
	return C.GoBytes(unsafe.Pointer(&m.Data), C.sizeof_embedded_pairing_wkdibe_gt_t)
}

// Set sets the value of an encryptable to the provided byte slice.
func (m *Encryptable) Set(data []byte) bool {
	if len(data) != int(C.sizeof_embedded_pairing_wkdibe_gt_t) {
		return false
	}
	C.memcpy(unsafe.Pointer(&m.Data), unsafe.Pointer(&data[0]), C.sizeof_embedded_pairing_wkdibe_gt_t)
	return true
}

// Marshal does the same thing as Bytes.
func (m *Encryptable) Marshal() []byte {
	return m.Bytes()
}

// Unmarshal does the same thing as Set.
func (m *Encryptable) Unmarshal(marshalled []byte) bool {
	return m.Set(marshalled)
}

// HashToSymmetricKey hashes the encryptable to get a symmetric key. The
// symmetric key fills the provided slice (which can be of any length, but
// remember that there are only 32 bytes of entropy in the underlying group
// element). Returns sthe provided slice.
func (m *Encryptable) HashToSymmetricKey(sk []byte) []byte {
	shake := sha3.NewShake256()
	shake.Write(m.Bytes())
	shake.Read(sk)
	return sk
}

// GenerateKey generates a random key, and an Encryptable that hashes to that
// key. The key is written to the provided slice, and that same slice is
// returned. Note that, while the slice can be of any length, there are only
// 32 bytes of entropy in the Encryptable
func GenerateKey(sk []byte) ([]byte, *Encryptable) {
	e := new(Encryptable).Random()
	e.HashToSymmetricKey(sk)
	return sk, e
}

// Signable represents a message that is signable with WKD-IBE. The intended
// usage is to hash the message to sign to a Signable, and then pass the
// Signable to the Sign function.
type Signable struct {
	Data C.embedded_pairing_wkdibe_scalar_t
}

// Hash assigns the value of this Signable to a cryptographic hash of the
// provided data. The cryptographic hash used is sha256.
func (m *Signable) Hash(data []byte) *Signable {
	digest := sha256.Sum256(data)
	return m.Set(digest[:])
}

// Set sets the value of this signable to the specified byte slice, which
// must be 32 bytes long. It will automatically "reduce" itself if the
// specified byte slice represents an int value greater than GroupOrder.
func (m *Signable) Set(data []byte) *Signable {
	if C.size_t(len(data)) != C.sizeof_embedded_pairing_wkdibe_scalar_t {
		panic("Slice has wrong size")
	}
	C.memcpy(unsafe.Pointer(&m.Data), unsafe.Pointer(&data[0]), C.sizeof_embedded_pairing_wkdibe_scalar_t)
	C.embedded_pairing_wkdibe_scalar_hash_reduce(&m.Data)
	return m
}

// HashToZp hashes a byte slice to an integer in Zp*.
func HashToZp(bytestring []byte) *big.Int {
	digest := sha256.Sum256(bytestring)
	bigint := new(big.Int).SetBytes(digest[:])
	bigint.Mod(bigint, new(big.Int).Add(GroupOrder, big.NewInt(-1)))
	bigint.Add(bigint, big.NewInt(1))
	return bigint
}
