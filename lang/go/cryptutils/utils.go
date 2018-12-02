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
#include "bls12_381/bls12_381.h"
*/
import "C"
import (
	"math/big"
	"unsafe"

	"golang.org/x/crypto/sha3"

	"github.com/samkumar/embedded-pairing/lang/go/bls12381"
	"github.com/samkumar/embedded-pairing/lang/go/internal"
)

// Encryptable represents a message that can be encrypted with WKD-IBE. The
// intended usage is to choose a random message, encrypt that message, and
// then hash the message to obtain a symmetric key.
type Encryptable struct {
	bls12381.GT
}

// Random sets the message to a random valid message and returns a pointer to
// the message on which it was invoked.
func (m *Encryptable) Random() *Encryptable {
	m.GT.Random(bls12381.GTGenerator)
	return m
}

// Bytes returns a slice of bytes representing the value of the message. It is
// a copy of the underlying C memory, so it can be safely mutated. It can be
// passed to a hash function to hash the message to a symmetric key.
func (m *Encryptable) Bytes() []byte {
	return m.GT.Marshal(make([]byte, bls12381.GTMarshalledSize))
}

// Set sets the value of an encryptable to the provided byte slice.
func (m *Encryptable) Set(data []byte) bool {
	return m.GT.Unmarshal(data) == &m.GT
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
	Data C.embedded_pairing_core_bigint_256_t
}

// Hash assigns the value of this Signable to a cryptographic hash of the
// provided data. The cryptographic hash used is sha256.
func (m *Signable) Hash(data []byte) *Signable {
	var hash [C.sizeof_embedded_pairing_core_bigint_256_t]byte

	shake := sha3.NewShake256()
	shake.Write(data)
	shake.Read(hash[:])

	C.embedded_pairing_bls12_381_zp_from_hash(&m.Data, unsafe.Pointer(&hash[0]))
	return m
}

// Set sets the value of this signable to the specified byte slice, which
// must be 32 bytes long. It will automatically "reduce" itself if the
// specified byte slice represents a value greater than bls12381.GroupOrder.
func (m *Signable) Set(data []byte) *Signable {
	if C.size_t(len(data)) != C.sizeof_embedded_pairing_core_bigint_256_t {
		panic("Slice has wrong size")
	}
	C.embedded_pairing_bls12_381_zp_from_hash(&m.Data, unsafe.Pointer(&data[0]))
	return m
}

// RandomZp samples a random element of Zp and stores it in the provided
// big.Int. The provided big.Int is then returned.
func RandomZp(result *big.Int) *big.Int {
	var x C.embedded_pairing_core_bigint_256_t
	C.embedded_pairing_bls12_381_zp_random(&x, internal.RandomBytesFunction)
	internal.BigIntFromC(result, unsafe.Pointer(&x), C.sizeof_embedded_pairing_core_bigint_256_t)
	return result
}

// HashToZp samples a random element of Zp and stores it in the provided
// big.Int. The provided big.Int is then returned.
func HashToZp(result *big.Int, buffer []byte) *big.Int {
	var s Signable
	s.Hash(buffer)
	internal.BigIntFromC(result, unsafe.Pointer(&s.Data), C.sizeof_embedded_pairing_core_bigint_256_t)
	return result
}
