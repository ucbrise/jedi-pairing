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

// Package lqibe provides a Go interface to an implementation of Identity-Based
// Encryption (IBE). The construction used is due to Libert and Quisquater; see
// http://cseweb.ucsd.edu/~mihir/cse208-06/libert-quisquater-ibe-acns-05.pdf
// for information about LQ-IBE.
package lqibe

/*
#cgo CFLAGS: -I ../../../include
#cgo LDFLAGS: ${SRCDIR}/pairing.a
#include "lqibe/lqibe.h"
*/
import "C"

import (
	"unsafe"

	"github.com/ucbrise/jedi-pairing/lang/go/internal"
	"golang.org/x/crypto/sha3"
)

// Params represents public parameters for an LQ IBE system.
type Params struct {
	Data C.embedded_pairing_lqibe_params_t
}

// ID represents a prepared ID in an LQ IBE system.
type ID struct {
	Data C.embedded_pairing_lqibe_id_t
}

// MasterKey represents the master secret key in an LQ IBE system.
type MasterKey struct {
	Data C.embedded_pairing_lqibe_masterkey_t
}

// SecretKey represents a secret key in an LQ IBE system.
type SecretKey struct {
	Data C.embedded_pairing_lqibe_secretkey_t
}

// Ciphertext represents a ciphertext in an LQ IBE system.
type Ciphertext struct {
	Data C.embedded_pairing_lqibe_ciphertext_t
}

// Hash hashes a byte slice to an ID.
func (id *ID) Hash(data []byte) *ID {
	idhash := new(C.embedded_pairing_lqibe_idhash_t)
	hashSlice := internal.PointerToByteSlice(unsafe.Pointer(&idhash.hash[0]), C.sizeof_embedded_pairing_lqibe_idhash_t)

	shake := sha3.NewShake256()
	shake.Write(data)
	shake.Read(hashSlice)

	C.embedded_pairing_lqibe_compute_id_from_hash(&id.Data, idhash)
	return id
}

// Setup generates a new LQ IBE system. It returns the new system's public
// parameters and master secret key.
func Setup() (*Params, *MasterKey) {
	pp := new(Params)
	msk := new(MasterKey)
	C.embedded_pairing_lqibe_setup(&pp.Data, &msk.Data, internal.RandomBytesFunction)
	return pp, msk
}

// KeyGen generates a secretkey for an ID in the LQ IBE system corresponding
// to the provided public parameters and master secret key.
func KeyGen(params *Params, msk *MasterKey, id *ID) *SecretKey {
	sk := new(SecretKey)
	C.embedded_pairing_lqibe_keygen(&sk.Data, &msk.Data, &id.Data)
	return sk
}

// Encrypt fills the specified buffer with a symmetric key and returns a
// ciphertext encoding the encrypted symmetric key. The symmetric key buffer
// can be of any length, but the underlying entropy is only 256 bits.
func Encrypt(symmetric []byte, params *Params, id *ID) *Ciphertext {
	c := new(Ciphertext)
	C.embedded_pairing_lqibe_encrypt(&c.Data, unsafe.Pointer(&symmetric[0]), C.size_t(len(symmetric)), &params.Data, &id.Data, internal.HashFillFunction, internal.RandomBytesFunction)
	return c
}

// Decrypt fills the specified buffer with the symmetric key encoded in the
// provided ciphertext. It returns the same buffer passed in as an argument.
func Decrypt(ciphertext *Ciphertext, sk *SecretKey, id *ID, symmetric []byte) []byte {
	C.embedded_pairing_lqibe_decrypt(unsafe.Pointer(&symmetric[0]), C.size_t(len(symmetric)), &ciphertext.Data, &sk.Data, &id.Data, internal.HashFillFunction)
	return symmetric
}
