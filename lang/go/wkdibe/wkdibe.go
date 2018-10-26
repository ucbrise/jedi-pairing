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

package wkdibe

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"runtime"
	"sort"
	"unsafe"

	"golang.org/x/crypto/sha3"
)

/*
#cgo CFLAGS: -I ../../../include
#cgo LDFLAGS: pairing.a
#include <stdlib.h>
#include <string.h>
#include "wkdibe/wkdibe.h"
#include "go_utils.h"
*/
import "C"

// GroupOrder is the order of the bilinear group on which this implementation
// is based. Signables and elements of attribute lists must have a value
// strictly less than this and strictly greater than 0.
var GroupOrder, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

// Encryptable represents a message that can be encrypted with WKD-IBE. The
// intended usage is to choose a random message, encrypt that message, and
// then hash the message to obtain a symmetric key.
type Encryptable struct {
	data C.embedded_pairing_wkdibe_gt_t
}

// Random sets the message to a random valid message and returns a pointer to
// the message on which it was invoked.
func (m *Encryptable) Random() *Encryptable {
	C.embedded_pairing_wkdibe_random_gt(&m.data, randomBytesFunction)
	return m
}

// Bytes returns a slice of bytes representing the value of the message. It is
// a copy of the underlying C memory, so it can be safely mutated. It can be
// passed to a hash function to hash the message to a symmetric key.
func (m *Encryptable) Bytes() []byte {
	return C.GoBytes(unsafe.Pointer(&m.data), C.sizeof_embedded_pairing_wkdibe_gt_t)
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

// Signable represents a message that is signable with WKD-IBE. The intended
// usage is to hash the message to sign to a Signable, and then pass the
// Signable to the Sign function.
type Signable struct {
	data C.embedded_pairing_wkdibe_scalar_t
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
	C.memcpy(unsafe.Pointer(&m.data), unsafe.Pointer(&data[0]), C.sizeof_embedded_pairing_wkdibe_scalar_t)
	C.embedded_pairing_wkdibe_scalar_hash_reduce(&m.data)
	return m
}

// Params represents public parameters for a WKD-IBE system.
type Params struct {
	data C.embedded_pairing_wkdibe_params_t
}

// Ciphertext represents a WKD-IBE ciphertext.
type Ciphertext struct {
	data C.embedded_pairing_wkdibe_ciphertext_t
}

// Signature represents a WKD-IBE signature.
type Signature struct {
	data C.embedded_pairing_wkdibe_signature_t
}

// SecretKey represents a WKD-IBE secret key.
type SecretKey struct {
	data C.embedded_pairing_wkdibe_secretkey_t
}

// MasterKey represents a WKD-IBE master key.
type MasterKey struct {
	data C.embedded_pairing_wkdibe_masterkey_t
}

// PreparedAttributeList represents precomputation for a specific attribute
// list to accelerate e.g., repeated encryption for that attribute list with
// the same public parameters.
type PreparedAttributeList struct {
	data C.embedded_pairing_wkdibe_precomputed_t
}

// AttributeIndex represents an attribute --- specifically, its index in the
// array of attributes.
type AttributeIndex int

// AttributeList represents a list of attributes. It is map from each set
// attribute (by its index) to the value of that attribute.
type AttributeList map[AttributeIndex]*big.Int

//export randomBytes
func randomBytes(buffer unsafe.Pointer, length int) {
	slice := (*[1 << 32]byte)(buffer)[:length:length]
	if _, err := rand.Read(slice); err != nil {
		panic(err)
	}
}

var randomBytesFunction = (*[0]byte)(C.go_random_bytes)

func convertAttributeList(attrs AttributeList) *C.embedded_pairing_wkdibe_attributelist_t {
	if attrs == nil {
		return nil
	}
	sorted := make([]int, 0, len(attrs))
	for idx := range attrs {
		sorted = append(sorted, int(idx))
	}
	sort.Ints(sorted)
	attrSlice := C.malloc(C.size_t(len(attrs)) * C.sizeof_embedded_pairing_wkdibe_attribute_t)
	for i, idx := range sorted {
		attr := attrs[AttributeIndex(idx)]
		attribute := (*C.embedded_pairing_wkdibe_attribute_t)(unsafe.Pointer(uintptr(attrSlice) + uintptr(i)*C.sizeof_embedded_pairing_wkdibe_attribute_t))
		attribute.idx = C.uint32_t(idx)
		if attr == nil {
			C.memset(unsafe.Pointer(&attribute.id), 0x00, C.sizeof_embedded_pairing_wkdibe_scalar_t)
			attribute.omitFromKeys = true
		} else {
			convertScalar(&attribute.id, attr)
			attribute.omitFromKeys = false
		}
	}
	attrList := &C.embedded_pairing_wkdibe_attributelist_t{
		attrs:  (*C.embedded_pairing_wkdibe_attribute_t)(attrSlice),
		length: C.size_t(len(attrs)),
		omitAllFromKeysUnlessPresent: false,
	}
	runtime.SetFinalizer(attrList, func(al *C.embedded_pairing_wkdibe_attributelist_t) {
		C.free(unsafe.Pointer(al.attrs))
	})
	return attrList
}

func convertScalar(result *C.embedded_pairing_wkdibe_scalar_t, scalar *big.Int) {
	if scalar.Sign() != 1 {
		panic("Invalid scalar: nonpositive")
	}
	resultSlice := (*[1 << 32]byte)(unsafe.Pointer(result))[:C.sizeof_embedded_pairing_wkdibe_scalar_t:C.sizeof_embedded_pairing_wkdibe_scalar_t]
	scalarBytes := scalar.Bytes()
	if len(scalarBytes) > len(resultSlice) {
		panic("Invalid scalar: too large")
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
}

func allocateSecretKeyB(sk *SecretKey, length int) {
	if length < 0 {
		panic("Too many attributes in attribute list")
	} else if length == 0 {
		sk.data.b = nil
	} else {
		sk.data.b = (*C.embedded_pairing_wkdibe_freeslot_t)(C.malloc(C.size_t(length) * C.sizeof_embedded_pairing_wkdibe_freeslot_t))
		runtime.SetFinalizer(sk, func(k *SecretKey) {
			C.free(unsafe.Pointer(k.data.b))
		})
	}
}

// NumAttributes returns the number of attributes supported. This was specified
// via the "l" argument when Setup was called.
func (params *Params) NumAttributes() int {
	return int(params.data.l)
}

// Setup generates the system parameters, which may be made visible to an
// adversary. The parameter "l" is the total number of attributes supported
// (indexed from 0 to l - 1).
func Setup(l int, supportSignatures bool) (*Params, *MasterKey) {
	pp := new(Params)
	msk := new(MasterKey)
	pp.data.h = (*C.embedded_pairing_wkdibe_g1_t)(C.malloc(C.size_t(l) * C.sizeof_embedded_pairing_wkdibe_g1_t))
	runtime.SetFinalizer(pp, func(p *Params) {
		C.free(unsafe.Pointer(p.data.h))
	})
	C.embedded_pairing_wkdibe_setup(&pp.data, &msk.data, C.int(l), C._Bool(supportSignatures), randomBytesFunction)
	return pp, msk
}

// KeyGen generates a key for an attribute list using the master key.
// The attrs argument is a mapping from attribute to its value; attributes
// not in the map are not set.
//
// If a slot is mapped to nil in the attribute set, that slot is free in the new
// private key, but cannot be filled in.
func KeyGen(params *Params, msk *MasterKey, attrs AttributeList) *SecretKey {
	sk := new(SecretKey)
	allocateSecretKeyB(sk, params.NumAttributes()-len(attrs))
	C.embedded_pairing_wkdibe_keygen(&sk.data, &params.data, &msk.data, convertAttributeList(attrs), randomBytesFunction)
	return sk
}

// QualifyKey uses a key to generate a new key with restricted permissions, by
// adding the the specified attributes. Remember that adding new attributes
// restricts the permissions. Furthermore, attributes are immutable once set,
// so the attrs map must contain mappings for attributes that are already set.
// The attrs argument is a mapping from attribute to its value; attributes
// not in the map are not set.
//
// If a slot is mapped to nil in the attribute set, that slot is free in the new
// private key, but cannot be filled in.
func QualifyKey(params *Params, qualify *SecretKey, attrs AttributeList) *SecretKey {
	sk := new(SecretKey)
	allocateSecretKeyB(sk, params.NumAttributes()-len(attrs))
	C.embedded_pairing_wkdibe_qualifykey(&sk.data, &params.data, &qualify.data, convertAttributeList(attrs), randomBytesFunction)
	return sk
}

// NonDelegableKeyGen is like KeyGen, except that the resulting key should only
// be used for decryption or signing. This is significantly faster than the
// regular KeyGen. However, the output should _not_ be delegated to another
// entity, as it is not properly re-randomized and could leak the master key.
//
// If a slot is mapped to nil in the attribute set, that slot is free in the
// new private key, but cannot be filled in.
func NonDelegableKeyGen(params *Params, msk *MasterKey, attrs AttributeList) *SecretKey {
	sk := new(SecretKey)
	allocateSecretKeyB(sk, params.NumAttributes()-len(attrs))
	C.embedded_pairing_wkdibe_nondelegable_keygen(&sk.data, &params.data, &msk.data, convertAttributeList(attrs))
	return sk
}

// NonDelegableQualifyKey is like QualifyKey, except that the resulting key
// should only be used for decryption or signing. This is significantly faster
// than the QualifyKey function. However, the output should _not_ be delegated
// to another entity, as it is not properly re-randomized and could leak
// information about the parent key.
//
// If a slot is mapped to nil in the attribute set, that slot is free in the new
// private key, but cannot be filled in.
func NonDelegableQualifyKey(params *Params, qualify *SecretKey, attrs AttributeList) *SecretKey {
	sk := new(SecretKey)
	allocateSecretKeyB(sk, params.NumAttributes()-len(attrs))
	C.embedded_pairing_wkdibe_nondelegable_qualifykey(&sk.data, &params.data, &qualify.data, convertAttributeList(attrs))
	return sk
}

// ResampleKey uses the provided private key to sample a new private key with
// the same capability, using the provided randomness t. If delegable is true,
// then the new private key can be qualified via QualifyKey or NonDelegableKey,
// but this function takes longer to execute. If delegable is false, the
// resulting private key cannot be used with QualifyKey or NonDelegableKey, but
// resampling is faster.
func ResampleKey(params *Params, precomputed *PreparedAttributeList, key *SecretKey, supportFurtherQualification bool) *SecretKey {
	sk := new(SecretKey)
	if supportFurtherQualification {
		allocateSecretKeyB(sk, int(key.data.l))
	} else {
		sk.data.b = nil
	}
	C.embedded_pairing_wkdibe_resamplekey(&sk.data, &params.data, &precomputed.data, &key.data, C._Bool(supportFurtherQualification), randomBytesFunction)
	return sk
}

// AdjustNonDelegable takes in a non-delegable key and the parent from which it
// was generated, and cheaply converts it into a non-delegable key for a
// different attribute set that could also be generated from the parent.
func AdjustNonDelegable(sk *SecretKey, parent *SecretKey, from AttributeList, to AttributeList) {
	C.embedded_pairing_wkdibe_adjust_nondelegable(&sk.data, &parent.data, convertAttributeList(from), convertAttributeList(to))
}

// PrepareAttributeList performs precomputation for the provided attribute
// list, to speed up future encryption or verification with that attribute
// list. The returned precomputed result can be safely reused multiple times.
// This can be useful if you are repeatedly encrypting messages or verifying
// signatures with the same attribute list and want to speed things up.
func PrepareAttributeList(params *Params, attrs AttributeList) *PreparedAttributeList {
	prepared := new(PreparedAttributeList)
	C.embedded_pairing_wkdibe_precompute(&prepared.data, &params.data, convertAttributeList(attrs))
	return prepared
}

// AdjustPreparedAttributeList takes as input a prepared attribute list, and
// modifies it to correspond to a different attribute list.
func AdjustPreparedAttributeList(prepared *PreparedAttributeList, params *Params, from AttributeList, to AttributeList) {
	C.embedded_pairing_wkdibe_adjust_precomputed(&prepared.data, &params.data, convertAttributeList(from), convertAttributeList(to))
}

// Encrypt converts the provided message to ciphertext, using the provided
// Attribute List and public parameters.
func Encrypt(message *Encryptable, params *Params, attrs AttributeList) *Ciphertext {
	ciphertext := new(Ciphertext)
	C.embedded_pairing_wkdibe_encrypt(&ciphertext.data, &message.data, &params.data, convertAttributeList(attrs), randomBytesFunction)
	return ciphertext
}

// EncryptPrepared encrypts the provided message, using the provided prepared
// attribute list to speed up the process.
func EncryptPrepared(message *Encryptable, params *Params, prepared *PreparedAttributeList) *Ciphertext {
	ciphertext := new(Ciphertext)
	C.embedded_pairing_wkdibe_encrypt_precomputed(&ciphertext.data, &message.data, &params.data, &prepared.data, randomBytesFunction)
	return ciphertext
}

// Decrypt recovers the original message from the provided ciphertext, using
// the provided secret key.
func Decrypt(ciphertext *Ciphertext, sk *SecretKey) *Encryptable {
	message := new(Encryptable)
	C.embedded_pairing_wkdibe_decrypt(&message.data, &ciphertext.data, &sk.data)
	return message
}

// DecryptWithMaster is the same as Decrypt, but requires the master key to be
// provided. It is substantially more efficient than generating a private key
// and then calling Decrypt.
func DecryptWithMaster(ciphertext *Ciphertext, msk *MasterKey) *Encryptable {
	message := new(Encryptable)
	C.embedded_pairing_wkdibe_decrypt_master(&message.data, &ciphertext.data, &msk.data)
	return message
}

// Sign produces a signature for the provided message hash, using the provided
// secret key. The signature may be produced on a more specialized attribute
// list than the key; alternatively, ATTRS may be left a nil if this is not
// needed.
func Sign(params *Params, sk *SecretKey, attrs AttributeList, message *Signable) *Signature {
	signature := new(Signature)
	C.embedded_pairing_wkdibe_sign(&signature.data, &params.data, &sk.data, convertAttributeList(attrs), &message.data, randomBytesFunction)
	return signature
}

// SignPrepared produces a signature for the provided message hash, using the
// provided prepared attribute list to speed up the process. The signature may
// be produced on a more specialized attribute list than the key; alternatively,
// ATTRS may be left a nil if this is not needed.
func SignPrepared(params *Params, sk *SecretKey, attrs AttributeList, prepared *PreparedAttributeList, message *Signable) *Signature {
	signature := new(Signature)
	C.embedded_pairing_wkdibe_sign_precomputed(&signature.data, &params.data, &sk.data, convertAttributeList(attrs), &prepared.data, &message.data, randomBytesFunction)
	return signature
}

// Verify verifies that the provided signature was produced using a secret key
// corresponding to the provided attribute set.
func Verify(params *Params, attrs AttributeList, signature *Signature, message *Signable) bool {
	return bool(C.embedded_pairing_wkdibe_verify(&params.data, convertAttributeList(attrs), &signature.data, &message.data))
}

// VerifyPrepared verifies the provided signature, using the provided prepared
// attribute list to speed up the process.
func VerifyPrepared(params *Params, prepared *PreparedAttributeList, signature *Signature, message *Signable) bool {
	return bool(C.embedded_pairing_wkdibe_verify_precomputed(&params.data, &prepared.data, &signature.data, &message.data))
}
