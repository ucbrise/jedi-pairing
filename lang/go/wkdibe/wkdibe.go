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

// Package wkdibe provides a Go interface to an implementation of WKD-IBE. See
// https://eprint.iacr.org/2007/221.pdf for more information about WKD-IBE.
// The implementation uses the construction of WKD-IBE based on BBG HIBE.
package wkdibe

/*
#cgo CFLAGS: -I ../../../include
#cgo LDFLAGS: ${SRCDIR}/pairing.a
#include <stdlib.h>
#include <string.h>
#include "wkdibe/wkdibe.h"
*/
import "C"

import (
	"math/big"
	"runtime"
	"sort"
	"unsafe"

	"github.com/ucbrise/jedi-pairing/lang/go/cryptutils"
	"github.com/ucbrise/jedi-pairing/lang/go/internal"
)

// Params represents public parameters for a WKD-IBE system.
type Params struct {
	Data C.embedded_pairing_wkdibe_params_t
}

// Ciphertext represents a WKD-IBE ciphertext.
type Ciphertext struct {
	Data C.embedded_pairing_wkdibe_ciphertext_t
}

// Signature represents a WKD-IBE signature.
type Signature struct {
	Data C.embedded_pairing_wkdibe_signature_t
}

// SecretKey represents a WKD-IBE secret key.
type SecretKey struct {
	Data C.embedded_pairing_wkdibe_secretkey_t
}

// MasterKey represents a WKD-IBE master key.
type MasterKey struct {
	Data C.embedded_pairing_wkdibe_masterkey_t
}

// PreparedAttributeList represents precomputation for a specific attribute
// list to accelerate e.g., repeated encryption for that attribute list with
// the same public parameters.
type PreparedAttributeList struct {
	Data C.embedded_pairing_wkdibe_precomputed_t
}

// AttributeIndex represents an attribute --- specifically, its index in the
// array of attributes.
type AttributeIndex int

// AttributeList represents a list of attributes. It is map from each set
// attribute (by its index) to the value of that attribute.
type AttributeList map[AttributeIndex]*big.Int

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
			internal.BigIntToC(unsafe.Pointer(&attribute.id), C.sizeof_embedded_pairing_wkdibe_scalar_t, attr)
			attribute.omitFromKeys = false
		}
	}
	attrList := &C.embedded_pairing_wkdibe_attributelist_t{
		attrs:                        (*C.embedded_pairing_wkdibe_attribute_t)(attrSlice),
		length:                       C.size_t(len(attrs)),
		omitAllFromKeysUnlessPresent: false,
	}
	runtime.SetFinalizer(attrList, func(al *C.embedded_pairing_wkdibe_attributelist_t) {
		C.free(unsafe.Pointer(al.attrs))
	})
	return attrList
}

func allocateSecretKeyB(sk *SecretKey, length int) {
	if length < 0 {
		panic("Too many attributes in attribute list")
	} else if length == 0 {
		sk.Data.b = nil
	} else {
		sk.Data.b = (*C.embedded_pairing_wkdibe_freeslot_t)(C.malloc(C.size_t(length) * C.sizeof_embedded_pairing_wkdibe_freeslot_t))
		runtime.SetFinalizer(sk, func(k *SecretKey) {
			C.free(unsafe.Pointer(k.Data.b))
		})
	}
}

// NumAttributes returns the number of attributes supported. This was specified
// via the "l" argument when Setup was called.
func (params *Params) NumAttributes() int {
	return int(params.Data.l)
}

// Setup generates the system parameters, which may be made visible to an
// adversary. The parameter "l" is the total number of attributes supported
// (indexed from 0 to l - 1).
func Setup(l int, supportSignatures bool) (*Params, *MasterKey) {
	pp := new(Params)
	msk := new(MasterKey)
	pp.Data.h = (*C.embedded_pairing_wkdibe_g1_t)(C.malloc(C.size_t(l) * C.sizeof_embedded_pairing_wkdibe_g1_t))
	runtime.SetFinalizer(pp, func(p *Params) {
		C.free(unsafe.Pointer(p.Data.h))
	})
	C.embedded_pairing_wkdibe_setup(&pp.Data, &msk.Data, C.int(l), C._Bool(supportSignatures), internal.RandomBytesFunction)
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
	C.embedded_pairing_wkdibe_keygen(&sk.Data, &params.Data, &msk.Data, convertAttributeList(attrs), internal.RandomBytesFunction)
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
	C.embedded_pairing_wkdibe_qualifykey(&sk.Data, &params.Data, &qualify.Data, convertAttributeList(attrs), internal.RandomBytesFunction)
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
	C.embedded_pairing_wkdibe_nondelegable_keygen(&sk.Data, &params.Data, &msk.Data, convertAttributeList(attrs))
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
	C.embedded_pairing_wkdibe_nondelegable_qualifykey(&sk.Data, &params.Data, &qualify.Data, convertAttributeList(attrs))
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
		allocateSecretKeyB(sk, int(key.Data.l))
	} else {
		sk.Data.b = nil
	}
	C.embedded_pairing_wkdibe_resamplekey(&sk.Data, &params.Data, &precomputed.Data, &key.Data, C._Bool(supportFurtherQualification), internal.RandomBytesFunction)
	return sk
}

// AdjustNonDelegable takes in a non-delegable key and the parent from which it
// was generated, and cheaply converts it into a non-delegable key for a
// different attribute set that could also be generated from the parent.
func AdjustNonDelegable(sk *SecretKey, parent *SecretKey, from AttributeList, to AttributeList) {
	length := int(parent.Data.l)
	if length != int(sk.Data.l) {
		if length == 0 {
			if sk.Data.b != nil {
				runtime.SetFinalizer(sk, nil)
				C.free(unsafe.Pointer(sk.Data.b))
				sk.Data.b = nil
			}
		} else if sk.Data.b == nil {
			allocateSecretKeyB(sk, length)
		} else {
			sk.Data.b = (*C.embedded_pairing_wkdibe_freeslot_t)(C.realloc(unsafe.Pointer(sk.Data.b), C.size_t(length)*C.sizeof_embedded_pairing_wkdibe_freeslot_t))
			if sk.Data.b == nil {
				panic("out of memory")
			}
		}
	}
	C.embedded_pairing_wkdibe_adjust_nondelegable(&sk.Data, &parent.Data, convertAttributeList(from), convertAttributeList(to))
}

// PrepareAttributeList performs precomputation for the provided attribute
// list, to speed up future encryption or verification with that attribute
// list. The returned precomputed result can be safely reused multiple times.
// This can be useful if you are repeatedly encrypting messages or verifying
// signatures with the same attribute list and want to speed things up.
func PrepareAttributeList(params *Params, attrs AttributeList) *PreparedAttributeList {
	prepared := new(PreparedAttributeList)
	C.embedded_pairing_wkdibe_precompute(&prepared.Data, &params.Data, convertAttributeList(attrs))
	return prepared
}

// AdjustPreparedAttributeList takes as input a prepared attribute list, and
// modifies it to correspond to a different attribute list.
func AdjustPreparedAttributeList(prepared *PreparedAttributeList, params *Params, from AttributeList, to AttributeList) {
	C.embedded_pairing_wkdibe_adjust_precomputed(&prepared.Data, &params.Data, convertAttributeList(from), convertAttributeList(to))
}

// Encrypt converts the provided message to ciphertext, using the provided
// Attribute List and public parameters.
func Encrypt(message *cryptutils.Encryptable, params *Params, attrs AttributeList) *Ciphertext {
	ciphertext := new(Ciphertext)
	C.embedded_pairing_wkdibe_encrypt(&ciphertext.Data, (*C.embedded_pairing_wkdibe_gt_t)(unsafe.Pointer(&message.Data)), &params.Data, convertAttributeList(attrs), internal.RandomBytesFunction)
	return ciphertext
}

// EncryptPrepared encrypts the provided message, using the provided prepared
// attribute list to speed up the process.
func EncryptPrepared(message *cryptutils.Encryptable, params *Params, prepared *PreparedAttributeList) *Ciphertext {
	ciphertext := new(Ciphertext)
	C.embedded_pairing_wkdibe_encrypt_precomputed(&ciphertext.Data, (*C.embedded_pairing_wkdibe_gt_t)(unsafe.Pointer(&message.Data)), &params.Data, &prepared.Data, internal.RandomBytesFunction)
	return ciphertext
}

// Decrypt recovers the original message from the provided ciphertext, using
// the provided secret key.
func Decrypt(ciphertext *Ciphertext, sk *SecretKey) *cryptutils.Encryptable {
	message := new(cryptutils.Encryptable)
	C.embedded_pairing_wkdibe_decrypt((*C.embedded_pairing_wkdibe_gt_t)(unsafe.Pointer(&message.Data)), &ciphertext.Data, &sk.Data)
	return message
}

// DecryptWithMaster is the same as Decrypt, but requires the master key to be
// provided. It is substantially more efficient than generating a private key
// and then calling Decrypt.
func DecryptWithMaster(ciphertext *Ciphertext, msk *MasterKey) *cryptutils.Encryptable {
	message := new(cryptutils.Encryptable)
	C.embedded_pairing_wkdibe_decrypt_master((*C.embedded_pairing_wkdibe_gt_t)(unsafe.Pointer(&message.Data)), &ciphertext.Data, &msk.Data)
	return message
}

// Sign produces a signature for the provided message hash, using the provided
// secret key. The signature may be produced on a more specialized attribute
// list than the key; alternatively, ATTRS may be left a nil if this is not
// needed.
func Sign(params *Params, sk *SecretKey, attrs AttributeList, message *cryptutils.Signable) *Signature {
	signature := new(Signature)
	C.embedded_pairing_wkdibe_sign(&signature.Data, &params.Data, &sk.Data, convertAttributeList(attrs), (*C.embedded_pairing_wkdibe_scalar_t)(unsafe.Pointer(&message.Data)), internal.RandomBytesFunction)
	return signature
}

// SignPrepared produces a signature for the provided message hash, using the
// provided prepared attribute list to speed up the process. The signature may
// be produced on a more specialized attribute list than the key; alternatively,
// ATTRS may be left a nil if this is not needed.
func SignPrepared(params *Params, sk *SecretKey, attrs AttributeList, prepared *PreparedAttributeList, message *cryptutils.Signable) *Signature {
	signature := new(Signature)
	C.embedded_pairing_wkdibe_sign_precomputed(&signature.Data, &params.Data, &sk.Data, convertAttributeList(attrs), &prepared.Data, (*C.embedded_pairing_wkdibe_scalar_t)(unsafe.Pointer(&message.Data)), internal.RandomBytesFunction)
	return signature
}

// Verify verifies that the provided signature was produced using a secret key
// corresponding to the provided attribute set.
func Verify(params *Params, attrs AttributeList, signature *Signature, message *cryptutils.Signable) bool {
	return bool(C.embedded_pairing_wkdibe_verify(&params.Data, convertAttributeList(attrs), &signature.Data, (*C.embedded_pairing_wkdibe_scalar_t)(unsafe.Pointer(&message.Data))))
}

// VerifyPrepared verifies the provided signature, using the provided prepared
// attribute list to speed up the process.
func VerifyPrepared(params *Params, prepared *PreparedAttributeList, signature *Signature, message *cryptutils.Signable) bool {
	return bool(C.embedded_pairing_wkdibe_verify_precomputed(&params.Data, &prepared.Data, &signature.Data, (*C.embedded_pairing_wkdibe_scalar_t)(unsafe.Pointer(&message.Data))))
}
