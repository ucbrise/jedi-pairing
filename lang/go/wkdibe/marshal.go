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

/*
#include <stdlib.h>
#include "wkdibe/wkdibe.h"
*/
import "C"

import (
	"runtime"
	"unsafe"
)

// Marshal encodes a Params object into a byte slice in either compressed or
// uncompressed form, depending on the argument.
func (p *Params) Marshal(compressed bool) []byte {
	length := C.embedded_pairing_wkdibe_params_get_marshalled_length(&p.Data, C._Bool(compressed))
	marshalled := make([]byte, length)
	C.embedded_pairing_wkdibe_params_marshal(unsafe.Pointer(&marshalled[0]), &p.Data, C._Bool(compressed))
	return marshalled
}

// Unmarshal recovers a Params object from a byte slice, which must encode
// either its compressed or uncompressed form, depending on the argument. If
// CHECKED is set to false, then unmarshalling is faster (some checks on the
// result are skipped), but the function will not detect if the group elements
// are not valid.
func (p *Params) Unmarshal(marshalled []byte, compressed bool, checked bool) bool {
	if len(marshalled) == 0 {
		return false
	}
	arrlength := C.embedded_pairing_wkdibe_params_set_length(&p.Data, unsafe.Pointer(&marshalled[0]), C.size_t(len(marshalled)), C._Bool(compressed))

	/* Allocate memory and set p.Data.h */
	if arrlength == -1 {
		return false
	} else if arrlength == 0 {
		if p.Data.h != nil {
			runtime.SetFinalizer(p, nil)
			C.free(unsafe.Pointer(p.Data.h))
			p.Data.h = nil
		}
	} else {
		blocksize := C.size_t(arrlength) * C.sizeof_embedded_pairing_wkdibe_g1_t
		if p.Data.h == nil {
			p.Data.h = (*C.embedded_pairing_wkdibe_g1_t)(C.malloc(blocksize))
			runtime.SetFinalizer(p, func(pp *Params) {
				C.free(unsafe.Pointer(pp.Data.h))
			})
		} else {
			p.Data.h = (*C.embedded_pairing_wkdibe_g1_t)(C.realloc(unsafe.Pointer(p.Data.h), blocksize))
			if p.Data.h == nil {
				panic("out of memory")
			}
		}
	}

	return bool(C.embedded_pairing_wkdibe_params_unmarshal(&p.Data, unsafe.Pointer(&marshalled[0]), C._Bool(compressed), C._Bool(checked)))
}

// CiphertextMarshalledLength returns the length, in bytes, of a marshalled
// ciphertext.
func CiphertextMarshalledLength(compressed bool) int {
	return int(C.embedded_pairing_wkdibe_ciphertext_get_marshalled_length(C._Bool(compressed)))
}

// Marshal encodes a Ciphertext object into a byte slice in either compressed
// or uncompressed form, depending on the argument.
func (c *Ciphertext) Marshal(compressed bool) []byte {
	length := C.embedded_pairing_wkdibe_ciphertext_get_marshalled_length(C._Bool(compressed))
	marshalled := make([]byte, length)
	C.embedded_pairing_wkdibe_ciphertext_marshal(unsafe.Pointer(&marshalled[0]), &c.Data, C._Bool(compressed))
	return marshalled
}

// Unmarshal recovers a Ciphertext object from a byte slice, which must encode
// either its compressed on uncompressed form, depending on the argument. If
// CHECKED is set to false, then unmarshalling is faster (some checks on the
// result are skipped), but the function will not detect if the group elements
// are not valid.
func (c *Ciphertext) Unmarshal(marshalled []byte, compressed bool, checked bool) bool {
	if len(marshalled) == 0 {
		return false
	}
	if C.embedded_pairing_wkdibe_ciphertext_get_marshalled_length(C._Bool(compressed)) != C.size_t(len(marshalled)) {
		return false
	}
	return bool(C.embedded_pairing_wkdibe_ciphertext_unmarshal(&c.Data, unsafe.Pointer(&marshalled[0]), C._Bool(compressed), C._Bool(checked)))
}

// Marshal encodes a Signature object into a byte slice in either compressed
// or uncompressed form, depending on the argument.
func (s *Signature) Marshal(compressed bool) []byte {
	length := C.embedded_pairing_wkdibe_signature_get_marshalled_length(C._Bool(compressed))
	marshalled := make([]byte, length)
	C.embedded_pairing_wkdibe_signature_marshal(unsafe.Pointer(&marshalled[0]), &s.Data, C._Bool(compressed))
	return marshalled
}

// SignatureMarshalledLength returns the length, in bytes, of a marshalled
// signature.
func SignatureMarshalledLength(compressed bool) int {
	return int(C.embedded_pairing_wkdibe_signature_get_marshalled_length(C._Bool(compressed)))
}

// Unmarshal recovers a Signature object from a byte slice, which must encode
// either its compressed on uncompressed form, depending on the argument. If
// CHECKED is set to false, then unmarshalling is faster (some checks on the
// result are skipped), but the function will not detect if the group elements
// are not valid.
func (s *Signature) Unmarshal(marshalled []byte, compressed bool, checked bool) bool {
	if len(marshalled) == 0 {
		return false
	}
	if C.embedded_pairing_wkdibe_signature_get_marshalled_length(C._Bool(compressed)) != C.size_t(len(marshalled)) {
		return false
	}
	return bool(C.embedded_pairing_wkdibe_signature_unmarshal(&s.Data, unsafe.Pointer(&marshalled[0]), C._Bool(compressed), C._Bool(checked)))
}

// Marshal encodes a SecretKey object into a byte slice in either compressed or
// uncompressed form, depending on the argument.
func (sk *SecretKey) Marshal(compressed bool) []byte {
	length := C.embedded_pairing_wkdibe_secretkey_get_marshalled_length(&sk.Data, C._Bool(compressed))
	marshalled := make([]byte, length)
	C.embedded_pairing_wkdibe_secretkey_marshal(unsafe.Pointer(&marshalled[0]), &sk.Data, C._Bool(compressed))
	return marshalled
}

// Unmarshal recovers a SecretKey object from a byte slice, which must encode
// either its compressed on uncompressed form, depending on the argument. If
// CHECKED is set to false, then unmarshalling is faster (some checks on the
// result are skipped), but the function will not detect if the group elements
// are not valid.
func (sk *SecretKey) Unmarshal(marshalled []byte, compressed bool, checked bool) bool {
	if len(marshalled) == 0 {
		return false
	}
	arrlength := C.embedded_pairing_wkdibe_secretkey_set_length(&sk.Data, unsafe.Pointer(&marshalled[0]), C.size_t(len(marshalled)), C._Bool(compressed))

	/* Allocate memory and set p.Data.h */
	if arrlength == -1 {
		return false
	} else if arrlength == 0 {
		if sk.Data.b != nil {
			runtime.SetFinalizer(sk, nil)
			C.free(unsafe.Pointer(sk.Data.b))
			sk.Data.b = nil
		}
	} else {
		blocksize := C.size_t(arrlength) * C.sizeof_embedded_pairing_wkdibe_freeslot_t
		if sk.Data.b == nil {
			sk.Data.b = (*C.embedded_pairing_wkdibe_freeslot_t)(C.malloc(blocksize))
			runtime.SetFinalizer(sk, func(k *SecretKey) {
				C.free(unsafe.Pointer(k.Data.b))
			})
		} else {
			sk.Data.b = (*C.embedded_pairing_wkdibe_freeslot_t)(C.realloc(unsafe.Pointer(sk.Data.b), blocksize))
			if sk.Data.b == nil {
				panic("out of memory")
			}
		}
	}

	return bool(C.embedded_pairing_wkdibe_secretkey_unmarshal(&sk.Data, unsafe.Pointer(&marshalled[0]), C._Bool(compressed), C._Bool(checked)))
}

// Marshal encodes a MasterKey object into a byte slice in either compressed or
// uncompressed form, depending on the argument.
func (msk *MasterKey) Marshal(compressed bool) []byte {
	length := C.embedded_pairing_wkdibe_masterkey_get_marshalled_length(C._Bool(compressed))
	marshalled := make([]byte, length)
	C.embedded_pairing_wkdibe_masterkey_marshal(unsafe.Pointer(&marshalled[0]), &msk.Data, C._Bool(compressed))
	return marshalled
}

// Unmarshal recovers a MasterKey object from a byte slice, which must encode
// either its compressed on uncompressed form, depending on the argument. If
// CHECKED is set to false, then unmarshalling is faster (some checks on the
// result are skipped), but the function will not detect if the group elements
// are not valid.
func (msk *MasterKey) Unmarshal(marshalled []byte, compressed bool, checked bool) bool {
	if len(marshalled) == 0 {
		return false
	}
	if C.embedded_pairing_wkdibe_masterkey_get_marshalled_length(C._Bool(compressed)) != C.size_t(len(marshalled)) {
		return false
	}
	return bool(C.embedded_pairing_wkdibe_masterkey_unmarshal(&msk.Data, unsafe.Pointer(&marshalled[0]), C._Bool(compressed), C._Bool(checked)))
}
