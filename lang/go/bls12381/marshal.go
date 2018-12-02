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

package bls12381

/*
#include "bls12_381/bls12_381.h"
*/
import "C"
import "unsafe"

// Sizes of group elements when marshalled
var (
	G1MarshalledCompressedSize   = int(C.embedded_pairing_bls12_381_g1_marshalled_compressed_size)
	G1MarshalledUncompressedSize = int(C.embedded_pairing_bls12_381_g1_marshalled_uncompressed_size)

	G2MarshalledCompressedSize   = int(C.embedded_pairing_bls12_381_g2_marshalled_compressed_size)
	G2MarshalledUncompressedSize = int(C.embedded_pairing_bls12_381_g2_marshalled_uncompressed_size)

	GTMarshalledSize = int(C.embedded_pairing_bls12_381_gt_marshalled_size)
)

// Marshal encodes an element of G1 into the provided byte slice, in either
// compressed or uncompressed form depending on the argument, and then returns
// the byte slice.
func (g *G1Affine) Marshal(into []byte, compressed bool) []byte {
	var size int
	if compressed {
		size = G1MarshalledCompressedSize
	} else {
		size = G1MarshalledUncompressedSize
	}
	if len(into) < size {
		return nil
	}
	C.embedded_pairing_bls12_381_g1_marshal(unsafe.Pointer(&into[0]), &g.Data, C._Bool(compressed))
	return into
}

// Unmarshal recovers an element of G1 from a byte slice, which must encode
// either its compressed or uncompressed form, depending on the argument. If
// CHECKED is set to false, then unmarshalling is faster (some checks on the
// result are skipped), but the function will not detect if the resulting group
// element is invalid.
func (g *G1Affine) Unmarshal(marshalled []byte, compressed bool, checked bool) *G1Affine {
	var size int
	if compressed {
		size = G1MarshalledCompressedSize
	} else {
		size = G1MarshalledUncompressedSize
	}
	if len(marshalled) < size || !C.embedded_pairing_bls12_381_g1_unmarshal(&g.Data, unsafe.Pointer(&marshalled[0]), C._Bool(compressed), C._Bool(checked)) {
		return nil
	}
	return g
}

// Marshal encodes an element of G2 into the provided byte slice, in either
// compressed or uncompressed form depending on the argument, and then returns
// the byte slice.
func (g *G2Affine) Marshal(into []byte, compressed bool) []byte {
	var size int
	if compressed {
		size = G2MarshalledCompressedSize
	} else {
		size = G2MarshalledUncompressedSize
	}
	if len(into) < size {
		return nil
	}
	C.embedded_pairing_bls12_381_g2_marshal(unsafe.Pointer(&into[0]), &g.Data, C._Bool(compressed))
	return into
}

// Unmarshal recovers an element of G2 from a byte slice, which must encode
// either its compressed or uncompressed form, depending on the argument. If
// CHECKED is set to false, then unmarshalling is faster (some checks on the
// result are skipped), but the function will not detect if the resulting group
// element is invalid.
func (g *G2Affine) Unmarshal(marshalled []byte, compressed bool, checked bool) *G2Affine {
	var size int
	if compressed {
		size = G2MarshalledCompressedSize
	} else {
		size = G2MarshalledUncompressedSize
	}
	if len(marshalled) < size || !C.embedded_pairing_bls12_381_g2_unmarshal(&g.Data, unsafe.Pointer(&marshalled[0]), C._Bool(compressed), C._Bool(checked)) {
		return nil
	}
	return g
}

// Marshal encodes an element of GT into the provided byte slice, and then
// returns the byte slice.
func (g *GT) Marshal(into []byte) []byte {
	if len(into) < GTMarshalledSize {
		return nil
	}
	C.embedded_pairing_bls12_381_gt_marshal(unsafe.Pointer(&into[0]), &g.Data)
	return into
}

// Unmarshal recovers an element of GT from a byte slice.
func (g *GT) Unmarshal(marshalled []byte) *GT {
	if len(marshalled) < GTMarshalledSize {
		return nil
	}
	C.embedded_pairing_bls12_381_gt_unmarshal(&g.Data, unsafe.Pointer(&marshalled[0]))
	return g
}
