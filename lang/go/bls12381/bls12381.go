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
#cgo CFLAGS: -I ../../../include
#cgo LDFLAGS: ${SRCDIR}/pairing.a
#include <stdlib.h>
#include <string.h>
#include "bls12_381/bls12_381.h"
*/
import "C"
import (
	"math/big"
	"unsafe"

	"github.com/samkumar/embedded-pairing/lang/go/internal"
	"golang.org/x/crypto/sha3"
)

// GroupOrder is a 255-bit prime number that is the order of G1, G2, and GT.
var GroupOrder, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

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
	var x C.embedded_pairing_core_bigint_256_t
	var hash [C.sizeof_embedded_pairing_core_bigint_256_t]byte

	shake := sha3.NewShake256()
	shake.Write(buffer)
	shake.Read(hash[:])

	C.embedded_pairing_bls12_381_zp_from_hash(&x, unsafe.Pointer(&hash[0]))
	internal.BigIntFromC(result, unsafe.Pointer(&x), C.sizeof_embedded_pairing_core_bigint_256_t)
	return result
}

// G1 is an element of G1, the smaller and faster source group of the BLS12-381
// pairing, in projective representation.
type G1 struct {
	data C.embedded_pairing_bls12_381_g1_t
}

// G1Affine is an element of G1, the smaller and faster source group of the
// BLS12-381 pairing, in affine representation.
type G1Affine struct {
	data C.embedded_pairing_bls12_381_g1affine_t
}

// G2 is an element of G2, the larger and slower source group of the BLS12-381
// pairing, in projective representation.
type G2 struct {
	data C.embedded_pairing_bls12_381_g2_t
}

// G2Affine is an element of G2, the larger and slower source group of the
// BLS12-381 pairing, in affine representation.
type G2Affine struct {
	data C.embedded_pairing_bls12_381_g2affine_t
}

// GT represents an element of GT, the target group of the BLS12-381 pairing.
type GT struct {
	data C.embedded_pairing_bls12_381_fq12_t
}

// G1AffineGenerator is the generator of group G1.
var G1GeneratorAffine = (*G1Affine)(unsafe.Pointer(C.embedded_pairing_bls12_381_g1affine_generator))

// G2AffineGenerator is the generator of group G2.
var G2GeneratorAffine = (*G2Affine)(unsafe.Pointer(C.embedded_pairing_bls12_381_g2affine_generator))

// GTGenerator is the generator of group GT.
var GTGenerator = (*GT)(unsafe.Pointer(C.embedded_pairing_bls12_381_gt_generator))

// Add computes result := a + b.
func (result *G1) Add(a *G1, b *G1) *G1 {
	C.embedded_pairing_bls12_381_g1_add(&result.data, &a.data, &b.data)
	return result
}

// AddMixed computes result := a + b.
func (result *G1) AddMixed(a *G1, b *G1Affine) *G1 {
	C.embedded_pairing_bls12_381_g1_add_mixed(&result.data, &a.data, &b.data)
	return result
}

// Negate computes result := -a.
func (result *G1) Negate(a *G1) *G1 {
	C.embedded_pairing_bls12_381_g1_negate(&result.data, &a.data)
	return result
}

// Double computes result := 2 * a.
func (result *G1) Double(a *G1) *G1 {
	C.embedded_pairing_bls12_381_g1_double(&result.data, &a.data)
	return result
}

// Multiply computes result := scalar * a.
func (result *G1) Multiply(a *G1, scalar *big.Int) *G1 {
	var s C.embedded_pairing_core_bigint_256_t
	internal.BigIntToC(unsafe.Pointer(&s), C.sizeof_embedded_pairing_core_bigint_256_t, scalar)
	C.embedded_pairing_bls12_381_g1_multiply(&result.data, &a.data, &s)
	return result
}

// MultiplyAffine computes result := scalar * a.
func (result *G1) MultiplyAffine(a *G1Affine, scalar *big.Int) *G1 {
	var s C.embedded_pairing_core_bigint_256_t
	internal.BigIntToC(unsafe.Pointer(&s), C.sizeof_embedded_pairing_core_bigint_256_t, scalar)
	C.embedded_pairing_bls12_381_g1_multiply_affine(&result.data, &a.data, &s)
	return result
}

// Random samples an element of G1 uniformly at random and stores it in result.
func (result *G1) Random() *G1 {
	C.embedded_pairing_bls12_381_g1_random(&result.data, internal.RandomBytesFunction)
	return result
}

// Copy computes result := a.
func (result *G1) Copy(a *G1) *G1 {
	C.memcpy(unsafe.Pointer(&result.data), unsafe.Pointer(&a.data), C.sizeof_embedded_pairing_bls12_381_g1_t)
	return result
}

// FromAffine computes result := a.
func (result *G1) FromAffine(a *G1Affine) *G1 {
	C.embedded_pairing_bls12_381_g1_from_affine(&result.data, &a.data)
	return result
}

// FromProjective computes result := a.
func (result *G1Affine) FromProjective(a *G1) *G1Affine {
	C.embedded_pairing_bls12_381_g1affine_from_projective(&result.data, &a.data)
	return result
}

// Negate computes result := -a.
func (result *G1Affine) Negate(a *G1Affine) *G1Affine {
	C.embedded_pairing_bls12_381_g1affine_negate(&result.data, &a.data)
	return result
}

// Hash hashes the contents of the provided buffer to an element of G1, and
// stores it in result.
func (result *G1Affine) Hash(buffer []byte) *G1Affine {
	var hash [C.sizeof_embedded_pairing_bls12_381_fq_t]byte

	shake := sha3.NewShake256()
	shake.Write(buffer)
	shake.Read(hash[:])

	C.embedded_pairing_bls12_381_g1affine_from_hash(&result.data, unsafe.Pointer(&hash[0]))
	return result
}

// Copy computes result := a.
func (result *G1Affine) Copy(a *G1Affine) *G1Affine {
	C.memcpy(unsafe.Pointer(&result.data), unsafe.Pointer(&a.data), C.sizeof_embedded_pairing_bls12_381_g1affine_t)
	return result
}

// Add computes result := a + b.
func (result *G2) Add(a *G2, b *G2) *G2 {
	C.embedded_pairing_bls12_381_g2_add(&result.data, &a.data, &b.data)
	return result
}

// AddMixed computes result := a + b.
func (result *G2) AddMixed(a *G2, b *G2Affine) *G2 {
	C.embedded_pairing_bls12_381_g2_add_mixed(&result.data, &a.data, &b.data)
	return result
}

// Negate computes result := -a.
func (result *G2) Negate(a *G2) *G2 {
	C.embedded_pairing_bls12_381_g2_negate(&result.data, &a.data)
	return result
}

// Double computes result := 2 * a.
func (result *G2) Double(a *G2) *G2 {
	C.embedded_pairing_bls12_381_g2_double(&result.data, &a.data)
	return result
}

// Multiply computes result := scalar * a.
func (result *G2) Multiply(a *G2, scalar *big.Int) *G2 {
	var s C.embedded_pairing_core_bigint_256_t
	internal.BigIntToC(unsafe.Pointer(&s), C.sizeof_embedded_pairing_core_bigint_256_t, scalar)
	C.embedded_pairing_bls12_381_g2_multiply(&result.data, &a.data, &s)
	return result
}

// MultiplyAffine computes result := scalar * a.
func (result *G2) MultiplyAffine(a *G2Affine, scalar *big.Int) *G2 {
	var s C.embedded_pairing_core_bigint_256_t
	internal.BigIntToC(unsafe.Pointer(&s), C.sizeof_embedded_pairing_core_bigint_256_t, scalar)
	C.embedded_pairing_bls12_381_g2_multiply_affine(&result.data, &a.data, &s)
	return result
}

// Random samples an element of G2 uniformly at random and stores it in result.
func (result *G2) Random() *G2 {
	C.embedded_pairing_bls12_381_g2_random(&result.data, internal.RandomBytesFunction)
	return result
}

// Copy computes result := a.
func (result *G2) Copy(a *G2) *G2 {
	C.memcpy(unsafe.Pointer(&result.data), unsafe.Pointer(&a.data), C.sizeof_embedded_pairing_bls12_381_g2_t)
	return result
}

// FromAffine computes result := a.
func (result *G2) FromAffine(a *G2Affine) *G2 {
	C.embedded_pairing_bls12_381_g2_from_affine(&result.data, &a.data)
	return result
}

// FromProjective computes result := a.
func (result *G2Affine) FromProjective(a *G2) *G2Affine {
	C.embedded_pairing_bls12_381_g2affine_from_projective(&result.data, &a.data)
	return result
}

// Negate computes result := -a.
func (result *G2Affine) Negate(a *G2Affine) *G2Affine {
	C.embedded_pairing_bls12_381_g2affine_negate(&result.data, &a.data)
	return result
}

// Hash hashes the contents of the provided buffer to an element of G2, and
// stores it in result.
func (result *G2Affine) Hash(buffer []byte) *G2Affine {
	var hash [C.sizeof_embedded_pairing_bls12_381_fq2_t]byte

	shake := sha3.NewShake256()
	shake.Write(buffer)
	shake.Read(hash[:])

	C.embedded_pairing_bls12_381_g2affine_from_hash(&result.data, unsafe.Pointer(&hash[0]))
	return result
}

// Copy computes result := a.
func (result *G2Affine) Copy(a *G2Affine) *G2Affine {
	C.memcpy(unsafe.Pointer(&result.data), unsafe.Pointer(&a.data), C.sizeof_embedded_pairing_bls12_381_g2affine_t)
	return result
}

// Add computes result := a + b.
func (result *GT) Add(a *GT, b *GT) *GT {
	C.embedded_pairing_bls12_381_gt_add(&result.data, &a.data, &b.data)
	return result
}

// Negate computes result := -a.
func (result *GT) Negate(a *GT) *GT {
	C.embedded_pairing_bls12_381_gt_negate(&result.data, &a.data)
	return result
}

// Double computes result := 2 * a.
func (result *GT) Double(a *GT) *GT {
	C.embedded_pairing_bls12_381_gt_double(&result.data, &a.data)
	return result
}

// Multiply computes result := scalar * a.
func (result *GT) Multiply(a *GT, scalar *big.Int) *GT {
	var s C.embedded_pairing_core_bigint_256_t
	internal.BigIntToC(unsafe.Pointer(&s), C.sizeof_embedded_pairing_core_bigint_256_t, scalar)
	C.embedded_pairing_bls12_381_gt_multiply(&result.data, &a.data, &s)
	return result
}

// Random computes result := scalar * a, where scalar is a random element of
// Zp, and then returns the chosen scalar. This is significantly faster than
// sampling a random scalar in Zp and then calling Multiply().
func (result *GT) Random(a *GT) (*GT, *big.Int) {
	var s C.embedded_pairing_core_bigint_256_t
	C.embedded_pairing_bls12_381_gt_multiply_random(&result.data, &s, &a.data, internal.RandomBytesFunction)

	scalar := new(big.Int)
	internal.BigIntFromC(scalar, unsafe.Pointer(&s), C.sizeof_embedded_pairing_core_bigint_256_t)
	return result, scalar
}

// Copy computes result := a.
func (result *GT) Copy(a *GT) *GT {
	C.memcpy(unsafe.Pointer(&result.data), unsafe.Pointer(&a.data), C.sizeof_embedded_pairing_bls12_381_fq12_t)
	return result
}

// Pairing computes result := e(a, b).
func (result *GT) Pairing(a *G1Affine, b *G2Affine) *GT {
	C.embedded_pairing_bls12_381_pairing(&result.data, &a.data, &b.data)
	return result
}

// PairingSum computes the sum of e(a[i], b[i]) for i = 0 ... len(a) - 1, and
// stores it in result. It is significantly faster than computing each term
// separately using Pairing() and then computing the sum using Add.
func (result *GT) PairingSum(a []*G1Affine, b []*G2Affine) *GT {
	numPairs := C.size_t(len(a))
	pairsPointer := C.malloc(numPairs * C.sizeof_embedded_pairing_bls12_381_pair_t)
	defer C.free(pairsPointer)

	pairs := (*C.embedded_pairing_bls12_381_pair_t)(pairsPointer)
	for i := range a {
		pair := (*C.embedded_pairing_bls12_381_pair_t)(unsafe.Pointer(uintptr(pairsPointer) + uintptr(i)*C.sizeof_embedded_pairing_bls12_381_pair_t))
		pair.g1 = &a[i].data
		pair.g2 = &b[i].data
	}

	C.embedded_pairing_bls12_381_pairing_sum(&result.data, pairs, numPairs)
	return result
}
