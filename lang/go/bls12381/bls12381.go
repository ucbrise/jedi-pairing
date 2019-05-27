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

// Package bls12381 provides a Go interface to the implementation of the
// BLS12-381 bilinear pairing. See https://z.cash/blog/new-snark-curve/ for
// more information about BLS12-381.
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

	"github.com/ucbrise/jedi-pairing/lang/go/internal"
	"golang.org/x/crypto/sha3"
)

// GroupOrder is a 255-bit prime number that is the order of G1, G2, and GT.
var GroupOrder = internal.BigIntFromC(new(big.Int), unsafe.Pointer(C.embedded_pairing_bls12_381_group_order), 32)

// G1 is an element of G1, the smaller and faster source group of the BLS12-381
// pairing, in projective representation.
type G1 struct {
	Data C.embedded_pairing_bls12_381_g1_t
}

// G1Affine is an element of G1, the smaller and faster source group of the
// BLS12-381 pairing, in affine representation.
type G1Affine struct {
	Data C.embedded_pairing_bls12_381_g1affine_t
}

// G2 is an element of G2, the larger and slower source group of the BLS12-381
// pairing, in projective representation.
type G2 struct {
	Data C.embedded_pairing_bls12_381_g2_t
}

// G2Affine is an element of G2, the larger and slower source group of the
// BLS12-381 pairing, in affine representation.
type G2Affine struct {
	Data C.embedded_pairing_bls12_381_g2affine_t
}

// G2Prepared represents a precomputed value derived from an element of G2 that
// accelerates pairing computations involving that element. Note that this is
// large (~20 KB) compared to other structures in this library.
type G2Prepared struct {
	Data C.embedded_pairing_bls12_381_g2prepared_t
}

// GT represents an element of GT, the target group of the BLS12-381 pairing.
type GT struct {
	Data C.embedded_pairing_bls12_381_fq12_t
}

// G1Zero is the zero (identity) element of group G1, in projective
// representation.
var G1Zero = (*G1)(unsafe.Pointer(C.embedded_pairing_bls12_381_g1_zero))

// G1ZeroAffine is the zero (identity) element of group G1, in affine
// representation.
var G1ZeroAffine = (*G1Affine)(unsafe.Pointer(C.embedded_pairing_bls12_381_g1affine_zero))

// G1GeneratorAffine is a generator of group G1, in affine representation.
var G1GeneratorAffine = (*G1Affine)(unsafe.Pointer(C.embedded_pairing_bls12_381_g1affine_generator))

// G2Zero is the zero (identity) element of group G2, in projective
// representation.
var G2Zero = (*G2)(unsafe.Pointer(C.embedded_pairing_bls12_381_g2_zero))

// G2ZeroAffine is the zero (identity) element of group G2, in affine
// representation.
var G2ZeroAffine = (*G2Affine)(unsafe.Pointer(C.embedded_pairing_bls12_381_g2affine_zero))

// G2GeneratorAffine is a generator of group G2, in affine representation.
var G2GeneratorAffine = (*G2Affine)(unsafe.Pointer(C.embedded_pairing_bls12_381_g2affine_generator))

// GTZero is the zero (identity) element of group GT.
var GTZero = (*GT)(unsafe.Pointer(C.embedded_pairing_bls12_381_gt_zero))

// GTGenerator is the generator of group GT.
var GTGenerator = (*GT)(unsafe.Pointer(C.embedded_pairing_bls12_381_gt_generator))

// Add computes result := a + b.
func (result *G1) Add(a *G1, b *G1) *G1 {
	C.embedded_pairing_bls12_381_g1_add(&result.Data, &a.Data, &b.Data)
	return result
}

// AddMixed computes result := a + b.
func (result *G1) AddMixed(a *G1, b *G1Affine) *G1 {
	C.embedded_pairing_bls12_381_g1_add_mixed(&result.Data, &a.Data, &b.Data)
	return result
}

// Negate computes result := -a.
func (result *G1) Negate(a *G1) *G1 {
	C.embedded_pairing_bls12_381_g1_negate(&result.Data, &a.Data)
	return result
}

// Double computes result := 2 * a.
func (result *G1) Double(a *G1) *G1 {
	C.embedded_pairing_bls12_381_g1_double(&result.Data, &a.Data)
	return result
}

// Multiply computes result := scalar * a.
func (result *G1) Multiply(a *G1, scalar *big.Int) *G1 {
	var s C.embedded_pairing_core_bigint_256_t
	internal.BigIntToC(unsafe.Pointer(&s), C.sizeof_embedded_pairing_core_bigint_256_t, scalar)
	C.embedded_pairing_bls12_381_g1_multiply(&result.Data, &a.Data, &s)
	return result
}

// MultiplyAffine computes result := scalar * a.
func (result *G1) MultiplyAffine(a *G1Affine, scalar *big.Int) *G1 {
	var s C.embedded_pairing_core_bigint_256_t
	internal.BigIntToC(unsafe.Pointer(&s), C.sizeof_embedded_pairing_core_bigint_256_t, scalar)
	C.embedded_pairing_bls12_381_g1_multiply_affine(&result.Data, &a.Data, &s)
	return result
}

// Random samples an element of G1 uniformly at random and stores it in result.
func (result *G1) Random() *G1 {
	C.embedded_pairing_bls12_381_g1_random(&result.Data, internal.RandomBytesFunction)
	return result
}

// Copy computes result := a.
func (result *G1) Copy(a *G1) *G1 {
	C.memcpy(unsafe.Pointer(&result.Data), unsafe.Pointer(&a.Data), C.sizeof_embedded_pairing_bls12_381_g1_t)
	return result
}

// G1Equal tests whether two elements of G1 are equal.
func G1Equal(a *G1, b *G1) bool {
	return bool(C.embedded_pairing_bls12_381_g1_equal(&a.Data, &b.Data))
}

// FromAffine computes result := a.
func (result *G1) FromAffine(a *G1Affine) *G1 {
	C.embedded_pairing_bls12_381_g1_from_affine(&result.Data, &a.Data)
	return result
}

// FromProjective computes result := a.
func (result *G1Affine) FromProjective(a *G1) *G1Affine {
	C.embedded_pairing_bls12_381_g1affine_from_projective(&result.Data, &a.Data)
	return result
}

// Negate computes result := -a.
func (result *G1Affine) Negate(a *G1Affine) *G1Affine {
	C.embedded_pairing_bls12_381_g1affine_negate(&result.Data, &a.Data)
	return result
}

// Hash hashes the contents of the provided buffer to an element of G1, and
// stores it in result.
func (result *G1Affine) Hash(buffer []byte) *G1Affine {
	var hash [C.sizeof_embedded_pairing_bls12_381_fq_t]byte

	shake := sha3.NewShake256()
	shake.Write(buffer)
	shake.Read(hash[:])

	C.embedded_pairing_bls12_381_g1affine_from_hash(&result.Data, unsafe.Pointer(&hash[0]))
	return result
}

// Copy computes result := a.
func (result *G1Affine) Copy(a *G1Affine) *G1Affine {
	C.memcpy(unsafe.Pointer(&result.Data), unsafe.Pointer(&a.Data), C.sizeof_embedded_pairing_bls12_381_g1affine_t)
	return result
}

// G1AffineEqual tests whether two elements of G1 are equal.
func G1AffineEqual(a *G1Affine, b *G1Affine) bool {
	return bool(C.embedded_pairing_bls12_381_g1affine_equal(&a.Data, &b.Data))
}

// Add computes result := a + b.
func (result *G2) Add(a *G2, b *G2) *G2 {
	C.embedded_pairing_bls12_381_g2_add(&result.Data, &a.Data, &b.Data)
	return result
}

// AddMixed computes result := a + b.
func (result *G2) AddMixed(a *G2, b *G2Affine) *G2 {
	C.embedded_pairing_bls12_381_g2_add_mixed(&result.Data, &a.Data, &b.Data)
	return result
}

// Negate computes result := -a.
func (result *G2) Negate(a *G2) *G2 {
	C.embedded_pairing_bls12_381_g2_negate(&result.Data, &a.Data)
	return result
}

// Double computes result := 2 * a.
func (result *G2) Double(a *G2) *G2 {
	C.embedded_pairing_bls12_381_g2_double(&result.Data, &a.Data)
	return result
}

// Multiply computes result := scalar * a.
func (result *G2) Multiply(a *G2, scalar *big.Int) *G2 {
	var s C.embedded_pairing_core_bigint_256_t
	internal.BigIntToC(unsafe.Pointer(&s), C.sizeof_embedded_pairing_core_bigint_256_t, scalar)
	C.embedded_pairing_bls12_381_g2_multiply(&result.Data, &a.Data, &s)
	return result
}

// MultiplyAffine computes result := scalar * a.
func (result *G2) MultiplyAffine(a *G2Affine, scalar *big.Int) *G2 {
	var s C.embedded_pairing_core_bigint_256_t
	internal.BigIntToC(unsafe.Pointer(&s), C.sizeof_embedded_pairing_core_bigint_256_t, scalar)
	C.embedded_pairing_bls12_381_g2_multiply_affine(&result.Data, &a.Data, &s)
	return result
}

// Random samples an element of G2 uniformly at random and stores it in result.
func (result *G2) Random() *G2 {
	C.embedded_pairing_bls12_381_g2_random(&result.Data, internal.RandomBytesFunction)
	return result
}

// Copy computes result := a.
func (result *G2) Copy(a *G2) *G2 {
	C.memcpy(unsafe.Pointer(&result.Data), unsafe.Pointer(&a.Data), C.sizeof_embedded_pairing_bls12_381_g2_t)
	return result
}

// G2Equal tests whether two elements of G2 are equal.
func G2Equal(a *G2, b *G2) bool {
	return bool(C.embedded_pairing_bls12_381_g2_equal(&a.Data, &b.Data))
}

// FromAffine computes result := a.
func (result *G2) FromAffine(a *G2Affine) *G2 {
	C.embedded_pairing_bls12_381_g2_from_affine(&result.Data, &a.Data)
	return result
}

// FromProjective computes result := a.
func (result *G2Affine) FromProjective(a *G2) *G2Affine {
	C.embedded_pairing_bls12_381_g2affine_from_projective(&result.Data, &a.Data)
	return result
}

// Negate computes result := -a.
func (result *G2Affine) Negate(a *G2Affine) *G2Affine {
	C.embedded_pairing_bls12_381_g2affine_negate(&result.Data, &a.Data)
	return result
}

// Hash hashes the contents of the provided buffer to an element of G2, and
// stores it in result.
func (result *G2Affine) Hash(buffer []byte) *G2Affine {
	var hash [C.sizeof_embedded_pairing_bls12_381_fq2_t]byte

	shake := sha3.NewShake256()
	shake.Write(buffer)
	shake.Read(hash[:])

	C.embedded_pairing_bls12_381_g2affine_from_hash(&result.Data, unsafe.Pointer(&hash[0]))
	return result
}

// Copy computes result := a.
func (result *G2Affine) Copy(a *G2Affine) *G2Affine {
	C.memcpy(unsafe.Pointer(&result.Data), unsafe.Pointer(&a.Data), C.sizeof_embedded_pairing_bls12_381_g2affine_t)
	return result
}

// G2AffineEqual tests whether two elements of G2 are equal.
func G2AffineEqual(a *G2Affine, b *G2Affine) bool {
	return bool(C.embedded_pairing_bls12_381_g2affine_equal(&a.Data, &b.Data))
}

// Prepare precomputes a value that can be used to accelerate future pairing
// computations using a (see PreparedPairing), and store it in result.
func (result *G2Prepared) Prepare(a *G2Affine) *G2Prepared {
	C.embedded_pairing_bls12_381_g2prepared_prepare(&result.Data, &a.Data)
	return result
}

// Add computes result := a + b.
func (result *GT) Add(a *GT, b *GT) *GT {
	C.embedded_pairing_bls12_381_gt_add(&result.Data, &a.Data, &b.Data)
	return result
}

// Negate computes result := -a.
func (result *GT) Negate(a *GT) *GT {
	C.embedded_pairing_bls12_381_gt_negate(&result.Data, &a.Data)
	return result
}

// Double computes result := 2 * a.
func (result *GT) Double(a *GT) *GT {
	C.embedded_pairing_bls12_381_gt_double(&result.Data, &a.Data)
	return result
}

// Multiply computes result := scalar * a.
func (result *GT) Multiply(a *GT, scalar *big.Int) *GT {
	var s C.embedded_pairing_core_bigint_256_t
	internal.BigIntToC(unsafe.Pointer(&s), C.sizeof_embedded_pairing_core_bigint_256_t, scalar)
	C.embedded_pairing_bls12_381_gt_multiply(&result.Data, &a.Data, &s)
	return result
}

// Random computes result := scalar * a, where scalar is a random element of
// Zp, and then returns the chosen scalar. This is significantly faster than
// sampling a random scalar in Zp and then calling Multiply().
func (result *GT) Random(a *GT) (*GT, *big.Int) {
	var s C.embedded_pairing_core_bigint_256_t
	C.embedded_pairing_bls12_381_gt_multiply_random(&result.Data, &s, &a.Data, internal.RandomBytesFunction)

	scalar := new(big.Int)
	internal.BigIntFromC(scalar, unsafe.Pointer(&s), C.sizeof_embedded_pairing_core_bigint_256_t)
	return result, scalar
}

// Copy computes result := a.
func (result *GT) Copy(a *GT) *GT {
	C.memcpy(unsafe.Pointer(&result.Data), unsafe.Pointer(&a.Data), C.sizeof_embedded_pairing_bls12_381_fq12_t)
	return result
}

// GTEqual test whether two elements of GT are equal.
func GTEqual(a *GT, b *GT) bool {
	return bool(C.embedded_pairing_bls12_381_gt_equal(&a.Data, &b.Data))
}

// Pairing computes result := e(a, b).
func (result *GT) Pairing(a *G1Affine, b *G2Affine) *GT {
	C.embedded_pairing_bls12_381_pairing(&result.Data, &a.Data, &b.Data)
	return result
}

// PreparedPairing computes result := e(a, b).
func (result *GT) PreparedPairing(a *G1Affine, b *G2Prepared) *GT {
	C.embedded_pairing_bls12_381_prepared_pairing(&result.Data, &a.Data, &b.Data)
	return result
}

// PairingSum computes the sum of e(a[i], b[i]) for i = 0 ... len(a) - 1 and
// e(c[j], d[j]) for j = 0 ... len(c) - 1 (so the sum of len(a) + len(c) terms
// total), and stores the in result. It is significantly faster than computing
// each term separately using Pairing() or PreparedPairing and then computing
// the sum using Add.
func (result *GT) PairingSum(a []*G1Affine, b []*G2Affine, c []*G1Affine, d []*G2Prepared) *GT {
	var affinePairs *C.embedded_pairing_bls12_381_affine_pair_t
	numAffinePairs := C.size_t(len(a))
	if numAffinePairs != 0 {
		aLen := numAffinePairs * C.sizeof_embedded_pairing_bls12_381_g1affine_t
		bLen := numAffinePairs * C.sizeof_embedded_pairing_bls12_381_g2affine_t
		pairsLen := numAffinePairs * C.sizeof_embedded_pairing_bls12_381_affine_pair_t

		buffer := C.malloc(aLen + bLen + pairsLen)
		defer C.free(buffer)

		affinePairs = (*C.embedded_pairing_bls12_381_affine_pair_t)(unsafe.Pointer(uintptr(buffer) + uintptr(aLen) + uintptr(bLen)))
		for i := range a {
			pair := (*C.embedded_pairing_bls12_381_affine_pair_t)(unsafe.Pointer(uintptr(buffer) + uintptr(aLen) + uintptr(bLen) + uintptr(i)*C.sizeof_embedded_pairing_bls12_381_affine_pair_t))
			pair.g1 = (*C.embedded_pairing_bls12_381_g1affine_t)(unsafe.Pointer(uintptr(buffer) + uintptr(i)*C.sizeof_embedded_pairing_bls12_381_g1affine_t))
			pair.g2 = (*C.embedded_pairing_bls12_381_g2affine_t)(unsafe.Pointer(uintptr(buffer) + uintptr(aLen) + uintptr(i)*C.sizeof_embedded_pairing_bls12_381_g2affine_t))
			*pair.g1 = a[i].Data
			*pair.g2 = b[i].Data
		}
	}

	var preparedPairs *C.embedded_pairing_bls12_381_prepared_pair_t
	numPreparedPairs := C.size_t(len(c))
	if numPreparedPairs != 0 {
		cLen := numAffinePairs * C.sizeof_embedded_pairing_bls12_381_g1affine_t
		dLen := numAffinePairs * C.sizeof_embedded_pairing_bls12_381_g2prepared_t
		pairsLen := numAffinePairs * C.sizeof_embedded_pairing_bls12_381_prepared_pair_t

		buffer := C.malloc(cLen + dLen + pairsLen)
		defer C.free(buffer)

		preparedPairs = (*C.embedded_pairing_bls12_381_prepared_pair_t)(unsafe.Pointer(uintptr(buffer) + uintptr(cLen) + uintptr(dLen)))
		for i := range c {
			pair := (*C.embedded_pairing_bls12_381_prepared_pair_t)(unsafe.Pointer(uintptr(buffer) + uintptr(cLen) + uintptr(dLen) + uintptr(i)*C.sizeof_embedded_pairing_bls12_381_prepared_pair_t))
			pair.g1 = (*C.embedded_pairing_bls12_381_g1affine_t)(unsafe.Pointer(uintptr(buffer) + uintptr(i)*C.sizeof_embedded_pairing_bls12_381_g1affine_t))
			pair.g2 = (*C.embedded_pairing_bls12_381_g2prepared_t)(unsafe.Pointer(uintptr(buffer) + uintptr(cLen) + uintptr(i)*C.sizeof_embedded_pairing_bls12_381_g2prepared_t))
			*pair.g1 = c[i].Data
			*pair.g2 = d[i].Data
		}
	}

	C.embedded_pairing_bls12_381_pairing_sum(&result.Data, affinePairs, numAffinePairs, preparedPairs, numPreparedPairs)
	return result
}
