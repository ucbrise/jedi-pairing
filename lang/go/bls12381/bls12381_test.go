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

import (
	"math/big"
	"testing"
)

func TestGeneratorBilinearity(t *testing.T) {
	gtgen := new(GT).Pairing(G1GeneratorAffine, G2GeneratorAffine)
	if *gtgen != *GTGenerator {
		t.Fatal("Found counterexample to bilinearity")
	}
}

func TestBilinearity(t *testing.T) {
	for i := 0; i != 100; i++ {
		a := new(G1).Random()
		b := new(G2).Random()

		x := RandomZp(new(big.Int))
		y := RandomZp(new(big.Int))

		xa := new(G1).Multiply(a, x)
		yb := new(G2).Multiply(b, y)

		eab := new(GT).Pairing(new(G1Affine).FromProjective(a), new(G2Affine).FromProjective(b))
		xyeab := new(GT).Multiply(eab, y)
		xyeab.Multiply(xyeab, x)
		exayb := new(GT).Pairing(new(G1Affine).FromProjective(xa), new(G2Affine).FromProjective(yb))

		if *xyeab != *exayb {
			t.Fatal("Found counterexample to bilinearity")
		}
	}
}
