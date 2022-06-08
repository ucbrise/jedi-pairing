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

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/antimatterhq/jedi-pairing/lang/go/bls12381"
)

func TestHashToZp(t *testing.T) {
	hashes := []*big.Int{}
	for i := 0; i != 1000; i++ {
		buffer := make([]byte, 128)
		if _, err := rand.Read(buffer); err != nil {
			t.Fatal(err)
		}
		a := HashToZp(new(big.Int), buffer)
		b := HashToZp(new(big.Int), buffer)
		if a.Cmp(b) != 0 {
			t.Fatal("Hash is not deterministic")
		}
		for _, hash := range hashes {
			if a.Cmp(hash) == 0 {
				t.Fatal("Hash is not collision-resistant")
			}
		}
		if a.Sign() == -1 || a.Cmp(bls12381.GroupOrder) != -1 {
			t.Fatal("Hash is outside of the valid range")
		}
		hashes = append(hashes, a)
	}
}
